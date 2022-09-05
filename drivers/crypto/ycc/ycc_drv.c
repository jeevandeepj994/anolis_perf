// SPDX-License-Identifier: GPL-2.0
/*
 * YCC: Drivers for Alibaba YCC (Yitian Cryptography Complex) cryptographic
 *   accelerator. Enables the on-chip cryptographic accelerator of Alibaba
 *   Yitian SoCs which is based on ARMv9 architecture.
 *
 * Copyright (C) 2020-2022 Alibaba Corporation. All rights reserved.
 * Author: Zelin Deng <zelin.deng@linux.alibaba.com>
 * Author: Guanjun <guanjun@linux.alibaba.com>
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/iommu.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>

#include "ycc_isr.h"
#include "ycc_cdev.h"
#include "ycc_ring.h"
#include "ycc_algs.h"
#include "ycc_uio.h"

static const char ycc_name[] = "ycc";

static int max_desc = 256;
static int user_rings;
static bool is_polling = true;
module_param(max_desc, int, 0644);
module_param(is_polling, bool, 0644);
module_param(user_rings, int, 0644);

atomic_t ycc_algs_refcnt;

LIST_HEAD(ycc_table);
DEFINE_MUTEX(ycc_mutex);

/*
 * Each ycc device (RCIEP or RCEC) supports upto 48 VFs
 * when enables SR-IOV. So each socket has 98 devices,
 * includes 2 PFs and 96 VFs.
 */
#define YCC_MAX_DEVICES		(98 * 4) /* Assume 4 sockets */
static DEFINE_IDR(ycc_idr);

int ycc_algorithm_register(void)
{
	int ret = 0;

	/* No kernel rings */
	if (user_rings == YCC_RINGPAIR_NUM)
		return ret;

	/* Only register once */
	if (atomic_inc_return(&ycc_algs_refcnt) > 1)
		return ret;

	ret = ycc_sym_register();
	if (ret)
		goto err;

	ret = ycc_aead_register();
	if (ret)
		goto unregister_sym;

	ret = ycc_pke_register();
	if (ret)
		goto unregister_aead;

	return 0;

unregister_aead:
	ycc_aead_unregister();
unregister_sym:
	ycc_sym_unregister();
err:
	atomic_dec(&ycc_algs_refcnt);
	return ret;
}

void ycc_algorithm_unregister(void)
{
	if (user_rings == YCC_RINGPAIR_NUM)
		return;

	if (atomic_dec_return(&ycc_algs_refcnt))
		return;

	ycc_pke_unregister();
	ycc_aead_unregister();
	ycc_sym_unregister();
}

static int ycc_device_flr(struct pci_dev *pdev, struct pci_dev *rcec_pdev)
{
	int ret;

	/*
	 * NOTE: When rciep gets FLR, its associated rcec gets reset as well.
	 * It does not make sense that individual pcie device should impact
	 * others. Before it has been fixed on silicon side, add a workaround to
	 * do FLR properly -- save both pci states and restore them latter.
	 */
	ret = pci_save_state(pdev);
	if (ret) {
		pr_err("Failed to save ycc pci state\n");
		return ret;
	}

	ret = pci_save_state(rcec_pdev);
	if (ret) {
		pr_err("Failed to save ycc rcec pci state\n");
		return ret;
	}

	if (pcie_has_flr(rcec_pdev))
		pcie_flr(rcec_pdev);

	if (pcie_has_flr(pdev))
		pcie_flr(pdev);

	pci_restore_state(pdev);
	pci_restore_state(rcec_pdev);

	return 0;
}

static int ycc_resource_setup(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	struct pci_dev *pdev = ydev->pdev;
	struct ycc_bar *abar, *cfg_bar;
	u32 hclk_status;
	int ret;

	ret = ycc_device_flr(pdev, rcec_pdev);
	if (ret)
		return ret;

	ret = pci_request_regions(pdev, ydev->dev_name);
	if (ret) {
		pr_err("Failed to request mem regions for rciep\n");
		return ret;
	}

	ret = -EIO;
	cfg_bar = &ydev->ycc_bars[YCC_SEC_CFG_BAR];
	cfg_bar->paddr = pci_resource_start(pdev, YCC_SEC_CFG_BAR);
	cfg_bar->size = pci_resource_len(pdev, YCC_SEC_CFG_BAR);
	cfg_bar->vaddr = ioremap(cfg_bar->paddr, cfg_bar->size);
	if (!cfg_bar->vaddr) {
		pr_err("Failed to ioremap rciep cfg bar\n");
		goto release_mem_regions;
	}

	ycc_g_err_mask(cfg_bar->vaddr);

	YCC_CSR_WR(cfg_bar->vaddr, REG_YCC_CTL, 0|YCC_CTRL_IRAM_EN);
	YCC_CSR_WR(cfg_bar->vaddr, REG_YCC_GO, 0|YCC_GO_PWRON);

	/* Waiting for ycc firmware ready, 1000ms is recommended by the HW designers */
	mdelay(1000);
	if (!(YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_GO) & YCC_GO_ENABLED)) {
		pr_err("Failed to set ycc enabled\n");
		goto iounmap_cfg_bar;
	}

	/* Check HCLK int status reg, some error happened at PWRON stage */
	hclk_status = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_HCLK_INT_STATUS);
	if (hclk_status & YCC_HCLK_INIT_ERR) {
		pr_err("Error happened when ycc was initializing\n");
		goto iounmap_cfg_bar;
	}

	abar = &ydev->ycc_bars[YCC_NSEC_Q_BAR];
	abar->paddr = pci_resource_start(pdev, YCC_NSEC_Q_BAR);
	abar->size = pci_resource_len(pdev, YCC_NSEC_Q_BAR);
	abar->vaddr = pci_iomap(pdev, YCC_NSEC_Q_BAR, abar->size);
	if (!abar->vaddr) {
		pr_err("Failed to ioremap rciep queue bar\n");
		goto iounmap_cfg_bar;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret < 0) {
		pr_info("Failed to set DMA bit mask 64, try 32\n");
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (ret < 0)
			goto iounmap_queue_bar;
	}

	ret = ycc_dev_rings_init(ydev, max_desc, user_rings);
	if (ret) {
		pr_err("Failed to init ycc rings\n");
		goto iounmap_queue_bar;
	}

	ret = ycc_enable_msix(ydev);
	if (ret <= 0) {
		pr_err("Failed to enable ycc msix, ret:%d\n", ret);
		ret = (ret == 0) ? -EINVAL : ret;
		goto release_rings;
	}

	ret = ycc_init_global_err(ydev);
	if (ret) {
		pr_err("Failed to enable ycc global err\n");
		goto disable_msix;
	}

	ret = ycc_alloc_irqs(ydev);
	if (ret) {
		pr_err("Failed to alloc ycc irqs\n");
		goto deinit_g_err;
	}

	YCC_CSR_WR(cfg_bar->vaddr, REG_YCC_HCLK_INT_STATUS, ~0);
	ycc_g_err_unmask(cfg_bar->vaddr);

	return 0;

deinit_g_err:
	ycc_deinit_global_err(ydev);
disable_msix:
	ycc_disable_msix(ydev);
release_rings:
	ycc_dev_rings_release(ydev, user_rings);
iounmap_queue_bar:
	iounmap(abar->vaddr);
iounmap_cfg_bar:
	iounmap(cfg_bar->vaddr);
release_mem_regions:
	pci_release_regions(pdev);

	return ret;
}

static void ycc_resource_free(struct ycc_dev *ydev)
{
	ycc_deinit_global_err(ydev);
	ycc_free_irqs(ydev);
	ycc_disable_msix(ydev);
	ycc_dev_rings_release(ydev, ydev->user_rings);
	iounmap(ydev->ycc_bars[YCC_SEC_CFG_BAR].vaddr);
	iounmap(ydev->ycc_bars[YCC_NSEC_Q_BAR].vaddr);
	pci_release_regions(ydev->pdev);
}

static inline bool ycc_rcec_match(struct pci_dev *pdev0, struct pci_dev *pdev1)
{
	return pdev0->bus->number == pdev1->bus->number;
}

static int ycc_rcec_bind(struct ycc_dev *ydev)
{
	struct ycc_dev *assoc_dev, *rciep, *rcec;
	struct list_head *itr;
	int ret = 0;

	if (list_empty(&ycc_table))
		goto out;

	list_for_each(itr, &ycc_table) {
		assoc_dev = list_entry(itr, struct ycc_dev, list);
		/* not in the same pci bus */
		if (!ycc_rcec_match(ydev->pdev, assoc_dev->pdev))
			continue;

		/* if sriov is enabled, it could be the same */
		if (ydev == assoc_dev)
			continue;

		/* if sriov is enabled, found other VFs */
		if (ydev->type == assoc_dev->type)
			continue;

		/* assocated device has been enabled sriov */
		if (test_bit(YDEV_STATUS_SRIOV, &assoc_dev->status))
			goto out;

		/* have been bound */
		if (test_bit(YDEV_STATUS_BIND, &assoc_dev->status))
			continue;

		ydev->assoc_dev = assoc_dev;
		assoc_dev->assoc_dev = ydev;
		rciep = (ydev->type == YCC_RCIEP) ? ydev : ydev->assoc_dev;
		rcec = rciep->assoc_dev;

		ret = sysfs_create_link(&rcec->pdev->dev.kobj,
					&rciep->pdev->dev.kobj, "ycc_rciep");
		if (ret)
			goto out;

		ret = sysfs_create_link(&rciep->pdev->dev.kobj,
					&rcec->pdev->dev.kobj, "ycc_rcec");
		if (ret)
			goto remove_rciep_link;

		ret = ycc_resource_setup(rciep);
		if (ret)
			goto remove_rcec_link;

		set_bit(YDEV_STATUS_READY, &rciep->status);
		set_bit(YDEV_STATUS_BIND, &rciep->status);
		set_bit(YDEV_STATUS_READY, &rcec->status);
		set_bit(YDEV_STATUS_BIND, &rcec->status);
		goto out;
	}

	return ret;

remove_rcec_link:
	sysfs_remove_link(&rciep->pdev->dev.kobj, "ycc_rcec");
remove_rciep_link:
	sysfs_remove_link(&rcec->pdev->dev.kobj, "ycc_rciep");
out:
	return ret;
}

static void ycc_rcec_unbind(struct ycc_dev *ydev)
{
	struct ycc_dev *rciep, *rcec;

	if (!test_bit(YDEV_STATUS_BIND, &ydev->status))
		return;

	rciep = (ydev->type == YCC_RCIEP) ? ydev : ydev->assoc_dev;
	rcec = rciep->assoc_dev;

	clear_bit(YDEV_STATUS_READY, &rciep->status);
	clear_bit(YDEV_STATUS_READY, &rcec->status);
	clear_bit(YDEV_STATUS_BIND, &rciep->status);
	clear_bit(YDEV_STATUS_BIND, &rcec->status);
	sysfs_remove_link(&rcec->pdev->dev.kobj, "ycc_rciep");
	sysfs_remove_link(&rciep->pdev->dev.kobj, "ycc_rcec");
	ycc_resource_free(rciep);
	rciep->assoc_dev = NULL;
	rcec->assoc_dev = NULL;
	ycc_algorithm_unregister();
}

static int ycc_dev_add(struct ycc_dev *ydev)
{
	int ret;

	mutex_lock(&ycc_mutex);
	ret = ycc_rcec_bind(ydev);
	if (ret)
		goto out;
	list_add_tail(&ydev->list, &ycc_table);

out:
	mutex_unlock(&ycc_mutex);
	return ret;
}

static void ycc_dev_del(struct ycc_dev *ydev)
{
	mutex_lock(&ycc_mutex);
	ycc_rcec_unbind(ydev);
	list_del(&ydev->list);
	mutex_unlock(&ycc_mutex);
}

static inline int ycc_rciep_init(struct ycc_dev *ydev, struct pci_dev *pdev)
{
	char name[YCC_MAX_DEBUGFS_NAME + 1];
	int idr;

	ydev->sec = false;
	ydev->dev_name = ycc_name;
	ydev->user_rings = user_rings;
	ydev->max_desc = max_desc;
	ydev->is_polling = is_polling;

	idr = idr_alloc(&ycc_idr, ydev, 0, YCC_MAX_DEVICES, GFP_KERNEL);
	if (idr < 0) {
		pr_err("Failed to allocate idr for ycc device\n");
		return idr;
	}

	ydev->id = idr;

	snprintf(name, YCC_MAX_DEBUGFS_NAME, "ycc_%02x:%02d.%02d",
		 pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	ydev->debug_dir = debugfs_create_dir(name, NULL);
	/* If failed to create debugfs, driver can still work */
	if (IS_ERR_OR_NULL(ydev->debug_dir)) {
		pr_warn("Failed to create debugfs for ycc device\n");
		ydev->debug_dir = NULL;
	}

	return 0;
}

static int ycc_drv_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ycc_dev *ydev;
	struct device *dev = &pdev->dev;
	int node = dev_to_node(dev);
	int ret = -ENOMEM;

	ydev = kzalloc_node(sizeof(struct ycc_dev), GFP_KERNEL, node);
	if (!ydev)
		return ret;

	ret = pci_enable_device(pdev);
	if (ret) {
		pr_err("Failed to enable ycc pci device\n");
		goto free_ydev;
	}
	pci_set_master(pdev);
	pci_set_drvdata(pdev, ydev);

	ydev->pdev = pdev;
	ydev->is_vf = false;
	ydev->enable_vf = false;
	ydev->node = node;
	if (id->device == PCI_DEVICE_ID_RCIEP) {
		ydev->type = YCC_RCIEP;
		ret = ycc_rciep_init(ydev, pdev);
		if (ret)
			goto disable_ydev;
	} else {
		ydev->type = YCC_RCEC;
	}

	ret = ycc_dev_add(ydev);
	if (ret)
		goto remove_debugfs;

	if (ydev->type == YCC_RCIEP) {
		/* TODO: add dev refcnt in ycc bind iommu domain */
		ret = ycc_bind_iommu_domain(pdev, ydev->id);
		if (ret) {
			pr_err("Failed to bind iommu domain for ycc pci device\n");
			goto dev_del;
		}
	}

	if (test_bit(YDEV_STATUS_READY, &ydev->status)) {
		ret = ycc_algorithm_register();
		if (ret) {
			pr_err("Failed to register algorithm\n");
			clear_bit(YDEV_STATUS_READY, &ydev->status);
			clear_bit(YDEV_STATUS_READY, &ydev->assoc_dev->status);
			goto unbind_domain;
		}
	}

	return ret;

unbind_domain:
	if (ydev->type == YCC_RCIEP)
		ycc_unbind_iommu_domain(pdev, ydev->id);
dev_del:
	ycc_dev_del(ydev);
remove_debugfs:
	if (ydev->type == YCC_RCIEP) {
		debugfs_remove_recursive(ydev->debug_dir);
		idr_remove(&ycc_idr, ydev->id);
	}
disable_ydev:
	pci_disable_device(pdev);
free_ydev:
	pr_err("Failed to probe :%s\n", ydev->type == YCC_RCIEP ? "rciep" : "rcec");
	kfree(ydev);
	return ret;
}

static void ycc_drv_remove(struct pci_dev *pdev)
{
	struct ycc_dev *ydev = pci_get_drvdata(pdev);

	ycc_dev_del(ydev);
	if (ydev->type == YCC_RCIEP) {
		ycc_unbind_iommu_domain(pdev, ydev->id);
		debugfs_remove_recursive(ydev->debug_dir);
		idr_remove(&ycc_idr, ydev->id);
	}

	pci_disable_sriov(pdev);
	pci_disable_device(pdev);
	kfree(ydev);
}

static int ycc_drv_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	const int totalvfs = pci_sriov_get_totalvfs(pdev);
	struct ycc_dev *ydev = pci_get_drvdata(pdev);
	struct ycc_dev *rciep = NULL;
	int ret = 0;

	if (!ydev) {
		pr_err("Failed to find ycc device\n");
		return -EFAULT;
	}

	if (!ydev->enable_vf && !numvfs)
		return -EINVAL;

	if (ydev->enable_vf && numvfs)
		return 0;

	if (test_bit(YDEV_STATUS_ERR, &ydev->status)) {
		pr_err("Device cannot be used, status %lu\n", ydev->status);
		return -EIO;
	}

	if (numvfs) {
		/*
		 * Before enabling SR-IOV, RCIEP and RCEC should been unbound
		 */
		if (test_bit(YDEV_STATUS_BIND, &ydev->status)) {
			rciep = (ydev->type == YCC_RCIEP) ? ydev : ydev->assoc_dev;

			if (ycc_dev_in_use(rciep)) {
				pr_info("Ycc is being used\n");
				return -EBUSY;
			}

			ycc_rcec_unbind(ydev);
		}

		ret = pci_enable_sriov(pdev, totalvfs);
		if (ret) {
			pr_err("Failed to enable ycc sriov\n");
			ret = ycc_rcec_bind(ydev);
			if (ret) {
				pr_err("Failed to rebind ycc\n");
				return ret;
			}
			return -EIO;
		}

		ydev->enable_vf = true;
		set_bit(YDEV_STATUS_SRIOV, &ydev->status);
		ret = totalvfs;
	} else {
		/*
		 * TODO: make sure vf is not in use;
		 * and notify vf that we are going to disable SR-IOV
		 */
		pci_disable_sriov(pdev);
		ycc_rcec_bind(ydev);

		ydev->enable_vf = false;
		clear_bit(YDEV_STATUS_SRIOV, &ydev->status);
	}

	return ret;
}

static const struct pci_device_id ycc_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_YCC, PCI_DEVICE_ID_RCIEP) },
	{ PCI_DEVICE(PCI_VENDOR_ID_YCC, PCI_DEVICE_ID_RCEC) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, ycc_id_table);

static struct pci_driver ycc_driver = {
	.name		= "ycc",
	.id_table	= ycc_id_table,
	.probe		= ycc_drv_probe,
	.remove		= ycc_drv_remove,
	.sriov_configure = ycc_drv_sriov_configure,
};

static int __init ycc_drv_init(void)
{
	int ret;

	if (user_rings > YCC_RINGPAIR_NUM)
		user_rings = YCC_RINGPAIR_NUM;

	atomic_set(&ycc_algs_refcnt, 0);

	ret = ycc_udma_init();
	if (ret)
		goto err;

	ret = ycc_cdev_register();
	if (ret)
		goto udma_exit;

	ret = pci_register_driver(&ycc_driver);
	if (ret)
		goto cdev_unregister;

	return 0;

udma_exit:
	ycc_udma_exit();
cdev_unregister:
	ycc_cdev_unregister();
err:
	return ret;
}

static void __exit ycc_drv_exit(void)
{
	ycc_cdev_unregister();
	pci_unregister_driver(&ycc_driver);
	ycc_udma_exit();
}

module_init(ycc_drv_init);
module_exit(ycc_drv_exit);
MODULE_AUTHOR("Zelin Deng <zelin.deng@linux.alibaba.com>");
MODULE_AUTHOR("Guanjun <guanjun@linux.alibaba.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Driver for Alibaba YCC cryptographic accelerator");
