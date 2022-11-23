// SPDX-License-Identifier: GPL-2.0
/*
 * ALICC: Drivers for Alibaba cryptographic accelerator. Enables the
 *   on-chip cryptographic accelerator of Alibaba SoCs which is
 *   based on ARMv9 architecture.
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

#include "alicc_isr.h"
#include "alicc_cdev.h"
#include "alicc_ring.h"
#include "alicc_algs.h"
#include "alicc_uio.h"

static const char alicc_name[] = "alicc";

static int max_desc = 256;
static int user_rings;
static bool is_polling = true;
module_param(max_desc, int, 0644);
module_param(is_polling, bool, 0644);
module_param(user_rings, int, 0644);

atomic_t alicc_algs_refcnt;

LIST_HEAD(alicc_table);
DEFINE_MUTEX(alicc_mutex);

/*
 * Each alicc device (RCIEP or RCEC) supports upto 48 VFs
 * when enables SR-IOV. So each socket has 98 devices,
 * includes 2 PFs and 96 VFs.
 */
#define ALICC_MAX_DEVICES		(98 * 4) /* Assume 4 sockets */
static DEFINE_IDR(alicc_idr);

int alicc_algorithm_register(void)
{
	int ret = 0;

	/* No kernel rings */
	if (user_rings == ALICC_RINGPAIR_NUM)
		return ret;

	/* Only register once */
	if (atomic_inc_return(&alicc_algs_refcnt) > 1)
		return ret;

	ret = alicc_sym_register();
	if (ret)
		goto err;

	ret = alicc_aead_register();
	if (ret)
		goto unregister_sym;

	ret = alicc_pke_register();
	if (ret)
		goto unregister_aead;

	return 0;

unregister_aead:
	alicc_aead_unregister();
unregister_sym:
	alicc_sym_unregister();
err:
	atomic_dec(&alicc_algs_refcnt);
	return ret;
}

void alicc_algorithm_unregister(void)
{
	if (user_rings == ALICC_RINGPAIR_NUM)
		return;

	if (atomic_dec_return(&alicc_algs_refcnt))
		return;

	alicc_pke_unregister();
	alicc_aead_unregister();
	alicc_sym_unregister();
}

static int alicc_device_flr(struct pci_dev *pdev, struct pci_dev *rcec_pdev)
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
		pr_err("Failed to save alicc pci state\n");
		return ret;
	}

	ret = pci_save_state(rcec_pdev);
	if (ret) {
		pr_err("Failed to save alicc rcec pci state\n");
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

static int alicc_resource_setup(struct alicc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	struct pci_dev *pdev = ydev->pdev;
	struct alicc_bar *abar, *cfg_bar;
	u32 hclk_status;
	int ret;

	ret = alicc_device_flr(pdev, rcec_pdev);
	if (ret)
		return ret;

	ret = pci_request_regions(pdev, ydev->dev_name);
	if (ret) {
		pr_err("Failed to request mem regions for rciep\n");
		return ret;
	}

	ret = -EIO;
	cfg_bar = &ydev->alicc_bars[ALICC_SEC_CFG_BAR];
	cfg_bar->paddr = pci_resource_start(pdev, ALICC_SEC_CFG_BAR);
	cfg_bar->size = pci_resource_len(pdev, ALICC_SEC_CFG_BAR);
	cfg_bar->vaddr = ioremap(cfg_bar->paddr, cfg_bar->size);
	if (!cfg_bar->vaddr) {
		pr_err("Failed to ioremap rciep cfg bar\n");
		goto release_mem_regions;
	}

	alicc_g_err_mask(cfg_bar->vaddr);

	ALICC_CSR_WR(cfg_bar->vaddr, REG_ALICC_CTL, 0|ALICC_CTRL_IRAM_EN);
	ALICC_CSR_WR(cfg_bar->vaddr, REG_ALICC_GO, 0|ALICC_GO_PWRON);

	/* Waiting for alicc firmware ready, 1000ms is recommended by the HW designers */
	mdelay(1000);
	if (!(ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_GO) & ALICC_GO_ENABLED)) {
		pr_err("Failed to set alicc enabled\n");
		goto iounmap_cfg_bar;
	}

	/* Check HCLK int status reg, some error happened at PWRON stage */
	hclk_status = ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_HCLK_INT_STATUS);
	if (hclk_status & ALICC_HCLK_INIT_ERR) {
		pr_err("Error happened when alicc was initializing\n");
		goto iounmap_cfg_bar;
	}

	abar = &ydev->alicc_bars[ALICC_NSEC_Q_BAR];
	abar->paddr = pci_resource_start(pdev, ALICC_NSEC_Q_BAR);
	abar->size = pci_resource_len(pdev, ALICC_NSEC_Q_BAR);
	abar->vaddr = pci_iomap(pdev, ALICC_NSEC_Q_BAR, abar->size);
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

	ret = alicc_dev_rings_init(ydev, max_desc, user_rings);
	if (ret) {
		pr_err("Failed to init alicc rings\n");
		goto iounmap_queue_bar;
	}

	ret = alicc_enable_msix(ydev);
	if (ret <= 0) {
		pr_err("Failed to enable alicc msix, ret:%d\n", ret);
		ret = (ret == 0) ? -EINVAL : ret;
		goto release_rings;
	}

	ret = alicc_init_global_err(ydev);
	if (ret) {
		pr_err("Failed to enable alicc global err\n");
		goto disable_msix;
	}

	ret = alicc_alloc_irqs(ydev);
	if (ret) {
		pr_err("Failed to alloc alicc irqs\n");
		goto deinit_g_err;
	}

	ALICC_CSR_WR(cfg_bar->vaddr, REG_ALICC_HCLK_INT_STATUS, ~0);
	alicc_g_err_unmask(cfg_bar->vaddr);

	return 0;

deinit_g_err:
	alicc_deinit_global_err(ydev);
disable_msix:
	alicc_disable_msix(ydev);
release_rings:
	alicc_dev_rings_release(ydev, user_rings);
iounmap_queue_bar:
	iounmap(abar->vaddr);
iounmap_cfg_bar:
	iounmap(cfg_bar->vaddr);
release_mem_regions:
	pci_release_regions(pdev);

	return ret;
}

static void alicc_resource_free(struct alicc_dev *ydev)
{
	alicc_deinit_global_err(ydev);
	alicc_free_irqs(ydev);
	alicc_disable_msix(ydev);
	alicc_dev_rings_release(ydev, ydev->user_rings);
	iounmap(ydev->alicc_bars[ALICC_SEC_CFG_BAR].vaddr);
	iounmap(ydev->alicc_bars[ALICC_NSEC_Q_BAR].vaddr);
	pci_release_regions(ydev->pdev);
}

static inline bool alicc_rcec_match(struct pci_dev *pdev0, struct pci_dev *pdev1)
{
	return pdev0->bus->number == pdev1->bus->number;
}

static int alicc_rcec_bind(struct alicc_dev *ydev)
{
	struct alicc_dev *assoc_dev, *rciep, *rcec;
	struct list_head *itr;
	int ret = 0;

	if (list_empty(&alicc_table))
		goto out;

	list_for_each(itr, &alicc_table) {
		assoc_dev = list_entry(itr, struct alicc_dev, list);
		/* not in the same pci bus */
		if (!alicc_rcec_match(ydev->pdev, assoc_dev->pdev))
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
		rciep = (ydev->type == ALICC_RCIEP) ? ydev : ydev->assoc_dev;
		rcec = rciep->assoc_dev;

		ret = sysfs_create_link(&rcec->pdev->dev.kobj,
					&rciep->pdev->dev.kobj, "alicc_rciep");
		if (ret)
			goto out;

		ret = sysfs_create_link(&rciep->pdev->dev.kobj,
					&rcec->pdev->dev.kobj, "alicc_rcec");
		if (ret)
			goto remove_rciep_link;

		ret = alicc_resource_setup(rciep);
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
	sysfs_remove_link(&rciep->pdev->dev.kobj, "alicc_rcec");
remove_rciep_link:
	sysfs_remove_link(&rcec->pdev->dev.kobj, "alicc_rciep");
out:
	return ret;
}

static void alicc_rcec_unbind(struct alicc_dev *ydev)
{
	struct alicc_dev *rciep, *rcec;

	if (!test_bit(YDEV_STATUS_BIND, &ydev->status))
		return;

	rciep = (ydev->type == ALICC_RCIEP) ? ydev : ydev->assoc_dev;
	rcec = rciep->assoc_dev;

	clear_bit(YDEV_STATUS_READY, &rciep->status);
	clear_bit(YDEV_STATUS_READY, &rcec->status);
	clear_bit(YDEV_STATUS_BIND, &rciep->status);
	clear_bit(YDEV_STATUS_BIND, &rcec->status);
	sysfs_remove_link(&rcec->pdev->dev.kobj, "alicc_rciep");
	sysfs_remove_link(&rciep->pdev->dev.kobj, "alicc_rcec");
	alicc_resource_free(rciep);
	rciep->assoc_dev = NULL;
	rcec->assoc_dev = NULL;
	alicc_algorithm_unregister();
}

static int alicc_dev_add(struct alicc_dev *ydev)
{
	int ret;

	mutex_lock(&alicc_mutex);
	ret = alicc_rcec_bind(ydev);
	if (ret)
		goto out;
	list_add_tail(&ydev->list, &alicc_table);

out:
	mutex_unlock(&alicc_mutex);
	return ret;
}

static void alicc_dev_del(struct alicc_dev *ydev)
{
	mutex_lock(&alicc_mutex);
	alicc_rcec_unbind(ydev);
	list_del(&ydev->list);
	mutex_unlock(&alicc_mutex);
}

static inline int alicc_rciep_init(struct alicc_dev *ydev, struct pci_dev *pdev)
{
	char name[ALICC_MAX_DEBUGFS_NAME + 1];
	int idr;

	ydev->sec = false;
	ydev->dev_name = alicc_name;
	ydev->user_rings = user_rings;
	ydev->max_desc = max_desc;
	ydev->is_polling = is_polling;

	idr = idr_alloc(&alicc_idr, ydev, 0, ALICC_MAX_DEVICES, GFP_KERNEL);
	if (idr < 0) {
		pr_err("Failed to allocate idr for alicc device\n");
		return idr;
	}

	ydev->id = idr;

	snprintf(name, ALICC_MAX_DEBUGFS_NAME, "alicc_%02x:%02d.%02d",
		 pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	ydev->debug_dir = debugfs_create_dir(name, NULL);
	/* If failed to create debugfs, driver can still work */
	if (IS_ERR_OR_NULL(ydev->debug_dir)) {
		pr_warn("Failed to create debugfs for alicc device\n");
		ydev->debug_dir = NULL;
	}

	return 0;
}

static int alicc_drv_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct alicc_dev *ydev;
	struct device *dev = &pdev->dev;
	int node = dev_to_node(dev);
	int ret = -ENOMEM;

	ydev = kzalloc_node(sizeof(struct alicc_dev), GFP_KERNEL, node);
	if (!ydev)
		return ret;

	ret = pci_enable_device(pdev);
	if (ret) {
		pr_err("Failed to enable alicc pci device\n");
		goto free_ydev;
	}
	pci_set_master(pdev);
	pci_set_drvdata(pdev, ydev);

	ydev->pdev = pdev;
	ydev->is_vf = false;
	ydev->enable_vf = false;
	ydev->node = node;
	if (id->device == PCI_DEVICE_ID_RCIEP) {
		ydev->type = ALICC_RCIEP;
		ret = alicc_rciep_init(ydev, pdev);
		if (ret)
			goto disable_ydev;
	} else {
		ydev->type = ALICC_RCEC;
	}

	ret = alicc_dev_add(ydev);
	if (ret)
		goto remove_debugfs;

	if (ydev->type == ALICC_RCIEP) {
		/* TODO: add dev refcnt in alicc bind iommu domain */
		ret = alicc_bind_iommu_domain(pdev, ydev->id);
		if (ret) {
			pr_err("Failed to bind iommu domain for alicc pci device\n");
			goto dev_del;
		}
	}

	if (test_bit(YDEV_STATUS_READY, &ydev->status)) {
		ret = alicc_algorithm_register();
		if (ret) {
			pr_err("Failed to register algorithm\n");
			clear_bit(YDEV_STATUS_READY, &ydev->status);
			clear_bit(YDEV_STATUS_READY, &ydev->assoc_dev->status);
			goto unbind_domain;
		}
	}

	return ret;

unbind_domain:
	if (ydev->type == ALICC_RCIEP)
		alicc_unbind_iommu_domain(pdev, ydev->id);
dev_del:
	alicc_dev_del(ydev);
remove_debugfs:
	if (ydev->type == ALICC_RCIEP) {
		debugfs_remove_recursive(ydev->debug_dir);
		idr_remove(&alicc_idr, ydev->id);
	}
disable_ydev:
	pci_disable_device(pdev);
free_ydev:
	pr_err("Failed to probe :%s\n", ydev->type == ALICC_RCIEP ? "rciep" : "rcec");
	kfree(ydev);
	return ret;
}

static void alicc_drv_remove(struct pci_dev *pdev)
{
	struct alicc_dev *ydev = pci_get_drvdata(pdev);

	alicc_dev_del(ydev);
	if (ydev->type == ALICC_RCIEP) {
		alicc_unbind_iommu_domain(pdev, ydev->id);
		debugfs_remove_recursive(ydev->debug_dir);
		idr_remove(&alicc_idr, ydev->id);
	}

	pci_disable_sriov(pdev);
	pci_disable_device(pdev);
	kfree(ydev);
}

static int alicc_drv_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	const int totalvfs = pci_sriov_get_totalvfs(pdev);
	struct alicc_dev *ydev = pci_get_drvdata(pdev);
	struct alicc_dev *rciep = NULL;
	int ret = 0;

	if (!ydev) {
		pr_err("Failed to find alicc device\n");
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
			rciep = (ydev->type == ALICC_RCIEP) ? ydev : ydev->assoc_dev;

			if (alicc_dev_in_use(rciep)) {
				pr_info("Ycc is being used\n");
				return -EBUSY;
			}

			alicc_rcec_unbind(ydev);
		}

		ret = pci_enable_sriov(pdev, totalvfs);
		if (ret) {
			pr_err("Failed to enable alicc sriov\n");
			ret = alicc_rcec_bind(ydev);
			if (ret) {
				pr_err("Failed to rebind alicc\n");
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
		alicc_rcec_bind(ydev);

		ydev->enable_vf = false;
		clear_bit(YDEV_STATUS_SRIOV, &ydev->status);
	}

	return ret;
}

static const struct pci_device_id alicc_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ALICC, PCI_DEVICE_ID_RCIEP) },
	{ PCI_DEVICE(PCI_VENDOR_ID_ALICC, PCI_DEVICE_ID_RCEC) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, alicc_id_table);

static struct pci_driver alicc_driver = {
	.name		= "alicc",
	.id_table	= alicc_id_table,
	.probe		= alicc_drv_probe,
	.remove		= alicc_drv_remove,
	.sriov_configure = alicc_drv_sriov_configure,
};

static int __init alicc_drv_init(void)
{
	int ret;

	if (user_rings > ALICC_RINGPAIR_NUM)
		user_rings = ALICC_RINGPAIR_NUM;

	atomic_set(&alicc_algs_refcnt, 0);

	ret = alicc_udma_init();
	if (ret)
		goto err;

	ret = alicc_cdev_register();
	if (ret)
		goto udma_exit;

	ret = pci_register_driver(&alicc_driver);
	if (ret)
		goto cdev_unregister;

	return 0;

udma_exit:
	alicc_udma_exit();
cdev_unregister:
	alicc_cdev_unregister();
err:
	return ret;
}

static void __exit alicc_drv_exit(void)
{
	alicc_cdev_unregister();
	pci_unregister_driver(&alicc_driver);
	alicc_udma_exit();
}

module_init(alicc_drv_init);
module_exit(alicc_drv_exit);
MODULE_AUTHOR("Zelin Deng <zelin.deng@linux.alibaba.com>");
MODULE_AUTHOR("Guanjun <guanjun@linux.alibaba.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Driver for Alibaba cryptographic accelerator");
