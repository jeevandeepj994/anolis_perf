// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/interrupt.h>

#include "ycc_isr.h"
#include "ycc_dev.h"
#include "ycc_ring.h"

extern void ycc_clear_cmd_ring(struct ycc_ring *ring);
extern void ycc_clear_resp_ring(struct ycc_ring *ring);

static irqreturn_t ycc_resp_isr(int irq, void *data)
{
	struct ycc_ring *ring = (struct ycc_ring *)data;

	schedule_work(&ring->work);

	return IRQ_HANDLED;
}

static int ycc_send_uevent(struct ycc_dev *ydev, const char *event)
{
	char *envp[3];
	char *dev_id;
	int ret;

	dev_id = kasprintf(GFP_ATOMIC, "YCC_DEVID=%d", ydev->id);
	if (!dev_id)
		return -ENOMEM;

	envp[0] = (char *)event;
	envp[1] = dev_id;
	envp[2] = NULL;

	ret = kobject_uevent_env(&ydev->pdev->dev.kobj, KOBJ_CHANGE, envp);
	if (ret)
		pr_err("Failed to send uevent for ycc:%d\n", ydev->id);

	kfree(dev_id);
	return ret;
}

static void ycc_fatal_error(struct ycc_dev *ydev)
{
	struct ycc_ring *ring;
	int i;

	for (i = 0; i < YCC_RINGPAIR_NUM; i++) {
		ring = ydev->rings + i;

		if (ring->type != KERN_RING)
			continue;

		spin_lock_bh(&ring->lock);
		ycc_clear_cmd_ring(ring);
		spin_unlock_bh(&ring->lock);

		ycc_clear_resp_ring(ring);
	}

	/*
	 * After all rings had been cleared, we should notify
	 * user space that ycc has fatal error
	 */
	ycc_send_uevent(ydev, "YCC_STATUS=fatal");
}

static void ycc_process_global_err(struct work_struct *work)
{
	struct ycc_dev *ydev = container_of(work, struct ycc_dev, work);
	struct ycc_bar *cfg_bar = &ydev->ycc_bars[YCC_SEC_CFG_BAR];
	struct ycc_ring *ring;
	u32 hclk_err, xclk_err;
	u32 xclk_ecc_uncor_err_0, xclk_ecc_uncor_err_1;
	u32 hclk_ecc_uncor_err;
	int i;

	if (pci_wait_for_pending_transaction(ydev->pdev))
		pr_warn("YCC: Failed to pending transaction\n");

	/* Notify user space YCC is in error handling */
	ycc_send_uevent(ydev, "YCC_STATUS=stopped");

	hclk_err = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_HCLK_INT_STATUS);
	xclk_err = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_XCLK_INT_STATUS);
	xclk_ecc_uncor_err_0 = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_XCLK_MEM_ECC_UNCOR_0);
	xclk_ecc_uncor_err_1 = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_XCLK_MEM_ECC_UNCOR_1);
	hclk_ecc_uncor_err = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_HCLK_MEM_ECC_UNCOR);

	if ((hclk_err & ~(YCC_HCLK_TRNG_ERR)) || xclk_err || hclk_ecc_uncor_err) {
		pr_err("YCC: Got uncorrected error, must be reset\n");
		/*
		 * Fatal error, as YCC cannot be reset in REE, clear ring data.
		 */
		return ycc_fatal_error(ydev);
	}

	if (xclk_ecc_uncor_err_0 || xclk_ecc_uncor_err_1) {
		pr_err("YCC: Got algorithm ECC error: %x ,%x\n",
		       xclk_ecc_uncor_err_0, xclk_ecc_uncor_err_1);
		return ycc_fatal_error(ydev);
	}

	/* This has to be queue error. Handling command rings. */
	for (i = 0; i < YCC_RINGPAIR_NUM; i++) {
		ring = ydev->rings + i;

		if (ring->type != KERN_RING)
			continue;

		ring->status = YCC_CSR_RD(ring->csr_vaddr, REG_RING_STATUS);
		if (ring->status) {
			pr_err("YCC: Dev: %d, Ring: %d got ring err: %x\n",
			       ydev->id, ring->ring_id, ring->status);
			spin_lock_bh(&ring->lock);
			ycc_clear_cmd_ring(ring);
			spin_unlock_bh(&ring->lock);
		}
	}

	/*
	 * Give HW a chance to process all pending_cmds
	 * through recovering transactions.
	 */
	pci_set_master(ydev->pdev);

	/* Handling response rings. */
	for (i = 0; i < YCC_RINGPAIR_NUM; i++) {
		ring = ydev->rings + i;

		if (ring->type != KERN_RING || !ring->status)
			continue;

		ycc_clear_resp_ring(ring);
	}

	ycc_g_err_unmask(cfg_bar->vaddr);
	clear_bit(YDEV_STATUS_ERR, &ydev->status);
	set_bit(YDEV_STATUS_READY, &ydev->status);
	ycc_send_uevent(ydev, "YCC_STATUS=ready");
}

static irqreturn_t ycc_g_err_isr(int irq, void *data)
{
	struct ycc_dev *ydev = (struct ycc_dev *)data;
	struct ycc_bar *cfg_bar;

	if (test_and_set_bit(YDEV_STATUS_ERR, &ydev->status))
		return IRQ_HANDLED;

	/* Mask global errors until it has been processed */
	cfg_bar = &ydev->ycc_bars[YCC_SEC_CFG_BAR];
	ycc_g_err_mask(cfg_bar->vaddr);

	clear_bit(YDEV_STATUS_READY, &ydev->status);

	/* Disable YCC mastering, no new transactions */
	pci_clear_master(ydev->pdev);

	schedule_work(&ydev->work);
	return IRQ_HANDLED;
}

void ycc_resp_work_process(struct work_struct *work)
{
	struct ycc_ring *ring = container_of(work, struct ycc_ring, work);

	ycc_dequeue(ring);
	if (ring->ydev->is_polling)
		schedule_work(work);
}

int ycc_enable_msix(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;

	/* Disable intx explicitly */
	return pci_alloc_irq_vectors(rcec_pdev, YCC_IRQS, YCC_IRQS, PCI_IRQ_MSIX);
}

void ycc_disable_msix(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;

	pci_free_irq_vectors(rcec_pdev);
}

static int ycc_setup_global_err_workqueue(struct ycc_dev *ydev)
{
	char name[32] = {0};

	sprintf(name, "ycc_dev_%d_g_errd", ydev->id);
	INIT_WORK(&ydev->work, ycc_process_global_err);

	/* Allocated, but not used temporarily */
	ydev->dev_err_q = alloc_workqueue(name, WQ_UNBOUND, 0);
	if (!ydev->dev_err_q) {
		pr_err("Failed to alloc workqueue for ycc:%d\n", ydev->id);
		return -ENOMEM;
	}

	return 0;
}

static void ycc_cleanup_global_err_workqueue(struct ycc_dev *ydev)
{
	if (ydev->dev_err_q)
		destroy_workqueue(ydev->dev_err_q);
}

int ycc_alloc_irqs(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	int num = ydev->is_vf ? 1 : YCC_RINGPAIR_NUM;
	int cpu, cpus = num_online_cpus();
	int i, j;
	int ret;

	/* The 0-47 are rings irqs, 48 is dev error irq */
	sprintf(ydev->err_irq_name, "ycc_dev_%d_global_err", ydev->id);
	ret = request_irq(pci_irq_vector(rcec_pdev, num),
			  ycc_g_err_isr, 0, ydev->err_irq_name, ydev);
	if (ret) {
		pr_err("Failed to alloc global irq interrupt for dev:%d\n", ydev->id);
		goto out;
	}

	if (ydev->is_polling)
		goto out;

	for (i = 0; i < num; i++) {
		if (ydev->rings[i].type != KERN_RING)
			continue;

		ydev->msi_name[i] = kzalloc(16, GFP_KERNEL);
		if (!ydev->msi_name[i])
			goto free_irq;
		snprintf(ydev->msi_name[i], 16, "ycc_ring_%d", i);
		ret = request_irq(pci_irq_vector(rcec_pdev, i), ycc_resp_isr,
				  0, ydev->msi_name[i], &ydev->rings[i]);
		if (ret) {
			kfree(ydev->msi_name[i]);
			goto free_irq;
		}
		if (!ydev->is_vf)
			cpu = (i % YCC_RINGPAIR_NUM) % cpus;
		else
			cpu = smp_processor_id() % cpus;

		ret = irq_set_affinity_hint(pci_irq_vector(rcec_pdev, i),
					    get_cpu_mask(cpu));
		if (ret) {
			free_irq(pci_irq_vector(rcec_pdev, i), &ydev->rings[i]);
			kfree(ydev->msi_name[i]);
			goto free_irq;
		}
	}

	return 0;

free_irq:
	for (j = 0; j < i; j++) {
		if (ydev->rings[i].type != KERN_RING)
			continue;

		free_irq(pci_irq_vector(rcec_pdev, j), &ydev->rings[j]);
		kfree(ydev->msi_name[j]);
	}
	free_irq(pci_irq_vector(rcec_pdev, num), ydev);
out:
	return ret;
}

void ycc_free_irqs(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	int num = ydev->is_vf ? 1 : YCC_RINGPAIR_NUM;
	int i;

	/* Free device err irq */
	free_irq(pci_irq_vector(rcec_pdev, num), ydev);

	if (ydev->is_polling)
		return;

	for (i = 0; i < num; i++) {
		if (ydev->rings[i].type != KERN_RING)
			continue;

		irq_set_affinity_hint(pci_irq_vector(rcec_pdev, i), NULL);
		free_irq(pci_irq_vector(rcec_pdev, i), &ydev->rings[i]);
		kfree(ydev->msi_name[i]);
	}
}

int ycc_init_global_err(struct ycc_dev *ydev)
{
	return ycc_setup_global_err_workqueue(ydev);
}

void ycc_deinit_global_err(struct ycc_dev *ydev)
{
	ycc_cleanup_global_err_workqueue(ydev);
}
