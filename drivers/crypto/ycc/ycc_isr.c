// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/interrupt.h>

#include "ycc_isr.h"
#include "ycc_dev.h"
#include "ycc_ring.h"

#define MAX_ERROR_RETRY		50000  /* every 100us, 5s in total */

static irqreturn_t ycc_resp_isr(int irq, void *data)
{
	struct ycc_ring *ring = (struct ycc_ring *)data;

	schedule_work(&ring->work);

	return IRQ_HANDLED;
}

static inline void ycc_clear_bme_and_wait_pending(struct pci_dev *pdev)
{
	pci_clear_master(pdev);

	if (pci_wait_for_pending_transaction(pdev))
		pr_warn("Failed to pending transaction\n");
}

static inline void ycc_set_bme(struct pci_dev *pdev)
{
	pci_set_master(pdev);
}

static void ycc_fatal_error(struct ycc_dev *ydev)
{
	struct ycc_ring *ring;
	u32 pending_cmd;
	int retry = MAX_ERROR_RETRY;
	int i;

	for (i = 0; i < YCC_RINGPAIR_NUM; i++) {
		/*
		 * First we make sure all ycc rings's prefetched cmds
		 * have been processed.
		 * If timeout, regard it as processed
		 */
		ring = &ydev->rings[i];
		if (ring->type != KERN_RING)
			continue;

		pending_cmd = YCC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);
		while (pending_cmd && retry--)
			udelay(100);

		ycc_clear_ring(ring, pending_cmd);
	}
}

static void ycc_process_global_err(struct work_struct *work)
{
	struct ycc_dev *ydev = container_of(work, struct ycc_dev, work);
	struct ycc_bar *cfg_bar = &ydev->ycc_bars[YCC_SEC_CFG_BAR];
	struct ycc_ring *ring;
	u32 hclk_err, xclk_err;
	u32 xclk_ecc_uncor_err_0, xclk_ecc_uncor_err_1;
	u32 hclk_ecc_uncor_err;
	u64 ycc_ring_status;
	u32 pending_cmd;
	int retry = MAX_ERROR_RETRY;
	int i;

	/* First disable ycc mastering, no new transactions */
	ycc_clear_bme_and_wait_pending(ydev->pdev);

	hclk_err = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_HCLK_INT_STATUS);
	xclk_err = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_XCLK_INT_STATUS);
	xclk_ecc_uncor_err_0 = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_XCLK_MEM_ECC_UNCOR_0);
	xclk_ecc_uncor_err_1 = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_XCLK_MEM_ECC_UNCOR_1);
	hclk_ecc_uncor_err = YCC_CSR_RD(cfg_bar->vaddr, REG_YCC_HCLK_MEM_ECC_UNCOR);

	if ((hclk_err & ~(YCC_HCLK_TRNG_ERR)) || xclk_err || hclk_ecc_uncor_err) {
		pr_debug("YCC: Got uncorrected error, must be reset\n");
		/*
		 * Fatal error, as ycc cannot be reset in REE,
		 * clear ring data.
		 */
		return ycc_fatal_error(ydev);
	}

	if (xclk_ecc_uncor_err_0 || xclk_ecc_uncor_err_1) {
		pr_debug("YCC: Got algorithm ECC error: %x ,%x\n",
		       xclk_ecc_uncor_err_0, xclk_ecc_uncor_err_1);
		return ycc_fatal_error(ydev);
	}

	/*
	 * This has to be queue error. As response can respond
	 * any way, just log the error and ignore it
	 */
	for (i = 0; i < YCC_RINGPAIR_NUM; i++) {
		ring = &ydev->rings[i];
		pending_cmd = YCC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);
		while (pending_cmd && retry--)
			udelay(100);

		/* Regard as fatal error */
		if (!retry)
			return ycc_fatal_error(ydev);

		ycc_ring_status = YCC_CSR_RD(ring->csr_vaddr, REG_RING_STATUS);
		if (ycc_ring_status)
			pr_debug("YCC: Dev:%d, Ring:%d got ring err:%llx\n",
				 ydev->id, ring->ring_id, ycc_ring_status);
	}

	ycc_set_bme(ydev->pdev);
	ycc_g_err_unmask(cfg_bar->vaddr);
	clear_bit(YDEV_STATUS_ERR, &ydev->status);
	set_bit(YDEV_STATUS_READY, &ydev->status);
}

static irqreturn_t ycc_g_err_isr(int irq, void *data)
{
	struct ycc_dev *ydev = (struct ycc_dev *)data;
	struct ycc_bar *cfg_bar;

	/* Mask global errors until it has been processed */
	cfg_bar = &ydev->ycc_bars[YCC_SEC_CFG_BAR];
	ycc_g_err_mask(cfg_bar->vaddr);

	if (test_and_set_bit(YDEV_STATUS_ERR, &ydev->status)) {
		ycc_g_err_unmask(cfg_bar->vaddr);
		return IRQ_HANDLED;
	}
	clear_bit(YDEV_STATUS_READY, &ydev->status);

	schedule_work(&ydev->work);
	return IRQ_HANDLED;
}

void ycc_resp_work_process(struct work_struct *work)
{
	struct ycc_ring *ring = container_of(work, struct ycc_ring, work);

	ycc_dequeue(ring);
	if (ring->ydev->is_polling) {
		udelay(100);
		schedule_work(work);
	}
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
