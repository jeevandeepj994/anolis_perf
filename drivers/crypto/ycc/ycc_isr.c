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

/*
 * TODO: will implement when ycc ring actually work.
 */
static void ycc_process_global_err(struct work_struct *work)
{
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

/*
 * TODO: will implement when ycc ring actually work.
 */
void ycc_resp_work_process(struct work_struct *work)
{
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

/*
 * TODO: Just request irq for global err. Irq for each ring
 * will be requested when ring actually work.
 */
int ycc_alloc_irqs(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	int num = ydev->is_vf ? 1 : YCC_RINGPAIR_NUM;
	int ret;

	sprintf(ydev->err_irq_name, "ycc_dev_%d_global_err", ydev->id);
	ret = request_irq(pci_irq_vector(rcec_pdev, num),
			  ycc_g_err_isr, 0, ydev->err_irq_name, ydev);
	if (ret)
		pr_err("Failed to alloc global irq interrupt for dev:%d\n", ydev->id);

	return ret;
}

/*
 * TODO: Same as the allocate action.
 */
void ycc_free_irqs(struct ycc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	int num = ydev->is_vf ? 1 : YCC_RINGPAIR_NUM;

	free_irq(pci_irq_vector(rcec_pdev, num), ydev);
}

int ycc_init_global_err(struct ycc_dev *ydev)
{
	return ycc_setup_global_err_workqueue(ydev);
}

void ycc_deinit_global_err(struct ycc_dev *ydev)
{
	ycc_cleanup_global_err_workqueue(ydev);
}
