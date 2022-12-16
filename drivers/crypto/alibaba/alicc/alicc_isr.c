// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/interrupt.h>

#include "alicc_isr.h"
#include "alicc_dev.h"
#include "alicc_ring.h"

extern void alicc_clear_cmd_ring(struct alicc_ring *ring);
extern void alicc_clear_resp_ring(struct alicc_ring *ring);

static irqreturn_t alicc_resp_isr(int irq, void *data)
{
	struct alicc_ring *ring = (struct alicc_ring *)data;

	schedule_work(&ring->work);

	return IRQ_HANDLED;
}

static int alicc_send_uevent(struct alicc_dev *ydev, const char *event)
{
	char *envp[3];
	char *dev_id;
	int ret;

	dev_id = kasprintf(GFP_ATOMIC, "ALICC_DEVID=%d", ydev->id);
	if (!dev_id)
		return -ENOMEM;

	envp[0] = (char *)event;
	envp[1] = dev_id;
	envp[2] = NULL;

	ret = kobject_uevent_env(&ydev->pdev->dev.kobj, KOBJ_CHANGE, envp);
	if (ret)
		pr_err("Failed to send uevent for alicc:%d\n", ydev->id);

	kfree(dev_id);
	return ret;
}

static void alicc_fatal_error(struct alicc_dev *ydev)
{
	struct alicc_ring *ring;
	int i;

	for (i = 0; i < ALICC_RINGPAIR_NUM; i++) {
		ring = ydev->rings + i;

		if (ring->type != KERN_RING)
			continue;

		spin_lock_bh(&ring->lock);
		alicc_clear_cmd_ring(ring);
		spin_unlock_bh(&ring->lock);

		alicc_clear_resp_ring(ring);
	}

	/*
	 * After all rings had been cleared, we should notify
	 * user space that alicc has fatal error
	 */
	alicc_send_uevent(ydev, "ALICC_STATUS=fatal");
}

static void alicc_process_global_err(struct work_struct *work)
{
	struct alicc_dev *ydev = container_of(work, struct alicc_dev, work);
	struct alicc_bar *cfg_bar = &ydev->alicc_bars[ALICC_SEC_CFG_BAR];
	struct alicc_ring *ring;
	u32 hclk_err, xclk_err;
	u32 xclk_ecc_uncor_err_0, xclk_ecc_uncor_err_1;
	u32 hclk_ecc_uncor_err;
	int i;

	if (pci_wait_for_pending_transaction(ydev->pdev))
		pr_warn("ALICC: Failed to pending transaction\n");

	/* Notify user space ALICC is in error handling */
	alicc_send_uevent(ydev, "ALICC_STATUS=stopped");

	hclk_err = ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_HCLK_INT_STATUS);
	xclk_err = ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_XCLK_INT_STATUS);
	xclk_ecc_uncor_err_0 = ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_XCLK_MEM_ECC_UNCOR_0);
	xclk_ecc_uncor_err_1 = ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_XCLK_MEM_ECC_UNCOR_1);
	hclk_ecc_uncor_err = ALICC_CSR_RD(cfg_bar->vaddr, REG_ALICC_HCLK_MEM_ECC_UNCOR);

	if ((hclk_err & ~(ALICC_HCLK_TRNG_ERR)) || xclk_err || hclk_ecc_uncor_err) {
		pr_err("ALICC: Got uncorrected error, must be reset\n");
		/*
		 * Fatal error, as ALICC cannot be reset in REE, clear ring data.
		 */
		return alicc_fatal_error(ydev);
	}

	if (xclk_ecc_uncor_err_0 || xclk_ecc_uncor_err_1) {
		pr_err("ALICC: Got algorithm ECC error: %x ,%x\n",
		       xclk_ecc_uncor_err_0, xclk_ecc_uncor_err_1);
		return alicc_fatal_error(ydev);
	}

	/* This has to be queue error. Handling command rings. */
	for (i = 0; i < ALICC_RINGPAIR_NUM; i++) {
		ring = ydev->rings + i;

		if (ring->type != KERN_RING)
			continue;

		ring->status = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_STATUS);
		if (ring->status) {
			pr_err("ALICC: Dev: %d, Ring: %d got ring err: %x\n",
			       ydev->id, ring->ring_id, ring->status);
			spin_lock_bh(&ring->lock);
			alicc_clear_cmd_ring(ring);
			spin_unlock_bh(&ring->lock);
		}
	}

	/*
	 * Give HW a chance to process all pending_cmds
	 * through recovering transactions.
	 */
	pci_set_master(ydev->pdev);

	/* Handling response rings. */
	for (i = 0; i < ALICC_RINGPAIR_NUM; i++) {
		ring = ydev->rings + i;

		if (ring->type != KERN_RING || !ring->status)
			continue;

		alicc_clear_resp_ring(ring);
	}

	alicc_g_err_unmask(cfg_bar->vaddr);
	clear_bit(YDEV_STATUS_ERR, &ydev->status);
	set_bit(YDEV_STATUS_READY, &ydev->status);
	alicc_send_uevent(ydev, "ALICC_STATUS=ready");
}

static irqreturn_t alicc_g_err_isr(int irq, void *data)
{
	struct alicc_dev *ydev = (struct alicc_dev *)data;
	struct alicc_bar *cfg_bar;

	if (test_and_set_bit(YDEV_STATUS_ERR, &ydev->status))
		return IRQ_HANDLED;

	/* Mask global errors until it has been processed */
	cfg_bar = &ydev->alicc_bars[ALICC_SEC_CFG_BAR];
	alicc_g_err_mask(cfg_bar->vaddr);

	clear_bit(YDEV_STATUS_READY, &ydev->status);

	/* Disable ALICC mastering, no new transactions */
	pci_clear_master(ydev->pdev);

	schedule_work(&ydev->work);
	return IRQ_HANDLED;
}

void alicc_resp_work_process(struct work_struct *work)
{
	struct alicc_ring *ring = container_of(work, struct alicc_ring, work);

	alicc_dequeue(ring);
	if (ring->ydev->is_polling)
		schedule_work(work);
}

int alicc_enable_msix(struct alicc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;

	/* Disable intx explicitly */
	return pci_alloc_irq_vectors(rcec_pdev, ALICC_IRQS, ALICC_IRQS, PCI_IRQ_MSIX);
}

void alicc_disable_msix(struct alicc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;

	pci_free_irq_vectors(rcec_pdev);
}

static int alicc_setup_global_err_workqueue(struct alicc_dev *ydev)
{
	char name[32] = {0};

	sprintf(name, "alicc_dev_%d_g_errd", ydev->id);
	INIT_WORK(&ydev->work, alicc_process_global_err);

	/* Allocated, but not used temporarily */
	ydev->dev_err_q = alloc_workqueue(name, WQ_UNBOUND, 0);
	if (!ydev->dev_err_q) {
		pr_err("Failed to alloc workqueue for alicc:%d\n", ydev->id);
		return -ENOMEM;
	}

	return 0;
}

static void alicc_cleanup_global_err_workqueue(struct alicc_dev *ydev)
{
	if (ydev->dev_err_q)
		destroy_workqueue(ydev->dev_err_q);
}

int alicc_alloc_irqs(struct alicc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	int num = ydev->is_vf ? 1 : ALICC_RINGPAIR_NUM;
	int cpu, cpus = num_online_cpus();
	int i, j;
	int ret;

	/* The 0-47 are rings irqs, 48 is dev error irq */
	sprintf(ydev->err_irq_name, "alicc_dev_%d_global_err", ydev->id);
	ret = request_irq(pci_irq_vector(rcec_pdev, num),
			  alicc_g_err_isr, 0, ydev->err_irq_name, ydev);
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
		snprintf(ydev->msi_name[i], 16, "alicc_ring_%d", i);
		ret = request_irq(pci_irq_vector(rcec_pdev, i), alicc_resp_isr,
				  0, ydev->msi_name[i], &ydev->rings[i]);
		if (ret) {
			kfree(ydev->msi_name[i]);
			goto free_irq;
		}
		if (!ydev->is_vf)
			cpu = (i % ALICC_RINGPAIR_NUM) % cpus;
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

void alicc_free_irqs(struct alicc_dev *ydev)
{
	struct pci_dev *rcec_pdev = ydev->assoc_dev->pdev;
	int num = ydev->is_vf ? 1 : ALICC_RINGPAIR_NUM;
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

int alicc_init_global_err(struct alicc_dev *ydev)
{
	return alicc_setup_global_err_workqueue(ydev);
}

void alicc_deinit_global_err(struct alicc_dev *ydev)
{
	alicc_cleanup_global_err_workqueue(ydev);
}
