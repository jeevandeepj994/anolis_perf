// SPDX-License-Identifier: GPL-2.0
#include <linux/uio_driver.h>
#include <linux/sched.h>
#include <linux/kobject.h>
#include <linux/semaphore.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/uio.h>
#include <linux/delay.h>

#include "ycc_ring.h"
#include "ycc_dev.h"

#define YCC_UIO_REMAP_SIZE	0x1000

/*
 * 1. Check if there're pending requests in ring
 * 2. If it still has pending requests, wait for completion
 * 3. If there're any requests that cannot complete, mark this ring as invalid
 * 4. When pending requests complete, update cmd wr ptr and resp rd ptr.
 */
static inline void ycc_uio_ring_cleanup(struct ycc_ring *ring)
{
	u32 pending_cmd;
	int retry = 5000;

	pending_cmd = YCC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);
	while (pending_cmd && retry--) {
		udelay(100);
		cpu_relax();
	}

	/* Mark ring as invalid */
	if (pending_cmd) {
		pr_warn("Ring: %d probably hung\n", ring->ring_id);
		ring->type = INVAL_RING;
		uio_unregister_device(ring->uio_info);
	}

	ring->cmd_rd_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR);
	ring->cmd_wr_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_WR_PTR);
	ring->resp_rd_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_RD_PTR);
	ring->resp_wr_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);

	if (ring->resp_rd_ptr != ring->resp_wr_ptr)
		YCC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_RD_PTR, ring->resp_wr_ptr);
}

static int ycc_uio_open(struct uio_info *info, struct inode *inode)
{
	struct ycc_ring *ring = info->priv;
	struct ycc_dev *ydev = ring->ydev;

	/*
	 * Uio ring only can be opened once to ensure atomicity
	 * in user space
	 */
	if (atomic_read(&ring->ref_cnt)) {
		pr_warn("Ring: %d has been occupied\n", ring->ring_id);
		return -EBUSY;
	}

	ycc_ring_get(ring);
	ycc_dev_get(ydev);

	return 0;
}

static int ycc_uio_release(struct uio_info *info, struct inode *inode)
{
	struct ycc_ring *ring = info->priv;
	struct ycc_dev *ydev = ring->ydev;

	/*
	 * Uio ring is monopolized by one user process, something is
	 * wrong if the refcnt is not 1.
	 */
	if (atomic_read(&ring->ref_cnt) != 1) {
		pr_err("Ring: %d has something wrong, ref_cnt=%d\n",
				ring->ring_id, atomic_read(&ring->ref_cnt));
		return -EFAULT;
	}

	ycc_uio_ring_cleanup(ring);

	ycc_ring_put(ring);
	ycc_dev_put(ydev);

	return 0;
}

static int ycc_uio_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_IO;

	return remap_pfn_range(vma, vma->vm_start, info->mem[0].addr >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start,
			       pgprot_noncached(vma->vm_page_prot));
}

static int ycc_uio_remap(struct ycc_ring *ring, struct uio_info *info)
{
	u8 name[32];

	snprintf(name, sizeof(name), "YCC_DEV_%02d_RING_%02d_MAP", ring->ydev->id, ring->ring_id);
	info->mem[0].name = kstrndup(name, sizeof(name), GFP_KERNEL);
	if (!info->mem[0].name)
		return -ENOMEM;

	info->mem[0].addr = ring->csr_paddr;
	info->mem[0].internal_addr = ring->csr_vaddr;
	info->mem[0].size = YCC_UIO_REMAP_SIZE;
	info->mem[0].memtype = UIO_MEM_PHYS;

	return 0;
}

int ycc_uio_register(struct ycc_ring *ring)
{
	struct device *dev = &ring->ydev->pdev->dev;
	struct uio_info *info;
	u8 name[32];
	int ret = -ENOMEM;

	info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
	if (!info)
		goto out;

	ret = ycc_uio_remap(ring, info);
	if (ret) {
		pr_err("Failed to kstrndup name for uio_mem\n");
		goto free_info;
	}

	snprintf(name, sizeof(name), "YCC_DEV_%02d_RING_%02d", ring->ydev->id, ring->ring_id);
	info->name = kstrndup(name, sizeof(name), GFP_KERNEL);
	if (!info->name) {
		pr_err("Failed to kstrndup name for uio_info\n");
		goto uio_unremap;
	}

	info->version = kstrndup("0.0.1", sizeof("0.0.1"), GFP_KERNEL);
	if (!info->version) {
		pr_err("Failed to kstrndup version for uio_info\n");
		goto free_info_name;
	}

	info->priv = ring;
	info->open = ycc_uio_open;
	info->release = ycc_uio_release;
	info->mmap = ycc_uio_mmap;
	info->irq_flags |= IRQF_SHARED | IRQF_ONESHOT;

	ret = uio_register_device(dev, info);
	if (ret) {
		pr_err("Failed to register uio device\n");
		goto free_info_version;
	}

	ring->uio_info = info;
	ring->type = USER_RING;
	return 0;
free_info_version:
	kfree(info->version);
free_info_name:
	kfree(info->name);
uio_unremap:
	kfree(info->mem[0].name);
free_info:
	kfree(info);
out:
	return ret;
}

void ycc_uio_unregister(struct ycc_ring *ring)
{
	struct uio_info *info = ring->uio_info;

	/* As it has been unregistered in close */
	if (ring->type != INVAL_RING)
		uio_unregister_device(info);

	kfree(info->version);
	kfree(info->name);
	kfree(info->mem[0].name);
	kfree(info);
	ring->uio_info = NULL;
}
