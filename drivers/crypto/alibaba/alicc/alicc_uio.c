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
#include <linux/hashtable.h>
#include <linux/iommu.h>
#include <linux/miscdevice.h>
#include <linux/version.h>

#include "alicc_ring.h"
#include "alicc_dev.h"
#include "alicc_uio.h"

#define ALICC_UIO_REMAP_SIZE	0x1000

/*
 * 1. Check if there're pending requests in ring
 * 2. If it still has pending requests, wait for completion
 * 3. If there're any requests that cannot complete, mark this ring as invalid
 * 4. When pending requests complete, update cmd wr ptr and resp rd ptr.
 */
static inline void alicc_uio_ring_cleanup(struct alicc_ring *ring)
{
	u32 pending_cmd;
	int retry = 5000;

	pending_cmd = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);
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

	ring->cmd_rd_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR);
	ring->cmd_wr_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_WR_PTR);
	ring->resp_rd_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_RD_PTR);
	ring->resp_wr_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);

	if (ring->resp_rd_ptr != ring->resp_wr_ptr)
		ALICC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_RD_PTR, ring->resp_wr_ptr);
}

static int alicc_uio_open(struct uio_info *info, struct inode *inode)
{
	struct alicc_ring *ring = info->priv;
	struct alicc_dev *ydev = ring->ydev;

	/*
	 * Uio ring only can be opened once to ensure atomicity
	 * in user space
	 */
	if (atomic_read(&ring->ref_cnt)) {
		pr_warn("Ring: %d has been occupied\n", ring->ring_id);
		return -EBUSY;
	}

	alicc_ring_get(ring);
	alicc_dev_get(ydev);

	return 0;
}

static int alicc_uio_release(struct uio_info *info, struct inode *inode)
{
	struct alicc_ring *ring = info->priv;
	struct alicc_dev *ydev = ring->ydev;

	/*
	 * Uio ring is monopolized by one user process, something is
	 * wrong if the refcnt is not 1.
	 */
	if (atomic_read(&ring->ref_cnt) != 1) {
		pr_err("Ring: %d has something wrong, ref_cnt=%d\n",
				ring->ring_id, atomic_read(&ring->ref_cnt));
		return -EFAULT;
	}

	alicc_uio_ring_cleanup(ring);

	alicc_ring_put(ring);
	alicc_dev_put(ydev);

	return 0;
}

static int alicc_uio_mmap(struct uio_info *info, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_IO;

	return remap_pfn_range(vma, vma->vm_start, info->mem[0].addr >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start,
			       pgprot_noncached(vma->vm_page_prot));
}

static int alicc_uio_remap(struct alicc_ring *ring, struct uio_info *info)
{
	u8 name[32];

	snprintf(name, sizeof(name), "ALICC_DEV_%02d_RING_%02d_MAP", ring->ydev->id, ring->ring_id);
	info->mem[0].name = kstrndup(name, sizeof(name), GFP_KERNEL);
	if (!info->mem[0].name)
		return -ENOMEM;

	info->mem[0].addr = ring->csr_paddr;
	info->mem[0].internal_addr = ring->csr_vaddr;
	info->mem[0].size = ALICC_UIO_REMAP_SIZE;
	info->mem[0].memtype = UIO_MEM_PHYS;

	return 0;
}

int alicc_uio_register(struct alicc_ring *ring)
{
	struct device *dev = &ring->ydev->pdev->dev;
	struct uio_info *info;
	u8 name[32];
	int ret = -ENOMEM;

	info = kzalloc(sizeof(struct uio_info), GFP_KERNEL);
	if (!info)
		goto out;

	ret = alicc_uio_remap(ring, info);
	if (ret) {
		pr_err("Failed to kstrndup name for uio_mem\n");
		goto free_info;
	}

	snprintf(name, sizeof(name), "ALICC_DEV_%02d_RING_%02d", ring->ydev->id, ring->ring_id);
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
	info->open = alicc_uio_open;
	info->release = alicc_uio_release;
	info->mmap = alicc_uio_mmap;
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

void alicc_uio_unregister(struct alicc_ring *ring)
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

static DEFINE_MUTEX(alicc_mem_lock);
/*
 * Each fd corresponding 1 info list. If there're multiple
 * fd opened, link itself
 */
struct alicc_udma_info_list {
	int pid; /* process id */
	DECLARE_HASHTABLE(udma_slot, PAGE_SHIFT);
	struct list_head fd_list;
	struct alicc_udma_large_info large_mem;
};

struct alicc_udma_kern_info {
	void *virt_addr; /* mem block start address */
	dma_addr_t dma_addr;
	size_t size;
	struct hlist_node udma_hlist;
};

#define ALICC_UIO_DEV_NR		(2)

static struct iommu_domain *alicc_domains[ALICC_UIO_DEV_NR];
static bool alicc_need_map = true;

/*
 * TODO: We don't allocate actual iommu_domain now.
 */
static inline int alicc_alloc_iommu_domain(void)
{
	if (!iommu_present(&pci_bus_type) || iommu_default_passthrough())
		alicc_need_map = false;

	return 0;
}

/*
 * TODO: We don't free actual iommu_domain now.
 */
static void alicc_free_iommu_domain(void)
{
}

int alicc_bind_iommu_domain(struct pci_dev *pdev, int id)
{
	struct iommu_domain *domain;

	if (!alicc_need_map)
		return 0;

	if (id >= ALICC_UIO_DEV_NR)
		return -EINVAL;

	domain = iommu_get_domain_for_dev(&pdev->dev);
	alicc_domains[id] = domain;

	return 0;
}

void alicc_unbind_iommu_domain(struct pci_dev *pdev, int id)
{
	if (!alicc_need_map)
		return;

	if (id >= ALICC_UIO_DEV_NR)
		return;

	alicc_domains[id] = NULL;
}


#define ALICC_SZ_2M	(2ULL << 20)
#define ALICC_2M_MASK	(ALICC_SZ_2M - 1)
/*
 * Direct mapping, iova equals phys.
 * So we don't use dma api, just phys_to_virt/virt_to_phys
 */
static int alicc_mem_map(void *vaddr, size_t size)
{
	phys_addr_t paddr;
	dma_addr_t iova;
	int ret = 0;

	if (!alicc_need_map)
		return 0;

	paddr = virt_to_phys(vaddr);
	iova = paddr;

	if (alicc_domains[0]) {
		ret = iommu_map(alicc_domains[0], iova, paddr, size, IOMMU_READ|IOMMU_WRITE);
		if (ret)
			goto out;
	}

	if (alicc_domains[1] && alicc_domains[1] != alicc_domains[0]) {
		ret = iommu_map(alicc_domains[1], iova, paddr, size, IOMMU_READ|IOMMU_WRITE);
		if (ret) {
			if (alicc_domains[0])
				iommu_unmap(alicc_domains[0], iova, size);

			goto out;
		}
	}

	if ((u64)iova & ALICC_2M_MASK)
		pr_debug("udma: iova=0x%llx, is not 2M aligned? %llx\n",
			(u64)iova, (u64)iova & ALICC_2M_MASK);
out:
	return ret;
}

static void alicc_mem_unmap(void *vaddr, size_t size)
{
	dma_addr_t iova;

	if (!alicc_need_map)
		return;

	/* As we are direct mapping */
	iova = (dma_addr_t)virt_to_phys(vaddr);
	if (alicc_domains[0])
		iommu_unmap(alicc_domains[0], iova, size);
	if (alicc_domains[1] && alicc_domains[1] != alicc_domains[0])
		iommu_unmap(alicc_domains[1], iova, size);
}

static inline int alicc_get_hash_key(dma_addr_t phys_addr)
{
	return (phys_addr >> 20) & ~PAGE_MASK;
}

static inline void alicc_udma_add_hash(struct alicc_udma_info_list *info_list,
				     struct alicc_udma_kern_info *kern_info)
{
	int key = alicc_get_hash_key(kern_info->dma_addr);

	hash_add_rcu(info_list->udma_slot, &kern_info->udma_hlist, key);
}

static inline void alicc_udma_del_hash(struct alicc_udma_kern_info *kern_info)
{
	hash_del_rcu(&kern_info->udma_hlist);
}

static inline
struct alicc_udma_kern_info *alicc_udma_find_kern(struct alicc_udma_info_list *info_list,
						  dma_addr_t dma_addr)
{
	int key = alicc_get_hash_key(dma_addr);
	struct alicc_udma_kern_info *kern_info = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(info_list->udma_slot, kern_info, udma_hlist, key) {
		if (kern_info->dma_addr == dma_addr)
			break;

		kern_info = NULL;
	}
	rcu_read_unlock();

	return kern_info;
}

#define ALICC_MEGA_SHIFT 20
#define ALICC_UDMA_SIZE (2 << ALICC_MEGA_SHIFT)
#define ALICC_UDMA_SIZE_MASK (~(ALICC_UDMA_SIZE - 1))
#define ALICC_UDMA_ALIGN(size) ((size + ALICC_UDMA_SIZE - 1) & (ALICC_UDMA_SIZE_MASK))

static struct alicc_udma_info *alicc_udma_mem_alloc(struct alicc_udma_info_list *info_list,
						size_t size,
						int node)
{
	struct alicc_udma_info *mem_info;
	struct alicc_udma_kern_info *kern_info;

	if (node != NUMA_NO_NODE && (node < 0 || node > MAX_NUMNODES))
		node = 0;

	kern_info = kzalloc(sizeof(struct alicc_udma_kern_info), GFP_KERNEL);
	if (!kern_info)
		return NULL;

	/* Always allocate 2M */
	size = ALICC_UDMA_ALIGN(size);

	mem_info = kzalloc_node(size, GFP_KERNEL, cpu_to_node(smp_processor_id()));
	if (!mem_info) {
		kfree(kern_info);
		return NULL;
	}

	if (((u64)mem_info & ALICC_2M_MASK))
		pr_debug("alicc mem info: va:0x%llx  mask:0x%llx result:%llu\n",
			(u64)mem_info, ALICC_2M_MASK, ((u64)mem_info & ALICC_2M_MASK));

	if (alicc_mem_map(mem_info, size)) {
		kfree(mem_info);
		kfree(kern_info);
		return NULL;
	}

	/* TODO: reuse structure for mem_info and kern_info */
	mem_info->size = size;
	mem_info->virt_addr = mem_info;
	mem_info->dma_addr = virt_to_phys(mem_info->virt_addr);

	kern_info->virt_addr = mem_info->virt_addr;
	kern_info->dma_addr = mem_info->dma_addr;
	kern_info->size = mem_info->size;

	alicc_udma_add_hash(info_list, kern_info);
	pr_debug("udma Allocated:%llx, %llx\n", (u64)kern_info->virt_addr, kern_info->dma_addr);

	return mem_info;
}

static void alicc_udma_mem_large_alloc(struct alicc_udma_large_info *large_info)
{
	void *mem = NULL;

	if (!large_info)
		return;

	mem = kzalloc_node(LARGE_ALLOC_SIZE, GFP_KERNEL, cpu_to_node(smp_processor_id()));
	if (!mem)
		return;

	if (alicc_mem_map(mem, LARGE_ALLOC_SIZE)) {
		kfree(mem);
		return;
	}

	large_info->virt_addr = mem;
	large_info->dma_addr = virt_to_phys(mem);
}

static void alicc_udma_mem_free(struct alicc_udma_info_list *info_list, dma_addr_t dma_addr)
{
	struct alicc_udma_kern_info *kern_info;

	kern_info = alicc_udma_find_kern(info_list, dma_addr);
	if (!kern_info)
		return;
	alicc_udma_del_hash(kern_info);
	alicc_mem_unmap(kern_info->virt_addr, kern_info->size);
	kfree(kern_info->virt_addr);
	kfree(kern_info);
}

static void alicc_udma_mem_large_free(struct alicc_udma_large_info *large_info)
{
	if (!large_info)
		return;

	alicc_mem_unmap(large_info->virt_addr, LARGE_ALLOC_SIZE);
	kfree(large_info->virt_addr);
	memset(large_info, 0, sizeof(struct alicc_udma_large_info));
}

static int alicc_udma_open(struct inode *inode, struct file *filp)
{
	struct alicc_udma_info_list *info_list;

	info_list = kzalloc(sizeof(struct alicc_udma_info_list), GFP_KERNEL);
	if (!info_list)
		return -ENOMEM;

	info_list->pid = current->tgid;
	hash_init(info_list->udma_slot);
	filp->private_data = (void *)info_list;

	return 0;
}

static int alicc_udma_release(struct inode *inode, struct file *filep)
{
	struct alicc_udma_info_list *info_list = (struct alicc_udma_info_list *)filep->private_data;
	struct alicc_udma_kern_info *kern_info;
	int bkt;

	hash_for_each(info_list->udma_slot, bkt, kern_info, udma_hlist) {
		pr_debug("releasing: %llx, %llx\n", (u64)kern_info->virt_addr, kern_info->dma_addr);
		alicc_udma_del_hash(kern_info);
		alicc_mem_unmap(kern_info->virt_addr, kern_info->size);
		kfree(kern_info->virt_addr);
		kfree(kern_info);
	}

	if ((info_list->large_mem).virt_addr)
		alicc_udma_mem_large_free(&info_list->large_mem);

	kfree(info_list);
	filep->private_data = NULL;
	return 0;
}

static long alicc_udma_ioctl(struct file *filep, uint cmd, ulong args)
{
	struct alicc_udma_info user_info, *mem_info;
	struct alicc_udma_info_list *info_list = (struct alicc_udma_info_list *)filep->private_data;
	int ret = 0;

	mutex_lock(&alicc_mem_lock);
	switch (cmd) {
	case ALICC_IOC_MEM_ALLOC:
		ret = copy_from_user(&user_info, (struct alicc_udma_info *)args, sizeof(user_info));
		if (ret) {
			ret = -EIO;
			goto ioctl_unlock;
		}
		mem_info = alicc_udma_mem_alloc(info_list, user_info.size, user_info.node);
		if (!mem_info) {
			ret = -ENOMEM;
			goto ioctl_unlock;
		}
		ret = copy_to_user((struct alicc_udma_info *)args, mem_info, sizeof(*mem_info));
		if (ret) {
			alicc_udma_mem_free(info_list, mem_info->dma_addr);
			ret = -EIO;
			goto ioctl_unlock;
		}
		break;
	case ALICC_IOC_MEM_FREE:
		ret = copy_from_user(&user_info, (struct alicc_udma_info *)args, sizeof(user_info));
		if (ret) {
			ret = -EIO;
			goto ioctl_unlock;
		}
		alicc_udma_mem_free(info_list, user_info.dma_addr);
		break;
	case ALICC_IOC_LARGE_MEM_ALLOC:
		if ((info_list->large_mem).virt_addr)
			goto ioctl_unlock;

		alicc_udma_mem_large_alloc(&(info_list->large_mem));
		if (!(info_list->large_mem).virt_addr) {
			ret = -ENOMEM;
			goto ioctl_unlock;
		}

		ret = copy_to_user((struct alicc_udma_large_info *)args, &(info_list->large_mem),
				   sizeof(struct alicc_udma_large_info));
		if (ret) {
			alicc_udma_mem_large_free(&(info_list->large_mem));
			ret = -EIO;
			goto ioctl_unlock;
		}
		break;
	case ALICC_IOC_LARGE_MEM_FREE:
		alicc_udma_mem_large_free(&(info_list->large_mem));
		break;
	default:
		ret = -EINVAL;
	}
ioctl_unlock:
	mutex_unlock(&alicc_mem_lock);
	return ret;
}

static int alicc_udma_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct alicc_udma_info_list *info_list = (struct alicc_udma_info_list *)filep->private_data;
	unsigned long vma_size = vma->vm_end - vma->vm_start;
	u64 dma_addr = vma->vm_pgoff << PAGE_SHIFT;
	struct alicc_udma_kern_info *kern_info;
	int ret;

	pr_debug("udma: get kern info for phys addr:%llx\n", (u64)dma_addr);

	if (dma_addr == (info_list->large_mem).dma_addr)
		goto skip_hash;

	kern_info = alicc_udma_find_kern(info_list, dma_addr);
	if (!kern_info)
		return -ENOMEM;

	if (kern_info->size < vma_size)
		return -ENOMEM;

skip_hash:
	ret = remap_pfn_range(vma,
			      vma->vm_start,
			      vma->vm_pgoff,
			      vma_size,
			      pgprot_writecombine(vma->vm_page_prot));

	return ret;
}

const struct file_operations alicc_udma_fops = {
	.open		= alicc_udma_open,
	.mmap		= alicc_udma_mmap,
	.release	= alicc_udma_release,
	.unlocked_ioctl	= alicc_udma_ioctl,
	.compat_ioctl	= alicc_udma_ioctl,
};

struct miscdevice alicc_udma_misc = {
	.minor		= 0,
	.name		= "alicc_udma",
	.fops		= &alicc_udma_fops,
};

int alicc_udma_init(void)
{
	int ret;

	ret = alicc_alloc_iommu_domain();
	if (ret)
		return ret;

	mutex_init(&alicc_mem_lock);

	ret = misc_register(&alicc_udma_misc);
	if (ret) {
		pr_err("Failed to register misc devices\n");
		alicc_free_iommu_domain();
	}

	return ret;
}

void alicc_udma_exit(void)
{
	alicc_free_iommu_domain();
	misc_deregister(&alicc_udma_misc);
}
