// SPDX-License-Identifier: GPL-2.0-only
/*
 * Share page table entries when possible to reduce the amount of extra
 * memory consumed by page tables
 *
 * Copyright (C) 2022 Oracle Corp. All rights reserved.
 * Authors:	Khalid Aziz <khalid.aziz@oracle.com>
 *		Matthew Wilcox <willy@infradead.org>
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/pgalloc.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/pgtable_share.h>
#include <linux/hugetlb.h>

static bool vma_is_suitable_pgtable_share(struct vm_area_struct *vma)
{
	if (!vma)
		return false;

	if (!vma->vm_file || !vma->vm_file->f_mapping)
		return false;

	/* hugetlb is not supported temporarily */
	if (is_vm_hugetlb_page(vma))
		return false;

	/* keep in PMD size alignment */
	if (((vma->vm_start | vma->vm_end) & (PMD_SIZE - 1)))
		return false;

	return true;
}

/*
 */
static pmd_t
*get_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d)) {
		p4d = p4d_alloc(mm, pgd, addr);
		if (!p4d)
			return NULL;
	}

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud)) {
		pud = pud_alloc(mm, p4d, addr);
		if (!pud)
			return NULL;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
		pmd = pmd_alloc(mm, pud, addr);
		if (!pmd)
			return NULL;
	}

	return pmd;
}

/*
 * Find the shared pmd entries in host mm struct and install them into
 * guest page tables.
 */
static int pgtable_share_copy_pmd(struct mm_struct *host_mm, struct mm_struct *guest_mm,
				  struct vm_area_struct *vma, unsigned long addr)
{
	pgd_t *guest_pgd;
	p4d_t *guest_p4d;
	pud_t *guest_pud;
	pmd_t *host_pmd;
	spinlock_t *host_ptl, *guest_ptl;

	guest_pgd = pgd_offset(guest_mm, addr);
	guest_p4d = p4d_offset(guest_pgd, addr);
	if (p4d_none(*guest_p4d)) {
		guest_p4d = p4d_alloc(guest_mm, guest_pgd, addr);
		if (!guest_p4d)
			return 1;
	}

	guest_pud = pud_offset(guest_p4d, addr);
	if (pud_none(*guest_pud)) {
		host_pmd = get_pmd(host_mm, addr);
		if (!host_pmd)
			return 1;

		get_page(virt_to_page(host_pmd));
		host_ptl = pmd_lockptr(host_mm, host_pmd);
		guest_ptl = pud_lockptr(guest_mm, guest_pud);
		spin_lock(host_ptl);
		spin_lock(guest_ptl);
		pud_populate(guest_mm, guest_pud,
			(pmd_t *)((unsigned long)host_pmd & PAGE_MASK));
		put_page(virt_to_page(host_pmd));
		spin_unlock(guest_ptl);
		spin_unlock(host_ptl);
	}

	return 0;
}

/*
 * Find the shared page tables in hosting mm struct and install those in
 * the guest mm struct
 */
vm_fault_t
find_shared_vma(struct vm_area_struct **vmap, unsigned long *addrp,
			unsigned int flags)
{
	struct pgtable_share_struct *info;
	struct mm_struct *host_mm;
	struct vm_area_struct *host_vma, *guest_vma = *vmap;
	unsigned long host_addr;
	pmd_t *guest_pmd, *host_pmd;

	if ((!guest_vma->vm_file) || (!guest_vma->vm_file->f_mapping))
		return 0;
	info = guest_vma->pgtable_share_data;
	if (!info) {
		pr_warn("VM_SHARED_PT vma with NULL ptshare_data");
		dump_stack_print_info(KERN_WARNING);
		return 0;
	}
	host_mm = info->mm;

	mmap_read_lock(host_mm);

	host_addr = *addrp - guest_vma->vm_start + host_mm->mmap_base;
	host_pmd = get_pmd(host_mm, host_addr);
	guest_pmd = get_pmd(guest_vma->vm_mm, *addrp);
	if (!pmd_same(*guest_pmd, *host_pmd)) {
		set_pmd(guest_pmd, *host_pmd);
		mmap_read_unlock(host_mm);
		return VM_FAULT_NOPAGE;
	}

	*addrp = host_addr;
	host_vma = find_vma(host_mm, host_addr);
	if (!host_vma)
		return VM_FAULT_SIGSEGV;

	/*
	 * Point vm_mm for the faulting vma to the mm struct holding shared
	 * page tables so the fault handling will happen in the right
	 * shared context
	 */
	guest_vma->vm_mm = host_mm;

	return 0;
}

/*
 * Create a new mm struct that will hold the shared PTEs. Pointer to
 * this new mm is stored in the data structure ptshare_data which also
 * includes a refcount for any current references to PTEs in this new
 * mm. This refcount is used to determine when the mm struct for shared
 * PTEs can be deleted.
 */
static int pgtable_share_new_mm(struct vm_area_struct *vma)
{
	struct mm_struct *new_mm;
	struct pgtable_share_struct *info = NULL;
	int retval = 0;
	unsigned long start = vma->vm_start;
	unsigned long len = vma->vm_end - vma->vm_start;

	new_mm = mm_alloc();
	if (!new_mm) {
		retval = -ENOMEM;
		goto err_free;
	}
	new_mm->mmap_base = start;
	new_mm->task_size = len;
	if (!new_mm->task_size)
		new_mm->task_size--;
	new_mm->owner = NULL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		retval = -ENOMEM;
		goto err_free;
	}
	info->mm = new_mm;
	info->start = start;
	info->size = len;
	refcount_set(&info->refcnt, 1);
	vma->pgtable_share_data = info;

	return retval;

err_free:
	if (new_mm)
		mmput(new_mm);
	kfree(info);
	return retval;
}

/*
 * insert vma into mm holding shared page tables
 */
int pgtable_share_insert_vma(struct mm_struct *host_mm, struct vm_area_struct *vma)
{
	struct vm_area_struct *new_vma;
	int err = 0;

	new_vma = vm_area_dup(vma);
	if (!new_vma)
		return -ENOMEM;

	new_vma->vm_file = NULL;
	/*
	 * This new vma belongs to host mm, so clear the VM_SHARED_PT
	 * flag on this so we know this is the host vma when we clean
	 * up page tables. Do not use THP for page table shared regions
	 */
	new_vma->vm_flags &= ~(VM_SHARED | VM_SHARED_PT);
	new_vma->vm_flags |= VM_NOHUGEPAGE;
	new_vma->vm_mm = host_mm;

	err = insert_vm_struct(host_mm, new_vma);
	if (err)
		return -ENOMEM;

	/*
	 * Copy the PMD entries from host mm to guest so they use the
	 * same PTEs
	 */
	err = pgtable_share_copy_pmd(host_mm, vma->vm_mm, vma, vma->vm_start);

	return err;
}

/*
 * Free the mm struct and page table data, and the shadow vma
 * is also freed in mmput()->exit_mmap()->unmap_vmas().
 */
static inline void free_pgtable_share_mm(struct pgtable_share_struct *info)
{
	mmput(info->mm);
	kfree(info);
}

/* mm_lock (write lock) of vma->vm_mm must be hold in caller */
void pgtable_share_create(struct vm_area_struct *vma)
{
	struct pgtable_share_struct *info;
	int ret;

	if (!vma_is_suitable_pgtable_share(vma))
		return;

	info = vma->pgtable_share_data;
	VM_BUG_ON_VMA(info, vma);

	ret = pgtable_share_new_mm(vma);
	if (ret < 0)
		return;

	info = vma->pgtable_share_data;
	/* Duplicate and insert shadow vma into shadow mm */
	ret = pgtable_share_insert_vma(info->mm, vma);
	if (ret < 0) {
		free_pgtable_share_mm(info);
		vma->pgtable_share_data = NULL;
		return;
	}

	vma->vm_flags |= VM_SHARED_PT;
}

/*
 * This function is called when a reference to the shared PTEs in mm
 * struct is dropped. It updates refcount and checks to see if last
 * reference to the mm struct holding shared PTEs has been dropped. If
 * so, it cleans up the mm struct and associated data structures
 */
void pgtable_share_del_mm(struct vm_area_struct *vma)
{
	struct pgtable_share_struct *info;
	struct file *file = vma->vm_file;

	if (!file || (!file->f_mapping))
		return;
	info = vma->pgtable_share_data;
	WARN_ON(!info);
	if (!info)
		return;

	if (refcount_dec_and_test(&info->refcnt)) {
		free_pgtable_share_mm(info);
		vma->pgtable_share_data = NULL;
	}
}
