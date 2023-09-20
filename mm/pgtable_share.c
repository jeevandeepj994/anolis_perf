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
#include <linux/mmdebug.h>
#include <asm/tlb.h>

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

inline struct pgtable_share_struct *vma_get_pgtable_share_data(struct vm_area_struct *vma)
{
	struct pgtable_share_struct *info;

	info = vma->pgtable_share_data;

	return info;
}

inline void vma_set_pgtable_share_data(struct vm_area_struct *vma,
				struct pgtable_share_struct *info)
{
	WRITE_ONCE(vma->pgtable_share_data, info);
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
	refcount_set(&info->refcnt, 1);
	vma_set_pgtable_share_data(vma, info);

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

	/*
	 * This new vma belongs to host mm, so clear the VM_SHARED_PT
	 * flag on this so we know this is the host vma when we clean
	 * up page tables. Do not use THP for page table shared regions
	 */
	new_vma->vm_flags &= ~VM_SHARED_PT;
	new_vma->vm_flags |= VM_NOHUGEPAGE;
	new_vma->vm_mm = host_mm;
	new_vma->vm_page_prot = vm_get_page_prot(new_vma->vm_flags);

	err = insert_vm_struct(host_mm, new_vma);
	if (err) {
		vm_area_free(new_vma);
		return -ENOMEM;
	}
	get_file(vma->vm_file);

	return err;
}

static pmd_t *pgtable_share_create_pmd(struct mm_struct *mm, unsigned long addr,
				       bool alloc_pte)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		goto out;

	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		goto out;

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		goto out;

	if (!alloc_pte)
		return pmd;

	if (!pmd_none(*pmd) && !pmd_bad(*pmd))
		return pmd;

	if (!pte_alloc(mm, pmd))
		return pmd;
out:
	return NULL;
}

/* mmlock held when exit */
vm_fault_t pgtable_share_page_fault(struct vm_fault *vmf, unsigned long addr)
{
	struct pgtable_share_struct *info;
	struct mm_struct *orig_mm, *shadow_mm;
	struct vm_area_struct *shadow_vma, *orig_vma = vmf->vma;
	unsigned long shadow_addr = addr;
	pmd_t *pmd, *shadow_pmd;
	spinlock_t *ptl;

	if ((!orig_vma->vm_file) || (!orig_vma->vm_file->f_mapping))
		return VM_FAULT_ERROR;

	info = vma_get_pgtable_share_data(orig_vma);
	if (!info) {
		pr_warn("VM_SHARED_PT vma with NULL pgtable_share_data");
		dump_stack_print_info(KERN_WARNING);
		return VM_FAULT_ERROR;
	}
	orig_mm = orig_vma->vm_mm;
	shadow_mm = info->mm;

	/*
	 * mm_lock of aboriginal mm has been hold in previous
	 * caller. Here calling trylock to avoid possible
	 * warning of recursive locking.
	 */
	if (!mmap_read_trylock(shadow_mm))
		mmap_read_lock(shadow_mm);

	pmd = pgtable_share_create_pmd(orig_mm, shadow_addr, false);
	if (!pmd)
		goto out;

	shadow_pmd = pgtable_share_create_pmd(shadow_mm, shadow_addr, true);
	if (!shadow_pmd)
		goto out;

	ptl = pmd_lock(orig_mm, pmd);
	if (!pmd_none(*pmd)) {
		if (!pmd_same(*pmd, *shadow_pmd)) {
			unsigned long pmd_aligned = (shadow_addr & PMD_MASK) >> PAGE_SHIFT;

			/*
			 * It's almost impossible to run here, but for
			 * security, print some warning messages and
			 * set original pmd.
			 */
			pr_warn("the original pmd has different value with shadow pmd");

			set_pmd_at(orig_mm, shadow_addr, pmd, *shadow_pmd);
			flush_tlb_range(orig_vma, pmd_aligned, pmd_aligned + PMD_SIZE);
			spin_unlock(ptl);
			return VM_FAULT_NOPAGE;
		}
	} else {
		pmd_populate(orig_mm, pmd, pmd_pgtable(*shadow_pmd));
		get_page(pmd_page(*shadow_pmd));
		add_mm_counter(orig_vma->vm_mm, MM_SHMEMPAGES, HPAGE_PMD_NR);
	}
	spin_unlock(ptl);

	shadow_vma = find_vma(shadow_mm, shadow_addr);
	if (!shadow_vma)
		return VM_FAULT_SIGSEGV;

	/*
	 * switch to shadow vma and shadow mm
	 */
	vmf->vma = shadow_vma;
	vmf->orig_vma = orig_vma;

	return 0;
out:
	return VM_FAULT_OOM;
}

/*
 * Free the mm struct created to hold shared PTEs and associated data
 * structures
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

	info = vma_get_pgtable_share_data(vma);
	VM_BUG_ON_VMA(info, vma);

	ret = pgtable_share_new_mm(vma);
	if (ret < 0)
		return;

	info = vma->pgtable_share_data;
	/* Duplicate and insert shadow vma into shadow mm */
	ret = pgtable_share_insert_vma(info->mm, vma);
	if (ret < 0)
		return;

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
	info = vma_get_pgtable_share_data(vma);
	WARN_ON(!info);
	if (!info)
		return;

	vma_set_pgtable_share_data(vma, NULL);
	if (refcount_dec_and_test(&info->refcnt))
		free_pgtable_share_mm(info);
}

void pgtable_share_clear_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
			     pmd_t *pmdp, unsigned long addr, unsigned long end)
{
	/* pgtable share vmas always align with PMD size */
	spinlock_t *ptl;

	ptl = pmd_lock(vma->vm_mm, pmdp);
	/*
	 * Make sure page fault will happen when accessing
	 * this area.
	 */
	put_page(pmd_pgtable(*pmdp));
	pmd_clear(pmdp);
	add_mm_counter(vma->vm_mm, MM_SHMEMPAGES, -HPAGE_PMD_NR);
	spin_unlock(ptl);

	tlb_change_page_size(tlb, PAGE_SIZE);
	tlb->cleared_ptes = 1;
	tlb->start = addr;
	tlb->end = end - PAGE_SIZE;

	tlb_flush_mmu_tlbonly(tlb);
}
