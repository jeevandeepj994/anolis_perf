#ifndef _LINUX_PGTABLE_SHARE_H_
#define _LINUX_PGTABLE_SHARE_H_

struct vm_area_struct;
struct mm_struct;

#ifdef CONFIG_PAGETABLE_SHARE
struct pgtable_share_struct {
	struct mm_struct *mm;
	refcount_t refcnt;
	unsigned long start;
	unsigned long size;
	unsigned long mode;
};

extern void pgtable_share_del_mm(struct vm_area_struct *vm);
extern int pgtable_share_insert_vma(struct mm_struct *mm, struct vm_area_struct *vma);
extern vm_fault_t find_shared_vma(struct vm_area_struct **vmap,
				  unsigned long *addrp, unsigned int flags);
extern void pgtable_share_create(struct vm_area_struct *vma);

static inline bool vma_is_pgtable_shared(const struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_SHARED_PT;
}
#else
static inline bool vma_is_pgtable_shared(const struct vm_area_struct *vma)
{
	return false;
}

static inline void pgtable_share_del_mm(struct vm_area_struct *vma)
{
}

static inline int pgtable_share_insert_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
	return 0;
}

static inline vm_fault_t find_shared_vma(struct vm_area_struct **vmap,
				  unsigned long *addrp, unsigned int flags)
{
	return 0;
}

static inline void pgtable_share_create(struct vm_area_struct *vma)
{
}
#endif
#endif
