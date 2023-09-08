#ifndef _LINUX_PGTABLE_SHARE_H_
#define _LINUX_PGTABLE_SHARE_H_

struct vm_area_struct;
struct mm_struct;

#ifdef CONFIG_PAGETABLE_SHARE
struct pgtable_share_struct {
	struct mm_struct *mm;
	refcount_t refcnt;
};

extern void pgtable_share_del_mm(struct vm_area_struct *vm);
extern int pgtable_share_insert_vma(struct mm_struct *mm, struct vm_area_struct *vma);
extern void pgtable_share_create(struct vm_area_struct *vma);
extern struct pgtable_share_struct *vma_get_pgtable_share_data(struct vm_area_struct *vma);
extern void vma_set_pgtable_share_mm(struct vm_area_struct *vma,
				     struct pgtable_share_struct *info);
extern vm_fault_t pgtable_share_page_fault(struct vm_fault *vmf,
					   unsigned long addr);

static inline bool vma_is_pgtable_shared(const struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_SHARED_PT;
}

static inline bool vma_is_shadow(const struct vm_area_struct *vma)
{
	return vma && vma->pgtable_share_data &&
		vma->vm_mm == vma->pgtable_share_data->mm;
}
#else
static inline bool vma_is_pgtable_shared(const struct vm_area_struct *vma)
{
	return false;
}

static inline struct pgtable_share_struct *vma_get_pgtable_share_data(struct vm_area_struct *vma)
{
	return NULL;
}

static inline void vma_set_pgtable_share_data(struct vm_area_struct *vma,
					      struct pgtable_share_struct *info)
{
}

static inline void pgtable_share_del_mm(struct vm_area_struct *vma)
{
}

static inline int pgtable_share_insert_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
	return 0;
}

static inline void pgtable_share_create(struct vm_area_struct *vma)
{
}

static inline vm_fault_t pgtable_share_page_fault(struct vm_fault *vmf, unsigned long addr)
{
	return 0;
}
#endif
#endif
