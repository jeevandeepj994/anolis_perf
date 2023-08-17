#ifndef _LINUX_PGTABLE_SHARE_H_
#define _LINUX_PGTABLE_SHARE_H_

struct vm_area_struct;
struct mm_struct;

struct pgtable_share_struct {
	struct mm_struct *mm;
	refcount_t refcnt;
	unsigned long start;
	unsigned long size;
	unsigned long mode;
};

extern int pgtable_share_new_mm(struct file *file, struct vm_area_struct *vma);
extern void pgtable_share_del_mm(struct vm_area_struct *vm);
extern int pgtable_share_insert_vma(struct mm_struct *mm, struct vm_area_struct *vma);
extern vm_fault_t find_shared_vma(struct vm_area_struct **vmap,
				  unsigned long *addrp, unsigned int flags);

static inline bool vma_is_shared(const struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_SHARED_PT;
}
#endif
