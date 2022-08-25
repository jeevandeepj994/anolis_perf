// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/mm_inline.h>

DEFINE_STATIC_KEY_FALSE(fcm_enabled_key);
DEFINE_STATIC_KEY_FALSE(fcm_staging_key);

noinline int fcm_cpr_fast(struct vm_area_struct *vma,
			  struct vm_area_struct *mpnt)
{
	return -EOPNOTSUPP;
}

noinline void fcm_cpr_bind(struct mm_struct *oldmm, struct mm_struct *mm,
			   int err)
{
}

noinline void fcm_cpr_rest(void)
{
}

noinline void fcm_cpr_done(struct mm_struct *mm, bool r, bool l)
{
}

noinline bool __is_pmd_fcm(pmd_t pmd)
{
	return false;
}

noinline void __fcm_fixup_pmd(struct vm_area_struct *mpnt, pmd_t *pmd,
			      unsigned long addr)
{
}

noinline void __fcm_fixup_vma(struct vm_area_struct *mpnt)
{
}
