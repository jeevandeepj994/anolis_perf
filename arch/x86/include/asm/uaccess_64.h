/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_UACCESS_64_H
#define _ASM_X86_UACCESS_64_H

/*
 * User space memory access functions
 */
#include <linux/compiler.h>
#include <linux/lockdep.h>
#include <linux/kasan-checks.h>
#include <asm/alternative.h>
#include <asm/cpufeatures.h>
#include <asm/page.h>
#ifdef CONFIG_USING_FPU_IN_KERNEL_NONATOMIC
#include <asm/fpu/api.h>
#endif

/*
 * Copy To/From Userspace
 */

/* Handles exceptions in both to and from, but doesn't do access_ok */
__must_check unsigned long
copy_user_enhanced_fast_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned len);

#ifdef CONFIG_USING_FPU_IN_KERNEL_NONATOMIC
#ifdef CONFIG_X86_Hygon_LMC_SSE2_ON
void fpu_save_xmm0_3(void *to, const void *from, unsigned len);
void fpu_restore_xmm0_3(void *to, const void *from, unsigned len);

#define kernel_fpu_states_save		fpu_save_xmm0_3
#define kernel_fpu_states_restore	fpu_restore_xmm0_3

__must_check unsigned long
copy_user_sse2_opt_string(void *to, const void *from, unsigned len);

#define copy_user_large_memory_generic_string	copy_user_sse2_opt_string

#endif //CONFIG_X86_Hygon_LMC_SSE2_ON

#ifdef CONFIG_X86_Hygon_LMC_AVX2_ON
void fpu_save_ymm0_7(void *to, const void *from, unsigned len);
void fpu_restore_ymm0_7(void *to, const void *from, unsigned len);

#define kernel_fpu_states_save		fpu_save_ymm0_7
#define kernel_fpu_states_restore	fpu_restore_ymm0_7

__must_check unsigned long
copy_user_avx2_pf64_nt_string(void *to, const void *from, unsigned len);

#define copy_user_large_memory_generic_string	copy_user_avx2_pf64_nt_string
#endif	//CONFIG_USING_AVX2_FOR_LAGRE_MEMORY_COPY

#if defined (CONFIG_X86_Hygon_LMC_SSE2_ON) || defined (CONFIG_X86_Hygon_LMC_AVX2_ON)
unsigned int get_nt_block_copy_mini_len(void);
unsigned int get_nt_block_copy_to_user_mini_nr_pages(void);
unsigned int get_nt_block_copy_from_user_mini_nr_pages(void);

static __always_inline __must_check unsigned long
copy_user_block_data_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;
	unsigned int nt_blk_cpy_mini_len = get_nt_block_copy_mini_len();
	if (nt_blk_cpy_mini_len && (nt_blk_cpy_mini_len <= len)
		&& (system_state == SYSTEM_RUNNING)
                && (!kernel_fpu_begin_nonatomic()))
        {
		ret = copy_user_large_memory_generic_string(to, from, len);
		kernel_fpu_end();

		return ret;
        }

	/* If CPU has ERMS feature, use copy_user_enhanced_fast_string.
	 * Otherwise, if CPU has rep_good feature, use copy_user_generic_string.
	 * Otherwise, use copy_user_generic_unrolled.
	 */
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}
#endif //CONFIG_X86_Hygon_LMC_SSE2_ON || CONFIG_X86_Hygon_LMC_AVX2_ON
#endif

static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

#ifdef CONFIG_USING_FPU_IN_KERNEL_NONATOMIC
#if defined (CONFIG_X86_Hygon_LMC_SSE2_ON) || defined (CONFIG_X86_Hygon_LMC_AVX2_ON)
	unsigned int nt_blk_cpy_mini_len = get_nt_block_copy_mini_len();
	if (((nt_blk_cpy_mini_len) && (nt_blk_cpy_mini_len <= len)
		&& (system_state == SYSTEM_RUNNING)
				&& (!kernel_fpu_begin_nonatomic())))
	{
		ret = copy_user_large_memory_generic_string(to, from, len);
		kernel_fpu_end();
		return ret;
	}
#endif
#endif
	/* If CPU has ERMS feature, use copy_user_enhanced_fast_string.
	 * Otherwise, if CPU has rep_good feature, use copy_user_generic_string.
	 * Otherwise, use copy_user_generic_unrolled.
	 */
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}

#if defined (CONFIG_X86_Hygon_LMC_SSE2_ON) || defined (CONFIG_X86_Hygon_LMC_AVX2_ON)
static __always_inline __must_check unsigned long
raw_copy_block_data_from_user(void *dst, const void __user *src, unsigned long size, unsigned long pages_nr)
{
	unsigned int mini_nr_pages = get_nt_block_copy_from_user_mini_nr_pages();
	if (mini_nr_pages && pages_nr >= mini_nr_pages)
		return copy_user_block_data_generic(dst, (__force void *)src, size);
	else
		return copy_user_generic(dst, (__force void *)src, size);
}

static __always_inline __must_check unsigned long
raw_copy_block_data_to_user(void __user *dst, const void *src, unsigned long size, unsigned long pages_nr)
{
	unsigned int mini_nr_pages = get_nt_block_copy_to_user_mini_nr_pages();
	if (mini_nr_pages && pages_nr >= mini_nr_pages)
		return copy_user_block_data_generic((__force void *)dst, src, size);
	else
		return copy_user_generic((__force void *)dst, src, size);
}
#else
static __always_inline __must_check unsigned long
raw_copy_block_data_from_user(void *dst, const void __user *src, unsigned long size,
				unsigned long pages_nr)
{
	pages_nr = pages_nr;
	return copy_user_generic(dst, (__force void *)src, size);
}

static __always_inline __must_check unsigned long
raw_copy_block_data_to_user(void __user *dst, const void *src, unsigned long size,
				unsigned long pages_nr)
{
	pages_nr = pages_nr;
	return copy_user_generic((__force void *)dst, src, size);
}
#endif //CONFIG_X86_Hygon_LMC_SSE2_ON || CONFIG_X86_Hygon_LMC_AVX2_ON

static __always_inline __must_check unsigned long
raw_copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	return copy_user_generic(dst, (__force void *)src, size);
}

static __always_inline __must_check unsigned long
raw_copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	return copy_user_generic((__force void *)dst, src, size);
}

static __always_inline __must_check
unsigned long raw_copy_in_user(void __user *dst, const void __user *src, unsigned long size)
 {
       return copy_user_generic((__force void *)dst,
                                (__force void *)src, size);
}

extern long __copy_user_nocache(void *dst, const void __user *src,
				unsigned size, int zerorest);

extern long __copy_user_flushcache(void *dst, const void __user *src, unsigned size);
extern void memcpy_page_flushcache(char *to, struct page *page, size_t offset,
			   size_t len);

static inline int
__copy_from_user_inatomic_nocache(void *dst, const void __user *src,
				  unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_nocache(dst, src, size, 0);
}

static inline int
__copy_from_user_flushcache(void *dst, const void __user *src, unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_flushcache(dst, src, size);
}
#endif /* _ASM_X86_UACCESS_64_H */
