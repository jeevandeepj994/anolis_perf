/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/asm.h>
#include <asm/kvm_host.h>

struct tdx_ex_ret {
	union {
		/* Used to retrieve values from hardware. */
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
		};
		/* Functions that return SEPT and level that failed. */
		struct {
			u64 septep;
			int level;
		};
		/* TDDBG{RD,WR} return the TDR, field code, and value. */
		struct {
			u64 tdr;
			u64 field;
			u64 field_val;
		};
		/* TDDBG{RD,WR}MEM return the address and its value. */
		struct {
			u64 addr;
			u64 val;
		};
		/* TDH_PHYMEM_PAGE_RDMD and TDH_PHYMEM_PAGE_RECLAIM return page metadata. */
		struct {
			u64 page_type;
			u64 owner;
			u64 page_size;
		};
		/* TDH_MEM_SEPT_RD returns the contents of the SEPT entry. */
		struct {
			u64 septe;
			u64 ign;
		};
		/*
		 * TDH_SYS_INFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		};
		/*
		 * TDH_MNG_INIT and TDH_SYS_INIT return CPUID info on error.  Note, only
		 * the leaf and subleaf are valid on TDH_MNG_INIT error.
		 */
		struct {
			u32 leaf;
			u32 subleaf;
			u32 eax_mask;
			u32 ebx_mask;
			u32 ecx_mask;
			u32 edx_mask;
			u32 eax_val;
			u32 ebx_val;
			u32 ecx_val;
			u32 edx_val;
		};
		/* TDH_SYS_TDMR_INIT returns the input PA and next PA. */
		struct {
			u64 prev;
			u64 next;
		};
	};
};

#define pr_seamcall_error(op, err)					  \
	pr_err_ratelimited("SEAMCALL[" #op "] failed: 0x%llx (cpu %d)\n", \
			   (err), smp_processor_id())

#define TDX_ERR(err, op)			\
({						\
	int __ret_warn_on = WARN_ON_ONCE(err);	\
						\
	if (unlikely(__ret_warn_on))		\
		pr_seamcall_error(op, err);	\
	__ret_warn_on;				\
})

#define tdenter(args...)		({ 0; })

#define seamcall ".byte 0x66,0x0f,0x01,0xcf"

#ifndef	INTEL_TDX_BOOT_TIME_SEAMCALL
#define __seamcall				\
	"1:" seamcall "\n\t"			\
	"jmp 3f\n\t"				\
	"2: call kvm_spurious_fault\n\t"	\
	"3:\n\t"				\
	_ASM_EXTABLE(1b, 2b)
#else
/*
 * The default BUG()s on faults, which is undesirable during boot, and calls
 * kvm_spurious_fault(), which isn't linkable if KVM is built as a module.
 * RAX contains '0' on success, TDX-SEAM errno on failure, vector on fault.
 */
#define __seamcall			\
	"1:" seamcall "\n\t"		\
	"2: \n\t"			\
	_ASM_EXTABLE_FAULT(1b, 2b)
#endif

#define seamcall_N(fn, inputs...)					\
do {									\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret)			\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	return ret;							\
} while (0)

#define seamcall_0(fn)	 						\
	seamcall_N(fn, "i"(0))
#define seamcall_1(fn, rcx)	 					\
	seamcall_N(fn, "c"(rcx))
#define seamcall_2(fn, rcx, rdx)					\
	seamcall_N(fn, "c"(rcx), "d"(rdx))
#define seamcall_3(fn, rcx, rdx, __r8)					\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N(fn, "c"(rcx), "d"(rdx), "r"(r8));			\
} while (0)
#define seamcall_4(fn, rcx, rdx, __r8, __r9)				\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N(fn, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));		\
} while (0)

#define seamcall_N_2(fn, ex, inputs...)					\
do {									\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret),			\
		       "=c"((ex)->rcx), "=d"((ex)->rdx)			\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	return ret;							\
} while (0)

#define seamcall_0_2(fn, ex)						\
	seamcall_N_2(fn, ex, "i"(0))
#define seamcall_1_2(fn, rcx, ex)					\
	seamcall_N_2(fn, ex, "c"(rcx))
#define seamcall_2_2(fn, rcx, rdx, ex)					\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_2(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_2(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_2(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_3(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret),			\
		       "=c"((ex)->rcx), "=d"((ex)->rdx), "=r"(r8_out)	\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	(ex)->r8 = r8_out;						\
	return ret;							\
} while (0)

#define seamcall_0_3(fn, ex)						\
	seamcall_N_3(fn, ex, "i"(0))
#define seamcall_1_3(fn, rcx, ex)					\
	seamcall_N_3(fn, ex, "c"(rcx))
#define seamcall_2_3(fn, rcx, rdx, ex)					\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_3(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_3(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_3(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_4(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	register long r9_out asm("r9");					\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=c"((ex)->rcx),	\
		       "=d"((ex)->rdx), "=r"(r8_out), "=r"(r9_out)	\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	(ex)->r8 = r8_out;						\
	(ex)->r9 = r9_out;						\
	return ret;							\
} while (0)

#define seamcall_0_4(fn, ex)						\
	seamcall_N_4(fn, ex, "i"(0))
#define seamcall_1_4(fn, rcx, ex)					\
	seamcall_N_4(fn, ex, "c"(rcx))
#define seamcall_2_4(fn, rcx, rdx, ex)					\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_4(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_4(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_4(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)

#define seamcall_N_5(fn, ex, inputs...)					\
do {									\
	register long r8_out asm("r8");					\
	register long r9_out asm("r9");					\
	register long r10_out asm("r10");				\
	u64 ret;							\
									\
	asm volatile(__seamcall						\
		     : ASM_CALL_CONSTRAINT, "=a"(ret), "=c"((ex)->rcx),	\
		       "=d"((ex)->rdx), "=r"(r8_out), "=r"(r9_out),	\
		       "=r"(r10_out)					\
		     : "a"(SEAMCALL_##fn), inputs			\
		     : );						\
	(ex)->r8 = r8_out;						\
	(ex)->r9 = r9_out;						\
	(ex)->r10 = r10_out;						\
	return ret;							\
} while (0)

#define seamcall_0_5(fn, ex)						\
	seamcall_N_5(fn, ex, "i"(0))
#define seamcall_1_5(fn, rcx, ex)					\
	seamcall_N_5(fn, ex, "c"(rcx))
#define seamcall_2_5(fn, rcx, rdx, ex)					\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx))
#define seamcall_3_5(fn, rcx, rdx, __r8, ex)				\
do {									\
	register long r8 asm("r8") = __r8;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8));		\
} while (0)
#define seamcall_4_5(fn, rcx, rdx, __r8, __r9, ex)			\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9));	\
} while (0)
#define seamcall_5_5(fn, rcx, rdx, __r8, __r9, __r10, ex)		\
do {									\
	register long r8 asm("r8") = __r8;				\
	register long r9 asm("r9") = __r9;				\
	register long r10 asm("r10") = __r10;				\
									\
	seamcall_N_5(fn, ex, "c"(rcx), "d"(rdx), "r"(r8), "r"(r9), "r"(r10)); \
} while (0)

static inline u64 tdh_mng_addcx(hpa_t tdr, hpa_t addr)
{
	seamcall_2(TDH_MNG_ADDCX, addr, tdr);
}

static inline u64 tdh_mem_page_add(hpa_t tdr, gpa_t gpa, hpa_t hpa, hpa_t source,
			    struct tdx_ex_ret *ex)
{
	seamcall_4_2(TDH_MEM_PAGE_ADD, gpa, tdr, hpa, source, ex);
}

static inline u64 tdh_mem_spet_add(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
			    struct tdx_ex_ret *ex)
{
	seamcall_3_2(TDH_MEM_SEPT_ADD, gpa | level, tdr, page, ex);
}

static inline u64 tdh_vp_addcx(hpa_t tdvpr, hpa_t addr)
{
	seamcall_2(TDH_VP_ADDCX, addr, tdvpr);
}

static inline u64 tdassignhkid(hpa_t tdr, int hkid)
{
	seamcall_3(TDASSIGNHKID, tdr, 0, hkid);
}

static inline u64 tdh_mem_page_aug(hpa_t tdr, gpa_t gpa, hpa_t hpa,
			    struct tdx_ex_ret *ex)
{
	seamcall_3_2(TDH_MEM_PAGE_AUG, gpa, tdr, hpa, ex);
}

static inline u64 tdh_mem_range_block(hpa_t tdr, gpa_t gpa, int level,
			  struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MEM_RANGE_BLOCK, gpa | level, tdr, ex);
}

static inline u64 tdh_mng_key_config(hpa_t tdr)
{
	seamcall_1(TDH_MNG_KEY_CONFIG, tdr);
}

static inline u64 tdh_mng_create(hpa_t tdr, int hkid)
{
	seamcall_2(TDH_MNG_CREATE, tdr, hkid);
}

static inline u64 tdh_mng_createvp(hpa_t tdr, hpa_t tdvpr)
{
	seamcall_2(TDH_MNG_CREATEVP, tdvpr, tdr);
}

static inline u64 tdh_mng_rd(hpa_t tdr, u64 field, struct tdx_ex_ret *ex)
{
	seamcall_2_3(TDH_MNG_RD, tdr, field, ex);
}

static inline u64 tdh_mng_wr(hpa_t tdr, u64 field, u64 val, u64 mask,
			  struct tdx_ex_ret *ex)
{
	seamcall_4_3(TDH_MNG_WR, tdr, field, val, mask, ex);
}

static inline u64 tdh_mng_rdmem(hpa_t addr, struct tdx_ex_ret *ex)
{
	seamcall_1_2(TDH_MNG_RDMEM, addr, ex);
}

static inline u64 tdh_mng_wrmem(hpa_t addr, u64 val, struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MNG_WRMEM, addr, val, ex);
}

static inline u64 tdh_mem_page_demote(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
			       struct tdx_ex_ret *ex)
{
	seamcall_3_2(TDH_MEM_PAGE_DEMOTE, gpa | level, tdr, page, ex);
}

static inline u64 tdh_mr_extend(hpa_t tdr, gpa_t gpa, struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MR_EXTEND, gpa, tdr, ex);
}

static inline u64 tdh_mr_finalize(hpa_t tdr)
{
	seamcall_1(TDH_MR_FINALIZE, tdr);
}

static inline u64 tdh_vp_flush(hpa_t tdvpr)
{
	seamcall_1(TDH_VP_FLUSH, tdvpr);
}

static inline u64 tdh_vp_flushdone(hpa_t tdr)
{
	seamcall_1(TDH_VP_FLUSHDONE, tdr);
}

static inline u64 tdh_mng_key_freeid(hpa_t tdr)
{
	seamcall_1(TDH_MNG_KEY_FREEID, tdr);
}

static inline u64 tdh_mng_init(hpa_t tdr, hpa_t td_params, struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MNG_INIT, tdr, td_params, ex);
}

static inline u64 tdh_mng_initvp(hpa_t tdvpr, u64 rcx)
{
	seamcall_2(TDH_MNG_INITVP, tdvpr, rcx);
}

static inline u64 tdh_mem_page_promote(hpa_t tdr, gpa_t gpa, int level,
				struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MEM_PAGE_PROMOTE, gpa | level, tdr, ex);
}

static inline u64 tdh_phymem_page_rdmd(hpa_t page, struct tdx_ex_ret *ex)
{
	seamcall_1_3(TDH_PHYMEM_PAGE_RDMD, page, ex);
}

static inline u64 tdh_mem_sept_rd(hpa_t tdr, gpa_t gpa, int level,
			   struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MEM_SEPT_RD, gpa | level, tdr, ex);
}

static inline u64 tdh_vp_rd(hpa_t tdvpr, u64 field, struct tdx_ex_ret *ex)
{
	seamcall_2_3(TDH_VP_RD, tdvpr, field, ex);
}

static inline u64 tdh_mng_key_reclaimid(hpa_t tdr)
{
	seamcall_1(TDH_MNG_KEY_RECLAIMID, tdr);
}

static inline u64 tdh_phymem_page_reclaim(hpa_t page, struct tdx_ex_ret *ex)
{
	seamcall_1_3(TDH_PHYMEM_PAGE_RECLAIM, page, ex);
}

static inline u64 tdh_mem_page_remove(hpa_t tdr, gpa_t gpa, int level,
				struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MEM_PAGE_REMOVE, gpa | level, tdr, ex);
}

static inline u64 tdh_mem_sept_remove(hpa_t tdr, gpa_t gpa, int level,
			       struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MEM_SEPT_REMOVE, gpa | level, tdr, ex);
}

static inline u64 tdh_sys_config(hpa_t tdmr, int nr_entries, int hkid)
{
	seamcall_3(TDH_SYS_CONFIG, tdmr, nr_entries, hkid);
}

static inline u64 tdh_sys_key_config(void)
{
	seamcall_0(TDH_SYS_KEY_CONFIG);
}

static inline u64 tdh_sys_info(hpa_t tdsysinfo, int nr_bytes, hpa_t cmr_info,
			    int nr_cmr_entries, struct tdx_ex_ret *ex)
{
	seamcall_4_4(TDH_SYS_INFO, tdsysinfo, nr_bytes, cmr_info, nr_cmr_entries, ex);
}

static inline u64 tdh_sys_init(u64 attributes, struct tdx_ex_ret *ex)
{
	seamcall_1_5(TDH_SYS_INIT, attributes, ex);
}

static inline u64 tdh_sys_lp_init(struct tdx_ex_ret *ex)
{
	seamcall_0_3(TDH_SYS_LP_INIT, ex);
}

static inline u64 tdh_sys_tdmr_init(hpa_t tdmr, struct tdx_ex_ret *ex)
{
	seamcall_1_2(TDH_SYS_TDMR_INIT, tdmr, ex);
}

static inline u64 tdh_sys_lp_shutdown(void)
{
	seamcall_0(TDH_SYS_LP_SHUTDOWN);
}

static inline u64 tdteardown(hpa_t tdr)
{
	seamcall_1(TDTEARDOWN, tdr);
}

static inline u64 tdh_mem_track(hpa_t tdr)
{
	seamcall_1(TDH_MEM_TRACK, tdr);
}

static inline u64 tdh_mem_range_unblock(hpa_t tdr, gpa_t gpa, int level,
			    struct tdx_ex_ret *ex)
{
	seamcall_2_2(TDH_MEM_RANGE_UNBLOCK, gpa | level, tdr, ex);
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	seamcall_1(TDH_PHYMEM_CACHE_WB, resume ? 1 : 0);
}

static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	seamcall_1(TDH_PHYMEM_PAGE_WBINVD, page);
}

static inline u64 tdh_mem_sept_wr(hpa_t tdr, gpa_t gpa, int level, u64 val,
			   struct tdx_ex_ret *ex)
{
	seamcall_3_2(TDH_MEM_SEPT_WR, gpa | level, tdr, val, ex);
}

static inline u64 tdh_vp_wr(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			  struct tdx_ex_ret *ex)
{
	seamcall_4_3(TDH_VP_WR, tdvpr, field, val, mask, ex);
}

#endif /* __KVM_X86_TDX_OPS_H */
