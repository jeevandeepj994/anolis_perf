// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "seam: " fmt

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <asm/apic.h>
#include <asm/cpu.h>
#include <asm/delay.h>
#include <asm/tdx.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/page_types.h>

#include "seamloader.h"

#define INTEL_TDX_BOOT_TIME_SEAMCALL 1
#include "vmx/tdx_arch.h"
#include "vmx/tdx_ops.h"
#include "vmx/tdx_errno.h"

/* Seamcalls of p-seamldr cannot be called concurrently. */
static DEFINE_SPINLOCK(seamcall_seamldr_lock);

int seamldr_info(hpa_t seamldr_info)
{
	u64 ret;

	spin_lock(&seamcall_seamldr_lock);
	ret = __seamldr_info(seamldr_info);
	spin_unlock(&seamcall_seamldr_lock);

	if (TDX_ERR(ret, SEAMLDR_INFO))
		return -EIO;

	return 0;
}

int seamldr_install(hpa_t seamldr_params)
{
	u64 ret;

	spin_lock(&seamcall_seamldr_lock);
	ret = __seamldr_install(seamldr_params);
	spin_unlock(&seamcall_seamldr_lock);

	if (TDX_ERR(ret, SEAMLDR_INSTALL))
		return -EIO;

	return 0;
}

int seamldr_shutdown(void)
{
	u64 ret;

	spin_lock(&seamcall_seamldr_lock);
	ret = __seamldr_shutdown();
	spin_unlock(&seamcall_seamldr_lock);

	if (TDX_ERR(ret, SEAMLDR_SHUTDOWN))
		return -EIO;

	return 0;
}

/* The ACM and input params need to be below 4G. */
static phys_addr_t __init seam_alloc_lowmem(phys_addr_t size)
{
	return memblock_phys_alloc_range(size, PAGE_SIZE, 0, BIT_ULL(32));
}

bool is_seamrr_enabled(void)
{
	u64 mtrrcap, seamrr_base, seamrr_mask;

	if (!boot_cpu_has(X86_FEATURE_MTRR) ||
	    rdmsrl_safe(MSR_MTRRcap, &mtrrcap) || !(mtrrcap & MTRRCAP_SEAMRR))
		return 0;

	if (rdmsrl_safe(MSR_IA32_SEAMRR_PHYS_BASE, &seamrr_base) ||
	    !(seamrr_base & MSR_IA32_SEAMRR_PHYS_BASE_CONFIGURED)) {
		pr_info("SEAMRR base is not configured by BIOS\n");
		return 0;
	}

	if (rdmsrl_safe(MSR_IA32_SEAMRR_PHYS_MASK, &seamrr_mask) ||
	    !(seamrr_mask & MSR_IA32_SEAMRR_PHYS_MASK_ENABLED)) {
		pr_info("SEAMRR is not enabled by BIOS\n");
		return 0;
	}

	return 1;
}

extern u64 launch_seamldr(unsigned long seamldr_pa, unsigned long seamldr_size);

int __init seam_load_module(void *seamldr, unsigned long seamldr_size)
{
	phys_addr_t seamldr_pa;
	int enteraccs_attempts = 10;
	u32 icr_busy;
	int ret;
	u64 err;

	if (!is_seamrr_enabled())
		return -EOPNOTSUPP;

	if (!seamldr_size) {
		pr_err("Invalid SEAMLDR ACM size\n");
		return -EINVAL;
	}

	/* GETSEC[EnterACCS] requires the ACM to be 4k aligned and below 4G. */
	seamldr_pa = __pa(seamldr);
	if (seamldr_pa >= BIT_ULL(32) || !IS_ALIGNED(seamldr_pa, 4096)) {
		seamldr_pa = seam_alloc_lowmem(seamldr_size);
		if (!seamldr_pa)
			return -ENOMEM;
		memcpy(__va(seamldr_pa), seamldr, seamldr_size);
	}

	ret = -EIO;
	/* Ensure APs are in WFS. */
	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_INT_ASSERT |
		       APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto free;

	apic_icr_write(APIC_DEST_ALLBUT | APIC_INT_LEVELTRIG | APIC_DM_INIT, 0);
	icr_busy = safe_apic_wait_icr_idle();
	if (WARN_ON(icr_busy))
		goto free;

	if (!static_cpu_has(X86_FEATURE_FSGSBASE))
		return -EOPNOTSUPP;

retry_enteraccs:
	err = launch_seamldr(seamldr_pa, seamldr_size);
#define SEAMLDR_EMODBUSY	0x8000000000000001ULL
#define SEAMLDR_EUNSPECERR	0x8000000000010003ULL
	if (err == SEAMLDR_EMODBUSY) {
		pr_warn("Found a SEAMLDR already loaded! Just reuse it\n");
		ret = 0;
		goto free;
	}

	if ((err == SEAMLDR_EUNSPECERR || err == -EFAULT) &&
	    !WARN_ON(!enteraccs_attempts--)) {
		udelay(1 * USEC_PER_MSEC);
		goto retry_enteraccs;
	}
	pr_info("Launch SEAMLDR returned %llx\n", err);
	if (!err)
		ret = 0;

free:
	if (seamldr_pa != __pa(seamldr))
		memblock_free_early(seamldr_pa, seamldr_size);

	return ret;
}
