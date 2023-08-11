// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/memblock.h>
#include <asm/mem_encrypt.h>
#include <asm/csv_command.h>
#include "../mm/mm_internal.h"

#include "csv_command_common.c"

u32 vendor_ebx __section(".data") = 0;
u32 vendor_ecx __section(".data") = 0;
u32 vendor_edx __section(".data") = 0;

struct secure_call_pages {
	struct csv_secure_call_cmd page_a;
	struct csv_secure_call_cmd page_b;
};

/*
 * Check whether host supports CSV in hygon platform.
 * Called in the guest, it always returns false.
 */
bool csv_enable(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long me_mask;
	u64 msr;
	bool csv_enabled;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return false;

	if (sev_status)
		return false;

	/* Check for the SME/CSV support leaf */
	eax = 0x80000000;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (eax < 0x8000001f)
		return false;

#define SME_BIT		BIT(0)
	/*
	 * Check for the CSV feature:
	 * CPUID Fn8000_001F[EAX]
	 * - Bit 30 - CSV support
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(eax & SME_BIT))
		return false;

	csv_enabled = (eax & CPUID_CSV_ENABLED) ? true : false;
	me_mask = 1UL << (ebx & 0x3f);

	/* No SME if Hypervisor bit is set */
	eax = 1;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (ecx & BIT(31))
		return false;

	/* For SME, check the SYSCFG MSR */
	msr = __rdmsr(MSR_K8_SYSCFG);
	if (!(msr & MSR_K8_SYSCFG_MEM_ENCRYPT))
		return false;

	return !!me_mask && csv_enabled;
}

bool noinstr csv_active(void)
{
	if (vendor_ebx == 0 || vendor_ecx == 0 || vendor_edx == 0) {
		u32 eax = 0;

		native_cpuid(&eax, &vendor_ebx, &vendor_ecx, &vendor_edx);
	}

	/* HygonGenuine */
	if (vendor_ebx == CPUID_VENDOR_HygonGenuine_ebx &&
	    vendor_ecx == CPUID_VENDOR_HygonGenuine_ecx &&
	    vendor_edx == CPUID_VENDOR_HygonGenuine_edx)
		return !!(sev_status & MSR_CSV_ENABLED);
	else
		return false;
}

void __init csv_early_reset_memory(struct boot_params *bp)
{
	if (!csv_active())
		return;

	csv_scan_secure_call_pages(bp);
	csv_early_secure_call(0, 0, CSV_SECURE_CMD_RESET);
}

void __init csv_early_update_memory_dec(u64 vaddr, u64 pages)
{
	if (!csv_active())
		return;

	if (pages)
		csv_early_secure_call(__pa(vaddr), pages, CSV_SECURE_CMD_DEC);
}

void __init csv_early_update_memory_enc(u64 vaddr, u64 pages)
{
	if (!csv_active())
		return;

	if (pages)
		csv_early_secure_call(__pa(vaddr), pages, CSV_SECURE_CMD_ENC);
}
