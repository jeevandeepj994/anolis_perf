// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hygon CSV Support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#ifdef CONFIG_HYGON_CSV

#include "misc.h"

#undef __init
#undef __initdata
#undef __pa
#define __init
#define __initdata
#define __pa(x)	((unsigned long)(x))

#include "../../kernel/csv_command_common.c"

static unsigned int csv_secure_call_init;
static unsigned int csv_enabled __section(".data");

/* Invoke it before jump to real kernel in case secure call pages are not mapped
 * in the identity page table.
 *
 * If no #VC happens, there is no identity mapping in page table for secure call
 * pages. And page fault is not supported in the early stage when real kernel is
 * running. As a result, CSV guest will shutdown when access secure call pages
 * by then.
 */
void csv_init_secure_call_pages(void *boot_params)
{
	if (csv_enabled &&!csv_secure_call_init) {
		/*
		 * boot_params may be not sanitized, but it's OK to access
		 * e820_table field.
		 */
		csv_scan_secure_call_pages(boot_params);
		csv_early_secure_call(0, 0, CSV_SECURE_CMD_RESET);
		csv_secure_call_init = 1;
	}
}

void set_csv_status(void)
{
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;

	eax = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);

	/* HygonGenuine */
	if (ebx == CPUID_VENDOR_HygonGenuine_ebx &&
	    ecx == CPUID_VENDOR_HygonGenuine_ecx &&
	    edx == CPUID_VENDOR_HygonGenuine_edx &&
	    sme_me_mask) {
		unsigned long low, high;

		asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV));

		if (low & MSR_CSV_ENABLED)
			csv_enabled = 1;
	}
}

#else /* !CONFIG_HYGON_CSV */

void csv_init_secure_call_pages(void *boot_params) { }
void set_csv_status(void) { }

#endif /* CONFIG_HYGON_CSV */
