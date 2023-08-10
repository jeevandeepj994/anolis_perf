// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hygon CSV Support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#ifdef CONFIG_HYGON_CSV

#include "misc.h"

#include "../../kernel/csv_command_common.c"

static unsigned int csv_enabled __section(".data");

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

void set_csv_status(void) { }

#endif /* CONFIG_HYGON_CSV */
