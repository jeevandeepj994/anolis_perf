// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file is shared between decompression boot code and running
 * linux kernel.
 */

#define CPUID_VENDOR_HygonGenuine_ebx	0x6f677948
#define CPUID_VENDOR_HygonGenuine_ecx	0x656e6975
#define CPUID_VENDOR_HygonGenuine_edx	0x6e65476e

#define MSR_CSV_ENABLED_BIT		30
#define MSR_CSV_ENABLED			BIT_ULL(MSR_CSV_ENABLED_BIT)
