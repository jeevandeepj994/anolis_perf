// SPDX-License-Identifier: GPL-2.0-only
/*
 * Confidential Computing Platform Capability checks
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/export.h>
#include <linux/cc_platform.h>
#include <linux/device.h>

#include <asm/coco.h>
#include <asm/processor.h>
#include <asm/tdx.h>

static enum cc_vendor vendor __ro_after_init;
static u64 cc_mask __ro_after_init;

#ifdef CONFIG_INTEL_TDX_GUEST

unsigned int x86_disable_cc = -1;

static int __init x86_cc_clear_setup(char *arg)
{
	get_option(&arg, &x86_disable_cc);

	return 1;
}
__setup("x86_cc_clear=", x86_cc_clear_setup);

#endif

static bool intel_cc_platform_has(enum cc_attr attr)
{
#ifdef CONFIG_INTEL_TDX_GUEST
	if (attr == x86_disable_cc)
		return false;

	switch (attr) {
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
	case CC_ATTR_HOTPLUG_DISABLED:
	case CC_ATTR_GUEST_TDX:
	case CC_ATTR_GUEST_MEM_ENCRYPT:
	case CC_ATTR_MEM_ENCRYPT:
	case CC_ATTR_GUEST_SECURE_TIME:
	case CC_ATTR_GUEST_CPUID_FILTER:
	case CC_ATTR_GUEST_RAND_LOOP:
		return true;
	case CC_ATTR_GUEST_DEVICE_FILTER:
		return tdx_filter_enabled();
	default:
		return false;
	}

	return false;
#else
	return false;
#endif
}

/*
 * SME and SEV are very similar but they are not the same, so there are
 * times that the kernel will need to distinguish between SME and SEV. The
 * cc_platform_has() function is used for this.  When a distinction isn't
 * needed, the CC_ATTR_MEM_ENCRYPT attribute can be used.
 *
 * The trampoline code is a good example for this requirement.  Before
 * paging is activated, SME will access all memory as decrypted, but SEV
 * will access all memory as encrypted.  So, when APs are being brought
 * up under SME the trampoline area cannot be encrypted, whereas under SEV
 * the trampoline area must be encrypted.
 */
static bool amd_cc_platform_has(enum cc_attr attr)
{
#ifdef CONFIG_AMD_MEM_ENCRYPT
	switch (attr) {
	case CC_ATTR_MEM_ENCRYPT:
		return sme_me_mask;

	case CC_ATTR_HOST_MEM_ENCRYPT:
		return sme_me_mask && !(sev_status & MSR_AMD64_SEV_ENABLED);

	case CC_ATTR_GUEST_MEM_ENCRYPT:
		return sev_status & MSR_AMD64_SEV_ENABLED;

	case CC_ATTR_GUEST_STATE_ENCRYPT:
		return sev_status & MSR_AMD64_SEV_ES_ENABLED;

	/*
	 * With SEV, the rep string I/O instructions need to be unrolled
	 * but SEV-ES supports them through the #VC handler.
	 */
	case CC_ATTR_GUEST_UNROLL_STRING_IO:
		return (sev_status & MSR_AMD64_SEV_ENABLED) &&
			!(sev_status & MSR_AMD64_SEV_ES_ENABLED);

	default:
		return false;
	}
#else
	return false;
#endif
}

static bool hyperv_cc_platform_has(enum cc_attr attr)
{
	return attr == CC_ATTR_GUEST_MEM_ENCRYPT;
}

bool cc_platform_has(enum cc_attr attr)
{
	switch (vendor) {
	case CC_VENDOR_AMD:
		return amd_cc_platform_has(attr);
	case CC_VENDOR_INTEL:
		return intel_cc_platform_has(attr);
	case CC_VENDOR_HYPERV:
		return hyperv_cc_platform_has(attr);
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(cc_platform_has);

u64 cc_mkenc(u64 val)
{
	/*
	 * Both AMD and Intel use a bit in the page table to indicate
	 * encryption status of the page.
	 *
	 * - for AMD, bit *set* means the page is encrypted
	 * - for Intel *clear* means encrypted.
	 */
	switch (vendor) {
	case CC_VENDOR_AMD:
		return val | cc_mask;
	case CC_VENDOR_INTEL:
		return val & ~cc_mask;
	default:
		return val;
	}
}

u64 cc_mkdec(u64 val)
{
	/* See comment in cc_mkenc() */
	switch (vendor) {
	case CC_VENDOR_AMD:
		return val & ~cc_mask;
	case CC_VENDOR_INTEL:
		return val | cc_mask;
	default:
		return val;
	}
}
EXPORT_SYMBOL_GPL(cc_mkdec);

__init void cc_set_vendor(enum cc_vendor v)
{
	vendor = v;
}

__init void cc_set_mask(u64 mask)
{
	cc_mask = mask;
}

/*
 * cc_guest_dev_authorized() - Used to get ARCH specific authorized status
 *			       of the given device.
 * @dev			     - device structure
 *
 * Return True to allow the device or False to deny it.
 *
 */
bool cc_guest_dev_authorized(struct device *dev)
{
	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return tdx_guest_dev_authorized(dev);

	return dev->authorized;
}
EXPORT_SYMBOL_GPL(cc_guest_dev_authorized);
