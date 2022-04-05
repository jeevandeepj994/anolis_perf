/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_BOOT_H
#define _ASM_X86_KVM_BOOT_H

#include <linux/init.h>

#define TDX_CPUID_LEAF_ID	0x21
#define TDX_IDENT		"IntelTDX    "

#ifdef CONFIG_KVM_INTEL_TDX
bool platform_has_tdx(void);
#else
static inline bool platform_has_tdx(void) { return false; }
#endif

extern enum tdx_module_status_t tdx_module_status;

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);

#else

static inline void tdx_early_init(void) { };

#endif /* CONFIG_INTEL_TDX_GUEST */

#endif /* _ASM_X86_KVM_BOOT_H */
