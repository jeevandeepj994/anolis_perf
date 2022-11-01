/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_BOOT_H
#define _ASM_X86_KVM_BOOT_H

#ifdef CONFIG_KVM_INTEL_TDX
bool platform_has_tdx(void);
#else
static inline bool platform_has_tdx(void) { return false; }
#endif

extern enum tdx_module_status_t tdx_module_status;

#endif /* _ASM_X86_KVM_BOOT_H */
