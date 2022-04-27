/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_BOOT_H
#define _ASM_X86_KVM_BOOT_H

#ifdef CONFIG_KVM_INTEL_TDX
void __init tdh_seam_init(void);
bool platform_has_tdx(void);
#else
static inline void __init tdh_seam_init(void) {}
static inline bool platform_has_tdx(void) { return false; }
#endif

#endif /* _ASM_X86_KVM_BOOT_H */
