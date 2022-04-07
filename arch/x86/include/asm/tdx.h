/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2022 Intel Corporation */
#ifndef _ASM_X86_TDX_H
#define _ASM_X86_TDX_H

#include <linux/init.h>
#include <linux/device.h>
#include <asm/ptrace.h>
#include <asm/shared/tdx.h>

/*
 * Used by the #VE exception handler to gather the #VE exception
 * info from the TDX module. This is a software only structure
 * and not part of the TDX module/VMM ABI.
 */
struct ve_info {
	u64 exit_reason;
	u64 exit_qual;
	/* Guest Linear (virtual) Address */
	u64 gla;
	/* Guest Physical (virtual) Address */
	u64 gpa;
	u32 instr_len;
	u32 instr_info;
};

#ifdef CONFIG_INTEL_TDX_GUEST

void __init tdx_early_init(void);
bool is_tdx_guest(void);
bool tdx_debug_enabled(void);

void __init tdx_filter_init(void);

bool tdx_get_ve_info(struct ve_info *ve);

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve);

void tdx_safe_halt(void);

bool tdx_early_handle_ve(struct pt_regs *regs);

phys_addr_t tdx_shared_mask(void);

int tdx_hcall_request_gpa_type(phys_addr_t start, phys_addr_t end, bool enc);

bool tdx_allowed_port(short int port);

int tdx_mcall_tdreport(u64 data, u64 reportdata);

int tdx_hcall_get_quote(u64 data);

extern void (*tdx_event_notify_handler)(void);

bool tdx_guest_dev_authorized(struct device *dev);

bool tdx_filter_enabled(void);

/* Update the trace point symbolic printing too */
enum tdx_fuzz_loc {
	TDX_FUZZ_MSR_READ,
	TDX_FUZZ_MMIO_READ,
	TDX_FUZZ_PORT_IN,
	TDX_FUZZ_CPUID1,
	TDX_FUZZ_CPUID2,
	TDX_FUZZ_CPUID3,
	TDX_FUZZ_CPUID4,
	TDX_FUZZ_MSR_READ_ERR,
	TDX_FUZZ_MSR_WRITE_ERR,
	TDX_FUZZ_MAP_ERR,
	TDX_FUZZ_PORT_IN_ERR,
	TDX_FUZZ_MAX
};

#ifdef CONFIG_TDX_FUZZ
u64 tdx_fuzz(u64 var, enum tdx_fuzz_loc loc);
bool tdx_fuzz_err(enum tdx_fuzz_loc loc);
#else
static inline u64 tdx_fuzz(u64 var, enum tdx_fuzz_loc loc) { return var; }
static inline bool tdx_fuzz_err(enum tdx_fuzz_loc loc) { return false; }
#endif

#else

static inline void tdx_early_init(void) { };
static inline bool is_tdx_guest(void) { return false; }
static inline void tdx_safe_halt(void) { };

static inline bool tdx_early_handle_ve(struct pt_regs *regs) { return false; }

static inline phys_addr_t tdx_shared_mask(void) { return 0; }


static inline int tdx_hcall_request_gpa_type(phys_addr_t start,
					     phys_addr_t end, bool enc)
{
	return -ENODEV;
}

static inline bool tdx_guest_dev_authorized(struct device *dev)
{
	return dev->authorized;
}

static inline bool tdx_filter_enabled(void) { return true; }

#endif /* CONFIG_INTEL_TDX_GUEST */

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_INTEL_TDX_GUEST)
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4);
#else
static inline long tdx_kvm_hypercall(unsigned int nr, unsigned long p1,
				     unsigned long p2, unsigned long p3,
				     unsigned long p4)
{
	return -ENODEV;
}
#endif /* CONFIG_INTEL_TDX_GUEST && CONFIG_KVM_GUEST */
#endif /* _ASM_X86_TDX_H */
