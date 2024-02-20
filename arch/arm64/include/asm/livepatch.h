/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_LIVEPATCH_H
#define _ASM_ARM64_LIVEPATCH_H

#include <linux/module.h>
#include <linux/ftrace.h>

#ifdef CONFIG_LIVEPATCH

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
static inline int klp_check_compiler_support(void)
{
	return 0;
}

static inline void klp_arch_set_pc(struct ftrace_regs *fregs, unsigned long pc)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);

	regs->pc = pc + 2 * AARCH64_INSN_SIZE;
}

#else
static inline int  klp_check_compiler_support(void)
{
	return 1;
}

static inline void klp_arch_set_pc(struct ftrace_regs *fregs, unsigned long pc)
{
}
#endif

#else
#error Live patching support is disabled; check CONFIG_LIVEPATCH
#endif

#endif /* _ASM_ARM64_LIVEPATCH_H */
