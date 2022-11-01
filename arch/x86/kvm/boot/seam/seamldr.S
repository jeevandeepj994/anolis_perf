/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ASM helper to load Intel SEAM module.
 *
 * Copyright (C) 2019 Intel Corporation
 *
 * Authors:
 *	Kai Huang <kai.huang>@intel.com
 */
#include <linux/linkage.h>
#include <linux/init.h>
#include <uapi/asm/processor-flags.h>
#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/msr-index.h>
#include <asm/segment.h>
#include <asm/unwind_hints.h>

.macro save_msr _msr
	movl	$(\_msr), %ecx
	rdmsr
	pushq	%rax
	pushq	%rdx
.endm

.macro restore_msr _msr
	popq	%rdx
	popq	%rax
	movl	$(\_msr), %ecx
	wrmsr
.endm

	.text
	__INIT
	.code64
SYM_CODE_START(launch_seamldr)
	UNWIND_HINT_FUNC

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx

	/* Save DR7, SEAMLDR sets it to 0x400. */
	movq	%dr7, %rax
	pushq	%rax

	/*
	 * The NP-SEAMLDR clobbers %rflags to the reset value. Save rflags to
	 * restore system/control flags and unmask interrupts later.
	 */
	pushfq

	movq	%cr4, %rax
	pushq	%rax
	orq 	$X86_CR4_FSGSBASE, %rax
	movq	%rax, %cr4

	rdgsbase %rax /* Save GS. */
	pushq  %rax

	/*
	 * The NP-SEAMLDR unconditionally sets CR4.PCIDE = 0 and restores CR3
	 * from %r11.  If CR4.PCIDE = 0, CR3 bit 3 and bit 4 are interpreted as
	 * PWT and PCD, not as a part of CR3.PCID[0:11].  When changing
	 * CR4.PCIDE from 0 to 1 if CR3.PCID != 0, it results in #GP.
	 *
	 * Clear CR3.PCID = 0 to avoid interpreting CR3.{PWT, PCD} and to allow
	 * to set CR4.PCIDE from 0 to 1.
	 */
	movq	%cr3, %r11
	pushq	%r11
	andq	$~X86_CR3_PCID_MASK, %r11

	/*
	 * SEAMLDR restores GDTR and CS before ExitAC, DS/ES/SS don't need to
	 * be manually preserved as this is 64-bit mode, and FS/GS and IDTR are
	 * not modified by EnterACCS or SEAMLDR.
	 */

	/* EnterACCS and SEAMLDR modify CR4 and CR0. */
	movq	%cr4, %rax
	pushq	%rax

	/* Enable CR4.SMXE for GETSEC */
	orq	$X86_CR4_SMXE, %rax
	movq	%rax, %cr4

	movq	%cr0, %rax
	pushq	%rax

	/*
	 * Load R9-R12 immediately, they won't be clobbered, unlike RDX.
	 * The SEAMLDR spec: 4.1 OS/VMM Loader steps to launch the NP-SEAMLDR
	 *
	 *  - R9: GDT base to be set up by the SEAMLDR when returning to the
	 *        kernel
	 *  - R10: RIP of resume point
	 *  - R11: CR3 with PCID=0 when returning to kernel (set above)
	 *  - R12: IDT to be set up by the NP-SEAMLDR when returning to the
	 *	   kernel
	 */
	sgdt	kernel_gdt64(%rip)
	movq	kernel_gdt64_base(%rip), %r9
	leaq	.Lseamldr_resume(%rip), %r10
	sidt	kernel_idt64(%rip)
	movq	kernel_idt64_base(%rip), %r12

	/* Save MSRs that are modified by EnterACCS and/or SEAMLDR */
	save_msr MSR_EFER
	save_msr MSR_IA32_CR_PAT
	save_msr MSR_IA32_MISC_ENABLE

	/*
	 * MSRs that are clobbered by SEAMLDR but are not enabled during early
	 * boot and so don't need to be saved/restored.
	 *
	 * save_msr MSR_IA32_DEBUGCTLMSR
	 * save_msr MSR_CORE_PERF_GLOBAL_CTRL
	 * save_msr MSR_IA32_PEBS_ENABLE
	 * save_msr MSR_IA32_RTIT_CTL
	 * save_msr MSR_IA32_LBR_CTRL
	 */

	/* Now as last step, save RSP before invoking GETSEC[ENTERACCS] */
	movq	%rsp, saved_rsp(%rip)

	/*
	 * Load the Remaining params for EnterACCS.
	 *
	 *  - EBX: SEAMLDR ACM physical address
	 *  - ECX: SEAMLDR ACM size
	 *  - EAX: 2
	 */
	movl	%edi, %ebx
	movl	%esi, %ecx

	/* Invoke GETSEC[ENTERACCS] */
	movl	$2, %eax
.Lseamldr_enteraccs:
	getsec

.Lseamldr_resume:
	/*
	 * SEAMLDR restores CRs and GDT.  Segment registers are flat, but
	 * don't hold kernel selectors.  Reload the data segs now.
	 */
	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss

	/*
	 * Restore stack from RIP relative storage, and then restore everything
	 * else from the stack.
	 */
	movq	saved_rsp(%rip), %rsp

	/*
	 * Restore CPU status, in reverse order of saving. Firstly, restore
	 * MSRs.
	 */
	restore_msr  MSR_IA32_MISC_ENABLE
	restore_msr  MSR_IA32_CR_PAT
	restore_msr  MSR_EFER

	popq	%rax
	movq	%rax, %cr0
	popq	%rax
	movq	%rax, %cr4

	popq	%rax
	movq	%rax, %cr3	/* Restore CR3.PCID */

	movq	%cr4, %rax
	orq 	$X86_CR4_FSGSBASE, %rax
	movq	%rax, %cr4

	popq	%rax
	wrgsbase %rax  /* Restore GS. */

	popq	%rax
	movq	%rax, %cr4

	popfq	/* Restore system/control flags and unmask interrupts. */

	popq	%rax
	movq	%rax, %dr7

	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp

	/* Far return to load the kernel's CS. */
	popq	%rax
	pushq	$__KERNEL_CS
	pushq	%rax

	movq	%r9, %rax
	UNWIND_HINT sp_reg=ORG_REG_SP sp_offset=16 type=UNWIND_HINT_TYPE_FUNC
	lretq

.pushsection .fixup, "ax"
	/*
	 * The CPU doesn't clobber its state when an exception happens with
	 * GETSEC[EtnerACCS] because it does the exception check before
	 * switching to the ACM mode.  Although it's unnecessary to restore the
	 * not-clobbered registers, share the exit code path because this isn't
	 * a fast path.
	 *
	 * If the GETSEC[EnterACCS] instruction faulted, return -EFAULT.
	 * As NP-SEAMLDR stores the error code in %r9, store the error code to
	 * %r9 to share the exit path.
	 */
1:
	movq	$-EFAULT, %r9
	jmp		.Lseamldr_resume
.popsection
	_ASM_EXTABLE(.Lseamldr_enteraccs, 1b)

SYM_CODE_END(launch_seamldr)

	__INITDATA
	.balign	8
kernel_gdt64:
	.word	0
kernel_gdt64_base:
	.quad	0

	.balign	8
kernel_idt64:
	.word	0
kernel_idt64_base:
	.quad	0

	.balign	8
saved_rsp:
	.quad	0
