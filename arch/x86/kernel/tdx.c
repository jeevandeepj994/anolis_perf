// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <asm/tdx.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_GET_VEINFO			3

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(exit_qual)		(((exit_qual) & 8) ? 1 : 0)
#define VE_GET_IO_SIZE(exit_qual)	(((exit_qual) & 7) + 1)
#define VE_GET_PORT_NUM(exit_qual)	((exit_qual) >> 16)
#define VE_IS_IO_STRING(exit_qual)	((exit_qual) & 16 ? 1 : 0)

/* Guest TD execution environment information */
static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

static bool tdx_guest_detected __ro_after_init;

/*
 * Wrapper for standard use of __tdx_hypercall with panic report
 * for TDCALL error.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14,
				 u64 r15, struct tdx_hypercall_output *out)
{
	struct tdx_hypercall_output dummy_out;
	u64 err;

	/* __tdx_hypercall() does not accept NULL output pointer */
	if (!out)
		out = &dummy_out;

	/* Non zero return value indicates buggy TDX module, so panic */
	err = __tdx_hypercall(TDX_HYPERCALL_STANDARD, fn, r12, r13, r14,
			      r15, out);
	if (err)
		panic("Hypercall fn %llu failed (Buggy TDX module!)\n", fn);

	return out->r10;
}

#ifdef CONFIG_KVM_GUEST
long tdx_kvm_hypercall(unsigned int nr, unsigned long p1, unsigned long p2,
		       unsigned long p3, unsigned long p4)
{
	struct tdx_hypercall_output out;

	/* Non zero return value indicates buggy TDX module, so panic */
	if (__tdx_hypercall(nr, p1, p2, p3, p4, 0, &out))
		panic("KVM hypercall %u failed. Buggy TDX module?\n", nr);

	return out.r10;
}
EXPORT_SYMBOL_GPL(tdx_kvm_hypercall);
#endif

/*
 * The highest bit of a guest physical address is the "sharing" bit.
 * Set it for shared pages and clear it for private pages.
 */
phys_addr_t tdx_shared_mask(void)
{
	return BIT_ULL(td_info.gpa_width - 1);
}

static void tdx_get_info(void)
{
	struct tdx_module_output out;
	u64 ret;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), sec 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 */
	ret = __tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	/* Non zero return value indicates buggy TDX module, so panic */
	if (ret)
		panic("TDINFO TDCALL failed (Buggy TDX module!)\n");

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

static u64 __cpuidle _tdx_halt(const bool irq_disabled, const bool do_sti)
{
	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of the TD guest and to determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled, the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 *
	 * do_sti parameter is used by the __tdx_hypercall() to decide
	 * whether to call the STI instruction before executing the
	 * TDCALL instruction.
	 */
	return _tdx_hypercall(EXIT_REASON_HLT, irq_disabled, 0, 0,
			      do_sti, NULL);
}

static bool tdx_halt(void)
{
	/*
	 * Since non safe halt is mainly used in CPU offlining
	 * and the guest will always stay in the halt state, don't
	 * call the STI instruction (set do_sti as false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	if (_tdx_halt(irq_disabled, do_sti))
		return false;

	return true;
}

void __cpuidle tdx_safe_halt(void)
{
	 /*
	  * For do_sti=true case, __tdx_hypercall() function enables
	  * interrupts using the STI instruction before the TDCALL. So
	  * set irq_disabled as false.
	  */
	const bool irq_disabled = false;
	const bool do_sti = true;

	/*
	 * Use WARN_ONCE() to report the failure.
	 */
	if (_tdx_halt(irq_disabled, do_sti))
		WARN_ONCE(1, "HLT instruction emulation failed\n");
}

static bool tdx_read_msr(unsigned int msr, u64 *val)
{
	struct tdx_hypercall_output out;

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), sec titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	if (_tdx_hypercall(EXIT_REASON_MSR_READ, msr, 0, 0, 0, &out))
		return false;

	*val = out.r11;

	return true;
}

static bool tdx_write_msr(unsigned int msr, unsigned int low,
			       unsigned int high)
{
	u64 ret;

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) sec titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_MSR_WRITE, msr, (u64)high << 32 | low,
			     0, 0, NULL);

	return ret ? false : true;
}

static bool tdx_handle_cpuid(struct pt_regs *regs)
{
	struct tdx_hypercall_output out;

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (_tdx_hypercall(EXIT_REASON_CPUID, regs->ax, regs->cx, 0, 0, &out))
		return false;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = out.r12;
	regs->bx = out.r13;
	regs->cx = out.r14;
	regs->dx = out.r15;

	return true;
}

static bool tdx_mmio(int size, bool write, unsigned long addr,
		     unsigned long *val)
{
	struct tdx_hypercall_output out;
	u64 err;

	err = _tdx_hypercall(EXIT_REASON_EPT_VIOLATION, size, write,
			     addr, *val, &out);
	if (err)
		return true;

	*val = out.r11;
	return false;
}

static bool tdx_mmio_read(int size, unsigned long addr, unsigned long *val)
{
	return tdx_mmio(size, false, addr, val);
}

static bool tdx_mmio_write(int size, unsigned long addr, unsigned long *val)
{
	return tdx_mmio(size, true, addr, val);
}

static int tdx_handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	char buffer[MAX_INSN_SIZE];
	unsigned long *reg, val = 0;
	struct insn insn = {};
	enum mmio_type mmio;
	int size;
	bool err;

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return -EFAULT;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return -EFAULT;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return -EFAULT;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EFAULT;
	}

	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		err = tdx_mmio_write(size, ve->gpa, &val);
		break;
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		err = tdx_mmio_write(size, ve->gpa, &val);
		break;
	case MMIO_READ:
		err = tdx_mmio_read(size, ve->gpa, &val);
		if (err)
			break;
		/* Zero-extend for 32-bit operation */
		if (size == 4)
			*reg = 0;
		memcpy(reg, &val, size);
		break;
	case MMIO_READ_ZERO_EXTEND:
		err = tdx_mmio_read(size, ve->gpa, &val);
		if (err)
			break;

		/* Zero extend based on operand size */
		memset(reg, 0, insn.opnd_bytes);
		memcpy(reg, &val, size);
		break;
	case MMIO_READ_SIGN_EXTEND: {
		u8 sign_byte = 0, msb = 7;

		err = tdx_mmio_read(size, ve->gpa, &val);
		if (err)
			break;

		if (size > 1)
			msb = 15;

		if (val & BIT(msb))
			sign_byte = -1;

		/* Sign extend based on operand size */
		memset(reg, sign_byte, insn.opnd_bytes);
		memcpy(reg, &val, size);
		break;
	}
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		return -EFAULT;
	}

	if (err)
		return -EFAULT;

	return insn.length;
}

/*
 * Emulate I/O using hypercall.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static bool tdx_handle_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_output out;
	int size, port, ret;
	u64 mask;
	bool in;

	if (VE_IS_IO_STRING(exit_qual))
		return false;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(BITS_PER_BYTE * size, 0);

	/*
	 * Emulate the I/O read/write via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) sec titled "TDG.VP.VMCALL<Instruction.IO>".
	 */
	ret = _tdx_hypercall(EXIT_REASON_IO_INSTRUCTION, size, !in, port,
			     in ? 0 : regs->ax, &out);
	if (!in)
		return !ret;

	regs->ax &= ~mask;
	regs->ax |= ret ? UINT_MAX : out.r11 & mask;

	return !ret;
}

/*
 * Early #VE exception handler. Only handles a subset of port I/O.
 * Intended only for earlyprintk. If failed, return false.
 */
__init bool tdx_early_handle_ve(struct pt_regs *regs)
{
	struct ve_info ve;

	if (tdx_get_ve_info(&ve))
		return false;

	if (ve.exit_reason != EXIT_REASON_IO_INSTRUCTION)
		return false;

	return tdx_handle_io(regs, ve.exit_qual);
}

bool tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	/*
	 * NMIs and machine checks are suppressed. Before this point any
	 * #VE is fatal. After this point (TDGETVEINFO call), NMIs and
	 * additional #VEs are permitted (but it is expected not to
	 * happen unless kernel panics).
	 */
	if (__tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out))
		return false;

	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = lower_32_bits(out.r10);
	ve->instr_info  = upper_32_bits(out.r10);

	return true;
}

/*
 * Handle the user initiated #VE.
 *
 * For example, executing the CPUID instruction from user space
 * is a valid case and hence the resulting #VE has to be handled.
 *
 * For dis-allowed or invalid #VE just return failure.
 */
static bool tdx_virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret = false;

	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		ret = tdx_handle_cpuid(regs);
		break;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		break;
	}

	return ret;
}

/* Handle the kernel #VE */
static bool tdx_virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret = false;
	u64 val;

	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		ret = tdx_halt();
		break;
	case EXIT_REASON_MSR_READ:
		ret = tdx_read_msr(regs->cx, &val);
		if (ret) {
			regs->ax = lower_32_bits(val);
			regs->dx = upper_32_bits(val);
		}
		break;
	case EXIT_REASON_MSR_WRITE:
		ret = tdx_write_msr(regs->cx, regs->ax, regs->dx);
		break;
	case EXIT_REASON_CPUID:
		ret = tdx_handle_cpuid(regs);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		ve->instr_len = tdx_handle_mmio(regs, ve);
		ret = ve->instr_len > 0;
		if (!ret)
			pr_warn_once("MMIO failed\n");
		break;
	case EXIT_REASON_IO_INSTRUCTION:
		ret = tdx_handle_io(regs, ve->exit_qual);
		break;
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		break;
	}

	return ret;
}

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret;

	if (user_mode(regs))
		ret = tdx_virt_exception_user(regs, ve);
	else
		ret = tdx_virt_exception_kernel(regs, ve);

	/* After successful #VE handling, move the IP */
	if (ret)
		regs->ip += ve->instr_len;

	return ret;
}

bool is_tdx_guest(void)
{
	return tdx_guest_detected;
}

void __init tdx_early_init(void)
{
	u32 eax, sig[3];

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	tdx_guest_detected = true;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	tdx_get_info();

	/*
	 * All bits above GPA width are reserved and kernel treats shared bit
	 * as flag, not as part of physical address.
	 *
	 * Adjust physical mask to only cover valid GPA bits.
	 */
	physical_mask &= GENMASK_ULL(td_info.gpa_width - 2, 0);

	pr_info("Guest detected\n");
}
