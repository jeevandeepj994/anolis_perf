// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <asm/inst.h>

u32 larch_insn_gen_lu32id(enum loongarch_gpr rd, int imm)
{
	union loongarch_instruction insn;

	insn.reg1i20_format.opcode = lu32id_op;
	insn.reg1i20_format.rd = rd;
	insn.reg1i20_format.immediate = imm;

	return insn.word;
}

u32 larch_insn_gen_lu52id(enum loongarch_gpr rd, enum loongarch_gpr rj, int imm)
{
	union loongarch_instruction insn;

	insn.reg2i12_format.opcode = lu52id_op;
	insn.reg2i12_format.rd = rd;
	insn.reg2i12_format.rj = rj;
	insn.reg2i12_format.immediate = imm;

	return insn.word;
}

u32 larch_insn_gen_jirl(enum loongarch_gpr rd, enum loongarch_gpr rj, unsigned long pc, unsigned long dest)
{
	union loongarch_instruction insn;

	insn.reg2i16_format.opcode = jirl_op;
	insn.reg2i16_format.rd = rd;
	insn.reg2i16_format.rj = rj;
	insn.reg2i16_format.immediate = (dest - pc) >> 2;

	return insn.word;
}

void simu_pc(struct pt_regs *regs, union loongarch_instruction insn)
{
	unsigned long pc = regs->csr_era;
	unsigned int rd = insn.reg1i20_format.rd;
	unsigned int imm = insn.reg1i20_format.immediate;

	if (pc & 3) {
		pr_warn("%s: invalid pc 0x%lx\n", __func__, pc);
		return;
	}

	switch (insn.reg1i20_format.opcode) {
	case pcaddi_op:
		regs->regs[rd] = pc + sign_extend64(imm << 2, 21);
		break;
	case pcaddu12i_op:
		regs->regs[rd] = pc + sign_extend64(imm << 12, 31);
		break;
	case pcaddu18i_op:
		regs->regs[rd] = pc + sign_extend64(imm << 18, 37);
		break;
	case pcalau12i_op:
		regs->regs[rd] = pc + sign_extend64(imm << 12, 31);
		regs->regs[rd] &= ~((1 << 12) - 1);
		break;
	default:
		pr_info("%s: unknown opcode\n", __func__);
		return;
	}

	regs->csr_era += LOONGARCH_INSN_SIZE;
}

void simu_branch(struct pt_regs *regs, union loongarch_instruction insn)
{
	unsigned int imm, imm_l, imm_h, rd, rj;
	unsigned long pc = regs->csr_era;

	if (pc & 3) {
		pr_warn("%s: invalid pc 0x%lx\n", __func__, pc);
		return;
	}

	imm_l = insn.reg0i26_format.immediate_l;
	imm_h = insn.reg0i26_format.immediate_h;
	switch (insn.reg0i26_format.opcode) {
	case b_op:
		regs->csr_era = pc + sign_extend64((imm_h << 16 | imm_l) << 2, 27);
		return;
	case bl_op:
		regs->csr_era = pc + sign_extend64((imm_h << 16 | imm_l) << 2, 27);
		regs->regs[1] = pc + LOONGARCH_INSN_SIZE;
		return;
	}

	imm_l = insn.reg1i21_format.immediate_l;
	imm_h = insn.reg1i21_format.immediate_h;
	rj = insn.reg1i21_format.rj;
	switch (insn.reg1i21_format.opcode) {
	case beqz_op:
		if (regs->regs[rj] == 0)
			regs->csr_era = pc + sign_extend64((imm_h << 16 | imm_l) << 2, 22);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		return;
	case bnez_op:
		if (regs->regs[rj] != 0)
			regs->csr_era = pc + sign_extend64((imm_h << 16 | imm_l) << 2, 22);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		return;
	}

	imm = insn.reg2i16_format.immediate;
	rj = insn.reg2i16_format.rj;
	rd = insn.reg2i16_format.rd;
	switch (insn.reg2i16_format.opcode) {
	case beq_op:
		if (regs->regs[rj] == regs->regs[rd])
			regs->csr_era = pc + sign_extend64(imm << 2, 17);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		break;
	case bne_op:
		if (regs->regs[rj] != regs->regs[rd])
			regs->csr_era = pc + sign_extend64(imm << 2, 17);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		break;
	case blt_op:
		if ((long)regs->regs[rj] < (long)regs->regs[rd])
			regs->csr_era = pc + sign_extend64(imm << 2, 17);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		break;
	case bge_op:
		if ((long)regs->regs[rj] >= (long)regs->regs[rd])
			regs->csr_era = pc + sign_extend64(imm << 2, 17);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		break;
	case bltu_op:
		if (regs->regs[rj] < regs->regs[rd])
			regs->csr_era = pc + sign_extend64(imm << 2, 17);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		break;
	case bgeu_op:
		if (regs->regs[rj] >= regs->regs[rd])
			regs->csr_era = pc + sign_extend64(imm << 2, 17);
		else
			regs->csr_era = pc + LOONGARCH_INSN_SIZE;
		break;
	case jirl_op:
		regs->csr_era = regs->regs[rj] + sign_extend64(imm << 2, 17);
		regs->regs[rd] = pc + LOONGARCH_INSN_SIZE;
		break;
	default:
		pr_info("%s: unknown opcode\n", __func__);
		return;
	}
}
