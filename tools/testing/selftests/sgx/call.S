/* SPDX-License-Identifier: GPL-2.0 */
/**
* Copyright(c) 2016-20 Intel Corporation.
*/

	.text

	.global sgx_call_vdso
sgx_call_vdso:
	.cfi_startproc
	push	%r15
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r15, 0
	push	%r14
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r14, 0
	push	%r13
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r13, 0
	push	%r12
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%r12, 0
	push	%rbx
	.cfi_adjust_cfa_offset	8
	.cfi_rel_offset		%rbx, 0
	push	$0
	.cfi_adjust_cfa_offset	8
	push	0x38(%rsp)
	.cfi_adjust_cfa_offset	8
	call	*eenter(%rip)
	add	$0x10, %rsp
	.cfi_adjust_cfa_offset	-0x10
	pop	%rbx
	.cfi_adjust_cfa_offset	-8
	pop	%r12
	.cfi_adjust_cfa_offset	-8
	pop	%r13
	.cfi_adjust_cfa_offset	-8
	pop	%r14
	.cfi_adjust_cfa_offset	-8
	pop	%r15
	.cfi_adjust_cfa_offset	-8
	ret
	.cfi_endproc


#define EEXIT	0x04

/* Relative to %rbp. */
#define SGX_ENCLAVE_OFFSET_OF_RUN		16

/* The offsets relative to struct sgx_enclave_run. */
#define SGX_ENCLAVE_RUN_TCS			0
#define SGX_ENCLAVE_RUN_LEAF			8

	.global eenter_no_vdso
eenter_no_vdso:
	/* Prolog */
	push	%rbp
	mov	%rsp, %rbp
	push	%rbx
	mov	%ecx, %eax

	/* Load struct sgx_enclave_run from stack */
	mov	SGX_ENCLAVE_OFFSET_OF_RUN(%rbp), %rcx

	/* Load TCS and AEP */
	mov	SGX_ENCLAVE_RUN_TCS(%rcx), %rbx
	lea	.Lasync_exit_pointer(%rip), %rcx

.Lasync_exit_pointer:
	enclu

	/* EEXIT jumps here unless the enclave is doing something fancy. */
	mov	SGX_ENCLAVE_OFFSET_OF_RUN(%rbp), %rbx

	/* Set exit_reason. */
	movl	$EEXIT, SGX_ENCLAVE_RUN_LEAF(%rbx)

	xor %eax, %eax

	pop %rbx
	leave
	ret
