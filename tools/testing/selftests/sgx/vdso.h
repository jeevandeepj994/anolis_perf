/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright(c) 2016-20 Intel Corporation.
 */
#ifndef _SELFTEST_ASM_X86_SGX_H
#define _SELFTEST_ASM_X86_SGX_H

#include <linux/types.h>
#include <linux/ioctl.h>

/**
 * struct sgx_enclave_run - the execution context of __vdso_sgx_enter_enclave()
 * @tcs:			TCS used to enter the enclave
 * @function:			The last seen ENCLU function (EENTER, ERESUME or EEXIT)
 * @exception_vector:		The interrupt vector of the exception
 * @exception_error_code:	The exception error code pulled out of the stack
 * @exception_addr:		The address that triggered the exception
 * @user_handler:		User provided callback run on exception
 * @user_data:			Data passed to the user handler
 * @reserved			Reserved for future extensions
 *
 * If @user_handler is provided, the handler will be invoked on all return paths
 * of the normal flow.  The user handler may transfer control, e.g. via a
 * longjmp() call or a C++ exception, without returning to
 * __vdso_sgx_enter_enclave().
 */
struct sgx_enclave_run {
	__u64 tcs;
	__u32 function;
	__u16 exception_vector;
	__u16 exception_error_code;
	__u64 exception_addr;
	__u64 user_handler;
	__u64 user_data;
	__u8  reserved[216];
};

/**
 * typedef sgx_enclave_user_handler_t - Exit handler function accepted by
 *					__vdso_sgx_enter_enclave()
 * @run:	The run instance given by the caller
 *
 * The register parameters contain the snapshot of their values at enclave
 * exit. An invalid ENCLU function number will cause -EINVAL to be returned
 * to the caller.
 *
 * Return:
 * - <= 0:	The given value is returned back to the caller.
 * - > 0:	ENCLU function to invoke, either EENTER or ERESUME.
 */
typedef int (*sgx_enclave_user_handler_t)(long rdi, long rsi, long rdx,
					  long rsp, long r8, long r9,
					  struct sgx_enclave_run *run);

/**
 * typedef vdso_sgx_enter_enclave_t - Prototype for __vdso_sgx_enter_enclave(),
 *				      a vDSO function to enter an SGX enclave.
 * @rdi:	Pass-through value for RDI
 * @rsi:	Pass-through value for RSI
 * @rdx:	Pass-through value for RDX
 * @function:	ENCLU function, must be EENTER or ERESUME
 * @r8:		Pass-through value for R8
 * @r9:		Pass-through value for R9
 * @run:	struct sgx_enclave_run, must be non-NULL
 *
 * NOTE: __vdso_sgx_enter_enclave() does not ensure full compliance with the
 * x86-64 ABI, e.g. doesn't handle XSAVE state.  Except for non-volatile
 * general purpose registers, EFLAGS.DF, and RSP alignment, preserving/setting
 * state in accordance with the x86-64 ABI is the responsibility of the enclave
 * and its runtime, i.e. __vdso_sgx_enter_enclave() cannot be called from C
 * code without careful consideration by both the enclave and its runtime.
 *
 * All general purpose registers except RAX, RBX and RCX are passed as-is to the
 * enclave.  RAX, RBX and RCX are consumed by EENTER and ERESUME and are loaded
 * with @function, asynchronous exit pointer, and @run.tcs respectively.
 *
 * RBP and the stack are used to anchor __vdso_sgx_enter_enclave() to the
 * pre-enclave state, e.g. to retrieve @run.exception and @run.user_handler
 * after an enclave exit.  All other registers are available for use by the
 * enclave and its runtime, e.g. an enclave can push additional data onto the
 * stack (and modify RSP) to pass information to the optional user handler (see
 * below).
 *
 * Most exceptions reported on ENCLU, including those that occur within the
 * enclave, are fixed up and reported synchronously instead of being delivered
 * via a standard signal. Debug Exceptions (#DB) and Breakpoints (#BP) are
 * never fixed up and are always delivered via standard signals. On synchrously
 * reported exceptions, -EFAULT is returned and details about the exception are
 * recorded in @run.exception, the optional sgx_enclave_exception struct.
 *
 * Return:
 * - 0:		ENCLU function was successfully executed.
 * - -EINVAL:	Invalid ENCL number (neither EENTER nor ERESUME).
 */
typedef int (*vdso_sgx_enter_enclave_t)(unsigned long rdi, unsigned long rsi,
					unsigned long rdx, unsigned int function,
					unsigned long r8,  unsigned long r9,
					struct sgx_enclave_run *run);
#endif /* _SELFTEST_ASM_X86_SGX_H */
