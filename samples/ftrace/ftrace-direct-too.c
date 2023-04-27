// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

#include <linux/mm.h> /* for handle_mm_fault() */
#include <linux/ftrace.h>

extern void my_direct_func(struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs);

void my_direct_func(struct vm_area_struct *vma, unsigned long address,
		    unsigned int flags, struct pt_regs *regs)
{
	trace_printk("handle mm fault vma=%p address=%lx flags=%x regs=%p\n",
		     vma, address, flags, regs);
}

extern void my_tramp(void *);

#ifdef CONFIG_X86_64

asm (
"	.pushsection    .text, \"ax\", @progbits\n"
"	.type		my_tramp, @function\n"
"	.globl		my_tramp\n"
"   my_tramp:"
"	pushq %rbp\n"
"	movq %rsp, %rbp\n"
"	pushq %rdi\n"
"	pushq %rsi\n"
"	pushq %rdx\n"
"	pushq %rcx\n"
"	call my_direct_func\n"
"	popq %rcx\n"
"	popq %rdx\n"
"	popq %rsi\n"
"	popq %rdi\n"
"	leave\n"
	ASM_RET
"	.size		my_tramp, .-my_tramp\n"
"	.popsection\n"
);

#endif /* CONFIG_X86_64 */

#ifdef CONFIG_ARM64

asm (
"	.pushsection	.text, \"ax\", @progbits\n"
"	.type		my_tramp, @function\n"
"	.globl		my_tramp\n"
"   my_tramp:"
"	bti	c\n"
"	sub	sp, sp, #48\n"
"	stp	x9, x30, [sp]\n"
"	stp	x0, x1, [sp, #16]\n"
"	stp	x2, x3, [sp, #32]\n"
"	bl	my_direct_func\n"
"	ldp	x30, x9, [sp]\n"
"	ldp	x0, x1, [sp, #16]\n"
"	ldp	x2, x3, [sp, #32]\n"
"	add	sp, sp, #48\n"
"	ret	x9\n"
"	.size		my_tramp, .-my_tramp\n"
"	.popsection\n"
);

#endif /* CONFIG_ARM64 */

static struct ftrace_ops direct;

static int __init ftrace_direct_init(void)
{
	ftrace_set_filter_ip(&direct, (unsigned long) handle_mm_fault, 0, 0);

	return register_ftrace_direct(&direct, (unsigned long) my_tramp);
}

static void __exit ftrace_direct_exit(void)
{
	unregister_ftrace_direct(&direct, (unsigned long)my_tramp, true);
}

module_init(ftrace_direct_init);
module_exit(ftrace_direct_exit);

MODULE_AUTHOR("Steven Rostedt");
MODULE_DESCRIPTION("Another example use case of using register_ftrace_direct()");
MODULE_LICENSE("GPL");
