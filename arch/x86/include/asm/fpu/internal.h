/* SPDX-License-Identifier: GPL-2.0 */

#if defined (CONFIG_X86_Hygon_LMC_SSE2_ON) || defined (CONFIG_X86_Hygon_LMC_AVX2_ON)
extern void save_fpregs_to_fpkernelstate(struct fpu *kfpu);
static inline void switch_kernel_fpu_prepare(struct task_struct *prev, int cpu)
 {
 	struct fpu *old_fpu = &prev->thread.fpu;
	if (static_cpu_has(X86_FEATURE_FPU) && !(prev->flags & PF_KTHREAD)) {
 		save_fpregs_to_fpkernelstate(old_fpu);
 	}
 }

 /* Internal helper for switch_kernel_fpu_finish() and signal frame setup */
 static inline void fpregs_restore_kernelregs(struct fpu *kfpu)
 {
    kernel_fpu_states_restore(NULL, &kfpu->fpstate->kernel_state, sizeof(kfpu->fpstate->kernel_state));
 }

static inline void switch_kernel_fpu_finish(struct task_struct *next)
{
    struct fpu *new_fpu = &next->thread.fpu;
    if (next->flags & PF_KTHREAD)
        return;

    if (cpu_feature_enabled(X86_FEATURE_FPU)
				 && test_ti_thread_flag((struct thread_info *)next,
							TIF_USING_FPU_NONATOMIC))
		fpregs_restore_kernelregs(new_fpu);
        
}
#endif