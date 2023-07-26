/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_LOONGARCH_SUSPEND_H
#define _ASM_LOONGARCH_SUSPEND_H

extern unsigned long eentry;
extern unsigned long tlbrentry;

void arch_common_resume(void);
void arch_common_suspend(void);
extern void loongarch_suspend_enter(void);
extern void loongarch_wakeup_start(void);
void enable_pcie_wakeup(void);
extern void swsusp_arch_save(void);

#endif /* _ASM_LOONGARCH_SUSPEND_H */
