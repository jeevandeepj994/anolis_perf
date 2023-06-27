// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/smp.h>
#include <linux/printk.h>
#include <asm/virt.h>
#include <asm/sysreg.h>

#define DEFINE_HW_TUNABLE2(NAME, H, L)					\
	static u64 CPUECTLR_MASK_##NAME	= GENMASK_ULL((H), (L));	\
	static int CPUECTLR_MAX_##NAME	= GENMASK((H) - (L), 0);	\
	static int CPUECTLR_SHIFT_##NAME = L;				\
	static int global_##NAME	= -1

#define DEFINE_HW_TUNABLE1(NAME, B)					\
	static u64 CPUECTLR_MASK_##NAME	= BIT(B);			\
	static int CPUECTLR_MAX_##NAME	= 1;				\
	static int CPUECTLR_SHIFT_##NAME = B;				\
	static int global_##NAME	= -1

#define CPUECTLR_MASK(NAME)		CPUECTLR_MASK_##NAME
#define CPUECTLR_MAX(NAME)		CPUECTLR_MAX_##NAME
#define CPUECTLR_SHIFT(NAME)		CPUECTLR_SHIFT_##NAME

#define SYSCTL_ENTRY_HW_TUNABLE(NAME)					\
	{								\
		.procname = #NAME,					\
		.data = &global_##NAME,					\
		.maxlen = sizeof(global_##NAME),			\
		.mode = 0644,						\
		.proc_handler = &proc_dointvec_minmax,			\
		.extra1 = SYSCTL_ZERO,					\
		.extra2 = &CPUECTLR_MAX(NAME),				\
	}

#define DIRTIED_HW_TUNABLE(NAME) (global_##NAME >= 0)

#define arm64_read_sysreg(v) ({					\
	u64 __ret;						\
	isb();							\
	asm volatile ("mrs %0, " __stringify(v) : "=r" (__ret) :: "memory"); \
	__ret;							\
})

#define arm64_write_sysreg(v, r) do {				\
	u64 __ret = (u64)(r);					\
	asm volatile ("msr " __stringify(v) ", %x0" : : "rZ" (__ret)); \
} while (0)

#define update_configure(v, NAME) do {				\
	if (DIRTIED_HW_TUNABLE(NAME)) {				\
		v &= ~CPUECTLR_MASK(NAME);			\
		v |= (u64)global_##NAME << CPUECTLR_SHIFT(NAME);	\
	}							\
} while (0)

#define ID_AA64MMFR1_VHE_MASK		GENMASK_ULL(11, 8)
#define ID_AA64MMFR1_VHE_VALID		0x1

DEFINE_HW_TUNABLE2(cmc_min_ways, 63, 61);
DEFINE_HW_TUNABLE2(inst_res_ways_l2, 60, 58);
DEFINE_HW_TUNABLE2(ws_threshold_l2, 25, 24);
DEFINE_HW_TUNABLE2(ws_threshold_l3, 23, 22);
DEFINE_HW_TUNABLE2(ws_threshold_l4, 21, 20);
DEFINE_HW_TUNABLE2(ws_threshold_dram, 19, 18);
DEFINE_HW_TUNABLE1(prefetch_disable, 15);
DEFINE_HW_TUNABLE1(prefetch_sts_disable, 9);
DEFINE_HW_TUNABLE1(prefetch_sti_disable, 8);

static int sysctl_update_cpuectlr;

static struct ctl_table_header *hw_sysctl_header;

static u64 *old_cpuectlr;
static bool *write_success;

static void save_cpuectlr(void *dummy)
{
	int cpu = smp_processor_id();
	u64 cpuectlr;

	/* 0. Get current cpuectlr */
	cpuectlr = arm64_read_sysreg(S3_0_C15_C1_4); //cpuectlr_el1 will fail

	old_cpuectlr[cpu] = cpuectlr;
}

static void update_cpuectlr(void *dummy)
{
	int cpu = smp_processor_id();
	u64 cpuectlr = old_cpuectlr[cpu];
	u64 new_cpuectlr;

	/* 1. update CMC configure */
	update_configure(cpuectlr, cmc_min_ways);

	/* 2. update instruct partition configure */
	update_configure(cpuectlr, inst_res_ways_l2);

	/* 3. update stream write configure */
	update_configure(cpuectlr, ws_threshold_l2);
	update_configure(cpuectlr, ws_threshold_l3);
	update_configure(cpuectlr, ws_threshold_l4);
	update_configure(cpuectlr, ws_threshold_dram);

	/* 4. update global prefetch configure */
	update_configure(cpuectlr, prefetch_disable);

	/* 5. update store prefetch configure */
	update_configure(cpuectlr, prefetch_sts_disable);
	update_configure(cpuectlr, prefetch_sti_disable);

	/* write register */
	arm64_write_sysreg(S3_0_C15_C1_4, cpuectlr);

	/* read again to verify writing is valid */
	new_cpuectlr = arm64_read_sysreg(S3_0_C15_C1_4);
	if (new_cpuectlr != cpuectlr) {
		pr_err("CPU #%d write cpuectlr failed: expect %llx, but %llx\n",
			cpu, cpuectlr, new_cpuectlr);
		write_success[cpu] = false;
		return;
	}

	pr_debug("CPU #%d origin cpuectlr: %llx, update to %llx\n", cpu, old_cpuectlr[cpu],
		cpuectlr);
}

static void recall_cpuectlr(void *dummy)
{
	int cpu = smp_processor_id();
	u64 cpuectlr;

	cpuectlr = arm64_read_sysreg(S3_0_C15_C1_4);
	if (old_cpuectlr[cpu] && old_cpuectlr[cpu] != cpuectlr) {
		arm64_write_sysreg(S3_0_C15_C1_4, old_cpuectlr[cpu]);
		pr_debug("CPU #%d recall cpuectlr to %llx\n", cpu, old_cpuectlr[cpu]);
	}
}

static int update_cpuectlr_sysctl_handler(struct ctl_table *table, int write,
		void *buffer, size_t *length, loff_t *ppos)
{
	int ret;
	int cpu;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (ret)
		return ret;
	if (write && sysctl_update_cpuectlr == 1) {
		for_each_possible_cpu(cpu)
			write_success[cpu] = true;

		on_each_cpu(update_cpuectlr, NULL, 1);

		/* recall and return errno if any core write fails */
		for_each_possible_cpu(cpu) {
			if (!write_success[cpu]) {
				on_each_cpu(recall_cpuectlr, NULL, 1);
				pr_err("update cpuectlr error\n");
				return -EACCES;
			}
		}
	}
	return 0;
}

static struct ctl_table hw_sysctl_table[] = {
	SYSCTL_ENTRY_HW_TUNABLE(cmc_min_ways),
	SYSCTL_ENTRY_HW_TUNABLE(inst_res_ways_l2),
	SYSCTL_ENTRY_HW_TUNABLE(ws_threshold_l2),
	SYSCTL_ENTRY_HW_TUNABLE(ws_threshold_l3),
	SYSCTL_ENTRY_HW_TUNABLE(ws_threshold_l4),
	SYSCTL_ENTRY_HW_TUNABLE(ws_threshold_dram),
	SYSCTL_ENTRY_HW_TUNABLE(prefetch_disable),
	SYSCTL_ENTRY_HW_TUNABLE(prefetch_sts_disable),
	SYSCTL_ENTRY_HW_TUNABLE(prefetch_sti_disable),
	{
		.procname = "update_cpuectlr",
		.data = &sysctl_update_cpuectlr,
		.maxlen = sizeof(sysctl_update_cpuectlr),
		.mode = 0644,
		.proc_handler = update_cpuectlr_sysctl_handler,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	},
	{},
};

static struct ctl_table hw_sysctl_root[] = {
	{
		.procname = "kernel",
		.mode = 0555,
		.child = hw_sysctl_table,
	},
	{},
};

static bool interface_init(void)
{
	hw_sysctl_header = register_sysctl_table(hw_sysctl_root);
	return !!hw_sysctl_header;
}

static void interface_exit(void)
{
	unregister_sysctl_table(hw_sysctl_header);
}

static int __init prefetch_tuning_init(void)
{
	bool is_guest;

#ifdef CONFIG_ARM64_VHE
	u64 id_aa64mmfr1 = arm64_read_sysreg(S3_0_C0_C7_1);

	is_guest = ((id_aa64mmfr1 & ID_AA64MMFR1_VHE_MASK) >> ID_AA64MMFR1_VHE_SHIFT)
		== ID_AA64MMFR1_VHE_VALID && !is_hyp_mode_available();
#else
	is_guest = false;
#endif

	if (!is_guest) {
		pr_err("prefetch_tuning module is only applicable to guest os scene\n");
		return -EPERM;
	}

	old_cpuectlr = kmalloc_array(num_possible_cpus(), sizeof(u64), GFP_KERNEL);
	if (!old_cpuectlr)
		return -ENOMEM;

	write_success = kmalloc_array(num_possible_cpus(), sizeof(bool), GFP_KERNEL);
	if (!write_success) {
		kfree(old_cpuectlr);
		return -ENOMEM;
	}

	if (!interface_init()) {
		pr_err("Failed to register cmc_sysctl_table");
		kfree(old_cpuectlr);
		kfree(write_success);
		return -EPERM;
	}

	on_each_cpu(save_cpuectlr, NULL, 1);

	return 0;
}

static void __exit prefetch_tuning_exit(void)
{
	on_each_cpu(recall_cpuectlr, NULL, 1);
	interface_exit();
	kfree(old_cpuectlr);
	kfree(write_success);
}

module_init(prefetch_tuning_init);
module_exit(prefetch_tuning_exit);

MODULE_DESCRIPTION("Prefetch Tuning Switch for Alibaba Cloud ECS");
MODULE_LICENSE("GPL v2");
