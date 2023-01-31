/* SPDX-License-Identifier: GPL-2.0 */

#define IDX_INVALID		-1

struct cpudl_item {
	u64			dl;
	int			cpu;
	int			idx;
};

struct cpudl {
	raw_spinlock_t		lock;
	int			size;
	cpumask_var_t		free_cpus;
	struct cpudl_item	*elements;

	CK_KABI_RESERVE(1)
	CK_KABI_RESERVE(2)
	CK_KABI_RESERVE(3)
	CK_KABI_RESERVE(4)
	CK_KABI_RESERVE(5)
	CK_KABI_RESERVE(6)
	CK_KABI_RESERVE(7)
	CK_KABI_RESERVE(8)
};

#ifdef CONFIG_SMP
int  cpudl_find(struct cpudl *cp, struct task_struct *p, struct cpumask *later_mask);
void cpudl_set(struct cpudl *cp, int cpu, u64 dl);
void cpudl_clear(struct cpudl *cp, int cpu);
int  cpudl_init(struct cpudl *cp);
void cpudl_set_freecpu(struct cpudl *cp, int cpu);
void cpudl_clear_freecpu(struct cpudl *cp, int cpu);
void cpudl_cleanup(struct cpudl *cp);
#endif /* CONFIG_SMP */
