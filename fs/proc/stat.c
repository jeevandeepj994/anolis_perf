// SPDX-License-Identifier: GPL-2.0
#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/irqnr.h>
#include <linux/sched/cputime.h>
#include <linux/tick.h>
#include <linux/cpuset.h>
#include <linux/pid_namespace.h>

#ifndef arch_irq_stat_cpu
#define arch_irq_stat_cpu(cpu) 0
#endif
#ifndef arch_irq_stat
#define arch_irq_stat() 0
#endif

u64 get_idle_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 idle, idle_usecs = -1ULL;

	if (cpu_online(cpu))
		idle_usecs = get_cpu_idle_time_us(cpu, NULL);

	if (idle_usecs == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.idle */
		idle = kcs->cpustat[CPUTIME_IDLE];
	else
		idle = idle_usecs * NSEC_PER_USEC;

	return idle;
}

u64 get_iowait_time(struct kernel_cpustat *kcs, int cpu)
{
	u64 iowait, iowait_usecs = -1ULL;

	if (cpu_online(cpu))
		iowait_usecs = get_cpu_iowait_time_us(cpu, NULL);

	if (iowait_usecs == -1ULL)
		/* !NO_HZ or cpu offline so we can rely on cpustat.iowait */
		iowait = kcs->cpustat[CPUTIME_IOWAIT];
	else
		iowait = iowait_usecs * NSEC_PER_USEC;

	return iowait;
}

static void show_irq_gap(struct seq_file *p, unsigned int gap)
{
	static const char zeros[] = " 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

	while (gap > 0) {
		unsigned int inc;

		inc = min_t(unsigned int, gap, ARRAY_SIZE(zeros) / 2);
		seq_write(p, zeros, 2 * inc);
		gap -= inc;
	}
}

static void show_all_irqs(struct seq_file *p)
{
	unsigned int i, next = 0;

	for_each_active_irq(i) {
		show_irq_gap(p, i - next);
		seq_put_decimal_ull(p, " ", kstat_irqs_usr(i));
		next = i + 1;
	}
	show_irq_gap(p, nr_irqs - next);
}

static int show_stat(struct seq_file *p, void *v)
{
	int i, j, seq = 0;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	u64 sum = 0;
	u64 sum_softirq = 0;
	unsigned int per_softirq_sums[NR_SOFTIRQS] = {0};
	struct timespec64 boottime;
	struct cpumask cpuset_allowed;
	unsigned int nr_runnable = 0;
	struct task_struct *init_tsk = NULL;
	struct cpuacct_usage_result res;
	enum rich_container_source from;
	bool rich_container;

	user = nice = system = idle = iowait =
		irq = softirq = steal = 0;
	guest = guest_nice = 0;
	getboottime64(&boottime);
	/* shift boot timestamp according to the timens offset */
	timens_sub_boottime(&boottime);

	rcu_read_lock();
	rich_container = in_rich_container(current);
	if (rich_container) {
		/* fix btime in containers */
		read_lock(&tasklist_lock);
		init_tsk = task_active_pid_ns(current)->child_reaper;
		get_task_struct(init_tsk);
		read_unlock(&tasklist_lock);
		boottime.tv_sec += init_tsk->start_time / NSEC_PER_SEC;

		rich_container_get_cpuset_cpus(&cpuset_allowed);
		rich_container_source(&from);
		for_each_cpu(i, &cpuset_allowed) {
			rich_container_get_usage(from, init_tsk, i, &res);
			user += res.user;
			nice += res.nice;
			system += res.system;
			idle += res.idle;
			iowait += res.iowait;
			irq += res.irq;
			softirq += res.softirq;
			steal += res.steal;
			guest += res.guest;
			guest_nice += res.guest_nice;
		}
	} else {
		for_each_possible_cpu(i) {
			struct kernel_cpustat kcpustat;
			u64 *cpustat = kcpustat.cpustat;

			kcpustat_cpu_fetch(&kcpustat, i);

			user            += cpustat[CPUTIME_USER];
			nice            += cpustat[CPUTIME_NICE];
			system          += cpustat[CPUTIME_SYSTEM];
			idle            += get_idle_time(&kcpustat, i);
			iowait          += get_iowait_time(&kcpustat, i);
			irq             += cpustat[CPUTIME_IRQ];
			softirq         += cpustat[CPUTIME_SOFTIRQ];
			steal           += cpustat[CPUTIME_STEAL];
			guest           += cpustat[CPUTIME_GUEST];
			guest_nice      += cpustat[CPUTIME_GUEST_NICE];
		}
	}
	rcu_read_unlock();

	for_each_possible_cpu(i) {
		sum += kstat_cpu_irqs_sum(i);
		sum += arch_irq_stat_cpu(i);

		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			per_softirq_sums[j] += softirq_stat;
			sum_softirq += softirq_stat;
		}
	}
	sum += arch_irq_stat();

	seq_put_decimal_ull(p, "cpu  ", nsec_to_clock_t(user));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(nice));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(system));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(idle));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(iowait));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(irq));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(softirq));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(steal));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest));
	seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest_nice));
	seq_putc(p, '\n');

	rcu_read_lock();
	if (rich_container) {
		for_each_cpu(i, &cpuset_allowed) {
			rich_container_get_usage(from, init_tsk, i, &res);

			seq_printf(p, "cpu%d", seq++);
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.user));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.nice));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.system));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.idle));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.iowait));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.irq));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.softirq));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.steal));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.guest));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(res.guest_nice));
			seq_putc(p, '\n');
		}
	} else {
		for_each_online_cpu(i) {
			struct kernel_cpustat kcpustat;
			u64 *cpustat = kcpustat.cpustat;

			kcpustat_cpu_fetch(&kcpustat, i);

			/* Copy values here to work around gcc-2.95.3, gcc-2.96 */
			user            = cpustat[CPUTIME_USER];
			nice            = cpustat[CPUTIME_NICE];
			system          = cpustat[CPUTIME_SYSTEM];
			idle            = get_idle_time(&kcpustat, i);
			iowait          = get_iowait_time(&kcpustat, i);
			irq             = cpustat[CPUTIME_IRQ];
			softirq         = cpustat[CPUTIME_SOFTIRQ];
			steal           = cpustat[CPUTIME_STEAL];
			guest           = cpustat[CPUTIME_GUEST];
			guest_nice      = cpustat[CPUTIME_GUEST_NICE];

			seq_printf(p, "cpu%d", i);
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(user));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(nice));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(system));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(idle));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(iowait));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(irq));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(softirq));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(steal));
			seq_put_decimal_ull(p, " ", nsec_to_clock_t(guest));
			seq_put_decimal_ull(p, " ",
					nsec_to_clock_t(guest_nice));
			seq_putc(p, '\n');
		}
	}
	rcu_read_unlock();

	seq_put_decimal_ull(p, "intr ", (unsigned long long)sum);

	show_all_irqs(p);

	rcu_read_lock();
	if (rich_container) {
		for_each_cpu(i, &cpuset_allowed)
			nr_runnable += rich_container_get_running(from, init_tsk, i);
	} else
		nr_runnable = nr_running();
	rcu_read_unlock();

	if (rich_container)
		put_task_struct(init_tsk);

	seq_printf(p,
		"\nctxt %llu\n"
		"btime %llu\n"
		"processes %lu\n"
		"procs_running %u\n"
		"procs_blocked %u\n",
		nr_context_switches(),
		(unsigned long long)boottime.tv_sec,
		total_forks,
		nr_runnable,
		nr_iowait());

	seq_put_decimal_ull(p, "softirq ", (unsigned long long)sum_softirq);

	for (i = 0; i < NR_SOFTIRQS; i++)
		seq_put_decimal_ull(p, " ", per_softirq_sums[i]);
	seq_putc(p, '\n');

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	unsigned int size = 1024 + 128 * num_online_cpus();

	/* minimum size to display an interrupt count : 2 bytes */
	size += 2 * nr_irqs;
	return single_open_size(file, show_stat, NULL, size);
}

static const struct proc_ops stat_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= stat_open,
	.proc_read_iter	= seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init proc_stat_init(void)
{
	proc_create("stat", 0, NULL, &stat_proc_ops);
	return 0;
}
fs_initcall(proc_stat_init);
