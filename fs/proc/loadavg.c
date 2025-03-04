// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/cpuset.h>
#include "internal.h"

static int loadavg_proc_show(struct seq_file *m, void *v)
{
	unsigned long avnrun[3];
	unsigned int nr_R = 0;
	struct cpumask cpuset_allowed;
	int i;

	rcu_read_lock();
	if (in_rich_container(current)) {
		struct task_struct *init_tsk;
		enum rich_container_source from;

		read_lock(&tasklist_lock);
		init_tsk = task_active_pid_ns(current)->child_reaper;
		get_task_struct(init_tsk);
		read_unlock(&tasklist_lock);

		rich_container_source(&from);
		rich_container_get_avenrun(from, init_tsk, avnrun, FIXED_1/200, 0, false);
		rich_container_get_cpuset_cpus(&cpuset_allowed);
		for_each_cpu(i, &cpuset_allowed)
			nr_R += rich_container_get_running(from, init_tsk, i);
		put_task_struct(init_tsk);
	} else {
		get_avenrun(avnrun, FIXED_1/200, 0);
		nr_R = nr_running();
	}
	rcu_read_unlock();

	seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %u/%d %d\n",
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
		nr_R, nr_threads,
		idr_get_cursor(&task_active_pid_ns(current)->idr) - 1);
	return 0;
}

static int __init proc_loadavg_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create_single("loadavg", 0, NULL, loadavg_proc_show);
	pde_make_permanent(pde);
	return 0;
}
fs_initcall(proc_loadavg_init);
