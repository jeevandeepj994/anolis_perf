/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PID_NS_H
#define _LINUX_PID_NS_H

#include <linux/sched.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
#include <linux/threads.h>
#include <linux/nsproxy.h>
#include <linux/kref.h>
#include <linux/ns_common.h>
#include <linux/idr.h>

/* MAX_PID_NS_LEVEL is needed for limiting size of 'struct pid' */
#define MAX_PID_NS_LEVEL 32

struct fs_pin;

struct pid_namespace {
	struct kref kref;
	struct idr idr;
	struct rcu_head rcu;
#ifdef CONFIG_MAX_PID_PER_NS
	int pid_max;
#endif
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
#ifdef CONFIG_BSD_PROCESS_ACCT
	struct fs_pin *bacct;
#endif
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;	/* group exit code if this pidns was rebooted */
	struct ns_common ns;
} __randomize_layout;

extern struct pid_namespace init_pid_ns;

#define PIDNS_ADDING (1U << 31)

#ifdef CONFIG_PID_NS
static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	if (ns != &init_pid_ns)
		kref_get(&ns->kref);
	return ns;
}

extern struct pid_namespace *copy_pid_ns(unsigned long flags,
	struct user_namespace *user_ns, struct pid_namespace *ns);
extern void zap_pid_ns_processes(struct pid_namespace *pid_ns);
extern int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd);
extern void put_pid_ns(struct pid_namespace *ns);

#else /* !CONFIG_PID_NS */
#include <linux/err.h>

static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	return ns;
}

static inline struct pid_namespace *copy_pid_ns(unsigned long flags,
	struct user_namespace *user_ns, struct pid_namespace *ns)
{
	if (flags & CLONE_NEWPID)
		ns = ERR_PTR(-EINVAL);
	return ns;
}

static inline void put_pid_ns(struct pid_namespace *ns)
{
}

static inline void zap_pid_ns_processes(struct pid_namespace *ns)
{
	BUG();
}

static inline int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	return 0;
}
#endif /* CONFIG_PID_NS */

extern struct pid_namespace *task_active_pid_ns(struct task_struct *tsk);
void pidhash_init(void);
void pid_idr_init(void);

struct rich_container_feature {
	const char *name;
	int id;
};

enum rc_feature_id {
	RC_CPUINFO,
	RC_MEMINFO,
	RC_CPUUSAGE,
	RC_UPTIME,
	RC_LOADAVG,
	RC_DISKQUOTA,
	RC_FEATURE_COUNT,
};

#ifdef CONFIG_RICH_CONTAINER
extern int sysctl_rich_container_enable;
extern u16 rc_feature_disable_mask;
extern int rich_container_feature_control_handler(struct ctl_table *ro_table,
						  int write, void *buffer,
						  size_t *lenp, loff_t *ppos);
#ifndef CONFIG_SCHEDSTATS_HOST
extern bool __sched_schedstats;
#endif
#ifndef CONFIG_RICH_CONTAINER_CG_SWITCH
extern int sysctl_rich_container_source;
extern int sysctl_rich_container_cpuinfo_source;
extern unsigned int sysctl_rich_container_cpuinfo_sharesbase;

static inline struct task_struct *rich_container_get_scenario(void)
{
	if (sysctl_rich_container_source == 1)
		return task_active_pid_ns(current)->child_reaper;

	return current;
}
#endif
static inline bool in_rich_container(struct task_struct *tsk,
				     enum rc_feature_id id)
{
	if (sysctl_rich_container_enable == 0)
		return false;

	return (task_active_pid_ns(tsk) != &init_pid_ns) && child_cpuacct(tsk)
		&& !(rc_feature_disable_mask & (1 << id));
}

void rich_container_get_cpuset_cpus(struct cpumask *pmask);
#else
static inline bool in_rich_container(struct task_struct *tsk,
				     enum rc_feature_id id)
{
	return false;
}

static inline void rich_container_get_cpuset_cpus(struct cpumask *pmask)
{
}

static inline struct task_struct *rich_container_get_scenario(void)
{
	return NULL;
}
#endif
static inline bool task_is_in_init_pid_ns(struct task_struct *tsk)
{
	return task_active_pid_ns(tsk) == &init_pid_ns;
}

#endif /* _LINUX_PID_NS_H */
