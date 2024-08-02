// SPDX-License-Identifier: GPL-2.0
/*
 * Group Balancer
 *
 * Group Balancer sched domains define and build
 * Copyright (C) 2024 Alibaba Group, Inc., Cruz Zhao <CruzZhao@linux.alibaba.com>
 */
#include "sched.h"
#include <linux/log2.h>
#include <linux/fs_context.h>

struct group_balancer_sched_domain {
	struct group_balancer_sched_domain		*parent;
	struct list_head				child;
	struct list_head				sibling;
	struct list_head				topology_level_sibling;
	struct list_head				size_level_sibling;
	unsigned long					gb_flags;
	char						*topology_name;
	unsigned int					span_weight;
	unsigned int					nr_children;
	struct kernfs_node				*kn;
	unsigned long					span[];
};

/* The topology that group balancer cares about. */
enum GROUP_BALANCER_TOPOLOGY {
	GROUP_BALANCER_ROOT,
	GROUP_BALANCER_SOCKET,
#ifdef CONFIG_NUMA
	GROUP_BALANCER_NUMA,
#endif
	GROUP_BALANCER_DIE,
	GROUP_BALANCER_LLC,
#ifdef CONFIG_SCHED_MC
	GROUP_BALANCER_MC,
#endif
#ifdef CONFIG_SCHED_CLUSTER
	GROUP_BALANCER_CLUSTER,
#endif
#ifdef CONFIG_SCHED_SMT
	GROUP_BALANCER_SMT,
#endif
	NR_GROUP_BALANCER_TOPOLOGY,
};

enum GROUP_BALANCER_TOPOLOGY_FLAGS {
	GROUP_BALANCER_ROOT_FLAG	= BIT(GROUP_BALANCER_ROOT),
	GROUP_BALANCER_SOCKET_FLAG	= BIT(GROUP_BALANCER_SOCKET),
#ifdef CONFIG_NUMA
	GROUP_BALANCER_NUMA_FLAG	= BIT(GROUP_BALANCER_NUMA),
#endif
	GROUP_BALANCER_DIE_FLAG		= BIT(GROUP_BALANCER_DIE),
	GROUP_BALANCER_LLC_FLAG		= BIT(GROUP_BALANCER_LLC),
#ifdef CONFIG_SCHED_MC
	GROUP_BALANCER_MC_FLAG		= BIT(GROUP_BALANCER_MC),
#endif
#ifdef CONFIG_SCHED_CLUSTER
	GROUP_BALANCER_CLUSTER_FLAG	= BIT(GROUP_BALANCER_CLUSTER),
#endif
#ifdef CONFIG_SCHED_SMT
	GROUP_BALANCER_SMT_FLAG		= BIT(GROUP_BALANCER_SMT),
#endif
};

struct group_balancer_topology_level {
	sched_domain_mask_f	mask;
	sched_domain_flags_f	sd_flags;
	unsigned long		gb_flags;
	char			*topology_name;
	struct list_head	domains;
	bool			skip;
};

struct group_balancer_size_level {
	int			size;
	/* Use list temporarily, we will change to use rb_tree later.*/
	struct list_head	domains;
};

LIST_HEAD(group_balancer_sched_domains);

DEFINE_RWLOCK(group_balancer_sched_domain_lock);

struct cpumask root_cpumask;

static struct kernfs_root *group_balancer_fs_root;
static struct kernfs_node *group_balancer_fs_root_kn;
struct group_balancer_fs_context {
	struct kernfs_fs_context	kfc;
	void				*tmp;
};

struct gftype {
	char			*name;
	umode_t			mode;
	const struct kernfs_ops	*kf_ops;
	int (*seq_show)(struct kernfs_open_file *of,
			struct seq_file *sf, void *v);
	ssize_t (*write)(struct kernfs_open_file *of,
			 char *buf, size_t nbytes, loff_t off);
};

const struct cpumask *cpu_llc_mask(int cpu)
{
	struct sched_domain *llc = rcu_dereference(per_cpu(sd_llc, cpu));

	return (const struct cpumask *)to_cpumask(llc->span);
}

const struct cpumask *cpu_die_mask(int cpu)
{
	return topology_die_cpumask(cpu);
}

const struct cpumask *cpu_core_mask(int cpu)
{
	return topology_core_cpumask(cpu);
}

const struct cpumask *cpu_root_mask(int cpu)
{
	return (const struct cpumask *)&root_cpumask;
}

#define GB_SD_INIT(type) \
	.gb_flags = GROUP_BALANCER_##type##_FLAG, \
	.topology_name = #type
/*
 * Group Balancer build group_balancer_sched_domains after kernel init,
 * so the following cpumask can be got safely.
 *
 * smt mask:		cpu_smt_mask
 * cluster mask:	cpu_clustergroup_mask
 * mc mask:		cpu_coregroup_mask
 * llc mask:		cpu_llc_mask
 * die mask:		cpu_die_mask
 * numa mask:		cpu_cpu_mask
 * socket mask:		cpu_core_mask
 * all mask:		cpu_root_mask
 */
static struct group_balancer_topology_level default_topology[] = {
	{ cpu_root_mask, GB_SD_INIT(ROOT) },
	{ cpu_core_mask, GB_SD_INIT(SOCKET) },
#ifdef CONFIG_NUMA
	{ cpu_cpu_mask, GB_SD_INIT(NUMA) },
#endif
	{ cpu_die_mask, GB_SD_INIT(DIE) },
	{ cpu_llc_mask, GB_SD_INIT(LLC) },
#ifdef CONFIG_SCHED_MC
	{ cpu_coregroup_mask, cpu_core_flags, GB_SD_INIT(MC) },
#endif
#ifdef CONFIG_SCHED_CLUSTER
	{ cpu_clustergroup_mask, cpu_cluster_flags, GB_SD_INIT(CLUSTER) },
#endif
#ifdef CONFIG_SCHED_SMT
	{ cpu_smt_mask, cpu_smt_flags, GB_SD_INIT(SMT) },
#endif
	{ NULL, },
};

#define for_each_gb_topology_level(tl)			\
	for (tl = default_topology; tl->mask; tl++)

#define for_each_topology_level_sibling(pos, gb_tl)	\
	list_for_each_entry(pos, &gb_tl->domains, topology_level_sibling)

#define for_each_topology_level_sibling_safe(pos, n, gb_tl)	\
	list_for_each_entry_safe(pos, n, &gb_tl->domains, topology_level_sibling)

/* NR_CPUS is 1024 now, we set log(1024) + 1 = 11 levels. */
#define NR_SIZE_LEVELS 11
struct group_balancer_size_level default_size[NR_SIZE_LEVELS];

#define for_each_gb_size_level(sl, i)			\
	for (sl = default_size, i = 0; i < NR_SIZE_LEVELS; sl++, i++)

#define for_each_gb_sd_child(pos, gb_sd)			\
	list_for_each_entry(pos, &gb_sd->child, sibling)

#define for_each_gb_sd_child_safe(pos, n, gb_sd)			\
	list_for_each_entry_safe(pos, n, &gb_sd->child, sibling)

#define group_balancer_sched_domain_first_child(gb_sd)		\
	list_first_entry(&gb_sd->child, struct group_balancer_sched_domain, sibling)

struct group_balancer_sched_domain *group_balancer_root_domain;

#define MAX_NAME_LEN		128

static inline struct cpumask *gb_sd_span(struct group_balancer_sched_domain *gb_sd)
{
	return to_cpumask(gb_sd->span);
}

static unsigned int get_size_level(struct group_balancer_sched_domain *gb_sd)
{
	int size_level = ilog2(gb_sd->span_weight);

	/* Prevent out-of-bound array access. */
	if (unlikely(size_level < 0))
		size_level = 0;
	else if (unlikely(size_level >= NR_SIZE_LEVELS))
		size_level = NR_SIZE_LEVELS - 1;

	return (unsigned int)size_level;
}

static void __add_to_size_level(struct group_balancer_sched_domain *gb_sd,
				unsigned int size_level)
{
	struct group_balancer_size_level *gb_sl;

	gb_sl = &default_size[size_level];
	list_add_tail(&gb_sd->size_level_sibling, &gb_sl->domains);
}

static void add_to_size_level(struct group_balancer_sched_domain *gb_sd)
{
	unsigned int size_level = get_size_level(gb_sd);

	__add_to_size_level(gb_sd, size_level);
}

static int group_balancer_seqfile_show(struct seq_file *m, void *arg)
{
	struct kernfs_open_file *of = m->private;
	struct gftype *gft = of->kn->priv;

	if (gft->seq_show)
		return gft->seq_show(of, m, arg);
	return 0;
}

static ssize_t group_balancer_file_write(struct kernfs_open_file *of, char *buf,
					 size_t nbytes, loff_t off)
{
	struct gftype *gft = of->kn->priv;

	if (gft->write)
		return gft->write(of, buf, nbytes, off);

	return -EINVAL;
}

static const struct kernfs_ops group_balancer_kf_single_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.write			= group_balancer_file_write,
	.seq_show		= group_balancer_seqfile_show,
};

struct group_balancer_sched_domain *kernfs_to_gb_sd(struct kernfs_node *kn)
{
	if (kernfs_type(kn) == KERNFS_DIR)
		return kn->priv;
	else
		return kn->parent->priv;
}

struct group_balancer_sched_domain *group_balancer_kn_lock_live(struct kernfs_node *kn)
{
	struct group_balancer_sched_domain *gb_sd = kernfs_to_gb_sd(kn);

	if (!gb_sd)
		return NULL;

	kernfs_break_active_protection(kn);
	cpus_read_lock();
	write_lock(&group_balancer_sched_domain_lock);

	return gb_sd;
}

void group_balancer_kn_unlock(struct kernfs_node *kn)
{
	struct group_balancer_sched_domain *gb_sd = kernfs_to_gb_sd(kn);

	if (!gb_sd)
		return;

	write_unlock(&group_balancer_sched_domain_lock);
	cpus_read_unlock();
	kernfs_unbreak_active_protection(kn);
}

static ssize_t group_balancer_cpus_write(struct kernfs_open_file *of,
					 char *buf, size_t nbytes, loff_t off)
{
	cpumask_var_t new, tmp;
	int cpu;
	struct rq *rq;
	struct group_balancer_sched_domain *gb_sd, *parent, *sibling, *child;
	int old_size_level, new_size_level;
	int ret = 0;

	if (!buf)
		return -EINVAL;
	if (!zalloc_cpumask_var(&new, GFP_KERNEL))
		return -ENOMEM;
	if (!zalloc_cpumask_var(&tmp, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_new;
	}

	gb_sd = group_balancer_kn_lock_live(of->kn);
	if (!gb_sd) {
		ret = -ENOENT;
		goto unlock;
	}

	ret = cpulist_parse(buf, new);
	if (ret) {
		ret = -EINVAL;
		goto unlock;
	}

	if (cpumask_equal(new, gb_sd_span(gb_sd)))
		goto unlock;

	parent = gb_sd->parent;
	if (parent) {
		/* New mask must be subset of parent.*/
		if (!cpumask_subset(new, gb_sd_span(parent))) {
			ret = -EINVAL;
			goto unlock;
		}

		/* New mask must not inersect with siblings. */
		for_each_gb_sd_child(sibling, parent) {
			if (gb_sd == sibling)
				continue;
			if (cpumask_intersects(new, gb_sd_span(sibling))) {
				ret = -EINVAL;
				goto unlock;
			}
		}
	}

	/* New mask must include all the cpus of the children. */
	for_each_gb_sd_child(child, gb_sd) {
		if (!cpumask_subset(gb_sd_span(child), new)) {
			ret = -EINVAL;
			goto unlock;
		}
	}

	/*
	 * rq->gb_sd points to the lowest level group_balancer_sched_domain
	 * that includes the cpu.
	 *
	 * We define two types of cpumask here: 'less' and 'more'.
	 * - 'less' is the cpus that new cpumask lacks.
	 * - 'more' is the cpus that new cpumask newly adds.
	 *
	 * As the cpus of a child must be subset of its parent, the cpus in
	 * 'less' and 'more' are not included by any child of gb_sd, and the
	 * lowest level group_balancer_sched_domain that includes 'less' is
	 * the parent of gb_sd, the lowest level group_balancer_sched_domain
	 * that includes 'more' is gb_sd.
	 *
	 * So we need to set the rq->gb_sd of the cpus in 'less' to parent.
	 * and set the rq->gb_sd of the cpus in 'more' to gb_sd.
	 */
	cpumask_andnot(tmp, gb_sd_span(gb_sd), new);
	for_each_cpu(cpu, tmp) {
		rq = cpu_rq(cpu);
		rq->gb_sd = parent;
	}

	cpumask_andnot(tmp, new, gb_sd_span(gb_sd));
	for_each_cpu(cpu, tmp) {
		rq = cpu_rq(cpu);
		rq->gb_sd = gb_sd;
	}

	old_size_level = get_size_level(gb_sd);
	cpumask_copy(gb_sd_span(gb_sd), new);
	gb_sd->span_weight = cpumask_weight(gb_sd_span(gb_sd));
	new_size_level = get_size_level(gb_sd);
	if (old_size_level != new_size_level) {
		list_del(&gb_sd->size_level_sibling);
		__add_to_size_level(gb_sd, new_size_level);
	}
	if (gb_sd == group_balancer_root_domain)
		cpumask_copy(&root_cpumask, new);

unlock:
	group_balancer_kn_unlock(of->kn);
	free_cpumask_var(tmp);
free_new:
	free_cpumask_var(new);

	return ret ?: nbytes;
}

static int group_balancer_cpus_show(struct kernfs_open_file *of,
				    struct seq_file *s, void *v)
{
	struct group_balancer_sched_domain *gb_sd;
	int ret = 0;

	gb_sd = group_balancer_kn_lock_live(of->kn);

	if (!gb_sd) {
		ret = -ENOENT;
		goto unlock;
	}

	seq_printf(s, "%*pbl\n", cpumask_pr_args(gb_sd_span(gb_sd)));
unlock:
	group_balancer_kn_unlock(of->kn);
	return ret;
}

static struct gftype group_balancer_files[] = {
	{
		.name		= "cpus",
		.mode		= 0644,
		.kf_ops		= &group_balancer_kf_single_ops,
		.write		= group_balancer_cpus_write,
		.seq_show	= group_balancer_cpus_show,
	},
};

static int group_balancer_kn_set_ugid(struct kernfs_node *kn)
{
	struct iattr iattr = { .ia_valid = ATTR_UID | ATTR_GID,
				.ia_uid = current_fsuid(),
				.ia_gid = current_fsgid(), };

	if (uid_eq(iattr.ia_uid, GLOBAL_ROOT_UID) &&
	    gid_eq(iattr.ia_gid, GLOBAL_ROOT_GID))
		return 0;

	return kernfs_setattr(kn, &iattr);
}

static int group_balancer_add_file(struct kernfs_node *parent_kn, struct gftype *gft)
{
	struct kernfs_node *kn;
	int ret;

	kn = __kernfs_create_file(parent_kn, gft->name, gft->mode,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  gft->kf_ops, gft, NULL, NULL);

	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = group_balancer_kn_set_ugid(kn);
	if (ret) {
		kernfs_remove(kn);
		return ret;
	}

	return ret;
}

static int group_balancer_add_files(struct kernfs_node *kn)
{
	struct gftype *gfts, *gft;
	int ret, len;

	gfts = group_balancer_files;
	len = ARRAY_SIZE(group_balancer_files);

	for (gft = gfts; gft < gfts + len; gft++) {
		ret = group_balancer_add_file(kn, gft);
		if (ret)
			goto err;
	}

	return 0;
err:
	pr_err("Group Balancer: Failed to add sysfs file %s, err=%d\n", gft->name, ret);
	while (--gft >= gfts)
		kernfs_remove_by_name(kn, gft->name);

	return ret;
}

static inline struct group_balancer_sched_domain
*alloc_init_group_balancer_sched_domain(struct kernfs_node *parent, const char *name, umode_t mode)
{
	struct group_balancer_sched_domain *new, *ret;
	struct kernfs_node *kn;
	int retval;

	if (!parent) {
		ret = ERR_PTR(-ENOENT);
		goto err_out;
	}

	new = kzalloc(sizeof(struct group_balancer_sched_domain) + cpumask_size(), GFP_KERNEL);
	if (!new) {
		ret = ERR_PTR(-ENOMEM);
		goto err_out;
	}

	kn = kernfs_create_dir(parent, name, mode, new);
	if (IS_ERR(kn)) {
		ret = (struct group_balancer_sched_domain *)kn;
		goto free_new;
	}
	new->kn = kn;

	retval = group_balancer_add_files(kn);
	if (retval) {
		ret = ERR_PTR(retval);
		goto remove_kn;
	}

	INIT_LIST_HEAD(&new->child);
	INIT_LIST_HEAD(&new->sibling);
	INIT_LIST_HEAD(&new->topology_level_sibling);
	INIT_LIST_HEAD(&new->size_level_sibling);

	return new;
remove_kn:
	kernfs_remove(kn);
free_new:
	kfree(new);
err_out:
	pr_err("Group Balancer: Failed to allocate and init a new group balancer sched domain.\n");
	return ret;
}

static void add_to_tree(struct group_balancer_sched_domain *gb_sd,
			struct group_balancer_sched_domain *parent)
{
	int cpu;
	struct rq *rq;

	if (parent) {
		list_add_tail(&gb_sd->sibling, &parent->child);
		gb_sd->parent = parent;
		parent->nr_children++;
	}
	gb_sd->span_weight = cpumask_weight(gb_sd_span(gb_sd));
	add_to_size_level(gb_sd);

	if (!gb_sd->nr_children) {
		for_each_cpu(cpu, gb_sd_span(gb_sd)) {
			rq = cpu_rq(cpu);
			rq->gb_sd = gb_sd;
		}
	}
}

static void free_group_balancer_sched_domain(struct group_balancer_sched_domain *gb_sd)
{
	int cpu;
	struct rq *rq;

	if (gb_sd->parent)
		gb_sd->parent->nr_children--;

	list_del(&gb_sd->sibling);
	list_del(&gb_sd->topology_level_sibling);
	list_del(&gb_sd->size_level_sibling);

	if (!gb_sd->nr_children) {
		for_each_cpu(cpu, gb_sd_span(gb_sd)) {
			rq = cpu_rq(cpu);
			rq->gb_sd = gb_sd->parent;
		}
	}

	if (gb_sd->kn)
		kernfs_remove(gb_sd->kn);

	kfree(gb_sd);
}

/* free group balancer sched domain tree from the leaf nodes. */
static void free_group_balancer_sched_domains(void)
{
	struct group_balancer_sched_domain *parent, *child, *ancestor, *n;

	parent = group_balancer_root_domain;
down:
	for_each_gb_sd_child_safe(child, n, parent) {
		parent = child;
		goto down;
up:
		continue;
	}

	ancestor = parent->parent;
	/* root domain should always be in memory. */
	if (parent != group_balancer_root_domain && !parent->nr_children) {
		n = list_next_entry(parent, sibling);
		free_group_balancer_sched_domain(parent);
	}

	child = n;
	parent = ancestor;
	if (parent)
		goto up;
}

static int move_group_balancer_kernfs(struct group_balancer_sched_domain *gb_sd,
				      struct group_balancer_sched_domain *new_parent)
{
	char *new_name = NULL;
	int id = new_parent->nr_children;
	int ret = 0;

	if (!gb_sd->kn || !new_parent->kn)
		return -ENOMEM;

	new_name = kmalloc(MAX_NAME_LEN, GFP_KERNEL);
	if (!new_name)
		return -ENOMEM;
	/*
	 * We use domain+id as new name, and if the name is already occupied, we let id++,
	 * until we find an unoccupied name.
	 */
	for (;;) {
		struct kernfs_node *dup;

		sprintf(new_name, "domain%d", id);
		dup = kernfs_find_and_get(new_parent->kn, new_name);
		if (!dup)
			break;
		kernfs_put(dup);
		id++;
	}

	ret = kernfs_rename(gb_sd->kn, new_parent->kn, new_name);
	kfree(new_name);

	return ret;
}

static int move_group_balancer_sched_domain(struct group_balancer_sched_domain *child,
					    struct group_balancer_sched_domain *new_parent,
					    bool *is_first_child)
{
	int ret = 0;

	ret = move_group_balancer_kernfs(child, new_parent);
	if (ret)
		return ret;

	if (*is_first_child) {
		*is_first_child = false;
		new_parent->topology_name = child->topology_name;
		new_parent->gb_flags = child->gb_flags;
	}
	cpumask_or(gb_sd_span(new_parent), gb_sd_span(child), gb_sd_span(new_parent));
	list_del(&child->sibling);
	child->parent->nr_children--;
	list_add_tail(&child->sibling, &new_parent->child);
	new_parent->nr_children++;
	child->parent = new_parent;

	return ret;
}

static int bi_divide_group_balancer_sched_domain(struct group_balancer_sched_domain *gb_sd)
{
	unsigned int weight = gb_sd->span_weight;
	unsigned int half = (weight + 1) / 2;
	unsigned int logn = ilog2(half);
	/*
	 * Find the power of 2 closest to half, and use this number
	 * to split weight into two parts, left and right, and keep
	 * left always the smaller one.
	 */
	unsigned int left = (half - (1 << logn) < (1 << (logn + 1)) - half) ?
			    1 << logn : weight - (1 << (logn + 1));
	bool is_first_child = true;
	struct group_balancer_sched_domain *child, *n;
	struct group_balancer_sched_domain *left_middle, *right_middle;
	int ret = 0;

	/*
	 * If a domain has more than two children, we add a middle level.
	 * For example, if a domain spans 48 cpus and 24 children, we add
	 * a middle level first, which contains two children who span 16
	 * and 32 cpus. And we will divide the new children in the next
	 * loop.
	 *
	 * As for the size of middle level dividing, we choose powers of
	 * two instead of half of span_weight, to make the division of
	 * lower levels simpler.
	 */
	if (gb_sd->nr_children > 2) {
		left_middle = alloc_init_group_balancer_sched_domain(gb_sd->kn,
								     "left", 0);
		if (IS_ERR(left_middle)) {
			ret = PTR_ERR(left_middle);
			goto err;
		}

		right_middle = alloc_init_group_balancer_sched_domain(gb_sd->kn,
								      "right", 0);
		if (IS_ERR(right_middle)) {
			ret = PTR_ERR(right_middle);
			goto free_left_middle;
		}

		for_each_gb_sd_child_safe(child, n, gb_sd) {
			/*
			 * Consider the following case, a domain spans 6
			 * cpus and 3 chidlren(each child spans 2 cpus),
			 * we just need to add right middle which spans 4
			 * cpus.
			 */
			ret = move_group_balancer_sched_domain(child, left_middle,
							       &is_first_child);
			if (ret)
				goto free_right_middle;

			if (cpumask_weight(gb_sd_span(left_middle)) >= left)
				break;
		}

		/*
		 * As left is always the smaller one, it is possible that
		 * left has only one child, if so, we delete the child.
		 */
		if (left_middle->nr_children == 1) {
			child = group_balancer_sched_domain_first_child(left_middle);
			free_group_balancer_sched_domain(child);
		}

		is_first_child = true;
		for_each_gb_sd_child_safe(child, n, gb_sd) {
			ret = move_group_balancer_sched_domain(child, right_middle,
							       &is_first_child);
			if (ret)
				goto free_right_middle;
		}

		add_to_tree(left_middle, gb_sd);
		add_to_tree(right_middle, gb_sd);
		/* Uniform naming format. "left" and "right" are temporary name. */
		ret = kernfs_rename(left_middle->kn, gb_sd->kn, "domain0");
		if (ret)
			goto err;
		ret = kernfs_rename(right_middle->kn, gb_sd->kn, "domain1");
		if (ret)
			goto err;
	}

	return 0;
free_right_middle:
	free_group_balancer_sched_domain(right_middle);
free_left_middle:
	free_group_balancer_sched_domain(left_middle);
err:
	free_group_balancer_sched_domains();
	return ret;
}

/* DFS to bi-divide group balancer sched domains. */
static int bi_divide_group_balancer_sched_domains(void)
{
	struct group_balancer_sched_domain *parent, *child;
	int ret = 0;

	/*
	 * Traverse all the domains from the group_balancer_sched_domains list,
	 * and add the new domains to the tail of the list, to ensure that all
	 * the domains will be traversed.
	 */
	parent = group_balancer_root_domain;
down:
	ret = bi_divide_group_balancer_sched_domain(parent);
	if (ret)
		goto out;
	for_each_gb_sd_child(child, parent) {
		parent = child;
		goto down;
up:
		continue;
	}
	if (parent == group_balancer_root_domain)
		goto out;

	child = parent;
	parent = parent->parent;
	if (parent)
		goto up;
out:
	return ret;
}

static int build_group_balancer_root_domain(void)
{
	struct group_balancer_sched_domain *root;

	root = alloc_init_group_balancer_sched_domain(group_balancer_fs_root_kn, "root_domain", 0);
	if (IS_ERR(root)) {
		pr_err("Group Balancer: Failed to alloc group_balancer root domain.\n");
		return PTR_ERR(root);
	}
	cpumask_copy(gb_sd_span(root), &root_cpumask);
	list_add_tail(&root->topology_level_sibling, &default_topology[0].domains);
	add_to_tree(root, NULL);
	group_balancer_root_domain = root;

	return 0;
}

/* BFS to build group balancer sched domain tree. */
static int build_group_balancer_sched_domains(void)
{
	int cpu;
	int ret;
	cpumask_var_t trial_cpumask, child_cpumask;
	struct group_balancer_topology_level *gb_tl, *next_gb_tl;
	struct group_balancer_sched_domain *parent, *n;
	char *name = NULL;

	/*
	 * The group balancer sched domain is a tree.
	 * If the root was not built on boot, build the root node first.
	 */
	if (unlikely(!group_balancer_root_domain)) {
		ret = build_group_balancer_root_domain();
		if (ret)
			goto err_out;
	}

	if (!zalloc_cpumask_var(&trial_cpumask, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto err_out;
	}
	if (!zalloc_cpumask_var(&child_cpumask, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto err_free_trial_cpumask;
	}

	name = kmalloc(MAX_NAME_LEN, GFP_KERNEL);
	if (!name) {
		ret = -ENOMEM;
		goto err_free_domains;
	}

	/* Build the tree by level. */
	for_each_gb_topology_level(gb_tl) {
		if (gb_tl->skip)
			continue;
		next_gb_tl = gb_tl + 1;
		while (next_gb_tl->skip && next_gb_tl->mask)
			next_gb_tl++;
		if (!next_gb_tl->mask)
			break;
		/* Build children from parent level. */
		for_each_topology_level_sibling_safe(parent, n, gb_tl) {
			/*
			 * If the cpumasks of the adjacent topology levels are the same,
			 * we move the domain to the next level, to make the loop
			 * continue.
			 */
			cpu = cpumask_first(gb_sd_span(parent));
			cpumask_and(child_cpumask, &root_cpumask, next_gb_tl->mask(cpu));
			if (cpumask_equal(gb_sd_span(parent), child_cpumask)) {
				list_del(&parent->topology_level_sibling);
				list_add_tail(&parent->topology_level_sibling,
					 &next_gb_tl->domains);
				parent->gb_flags &= next_gb_tl->gb_flags;
				continue;
			}
			cpumask_copy(trial_cpumask, gb_sd_span(parent));
			for_each_cpu(cpu, trial_cpumask) {
				struct group_balancer_sched_domain *child;

				cpumask_and(child_cpumask, &root_cpumask, next_gb_tl->mask(cpu));
				cpumask_andnot(trial_cpumask, trial_cpumask, child_cpumask);
				/*
				 * parent->nr_children is  a variable that only increases and never
				 * decreases at this stage. So if we use domain+nr_children as name,
				 * there will be no duplicate names.
				 */
				sprintf(name, "domain%d", parent->nr_children);
				child = alloc_init_group_balancer_sched_domain(parent->kn, name, 0);
				if (IS_ERR(child)) {
					ret = PTR_ERR(child);
					goto err_free_name;
				}
				cpumask_copy(gb_sd_span(child), child_cpumask);
				child->topology_name = next_gb_tl->topology_name;
				list_add_tail(&child->topology_level_sibling, &next_gb_tl->domains);
				child->gb_flags &= next_gb_tl->gb_flags;
				add_to_tree(child, parent);
			}
		}
	}

	kfree(name);
	free_cpumask_var(child_cpumask);
	free_cpumask_var(trial_cpumask);
	return bi_divide_group_balancer_sched_domains();

err_free_name:
	kfree(name);
err_free_domains:
	free_group_balancer_sched_domains();
	free_cpumask_var(child_cpumask);
err_free_trial_cpumask:
	free_cpumask_var(trial_cpumask);
err_out:
	return ret;
}

static inline struct group_balancer_fs_context *group_balancer_fc2context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc = fc->fs_private;

	return container_of(kfc, struct group_balancer_fs_context, kfc);
}


static int group_balancer_get_tree(struct fs_context *fc)
{

	return kernfs_get_tree(fc);
}

static void group_balancer_fs_context_free(struct fs_context *fc)
{
	struct group_balancer_fs_context *ctx = group_balancer_fc2context(fc);

	kernfs_free_fs_context(fc);
	kfree(ctx);
}

static const struct fs_context_operations group_balancer_context_ops = {
	.free			= group_balancer_fs_context_free,
	.get_tree		= group_balancer_get_tree,
};

static int group_balancer_init_fs_context(struct fs_context *fc)
{
	struct group_balancer_fs_context *ctx;

	ctx = kzalloc(sizeof(struct group_balancer_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->kfc.root = group_balancer_fs_root;
	ctx->kfc.magic = GROUP_BALANCER_MAGIC;
	fc->fs_private = &ctx->kfc;
	fc->ops = &group_balancer_context_ops;
	put_user_ns(fc->user_ns);
	fc->user_ns = get_user_ns(&init_user_ns);
	fc->global = true;
	return 0;
}

static void group_balancer_kill_sb(struct super_block *sb)
{
	kernfs_kill_sb(sb);
}

static struct file_system_type group_balancer_fs_type = {
	.name			= "group_balancer",
	.init_fs_context	= group_balancer_init_fs_context,
	.kill_sb		= group_balancer_kill_sb,
};

static int group_balancer_mkdir(struct kernfs_node *kn, const char *name, umode_t mode)
{
	struct group_balancer_sched_domain *new;
	struct group_balancer_sched_domain *parent = kernfs_to_gb_sd(kn);

	if (kn == group_balancer_fs_root_kn)
		return -EPERM;

	group_balancer_kn_lock_live(kn);
	new = alloc_init_group_balancer_sched_domain(kn, name, mode);
	add_to_tree(new, parent);
	group_balancer_kn_unlock(kn);
	if (IS_ERR(new))
		return PTR_ERR(new);

	return 0;
}

static int group_balancer_rmdir(struct kernfs_node *kn)
{
	struct group_balancer_sched_domain *gb_sd;
	int ret = 0;

	gb_sd = kn->priv;

	if (gb_sd == group_balancer_root_domain) {
		ret = -EPERM;
		goto unlock;
	}
	if (gb_sd->nr_children) {
		ret = -EBUSY;
		goto unlock;
	}

	group_balancer_kn_lock_live(kn);
	free_group_balancer_sched_domain(gb_sd);

unlock:
	group_balancer_kn_unlock(kn);
	return ret;
}

static struct kernfs_syscall_ops group_balancer_kf_syscall_ops = {
	.mkdir		= group_balancer_mkdir,
	.rmdir		= group_balancer_rmdir,
};

void sched_init_group_balancer_levels(void)
{
	struct group_balancer_topology_level *tl;
	struct group_balancer_size_level *sl;
	int i;

	for_each_gb_topology_level(tl)
		INIT_LIST_HEAD(&tl->domains);

	for_each_gb_size_level(sl, i) {
		sl->size = 1<<i;
		INIT_LIST_HEAD(&sl->domains);
	}
}

/*
 * Here are some cases that some topologies are not reported correctly,
 * e.g., on some virtual machines, DIE cpumask is incorrect, which only
 * includes one cpu.
 * To avoid building incorrect group balancer sched domains due to this
 * kind of incorrect topology, we check whether the topology is correct,
 * and if not, we mark it should be skipped.
 */
static void validate_topology_levels(void)
{
	struct group_balancer_topology_level *gb_tl, *next_gb_tl;
	int i;

	for (i = 1; i < NR_GROUP_BALANCER_TOPOLOGY - 1; i++) {
		gb_tl = &default_topology[i];
		next_gb_tl = &default_topology[i + 1];
		if (!next_gb_tl->mask)
			break;
		if (!cpumask_subset(next_gb_tl->mask(0), gb_tl->mask(0)) ||
		    (cpumask_weight(gb_tl->mask(0)) <= 1))
			gb_tl->skip = true;
	}
}

void sched_init_group_balancer_sched_domains(void)
{
	int ret;

	cpus_read_lock();
	write_lock(&group_balancer_sched_domain_lock);
	ret = build_group_balancer_sched_domains();
	if (ret)
		pr_err("Group Balancer: Failed to build group balancer sched domains: %d\n", ret);
	else
		pr_info("Group Balancer: Build group balancer sched domains successfully.\n");
	write_unlock(&group_balancer_sched_domain_lock);
	cpus_read_unlock();
}

void sched_clear_group_balancer_sched_domains(void)
{
	cpus_read_lock();
	write_lock(&group_balancer_sched_domain_lock);
	free_group_balancer_sched_domains();
	pr_info("Group Balancer: Free group balancer sched domains.\n");
	write_unlock(&group_balancer_sched_domain_lock);
	cpus_read_unlock();
}

static int __init sched_init_group_balancer_kernfs(void)
{
	int ret = 0;

	group_balancer_fs_root = kernfs_create_root(&group_balancer_kf_syscall_ops, 0, NULL);
	if (IS_ERR(group_balancer_fs_root))
		return PTR_ERR(group_balancer_fs_root);

	group_balancer_fs_root_kn = group_balancer_fs_root->kn;

	ret = sysfs_create_mount_point(fs_kobj, "group_balancer");
	if (ret)
		goto cleanup_root;

	pr_info("Group Balancer: Created group balancer mount point.\n");
	ret = register_filesystem(&group_balancer_fs_type);
	if (ret)
		goto cleanup_mountpoint;

	pr_info("Group Balancer: Registered group balancer file system.\n");

	return 0;

cleanup_mountpoint:
	sysfs_remove_mount_point(fs_kobj, "group_balancer");
cleanup_root:
	kernfs_destroy_root(group_balancer_fs_root);
	pr_err("Group Balancer: Failed to register group balancer file system.\n");
	return ret;
}

static int __init group_balancer_init(void)
{
	int ret;

	cpumask_copy(&root_cpumask, cpu_online_mask);
	sched_init_group_balancer_levels();
	validate_topology_levels();
	ret = sched_init_group_balancer_kernfs();
	if (ret)
		return ret;
	return build_group_balancer_root_domain();
}

late_initcall(group_balancer_init);

static void __exit sched_exit_group_balancer_kernfs(void)
{
	unregister_filesystem(&group_balancer_fs_type);
	sysfs_remove_mount_point(fs_kobj, "group_balancer");
	kernfs_destroy_root(group_balancer_fs_root);
	group_balancer_fs_root_kn = NULL;
}

__exitcall(sched_exit_group_balancer_kernfs);
