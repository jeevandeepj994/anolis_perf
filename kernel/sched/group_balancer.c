// SPDX-License-Identifier: GPL-2.0
/*
 * Group Balancer
 *
 * Group Balancer sched domains define and build
 * Copyright (C) 2024 Alibaba Group, Inc., Cruz Zhao <CruzZhao@linux.alibaba.com>
 */
#include "sched.h"
#include <linux/log2.h>

struct group_balancer_sched_domain {
	struct group_balancer_sched_domain		*parent;
	struct list_head				child;
	struct list_head				sibling;
	struct list_head				topology_level_sibling;
	struct list_head				size_level_sibling;
	struct list_head				gb_sibling;
	unsigned long					gb_flags;
	char						*name;
	unsigned int					span_weight;
	unsigned int					nr_children;
	unsigned long					span[];
};

/* The topology that group balancer cares about. */
enum GROUP_BALANCER_TOPOLOGY {
#ifdef CONFIG_SCHED_SMT
	GROUP_BALANCER_SMT,
#endif
#ifdef CONFIG_SCHED_CLUSTER
	GROUP_BALANCER_CLUSTER,
#endif
#ifdef CONFIG_SCHED_MC
	GROUP_BALANCER_MC,
#endif
	GROUP_BALANCER_LLC,
	GROUP_BALANCER_DIE,
#ifdef CONFIG_NUMA
	GROUP_BALANCER_NUMA,
#endif
	GROUP_BALANCER_SOCKET,
	GROUP_BALANCER_ROOT,
};

enum GROUP_BALANCER_TOPOLOGY_FLAGS {
#ifdef CONFIG_SCHED_SMT
	GROUP_BALANCER_SMT_FLAG		= BIT(GROUP_BALANCER_SMT),
#endif
#ifdef CONFIG_SCHED_CLUSTER
	GROUP_BALANCER_CLUSTER_FLAG	= BIT(GROUP_BALANCER_CLUSTER),
#endif
#ifdef CONFIG_SCHED_MC
	GROUP_BALANCER_MC_FLAG		= BIT(GROUP_BALANCER_MC),
#endif
	GROUP_BALANCER_LLC_FLAG		= BIT(GROUP_BALANCER_LLC),
	GROUP_BALANCER_DIE_FLAG		= BIT(GROUP_BALANCER_DIE),
#ifdef CONFIG_NUMA
	GROUP_BALANCER_NUMA_FLAG	= BIT(GROUP_BALANCER_NUMA),
#endif
	GROUP_BALANCER_SOCKET_FLAG	= BIT(GROUP_BALANCER_SOCKET),
	GROUP_BALANCER_ROOT_FLAG	= BIT(GROUP_BALANCER_ROOT),
};

struct group_balancer_topology_level {
	sched_domain_mask_f	mask;
	sched_domain_flags_f	sd_flags;
	unsigned long		gb_flags;
	char			*name;
	struct list_head	domains;
};

struct group_balancer_size_level {
	int			size;
	/* Use list temporarily, we will change to use rb_tree later.*/
	struct list_head	domains;
};

bool __maybe_unused gb_sd_auto_generated = true;

LIST_HEAD(group_balancer_sched_domains);

DEFINE_RWLOCK(group_balancer_sched_domain_lock);

struct cpumask root_cpumask;

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

#define GB_SD_INIT(type)	.gb_flags = GROUP_BALANCER_##type##_FLAG, .name = #type
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
	for (sl = default_size, i = 0; i <= NR_SIZE_LEVELS; sl++, i++)

#define for_each_gb_sd_child_safe(pos, n, gb_sd)			\
	list_for_each_entry_safe(pos, n, &gb_sd->child, sibling)

#define for_each_group_balancer_sched_domain(pos)	\
	list_for_each_entry(pos, &group_balancer_sched_domains, gb_sibling)

#define for_each_group_balancer_sched_domain_safe(pos, n)	\
	list_for_each_entry_safe(pos, n, &group_balancer_sched_domains, gb_sibling)

struct group_balancer_sched_domain *group_balancer_root_domain;

static inline struct group_balancer_sched_domain
*alloc_init_group_balancer_sched_domain(void)
{
	struct group_balancer_sched_domain *new;

	new = kzalloc(sizeof(struct group_balancer_sched_domain) + cpumask_size(), GFP_KERNEL);
	if (!new)
		return NULL;
	INIT_LIST_HEAD(&new->child);
	INIT_LIST_HEAD(&new->sibling);
	INIT_LIST_HEAD(&new->topology_level_sibling);
	INIT_LIST_HEAD(&new->size_level_sibling);
	INIT_LIST_HEAD(&new->gb_sibling);
	list_add_tail(&new->gb_sibling, &group_balancer_sched_domains);

	/* TODO: init new->span. */
	return new;
}

static void free_group_balancer_sched_domains(void)
{
	struct group_balancer_sched_domain *gb_sd, *n;

	for_each_group_balancer_sched_domain_safe(gb_sd, n) {
		if (gb_sd->parent)
			gb_sd->parent->nr_children--;

		list_del(&gb_sd->sibling);
		list_del(&gb_sd->topology_level_sibling);
		list_del(&gb_sd->size_level_sibling);
		list_del(&gb_sd->gb_sibling);
		kfree(gb_sd);
	}
}

static inline struct cpumask *gb_sd_span(struct group_balancer_sched_domain *gb_sd)
{
	return to_cpumask(gb_sd->span);
}

static void add_to_size_level(struct group_balancer_sched_domain *gb_sd)
{
	unsigned int size_level = ilog2(gb_sd->span_weight);
	struct group_balancer_size_level *gb_sl;

	if (unlikely(size_level >= NR_SIZE_LEVELS))
		return;

	gb_sl = &default_size[size_level];

	list_add(&gb_sd->size_level_sibling, &gb_sl->domains);
}

static int bi_divide_group_balancer_sched_domains(void)
{
	struct group_balancer_sched_domain *gb_sd;

	/*
	 * Traverse all the domains from the group_balancer_sched_domains list,
	 * and add the new domains to the tail of the list, to ensure that all
	 * the domains will be traversed.
	 */
	for_each_group_balancer_sched_domain(gb_sd) {
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
			unsigned int weight = gb_sd->span_weight;
			unsigned int half = (weight + 1) / 2;
			unsigned int logn = ilog2(half);
			unsigned int left = 1 << logn;
			bool is_first_child = true;
			struct group_balancer_sched_domain *child, *n;
			struct group_balancer_sched_domain *left_middle, *right_middle;

			left_middle = alloc_init_group_balancer_sched_domain();
			if (!left_middle) {
				free_group_balancer_sched_domains();
				return -ENOMEM;
			}

			right_middle = alloc_init_group_balancer_sched_domain();
			if (!right_middle) {
				free_group_balancer_sched_domains();
				return -ENOMEM;
			}

			for_each_gb_sd_child_safe(child, n, gb_sd) {
				/*
				 * Consider the following case, a domain spans 6
				 * cpus and 3 chidlren(each child spans 2 cpus),
				 * we just need to add right middle which spans 4
				 * cpus.
				 */
				list_del(&child->sibling);
				if (is_first_child) {
					is_first_child = false;
					left_middle->name = child->name;
					if (child->span_weight >= left) {
						kfree(left_middle);
						left_middle = child;
						break;
					}
				}
				cpumask_or(gb_sd_span(left_middle), gb_sd_span(child),
					   gb_sd_span(left_middle));
				child->parent = left_middle;
				list_add(&child->sibling, &left_middle->child);
				left_middle->nr_children++;
				if (cpumask_weight(gb_sd_span(left_middle)) >= left)
					break;
			}

			is_first_child = true;
			for_each_gb_sd_child_safe(child, n, gb_sd) {
				list_del_init(&child->sibling);
				if (is_first_child) {
					is_first_child = false;
					right_middle->name = child->name;
				}
				cpumask_or(gb_sd_span(right_middle), gb_sd_span(child),
					   gb_sd_span(right_middle));
				child->parent = right_middle;
				list_add(&child->sibling, &right_middle->child);
				right_middle->nr_children++;
			}

			left_middle->span_weight = cpumask_weight(gb_sd_span(left_middle));
			right_middle->span_weight = cpumask_weight(gb_sd_span(right_middle));
			list_add(&left_middle->sibling, &gb_sd->child);
			list_add(&right_middle->sibling, &gb_sd->child);
			gb_sd->nr_children = 2;
			add_to_size_level(left_middle);
			add_to_size_level(right_middle);
		}
	}

	return 0;
}

/* BFS to build group balancer sched domain tree. */
static int build_group_balancer_sched_domains(const struct cpumask *cpu_map)
{
	int cpu;
	struct cpumask trail_map;
	struct group_balancer_topology_level *gb_tl, *next_gb_tl;
	struct group_balancer_sched_domain *parent, *n, *root;

	cpumask_copy(&root_cpumask, cpu_map);

	/*
	 * The group balancer sched domain is a tree.
	 * Build the root node first.
	 */
	root = alloc_init_group_balancer_sched_domain();
	if (!root)
		return -ENOMEM;
	cpumask_copy(gb_sd_span(root), cpu_map);
	root->span_weight = cpumask_weight(gb_sd_span(root));
	add_to_size_level(root);
	list_add(&root->topology_level_sibling, &default_topology[0].domains);

	/* Build the tree by level. */
	for_each_gb_topology_level(gb_tl) {
		next_gb_tl = gb_tl + 1;
		if (!next_gb_tl->mask)
			break;
		/* Build children from parent level. */
		for_each_topology_level_sibling_safe(parent, n, gb_tl) {
			cpumask_copy(&trail_map, gb_sd_span(parent));
			for_each_cpu(cpu, &trail_map) {
				struct group_balancer_sched_domain *child;

				cpumask_andnot(&trail_map, &trail_map, next_gb_tl->mask(cpu));
				/*
				 * If the cpumasks of the adjacent topology levels are the same,
				 * we move the domain to the next level, to make the loop
				 * continue.
				 */
				if (cpumask_equal(gb_sd_span(parent), next_gb_tl->mask(cpu))) {
					list_del(&parent->topology_level_sibling);
					list_add(&parent->topology_level_sibling,
						 &next_gb_tl->domains);
					parent->gb_flags &= next_gb_tl->gb_flags;
					continue;
				}
				child = alloc_init_group_balancer_sched_domain();
				if (!child) {
					free_group_balancer_sched_domains();
					return -ENOMEM;
				}
				cpumask_copy(gb_sd_span(child), next_gb_tl->mask(cpu));
				child->span_weight = cpumask_weight(gb_sd_span(child));
				child->name = next_gb_tl->name;
				list_add(&child->topology_level_sibling, &next_gb_tl->domains);
				child->gb_flags &= next_gb_tl->gb_flags;
				child->parent = parent;
				list_add(&child->sibling, &parent->child);
				parent->nr_children++;
				add_to_size_level(child);
			}
		}
	}

	return bi_divide_group_balancer_sched_domains();
}

static void attach_cpus_to_group_balancer_sched_domains(void)
{
	struct group_balancer_topology_level *gb_tl, *next_gb_tl;
	struct group_balancer_sched_domain *gb_sd;
	int cpu;
	struct rq *rq;
	struct cpumask trail_map;

	cpumask_copy(&trail_map, cpu_possible_mask);
	/* Find the bottom level. */
	for_each_gb_topology_level(gb_tl) {
		next_gb_tl = gb_tl + 1;
		if (!next_gb_tl->mask)
			break;
	}

	for_each_topology_level_sibling(gb_sd, gb_tl) {
		for_each_cpu(cpu, gb_sd_span(gb_sd)) {
			rq = cpu_rq(cpu);
			rq->gb_sd = gb_sd;
			cpumask_clear_cpu(cpu, &trail_map);
		}
	}

	for_each_cpu(cpu, &trail_map) {
		rq = cpu_rq(cpu);
		rq->gb_sd = NULL;
	}
}

static void detach_cpus_from_group_balancer_sched_domains(void)
{
	int cpu;
	struct rq *rq;

	for_each_cpu(cpu, cpu_possible_mask) {
		rq = cpu_rq(cpu);
		rq->gb_sd = NULL;
	}
}

void sched_init_group_balancer(void)
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

int sched_init_group_balancer_sched_domains(const struct cpumask *cpu_map)
{
	int err;

	cpus_read_lock();
	write_lock(&group_balancer_sched_domain_lock);
	err = build_group_balancer_sched_domains(cpu_map);
	if (!err)
		attach_cpus_to_group_balancer_sched_domains();
	write_unlock(&group_balancer_sched_domain_lock);
	cpus_read_unlock();

	return err;
}

void sched_clear_group_balancer_sched_domains(void)
{
	cpus_read_lock();
	write_lock(&group_balancer_sched_domain_lock);
	free_group_balancer_sched_domains();
	detach_cpus_from_group_balancer_sched_domains();
	write_unlock(&group_balancer_sched_domain_lock);
	cpus_read_unlock();
}
