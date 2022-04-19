/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications over RDMA (SMC-R), RoCE and iWARP
 *
 *  Definitions for LLC (link layer control) message handling
 *
 *  Copyright (c) 2020-2021 Alibaba Group.
 *
 *  Author(s):  Wangguangguan <guangguan.wang@linux.alibaba.com>
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include "smc_ipi.h"

static inline bool smc_ipi_share_cache(int this_cpu, int that_cpu)
{
	return topology_physical_package_id(this_cpu) ==
		topology_physical_package_id(that_cpu);
}

struct smc_ipi_cpu_maps {
	int nodes;  // numa node cnt
	u16 lens[MAX_NUMNODES];  // cpu map's len for per numa node
	u16 cpus[MAX_NUMNODES][NR_CPUS]; // cpu maps for per numa node
};

struct smc_ipi_cpu_maps ipi_cpu_maps;

int smc_ipi_get_cpu(struct smc_sock *smc)
{
	int node = 0;

	if (unlikely(smc->ipi_preferred_cpu < 0))
		goto remap;

	// if last_cpu and preferred ipi cpu are in the same cache
	// domain, then used the preferred ipi cpu.
	if (likely(smc_ipi_share_cache(smc->last_cpu, smc->ipi_preferred_cpu)))
		return smc->ipi_preferred_cpu;

remap:
	// otherwise, update preferred ipi cpu from cpu maps,
	// which will be in the same cache domaim with last_cpu.
	node = cpu_to_node(smc->last_cpu);
	if (WARN_ON(node == NUMA_NO_NODE)) {
		smc->last_cpu = raw_smp_processor_id();
		smc->ipi_preferred_cpu = raw_smp_processor_id();
		return smc->ipi_preferred_cpu;
	}

	// use quadruples hash to get ipi cpu,
	// in the same cache domain with last_cpu
	smc->ipi_preferred_cpu = ipi_cpu_maps.cpus[node]
		[reciprocal_scale(smc->sk.sk_hash, ipi_cpu_maps.lens[node])];
	smc->ipi_preferred_cpu =
		smc_ipi_share_cache(smc->last_cpu, smc->ipi_preferred_cpu) ?
		smc->ipi_preferred_cpu : smc->last_cpu;

	return smc->ipi_preferred_cpu;
}

struct smc_ipi_data {
	struct list_head	list;	//list to store pending smc_sock
	struct {
		spinlock_t	lock;	// lock
		atomic_t	owner;	// lock owners cnt
	} lock;	// fastlock, used for protecting list
	call_single_data_t	csd;	// csd for ipi function call
	unsigned int		cpu;	// data's onwer cpu id
	unsigned long		state;	// ipi state
	struct tasklet_struct	process_tasklet;	// ipi process tasklet
};

#define SMC_IPI_STATE_RUN	0

static DEFINE_PER_CPU_ALIGNED(struct smc_ipi_data, smc_ipi_data);

static inline void smc_ipi_lock_init(struct smc_ipi_data *ipi_data)
{
	spin_lock_init(&ipi_data->lock.lock);

	// the lock in fastlock should be initiated to locked state,
	// hense the first one to get the lock without processing lock,
	// and others will be spined when the lock has been owned.
	spin_lock(&ipi_data->lock.lock);
	atomic_set(&ipi_data->lock.owner, 0);
}

static inline void smc_ipi_lock(struct smc_ipi_data *ipi_data)
{
	if (atomic_inc_return(&ipi_data->lock.owner) > 1) {
		// if more than one owners,
		// spin here for others to unlock the lock
		spin_lock(&ipi_data->lock.lock);
	}
}

static inline void smc_ipi_unlock(struct smc_ipi_data *ipi_data)
{
	if (!atomic_dec_and_test(&ipi_data->lock.owner)) {
		// if still has any waiters for the lock,
		// unlock the lock to let others get the lock.
		spin_unlock(&ipi_data->lock.lock);
	}
}

// smc_send_ipi should be called in softirq/irq context,
// once the ipi lock used in this function is not irq saved.
void smc_ipi_send_ipi(struct smc_sock *smc)
{
	struct smc_ipi_data *ipi_data =
		&per_cpu(smc_ipi_data, smc->ipi_preferred_cpu);

	// the smc_sock already in ipi pending list
	if (test_bit(SMC_SOCK_IPI, &smc->flags))
		return;

	// set the flag to indicate the smc_sock in ipi pending list
	set_bit(SMC_SOCK_IPI, &smc->flags);
	sock_hold(&smc->sk);

	smc_ipi_lock(ipi_data);
	list_add_tail(&smc->ipi_list, &ipi_data->list);
	smc_ipi_unlock(ipi_data);

	// test if the target cpu is in ipi processing
	if (!test_bit(SMC_IPI_STATE_RUN, &ipi_data->state))
		smp_call_function_single_async(smc->ipi_preferred_cpu,
					       &ipi_data->csd);
}

static void smc_ipi_trigger(void *data)
{
	struct smc_ipi_data *ipi_data = (struct smc_ipi_data *)data;

	tasklet_schedule(&ipi_data->process_tasklet);
}

static void smc_ipi_tasklet_fn(unsigned long data)
{
	struct smc_ipi_data *ipi_data = (struct smc_ipi_data *)data;
	struct list_head *pos, *q;
	LIST_HEAD(process_list);

	set_bit(SMC_IPI_STATE_RUN, &ipi_data->state);
	while (!list_empty(&ipi_data->list)) {
		smc_ipi_lock(ipi_data);
		list_splice_tail_init(&ipi_data->list, &process_list);
		smc_ipi_unlock(ipi_data);

		list_for_each_safe(pos, q, &process_list) {
			struct smc_sock *smc =
				list_entry(pos, struct smc_sock, ipi_list);
			list_del(&smc->ipi_list);
			smc->sk.sk_data_ready(&smc->sk);
			clear_bit(SMC_SOCK_IPI, &smc->flags);
			sock_put(&smc->sk);
		}
	}
	clear_bit(SMC_IPI_STATE_RUN, &ipi_data->state);
}

int __init smc_ipi_init(void)
{
	int node = 0, cpu = 0;

	memset(&ipi_cpu_maps, 0, sizeof(struct smc_ipi_cpu_maps));
	ipi_cpu_maps.nodes = num_possible_nodes();
	for_each_node(node) {
		const struct cpumask *mask = cpumask_of_node(node);

		for_each_cpu(cpu, mask) {
			ipi_cpu_maps.cpus[node][ipi_cpu_maps.lens[node]++] = cpu;
		}
	}

	for_each_possible_cpu(cpu) {
		struct smc_ipi_data *ipi_data = &per_cpu(smc_ipi_data, cpu);

		INIT_LIST_HEAD(&ipi_data->list);
		smc_ipi_lock_init(ipi_data);
		ipi_data->csd.func = smc_ipi_trigger;
		ipi_data->csd.info = ipi_data;
		ipi_data->cpu = cpu;
		ipi_data->state = 0;

		tasklet_init(&ipi_data->process_tasklet, smc_ipi_tasklet_fn,
			     (unsigned long)ipi_data);
	}

	return 0;
}

void smc_ipi_exit(void)
{
	int i = 0;

	for_each_possible_cpu(i) {
		struct smc_ipi_data *ipi_data = &per_cpu(smc_ipi_data, i);

		tasklet_kill(&ipi_data->process_tasklet);
	}
}

