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

#ifndef _SMC_IPI_H
#define _SMC_IPI_H

#include <linux/smp.h>
#include "smc.h"

int smc_ipi_get_cpu(struct smc_sock *smc);

// called when sock link established.
static inline void smc_ipi_init_ipi(struct smc_sock *smc)
{
	smc->last_cpu = raw_smp_processor_id();

	// copy sk_hash from clcsock. sk_hash is calced by quadruples
	smc->sk.sk_hash = smc->clcsock->sk->sk_hash;

	// set invalid ipi cpu, smc_ipi_get_cpu will remap the
	// ipi_preferred_cpu arrcording to the quadruples hash
	smc->ipi_preferred_cpu = -1;
	smc->ipi_preferred_cpu = smc_ipi_get_cpu(smc);
}

static inline bool smc_ipi_need_ipi(struct smc_sock *smc)
{
	int cpu = raw_smp_processor_id();
	int ipi_cpu = smc_ipi_get_cpu(smc);

	if (!IS_ENABLED(CONFIG_SMP) || cpu == ipi_cpu)
		return false;

	return cpu_online(ipi_cpu);
}

void smc_ipi_send_ipi(struct smc_sock *smc);

int __init smc_ipi_init(void);
void smc_ipi_exit(void);
#endif

