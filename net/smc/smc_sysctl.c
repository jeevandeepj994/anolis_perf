// SPDX-License-Identifier: GPL-2.0
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  smc_sysctl.c: sysctl interface to SMC subsystem.
 *
 *  Copyright (c) 2022, Alibaba Inc.
 *
 *  Author: Tony Lu <tonylu@linux.alibaba.com>
 *
 */

#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>

#include "smc.h"
#include "smc_sysctl.h"
#include "smc_core.h"

static int min_sndbuf = SMC_BUF_MIN_SIZE;
static int min_rcvbuf = SMC_BUF_MIN_SIZE;

static struct ctl_table smc_table[] = {
	{
		.procname       = "autocorking_size",
		.data           = &init_net.smc.sysctl_autocorking_size,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname       = "wmem_default",
		.data           = &init_net.smc.sysctl_wmem_default,
		.maxlen         = sizeof(init_net.smc.sysctl_wmem_default),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &min_sndbuf,
	},
	{
		.procname       = "rmem_default",
		.data           = &init_net.smc.sysctl_rmem_default,
		.maxlen         = sizeof(init_net.smc.sysctl_rmem_default),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &min_rcvbuf,
	},
	{  }
};

int __net_init smc_sysctl_net_init(struct net *net)
{
	struct ctl_table *table;

	table = smc_table;
	if (!net_eq(net, &init_net)) {
		int i;

		table = kmemdup(table, sizeof(smc_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;

		for (i = 0; i < ARRAY_SIZE(smc_table) - 1; i++)
			table[i].data += (void *)net - (void *)&init_net;
	}

	net->smc.smc_hdr = register_net_sysctl(net, "net/smc", table);
	if (!net->smc.smc_hdr)
		goto err_reg;

	net->smc.sysctl_autocorking_size = SMC_AUTOCORKING_DEFAULT_SIZE;
	net->smc.sysctl_wmem_default = 256 * 1024;
	net->smc.sysctl_rmem_default = 384 * 1024;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

void __net_exit smc_sysctl_net_exit(struct net *net)
{
	struct ctl_table *table;

	table = net->smc.smc_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->smc.smc_hdr);
	if (!net_eq(net, &init_net))
		kfree(table);
}
