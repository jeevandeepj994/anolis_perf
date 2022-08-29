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
#include "smc_core.h"
#include "smc_sysctl.h"
#include "smc_core.h"

static int min_sndbuf = SMC_BUF_MIN_SIZE;
static int min_rcvbuf = SMC_BUF_MIN_SIZE;

static int two = 2;

static struct ctl_table smc_table[] = {
	{
		.procname       = "autocorking_size",
		.data           = &init_net.smc.sysctl_autocorking_size,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname	= "smcr_buf_type",
		.data		= &init_net.smc.sysctl_smcr_buf_type,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &two,
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
	{
		.procname	= "tcp2smc",
		.data		= &init_net.smc.sysctl_tcp2smc,
		.maxlen		= sizeof(init_net.smc.sysctl_tcp2smc),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "allow_different_subnet",
		.data		= &init_net.smc.sysctl_allow_different_subnet,
		.maxlen		= sizeof(init_net.smc.sysctl_allow_different_subnet),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname       = "limit_handshake",
		.data           = &init_net.smc.limit_smc_hs,
		.maxlen         = sizeof(init_net.smc.limit_smc_hs),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname	= "disable_multiple_link",
		.data		= &init_net.smc.sysctl_disable_multiple_link,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "simplify_rkey_exhcange",
		.data		= &init_net.smc.sysctl_simplify_rkey_exhcange,
		.maxlen		= sizeof(init_net.smc.sysctl_simplify_rkey_exhcange),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "fastopen",
		.data		= &init_net.smc.sysctl_smc_fastopen,
		.maxlen		= sizeof(init_net.smc.sysctl_smc_fastopen),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "sysctl_smc_experiments",
		.data		= &init_net.smc.sysctl_smc_experiments,
		.maxlen		= sizeof(init_net.smc.sysctl_smc_experiments),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "keep_first_contact_clcsock",
		.data		= &init_net.smc.sysctl_keep_first_contact_clcsock,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
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
	net->smc.sysctl_smcr_buf_type = SMCR_PHYS_CONT_BUFS;
	net->smc.sysctl_wmem_default = 256 * 1024;
	net->smc.sysctl_rmem_default = 384 * 1024;
	net->smc.sysctl_tcp2smc = 0;
	net->smc.sysctl_allow_different_subnet = 1;
	net->smc.sysctl_keep_first_contact_clcsock = 1;
	net->smc.sysctl_disable_multiple_link = 1;
	/* default on */
	net->smc.sysctl_simplify_rkey_exhcange = 1;
	net->smc.sysctl_smc_fastopen = 1;
	/* default off */
	net->smc.sysctl_smc_experiments = 0;
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
