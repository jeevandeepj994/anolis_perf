// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 Alibaba Group Holding Limited.  All Rights Reserved. */

#define KMSG_COMPONENT "VTOA"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt
#include <linux/netfilter.h>

#include "vtoa.h"
#include "vtoa_ctl.h"

/* mode 0: default mode, save: cport + cip
 * mode 1: save: cport + cip + vip-4bytes
 * mode 2: save: cport + cip + vid + vip-7bytes
 */
int sysctl_v6vtoa_info_mode;
static int v6vtoa_info_mode_int_min;
static int v6vtoa_info_mode_int_max = 2;

int v6vtoa_vip_prefixlen_learned;
struct in6_addr v6vtoa_vip_prefix = IN6ADDR_ANY_INIT;

static DEFINE_MUTEX(__v6vtoa_info_mode_mutex);
static DEFINE_MUTEX(__vtoa_mutex);

static int sysctl_set_v6vtoa_info_mode(struct ctl_table *table, int write,
				       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int *valp = table->data, *min = table->extra1, *max = table->extra2;
	int val_old, ret;

	if (mutex_lock_interruptible(&__v6vtoa_info_mode_mutex))
		return -ERESTARTSYS;

	/* backup the value first */
	val_old = *valp;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (write &&  (*valp < *min || *valp > *max)) {
		/* Restore the correct value */
		*valp = val_old;
		ret = -EINVAL;
		goto out;
	}

	if (*valp == val_old)
		goto out;

	memset(&v6vtoa_vip_prefix, 0, sizeof(v6vtoa_vip_prefix));
	v6vtoa_vip_prefixlen_learned = 0;
	pr_info("reset v6vtoa_vip_prifix_learned after v6vtoa_info_mode set to %d!\n", *valp);
out:
	mutex_unlock(&__v6vtoa_info_mode_mutex);
	return ret;
}

/* SLB_VTOA sysctl table (under the /proc/sys/net/ipv4/slb_vtoa/) */
static struct ctl_table vtoa_vars[] = {
	{
		.procname = "v6vtoa_info_mode",
		.data = &sysctl_v6vtoa_info_mode,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = sysctl_set_v6vtoa_info_mode,
		.extra1 = &v6vtoa_info_mode_int_min,
		.extra2 = &v6vtoa_info_mode_int_max,
	},
	{ }
};

static struct ctl_table_header *sysctl_header;

#define GET_CMDID(cmd)		((cmd) - VTOA_BASE_CTL)
#define GET_VS_ARG_LEN		(sizeof(struct vtoa_get_vs))
#define GET_VS4RDS_ARG_LEN	(sizeof(struct vtoa_get_vs4rds))
#define GET_V6VS_ARG_LEN		(sizeof(struct v6vtoa_get_vs))

static const unsigned char get_arglen[GET_CMDID(VTOA_SO_GET_MAX) + 1] = {
	[GET_CMDID(VTOA_SO_GET_VS)]	= GET_VS_ARG_LEN,
	[GET_CMDID(VTOA_SO_GET_VS4RDS)]	= GET_VS4RDS_ARG_LEN,
	[GET_CMDID(HYBRID_VTOA_SO_GET_VS)] = GET_V6VS_ARG_LEN,
};

static int
do_vtoa_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	int ret = 0;
	struct vtoa_data *tdata = SK_TOA_DATA(sk);
	struct toa_vip_data *tdata_vip = SK_TOA_DATA(sk) + TCPOLEN_TOA;

	if (*len < get_arglen[GET_CMDID(cmd)]) {
		pr_err("get_ctl: len %u < %u\n",
		       *len, get_arglen[GET_CMDID(cmd)]);
		return -EINVAL;
	}

	switch (cmd) {
	case VTOA_SO_GET_VS:
		{
			struct vtoa_get_vs vs = { {0, 0, 0} };

			/* VPC */
			if (tdata->optcode == TCPOPT_VTOA &&
			    tdata->optsize == TCPOLEN_VTOA) {
				vs.vs.vid = tdata->vid;
				vs.vs.vaddr = tdata->vip;
				vs.vs.vport = tdata->vport;
			/* FNAT:cip+vip */
			} else if (tdata->optcode == TCPOPT_TOA &&
				   tdata->optsize == TCPOLEN_TOA &&
				tdata_vip->optcode == TCPOPT_TOA_VIP &&
				tdata_vip->optsize == TCPOLEN_TOA_VIP) {
				vs.vs.vid = 0;
				vs.vs.vaddr = tdata_vip->ip;
				vs.vs.vport = tdata_vip->port;
			/* FNAT:vip */
			} else if (tdata->optcode == TCPOPT_TOA_VIP &&
				   tdata->optsize == TCPOLEN_TOA_VIP) {
				tdata_vip = (void *)tdata;
				vs.vs.vid = 0;
				vs.vs.vaddr = tdata_vip->ip;
				vs.vs.vport = tdata_vip->port;
			} else {
				ret = -ESRCH;
				break;
			}
			if (copy_to_user(user, &vs, sizeof(vs))) {
				pr_err("%s err: copy to user.\n", __func__);
				ret = -EFAULT;
			}
			break;
		}
	case HYBRID_VTOA_SO_GET_VS:
		{
			struct v6vtoa_get_vs v6vs = { {0, {{0}}} };
			struct v6vtoa_data *v6vtdata = SK_TOA_DATA(sk);

			v6vs.vs.vaddr_af = AF_INET;
			/* VPC */
			if (tdata->optcode == TCPOPT_VTOA &&
			    tdata->optsize == TCPOLEN_VTOA) {
				v6vs.vs.vid = tdata->vid;  //in host order
				v6vs.vs.vaddr.ip = tdata->vip; //in network order
				v6vs.vs.vport = tdata->vport;
			/* FNAT:cip+vip */
			} else if (tdata->optcode == TCPOPT_TOA &&
				   tdata->optsize == TCPOLEN_TOA &&
				tdata_vip->optcode == TCPOPT_TOA_VIP &&
				tdata_vip->optsize == TCPOLEN_TOA_VIP) {
				v6vs.vs.vid = 0;
				v6vs.vs.vaddr.ip = tdata_vip->ip;
				v6vs.vs.vport = tdata_vip->port;
			/* FNAT:vip */
			} else if (tdata->optcode == TCPOPT_TOA_VIP &&
				tdata->optsize == TCPOLEN_TOA_VIP) {
				tdata_vip = (void *)tdata;
				v6vs.vs.vid = 0;
				v6vs.vs.vaddr.ip = tdata_vip->ip;
				v6vs.vs.vport = tdata_vip->port;
			/* FNAT: v6vtoa */
			} else if (tdata->optcode == TCPOPT_V6VTOA &&
				tdata->optsize == TCPOLEN_V6VTOA) {
				v6vs.vs.vid = 0xffffff;
				v6vs.vs.vaddr_af = AF_INET6;
				v6vs.vs.vport = 0;

				if (sizeof(sk->sk_toa_data) >= TCPOLEN_V6VTOA) {
					v6vs.vs.vid = ntohl(VID_BE_UNFOLD(v6vtdata->vid));
					memcpy(&v6vs.vs.vaddr, v6vtdata->vip,
					       sizeof(v6vtdata->vip));

				} else if (sysctl_v6vtoa_info_mode == 0) {
					/* mode 0: default mode, save: cport + cip */
					pr_info("warning get_v6vs: vid and vip not available in mode 0.\n");
				} else if (sysctl_v6vtoa_info_mode == 1) {
					memcpy(&v6vs.vs.vaddr,
					       &v6vtoa_vip_prefix,
					       IPV6_PREFIX_4BYTES);
					memcpy((char *)&v6vs.vs.vaddr + IPV6_PREFIX_4BYTES,
					       (char *)v6vtdata + OFFSETOF_VID(v6vtdata),
					       sizeof(v6vtdata->vip) - IPV6_PREFIX_4BYTES);

				} else if (sysctl_v6vtoa_info_mode == 2) {
					v6vs.vs.vid = ntohl(VID_BE_UNFOLD(v6vtdata->vid));
					memcpy(&v6vs.vs.vaddr,
					       &v6vtoa_vip_prefix,
					       IPV6_PREFIX_7BYTES);
					memcpy((char *)&v6vs.vs.vaddr + IPV6_PREFIX_7BYTES,
					       (char *)v6vtdata + OFFSETOF_RESERVED(v6vtdata),
					       sizeof(v6vtdata->vip) - IPV6_PREFIX_7BYTES);

				} else {
					pr_err("err get_v6vs: unexpected mode %d.\n",
					       sysctl_v6vtoa_info_mode);
					ret = -EFAULT;
					return ret;
				}

				if (copy_to_user(user, &v6vs, sizeof(v6vs))) {
					pr_err("get_v6vs err: copy to user.\n");
					ret = -EFAULT;
				}

				return ret;
			}

			ret = -ESRCH;
			break;
		}

	case VTOA_SO_GET_VS4RDS:
		{
			char arg[sizeof(struct vtoa_get_vs4rds) + sizeof(struct vtoa_vs)];
			struct vtoa_get_vs4rds *vs4rds = (void *)arg;

			if (*len != sizeof(struct vtoa_get_vs4rds) + sizeof(struct vtoa_vs)) {
				ret = -EINVAL;
				break;
			}
			/* VPC */
			if (tdata->optcode == TCPOPT_VTOA && tdata->optsize == TCPOLEN_VTOA) {
				vs4rds->entrytable->vid = tdata->vid;
				vs4rds->entrytable->vaddr = tdata->vip;
				vs4rds->entrytable->vport = tdata->vport;
			/* FNAT:cip+vip */
			} else if (tdata->optcode == TCPOPT_TOA &&
				tdata->optsize == TCPOLEN_TOA &&
				tdata_vip->optcode == TCPOPT_TOA_VIP &&
				tdata_vip->optsize == TCPOLEN_TOA_VIP) {
				vs4rds->entrytable->vid = 0;
				vs4rds->entrytable->vaddr = tdata_vip->ip;
				vs4rds->entrytable->vport = tdata_vip->port;
			/* FNAT:vip */
			} else if (tdata->optcode == TCPOPT_TOA_VIP &&
				tdata->optsize == TCPOLEN_TOA_VIP) {
				tdata_vip = (void *)tdata;
				vs4rds->entrytable->vid = 0;
				vs4rds->entrytable->vaddr = tdata_vip->ip;
				vs4rds->entrytable->vport = tdata_vip->port;
			} else {
				ret = -ESRCH;
				break;
			}
			if (copy_to_user(((struct vtoa_get_vs4rds *)user)->entrytable,
					 vs4rds->entrytable, sizeof(struct vtoa_vs))) {
				pr_err("%s err: copy to user.\n", __func__);
				ret = -EFAULT;
			}
			break;
		}
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int
do_v6vtoa_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	struct v6vtoa_data *v6vtdata = SK_TOA_DATA(sk);
	struct vtoa_data *tdata = SK_TOA_DATA(sk);
	struct v6vtoa_get_vs v6vs = { {0, {{0}}} };
	int ret = 0;

	if (*len < get_arglen[GET_CMDID(cmd)]) {
		pr_err("get_ctl: len %u < %u\n",
		       *len, get_arglen[GET_CMDID(cmd)]);
		return -EINVAL;
	}

	if (cmd != HYBRID_VTOA_SO_GET_VS)
		return -EINVAL;

	if (tdata->optcode != TCPOPT_V6VTOA || tdata->optsize != TCPOLEN_V6VTOA)
		return -ESRCH;

	/* default vid is invalid, in cpu order */
	v6vs.vs.vid = 0xffffff;
	v6vs.vs.vaddr_af = AF_INET6;
	v6vs.vs.vport = 0;

	if (sizeof(sk->sk_toa_data) >= TCPOLEN_V6VTOA) {
		v6vs.vs.vid = ntohl(VID_BE_UNFOLD(v6vtdata->vid));
		memcpy(&v6vs.vs.vaddr, v6vtdata->vip, sizeof(v6vtdata->vip));

	} else if (sysctl_v6vtoa_info_mode == 0) {
		/* mode 0: default mode, save: cport + cip */
		pr_info("warning get_v6vs: vid and vip not available in mode 0.\n");

	} else if (sysctl_v6vtoa_info_mode == 1) {
		memcpy(&v6vs.vs.vaddr, &v6vtoa_vip_prefix, IPV6_PREFIX_4BYTES);
		memcpy((char *)&v6vs.vs.vaddr + IPV6_PREFIX_4BYTES,
		       (char *)v6vtdata + OFFSETOF_VID(v6vtdata),
		       sizeof(v6vtdata->vip) - IPV6_PREFIX_4BYTES);

	} else if (sysctl_v6vtoa_info_mode == 2) {
		v6vs.vs.vid = ntohl(VID_BE_UNFOLD(v6vtdata->vid));
		memcpy(&v6vs.vs.vaddr, &v6vtoa_vip_prefix, IPV6_PREFIX_7BYTES);
		memcpy((char *)&v6vs.vs.vaddr + IPV6_PREFIX_7BYTES,
		       (char *)v6vtdata + OFFSETOF_RESERVED(v6vtdata),
		       sizeof(v6vtdata->vip) - IPV6_PREFIX_7BYTES);

	} else {
		pr_err("err get_v6vs: unexpected mode %d.\n", sysctl_v6vtoa_info_mode);
		ret = -EFAULT;
		return ret;
	}

	if (copy_to_user(user, &v6vs, sizeof(v6vs))) {
		pr_err("get_v6vs err: copy to user.\n");
		ret = -EFAULT;
	}

	return ret;
}

static struct nf_sockopt_ops vtoa_sockopts = {
	.pf = PF_INET,
	.get_optmin = VTOA_BASE_CTL,
	.get_optmax = VTOA_SO_GET_MAX + 1,
	.get = do_vtoa_get_ctl,
	.owner = THIS_MODULE,
};

static struct nf_sockopt_ops v6vtoa_sockopts = {
	.pf = PF_INET6,
	.get_optmin = VTOA_BASE_CTL,
	.get_optmax = VTOA_SO_GET_MAX + 1,
	.get = do_v6vtoa_get_ctl,
	.owner = THIS_MODULE,
};

static int vtoa_init_sysctl(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(vtoa_vars, sizeof(vtoa_vars), GFP_KERNEL);
	if (!table)
		goto out;

	sysctl_header = register_net_sysctl(net, "net/ipv4/slb_vtoa", table);
	if (!sysctl_header) {
		pr_err("can't register to sysctl.\n");
		goto out_register;
	}
	return 0;

out_register:
	kfree(table);
out:
	return -ENOMEM;
}

static void vtoa_cleanup_sysctl(struct net *net)
{
	struct ctl_table *table;

	if (sysctl_header) {
		table = sysctl_header->ctl_table_arg;
		unregister_net_sysctl_table(sysctl_header);

		kfree(table);
	}
}

int __init vtoa_ctl_init(void)
{
	int ret;

	ret = nf_register_sockopt(&vtoa_sockopts);
	if (ret < 0) {
		pr_err("cannot register vtoa_sockopts.\n");
		goto register_sockopt_fail;
	}

	ret = nf_register_sockopt(&v6vtoa_sockopts);
	if (ret < 0)
		pr_err("cannot register ipv6 vtoa_sockopts.\n");

	ret = vtoa_init_sysctl(&init_net);
	if (ret < 0)
		goto register_sysctl_fail;

	pr_info("vtoa init finish.\n");
	return 0;

register_sysctl_fail:
	nf_unregister_sockopt(&v6vtoa_sockopts);
	nf_unregister_sockopt(&vtoa_sockopts);
register_sockopt_fail:
	return ret;
}

void __exit vtoa_ctl_cleanup(void)
{
	vtoa_cleanup_sysctl(&init_net);
	nf_unregister_sockopt(&v6vtoa_sockopts);
	nf_unregister_sockopt(&vtoa_sockopts);
}
