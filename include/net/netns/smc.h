/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_SMC_H__
#define __NETNS_SMC_H__
#include <linux/mutex.h>
#include <linux/percpu.h>

#define SMC_IWARP_RSVD_PORTS_NUM	16 /* must be 16 */

struct smc_stats_rsn;
struct smc_stats;
struct netns_smc {
	/* per cpu counters for SMC */
	struct smc_stats __percpu	*smc_stats;
	/* protect fback_rsn */
	spinlock_t			mutex_fback_rsn;
	struct smc_stats_rsn		*fback_rsn;
	int				limit_smc_hs;	/* constraint on handshake */
	atomic_t			iwarp_cnt;
	struct socket			*rsvd_sock[SMC_IWARP_RSVD_PORTS_NUM];
#ifdef CONFIG_SYSCTL
	struct ctl_table_header		*smc_hdr;
#endif
	unsigned int			sysctl_autocorking_size;
	unsigned int			sysctl_smcr_buf_type;
	unsigned int			sysctl_vendor_exp_options;
	int				sysctl_smcr_testlink_time;
	int				sysctl_wmem;
	int				sysctl_rmem;
	int				sysctl_tcp2smc;
};
#endif
