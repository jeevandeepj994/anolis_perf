/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_SMC_H__
#define __NETNS_SMC_H__
#include <linux/mutex.h>
#include <linux/percpu.h>

struct smc_stats_rsn;
struct smc_stats;
struct netns_smc {
	/* per cpu counters for SMC */
	struct smc_stats __percpu	*smc_stats;
	/* protect fback_rsn */
	struct mutex			mutex_fback_rsn;
	struct smc_stats_rsn		*fback_rsn;

	bool				limit_smc_hs;	/* constraint on handshake */
#ifdef CONFIG_SYSCTL
	struct ctl_table_header		*smc_hdr;
#endif
	unsigned int			sysctl_autocorking_size;
	unsigned int			sysctl_smcr_buf_type;
	int				sysctl_smcr_testlink_time;
	int				sysctl_wmem;
	int				sysctl_rmem;

	CK_KABI_RESERVE(1)
	CK_KABI_RESERVE(2)
	CK_KABI_RESERVE(3)
	CK_KABI_RESERVE(4)
	CK_KABI_RESERVE(5)
	CK_KABI_RESERVE(6)
	CK_KABI_RESERVE(7)
	CK_KABI_RESERVE(8)
	CK_KABI_RESERVE(9)
	CK_KABI_RESERVE(10)
	CK_KABI_RESERVE(11)
	CK_KABI_RESERVE(12)
	CK_KABI_RESERVE(13)
	CK_KABI_RESERVE(14)
	CK_KABI_RESERVE(15)
	CK_KABI_RESERVE(16)
	CK_KABI_RESERVE(17)
	CK_KABI_RESERVE(18)
	CK_KABI_RESERVE(19)
	CK_KABI_RESERVE(20)
	CK_KABI_RESERVE(21)
	CK_KABI_RESERVE(22)
	CK_KABI_RESERVE(23)
	CK_KABI_RESERVE(24)
	CK_KABI_RESERVE(25)
	CK_KABI_RESERVE(26)
	CK_KABI_RESERVE(27)
	CK_KABI_RESERVE(28)
	CK_KABI_RESERVE(29)
	CK_KABI_RESERVE(30)
	CK_KABI_RESERVE(31)
	CK_KABI_RESERVE(32)
};
#endif
