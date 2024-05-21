/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Unix network namespace
 */
#ifndef __NETNS_UNIX_H__
#define __NETNS_UNIX_H__

#include <linux/ck_kabi.h>

struct ctl_table_header;
struct netns_unix {
	int			sysctl_max_dgram_qlen;
	struct ctl_table_header	*ctl;

	CK_KABI_RESERVE(1)
	CK_KABI_RESERVE(2)
};

#endif /* __NETNS_UNIX_H__ */
