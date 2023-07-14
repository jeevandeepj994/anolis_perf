/* SPDX-License-Identifier: GPL-2.0 */

#ifndef VTOA_CTL_H_INCLUDE
#define VTOA_CTL_H_INCLUDE

#include "vtoa.h"

union vtoa_ipaddr {
	u32 all[4];
	u32 ip;
	u32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

struct v6vtoa_vs {
	/* VPC ID */
	__u32		vid;
	/* vip */
	union vtoa_ipaddr	vaddr;
	__u16		vaddr_af;
	/* vport */
	__be16		vport;
};

struct v6vtoa_get_vs {
	struct v6vtoa_vs vs;
};

struct v6vtoa_get_vs4rds {
	/* which connection*/
	__u16 protocol;
	/* client address */
	union vtoa_ipaddr caddr;
	__be16 cport;
	/* destination address */
	union vtoa_ipaddr daddr;
	__be16 dport;
	/* the virtual servers */
	struct v6vtoa_vs entrytable[0];
};

struct vtoa_vs {
	/* VPC ID */
	__u32		vid;
	/* vip */
	__be32		vaddr;
	/* vport */
	__be16		vport;
};

struct vtoa_get_vs {
	struct vtoa_vs vs;
};

struct vtoa_get_vs4rds {
	/* which connection*/
	__u16 protocol;
	/* client address */
	__be32 caddr;
	__be16 cport;
	/* destination address */
	__be32 daddr;
	__be16 dport;

	/* the virtual servers */
	struct vtoa_vs entrytable[0];
};

#define VTOA_BASE_CTL		(64 + 1024 + 64 + 64 + 64 + 64)

#define VTOA_SO_GET_VS		(VTOA_BASE_CTL + 1)
#define VTOA_SO_GET_VS4RDS	(VTOA_BASE_CTL + 2)
#define HYBRID_VTOA_SO_GET_VS	(VTOA_BASE_CTL + 3)
#define VTOA_SO_GET_MAX	(HYBRID_VTOA_SO_GET_VS)

int vtoa_ctl_init(void);
void vtoa_ctl_cleanup(void);

#endif
