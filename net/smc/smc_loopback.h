/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications Direct over loopback device.
 *
 *  Provide a SMC-D loopback dummy device.
 *
 *  Copyright (c) 2022, Alibaba Inc.
 *
 *  Author: Wen Gu <guwen@linux.alibaba.com>
 *          Tony Lu <tonylu@linux.alibaba.com>
 *
 */

#ifndef _SMC_LOOPBACK_H
#define _SMC_LOOPBACK_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/err.h>
#include <net/smc.h>

#include "smc_core.h"

#define SMC_LO_CHID 0xFFFF
#define SMC_LODEV_MAX_DMBS 5000
#define SMC_LODEV_MAX_DMBS_BUCKETS 16

struct smc_lo_dmb_node {
	struct hlist_node list;
	u64 token;
	u32 len;
	u32 sba_idx;
	void *cpu_addr;
	dma_addr_t dma_addr;
	refcount_t refcnt;
	u8 freeing : 1;
};

struct smc_lo_dev {
	struct smcd_dev *smcd;
	struct device dev;
	u16 chid;
	u64 local_gid;
	DECLARE_BITMAP(sba_idx_mask, SMC_LODEV_MAX_DMBS);
	rwlock_t dmb_ht_lock;
	DECLARE_HASHTABLE(dmb_ht, SMC_LODEV_MAX_DMBS_BUCKETS);
	atomic_t dmb_cnt;
	wait_queue_head_t dmbs_release;
	wait_queue_head_t ldev_release;
};

int smc_loopback_init(void);
void smc_loopback_exit(void);

#endif /* _SMC_LOOPBACK_H */
