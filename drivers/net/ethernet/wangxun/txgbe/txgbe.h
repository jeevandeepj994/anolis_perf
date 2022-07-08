/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_H_
#define _TXGBE_H_

#include <net/ip.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <linux/timecounter.h>
#include <linux/clocksource.h>
#include <linux/aer.h>

#include "txgbe_type.h"

struct txgbe_ring {
	u8 reg_idx;
} ____cacheline_internodealigned_in_smp;

#define TXGBE_MAX_FDIR_INDICES          63

#define TXGBE_MAX_RX_QUEUES   (TXGBE_MAX_FDIR_INDICES + 1)
#define TXGBE_MAX_TX_QUEUES   (TXGBE_MAX_FDIR_INDICES + 1)

#define TXGBE_MAX_MSIX_Q_VECTORS_SAPPHIRE       64

struct txgbe_mac_addr {
	u8 addr[ETH_ALEN];
	u16 state; /* bitmask */
	u64 pools;
};

#define TXGBE_MAC_STATE_DEFAULT         0x1
#define TXGBE_MAC_STATE_MODIFIED        0x2
#define TXGBE_MAC_STATE_IN_USE          0x4

/**
 * txgbe_adapter.flag2
 **/
#define TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED     BIT(0)

/* board specific private data structure */
struct txgbe_adapter {
	u8 __iomem *io_addr;
	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;

	unsigned long state;

	/* Some features need tri-state capability,
	 * thus the additional *_CAPABLE flags.
	 */
	u32 flags2;
	/* Tx fast path data */
	int num_tx_queues;
	u16 tx_itr_setting;

	/* Rx fast path data */
	int num_rx_queues;
	u16 rx_itr_setting;

	/* TX */
	struct txgbe_ring *tx_ring[TXGBE_MAX_TX_QUEUES] ____cacheline_aligned_in_smp;

	int max_q_vectors;      /* upper limit of q_vectors for device */

	/* structs defined in txgbe_hw.h */
	struct txgbe_hw hw;
	u16 msg_enable;

	struct timer_list service_timer;
	struct work_struct service_task;
	u32 atr_sample_rate;

	char eeprom_id[32];
	bool netdev_registered;

	struct txgbe_mac_addr *mac_table;

};

enum txgbe_state_t {
	__TXGBE_TESTING,
	__TXGBE_RESETTING,
	__TXGBE_DOWN,
	__TXGBE_HANGING,
	__TXGBE_DISABLED,
	__TXGBE_REMOVING,
	__TXGBE_SERVICE_SCHED,
	__TXGBE_SERVICE_INITED,
	__TXGBE_IN_SFP_INIT,
	__TXGBE_PTP_RUNNING,
	__TXGBE_PTP_TX_IN_PROGRESS,
};

/* needed by txgbe_main.c */
void txgbe_service_event_schedule(struct txgbe_adapter *adapter);
void txgbe_assign_netdev_ops(struct net_device *netdev);

int txgbe_open(struct net_device *netdev);
int txgbe_close(struct net_device *netdev);
void txgbe_down(struct txgbe_adapter *adapter);
void txgbe_reset(struct txgbe_adapter *adapter);
s32 txgbe_init_shared_code(struct txgbe_hw *hw);
void txgbe_disable_device(struct txgbe_adapter *adapter);

/**
 * interrupt masking operations. each bit in PX_ICn correspond to a interrupt.
 * disable a interrupt by writing to PX_IMS with the corresponding bit=1
 * enable a interrupt by writing to PX_IMC with the corresponding bit=1
 * trigger a interrupt by writing to PX_ICS with the corresponding bit=1
 **/
#define TXGBE_INTR_ALL (~0ULL)
#define TXGBE_INTR_MISC(A) (1ULL << (A)->num_q_vectors)
#define TXGBE_INTR_QALL(A) (TXGBE_INTR_MISC(A) - 1)
#define TXGBE_INTR_Q(i) (1ULL << (i))
static inline void txgbe_intr_enable(struct txgbe_hw *hw, u64 qmask)
{
	u32 mask;

	mask = (qmask & 0xFFFFFFFF);
	if (mask)
		wr32(hw, TXGBE_PX_IMC(0), mask);
	mask = (qmask >> 32);
	if (mask)
		wr32(hw, TXGBE_PX_IMC(1), mask);

	/* skip the flush */
}

static inline void txgbe_intr_disable(struct txgbe_hw *hw, u64 qmask)
{
	u32 mask;

	mask = (qmask & 0xFFFFFFFF);
	if (mask)
		wr32(hw, TXGBE_PX_IMS(0), mask);
	mask = (qmask >> 32);
	if (mask)
		wr32(hw, TXGBE_PX_IMS(1), mask);

	/* skip the flush */
}

#define msec_delay(_x) msleep(_x)
#define usec_delay(_x) udelay(_x)

extern char txgbe_driver_name[];

struct txgbe_msg {
	u16 msg_enable;
};

__maybe_unused static struct net_device *txgbe_hw_to_netdev(const struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter =
		container_of(hw, struct txgbe_adapter, hw);
	return adapter->netdev;
}

__maybe_unused static struct txgbe_msg *txgbe_hw_to_msg(const struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter =
		container_of(hw, struct txgbe_adapter, hw);
	return (struct txgbe_msg *)&adapter->msg_enable;
}

#define txgbe_dbg(hw, fmt, arg...) \
	netdev_dbg(txgbe_hw_to_netdev(hw), fmt, ##arg)

#define TXGBE_FAILED_READ_CFG_DWORD 0xffffffffU
#define TXGBE_FAILED_READ_CFG_WORD  0xffffU
#define TXGBE_FAILED_READ_CFG_BYTE  0xffU

extern u16 txgbe_read_pci_cfg_word(struct txgbe_hw *hw, u32 reg);

enum {
	TXGBE_ERROR_SOFTWARE,
	TXGBE_ERROR_POLLING,
	TXGBE_ERROR_INVALID_STATE,
	TXGBE_ERROR_UNSUPPORTED,
	TXGBE_ERROR_ARGUMENT,
	TXGBE_ERROR_CAUTION,
};

#define ERROR_REPORT(hw, level, format, arg...) do {                           \
	switch (level) {                                                       \
	case TXGBE_ERROR_SOFTWARE:                                             \
		/* fallthrough */                                              \
	case TXGBE_ERROR_CAUTION:                                              \
		/* fallthrough */                                              \
	case TXGBE_ERROR_POLLING:                                              \
		netif_warn(txgbe_hw_to_msg(hw), drv, txgbe_hw_to_netdev(hw),   \
			   format, ## arg);                                    \
		break;                                                         \
	case TXGBE_ERROR_INVALID_STATE:                                        \
		/* fallthrough */                                              \
	case TXGBE_ERROR_UNSUPPORTED:                                          \
		/* fallthrough */                                              \
	case TXGBE_ERROR_ARGUMENT:                                             \
		netif_err(txgbe_hw_to_msg(hw), hw, txgbe_hw_to_netdev(hw),     \
			  format, ## arg);                                     \
		break;                                                         \
	default:                                                               \
		break;                                                         \
	}                                                                      \
} while (0)

#define ERROR_REPORT1 ERROR_REPORT
#define ERROR_REPORT2 ERROR_REPORT
#define ERROR_REPORT3 ERROR_REPORT

#endif /* _TXGBE_H_ */
