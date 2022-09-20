/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _NGBE_H_
#define _NGBE_H_

#include "ngbe_type.h"

#define NGBE_MAX_FDIR_INDICES		        7
#define NGBE_MAX_MSIX_Q_VECTORS_EMERALD     9

#define NGBE_MAX_RX_QUEUES		(NGBE_MAX_FDIR_INDICES + 1)
#define NGBE_MAX_TX_QUEUES		(NGBE_MAX_FDIR_INDICES + 1)

#define NGBE_FLAG_NEED_LINK_UPDATE             (u32)(1 << 13)
#define NGBE_FLAG_NEED_ANC_CHECK               (u32)(1 << 14)

#define NGBE_FLAG2_SEARCH_FOR_SFP              (u32)(1 << 5)

#define NGBE_INTR_ALL                  0x1FF

/* TX/RX descriptor defines */
#define NGBE_DEFAULT_TXD               512 /* default ring size */
#define NGBE_DEFAULT_TX_WORK           256
#define NGBE_DEFAULT_RXD               512 /* default ring size */
#define NGBE_DEFAULT_RX_WORK           256

enum ngbe_state_t {
	__NGBE_TESTING,
	__NGBE_RESETTING,
	__NGBE_DOWN,
	__NGBE_HANGING,
	__NGBE_DISABLED,
	__NGBE_REMOVING,
	__NGBE_SERVICE_SCHED,
	__NGBE_SERVICE_INITED,
	__NGBE_IN_SFP_INIT,
};

struct ngbe_mac_addr {
	u8 addr[ETH_ALEN];
	u16 state; /* bitmask */
	u64 pools;
};

/* board specific private data structure */
struct ngbe_adapter {
	u8 __iomem *io_addr;    /* Mainly for iounmap use */
	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;

	int max_q_vectors;      /* upper limit of q_vectors for device */
	u32 flags;
	u32 flags2;
	unsigned long state;

	unsigned int tx_ring_count;
	unsigned int rx_ring_count;

	/* Tx fast path data */
	u16 tx_work_limit;

	/* Rx fast path data */
	u16 rx_work_limit;

	/* structs defined in ngbe_hw.h */
	struct ngbe_hw hw;
	u16 msg_enable;

	struct ngbe_mac_addr *mac_table;

	u32 tx_timeout_recovery_level;
};

struct ngbe_msg {
	u16 msg_enable;
};

extern char ngbe_driver_name[];

static struct net_device *ngbe_hw_to_netdev(const struct ngbe_hw *hw)
{
	return ((struct ngbe_adapter *)hw->back)->netdev;
}

static struct ngbe_msg *ngbe_hw_to_msg(const struct ngbe_hw *hw)
{
	struct ngbe_adapter *adapter =
		container_of(hw, struct ngbe_adapter, hw);
	return (struct ngbe_msg *)&adapter->msg_enable;
}

static inline void ngbe_intr_disable(struct ngbe_hw *hw, u64 qmask)
{
	u32 mask;

	mask = (qmask & 0xFFFFFFFF);
	if (mask)
		wr32(hw, NGBE_PX_IMS, mask);
}

static inline struct device *pci_dev_to_dev(struct pci_dev *pdev)
{
	return &pdev->dev;
}

enum {
	NGBE_ERROR_SOFTWARE,
	NGBE_ERROR_POLLING,
	NGBE_ERROR_INVALID_STATE,
	NGBE_ERROR_UNSUPPORTED,
	NGBE_ERROR_ARGUMENT,
	NGBE_ERROR_CAUTION,
};

#define ERROR_REPORT(hw, level, format, arg...) do {                      \
	switch (level) {                                                      \
	case NGBE_ERROR_SOFTWARE:                                             \
		/* fallthrough */                                                \
	case NGBE_ERROR_CAUTION:                                              \
		/* fallthrough */                                                \
	case NGBE_ERROR_POLLING:                                              \
		netif_warn(ngbe_hw_to_msg(hw), drv, ngbe_hw_to_netdev(hw),        \
				format, ## arg);                                          \
		break;                                                            \
	case NGBE_ERROR_INVALID_STATE:                                        \
		/* fallthrough */                                                \
	case NGBE_ERROR_UNSUPPORTED:                                          \
		/* fallthrough */                                                \
	case NGBE_ERROR_ARGUMENT:                                             \
		netif_err(ngbe_hw_to_msg(hw), hw, ngbe_hw_to_netdev(hw),          \
				format, ## arg);                                          \
		break;                                                            \
	default:                                                              \
		break;                                                            \
	}                                                                     \
} while (0)

#define ERROR_REPORT1 ERROR_REPORT
#define ERROR_REPORT2 ERROR_REPORT
#define ERROR_REPORT3 ERROR_REPORT

#define hw_dbg(hw, format, arg...) \
	netdev_dbg(ngbe_hw_to_netdev(hw), format, ## arg)
#define hw_err(hw, format, arg...) \
	netdev_err(ngbe_hw_to_netdev(hw), format, ## arg)
#define e_dev_info(format, arg...) \
	dev_info(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dev_warn(format, arg...) \
	dev_warn(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dev_err(format, arg...) \
	dev_err(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dev_notice(format, arg...) \
	dev_notice(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dbg(msglvl, format, arg...) \
	netif_dbg(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_info(msglvl, format, arg...) \
	netif_info(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_err(msglvl, format, arg...) \
	netif_err(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_warn(msglvl, format, arg...) \
	netif_warn(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_crit(msglvl, format, arg...) \
	netif_crit(adapter, msglvl, adapter->netdev, format, ## arg)

#endif /* _NGBE_H_ */
