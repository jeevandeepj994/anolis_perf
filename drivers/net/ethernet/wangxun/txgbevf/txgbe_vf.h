/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2024 Beijing WangXun Technology Co., Ltd. */

#ifndef __TXGBE_VF_H__
#define __TXGBE_VF_H__

#ifndef PCI_VENDOR_ID_WANGXUN
#define PCI_VENDOR_ID_WANGXUN                   0x8088
#endif

#define TXGBE_DEV_ID_SP1000_VF                  0x1000
#define TXGBE_DEV_ID_WX1820_VF                  0x2000

#define TXGBE_VF_MAX_TX_QUEUES  4
#define TXGBE_VF_MAX_RX_QUEUES  4

struct txgbe_adapter {
	u8 __iomem *io_addr;
	u8 __iomem *b4_addr;
	struct net_device *netdev;
	struct pci_dev *pdev;
};

#endif
