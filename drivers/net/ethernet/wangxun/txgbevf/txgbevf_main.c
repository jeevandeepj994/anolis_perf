// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2024 Beijing WangXun Technology Co., Ltd. */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/aer.h>
#include <linux/etherdevice.h>
#include <linux/atomic.h>
#

#include "txgbe_vf.h"
#include "txgbe_mbx.h"

char txgbe_driver_name[] = "txgbevf";

static const char txgbe_driver_string[] =
	"WangXun(R) 10GbE PCI Express Virtual Function Linux Network Driver";

const char txgbe_driver_version[] = __stringify(1.3.1);

char txgbe_firmware_version[TXGBE_FW_VER_SIZE] = "N/A";

/* txgbe_pci_tbl - PCI Device ID Table */
static struct pci_device_id txgbe_pci_tbl[] = {
	{ PCI_VDEVICE(WANGXUN, TXGBE_DEV_ID_SP1000_VF), 0},
	{ PCI_VDEVICE(WANGXUN, TXGBE_DEV_ID_WX1820_VF), 0},
	{ .device = 0 } /* required last entry */
};

static struct txgbe_info txgbe_sp_vf_info = {
	.mac    = txgbe_mac_sp_vf,
	.flags  = 0,
};

static const struct txgbe_info *txgbe_info_tbl[] = {
	[board_sp_vf] = &txgbe_sp_vf_info,
};

static const struct net_device_ops txgbe_netdev_ops = {
	.ndo_open               = txgbe_open,
	.ndo_stop               = txgbe_close,
};

static inline int txgbevf_init_rss_key(struct txgbe_adapter *adapter)
{
	u32 *rss_key;

	if (!adapter->rss_key) {
		rss_key = kzalloc(40, GFP_KERNEL);
		if (unlikely(!rss_key))
			return -ENOMEM;
		netdev_rss_key_fill(rss_key, 40);
		adapter->rss_key = rss_key;
	}
	return 0;
}

int txgbe_open(struct net_device *netdev)
{
	return 0;
}

int txgbe_close(struct net_device *netdev)
{
	return 0;
}

void txgbe_assign_netdev_ops(struct net_device *dev)
{
	dev->netdev_ops = &txgbe_netdev_ops;
}

void txgbe_negotiate_api(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	int api[] = {
		     txgbe_mbox_api_13,
		     txgbe_mbox_api_12,
		     txgbe_mbox_api_11,
		     txgbe_mbox_api_10,
		     txgbe_mbox_api_unknown};
	int err = 0, idx = 0;

	spin_lock_bh(&adapter->mbx_lock);

	while (api[idx] != txgbe_mbox_api_unknown) {
		err = txgbe_negotiate_api_version(hw, api[idx]);
		if (!err)
			break;
		idx++;
	}

	spin_unlock_bh(&adapter->mbx_lock);
}

/**
 * txgbe_sw_init - Initialize general software structures (struct txgbe_adapter)
 * @adapter: board private structure to initialize
 **/
static int txgbe_sw_init(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	struct net_device *netdev = adapter->netdev;
	int err = 0;

	/* PCI config space info */
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;

	txgbe_init_ops_vf(hw);
	hw->mbx.ops.init_params(hw);
	err = txgbevf_init_rss_key(adapter);
	if (err)
		return err;

	/* assume legacy case in which PF would only give VF 2 queues */
	hw->mac.max_tx_queues = 4;
	hw->mac.max_rx_queues = 4;

	/* lock to protect mailbox accesses */
	spin_lock_init(&adapter->mbx_lock);
	spin_lock_init(&adapter->pf_count_lock);

	/*make sure PF is up*/
	if (adapter->bd_number == 0)
		msleep(1500);

	err = hw->mac.ops.reset_hw(hw);
	if (err) {
		dev_info(&pdev->dev,
			 "PF still in reset state.  Is the PF interface up?\n");
	} else {
		err = hw->mac.ops.init_hw(hw);
		if (err) {
			dev_err(&pdev->dev,
				"init_shared_code failed: %d\n", err);
			return err;
		}
		txgbe_negotiate_api(adapter);
		err = hw->mac.ops.get_mac_addr(hw, hw->mac.addr);
		if (err)
			dev_info(&pdev->dev, "Error reading MAC address\n");
		else if (is_zero_ether_addr(adapter->hw.mac.addr))
			dev_info(&pdev->dev,
				 "MAC address not assigned by administrator.\n");
		ether_addr_copy(netdev->dev_addr, hw->mac.addr);
	}

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		dev_info(&pdev->dev, "Assigning random MAC address\n");
		eth_hw_addr_random(netdev);
		ether_addr_copy(hw->mac.addr, netdev->dev_addr);
		ether_addr_copy(hw->mac.perm_addr, netdev->dev_addr);
	}

	/* Enable dynamic interrupt throttling rates */
	adapter->rx_itr_setting = 1;
	adapter->tx_itr_setting = 1;

	/* set default ring sizes */
	adapter->tx_ring_count = TXGBE_DEFAULT_TXD;
	adapter->rx_ring_count = TXGBE_DEFAULT_RXD;

	/* enable rx csum by default */
	adapter->flagsd |= TXGBE_F_CAP_RX_CSUM;

	adapter->link_state = true;

	set_bit(__TXGBE_DOWN, &adapter->state);

	return 0;
}

void txgbe_init_last_counter_stats(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	int i = 0;

	adapter->last_stats.gprc = 0;
	adapter->last_stats.gorc = 0;
	adapter->last_stats.gptc = 0;
	adapter->last_stats.gotc = 0;
	adapter->last_stats.mprc = 0;

	for (i = 0; i < MAX_RX_QUEUES; i++) {
		adapter->last_reg_stats[i].gprc = rd32(hw, TXGBE_VXGPRC(i));
		adapter->last_stats.gprc += adapter->last_reg_stats[i].gprc;

		adapter->last_reg_stats[i].gorc = rd32(hw, TXGBE_VXGORC_LSB(i));
		adapter->last_reg_stats[i].gorc = adapter->last_reg_stats[i].gorc |
			((u64)(rd32(hw, TXGBE_VXGORC_MSB(i))) << 32);
		adapter->last_stats.gorc += adapter->last_reg_stats[i].gorc;

		adapter->last_reg_stats[i].gptc = rd32(hw, TXGBE_VXGPTC(i));
		adapter->last_stats.gptc += adapter->last_reg_stats[i].gptc;

		adapter->last_reg_stats[i].gotc = rd32(hw, TXGBE_VXGOTC_LSB(i));
		adapter->last_reg_stats[i].gotc = adapter->last_reg_stats[i].gotc |
			((u64)(rd32(hw, TXGBE_VXGOTC_MSB(i))) << 32);
		adapter->last_stats.gotc += adapter->last_reg_stats[i].gotc;

		adapter->last_reg_stats[i].mprc = rd32(hw, TXGBE_VXMPRC(i));
		adapter->last_stats.mprc += adapter->last_reg_stats[i].mprc;

		adapter->reg_stats[i].gprc = 0;
		adapter->reg_stats[i].gorc = 0;
		adapter->reg_stats[i].gptc = 0;
		adapter->reg_stats[i].gotc = 0;
		adapter->reg_stats[i].mprc = 0;
	}

	adapter->base_stats.gprc = adapter->last_stats.gprc;
	adapter->base_stats.gorc = adapter->last_stats.gorc;
	adapter->base_stats.gptc = adapter->last_stats.gptc;
	adapter->base_stats.gotc = adapter->last_stats.gotc;
	adapter->base_stats.mprc = adapter->last_stats.mprc;
}
/**
 * txgbe_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in txgbe_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * txgbe_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int txgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct txgbe_adapter *adapter = NULL;
	struct net_device *netdev;
	int err;
	struct txgbe_hw *hw = NULL;
	const struct txgbe_info *ei = txgbe_info_tbl[ent->driver_data];
	static int cards_found;
	unsigned int min_mtu, max_mtu;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = pci_request_selected_regions(pdev,
					   pci_select_bars(pdev, IORESOURCE_MEM),
					   txgbe_driver_name);
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed 0x%x\n", err);
		goto err_pci_disable_dev;
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev,
			"No usable DMA configuration, aborting\n");
		goto err_pci_disable_dev;
	}

	netdev = devm_alloc_etherdev_mqs(&pdev->dev,
					 sizeof(struct txgbe_adapter),
					 TXGBE_VF_MAX_TX_QUEUES,
					 TXGBE_VF_MAX_RX_QUEUES);
	if (!netdev) {
		err = -ENOMEM;
		goto err_pci_release_regions;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;

	hw->back = adapter;
	hw->msg_enable = &adapter->msg_enable;
	hw->pdev = adapter->pdev;
	hw->mac.type = ei->mac;
	adapter->flagsd = ei->flags;
	adapter->msg_enable = DEFAULT_DEBUG_LEVEL;

	pci_save_state(pdev);

	adapter->io_addr = devm_ioremap(&pdev->dev,
					pci_resource_start(pdev, 0),
					pci_resource_len(pdev, 0));
	if (!adapter->io_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}

	adapter->b4_addr = devm_ioremap(&pdev->dev,
					pci_resource_start(pdev, 4),
					pci_resource_len(pdev, 4));
	if (!adapter->b4_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}

	txgbe_assign_netdev_ops(netdev);
	adapter->bd_number = cards_found;

		/* setup the private structure */
	err = txgbe_sw_init(adapter);
	if (err)
		goto err_sw_init;

	min_mtu = ETH_MIN_MTU;
	switch (adapter->hw.api_version) {
	case txgbe_mbox_api_11:
	case txgbe_mbox_api_12:
	case txgbe_mbox_api_13:
		max_mtu = TXGBE_MAX_JUMBO_FRAME_SIZE -
			  (ETH_HLEN + ETH_FCS_LEN);
		break;
	default:
		if (adapter->hw.mac.type != txgbe_mac_sp_vf)
			max_mtu = TXGBE_MAX_JUMBO_FRAME_SIZE -
				  (ETH_HLEN + ETH_FCS_LEN);
		else
			max_mtu = ETH_DATA_LEN + ETH_FCS_LEN;
		break;
	}

	netdev->min_mtu = min_mtu;
	netdev->max_mtu = max_mtu;

	hw->mac.ops.get_fw_version(hw);

	strcpy(netdev->name, "eth%d");

	err = register_netdev(netdev);
	if (err)
		goto err_sw_init;

	pci_set_drvdata(pdev, netdev);
	netif_carrier_off(netdev);

	netif_tx_stop_all_queues(netdev);
	txgbe_init_last_counter_stats(adapter);

	cards_found++;

	return 0;

err_sw_init:
	iounmap(adapter->io_addr);
err_pci_release_regions:
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_disable_dev:
	if (!adapter)
		pci_disable_device(pdev);
	return err;
}

/**
 * txgbe_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * txgbe_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void txgbe_remove(struct pci_dev *pdev)
{
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

	pci_disable_pcie_error_reporting(pdev);
}

static struct pci_driver txgbe_driver = {
	.name     = txgbe_driver_name,
	.id_table = txgbe_pci_tbl,
	.probe    = txgbe_probe,
	.remove   = txgbe_remove,
};

/**
 * txgbe_init_module - Driver Registration Routine
 *
 * txgbe_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init txgbe_init_module(void)
{
	int ret;

	ret = pci_register_driver(&txgbe_driver);
	return ret;
}

module_init(txgbe_init_module);

/**
 * txgbe_exit_module - Driver Exit Cleanup Routine
 *
 * txgbe_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit txgbe_exit_module(void)
{
	pci_unregister_driver(&txgbe_driver);
}

module_exit(txgbe_exit_module);

MODULE_DEVICE_TABLE(pci, txgbe_pci_tbl);
MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <software@trustnetic.com>");
MODULE_DESCRIPTION("WangXun(R) 10 Gigabit PCI Express Virtual Function Network Driver");
MODULE_LICENSE("GPL");
