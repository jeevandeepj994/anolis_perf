// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/aer.h>
#include <linux/etherdevice.h>

#include "ngbe.h"
#include "ngbe_phy.h"
#include "ngbe_hw.h"

char ngbe_driver_name[] = "ngbe";

/* ngbe_pci_tbl - PCI Device ID Table
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id ngbe_pci_tbl[] = {
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL_W), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A2), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A2S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A4), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A4S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL2), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL2S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL4), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860AL4S), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860LC), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A1), 0},
	{ PCI_VDEVICE(WANGXUN, NGBE_DEV_ID_EM_WX1860A1L), 0},
	/* required last entry */
	{ .device = 0 }
};

#define DEFAULT_DEBUG_LEVEL_SHIFT 3

static void ngbe_dev_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct ngbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;

	netif_device_detach(netdev);

	pci_disable_device(pdev);
}

static void ngbe_shutdown(struct pci_dev *pdev)
{
	bool wake;

	ngbe_dev_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wake);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

/**
 *  ngbe_init_ops - Inits func ptrs and MAC type
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_ops(struct ngbe_hw *hw)
{
	ngbe_init_phy_ops_common(hw);
	ngbe_init_ops_common(hw);
	ngbe_init_external_phy_ops_common(hw);

	return NGBE_OK;
}

/**
 *  ngbe_init_shared_code - Initialize the shared code
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_shared_code(struct ngbe_hw *hw)
{
	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_SFP ||
	    (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_M88E1512_SFP)
		hw->phy.type = ngbe_phy_m88e1512_sfi;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_RJ45 ||
		 (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_RJ45)
		hw->phy.type = ngbe_phy_m88e1512;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_M88E1512_MIX)
		hw->phy.type = ngbe_phy_m88e1512_unknown;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_YT8521S_SFP ||
		 (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_YT8521S_SFP_GPIO ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_YT8521S_SFP)
		hw->phy.type = ngbe_phy_yt8521s_sfi;
	else if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_INTERNAL_YT8521S_SFP ||
		 (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_INTERNAL_YT8521S_SFP_GPIO)
		hw->phy.type = ngbe_phy_internal_yt8521s_sfi;
	else
		hw->phy.type = ngbe_phy_internal;

	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_M88E1512_SFP ||
	    (hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_LY_YT8521S_SFP ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_YT8521S_SFP_GPIO ||
		(hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_INTERNAL_YT8521S_SFP_GPIO)
		hw->gpio_ctl = 1;

	/* select claus22 */
	wr32(hw, NGBE_MDIO_CLAUSE_SELECT, 0xF);

	return ngbe_init_ops(hw);
}

static int ngbe_sw_init(struct ngbe_adapter *adapter)
{
	struct ngbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	int err;
	u32 ssid = 0;

	/* PCI config space info */
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	hw->revision_id = pdev->revision;
	hw->oem_svid = pdev->subsystem_vendor;
	hw->oem_ssid = pdev->subsystem_device;

	if (pdev->subsystem_vendor == PCI_VENDOR_ID_WANGXUN) {
		hw->subsystem_vendor_id = pdev->subsystem_vendor;
		hw->subsystem_device_id = pdev->subsystem_device;
	} else {
		ssid = ngbe_flash_read_dword(hw, 0xfffdc);
		if (ssid == 0x1) {
			e_err(probe, "read of internal subsystem device id failed\n");
			err = -ENODEV;
			goto out;
		}
		hw->subsystem_device_id = ssid >> 8 | ssid << 8;
	}

	/* phy type, phy ops, mac ops */
	err = ngbe_init_shared_code(hw);
	if (err) {
		e_err(probe, "init_shared_code failed: %d\n", err);
		goto out;
	}

	adapter->mac_table = kzalloc(sizeof(*adapter->mac_table) *
						 hw->mac.num_rar_entries,
						 GFP_ATOMIC);
	if (!adapter->mac_table) {
		err = NGBE_ERR_OUT_OF_MEM;
		e_err(probe, "mac_table allocation failed: %d\n", err);
		goto out;
	}

	/* Set common capability flags and settings */
	adapter->max_q_vectors = NGBE_MAX_MSIX_Q_VECTORS_EMERALD;

	/* set default ring sizes */
	adapter->tx_ring_count = NGBE_DEFAULT_TXD;
	adapter->rx_ring_count = NGBE_DEFAULT_RXD;

	/* set default work limits */
	adapter->tx_work_limit = NGBE_DEFAULT_TX_WORK;
	adapter->rx_work_limit = NGBE_DEFAULT_RX_WORK;

	adapter->tx_timeout_recovery_level = 0;

	set_bit(__NGBE_DOWN, &adapter->state);
out:
	return err;
}

/**
 * ngbe_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 **/
int ngbe_open(struct net_device *netdev)
{
	return 0;
}

/**
 * ngbe_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 **/
int ngbe_close(struct net_device *netdev)
{
	return 0;
}

static const struct net_device_ops ngbe_netdev_ops = {
	.ndo_open = ngbe_open,
	.ndo_stop = ngbe_close,
};

void ngbe_assign_netdev_ops(struct net_device *dev)
{
	dev->netdev_ops = &ngbe_netdev_ops;
}

/**
 * ngbe_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ngbe_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * ngbe_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int ngbe_probe(struct pci_dev *pdev,
		      const struct pci_device_id __always_unused *ent)
{
	struct ngbe_adapter *adapter = NULL;
	struct net_device *netdev;
	struct ngbe_hw *hw = NULL;
	struct device *dev = &pdev->dev;
	int err;
	int size;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev,
			"No usable DMA configuration, aborting\n");
		goto err_pci_disable_dev;
	}

	err = pci_request_selected_regions(pdev,
					   pci_select_bars(pdev, IORESOURCE_MEM),
					   ngbe_driver_name);
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed %d\n", err);
		goto err_pci_disable_dev;
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);

	/* errata 16 */
	pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL,
					   PCI_EXP_DEVCTL_READRQ,
									   0x1000);

	size = sizeof(struct ngbe_adapter);
	netdev = devm_alloc_etherdev_mqs(dev,
					 size,
									 NGBE_MAX_TX_QUEUES,
									 NGBE_MAX_RX_QUEUES);
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
	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

	adapter->io_addr = devm_ioremap(&pdev->dev,
					pci_resource_start(pdev, 0),
					pci_resource_len(pdev, 0));
	if (!adapter->io_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}

	/* default config: 10/100/1000M autoneg on */
	hw->mac.autoneg = true;
	hw->phy.autoneg_advertised = NGBE_LINK_SPEED_AUTONEG;
	hw->phy.force_speed = NGBE_LINK_SPEED_UNKNOWN;
	/* assign netdev ops and ethtool ops */
	ngbe_assign_netdev_ops(netdev);

	/* setup the private structure */
	err = ngbe_sw_init(adapter);
	if (err)
		goto err_sw_init;

	netdev->features |= NETIF_F_HIGHDMA;

	pci_set_drvdata(pdev, adapter);

	hw->phy.reset_if_overtemp = true;
	err = TCALL(hw, mac.ops.reset_hw);
	hw->phy.reset_if_overtemp = false;
	if (err) {
		e_dev_err("HW reset failed: %d\n", err);
		goto err_sw_init;
	}

	return 0;

err_pci_release_regions:
	pci_disable_pcie_error_reporting(pdev);
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_disable_dev:
	pci_disable_device(pdev);
err_sw_init:
	adapter->flags2 &= ~NGBE_FLAG2_SEARCH_FOR_SFP;
	kfree(adapter->mac_table);
	iounmap(adapter->io_addr);

	return err;
}

/**
 * ngbe_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * ngbe_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void ngbe_remove(struct pci_dev *pdev)
{
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

	pci_disable_pcie_error_reporting(pdev);

	pci_disable_device(pdev);
}

static struct pci_driver ngbe_driver = {
	.name     = ngbe_driver_name,
	.id_table = ngbe_pci_tbl,
	.probe    = ngbe_probe,
	.remove   = ngbe_remove,
	.shutdown = ngbe_shutdown,
};

module_pci_driver(ngbe_driver);

MODULE_DEVICE_TABLE(pci, ngbe_pci_tbl);
MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <software@net-swift.com>");
MODULE_DESCRIPTION("WangXun(R) Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
