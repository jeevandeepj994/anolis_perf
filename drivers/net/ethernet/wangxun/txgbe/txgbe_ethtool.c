// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/firmware.h>
#include <linux/net_tstamp.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "txgbe.h"
#include "txgbe_hw.h"
#include "txgbe_phy.h"

#define TXGBE_ALL_RAR_ENTRIES 16
#define TXGBE_RSS_INDIR_TBL_MAX 64

enum {NETDEV_STATS, TXGBE_STATS};

struct txgbe_stats {
	char stat_string[ETH_GSTRING_LEN];
	int type;
	int sizeof_stat;
	int stat_offset;
};

#define TXGBE_STAT(str, m) { \
		.stat_string = str, \
		.type = TXGBE_STATS, \
		.sizeof_stat = sizeof(((struct txgbe_adapter *)0)->m), \
		.stat_offset = offsetof(struct txgbe_adapter, m) }
#define TXGBE_NETDEV_STAT(str, m) { \
		.stat_string = str, \
		.type = NETDEV_STATS, \
		.sizeof_stat = sizeof(((struct rtnl_link_stats64 *)0)->m), \
		.stat_offset = offsetof(struct rtnl_link_stats64, m) }

static const struct txgbe_stats txgbe_gstrings_stats[] = {
	TXGBE_NETDEV_STAT("rx_packets", rx_packets),
	TXGBE_NETDEV_STAT("tx_packets", tx_packets),
	TXGBE_NETDEV_STAT("rx_bytes", rx_bytes),
	TXGBE_NETDEV_STAT("tx_bytes", tx_bytes),
	TXGBE_STAT("rx_pkts_nic", stats.gprc),
	TXGBE_STAT("tx_pkts_nic", stats.gptc),
	TXGBE_STAT("rx_bytes_nic", stats.gorc),
	TXGBE_STAT("tx_bytes_nic", stats.gotc),
	TXGBE_STAT("lsc_int", lsc_int),
	TXGBE_STAT("tx_busy", tx_busy),
	TXGBE_STAT("non_eop_descs", non_eop_descs),
	TXGBE_NETDEV_STAT("rx_errors", rx_errors),
	TXGBE_NETDEV_STAT("tx_errors", tx_errors),
	TXGBE_NETDEV_STAT("rx_dropped", rx_dropped),
	TXGBE_NETDEV_STAT("tx_dropped", tx_dropped),
	TXGBE_NETDEV_STAT("multicast", multicast),
	TXGBE_STAT("broadcast", stats.bprc),
	TXGBE_STAT("rx_no_buffer_count", stats.rnbc[0]),
	TXGBE_NETDEV_STAT("collisions", collisions),
	TXGBE_NETDEV_STAT("rx_over_errors", rx_over_errors),
	TXGBE_NETDEV_STAT("rx_crc_errors", rx_crc_errors),
	TXGBE_NETDEV_STAT("rx_frame_errors", rx_frame_errors),
	TXGBE_STAT("hw_rsc_aggregated", rsc_total_count),
	TXGBE_STAT("hw_rsc_flushed", rsc_total_flush),
	TXGBE_STAT("fdir_match", stats.fdirmatch),
	TXGBE_STAT("fdir_miss", stats.fdirmiss),
	TXGBE_STAT("fdir_overflow", fdir_overflow),
	TXGBE_NETDEV_STAT("rx_fifo_errors", rx_fifo_errors),
	TXGBE_NETDEV_STAT("rx_missed_errors", rx_missed_errors),
	TXGBE_NETDEV_STAT("tx_aborted_errors", tx_aborted_errors),
	TXGBE_NETDEV_STAT("tx_carrier_errors", tx_carrier_errors),
	TXGBE_NETDEV_STAT("tx_fifo_errors", tx_fifo_errors),
	TXGBE_NETDEV_STAT("tx_heartbeat_errors", tx_heartbeat_errors),
	TXGBE_STAT("tx_timeout_count", tx_timeout_count),
	TXGBE_STAT("tx_restart_queue", restart_queue),
	TXGBE_STAT("rx_long_length_count", stats.roc),
	TXGBE_STAT("rx_short_length_count", stats.ruc),
	TXGBE_STAT("tx_flow_control_xon", stats.lxontxc),
	TXGBE_STAT("rx_flow_control_xon", stats.lxonrxc),
	TXGBE_STAT("tx_flow_control_xoff", stats.lxofftxc),
	TXGBE_STAT("rx_flow_control_xoff", stats.lxoffrxc),
	TXGBE_STAT("rx_csum_offload_good_count", hw_csum_rx_good),
	TXGBE_STAT("rx_csum_offload_errors", hw_csum_rx_error),
	TXGBE_STAT("alloc_rx_page_failed", alloc_rx_page_failed),
	TXGBE_STAT("alloc_rx_buff_failed", alloc_rx_buff_failed),
	TXGBE_STAT("rx_no_dma_resources", hw_rx_no_dma_resources),
	TXGBE_STAT("os2bmc_rx_by_bmc", stats.o2bgptc),
	TXGBE_STAT("os2bmc_tx_by_bmc", stats.b2ospc),
	TXGBE_STAT("os2bmc_tx_by_host", stats.o2bspc),
	TXGBE_STAT("os2bmc_rx_by_host", stats.b2ogprc),
	TXGBE_STAT("tx_hwtstamp_timeouts", tx_hwtstamp_timeouts),
	TXGBE_STAT("rx_hwtstamp_cleared", rx_hwtstamp_cleared),
};

/* txgbe allocates num_tx_queues and num_rx_queues symmetrically so
 * we set the num_rx_queues to evaluate to num_tx_queues. This is
 * used because we do not have a good way to get the max number of
 * rx queues with CONFIG_RPS disabled.
 */
#define TXGBE_NUM_RX_QUEUES netdev->num_tx_queues
#define TXGBE_NUM_TX_QUEUES netdev->num_tx_queues

#define TXGBE_QUEUE_STATS_LEN ( \
		(TXGBE_NUM_TX_QUEUES + TXGBE_NUM_RX_QUEUES) * \
		(sizeof(struct txgbe_queue_stats) / sizeof(u64)))
#define TXGBE_GLOBAL_STATS_LEN  ARRAY_SIZE(txgbe_gstrings_stats)
#define TXGBE_PB_STATS_LEN ( \
		(sizeof(((struct txgbe_adapter *)0)->stats.pxonrxc) + \
		 sizeof(((struct txgbe_adapter *)0)->stats.pxontxc) + \
		 sizeof(((struct txgbe_adapter *)0)->stats.pxoffrxc) + \
		 sizeof(((struct txgbe_adapter *)0)->stats.pxofftxc)) \
		/ sizeof(u64))
#define TXGBE_STATS_LEN (TXGBE_GLOBAL_STATS_LEN + \
			 TXGBE_PB_STATS_LEN + \
			 TXGBE_QUEUE_STATS_LEN)

static const char txgbe_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)", "Eeprom test    (offline)",
	"Interrupt test (offline)", "Loopback test  (offline)",
	"Link test   (on/offline)"
};

#define TXGBE_TEST_LEN  (sizeof(txgbe_gstrings_test) / ETH_GSTRING_LEN)

/* currently supported speeds for 10G */
#define ADVERTISED_MASK_10G (SUPPORTED_10000baseT_Full | \
			     SUPPORTED_10000baseKX4_Full | \
			     SUPPORTED_10000baseKR_Full)

#define txgbe_isbackplane(type)  \
			((type == txgbe_media_type_backplane) ? true : false)

static __u32 txgbe_backplane_type(struct txgbe_hw *hw)
{
	__u32 mode = 0x00;

	switch (hw->phy.link_mode) {
	case TXGBE_PHYSICAL_LAYER_10GBASE_KX4:
		mode = SUPPORTED_10000baseKX4_Full;
		break;
	case TXGBE_PHYSICAL_LAYER_10GBASE_KR:
		mode = SUPPORTED_10000baseKR_Full;
		break;
	case TXGBE_PHYSICAL_LAYER_1000BASE_KX:
		mode = SUPPORTED_1000baseKX_Full;
		break;
	default:
		mode = (SUPPORTED_10000baseKX4_Full |
			SUPPORTED_10000baseKR_Full |
			SUPPORTED_1000baseKX_Full);
		break;
	}
	return mode;
}

static int txgbe_get_link_ksettings(struct net_device *netdev,
				    struct ethtool_link_ksettings *cmd)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	u32 supported_link;
	u32 link_speed = 0;
	bool autoneg = false;
	u32 supported, advertising;
	bool link_up;

	ethtool_convert_link_mode_to_legacy_u32(&supported,
						cmd->link_modes.supported);

	TCALL(hw, mac.ops.get_link_capabilities, &supported_link, &autoneg);

	/* set the supported link speeds */
	if (supported_link & TXGBE_LINK_SPEED_10GB_FULL)
		supported |= (txgbe_isbackplane(hw->phy.media_type)) ?
			txgbe_backplane_type(hw) : SUPPORTED_10000baseT_Full;
	if (supported_link & TXGBE_LINK_SPEED_1GB_FULL)
		supported |= (txgbe_isbackplane(hw->phy.media_type)) ?
			SUPPORTED_1000baseKX_Full : SUPPORTED_1000baseT_Full;
	if (supported_link & TXGBE_LINK_SPEED_100_FULL)
		supported |= SUPPORTED_100baseT_Full;
	if (supported_link & TXGBE_LINK_SPEED_10_FULL)
		supported |= SUPPORTED_10baseT_Full;

	/* default advertised speed if phy.autoneg_advertised isn't set */
	advertising = supported;

	/* set the advertised speeds */
	if (hw->phy.autoneg_advertised) {
		advertising = 0;
		if (hw->phy.autoneg_advertised & TXGBE_LINK_SPEED_100_FULL)
			advertising |= ADVERTISED_100baseT_Full;
		if (hw->phy.autoneg_advertised & TXGBE_LINK_SPEED_10GB_FULL)
			advertising |= (supported & ADVERTISED_MASK_10G);
		if (hw->phy.autoneg_advertised & TXGBE_LINK_SPEED_1GB_FULL) {
			if (supported & SUPPORTED_1000baseKX_Full)
				advertising |= ADVERTISED_1000baseKX_Full;
			else
				advertising |= ADVERTISED_1000baseT_Full;
		}
		if (hw->phy.autoneg_advertised & TXGBE_LINK_SPEED_10_FULL)
			advertising |= ADVERTISED_10baseT_Full;
	} else {
		/* default modes in case phy.autoneg_advertised isn't set */
		if (supported_link & TXGBE_LINK_SPEED_10GB_FULL)
			advertising |= ADVERTISED_10000baseT_Full;
		if (supported_link & TXGBE_LINK_SPEED_1GB_FULL)
			advertising |= ADVERTISED_1000baseT_Full;
		if (supported_link & TXGBE_LINK_SPEED_100_FULL)
			advertising |= ADVERTISED_100baseT_Full;
		if (hw->phy.multispeed_fiber && !autoneg) {
			if (supported_link & TXGBE_LINK_SPEED_10GB_FULL)
				advertising = ADVERTISED_10000baseT_Full;
		}
		if (supported_link & TXGBE_LINK_SPEED_10_FULL)
			advertising |= ADVERTISED_10baseT_Full;
	}

	if (autoneg) {
		supported |= SUPPORTED_Autoneg;
		advertising |= ADVERTISED_Autoneg;
		cmd->base.autoneg = AUTONEG_ENABLE;
	} else {
		cmd->base.autoneg = AUTONEG_DISABLE;
	}

	/* Determine the remaining settings based on the PHY type. */
	switch (adapter->hw.phy.type) {
	case txgbe_phy_tn:
	case txgbe_phy_aq:
	case txgbe_phy_cu_unknown:
		supported |= SUPPORTED_TP;
		advertising |= ADVERTISED_TP;
		cmd->base.port = PORT_TP;
		break;
	case txgbe_phy_qt:
		supported |= SUPPORTED_FIBRE;
		advertising |= ADVERTISED_FIBRE;
		cmd->base.port = PORT_FIBRE;
		break;
	case txgbe_phy_nl:
	case txgbe_phy_sfp_passive_tyco:
	case txgbe_phy_sfp_passive_unknown:
	case txgbe_phy_sfp_ftl:
	case txgbe_phy_sfp_avago:
	case txgbe_phy_sfp_intel:
	case txgbe_phy_sfp_unknown:
		switch (adapter->hw.phy.sfp_type) {
			/* SFP+ devices, further checking needed */
		case txgbe_sfp_type_da_cu:
		case txgbe_sfp_type_da_cu_core0:
		case txgbe_sfp_type_da_cu_core1:
			supported |= SUPPORTED_FIBRE;
			advertising |= ADVERTISED_FIBRE;
			cmd->base.port = PORT_DA;
			break;
		case txgbe_sfp_type_sr:
		case txgbe_sfp_type_lr:
		case txgbe_sfp_type_srlr_core0:
		case txgbe_sfp_type_srlr_core1:
		case txgbe_sfp_type_1g_sx_core0:
		case txgbe_sfp_type_1g_sx_core1:
		case txgbe_sfp_type_1g_lx_core0:
		case txgbe_sfp_type_1g_lx_core1:
			supported |= SUPPORTED_FIBRE;
			advertising |= ADVERTISED_FIBRE;
			cmd->base.port = PORT_FIBRE;
			break;
		case txgbe_sfp_type_not_present:
			supported |= SUPPORTED_FIBRE;
			advertising |= ADVERTISED_FIBRE;
			cmd->base.port = PORT_NONE;
			break;
		case txgbe_sfp_type_1g_cu_core0:
		case txgbe_sfp_type_1g_cu_core1:
			supported |= SUPPORTED_TP;
			advertising |= ADVERTISED_TP;
			cmd->base.port = PORT_TP;
			break;
		case txgbe_sfp_type_unknown:
		default:
			supported |= SUPPORTED_FIBRE;
			advertising |= ADVERTISED_FIBRE;
			cmd->base.port = PORT_OTHER;
			break;
		}
		break;
	case txgbe_phy_xaui:
		supported |= SUPPORTED_TP;
		advertising |= ADVERTISED_TP;
		cmd->base.port = PORT_TP;
		break;
	case txgbe_phy_unknown:
	case txgbe_phy_generic:
	case txgbe_phy_sfp_unsupported:
	default:
		supported |= SUPPORTED_FIBRE;
		advertising |= ADVERTISED_FIBRE;
		cmd->base.port = PORT_OTHER;
		break;
	}

	if (!in_interrupt()) {
		TCALL(hw, mac.ops.check_link, &link_speed, &link_up, false);
	} else {
		link_speed = adapter->link_speed;
		link_up = adapter->link_up;
	}

	supported |= SUPPORTED_Pause;

	switch (hw->fc.requested_mode) {
	case txgbe_fc_full:
		advertising |= ADVERTISED_Pause;
		break;
	case txgbe_fc_rx_pause:
		advertising |= ADVERTISED_Pause |
				ADVERTISED_Asym_Pause;
		break;
	case txgbe_fc_tx_pause:
		advertising |= ADVERTISED_Asym_Pause;
		break;
	default:
		advertising &= ~(ADVERTISED_Pause |
				 ADVERTISED_Asym_Pause);
	}

	if (link_up) {
		switch (link_speed) {
		case TXGBE_LINK_SPEED_10GB_FULL:
			cmd->base.speed = SPEED_10000;
			break;
		case TXGBE_LINK_SPEED_1GB_FULL:
			cmd->base.speed = SPEED_1000;
			break;
		case TXGBE_LINK_SPEED_100_FULL:
			cmd->base.speed = SPEED_100;
			break;
		case TXGBE_LINK_SPEED_10_FULL:
			cmd->base.speed = SPEED_10;
			break;
		default:
			break;
		}
		cmd->base.duplex = DUPLEX_FULL;
	} else {
		cmd->base.speed = -1;
		cmd->base.duplex = -1;
	}

	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.supported,
						supported);
	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.advertising,
						advertising);
	return 0;
}

static int txgbe_set_link_ksettings(struct net_device *netdev,
				    const struct ethtool_link_ksettings *cmd)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	u32 advertised, old;
	s32 err = 0;
	u32 supported, advertising;

	ethtool_convert_link_mode_to_legacy_u32(&supported,
						cmd->link_modes.supported);
	ethtool_convert_link_mode_to_legacy_u32(&advertising,
						cmd->link_modes.advertising);

	if (hw->phy.multispeed_fiber) {
		/* this function does not support duplex forcing, but can
		 * limit the advertising of the adapter to the specified speed
		 */
		if (advertising & ~supported)
			return -EINVAL;

		/* only allow one speed at a time if no autoneg */
		if (!cmd->base.autoneg && hw->phy.multispeed_fiber) {
			if (advertising == (ADVERTISED_10000baseT_Full |
			    ADVERTISED_1000baseT_Full))
				return -EINVAL;
		}
		old = hw->phy.autoneg_advertised;
		advertised = 0;
		if (advertising & ADVERTISED_10000baseT_Full)
			advertised |= TXGBE_LINK_SPEED_10GB_FULL;

		if (advertising & ADVERTISED_1000baseT_Full)
			advertised |= TXGBE_LINK_SPEED_1GB_FULL;

		if (advertising & ADVERTISED_100baseT_Full)
			advertised |= TXGBE_LINK_SPEED_100_FULL;

		if (advertising & ADVERTISED_10baseT_Full)
			advertised |= TXGBE_LINK_SPEED_10_FULL;

		if (old == advertised)
			return err;
		/* this sets the link speed and restarts auto-neg */
		while (test_and_set_bit(__TXGBE_IN_SFP_INIT, &adapter->state))
			usleep_range(1000, 2000);

		hw->mac.autotry_restart = true;
		err = TCALL(hw, mac.ops.setup_link, advertised, true);
		if (err) {
			netif_info(adapter, probe, adapter->netdev,
				   "setup link failed with code %d\n", err);
			TCALL(hw, mac.ops.setup_link, old, true);
		}
		if ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP)
			TCALL(hw, mac.ops.flap_tx_laser);
		clear_bit(__TXGBE_IN_SFP_INIT, &adapter->state);
	} else if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_KR_KX_KX4 ||
		   (hw->subsystem_device_id & 0xF0) == TXGBE_ID_MAC_SGMII) {
		if (!cmd->base.autoneg) {
			if (advertising == (ADVERTISED_10000baseKR_Full |
					    ADVERTISED_1000baseKX_Full |
					    ADVERTISED_10000baseKX4_Full))
				return -EINVAL;
		} else {
			err = txgbe_set_link_to_kr(hw, 1);
			return err;
		}
		advertised = 0;
		if (advertising & ADVERTISED_10000baseKR_Full) {
			err = txgbe_set_link_to_kr(hw, 1);
			advertised |= TXGBE_LINK_SPEED_10GB_FULL;
		} else if (advertising & ADVERTISED_10000baseKX4_Full) {
			err = txgbe_set_link_to_kx4(hw, 1);
			advertised |= TXGBE_LINK_SPEED_10GB_FULL;
		} else if (advertising & ADVERTISED_1000baseKX_Full) {
			advertised |= TXGBE_LINK_SPEED_1GB_FULL;
			err = txgbe_set_link_to_kx(hw, TXGBE_LINK_SPEED_1GB_FULL, 0);
		}
	} else {
		/* in this case we currently only support 10Gb/FULL */
		u32 speed = cmd->base.speed;

		if (cmd->base.autoneg == AUTONEG_ENABLE ||
		    advertising != ADVERTISED_10000baseT_Full ||
		    (speed + cmd->base.duplex != SPEED_10000 + DUPLEX_FULL))
			return -EINVAL;
	}

	return err;
}

static void txgbe_get_pauseparam(struct net_device *netdev,
				 struct ethtool_pauseparam *pause)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;

	if (txgbe_device_supports_autoneg_fc(hw) &&
	    !hw->fc.disable_fc_autoneg)
		pause->autoneg = 1;
	else
		pause->autoneg = 0;

	if (hw->fc.current_mode == txgbe_fc_rx_pause) {
		pause->rx_pause = 1;
	} else if (hw->fc.current_mode == txgbe_fc_tx_pause) {
		pause->tx_pause = 1;
	} else if (hw->fc.current_mode == txgbe_fc_full) {
		pause->rx_pause = 1;
		pause->tx_pause = 1;
	}
}

static int txgbe_set_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pause)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	struct txgbe_fc_info fc = hw->fc;

	/* some devices do not support autoneg of flow control */
	if (pause->autoneg == AUTONEG_ENABLE &&
	    !txgbe_device_supports_autoneg_fc(hw))
		return -EINVAL;

	fc.disable_fc_autoneg = (pause->autoneg != AUTONEG_ENABLE);

	if ((pause->rx_pause && pause->tx_pause) || pause->autoneg)
		fc.requested_mode = txgbe_fc_full;
	else if (pause->rx_pause)
		fc.requested_mode = txgbe_fc_rx_pause;
	else if (pause->tx_pause)
		fc.requested_mode = txgbe_fc_tx_pause;
	else
		fc.requested_mode = txgbe_fc_none;

	/* if the thing changed then we'll update and use new autoneg */
	if (memcmp(&fc, &hw->fc, sizeof(struct txgbe_fc_info))) {
		hw->fc = fc;
		if (netif_running(netdev))
			txgbe_reinit_locked(adapter);
		else
			txgbe_reset(adapter);
	}

	return 0;
}

static u32 txgbe_get_msglevel(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	return adapter->msg_enable;
}

static void txgbe_set_msglevel(struct net_device *netdev, u32 data)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	adapter->msg_enable = data;
}

#define TXGBE_REGS_LEN  4096
static int txgbe_get_regs_len(struct net_device __always_unused *netdev)
{
	return TXGBE_REGS_LEN * sizeof(u32);
}

#define TXGBE_GET_STAT(_A_, _R_)        (_A_->stats._R_)

static void txgbe_get_regs(struct net_device *netdev, struct ethtool_regs *regs,
			   void *p)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	u32 *regs_buff = p;
	u32 i;
	u32 id = 0;

	memset(p, 0, TXGBE_REGS_LEN * sizeof(u32));
	regs_buff[TXGBE_REGS_LEN - 1] = 0x55555555;

	regs->version = hw->revision_id << 16 |
			hw->device_id;

	/* Global Registers */
	/* chip control */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_PWR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_PF_SM);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_RST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_ST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_SWSM);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_MIS_RST_ST);
	/* pvt sensor */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_EN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_ST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_ALARM_THRE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_DALARM_THRE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_INT_EN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TS_ALARM_ST);
	/* Fmgr Register */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_CMD);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_DATA);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_STATUS);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_USR_CMD);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_CMDCFG0);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_CMDCFG1);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_ILDR_STATUS);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_SPI_ILDR_SWPTR);

	/* Port Registers */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_PORT_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_PORT_ST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_EX_VTYPE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_VXLAN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_VXLAN_GPE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_GENEVE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_TEREDO);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_TCP_TIME);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_LED_CTL);
	/* GPIO */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_GPIO_DR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_GPIO_DDR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_GPIO_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_GPIO_INTEN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_GPIO_INTMASK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_GPIO_INTSTATUS);
	/* I2C */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CON);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_TAR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_DATA_CMD);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_SS_SCL_HCNT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_SS_SCL_LCNT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_FS_SCL_HCNT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_FS_SCL_LCNT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_HS_SCL_HCNT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_INTR_STAT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_INTR_MASK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_RAW_INTR_STAT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_RX_TL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_TX_TL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_INTR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_RX_UNDER);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_RX_OVER);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_TX_OVER);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_RD_REQ);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_TX_ABRT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_RX_DONE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_ACTIVITY);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_STOP_DET);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_START_DET);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_GEN_CALL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_ENABLE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_STATUS);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_TXFLR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_RXFLR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_SDA_HOLD);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_TX_ABRT_SOURCE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_SDA_SETUP);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_ENABLE_STATUS);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_FS_SPKLEN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_HS_SPKLEN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_SCL_STUCK_TIMEOUT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_SDA_STUCK_TIMEOUT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_CLR_SCL_STUCK_DET);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_DEVICE_ID);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_COMP_PARAM_1);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_COMP_VERSION);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_I2C_COMP_TYPE);
	/* TX TPH */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_TPH_TDESC);
	/* RX TPH */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_TPH_RDESC);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_TPH_RHDR);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_CFG_TPH_RPL);

	/* TDMA */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_VF_TE(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_VF_TE(1));
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_PB_THRE(i));
	for (i = 0; i < 4; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_LLQ(i));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_ETYPE_LB_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_ETYPE_LB_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_ETYPE_AS_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_ETYPE_AS_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_MAC_AS_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_MAC_AS_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_VLAN_AS_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_VLAN_AS_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_TCP_FLG_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_TCP_FLG_H);
	for (i = 0; i < 64; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_VLAN_INS(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_ETAG_INS(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_PBWARB_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_MMW);
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_PBWARB_CFG(i));
	for (i = 0; i < 128; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_VM_CREDIT(i));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_FC_EOF);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDM_FC_SOF);

	/* RDMA */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_ARB_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_VF_RE(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_VF_RE(1));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_RSC_CTL);
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_ARB_CFG(i));
	for (i = 0; i < 4; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_PF_QDE(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDM_PF_HIDE(i));
	}

	/* RDB */
	/*flow control */
	for (i = 0; i < 4; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RFCV(i));
	for (i = 0; i < 8; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RFCL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RFCH(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RFCRT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RFCC);
	/* receive packet buffer */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_PB_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_PB_WRAP);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_UP2TC);
	for (i = 0; i < 8; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_PB_SZ(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_MPCNT(i));
	}
	/* lli interrupt */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_LLI_THRE);
	/* ring assignment */
	for (i = 0; i < 64; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_PL_CFG(i));
	for (i = 0; i < 32; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RSSTBL(i));
	for (i = 0; i < 10; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RSSRK(i));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RSS_TC);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_RA_CTL);
	for (i = 0; i < 128; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_5T_SA(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_5T_DA(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_5T_SDP(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_5T_CTL0(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_5T_CTL1(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_SYN_CLS);
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_ETYPE_CLS(i));
	/* fcoe redirection table */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FCRE_CTL);
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FCRE_TBL(i));
	/*flow director */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_HKEY);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_SKEY);
	for (i = 0; i < 16; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_FLEX_CFG(i));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_FREE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_LEN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_USE_ST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_FAIL_ST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_MATCH);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_MISS);
	for (i = 0; i < 3; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_IP6(i));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_SA);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_DA);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_PORT);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_FLEX);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_HASH);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_CMD);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_DA4_MSK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_SA4_MSK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_TCP_MSK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_UDP_MSK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_SCTP_MSK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_IP6_MSK);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RDB_FDIR_OTHER_MSK);

	/* PSR */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VLAN_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VM_CTL);
	for (i = 0; i < 64; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VM_L2CTL(i));
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_ETYPE_SWC(i));
	for (i = 0; i < 128; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MC_TBL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_UC_TBL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VLAN_TBL(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MAC_SWC_AD_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MAC_SWC_AD_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MAC_SWC_VM_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MAC_SWC_VM_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MAC_SWC_IDX);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VLAN_SWC);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VLAN_SWC_VM_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VLAN_SWC_VM_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_VLAN_SWC_IDX);
	for (i = 0; i < 4; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MR_CTL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MR_VLAN_L(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MR_VLAN_H(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MR_VM_L(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_MR_VM_H(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_1588_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_1588_STMPL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_1588_STMPH);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_1588_ATTRL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_1588_ATTRH);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_1588_MSGTYPE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_WKUP_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_WKUP_IPV);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_LAN_FLEX_CTL);
	for (i = 0; i < 4; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_WKUP_IP4TBL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_WKUP_IP6TBL(i));
	}
	for (i = 0; i < 16; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_LAN_FLEX_DW_L(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_LAN_FLEX_DW_H(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_LAN_FLEX_MSK(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PSR_LAN_FLEX_CTL);

	/* TDB */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDB_RFCS);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDB_PB_SZ(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDB_UP2TC);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDB_PBRARB_CTL);
	for (i = 0; i < 8; i++)
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDB_PBRARB_CFG(i));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TDB_MNG_TC);

	/* tsec */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_ST);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_BUF_AF);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_BUF_AE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_MIN_IFG);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_STMPL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_STMPH);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_SYSTIML);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_SYSTIMH);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_INC);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_ADJL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_TSC_1588_ADJH);

	/* RSEC */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RSC_CTL);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_RSC_ST);

	/* BAR register */
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_MISC_IC);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_MISC_ICS);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_MISC_IEN);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_GPIE);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IC(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IC(1));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_ICS(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_ICS(1));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IMS(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IMS(1));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IMC(0));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IMC(1));
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_ISB_ADDR_L);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_ISB_ADDR_H);
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_ITRSEL);
	for (i = 0; i < 64; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_ITR(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_IVAR(i));
	}
	regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_MISC_IVAR);
	for (i = 0; i < 128; i++) {
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_RR_BAL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_RR_BAH(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_RR_WP(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_RR_RP(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_RR_CFG(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_TR_BAL(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_TR_BAH(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_TR_WP(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_TR_RP(i));
		regs_buff[id++] = TXGBE_R32_Q(hw, TXGBE_PX_TR_CFG(i));
	}
}

static int txgbe_get_eeprom_len(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	return adapter->hw.eeprom.word_size * 2;
}

static int txgbe_get_eeprom(struct net_device *netdev,
			    struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	u16 *eeprom_buff;
	int first_word, last_word, eeprom_len;
	int ret_val = 0;
	u16 i;

	if (eeprom->len == 0)
		return -EINVAL;

	eeprom->magic = hw->vendor_id | (hw->device_id << 16);

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;
	eeprom_len = last_word - first_word + 1;

	eeprom_buff = kmalloc_array(eeprom_len, sizeof(u16), GFP_KERNEL);
	if (!eeprom_buff)
		return -ENOMEM;

	ret_val = TCALL(hw, eeprom.ops.read_buffer, first_word, eeprom_len,
			eeprom_buff);

	/* Device's eeprom is always little-endian, word addressable */
	for (i = 0; i < eeprom_len; i++)
		le16_to_cpus(&eeprom_buff[i]);

	memcpy(bytes, (u8 *)eeprom_buff + (eeprom->offset & 1), eeprom->len);
	kfree(eeprom_buff);

	return ret_val;
}

static int txgbe_set_eeprom(struct net_device *netdev,
			    struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	u16 *eeprom_buff;
	void *ptr;
	int max_len, first_word, last_word, ret_val = 0;
	u16 i;

	if (eeprom->len == 0)
		return -EINVAL;

	if (eeprom->magic != (hw->vendor_id | (hw->device_id << 16)))
		return -EINVAL;

	max_len = hw->eeprom.word_size * 2;

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;
	eeprom_buff = kmalloc(max_len, GFP_KERNEL);
	if (!eeprom_buff)
		return -ENOMEM;

	ptr = eeprom_buff;

	if (eeprom->offset & 1) {
		/* need read/modify/write of first changed EEPROM word
		 * only the second byte of the word is being modified
		 */
		ret_val = TCALL(hw, eeprom.ops.read, first_word,
				&eeprom_buff[0]);
		if (ret_val)
			goto err;

		ptr++;
	}
	if (((eeprom->offset + eeprom->len) & 1) && ret_val == 0) {
		/* need read/modify/write of last changed EEPROM word
		 * only the first byte of the word is being modified
		 */
		ret_val = TCALL(hw, eeprom.ops.read, last_word,
				&eeprom_buff[last_word - first_word]);
		if (ret_val)
			goto err;
	}

	/* Device's eeprom is always little-endian, word addressable */
	for (i = 0; i < last_word - first_word + 1; i++)
		le16_to_cpus(&eeprom_buff[i]);

	memcpy(ptr, bytes, eeprom->len);

	for (i = 0; i < last_word - first_word + 1; i++)
		cpu_to_le16s(&eeprom_buff[i]);

	ret_val = TCALL(hw, eeprom.ops.write_buffer, first_word,
			last_word - first_word + 1,
			eeprom_buff);

	/* Update the checksum */
	if (ret_val == 0)
		TCALL(hw, eeprom.ops.update_checksum);

err:
	kfree(eeprom_buff);
	return ret_val;
}

static void txgbe_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	strncpy(drvinfo->driver, txgbe_driver_name,
		sizeof(drvinfo->driver) - 1);
	strncpy(drvinfo->version, txgbe_driver_version,
		sizeof(drvinfo->version) - 1);
	strncpy(drvinfo->fw_version, adapter->eeprom_id,
		sizeof(drvinfo->fw_version));
	strncpy(drvinfo->bus_info, pci_name(adapter->pdev),
		sizeof(drvinfo->bus_info) - 1);
	if (adapter->num_tx_queues <= TXGBE_NUM_RX_QUEUES) {
		drvinfo->n_stats = TXGBE_STATS_LEN -
				   (TXGBE_NUM_RX_QUEUES - adapter->num_tx_queues) *
				   (sizeof(struct txgbe_queue_stats) / sizeof(u64)) * 2;
	} else {
		drvinfo->n_stats = TXGBE_STATS_LEN;
	}
	drvinfo->testinfo_len = TXGBE_TEST_LEN;
	drvinfo->regdump_len = txgbe_get_regs_len(netdev);
}

static void txgbe_get_ringparam(struct net_device *netdev,
				struct ethtool_ringparam *ring)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	ring->rx_max_pending = TXGBE_MAX_RXD;
	ring->tx_max_pending = TXGBE_MAX_TXD;
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_pending = adapter->rx_ring_count;
	ring->tx_pending = adapter->tx_ring_count;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

static int txgbe_set_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_ring *temp_ring;
	int i, err = 0;
	u32 new_rx_count, new_tx_count;

	if (ring->rx_mini_pending || ring->rx_jumbo_pending)
		return -EINVAL;

	new_tx_count = clamp_t(u32, ring->tx_pending,
			       TXGBE_MIN_TXD, TXGBE_MAX_TXD);
	new_tx_count = ALIGN(new_tx_count, TXGBE_REQ_TX_DESCRIPTOR_MULTIPLE);

	new_rx_count = clamp_t(u32, ring->rx_pending,
			       TXGBE_MIN_RXD, TXGBE_MAX_RXD);
	new_rx_count = ALIGN(new_rx_count, TXGBE_REQ_RX_DESCRIPTOR_MULTIPLE);

	if (new_tx_count == adapter->tx_ring_count &&
	    new_rx_count == adapter->rx_ring_count) {
		/* nothing to do */
		return 0;
	}

	while (test_and_set_bit(__TXGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	if (!netif_running(adapter->netdev)) {
		for (i = 0; i < adapter->num_tx_queues; i++)
			adapter->tx_ring[i]->count = new_tx_count;
		for (i = 0; i < adapter->num_rx_queues; i++)
			adapter->rx_ring[i]->count = new_rx_count;
		adapter->tx_ring_count = new_tx_count;
		adapter->rx_ring_count = new_rx_count;
		goto clear_reset;
	}

	/* allocate temporary buffer to store rings in */
	i = max_t(int, adapter->num_tx_queues, adapter->num_rx_queues);
	temp_ring = vmalloc(i * sizeof(struct txgbe_ring));

	if (!temp_ring) {
		err = -ENOMEM;
		goto clear_reset;
	}

	txgbe_down(adapter);

	/* Setup new Tx resources and free the old Tx resources in that order.
	 * We can then assign the new resources to the rings via a memcpy.
	 * The advantage to this approach is that we are guaranteed to still
	 * have resources even in the case of an allocation failure.
	 */
	if (new_tx_count != adapter->tx_ring_count) {
		for (i = 0; i < adapter->num_tx_queues; i++) {
			memcpy(&temp_ring[i], adapter->tx_ring[i],
			       sizeof(struct txgbe_ring));

			temp_ring[i].count = new_tx_count;
			err = txgbe_setup_tx_resources(&temp_ring[i]);
			if (err) {
				while (i) {
					i--;
					txgbe_free_tx_resources(&temp_ring[i]);
				}
				goto err_setup;
			}
		}

		for (i = 0; i < adapter->num_tx_queues; i++) {
			txgbe_free_tx_resources(adapter->tx_ring[i]);

			memcpy(adapter->tx_ring[i], &temp_ring[i],
			       sizeof(struct txgbe_ring));
		}

		adapter->tx_ring_count = new_tx_count;
	}

	/* Repeat the process for the Rx rings if needed */
	if (new_rx_count != adapter->rx_ring_count) {
		for (i = 0; i < adapter->num_rx_queues; i++) {
			memcpy(&temp_ring[i], adapter->rx_ring[i],
			       sizeof(struct txgbe_ring));

			temp_ring[i].count = new_rx_count;
			err = txgbe_setup_rx_resources(&temp_ring[i]);
			if (err) {
				while (i) {
					i--;
					txgbe_free_rx_resources(&temp_ring[i]);
				}
				goto err_setup;
			}
		}

		for (i = 0; i < adapter->num_rx_queues; i++) {
			txgbe_free_rx_resources(adapter->rx_ring[i]);
			memcpy(adapter->rx_ring[i], &temp_ring[i],
			       sizeof(struct txgbe_ring));
		}

		adapter->rx_ring_count = new_rx_count;
	}

err_setup:
	txgbe_up(adapter);
	vfree(temp_ring);
clear_reset:
	clear_bit(__TXGBE_RESETTING, &adapter->state);
	return err;
}

static int txgbe_get_sset_count(struct net_device *netdev, int sset)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	switch (sset) {
	case ETH_SS_TEST:
		return TXGBE_TEST_LEN;
	case ETH_SS_STATS:
		if (adapter->num_tx_queues <= TXGBE_NUM_RX_QUEUES) {
			return TXGBE_STATS_LEN -
			       (TXGBE_NUM_RX_QUEUES - adapter->num_tx_queues) *
			       (sizeof(struct txgbe_queue_stats) / sizeof(u64)) * 2;
		} else {
			return TXGBE_STATS_LEN;
		}
	default:
		return -EOPNOTSUPP;
	}
}

static void txgbe_get_ethtool_stats(struct net_device *netdev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct rtnl_link_stats64 temp;
	const struct rtnl_link_stats64 *net_stats;

	unsigned int start;
	struct txgbe_ring *ring;
	int i, j;
	char *p;

	txgbe_update_stats(adapter);
	net_stats = dev_get_stats(netdev, &temp);

	for (i = 0; i < TXGBE_GLOBAL_STATS_LEN; i++) {
		switch (txgbe_gstrings_stats[i].type) {
		case NETDEV_STATS:
			p = (char *)net_stats +
				txgbe_gstrings_stats[i].stat_offset;
			break;
		case TXGBE_STATS:
			p = (char *)adapter +
				txgbe_gstrings_stats[i].stat_offset;
			break;
		default:
			data[i] = 0;
			continue;
		}

		data[i] = (txgbe_gstrings_stats[i].sizeof_stat ==
			   sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}

	for (j = 0; j < adapter->num_tx_queues; j++) {
		ring = adapter->tx_ring[j];
		if (!ring) {
			data[i++] = 0;
			data[i++] = 0;
			continue;
		}

		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			data[i] = ring->stats.packets;
			data[i + 1] = ring->stats.bytes;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		i += 2;
	}
	for (j = 0; j < adapter->num_rx_queues; j++) {
		ring = adapter->rx_ring[j];
		if (!ring) {
			data[i++] = 0;
			data[i++] = 0;
			continue;
		}

		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			data[i] = ring->stats.packets;
			data[i + 1] = ring->stats.bytes;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		i += 2;
	}
	for (j = 0; j < TXGBE_MAX_PACKET_BUFFERS; j++) {
		data[i++] = adapter->stats.pxontxc[j];
		data[i++] = adapter->stats.pxofftxc[j];
	}
	for (j = 0; j < TXGBE_MAX_PACKET_BUFFERS; j++) {
		data[i++] = adapter->stats.pxonrxc[j];
		data[i++] = adapter->stats.pxoffrxc[j];
	}
}

static void txgbe_get_strings(struct net_device *netdev, u32 stringset,
			      u8 *data)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	char *p = (char *)data;
	int i;

	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, *txgbe_gstrings_test,
		       TXGBE_TEST_LEN * ETH_GSTRING_LEN);
		break;
	case ETH_SS_STATS:
		for (i = 0; i < TXGBE_GLOBAL_STATS_LEN; i++) {
			memcpy(p, txgbe_gstrings_stats[i].stat_string,
			       ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}

		for (i = 0; i < adapter->num_tx_queues; i++) {
			sprintf(p, "tx_queue_%u_packets", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "tx_queue_%u_bytes", i);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < adapter->num_rx_queues; i++) {
			sprintf(p, "rx_queue_%u_packets", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "rx_queue_%u_bytes", i);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < TXGBE_MAX_PACKET_BUFFERS; i++) {
			sprintf(p, "tx_pb_%u_pxon", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "tx_pb_%u_pxoff", i);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < TXGBE_MAX_PACKET_BUFFERS; i++) {
			sprintf(p, "rx_pb_%u_pxon", i);
			p += ETH_GSTRING_LEN;
			sprintf(p, "rx_pb_%u_pxoff", i);
			p += ETH_GSTRING_LEN;
		}
		break;
	}
}

static int txgbe_link_test(struct txgbe_adapter *adapter, u64 *data)
{
	struct txgbe_hw *hw = &adapter->hw;
	bool link_up;
	u32 link_speed = 0;

	if (TXGBE_REMOVED(hw->hw_addr)) {
		*data = 1;
		return 1;
	}
	*data = 0;
	TCALL(hw, mac.ops.check_link, &link_speed, &link_up, true);
	if (!link_up)
		*data = 1;
	return *data;
}

/* ethtool register test data */
struct txgbe_reg_test {
	u32 reg;
	u8  array_len;
	u8  test_type;
	u32 mask;
	u32 write;
};

/* In the hardware, registers are laid out either singly, in arrays
 * spaced 0x40 bytes apart, or in contiguous tables.  We assume
 * most tests take place on arrays or single registers (handled
 * as a single-element array) and special-case the tables.
 * Table tests are always pattern tests.
 *
 * We also make provision for some required setup steps by specifying
 * registers to be written without any read-back testing.
 */

#define PATTERN_TEST    1
#define SET_READ_TEST   2
#define WRITE_NO_TEST   3
#define TABLE32_TEST    4
#define TABLE64_TEST_LO 5
#define TABLE64_TEST_HI 6

/* default sapphire register test */
static struct txgbe_reg_test reg_test_sapphire[] = {
	{ TXGBE_RDB_RFCL(0), 1, PATTERN_TEST, 0x8007FFF0, 0x8007FFF0 },
	{ TXGBE_RDB_RFCH(0), 1, PATTERN_TEST, 0x8007FFF0, 0x8007FFF0 },
	{ TXGBE_PSR_VLAN_CTL, 1, PATTERN_TEST, 0x00000000, 0x00000000 },
	{ TXGBE_PX_RR_BAL(0), 4, PATTERN_TEST, 0xFFFFFF80, 0xFFFFFF80 },
	{ TXGBE_PX_RR_BAH(0), 4, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ TXGBE_PX_RR_CFG(0), 4, WRITE_NO_TEST, 0, TXGBE_PX_RR_CFG_RR_EN },
	{ TXGBE_RDB_RFCH(0), 1, PATTERN_TEST, 0x8007FFF0, 0x8007FFF0 },
	{ TXGBE_RDB_RFCV(0), 1, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ TXGBE_PX_TR_BAL(0), 4, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ TXGBE_PX_TR_BAH(0), 4, PATTERN_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ TXGBE_RDB_PB_CTL, 1, SET_READ_TEST, 0x00000001, 0x00000001 },
	{ TXGBE_PSR_MC_TBL(0), 128, TABLE32_TEST, 0xFFFFFFFF, 0xFFFFFFFF },
	{ .reg = 0 }
};

static bool reg_pattern_test(struct txgbe_adapter *adapter, u64 *data, int reg,
			     u32 mask, u32 write)
{
	u32 pat, val, before;
	static const u32 test_pattern[] = {
		0x5A5A5A5A, 0xA5A5A5A5, 0x00000000, 0xFFFFFFFF
	};

	if (TXGBE_REMOVED(adapter->hw.hw_addr)) {
		*data = 1;
		return true;
	}
	for (pat = 0; pat < ARRAY_SIZE(test_pattern); pat++) {
		before = rd32(&adapter->hw, reg);
		wr32(&adapter->hw, reg, test_pattern[pat] & write);
		val = rd32(&adapter->hw, reg);
		if (val != (test_pattern[pat] & write & mask)) {
			netif_err(adapter, drv, adapter->netdev,
				  "pattern test reg %04X failed: got 0x%08X expected 0x%08X\n",
				  reg, val, test_pattern[pat] & write & mask);
			*data = reg;
			wr32(&adapter->hw, reg, before);
			return true;
		}
		wr32(&adapter->hw, reg, before);
	}
	return false;
}

static bool reg_set_and_check(struct txgbe_adapter *adapter, u64 *data, int reg,
			      u32 mask, u32 write)
{
	u32 val, before;

	if (TXGBE_REMOVED(adapter->hw.hw_addr)) {
		*data = 1;
		return true;
	}
	before = rd32(&adapter->hw, reg);
	wr32(&adapter->hw, reg, write & mask);
	val = rd32(&adapter->hw, reg);
	if ((write & mask) != (val & mask)) {
		netif_err(adapter, drv, adapter->netdev,
			  "set/check reg %04X test failed: got 0x%08X expected 0x%08X\n",
			  reg, (val & mask), (write & mask));
		*data = reg;
		wr32(&adapter->hw, reg, before);
		return true;
	}
	wr32(&adapter->hw, reg, before);
	return false;
}

static bool txgbe_reg_test(struct txgbe_adapter *adapter, u64 *data)
{
	struct txgbe_reg_test *test;
	struct txgbe_hw *hw = &adapter->hw;
	u32 i;

	if (TXGBE_REMOVED(hw->hw_addr)) {
		netif_err(adapter, drv, adapter->netdev,
			  "Adapter removed - register test blocked\n");
		*data = 1;
		return true;
	}

	test = reg_test_sapphire;

	/* Perform the remainder of the register test, looping through
	 * the test table until we either fail or reach the null entry.
	 */
	while (test->reg) {
		for (i = 0; i < test->array_len; i++) {
			bool b = false;

			switch (test->test_type) {
			case PATTERN_TEST:
				b = reg_pattern_test(adapter, data,
						     test->reg + (i * 0x40),
						     test->mask,
						     test->write);
				break;
			case SET_READ_TEST:
				b = reg_set_and_check(adapter, data,
						      test->reg + (i * 0x40),
						      test->mask,
						      test->write);
				break;
			case WRITE_NO_TEST:
				wr32(hw, test->reg + (i * 0x40),
				     test->write);
				break;
			case TABLE32_TEST:
				b = reg_pattern_test(adapter, data,
						     test->reg + (i * 4),
						     test->mask,
						     test->write);
				break;
			case TABLE64_TEST_LO:
				b = reg_pattern_test(adapter, data,
						     test->reg + (i * 8),
						     test->mask,
						     test->write);
				break;
			case TABLE64_TEST_HI:
				b = reg_pattern_test(adapter, data,
						     (test->reg + 4) + (i * 8),
						     test->mask,
						     test->write);
				break;
			}
			if (b)
				return true;
		}
		test++;
	}

	*data = 0;
	return false;
}

static bool txgbe_eeprom_test(struct txgbe_adapter *adapter, u64 *data)
{
	struct txgbe_hw *hw = &adapter->hw;
	bool status = true;

	if (TCALL(hw, eeprom.ops.validate_checksum, NULL)) {
		*data = 1;
	} else {
		*data = 0;
		status = false;
	}
	return status;
}

static irqreturn_t txgbe_test_intr(int __always_unused irq, void *data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	u64 icr;

	/* get misc interrupt, as cannot get ring interrupt status */
	icr = txgbe_misc_isb(adapter, TXGBE_ISB_VEC1);
	icr <<= 32;
	icr |= txgbe_misc_isb(adapter, TXGBE_ISB_VEC0);

	adapter->test_icr = icr;

	return IRQ_HANDLED;
}

static int txgbe_intr_test(struct txgbe_adapter *adapter, u64 *data)
{
	struct net_device *netdev = adapter->netdev;
	u64 mask;
	u32 i = 0, shared_int = true;
	u32 irq = adapter->pdev->irq;

	if (TXGBE_REMOVED(adapter->hw.hw_addr)) {
		*data = 1;
		return -1;
	}
	*data = 0;

	/* Hook up test interrupt handler just for this test */
	if (adapter->msix_entries) {
		/* NOTE: we don't test MSI-X interrupts here, yet */
		return 0;
	} else if (adapter->flags & TXGBE_FLAG_MSI_ENABLED) {
		shared_int = false;
		if (request_irq(irq, &txgbe_test_intr, 0, netdev->name,
				netdev)) {
			*data = 1;
			return -1;
		}
	} else if (!request_irq(irq, &txgbe_test_intr, IRQF_PROBE_SHARED,
				netdev->name, netdev)) {
		shared_int = false;
	} else if (request_irq(irq, &txgbe_test_intr, IRQF_SHARED,
			       netdev->name, netdev)) {
		*data = 1;
		return -1;
	}
	netif_info(adapter, hw, netdev, "testing %s interrupt\n",
		   (shared_int ? "shared" : "unshared"));

	/* Disable all the interrupts */
	txgbe_irq_disable(adapter);
	TXGBE_WRITE_FLUSH(&adapter->hw);
	usleep_range(10000, 20000);

	/* Test each interrupt */
	for (; i < 1; i++) {
		/* Interrupt to test */
		mask = 1ULL << i;

		if (!shared_int) {
			/* Disable the interrupts to be reported in
			 * the cause register and then force the same
			 * interrupt and see if one gets posted.  If
			 * an interrupt was posted to the bus, the
			 * test failed.
			 */
			adapter->test_icr = 0;
			txgbe_intr_disable(&adapter->hw, ~mask);
			txgbe_intr_trigger(&adapter->hw, mask);
			TXGBE_WRITE_FLUSH(&adapter->hw);
			usleep_range(10000, 20000);

			if (adapter->test_icr & mask) {
				*data = 3;
				break;
			}
		}

		/* Enable the interrupt to be reported in the cause
		 * register and then force the same interrupt and see
		 * if one gets posted.  If an interrupt was not posted
		 * to the bus, the test failed.
		 */
		adapter->test_icr = 0;
		txgbe_intr_disable(&adapter->hw, TXGBE_INTR_ALL);
		txgbe_intr_trigger(&adapter->hw, mask);
		TXGBE_WRITE_FLUSH(&adapter->hw);
		usleep_range(10000, 20000);

		if (!(adapter->test_icr & mask)) {
			*data = 4;
			break;
		}
	}

	/* Disable all the interrupts */
	txgbe_intr_disable(&adapter->hw, TXGBE_INTR_ALL);
	TXGBE_WRITE_FLUSH(&adapter->hw);
	usleep_range(10000, 20000);

	/* Unhook test interrupt handler */
	free_irq(irq, netdev);

	return *data;
}

static void txgbe_free_desc_rings(struct txgbe_adapter *adapter)
{
	struct txgbe_ring *tx_ring = &adapter->test_tx_ring;
	struct txgbe_ring *rx_ring = &adapter->test_rx_ring;
	struct txgbe_hw *hw = &adapter->hw;

	/* shut down the DMA engines now so they can be reinitialized later */

	/* first Rx */
	TCALL(hw, mac.ops.disable_rx);
	txgbe_disable_rx_queue(adapter, rx_ring);

	/* now Tx */
	wr32(hw, TXGBE_PX_TR_CFG(tx_ring->reg_idx), 0);

	wr32m(hw, TXGBE_TDM_CTL, TXGBE_TDM_CTL_TE, 0);

	txgbe_reset(adapter);

	txgbe_free_tx_resources(&adapter->test_tx_ring);
	txgbe_free_rx_resources(&adapter->test_rx_ring);
}

static int txgbe_setup_desc_rings(struct txgbe_adapter *adapter)
{
	struct txgbe_ring *tx_ring = &adapter->test_tx_ring;
	struct txgbe_ring *rx_ring = &adapter->test_rx_ring;
	struct txgbe_hw *hw = &adapter->hw;
	int ret_val;
	int err;

	TCALL(hw, mac.ops.setup_rxpba, 0, 0, PBA_STRATEGY_EQUAL);

	/* Setup Tx descriptor ring and Tx buffers */
	tx_ring->count = TXGBE_DEFAULT_TXD;
	tx_ring->queue_index = 0;
	tx_ring->dev = &adapter->pdev->dev;
	tx_ring->netdev = adapter->netdev;
	tx_ring->reg_idx = adapter->tx_ring[0]->reg_idx;

	err = txgbe_setup_tx_resources(tx_ring);
	if (err)
		return 1;

	wr32m(&adapter->hw, TXGBE_TDM_CTL,
	      TXGBE_TDM_CTL_TE, TXGBE_TDM_CTL_TE);

	txgbe_configure_tx_ring(adapter, tx_ring);

	/* enable mac transmitter */
	wr32m(hw, TXGBE_MAC_TX_CFG,
	      TXGBE_MAC_TX_CFG_TE | TXGBE_MAC_TX_CFG_SPEED_MASK,
	      TXGBE_MAC_TX_CFG_TE | TXGBE_MAC_TX_CFG_SPEED_10G);

	/* Setup Rx Descriptor ring and Rx buffers */
	rx_ring->count = TXGBE_DEFAULT_RXD;
	rx_ring->queue_index = 0;
	rx_ring->dev = &adapter->pdev->dev;
	rx_ring->netdev = adapter->netdev;
	rx_ring->reg_idx = adapter->rx_ring[0]->reg_idx;

	err = txgbe_setup_rx_resources(rx_ring);
	if (err) {
		ret_val = 4;
		goto err_nomem;
	}

	TCALL(hw, mac.ops.disable_rx);

	txgbe_configure_rx_ring(adapter, rx_ring);

	TCALL(hw, mac.ops.enable_rx);

	return 0;

err_nomem:
	txgbe_free_desc_rings(adapter);
	return ret_val;
}

static int txgbe_setup_config(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 reg_data;

	/* Setup traffic loopback */
	reg_data = rd32(hw, TXGBE_PSR_CTL);
	reg_data |= TXGBE_PSR_CTL_BAM | TXGBE_PSR_CTL_UPE |
		TXGBE_PSR_CTL_MPE | TXGBE_PSR_CTL_TPE;
	wr32(hw, TXGBE_PSR_CTL, reg_data);

	wr32(hw, TXGBE_RSC_CTL,
	     (rd32(hw, TXGBE_RSC_CTL) |
	      TXGBE_RSC_CTL_SAVE_MAC_ERR) &
	     ~TXGBE_RSC_CTL_SECRX_DIS);

	wr32(hw, TXGBE_RSC_LSEC_CTL, 0x4);

	wr32(hw, TXGBE_PSR_VLAN_CTL,
	     rd32(hw, TXGBE_PSR_VLAN_CTL) &
	     ~TXGBE_PSR_VLAN_CTL_VFE);

	wr32m(&adapter->hw, TXGBE_MAC_RX_CFG,
	      TXGBE_MAC_RX_CFG_LM, ~TXGBE_MAC_RX_CFG_LM);
	wr32m(&adapter->hw, TXGBE_CFG_PORT_CTL,
	      TXGBE_CFG_PORT_CTL_FORCE_LKUP,
	      ~TXGBE_CFG_PORT_CTL_FORCE_LKUP);

	TXGBE_WRITE_FLUSH(hw);
	usleep_range(10000, 20000);

	return 0;
}

static int txgbe_setup_phy_loopback_test(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 value;
	/* setup phy loopback */
	value = txgbe_rd32_epcs(hw, TXGBE_PHY_MISC_CTL0);
	value |= TXGBE_PHY_MISC_CTL0_TX2RX_LB_EN_0 |
		TXGBE_PHY_MISC_CTL0_TX2RX_LB_EN_3_1;

	txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, value);

	value = txgbe_rd32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1);
	txgbe_wr32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1,
			value | TXGBE_SR_PMA_MMD_CTL1_LB_EN);
	return 0;
}

static void txgbe_phy_loopback_cleanup(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 value;

	value = txgbe_rd32_epcs(hw, TXGBE_PHY_MISC_CTL0);
	value &= ~(TXGBE_PHY_MISC_CTL0_TX2RX_LB_EN_0 |
		   TXGBE_PHY_MISC_CTL0_TX2RX_LB_EN_3_1);

	txgbe_wr32_epcs(hw, TXGBE_PHY_MISC_CTL0, value);
	value = txgbe_rd32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1);
	txgbe_wr32_epcs(hw, TXGBE_SR_PMA_MMD_CTL1,
			value & ~TXGBE_SR_PMA_MMD_CTL1_LB_EN);
}

static void txgbe_create_lbtest_frame(struct sk_buff *skb,
				      unsigned int frame_size)
{
	memset(skb->data, 0xFF, frame_size);
	frame_size >>= 1;
	memset(&skb->data[frame_size], 0xAA, frame_size / 2 - 1);
	skb->data[frame_size + 10] = 0xBE;
	skb->data[frame_size + 12] = 0xAF;
}

static bool txgbe_check_lbtest_frame(struct txgbe_rx_buffer *rx_buffer,
				     unsigned int frame_size)
{
	unsigned char *data;
	bool match = true;

	frame_size >>= 1;
	data = kmap(rx_buffer->page) + rx_buffer->page_offset;

	if (data[3] != 0xFF ||
	    data[frame_size + 10] != 0xBE ||
	    data[frame_size + 12] != 0xAF)
		match = false;

	kunmap(rx_buffer->page);
	return match;
}

static u16 txgbe_clean_test_rings(struct txgbe_ring *rx_ring,
				  struct txgbe_ring *tx_ring,
				  unsigned int size)
{
	union txgbe_rx_desc *rx_desc;
	struct txgbe_rx_buffer *rx_buffer;
	struct txgbe_tx_buffer *tx_buffer;
	const int bufsz = txgbe_rx_bufsz(rx_ring);
	u16 rx_ntc, tx_ntc, count = 0;

	/* initialize next to clean and descriptor values */
	rx_ntc = rx_ring->next_to_clean;
	tx_ntc = tx_ring->next_to_clean;
	rx_desc = TXGBE_RX_DESC(rx_ring, rx_ntc);

	while (txgbe_test_staterr(rx_desc, TXGBE_RXD_STAT_DD)) {
		/* unmap buffer on Tx side */
		tx_buffer = &tx_ring->tx_buffer_info[tx_ntc];
		txgbe_unmap_and_free_tx_resource(tx_ring, tx_buffer);

		/* check Rx buffer */
		rx_buffer = &rx_ring->rx_buffer_info[rx_ntc];

		/* sync Rx buffer for CPU read */
		dma_sync_single_for_cpu(rx_ring->dev,
					rx_buffer->page_dma,
					bufsz,
					DMA_FROM_DEVICE);

		/* verify contents of skb */
		if (txgbe_check_lbtest_frame(rx_buffer, size))
			count++;

		/* sync Rx buffer for device write */
		dma_sync_single_for_device(rx_ring->dev,
					   rx_buffer->page_dma,
					   bufsz,
					   DMA_FROM_DEVICE);

		/* increment Rx/Tx next to clean counters */
		rx_ntc++;
		if (rx_ntc == rx_ring->count)
			rx_ntc = 0;
		tx_ntc++;
		if (tx_ntc == tx_ring->count)
			tx_ntc = 0;

		/* fetch next descriptor */
		rx_desc = TXGBE_RX_DESC(rx_ring, rx_ntc);
	}

	/* re-map buffers to ring, store next to clean values */
	txgbe_alloc_rx_buffers(rx_ring, count);
	rx_ring->next_to_clean = rx_ntc;
	tx_ring->next_to_clean = tx_ntc;

	return count;
}

static int txgbe_run_loopback_test(struct txgbe_adapter *adapter)
{
	struct txgbe_ring *tx_ring = &adapter->test_tx_ring;
	struct txgbe_ring *rx_ring = &adapter->test_rx_ring;
	int i, j, lc, good_cnt, ret_val = 0;
	unsigned int size = 1024;
	netdev_tx_t tx_ret_val;
	struct sk_buff *skb;
	u32 flags_orig = adapter->flags;

	/* allocate test skb */
	skb = alloc_skb(size, GFP_KERNEL);
	if (!skb)
		return 11;

	/* place data into test skb */
	txgbe_create_lbtest_frame(skb, size);
	skb_put(skb, size);

	/* Calculate the loop count based on the largest descriptor ring
	 * The idea is to wrap the largest ring a number of times using 64
	 * send/receive pairs during each loop
	 */

	if (rx_ring->count <= tx_ring->count)
		lc = ((tx_ring->count / 64) * 2) + 1;
	else
		lc = ((rx_ring->count / 64) * 2) + 1;

	for (j = 0; j <= lc; j++) {
		/* reset count of good packets */
		good_cnt = 0;

		/* place 64 packets on the transmit queue*/
		for (i = 0; i < 64; i++) {
			skb_get(skb);
			tx_ret_val = txgbe_xmit_frame_ring(skb,
							   adapter,
							   tx_ring);
			if (tx_ret_val == NETDEV_TX_OK)
				good_cnt++;
		}

		if (good_cnt != 64) {
			ret_val = 12;
			break;
		}

		/* allow 200 milliseconds for packets to go from Tx to Rx */
		msleep(200);

		good_cnt = txgbe_clean_test_rings(rx_ring, tx_ring, size);
		if (j == 0) {
			continue;
		} else if (good_cnt != 64) {
			ret_val = 13;
			break;
		}
	}

	/* free the original skb */
	kfree_skb(skb);
	adapter->flags = flags_orig;

	return ret_val;
}

static int txgbe_loopback_test(struct txgbe_adapter *adapter, u64 *data)
{
	*data = txgbe_setup_desc_rings(adapter);
	if (*data)
		goto out;

	*data = txgbe_setup_config(adapter);
	if (*data)
		goto err_loopback;

	*data = txgbe_setup_phy_loopback_test(adapter);
	if (*data)
		goto err_loopback;
	*data = txgbe_run_loopback_test(adapter);
	if (*data)
		netif_info(adapter, hw, adapter->netdev,
			   "phy loopback testing failed\n");
	txgbe_phy_loopback_cleanup(adapter);

err_loopback:
	txgbe_free_desc_rings(adapter);
out:
	return *data;
}

static void txgbe_diag_test(struct net_device *netdev,
			    struct ethtool_test *eth_test, u64 *data)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	bool if_running = netif_running(netdev);
	struct txgbe_hw *hw = &adapter->hw;

	if (TXGBE_REMOVED(hw->hw_addr)) {
		netif_err(adapter, drv, netdev,
			  "Adapter removed - test blocked\n");
		data[0] = 1;
		data[1] = 1;
		data[2] = 1;
		data[3] = 1;
		data[4] = 1;
		eth_test->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	set_bit(__TXGBE_TESTING, &adapter->state);
	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		/* Offline tests */
		netif_info(adapter, hw, netdev, "offline testing starting\n");

		/* Link test performed before hardware reset so autoneg doesn't
		 * interfere with test result
		 */
		if (txgbe_link_test(adapter, &data[4]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (if_running)
			/* indicate we're in test mode */
			txgbe_close(netdev);
		else
			txgbe_reset(adapter);

		netif_info(adapter, hw, netdev, "register testing starting\n");
		if (txgbe_reg_test(adapter, &data[0]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		txgbe_reset(adapter);
		netif_info(adapter, hw, netdev, "eeprom testing starting\n");
		if (txgbe_eeprom_test(adapter, &data[1]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		txgbe_reset(adapter);
		netif_info(adapter, hw, netdev, "interrupt testing starting\n");
		if (txgbe_intr_test(adapter, &data[2]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (!(((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP) ||
		      ((hw->subsystem_device_id & TXGBE_WOL_MASK) == TXGBE_WOL_SUP))) {
			txgbe_reset(adapter);
			netif_info(adapter, hw, netdev,
				   "loopback testing starting\n");
			if (txgbe_loopback_test(adapter, &data[3]))
				eth_test->flags |= ETH_TEST_FL_FAILED;
		}

		data[3] = 0;

		txgbe_reset(adapter);

		/* clear testing bit and return adapter to previous state */
		clear_bit(__TXGBE_TESTING, &adapter->state);
		if (if_running)
			txgbe_open(netdev);
		else
			TCALL(hw, mac.ops.disable_tx_laser);
	} else {
		netif_info(adapter, hw, netdev, "online testing starting\n");

		/* Online tests */
		if (txgbe_link_test(adapter, &data[4]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* Offline tests aren't run; pass by default */
		data[0] = 0;
		data[1] = 0;
		data[2] = 0;
		data[3] = 0;

		clear_bit(__TXGBE_TESTING, &adapter->state);
	}

	msleep_interruptible(4 * 1000);
}

static int txgbe_wol_exclusion(struct txgbe_adapter *adapter,
			       struct ethtool_wolinfo *wol)
{
	int retval = 0;

	/* WOL not supported for all devices */
	if (!txgbe_wol_supported(adapter)) {
		retval = 1;
		wol->supported = 0;
	}

	return retval;
}

static void txgbe_get_wol(struct net_device *netdev,
			  struct ethtool_wolinfo *wol)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;

	wol->supported = WAKE_UCAST | WAKE_MCAST |
			 WAKE_BCAST | WAKE_MAGIC;
	wol->wolopts = 0;

	if (txgbe_wol_exclusion(adapter, wol) ||
	    !device_can_wakeup(&adapter->pdev->dev))
		return;
	if ((hw->subsystem_device_id & TXGBE_WOL_MASK) != TXGBE_WOL_SUP)
		return;

	if (adapter->wol & TXGBE_PSR_WKUP_CTL_EX)
		wol->wolopts |= WAKE_UCAST;
	if (adapter->wol & TXGBE_PSR_WKUP_CTL_MC)
		wol->wolopts |= WAKE_MCAST;
	if (adapter->wol & TXGBE_PSR_WKUP_CTL_BC)
		wol->wolopts |= WAKE_BCAST;
	if (adapter->wol & TXGBE_PSR_WKUP_CTL_MAG)
		wol->wolopts |= WAKE_MAGIC;
}

static int txgbe_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;

	if (wol->wolopts & (WAKE_PHY | WAKE_ARP | WAKE_MAGICSECURE))
		return -EOPNOTSUPP;

	if (txgbe_wol_exclusion(adapter, wol))
		return wol->wolopts ? -EOPNOTSUPP : 0;
	if ((hw->subsystem_device_id & TXGBE_WOL_MASK) != TXGBE_WOL_SUP)
		return -EOPNOTSUPP;

	adapter->wol = 0;

	if (wol->wolopts & WAKE_UCAST)
		adapter->wol |= TXGBE_PSR_WKUP_CTL_EX;
	if (wol->wolopts & WAKE_MCAST)
		adapter->wol |= TXGBE_PSR_WKUP_CTL_MC;
	if (wol->wolopts & WAKE_BCAST)
		adapter->wol |= TXGBE_PSR_WKUP_CTL_BC;
	if (wol->wolopts & WAKE_MAGIC)
		adapter->wol |= TXGBE_PSR_WKUP_CTL_MAG;

	hw->wol_enabled = !!(adapter->wol);
	wr32(hw, TXGBE_PSR_WKUP_CTL, adapter->wol);

	device_set_wakeup_enable(&adapter->pdev->dev, adapter->wol);

	return 0;
}

static int txgbe_nway_reset(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	if (netif_running(netdev))
		txgbe_reinit_locked(adapter);

	return 0;
}

static int txgbe_set_phys_id(struct net_device *netdev,
			     enum ethtool_phys_id_state state)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		adapter->led_reg = rd32(hw, TXGBE_CFG_LED_CTL);
		return 2;

	case ETHTOOL_ID_ON:
		if (hw->oem_ssid != 0x0085 && hw->oem_svid == 0x1bd4) {
			if (adapter->link_up) {
				switch (adapter->link_speed) {
				case TXGBE_LINK_SPEED_10GB_FULL:
					TCALL(hw, mac.ops.led_on, TXGBE_LED_LINK_10G);
					break;
				case TXGBE_LINK_SPEED_1GB_FULL:
					TCALL(hw, mac.ops.led_on, TXGBE_LED_LINK_1G);
					break;
				case TXGBE_LINK_SPEED_100_FULL:
					TCALL(hw, mac.ops.led_on, TXGBE_LED_LINK_100M);
					break;
				default:
					break;
				}
			} else {
				TCALL(hw, mac.ops.led_on, TXGBE_LED_LINK_10G);
			}
		} else {
			TCALL(hw, mac.ops.led_on, TXGBE_LED_LINK_UP);
		}
		break;

	case ETHTOOL_ID_OFF:
		if (hw->oem_ssid != 0x0085 && hw->oem_svid == 0x1bd4) {
			if (adapter->link_up) {
				switch (adapter->link_speed) {
				case TXGBE_LINK_SPEED_10GB_FULL:
					TCALL(hw, mac.ops.led_off, TXGBE_LED_LINK_10G);
					break;
				case TXGBE_LINK_SPEED_1GB_FULL:
					TCALL(hw, mac.ops.led_off, TXGBE_LED_LINK_1G);
					break;
				case TXGBE_LINK_SPEED_100_FULL:
					TCALL(hw, mac.ops.led_off, TXGBE_LED_LINK_100M);
					break;
				default:
					break;
				}
			} else {
				TCALL(hw, mac.ops.led_off, TXGBE_LED_LINK_10G);
			}
		} else {
			TCALL(hw, mac.ops.led_off, TXGBE_LED_LINK_UP);
		}
		break;

	case ETHTOOL_ID_INACTIVE:
		/* Restore LED settings */
		wr32(&adapter->hw, TXGBE_CFG_LED_CTL, adapter->led_reg);
		break;
	}

	return 0;
}

static int txgbe_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *ec)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	ec->tx_max_coalesced_frames_irq = adapter->tx_work_limit;
	/* only valid if in constant ITR mode */
	if (adapter->rx_itr_setting <= 1)
		ec->rx_coalesce_usecs = adapter->rx_itr_setting;
	else
		ec->rx_coalesce_usecs = adapter->rx_itr_setting >> 2;

	/* if in mixed tx/rx queues per vector mode, report only rx settings */
	if (adapter->q_vector[0]->tx.count && adapter->q_vector[0]->rx.count)
		return 0;

	/* only valid if in constant ITR mode */
	if (adapter->tx_itr_setting <= 1)
		ec->tx_coalesce_usecs = adapter->tx_itr_setting;
	else
		ec->tx_coalesce_usecs = adapter->tx_itr_setting >> 2;

	return 0;
}

/* this function must be called before setting the new value of
 * rx_itr_setting
 */
static bool txgbe_update_rsc(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	/* nothing to do if LRO or RSC are not enabled */
	if (!(adapter->flags2 & TXGBE_FLAG2_RSC_CAPABLE) ||
	    !(netdev->features & NETIF_F_LRO))
		return false;

	/* check the feature flag value and enable RSC if necessary */
	if (adapter->rx_itr_setting == 1 ||
	    adapter->rx_itr_setting > TXGBE_MIN_RSC_ITR) {
		if (!(adapter->flags2 & TXGBE_FLAG2_RSC_ENABLED)) {
			adapter->flags2 |= TXGBE_FLAG2_RSC_ENABLED;
			netif_info(adapter, probe, netdev,
				   "rx-usecs value high enough to re-enable RSC\n");
			return true;
		}
	/* if interrupt rate is too high then disable RSC */
	} else if (adapter->flags2 & TXGBE_FLAG2_RSC_ENABLED) {
		adapter->flags2 &= ~TXGBE_FLAG2_RSC_ENABLED;
		netif_info(adapter, probe, netdev,
			   "rx-usecs set too low, disabling RSC\n");
		return true;
	}
	return false;
}

static int txgbe_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *ec)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_q_vector *q_vector;
	int i;
	u16 tx_itr_param, rx_itr_param;
	u16  tx_itr_prev;
	bool need_reset = false;

	if (adapter->q_vector[0]->tx.count && adapter->q_vector[0]->rx.count) {
		/* reject Tx specific changes in case of mixed RxTx vectors */
		if (ec->tx_coalesce_usecs)
			return -EINVAL;
		tx_itr_prev = adapter->rx_itr_setting;
	} else {
		tx_itr_prev = adapter->tx_itr_setting;
	}

	if (ec->tx_max_coalesced_frames_irq)
		adapter->tx_work_limit = ec->tx_max_coalesced_frames_irq;

	if ((ec->rx_coalesce_usecs > (TXGBE_MAX_EITR >> 2)) ||
	    (ec->tx_coalesce_usecs > (TXGBE_MAX_EITR >> 2)))
		return -EINVAL;

	if (ec->rx_coalesce_usecs > 1)
		adapter->rx_itr_setting = ec->rx_coalesce_usecs << 2;
	else
		adapter->rx_itr_setting = ec->rx_coalesce_usecs;

	if (adapter->rx_itr_setting == 1)
		rx_itr_param = TXGBE_20K_ITR;
	else
		rx_itr_param = adapter->rx_itr_setting;

	if (ec->tx_coalesce_usecs > 1)
		adapter->tx_itr_setting = ec->tx_coalesce_usecs << 2;
	else
		adapter->tx_itr_setting = ec->tx_coalesce_usecs;

	if (adapter->tx_itr_setting == 1)
		tx_itr_param = TXGBE_12K_ITR;
	else
		tx_itr_param = adapter->tx_itr_setting;

	/* mixed Rx/Tx */
	if (adapter->q_vector[0]->tx.count && adapter->q_vector[0]->rx.count)
		adapter->tx_itr_setting = adapter->rx_itr_setting;

	/* detect ITR changes that require update of TXDCTL.WTHRESH */
	if (adapter->tx_itr_setting != 1 &&
	    adapter->tx_itr_setting < TXGBE_100K_ITR) {
		if (tx_itr_prev == 1 ||
		    tx_itr_prev >= TXGBE_100K_ITR)
			need_reset = true;
	} else {
		if (tx_itr_prev != 1 &&
		    tx_itr_prev < TXGBE_100K_ITR)
			need_reset = true;
	}

	/* check the old value and enable RSC if necessary */
	need_reset |= txgbe_update_rsc(adapter);

	for (i = 0; i < adapter->num_q_vectors; i++) {
		q_vector = adapter->q_vector[i];
		q_vector->tx.work_limit = adapter->tx_work_limit;
		q_vector->rx.work_limit = adapter->rx_work_limit;
		if (q_vector->tx.count && !q_vector->rx.count)
			/* tx only */
			q_vector->itr = tx_itr_param;
		else
			/* rx only or mixed */
			q_vector->itr = rx_itr_param;
		txgbe_write_eitr(q_vector);
	}

	/* do reset here at the end to make sure EITR==0 case is handled
	 * correctly w.r.t stopping tx, and changing TXDCTL.WTHRESH settings
	 * also locks in RSC enable/disable which requires reset
	 */
	if (need_reset)
		txgbe_do_reset(netdev);

	return 0;
}

static int txgbe_get_ethtool_fdir_entry(struct txgbe_adapter *adapter,
					struct ethtool_rxnfc *cmd)
{
	union txgbe_atr_input *mask = &adapter->fdir_mask;
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct hlist_node *node;
	struct txgbe_fdir_filter *rule = NULL;

	/* report total rule count */
	cmd->data = (1024 << adapter->fdir_pballoc) - 2;

	hlist_for_each_entry_safe(rule, node,
				  &adapter->fdir_filter_list, fdir_node) {
		if (fsp->location <= rule->sw_idx)
			break;
	}

	if (!rule || fsp->location != rule->sw_idx)
		return -EINVAL;

	/* fill out the flow spec entry */

	/* set flow type field */
	switch (rule->filter.formatted.flow_type) {
	case TXGBE_ATR_FLOW_TYPE_TCPV4:
		fsp->flow_type = TCP_V4_FLOW;
		break;
	case TXGBE_ATR_FLOW_TYPE_UDPV4:
		fsp->flow_type = UDP_V4_FLOW;
		break;
	case TXGBE_ATR_FLOW_TYPE_SCTPV4:
		fsp->flow_type = SCTP_V4_FLOW;
		break;
	case TXGBE_ATR_FLOW_TYPE_IPV4:
		fsp->flow_type = IP_USER_FLOW;
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = 0;
		fsp->m_u.usr_ip4_spec.proto = 0;
		break;
	default:
		return -EINVAL;
	}

	fsp->h_u.tcp_ip4_spec.psrc = rule->filter.formatted.src_port;
	fsp->m_u.tcp_ip4_spec.psrc = mask->formatted.src_port;
	fsp->h_u.tcp_ip4_spec.pdst = rule->filter.formatted.dst_port;
	fsp->m_u.tcp_ip4_spec.pdst = mask->formatted.dst_port;
	fsp->h_u.tcp_ip4_spec.ip4src = rule->filter.formatted.src_ip[0];
	fsp->m_u.tcp_ip4_spec.ip4src = mask->formatted.src_ip[0];
	fsp->h_u.tcp_ip4_spec.ip4dst = rule->filter.formatted.dst_ip[0];
	fsp->m_u.tcp_ip4_spec.ip4dst = mask->formatted.dst_ip[0];
	fsp->h_ext.vlan_etype = rule->filter.formatted.flex_bytes;
	fsp->m_ext.vlan_etype = mask->formatted.flex_bytes;
	fsp->h_ext.data[1] = htonl(rule->filter.formatted.vm_pool);
	fsp->m_ext.data[1] = htonl(mask->formatted.vm_pool);
	fsp->flow_type |= FLOW_EXT;

	/* record action */
	if (rule->action == TXGBE_RDB_FDIR_DROP_QUEUE)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else
		fsp->ring_cookie = rule->action;

	return 0;
}

static int txgbe_get_ethtool_fdir_all(struct txgbe_adapter *adapter,
				      struct ethtool_rxnfc *cmd,
				      u32 *rule_locs)
{
	struct hlist_node *node;
	struct txgbe_fdir_filter *rule;
	int cnt = 0;

	/* report total rule count */
	cmd->data = (1024 << adapter->fdir_pballoc) - 2;

	hlist_for_each_entry_safe(rule, node,
				  &adapter->fdir_filter_list, fdir_node) {
		if (cnt == cmd->rule_cnt)
			return -EMSGSIZE;
		rule_locs[cnt] = rule->sw_idx;
		cnt++;
	}

	cmd->rule_cnt = cnt;

	return 0;
}

static int txgbe_get_rss_hash_opts(struct txgbe_adapter *adapter,
				   struct ethtool_rxnfc *cmd)
{
	cmd->data = 0;

	/* Report default options for RSS on txgbe */
	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		/* fallthrough */
	case UDP_V4_FLOW:
		if (adapter->flags2 & TXGBE_FLAG2_RSS_FIELD_IPV4_UDP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		/* fallthrough */
	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:
		cmd->data |= RXH_IP_SRC | RXH_IP_DST;
		break;
	case TCP_V6_FLOW:
		cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		/* fallthrough */
	case UDP_V6_FLOW:
		if (adapter->flags2 & TXGBE_FLAG2_RSS_FIELD_IPV6_UDP)
			cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		/* fallthrough */
	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:
		cmd->data |= RXH_IP_SRC | RXH_IP_DST;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int txgbe_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd,
			   u32 *rule_locs)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = adapter->num_rx_queues;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = adapter->fdir_filter_count;
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = txgbe_get_ethtool_fdir_entry(adapter, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
		ret = txgbe_get_ethtool_fdir_all(adapter, cmd,
						 (u32 *)rule_locs);
		break;
	case ETHTOOL_GRXFH:
		ret = txgbe_get_rss_hash_opts(adapter, cmd);
		break;
	default:
		break;
	}

	return ret;
}

static int txgbe_update_ethtool_fdir_entry(struct txgbe_adapter *adapter,
					   struct txgbe_fdir_filter *input,
					   u16 sw_idx)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct hlist_node *node, *parent;
	struct txgbe_fdir_filter *rule;
	bool deleted = false;
	s32 err;

	parent = NULL;
	rule = NULL;

	hlist_for_each_entry_safe(rule, node,
				  &adapter->fdir_filter_list, fdir_node) {
		/* hash found, or no matching entry */
		if (rule->sw_idx >= sw_idx)
			break;
		parent = node;
	}

	/* if there is an old rule occupying our place remove it */
	if (rule && rule->sw_idx == sw_idx) {
		/* hardware filters are only configured when interface is up,
		 * and we should not issue filter commands while the interface
		 * is down
		 */
		if (netif_running(adapter->netdev) &&
		    (!input || rule->filter.formatted.bkt_hash !=
		     input->filter.formatted.bkt_hash)) {
			err = txgbe_fdir_erase_perfect_filter(hw,
							      &rule->filter,
							      sw_idx);
			if (err)
				return -EINVAL;
		}

		hlist_del(&rule->fdir_node);
		kfree(rule);
		adapter->fdir_filter_count--;
		deleted = true;
	}

	/* If we weren't given an input, then this was a request to delete a
	 * filter. We should return -EINVAL if the filter wasn't found, but
	 * return 0 if the rule was successfully deleted.
	 */
	if (!input)
		return deleted ? 0 : -EINVAL;

	/* initialize node and set software index */
	INIT_HLIST_NODE(&input->fdir_node);

	/* add filter to the list */
	if (parent)
		hlist_add_behind(&input->fdir_node, parent);
	else
		hlist_add_head(&input->fdir_node,
			       &adapter->fdir_filter_list);

	/* update counts */
	adapter->fdir_filter_count++;

	return 0;
}

static int txgbe_flowspec_to_flow_type(struct ethtool_rx_flow_spec *fsp,
				       u8 *flow_type)
{
	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
		*flow_type = TXGBE_ATR_FLOW_TYPE_TCPV4;
		break;
	case UDP_V4_FLOW:
		*flow_type = TXGBE_ATR_FLOW_TYPE_UDPV4;
		break;
	case SCTP_V4_FLOW:
		*flow_type = TXGBE_ATR_FLOW_TYPE_SCTPV4;
		break;
	case IP_USER_FLOW:
		switch (fsp->h_u.usr_ip4_spec.proto) {
		case IPPROTO_TCP:
			*flow_type = TXGBE_ATR_FLOW_TYPE_TCPV4;
			break;
		case IPPROTO_UDP:
			*flow_type = TXGBE_ATR_FLOW_TYPE_UDPV4;
			break;
		case IPPROTO_SCTP:
			*flow_type = TXGBE_ATR_FLOW_TYPE_SCTPV4;
			break;
		case 0:
			if (!fsp->m_u.usr_ip4_spec.proto) {
				*flow_type = TXGBE_ATR_FLOW_TYPE_IPV4;
				break;
			}
			/* fallthrough */
		default:
			return 0;
		}
		break;
	default:
		return 0;
	}

	return 1;
}

static bool txgbe_match_ethtool_fdir_entry(struct txgbe_adapter *adapter,
					   struct txgbe_fdir_filter *input)
{
	struct hlist_node *node2;
	struct txgbe_fdir_filter *rule = NULL;

	hlist_for_each_entry_safe(rule, node2,
				  &adapter->fdir_filter_list, fdir_node) {
		if (rule->filter.formatted.bkt_hash ==
		    input->filter.formatted.bkt_hash &&
		    rule->action == input->action) {
			netif_info(adapter, drv, adapter->netdev,
				   "FDIR entry already exist\n");
			return true;
		}
	}
	return false;
}

static int txgbe_add_ethtool_fdir_entry(struct txgbe_adapter *adapter,
					struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct txgbe_hw *hw = &adapter->hw;
	struct txgbe_fdir_filter *input;
	union txgbe_atr_input mask;
	u8 queue;
	int err;
	u16 ptype = 0;

	if (!(adapter->flags & TXGBE_FLAG_FDIR_PERFECT_CAPABLE))
		return -EOPNOTSUPP;

	/* ring_cookie is a masked into a set of queues and txgbe pools or
	 * we use drop index
	 */
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		queue = TXGBE_RDB_FDIR_DROP_QUEUE;
	} else {
		u32 ring = ethtool_get_flow_spec_ring(fsp->ring_cookie);

		if (ring >= adapter->num_rx_queues)
			return -EINVAL;

		/* Map the ring onto the absolute queue index */
		queue = adapter->rx_ring[ring]->reg_idx;
	}

	/* Don't allow indexes to exist outside of available space */
	if (fsp->location >= ((1024 << adapter->fdir_pballoc) - 2)) {
		netif_err(adapter, drv, adapter->netdev,
			  "Location out of range\n");
		return -EINVAL;
	}

	input = kzalloc(sizeof(*input), GFP_ATOMIC);
	if (!input)
		return -ENOMEM;

	memset(&mask, 0, sizeof(union txgbe_atr_input));

	/* set SW index */
	input->sw_idx = fsp->location;

	/* record flow type */
	if (!txgbe_flowspec_to_flow_type(fsp,
					 &input->filter.formatted.flow_type)) {
		netif_err(adapter, drv, adapter->netdev,
			  "Unrecognized flow type\n");
		goto err_out;
	}

	mask.formatted.flow_type = TXGBE_ATR_L4TYPE_IPV6_MASK |
				   TXGBE_ATR_L4TYPE_MASK;

	if (input->filter.formatted.flow_type == TXGBE_ATR_FLOW_TYPE_IPV4)
		mask.formatted.flow_type &= TXGBE_ATR_L4TYPE_IPV6_MASK;

	/* Copy input into formatted structures */
	input->filter.formatted.src_ip[0] = fsp->h_u.tcp_ip4_spec.ip4src;
	mask.formatted.src_ip[0] = fsp->m_u.tcp_ip4_spec.ip4src;
	input->filter.formatted.dst_ip[0] = fsp->h_u.tcp_ip4_spec.ip4dst;
	mask.formatted.dst_ip[0] = fsp->m_u.tcp_ip4_spec.ip4dst;
	input->filter.formatted.src_port = fsp->h_u.tcp_ip4_spec.psrc;
	mask.formatted.src_port = fsp->m_u.tcp_ip4_spec.psrc;
	input->filter.formatted.dst_port = fsp->h_u.tcp_ip4_spec.pdst;
	mask.formatted.dst_port = fsp->m_u.tcp_ip4_spec.pdst;

	if (fsp->flow_type & FLOW_EXT) {
		input->filter.formatted.vm_pool =
				(unsigned char)ntohl(fsp->h_ext.data[1]);
		mask.formatted.vm_pool =
				(unsigned char)ntohl(fsp->m_ext.data[1]);
		input->filter.formatted.flex_bytes =
						fsp->h_ext.vlan_etype;
		mask.formatted.flex_bytes = fsp->m_ext.vlan_etype;
	}

	switch (input->filter.formatted.flow_type) {
	case TXGBE_ATR_FLOW_TYPE_TCPV4:
		ptype = TXGBE_PTYPE_L2_IPV4_TCP;
		break;
	case TXGBE_ATR_FLOW_TYPE_UDPV4:
		ptype = TXGBE_PTYPE_L2_IPV4_UDP;
		break;
	case TXGBE_ATR_FLOW_TYPE_SCTPV4:
		ptype = TXGBE_PTYPE_L2_IPV4_SCTP;
		break;
	case TXGBE_ATR_FLOW_TYPE_IPV4:
		ptype = TXGBE_PTYPE_L2_IPV4;
		break;
	case TXGBE_ATR_FLOW_TYPE_TCPV6:
		ptype = TXGBE_PTYPE_L2_IPV6_TCP;
		break;
	case TXGBE_ATR_FLOW_TYPE_UDPV6:
		ptype = TXGBE_PTYPE_L2_IPV6_UDP;
		break;
	case TXGBE_ATR_FLOW_TYPE_SCTPV6:
		ptype = TXGBE_PTYPE_L2_IPV6_SCTP;
		break;
	case TXGBE_ATR_FLOW_TYPE_IPV6:
		ptype = TXGBE_PTYPE_L2_IPV6;
		break;
	default:
		break;
	}

	input->filter.formatted.vlan_id = htons(ptype);
	if (mask.formatted.flow_type & TXGBE_ATR_L4TYPE_MASK)
		mask.formatted.vlan_id = htons(0xFFFF);
	else
		mask.formatted.vlan_id = htons(0xFFF8);

	/* determine if we need to drop or route the packet */
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC)
		input->action = TXGBE_RDB_FDIR_DROP_QUEUE;
	else
		input->action = fsp->ring_cookie;

	spin_lock(&adapter->fdir_perfect_lock);

	if (hlist_empty(&adapter->fdir_filter_list)) {
		/* save mask and program input mask into HW */
		memcpy(&adapter->fdir_mask, &mask, sizeof(mask));
		err = txgbe_fdir_set_input_mask(hw, &mask,
						adapter->cloud_mode);
		if (err) {
			netif_err(adapter, drv, adapter->netdev,
				  "Error writing mask\n");
			goto err_out_w_lock;
		}
	} else if (memcmp(&adapter->fdir_mask, &mask, sizeof(mask))) {
		netif_err(adapter, drv, adapter->netdev,
			  "Hardware only supports one mask per port. To change the mask you must first delete all the rules.\n");
		goto err_out_w_lock;
	}

	/* apply mask and compute/store hash */
	txgbe_atr_compute_perfect_hash(&input->filter, &mask);

	/* check if new entry does not exist on filter list */
	if (txgbe_match_ethtool_fdir_entry(adapter, input))
		goto err_out_w_lock;

	/* only program filters to hardware if the net device is running, as
	 * we store the filters in the Rx buffer which is not allocated when
	 * the device is down
	 */
	if (netif_running(adapter->netdev)) {
		err = txgbe_fdir_write_perfect_filter(hw,
						      &input->filter, input->sw_idx, queue,
						      adapter->cloud_mode);
		if (err)
			goto err_out_w_lock;
	}

	txgbe_update_ethtool_fdir_entry(adapter, input, input->sw_idx);

	spin_unlock(&adapter->fdir_perfect_lock);

	return err;
err_out_w_lock:
	spin_unlock(&adapter->fdir_perfect_lock);
err_out:
	kfree(input);
	return -EINVAL;
}

static int txgbe_del_ethtool_fdir_entry(struct txgbe_adapter *adapter,
					struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	int err;

	spin_lock(&adapter->fdir_perfect_lock);
	err = txgbe_update_ethtool_fdir_entry(adapter, NULL, fsp->location);
	spin_unlock(&adapter->fdir_perfect_lock);

	return err;
}

#define UDP_RSS_FLAGS (TXGBE_FLAG2_RSS_FIELD_IPV4_UDP | \
		       TXGBE_FLAG2_RSS_FIELD_IPV6_UDP)
static int txgbe_set_rss_hash_opt(struct txgbe_adapter *adapter,
				  struct ethtool_rxnfc *nfc)
{
	u32 flags2 = adapter->flags2;

	/* RSS does not support anything other than hashing
	 * to queues on src and dst IPs and ports
	 */
	if (nfc->data & ~(RXH_IP_SRC | RXH_IP_DST |
			  RXH_L4_B_0_1 | RXH_L4_B_2_3))
		return -EINVAL;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
	case TCP_V6_FLOW:
		if (!(nfc->data & RXH_IP_SRC) ||
		    !(nfc->data & RXH_IP_DST) ||
		    !(nfc->data & RXH_L4_B_0_1) ||
		    !(nfc->data & RXH_L4_B_2_3))
			return -EINVAL;
		break;
	case UDP_V4_FLOW:
		if (!(nfc->data & RXH_IP_SRC) ||
		    !(nfc->data & RXH_IP_DST))
			return -EINVAL;
		switch (nfc->data & (RXH_L4_B_0_1 | RXH_L4_B_2_3)) {
		case 0:
			flags2 &= ~TXGBE_FLAG2_RSS_FIELD_IPV4_UDP;
			break;
		case (RXH_L4_B_0_1 | RXH_L4_B_2_3):
			flags2 |= TXGBE_FLAG2_RSS_FIELD_IPV4_UDP;
			break;
		default:
			return -EINVAL;
		}
		break;
	case UDP_V6_FLOW:
		if (!(nfc->data & RXH_IP_SRC) ||
		    !(nfc->data & RXH_IP_DST))
			return -EINVAL;
		switch (nfc->data & (RXH_L4_B_0_1 | RXH_L4_B_2_3)) {
		case 0:
			flags2 &= ~TXGBE_FLAG2_RSS_FIELD_IPV6_UDP;
			break;
		case (RXH_L4_B_0_1 | RXH_L4_B_2_3):
			flags2 |= TXGBE_FLAG2_RSS_FIELD_IPV6_UDP;
			break;
		default:
			return -EINVAL;
		}
		break;
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case SCTP_V4_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case SCTP_V6_FLOW:
		if (!(nfc->data & RXH_IP_SRC) ||
		    !(nfc->data & RXH_IP_DST) ||
		    (nfc->data & RXH_L4_B_0_1) ||
		    (nfc->data & RXH_L4_B_2_3))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	/* if we changed something we need to update flags */
	if (flags2 != adapter->flags2) {
		struct txgbe_hw *hw = &adapter->hw;
		u32 mrqc;

		mrqc = rd32(hw, TXGBE_RDB_RA_CTL);

		if ((flags2 & UDP_RSS_FLAGS) &&
		    !(adapter->flags2 & UDP_RSS_FLAGS))
			netif_warn(adapter, drv, adapter->netdev,
				   "enabling UDP RSS: fragmented packets may arrive out of order to the stack above\n");

		adapter->flags2 = flags2;

		/* Perform hash on these packet types */
		mrqc |= TXGBE_RDB_RA_CTL_RSS_IPV4
		      | TXGBE_RDB_RA_CTL_RSS_IPV4_TCP
		      | TXGBE_RDB_RA_CTL_RSS_IPV6
		      | TXGBE_RDB_RA_CTL_RSS_IPV6_TCP;

		mrqc &= ~(TXGBE_RDB_RA_CTL_RSS_IPV4_UDP |
			  TXGBE_RDB_RA_CTL_RSS_IPV6_UDP);

		if (flags2 & TXGBE_FLAG2_RSS_FIELD_IPV4_UDP)
			mrqc |= TXGBE_RDB_RA_CTL_RSS_IPV4_UDP;

		if (flags2 & TXGBE_FLAG2_RSS_FIELD_IPV6_UDP)
			mrqc |= TXGBE_RDB_RA_CTL_RSS_IPV6_UDP;

		wr32(hw, TXGBE_RDB_RA_CTL, mrqc);
	}

	return 0;
}

static int txgbe_set_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		ret = txgbe_add_ethtool_fdir_entry(adapter, cmd);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		ret = txgbe_del_ethtool_fdir_entry(adapter, cmd);
		break;
	case ETHTOOL_SRXFH:
		ret = txgbe_set_rss_hash_opt(adapter, cmd);
		break;
	default:
		break;
	}

	return ret;
}

static u32 txgbe_get_rxfh_key_size(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	return sizeof(adapter->rss_key);
}

static u32 txgbe_rss_indir_size(struct net_device *netdev)
{
	return 128;
}

static void txgbe_get_reta(struct txgbe_adapter *adapter, u32 *indir)
{
	int i, reta_size = 128;

	for (i = 0; i < reta_size; i++)
		indir[i] = adapter->rss_indir_tbl[i];
}

static int txgbe_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			  u8 *hfunc)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (indir)
		txgbe_get_reta(adapter, indir);

	if (key)
		memcpy(key, adapter->rss_key, txgbe_get_rxfh_key_size(netdev));

	return 0;
}

static int txgbe_set_rxfh(struct net_device *netdev, const u32 *indir,
			  const u8 *key, const u8 hfunc)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	int i;
	u32 reta_entries = 128;

	if (hfunc)
		return -EINVAL;

	/* Fill out the redirection table */
	if (indir) {
		int max_queues = min_t(int, adapter->num_rx_queues,
				       TXGBE_RSS_INDIR_TBL_MAX);

		/* Verify user input. */
		for (i = 0; i < reta_entries; i++)
			if (indir[i] >= max_queues)
				return -EINVAL;

		for (i = 0; i < reta_entries; i++)
			adapter->rss_indir_tbl[i] = indir[i];
	}

	/* Fill out the rss hash key */
	if (key)
		memcpy(adapter->rss_key, key, txgbe_get_rxfh_key_size(netdev));

	txgbe_store_reta(adapter);

	return 0;
}

static int txgbe_get_ts_info(struct net_device *dev,
			     struct ethtool_ts_info *info)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);

	/* we always support timestamping disabled */
	info->rx_filters = 1 << HWTSTAMP_FILTER_NONE;

	info->so_timestamping =
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;

	if (adapter->ptp_clock)
		info->phc_index = ptp_clock_index(adapter->ptp_clock);
	else
		info->phc_index = -1;

	info->tx_types =
		(1 << HWTSTAMP_TX_OFF) |
		(1 << HWTSTAMP_TX_ON);

	info->rx_filters |=
		(1 << HWTSTAMP_FILTER_PTP_V1_L4_SYNC) |
		(1 << HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ) |
		(1 << HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
		(1 << HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
		(1 << HWTSTAMP_FILTER_PTP_V2_SYNC) |
		(1 << HWTSTAMP_FILTER_PTP_V2_L2_SYNC) |
		(1 << HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
		(1 << HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
		(1 << HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ) |
		(1 << HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ) |
		(1 << HWTSTAMP_FILTER_PTP_V2_EVENT);

	return 0;
}

static unsigned int txgbe_max_channels(struct txgbe_adapter *adapter)
{
	unsigned int max_combined;

	if (!(adapter->flags & TXGBE_FLAG_MSIX_ENABLED)) {
		/* We only support one q_vector without MSI-X */
		max_combined = 1;
	} else if (adapter->atr_sample_rate) {
		/* support up to 64 queues with ATR */
		max_combined = TXGBE_MAX_FDIR_INDICES;
	} else {
		/* support up to max allowed queues with RSS */
		max_combined = TXGBE_MAX_RSS_INDICES;
	}

	return max_combined;
}

static void txgbe_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);

	/* report maximum channels */
	ch->max_combined = txgbe_max_channels(adapter);

	/* report info for other vector */
	if (adapter->flags & TXGBE_FLAG_MSIX_ENABLED) {
		ch->max_other = NON_Q_VECTORS;
		ch->other_count = NON_Q_VECTORS;
	}

	/* record RSS queues */
	ch->combined_count = adapter->ring_feature[RING_F_RSS].indices;

	/* nothing else to report if RSS is disabled */
	if (ch->combined_count == 1)
		return;

	/* if ATR is disabled we can exit */
	if (!adapter->atr_sample_rate)
		return;

	/* report flow director queues as maximum channels */
	ch->combined_count = adapter->ring_feature[RING_F_FDIR].indices;
}

static int txgbe_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);
	unsigned int count = ch->combined_count;
	u8 max_rss_indices = TXGBE_MAX_RSS_INDICES;

	/* verify they are not requesting separate vectors */
	if (!count || ch->rx_count || ch->tx_count)
		return -EINVAL;

	/* verify other_count has not changed */
	if (ch->other_count != NON_Q_VECTORS)
		return -EINVAL;

	/* verify the number of channels does not exceed hardware limits */
	if (count > txgbe_max_channels(adapter))
		return -EINVAL;

	/* update feature limits from largest to smallest supported values */
	adapter->ring_feature[RING_F_FDIR].limit = count;

	/* cap RSS limit */
	if (count > max_rss_indices)
		count = max_rss_indices;
	adapter->ring_feature[RING_F_RSS].limit = count;

	/* use setup TC to update any traffic class queue mapping */
	return txgbe_setup_tc(dev, netdev_get_num_tc(dev));
}

static int txgbe_get_module_info(struct net_device *dev,
				 struct ethtool_modinfo *modinfo)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);
	struct txgbe_hw *hw = &adapter->hw;
	u32 status;
	u8 sff8472_rev, addr_mode;
	bool page_swap = false;

	/* Check whether we support SFF-8472 or not */
	status = TCALL(hw, phy.ops.read_i2c_eeprom,
		       TXGBE_SFF_SFF_8472_COMP,
		       &sff8472_rev);
	if (status != 0)
		return -EIO;

	/* addressing mode is not supported */
	status = TCALL(hw, phy.ops.read_i2c_eeprom,
		       TXGBE_SFF_SFF_8472_SWAP,
		       &addr_mode);
	if (status != 0)
		return -EIO;

	if (addr_mode & TXGBE_SFF_ADDRESSING_MODE) {
		netif_err(adapter, drv, dev,
			  "Address change required to access page 0xA2, but not supported. Please report the module type to the driver maintainers.\n");
		page_swap = true;
	}

	if (sff8472_rev == TXGBE_SFF_SFF_8472_UNSUP || page_swap) {
		/* We have a SFP, but it does not support SFF-8472 */
		modinfo->type = ETH_MODULE_SFF_8079;
		modinfo->eeprom_len = ETH_MODULE_SFF_8079_LEN;
	} else {
		/* We have a SFP which supports a revision of SFF-8472. */
		modinfo->type = ETH_MODULE_SFF_8472;
		modinfo->eeprom_len = ETH_MODULE_SFF_8472_LEN;
	}

	return 0;
}

static int txgbe_get_module_eeprom(struct net_device *dev,
				   struct ethtool_eeprom *ee,
				   u8 *data)
{
	struct txgbe_adapter *adapter = netdev_priv(dev);
	struct txgbe_hw *hw = &adapter->hw;
	u32 status = TXGBE_ERR_PHY_ADDR_INVALID;
	u8 databyte = 0xFF;
	int i = 0;

	if (ee->len == 0)
		return -EINVAL;

	for (i = ee->offset; i < ee->offset + ee->len; i++) {
		/* I2C reads can take long time */
		if (test_bit(__TXGBE_IN_SFP_INIT, &adapter->state))
			return -EBUSY;

		if (i < ETH_MODULE_SFF_8079_LEN)
			status = TCALL(hw, phy.ops.read_i2c_eeprom, i,
				       &databyte);
		else
			status = TCALL(hw, phy.ops.read_i2c_sff8472, i,
				       &databyte);

		if (status != 0)
			return -EIO;

		data[i - ee->offset] = databyte;
	}

	return 0;
}

static int txgbe_set_flash(struct net_device *netdev, struct ethtool_flash *ef)
{
	int ret;
	const struct firmware *fw;
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	ret = request_firmware(&fw, ef->data, &netdev->dev);
	if (ret < 0)
		return ret;

	if (txgbe_mng_present(&adapter->hw))
		ret = txgbe_upgrade_flash_hostif(&adapter->hw,
						 ef->region,
						 fw->data, fw->size);
	else
		ret = -EOPNOTSUPP;

	release_firmware(fw);
	if (!ret)
		dev_info(&netdev->dev,
			 "loaded firmware %s, reboot to make firmware work\n",
			 ef->data);
	return ret;
}

static const struct ethtool_ops txgbe_ethtool_ops = {
	.get_link_ksettings     = txgbe_get_link_ksettings,
	.set_link_ksettings     = txgbe_set_link_ksettings,
	.get_drvinfo            = txgbe_get_drvinfo,
	.get_regs_len           = txgbe_get_regs_len,
	.get_regs               = txgbe_get_regs,
	.get_wol                = txgbe_get_wol,
	.set_wol                = txgbe_set_wol,
	.nway_reset             = txgbe_nway_reset,
	.get_link               = ethtool_op_get_link,
	.get_eeprom_len         = txgbe_get_eeprom_len,
	.get_eeprom             = txgbe_get_eeprom,
	.set_eeprom             = txgbe_set_eeprom,
	.get_ringparam          = txgbe_get_ringparam,
	.set_ringparam          = txgbe_set_ringparam,
	.get_pauseparam         = txgbe_get_pauseparam,
	.set_pauseparam         = txgbe_set_pauseparam,
	.get_msglevel           = txgbe_get_msglevel,
	.set_msglevel           = txgbe_set_msglevel,
	.self_test              = txgbe_diag_test,
	.get_strings            = txgbe_get_strings,
	.set_phys_id            = txgbe_set_phys_id,
	.get_sset_count         = txgbe_get_sset_count,
	.get_ethtool_stats      = txgbe_get_ethtool_stats,
	.get_coalesce           = txgbe_get_coalesce,
	.set_coalesce           = txgbe_set_coalesce,
	.get_rxnfc              = txgbe_get_rxnfc,
	.set_rxnfc              = txgbe_set_rxnfc,
	.get_channels           = txgbe_get_channels,
	.set_channels           = txgbe_set_channels,
	.get_module_info        = txgbe_get_module_info,
	.get_module_eeprom      = txgbe_get_module_eeprom,
	.get_ts_info            = txgbe_get_ts_info,
	.get_rxfh_indir_size    = txgbe_rss_indir_size,
	.get_rxfh_key_size      = txgbe_get_rxfh_key_size,
	.get_rxfh               = txgbe_get_rxfh,
	.set_rxfh               = txgbe_set_rxfh,
	.flash_device           = txgbe_set_flash,
};

void txgbe_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &txgbe_ethtool_ops;
}
