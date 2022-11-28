// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#include "ngbe_type.h"
#include "ngbe_hw.h"
#include "ngbe_phy.h"
#include "ngbe.h"

#define NGBE_SP_RAR_ENTRIES        32
#define NGBE_FAILED_READ_CFG_WORD  0xffffU

u8 fmgr_cmd_op(struct ngbe_hw *hw, u32 cmd, u32 cmd_addr)
{
	u32 cmd_val = 0;
	u32 time_out = 0;

	cmd_val = (cmd << SPI_CLK_CMD_OFFSET) |
			  (SPI_CLK_DIV << SPI_CLK_DIV_OFFSET) |
			  cmd_addr;
	wr32(hw, SPI_H_CMD_REG_ADDR, cmd_val);
	while (1) {
		if (rd32(hw, SPI_H_STA_REG_ADDR) & 0x1)
			break;

		if (time_out == SPI_TIME_OUT_VALUE)
			return 1;

		time_out = time_out + 1;
		usleep_range(10, 200);
	}

	return 0;
}

u32 ngbe_flash_read_dword(struct ngbe_hw *hw, u32 addr)
{
	u8 status;

	status = fmgr_cmd_op(hw, SPI_CMD_READ_DWORD, addr);
	if (status)
		return (u32)status;

	return rd32(hw, SPI_H_DAT_REG_ADDR);
}

/**
 *  ngbe_get_media_type - Get media type
 *  @hw: pointer to hardware structure
 **/
enum ngbe_media_type ngbe_get_media_type(struct ngbe_hw *hw)
{
	enum ngbe_media_type media_type;

	media_type = ngbe_media_type_copper;

	return media_type;
}

/**
 * ngbe_setup_copper_link - Set the PHY autoneg advertised field
 * @hw: pointer to hardware structure
 * @speed: new link speed
 * @autoneg_wait_to_complete: true if waiting is needed to complete
 **/
static s32 ngbe_setup_copper_link(struct ngbe_hw *hw,
				  u32 speed,
			bool need_restart_AN)
{
	s32 status = 0;
	struct ngbe_adapter *adapter = hw->back;

	/* Setup the PHY according to input speed */
	if (!((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA))
		status = TCALL(hw, phy.ops.setup_link, speed, need_restart_AN);

	adapter->flags |= NGBE_FLAG_NEED_ANC_CHECK;

	return status;
}

/**
 * ngbe_get_copper_link_capabilities - Determines link capabilities
 * @hw: pointer to hardware structure
 * @speed: pointer to link speed
 * @autoneg: boolean auto-negotiation value
 **/
s32 ngbe_get_copper_link_capabilities(struct ngbe_hw *hw,
				      u32 *speed,
		bool *autoneg)
{
	s32 status = 0;
	u16 value = 0;

	*speed = 0;

	if (hw->mac.autoneg)
		*autoneg = true;
	else
		*autoneg = false;

	if (status == 0) {
		*speed = NGBE_LINK_SPEED_10_FULL |
		  NGBE_LINK_SPEED_100_FULL |
		  NGBE_LINK_SPEED_1GB_FULL;
	}

	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA) {
		*speed = NGBE_LINK_SPEED_1GB_FULL;
		hw->phy.link_mode = NGBE_PHYSICAL_LAYER_1000BASE_T;
		*autoneg = false;
	}

	if (hw->phy.type == ngbe_phy_m88e1512_sfi) {
		*speed = NGBE_LINK_SPEED_1GB_FULL;
		hw->phy.link_mode = NGBE_PHYSICAL_LAYER_1000BASE_T;
	}

	if (hw->phy.type == ngbe_phy_yt8521s_sfi) {
		ngbe_phy_read_reg_ext_yt(hw, 0xA001, 0, &value);
		if ((value & 7) == 1) {
			*speed = NGBE_LINK_SPEED_1GB_FULL;
			hw->phy.link_mode = NGBE_PHYSICAL_LAYER_1000BASE_T;
		}
	}

	return status;
}

int ngbe_check_flash_load(struct ngbe_hw *hw, u32 check_bit)
{
	u32 i = 0;
	u32 reg = 0;
	int err = 0;
	/* if there's flash existing */
	if (!(rd32(hw, NGBE_SPI_STATUS) &
		NGBE_SPI_STATUS_FLASH_BYPASS)) {
		/* wait hw load flash done */
		for (i = 0; i < NGBE_MAX_FLASH_LOAD_POLL_TIME; i++) {
			reg = rd32(hw, NGBE_SPI_ILDR_STATUS);
			if (!(reg & check_bit))
				break;

			msleep(200);
		}
		if (i == NGBE_MAX_FLASH_LOAD_POLL_TIME) {
			err = NGBE_ERR_FLASH_LOADING_FAILED;
			ERROR_REPORT1(hw, NGBE_ERROR_POLLING, "HW Loading Flash failed: %d\n", err);
		}
	}

	return err;
}

/**
 *  ngbe_init_thermal_sensor_thresh - Inits thermal sensor thresholds
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_thermal_sensor_thresh(struct ngbe_hw *hw)
{
	s32 status = 0;

	struct ngbe_thermal_sensor_data *data = &hw->mac.thermal_sensor_data;

	memset(data, 0, sizeof(struct ngbe_thermal_sensor_data));

	/* Only support thermal sensors attached to SP physical port 0 */
	if (hw->bus.lan_id)
		return NGBE_NOT_IMPLEMENTED;

	wr32(hw, NGBE_TS_INT_EN,
	     NGBE_TS_INT_EN_DALARM_INT_EN |
		 NGBE_TS_INT_EN_ALARM_INT_EN);
	wr32(hw, NGBE_TS_EN, NGBE_TS_EN_ENA);

	data->sensor.alarm_thresh = 115;
	wr32(hw, NGBE_TS_ALARM_THRE, 0x344);/* magic num */
	data->sensor.dalarm_thresh = 110;
	wr32(hw, NGBE_TS_DALARM_THRE, 0x330);/* magic num */

	return status;
}

int ngbe_reset_misc(struct ngbe_hw *hw)
{
	int i;

	/* receive packets that size > 2048 */
	wr32m(hw, NGBE_MAC_RX_CFG,
	      NGBE_MAC_RX_CFG_JE, NGBE_MAC_RX_CFG_JE);

	/* clear counters on read */
	wr32m(hw, NGBE_MMC_CONTROL,
	      NGBE_MMC_CONTROL_RSTONRD, NGBE_MMC_CONTROL_RSTONRD);

	wr32m(hw, NGBE_MAC_RX_FLOW_CTRL,
	      NGBE_MAC_RX_FLOW_CTRL_RFE, NGBE_MAC_RX_FLOW_CTRL_RFE);

	wr32(hw, NGBE_MAC_PKT_FLT,
	     NGBE_MAC_PKT_FLT_PR);

	wr32m(hw, NGBE_MIS_RST_ST,
	      NGBE_MIS_RST_ST_RST_INIT, 0x1E00);

	/* errata 4: initialize mng flex tbl and wakeup flex tbl*/
	wr32(hw, NGBE_PSR_MNG_FLEX_SEL, 0);
	for (i = 0; i < 16; i++) {
		wr32(hw, NGBE_PSR_MNG_FLEX_DW_L(i), 0);
		wr32(hw, NGBE_PSR_MNG_FLEX_DW_H(i), 0);
		wr32(hw, NGBE_PSR_MNG_FLEX_MSK(i), 0);
	}
	wr32(hw, NGBE_PSR_LAN_FLEX_SEL, 0);
	for (i = 0; i < 16; i++) {
		wr32(hw, NGBE_PSR_LAN_FLEX_DW_L(i), 0);
		wr32(hw, NGBE_PSR_LAN_FLEX_DW_H(i), 0);
		wr32(hw, NGBE_PSR_LAN_FLEX_MSK(i), 0);
	}

	/* set pause frame dst mac addr */
	wr32(hw, NGBE_RDB_PFCMACDAL, 0xC2000001);
	wr32(hw, NGBE_RDB_PFCMACDAH, 0x0180);

	wr32(hw, NGBE_MDIO_CLAUSE_SELECT, 0xF);

	if (hw->gpio_ctl == 1) {
		/* gpio0 is used to power on/off control*/
		wr32(hw, NGBE_GPIO_DDR, 0x1);
		wr32(hw, NGBE_GPIO_DR, NGBE_GPIO_DR_0);
	}

	ngbe_init_thermal_sensor_thresh(hw);

	return 0;
}

/**
 *  ngbe_init_hw - Generic hardware initialization
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_hw(struct ngbe_hw *hw)
{
	s32 status;

	/* Reset the hardware */
	status = TCALL(hw, mac.ops.reset_hw);

	if (status == 0) {
		/* Start the HW */
		status = TCALL(hw, mac.ops.start_hw);
	}

	return status;
}

/**
 *  ngbe_reset_hw - Perform hardware reset
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_reset_hw(struct ngbe_hw *hw)
{
	s32 status;
	u32 reset = 0;
	u32 i;
	struct ngbe_mac_info *mac = &hw->mac;
	u32 sr_pcs_ctl = 0;
	u32 sr_pma_mmd_ctl1 = 0;
	u32 sr_an_mmd_ctl = 0;
	u32 sr_an_mmd_adv_reg2 = 0;
	u32 vr_xs_or_pcs_mmd_digi_ctl1 = 0;
	u32 curr_vr_xs_or_pcs_mmd_digi_ctl1 = 0;
	u32 curr_sr_pcs_ctl = 0;
	u32 curr_sr_pma_mmd_ctl1 = 0;
	u32 curr_sr_an_mmd_ctl = 0;
	u32 curr_sr_an_mmd_adv_reg2 = 0;
	u32 reset_status = 0;
	u32 rst_delay = 0;
	struct ngbe_adapter *adapter = NULL;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	status = TCALL(hw, mac.ops.stop_adapter);
	if (status != 0)
		goto reset_hw_out;

	/* Identify PHY and related function pointers */
	if (!((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA)) {
		status = TCALL(hw, phy.ops.init);
		if (status)
			goto reset_hw_out;
	}

	if (ngbe_get_media_type(hw) == ngbe_media_type_copper) {
		mac->ops.setup_link = ngbe_setup_copper_link;
		mac->ops.get_link_capabilities =
				 ngbe_get_copper_link_capabilities;
	}

	/* Issue global reset to the MAC.  Needs to be SW reset if link is up.
	 * If link reset is used when link is up, it might reset the PHY when
	 * mng is using it.  If link is down or the flag to force full link
	 * reset is set, then perform link reset.
	 */
	if (hw->force_full_reset) {
		rst_delay = (rd32(hw, NGBE_MIS_RST_ST) &
			NGBE_MIS_RST_ST_RST_INIT) >>
			NGBE_MIS_RST_ST_RST_INI_SHIFT;
		if (hw->reset_type == NGBE_SW_RESET) {
			for (i = 0; i < rst_delay + 20; i++) {
				reset_status =
					rd32(hw, NGBE_MIS_RST_ST);
				if (!(reset_status &
				    NGBE_MIS_RST_ST_DEV_RST_ST_MASK))
					break;
				msleep(100);
			}

			if (reset_status & NGBE_MIS_RST_ST_DEV_RST_ST_MASK) {
				status = NGBE_ERR_RESET_FAILED;
				ERROR_REPORT1(hw, NGBE_ERROR_POLLING,
					      "software reset polling failed to complete.\n");

				goto reset_hw_out;
			}
			status = ngbe_check_flash_load(hw, NGBE_SPI_ILDR_STATUS_SW_RESET);
			if (status != 0)
				goto reset_hw_out;

		} else if (hw->reset_type == NGBE_GLOBAL_RESET) {
			adapter = (struct ngbe_adapter *)hw->back;
			msleep(100 * rst_delay + 2000);
			pci_restore_state(adapter->pdev);
			pci_save_state(adapter->pdev);
			pci_wake_from_d3(adapter->pdev, false);
		}
	} else {
		if (hw->bus.lan_id == 0)
			reset = NGBE_MIS_RST_LAN0_RST;
		else if (hw->bus.lan_id == 1)
			reset = NGBE_MIS_RST_LAN1_RST;
		else if (hw->bus.lan_id == 2)
			reset = NGBE_MIS_RST_LAN2_RST;
		else if (hw->bus.lan_id == 3)
			reset = NGBE_MIS_RST_LAN3_RST;

		wr32(hw, NGBE_MIS_RST,
		     reset | rd32(hw, NGBE_MIS_RST));
		NGBE_WRITE_FLUSH(hw);

		mdelay(15);
	}

	status = ngbe_reset_misc(hw);
	if (status != 0)
		goto reset_hw_out;

	if (!hw->mac.orig_link_settings_stored) {
		hw->mac.orig_sr_pcs_ctl2 = sr_pcs_ctl;
		hw->mac.orig_sr_pma_mmd_ctl1 = sr_pma_mmd_ctl1;
		hw->mac.orig_sr_an_mmd_ctl = sr_an_mmd_ctl;
		hw->mac.orig_sr_an_mmd_adv_reg2 = sr_an_mmd_adv_reg2;
		hw->mac.orig_vr_xs_or_pcs_mmd_digi_ctl1 =
						vr_xs_or_pcs_mmd_digi_ctl1;
		hw->mac.orig_link_settings_stored = true;
	} else {
		/* If MNG FW is running on a multi-speed device that
		 * doesn't autoneg with out driver support we need to
		 * leave LMS in the state it was before we MAC reset.
		 * Likewise if we support WoL we don't want change the
		 * LMS state.
		 */
		hw->mac.orig_sr_pcs_ctl2 = curr_sr_pcs_ctl;
		hw->mac.orig_sr_pma_mmd_ctl1 = curr_sr_pma_mmd_ctl1;
		hw->mac.orig_sr_an_mmd_ctl = curr_sr_an_mmd_ctl;
		hw->mac.orig_sr_an_mmd_adv_reg2 =
					curr_sr_an_mmd_adv_reg2;
		hw->mac.orig_vr_xs_or_pcs_mmd_digi_ctl1 =
					curr_vr_xs_or_pcs_mmd_digi_ctl1;
	}

	/* Store the permanent mac address */
	TCALL(hw, mac.ops.get_mac_addr, hw->mac.perm_addr);

	/* Store MAC address from RAR0, clear receive address registers, and
	 * clear the multicast table.  Also reset num_rar_entries to 128,
	 * since we modify this value when programming the SAN MAC address.
	 */
	hw->mac.num_rar_entries = NGBE_SP_RAR_ENTRIES;
	TCALL(hw, mac.ops.init_rx_addrs);

	pci_set_master(((struct ngbe_adapter *)hw->back)->pdev);

reset_hw_out:
	return status;
}

/**
 * ngbe_clear_hw_cntrs - Generic clear hardware counters
 * @hw: pointer to hardware structure
 **/
s32 ngbe_clear_hw_cntrs(struct ngbe_hw *hw)
{
	u16 i = 0;

	rd32(hw, NGBE_RX_CRC_ERROR_FRAMES_LOW);
	rd32(hw, NGBE_RX_LEN_ERROR_FRAMES_LOW);
	rd32(hw, NGBE_RDB_LXONTXC);
	rd32(hw, NGBE_RDB_LXOFFTXC);

	/* rd32(hw, NGBE_MAC_LXONRXC); */
	rd32(hw, NGBE_MAC_LXOFFRXC);

	for (i = 0; i < 8; i++) {
		wr32m(hw, NGBE_MMC_CONTROL, NGBE_MMC_CONTROL_UP, i << 16);
		rd32(hw, NGBE_MAC_PXOFFRXC);
	}

	for (i = 0; i < 8; i++)
		wr32(hw, NGBE_PX_MPRC(i), 0);

	/* BPRC */
	rd32(hw, NGBE_PX_GPRC);
	rd32(hw, NGBE_PX_GPTC);
	rd32(hw, NGBE_PX_GORC_MSB);
	rd32(hw, NGBE_PX_GOTC_MSB);

	rd32(hw, NGBE_RX_BC_FRAMES_GOOD_LOW);
	rd32(hw, NGBE_RX_UNDERSIZE_FRAMES_GOOD);
	rd32(hw, NGBE_RX_OVERSIZE_FRAMES_GOOD);
	rd32(hw, NGBE_RX_FRAME_CNT_GOOD_BAD_LOW);
	rd32(hw, NGBE_TX_FRAME_CNT_GOOD_BAD_LOW);
	rd32(hw, NGBE_TX_MC_FRAMES_GOOD_LOW);
	rd32(hw, NGBE_TX_BC_FRAMES_GOOD_LOW);
	rd32(hw, NGBE_RDM_DRP_PKT);

	return 0;
}

/**
 * ngbe_get_mac_addr - Generic get MAC address
 * @hw: pointer to hardware structure
 * @mac_addr: Adapter MAC address
 **/
s32 ngbe_get_mac_addr(struct ngbe_hw *hw, u8 *mac_addr)
{
	u32 rar_high;
	u32 rar_low;
	u16 i;

	wr32(hw, NGBE_PSR_MAC_SWC_IDX, 0);
	rar_high = rd32(hw, NGBE_PSR_MAC_SWC_AD_H);
	rar_low = rd32(hw, NGBE_PSR_MAC_SWC_AD_L);

	for (i = 0; i < 2; i++)
		mac_addr[i] = (u8)(rar_high >> (1 - i) * 8);

	for (i = 0; i < 4; i++)
		mac_addr[i + 2] = (u8)(rar_low >> (3 - i) * 8);

	return 0;
}

/**
 *  ngbe_disable_pcie_master - Disable PCI-express master access
 *  @hw: pointer to hardware structure
 *
 *  Disables PCI-Express master access and verifies there are no pending
 *  requests. NGBE_ERR_MASTER_REQUESTS_PENDING is returned if master disable
 *  bit hasn't caused the master requests to be disabled, else 0
 *  is returned signifying master requests disabled.
 **/
s32 ngbe_disable_pcie_master(struct ngbe_hw *hw)
{
	s32 status = 0;
	u32 i;

	/* Always set this bit to ensure any future transactions are blocked */
	pci_clear_master(((struct ngbe_adapter *)hw->back)->pdev);

	/* Exit if master requests are blocked */
	if (!(rd32(hw, NGBE_PX_TRANSACTION_PENDING)) || NGBE_REMOVED(hw->hw_addr))
		goto out;

	/* Poll for master request bit to clear */
	for (i = 0; i < NGBE_PCI_MASTER_DISABLE_TIMEOUT; i++) {
		usleep_range(100, 200);
		if (!(rd32(hw, NGBE_PX_TRANSACTION_PENDING)))
			goto out;
	}

		ERROR_REPORT1(hw, NGBE_ERROR_POLLING,
			      "PCIe transaction pending bit did not clear.\n");
		status = NGBE_ERR_MASTER_REQUESTS_PENDING;
out:
	return status;
}

/**
 * ngbe_stop_adapter - Generic stop Tx/Rx units
 * @hw: pointer to hardware structure
 **/
s32 ngbe_stop_adapter(struct ngbe_hw *hw)
{
	u16 i;

	/* Set the adapter_stopped flag so other driver functions stop touching
	 * the hardware
	 */
	hw->adapter_stopped = true;

	/* Disable the receive unit */
	TCALL(hw, mac.ops.disable_rx);

	/* Set interrupt mask to stop interrupts from being generated */
	ngbe_intr_disable(hw, NGBE_INTR_ALL);

	/* Clear any pending interrupts, flush previous writes */
	wr32(hw, NGBE_PX_MISC_IC, 0xffffffff);

	wr32(hw, NGBE_BME_CTL, 0x3);

	/* Disable the transmit unit.  Each queue must be disabled. */
	for (i = 0; i < hw->mac.max_tx_queues; i++) {
		wr32m(hw, NGBE_PX_TR_CFG(i),
		      NGBE_PX_TR_CFG_SWFLSH | NGBE_PX_TR_CFG_ENABLE,
			  NGBE_PX_TR_CFG_SWFLSH);
	}

	/* Disable the receive unit by stopping each queue */
	for (i = 0; i < hw->mac.max_rx_queues; i++) {
		wr32m(hw, NGBE_PX_RR_CFG(i),
		      NGBE_PX_RR_CFG_RR_EN, 0);
	}

	/* flush all queues disables */
	NGBE_WRITE_FLUSH(hw);
	mdelay(2);

	/* Prevent the PCI-E bus from hanging by disabling PCI-E master
	 * access and verify no pending requests
	 */
	return ngbe_disable_pcie_master(hw);
}

static bool ngbe_check_cfg_remove(struct ngbe_hw *hw, struct pci_dev *pdev)
{
	u16 value;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &value);
	if (value == NGBE_FAILED_READ_CFG_WORD)
		return true;

	return false;
}

static u16 ngbe_read_pci_cfg_word(struct ngbe_hw *hw, u32 reg)
{
	struct ngbe_adapter *adapter = hw->back;
	u16 value;

	if (NGBE_REMOVED(hw->hw_addr))
		return NGBE_FAILED_READ_CFG_WORD;
	pci_read_config_word(adapter->pdev, reg, &value);
	if (value == NGBE_FAILED_READ_CFG_WORD &&
	    ngbe_check_cfg_remove(hw, adapter->pdev))
		return NGBE_FAILED_READ_CFG_WORD;

	return value;
}

/**
 * ngbe_set_pci_config_data - Generic store PCI bus info
 * @hw: pointer to hardware structure
 * @link_status: the link status returned by the PCI config space
 **/
void ngbe_set_pci_config_data(struct ngbe_hw *hw, u16 link_status)
{
	if (hw->bus.type == ngbe_bus_type_unknown)
		hw->bus.type = ngbe_bus_type_pci_express;

	switch (link_status & NGBE_PCI_LINK_WIDTH) {
	case NGBE_PCI_LINK_WIDTH_1:
		hw->bus.width = ngbe_bus_width_pcie_x1;
		break;
	case NGBE_PCI_LINK_WIDTH_2:
		hw->bus.width = ngbe_bus_width_pcie_x2;
		break;
	case NGBE_PCI_LINK_WIDTH_4:
		hw->bus.width = ngbe_bus_width_pcie_x4;
		break;
	case NGBE_PCI_LINK_WIDTH_8:
		hw->bus.width = ngbe_bus_width_pcie_x8;
		break;
	default:
		hw->bus.width = ngbe_bus_width_unknown;
		break;
	}

	switch (link_status & NGBE_PCI_LINK_SPEED) {
	case NGBE_PCI_LINK_SPEED_2500:
		hw->bus.speed = ngbe_bus_speed_2500;
		break;
	case NGBE_PCI_LINK_SPEED_5000:
		hw->bus.speed = ngbe_bus_speed_5000;
		break;
	case NGBE_PCI_LINK_SPEED_8000:
		hw->bus.speed = ngbe_bus_speed_8000;
		break;
	default:
		hw->bus.speed = ngbe_bus_speed_unknown;
		break;
	}
}

/**
 * ngbe_get_bus_info - Generic set PCI bus info
 * @hw: pointer to hardware structure
 **/
s32 ngbe_get_bus_info(struct ngbe_hw *hw)
{
	u16 link_status;

	/* Get the negotiated link width and speed from PCI config space */
	link_status = ngbe_read_pci_cfg_word(hw, NGBE_PCI_LINK_STATUS);

	ngbe_set_pci_config_data(hw, link_status);

	return 0;
}

/**
 * ngbe_mng_present - returns true when manangbeent capability is present
 * @hw: pointer to hardware structure
 */
bool ngbe_mng_present(struct ngbe_hw *hw)
{
	u32 fwsm;

	fwsm = rd32(hw, NGBE_MIS_ST);
	return fwsm & NGBE_MIS_ST_MNG_INIT_DN;
}

bool ngbe_check_mng_access(struct ngbe_hw *hw)
{
	if (!ngbe_mng_present(hw))
		return false;
	return true;
}

/**
 * ngbe_set_lan_id_multi_port_pcie - Set LAN id for PCIe multiple port devices
 * @hw: pointer to the HW structure
 **/
void ngbe_set_lan_id_multi_port_pcie(struct ngbe_hw *hw)
{
	struct ngbe_bus_info *bus = &hw->bus;
	u32 reg = 0;

	reg = rd32(hw, NGBE_CFG_PORT_ST);
	bus->lan_id = NGBE_CFG_PORT_ST_LAN_ID(reg);
	bus->func = bus->lan_id;
}

/**
 * ngbe_release_eeprom_semaphore - Release hardware semaphore
 * @hw: pointer to hardware structure
 **/
static void ngbe_release_eeprom_semaphore(struct ngbe_hw *hw)
{
	if (ngbe_check_mng_access(hw)) {
		wr32m(hw, NGBE_MIS_SWSM,
		      NGBE_MIS_SWSM_SMBI, 0);
		NGBE_WRITE_FLUSH(hw);
	}
}

/**
 * ngbe_get_eeprom_semaphore - Get hardware semaphore
 * @hw: pointer to hardware structure
 **/
static s32 ngbe_get_eeprom_semaphore(struct ngbe_hw *hw)
{
	s32 status = NGBE_ERR_EEPROM;
	u32 timeout = 2000;
	u32 i;
	u32 swsm;

	/* Get SMBI software semaphore between device drivers first */
	for (i = 0; i < timeout; i++) {
		/* If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = rd32(hw, NGBE_MIS_SWSM);
		if (!(swsm & NGBE_MIS_SWSM_SMBI)) {
			status = 0;
			break;
		}
		usleep_range(50, 100);
	}

	if (i == timeout) {
		/* this release is particularly important because our attempts
		 * above to get the semaphore may have succeeded, and if there
		 * was a timeout, we should unconditionally clear the semaphore
		 * bits to free the driver to make progress
		 */
		ngbe_release_eeprom_semaphore(hw);

		usleep_range(50, 100);
		/* one last try
		 * If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = rd32(hw, NGBE_MIS_SWSM);
		if (!(swsm & NGBE_MIS_SWSM_SMBI))
			status = 0;
	}

	return status;
}

/**
 * ngbe_release_swfw_sync - Release SWFW semaphore
 * @hw: pointer to hardware structure
 * @mask: Mask to specify which semaphore to release
 **/
void ngbe_release_swfw_sync(struct ngbe_hw *hw, u32 mask)
{
	ngbe_get_eeprom_semaphore(hw);
	if (ngbe_check_mng_access(hw))
		wr32m(hw, NGBE_MNG_SWFW_SYNC, mask, 0);

	ngbe_release_eeprom_semaphore(hw);
}

/**
 * ngbe_acquire_swfw_sync - Acquire SWFW semaphore
 * @hw: pointer to hardware structure
 * @mask: Mask to specify which semaphore to acquire
 **/
s32 ngbe_acquire_swfw_sync(struct ngbe_hw *hw, u32 mask)
{
	u32 gssr = 0;
	u32 swmask = mask;
	u32 fwmask = mask << 16;
	u32 timeout = 200;
	u32 i;

	for (i = 0; i < timeout; i++) {
		/* SW NVM semaphore bit is used for access to all
		 * SW_FW_SYNC bits (not just NVM)
		 */
		if (ngbe_get_eeprom_semaphore(hw))
			return NGBE_ERR_SWFW_SYNC;

		if (ngbe_check_mng_access(hw)) {
			gssr = rd32(hw, NGBE_MNG_SWFW_SYNC);
			if (!(gssr & (fwmask | swmask))) {
				gssr |= swmask;
				wr32(hw, NGBE_MNG_SWFW_SYNC, gssr);

				ngbe_release_eeprom_semaphore(hw);
			} else {
				/* Resource is currently in use by FW or SW */
				ngbe_release_eeprom_semaphore(hw);
				mdelay(5);
			}

			if (!(gssr & (fwmask | swmask)))
				return 0;
		}
	}

	ERROR_REPORT1(hw, NGBE_ERROR_POLLING,
		      "%s: i = %u, gssr = %u\n", __func__, i, gssr);

	/* If time expired clear the bits holding the lock and retry */
	if (gssr & (fwmask | swmask))
		ngbe_release_swfw_sync(hw, gssr & (fwmask | swmask));

	mdelay(5);

	return NGBE_ERR_SWFW_SYNC;
}

/**
 * ngbe_disable_sec_rx_path - Stops the receive data path
 * @hw: pointer to hardware structure
 **/
s32 ngbe_disable_sec_rx_path(struct ngbe_hw *hw)
{
	int i;
	int secrxreg;

	wr32m(hw, NGBE_RSEC_CTL,
	      NGBE_RSEC_CTL_RX_DIS, NGBE_RSEC_CTL_RX_DIS);
	for (i = 0; i < 40; i++) {
		secrxreg = rd32(hw, NGBE_RSEC_ST);
		if (secrxreg & NGBE_RSEC_ST_RSEC_RDY)
			break;

		usleep_range(1000, 2000);
	}

	return 0;
}

/**
 * ngbe_enable_sec_rx_path - Enables the receive data path
 * @hw: pointer to hardware structure
 **/
s32 ngbe_enable_sec_rx_path(struct ngbe_hw *hw)
{
	wr32m(hw, NGBE_RSEC_CTL,
	      NGBE_RSEC_CTL_RX_DIS, 0);
	NGBE_WRITE_FLUSH(hw);

	return 0;
}

/**
 * ngbe_enable_rx_dma - Enable the Rx DMA unit on emerald
 * @hw: pointer to hardware structure
 * @regval: register value to write to RXCTRL
 **/
s32 ngbe_enable_rx_dma(struct ngbe_hw *hw, u32 regval)
{
	/* Workaround for emerald silicon errata when enabling the Rx datapath.
	 * If traffic is incoming before we enable the Rx unit, it could hang
	 * the Rx DMA unit.  Therefore, make sure the security engine is
	 * completely disabled prior to enabling the Rx unit.
	 */
	TCALL(hw, mac.ops.disable_sec_rx_path);

	if (regval & NGBE_RDB_PB_CTL_PBEN)
		TCALL(hw, mac.ops.enable_rx);
	else
		TCALL(hw, mac.ops.disable_rx);

	TCALL(hw, mac.ops.enable_sec_rx_path);

	return 0;
}

/**
 *  ngbe_start_hw - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_start_hw(struct ngbe_hw *hw)
{
	int ret_val = 0;

	/* Set the media type */
	hw->phy.media_type = TCALL(hw, mac.ops.get_media_type);

	/* Clear the VLAN filter table */
	TCALL(hw, mac.ops.clear_vfta);

	/* Clear statistics registers */
	TCALL(hw, mac.ops.clear_hw_cntrs);

	NGBE_WRITE_FLUSH(hw);

	/* Clear adapter stopped flag */
	hw->adapter_stopped = false;

	return ret_val;
}

/**
 *  ngbe_get_device_caps - Get additional device capabilities
 *  @hw: pointer to hardware structure
 *  @device_caps: the EEPROM word with the extra device capabilities
 **/
s32 ngbe_get_device_caps(struct ngbe_hw *hw, u16 *device_caps)
{
	TCALL(hw, eeprom.ops.read,
	      hw->eeprom.sw_region_offset + NGBE_DEVICE_CAPS, device_caps);

	return 0;
}

/**
 * ngbe_set_rar - Set Rx address register
 * @hw: pointer to hardware structure
 * @index: Receive address register to write
 * @addr: Address to put into receive address register
 * @vmdq: VMDq "set" or "pool" index
 * @enable_addr: set flag that address is active
 **/
s32 ngbe_set_rar(struct ngbe_hw *hw, u32 index, u8 *addr, u64 pools,
		 u32 enable_addr)
{
	u32 rar_low, rar_high;
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (index >= rar_entries) {
		ERROR_REPORT2(hw, NGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", index);
		return NGBE_ERR_INVALID_ARGUMENT;
	}

	/* select the MAC address */
	wr32(hw, NGBE_PSR_MAC_SWC_IDX, index);

	/* setup VMDq pool mapping */
	wr32(hw, NGBE_PSR_MAC_SWC_VM, pools & 0xFFFFFFFF);

	/* HW expects these in little endian so we reverse the byte
	 * order from network order (big endian) to little endian
	 *
	 * Some parts put the VMDq setting in the extra RAH bits,
	 * so save everything except the lower 16 bits that hold part
	 * of the address and the address valid bit.
	 */
	rar_low = ((u32)addr[5] |
			  ((u32)addr[4] << 8) |
			  ((u32)addr[3] << 16) |
			  ((u32)addr[2] << 24));
	rar_high = ((u32)addr[1] |
			   ((u32)addr[0] << 8));
	if (enable_addr != 0)
		rar_high |= NGBE_PSR_MAC_SWC_AD_H_AV;

	wr32(hw, NGBE_PSR_MAC_SWC_AD_L, rar_low);
	wr32m(hw, NGBE_PSR_MAC_SWC_AD_H,
	      (NGBE_PSR_MAC_SWC_AD_H_AD(~0) |
		  NGBE_PSR_MAC_SWC_AD_H_ADTYPE(~0) |
		  NGBE_PSR_MAC_SWC_AD_H_AV),
		  rar_high);

	return 0;
}

/**
 * ngbe_clear_rar - Remove Rx address register
 * @hw: pointer to hardware structure
 * @index: Receive address register to write
 **/
s32 ngbe_clear_rar(struct ngbe_hw *hw, u32 index)
{
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (index >= rar_entries) {
		ERROR_REPORT2(hw, NGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", index);

		return NGBE_ERR_INVALID_ARGUMENT;
	}

	/* Some parts put the VMDq setting in the extra RAH bits,
	 * so save everything except the lower 16 bits that hold part
	 * of the address and the address valid bit.
	 */
	wr32(hw, NGBE_PSR_MAC_SWC_IDX, index);

	wr32(hw, NGBE_PSR_MAC_SWC_VM, 0);
	wr32(hw, NGBE_PSR_MAC_SWC_AD_L, 0);
	wr32m(hw, NGBE_PSR_MAC_SWC_AD_H,
	      (NGBE_PSR_MAC_SWC_AD_H_AD(~0) |
		  NGBE_PSR_MAC_SWC_AD_H_ADTYPE(~0) |
		  NGBE_PSR_MAC_SWC_AD_H_AV),
		  0);

	return 0;
}

/**
 * ngbe_validate_mac_addr - Validate MAC address
 * @mac_addr: pointer to MAC address.
 **/
s32 ngbe_validate_mac_addr(u8 *mac_addr)
{
	s32 status = 0;

	/* Make sure it is not a multicast address */
	if (NGBE_IS_MULTICAST(mac_addr))
		status = NGBE_ERR_INVALID_MAC_ADDR;
	else if (NGBE_IS_BROADCAST(mac_addr))
		status = NGBE_ERR_INVALID_MAC_ADDR;
	else if (mac_addr[0] == 0 && mac_addr[1] == 0 && mac_addr[2] == 0 &&
		 mac_addr[3] == 0 && mac_addr[4] == 0 && mac_addr[5] == 0)
		status = NGBE_ERR_INVALID_MAC_ADDR;

	return status;
}

/**
 * ngbe_init_rx_addrs - Initializes receive address filters.
 * @hw: pointer to hardware structure
 **/
s32 ngbe_init_rx_addrs(struct ngbe_hw *hw)
{
	u32 i;
	u32 rar_entries = hw->mac.num_rar_entries;
	u32 psrctl;

	/* If the current mac address is valid, assume it is a software override
	 * to the permanent address.
	 * Otherwise, use the permanent address from the eeprom.
	 */
	if (ngbe_validate_mac_addr(hw->mac.addr) ==
		NGBE_ERR_INVALID_MAC_ADDR) {
		/* Get the MAC address from the RAR0 for later reference */
		TCALL(hw, mac.ops.get_mac_addr, hw->mac.addr);
	} else {
		/* Setup the receive address. */
		TCALL(hw, mac.ops.set_rar, 0, hw->mac.addr, 0,
		      NGBE_PSR_MAC_SWC_AD_H_AV);
	}
	hw->addr_ctrl.overflow_promisc = 0;
	hw->addr_ctrl.rar_used_count = 1;

	/* Zero out the other receive addresses. */
	for (i = 1; i < rar_entries; i++) {
		wr32(hw, NGBE_PSR_MAC_SWC_IDX, i);
		wr32(hw, NGBE_PSR_MAC_SWC_AD_L, 0);
		wr32(hw, NGBE_PSR_MAC_SWC_AD_H, 0);
	}

	/* Clear the MTA */
	hw->addr_ctrl.mta_in_use = 0;
	psrctl = rd32(hw, NGBE_PSR_CTL);
	psrctl &= ~(NGBE_PSR_CTL_MO | NGBE_PSR_CTL_MFE);
	psrctl |= hw->mac.mc_filter_type << NGBE_PSR_CTL_MO_SHIFT;
	wr32(hw, NGBE_PSR_CTL, psrctl);

	for (i = 0; i < hw->mac.mcft_size; i++)
		wr32(hw, NGBE_PSR_MC_TBL(i), 0);

	TCALL(hw, mac.ops.init_uta_tables);

	return 0;
}

/**
 * ngbe_add_uc_addr - Adds a secondary unicast address.
 * @hw: pointer to hardware structure
 * @addr: new address
 **/
void ngbe_add_uc_addr(struct ngbe_hw *hw, u8 *addr, u32 vmdq)
{
	u32 rar_entries = hw->mac.num_rar_entries;
	u32 rar;

	/* Place this address in the RAR if there is room,
	 * else put the controller into promiscuous mode
	 */
	if (hw->addr_ctrl.rar_used_count < rar_entries) {
		rar = hw->addr_ctrl.rar_used_count;
		TCALL(hw, mac.ops.set_rar, rar, addr, vmdq,
		      NGBE_PSR_MAC_SWC_AD_H_AV);
		hw->addr_ctrl.rar_used_count++;
	} else {
		hw->addr_ctrl.overflow_promisc++;
	}
}

/**
 * ngbe_mta_vector - Determines bit-vector in multicast table to set
 * @hw: pointer to hardware structure
 * @mc_addr: the multicast address
 **/
static s32 ngbe_mta_vector(struct ngbe_hw *hw, u8 *mc_addr)
{
	u32 vector = 0;

	switch (hw->mac.mc_filter_type) {
	case 0:   /* use bits [47:36] of the address */
		vector = ((mc_addr[4] >> 4) | (((u16)mc_addr[5]) << 4));
		break;
	case 1:   /* use bits [46:35] of the address */
		vector = ((mc_addr[4] >> 3) | (((u16)mc_addr[5]) << 5));
		break;
	case 2:   /* use bits [45:34] of the address */
		vector = ((mc_addr[4] >> 2) | (((u16)mc_addr[5]) << 6));
		break;
	case 3:   /* use bits [43:32] of the address */
		vector = ((mc_addr[4]) | (((u16)mc_addr[5]) << 8));
		break;
	default:  /* Invalid mc_filter_type */
		WARN_ON(1);
		break;
	}

	/* vector can only be 12-bits or boundary will be exceeded */
	vector &= 0xFFF;
	return vector;
}

/**
 *  ngbe_set_mta - Set bit-vector in multicast table
 *  @hw: pointer to hardware structure
 *  @hash_value: Multicast address hash value
 **/
void ngbe_set_mta(struct ngbe_hw *hw, u8 *mc_addr)
{
	u32 vector;
	u32 vector_bit;
	u32 vector_reg;

	hw->addr_ctrl.mta_in_use++;

	vector = ngbe_mta_vector(hw, mc_addr);

	/* The MTA is a register array of 128 32-bit registers. It is treated
	 * like an array of 4096 bits.  We want to set bit
	 * BitArray[vector_value]. So we figure out what register the bit is
	 * in, read it, OR in the new bit, then write back the new value.  The
	 * register is determined by the upper 7 bits of the vector value and
	 * the bit within that register are determined by the lower 5 bits of
	 * the value.
	 */
	vector_reg = (vector >> 5) & 0x7F;
	vector_bit = vector & 0x1F;
	hw->mac.mta_shadow[vector_reg] |= (1 << vector_bit);
}

/**
 * ngbe_update_uc_addr_list - Updates MAC list of secondary addresses
 * @hw: pointer to hardware structure
 * @list: the list of new addresses
 * @count: number of addresses
 * @itr: iterator function to walk the address list
 **/
s32 ngbe_update_uc_addr_list(struct ngbe_hw *hw, u8 *list,
			     u32 count, ngbe_mc_itr itr)
{
	u8 *addr;
	u32 i;
	u32 old_promisc_setting = hw->addr_ctrl.overflow_promisc;
	u32 uc_addr_in_use;
	u32 vmdq;

	/* Clear accounting of old secondary address list,
	 * don't count RAR[0]
	 */
	uc_addr_in_use = hw->addr_ctrl.rar_used_count - 1;
	hw->addr_ctrl.rar_used_count -= uc_addr_in_use;
	hw->addr_ctrl.overflow_promisc = 0;

	/* Zero out the other receive addresses */
	for (i = 0; i < uc_addr_in_use; i++) {
		wr32(hw, NGBE_PSR_MAC_SWC_IDX, 1 + i);
		wr32(hw, NGBE_PSR_MAC_SWC_AD_L, 0);
		wr32(hw, NGBE_PSR_MAC_SWC_AD_H, 0);
	}

	/* Add the new addresses */
	for (i = 0; i < count; i++) {
		addr = itr(hw, &list, &vmdq);
		ngbe_add_uc_addr(hw, addr, vmdq);
	}

	if (hw->addr_ctrl.overflow_promisc) {
		/* enable promisc if not already in overflow or set by user */
		if (!old_promisc_setting && !hw->addr_ctrl.user_set_promisc)
			wr32m(hw, NGBE_PSR_CTL,
			      NGBE_PSR_CTL_UPE, NGBE_PSR_CTL_UPE);
	} else {
		/* only disable if set by overflow, not by user */
		if (old_promisc_setting && !hw->addr_ctrl.user_set_promisc)
			wr32m(hw, NGBE_PSR_CTL,
			      NGBE_PSR_CTL_UPE, 0);
	}

	return 0;
}

/**
 * ngbe_update_mc_addr_list - Updates MAC list of multicast addresses
 * @hw: pointer to hardware structure
 * @list: the list of new multicast addresses
 * @count: number of addresses
 * @itr: iterator function to walk the multicast address list
 * @clear: flag, when set clears the table beforehand
 **/
s32 ngbe_update_mc_addr_list(struct ngbe_hw *hw, u8 *list,
			     u32 count, ngbe_mc_itr itr,
									 bool clear)
{
	u32 i;
	u32 vmdq;
	u32 psrctl;

	/* Set the new number of MC addresses that we are being requested to
	 * use.
	 */
	hw->addr_ctrl.num_mc_addrs = count;
	hw->addr_ctrl.mta_in_use = 0;

	/* Clear mta_shadow */
	if (clear)
		memset(&hw->mac.mta_shadow, 0, sizeof(hw->mac.mta_shadow));

	/* Update mta_shadow */
	for (i = 0; i < count; i++)
		ngbe_set_mta(hw, itr(hw, &list, &vmdq));

	/* Enable mta */
	for (i = 0; i < hw->mac.mcft_size; i++)
		wr32a(hw, NGBE_PSR_MC_TBL(0), i,
		      hw->mac.mta_shadow[i]);

	if (hw->addr_ctrl.mta_in_use > 0) {
		psrctl = rd32(hw, NGBE_PSR_CTL);
		psrctl &= ~(NGBE_PSR_CTL_MO | NGBE_PSR_CTL_MFE);
		psrctl |= NGBE_PSR_CTL_MFE |
				  (hw->mac.mc_filter_type << NGBE_PSR_CTL_MO_SHIFT);
		wr32(hw, NGBE_PSR_CTL, psrctl);
	}

	return 0;
}

/**
 * ngbe_enable_mc - Enable multicast address in RAR
 * @hw: pointer to hardware structure
 **/
s32 ngbe_enable_mc(struct ngbe_hw *hw)
{
	struct ngbe_addr_filter_info *nafi = &hw->addr_ctrl;
	u32 psrctl;

	if (nafi->mta_in_use > 0) {
		psrctl = rd32(hw, NGBE_PSR_CTL);
		psrctl &= ~(NGBE_PSR_CTL_MO | NGBE_PSR_CTL_MFE);
		psrctl |= NGBE_PSR_CTL_MFE |
				  (hw->mac.mc_filter_type << NGBE_PSR_CTL_MO_SHIFT);
		wr32(hw, NGBE_PSR_CTL, psrctl);
	}

	return 0;
}

/**
 * ngbe_disable_mc - Disable multicast address in RAR
 * @hw: pointer to hardware structure
 **/
s32 ngbe_disable_mc(struct ngbe_hw *hw)
{
	struct ngbe_addr_filter_info *nafi = &hw->addr_ctrl;
	u32 psrctl;

	if (nafi->mta_in_use > 0) {
		psrctl = rd32(hw, NGBE_PSR_CTL);
		psrctl &= ~(NGBE_PSR_CTL_MO | NGBE_PSR_CTL_MFE);
		psrctl |= hw->mac.mc_filter_type << NGBE_PSR_CTL_MO_SHIFT;
		wr32(hw, NGBE_PSR_CTL, psrctl);
	}

	return 0;
}

void ngbe_enable_rx(struct ngbe_hw *hw)
{
	u32 pfdtxgswc;

	/* enable mac receiver */
	wr32m(hw, NGBE_MAC_RX_CFG,
	      NGBE_MAC_RX_CFG_RE, NGBE_MAC_RX_CFG_RE);

	wr32m(hw, NGBE_RSEC_CTL, 0x2, 0);

	wr32m(hw, NGBE_RDB_PB_CTL,
	      NGBE_RDB_PB_CTL_PBEN, NGBE_RDB_PB_CTL_PBEN);

	if (hw->mac.set_lben) {
		pfdtxgswc = rd32(hw, NGBE_PSR_CTL);
		pfdtxgswc |= NGBE_PSR_CTL_SW_EN;
		wr32(hw, NGBE_PSR_CTL, pfdtxgswc);
		hw->mac.set_lben = false;
	}
}

void ngbe_disable_rx(struct ngbe_hw *hw)
{
	u32 pfdtxgswc;
	u32 rxctrl;

	rxctrl = rd32(hw, NGBE_RDB_PB_CTL);

	if (rxctrl & NGBE_RDB_PB_CTL_PBEN) {
		pfdtxgswc = rd32(hw, NGBE_PSR_CTL);
		if (pfdtxgswc & NGBE_PSR_CTL_SW_EN) {
			pfdtxgswc &= ~NGBE_PSR_CTL_SW_EN;
			wr32(hw, NGBE_PSR_CTL, pfdtxgswc);
			hw->mac.set_lben = true;
		} else {
			hw->mac.set_lben = false;
		}
		rxctrl &= ~NGBE_RDB_PB_CTL_PBEN;
		wr32(hw, NGBE_RDB_PB_CTL, rxctrl);

		/* OCP NCSI BMC need it */
		if (!(((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_OCP_CARD) ||
		      ((hw->subsystem_device_id & NGBE_WOL_MASK) == NGBE_WOL_SUP) ||
			   ((hw->subsystem_device_id & NGBE_NCSI_MASK) == NGBE_NCSI_SUP))) {
		/* disable mac receiver */
			wr32m(hw, NGBE_MAC_RX_CFG,
			      NGBE_MAC_RX_CFG_RE, 0);
		}
	}
}

/**
 *  ngbe_insert_mac_addr - Find a RAR for this mac address
 *  @hw: pointer to hardware structure
 *  @addr: Address to put into receive address register
 *  @vmdq: VMDq pool to assign
 *
 *  Puts an ethernet address into a receive address register, or
 *  finds the rar that it is aleady in; adds to the pool list
 **/
s32 ngbe_insert_mac_addr(struct ngbe_hw *hw, u8 *addr, u32 vmdq)
{
	static const u32 NO_EMPTY_RAR_FOUND = 0xFFFFFFFF;
	u32 first_empty_rar = NO_EMPTY_RAR_FOUND;
	u32 rar;
	u32 rar_low, rar_high;
	u32 addr_low, addr_high;

	/* swap bytes for HW little endian */
	addr_low  = addr[5] |
				(addr[4] << 8) |
				(addr[3] << 16) |
				(addr[2] << 24);
	addr_high = addr[1] | (addr[0] << 8);

	/* Either find the mac_id in rar or find the first empty space.
	 * rar_highwater points to just after the highest currently used
	 * rar in order to shorten the search.  It grows when we add a new
	 * rar to the top.
	 */
	for (rar = 0; rar < hw->mac.rar_highwater; rar++) {
		wr32(hw, NGBE_PSR_MAC_SWC_IDX, rar);
		rar_high = rd32(hw, NGBE_PSR_MAC_SWC_AD_H);

		if (((NGBE_PSR_MAC_SWC_AD_H_AV & rar_high) == 0) &&
		    first_empty_rar == NO_EMPTY_RAR_FOUND) {
			first_empty_rar = rar;
		} else if ((rar_high & 0xFFFF) == addr_high) {
			rar_low = rd32(hw, NGBE_PSR_MAC_SWC_AD_L);
			if (rar_low == addr_low)
				break;    /* found it already in the rars */
		}
	}

	if (rar >= hw->mac.rar_highwater) {
		if (first_empty_rar != NO_EMPTY_RAR_FOUND) {
			/* stick it into first empty RAR slot we found */
			rar = first_empty_rar;
			TCALL(hw, mac.ops.set_rar, rar, addr, vmdq,
			      NGBE_PSR_MAC_SWC_AD_H_AV);
		} else if (rar == hw->mac.rar_highwater) {
			/* add it to the top of the list and inc the highwater mark */
			TCALL(hw, mac.ops.set_rar, rar, addr, vmdq,
			      NGBE_PSR_MAC_SWC_AD_H_AV);
			hw->mac.rar_highwater++;
		} else if (rar >= hw->mac.num_rar_entries) {
			return NGBE_ERR_INVALID_MAC_ADDR;
		}
	}

	return rar;
}

/**
 * ngbe_find_vlvf_slot - find the vlanid or the first empty slot
 * @hw: pointer to hardware structure
 * @vlan: VLAN id to write to VLAN filter
 **/
s32 ngbe_find_vlvf_slot(struct ngbe_hw *hw, u32 vlan)
{
	u32 bits = 0;
	u32 first_empty_slot = 0;
	s32 regindex;

	/* short cut the special case */
	if (vlan == 0)
		return 0;

	/* Search for the vlan id in the VLVF entries. Save off the first empty
	 * slot found along the way
	 */
	for (regindex = 1; regindex < NGBE_PSR_VLAN_SWC_ENTRIES; regindex++) {
		wr32(hw, NGBE_PSR_VLAN_SWC_IDX, regindex);
		bits = rd32(hw, NGBE_PSR_VLAN_SWC);
		if (!bits && !(first_empty_slot))
			first_empty_slot = regindex;
		else if ((bits & 0x0FFF) == vlan)
			break;
	}

	/* If regindex is less than NGBE_VLVF_ENTRIES, then we found the vlan
	 * in the VLVF. Else use the first empty VLVF register for this
	 * vlan id.
	 */
	if (regindex >= NGBE_PSR_VLAN_SWC_ENTRIES) {
		if (first_empty_slot) {
			regindex = first_empty_slot;
		} else {
			ERROR_REPORT1(hw, NGBE_ERROR_SOFTWARE,
				      "No space in VLVF.\n");
			regindex = NGBE_ERR_NO_SPACE;
		}
	}

	return regindex;
}

/**
 *  ngbe_set_vlvf - Set VLAN Pool Filter
 *  @hw: pointer to hardware structure
 *  @vlan: VLAN id to write to VLAN filter
 *  @vind: VMDq output index that maps queue to VLAN id in VFVFB
 *  @vlan_on: boolean flag to turn on/off VLAN in VFVF
 *  @vfta_changed: pointer to boolean flag which indicates whether VFTA
 *                 should be changed
 **/
s32 ngbe_set_vlvf(struct ngbe_hw *hw, u32 vlan, u32 vind,
		  bool vlan_on, bool *vfta_changed)
{
	u32 vt;

	if (vlan > 4095)
		return NGBE_ERR_PARAM;

	/* If VT Mode is set
	 *   Either vlan_on
	 *     make sure the vlan is in VLVF
	 *     set the vind bit in the matching VLVFB
	 *   Or !vlan_on
	 *     clear the pool bit and possibly the vind
	 */
	vt = rd32(hw, NGBE_CFG_PORT_CTL);
	if (vt & NGBE_CFG_PORT_CTL_NUM_VT_MASK) {
		s32 vlvf_index;
		u32 bits = 0;

		vlvf_index = ngbe_find_vlvf_slot(hw, vlan);
		if (vlvf_index < 0)
			return vlvf_index;

		wr32(hw, NGBE_PSR_VLAN_SWC_IDX, vlvf_index);
		if (vlan_on) {
			/* set the pool bit */
			if (vind < 32) {
				bits = rd32(hw, NGBE_PSR_VLAN_SWC_VM_L);
				bits |= (1 << vind);
				wr32(hw, NGBE_PSR_VLAN_SWC_VM_L, bits);
			}
		} else {
			/* clear the pool bit */
			if (vind < 32) {
				bits = rd32(hw, NGBE_PSR_VLAN_SWC_VM_L);
				bits &= ~(1 << vind);
				wr32(hw, NGBE_PSR_VLAN_SWC_VM_L, bits);
			} else {
				bits |= rd32(hw, NGBE_PSR_VLAN_SWC_VM_L);
			}
		}

		/* If there are still bits set in the VLVFB registers
		 * for the VLAN ID indicated we need to see if the
		 * caller is requesting that we clear the VFTA entry bit.
		 * If the caller has requested that we clear the VFTA
		 * entry bit but there are still pools/VFs using this VLAN
		 * ID entry then ignore the request.  We're not worried
		 * about the case where we're turning the VFTA VLAN ID
		 * entry bit on, only when requested to turn it off as
		 * there may be multiple pools and/or VFs using the
		 * VLAN ID entry.  In that case we cannot clear the
		 * VFTA bit until all pools/VFs using that VLAN ID have also
		 * been cleared.  This will be indicated by "bits" being
		 * zero.
		 */
		if (bits) {
			wr32(hw, NGBE_PSR_VLAN_SWC, (NGBE_PSR_VLAN_SWC_VIEN | vlan));
			if (!vlan_on && vfta_changed) {
				/* someone wants to clear the vfta entry
				 * but some pools/VFs are still using it.
				 * Ignore it.
				 */
				*vfta_changed = false;
			}
		} else {
			wr32(hw, NGBE_PSR_VLAN_SWC, 0);
		}
	}

	return 0;
}

/**
 * ngbe_set_vfta - Set VLAN filter table
 * @hw: pointer to hardware structure
 * @vlan: VLAN id to write to VLAN filter
 * @vind: VMDq output index that maps queue to VLAN id in VFVFB
 * @vlan_on: boolean flag to turn on/off VLAN in VFVF
 **/
s32 ngbe_set_vfta(struct ngbe_hw *hw, u32 vlan, u32 vind, bool vlan_on)
{
	s32 regindex;
	u32 bitindex;
	u32 vfta;
	u32 targetbit;
	s32 ret_val = 0;
	bool vfta_changed = false;

	if (vlan > 4095)
		return NGBE_ERR_PARAM;

	/* this is a 2 part operation - first the VFTA, then the
	 * VLVF and VLVFB if VT Mode is set
	 * We don't write the VFTA until we know the VLVF part succeeded.
	 */

	/* Part 1
	 * The VFTA is a bitstring made up of 128 32-bit registers
	 * that enable the particular VLAN id, much like the MTA:
	 * bits[11-5]: which register
	 * bits[4-0]:  which bit in the register
	 */
	regindex = (vlan >> 5) & 0x7F;
	bitindex = vlan & 0x1F;
	targetbit = (1 << bitindex);
	/* errata 5 */
	vfta = hw->mac.vft_shadow[regindex];
	if (vlan_on) {
		if (!(vfta & targetbit)) {
			vfta |= targetbit;
			vfta_changed = true;
		}
	} else {
		if ((vfta & targetbit)) {
			vfta &= ~targetbit;
			vfta_changed = true;
		}
	}

	/* Part 2
	 * Call ngbe_set_vlvf to set VLVFB and VLVF
	 */
	ret_val = ngbe_set_vlvf(hw, vlan, vind, vlan_on,
				&vfta_changed);
	if (ret_val != 0)
		return ret_val;

	if (vfta_changed)
		wr32(hw, NGBE_PSR_VLAN_TBL(regindex), vfta);
	/* errata 5 */
	hw->mac.vft_shadow[regindex] = vfta;
	return 0;
}

/**
 *	ngbe_clear_vfta - Clear VLAN filter table
 *	@hw: pointer to hardware structure
 **/
s32 ngbe_clear_vfta(struct ngbe_hw *hw)
{
	u32 offset;

	for (offset = 0; offset < hw->mac.vft_size; offset++) {
		wr32(hw, NGBE_PSR_VLAN_TBL(offset), 0);
		/* errata 5 */
		hw->mac.vft_shadow[offset] = 0;
	}

	for (offset = 0; offset < NGBE_PSR_VLAN_SWC_ENTRIES; offset++) {
		wr32(hw, NGBE_PSR_VLAN_SWC_IDX, offset);
		wr32(hw, NGBE_PSR_VLAN_SWC, 0);
		wr32(hw, NGBE_PSR_VLAN_SWC_VM_L, 0);
	}

	return 0;
}

/**
 *  ngbe_init_uta_tables - Initialize the Unicast Table Array
 *  @hw: pointer to hardware structure
 **/
s32 ngbe_init_uta_tables(struct ngbe_hw *hw)
{
	int i;

	for (i = 0; i < 128; i++)
		wr32(hw, NGBE_PSR_UC_TBL(i), 0);

	return 0;
}

/**
 * ngbe_set_mac_anti_spoofing - Enable/Disable MAC anti-spoofing
 * @hw: pointer to hardware structure
 * @enable: enable or disable switch for anti-spoofing
 * @pf: Physical Function pool - do not enable anti-spoofing for the PF
 *
 **/
void ngbe_set_mac_anti_spoofing(struct ngbe_hw *hw, bool enable, int pf)
{
	u64 pfvfspoof = 0;

	if (enable) {
		/* The PF should be allowed to spoof so that it can support
		 * emulation mode NICs.  Do not set the bits assigned to the PF
		 * Remaining pools belong to the PF so they do not need to have
		 * anti-spoofing enabled.
		 */
		pfvfspoof = (1 << pf) - 1;
		wr32(hw, NGBE_TDM_MAC_AS_L, pfvfspoof & 0xff);
	} else {
		wr32(hw, NGBE_TDM_MAC_AS_L, 0);
	}
}

/**
 * ngbe_set_vlan_anti_spoofing - Enable/Disable VLAN anti-spoofing
 * @hw: pointer to hardware structure
 * @enable: enable or disable switch for VLAN anti-spoofing
 * @vf: Virtual Function pool - VF Pool to set for VLAN anti-spoofing
 **/
void ngbe_set_vlan_anti_spoofing(struct ngbe_hw *hw, bool enable, int vf)
{
	u32 pfvfspoof;

	if (vf > 8)
		return;

	pfvfspoof = rd32(hw, NGBE_TDM_VLAN_AS_L);
	if (enable)
		pfvfspoof |= (1 << vf);
	else
		pfvfspoof &= ~(1 << vf);
	wr32(hw, NGBE_TDM_VLAN_AS_L, pfvfspoof);
}

/**
 * ngbe_set_ethertype_anti_spoofing - Enable/Disable Ethertype anti-spoofing
 * @hw: pointer to hardware structure
 * @enable: enable or disable switch for Ethertype anti-spoofing
 * @vf: Virtual Function pool - VF Pool to set for Ethertype anti-spoofing
 **/
void ngbe_set_ethertype_anti_spoofing(struct ngbe_hw *hw, bool enable, int vf)
{
	u32 pfvfspoof;

	if (vf <= 8) {
		pfvfspoof = rd32(hw, NGBE_TDM_ETYPE_AS_L);
		if (enable)
			pfvfspoof |= (1 << vf);
		else
			pfvfspoof &= ~(1 << vf);
		wr32(hw, NGBE_TDM_ETYPE_AS_L, pfvfspoof);
	}
}

/**
 *	ngbe_get_link_capabilities - Determines link capabilities
 *	@hw: pointer to hardware structure
 *	@speed: pointer to link speed
 *	@autoneg: true when autoneg or autotry is enabled
 *
 *	Determines the link capabilities by reading the AUTOC register.
 **/
s32 ngbe_get_link_capabilities(struct ngbe_hw *hw,
			       u32 *speed,
										bool *autoneg)
{
	s32 status = 0;

	if (hw->device_id == NGBE_DEV_ID_EM_WX1860A2 ||
	    hw->device_id == NGBE_DEV_ID_EM_WX1860A2S ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860A4 ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860A4S ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860AL2 ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860AL2S ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860AL4 ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860AL4S ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860AL_W ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860A1 ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860A1L ||
		hw->device_id == NGBE_DEV_ID_EM_WX1860LC) {
		*speed = NGBE_LINK_SPEED_1GB_FULL |
				 NGBE_LINK_SPEED_100_FULL |
				 NGBE_LINK_SPEED_10_FULL;
		*autoneg = false;
		hw->phy.link_mode = NGBE_PHYSICAL_LAYER_1000BASE_T |
							NGBE_PHYSICAL_LAYER_100BASE_TX;
	}

	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA) {
		*speed = NGBE_LINK_SPEED_1GB_FULL;
		hw->phy.link_mode = NGBE_PHYSICAL_LAYER_1000BASE_T;
		*autoneg = false;
	}

	return status;
}

/**
 * ngbe_check_mac_link - Determine link and speed status
 * @hw: pointer to hardware structure
 * @speed: pointer to link speed
 * @link_up: true when link is up
 * @link_up_wait_to_complete: bool used to wait for link up or not
 **/
s32 ngbe_check_mac_link(struct ngbe_hw *hw,
			u32 *speed,
							  bool *link_up,
							  bool link_up_wait_to_complete)
{
	u32 i;
	u16 value = 0;
	s32 status = 0;
	u16 speed_sta = 0;

	if ((hw->subsystem_device_id & NGBE_OEM_MASK) == NGBE_SUBID_RGMII_FPGA) {
		*link_up = true;
		*speed = NGBE_LINK_SPEED_1GB_FULL;
		return status;
	}

	if (link_up_wait_to_complete) {
		for (i = 0; i < NGBE_LINK_UP_TIME; i++) {
			status = TCALL(hw, phy.ops.read_reg, 0x1A, 0xA43, &value);
			if (!status && (value & 0x4))
				*link_up = true;
			else
				*link_up = false;

			if (*link_up)
				break;
			msleep(100);
		}
	} else {
		status = TCALL(hw, phy.ops.read_reg, 0x1A, 0xA43, &value);
		if (!status && (value & 0x4))
			*link_up = true;
		else
			*link_up = false;
	}

	speed_sta = value & 0x38;
	if (*link_up) {
		if (speed_sta == 0x28)
			*speed = NGBE_LINK_SPEED_1GB_FULL;
		else if (speed_sta == 0x18)
			*speed = NGBE_LINK_SPEED_100_FULL;
		else if (speed_sta == 0x8)
			*speed = NGBE_LINK_SPEED_10_FULL;
	} else {
		*speed = NGBE_LINK_SPEED_UNKNOWN;
	}

	return status;
}

s32 ngbe_check_mac_link_mdi(struct ngbe_hw *hw, u32 *speed, bool *link_up, bool wait)
{
	u32 i;
	u16 value = 0;
	s32 status = 0;
	u16 speed_sta = 0;

	/* select page */
	if (hw->phy.type == ngbe_phy_m88e1512)
		status = TCALL(hw, phy.ops.write_reg_mdi, 22, 0, 0);
	else
		status = TCALL(hw, phy.ops.write_reg_mdi, 22, 0, 1);

	status = TCALL(hw, phy.ops.read_reg_mdi, 17, 0, &value);

	if (wait) {
		for (i = 0; i < NGBE_LINK_UP_TIME; i++) {
			status = TCALL(hw, phy.ops.read_reg_mdi, 17, 0, &value);
			if (value & 0x400)
				*link_up = true;
			else
				*link_up = false;

			if (*link_up)
				break;
			msleep(100);
		}
	} else {
		status = TCALL(hw, phy.ops.read_reg_mdi, 17, 0, &value);
		if (value & 0x400)
			*link_up = true;
		else
			*link_up = false;
	}

	speed_sta = value & 0xC000;
	if (*link_up) {
		if (speed_sta == 0x8000)
			*speed = NGBE_LINK_SPEED_1GB_FULL;
		else if (speed_sta == 0x4000)
			*speed = NGBE_LINK_SPEED_100_FULL;
		else if (speed_sta == 0x0000)
			*speed = NGBE_LINK_SPEED_10_FULL;
	} else {
		*speed = NGBE_LINK_SPEED_UNKNOWN;
	}

	return status;
}

s32 ngbe_check_mac_link_yt(struct ngbe_hw *hw, u32 *speed, bool *link_up, bool wait)
{
	u32 i;
	u16 value = 0;
	s32 status = 0;
	u16 speed_sta = 0;

	if (wait) {
		for (i = 0; i < NGBE_LINK_UP_TIME; i++) {
			status = ngbe_phy_read_reg_sds_mii_yt(hw, 0x11, 0, &value);
			if (value & 0x400)
				*link_up = true;
			else
				*link_up = false;

			if (*link_up)
				break;
			msleep(100);
		}
	} else {
		status = ngbe_phy_read_reg_sds_mii_yt(hw, 0x11, 0, &value);

		if (value & 0x400) {
			*link_up = true;
		} else {
			*link_up = false;

			ngbe_phy_read_reg_mdi(hw, 0x11, 0, &value);
			if (value & 0x400)
				*link_up = true;
			else
				*link_up = false;
		}
	}

	speed_sta = value & 0xC000;
	if (*link_up) {
		if (speed_sta == 0x8000)
			*speed = NGBE_LINK_SPEED_1GB_FULL;
		else if (speed_sta == 0x4000)
			*speed = NGBE_LINK_SPEED_100_FULL;
		else if (speed_sta == 0x0000)
			*speed = NGBE_LINK_SPEED_10_FULL;
	} else {
		*speed = NGBE_LINK_SPEED_UNKNOWN;
	}

	return status;
}

/**
 * ngbe_set_rxpba - Initialize Rx packet buffer
 * @hw: pointer to hardware structure
 * @num_pb: number of packet buffers to allocate
 * @headroom: reserve n KB of headroom
 * @strategy: packet buffer allocation strategy
 **/
void ngbe_set_rxpba(struct ngbe_hw *hw, int num_pb, u32 headroom,
		    int strategy)
{
	u32 pbsize = hw->mac.rx_pb_size;
	u32 rxpktsize, txpktsize, txpbthresh;

	/* Reserve headroom */
	pbsize -= headroom;

	if (!num_pb)
		num_pb = 1;

	/* Divide remaining packet buffer space amongst the number of packet
	 * buffers requested using supplied strategy.
	 */
	switch (strategy) {
	case PBA_STRATEGY_EQUAL:
		rxpktsize = (pbsize / num_pb) << NGBE_RDB_PB_SZ_SHIFT;
		wr32(hw, NGBE_RDB_PB_SZ, rxpktsize);
		break;
	default:
		break;
	}

	/* Only support an equally distributed Tx packet buffer strategy. */
	txpktsize = NGBE_TDB_PB_SZ_MAX / num_pb;
	txpbthresh = (txpktsize / NGBE_KB_TO_B) - NGBE_TXPKT_SIZE_MAX;

	wr32(hw, NGBE_TDB_PB_SZ, txpktsize);
	wr32(hw, NGBE_TDM_PB_THRE, txpbthresh);
}

s32 ngbe_init_ops_common(struct ngbe_hw *hw)
{
	struct ngbe_mac_info *mac = &hw->mac;

	/* MAC */
	mac->ops.init_hw = ngbe_init_hw;
	mac->ops.reset_hw = ngbe_reset_hw;
	mac->ops.clear_hw_cntrs = ngbe_clear_hw_cntrs;
	mac->ops.get_mac_addr = ngbe_get_mac_addr;
	mac->ops.stop_adapter = ngbe_stop_adapter;
	mac->ops.get_bus_info = ngbe_get_bus_info;
	mac->ops.set_lan_id = ngbe_set_lan_id_multi_port_pcie;
	mac->ops.acquire_swfw_sync = ngbe_acquire_swfw_sync;
	mac->ops.release_swfw_sync = ngbe_release_swfw_sync;
	mac->ops.get_media_type = ngbe_get_media_type;
	mac->ops.disable_sec_rx_path = ngbe_disable_sec_rx_path;
	mac->ops.enable_sec_rx_path = ngbe_enable_sec_rx_path;
	mac->ops.enable_rx_dma = ngbe_enable_rx_dma;
	mac->ops.start_hw = ngbe_start_hw;
	mac->ops.get_device_caps = ngbe_get_device_caps;

	/* RAR, Multicast, VLAN */
	mac->ops.set_rar = ngbe_set_rar;
	mac->ops.clear_rar = ngbe_clear_rar;
	mac->ops.init_rx_addrs = ngbe_init_rx_addrs;
	mac->ops.update_uc_addr_list = ngbe_update_uc_addr_list;
	mac->ops.update_mc_addr_list = ngbe_update_mc_addr_list;
	mac->ops.enable_mc = ngbe_enable_mc;
	mac->ops.disable_mc = ngbe_disable_mc;
	mac->ops.enable_rx = ngbe_enable_rx;
	mac->ops.disable_rx = ngbe_disable_rx;
	mac->ops.insert_mac_addr = ngbe_insert_mac_addr;
	mac->ops.set_vfta = ngbe_set_vfta;
	mac->ops.set_vlvf = ngbe_set_vlvf;
	mac->ops.clear_vfta = ngbe_clear_vfta;
	mac->ops.init_uta_tables = ngbe_init_uta_tables;
	mac->ops.set_mac_anti_spoofing = ngbe_set_mac_anti_spoofing;
	mac->ops.set_vlan_anti_spoofing = ngbe_set_vlan_anti_spoofing;
	mac->ops.set_ethertype_anti_spoofing =
				ngbe_set_ethertype_anti_spoofing;

		/* Link */
	mac->ops.get_link_capabilities = ngbe_get_link_capabilities;
	mac->ops.check_link = ngbe_check_mac_link;
	mac->ops.setup_rxpba = ngbe_set_rxpba;

	if (hw->phy.type == ngbe_phy_m88e1512 ||
	    hw->phy.type == ngbe_phy_m88e1512_sfi ||
		hw->phy.type == ngbe_phy_m88e1512_unknown)
		mac->ops.check_link = ngbe_check_mac_link_mdi;
	else if (hw->phy.type == ngbe_phy_yt8521s_sfi)
		mac->ops.check_link = ngbe_check_mac_link_yt;

	return NGBE_OK;
}
