// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_type.h"
#include "txgbe_hw.h"
#include "txgbe.h"

#define TXGBE_SP_MAX_TX_QUEUES  128
#define TXGBE_SP_MAX_RX_QUEUES  128
#define TXGBE_SP_RAR_ENTRIES    128

s32 txgbe_init_hw(struct txgbe_hw *hw)
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
 *  txgbe_get_mac_addr - Generic get MAC address
 *  @hw: pointer to hardware structure
 *  @mac_addr: Adapter MAC address
 *
 *  Reads the adapter's MAC address from first Receive Address Register (RAR0)
 *  A reset of the adapter must be performed prior to calling this function
 *  in order for the MAC address to have been loaded from the EEPROM into RAR0
 **/
s32 txgbe_get_mac_addr(struct txgbe_hw *hw, u8 *mac_addr)
{
	u32 rar_high;
	u32 rar_low;
	u16 i;

	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, 0);
	rar_high = rd32(hw, TXGBE_PSR_MAC_SWC_AD_H);
	rar_low = rd32(hw, TXGBE_PSR_MAC_SWC_AD_L);

	for (i = 0; i < 2; i++)
		mac_addr[i] = (u8)(rar_high >> (1 - i) * 8);

	for (i = 0; i < 4; i++)
		mac_addr[i + 2] = (u8)(rar_low >> (3 - i) * 8);

	return 0;
}

/**
 *  txgbe_set_pci_config_data - Generic store PCI bus info
 *  @hw: pointer to hardware structure
 *  @link_status: the link status returned by the PCI config space
 *
 *  Stores the PCI bus info (speed, width, type) within the txgbe_hw structure
 **/
void txgbe_set_pci_config_data(struct txgbe_hw *hw, u16 link_status)
{
	if (hw->bus.type == txgbe_bus_type_unknown)
		hw->bus.type = txgbe_bus_type_pci_express;

	switch (link_status & TXGBE_PCI_LINK_WIDTH) {
	case TXGBE_PCI_LINK_WIDTH_1:
		hw->bus.width = txgbe_bus_width_pcie_x1;
		break;
	case TXGBE_PCI_LINK_WIDTH_2:
		hw->bus.width = txgbe_bus_width_pcie_x2;
		break;
	case TXGBE_PCI_LINK_WIDTH_4:
		hw->bus.width = txgbe_bus_width_pcie_x4;
		break;
	case TXGBE_PCI_LINK_WIDTH_8:
		hw->bus.width = txgbe_bus_width_pcie_x8;
		break;
	default:
		hw->bus.width = txgbe_bus_width_unknown;
		break;
	}

	switch (link_status & TXGBE_PCI_LINK_SPEED) {
	case TXGBE_PCI_LINK_SPEED_2500:
		hw->bus.speed = txgbe_bus_speed_2500;
		break;
	case TXGBE_PCI_LINK_SPEED_5000:
		hw->bus.speed = txgbe_bus_speed_5000;
		break;
	case TXGBE_PCI_LINK_SPEED_8000:
		hw->bus.speed = txgbe_bus_speed_8000;
		break;
	default:
		hw->bus.speed = txgbe_bus_speed_unknown;
		break;
	}
}

/**
 *  txgbe_get_bus_info - Generic set PCI bus info
 *  @hw: pointer to hardware structure
 *
 *  Gets the PCI bus info (speed, width, type) then calls helper function to
 *  store this data within the txgbe_hw structure.
 **/
s32 txgbe_get_bus_info(struct txgbe_hw *hw)
{
	u16 link_status;

	/* Get the negotiated link width and speed from PCI config space */
	link_status = txgbe_read_pci_cfg_word(hw, TXGBE_PCI_LINK_STATUS);

	txgbe_set_pci_config_data(hw, link_status);

	return 0;
}

/**
 *  txgbe_set_lan_id_multi_port_pcie - Set LAN id for PCIe multiple port devices
 *  @hw: pointer to the HW structure
 *
 *  Determines the LAN function id by reading memory-mapped registers
 *  and swaps the port value if requested.
 **/
s32 txgbe_set_lan_id_multi_port_pcie(struct txgbe_hw *hw)
{
	struct txgbe_bus_info *bus = &hw->bus;
	u32 reg;

	reg = rd32(hw, TXGBE_CFG_PORT_ST);
	bus->lan_id = TXGBE_CFG_PORT_ST_LAN_ID(reg);

	/* check for a port swap */
	reg = rd32(hw, TXGBE_MIS_PWR);
	if (TXGBE_MIS_PWR_LAN_ID(reg) == TXGBE_MIS_PWR_LAN_ID_1)
		bus->func = 0;
	else
		bus->func = bus->lan_id;

	return 0;
}

/**
 *  txgbe_stop_adapter - Generic stop Tx/Rx units
 *  @hw: pointer to hardware structure
 *
 *  Sets the adapter_stopped flag within txgbe_hw struct. Clears interrupts,
 *  disables transmit and receive units. The adapter_stopped flag is used by
 *  the shared code and drivers to determine if the adapter is in a stopped
 *  state and should not touch the hardware.
 **/
s32 txgbe_stop_adapter(struct txgbe_hw *hw)
{
	u16 i;

	/* Set the adapter_stopped flag so other driver functions stop touching
	 * the hardware
	 */
	hw->adapter_stopped = true;

	/* Disable the receive unit */
	TCALL(hw, mac.ops.disable_rx);

	/* Set interrupt mask to stop interrupts from being generated */
	txgbe_intr_disable(hw, TXGBE_INTR_ALL);

	/* Clear any pending interrupts, flush previous writes */
	wr32(hw, TXGBE_PX_MISC_IC, 0xffffffff);
	wr32(hw, TXGBE_BME_CTL, 0x3);

	/* Disable the transmit unit.  Each queue must be disabled. */
	for (i = 0; i < hw->mac.max_tx_queues; i++) {
		wr32m(hw, TXGBE_PX_TR_CFG(i),
		      TXGBE_PX_TR_CFG_SWFLSH | TXGBE_PX_TR_CFG_ENABLE,
		      TXGBE_PX_TR_CFG_SWFLSH);
	}

	/* Disable the receive unit by stopping each queue */
	for (i = 0; i < hw->mac.max_rx_queues; i++) {
		wr32m(hw, TXGBE_PX_RR_CFG(i),
		      TXGBE_PX_RR_CFG_RR_EN, 0);
	}

	/* flush all queues disables */
	TXGBE_WRITE_FLUSH(hw);

	/* Prevent the PCI-E bus from hanging by disabling PCI-E master
	 * access and verify no pending requests
	 */
	return txgbe_disable_pcie_master(hw);
}

/**
 *  txgbe_set_rar - Set Rx address register
 *  @hw: pointer to hardware structure
 *  @index: Receive address register to write
 *  @addr: Address to put into receive address register
 *  @pools: VMDq "set" or "pool" index
 *  @enable_addr: set flag that address is active
 *
 *  Puts an ethernet address into a receive address register.
 **/
s32 txgbe_set_rar(struct txgbe_hw *hw, u32 index, u8 *addr, u64 pools,
		  u32 enable_addr)
{
	u32 rar_low, rar_high;
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (index >= rar_entries) {
		ERROR_REPORT2(hw, TXGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", index);
		return TXGBE_ERR_INVALID_ARGUMENT;
	}

	/* select the MAC address */
	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, index);

	/* setup VMDq pool mapping */
	wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, pools & 0xFFFFFFFF);
	wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, pools >> 32);

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
		rar_high |= TXGBE_PSR_MAC_SWC_AD_H_AV;

	wr32(hw, TXGBE_PSR_MAC_SWC_AD_L, rar_low);
	wr32m(hw, TXGBE_PSR_MAC_SWC_AD_H,
	      (TXGBE_PSR_MAC_SWC_AD_H_AD(~0) |
	       TXGBE_PSR_MAC_SWC_AD_H_ADTYPE(~0) |
	       TXGBE_PSR_MAC_SWC_AD_H_AV),
	      rar_high);

	return 0;
}

/**
 *  txgbe_clear_rar - Remove Rx address register
 *  @hw: pointer to hardware structure
 *  @index: Receive address register to write
 *
 *  Clears an ethernet address from a receive address register.
 **/
s32 txgbe_clear_rar(struct txgbe_hw *hw, u32 index)
{
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (index >= rar_entries) {
		ERROR_REPORT2(hw, TXGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", index);
		return TXGBE_ERR_INVALID_ARGUMENT;
	}

	/* Some parts put the VMDq setting in the extra RAH bits,
	 * so save everything except the lower 16 bits that hold part
	 * of the address and the address valid bit.
	 */
	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, index);

	wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, 0);
	wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, 0);

	wr32(hw, TXGBE_PSR_MAC_SWC_AD_L, 0);
	wr32m(hw, TXGBE_PSR_MAC_SWC_AD_H,
	      (TXGBE_PSR_MAC_SWC_AD_H_AD(~0) |
	       TXGBE_PSR_MAC_SWC_AD_H_ADTYPE(~0) |
	       TXGBE_PSR_MAC_SWC_AD_H_AV),
	      0);

	return 0;
}

/**
 *  txgbe_init_rx_addrs - Initializes receive address filters.
 *  @hw: pointer to hardware structure
 *
 *  Places the MAC address in receive address register 0 and clears the rest
 *  of the receive address registers. Clears the multicast table. Assumes
 *  the receiver is in reset when the routine is called.
 **/
s32 txgbe_init_rx_addrs(struct txgbe_hw *hw)
{
	u32 i;
	u32 rar_entries = hw->mac.num_rar_entries;
	u32 psrctl;

	/* If the current mac address is valid, assume it is a software override
	 * to the permanent address.
	 * Otherwise, use the permanent address from the eeprom.
	 */
	if (!is_valid_ether_addr(hw->mac.addr)) {
		/* Get the MAC address from the RAR0 for later reference */
		TCALL(hw, mac.ops.get_mac_addr, hw->mac.addr);

		txgbe_dbg(hw, "Keeping Current RAR0 Addr =%.2X %.2X %.2X %.2X %.2X %.2X\n",
			  hw->mac.addr[0], hw->mac.addr[1],
			  hw->mac.addr[2], hw->mac.addr[3],
			  hw->mac.addr[4], hw->mac.addr[5]);
	} else {
		/* Setup the receive address. */
		txgbe_dbg(hw, "Overriding MAC Address in RAR[0]\n");
		txgbe_dbg(hw, "New MAC Addr =%.2X %.2X %.2X %.2X %.2X %.2X\n",
			  hw->mac.addr[0], hw->mac.addr[1],
			  hw->mac.addr[2], hw->mac.addr[3],
			  hw->mac.addr[4], hw->mac.addr[5]);

		TCALL(hw, mac.ops.set_rar, 0, hw->mac.addr, 0,
		      TXGBE_PSR_MAC_SWC_AD_H_AV);

		/* clear VMDq pool/queue selection for RAR 0 */
		TCALL(hw, mac.ops.clear_vmdq, 0, TXGBE_CLEAR_VMDQ_ALL);
	}
	hw->addr_ctrl.overflow_promisc = 0;

	hw->addr_ctrl.rar_used_count = 1;

	/* Zero out the other receive addresses. */
	txgbe_dbg(hw, "Clearing RAR[1-%d]\n", rar_entries - 1);
	for (i = 1; i < rar_entries; i++) {
		wr32(hw, TXGBE_PSR_MAC_SWC_IDX, i);
		wr32(hw, TXGBE_PSR_MAC_SWC_AD_L, 0);
		wr32(hw, TXGBE_PSR_MAC_SWC_AD_H, 0);
	}

	/* Clear the MTA */
	hw->addr_ctrl.mta_in_use = 0;
	psrctl = rd32(hw, TXGBE_PSR_CTL);
	psrctl &= ~(TXGBE_PSR_CTL_MO | TXGBE_PSR_CTL_MFE);
	psrctl |= hw->mac.mc_filter_type << TXGBE_PSR_CTL_MO_SHIFT;
	wr32(hw, TXGBE_PSR_CTL, psrctl);
	txgbe_dbg(hw, " Clearing MTA\n");
	for (i = 0; i < hw->mac.mcft_size; i++)
		wr32(hw, TXGBE_PSR_MC_TBL(i), 0);

	TCALL(hw, mac.ops.init_uta_tables);

	return 0;
}

/**
 *  txgbe_disable_pcie_master - Disable PCI-express master access
 *  @hw: pointer to hardware structure
 *
 *  Disables PCI-Express master access and verifies there are no pending
 *  requests. TXGBE_ERR_MASTER_REQUESTS_PENDING is returned if master disable
 *  bit hasn't caused the master requests to be disabled, else 0
 *  is returned signifying master requests disabled.
 **/
s32 txgbe_disable_pcie_master(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = container_of(hw, struct txgbe_adapter, hw);
	s32 status = 0;
	u32 i;

	/* Always set this bit to ensure any future transactions are blocked */
	pci_clear_master(adapter->pdev);

	/* Exit if master requests are blocked */
	if (!(rd32(hw, TXGBE_PX_TRANSACTION_PENDING)) ||
	    TXGBE_REMOVED(hw->hw_addr))
		goto out;

	/* Poll for master request bit to clear */
	for (i = 0; i < TXGBE_PCI_MASTER_DISABLE_TIMEOUT; i++) {
		usec_delay(100);
		if (!(rd32(hw, TXGBE_PX_TRANSACTION_PENDING)))
			goto out;
	}

	ERROR_REPORT1(hw, TXGBE_ERROR_POLLING,
		      "PCIe transaction pending bit did not clear.\n");
	status = TXGBE_ERR_MASTER_REQUESTS_PENDING;
out:
	return status;
}

/**
 *  txgbe_get_san_mac_addr - SAN MAC address retrieval from the EEPROM
 *  @hw: pointer to hardware structure
 *  @san_mac_addr: SAN MAC address
 *
 *  Reads the SAN MAC address.
 **/
s32 txgbe_get_san_mac_addr(struct txgbe_hw *hw, u8 *san_mac_addr)
{
	u8 i;

	/* No addresses available in this EEPROM.  It's not an
	 * error though, so just wipe the local address and return.
	 */
	for (i = 0; i < 6; i++)
		san_mac_addr[i] = 0xFF;
	return 0;
}

/**
 *  txgbe_clear_vmdq - Disassociate a VMDq pool index from a rx address
 *  @hw: pointer to hardware struct
 *  @rar: receive address register index to disassociate
 *  @vmdq: VMDq pool index to remove from the rar
 **/
s32 txgbe_clear_vmdq(struct txgbe_hw *hw, u32 rar, u32 __maybe_unused vmdq)
{
	u32 mpsar_lo, mpsar_hi;
	u32 rar_entries = hw->mac.num_rar_entries;

	/* Make sure we are using a valid rar index range */
	if (rar >= rar_entries) {
		ERROR_REPORT2(hw, TXGBE_ERROR_ARGUMENT,
			      "RAR index %d is out of range.\n", rar);
		return TXGBE_ERR_INVALID_ARGUMENT;
	}

	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, rar);
	mpsar_lo = rd32(hw, TXGBE_PSR_MAC_SWC_VM_L);
	mpsar_hi = rd32(hw, TXGBE_PSR_MAC_SWC_VM_H);

	if (TXGBE_REMOVED(hw->hw_addr))
		goto done;

	if (!mpsar_lo && !mpsar_hi)
		goto done;

	/* was that the last pool using this rar? */
	if (mpsar_lo == 0 && mpsar_hi == 0 && rar != 0)
		TCALL(hw, mac.ops.clear_rar, rar);
done:
	return 0;
}

/**
 *  This function should only be involved in the IOV mode.
 *  In IOV mode, Default pool is next pool after the number of
 *  VFs advertized and not 0.
 *  MPSAR table needs to be updated for SAN_MAC RAR [hw->mac.san_mac_rar_index]
 *
 *  txgbe_set_vmdq_san_mac - Associate default VMDq pool index with a rx address
 *  @hw: pointer to hardware struct
 *  @vmdq: VMDq pool index
 **/
s32 txgbe_set_vmdq_san_mac(struct txgbe_hw *hw, u32 vmdq)
{
	u32 rar = hw->mac.san_mac_rar_index;

	wr32(hw, TXGBE_PSR_MAC_SWC_IDX, rar);
	if (vmdq < 32) {
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, 1 << vmdq);
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, 0);
	} else {
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_L, 0);
		wr32(hw, TXGBE_PSR_MAC_SWC_VM_H, 1 << (vmdq - 32));
	}

	return 0;
}

/**
 *  txgbe_init_uta_tables - Initialize the Unicast Table Array
 *  @hw: pointer to hardware structure
 **/
s32 txgbe_init_uta_tables(struct txgbe_hw *hw)
{
	int i;

	txgbe_dbg(hw, " Clearing UTA\n");

	for (i = 0; i < 128; i++)
		wr32(hw, TXGBE_PSR_UC_TBL(i), 0);

	return 0;
}

/* cmd_addr is used for some special command:
 * 1. to be sector address, when implemented erase sector command
 * 2. to be flash address when implemented read, write flash address
 */
u8 fmgr_cmd_op(struct txgbe_hw *hw, u32 cmd, u32 cmd_addr)
{
	u32 cmd_val = 0;
	u32 time_out = 0;

	cmd_val = (cmd << SPI_CLK_CMD_OFFSET) |
		  (SPI_CLK_DIV << SPI_CLK_DIV_OFFSET) | cmd_addr;
	wr32(hw, SPI_H_CMD_REG_ADDR, cmd_val);
	while (1) {
		if (rd32(hw, SPI_H_STA_REG_ADDR) & 0x1)
			break;

		if (time_out == SPI_TIME_OUT_VALUE)
			return 1;

		time_out = time_out + 1;
		usleep_range(10, 20);
	}

	return 0;
}

u32 txgbe_flash_read_dword(struct txgbe_hw *hw, u32 addr)
{
	u8 status = fmgr_cmd_op(hw, SPI_CMD_READ_DWORD, addr);

	if (status)
		return (u32)status;

	return rd32(hw, SPI_H_DAT_REG_ADDR);
}

/**
 *  txgbe_init_thermal_sensor_thresh - Inits thermal sensor thresholds
 *  @hw: pointer to hardware structure
 *
 *  Inits the thermal sensor thresholds according to the NVM map
 *  and save off the threshold and location values into mac.thermal_sensor_data
 **/
s32 txgbe_init_thermal_sensor_thresh(struct txgbe_hw *hw)
{
	s32 status = 0;

	struct txgbe_thermal_sensor_data *data = &hw->mac.thermal_sensor_data;

	memset(data, 0, sizeof(struct txgbe_thermal_sensor_data));

	/* Only support thermal sensors attached to SP physical port 0 */
	if (hw->bus.lan_id)
		return TXGBE_NOT_IMPLEMENTED;

	wr32(hw, TXGBE_TS_CTL, TXGBE_TS_CTL_EVAL_MD);
	wr32(hw, TXGBE_TS_INT_EN,
	     TXGBE_TS_INT_EN_ALARM_INT_EN | TXGBE_TS_INT_EN_DALARM_INT_EN);
	wr32(hw, TXGBE_TS_EN, TXGBE_TS_EN_ENA);

	data->sensor.alarm_thresh = 100;
	wr32(hw, TXGBE_TS_ALARM_THRE, 677);
	data->sensor.dalarm_thresh = 90;
	wr32(hw, TXGBE_TS_DALARM_THRE, 614);

	return status;
}

s32 txgbe_disable_rx(struct txgbe_hw *hw)
{
	u32 pfdtxgswc;
	u32 rxctrl;

	rxctrl = rd32(hw, TXGBE_RDB_PB_CTL);
	if (rxctrl & TXGBE_RDB_PB_CTL_RXEN) {
		pfdtxgswc = rd32(hw, TXGBE_PSR_CTL);
		if (pfdtxgswc & TXGBE_PSR_CTL_SW_EN) {
			pfdtxgswc &= ~TXGBE_PSR_CTL_SW_EN;
			wr32(hw, TXGBE_PSR_CTL, pfdtxgswc);
			hw->mac.set_lben = true;
		} else {
			hw->mac.set_lben = false;
		}
		rxctrl &= ~TXGBE_RDB_PB_CTL_RXEN;
		wr32(hw, TXGBE_RDB_PB_CTL, rxctrl);

		if (!(((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP) ||
		      ((hw->subsystem_device_id & TXGBE_WOL_MASK) == TXGBE_WOL_SUP))) {
			/* disable mac receiver */
			wr32m(hw, TXGBE_MAC_RX_CFG,
			      TXGBE_MAC_RX_CFG_RE, 0);
		}
	}

	return 0;
}

int txgbe_check_flash_load(struct txgbe_hw *hw, u32 check_bit)
{
	u32 i = 0;
	u32 reg = 0;
	int err = 0;
	/* if there's flash existing */
	if (!(rd32(hw, TXGBE_SPI_STATUS) &
	      TXGBE_SPI_STATUS_FLASH_BYPASS)) {
		/* wait hw load flash done */
		for (i = 0; i < TXGBE_MAX_FLASH_LOAD_POLL_TIME; i++) {
			reg = rd32(hw, TXGBE_SPI_ILDR_STATUS);
			if (!(reg & check_bit)) {
				/* done */
				break;
			}
			msleep(200);
		}
		if (i == TXGBE_MAX_FLASH_LOAD_POLL_TIME)
			err = TXGBE_ERR_FLASH_LOADING_FAILED;
	}
	return err;
}

/**
 *  txgbe_init_ops - Inits func ptrs and MAC type
 *  @hw: pointer to hardware structure
 *
 *  Initialize the function pointers and assign the MAC type for sapphire.
 *  Does not touch the hardware.
 **/

s32 txgbe_init_ops(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;

	/* MAC */
	mac->ops.init_hw = txgbe_init_hw;
	mac->ops.get_mac_addr = txgbe_get_mac_addr;
	mac->ops.stop_adapter = txgbe_stop_adapter;
	mac->ops.get_bus_info = txgbe_get_bus_info;
	mac->ops.set_lan_id = txgbe_set_lan_id_multi_port_pcie;
	mac->ops.reset_hw = txgbe_reset_hw;
	mac->ops.start_hw = txgbe_start_hw;
	mac->ops.get_san_mac_addr = txgbe_get_san_mac_addr;

	/* RAR */
	mac->ops.set_rar = txgbe_set_rar;
	mac->ops.clear_rar = txgbe_clear_rar;
	mac->ops.init_rx_addrs = txgbe_init_rx_addrs;
	mac->ops.disable_rx = txgbe_disable_rx;
	mac->ops.set_vmdq_san_mac = txgbe_set_vmdq_san_mac;
	mac->ops.init_uta_tables = txgbe_init_uta_tables;

	mac->num_rar_entries    = TXGBE_SP_RAR_ENTRIES;
	mac->max_rx_queues      = TXGBE_SP_MAX_RX_QUEUES;
	mac->max_tx_queues      = TXGBE_SP_MAX_TX_QUEUES;

	/* Manageability interface */
	mac->ops.init_thermal_sensor_thresh =
				      txgbe_init_thermal_sensor_thresh;

	return 0;
}

int txgbe_reset_misc(struct txgbe_hw *hw)
{
	int i;

	/* receive packets that size > 2048 */
	wr32m(hw, TXGBE_MAC_RX_CFG,
	      TXGBE_MAC_RX_CFG_JE, TXGBE_MAC_RX_CFG_JE);

	/* clear counters on read */
	wr32m(hw, TXGBE_MMC_CONTROL,
	      TXGBE_MMC_CONTROL_RSTONRD, TXGBE_MMC_CONTROL_RSTONRD);

	wr32m(hw, TXGBE_MAC_RX_FLOW_CTRL,
	      TXGBE_MAC_RX_FLOW_CTRL_RFE, TXGBE_MAC_RX_FLOW_CTRL_RFE);

	wr32(hw, TXGBE_MAC_PKT_FLT, TXGBE_MAC_PKT_FLT_PR);

	wr32m(hw, TXGBE_MIS_RST_ST,
	      TXGBE_MIS_RST_ST_RST_INIT, 0x1E00);

	/* errata 4: initialize mng flex tbl and wakeup flex tbl*/
	wr32(hw, TXGBE_PSR_MNG_FLEX_SEL, 0);
	for (i = 0; i < 16; i++) {
		wr32(hw, TXGBE_PSR_MNG_FLEX_DW_L(i), 0);
		wr32(hw, TXGBE_PSR_MNG_FLEX_DW_H(i), 0);
		wr32(hw, TXGBE_PSR_MNG_FLEX_MSK(i), 0);
	}
	wr32(hw, TXGBE_PSR_LAN_FLEX_SEL, 0);
	for (i = 0; i < 16; i++) {
		wr32(hw, TXGBE_PSR_LAN_FLEX_DW_L(i), 0);
		wr32(hw, TXGBE_PSR_LAN_FLEX_DW_H(i), 0);
		wr32(hw, TXGBE_PSR_LAN_FLEX_MSK(i), 0);
	}

	/* set pause frame dst mac addr */
	wr32(hw, TXGBE_RDB_PFCMACDAL, 0xC2000001);
	wr32(hw, TXGBE_RDB_PFCMACDAH, 0x0180);

	txgbe_init_thermal_sensor_thresh(hw);

	return 0;
}

/**
 *  txgbe_reset_hw - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
s32 txgbe_reset_hw(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = container_of(hw, struct txgbe_adapter, hw);
	u32 reset = 0;
	s32 status;
	u32 i;

	u32 reset_status = 0;
	u32 rst_delay = 0;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	status = TCALL(hw, mac.ops.stop_adapter);
	if (status != 0)
		goto reset_hw_out;

	/* Issue global reset to the MAC.  Needs to be SW reset if link is up.
	 * If link reset is used when link is up, it might reset the PHY when
	 * mng is using it.  If link is down or the flag to force full link
	 * reset is set, then perform link reset.
	 */
	if (hw->force_full_reset) {
		rst_delay = (rd32(hw, TXGBE_MIS_RST_ST) &
			     TXGBE_MIS_RST_ST_RST_INIT) >>
			     TXGBE_MIS_RST_ST_RST_INI_SHIFT;
		if (hw->reset_type == TXGBE_SW_RESET) {
			for (i = 0; i < rst_delay + 20; i++) {
				reset_status =
					rd32(hw, TXGBE_MIS_RST_ST);
				if (!(reset_status &
				    TXGBE_MIS_RST_ST_DEV_RST_ST_MASK))
					break;
				msleep(100);
			}

			if (reset_status & TXGBE_MIS_RST_ST_DEV_RST_ST_MASK) {
				status = TXGBE_ERR_RESET_FAILED;
				txgbe_dbg(hw, "Global reset polling failed to complete.\n");
				goto reset_hw_out;
			}
			status = txgbe_check_flash_load(hw, TXGBE_SPI_ILDR_STATUS_SW_RESET);
			if (status != 0)
				goto reset_hw_out;
		} else if (hw->reset_type == TXGBE_GLOBAL_RESET) {
			struct txgbe_adapter *adapter =
				container_of(hw, struct txgbe_adapter, hw);
			msleep(100 * rst_delay + 2000);
			pci_restore_state(adapter->pdev);
			pci_save_state(adapter->pdev);
			pci_wake_from_d3(adapter->pdev, false);
		}
	} else {
		if (hw->bus.lan_id == 0)
			reset = TXGBE_MIS_RST_LAN0_RST;
		else
			reset = TXGBE_MIS_RST_LAN1_RST;

		wr32(hw, TXGBE_MIS_RST,
		     reset | rd32(hw, TXGBE_MIS_RST));
		TXGBE_WRITE_FLUSH(hw);
		usec_delay(10);

		if (hw->bus.lan_id == 0)
			status = txgbe_check_flash_load(hw, TXGBE_SPI_ILDR_STATUS_LAN0_SW_RST);
		else
			status = txgbe_check_flash_load(hw, TXGBE_SPI_ILDR_STATUS_LAN1_SW_RST);

		if (status != 0)
			goto reset_hw_out;
	}

	status = txgbe_reset_misc(hw);
	if (status != 0)
		goto reset_hw_out;

	/* Store the permanent mac address */
	TCALL(hw, mac.ops.get_mac_addr, hw->mac.perm_addr);

	/* Store MAC address from RAR0, clear receive address registers, and
	 * clear the multicast table.  Also reset num_rar_entries to 128,
	 * since we modify this value when programming the SAN MAC address.
	 */
	hw->mac.num_rar_entries = 128;
	TCALL(hw, mac.ops.init_rx_addrs);

	/* Store the permanent SAN mac address */
	TCALL(hw, mac.ops.get_san_mac_addr, hw->mac.san_addr);

	/* Add the SAN MAC address to the RAR only if it's a valid address */
	if (is_valid_ether_addr(hw->mac.san_addr)) {
		TCALL(hw, mac.ops.set_rar, hw->mac.num_rar_entries - 1,
		      hw->mac.san_addr, 0, TXGBE_PSR_MAC_SWC_AD_H_AV);

		/* Save the SAN MAC RAR index */
		hw->mac.san_mac_rar_index = hw->mac.num_rar_entries - 1;

		/* Reserve the last RAR for the SAN MAC address */
		hw->mac.num_rar_entries--;
	}

	pci_set_master(adapter->pdev);

reset_hw_out:
	return status;
}

/**
 *  txgbe_start_hw - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 *
 *  Starts the hardware using the generic start_hw function
 *  and the generation start_hw function.
 *  Then performs revision-specific operations, if any.
 **/
s32 txgbe_start_hw(struct txgbe_hw *hw)
{
	int ret_val = 0;
	u32 i;

	/* Clear the rate limiters */
	for (i = 0; i < hw->mac.max_tx_queues; i++) {
		wr32(hw, TXGBE_TDM_RP_IDX, i);
		wr32(hw, TXGBE_TDM_RP_RATE, 0);
	}
	TXGBE_WRITE_FLUSH(hw);

	/* Clear adapter stopped flag */
	hw->adapter_stopped = false;

	/* We need to run link autotry after the driver loads */
	hw->mac.autotry_restart = true;

	return ret_val;
}
