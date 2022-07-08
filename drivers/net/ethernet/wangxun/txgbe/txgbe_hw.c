// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#include "txgbe_type.h"
#include "txgbe_hw.h"
#include "txgbe.h"

#define TXGBE_SP_MAX_TX_QUEUES  128
#define TXGBE_SP_MAX_RX_QUEUES  128
#define TXGBE_SP_RAR_ENTRIES    128

static s32 txgbe_get_eeprom_semaphore(struct txgbe_hw *hw);
static void txgbe_release_eeprom_semaphore(struct txgbe_hw *hw);

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
 *  txgbe_read_pba_string - Reads part number string from EEPROM
 *  @hw: pointer to hardware structure
 *  @pba_num: stores the part number string from the EEPROM
 *  @pba_num_size: part number string buffer length
 *
 *  Reads the part number string from the EEPROM.
 **/
s32 txgbe_read_pba_string(struct txgbe_hw *hw, u8 *pba_num,
			  u32 pba_num_size)
{
	s32 ret_val;
	u16 data;
	u16 pba_ptr;
	u16 offset;
	u16 length;

	if (!pba_num) {
		txgbe_dbg(hw, "PBA string buffer was null\n");
		return TXGBE_ERR_INVALID_ARGUMENT;
	}

	ret_val = TCALL(hw, eeprom.ops.read,
			hw->eeprom.sw_region_offset + TXGBE_PBANUM0_PTR,
			&data);
	if (ret_val) {
		txgbe_dbg(hw, "NVM Read Error\n");
		return ret_val;
	}

	ret_val = TCALL(hw, eeprom.ops.read,
			hw->eeprom.sw_region_offset + TXGBE_PBANUM1_PTR,
			&pba_ptr);
	if (ret_val) {
		txgbe_dbg(hw, "NVM Read Error\n");
		return ret_val;
	}

	/* if data is not ptr guard the PBA must be in legacy format which
	 * means pba_ptr is actually our second data word for the PBA number
	 * and we can decode it into an ascii string
	 */
	if (data != TXGBE_PBANUM_PTR_GUARD) {
		txgbe_dbg(hw, "NVM PBA number is not stored as string\n");

		/* we will need 11 characters to store the PBA */
		if (pba_num_size < 11) {
			txgbe_dbg(hw, "PBA string buffer too small\n");
			return TXGBE_ERR_NO_SPACE;
		}

		/* extract hex string from data and pba_ptr */
		pba_num[0] = (data >> 12) & 0xF;
		pba_num[1] = (data >> 8) & 0xF;
		pba_num[2] = (data >> 4) & 0xF;
		pba_num[3] = data & 0xF;
		pba_num[4] = (pba_ptr >> 12) & 0xF;
		pba_num[5] = (pba_ptr >> 8) & 0xF;
		pba_num[6] = '-';
		pba_num[7] = 0;
		pba_num[8] = (pba_ptr >> 4) & 0xF;
		pba_num[9] = pba_ptr & 0xF;

		/* put a null character on the end of our string */
		pba_num[10] = '\0';

		/* switch all the data but the '-' to hex char */
		for (offset = 0; offset < 10; offset++) {
			if (pba_num[offset] < 0xA)
				pba_num[offset] += '0';
			else if (pba_num[offset] < 0x10)
				pba_num[offset] += 'A' - 0xA;
		}

		return 0;
	}

	ret_val = TCALL(hw, eeprom.ops.read, pba_ptr, &length);
	if (ret_val) {
		txgbe_dbg(hw, "NVM Read Error\n");
		return ret_val;
	}

	if (length == 0xFFFF || length == 0) {
		txgbe_dbg(hw, "NVM PBA number section invalid length\n");
		return TXGBE_ERR_PBA_SECTION;
	}

	/* check if pba_num buffer is big enough */
	if (pba_num_size  < (((u32)length * 2) - 1)) {
		txgbe_dbg(hw, "PBA string buffer too small\n");
		return TXGBE_ERR_NO_SPACE;
	}

	/* trim pba length from start of string */
	pba_ptr++;
	length--;

	for (offset = 0; offset < length; offset++) {
		ret_val = TCALL(hw, eeprom.ops.read, pba_ptr + offset, &data);
		if (ret_val) {
			txgbe_dbg(hw, "NVM Read Error\n");
			return ret_val;
		}
		pba_num[offset * 2] = (u8)(data >> 8);
		pba_num[(offset * 2) + 1] = (u8)(data & 0xFF);
	}
	pba_num[offset * 2] = '\0';

	return 0;
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
 *  txgbe_get_eeprom_semaphore - Get hardware semaphore
 *  @hw: pointer to hardware structure
 *
 *  Sets the hardware semaphores so EEPROM access can occur for bit-bang method
 **/
static s32 txgbe_get_eeprom_semaphore(struct txgbe_hw *hw)
{
	s32 status = TXGBE_ERR_EEPROM;
	u32 timeout = 2000;
	u32 i;
	u32 swsm;

	/* Get SMBI software semaphore between device drivers first */
	for (i = 0; i < timeout; i++) {
		/* If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = rd32(hw, TXGBE_MIS_SWSM);
		if (!(swsm & TXGBE_MIS_SWSM_SMBI)) {
			status = 0;
			break;
		}
		usec_delay(50);
	}

	if (i == timeout) {
		txgbe_dbg(hw, "Driver can't access the Eeprom - SMBI Semaphore not granted.\n");

		/* this release is particularly important because our attempts
		 * above to get the semaphore may have succeeded, and if there
		 * was a timeout, we should unconditionally clear the semaphore
		 * bits to free the driver to make progress
		 */
		txgbe_release_eeprom_semaphore(hw);

		usec_delay(50);
		/* one last try
		 * If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = rd32(hw, TXGBE_MIS_SWSM);
		if (!(swsm & TXGBE_MIS_SWSM_SMBI))
			status = 0;
	}

	/* Now get the semaphore between SW/FW through the SWESMBI bit */
	if (status == 0) {
		for (i = 0; i < timeout; i++) {
			if (txgbe_check_mng_access(hw)) {
			/* Set the SW EEPROM semaphore bit to request access */
				wr32m(hw, TXGBE_MNG_SW_SM,
				      TXGBE_MNG_SW_SM_SM, TXGBE_MNG_SW_SM_SM);

				/* If we set the bit successfully then we got
				 * semaphore.
				 */
				swsm = rd32(hw, TXGBE_MNG_SW_SM);
				if (swsm & TXGBE_MNG_SW_SM_SM)
					break;
			}
			usec_delay(50);
		}

		/* Release semaphores and return error if SW EEPROM semaphore
		 * was not granted because we don't have access to the EEPROM
		 */
		if (i >= timeout) {
			ERROR_REPORT1(hw, TXGBE_ERROR_POLLING,
				      "SWESMBI Software EEPROM semaphore not granted.\n");
			txgbe_release_eeprom_semaphore(hw);
			status = TXGBE_ERR_EEPROM;
		}
	} else {
		ERROR_REPORT1(hw, TXGBE_ERROR_POLLING,
			      "Software semaphore SMBI between device drivers not granted.\n");
	}

	return status;
}

/**
 *  txgbe_release_eeprom_semaphore - Release hardware semaphore
 *  @hw: pointer to hardware structure
 *
 *  This function clears hardware semaphore bits.
 **/
static void txgbe_release_eeprom_semaphore(struct txgbe_hw *hw)
{
	if (txgbe_check_mng_access(hw)) {
		wr32m(hw, TXGBE_MNG_SW_SM, TXGBE_MNG_SW_SM_SM, 0);
		wr32m(hw, TXGBE_MIS_SWSM, TXGBE_MIS_SWSM_SMBI, 0);
		TXGBE_WRITE_FLUSH(hw);
	}
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
 *  txgbe_acquire_swfw_sync - Acquire SWFW semaphore
 *  @hw: pointer to hardware structure
 *  @mask: Mask to specify which semaphore to acquire
 *
 *  Acquires the SWFW semaphore through the GSSR register for the specified
 *  function (CSR, PHY0, PHY1, EEPROM, Flash)
 **/
s32 txgbe_acquire_swfw_sync(struct txgbe_hw *hw, u32 mask)
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
		if (txgbe_get_eeprom_semaphore(hw))
			return TXGBE_ERR_SWFW_SYNC;

		if (txgbe_check_mng_access(hw)) {
			gssr = rd32(hw, TXGBE_MNG_SWFW_SYNC);
			if (gssr & (fwmask | swmask)) {
				/* Resource is currently in use by FW or SW */
				txgbe_release_eeprom_semaphore(hw);
				msec_delay(5);
			} else {
				gssr |= swmask;
				wr32(hw, TXGBE_MNG_SWFW_SYNC, gssr);
				txgbe_release_eeprom_semaphore(hw);
				return 0;
			}
		}
	}

	/* If time expired clear the bits holding the lock and retry */
	if (gssr & (fwmask | swmask))
		txgbe_release_swfw_sync(hw, gssr & (fwmask | swmask));

	msec_delay(5);
	return TXGBE_ERR_SWFW_SYNC;
}

/**
 *  txgbe_release_swfw_sync - Release SWFW semaphore
 *  @hw: pointer to hardware structure
 *  @mask: Mask to specify which semaphore to release
 *
 *  Releases the SWFW semaphore through the GSSR register for the specified
 *  function (CSR, PHY0, PHY1, EEPROM, Flash)
 **/
s32 txgbe_release_swfw_sync(struct txgbe_hw *hw, u32 mask)
{
	txgbe_get_eeprom_semaphore(hw);
	if (txgbe_check_mng_access(hw))
		wr32m(hw, TXGBE_MNG_SWFW_SYNC, mask, 0);

	txgbe_release_eeprom_semaphore(hw);

	return 0;
}

/**
 *  txgbe_get_san_mac_addr_offset - Get SAN MAC address offset from the EEPROM
 *  @hw: pointer to hardware structure
 *  @san_mac_offset: SAN MAC address offset
 *
 *  This function will read the EEPROM location for the SAN MAC address
 *  pointer, and returns the value at that location.  This is used in both
 *  get and set mac_addr routines.
 **/
static s32 txgbe_get_san_mac_addr_offset(struct txgbe_hw *hw,
					 u16 *san_mac_offset)
{
	s32 ret_val;

	/* First read the EEPROM pointer to see if the MAC addresses are
	 * available.
	 */
	ret_val = TCALL(hw, eeprom.ops.read,
			hw->eeprom.sw_region_offset + TXGBE_SAN_MAC_ADDR_PTR,
			san_mac_offset);
	if (ret_val) {
		ERROR_REPORT2(hw, TXGBE_ERROR_INVALID_STATE,
			      "eeprom at offset %d failed",
			      TXGBE_SAN_MAC_ADDR_PTR);
	}

	return ret_val;
}

/**
 *  txgbe_get_san_mac_addr - SAN MAC address retrieval from the EEPROM
 *  @hw: pointer to hardware structure
 *  @san_mac_addr: SAN MAC address
 *
 *  Reads the SAN MAC address from the EEPROM.
 **/
s32 txgbe_get_san_mac_addr(struct txgbe_hw *hw, u8 *san_mac_addr)
{
	u16 san_mac_data, san_mac_offset;
	u8 i;
	s32 ret_val;

	/* First read the EEPROM pointer to see if the MAC addresses are
	 * available.  If they're not, no point in calling set_lan_id() here.
	 */
	ret_val = txgbe_get_san_mac_addr_offset(hw, &san_mac_offset);
	if (ret_val || san_mac_offset == 0 || san_mac_offset == 0xFFFF)
		goto san_mac_addr_out;

	/* apply the port offset to the address offset */
	(hw->bus.func) ? (san_mac_offset += TXGBE_SAN_MAC_ADDR_PORT1_OFFSET) :
			 (san_mac_offset += TXGBE_SAN_MAC_ADDR_PORT0_OFFSET);
	for (i = 0; i < 3; i++) {
		ret_val = TCALL(hw, eeprom.ops.read, san_mac_offset,
				&san_mac_data);
		if (ret_val) {
			ERROR_REPORT2(hw, TXGBE_ERROR_INVALID_STATE,
				      "eeprom read at offset %d failed",
				      san_mac_offset);
			goto san_mac_addr_out;
		}
		san_mac_addr[i * 2] = (u8)(san_mac_data);
		san_mac_addr[i * 2 + 1] = (u8)(san_mac_data >> 8);
		san_mac_offset++;
	}
	return 0;

san_mac_addr_out:
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

/**
 *  Get alternative WWNN/WWPN prefix from the EEPROM
 *  @hw: pointer to hardware structure
 *  @wwnn_prefix: the alternative WWNN prefix
 *  @wwpn_prefix: the alternative WWPN prefix
 *
 *  This function will read the EEPROM from the alternative SAN MAC address
 *  block to check the support for the alternative WWNN/WWPN prefix support.
 **/
s32 txgbe_get_wwn_prefix(struct txgbe_hw *hw, u16 *wwnn_prefix,
			 u16 *wwpn_prefix)
{
	u16 offset, caps;
	u16 alt_san_mac_blk_offset;

	/* clear output first */
	*wwnn_prefix = 0xFFFF;
	*wwpn_prefix = 0xFFFF;

	/* check if alternative SAN MAC is supported */
	offset = hw->eeprom.sw_region_offset + TXGBE_ALT_SAN_MAC_ADDR_BLK_PTR;
	if (TCALL(hw, eeprom.ops.read, offset, &alt_san_mac_blk_offset))
		goto wwn_prefix_err;

	if (alt_san_mac_blk_offset == 0 ||
	    alt_san_mac_blk_offset == 0xFFFF)
		goto wwn_prefix_out;

	/* check capability in alternative san mac address block */
	offset = alt_san_mac_blk_offset + TXGBE_ALT_SAN_MAC_ADDR_CAPS_OFFSET;
	if (TCALL(hw, eeprom.ops.read, offset, &caps))
		goto wwn_prefix_err;
	if (!(caps & TXGBE_ALT_SAN_MAC_ADDR_CAPS_ALTWWN))
		goto wwn_prefix_out;

	/* get the corresponding prefix for WWNN/WWPN */
	offset = alt_san_mac_blk_offset + TXGBE_ALT_SAN_MAC_ADDR_WWNN_OFFSET;
	if (TCALL(hw, eeprom.ops.read, offset, wwnn_prefix)) {
		ERROR_REPORT2(hw, TXGBE_ERROR_INVALID_STATE,
			      "eeprom read at offset %d failed", offset);
	}

	offset = alt_san_mac_blk_offset + TXGBE_ALT_SAN_MAC_ADDR_WWPN_OFFSET;
	if (TCALL(hw, eeprom.ops.read, offset, wwpn_prefix))
		goto wwn_prefix_err;

wwn_prefix_err:
	ERROR_REPORT2(hw, TXGBE_ERROR_INVALID_STATE,
		      "eeprom read at offset %d failed", offset);
wwn_prefix_out:
	return 0;
}

/**
 *  txgbe_calculate_checksum - Calculate checksum for buffer
 *  @buffer: pointer to EEPROM
 *  @length: size of EEPROM to calculate a checksum for
 *  Calculates the checksum for some buffer on a specified length.  The
 *  checksum calculated is returned.
 **/
u8 txgbe_calculate_checksum(u8 *buffer, u32 length)
{
	u32 i;
	u8 sum = 0;

	if (!buffer)
		return 0;

	for (i = 0; i < length; i++)
		sum += buffer[i];

	return (u8)(0 - sum);
}

/**
 *  txgbe_host_interface_command - Issue command to manageability block
 *  @hw: pointer to the HW structure
 *  @buffer: contains the command to write and where the return status will
 *   be placed
 *  @length: length of buffer, must be multiple of 4 bytes
 *  @timeout: time in ms to wait for command completion
 *  @return_data: read and return data from the buffer (true) or not (false)
 *   Needed because FW structures are big endian and decoding of
 *   these fields can be 8 bit or 16 bit based on command. Decoding
 *   is not easily understood without making a table of commands.
 *   So we will leave this up to the caller to read back the data
 *   in these cases.
 *
 *  Communicates with the manageability block.  On success return 0
 *  else return TXGBE_ERR_HOST_INTERFACE_COMMAND.
 **/
s32 txgbe_host_interface_command(struct txgbe_hw *hw, u32 *buffer,
				 u32 length, u32 timeout, bool return_data)
{
	u32 hicr, i, bi;
	u32 hdr_size = sizeof(struct txgbe_hic_hdr);
	u16 buf_len;
	u32 dword_len;
	s32 status = 0;
	u32 buf[64] = {};

	if (length == 0 || length > TXGBE_HI_MAX_BLOCK_BYTE_LENGTH) {
		txgbe_dbg(hw, "Buffer length failure buffersize=%d.\n", length);
		return TXGBE_ERR_HOST_INTERFACE_COMMAND;
	}

	if (TCALL(hw, mac.ops.acquire_swfw_sync, TXGBE_MNG_SWFW_SYNC_SW_MB) != 0)
		return TXGBE_ERR_SWFW_SYNC;

	/* Calculate length in DWORDs. We must be DWORD aligned */
	if ((length % (sizeof(u32))) != 0) {
		txgbe_dbg(hw, "Buffer length failure, not aligned to dword");
		status = TXGBE_ERR_INVALID_ARGUMENT;
		goto rel_out;
	}

	dword_len = length >> 2;

	/* The device driver writes the relevant command block
	 * into the ram area.
	 */
	for (i = 0; i < dword_len; i++) {
		if (txgbe_check_mng_access(hw)) {
			wr32a(hw, TXGBE_MNG_MBOX, i, (__force u32)cpu_to_le32(buffer[i]));
			/* write flush */
			buf[i] = rd32a(hw, TXGBE_MNG_MBOX, i);
		} else {
			status = TXGBE_ERR_MNG_ACCESS_FAILED;
			goto rel_out;
		}
	}
	/* Setting this bit tells the ARC that a new command is pending. */
	if (txgbe_check_mng_access(hw)) {
		wr32m(hw, TXGBE_MNG_MBOX_CTL,
		      TXGBE_MNG_MBOX_CTL_SWRDY, TXGBE_MNG_MBOX_CTL_SWRDY);
	} else {
		status = TXGBE_ERR_MNG_ACCESS_FAILED;
		goto rel_out;
	}

	for (i = 0; i < timeout; i++) {
		if (txgbe_check_mng_access(hw)) {
			hicr = rd32(hw, TXGBE_MNG_MBOX_CTL);
			if ((hicr & TXGBE_MNG_MBOX_CTL_FWRDY))
				break;
		}
		msec_delay(1);
	}

	buf[0] = rd32(hw, TXGBE_MNG_MBOX);
	if ((buf[0] & 0xff0000) >> 16 == 0x80) {
		txgbe_dbg(hw, "It's unknown cmd.\n");
		status = TXGBE_ERR_MNG_ACCESS_FAILED;
		goto rel_out;
	}
	/* Check command completion */
	if (timeout != 0 && i == timeout) {
		ERROR_REPORT1(hw, TXGBE_ERROR_CAUTION,
			      "Command has failed with no status valid.\n");

		ERROR_REPORT1(hw, TXGBE_ERROR_CAUTION, "write value:\n");
		for (i = 0; i < dword_len; i++)
			ERROR_REPORT1(hw, TXGBE_ERROR_CAUTION, "%x ", buffer[i]);
		ERROR_REPORT1(hw, TXGBE_ERROR_CAUTION, "read value:\n");
		for (i = 0; i < dword_len; i++)
			ERROR_REPORT1(hw, TXGBE_ERROR_CAUTION, "%x ", buf[i]);
		if ((buffer[0] & 0xff) != (~buf[0] >> 24)) {
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
			goto rel_out;
		}
	}

	if (!return_data)
		goto rel_out;

	/* Calculate length in DWORDs */
	dword_len = hdr_size >> 2;

	/* first pull in the header so we know the buffer length */
	for (bi = 0; bi < dword_len; bi++) {
		if (txgbe_check_mng_access(hw)) {
			buffer[bi] = rd32a(hw, TXGBE_MNG_MBOX, bi);
			le32_to_cpus(&buffer[bi]);
		} else {
			status = TXGBE_ERR_MNG_ACCESS_FAILED;
			goto rel_out;
		}
	}

	/* If there is any thing in data position pull it in */
	buf_len = ((struct txgbe_hic_hdr *)buffer)->buf_len;
	if (buf_len == 0)
		goto rel_out;

	if (length < buf_len + hdr_size) {
		txgbe_dbg(hw, "Buffer not large enough for reply message.\n");
		status = TXGBE_ERR_HOST_INTERFACE_COMMAND;
		goto rel_out;
	}

	/* Calculate length in DWORDs, add 3 for odd lengths */
	dword_len = (buf_len + 3) >> 2;

	/* Pull in the rest of the buffer (bi is where we left off) */
	for (; bi <= dword_len; bi++) {
		if (txgbe_check_mng_access(hw)) {
			buffer[bi] = rd32a(hw, TXGBE_MNG_MBOX, bi);
			le32_to_cpus(&buffer[bi]);
		} else {
			status = TXGBE_ERR_MNG_ACCESS_FAILED;
			goto rel_out;
		}
	}

rel_out:
	TCALL(hw, mac.ops.release_swfw_sync, TXGBE_MNG_SWFW_SYNC_SW_MB);
	return status;
}

/**
 *  txgbe_set_fw_drv_ver - Sends driver version to firmware
 *  @hw: pointer to the HW structure
 *  @maj: driver version major number
 *  @min: driver version minor number
 *  @build: driver version build number
 *  @sub: driver version sub build number
 *
 *  Sends driver version number to firmware through the manageability
 *  block.  On success return 0
 *  else returns TXGBE_ERR_SWFW_SYNC when encountering an error acquiring
 *  semaphore or TXGBE_ERR_HOST_INTERFACE_COMMAND when command fails.
 **/
s32 txgbe_set_fw_drv_ver(struct txgbe_hw *hw, u8 maj, u8 min,
			 u8 build, u8 sub)
{
	struct txgbe_hic_drv_info fw_cmd;
	int i;
	s32 ret_val = 0;

	fw_cmd.hdr.cmd = FW_CEM_CMD_DRIVER_INFO;
	fw_cmd.hdr.buf_len = FW_CEM_CMD_DRIVER_INFO_LEN;
	fw_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	fw_cmd.port_num = (u8)hw->bus.func;
	fw_cmd.ver_maj = maj;
	fw_cmd.ver_min = min;
	fw_cmd.ver_build = build;
	fw_cmd.ver_sub = sub;
	fw_cmd.hdr.checksum = 0;
	fw_cmd.hdr.checksum = txgbe_calculate_checksum((u8 *)&fw_cmd,
						       (FW_CEM_HDR_LEN + fw_cmd.hdr.buf_len));
	fw_cmd.pad = 0;
	fw_cmd.pad2 = 0;

	for (i = 0; i <= FW_CEM_MAX_RETRIES; i++) {
		ret_val = txgbe_host_interface_command(hw, (u32 *)&fw_cmd,
						       sizeof(fw_cmd),
						       TXGBE_HI_COMMAND_TIMEOUT,
						       true);
		if (ret_val != 0)
			continue;

		if (fw_cmd.hdr.cmd_or_resp.ret_status ==
		    FW_CEM_RESP_STATUS_SUCCESS)
			ret_val = 0;
		else
			ret_val = TXGBE_ERR_HOST_INTERFACE_COMMAND;

		break;
	}

	return ret_val;
}

/**
 *  txgbe_reset_hostif - send reset cmd to fw
 *  @hw: pointer to hardware structure
 *
 *  Sends reset cmd to firmware through the manageability
 *  block.  On success return 0
 *  else returns TXGBE_ERR_SWFW_SYNC when encountering an error acquiring
 *  semaphore or TXGBE_ERR_HOST_INTERFACE_COMMAND when command fails.
 **/
s32 txgbe_reset_hostif(struct txgbe_hw *hw)
{
	struct txgbe_hic_reset reset_cmd;
	int i;
	s32 status = 0;

	reset_cmd.hdr.cmd = FW_RESET_CMD;
	reset_cmd.hdr.buf_len = FW_RESET_LEN;
	reset_cmd.hdr.cmd_or_resp.cmd_resv = FW_CEM_CMD_RESERVED;
	reset_cmd.lan_id = hw->bus.lan_id;
	reset_cmd.reset_type = (u16)hw->reset_type;
	reset_cmd.hdr.checksum = 0;
	reset_cmd.hdr.checksum = txgbe_calculate_checksum((u8 *)&reset_cmd,
							  (FW_CEM_HDR_LEN +
							   reset_cmd.hdr.buf_len));

	for (i = 0; i <= FW_CEM_MAX_RETRIES; i++) {
		status = txgbe_host_interface_command(hw, (u32 *)&reset_cmd,
						      sizeof(reset_cmd),
						      TXGBE_HI_COMMAND_TIMEOUT,
						      true);
		if (status != 0)
			continue;

		if (reset_cmd.hdr.cmd_or_resp.ret_status ==
		    FW_CEM_RESP_STATUS_SUCCESS)
			status = 0;
		else
			status = TXGBE_ERR_HOST_INTERFACE_COMMAND;

		break;
	}

	return status;
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

/**
 * txgbe_mng_present - returns true when management capability is present
 * @hw: pointer to hardware structure
 */
bool txgbe_mng_present(struct txgbe_hw *hw)
{
	u32 fwsm;

	fwsm = rd32(hw, TXGBE_MIS_ST);
	return fwsm & TXGBE_MIS_ST_MNG_INIT_DN;
}

bool txgbe_check_mng_access(struct txgbe_hw *hw)
{
	bool ret = false;
	u32 rst_delay;
	u32 i;

	struct txgbe_adapter *adapter = container_of(hw, struct txgbe_adapter, hw);

	if (!txgbe_mng_present(hw))
		return false;
	if (adapter->hw.revision_id != TXGBE_SP_MPW)
		return true;
	if (!(adapter->flags2 & TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED))
		return true;

	rst_delay = (rd32(&adapter->hw, TXGBE_MIS_RST_ST) &
		     TXGBE_MIS_RST_ST_RST_INIT) >>
		     TXGBE_MIS_RST_ST_RST_INI_SHIFT;
	for (i = 0; i < rst_delay + 2; i++) {
		if (!(adapter->flags2 & TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED)) {
			ret = true;
			break;
		}
		msleep(100);
	}
	return ret;
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
	struct txgbe_eeprom_info *eeprom = &hw->eeprom;

	/* MAC */
	mac->ops.init_hw = txgbe_init_hw;
	mac->ops.get_mac_addr = txgbe_get_mac_addr;
	mac->ops.stop_adapter = txgbe_stop_adapter;
	mac->ops.get_bus_info = txgbe_get_bus_info;
	mac->ops.set_lan_id = txgbe_set_lan_id_multi_port_pcie;
	mac->ops.acquire_swfw_sync = txgbe_acquire_swfw_sync;
	mac->ops.release_swfw_sync = txgbe_release_swfw_sync;
	mac->ops.reset_hw = txgbe_reset_hw;
	mac->ops.start_hw = txgbe_start_hw;
	mac->ops.get_san_mac_addr = txgbe_get_san_mac_addr;
	mac->ops.get_wwn_prefix = txgbe_get_wwn_prefix;

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

	/* EEPROM */
	eeprom->ops.init_params = txgbe_init_eeprom_params;
	eeprom->ops.calc_checksum = txgbe_calc_eeprom_checksum;
	eeprom->ops.read = txgbe_read_ee_hostif;
	eeprom->ops.read_buffer = txgbe_read_ee_hostif_buffer;
	eeprom->ops.validate_checksum = txgbe_validate_eeprom_checksum;

	/* Manageability interface */
	mac->ops.set_fw_drv_ver = txgbe_set_fw_drv_ver;

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
			/* errata 7 */
			if (txgbe_mng_present(hw) &&
			    hw->revision_id == TXGBE_SP_MPW) {
				struct txgbe_adapter *adapter =
					container_of(hw, struct txgbe_adapter, hw);
				adapter->flags2 &=
					~TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED;
			}
		} else if (hw->reset_type == TXGBE_GLOBAL_RESET) {
			struct txgbe_adapter *adapter =
				container_of(hw, struct txgbe_adapter, hw);
			msleep(100 * rst_delay + 2000);
			pci_restore_state(adapter->pdev);
			pci_save_state(adapter->pdev);
			pci_wake_from_d3(adapter->pdev, false);
		}
	} else {
		if (txgbe_mng_present(hw)) {
			if (!(((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP) ||
			      ((hw->subsystem_device_id & TXGBE_WOL_MASK) == TXGBE_WOL_SUP))) {
				txgbe_reset_hostif(hw);
			}
		} else {
			if (hw->bus.lan_id == 0)
				reset = TXGBE_MIS_RST_LAN0_RST;
			else
				reset = TXGBE_MIS_RST_LAN1_RST;

			wr32(hw, TXGBE_MIS_RST,
			     reset | rd32(hw, TXGBE_MIS_RST));
			TXGBE_WRITE_FLUSH(hw);
		}
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

	/* Store the alternative WWNN/WWPN prefix */
	TCALL(hw, mac.ops.get_wwn_prefix, &hw->mac.wwnn_prefix,
	      &hw->mac.wwpn_prefix);

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

/**
 *  txgbe_init_eeprom_params - Initialize EEPROM params
 *  @hw: pointer to hardware structure
 *
 *  Initializes the EEPROM parameters txgbe_eeprom_info within the
 *  txgbe_hw struct in order to set up EEPROM access.
 **/
s32 txgbe_init_eeprom_params(struct txgbe_hw *hw)
{
	struct txgbe_eeprom_info *eeprom = &hw->eeprom;
	u16 eeprom_size;
	s32 status = 0;
	u16 data;

	if (eeprom->type == txgbe_eeprom_uninitialized) {
		eeprom->semaphore_delay = 10;
		eeprom->type = txgbe_eeprom_none;

		if (!(rd32(hw, TXGBE_SPI_STATUS) &
		      TXGBE_SPI_STATUS_FLASH_BYPASS)) {
			eeprom->type = txgbe_flash;

			eeprom_size = 4096;
			eeprom->word_size = eeprom_size >> 1;

			txgbe_dbg(hw, "Eeprom params: type = %d, size = %d\n",
				  eeprom->type, eeprom->word_size);
		}
	}

	status = TCALL(hw, eeprom.ops.read, TXGBE_SW_REGION_PTR, &data);
	if (status) {
		txgbe_dbg(hw, "NVM Read Error\n");
		return status;
	}
	eeprom->sw_region_offset = data >> 1;

	return status;
}

/**
 *  txgbe_read_ee_hostif - Read EEPROM word using a host interface cmd
 *  assuming that the semaphore is already obtained.
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @data: word read from the EEPROM
 *
 *  Reads a 16 bit word from the EEPROM using the hostif.
 **/
s32 txgbe_read_ee_hostif_data(struct txgbe_hw *hw, u16 offset,
			      u16 *data)
{
	s32 status;
	struct txgbe_hic_read_shadow_ram buffer;

	buffer.hdr.req.cmd = FW_READ_SHADOW_RAM_CMD;
	buffer.hdr.req.buf_lenh = 0;
	buffer.hdr.req.buf_lenl = FW_READ_SHADOW_RAM_LEN;
	buffer.hdr.req.checksum = FW_DEFAULT_CHECKSUM;

	/* convert offset from words to bytes */
	buffer.address = (__force u32)cpu_to_be32(offset * 2);
	/* one word */
	buffer.length = (__force u16)cpu_to_be16(sizeof(u16));

	status = txgbe_host_interface_command(hw, (u32 *)&buffer,
					      sizeof(buffer),
					      TXGBE_HI_COMMAND_TIMEOUT, false);

	if (status)
		return status;
	if (txgbe_check_mng_access(hw)) {
		*data = (u16)rd32a(hw, TXGBE_MNG_MBOX, FW_NVM_DATA_OFFSET);
	} else {
		status = TXGBE_ERR_MNG_ACCESS_FAILED;
		return status;
	}

	return 0;
}

/**
 *  txgbe_read_ee_hostif - Read EEPROM word using a host interface cmd
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @data: word read from the EEPROM
 *
 *  Reads a 16 bit word from the EEPROM using the hostif.
 **/
s32 txgbe_read_ee_hostif(struct txgbe_hw *hw, u16 offset,
			 u16 *data)
{
	s32 status = 0;

	if (TCALL(hw, mac.ops.acquire_swfw_sync,
		  TXGBE_MNG_SWFW_SYNC_SW_FLASH) == 0) {
		status = txgbe_read_ee_hostif_data(hw, offset, data);
		TCALL(hw, mac.ops.release_swfw_sync,
		      TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	} else {
		status = TXGBE_ERR_SWFW_SYNC;
	}

	return status;
}

/**
 *  txgbe_read_ee_hostif_buffer- Read EEPROM word(s) using hostif
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @words: number of words
 *  @data: word(s) read from the EEPROM
 *
 *  Reads a 16 bit word(s) from the EEPROM using the hostif.
 **/
s32 txgbe_read_ee_hostif_buffer(struct txgbe_hw *hw,
				u16 offset, u16 words, u16 *data)
{
	struct txgbe_hic_read_shadow_ram buffer;
	u32 current_word = 0;
	u16 words_to_read;
	s32 status;
	u32 i;
	u32 value = 0;

	/* Take semaphore for the entire operation. */
	status = TCALL(hw, mac.ops.acquire_swfw_sync,
		       TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	if (status) {
		txgbe_dbg(hw, "EEPROM read buffer - semaphore failed\n");
		return status;
	}
	while (words) {
		if (words > FW_MAX_READ_BUFFER_SIZE / 2)
			words_to_read = FW_MAX_READ_BUFFER_SIZE / 2;
		else
			words_to_read = words;

		buffer.hdr.req.cmd = FW_READ_SHADOW_RAM_CMD;
		buffer.hdr.req.buf_lenh = 0;
		buffer.hdr.req.buf_lenl = FW_READ_SHADOW_RAM_LEN;
		buffer.hdr.req.checksum = FW_DEFAULT_CHECKSUM;

		/* convert offset from words to bytes */
		buffer.address = (__force u32)cpu_to_be32((offset + current_word) * 2);
		buffer.length = (__force u16)cpu_to_be16(words_to_read * 2);

		status = txgbe_host_interface_command(hw, (u32 *)&buffer,
						      sizeof(buffer),
						      TXGBE_HI_COMMAND_TIMEOUT,
						      false);

		if (status) {
			txgbe_dbg(hw, "Host interface command failed\n");
			goto out;
		}

		for (i = 0; i < words_to_read; i++) {
			u32 reg = TXGBE_MNG_MBOX + (FW_NVM_DATA_OFFSET << 2) +
				  2 * i;
			if (txgbe_check_mng_access(hw)) {
				value = rd32(hw, reg);
			} else {
				status = TXGBE_ERR_MNG_ACCESS_FAILED;
				return status;
			}
			data[current_word] = (u16)(value & 0xffff);
			current_word++;
			i++;
			if (i < words_to_read) {
				value >>= 16;
				data[current_word] = (u16)(value & 0xffff);
				current_word++;
			}
		}
		words -= words_to_read;
	}

out:
	TCALL(hw, mac.ops.release_swfw_sync, TXGBE_MNG_SWFW_SYNC_SW_FLASH);
	return status;
}

/**
 *  txgbe_calc_eeprom_checksum - Calculates and returns the checksum
 *  @hw: pointer to hardware structure
 *
 *  Returns a negative error code on error, or the 16-bit checksum
 **/
s32 txgbe_calc_eeprom_checksum(struct txgbe_hw *hw)
{
	u16 *buffer = NULL;
	u32 buffer_size = 0;

	u16 *eeprom_ptrs = NULL;
	u16 *local_buffer;
	s32 status;
	u16 checksum = 0;
	u16 i;

	TCALL(hw, eeprom.ops.init_params);

	if (!buffer) {
		eeprom_ptrs = vmalloc(TXGBE_EEPROM_LAST_WORD * sizeof(u16));
		if (!eeprom_ptrs)
			return TXGBE_ERR_NO_SPACE;
		/* Read pointer area */
		status = txgbe_read_ee_hostif_buffer(hw, 0,
						     TXGBE_EEPROM_LAST_WORD,
						     eeprom_ptrs);
		if (status) {
			txgbe_dbg(hw, "Failed to read EEPROM image\n");
			return status;
		}
		local_buffer = eeprom_ptrs;
	} else {
		if (buffer_size < TXGBE_EEPROM_LAST_WORD)
			return TXGBE_ERR_PARAM;
		local_buffer = buffer;
	}

	for (i = 0; i < TXGBE_EEPROM_LAST_WORD; i++)
		if (i != hw->eeprom.sw_region_offset + TXGBE_EEPROM_CHECKSUM)
			checksum += local_buffer[i];

	checksum = (u16)TXGBE_EEPROM_SUM - checksum;
	if (eeprom_ptrs)
		vfree(eeprom_ptrs);

	return (s32)checksum;
}

/**
 *  txgbe_validate_eeprom_checksum - Validate EEPROM checksum
 *  @hw: pointer to hardware structure
 *  @checksum_val: calculated checksum
 *
 *  Performs checksum calculation and validates the EEPROM checksum.  If the
 *  caller does not need checksum_val, the value can be NULL.
 **/
s32 txgbe_validate_eeprom_checksum(struct txgbe_hw *hw,
				   u16 *checksum_val)
{
	s32 status;
	u16 checksum;
	u16 read_checksum = 0;

	/* Read the first word from the EEPROM. If this times out or fails, do
	 * not continue or we could be in for a very long wait while every
	 * EEPROM read fails
	 */
	status = TCALL(hw, eeprom.ops.read, 0, &checksum);
	if (status) {
		txgbe_dbg(hw, "EEPROM read failed\n");
		return status;
	}

	status = TCALL(hw, eeprom.ops.calc_checksum);
	if (status < 0)
		return status;

	checksum = (u16)(status & 0xffff);

	status = txgbe_read_ee_hostif(hw, hw->eeprom.sw_region_offset +
				      TXGBE_EEPROM_CHECKSUM,
				      &read_checksum);
	if (status)
		return status;

	/* Verify read checksum from EEPROM is the same as
	 * calculated checksum
	 */
	if (read_checksum != checksum) {
		status = TXGBE_ERR_EEPROM_CHECKSUM;
		ERROR_REPORT1(hw, TXGBE_ERROR_INVALID_STATE,
			      "Invalid EEPROM checksum\n");
	}

	/* If the user cares, return the calculated checksum */
	if (checksum_val)
		*checksum_val = checksum;

	return status;
}
