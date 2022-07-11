/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_HW_H_
#define _TXGBE_HW_H_

#define SPI_CLK_DIV           2

#define SPI_CMD_READ_DWORD    1  /* SPI read a dword command */

#define SPI_CLK_CMD_OFFSET    28  /* SPI command field offset in Command register */
#define SPI_CLK_DIV_OFFSET    25  /* SPI clock divide field offset in Command register */

#define SPI_TIME_OUT_VALUE           10000
#define SPI_H_CMD_REG_ADDR           0x10104  /* SPI Command register address */
#define SPI_H_DAT_REG_ADDR           0x10108  /* SPI Data register address */
#define SPI_H_STA_REG_ADDR           0x1010c  /* SPI Status register address */

u16 txgbe_get_pcie_msix_count(struct txgbe_hw *hw);
s32 txgbe_init_hw(struct txgbe_hw *hw);
s32 txgbe_start_hw(struct txgbe_hw *hw);
s32 txgbe_read_pba_string(struct txgbe_hw *hw, u8 *pba_num,
			  u32 pba_num_size);
s32 txgbe_get_mac_addr(struct txgbe_hw *hw, u8 *mac_addr);
s32 txgbe_get_bus_info(struct txgbe_hw *hw);
void txgbe_set_pci_config_data(struct txgbe_hw *hw, u16 link_status);
s32 txgbe_set_lan_id_multi_port_pcie(struct txgbe_hw *hw);
s32 txgbe_stop_adapter(struct txgbe_hw *hw);

s32 txgbe_led_on(struct txgbe_hw *hw, u32 index);
s32 txgbe_led_off(struct txgbe_hw *hw, u32 index);

s32 txgbe_set_rar(struct txgbe_hw *hw, u32 index, u8 *addr, u64 pools,
		  u32 enable_addr);
s32 txgbe_clear_rar(struct txgbe_hw *hw, u32 index);
s32 txgbe_init_rx_addrs(struct txgbe_hw *hw);

s32 txgbe_acquire_swfw_sync(struct txgbe_hw *hw, u32 mask);
s32 txgbe_release_swfw_sync(struct txgbe_hw *hw, u32 mask);
s32 txgbe_disable_pcie_master(struct txgbe_hw *hw);

s32 txgbe_get_san_mac_addr(struct txgbe_hw *hw, u8 *san_mac_addr);

s32 txgbe_set_vmdq_san_mac(struct txgbe_hw *hw, u32 vmdq);
s32 txgbe_clear_vmdq(struct txgbe_hw *hw, u32 rar, u32 vmdq);
s32 txgbe_init_uta_tables(struct txgbe_hw *hw);

s32 txgbe_get_wwn_prefix(struct txgbe_hw *hw, u16 *wwnn_prefix,
			 u16 *wwpn_prefix);

s32 txgbe_set_fw_drv_ver(struct txgbe_hw *hw, u8 maj, u8 min,
			 u8 build, u8 ver);
s32 txgbe_reset_hostif(struct txgbe_hw *hw);
u8 txgbe_calculate_checksum(u8 *buffer, u32 length);
s32 txgbe_host_interface_command(struct txgbe_hw *hw, u32 *buffer,
				 u32 length, u32 timeout, bool return_data);

bool txgbe_mng_present(struct txgbe_hw *hw);
bool txgbe_check_mng_access(struct txgbe_hw *hw);

s32 txgbe_init_thermal_sensor_thresh(struct txgbe_hw *hw);
s32 txgbe_disable_rx(struct txgbe_hw *hw);
s32 txgbe_setup_mac_link_multispeed_fiber(struct txgbe_hw *hw,
					  u32 speed,
					  bool autoneg_wait_to_complete);
int txgbe_check_flash_load(struct txgbe_hw *hw, u32 check_bit);

s32 txgbe_get_link_capabilities(struct txgbe_hw *hw,
				u32 *speed, bool *autoneg);
enum txgbe_media_type txgbe_get_media_type(struct txgbe_hw *hw);
s32 txgbe_disable_tx_laser_multispeed_fiber(struct txgbe_hw *hw);
s32 txgbe_enable_tx_laser_multispeed_fiber(struct txgbe_hw *hw);
s32 txgbe_flap_tx_laser_multispeed_fiber(struct txgbe_hw *hw);
s32 txgbe_set_hard_rate_select_speed(struct txgbe_hw *hw, u32 speed);
s32 txgbe_setup_mac_link(struct txgbe_hw *hw, u32 speed,
			 bool autoneg_wait_to_complete);
s32 txgbe_check_mac_link(struct txgbe_hw *hw, u32 *speed,
			 bool *link_up, bool link_up_wait_to_complete);
void txgbe_init_mac_link_ops(struct txgbe_hw *hw);
int txgbe_reset_misc(struct txgbe_hw *hw);
s32 txgbe_reset_hw(struct txgbe_hw *hw);
s32 txgbe_identify_phy(struct txgbe_hw *hw);
s32 txgbe_init_phy_ops(struct txgbe_hw *hw);
s32 txgbe_init_ops(struct txgbe_hw *hw);

s32 txgbe_init_eeprom_params(struct txgbe_hw *hw);
s32 txgbe_calc_eeprom_checksum(struct txgbe_hw *hw);
s32 txgbe_validate_eeprom_checksum(struct txgbe_hw *hw,
				   u16 *checksum_val);
s32 txgbe_read_ee_hostif_buffer(struct txgbe_hw *hw,
				u16 offset, u16 words, u16 *data);
s32 txgbe_read_ee_hostif_data(struct txgbe_hw *hw, u16 offset, u16 *data);
s32 txgbe_read_ee_hostif(struct txgbe_hw *hw, u16 offset, u16 *data);
u32 txgbe_rd32_epcs(struct txgbe_hw *hw, u32 addr);
void txgbe_wr32_epcs(struct txgbe_hw *hw, u32 addr, u32 data);
void txgbe_wr32_ephy(struct txgbe_hw *hw, u32 addr, u32 data);

s32 txgbe_upgrade_flash_hostif(struct txgbe_hw *hw,  u32 region,
			       const u8 *data, u32 size);

s32 txgbe_close_notify(struct txgbe_hw *hw);
s32 txgbe_open_notify(struct txgbe_hw *hw);

s32 txgbe_set_link_to_kr(struct txgbe_hw *hw, bool autoneg);
s32 txgbe_set_link_to_kx4(struct txgbe_hw *hw, bool autoneg);

s32 txgbe_set_link_to_kx(struct txgbe_hw *hw,
			 u32 speed,
			 bool autoneg);

u8 fmgr_cmd_op(struct txgbe_hw *hw, u32 cmd, u32 cmd_addr);
u32 txgbe_flash_read_dword(struct txgbe_hw *hw, u32 addr);

#endif /* _TXGBE_HW_H_ */
