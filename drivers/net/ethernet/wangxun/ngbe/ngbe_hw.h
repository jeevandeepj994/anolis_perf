/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _NGBE_HW_H_
#define _NGBE_HW_H_

#define SPI_CLK_CMD_OFFSET      28 /* SPI command field offset */
#define SPI_CLK_DIV_OFFSET      25 /* SPI clock divide field offset */
#define SPI_CLK_DIV             3
#define SPI_TIME_OUT_VALUE      10000
#define SPI_SECTOR_SIZE         (4 * 1024)  /* FLASH sector size is 64KB */

#define SPI_CMD_WRITE_DWORD     0  /* SPI write a dword command */
#define SPI_CMD_READ_DWORD      1  /* SPI read a dword command */
#define SPI_CMD_USER_CMD        5  /* SPI user command */
#define SPI_CMD_ERASE_SECTOR    3  /* SPI erase sector command */
#define SPI_CMD_ERASE_CHIP      4  /* SPI erase chip command */

#define SPI_H_CMD_REG_ADDR      0x10104  /* SPI Command register address */
#define SPI_H_DAT_REG_ADDR      0x10108  /* SPI Data register address */
#define SPI_H_STA_REG_ADDR      0x1010c  /* SPI Status register address */
#define SPI_H_USR_CMD_REG_ADDR  0x10110  /* SPI User Command register address */
#define SPI_CMD_CFG1_ADDR       0x10118  /* Flash command configuration register 1 */

#define MAC_ADDR0_WORD0_OFFSET_1G    0x006000c  /* MAC Address for LAN0 */
#define MAC_ADDR0_WORD1_OFFSET_1G    0x0060014
#define MAC_ADDR1_WORD0_OFFSET_1G    0x006800c  /* MAC Address for LAN1 */
#define MAC_ADDR1_WORD1_OFFSET_1G    0x0068014
#define MAC_ADDR2_WORD0_OFFSET_1G    0x007000c  /* MAC Address for LAN2 */
#define MAC_ADDR2_WORD1_OFFSET_1G    0x0070014
#define MAC_ADDR3_WORD0_OFFSET_1G    0x007800c  /* MAC Address for LAN3 */
#define MAC_ADDR3_WORD1_OFFSET_1G    0x0078014
#define PRODUCT_SERIAL_NUM_OFFSET_1G    0x00f0000  /* Product Serial Number */

/* Flow control defines */
#define NGBE_TAF_SYM_PAUSE (0x1)
#define NGBE_TAF_ASM_PAUSE (0x2)

u32 ngbe_flash_read_dword(struct ngbe_hw *hw, u32 addr);
int ngbe_check_flash_load(struct ngbe_hw *hw, u32 check_bit);
s32 ngbe_init_hw(struct ngbe_hw *hw);
s32 ngbe_host_if_command(struct ngbe_hw *hw, u32 *buffer,
			 u32 length, u32 timeout, bool return_data);
u8 ngbe_calculate_checksum(u8 *buffer, u32 length);
bool ngbe_check_mng_access(struct ngbe_hw *hw);
bool ngbe_mng_present(struct ngbe_hw *hw);
s32 ngbe_write_ee_hostif(struct ngbe_hw *hw, u16 offset,
			 u16 data);
s32 ngbe_disable_pcie_master(struct ngbe_hw *hw);
s32 ngbe_read_ee_hostif(struct ngbe_hw *hw, u16 offset, u16 *data);
int ngbe_upgrade_flash(struct ngbe_hw *hw, u32 region,
		       const u8 *data, u32 size);
s32 ngbe_upgrade_flash_hostif(struct ngbe_hw *hw, u32 region,
			      const u8 *data, u32 size);
s32 ngbe_init_ops_common(struct ngbe_hw *hw);

#endif
