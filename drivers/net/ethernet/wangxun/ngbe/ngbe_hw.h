/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _NGBE_HW_H_
#define _NGBE_HW_H_

#define SPI_CMD_READ_DWORD		1  /* SPI read a dword command */
#define SPI_CLK_CMD_OFFSET      28 /* SPI command field offset */
#define SPI_CLK_DIV_OFFSET      25 /* SPI clock divide field offset */
#define SPI_CLK_DIV             3
#define SPI_TIME_OUT_VALUE      10000
#define SPI_H_CMD_REG_ADDR      0x10104  /* SPI Command register address */
#define SPI_H_STA_REG_ADDR      0x1010c  /* SPI Status register address */

#define SPI_H_DAT_REG_ADDR          0x10108  // SPI Data register address

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
s32 ngbe_init_ops_common(struct ngbe_hw *hw);

#endif
