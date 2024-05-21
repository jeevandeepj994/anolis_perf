/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd. */
#ifndef _NGBE_PHY_H_
#define _NGBE_PHY_H_

s32 ngbe_phy_read_reg_mdi(struct ngbe_hw *hw,
			  u32 reg_addr,
									u32 device_type,
									u16 *phy_data);
s32 ngbe_phy_write_reg_mdi(struct ngbe_hw *hw,
			   u32 reg_addr,
									u32 device_type,
									u16 phy_data);
s32 ngbe_phy_read_reg_ext_yt(struct ngbe_hw *hw, u32 addr, u32 type, u16 *phy_data);
s32 ngbe_phy_read_reg_sds_mii_yt(struct ngbe_hw *hw, u32 addr, u32 type, u16 *phy_data);
s32 ngbe_init_phy_ops_common(struct ngbe_hw *hw);
u32 ngbe_phy_setup_link(struct ngbe_hw *hw,
			u32 speed,
								bool need_restart_AN);
u32 ngbe_phy_setup_link_m88e1512(struct ngbe_hw *hw,
				 u32 speed,
									bool __maybe_unused wait);
u32 ngbe_phy_setup_link_yt(struct ngbe_hw *hw,
			   u32 speed,
										 bool wait);
s32 ngbe_phy_reset_m88e1512(struct ngbe_hw *hw);
s32 ngbe_phy_reset_yt(struct ngbe_hw *hw);
s32 ngbe_phy_check_overtemp(struct ngbe_hw *hw);
s32 ngbe_phy_check_event_m88e1512(struct ngbe_hw *hw);
s32 ngbe_phy_check_event_yt(struct ngbe_hw *hw);
s32 ngbe_phy_get_adv_pause_m88e1512(struct ngbe_hw *hw, u8 *pause_bit);
s32 ngbe_phy_get_adv_pause_yt(struct ngbe_hw *hw, u8 *pause_bit);
s32 ngbe_phy_get_lp_adv_pause_m88e1512(struct ngbe_hw *hw, u8 *pause_bit);
s32 ngbe_phy_get_lp_adv_pause_yt(struct ngbe_hw *hw, u8 *pause_bit);
s32 ngbe_phy_set_pause_adv_m88e1512(struct ngbe_hw *hw, u16 pause_bit);
s32 ngbe_phy_set_pause_adv_yt(struct ngbe_hw *hw, u16 pause_bit);
s32 ngbe_phy_write_reg_ext_yt(struct ngbe_hw *hw, u32 addr, u32 type, u16 phy_data);
s32 ngbe_init_phy_ops_common(struct ngbe_hw *hw);
s32 ngbe_init_external_phy_ops_common(struct ngbe_hw *hw);
#endif
