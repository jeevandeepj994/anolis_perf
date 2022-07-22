/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_TYPE_H_
#define _TXGBE_TYPE_H_

#include <linux/types.h>
#include <linux/netdevice.h>

/************ txgbe_register.h ************/
/* Vendor ID */
#ifndef PCI_VENDOR_ID_WANGXUN
#define PCI_VENDOR_ID_WANGXUN                   0x8088
#endif

/* Device IDs */
#define TXGBE_DEV_ID_SP1000                     0x1001
#define TXGBE_DEV_ID_WX1820                     0x2001

/* Subsystem IDs */
/* SFP */
#define TXGBE_ID_SP1000_SFP                     0x0000
#define TXGBE_ID_WX1820_SFP                     0x2000
#define TXGBE_ID_SFP                            0x00

/* copper */
#define TXGBE_ID_SP1000_XAUI                    0x1010
#define TXGBE_ID_WX1820_XAUI                    0x2010
#define TXGBE_ID_XAUI                           0x10
#define TXGBE_ID_SP1000_SGMII                   0x1020
#define TXGBE_ID_WX1820_SGMII                   0x2020
#define TXGBE_ID_SGMII                          0x20
/* backplane */
#define TXGBE_ID_SP1000_KR_KX_KX4               0x1030
#define TXGBE_ID_WX1820_KR_KX_KX4               0x2030
#define TXGBE_ID_KR_KX_KX4                      0x30
/* MAC Interface */
#define TXGBE_ID_SP1000_MAC_XAUI                0x1040
#define TXGBE_ID_WX1820_MAC_XAUI                0x2040
#define TXGBE_ID_MAC_XAUI                       0x40
#define TXGBE_ID_SP1000_MAC_SGMII               0x1060
#define TXGBE_ID_WX1820_MAC_SGMII               0x2060
#define TXGBE_ID_MAC_SGMII                      0x60

#define TXGBE_NCSI_SUP                          0x8000
#define TXGBE_NCSI_MASK                         0x8000
#define TXGBE_WOL_SUP                           0x4000
#define TXGBE_WOL_MASK                          0x4000
#define TXGBE_DEV_MASK                          0xf0

/* Combined interface*/
#define TXGBE_ID_SFI_XAUI			0x50

/* Revision ID */
#define TXGBE_SP_MPW  1
/* ETH PHY Registers */
#define TXGBE_SR_XS_PCS_MMD_STATUS1             0x30001
#define TXGBE_SR_PCS_CTL2                       0x30007
#define TXGBE_SR_PMA_MMD_CTL1                   0x10000
#define TXGBE_SR_MII_MMD_CTL                    0x1F0000
#define TXGBE_SR_MII_MMD_DIGI_CTL               0x1F8000
#define TXGBE_SR_MII_MMD_AN_CTL                 0x1F8001
#define TXGBE_SR_MII_MMD_AN_ADV                 0x1F0004
#define TXGBE_SR_MII_MMD_AN_ADV_PAUSE(_v)       ((0x3 & (_v)) << 7)
#define TXGBE_SR_MII_MMD_AN_ADV_PAUSE_ASM       0x80
#define TXGBE_SR_MII_MMD_AN_ADV_PAUSE_SYM       0x100
#define TXGBE_SR_MII_MMD_LP_BABL                0x1F0005
#define TXGBE_SR_AN_MMD_CTL                     0x70000
#define TXGBE_SR_AN_MMD_ADV_REG1                0x70010
#define TXGBE_SR_AN_MMD_ADV_REG1_PAUSE(_v)      ((0x3 & (_v)) << 10)
#define TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_SYM      0x400
#define TXGBE_SR_AN_MMD_ADV_REG1_PAUSE_ASM      0x800
#define TXGBE_SR_AN_MMD_ADV_REG2                0x70011
#define TXGBE_SR_AN_MMD_LP_ABL1                 0x70013
#define TXGBE_VR_AN_KR_MODE_CL                  0x78003
#define TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1        0x38000
#define TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS      0x38010
#define TXGBE_PHY_MPLLA_CTL0                    0x18071
#define TXGBE_PHY_MPLLA_CTL3                    0x18077
#define TXGBE_PHY_MISC_CTL0                     0x18090
#define TXGBE_PHY_VCO_CAL_LD0                   0x18092
#define TXGBE_PHY_VCO_CAL_LD1                   0x18093
#define TXGBE_PHY_VCO_CAL_LD2                   0x18094
#define TXGBE_PHY_VCO_CAL_LD3                   0x18095
#define TXGBE_PHY_VCO_CAL_REF0                  0x18096
#define TXGBE_PHY_VCO_CAL_REF1                  0x18097
#define TXGBE_PHY_RX_AD_ACK                     0x18098
#define TXGBE_PHY_AFE_DFE_ENABLE                0x1805D
#define TXGBE_PHY_DFE_TAP_CTL0                  0x1805E
#define TXGBE_PHY_RX_EQ_ATT_LVL0                0x18057
#define TXGBE_PHY_RX_EQ_CTL0                    0x18058
#define TXGBE_PHY_RX_EQ_CTL                     0x1805C
#define TXGBE_PHY_TX_EQ_CTL0                    0x18036
#define TXGBE_PHY_TX_EQ_CTL1                    0x18037
#define TXGBE_PHY_TX_RATE_CTL                   0x18034
#define TXGBE_PHY_RX_RATE_CTL                   0x18054
#define TXGBE_PHY_TX_GEN_CTL2                   0x18032
#define TXGBE_PHY_RX_GEN_CTL2                   0x18052
#define TXGBE_PHY_RX_GEN_CTL3                   0x18053
#define TXGBE_PHY_MPLLA_CTL2                    0x18073
#define TXGBE_PHY_RX_POWER_ST_CTL               0x18055
#define TXGBE_PHY_TX_POWER_ST_CTL               0x18035
#define TXGBE_PHY_TX_GENCTRL1                   0x18031

#define TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_R        0x0
#define TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_X        0x1
#define TXGBE_SR_PCS_CTL2_PCS_TYPE_SEL_MASK     0x3
#define TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_1G      0x0
#define TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_10G     0x2000
#define TXGBE_SR_PMA_MMD_CTL1_SPEED_SEL_MASK    0x2000
#define TXGBE_SR_PMA_MMD_CTL1_LB_EN             0x1
#define TXGBE_SR_MII_MMD_CTL_AN_EN              0x1000
#define TXGBE_SR_MII_MMD_CTL_RESTART_AN         0x0200
#define TXGBE_SR_AN_MMD_CTL_RESTART_AN          0x0200
#define TXGBE_SR_AN_MMD_CTL_ENABLE              0x1000
#define TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_KX4    0x40
#define TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_KX     0x20
#define TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_KR     0x80
#define TXGBE_SR_AN_MMD_ADV_REG2_BP_TYPE_MASK   0xFFFF
#define TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1_ENABLE 0x1000
#define TXGBE_VR_XS_OR_PCS_MMD_DIGI_CTL1_VR_RST 0x8000
#define TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_MASK            0x1C
#define TXGBE_VR_XS_OR_PCS_MMD_DIGI_STATUS_PSEQ_POWER_GOOD      0x10

#define TXGBE_PHY_MPLLA_CTL0_MULTIPLIER_1GBASEX_KX              32
#define TXGBE_PHY_MPLLA_CTL0_MULTIPLIER_10GBASER_KR             33
#define TXGBE_PHY_MPLLA_CTL0_MULTIPLIER_OTHER                   40
#define TXGBE_PHY_MPLLA_CTL0_MULTIPLIER_MASK                    0xFF
#define TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_1GBASEX_KX           0x56
#define TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_10GBASER_KR          0x7B
#define TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_OTHER                0x56
#define TXGBE_PHY_MPLLA_CTL3_MULTIPLIER_BW_MASK                 0x7FF
#define TXGBE_PHY_MISC_CTL0_TX2RX_LB_EN_0                       0x1
#define TXGBE_PHY_MISC_CTL0_TX2RX_LB_EN_3_1                     0xE
#define TXGBE_PHY_MISC_CTL0_RX_VREF_CTRL                        0x1F00
#define TXGBE_PHY_VCO_CAL_LD0_1GBASEX_KX                        1344
#define TXGBE_PHY_VCO_CAL_LD0_10GBASER_KR                       1353
#define TXGBE_PHY_VCO_CAL_LD0_OTHER                             1360
#define TXGBE_PHY_VCO_CAL_LD0_MASK                              0x1000
#define TXGBE_PHY_VCO_CAL_REF0_LD0_1GBASEX_KX                   42
#define TXGBE_PHY_VCO_CAL_REF0_LD0_10GBASER_KR                  41
#define TXGBE_PHY_VCO_CAL_REF0_LD0_OTHER                        34
#define TXGBE_PHY_VCO_CAL_REF0_LD0_MASK                         0x3F
#define TXGBE_PHY_AFE_DFE_ENABLE_DFE_EN0                        0x10
#define TXGBE_PHY_AFE_DFE_ENABLE_AFE_EN0                        0x1
#define TXGBE_PHY_AFE_DFE_ENABLE_MASK                           0xFF
#define TXGBE_PHY_RX_EQ_CTL_CONT_ADAPT0                         0x1
#define TXGBE_PHY_RX_EQ_CTL_CONT_ADAPT_MASK                     0xF
#define TXGBE_PHY_TX_RATE_CTL_TX0_RATE_10GBASER_KR              0x0
#define TXGBE_PHY_TX_RATE_CTL_TX0_RATE_RXAUI                    0x1
#define TXGBE_PHY_TX_RATE_CTL_TX0_RATE_1GBASEX_KX               0x3
#define TXGBE_PHY_TX_RATE_CTL_TX0_RATE_OTHER                    0x2
#define TXGBE_PHY_TX_RATE_CTL_TX1_RATE_OTHER                    0x20
#define TXGBE_PHY_TX_RATE_CTL_TX2_RATE_OTHER                    0x200
#define TXGBE_PHY_TX_RATE_CTL_TX3_RATE_OTHER                    0x2000
#define TXGBE_PHY_TX_RATE_CTL_TX0_RATE_MASK                     0x7
#define TXGBE_PHY_TX_RATE_CTL_TX1_RATE_MASK                     0x70
#define TXGBE_PHY_TX_RATE_CTL_TX2_RATE_MASK                     0x700
#define TXGBE_PHY_TX_RATE_CTL_TX3_RATE_MASK                     0x7000
#define TXGBE_PHY_RX_RATE_CTL_RX0_RATE_10GBASER_KR              0x0
#define TXGBE_PHY_RX_RATE_CTL_RX0_RATE_RXAUI                    0x1
#define TXGBE_PHY_RX_RATE_CTL_RX0_RATE_1GBASEX_KX               0x3
#define TXGBE_PHY_RX_RATE_CTL_RX0_RATE_OTHER                    0x2
#define TXGBE_PHY_RX_RATE_CTL_RX1_RATE_OTHER                    0x20
#define TXGBE_PHY_RX_RATE_CTL_RX2_RATE_OTHER                    0x200
#define TXGBE_PHY_RX_RATE_CTL_RX3_RATE_OTHER                    0x2000
#define TXGBE_PHY_RX_RATE_CTL_RX0_RATE_MASK                     0x7
#define TXGBE_PHY_RX_RATE_CTL_RX1_RATE_MASK                     0x70
#define TXGBE_PHY_RX_RATE_CTL_RX2_RATE_MASK                     0x700
#define TXGBE_PHY_RX_RATE_CTL_RX3_RATE_MASK                     0x7000
#define TXGBE_PHY_TX_GEN_CTL2_TX0_WIDTH_10GBASER_KR             0x200
#define TXGBE_PHY_TX_GEN_CTL2_TX0_WIDTH_10GBASER_KR_RXAUI       0x300
#define TXGBE_PHY_TX_GEN_CTL2_TX0_WIDTH_OTHER                   0x100
#define TXGBE_PHY_TX_GEN_CTL2_TX0_WIDTH_MASK                    0x300
#define TXGBE_PHY_TX_GEN_CTL2_TX1_WIDTH_OTHER                   0x400
#define TXGBE_PHY_TX_GEN_CTL2_TX1_WIDTH_MASK                    0xC00
#define TXGBE_PHY_TX_GEN_CTL2_TX2_WIDTH_OTHER                   0x1000
#define TXGBE_PHY_TX_GEN_CTL2_TX2_WIDTH_MASK                    0x3000
#define TXGBE_PHY_TX_GEN_CTL2_TX3_WIDTH_OTHER                   0x4000
#define TXGBE_PHY_TX_GEN_CTL2_TX3_WIDTH_MASK                    0xC000
#define TXGBE_PHY_RX_GEN_CTL2_RX0_WIDTH_10GBASER_KR             0x200
#define TXGBE_PHY_RX_GEN_CTL2_RX0_WIDTH_10GBASER_KR_RXAUI       0x300
#define TXGBE_PHY_RX_GEN_CTL2_RX0_WIDTH_OTHER                   0x100
#define TXGBE_PHY_RX_GEN_CTL2_RX0_WIDTH_MASK                    0x300
#define TXGBE_PHY_RX_GEN_CTL2_RX1_WIDTH_OTHER                   0x400
#define TXGBE_PHY_RX_GEN_CTL2_RX1_WIDTH_MASK                    0xC00
#define TXGBE_PHY_RX_GEN_CTL2_RX2_WIDTH_OTHER                   0x1000
#define TXGBE_PHY_RX_GEN_CTL2_RX2_WIDTH_MASK                    0x3000
#define TXGBE_PHY_RX_GEN_CTL2_RX3_WIDTH_OTHER                   0x4000
#define TXGBE_PHY_RX_GEN_CTL2_RX3_WIDTH_MASK                    0xC000

#define TXGBE_PHY_MPLLA_CTL2_DIV_CLK_EN_8                       0x100
#define TXGBE_PHY_MPLLA_CTL2_DIV_CLK_EN_10                      0x200
#define TXGBE_PHY_MPLLA_CTL2_DIV_CLK_EN_16P5                    0x400
#define TXGBE_PHY_MPLLA_CTL2_DIV_CLK_EN_MASK                    0x700

#define TXGBE_XPCS_POWER_GOOD_MAX_POLLING_TIME  100
#define TXGBE_PHY_INIT_DONE_POLLING_TIME        100

/**************** Global Registers ****************************/
/* chip control Registers */
#define TXGBE_MIS_RST                   0x1000C
#define TXGBE_MIS_PWR                   0x10000
#define TXGBE_MIS_CTL                   0x10004
#define TXGBE_MIS_PF_SM                 0x10008
#define TXGBE_MIS_PRB_CTL               0x10010
#define TXGBE_MIS_ST                    0x10028
#define TXGBE_MIS_SWSM                  0x1002C
#define TXGBE_MIS_RST_ST                0x10030

#define TXGBE_MIS_RST_SW_RST            0x00000001U
#define TXGBE_MIS_RST_LAN0_RST          0x00000002U
#define TXGBE_MIS_RST_LAN1_RST          0x00000004U
#define TXGBE_MIS_RST_LAN0_CHG_ETH_MODE 0x20000000U
#define TXGBE_MIS_RST_LAN1_CHG_ETH_MODE 0x40000000U
#define TXGBE_MIS_RST_GLOBAL_RST        0x80000000U
#define TXGBE_MIS_RST_MASK      (TXGBE_MIS_RST_SW_RST | \
				 TXGBE_MIS_RST_LAN0_RST | \
				 TXGBE_MIS_RST_LAN1_RST)
#define TXGBE_MIS_PWR_LAN_ID(_r)        ((0xC0000000U & (_r)) >> 30)
#define TXGBE_MIS_PWR_LAN_ID_0          (1)
#define TXGBE_MIS_PWR_LAN_ID_1          (2)
#define TXGBE_MIS_PWR_LAN_ID_A          (3)
#define TXGBE_MIS_ST_MNG_INIT_DN        0x00000001U
#define TXGBE_MIS_ST_MNG_VETO           0x00000100U
#define TXGBE_MIS_ST_LAN0_ECC           0x00010000U
#define TXGBE_MIS_ST_LAN1_ECC           0x00020000U
#define TXGBE_MIS_ST_MNG_ECC            0x00040000U
#define TXGBE_MIS_ST_PCORE_ECC          0x00080000U
#define TXGBE_MIS_ST_PCIWRP_ECC         0x00100000U
#define TXGBE_MIS_SWSM_SMBI             1
#define TXGBE_MIS_RST_ST_DEV_RST_ST_DONE        0x00000000U
#define TXGBE_MIS_RST_ST_DEV_RST_ST_REQ         0x00080000U
#define TXGBE_MIS_RST_ST_DEV_RST_ST_INPROGRESS  0x00100000U
#define TXGBE_MIS_RST_ST_DEV_RST_ST_MASK        0x00180000U
#define TXGBE_MIS_RST_ST_DEV_RST_TYPE_MASK      0x00070000U
#define TXGBE_MIS_RST_ST_DEV_RST_TYPE_SHIFT     16
#define TXGBE_MIS_RST_ST_DEV_RST_TYPE_SW_RST    0x3
#define TXGBE_MIS_RST_ST_DEV_RST_TYPE_GLOBAL_RST 0x5
#define TXGBE_MIS_RST_ST_RST_INIT       0x0000FF00U
#define TXGBE_MIS_RST_ST_RST_INI_SHIFT  8
#define TXGBE_MIS_RST_ST_RST_TIM        0x000000FFU
#define TXGBE_MIS_PF_SM_SM              1
#define TXGBE_MIS_PRB_CTL_LAN0_UP       0x2
#define TXGBE_MIS_PRB_CTL_LAN1_UP       0x1

/* Sensors for PVT(Process Voltage Temperature) */
#define TXGBE_TS_CTL                    0x10300
#define TXGBE_TS_EN                     0x10304
#define TXGBE_TS_ST                     0x10308
#define TXGBE_TS_ALARM_THRE             0x1030C
#define TXGBE_TS_DALARM_THRE            0x10310
#define TXGBE_TS_INT_EN                 0x10314
#define TXGBE_TS_ALARM_ST               0x10318
#define TXGBE_TS_ALARM_ST_DALARM        0x00000002U
#define TXGBE_TS_ALARM_ST_ALARM         0x00000001U

#define TXGBE_TS_CTL_EVAL_MD            0x80000000U
#define TXGBE_TS_EN_ENA                 0x00000001U
#define TXGBE_TS_ST_DATA_OUT_MASK       0x000003FFU
#define TXGBE_TS_ALARM_THRE_MASK        0x000003FFU
#define TXGBE_TS_DALARM_THRE_MASK       0x000003FFU
#define TXGBE_TS_INT_EN_DALARM_INT_EN   0x00000002U
#define TXGBE_TS_INT_EN_ALARM_INT_EN    0x00000001U

struct txgbe_thermal_diode_data {
	s16 temp;
	s16 alarm_thresh;
	s16 dalarm_thresh;
};

struct txgbe_thermal_sensor_data {
	struct txgbe_thermal_diode_data sensor;
};

/* FMGR Registers */
#define TXGBE_SPI_ILDR_STATUS           0x10120
#define TXGBE_SPI_ILDR_STATUS_PERST     0x00000001U /* PCIE_PERST is done */
#define TXGBE_SPI_ILDR_STATUS_PWRRST    0x00000002U /* Power on reset is done */
#define TXGBE_SPI_ILDR_STATUS_SW_RESET  0x00000080U /* software reset is done */
#define TXGBE_SPI_ILDR_STATUS_LAN0_SW_RST 0x00000200U /* lan0 soft reset done */
#define TXGBE_SPI_ILDR_STATUS_LAN1_SW_RST 0x00000400U /* lan1 soft reset done */

#define TXGBE_MAX_FLASH_LOAD_POLL_TIME  10

#define TXGBE_SPI_CMD                   0x10104
#define TXGBE_SPI_CMD_CMD(_v)           (((_v) & 0x7) << 28)
#define TXGBE_SPI_CMD_CLK(_v)           (((_v) & 0x7) << 25)
#define TXGBE_SPI_CMD_ADDR(_v)          (((_v) & 0xFFFFFF))
#define TXGBE_SPI_DATA                  0x10108
#define TXGBE_SPI_DATA_BYPASS           ((0x1) << 31)
#define TXGBE_SPI_DATA_STATUS(_v)       (((_v) & 0xFF) << 16)
#define TXGBE_SPI_DATA_OP_DONE          ((0x1))

#define TXGBE_SPI_STATUS                0x1010C
#define TXGBE_SPI_STATUS_OPDONE         ((0x1))
#define TXGBE_SPI_STATUS_FLASH_BYPASS   ((0x1) << 31)

#define TXGBE_SPI_USR_CMD               0x10110
#define TXGBE_SPI_CMDCFG0               0x10114
#define TXGBE_SPI_CMDCFG1               0x10118
#define TXGBE_SPI_ECC_CTL               0x10130
#define TXGBE_SPI_ECC_INJ               0x10134
#define TXGBE_SPI_ECC_ST                0x10138
#define TXGBE_SPI_ILDR_SWPTR            0x10124

/************************* Port Registers ************************************/
/* I2C registers */
#define TXGBE_I2C_CON                   0x14900 /* I2C Control */
#define TXGBE_I2C_CON_SLAVE_DISABLE     ((1 << 6))
#define TXGBE_I2C_CON_RESTART_EN        ((1 << 5))
#define TXGBE_I2C_CON_10BITADDR_MASTER  ((1 << 4))
#define TXGBE_I2C_CON_10BITADDR_SLAVE   ((1 << 3))
#define TXGBE_I2C_CON_SPEED(_v)         (((_v) & 0x3) << 1)
#define TXGBE_I2C_CON_MASTER_MODE       ((1 << 0))
#define TXGBE_I2C_TAR                   0x14904 /* I2C Target Address */
#define TXGBE_I2C_DATA_CMD              0x14910 /* I2C Rx/Tx Data Buf and Cmd */
#define TXGBE_I2C_DATA_CMD_STOP         ((1 << 9))
#define TXGBE_I2C_DATA_CMD_READ         ((1 << 8) | TXGBE_I2C_DATA_CMD_STOP)
#define TXGBE_I2C_DATA_CMD_WRITE        ((0 << 8) | TXGBE_I2C_DATA_CMD_STOP)
#define TXGBE_I2C_SS_SCL_HCNT           0x14914 /* Standard speed I2C Clock SCL High Count */
#define TXGBE_I2C_SS_SCL_LCNT           0x14918 /* Standard speed I2C Clock SCL Low Count */
#define TXGBE_I2C_FS_SCL_HCNT           0x1491C
#define TXGBE_I2C_FS_SCL_LCNT           0x14920
#define TXGBE_I2C_HS_SCL_HCNT           0x14924 /* High speed I2C Clock SCL High Count */
#define TXGBE_I2C_HS_SCL_LCNT           0x14928 /* High speed I2C Clock SCL Low Count */
#define TXGBE_I2C_INTR_STAT             0x1492C /* I2C Interrupt Status */
#define TXGBE_I2C_RAW_INTR_STAT         0x14934 /* I2C Raw Interrupt Status */
#define TXGBE_I2C_INTR_STAT_RX_FULL     ((0x1) << 2)
#define TXGBE_I2C_INTR_STAT_TX_EMPTY    ((0x1) << 4)
#define TXGBE_I2C_INTR_MASK             0x14930 /* I2C Interrupt Mask */
#define TXGBE_I2C_RX_TL                 0x14938 /* I2C Receive FIFO Threshold */
#define TXGBE_I2C_TX_TL                 0x1493C /* I2C TX FIFO Threshold */
#define TXGBE_I2C_CLR_INTR              0x14940 /* Clear Combined and Individual Int */
#define TXGBE_I2C_CLR_RX_UNDER          0x14944 /* Clear RX_UNDER Interrupt */
#define TXGBE_I2C_CLR_RX_OVER           0x14948 /* Clear RX_OVER Interrupt */
#define TXGBE_I2C_CLR_TX_OVER           0x1494C /* Clear TX_OVER Interrupt */
#define TXGBE_I2C_CLR_RD_REQ            0x14950 /* Clear RD_REQ Interrupt */
#define TXGBE_I2C_CLR_TX_ABRT           0x14954 /* Clear TX_ABRT Interrupt */
#define TXGBE_I2C_CLR_RX_DONE           0x14958 /* Clear RX_DONE Interrupt */
#define TXGBE_I2C_CLR_ACTIVITY          0x1495C /* Clear ACTIVITY Interrupt */
#define TXGBE_I2C_CLR_STOP_DET          0x14960 /* Clear STOP_DET Interrupt */
#define TXGBE_I2C_CLR_START_DET         0x14964 /* Clear START_DET Interrupt */
#define TXGBE_I2C_CLR_GEN_CALL          0x14968 /* Clear GEN_CALL Interrupt */
#define TXGBE_I2C_ENABLE                0x1496C /* I2C Enable */
#define TXGBE_I2C_STATUS                0x14970 /* I2C Status register */
#define TXGBE_I2C_STATUS_MST_ACTIVITY   ((1U << 5))
#define TXGBE_I2C_TXFLR                 0x14974 /* Transmit FIFO Level Reg */
#define TXGBE_I2C_RXFLR                 0x14978 /* Receive FIFO Level Reg */
#define TXGBE_I2C_SDA_HOLD              0x1497C /* SDA hold time length reg */
#define TXGBE_I2C_TX_ABRT_SOURCE        0x14980 /* I2C TX Abort Status Reg */
#define TXGBE_I2C_SDA_SETUP             0x14994 /* I2C SDA Setup Register */
#define TXGBE_I2C_ENABLE_STATUS         0x1499C /* I2C Enable Status Register */
#define TXGBE_I2C_FS_SPKLEN             0x149A0 /* ISS and FS spike suppression limit */
#define TXGBE_I2C_HS_SPKLEN             0x149A4 /* HS spike suppression limit */
#define TXGBE_I2C_SCL_STUCK_TIMEOUT     0x149AC /* I2C SCL stuck at low timeout register */
#define TXGBE_I2C_SDA_STUCK_TIMEOUT     0x149B0 /*I2C SDA Stuck at Low Timeout*/
#define TXGBE_I2C_CLR_SCL_STUCK_DET     0x149B4 /* Clear SCL Stuck at Low Detect Interrupt */
#define TXGBE_I2C_DEVICE_ID             0x149b8 /* I2C Device ID */
#define TXGBE_I2C_COMP_PARAM_1          0x149f4 /* Component Parameter Reg */
#define TXGBE_I2C_COMP_VERSION          0x149f8 /* Component Version ID */
#define TXGBE_I2C_COMP_TYPE             0x149fc /* DesignWare Component Type Reg */

#define TXGBE_I2C_SLAVE_ADDR            (0xA0 >> 1)
#define TXGBE_I2C_THERMAL_SENSOR_ADDR   0xF8

/* port cfg Registers */
#define TXGBE_CFG_PORT_CTL              0x14400
#define TXGBE_CFG_PORT_ST               0x14404
#define TXGBE_CFG_EX_VTYPE              0x14408
#define TXGBE_CFG_LED_CTL               0x14424
#define TXGBE_CFG_VXLAN                 0x14410
#define TXGBE_CFG_VXLAN_GPE             0x14414
#define TXGBE_CFG_GENEVE                0x14418
#define TXGBE_CFG_TEREDO                0x1441C
#define TXGBE_CFG_TCP_TIME              0x14420
#define TXGBE_CFG_TAG_TPID(_i)          (0x14430 + ((_i) * 4))
/* port cfg bit */
#define TXGBE_CFG_PORT_CTL_PFRSTD       0x00004000U /* Phy Function Reset Done */
#define TXGBE_CFG_PORT_CTL_D_VLAN       0x00000001U /* double vlan*/
#define TXGBE_CFG_PORT_CTL_ETAG_ETYPE_VLD 0x00000002U
#define TXGBE_CFG_PORT_CTL_QINQ         0x00000004U
#define TXGBE_CFG_PORT_CTL_DRV_LOAD     0x00000008U
#define TXGBE_CFG_PORT_CTL_FORCE_LKUP   0x00000010U /* force link up */
#define TXGBE_CFG_PORT_CTL_DCB_EN       0x00000400U /* dcb enabled */
#define TXGBE_CFG_PORT_CTL_NUM_TC_MASK  0x00000800U /* number of TCs */
#define TXGBE_CFG_PORT_CTL_NUM_TC_4     0x00000000U
#define TXGBE_CFG_PORT_CTL_NUM_TC_8     0x00000800U
#define TXGBE_CFG_PORT_CTL_NUM_VT_MASK  0x00003000U /* number of TVs */
#define TXGBE_CFG_PORT_CTL_NUM_VT_NONE  0x00000000U
#define TXGBE_CFG_PORT_CTL_NUM_VT_16    0x00001000U
#define TXGBE_CFG_PORT_CTL_NUM_VT_32    0x00002000U
#define TXGBE_CFG_PORT_CTL_NUM_VT_64    0x00003000U
/* Status Bit */
#define TXGBE_CFG_PORT_ST_LINK_UP       0x00000001U
#define TXGBE_CFG_PORT_ST_LINK_10G      0x00000002U
#define TXGBE_CFG_PORT_ST_LINK_1G       0x00000004U
#define TXGBE_CFG_PORT_ST_LINK_100M     0x00000008U
#define TXGBE_CFG_PORT_ST_LAN_ID(_r)    ((0x00000100U & (_r)) >> 8)
#define TXGBE_LINK_UP_TIME              90
/* LED CTL Bit */
#define TXGBE_CFG_LED_CTL_LINK_BSY_SEL  0x00000010U
#define TXGBE_CFG_LED_CTL_LINK_100M_SEL 0x00000008U
#define TXGBE_CFG_LED_CTL_LINK_1G_SEL   0x00000004U
#define TXGBE_CFG_LED_CTL_LINK_10G_SEL  0x00000002U
#define TXGBE_CFG_LED_CTL_LINK_UP_SEL   0x00000001U
#define TXGBE_CFG_LED_CTL_LINK_OD_SHIFT 16
/* LED modes */
#define TXGBE_LED_LINK_UP               TXGBE_CFG_LED_CTL_LINK_UP_SEL
#define TXGBE_LED_LINK_10G              TXGBE_CFG_LED_CTL_LINK_10G_SEL
#define TXGBE_LED_LINK_ACTIVE           TXGBE_CFG_LED_CTL_LINK_BSY_SEL
#define TXGBE_LED_LINK_1G               TXGBE_CFG_LED_CTL_LINK_1G_SEL
#define TXGBE_LED_LINK_100M             TXGBE_CFG_LED_CTL_LINK_100M_SEL

/* GPIO Registers */
#define TXGBE_GPIO_DR                   0x14800
#define TXGBE_GPIO_DDR                  0x14804
#define TXGBE_GPIO_CTL                  0x14808
#define TXGBE_GPIO_INTEN                0x14830
#define TXGBE_GPIO_INTMASK              0x14834
#define TXGBE_GPIO_INTTYPE_LEVEL        0x14838
#define TXGBE_GPIO_INTSTATUS            0x14844
#define TXGBE_GPIO_EOI                  0x1484C
/*GPIO bit */
#define TXGBE_GPIO_DR_0         0x00000001U /* SDP0 Data Value */
#define TXGBE_GPIO_DR_1         0x00000002U /* SDP1 Data Value */
#define TXGBE_GPIO_DR_2         0x00000004U /* SDP2 Data Value */
#define TXGBE_GPIO_DR_3         0x00000008U /* SDP3 Data Value */
#define TXGBE_GPIO_DR_4         0x00000010U /* SDP4 Data Value */
#define TXGBE_GPIO_DR_5         0x00000020U /* SDP5 Data Value */
#define TXGBE_GPIO_DR_6         0x00000040U /* SDP6 Data Value */
#define TXGBE_GPIO_DR_7         0x00000080U /* SDP7 Data Value */
#define TXGBE_GPIO_DDR_0        0x00000001U /* SDP0 IO direction */
#define TXGBE_GPIO_DDR_1        0x00000002U /* SDP1 IO direction */
#define TXGBE_GPIO_DDR_2        0x00000004U /* SDP1 IO direction */
#define TXGBE_GPIO_DDR_3        0x00000008U /* SDP3 IO direction */
#define TXGBE_GPIO_DDR_4        0x00000010U /* SDP4 IO direction */
#define TXGBE_GPIO_DDR_5        0x00000020U /* SDP5 IO direction */
#define TXGBE_GPIO_DDR_6        0x00000040U /* SDP6 IO direction */
#define TXGBE_GPIO_DDR_7        0x00000080U /* SDP7 IO direction */
#define TXGBE_GPIO_CTL_SW_MODE  0x00000000U /* SDP software mode */
#define TXGBE_GPIO_INTEN_1      0x00000002U /* SDP1 interrupt enable */
#define TXGBE_GPIO_INTEN_2      0x00000004U /* SDP2 interrupt enable */
#define TXGBE_GPIO_INTEN_3      0x00000008U /* SDP3 interrupt enable */
#define TXGBE_GPIO_INTEN_5      0x00000020U /* SDP5 interrupt enable */
#define TXGBE_GPIO_INTEN_6      0x00000040U /* SDP6 interrupt enable */
#define TXGBE_GPIO_INTTYPE_LEVEL_2 0x00000004U /* SDP2 interrupt type level */
#define TXGBE_GPIO_INTTYPE_LEVEL_3 0x00000008U /* SDP3 interrupt type level */
#define TXGBE_GPIO_INTTYPE_LEVEL_5 0x00000020U /* SDP5 interrupt type level */
#define TXGBE_GPIO_INTTYPE_LEVEL_6 0x00000040U /* SDP6 interrupt type level */
#define TXGBE_GPIO_INTSTATUS_1  0x00000002U /* SDP1 interrupt status */
#define TXGBE_GPIO_INTSTATUS_2  0x00000004U /* SDP2 interrupt status */
#define TXGBE_GPIO_INTSTATUS_3  0x00000008U /* SDP3 interrupt status */
#define TXGBE_GPIO_INTSTATUS_5  0x00000020U /* SDP5 interrupt status */
#define TXGBE_GPIO_INTSTATUS_6  0x00000040U /* SDP6 interrupt status */
#define TXGBE_GPIO_EOI_2        0x00000004U /* SDP2 interrupt clear */
#define TXGBE_GPIO_EOI_3        0x00000008U /* SDP3 interrupt clear */
#define TXGBE_GPIO_EOI_5        0x00000020U /* SDP5 interrupt clear */
#define TXGBE_GPIO_EOI_6        0x00000040U /* SDP6 interrupt clear */

/* TPH registers */
#define TXGBE_CFG_TPH_TDESC     0x14F00 /* TPH conf for Tx desc write back */
#define TXGBE_CFG_TPH_RDESC     0x14F04 /* TPH conf for Rx desc write back */
#define TXGBE_CFG_TPH_RHDR      0x14F08 /* TPH conf for writing Rx pkt header */
#define TXGBE_CFG_TPH_RPL       0x14F0C /* TPH conf for payload write access */
/* TPH bit */
#define TXGBE_CFG_TPH_TDESC_EN  0x80000000U
#define TXGBE_CFG_TPH_TDESC_PH_SHIFT 29
#define TXGBE_CFG_TPH_TDESC_ST_SHIFT 16
#define TXGBE_CFG_TPH_RDESC_EN  0x80000000U
#define TXGBE_CFG_TPH_RDESC_PH_SHIFT 29
#define TXGBE_CFG_TPH_RDESC_ST_SHIFT 16
#define TXGBE_CFG_TPH_RHDR_EN   0x00008000U
#define TXGBE_CFG_TPH_RHDR_PH_SHIFT 13
#define TXGBE_CFG_TPH_RHDR_ST_SHIFT 0
#define TXGBE_CFG_TPH_RPL_EN    0x80000000U
#define TXGBE_CFG_TPH_RPL_PH_SHIFT 29
#define TXGBE_CFG_TPH_RPL_ST_SHIFT 16

/*********************** Transmit DMA registers **************************/
/* transmit global control */
#define TXGBE_TDM_CTL           0x18000
#define TXGBE_TDM_VF_TE(_i)     (0x18004 + ((_i) * 4))
#define TXGBE_TDM_PB_THRE(_i)   (0x18020 + ((_i) * 4)) /* 8 of these 0 - 7 */
#define TXGBE_TDM_LLQ(_i)       (0x18040 + ((_i) * 4)) /* 4 of these (0-3) */
#define TXGBE_TDM_ETYPE_LB_L    0x18050
#define TXGBE_TDM_ETYPE_LB_H    0x18054
#define TXGBE_TDM_ETYPE_AS_L    0x18058
#define TXGBE_TDM_ETYPE_AS_H    0x1805C
#define TXGBE_TDM_MAC_AS_L      0x18060
#define TXGBE_TDM_MAC_AS_H      0x18064
#define TXGBE_TDM_VLAN_AS_L     0x18070
#define TXGBE_TDM_VLAN_AS_H     0x18074
#define TXGBE_TDM_TCP_FLG_L     0x18078
#define TXGBE_TDM_TCP_FLG_H     0x1807C
#define TXGBE_TDM_VLAN_INS(_i)  (0x18100 + ((_i) * 4)) /* 64 of these 0 - 63 */
/* TDM CTL BIT */
#define TXGBE_TDM_CTL_TE        0x1 /* Transmit Enable */
#define TXGBE_TDM_CTL_PADDING   0x2 /* Padding byte number for ipsec ESP */
#define TXGBE_TDM_CTL_VT_SHIFT  16  /* VLAN EtherType */
/* Per VF Port VLAN insertion rules */
#define TXGBE_TDM_VLAN_INS_VLANA_DEFAULT 0x40000000U /*Always use default VLAN*/
#define TXGBE_TDM_VLAN_INS_VLANA_NEVER   0x80000000U /* Never insert VLAN tag */

#define TXGBE_TDM_RP_CTL        0x18400
#define TXGBE_TDM_RP_CTL_RST    ((0x1) << 0)
#define TXGBE_TDM_RP_CTL_RPEN   ((0x1) << 2)
#define TXGBE_TDM_RP_CTL_RLEN   ((0x1) << 3)
#define TXGBE_TDM_RP_IDX        0x1820C
#define TXGBE_TDM_RP_RATE       0x18404
#define TXGBE_TDM_RP_RATE_MIN(v) ((0x3FFF & (v)))
#define TXGBE_TDM_RP_RATE_MAX(v) ((0x3FFF & (v)) << 16)

/* qos */
#define TXGBE_TDM_PBWARB_CTL    0x18200
#define TXGBE_TDM_PBWARB_CFG(_i) (0x18220 + ((_i) * 4)) /* 8 of these (0-7) */
#define TXGBE_TDM_MMW           0x18208
#define TXGBE_TDM_VM_CREDIT(_i) (0x18500 + ((_i) * 4))
#define TXGBE_TDM_VM_CREDIT_VAL(v) (0x3FF & (v))
/* fcoe */
#define TXGBE_TDM_FC_EOF        0x18384
#define TXGBE_TDM_FC_SOF        0x18380
/* etag */
#define TXGBE_TDM_ETAG_INS(_i)  (0x18700 + ((_i) * 4)) /* 64 of these 0 - 63 */
/* statistic */
#define TXGBE_TDM_SEC_DRP       0x18304
#define TXGBE_TDM_PKT_CNT       0x18308
#define TXGBE_TDM_OS2BMC_CNT    0x18314

/**************************** Receive DMA registers **************************/
/* receive control */
#define TXGBE_RDM_ARB_CTL       0x12000
#define TXGBE_RDM_VF_RE(_i)     (0x12004 + ((_i) * 4))
#define TXGBE_RDM_RSC_CTL       0x1200C
#define TXGBE_RDM_ARB_CFG(_i)   (0x12040 + ((_i) * 4)) /* 8 of these (0-7) */
#define TXGBE_RDM_PF_QDE(_i)    (0x12080 + ((_i) * 4))
#define TXGBE_RDM_PF_HIDE(_i)   (0x12090 + ((_i) * 4))
/* VFRE bitmask */
#define TXGBE_RDM_VF_RE_ENABLE_ALL  0xFFFFFFFFU

/* FCoE DMA Context Registers */
#define TXGBE_RDM_FCPTRL            0x12410
#define TXGBE_RDM_FCPTRH            0x12414
#define TXGBE_RDM_FCBUF             0x12418
#define TXGBE_RDM_FCBUF_VALID       ((0x1)) /* DMA Context Valid */
#define TXGBE_RDM_FCBUF_SIZE(_v)    (((_v) & 0x3) << 3) /* User Buffer Size */
#define TXGBE_RDM_FCBUF_COUNT(_v)   (((_v) & 0xFF) << 8) /* Num of User Buf */
#define TXGBE_RDM_FCBUF_OFFSET(_v)  (((_v) & 0xFFFF) << 16) /* User Buf Offset*/
#define TXGBE_RDM_FCRW              0x12420
#define TXGBE_RDM_FCRW_FCSEL(_v)    (((_v) & 0x1FF))  /* FC X_ID: 11 bits */
#define TXGBE_RDM_FCRW_WE           ((0x1) << 14)   /* Write enable */
#define TXGBE_RDM_FCRW_RE           ((0x1) << 15)   /* Read enable */
#define TXGBE_RDM_FCRW_LASTSIZE(_v) (((_v) & 0xFFFF) << 16)

/* statistic */
#define TXGBE_RDM_DRP_PKT           0x12500
#define TXGBE_RDM_BMC2OS_CNT        0x12510

/***************************** RDB registers *********************************/
/* Flow Control Registers */
#define TXGBE_RDB_RFCV(_i)          (0x19200 + ((_i) * 4)) /* 4 of these (0-3)*/
#define TXGBE_RDB_RFCL(_i)          (0x19220 + ((_i) * 4)) /* 8 of these (0-7)*/
#define TXGBE_RDB_RFCH(_i)          (0x19260 + ((_i) * 4)) /* 8 of these (0-7)*/
#define TXGBE_RDB_RFCRT             0x192A0
#define TXGBE_RDB_RFCC              0x192A4
/* receive packet buffer */
#define TXGBE_RDB_PB_WRAP           0x19004
#define TXGBE_RDB_PB_SZ(_i)         (0x19020 + ((_i) * 4))
#define TXGBE_RDB_PB_CTL            0x19000
#define TXGBE_RDB_UP2TC             0x19008
#define TXGBE_RDB_PB_SZ_SHIFT       10
#define TXGBE_RDB_PB_SZ_MASK        0x000FFC00U
/* lli interrupt */
#define TXGBE_RDB_LLI_THRE          0x19080
#define TXGBE_RDB_LLI_THRE_SZ(_v)   ((0xFFF & (_v)))
#define TXGBE_RDB_LLI_THRE_UP(_v)   ((0x7 & (_v)) << 16)
#define TXGBE_RDB_LLI_THRE_UP_SHIFT 16

/* ring assignment */
#define TXGBE_RDB_PL_CFG(_i)    (0x19300 + ((_i) * 4))
#define TXGBE_RDB_RSSTBL(_i)    (0x19400 + ((_i) * 4))
#define TXGBE_RDB_RSSRK(_i)     (0x19480 + ((_i) * 4))
#define TXGBE_RDB_RSS_TC        0x194F0
#define TXGBE_RDB_RA_CTL        0x194F4
#define TXGBE_RDB_5T_SA(_i)     (0x19600 + ((_i) * 4)) /* Src Addr Q Filter */
#define TXGBE_RDB_5T_DA(_i)     (0x19800 + ((_i) * 4)) /* Dst Addr Q Filter */
#define TXGBE_RDB_5T_SDP(_i)    (0x19A00 + ((_i) * 4)) /*Src Dst Addr Q Filter*/
#define TXGBE_RDB_5T_CTL0(_i)   (0x19C00 + ((_i) * 4)) /* Five Tuple Q Filter */
#define TXGBE_RDB_ETYPE_CLS(_i) (0x19100 + ((_i) * 4)) /* EType Q Select */
#define TXGBE_RDB_SYN_CLS       0x19130
#define TXGBE_RDB_5T_CTL1(_i)   (0x19E00 + ((_i) * 4)) /*128 of these (0-127)*/
/* Flow Director registers */
#define TXGBE_RDB_FDIR_CTL          0x19500
#define TXGBE_RDB_FDIR_HKEY         0x19568
#define TXGBE_RDB_FDIR_SKEY         0x1956C
#define TXGBE_RDB_FDIR_DA4_MSK      0x1953C
#define TXGBE_RDB_FDIR_SA4_MSK      0x19540
#define TXGBE_RDB_FDIR_TCP_MSK      0x19544
#define TXGBE_RDB_FDIR_UDP_MSK      0x19548
#define TXGBE_RDB_FDIR_SCTP_MSK     0x19560
#define TXGBE_RDB_FDIR_IP6_MSK      0x19574
#define TXGBE_RDB_FDIR_OTHER_MSK    0x19570
#define TXGBE_RDB_FDIR_FLEX_CFG(_i) (0x19580 + ((_i) * 4))
/* Flow Director Stats registers */
#define TXGBE_RDB_FDIR_FREE         0x19538
#define TXGBE_RDB_FDIR_LEN          0x1954C
#define TXGBE_RDB_FDIR_USE_ST       0x19550
#define TXGBE_RDB_FDIR_FAIL_ST      0x19554
#define TXGBE_RDB_FDIR_MATCH        0x19558
#define TXGBE_RDB_FDIR_MISS         0x1955C
/* Flow Director Programming registers */
#define TXGBE_RDB_FDIR_IP6(_i)      (0x1950C + ((_i) * 4)) /* 3 of these (0-2)*/
#define TXGBE_RDB_FDIR_SA           0x19518
#define TXGBE_RDB_FDIR_DA           0x1951C
#define TXGBE_RDB_FDIR_PORT         0x19520
#define TXGBE_RDB_FDIR_FLEX         0x19524
#define TXGBE_RDB_FDIR_HASH         0x19528
#define TXGBE_RDB_FDIR_CMD          0x1952C
/* VM RSS */
#define TXGBE_RDB_VMRSSRK(_i, _p)   (0x1A000 + ((_i) * 4) + ((_p) * 0x40))
#define TXGBE_RDB_VMRSSTBL(_i, _p)  (0x1B000 + ((_i) * 4) + ((_p) * 0x40))
/* FCoE Redirection */
#define TXGBE_RDB_FCRE_TBL_SIZE     (8) /* Max entries in FCRETA */
#define TXGBE_RDB_FCRE_CTL          0x19140
#define TXGBE_RDB_FCRE_CTL_ENA      ((0x1)) /* FCoE Redir Table Enable */
#define TXGBE_RDB_FCRE_TBL(_i)      (0x19160 + ((_i) * 4))
#define TXGBE_RDB_FCRE_TBL_RING(_v) (((_v) & 0x7F)) /* output queue number */
/* statistic */
#define TXGBE_RDB_MPCNT(_i)         (0x19040 + ((_i) * 4)) /* 8 of 3FA0-3FBC*/
#define TXGBE_RDB_LXONTXC           0x1921C
#define TXGBE_RDB_LXOFFTXC          0x19218
#define TXGBE_RDB_PXON2OFFCNT(_i)   (0x19280 + ((_i) * 4)) /* 8 of these */
#define TXGBE_RDB_PXONTXC(_i)       (0x192E0 + ((_i) * 4)) /* 8 of 3F00-3F1C*/
#define TXGBE_RDB_PXOFFTXC(_i)      (0x192C0 + ((_i) * 4)) /* 8 of 3F20-3F3C*/
#define TXGBE_RDB_PFCMACDAL         0x19210
#define TXGBE_RDB_PFCMACDAH         0x19214
#define TXGBE_RDB_TXSWERR           0x1906C
#define TXGBE_RDB_TXSWERR_TB_FREE   0x3FF
/* rdb_pl_cfg reg mask */
#define TXGBE_RDB_PL_CFG_L4HDR          0x2
#define TXGBE_RDB_PL_CFG_L3HDR          0x4
#define TXGBE_RDB_PL_CFG_L2HDR          0x8
#define TXGBE_RDB_PL_CFG_TUN_OUTER_L2HDR 0x20
#define TXGBE_RDB_PL_CFG_TUN_TUNHDR     0x10
#define TXGBE_RDB_PL_CFG_RSS_PL_MASK    0x7
#define TXGBE_RDB_PL_CFG_RSS_PL_SHIFT   29
/* RQTC Bit Masks and Shifts */
#define TXGBE_RDB_RSS_TC_SHIFT_TC(_i)   ((_i) * 4)
#define TXGBE_RDB_RSS_TC_TC0_MASK       (0x7 << 0)
#define TXGBE_RDB_RSS_TC_TC1_MASK       (0x7 << 4)
#define TXGBE_RDB_RSS_TC_TC2_MASK       (0x7 << 8)
#define TXGBE_RDB_RSS_TC_TC3_MASK       (0x7 << 12)
#define TXGBE_RDB_RSS_TC_TC4_MASK       (0x7 << 16)
#define TXGBE_RDB_RSS_TC_TC5_MASK       (0x7 << 20)
#define TXGBE_RDB_RSS_TC_TC6_MASK       (0x7 << 24)
#define TXGBE_RDB_RSS_TC_TC7_MASK       (0x7 << 28)
/* Packet Buffer Initialization */
#define TXGBE_MAX_PACKET_BUFFERS        8
#define TXGBE_RDB_PB_SZ_48KB    0x00000030U /* 48KB Packet Buffer */
#define TXGBE_RDB_PB_SZ_64KB    0x00000040U /* 64KB Packet Buffer */
#define TXGBE_RDB_PB_SZ_80KB    0x00000050U /* 80KB Packet Buffer */
#define TXGBE_RDB_PB_SZ_128KB   0x00000080U /* 128KB Packet Buffer */
#define TXGBE_RDB_PB_SZ_MAX     0x00000200U /* 512KB Packet Buffer */

/* Packet buffer allocation strategies */
enum {
	PBA_STRATEGY_EQUAL      = 0, /* Distribute PB space equally */
#define PBA_STRATEGY_EQUAL      PBA_STRATEGY_EQUAL
	PBA_STRATEGY_WEIGHTED   = 1, /* Weight front half of TCs */
#define PBA_STRATEGY_WEIGHTED   PBA_STRATEGY_WEIGHTED
};

/* FCRTL Bit Masks */
#define TXGBE_RDB_RFCL_XONE             0x80000000U /* XON enable */
#define TXGBE_RDB_RFCH_XOFFE            0x80000000U /* Packet buffer fc enable */
/* FCCFG Bit Masks */
#define TXGBE_RDB_RFCC_RFCE_802_3X      0x00000008U /* Tx link FC enable */
#define TXGBE_RDB_RFCC_RFCE_PRIORITY    0x00000010U /* Tx priority FC enable */

/* Immediate Interrupt Rx (A.K.A. Low Latency Interrupt) */
#define TXGBE_RDB_5T_CTL1_SIZE_BP       0x00001000U /* Packet size bypass */
#define TXGBE_RDB_5T_CTL1_LLI           0x00100000U /* Enables low latency Int */
#define TXGBE_RDB_LLI_THRE_PRIORITY_MASK 0x00070000U /* VLAN priority mask */
#define TXGBE_RDB_LLI_THRE_PRIORITY_EN  0x00080000U /* VLAN priority enable */
#define TXGBE_RDB_LLI_THRE_CMN_EN       0x00100000U /* cmn packet receiveed */

#define TXGBE_MAX_RDB_5T_CTL0_FILTERS           128
#define TXGBE_RDB_5T_CTL0_PROTOCOL_MASK         0x00000003U
#define TXGBE_RDB_5T_CTL0_PROTOCOL_TCP          0x00000000U
#define TXGBE_RDB_5T_CTL0_PROTOCOL_UDP          0x00000001U
#define TXGBE_RDB_5T_CTL0_PROTOCOL_SCTP         2
#define TXGBE_RDB_5T_CTL0_PRIORITY_MASK         0x00000007U
#define TXGBE_RDB_5T_CTL0_PRIORITY_SHIFT        2
#define TXGBE_RDB_5T_CTL0_POOL_MASK             0x0000003FU
#define TXGBE_RDB_5T_CTL0_POOL_SHIFT            8
#define TXGBE_RDB_5T_CTL0_5TUPLE_MASK_MASK      0x0000001FU
#define TXGBE_RDB_5T_CTL0_5TUPLE_MASK_SHIFT     25
#define TXGBE_RDB_5T_CTL0_SOURCE_ADDR_MASK      0x1E
#define TXGBE_RDB_5T_CTL0_DEST_ADDR_MASK        0x1D
#define TXGBE_RDB_5T_CTL0_SOURCE_PORT_MASK      0x1B
#define TXGBE_RDB_5T_CTL0_DEST_PORT_MASK        0x17
#define TXGBE_RDB_5T_CTL0_PROTOCOL_COMP_MASK    0x0F
#define TXGBE_RDB_5T_CTL0_POOL_MASK_EN          0x40000000U
#define TXGBE_RDB_5T_CTL0_QUEUE_ENABLE          0x80000000U

#define TXGBE_RDB_ETYPE_CLS_RX_QUEUE            0x007F0000U /* bits 22:16 */
#define TXGBE_RDB_ETYPE_CLS_RX_QUEUE_SHIFT      16
#define TXGBE_RDB_ETYPE_CLS_LLI                 0x20000000U /* bit 29 */
#define TXGBE_RDB_ETYPE_CLS_QUEUE_EN            0x80000000U /* bit 31 */

/* Receive Config masks */
#define TXGBE_RDB_PB_CTL_RXEN           (0x80000000) /* Enable Receiver */
#define TXGBE_RDB_PB_CTL_DISABLED       0x1

#define TXGBE_RDB_RA_CTL_RSS_EN         0x00000004U /* RSS Enable */
#define TXGBE_RDB_RA_CTL_RSS_MASK       0xFFFF0000U
#define TXGBE_RDB_RA_CTL_RSS_IPV4_TCP   0x00010000U
#define TXGBE_RDB_RA_CTL_RSS_IPV4       0x00020000U
#define TXGBE_RDB_RA_CTL_RSS_IPV6       0x00100000U
#define TXGBE_RDB_RA_CTL_RSS_IPV6_TCP   0x00200000U
#define TXGBE_RDB_RA_CTL_RSS_IPV4_UDP   0x00400000U
#define TXGBE_RDB_RA_CTL_RSS_IPV6_UDP   0x00800000U

enum txgbe_fdir_pballoc_type {
	TXGBE_FDIR_PBALLOC_NONE = 0,
	TXGBE_FDIR_PBALLOC_64K  = 1,
	TXGBE_FDIR_PBALLOC_128K = 2,
	TXGBE_FDIR_PBALLOC_256K = 3,
};

/* Flow Director register values */
#define TXGBE_RDB_FDIR_CTL_PBALLOC_64K          0x00000001U
#define TXGBE_RDB_FDIR_CTL_PBALLOC_128K         0x00000002U
#define TXGBE_RDB_FDIR_CTL_PBALLOC_256K         0x00000003U
#define TXGBE_RDB_FDIR_CTL_INIT_DONE            0x00000008U
#define TXGBE_RDB_FDIR_CTL_PERFECT_MATCH        0x00000010U
#define TXGBE_RDB_FDIR_CTL_REPORT_STATUS        0x00000020U
#define TXGBE_RDB_FDIR_CTL_REPORT_STATUS_ALWAYS 0x00000080U
#define TXGBE_RDB_FDIR_CTL_DROP_Q_SHIFT         8
#define TXGBE_RDB_FDIR_CTL_FILTERMODE_SHIFT     21
#define TXGBE_RDB_FDIR_CTL_MAX_LENGTH_SHIFT     24
#define TXGBE_RDB_FDIR_CTL_HASH_BITS_SHIFT      20
#define TXGBE_RDB_FDIR_CTL_FULL_THRESH_MASK     0xF0000000U
#define TXGBE_RDB_FDIR_CTL_FULL_THRESH_SHIFT    28

#define TXGBE_RDB_FDIR_TCP_MSK_DPORTM_SHIFT     16
#define TXGBE_RDB_FDIR_UDP_MSK_DPORTM_SHIFT     16
#define TXGBE_RDB_FDIR_IP6_MSK_DIPM_SHIFT       16
#define TXGBE_RDB_FDIR_OTHER_MSK_POOL           0x00000004U
#define TXGBE_RDB_FDIR_OTHER_MSK_L4P            0x00000008U
#define TXGBE_RDB_FDIR_OTHER_MSK_L3P            0x00000010U
#define TXGBE_RDB_FDIR_OTHER_MSK_TUN_TYPE       0x00000020U
#define TXGBE_RDB_FDIR_OTHER_MSK_TUN_OUTIP      0x00000040U
#define TXGBE_RDB_FDIR_OTHER_MSK_TUN            0x00000080U

#define TXGBE_RDB_FDIR_FLEX_CFG_BASE_MAC        0x00000000U
#define TXGBE_RDB_FDIR_FLEX_CFG_BASE_IP         0x00000001U
#define TXGBE_RDB_FDIR_FLEX_CFG_BASE_L4_HDR     0x00000002U
#define TXGBE_RDB_FDIR_FLEX_CFG_BASE_L4_PAYLOAD 0x00000003U
#define TXGBE_RDB_FDIR_FLEX_CFG_BASE_MSK        0x00000003U
#define TXGBE_RDB_FDIR_FLEX_CFG_MSK             0x00000004U
#define TXGBE_RDB_FDIR_FLEX_CFG_OFST            0x000000F8U
#define TXGBE_RDB_FDIR_FLEX_CFG_OFST_SHIFT      3
#define TXGBE_RDB_FDIR_FLEX_CFG_VM_SHIFT        8

#define TXGBE_RDB_FDIR_PORT_DESTINATION_SHIFT   16
#define TXGBE_RDB_FDIR_FLEX_FLEX_SHIFT          16
#define TXGBE_RDB_FDIR_HASH_BUCKET_VALID_SHIFT  15
#define TXGBE_RDB_FDIR_HASH_SIG_SW_INDEX_SHIFT  16

#define TXGBE_RDB_FDIR_CMD_CMD_MASK             0x00000003U
#define TXGBE_RDB_FDIR_CMD_CMD_ADD_FLOW         0x00000001U
#define TXGBE_RDB_FDIR_CMD_CMD_REMOVE_FLOW      0x00000002U
#define TXGBE_RDB_FDIR_CMD_CMD_QUERY_REM_FILT   0x00000003U
#define TXGBE_RDB_FDIR_CMD_FILTER_VALID         0x00000004U
#define TXGBE_RDB_FDIR_CMD_FILTER_UPDATE        0x00000008U
#define TXGBE_RDB_FDIR_CMD_IPv6DMATCH           0x00000010U
#define TXGBE_RDB_FDIR_CMD_L4TYPE_UDP           0x00000020U
#define TXGBE_RDB_FDIR_CMD_L4TYPE_TCP           0x00000040U
#define TXGBE_RDB_FDIR_CMD_L4TYPE_SCTP          0x00000060U
#define TXGBE_RDB_FDIR_CMD_IPV6                 0x00000080U
#define TXGBE_RDB_FDIR_CMD_CLEARHT              0x00000100U
#define TXGBE_RDB_FDIR_CMD_DROP                 0x00000200U
#define TXGBE_RDB_FDIR_CMD_INT                  0x00000400U
#define TXGBE_RDB_FDIR_CMD_LAST                 0x00000800U
#define TXGBE_RDB_FDIR_CMD_COLLISION            0x00001000U
#define TXGBE_RDB_FDIR_CMD_QUEUE_EN             0x00008000U
#define TXGBE_RDB_FDIR_CMD_FLOW_TYPE_SHIFT      5
#define TXGBE_RDB_FDIR_CMD_RX_QUEUE_SHIFT       16
#define TXGBE_RDB_FDIR_CMD_TUNNEL_FILTER_SHIFT  23
#define TXGBE_RDB_FDIR_CMD_VT_POOL_SHIFT        24
#define TXGBE_RDB_FDIR_INIT_DONE_POLL           10
#define TXGBE_RDB_FDIR_CMD_CMD_POLL             10
#define TXGBE_RDB_FDIR_CMD_TUNNEL_FILTER        0x00800000U
#define TXGBE_RDB_FDIR_DROP_QUEUE               127
#define TXGBE_FDIR_INIT_DONE_POLL               10

/******************************* PSR Registers *******************************/
/* psr control */
#define TXGBE_PSR_CTL                   0x15000
#define TXGBE_PSR_VLAN_CTL              0x15088
#define TXGBE_PSR_VM_CTL                0x151B0
/* Header split receive */
#define TXGBE_PSR_CTL_SW_EN             0x00040000U
#define TXGBE_PSR_CTL_RSC_DIS           0x00010000U
#define TXGBE_PSR_CTL_RSC_ACK           0x00020000U
#define TXGBE_PSR_CTL_PCSD              0x00002000U
#define TXGBE_PSR_CTL_IPPCSE            0x00001000U
#define TXGBE_PSR_CTL_BAM               0x00000400U
#define TXGBE_PSR_CTL_UPE               0x00000200U
#define TXGBE_PSR_CTL_MPE               0x00000100U
#define TXGBE_PSR_CTL_MFE               0x00000080U
#define TXGBE_PSR_CTL_MO                0x00000060U
#define TXGBE_PSR_CTL_TPE               0x00000010U
#define TXGBE_PSR_CTL_MO_SHIFT          5
/* VT_CTL bitmasks */
#define TXGBE_PSR_VM_CTL_DIS_DEFPL      0x20000000U /* disable default pool */
#define TXGBE_PSR_VM_CTL_REPLEN         0x40000000U /* replication enabled */
#define TXGBE_PSR_VM_CTL_POOL_SHIFT     7
#define TXGBE_PSR_VM_CTL_POOL_MASK      (0x3F << TXGBE_PSR_VM_CTL_POOL_SHIFT)
/* VLAN Control Bit Masks */
#define TXGBE_PSR_VLAN_CTL_VET          0x0000FFFFU  /* bits 0-15 */
#define TXGBE_PSR_VLAN_CTL_CFI          0x10000000U  /* bit 28 */
#define TXGBE_PSR_VLAN_CTL_CFIEN        0x20000000U  /* bit 29 */
#define TXGBE_PSR_VLAN_CTL_VFE          0x40000000U  /* bit 30 */

/* vm L2 contorl */
#define TXGBE_PSR_VM_L2CTL(_i)          (0x15600 + ((_i) * 4))
/* VMOLR bitmasks */
#define TXGBE_PSR_VM_L2CTL_LBDIS        0x00000002U /* disable loopback */
#define TXGBE_PSR_VM_L2CTL_LLB          0x00000004U /* local pool loopback */
#define TXGBE_PSR_VM_L2CTL_UPE          0x00000010U /* unicast promiscuous */
#define TXGBE_PSR_VM_L2CTL_TPE          0x00000020U /* ETAG promiscuous */
#define TXGBE_PSR_VM_L2CTL_VACC         0x00000040U /* accept nomatched vlan */
#define TXGBE_PSR_VM_L2CTL_VPE          0x00000080U /* vlan promiscuous mode */
#define TXGBE_PSR_VM_L2CTL_AUPE         0x00000100U /* accept untagged packets */
#define TXGBE_PSR_VM_L2CTL_ROMPE        0x00000200U /*accept packets in MTA tbl*/
#define TXGBE_PSR_VM_L2CTL_ROPE         0x00000400U /* accept packets in UC tbl*/
#define TXGBE_PSR_VM_L2CTL_BAM          0x00000800U /* accept broadcast packets*/
#define TXGBE_PSR_VM_L2CTL_MPE          0x00001000U /* multicast promiscuous */

/* etype switcher 1st stage */
#define TXGBE_PSR_ETYPE_SWC(_i) (0x15128 + ((_i) * 4)) /* EType Queue Filter */
/* ETYPE Queue Filter/Select Bit Masks */
#define TXGBE_MAX_PSR_ETYPE_SWC_FILTERS         8
#define TXGBE_PSR_ETYPE_SWC_FCOE                0x08000000U /* bit 27 */
#define TXGBE_PSR_ETYPE_SWC_TX_ANTISPOOF        0x20000000U /* bit 29 */
#define TXGBE_PSR_ETYPE_SWC_1588                0x40000000U /* bit 30 */
#define TXGBE_PSR_ETYPE_SWC_FILTER_EN           0x80000000U /* bit 31 */
#define TXGBE_PSR_ETYPE_SWC_POOL_ENABLE         BIT(26)
#define TXGBE_PSR_ETYPE_SWC_POOL_SHIFT          20
/* ETQF filter list: one static filter per filter consumer. This is
 *                 to avoid filter collisions later. Add new filters
 *                 here!!
 *
 * Current filters:
 *      EAPOL 802.1x (0x888e): Filter 0
 *      FCoE (0x8906):   Filter 2
 *      1588 (0x88f7):   Filter 3
 *      FIP  (0x8914):   Filter 4
 *      LLDP (0x88CC):   Filter 5
 *      LACP (0x8809):   Filter 6
 *      FC   (0x8808):   Filter 7
 */
#define TXGBE_PSR_ETYPE_SWC_FILTER_EAPOL        0
#define TXGBE_PSR_ETYPE_SWC_FILTER_FCOE         2
#define TXGBE_PSR_ETYPE_SWC_FILTER_1588         3
#define TXGBE_PSR_ETYPE_SWC_FILTER_FIP          4
#define TXGBE_PSR_ETYPE_SWC_FILTER_LLDP         5
#define TXGBE_PSR_ETYPE_SWC_FILTER_LACP         6
#define TXGBE_PSR_ETYPE_SWC_FILTER_FC           7

/* mcasst/ucast overflow tbl */
#define TXGBE_PSR_MC_TBL(_i)    (0x15200  + ((_i) * 4))
#define TXGBE_PSR_UC_TBL(_i)    (0x15400 + ((_i) * 4))

/* vlan tbl */
#define TXGBE_PSR_VLAN_TBL(_i)  (0x16000 + ((_i) * 4))

/* mac switcher */
#define TXGBE_PSR_MAC_SWC_AD_L  0x16200
#define TXGBE_PSR_MAC_SWC_AD_H  0x16204
#define TXGBE_PSR_MAC_SWC_VM_L  0x16208
#define TXGBE_PSR_MAC_SWC_VM_H  0x1620C
#define TXGBE_PSR_MAC_SWC_IDX   0x16210
/* RAH */
#define TXGBE_PSR_MAC_SWC_AD_H_AD(v)       (((v) & 0xFFFF))
#define TXGBE_PSR_MAC_SWC_AD_H_ADTYPE(v)   (((v) & 0x1) << 30)
#define TXGBE_PSR_MAC_SWC_AD_H_AV       0x80000000U
#define TXGBE_CLEAR_VMDQ_ALL            0xFFFFFFFFU

/* vlan switch */
#define TXGBE_PSR_VLAN_SWC      0x16220
#define TXGBE_PSR_VLAN_SWC_VM_L 0x16224
#define TXGBE_PSR_VLAN_SWC_VM_H 0x16228
#define TXGBE_PSR_VLAN_SWC_IDX  0x16230         /* 64 vlan entries */
/* VLAN pool filtering masks */
#define TXGBE_PSR_VLAN_SWC_VIEN         0x80000000U  /* filter is valid */
#define TXGBE_PSR_VLAN_SWC_ENTRIES      64
#define TXGBE_PSR_VLAN_SWC_VLANID_MASK  0x00000FFFU
#define TXGBE_ETHERNET_IEEE_VLAN_TYPE   0x8100  /* 802.1q protocol */

/* cloud switch */
#define TXGBE_PSR_CL_SWC_DST0    0x16240
#define TXGBE_PSR_CL_SWC_DST1    0x16244
#define TXGBE_PSR_CL_SWC_DST2    0x16248
#define TXGBE_PSR_CL_SWC_DST3    0x1624c
#define TXGBE_PSR_CL_SWC_KEY     0x16250
#define TXGBE_PSR_CL_SWC_CTL     0x16254
#define TXGBE_PSR_CL_SWC_VM_L    0x16258
#define TXGBE_PSR_CL_SWC_VM_H    0x1625c
#define TXGBE_PSR_CL_SWC_IDX     0x16260

#define TXGBE_PSR_CL_SWC_CTL_VLD        0x80000000U
#define TXGBE_PSR_CL_SWC_CTL_DST_MSK    0x00000002U
#define TXGBE_PSR_CL_SWC_CTL_KEY_MSK    0x00000001U

/* FCoE SOF/EOF */
#define TXGBE_PSR_FC_EOF        0x15158
#define TXGBE_PSR_FC_SOF        0x151F8
/* FCoE Filter Context Registers */
#define TXGBE_PSR_FC_FLT_CTXT           0x15108
#define TXGBE_PSR_FC_FLT_CTXT_VALID     ((0x1)) /* Filter Context Valid */
#define TXGBE_PSR_FC_FLT_CTXT_FIRST     ((0x1) << 1) /* Filter First */
#define TXGBE_PSR_FC_FLT_CTXT_WR        ((0x1) << 2) /* Write/Read Context */
#define TXGBE_PSR_FC_FLT_CTXT_SEQID(_v) (((_v) & 0xFF) << 8) /* Sequence ID */
#define TXGBE_PSR_FC_FLT_CTXT_SEQCNT(_v) (((_v) & 0xFFFF) << 16) /* Seq Count */

#define TXGBE_PSR_FC_FLT_RW             0x15110
#define TXGBE_PSR_FC_FLT_RW_FCSEL(_v)   (((_v) & 0x1FF)) /* FC OX_ID: 11 bits */
#define TXGBE_PSR_FC_FLT_RW_RVALDT      ((0x1) << 13)  /* Fast Re-Validation */
#define TXGBE_PSR_FC_FLT_RW_WE          ((0x1) << 14)  /* Write Enable */
#define TXGBE_PSR_FC_FLT_RW_RE          ((0x1) << 15)  /* Read Enable */

#define TXGBE_PSR_FC_PARAM              0x151D8

/* FCoE Receive Control */
#define TXGBE_PSR_FC_CTL                0x15100
#define TXGBE_PSR_FC_CTL_FCOELLI        ((0x1))   /* Low latency interrupt */
#define TXGBE_PSR_FC_CTL_SAVBAD         ((0x1) << 1) /* Save Bad Frames */
#define TXGBE_PSR_FC_CTL_FRSTRDH        ((0x1) << 2) /* EN 1st Read Header */
#define TXGBE_PSR_FC_CTL_LASTSEQH       ((0x1) << 3) /* EN Last Header in Seq */
#define TXGBE_PSR_FC_CTL_ALLH           ((0x1) << 4) /* EN All Headers */
#define TXGBE_PSR_FC_CTL_FRSTSEQH       ((0x1) << 5) /* EN 1st Seq. Header */
#define TXGBE_PSR_FC_CTL_ICRC           ((0x1) << 6) /* Ignore Bad FC CRC */
#define TXGBE_PSR_FC_CTL_FCCRCBO        ((0x1) << 7) /* FC CRC Byte Ordering */
#define TXGBE_PSR_FC_CTL_FCOEVER(_v)    (((_v) & 0xF) << 8) /* FCoE Version */

/* Management */
#define TXGBE_PSR_MNG_FIT_CTL           0x15820
/* Management Bit Fields and Masks */
#define TXGBE_PSR_MNG_FIT_CTL_MPROXYE    0x40000000U /* Management Proxy Enable*/
#define TXGBE_PSR_MNG_FIT_CTL_RCV_TCO_EN 0x00020000U /* Rcv TCO packet enable */
#define TXGBE_PSR_MNG_FIT_CTL_EN_BMC2OS  0x10000000U /* Ena BMC2OS and OS2BMC traffic */
#define TXGBE_PSR_MNG_FIT_CTL_EN_BMC2OS_SHIFT   28

#define TXGBE_PSR_MNG_FLEX_SEL  0x1582C
#define TXGBE_PSR_MNG_FLEX_DW_L(_i) (0x15A00 + ((_i) * 16))
#define TXGBE_PSR_MNG_FLEX_DW_H(_i) (0x15A04 + ((_i) * 16))
#define TXGBE_PSR_MNG_FLEX_MSK(_i)  (0x15A08 + ((_i) * 16))

/* mirror */
#define TXGBE_PSR_MR_CTL(_i)    (0x15B00 + ((_i) * 4))
#define TXGBE_PSR_MR_VLAN_L(_i) (0x15B10 + ((_i) * 8))
#define TXGBE_PSR_MR_VLAN_H(_i) (0x15B14 + ((_i) * 8))
#define TXGBE_PSR_MR_VM_L(_i)   (0x15B30 + ((_i) * 8))
#define TXGBE_PSR_MR_VM_H(_i)   (0x15B34 + ((_i) * 8))

/* 1588 */
#define TXGBE_PSR_1588_CTL      0x15188 /* Rx Time Sync Control register - RW */
#define TXGBE_PSR_1588_STMPL    0x151E8 /* Rx timestamp Low - RO */
#define TXGBE_PSR_1588_STMPH    0x151A4 /* Rx timestamp High - RO */
#define TXGBE_PSR_1588_ATTRL    0x151A0 /* Rx timestamp attribute low - RO */
#define TXGBE_PSR_1588_ATTRH    0x151A8 /* Rx timestamp attribute high - RO */
#define TXGBE_PSR_1588_MSGTYPE  0x15120 /* RX message type register low - RW */
/* 1588 CTL Bit */
#define TXGBE_PSR_1588_CTL_VALID            0x00000001U /* Rx timestamp valid */
#define TXGBE_PSR_1588_CTL_TYPE_MASK        0x0000000EU /* Rx type mask */
#define TXGBE_PSR_1588_CTL_TYPE_L2_V2       0x00
#define TXGBE_PSR_1588_CTL_TYPE_L4_V1       0x02
#define TXGBE_PSR_1588_CTL_TYPE_L2_L4_V2    0x04
#define TXGBE_PSR_1588_CTL_TYPE_EVENT_V2    0x0A
#define TXGBE_PSR_1588_CTL_ENABLED          0x00000010U /* Rx Timestamp enabled*/
/* 1588 msg type bit */
#define TXGBE_PSR_1588_MSGTYPE_V1_CTRLT_MASK            0x000000FFU
#define TXGBE_PSR_1588_MSGTYPE_V1_SYNC_MSG              0x00
#define TXGBE_PSR_1588_MSGTYPE_V1_DELAY_REQ_MSG         0x01
#define TXGBE_PSR_1588_MSGTYPE_V1_FOLLOWUP_MSG          0x02
#define TXGBE_PSR_1588_MSGTYPE_V1_DELAY_RESP_MSG        0x03
#define TXGBE_PSR_1588_MSGTYPE_V1_MGMT_MSG              0x04
#define TXGBE_PSR_1588_MSGTYPE_V2_MSGID_MASK            0x0000FF00U
#define TXGBE_PSR_1588_MSGTYPE_V2_SYNC_MSG              0x0000
#define TXGBE_PSR_1588_MSGTYPE_V2_DELAY_REQ_MSG         0x0100
#define TXGBE_PSR_1588_MSGTYPE_V2_PDELAY_REQ_MSG        0x0200
#define TXGBE_PSR_1588_MSGTYPE_V2_PDELAY_RESP_MSG       0x0300
#define TXGBE_PSR_1588_MSGTYPE_V2_FOLLOWUP_MSG          0x0800
#define TXGBE_PSR_1588_MSGTYPE_V2_DELAY_RESP_MSG        0x0900
#define TXGBE_PSR_1588_MSGTYPE_V2_PDELAY_FOLLOWUP_MSG   0x0A00
#define TXGBE_PSR_1588_MSGTYPE_V2_ANNOUNCE_MSG          0x0B00
#define TXGBE_PSR_1588_MSGTYPE_V2_SIGNALLING_MSG        0x0C00
#define TXGBE_PSR_1588_MSGTYPE_V2_MGMT_MSG              0x0D00

/* Wake up registers */
#define TXGBE_PSR_WKUP_CTL      0x15B80
#define TXGBE_PSR_WKUP_IPV      0x15B84
#define TXGBE_PSR_LAN_FLEX_SEL  0x15B8C
#define TXGBE_PSR_WKUP_IP4TBL(_i)       (0x15BC0 + ((_i) * 4))
#define TXGBE_PSR_WKUP_IP6TBL(_i)       (0x15BE0 + ((_i) * 4))
#define TXGBE_PSR_LAN_FLEX_DW_L(_i)     (0x15C00 + ((_i) * 16))
#define TXGBE_PSR_LAN_FLEX_DW_H(_i)     (0x15C04 + ((_i) * 16))
#define TXGBE_PSR_LAN_FLEX_MSK(_i)      (0x15C08 + ((_i) * 16))
#define TXGBE_PSR_LAN_FLEX_CTL  0x15CFC
/* Wake Up Filter Control Bit */
#define TXGBE_PSR_WKUP_CTL_LNKC 0x00000001U /* Link Status Change Wakeup Enable*/
#define TXGBE_PSR_WKUP_CTL_MAG  0x00000002U /* Magic Packet Wakeup Enable */
#define TXGBE_PSR_WKUP_CTL_EX   0x00000004U /* Directed Exact Wakeup Enable */
#define TXGBE_PSR_WKUP_CTL_MC   0x00000008U /* Directed Multicast Wakeup Enable*/
#define TXGBE_PSR_WKUP_CTL_BC   0x00000010U /* Broadcast Wakeup Enable */
#define TXGBE_PSR_WKUP_CTL_ARP  0x00000020U /* ARP Request Packet Wakeup Enable*/
#define TXGBE_PSR_WKUP_CTL_IPV4 0x00000040U /* Directed IPv4 Pkt Wakeup Enable */
#define TXGBE_PSR_WKUP_CTL_IPV6 0x00000080U /* Directed IPv6 Pkt Wakeup Enable */
#define TXGBE_PSR_WKUP_CTL_IGNORE_TCO   0x00008000U /* Ignore WakeOn TCO pkts */
#define TXGBE_PSR_WKUP_CTL_FLX0         0x00010000U /* Flexible Filter 0 Ena */
#define TXGBE_PSR_WKUP_CTL_FLX1         0x00020000U /* Flexible Filter 1 Ena */
#define TXGBE_PSR_WKUP_CTL_FLX2         0x00040000U /* Flexible Filter 2 Ena */
#define TXGBE_PSR_WKUP_CTL_FLX3         0x00080000U /* Flexible Filter 3 Ena */
#define TXGBE_PSR_WKUP_CTL_FLX4         0x00100000U /* Flexible Filter 4 Ena */
#define TXGBE_PSR_WKUP_CTL_FLX5         0x00200000U /* Flexible Filter 5 Ena */
#define TXGBE_PSR_WKUP_CTL_FLX_FILTERS  0x000F0000U /* Mask for 4 flex filters */
#define TXGBE_PSR_WKUP_CTL_FLX_FILTERS_6 0x003F0000U /* Mask for 6 flex filters*/
#define TXGBE_PSR_WKUP_CTL_FLX_FILTERS_8 0x00FF0000U /* Mask for 8 flex filters*/
#define TXGBE_PSR_WKUP_CTL_FW_RST_WK    0x80000000U /* Ena wake on FW reset assertion */
/* Mask for Ext. flex filters */
#define TXGBE_PSR_WKUP_CTL_EXT_FLX_FILTERS  0x00300000U
#define TXGBE_PSR_WKUP_CTL_ALL_FILTERS   0x000F00FFU /* Mask all 4 flex filters*/
#define TXGBE_PSR_WKUP_CTL_ALL_FILTERS_6 0x003F00FFU /* Mask all 6 flex filters*/
#define TXGBE_PSR_WKUP_CTL_ALL_FILTERS_8 0x00FF00FFU /* Mask all 8 flex filters*/
#define TXGBE_PSR_WKUP_CTL_FLX_OFFSET    16 /* Offset to the Flex Filters bits*/

#define TXGBE_PSR_MAX_SZ                0x15020

/****************************** TDB ******************************************/
#define TXGBE_TDB_RFCS                  0x1CE00
#define TXGBE_TDB_PB_SZ(_i)             (0x1CC00 + ((_i) * 4)) /* 8 of these */
#define TXGBE_TDB_MNG_TC                0x1CD10
#define TXGBE_TDB_PRB_CTL               0x17010
#define TXGBE_TDB_PBRARB_CTL            0x1CD00
#define TXGBE_TDB_UP2TC                 0x1C800
#define TXGBE_TDB_PBRARB_CFG(_i)        (0x1CD20 + ((_i) * 4)) /* 8 of (0-7) */

#define TXGBE_TDB_PB_SZ_20KB    0x00005000U /* 20KB Packet Buffer */
#define TXGBE_TDB_PB_SZ_40KB    0x0000A000U /* 40KB Packet Buffer */
#define TXGBE_TDB_PB_SZ_MAX     0x00028000U /* 160KB Packet Buffer */
#define TXGBE_TXPKT_SIZE_MAX    0xA /* Max Tx Packet size */
#define TXGBE_MAX_PB            8

/****************************** TSEC *****************************************/
/* Security Control Registers */
#define TXGBE_TSC_CTL                   0x1D000
#define TXGBE_TSC_ST                    0x1D004
#define TXGBE_TSC_BUF_AF                0x1D008
#define TXGBE_TSC_BUF_AE                0x1D00C
#define TXGBE_TSC_PRB_CTL               0x1D010
#define TXGBE_TSC_MIN_IFG               0x1D020
/* Security Bit Fields and Masks */
#define TXGBE_TSC_CTL_SECTX_DIS         0x00000001U
#define TXGBE_TSC_CTL_TX_DIS            0x00000002U
#define TXGBE_TSC_CTL_STORE_FORWARD     0x00000004U
#define TXGBE_TSC_CTL_IV_MSK_EN         0x00000008U
#define TXGBE_TSC_ST_SECTX_RDY          0x00000001U
#define TXGBE_TSC_ST_OFF_DIS            0x00000002U
#define TXGBE_TSC_ST_ECC_TXERR          0x00000004U

/* LinkSec (MacSec) Registers */
#define TXGBE_TSC_LSEC_CAP              0x1D200
#define TXGBE_TSC_LSEC_CTL              0x1D204
#define TXGBE_TSC_LSEC_SCI_L            0x1D208
#define TXGBE_TSC_LSEC_SCI_H            0x1D20C
#define TXGBE_TSC_LSEC_SA               0x1D210
#define TXGBE_TSC_LSEC_PKTNUM0          0x1D214
#define TXGBE_TSC_LSEC_PKTNUM1          0x1D218
#define TXGBE_TSC_LSEC_KEY0(_n)         0x1D21C
#define TXGBE_TSC_LSEC_KEY1(_n)         0x1D22C
#define TXGBE_TSC_LSEC_UNTAG_PKT        0x1D23C
#define TXGBE_TSC_LSEC_ENC_PKT          0x1D240
#define TXGBE_TSC_LSEC_PROT_PKT         0x1D244
#define TXGBE_TSC_LSEC_ENC_OCTET        0x1D248
#define TXGBE_TSC_LSEC_PROT_OCTET       0x1D24C

/* IpSec Registers */
#define TXGBE_TSC_IPS_IDX               0x1D100
#define TXGBE_TSC_IPS_IDX_WT        0x80000000U
#define TXGBE_TSC_IPS_IDX_RD        0x40000000U
#define TXGBE_TSC_IPS_IDX_SD_IDX    0x0U /* */
#define TXGBE_TSC_IPS_IDX_EN        0x00000001U
#define TXGBE_TSC_IPS_SALT              0x1D104
#define TXGBE_TSC_IPS_KEY(i)            (0x1D108 + ((i) * 4))

/* 1588 */
#define TXGBE_TSC_1588_CTL              0x1D400 /* Tx Time Sync Control reg */
#define TXGBE_TSC_1588_STMPL            0x1D404 /* Tx timestamp value Low */
#define TXGBE_TSC_1588_STMPH            0x1D408 /* Tx timestamp value High */
#define TXGBE_TSC_1588_SYSTIML          0x1D40C /* System time register Low */
#define TXGBE_TSC_1588_SYSTIMH          0x1D410 /* System time register High */
#define TXGBE_TSC_1588_INC              0x1D414 /* Increment attributes reg */
#define TXGBE_TSC_1588_INC_IV(v)   (((v) & 0xFFFFFF))
#define TXGBE_TSC_1588_INC_IP(v)   (((v) & 0xFF) << 24)
#define TXGBE_TSC_1588_INC_IVP(v, p)  \
				(((v) & 0xFFFFFF) | TXGBE_TSC_1588_INC_IP(p))

#define TXGBE_TSC_1588_ADJL         0x1D418 /* Time Adjustment Offset reg Low */
#define TXGBE_TSC_1588_ADJH         0x1D41C /* Time Adjustment Offset reg High*/
/* 1588 fields */
#define TXGBE_TSC_1588_CTL_VALID    0x00000001U /* Tx timestamp valid */
#define TXGBE_TSC_1588_CTL_ENABLED  0x00000010U /* Tx timestamping enabled */

/********************************* RSEC **************************************/
/* general rsec */
#define TXGBE_RSC_CTL                   0x17000
#define TXGBE_RSC_ST                    0x17004
/* general rsec fields */
#define TXGBE_RSC_CTL_SECRX_DIS         0x00000001U
#define TXGBE_RSC_CTL_RX_DIS            0x00000002U
#define TXGBE_RSC_CTL_CRC_STRIP         0x00000004U
#define TXGBE_RSC_CTL_IV_MSK_EN         0x00000008U
#define TXGBE_RSC_CTL_SAVE_MAC_ERR      0x00000040U
#define TXGBE_RSC_ST_RSEC_RDY           0x00000001U
#define TXGBE_RSC_ST_RSEC_OFLD_DIS      0x00000002U
#define TXGBE_RSC_ST_ECC_RXERR          0x00000004U

/* link sec */
#define TXGBE_RSC_LSEC_CAP              0x17200
#define TXGBE_RSC_LSEC_CTL              0x17204
#define TXGBE_RSC_LSEC_SCI_L            0x17208
#define TXGBE_RSC_LSEC_SCI_H            0x1720C
#define TXGBE_RSC_LSEC_SA0              0x17210
#define TXGBE_RSC_LSEC_SA1              0x17214
#define TXGBE_RSC_LSEC_PKNUM0           0x17218
#define TXGBE_RSC_LSEC_PKNUM1           0x1721C
#define TXGBE_RSC_LSEC_KEY0(_n)         0x17220
#define TXGBE_RSC_LSEC_KEY1(_n)         0x17230
#define TXGBE_RSC_LSEC_UNTAG_PKT        0x17240
#define TXGBE_RSC_LSEC_DEC_OCTET        0x17244
#define TXGBE_RSC_LSEC_VLD_OCTET        0x17248
#define TXGBE_RSC_LSEC_BAD_PKT          0x1724C
#define TXGBE_RSC_LSEC_NOSCI_PKT        0x17250
#define TXGBE_RSC_LSEC_UNSCI_PKT        0x17254
#define TXGBE_RSC_LSEC_UNCHK_PKT        0x17258
#define TXGBE_RSC_LSEC_DLY_PKT          0x1725C
#define TXGBE_RSC_LSEC_LATE_PKT         0x17260
#define TXGBE_RSC_LSEC_OK_PKT(_n)       0x17264
#define TXGBE_RSC_LSEC_INV_PKT(_n)      0x17274
#define TXGBE_RSC_LSEC_BADSA_PKT        0x1727C
#define TXGBE_RSC_LSEC_INVSA_PKT        0x17280

/* ipsec */
#define TXGBE_RSC_IPS_IDX               0x17100
#define TXGBE_RSC_IPS_IDX_WT        0x80000000U
#define TXGBE_RSC_IPS_IDX_RD        0x40000000U
#define TXGBE_RSC_IPS_IDX_TB_IDX    0x0U /* */
#define TXGBE_RSC_IPS_IDX_TB_IP     0x00000002U
#define TXGBE_RSC_IPS_IDX_TB_SPI    0x00000004U
#define TXGBE_RSC_IPS_IDX_TB_KEY    0x00000006U
#define TXGBE_RSC_IPS_IDX_EN        0x00000001U
#define TXGBE_RSC_IPS_IP(i)             (0x17104 + ((i) * 4))
#define TXGBE_RSC_IPS_SPI               0x17114
#define TXGBE_RSC_IPS_IP_IDX            0x17118
#define TXGBE_RSC_IPS_KEY(i)            (0x1711C + ((i) * 4))
#define TXGBE_RSC_IPS_SALT              0x1712C
#define TXGBE_RSC_IPS_MODE              0x17130
#define TXGBE_RSC_IPS_MODE_IPV6         0x00000010
#define TXGBE_RSC_IPS_MODE_DEC          0x00000008
#define TXGBE_RSC_IPS_MODE_ESP          0x00000004
#define TXGBE_RSC_IPS_MODE_AH           0x00000002
#define TXGBE_RSC_IPS_MODE_VALID        0x00000001

/************************************** ETH PHY ******************************/
#define TXGBE_XPCS_IDA_ADDR    0x13000
#define TXGBE_XPCS_IDA_DATA    0x13004
#define TXGBE_ETHPHY_IDA_ADDR  0x13008
#define TXGBE_ETHPHY_IDA_DATA  0x1300C

/************************************** MNG ********************************/
#define TXGBE_MNG_FW_SM         0x1E000
#define TXGBE_MNG_SW_SM         0x1E004
#define TXGBE_MNG_SWFW_SYNC     0x1E008
#define TXGBE_MNG_MBOX          0x1E100
#define TXGBE_MNG_MBOX_CTL      0x1E044
#define TXGBE_MNG_OS2BMC_CNT    0x1E094
#define TXGBE_MNG_BMC2OS_CNT    0x1E090

/* Firmware Semaphore Register */
#define TXGBE_MNG_FW_SM_MODE_MASK       0xE
#define TXGBE_MNG_FW_SM_TS_ENABLED      0x1
/* SW Semaphore Register bitmasks */
#define TXGBE_MNG_SW_SM_SM              0x00000001U /* software Semaphore */

/* SW_FW_SYNC definitions */
#define TXGBE_MNG_SWFW_SYNC_SW_PHY      0x0001
#define TXGBE_MNG_SWFW_SYNC_SW_FLASH    0x0008
#define TXGBE_MNG_SWFW_SYNC_SW_MB       0x0004

#define TXGBE_MNG_MBOX_CTL_SWRDY        0x1
#define TXGBE_MNG_MBOX_CTL_SWACK        0x2
#define TXGBE_MNG_MBOX_CTL_FWRDY        0x4
#define TXGBE_MNG_MBOX_CTL_FWACK        0x8

/************************************* ETH MAC *****************************/
#define TXGBE_MAC_TX_CFG                0x11000
#define TXGBE_MAC_RX_CFG                0x11004
#define TXGBE_MAC_PKT_FLT               0x11008
#define TXGBE_MAC_PKT_FLT_PR            (0x1) /* promiscuous mode */
#define TXGBE_MAC_PKT_FLT_RA            (0x80000000) /* receive all */
#define TXGBE_MAC_WDG_TIMEOUT           0x1100C
#define TXGBE_MAC_RX_FLOW_CTRL          0x11090
#define TXGBE_MAC_ADDRESS0_HIGH         0x11300
#define TXGBE_MAC_ADDRESS0_LOW          0x11304

#define TXGBE_MAC_TX_CFG_TE             0x00000001U
#define TXGBE_MAC_TX_CFG_SPEED_MASK     0x60000000U
#define TXGBE_MAC_TX_CFG_SPEED_10G      0x00000000U
#define TXGBE_MAC_TX_CFG_SPEED_1G       0x60000000U
#define TXGBE_MAC_RX_CFG_RE             0x00000001U
#define TXGBE_MAC_RX_CFG_JE             0x00000100U
#define TXGBE_MAC_RX_CFG_LM             0x00000400U
#define TXGBE_MAC_WDG_TIMEOUT_PWE       0x00000100U
#define TXGBE_MAC_WDG_TIMEOUT_WTO_MASK  0x0000000FU
#define TXGBE_MAC_WDG_TIMEOUT_WTO_DELTA 2

#define TXGBE_MAC_RX_FLOW_CTRL_RFE      0x00000001U /* receive fc enable */
#define TXGBE_MAC_RX_FLOW_CTRL_PFCE     0x00000100U /* pfc enable */

#define TXGBE_MSCA                      0x11200
#define TXGBE_MSCA_RA(v)                ((0xFFFF & (v)))
#define TXGBE_MSCA_PA(v)                ((0x1F & (v)) << 16)
#define TXGBE_MSCA_DA(v)                ((0x1F & (v)) << 21)
#define TXGBE_MSCC                      0x11204
#define TXGBE_MSCC_DATA(v)              ((0xFFFF & (v)))
#define TXGBE_MSCC_CMD(v)               ((0x3 & (v)) << 16)
enum TXGBE_MSCA_CMD_value {
	TXGBE_MSCA_CMD_RSV = 0,
	TXGBE_MSCA_CMD_WRITE,
	TXGBE_MSCA_CMD_POST_READ,
	TXGBE_MSCA_CMD_READ,
};

#define TXGBE_MSCC_SADDR                ((0x1U) << 18)
#define TXGBE_MSCC_CR(v)                ((0x8U & (v)) << 19)
#define TXGBE_MSCC_BUSY                 ((0x1U) << 22)

/* EEE registers */

/* statistic */
#define TXGBE_MAC_LXONRXC               0x11E0C
#define TXGBE_MAC_LXOFFRXC              0x11988
#define TXGBE_MAC_PXONRXC(_i)           (0x11E30 + ((_i) * 4)) /* 8 of these */
#define TXGBE_MAC_PXOFFRXC              0x119DC
#define TXGBE_RX_BC_FRAMES_GOOD_LOW     0x11918
#define TXGBE_RX_CRC_ERROR_FRAMES_LOW   0x11928
#define TXGBE_RX_LEN_ERROR_FRAMES_LOW   0x11978
#define TXGBE_RX_UNDERSIZE_FRAMES_GOOD  0x11938
#define TXGBE_RX_OVERSIZE_FRAMES_GOOD   0x1193C
#define TXGBE_RX_FRAME_CNT_GOOD_BAD_LOW 0x11900
#define TXGBE_TX_FRAME_CNT_GOOD_BAD_LOW 0x1181C
#define TXGBE_TX_MC_FRAMES_GOOD_LOW     0x1182C
#define TXGBE_TX_BC_FRAMES_GOOD_LOW     0x11824
#define TXGBE_MMC_CONTROL               0x11800
#define TXGBE_MMC_CONTROL_RSTONRD       0x4 /* reset on read */
#define TXGBE_MMC_CONTROL_UP            0x700

/********************************* BAR registers ***************************/
/* Interrupt Registers */
#define TXGBE_BME_CTL				0x12020
#define TXGBE_PX_MISC_IC                        0x100
#define TXGBE_PX_MISC_ICS                       0x104
#define TXGBE_PX_MISC_IEN                       0x108
#define TXGBE_PX_MISC_IVAR                      0x4FC
#define TXGBE_PX_GPIE                           0x118
#define TXGBE_PX_ISB_ADDR_L                     0x160
#define TXGBE_PX_ISB_ADDR_H                     0x164
#define TXGBE_PX_TCP_TIMER                      0x170
#define TXGBE_PX_ITRSEL                         0x180
#define TXGBE_PX_IC(_i)                         (0x120 + (_i) * 4)
#define TXGBE_PX_ICS(_i)                        (0x130 + (_i) * 4)
#define TXGBE_PX_IMS(_i)                        (0x140 + (_i) * 4)
#define TXGBE_PX_IMC(_i)                        (0x150 + (_i) * 4)
#define TXGBE_PX_IVAR(_i)                       (0x500 + (_i) * 4)
#define TXGBE_PX_ITR(_i)                        (0x200 + (_i) * 4)
#define TXGBE_PX_TRANSACTION_PENDING            0x168
#define TXGBE_PX_INTA                           0x110

/* Interrupt register bitmasks */
/* Extended Interrupt Cause Read */
#define TXGBE_PX_MISC_IC_ETH_LKDN       0x00000100U /* eth link down */
#define TXGBE_PX_MISC_IC_DEV_RST        0x00000400U /* device reset event */
#define TXGBE_PX_MISC_IC_TIMESYNC       0x00000800U /* time sync */
#define TXGBE_PX_MISC_IC_STALL          0x00001000U /* trans or recv path is stalled */
#define TXGBE_PX_MISC_IC_LINKSEC        0x00002000U /* Tx LinkSec require key exchange */
#define TXGBE_PX_MISC_IC_RX_MISS        0x00004000U /* Packet Buffer Overrun */
#define TXGBE_PX_MISC_IC_FLOW_DIR       0x00008000U /* FDir Exception */
#define TXGBE_PX_MISC_IC_I2C            0x00010000U /* I2C interrupt */
#define TXGBE_PX_MISC_IC_ETH_EVENT      0x00020000U /* err reported by MAC except eth link down */
#define TXGBE_PX_MISC_IC_ETH_LK         0x00040000U /* link up */
#define TXGBE_PX_MISC_IC_ETH_AN         0x00080000U /* link auto-nego done */
#define TXGBE_PX_MISC_IC_INT_ERR        0x00100000U /* integrity error */
#define TXGBE_PX_MISC_IC_SPI            0x00200000U /* SPI interface */
#define TXGBE_PX_MISC_IC_VF_MBOX        0x00800000U /* VF-PF message box */
#define TXGBE_PX_MISC_IC_GPIO           0x04000000U /* GPIO interrupt */
#define TXGBE_PX_MISC_IC_PCIE_REQ_ERR   0x08000000U /* pcie request error int */
#define TXGBE_PX_MISC_IC_OVER_HEAT      0x10000000U /* overheat detection */
#define TXGBE_PX_MISC_IC_PROBE_MATCH    0x20000000U /* probe match */
#define TXGBE_PX_MISC_IC_MNG_HOST_MBOX  0x40000000U /* mng mailbox */
#define TXGBE_PX_MISC_IC_TIMER          0x80000000U /* tcp timer */

/* Extended Interrupt Cause Set */
#define TXGBE_PX_MISC_ICS_ETH_LKDN      0x00000100U
#define TXGBE_PX_MISC_ICS_DEV_RST       0x00000400U
#define TXGBE_PX_MISC_ICS_TIMESYNC      0x00000800U
#define TXGBE_PX_MISC_ICS_STALL         0x00001000U
#define TXGBE_PX_MISC_ICS_LINKSEC       0x00002000U
#define TXGBE_PX_MISC_ICS_RX_MISS       0x00004000U
#define TXGBE_PX_MISC_ICS_FLOW_DIR      0x00008000U
#define TXGBE_PX_MISC_ICS_I2C           0x00010000U
#define TXGBE_PX_MISC_ICS_ETH_EVENT     0x00020000U
#define TXGBE_PX_MISC_ICS_ETH_LK        0x00040000U
#define TXGBE_PX_MISC_ICS_ETH_AN        0x00080000U
#define TXGBE_PX_MISC_ICS_INT_ERR       0x00100000U
#define TXGBE_PX_MISC_ICS_SPI           0x00200000U
#define TXGBE_PX_MISC_ICS_VF_MBOX       0x00800000U
#define TXGBE_PX_MISC_ICS_GPIO          0x04000000U
#define TXGBE_PX_MISC_ICS_PCIE_REQ_ERR  0x08000000U
#define TXGBE_PX_MISC_ICS_OVER_HEAT     0x10000000U
#define TXGBE_PX_MISC_ICS_PROBE_MATCH   0x20000000U
#define TXGBE_PX_MISC_ICS_MNG_HOST_MBOX 0x40000000U
#define TXGBE_PX_MISC_ICS_TIMER         0x80000000U

/* Extended Interrupt Enable Set */
#define TXGBE_PX_MISC_IEN_ETH_LKDN      0x00000100U
#define TXGBE_PX_MISC_IEN_DEV_RST       0x00000400U
#define TXGBE_PX_MISC_IEN_TIMESYNC      0x00000800U
#define TXGBE_PX_MISC_IEN_STALL         0x00001000U
#define TXGBE_PX_MISC_IEN_LINKSEC       0x00002000U
#define TXGBE_PX_MISC_IEN_RX_MISS       0x00004000U
#define TXGBE_PX_MISC_IEN_FLOW_DIR      0x00008000U
#define TXGBE_PX_MISC_IEN_I2C           0x00010000U
#define TXGBE_PX_MISC_IEN_ETH_EVENT     0x00020000U
#define TXGBE_PX_MISC_IEN_ETH_LK        0x00040000U
#define TXGBE_PX_MISC_IEN_ETH_AN        0x00080000U
#define TXGBE_PX_MISC_IEN_INT_ERR       0x00100000U
#define TXGBE_PX_MISC_IEN_SPI           0x00200000U
#define TXGBE_PX_MISC_IEN_VF_MBOX       0x00800000U
#define TXGBE_PX_MISC_IEN_GPIO          0x04000000U
#define TXGBE_PX_MISC_IEN_PCIE_REQ_ERR  0x08000000U
#define TXGBE_PX_MISC_IEN_OVER_HEAT     0x10000000U
#define TXGBE_PX_MISC_IEN_PROBE_MATCH   0x20000000U
#define TXGBE_PX_MISC_IEN_MNG_HOST_MBOX 0x40000000U
#define TXGBE_PX_MISC_IEN_TIMER         0x80000000U

#define TXGBE_PX_MISC_IEN_MASK ( \
				TXGBE_PX_MISC_IEN_ETH_LKDN | \
				TXGBE_PX_MISC_IEN_DEV_RST | \
				TXGBE_PX_MISC_IEN_ETH_EVENT | \
				TXGBE_PX_MISC_IEN_ETH_LK | \
				TXGBE_PX_MISC_IEN_ETH_AN | \
				TXGBE_PX_MISC_IEN_INT_ERR | \
				TXGBE_PX_MISC_IEN_VF_MBOX | \
				TXGBE_PX_MISC_IEN_GPIO | \
				TXGBE_PX_MISC_IEN_MNG_HOST_MBOX | \
				TXGBE_PX_MISC_IEN_STALL | \
				TXGBE_PX_MISC_IEN_PCIE_REQ_ERR | \
				TXGBE_PX_MISC_IEN_TIMER)

/* General purpose Interrupt Enable */
#define TXGBE_PX_GPIE_MODEL             0x00000001U
#define TXGBE_PX_GPIE_IMEN              0x00000002U
#define TXGBE_PX_GPIE_LL_INTERVAL       0x000000F0U
#define TXGBE_PX_GPIE_RSC_DELAY         0x00000700U

/* Interrupt Vector Allocation Registers */
#define TXGBE_PX_IVAR_REG_NUM              64
#define TXGBE_PX_IVAR_ALLOC_VAL            0x80 /* Interrupt Allocation valid */

#define TXGBE_MAX_INT_RATE              500000
#define TXGBE_MIN_INT_RATE              980
#define TXGBE_MAX_EITR                  0x00000FF8U
#define TXGBE_MIN_EITR                  8
#define TXGBE_PX_ITR_ITR_INT_MASK       0x00000FF8U
#define TXGBE_PX_ITR_LLI_CREDIT         0x001f0000U
#define TXGBE_PX_ITR_LLI_MOD            0x00008000U
#define TXGBE_PX_ITR_CNT_WDIS           0x80000000U
#define TXGBE_PX_ITR_ITR_CNT            0x0FE00000U

/* transmit DMA Registers */
#define TXGBE_PX_TR_BAL(_i)     (0x03000 + ((_i) * 0x40))
#define TXGBE_PX_TR_BAH(_i)     (0x03004 + ((_i) * 0x40))
#define TXGBE_PX_TR_WP(_i)      (0x03008 + ((_i) * 0x40))
#define TXGBE_PX_TR_RP(_i)      (0x0300C + ((_i) * 0x40))
#define TXGBE_PX_TR_CFG(_i)     (0x03010 + ((_i) * 0x40))
/* Transmit Config masks */
#define TXGBE_PX_TR_CFG_ENABLE          (1) /* Ena specific Tx Queue */
#define TXGBE_PX_TR_CFG_TR_SIZE_SHIFT   1 /* tx desc number per ring */
#define TXGBE_PX_TR_CFG_SWFLSH          BIT(26) /* Tx Desc. wr-bk flushing */
#define TXGBE_PX_TR_CFG_WTHRESH_SHIFT   16 /* shift to WTHRESH bits */
#define TXGBE_PX_TR_CFG_THRE_SHIFT      8

#define TXGBE_PX_TR_RPn(q_per_pool, vf_number, vf_q_index) \
		(TXGBE_PX_TR_RP((q_per_pool) * (vf_number) + (vf_q_index)))
#define TXGBE_PX_TR_WPn(q_per_pool, vf_number, vf_q_index) \
		(TXGBE_PX_TR_WP((q_per_pool) * (vf_number) + (vf_q_index)))

/* Receive DMA Registers */
#define TXGBE_PX_RR_BAL(_i)             (0x01000 + ((_i) * 0x40))
#define TXGBE_PX_RR_BAH(_i)             (0x01004 + ((_i) * 0x40))
#define TXGBE_PX_RR_WP(_i)              (0x01008 + ((_i) * 0x40))
#define TXGBE_PX_RR_RP(_i)              (0x0100C + ((_i) * 0x40))
#define TXGBE_PX_RR_CFG(_i)             (0x01010 + ((_i) * 0x40))
/* PX_RR_CFG bit definitions */
#define TXGBE_PX_RR_CFG_RR_SIZE_SHIFT           1
#define TXGBE_PX_RR_CFG_BSIZEPKT_SHIFT          2 /* so many KBs */
#define TXGBE_PX_RR_CFG_BSIZEHDRSIZE_SHIFT      6 /* 64byte resolution (>> 6)
						   * + at bit 8 offset (<< 12)
						   *  = (<< 6)
						   */
#define TXGBE_PX_RR_CFG_DROP_EN         0x40000000U
#define TXGBE_PX_RR_CFG_VLAN            0x80000000U
#define TXGBE_PX_RR_CFG_RSC             0x20000000U
#define TXGBE_PX_RR_CFG_CNTAG           0x10000000U
#define TXGBE_PX_RR_CFG_RSC_CNT_MD      0x08000000U
#define TXGBE_PX_RR_CFG_SPLIT_MODE      0x04000000U
#define TXGBE_PX_RR_CFG_STALL           0x02000000U
#define TXGBE_PX_RR_CFG_MAX_RSCBUF_1    0x00000000U
#define TXGBE_PX_RR_CFG_MAX_RSCBUF_4    0x00800000U
#define TXGBE_PX_RR_CFG_MAX_RSCBUF_8    0x01000000U
#define TXGBE_PX_RR_CFG_MAX_RSCBUF_16   0x01800000U
#define TXGBE_PX_RR_CFG_RR_THER         0x00070000U
#define TXGBE_PX_RR_CFG_RR_THER_SHIFT   16

#define TXGBE_PX_RR_CFG_RR_HDR_SZ       0x0000F000U
#define TXGBE_PX_RR_CFG_RR_BUF_SZ       0x00000F00U
#define TXGBE_PX_RR_CFG_RR_SZ           0x0000007EU
#define TXGBE_PX_RR_CFG_RR_EN           0x00000001U

/* statistic */
#define TXGBE_PX_MPRC(_i)               (0x1020 + ((_i) * 64))
#define TXGBE_VX_GPRC(_i)               (0x01014 + (0x40 * (_i)))
#define TXGBE_VX_GPTC(_i)               (0x03014 + (0x40 * (_i)))
#define TXGBE_VX_GORC_LSB(_i)           (0x01018 + (0x40 * (_i)))
#define TXGBE_VX_GORC_MSB(_i)           (0x0101C + (0x40 * (_i)))
#define TXGBE_VX_GOTC_LSB(_i)           (0x03018 + (0x40 * (_i)))
#define TXGBE_VX_GOTC_MSB(_i)           (0x0301C + (0x40 * (_i)))
#define TXGBE_VX_MPRC(_i)               (0x01020 + (0x40 * (_i)))

#define TXGBE_PX_GPRC                   0x12504
#define TXGBE_PX_GPTC                   0x18308

#define TXGBE_PX_GORC_LSB               0x12508
#define TXGBE_PX_GORC_MSB               0x1250C

#define TXGBE_PX_GOTC_LSB               0x1830C
#define TXGBE_PX_GOTC_MSB               0x18310

/************************************* Stats registers ************************/
#define TXGBE_FCCRC         0x15160 /* Num of Good Eth CRC w/ Bad FC CRC */
#define TXGBE_FCOERPDC      0x12514 /* FCoE Rx Packets Dropped Count */
#define TXGBE_FCLAST        0x12518 /* FCoE Last Error Count */
#define TXGBE_FCOEPRC       0x15164 /* Number of FCoE Packets Received */
#define TXGBE_FCOEDWRC      0x15168 /* Number of FCoE DWords Received */
#define TXGBE_FCOEPTC       0x18318 /* Number of FCoE Packets Transmitted */
#define TXGBE_FCOEDWTC      0x1831C /* Number of FCoE DWords Transmitted */

/*************************** Flash region definition *************************/
/* EEC Register */
#define TXGBE_EEC_SK            0x00000001U /* EEPROM Clock */
#define TXGBE_EEC_CS            0x00000002U /* EEPROM Chip Select */
#define TXGBE_EEC_DI            0x00000004U /* EEPROM Data In */
#define TXGBE_EEC_DO            0x00000008U /* EEPROM Data Out */
#define TXGBE_EEC_FWE_MASK      0x00000030U /* FLASH Write Enable */
#define TXGBE_EEC_FWE_DIS       0x00000010U /* Disable FLASH writes */
#define TXGBE_EEC_FWE_EN        0x00000020U /* Enable FLASH writes */
#define TXGBE_EEC_FWE_SHIFT     4
#define TXGBE_EEC_REQ           0x00000040U /* EEPROM Access Request */
#define TXGBE_EEC_GNT           0x00000080U /* EEPROM Access Grant */
#define TXGBE_EEC_PRES          0x00000100U /* EEPROM Present */
#define TXGBE_EEC_ARD           0x00000200U /* EEPROM Auto Read Done */
#define TXGBE_EEC_FLUP          0x00800000U /* Flash update command */
#define TXGBE_EEC_SEC1VAL       0x02000000U /* Sector 1 Valid */
#define TXGBE_EEC_FLUDONE       0x04000000U /* Flash update done */
/* EEPROM Addressing bits based on type (0-small, 1-large) */
#define TXGBE_EEC_ADDR_SIZE     0x00000400U
#define TXGBE_EEC_SIZE          0x00007800U /* EEPROM Size */
#define TXGBE_EERD_MAX_ADDR     0x00003FFFU /* EERD allows 14 bits for addr. */

#define TXGBE_EEC_SIZE_SHIFT            11
#define TXGBE_EEPROM_WORD_SIZE_SHIFT    6
#define TXGBE_EEPROM_OPCODE_BITS        8

/* FLA Register */
#define TXGBE_FLA_LOCKED        0x00000040U

/* Part Number String Length */
#define TXGBE_PBANUM_LENGTH     32

/* Checksum and EEPROM pointers */
#define TXGBE_PBANUM_PTR_GUARD          0xFAFA
#define TXGBE_EEPROM_CHECKSUM           0x2F
#define TXGBE_EEPROM_SUM                0xBABA
#define TXGBE_ATLAS0_CONFIG_PTR         0x04
#define TXGBE_PHY_PTR                   0x04
#define TXGBE_ATLAS1_CONFIG_PTR         0x05
#define TXGBE_OPTION_ROM_PTR            0x05
#define TXGBE_PCIE_GENERAL_PTR          0x06
#define TXGBE_PCIE_CONFIG0_PTR          0x07
#define TXGBE_PCIE_CONFIG1_PTR          0x08
#define TXGBE_CORE0_PTR                 0x09
#define TXGBE_CORE1_PTR                 0x0A
#define TXGBE_MAC0_PTR                  0x0B
#define TXGBE_MAC1_PTR                  0x0C
#define TXGBE_CSR0_CONFIG_PTR           0x0D
#define TXGBE_CSR1_CONFIG_PTR           0x0E
#define TXGBE_PCIE_ANALOG_PTR           0x02
#define TXGBE_SHADOW_RAM_SIZE           0x4000
#define TXGBE_TXGBE_PCIE_GENERAL_SIZE   0x24
#define TXGBE_PCIE_CONFIG_SIZE          0x08
#define TXGBE_EEPROM_LAST_WORD          0x800
#define TXGBE_FW_PTR                    0x0F
#define TXGBE_PBANUM0_PTR               0x05
#define TXGBE_PBANUM1_PTR               0x06
#define TXGBE_ALT_MAC_ADDR_PTR          0x37
#define TXGBE_FREE_SPACE_PTR            0x3E
#define TXGBE_SW_REGION_PTR             0x1C

#define TXGBE_SAN_MAC_ADDR_PTR          0x18
#define TXGBE_DEVICE_CAPS               0x1C
#define TXGBE_EEPROM_VERSION_L          0x1D
#define TXGBE_EEPROM_VERSION_H          0x1E
#define TXGBE_ISCSI_BOOT_CONFIG         0x07

#define TXGBE_SERIAL_NUMBER_MAC_ADDR    0x11
#define TXGBE_MAX_MSIX_VECTORS_SAPPHIRE 0x40

/* MSI-X capability fields masks */
#define TXGBE_PCIE_MSIX_TBL_SZ_MASK     0x7FF

/* Legacy EEPROM word offsets */
#define TXGBE_ISCSI_BOOT_CAPS           0x0033
#define TXGBE_ISCSI_SETUP_PORT_0        0x0030
#define TXGBE_ISCSI_SETUP_PORT_1        0x0034

/* EEPROM Commands - SPI */
#define TXGBE_EEPROM_MAX_RETRY_SPI      5000 /* Max wait 5ms for RDY signal */
#define TXGBE_EEPROM_STATUS_RDY_SPI     0x01
#define TXGBE_EEPROM_READ_OPCODE_SPI    0x03  /* EEPROM read opcode */
#define TXGBE_EEPROM_WRITE_OPCODE_SPI   0x02  /* EEPROM write opcode */
#define TXGBE_EEPROM_A8_OPCODE_SPI      0x08  /* opcode bit-3 = addr bit-8 */
#define TXGBE_EEPROM_WREN_OPCODE_SPI    0x06  /* EEPROM set Write Ena latch */
/* EEPROM reset Write Enable latch */
#define TXGBE_EEPROM_WRDI_OPCODE_SPI        0x04
#define TXGBE_EEPROM_RDSR_OPCODE_SPI        0x05  /* EEPROM read Status reg */
#define TXGBE_EEPROM_WRSR_OPCODE_SPI        0x01  /* EEPROM write Status reg */
#define TXGBE_EEPROM_ERASE4K_OPCODE_SPI     0x20  /* EEPROM ERASE 4KB */
#define TXGBE_EEPROM_ERASE64K_OPCODE_SPI    0xD8  /* EEPROM ERASE 64KB */
#define TXGBE_EEPROM_ERASE256_OPCODE_SPI    0xDB  /* EEPROM ERASE 256B */

/* EEPROM Read Register */
#define TXGBE_EEPROM_RW_REG_DATA        16 /* data offset in EEPROM read reg */
#define TXGBE_EEPROM_RW_REG_DONE        2 /* Offset to READ done bit */
#define TXGBE_EEPROM_RW_REG_START       1 /* First bit to start operation */
#define TXGBE_EEPROM_RW_ADDR_SHIFT      2 /* Shift to the address bits */
#define TXGBE_NVM_POLL_WRITE            1 /* Flag for polling for wr complete */
#define TXGBE_NVM_POLL_READ             0 /* Flag for polling for rd complete */

#define NVM_INIT_CTRL_3                 0x38
#define NVM_INIT_CTRL_3_LPLU            0x8
#define NVM_INIT_CTRL_3_D10GMP_PORT0    0x40
#define NVM_INIT_CTRL_3_D10GMP_PORT1    0x100

#define TXGBE_ETH_LENGTH_OF_ADDRESS     6

#define TXGBE_EEPROM_PAGE_SIZE_MAX      128
#define TXGBE_EEPROM_RD_BUFFER_MAX_COUNT        256 /* words rd in burst */
#define TXGBE_EEPROM_WR_BUFFER_MAX_COUNT        256 /* words wr in burst */
#define TXGBE_EEPROM_CTRL_2             1 /* EEPROM CTRL word 2 */
#define TXGBE_EEPROM_CCD_BIT            2

#ifndef TXGBE_EEPROM_GRANT_ATTEMPTS
#define TXGBE_EEPROM_GRANT_ATTEMPTS     1000 /* EEPROM attempts to gain grant */
#endif

#ifndef TXGBE_EERD_EEWR_ATTEMPTS
/* Number of 5 microseconds we wait for EERD read and
 * EERW write to complete
 */
#define TXGBE_EERD_EEWR_ATTEMPTS        100000
#endif

#ifndef TXGBE_FLUDONE_ATTEMPTS
/* # attempts we wait for flush update to complete */
#define TXGBE_FLUDONE_ATTEMPTS          20000
#endif

#define TXGBE_PCIE_CTRL2                0x5   /* PCIe Control 2 Offset */
#define TXGBE_PCIE_CTRL2_DUMMY_ENABLE   0x8   /* Dummy Function Enable */
#define TXGBE_PCIE_CTRL2_LAN_DISABLE    0x2   /* LAN PCI Disable */
#define TXGBE_PCIE_CTRL2_DISABLE_SELECT 0x1   /* LAN Disable Select */

#define TXGBE_SAN_MAC_ADDR_PORT0_OFFSET         0x0
#define TXGBE_SAN_MAC_ADDR_PORT1_OFFSET         0x3
#define TXGBE_DEVICE_CAPS_ALLOW_ANY_SFP         0x1
#define TXGBE_DEVICE_CAPS_FCOE_OFFLOADS         0x2
#define TXGBE_FW_LESM_PARAMETERS_PTR            0x2
#define TXGBE_FW_LESM_STATE_1                   0x1
#define TXGBE_FW_LESM_STATE_ENABLED             0x8000 /* LESM Enable bit */
#define TXGBE_FW_PASSTHROUGH_PATCH_CONFIG_PTR   0x4
#define TXGBE_FW_PATCH_VERSION_4                0x7
#define TXGBE_FCOE_IBA_CAPS_BLK_PTR             0x33 /* iSCSI/FCOE block */
#define TXGBE_FCOE_IBA_CAPS_FCOE                0x20 /* FCOE flags */
#define TXGBE_ISCSI_FCOE_BLK_PTR                0x17 /* iSCSI/FCOE block */
#define TXGBE_ISCSI_FCOE_FLAGS_OFFSET           0x0 /* FCOE flags */
#define TXGBE_ISCSI_FCOE_FLAGS_ENABLE           0x1 /* FCOE flags enable bit */
#define TXGBE_ALT_SAN_MAC_ADDR_BLK_PTR          0x17 /* Alt. SAN MAC block */
#define TXGBE_ALT_SAN_MAC_ADDR_CAPS_OFFSET      0x0 /* Alt SAN MAC capability */
#define TXGBE_ALT_SAN_MAC_ADDR_PORT0_OFFSET     0x1 /* Alt SAN MAC 0 offset */
#define TXGBE_ALT_SAN_MAC_ADDR_PORT1_OFFSET     0x4 /* Alt SAN MAC 1 offset */
#define TXGBE_ALT_SAN_MAC_ADDR_WWNN_OFFSET      0x7 /* Alt WWNN prefix offset */
#define TXGBE_ALT_SAN_MAC_ADDR_WWPN_OFFSET      0x8 /* Alt WWPN prefix offset */
#define TXGBE_ALT_SAN_MAC_ADDR_CAPS_SANMAC      0x0 /* Alt SAN MAC exists */
#define TXGBE_ALT_SAN_MAC_ADDR_CAPS_ALTWWN      0x1 /* Alt WWN base exists */
#define TXGBE_DEVICE_CAPS_WOL_PORT0_1   0x4 /* WoL supported on ports 0 & 1 */
#define TXGBE_DEVICE_CAPS_WOL_PORT0     0x8 /* WoL supported on port 0 */
#define TXGBE_DEVICE_CAPS_WOL_MASK      0xC /* Mask for WoL capabilities */

/******************************** PCI Bus Info *******************************/
#define TXGBE_PCI_DEVICE_STATUS         0xAA
#define TXGBE_PCI_DEVICE_STATUS_TRANSACTION_PENDING     0x0020
#define TXGBE_PCI_LINK_STATUS           0xB2
#define TXGBE_PCI_DEVICE_CONTROL2       0xC8
#define TXGBE_PCI_LINK_WIDTH            0x3F0
#define TXGBE_PCI_LINK_WIDTH_1          0x10
#define TXGBE_PCI_LINK_WIDTH_2          0x20
#define TXGBE_PCI_LINK_WIDTH_4          0x40
#define TXGBE_PCI_LINK_WIDTH_8          0x80
#define TXGBE_PCI_LINK_SPEED            0xF
#define TXGBE_PCI_LINK_SPEED_2500       0x1
#define TXGBE_PCI_LINK_SPEED_5000       0x2
#define TXGBE_PCI_LINK_SPEED_8000       0x3
#define TXGBE_PCI_HEADER_TYPE_REGISTER  0x0E
#define TXGBE_PCI_HEADER_TYPE_MULTIFUNC 0x80
#define TXGBE_PCI_DEVICE_CONTROL2_16ms  0x0005

#define TXGBE_PCIDEVCTRL2_RELAX_ORDER_OFFSET    4
#define TXGBE_PCIDEVCTRL2_RELAX_ORDER_MASK      \
				(0x0001 << TXGBE_PCIDEVCTRL2_RELAX_ORDER_OFFSET)
#define TXGBE_PCIDEVCTRL2_RELAX_ORDER_ENABLE    \
				(0x01 << TXGBE_PCIDEVCTRL2_RELAX_ORDER_OFFSET)

#define TXGBE_PCIDEVCTRL2_TIMEO_MASK    0xf
#define TXGBE_PCIDEVCTRL2_16_32ms_def   0x0
#define TXGBE_PCIDEVCTRL2_50_100us      0x1
#define TXGBE_PCIDEVCTRL2_1_2ms         0x2
#define TXGBE_PCIDEVCTRL2_16_32ms       0x5
#define TXGBE_PCIDEVCTRL2_65_130ms      0x6
#define TXGBE_PCIDEVCTRL2_260_520ms     0x9
#define TXGBE_PCIDEVCTRL2_1_2s          0xa
#define TXGBE_PCIDEVCTRL2_4_8s          0xd
#define TXGBE_PCIDEVCTRL2_17_34s        0xe

/****************** Manageablility Host Interface defines ********************/
#define TXGBE_HI_MAX_BLOCK_BYTE_LENGTH  256 /* Num of bytes in range */
#define TXGBE_HI_MAX_BLOCK_DWORD_LENGTH 64 /* Num of dwords in range */
#define TXGBE_HI_COMMAND_TIMEOUT        5000 /* Process HI command limit */

/* CEM Support */
#define FW_CEM_HDR_LEN                  0x4
#define FW_CEM_CMD_DRIVER_INFO          0xDD
#define FW_CEM_CMD_DRIVER_INFO_LEN      0x5
#define FW_CEM_CMD_RESERVED             0X0
#define FW_CEM_MAX_RETRIES              3
#define FW_CEM_RESP_STATUS_SUCCESS      0x1
#define FW_READ_SHADOW_RAM_CMD          0x31
#define FW_READ_SHADOW_RAM_LEN          0x6
#define FW_WRITE_SHADOW_RAM_CMD         0x33
#define FW_WRITE_SHADOW_RAM_LEN         0xA /* 8 plus 1 WORD to write */
#define FW_DEFAULT_CHECKSUM             0xFF /* checksum always 0xFF */
#define FW_NVM_DATA_OFFSET              3
#define FW_MAX_READ_BUFFER_SIZE         244
#define FW_RESET_CMD                    0xDF
#define FW_RESET_LEN                    0x2
#define FW_DW_OPEN_NOTIFY               0xE9
#define FW_DW_CLOSE_NOTIFY              0xEA

#define TXGBE_CHECKSUM_CAP_ST_PASS      0x80658383
#define TXGBE_CHECKSUM_CAP_ST_FAIL      0x70657376

/* Host Interface Command Structures */
struct txgbe_hic_hdr {
	u8 cmd;
	u8 buf_len;
	union {
		u8 cmd_resv;
		u8 ret_status;
	} cmd_or_resp;
	u8 checksum;
};

struct txgbe_hic_hdr2_req {
	u8 cmd;
	u8 buf_lenh;
	u8 buf_lenl;
	u8 checksum;
};

struct txgbe_hic_hdr2_rsp {
	u8 cmd;
	u8 buf_lenl;
	u8 buf_lenh_status;     /* 7-5: high bits of buf_len, 4-0: status */
	u8 checksum;
};

union txgbe_hic_hdr2 {
	struct txgbe_hic_hdr2_req req;
	struct txgbe_hic_hdr2_rsp rsp;
};

struct txgbe_hic_drv_info {
	struct txgbe_hic_hdr hdr;
	u8 port_num;
	u8 ver_sub;
	u8 ver_build;
	u8 ver_min;
	u8 ver_maj;
	u8 pad; /* end spacing to ensure length is mult. of dword */
	u16 pad2; /* end spacing to ensure length is mult. of dword2 */
};

/* These need to be dword aligned */
struct txgbe_hic_read_shadow_ram {
	union txgbe_hic_hdr2 hdr;
	u32 address;
	u16 length;
	u16 pad2;
	u16 data;
	u16 pad3;
};

struct txgbe_hic_write_shadow_ram {
	union txgbe_hic_hdr2 hdr;
	u32 address;
	u16 length;
	u16 pad2;
	u16 data;
	u16 pad3;
};

struct txgbe_hic_reset {
	struct txgbe_hic_hdr hdr;
	u16 lan_id;
	u16 reset_type;
};

/* Number of 100 microseconds we wait for PCI Express master disable */
#define TXGBE_PCI_MASTER_DISABLE_TIMEOUT        800

/* Autonegotiation advertised speeds */
typedef u32 txgbe_autoneg_advertised;
/* Link speed */
#define TXGBE_LINK_SPEED_UNKNOWN        0
#define TXGBE_LINK_SPEED_100_FULL       1
#define TXGBE_LINK_SPEED_1GB_FULL       2
#define TXGBE_LINK_SPEED_10GB_FULL      4
#define TXGBE_LINK_SPEED_10_FULL        8
#define TXGBE_LINK_SPEED_AUTONEG  (TXGBE_LINK_SPEED_100_FULL | \
				   TXGBE_LINK_SPEED_1GB_FULL | \
				   TXGBE_LINK_SPEED_10GB_FULL | \
				   TXGBE_LINK_SPEED_10_FULL)

/* Physical layer type */
typedef u32 txgbe_physical_layer;
#define TXGBE_PHYSICAL_LAYER_UNKNOWN            0
#define TXGBE_PHYSICAL_LAYER_10GBASE_T          0x0001
#define TXGBE_PHYSICAL_LAYER_1000BASE_T         0x0002
#define TXGBE_PHYSICAL_LAYER_100BASE_TX         0x0004
#define TXGBE_PHYSICAL_LAYER_SFP_PLUS_CU        0x0008
#define TXGBE_PHYSICAL_LAYER_10GBASE_LR         0x0010
#define TXGBE_PHYSICAL_LAYER_10GBASE_LRM        0x0020
#define TXGBE_PHYSICAL_LAYER_10GBASE_SR         0x0040
#define TXGBE_PHYSICAL_LAYER_10GBASE_KX4        0x0080
#define TXGBE_PHYSICAL_LAYER_1000BASE_KX        0x0200
#define TXGBE_PHYSICAL_LAYER_1000BASE_BX        0x0400
#define TXGBE_PHYSICAL_LAYER_10GBASE_KR         0x0800
#define TXGBE_PHYSICAL_LAYER_10GBASE_XAUI       0x1000
#define TXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA      0x2000
#define TXGBE_PHYSICAL_LAYER_1000BASE_SX        0x4000

enum txgbe_eeprom_type {
	txgbe_eeprom_uninitialized = 0,
	txgbe_eeprom_spi,
	txgbe_flash,
	txgbe_eeprom_none /* No NVM support */
};

enum txgbe_phy_type {
	txgbe_phy_unknown = 0,
	txgbe_phy_none,
	txgbe_phy_tn,
	txgbe_phy_aq,
	txgbe_phy_cu_unknown,
	txgbe_phy_qt,
	txgbe_phy_xaui,
	txgbe_phy_nl,
	txgbe_phy_sfp_passive_tyco,
	txgbe_phy_sfp_passive_unknown,
	txgbe_phy_sfp_active_unknown,
	txgbe_phy_sfp_avago,
	txgbe_phy_sfp_ftl,
	txgbe_phy_sfp_ftl_active,
	txgbe_phy_sfp_unknown,
	txgbe_phy_sfp_intel,
	txgbe_phy_sfp_unsupported, /*Enforce bit set with unsupported module*/
	txgbe_phy_generic
};

/* SFP+ module type IDs:
 *
 * ID   Module Type
 * =============
 * 0    SFP_DA_CU
 * 1    SFP_SR
 * 2    SFP_LR
 * 3    SFP_DA_CU_CORE0
 * 4    SFP_DA_CU_CORE1
 * 5    SFP_SR/LR_CORE0
 * 6    SFP_SR/LR_CORE1
 */
enum txgbe_sfp_type {
	txgbe_sfp_type_da_cu = 0,
	txgbe_sfp_type_sr = 1,
	txgbe_sfp_type_lr = 2,
	txgbe_sfp_type_da_cu_core0 = 3,
	txgbe_sfp_type_da_cu_core1 = 4,
	txgbe_sfp_type_srlr_core0 = 5,
	txgbe_sfp_type_srlr_core1 = 6,
	txgbe_sfp_type_da_act_lmt_core0 = 7,
	txgbe_sfp_type_da_act_lmt_core1 = 8,
	txgbe_sfp_type_1g_cu_core0 = 9,
	txgbe_sfp_type_1g_cu_core1 = 10,
	txgbe_sfp_type_1g_sx_core0 = 11,
	txgbe_sfp_type_1g_sx_core1 = 12,
	txgbe_sfp_type_1g_lx_core0 = 13,
	txgbe_sfp_type_1g_lx_core1 = 14,
	txgbe_sfp_type_not_present = 0xFFFE,
	txgbe_sfp_type_unknown = 0xFFFF
};

enum txgbe_media_type {
	txgbe_media_type_unknown = 0,
	txgbe_media_type_fiber,
	txgbe_media_type_copper,
	txgbe_media_type_backplane,
	txgbe_media_type_virtual
};

/* PCI bus types */
enum txgbe_bus_type {
	txgbe_bus_type_unknown = 0,
	txgbe_bus_type_pci,
	txgbe_bus_type_pcix,
	txgbe_bus_type_pci_express,
	txgbe_bus_type_internal,
	txgbe_bus_type_reserved
};

/* PCI bus speeds */
enum txgbe_bus_speed {
	txgbe_bus_speed_unknown	= 0,
	txgbe_bus_speed_33	= 33,
	txgbe_bus_speed_66	= 66,
	txgbe_bus_speed_100	= 100,
	txgbe_bus_speed_120	= 120,
	txgbe_bus_speed_133	= 133,
	txgbe_bus_speed_2500	= 2500,
	txgbe_bus_speed_5000	= 5000,
	txgbe_bus_speed_8000	= 8000,
	txgbe_bus_speed_reserved
};

/* PCI bus widths */
enum txgbe_bus_width {
	txgbe_bus_width_unknown	= 0,
	txgbe_bus_width_pcie_x1	= 1,
	txgbe_bus_width_pcie_x2	= 2,
	txgbe_bus_width_pcie_x4	= 4,
	txgbe_bus_width_pcie_x8	= 8,
	txgbe_bus_width_32	= 32,
	txgbe_bus_width_64	= 64,
	txgbe_bus_width_reserved
};

struct txgbe_addr_filter_info {
	u32 num_mc_addrs;
	u32 rar_used_count;
	u32 mta_in_use;
	u32 overflow_promisc;
	bool user_set_promisc;
};

/* Bus parameters */
struct txgbe_bus_info {
	enum txgbe_bus_speed speed;
	enum txgbe_bus_width width;
	enum txgbe_bus_type type;

	u16 func;
	u16 lan_id;
};

/* forward declaration */
struct txgbe_hw;

/* Function pointer table */
struct txgbe_eeprom_operations {
	s32 (*init_params)(struct txgbe_hw *hw);
	s32 (*read)(struct txgbe_hw *hw, u16 offset, u16 *data);
	s32 (*read_buffer)(struct txgbe_hw *hw,
			   u16 offset, u16 words, u16 *data);
	s32 (*validate_checksum)(struct txgbe_hw *hw, u16 *checksum_val);
	s32 (*calc_checksum)(struct txgbe_hw *hw);
};

struct txgbe_mac_operations {
	s32 (*init_hw)(struct txgbe_hw *hw);
	s32 (*reset_hw)(struct txgbe_hw *hw);
	s32 (*start_hw)(struct txgbe_hw *hw);
	s32 (*clear_hw_cntrs)(struct txgbe_hw *hw);
	enum txgbe_media_type (*get_media_type)(struct txgbe_hw *hw);
	s32 (*get_mac_addr)(struct txgbe_hw *hw, u8 *mac_addr);
	s32 (*get_san_mac_addr)(struct txgbe_hw *hw, u8 *san_mac_addr);
	s32 (*get_wwn_prefix)(struct txgbe_hw *hw, u16 *wwnn_prefix,
			      u16 *wwpn_prefix);
	s32 (*stop_adapter)(struct txgbe_hw *hw);
	s32 (*get_bus_info)(struct txgbe_hw *hw);
	s32 (*set_lan_id)(struct txgbe_hw *hw);
	s32 (*acquire_swfw_sync)(struct txgbe_hw *hw, u32 mask);
	s32 (*release_swfw_sync)(struct txgbe_hw *hw, u32 mask);

	/* Link */
	s32 (*disable_tx_laser)(struct txgbe_hw *hw);
	s32 (*enable_tx_laser)(struct txgbe_hw *hw);
	s32 (*flap_tx_laser)(struct txgbe_hw *hw);
	s32 (*setup_link)(struct txgbe_hw *hw, u32 speed,
			  bool autoneg_wait_to_complete);
	s32 (*setup_mac_link)(struct txgbe_hw *hw, u32 speed,
			      bool autoneg_wait_to_complete);
	s32 (*check_link)(struct txgbe_hw *hw, u32 *speed,
			  bool *link_up, bool link_up_wait_to_complete);
	s32 (*get_link_capabilities)(struct txgbe_hw *hw, u32 *speed,
				     bool *autoneg);
	s32 (*set_rate_select_speed)(struct txgbe_hw *hw, u32 speed);

	/* LED */
	s32 (*led_on)(struct txgbe_hw *hw, u32 index);
	s32 (*led_off)(struct txgbe_hw *hw, u32 index);

	/* RAR */
	s32 (*set_rar)(struct txgbe_hw *hw, u32 index, u8 *addr, u64 pools,
		       u32 enable_addr);
	s32 (*clear_rar)(struct txgbe_hw *hw, u32 index);
	s32 (*set_vmdq_san_mac)(struct txgbe_hw *hw, u32 vmdq);
	s32 (*clear_vmdq)(struct txgbe_hw *hw, u32 rar, u32 vmdq);
	s32 (*init_rx_addrs)(struct txgbe_hw *hw);
	s32 (*init_uta_tables)(struct txgbe_hw *hw);

	/* Manageability interface */
	s32 (*set_fw_drv_ver)(struct txgbe_hw *hw, u8 maj, u8 min,
			      u8 build, u8 ver);
	s32 (*init_thermal_sensor_thresh)(struct txgbe_hw *hw);
	s32 (*disable_rx)(struct txgbe_hw *hw);
};

struct txgbe_phy_operations {
	s32 (*identify)(struct txgbe_hw *hw);
	s32 (*identify_sfp)(struct txgbe_hw *hw);
	s32 (*init)(struct txgbe_hw *hw);
	s32 (*read_i2c_byte)(struct txgbe_hw *hw, u8 byte_offset,
			     u8 dev_addr, u8 *data);
	s32 (*read_i2c_eeprom)(struct txgbe_hw *hw, u8 byte_offset,
			       u8 *eeprom_data);
	s32 (*check_overtemp)(struct txgbe_hw *hw);
};

struct txgbe_eeprom_info {
	struct txgbe_eeprom_operations ops;
	enum txgbe_eeprom_type type;
	u32 semaphore_delay;
	u16 word_size;
	u16 sw_region_offset;
};

struct txgbe_mac_info {
	struct txgbe_mac_operations ops;
	u8 addr[TXGBE_ETH_LENGTH_OF_ADDRESS];
	u8 perm_addr[TXGBE_ETH_LENGTH_OF_ADDRESS];
	u8 san_addr[TXGBE_ETH_LENGTH_OF_ADDRESS];
	/* prefix for World Wide Node Name (WWNN) */
	u16 wwnn_prefix;
	/* prefix for World Wide Port Name (WWPN) */
	u16 wwpn_prefix;
	s32 mc_filter_type;
	u32 mcft_size;
	u32 num_rar_entries;
	u32 max_tx_queues;
	u32 max_rx_queues;
	u32 orig_sr_pcs_ctl2;
	u32 orig_sr_pma_mmd_ctl1;
	u32 orig_sr_an_mmd_ctl;
	u32 orig_sr_an_mmd_adv_reg2;
	u32 orig_vr_xs_or_pcs_mmd_digi_ctl1;
	u8  san_mac_rar_index;
	u16 max_msix_vectors;
	bool orig_link_settings_stored;
	bool autotry_restart;
	struct txgbe_thermal_sensor_data  thermal_sensor_data;
	bool set_lben;
};

struct txgbe_phy_info {
	struct txgbe_phy_operations ops;
	enum txgbe_phy_type type;
	enum txgbe_sfp_type sfp_type;
	enum txgbe_media_type media_type;
	u32 phy_semaphore_mask;
	txgbe_autoneg_advertised autoneg_advertised;
	bool multispeed_fiber;
	txgbe_physical_layer link_mode;
};

enum txgbe_reset_type {
	TXGBE_LAN_RESET = 0,
	TXGBE_SW_RESET,
	TXGBE_GLOBAL_RESET
};

enum txgbe_link_status {
	TXGBE_LINK_STATUS_NONE = 0,
	TXGBE_LINK_STATUS_KX,
	TXGBE_LINK_STATUS_KX4
};

struct txgbe_hw {
	u8 __iomem *hw_addr;
	struct txgbe_mac_info mac;
	struct txgbe_addr_filter_info addr_ctrl;
	struct txgbe_phy_info phy;
	struct txgbe_eeprom_info eeprom;
	struct txgbe_bus_info bus;
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;
	bool adapter_stopped;
	enum txgbe_reset_type reset_type;
	bool force_full_reset;
	enum txgbe_link_status link_status;
	u16 oem_ssid;
	u16 oem_svid;
};

#define TCALL(hw, func, args...) (((hw)->func) \
		? (hw)->func((hw), ##args) : TXGBE_NOT_IMPLEMENTED)

/* Error Codes */
#define TXGBE_ERR                                100
#define TXGBE_NOT_IMPLEMENTED                    0x7FFFFFFF
/* (-TXGBE_ERR, TXGBE_ERR): reserved for non-txgbe defined error code */
#define TXGBE_ERR_NOSUPP                        -(TXGBE_ERR + 0)
#define TXGBE_ERR_EEPROM                        -(TXGBE_ERR + 1)
#define TXGBE_ERR_EEPROM_CHECKSUM               -(TXGBE_ERR + 2)
#define TXGBE_ERR_PHY                           -(TXGBE_ERR + 3)
#define TXGBE_ERR_CONFIG                        -(TXGBE_ERR + 4)
#define TXGBE_ERR_PARAM                         -(TXGBE_ERR + 5)
#define TXGBE_ERR_MAC_TYPE                      -(TXGBE_ERR + 6)
#define TXGBE_ERR_UNKNOWN_PHY                   -(TXGBE_ERR + 7)
#define TXGBE_ERR_LINK_SETUP                    -(TXGBE_ERR + 8)
#define TXGBE_ERR_ADAPTER_STOPPED               -(TXGBE_ERR + 9)
#define TXGBE_ERR_INVALID_MAC_ADDR              -(TXGBE_ERR + 10)
#define TXGBE_ERR_DEVICE_NOT_SUPPORTED          -(TXGBE_ERR + 11)
#define TXGBE_ERR_MASTER_REQUESTS_PENDING       -(TXGBE_ERR + 12)
#define TXGBE_ERR_INVALID_LINK_SETTINGS         -(TXGBE_ERR + 13)
#define TXGBE_ERR_AUTONEG_NOT_COMPLETE          -(TXGBE_ERR + 14)
#define TXGBE_ERR_RESET_FAILED                  -(TXGBE_ERR + 15)
#define TXGBE_ERR_SWFW_SYNC                     -(TXGBE_ERR + 16)
#define TXGBE_ERR_PHY_ADDR_INVALID              -(TXGBE_ERR + 17)
#define TXGBE_ERR_I2C                           -(TXGBE_ERR + 18)
#define TXGBE_ERR_SFP_NOT_SUPPORTED             -(TXGBE_ERR + 19)
#define TXGBE_ERR_SFP_NOT_PRESENT               -(TXGBE_ERR + 20)
#define TXGBE_ERR_SFP_NO_INIT_SEQ_PRESENT       -(TXGBE_ERR + 21)
#define TXGBE_ERR_NO_SAN_ADDR_PTR               -(TXGBE_ERR + 22)
#define TXGBE_ERR_FDIR_REINIT_FAILED            -(TXGBE_ERR + 23)
#define TXGBE_ERR_EEPROM_VERSION                -(TXGBE_ERR + 24)
#define TXGBE_ERR_NO_SPACE                      -(TXGBE_ERR + 25)
#define TXGBE_ERR_OVERTEMP                      -(TXGBE_ERR + 26)
#define TXGBE_ERR_UNDERTEMP                     -(TXGBE_ERR + 27)
#define TXGBE_ERR_FC_NOT_NEGOTIATED             -(TXGBE_ERR + 28)
#define TXGBE_ERR_FC_NOT_SUPPORTED              -(TXGBE_ERR + 29)
#define TXGBE_ERR_SFP_SETUP_NOT_COMPLETE        -(TXGBE_ERR + 30)
#define TXGBE_ERR_PBA_SECTION                   -(TXGBE_ERR + 31)
#define TXGBE_ERR_INVALID_ARGUMENT              -(TXGBE_ERR + 32)
#define TXGBE_ERR_HOST_INTERFACE_COMMAND        -(TXGBE_ERR + 33)
#define TXGBE_ERR_OUT_OF_MEM                    -(TXGBE_ERR + 34)
#define TXGBE_ERR_FEATURE_NOT_SUPPORTED         -(TXGBE_ERR + 36)
#define TXGBE_ERR_EEPROM_PROTECTED_REGION       -(TXGBE_ERR + 37)
#define TXGBE_ERR_FDIR_CMD_INCOMPLETE           -(TXGBE_ERR + 38)
#define TXGBE_ERR_FLASH_LOADING_FAILED          -(TXGBE_ERR + 39)
#define TXGBE_ERR_XPCS_POWER_UP_FAILED          -(TXGBE_ERR + 40)
#define TXGBE_ERR_FW_RESP_INVALID               -(TXGBE_ERR + 41)
#define TXGBE_ERR_PHY_INIT_NOT_DONE             -(TXGBE_ERR + 42)
#define TXGBE_ERR_TIMEOUT                       -(TXGBE_ERR + 43)
#define TXGBE_ERR_TOKEN_RETRY                   -(TXGBE_ERR + 44)
#define TXGBE_ERR_REGISTER                      -(TXGBE_ERR + 45)
#define TXGBE_ERR_MBX                           -(TXGBE_ERR + 46)
#define TXGBE_ERR_MNG_ACCESS_FAILED             -(TXGBE_ERR + 47)

/**
 * register operations
 **/
/* read register */
#define TXGBE_DEAD_READ_RETRIES     10
#define TXGBE_DEAD_READ_REG         0xdeadbeefU
#define TXGBE_DEAD_READ_REG64       0xdeadbeefdeadbeefULL
#define TXGBE_FAILED_READ_REG       0xffffffffU
#define TXGBE_FAILED_READ_REG64     0xffffffffffffffffULL

static inline bool TXGBE_REMOVED(void __iomem *addr)
{
	return unlikely(!addr);
}

static inline u32
txgbe_rd32(u8 __iomem *base)
{
	return readl(base);
}

static inline u32
rd32(struct txgbe_hw *hw, u32 reg)
{
	u8 __iomem *base = READ_ONCE(hw->hw_addr);
	u32 val = TXGBE_FAILED_READ_REG;

	if (unlikely(!base))
		return val;

	val = txgbe_rd32(base + reg);

	return val;
}

#define rd32a(a, reg, offset) ( \
	rd32((a), (reg) + ((offset) << 2)))

static inline u32
rd32m(struct txgbe_hw *hw, u32 reg, u32 mask)
{
	u8 __iomem *base = READ_ONCE(hw->hw_addr);
	u32 val = TXGBE_FAILED_READ_REG;

	if (unlikely(!base))
		return val;

	val = txgbe_rd32(base + reg);
	if (unlikely(val == TXGBE_FAILED_READ_REG))
		return val;

	return val & mask;
}

/* write register */
static inline void
txgbe_wr32(u8 __iomem *base, u32 val)
{
	writel(val, base);
}

static inline void
wr32(struct txgbe_hw *hw, u32 reg, u32 val)
{
	u8 __iomem *base = READ_ONCE(hw->hw_addr);

	if (unlikely(!base))
		return;

	txgbe_wr32(base + reg, val);
}

#define wr32a(a, reg, off, val) \
	wr32((a), (reg) + ((off) << 2), (val))

static inline void
wr32m(struct txgbe_hw *hw, u32 reg, u32 mask, u32 field)
{
	u8 __iomem *base = READ_ONCE(hw->hw_addr);
	u32 val;

	if (unlikely(!base))
		return;

	val = txgbe_rd32(base + reg);
	if (unlikely(val == TXGBE_FAILED_READ_REG))
		return;

	val = ((val & ~mask) | (field & mask));
	txgbe_wr32(base + reg, val);
}

/* poll register */
#define TXGBE_I2C_TIMEOUT  1000
static inline s32
txgbe_po32m(struct txgbe_hw *hw, u32 reg, u32 mask,
	    u32 field, int usecs, int count)
{
	int loop;

	loop = (count ? count : (usecs + 9) / 10);
	usecs = (loop ? (usecs + loop - 1) / loop : 0);

	count = loop;
	do {
		u32 value = rd32(hw, reg);

		if ((value & mask) == (field & mask))
			break;

		if (loop-- <= 0)
			break;

		udelay(usecs);
	} while (true);

	return (count - loop <= count ? 0 : TXGBE_ERR_TIMEOUT);
}

#define TXGBE_WRITE_FLUSH(H) rd32(H, TXGBE_MIS_PWR)

#endif /* _TXGBE_TYPE_H_ */
