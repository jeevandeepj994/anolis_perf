/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2024 Beijing WangXun Technology Co., Ltd. */

#ifndef __TXGBE_VF_H__
#define __TXGBE_VF_H__

#include <linux/types.h>
#include <linux/netdevice.h>

#ifndef PCI_VENDOR_ID_WANGXUN
#define PCI_VENDOR_ID_WANGXUN                   0x8088
#endif

#define TXGBE_DEV_ID_SP1000_VF                  0x1000
#define TXGBE_DEV_ID_WX1820_VF                  0x2000

#define TXGBE_VF_MAX_TX_QUEUES  4
#define TXGBE_VF_MAX_RX_QUEUES  4

#define MAX_RX_QUEUES (TXGBE_VF_MAX_RX_QUEUES)
#define MAX_TX_QUEUES (TXGBE_VF_MAX_TX_QUEUES)

#define TXGBE_DEFAULT_TXD   128
#define TXGBE_DEFAULT_RXD   128

#define TXGBE_MAX_JUMBO_FRAME_SIZE        9432

#define TXGBE_VF_INIT_TIMEOUT           200
#define TXGBE_VF_PERMADDR_MSG_LEN       4
#define TXGBE_VF_IRQ_CLEAR_MASK         7

#define TXGBE_FW_VER_SIZE       32

#define TXGBE_VXCTRL                0x00008
#define TXGBE_VXMRQC                0x00078
#define TXGBE_VXICR                 0x00100
#define TXGBE_VXICS                 0x00104
#define TXGBE_VXIMS                 0x00108

#define TXGBE_VXCTRL_RST            BIT(0)

/* Receive Path */
#define TXGBE_VXRXDCTL_ENABLE     ((0x1) << 0)
#define TXGBE_VXRXDCTL(r)         (0x01010 + (0x40 * (r)))
#define TXGBE_VXRXDCTL_BUFSZ(f)   ((0xF & (f)) << 8)
#define TXGBE_VXRXDCTL_HDRSZ(f)   ((0xF & (f)) << 12)

/* Transmit Path */
#define TXGBE_VXTXDCTL(r)         (0x03010 + (0x40 * (r)))
#define TXGBE_VXTXDCTL_ENABLE     ((0x1) << 0)
#define TXGBE_VXTXDCTL_BUFLEN(f)  ((0x3F & (f)) << 1)
#define TXGBE_VXTXDCTL_PTHRESH(f) ((0xF & (f)) << 8)
#define TXGBE_VXTXDCTL_WTHRESH(f) ((0x7F & (f)) << 16)
#define TXGBE_VXTXDCTL_FLUSH      ((0x1) << 26)

/* board specific private data structure */
#define TXGBE_F_CAP_RX_CSUM             BIT(0)

#define TXGBE_VXGPRC(r)            (0x01014 + (0x40 * (r)))
#define TXGBE_VXGORC_LSB(r)        (0x01018 + (0x40 * (r)))
#define TXGBE_VXGORC_MSB(r)        (0x0101C + (0x40 * (r)))
#define TXGBE_VXMPRC(r)            (0x01020 + (0x40 * (r)))
#define TXGBE_VXGPTC(r)            (0x03014 + (0x40 * (r)))
#define TXGBE_VXGOTC_LSB(r)        (0x03018 + (0x40 * (r)))
#define TXGBE_VXGOTC_MSB(r)        (0x0301C + (0x40 * (r)))

#define TXGBE_VXSTATUS              0x00004
#define TXGBE_VXSTATUS_UP           BIT(0)
#define TXGBE_VXSTATUS_SPEED(g)     ((0x7 & (g)) >> 1)
#define TXGBE_VXSTATUS_SPEED_10G   (0x1)
#define TXGBE_VXSTATUS_SPEED_1G    (0x2)
#define TXGBE_VXSTATUS_SPEED_100M  (0x4)

#define TXGBE_VXMAILBOX         0x00600
#define TXGBE_VXMAILBOX_REQ     ((0x1) << 0) /* Request for PF Ready bit */
#define TXGBE_VXMAILBOX_ACK     ((0x1) << 1) /* Ack PF message received */
#define TXGBE_VXMAILBOX_VFU     ((0x1) << 2) /* VF owns the mailbox buffer */
#define TXGBE_VXMAILBOX_PFU     ((0x1) << 3) /* PF owns the mailbox buffer */
#define TXGBE_VXMAILBOX_PFSTS   ((0x1) << 4) /* PF wrote a message in the MB */
#define TXGBE_VXMAILBOX_PFACK   ((0x1) << 5) /* PF ack the previous VF msg */
#define TXGBE_VXMAILBOX_RSTI    ((0x1) << 6) /* PF has reset indication */
#define TXGBE_VXMAILBOX_RSTD    ((0x1) << 7) /* PF has indicated reset done */
#define TXGBE_VXMAILBOX_R2C_BITS (TXGBE_VXMAILBOX_RSTD |\
						TXGBE_VXMAILBOX_PFSTS | TXGBE_VXMAILBOX_PFACK)
#define TXGBE_VXMAILBOX_SIZE    (16 - 1)

#define TXGBE_VXMBMEM           0x00C00 /* 16*4B */

#define TXGBE_LINK_SPEED_100_FULL       0x0008
#define TXGBE_LINK_SPEED_1GB_FULL       0x0020
#define TXGBE_LINK_SPEED_10GB_FULL      0x0080

__maybe_unused static int txgbe_conf_size(int v, int mwidth, int uwidth)
{
	int _v = v;

	return (_v) == 2 << (mwidth) ? 0 : (_v) >> (uwidth);
}

#define txgbe_buf_len(v)    txgbe_conf_size(v, 13, 7)
#define txgbe_hdr_sz(v)     txgbe_conf_size(v, 10, 6)
#define txgbe_buf_sz(v)     txgbe_conf_size(v, 14, 10)
#define txgbe_pkt_thresh(v) txgbe_conf_size(v, 4, 0)

/* Supported Rx Buffer Sizes */
#define TXGBE_RXBUFFER_256    (256)    /* Used for packet split */
#define TXGBE_RXBUFFER_2048   (2048)
#define TXGBE_RXBUFFER_3072   (3072)
#define TXGBE_RX_HDR_SIZE TXGBE_RXBUFFER_256
#define TXGBE_RX_BUF_SIZE TXGBE_RXBUFFER_2048

enum txgbe_xcast_modes {
	TXGBE_XCAST_MODE_NONE = 0,
	TXGBE_XCAST_MODE_MULTI,
	TXGBE_XCAST_MODE_ALLMULTI,
	TXGBE_XCAST_MODE_PROMISC,
};

/* Error Codes:
 * (-256, 256): reserved for non-txgbe defined error code
 */
#define TXGBE_ERR_BASE (0x100)
enum txgbe_error {
	TXGBE_ERR_NULL = TXGBE_ERR_BASE, /* errline=__LINE__+errno-256 */
	TXGBE_ERR_NOSUPP,
	TXGBE_ERR_EEPROM,
	TXGBE_ERR_EEPROM_CHECKSUM,
	TXGBE_ERR_PHY,
	TXGBE_ERR_CONFIG,
	TXGBE_ERR_PARAM,
	TXGBE_ERR_MAC_TYPE,
	TXGBE_ERR_UNKNOWN_PHY,
	TXGBE_ERR_LINK_SETUP,
	TXGBE_ERR_ADAPTER_STOPPED,
	TXGBE_ERR_INVALID_MAC_ADDR,
	TXGBE_ERR_DEVICE_NOT_SUPPORTED,
	TXGBE_ERR_MASTER_REQUESTS_PENDING,
	TXGBE_ERR_INVALID_LINK_SETTINGS,
	TXGBE_ERR_AUTONEG_NOT_COMPLETE,
	TXGBE_ERR_RESET_FAILED,
	TXGBE_ERR_SWFW_SYNC,
	TXGBE_ERR_PHY_ADDR_INVALID,
	TXGBE_ERR_I2C,
	TXGBE_ERR_SFP_NOT_SUPPORTED,
	TXGBE_ERR_SFP_NOT_PRESENT,
	TXGBE_ERR_SFP_NO_INIT_SEQ_PRESENT,
	TXGBE_ERR_NO_SAN_ADDR_PTR,
	TXGBE_ERR_FDIR_REINIT_FAILED,
	TXGBE_ERR_EEPROM_VERSION,
	TXGBE_ERR_NO_SPACE,
	TXGBE_ERR_OVERTEMP,
	TXGBE_ERR_UNDERTEMP,
	TXGBE_ERR_FC_NOT_NEGOTIATED,
	TXGBE_ERR_FC_NOT_SUPPORTED,
	TXGBE_ERR_SFP_SETUP_NOT_COMPLETE,
	TXGBE_ERR_PBA_SECTION,
	TXGBE_ERR_INVALID_ARGUMENT,
	TXGBE_ERR_HOST_INTERFACE_COMMAND,
	TXGBE_ERR_OUT_OF_MEM,
	TXGBE_ERR_FEATURE_NOT_SUPPORTED,
	TXGBE_ERR_EEPROM_PROTECTED_REGION,
	TXGBE_ERR_FDIR_CMD_INCOMPLETE,
	TXGBE_ERR_FLASH_LOADING_FAILED,
	TXGBE_ERR_XPCS_POWER_UP_FAILED,
	TXGBE_ERR_FW_RESP_INVALID,
	TXGBE_ERR_PHY_INIT_NOT_DONE,
	TXGBE_ERR_TOKEN_RETRY,
	TXGBE_ERR_REG_TMOUT,
	TXGBE_ERR_REG_ACCESS,
	TXGBE_ERR_MBX,
};

#define TXGBE_ERR_NOSUPP                      (-TXGBE_ERR_NOSUPP)
#define TXGBE_ERR_EEPROM                      (-TXGBE_ERR_EEPROM)
#define TXGBE_ERR_EEPROM_CHECKSUM             (-TXGBE_ERR_EEPROM_CHECKSUM)
#define TXGBE_ERR_PHY                         (-TXGBE_ERR_PHY)
#define TXGBE_ERR_CONFIG                      (-TXGBE_ERR_CONFIG)
#define TXGBE_ERR_PARAM                       (-TXGBE_ERR_PARAM)
#define TXGBE_ERR_MAC_TYPE                    (-TXGBE_ERR_MAC_TYPE)
#define TXGBE_ERR_UNKNOWN_PHY                 (-TXGBE_ERR_UNKNOWN_PHY)
#define TXGBE_ERR_LINK_SETUP                  (-TXGBE_ERR_LINK_SETUP)
#define TXGBE_ERR_ADAPTER_STOPPED             (-TXGBE_ERR_ADAPTER_STOPPED)
#define TXGBE_ERR_INVALID_MAC_ADDR            (-TXGBE_ERR_INVALID_MAC_ADDR)
#define TXGBE_ERR_DEVICE_NOT_SUPPORTED        (-TXGBE_ERR_DEVICE_NOT_SUPPORTED)
#define TXGBE_ERR_MASTER_REQUESTS_PENDING     (-TXGBE_ERR_MASTER_REQUESTS_PENDING)
#define TXGBE_ERR_INVALID_LINK_SETTINGS       (-TXGBE_ERR_INVALID_LINK_SETTINGS)
#define TXGBE_ERR_AUTONEG_NOT_COMPLETE        (-TXGBE_ERR_AUTONEG_NOT_COMPLETE)
#define TXGBE_ERR_RESET_FAILED                (-TXGBE_ERR_RESET_FAILED)
#define TXGBE_ERR_SWFW_SYNC                   (-TXGBE_ERR_SWFW_SYNC)
#define TXGBE_ERR_PHY_ADDR_INVALID            (-TXGBE_ERR_PHY_ADDR_INVALID)
#define TXGBE_ERR_I2C                         (-TXGBE_ERR_I2C)
#define TXGBE_ERR_SFP_NOT_SUPPORTED           (-TXGBE_ERR_SFP_NOT_SUPPORTED)
#define TXGBE_ERR_SFP_NOT_PRESENT             (-TXGBE_ERR_SFP_NOT_PRESENT)
#define TXGBE_ERR_SFP_NO_INIT_SEQ_PRESENT     (-TXGBE_ERR_SFP_NO_INIT_SEQ_PRESENT)
#define TXGBE_ERR_NO_SAN_ADDR_PTR             (-TXGBE_ERR_NO_SAN_ADDR_PTR)
#define TXGBE_ERR_FDIR_REINIT_FAILED          (-TXGBE_ERR_FDIR_REINIT_FAILED)
#define TXGBE_ERR_EEPROM_VERSION              (-TXGBE_ERR_EEPROM_VERSION)
#define TXGBE_ERR_NO_SPACE                    (-TXGBE_ERR_NO_SPACE)
#define TXGBE_ERR_OVERTEMP                    (-TXGBE_ERR_OVERTEMP)
#define TXGBE_ERR_UNDERTEMP                   (-TXGBE_ERR_UNDERTEMP)
#define TXGBE_ERR_FC_NOT_NEGOTIATED           (-TXGBE_ERR_FC_NOT_NEGOTIATED)
#define TXGBE_ERR_FC_NOT_SUPPORTED            (-TXGBE_ERR_FC_NOT_SUPPORTED)
#define TXGBE_ERR_SFP_SETUP_NOT_COMPLETE      (-TXGBE_ERR_SFP_SETUP_NOT_COMPLETE)
#define TXGBE_ERR_PBA_SECTION                 (-TXGBE_ERR_PBA_SECTION)
#define TXGBE_ERR_INVALID_ARGUMENT            (-TXGBE_ERR_INVALID_ARGUMENT)
#define TXGBE_ERR_HOST_INTERFACE_COMMAND      (-TXGBE_ERR_HOST_INTERFACE_COMMAND)
#define TXGBE_ERR_OUT_OF_MEM                  (-TXGBE_ERR_OUT_OF_MEM)
#define TXGBE_ERR_FEATURE_NOT_SUPPORTED       (-TXGBE_ERR_FEATURE_NOT_SUPPORTED)
#define TXGBE_ERR_EEPROM_PROTECTED_REGION     (-TXGBE_ERR_EEPROM_PROTECTED_REGION)
#define TXGBE_ERR_FDIR_CMD_INCOMPLETE         (-TXGBE_ERR_FDIR_CMD_INCOMPLETE)
#define TXGBE_ERR_FLASH_LOADING_FAILED        (-TXGBE_ERR_FLASH_LOADING_FAILED)
#define TXGBE_ERR_XPCS_POWER_UP_FAILED        (-TXGBE_ERR_XPCS_POWER_UP_FAILED)
#define TXGBE_ERR_FW_RESP_INVALID             (-TXGBE_ERR_FW_RESP_INVALID)
#define TXGBE_ERR_PHY_INIT_NOT_DONE           (-TXGBE_ERR_PHY_INIT_NOT_DONE)
#define TXGBE_ERR_TOKEN_RETRY                 (-TXGBE_ERR_TOKEN_RETRY)
#define TXGBE_ERR_REG_TMOUT                   (-TXGBE_ERR_REG_TMOUT)
#define TXGBE_ERR_REG_ACCESS                  (-TXGBE_ERR_REG_ACCESS)
#define TXGBE_ERR_MBX                         (-TXGBE_ERR_MBX)

extern char txgbe_firmware_version[];

typedef u32 txgbe_link_speed;

struct txgbe_hw;

typedef u8* (*txgbe_mc_addr_itr) (struct txgbe_hw *hw, u8 **mc_addr_ptr, u32 *vmdq);

enum txbgevf_state_t {
	__TXGBE_TESTING,
	__TXGBE_RESETTING,
	__TXGBE_DOWN,
	__TXGBE_DISABLED,
	__TXGBE_REMOVING,
	__TXGBE_SERVICE_SCHED,
	__TXGBE_SERVICE_INITED,
	__TXGBE_RESET_REQUESTED,
	__TXGBE_QUEUE_RESET_REQUESTED,
};

enum txgbe_mac_type {
	txgbe_mac_unknown = 0,
	txgbe_mac_sp,
	txgbe_mac_sp_vf,
	txgbe_num_macs
};

struct txgbe_info {
	enum txgbe_mac_type     mac;
	unsigned int            flags;
};

enum txgbe_boards {
	board_sp_vf,
};

struct txgbe_mac_operations {
	s32 (*init_hw)(struct txgbe_hw *hw);
	s32 (*reset_hw)(struct txgbe_hw *hw);
	s32 (*start_hw)(struct txgbe_hw *hw);
	s32 (*get_mac_addr)(struct txgbe_hw *hw, u8 *mac_addr);
	s32 (*get_fw_version)(struct txgbe_hw *hw);

	/* Link */
	s32 (*check_link)(struct txgbe_hw *hw,
			  txgbe_link_speed *speed, bool *link_up, bool autoneg_wait_to_complete);

	/* RAR, Multicast, VLAN */
	s32 (*set_rar)(struct txgbe_hw *hw, u32 index, u8 *addr, u32 vmdq, u32 enable_addr);
	s32 (*set_uc_addr)(struct txgbe_hw *hw, u32 index, u8 *addr);

	s32 (*update_mc_addr_list)(struct txgbe_hw *hw, u8 *mc_addr_list,
				   u32 mc_addr_count, txgbe_mc_addr_itr next,
				 bool clear);
	s32 (*update_xcast_mode)(struct txgbe_hw *hw, int xcast_mode);
	s32 (*get_link_state)(struct txgbe_hw *hw, bool *link_state);
	s32 (*set_vfta)(struct txgbe_hw *hw, u32 vlan, u32 vind, bool vlan_on, bool vlvf_bypass);
};

struct txgbe_mac_info {
	struct txgbe_mac_operations ops;
	u8 addr[6];
	u8 perm_addr[6];

	enum txgbe_mac_type type;

	s32  mc_filter_type;

	bool get_link_status;
	u32  max_tx_queues;
	u32  max_rx_queues;
	u32  max_msix_vectors;
};

struct txgbe_mbx_operations {
	void (*init_params)(struct txgbe_hw *hw);
	s32  (*read)(struct txgbe_hw *hw, u32 *msg, u16 size, u16 mbx_id);
	s32  (*write)(struct txgbe_hw *hw, u32 *msg, u16 size, u16 mbx_id);
	s32  (*read_posted)(struct txgbe_hw *hw, u32 *msg, u16 size, u16 mbx_id);
	s32  (*write_posted)(struct txgbe_hw *hw, u32 *msg, u16 size, u16 mbx_id);
	s32  (*check_for_msg)(struct txgbe_hw *hw, u16 mbx_id);
	s32  (*check_for_ack)(struct txgbe_hw *hw, u16 mbx_id);
	s32  (*check_for_rst)(struct txgbe_hw *hw, u16 mbx_id);
};

struct txgbe_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct txgbe_mbx_info {
	struct txgbe_mbx_operations ops;
	struct txgbe_mbx_stats stats;
	u32 timeout;
	u32 udelay;
	u32 v2p_mailbox; /* buffered r2c bits */
	u16 size;
};

struct txgbe_hw {
	void *back;
	u16 *msg_enable;
	struct pci_dev *pdev;

	u8 __iomem *hw_addr;
	u8 __iomem *b4_addr;

	struct txgbe_mac_info mac;
	struct txgbe_mbx_info mbx;

	u16 device_id;
	u16 subsystem_vendor_id;
	u16 subsystem_device_id;
	u16 vendor_id;

	u8  revision_id;
	bool adapter_stopped;

	int api_version;

	u32 b4_buf[16];
};

struct txgbe_sw_stats {
	u64 tx_busy;
	u64 tx_restart_queue;
	u64 tx_timeout_count;
	u64 rx_csum_bad;
	u64 rx_no_dma_resources;
	u64 rx_alloc_page_failed;
	u64 rx_alloc_buff_failed;
};

struct txgbe_hw_stats {
	u64 gprc;
	u64 gptc;
	u64 gorc;
	u64 gotc;
	u64 mprc;
};
struct txgbe_adapter {
	u8 __iomem *io_addr;
	u8 __iomem *b4_addr;
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct txgbe_hw hw;
	unsigned long state;
	u32 *rss_key;

	/* statistic states */
	struct rtnl_link_stats64 net_stats;
	struct txgbe_sw_stats sw_stats;
	struct txgbe_hw_stats stats, last_stats, base_stats, reset_stats;
	struct txgbe_hw_stats reg_stats[MAX_TX_QUEUES], last_reg_stats[MAX_TX_QUEUES];

#define DEFAULT_DEBUG_LEVEL (0x7)
	u16 msg_enable;

	u32 flagsd; /* flags define: CAP */
	u16 bd_number;

	/* mailbox spin lock */
	spinlock_t mbx_lock;

	/* pf statstic spin lock */
	spinlock_t pf_count_lock;

	/* Tx hotpath */
	u16 tx_ring_count;
	u16 num_tx_queues;
	u16 tx_itr_setting;

	/* Rx hotpath */
	u16 rx_ring_count;
	u16 num_rx_queues;
	u16 rx_itr_setting;

	bool link_state;
};

__maybe_unused static struct net_device *txgbe_hw_to_netdev(const struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter =
		container_of(hw, struct txgbe_adapter, hw);
	return adapter->netdev;
}

#define  txgbevf_dbg(hw, fmt, arg...) \
	netdev_dbg(txgbe_hw_to_netdev(hw), fmt, ##arg)

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
txgbe_rd32(u8 __iomem *base, u32 reg)
{
	return readl(base + reg);
}

static inline u32
rd32(struct txgbe_hw *hw, u32 reg)
{
	u8 __iomem *base = READ_ONCE(hw->hw_addr);
	u32 val = TXGBE_FAILED_READ_REG;

	if (unlikely(!base))
		return val;

	val = txgbe_rd32(base, reg);

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

	val = txgbe_rd32(base, reg);
	if (unlikely(val == TXGBE_FAILED_READ_REG))
		return val;

	return val & mask;
}

/* write register */
static inline void
txgbe_wr32(u8 __iomem *base, u32 reg, u32 val)
{
	writel(val, base + reg);
}

static inline void
wr32(struct txgbe_hw *hw, u32 reg, u32 val)
{
	u8 __iomem *base = READ_ONCE(hw->hw_addr);

	if (unlikely(!base))
		return;

	txgbe_wr32(base, reg, val);
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

	val = txgbe_rd32(base, reg);
	if (unlikely(val == TXGBE_FAILED_READ_REG))
		return;

	val = ((val & ~mask) | (field & mask));
	txgbe_wr32(base, reg, val);
}

/* poll register */
#define TXGBE_MDIO_TIMEOUT 1000
#define TXGBE_I2C_TIMEOUT  1000
#define TXGBE_SPI_TIMEOUT  1000
static inline s32
po32m(struct txgbe_hw *hw, u32 reg, u32 mask, u32 field, u16 time, u16 loop)
{
	bool msec = false;

	if (time / loop > 1000 * MAX_UDELAY_MS) {
		msec = true;
		time /= 1000;
	}

	do {
		u32 val = rd32(hw, reg);

		if (val == TXGBE_FAILED_READ_REG)
			return TXGBE_ERR_REG_ACCESS;

		if (val != TXGBE_DEAD_READ_REG &&
		    (val & mask) == (field & mask))
			break;
		else if (--loop == 0)
			break;

		if (msec)
			mdelay(time);
		else
			udelay(time);
	} while (true);

	return (loop > 0 ? 0 : -TXGBE_ERR_REG_TMOUT);
}

#define txgbe_flush(a) rd32(a, TXGBE_VXSTATUS)

int txgbe_open(struct net_device *netdev);
int txgbe_close(struct net_device *netdev);
int txgbe_negotiate_api_version(struct txgbe_hw *hw, int api);
void txgbe_init_ops_vf(struct txgbe_hw *hw);

#endif
