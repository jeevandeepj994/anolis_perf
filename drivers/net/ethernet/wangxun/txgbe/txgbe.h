/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_H_
#define _TXGBE_H_

#include <net/ip.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/if_vlan.h>
#include <linux/sctp.h>
#include <linux/etherdevice.h>
#include <linux/timecounter.h>
#include <linux/clocksource.h>
#include <linux/aer.h>

#include "txgbe_type.h"

#ifndef MAX_REQUEST_SIZE
#define MAX_REQUEST_SIZE 256
#endif

/* Ether Types */
#define TXGBE_ETH_P_CNM                         0x22E7
#define TXGBE_ETH_P_LLDP                        0x88CC

/* TX/RX descriptor defines */
#define TXGBE_DEFAULT_TXD               512
#define TXGBE_DEFAULT_TX_WORK   256
#define TXGBE_MAX_TXD                   8192
#define TXGBE_MIN_TXD                   128

#if (PAGE_SIZE < 8192)
#define TXGBE_DEFAULT_RXD               512
#define TXGBE_DEFAULT_RX_WORK   256
#else
#define TXGBE_DEFAULT_RXD               256
#define TXGBE_DEFAULT_RX_WORK   128
#endif

#define TXGBE_MAX_RXD                   8192
#define TXGBE_MIN_RXD                   128

/* flow control */
#define TXGBE_DEFAULT_FCPAUSE   0xFFFF

/* Supported Rx Buffer Sizes */
#define TXGBE_RXBUFFER_256       256  /* Used for skb receive header */
#define TXGBE_RXBUFFER_2K       2048
#define TXGBE_RXBUFFER_3K       3072
#define TXGBE_RXBUFFER_4K       4096
#define TXGBE_MAX_RXBUFFER      16384  /* largest size for single descriptor */

/* NOTE: netdev_alloc_skb reserves up to 64 bytes, NET_IP_ALIGN means we
 * reserve 64 more, and skb_shared_info adds an additional 320 bytes more,
 * this adds up to 448 bytes of extra data.
 *
 * Since netdev_alloc_skb now allocates a page fragment we can use a value
 * of 256 and the resultant skb will have a truesize of 960 or less.
 */
#define TXGBE_RX_HDR_SIZE       TXGBE_RXBUFFER_256

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define TXGBE_RX_BUFFER_WRITE   16      /* Must be power of 2 */
#define TXGBE_RX_DMA_ATTR \
	(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

enum txgbe_tx_flags {
	/* cmd_type flags */
	TXGBE_TX_FLAGS_HW_VLAN  = 0x01,
	TXGBE_TX_FLAGS_TSO      = 0x02,
	TXGBE_TX_FLAGS_TSTAMP   = 0x04,

	/* olinfo flags */
	TXGBE_TX_FLAGS_CC       = 0x08,
	TXGBE_TX_FLAGS_IPV4     = 0x10,
	TXGBE_TX_FLAGS_CSUM     = 0x20,
	TXGBE_TX_FLAGS_OUTER_IPV4 = 0x100,
	TXGBE_TX_FLAGS_LINKSEC	= 0x200,
	TXGBE_TX_FLAGS_IPSEC    = 0x400,

	/* software defined flags */
	TXGBE_TX_FLAGS_SW_VLAN  = 0x40,
	TXGBE_TX_FLAGS_FCOE     = 0x80,
};

/* VLAN info */
#define TXGBE_TX_FLAGS_VLAN_MASK        0xffff0000
#define TXGBE_TX_FLAGS_VLAN_PRIO_MASK   0xe0000000
#define TXGBE_TX_FLAGS_VLAN_PRIO_SHIFT  29
#define TXGBE_TX_FLAGS_VLAN_SHIFT       16

#define TXGBE_MAX_RX_DESC_POLL          10

#define TXGBE_MAX_PF_MACVLANS           15

#define TXGBE_MAX_TXD_PWR       14
#define TXGBE_MAX_DATA_PER_TXD  BIT(TXGBE_MAX_TXD_PWR)

/* Tx Descriptors needed, worst case */
#define TXD_USE_COUNT(S)        DIV_ROUND_UP((S), TXGBE_MAX_DATA_PER_TXD)
#ifndef MAX_SKB_FRAGS
#define DESC_NEEDED     4
#elif (MAX_SKB_FRAGS < 16)
#define DESC_NEEDED     ((MAX_SKB_FRAGS * TXD_USE_COUNT(PAGE_SIZE)) + 4)
#else
#define DESC_NEEDED     (MAX_SKB_FRAGS + 4)
#endif

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer
 */
struct txgbe_tx_buffer {
	union txgbe_tx_desc *next_to_watch;
	struct sk_buff *skb;
	unsigned int bytecount;
	unsigned short gso_segs;
	__be16 protocol;
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
};

struct txgbe_rx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
	dma_addr_t page_dma;
	struct page *page;
	unsigned int page_offset;
};

struct txgbe_queue_stats {
	u64 packets;
	u64 bytes;
};

struct txgbe_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
};

struct txgbe_rx_queue_stats {
	u64 rsc_count;
	u64 rsc_flush;
	u64 non_eop_descs;
	u64 alloc_rx_page_failed;
	u64 alloc_rx_buff_failed;
	u64 csum_good_cnt;
	u64 csum_err;
};

enum txgbe_ring_state_t {
	__TXGBE_RX_BUILD_SKB_ENABLED,
	__TXGBE_TX_XPS_INIT_DONE,
	__TXGBE_TX_DETECT_HANG,
	__TXGBE_HANG_CHECK_ARMED,
	__TXGBE_RX_RSC_ENABLED,
};

struct txgbe_fwd_adapter {
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	struct txgbe_adapter *adapter;
};

#define ring_uses_build_skb(ring) \
	test_bit(__TXGBE_RX_BUILD_SKB_ENABLED, &(ring)->state)

#define check_for_tx_hang(ring) \
	test_bit(__TXGBE_TX_DETECT_HANG, &(ring)->state)
#define set_check_for_tx_hang(ring) \
	set_bit(__TXGBE_TX_DETECT_HANG, &(ring)->state)
#define clear_check_for_tx_hang(ring) \
	clear_bit(__TXGBE_TX_DETECT_HANG, &(ring)->state)
#define ring_is_rsc_enabled(ring) \
	test_bit(__TXGBE_RX_RSC_ENABLED, &(ring)->state)
#define set_ring_rsc_enabled(ring) \
	set_bit(__TXGBE_RX_RSC_ENABLED, &(ring)->state)
#define clear_ring_rsc_enabled(ring) \
	clear_bit(__TXGBE_RX_RSC_ENABLED, &(ring)->state)

struct txgbe_ring {
	struct txgbe_ring *next;        /* pointer to next ring in q_vector */
	struct txgbe_q_vector *q_vector; /* backpointer to host q_vector */
	struct net_device *netdev;      /* netdev ring belongs to */
	struct device *dev;             /* device for DMA mapping */
	struct txgbe_fwd_adapter *accel;
	void *desc;                     /* descriptor ring memory */
	union {
		struct txgbe_tx_buffer *tx_buffer_info;
		struct txgbe_rx_buffer *rx_buffer_info;
	};
	unsigned long state;
	u8 __iomem *tail;
	dma_addr_t dma;                 /* phys. address of descriptor ring */
	unsigned int size;              /* length in bytes */

	u16 count;                      /* amount of descriptors */

	u8 queue_index; /* needed for multiqueue queue management */
	u8 reg_idx;
	u16 next_to_use;
	u16 next_to_clean;
	u16 rx_buf_len;
	u16 next_to_alloc;
	struct txgbe_queue_stats stats;
	struct u64_stats_sync syncp;

	union {
		struct txgbe_tx_queue_stats tx_stats;
		struct txgbe_rx_queue_stats rx_stats;
	};
} ____cacheline_internodealigned_in_smp;

enum txgbe_ring_f_enum {
	RING_F_NONE = 0,
	RING_F_RSS,
	RING_F_ARRAY_SIZE  /* must be last in enum set */
};

#define TXGBE_MAX_RSS_INDICES           63
#define TXGBE_MAX_FDIR_INDICES          63

#define TXGBE_MAX_RX_QUEUES   (TXGBE_MAX_FDIR_INDICES + 1)
#define TXGBE_MAX_TX_QUEUES   (TXGBE_MAX_FDIR_INDICES + 1)

#define TXGBE_MAX_MACVLANS      32

struct txgbe_ring_feature {
	u16 limit;      /* upper limit on feature indices */
	u16 indices;    /* current value of indices */
	u16 mask;       /* Mask used for feature to ring mapping */
	u16 offset;     /* offset to start of feature */
};

static inline unsigned int txgbe_rx_bufsz(struct txgbe_ring __maybe_unused *ring)
{
#if MAX_SKB_FRAGS < 8
	return ALIGN(TXGBE_MAX_RXBUFFER / MAX_SKB_FRAGS, 1024);
#else
	return TXGBE_RXBUFFER_2K;
#endif
}

static inline unsigned int txgbe_rx_pg_order(struct txgbe_ring __maybe_unused *ring)
{
	return 0;
}

#define txgbe_rx_pg_size(_ring) (PAGE_SIZE << txgbe_rx_pg_order(_ring))

struct txgbe_ring_container {
	struct txgbe_ring *ring;        /* pointer to linked list of rings */
	unsigned int total_bytes;       /* total bytes processed this int */
	unsigned int total_packets;     /* total packets processed this int */
	u16 work_limit;                 /* total work allowed per interrupt */
	u8 count;                       /* total number of rings in vector */
	u8 itr;                         /* current ITR setting for ring */
};

/* iterator for handling rings in ring container */
#define txgbe_for_each_ring(pos, head) \
	for (pos = (head).ring; pos; pos = pos->next)

/* MAX_MSIX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
struct txgbe_q_vector {
	struct txgbe_adapter *adapter;
	int cpu;
	u16 v_idx;      /* index of q_vector within array, also used for
			 * finding the bit in EICR and friends that
			 * represents the vector for this ring
			 */
	u16 itr;        /* Interrupt throttle rate written to EITR */
	struct txgbe_ring_container rx, tx;

	struct napi_struct napi;
	cpumask_t affinity_mask;
	int numa_node;
	struct rcu_head rcu;    /* to avoid race with update stats on free */
	char name[IFNAMSIZ + 17];

	/* for dynamic allocation of rings associated with this q_vector */
	struct txgbe_ring ring[0] ____cacheline_internodealigned_in_smp;
};

/* microsecond values for various ITR rates shifted by 2 to fit itr register
 * with the first 3 bits reserved 0
 */
#define TXGBE_MIN_RSC_ITR       24
#define TXGBE_100K_ITR          40
#define TXGBE_20K_ITR           200
#define TXGBE_16K_ITR           248
#define TXGBE_12K_ITR           336

/* txgbe_test_staterr - tests bits in Rx descriptor status and error fields */
static inline __le32 txgbe_test_staterr(union txgbe_rx_desc *rx_desc,
					const u32 stat_err_bits)
{
	return rx_desc->wb.upper.status_error & cpu_to_le32(stat_err_bits);
}

/* txgbe_desc_unused - calculate if we have unused descriptors */
static inline u16 txgbe_desc_unused(struct txgbe_ring *ring)
{
	u16 ntc = ring->next_to_clean;
	u16 ntu = ring->next_to_use;

	return ((ntc > ntu) ? 0 : ring->count) + ntc - ntu - 1;
}

#define TXGBE_RX_DESC(R, i)     \
	(&(((union txgbe_rx_desc *)((R)->desc))[i]))
#define TXGBE_TX_DESC(R, i)     \
	(&(((union txgbe_tx_desc *)((R)->desc))[i]))
#define TXGBE_TX_CTXTDESC(R, i) \
	(&(((struct txgbe_tx_context_desc *)((R)->desc))[i]))

#define TXGBE_MAX_JUMBO_FRAME_SIZE      9432 /* max payload 9414 */

#define TCP_TIMER_VECTOR        0
#define OTHER_VECTOR    1
#define NON_Q_VECTORS   (OTHER_VECTOR + TCP_TIMER_VECTOR)

#define TXGBE_MAX_MSIX_Q_VECTORS_SAPPHIRE       64

struct txgbe_mac_addr {
	u8 addr[ETH_ALEN];
	u16 state; /* bitmask */
	u64 pools;
};

#define TXGBE_MAC_STATE_DEFAULT         0x1
#define TXGBE_MAC_STATE_MODIFIED        0x2
#define TXGBE_MAC_STATE_IN_USE          0x4

#define MAX_MSIX_Q_VECTORS      TXGBE_MAX_MSIX_Q_VECTORS_SAPPHIRE
#define MAX_MSIX_COUNT          TXGBE_MAX_MSIX_VECTORS_SAPPHIRE

#define MIN_MSIX_Q_VECTORS      1
#define MIN_MSIX_COUNT          (MIN_MSIX_Q_VECTORS + NON_Q_VECTORS)

/* default to trying for four seconds */
#define TXGBE_TRY_LINK_TIMEOUT  (4 * HZ)
#define TXGBE_SFP_POLL_JIFFIES  (2 * HZ)        /* SFP poll every 2 seconds */

/**
 * txgbe_adapter.flag
 **/
#define TXGBE_FLAG_NEED_LINK_UPDATE             BIT(0)
#define TXGBE_FLAG_NEED_LINK_CONFIG             BIT(1)
#define TXGBE_FLAG_MSI_ENABLED                  BIT(2)
#define TXGBE_FLAG_MSIX_ENABLED                 BIT(3)
#define TXGBE_FLAG_VXLAN_OFFLOAD_CAPABLE        BIT(4)
#define TXGBE_FLAG_VXLAN_OFFLOAD_ENABLE         BIT(5)

/**
 * txgbe_adapter.flag2
 **/
#define TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED     BIT(0)
#define TXGBE_FLAG2_SFP_NEEDS_RESET             BIT(1)
#define TXGBE_FLAG2_TEMP_SENSOR_EVENT           BIT(2)
#define TXGBE_FLAG2_PF_RESET_REQUESTED          BIT(3)
#define TXGBE_FLAG2_RESET_INTR_RECEIVED         BIT(4)
#define TXGBE_FLAG2_GLOBAL_RESET_REQUESTED      BIT(5)
#define TXGBE_FLAG2_RSC_CAPABLE                 BIT(6)
#define TXGBE_FLAG2_RSC_ENABLED                 BIT(7)
#define TXGBE_FLAG2_RSS_FIELD_IPV4_UDP          BIT(8)
#define TXGBE_FLAG2_RSS_FIELD_IPV6_UDP          BIT(9)
#define TXGBE_FLAG2_RSS_ENABLED                 BIT(10)

#define TXGBE_SET_FLAG(_input, _flag, _result) \
	((_flag <= _result) ? \
	 ((u32)(_input & _flag) * (_result / _flag)) : \
	 ((u32)(_input & _flag) / (_flag / _result)))

enum txgbe_isb_idx {
	TXGBE_ISB_HEADER,
	TXGBE_ISB_MISC,
	TXGBE_ISB_VEC0,
	TXGBE_ISB_VEC1,
	TXGBE_ISB_MAX
};

/* board specific private data structure */
struct txgbe_adapter {
	u8 __iomem *io_addr;
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;

	unsigned long state;

	/* Some features need tri-state capability,
	 * thus the additional *_CAPABLE flags.
	 */
	u32 flags;
	u32 flags2;
	/* Tx fast path data */
	int num_tx_queues;
	u16 tx_itr_setting;
	u16 tx_work_limit;

	/* Rx fast path data */
	int num_rx_queues;
	u16 rx_itr_setting;
	u16 rx_work_limit;

	/* TX */
	struct txgbe_ring *tx_ring[TXGBE_MAX_TX_QUEUES] ____cacheline_aligned_in_smp;

	u64 restart_queue;
	u64 lsc_int;
	u32 tx_timeout_count;

	/* RX */
	struct txgbe_ring *rx_ring[TXGBE_MAX_RX_QUEUES];
	u64 hw_csum_rx_error;
	u64 hw_csum_rx_good;
	u64 hw_rx_no_dma_resources;
	u64 rsc_total_count;
	u64 rsc_total_flush;
	u64 non_eop_descs;
	u32 alloc_rx_page_failed;
	u32 alloc_rx_buff_failed;

	struct txgbe_q_vector *q_vector[MAX_MSIX_Q_VECTORS];

	int num_q_vectors;      /* current number of q_vectors for device */
	int max_q_vectors;      /* upper limit of q_vectors for device */
	struct txgbe_ring_feature ring_feature[RING_F_ARRAY_SIZE];
	struct msix_entry *msix_entries;

	/* structs defined in txgbe_hw.h */
	struct txgbe_hw hw;
	u16 msg_enable;
	struct txgbe_hw_stats stats;

	u64 tx_busy;
	unsigned int tx_ring_count;
	unsigned int rx_ring_count;

	u32 link_speed;
	bool link_up;
	unsigned long sfp_poll_time;
	unsigned long link_check_timeout;

	struct timer_list service_timer;
	struct work_struct service_task;
	u32 atr_sample_rate;

	char eeprom_id[32];
	bool netdev_registered;
	u32 interrupt_event;

	struct txgbe_mac_addr *mac_table;

	__le16 vxlan_port;
	unsigned long fwd_bitmask; /* bitmask indicating in use pools */

#define TXGBE_MAX_RETA_ENTRIES 128
	u8 rss_indir_tbl[TXGBE_MAX_RETA_ENTRIES];
#define TXGBE_RSS_KEY_SIZE     40
	u32 *rss_key;

	/* misc interrupt status block */
	dma_addr_t isb_dma;
	u32 *isb_mem;
	u32 isb_tag[TXGBE_ISB_MAX];
};

static inline u32 txgbe_misc_isb(struct txgbe_adapter *adapter,
				 enum txgbe_isb_idx idx)
{
	u32 cur_tag = 0;

	cur_tag = adapter->isb_mem[TXGBE_ISB_HEADER];

	adapter->isb_tag[idx] = cur_tag;

	return adapter->isb_mem[idx];
}

enum txgbe_state_t {
	__TXGBE_TESTING,
	__TXGBE_RESETTING,
	__TXGBE_DOWN,
	__TXGBE_HANGING,
	__TXGBE_DISABLED,
	__TXGBE_REMOVING,
	__TXGBE_SERVICE_SCHED,
	__TXGBE_SERVICE_INITED,
	__TXGBE_IN_SFP_INIT,
	__TXGBE_PTP_RUNNING,
	__TXGBE_PTP_TX_IN_PROGRESS,
};

struct txgbe_cb {
	dma_addr_t dma;
	u16     append_cnt;      /* number of skb's appended */
	bool    page_released;
	bool    dma_released;
};

#define TXGBE_CB(skb) ((struct txgbe_cb *)(skb)->cb)

/* needed by txgbe_main.c */
void txgbe_service_event_schedule(struct txgbe_adapter *adapter);
void txgbe_assign_netdev_ops(struct net_device *netdev);

void txgbe_irq_disable(struct txgbe_adapter *adapter);
void txgbe_irq_enable(struct txgbe_adapter *adapter, bool queues, bool flush);
int txgbe_open(struct net_device *netdev);
int txgbe_close(struct net_device *netdev);
void txgbe_up(struct txgbe_adapter *adapter);
void txgbe_down(struct txgbe_adapter *adapter);
void txgbe_reinit_locked(struct txgbe_adapter *adapter);
void txgbe_reset(struct txgbe_adapter *adapter);
s32 txgbe_init_shared_code(struct txgbe_hw *hw);
void txgbe_disable_device(struct txgbe_adapter *adapter);
int txgbe_setup_rx_resources(struct txgbe_ring *rx_ring);
int txgbe_setup_tx_resources(struct txgbe_ring *tx_ring);
void txgbe_free_rx_resources(struct txgbe_ring *rx_ring);
void txgbe_free_tx_resources(struct txgbe_ring *tx_ring);
void txgbe_configure_rx_ring(struct txgbe_adapter *adapter,
			     struct txgbe_ring *ring);
void txgbe_configure_tx_ring(struct txgbe_adapter *adapter,
			     struct txgbe_ring *ring);
void txgbe_update_stats(struct txgbe_adapter *adapter);
int txgbe_init_interrupt_scheme(struct txgbe_adapter *adapter);
void txgbe_reset_interrupt_capability(struct txgbe_adapter *adapter);
void txgbe_set_interrupt_capability(struct txgbe_adapter *adapter);
void txgbe_clear_interrupt_scheme(struct txgbe_adapter *adapter);
netdev_tx_t txgbe_xmit_frame_ring(struct sk_buff *skb,
				  struct txgbe_adapter *adapter,
				  struct txgbe_ring *tx_ring);
void txgbe_unmap_and_free_tx_resource(struct txgbe_ring *ring,
				      struct txgbe_tx_buffer *tx_buffer);
void txgbe_alloc_rx_buffers(struct txgbe_ring *rx_ring, u16 cleaned_count);
void txgbe_configure_rscctl(struct txgbe_adapter *adapter,
			    struct txgbe_ring *ring);
void txgbe_configure_port(struct txgbe_adapter *adapter);
void txgbe_clear_vxlan_port(struct txgbe_adapter *adapter);
void txgbe_set_rx_mode(struct net_device *netdev);
int txgbe_write_mc_addr_list(struct net_device *netdev);
void txgbe_tx_ctxtdesc(struct txgbe_ring *tx_ring, u32 vlan_macip_lens,
		       u32 fcoe_sof_eof, u32 type_tucmd, u32 mss_l4len_idx);
void txgbe_do_reset(struct net_device *netdev);
void txgbe_write_eitr(struct txgbe_q_vector *q_vector);
int txgbe_poll(struct napi_struct *napi, int budget);
void txgbe_disable_rx_queue(struct txgbe_adapter *adapter,
			    struct txgbe_ring *ring);
void txgbe_disable_tx_queue(struct txgbe_adapter *adapter,
			    struct txgbe_ring *ring);
void txgbe_vlan_strip_enable(struct txgbe_adapter *adapter);
void txgbe_vlan_strip_disable(struct txgbe_adapter *adapter);

static inline struct netdev_queue *txring_txq(const struct txgbe_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->queue_index);
}

int txgbe_write_uc_addr_list(struct net_device *netdev, int pool);
int txgbe_add_mac_filter(struct txgbe_adapter *adapter, u8 *addr, u16 pool);
int txgbe_del_mac_filter(struct txgbe_adapter *adapter, u8 *addr, u16 pool);
int txgbe_available_rars(struct txgbe_adapter *adapter);
void txgbe_vlan_mode(struct net_device *netdev, u32 features);

void txgbe_set_rx_drop_en(struct txgbe_adapter *adapter);

void txgbe_store_reta(struct txgbe_adapter *adapter);

/**
 * interrupt masking operations. each bit in PX_ICn correspond to a interrupt.
 * disable a interrupt by writing to PX_IMS with the corresponding bit=1
 * enable a interrupt by writing to PX_IMC with the corresponding bit=1
 * trigger a interrupt by writing to PX_ICS with the corresponding bit=1
 **/
#define TXGBE_INTR_ALL (~0ULL)
#define TXGBE_INTR_MISC(A) (1ULL << (A)->num_q_vectors)
#define TXGBE_INTR_QALL(A) (TXGBE_INTR_MISC(A) - 1)
#define TXGBE_INTR_Q(i) (1ULL << (i))
static inline void txgbe_intr_enable(struct txgbe_hw *hw, u64 qmask)
{
	u32 mask;

	mask = (qmask & 0xFFFFFFFF);
	if (mask)
		wr32(hw, TXGBE_PX_IMC(0), mask);
	mask = (qmask >> 32);
	if (mask)
		wr32(hw, TXGBE_PX_IMC(1), mask);

	/* skip the flush */
}

static inline void txgbe_intr_disable(struct txgbe_hw *hw, u64 qmask)
{
	u32 mask;

	mask = (qmask & 0xFFFFFFFF);
	if (mask)
		wr32(hw, TXGBE_PX_IMS(0), mask);
	mask = (qmask >> 32);
	if (mask)
		wr32(hw, TXGBE_PX_IMS(1), mask);

	/* skip the flush */
}

#define TXGBE_RING_SIZE(R) ((R)->count < TXGBE_MAX_TXD ? (R)->count / 128 : 0)

#define msec_delay(_x) msleep(_x)
#define usec_delay(_x) udelay(_x)

extern char txgbe_driver_name[];

struct txgbe_msg {
	u16 msg_enable;
};

__maybe_unused static struct net_device *txgbe_hw_to_netdev(const struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter =
		container_of(hw, struct txgbe_adapter, hw);
	return adapter->netdev;
}

__maybe_unused static struct txgbe_msg *txgbe_hw_to_msg(const struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter =
		container_of(hw, struct txgbe_adapter, hw);
	return (struct txgbe_msg *)&adapter->msg_enable;
}

#define txgbe_dbg(hw, fmt, arg...) \
	netdev_dbg(txgbe_hw_to_netdev(hw), fmt, ##arg)

#define TXGBE_FAILED_READ_CFG_DWORD 0xffffffffU
#define TXGBE_FAILED_READ_CFG_WORD  0xffffU
#define TXGBE_FAILED_READ_CFG_BYTE  0xffU

extern u16 txgbe_read_pci_cfg_word(struct txgbe_hw *hw, u32 reg);

enum {
	TXGBE_ERROR_SOFTWARE,
	TXGBE_ERROR_POLLING,
	TXGBE_ERROR_INVALID_STATE,
	TXGBE_ERROR_UNSUPPORTED,
	TXGBE_ERROR_ARGUMENT,
	TXGBE_ERROR_CAUTION,
};

#define ERROR_REPORT(hw, level, format, arg...) do {                           \
	switch (level) {                                                       \
	case TXGBE_ERROR_SOFTWARE:                                             \
		/* fallthrough */                                              \
	case TXGBE_ERROR_CAUTION:                                              \
		/* fallthrough */                                              \
	case TXGBE_ERROR_POLLING:                                              \
		netif_warn(txgbe_hw_to_msg(hw), drv, txgbe_hw_to_netdev(hw),   \
			   format, ## arg);                                    \
		break;                                                         \
	case TXGBE_ERROR_INVALID_STATE:                                        \
		/* fallthrough */                                              \
	case TXGBE_ERROR_UNSUPPORTED:                                          \
		/* fallthrough */                                              \
	case TXGBE_ERROR_ARGUMENT:                                             \
		netif_err(txgbe_hw_to_msg(hw), hw, txgbe_hw_to_netdev(hw),     \
			  format, ## arg);                                     \
		break;                                                         \
	default:                                                               \
		break;                                                         \
	}                                                                      \
} while (0)

#define ERROR_REPORT1 ERROR_REPORT
#define ERROR_REPORT2 ERROR_REPORT
#define ERROR_REPORT3 ERROR_REPORT

#endif /* _TXGBE_H_ */
