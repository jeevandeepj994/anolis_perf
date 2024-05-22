// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2024 Beijing WangXun Technology Co., Ltd. */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/aer.h>
#include <linux/etherdevice.h>
#include <linux/atomic.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>

#include "txgbe_vf.h"
#include "txgbe_mbx.h"
#include "txgbe_txrx.h"

char txgbe_driver_name[] = "txgbevf";

static const char txgbe_driver_string[] =
	"WangXun(R) 10GbE PCI Express Virtual Function Linux Network Driver";

#define DRV_VERSION     __stringify(1.3.1-k)
const char txgbevf_driver_version[32] = DRV_VERSION;

char txgbe_firmware_version[TXGBE_FW_VER_SIZE] = "N/A";

/* txgbe_pci_tbl - PCI Device ID Table */
static struct pci_device_id txgbe_pci_tbl[] = {
	{ PCI_VDEVICE(WANGXUN, TXGBE_DEV_ID_SP1000_VF), 0},
	{ PCI_VDEVICE(WANGXUN, TXGBE_DEV_ID_WX1820_VF), 0},
	{ .device = 0 } /* required last entry */
};

static struct txgbe_info txgbe_sp_vf_info = {
	.mac    = txgbe_mac_sp_vf,
	.flags  = 0,
};

static const struct txgbe_info *txgbe_info_tbl[] = {
	[board_sp_vf] = &txgbe_sp_vf_info,
};

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

static inline int txgbevf_init_rss_key(struct txgbe_adapter *adapter)
{
	u32 *rss_key;

	if (!adapter->rss_key) {
		rss_key = kzalloc(40, GFP_KERNEL);
		if (unlikely(!rss_key))
			return -ENOMEM;
		netdev_rss_key_fill(rss_key, 40);
		adapter->rss_key = rss_key;
	}
	return 0;
}

void txgbe_negotiate_api(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	int api[] = {
		     txgbe_mbox_api_13,
		     txgbe_mbox_api_12,
		     txgbe_mbox_api_11,
		     txgbe_mbox_api_10,
		     txgbe_mbox_api_unknown};
	int err = 0, idx = 0;

	spin_lock_bh(&adapter->mbx_lock);

	while (api[idx] != txgbe_mbox_api_unknown) {
		err = txgbe_negotiate_api_version(hw, api[idx]);
		if (!err)
			break;
		idx++;
	}

	spin_unlock_bh(&adapter->mbx_lock);
}

void txgbe_reset(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	s32 err;

	if (unlikely(!hw->hw_addr))
		return;

	err = hw->mac.ops.reset_hw(hw);
	if (!err)
		err = hw->mac.ops.init_hw(hw);

	if (err)
		e_err(probe, "reset function\n");
	else
		txgbe_negotiate_api(adapter);

	if (is_valid_ether_addr(adapter->hw.mac.addr)) {
		ether_addr_copy(netdev->dev_addr, adapter->hw.mac.addr);
		ether_addr_copy(netdev->perm_addr, adapter->hw.mac.addr);
	}

	adapter->last_reset = jiffies;
}

/**
 * txgbe_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 **/
void txgbe_clean_tx_ring(struct txgbe_ring *tx_ring)
{
	u16 i = tx_ring->next_to_clean;
	struct txgbe_tx_buffer *tx_buffer = &tx_ring->tx_buffer_info[i];

	while (i != tx_ring->next_to_use) {
		struct txgbe_tx_desc *eop_desc, *tx_desc;

		/* Free all the Tx ring sk_buffs */
		dev_kfree_skb_any(tx_buffer->skb);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);

		/* check for eop_desc to determine the end of the packet */
		eop_desc = tx_buffer->next_to_watch;
		tx_desc = TXGBE_TX_DESC(tx_ring, i);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(i == tx_ring->count)) {
				i = 0;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = TXGBE_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buffer, len))
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buffer, dma),
					       dma_unmap_len(tx_buffer, len),
					       DMA_TO_DEVICE);
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buffer++;
		i++;
		if (unlikely(i == tx_ring->count)) {
			i = 0;
			tx_buffer = tx_ring->tx_buffer_info;
		}
	}

	/* reset BQL for queue */
	netdev_tx_reset_queue(txring_txq(tx_ring));

	/* reset next_to_use and next_to_clean */
	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
}

/**
 * txgbe_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void txgbe_free_tx_resources(struct txgbe_ring *tx_ring)
{
	txgbe_clean_tx_ring(tx_ring);

	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;

	/* if not set, then don't free */
	if (!tx_ring->desc)
		return;

	dma_free_coherent(tx_ring->dev, tx_ring->size,
			  tx_ring->desc, tx_ring->dma_addr);

	tx_ring->desc = NULL;
}

/**
 * txgbe_setup_tx_resources - allocate Tx resources (Descriptors)
 * @tx_ring:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
int txgbe_setup_tx_resources(struct txgbe_ring *tx_ring)
{
	int size;

	size = sizeof(struct txgbe_tx_buffer) * tx_ring->count;
	tx_ring->tx_buffer_info = vmalloc(size);
	if (!tx_ring->tx_buffer_info)
		goto err;

	u64_stats_init(&tx_ring->syncp);

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(struct txgbe_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	tx_ring->desc = dma_alloc_coherent(tx_ring->dev, tx_ring->size,
					   &tx_ring->dma_addr, GFP_KERNEL);
	if (!tx_ring->desc)
		goto err;

	return 0;

err:
	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;
	dev_err(tx_ring->dev, "Unable to allocate memory for the Tx descriptor ring\n");
	return -ENOMEM;
}

/**
 * txgbe_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
int txgbe_setup_all_tx_resources(struct txgbe_adapter *adapter)
{
	int i;
	int err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = txgbe_setup_tx_resources(adapter->tx_ring[i]);
		if (!err)
			continue;
		e_err(drv, "Allocation for Tx Queue %u failed\n", i);
		goto err_setup_tx;
	}

	return 0;
err_setup_tx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		txgbe_free_tx_resources(adapter->tx_ring[i]);
	return err;
}

/**
 * txgbe_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
void txgbe_free_all_tx_resources(struct txgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		if (adapter->tx_ring[i]->desc)
			txgbe_free_tx_resources(adapter->tx_ring[i]);
}

/**
 * txgbe_setup_rx_resources - allocate Rx resources (Descriptors)
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int txgbe_setup_rx_resources(struct txgbe_adapter *adapter,
			     struct txgbe_ring *rx_ring)
{
	int size;

	size = sizeof(struct txgbe_rx_buffer) * rx_ring->count;
	rx_ring->rx_buffer_info = vmalloc(size);
	if (!rx_ring->rx_buffer_info)
		goto err;

	u64_stats_init(&rx_ring->syncp);

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union txgbe_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	rx_ring->desc = dma_alloc_coherent(rx_ring->dev, rx_ring->size,
					   &rx_ring->dma_addr, GFP_KERNEL);

	if (!rx_ring->desc)
		goto err;

	return 0;
err:
	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;
	dev_err(rx_ring->dev, "Unable to allocate memory for the Rx descriptor ring\n");
	return -ENOMEM;
}

/**
 * txgbe_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
int txgbe_setup_all_rx_resources(struct txgbe_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = txgbe_setup_rx_resources(adapter, adapter->rx_ring[i]);
		if (!err)
			continue;
		e_err(probe, "Allocation for Rx Queue %u failed\n", i);
		goto err_setup_rx;
	}

	return 0;
err_setup_rx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		txgbe_free_rx_resources(adapter->rx_ring[i]);
	return err;
}

/**
 * txgbe_clean_rx_ring - Free Rx Buffers per Queue
 * @rx_ring: ring to free buffers from
 **/
void txgbe_clean_rx_ring(struct txgbe_ring *rx_ring)
{
	u16 i = rx_ring->next_to_clean;

	/* Free Rx ring sk_buff */
	if (rx_ring->skb) {
		dev_kfree_skb(rx_ring->skb);
		rx_ring->skb = NULL;
	}

	/* Free all the Rx ring pages */
	while (i != rx_ring->next_to_alloc) {
		struct txgbe_rx_buffer *rx_buffer;

		rx_buffer = &rx_ring->rx_buffer_info[i];

		/* Invalidate cache lines that may have been written to by
		 * device so that we avoid corrupting memory.
		 */
		dma_sync_single_range_for_cpu(rx_ring->dev,
					      rx_buffer->dma_addr,
					      rx_buffer->page_offset,
					      txgbe_rx_bufsz(rx_ring),
					      DMA_FROM_DEVICE);

		/* free resources associated with mapping */
		dma_unmap_page_attrs(rx_ring->dev,
				     rx_buffer->dma_addr,
				     txgbe_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE,
				     TXGBE_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_buffer->page,
					rx_buffer->pagecnt_bias);

		i++;
		if (i == rx_ring->count)
			i = 0;
	}

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * txgbe_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
void txgbe_clean_all_rx_rings(struct txgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		txgbe_clean_rx_ring(adapter->rx_ring[i]);
}

/**
 * txgbe_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
void txgbe_clean_all_tx_rings(struct txgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		txgbe_clean_tx_ring(adapter->tx_ring[i]);
}

/**
 * txgbe_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void txgbe_free_rx_resources(struct txgbe_ring *rx_ring)
{
	txgbe_clean_rx_ring(rx_ring);

	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;

	dma_free_coherent(rx_ring->dev, rx_ring->size,
			  rx_ring->desc, rx_ring->dma_addr);

	rx_ring->desc = NULL;
}

/**
 * txgbe_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
void txgbe_free_all_rx_resources(struct txgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		if (adapter->rx_ring[i]->desc)
			txgbe_free_rx_resources(adapter->rx_ring[i]);
}

int txgbe_configure_dcb(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	unsigned int def_q = 0;
	unsigned int num_tcs = 0;
	unsigned int num_rx_queues = adapter->num_rx_queues;
	unsigned int num_tx_queues = adapter->num_tx_queues;
	int err;

	spin_lock_bh(&adapter->mbx_lock);

	/* fetch queue configuration from the PF */
	err = txgbe_get_queues(hw, &num_tcs, &def_q);

	spin_unlock_bh(&adapter->mbx_lock);

	if (err)
		return err;

	if (num_tcs > 1) {
		/* we need only one Tx queue */
		num_tx_queues = 1;

		/* update default Tx ring register index */
		adapter->tx_ring[0]->reg_idx = def_q;

		/* we need as many queues as traffic classes */
		num_rx_queues = num_tcs;
	}

	/* if we have a bad config abort request queue reset */
	if (adapter->num_rx_queues != num_rx_queues ||
	    adapter->num_tx_queues != num_tx_queues) {
		/* force mailbox timeout to prevent further messages */
		hw->mbx.timeout = 0;

		/* wait for watchdog to come around and bail us out */
		adapter->flagsd |= TXGBE_F_REQ_QUEUE_RESET;
	}

	return 0;
}

void txgbe_restore_vlan(struct txgbe_adapter *adapter)
{
	u16 vid;

	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID)
		txgbe_vlan_rx_add_vid(adapter->netdev, htons(ETH_P_8021Q), vid);
}

/**
 * txgbe_configure_tx_ring - Configure Tx ring after Reset
 * @adapter: board private structure
 * @ring: structure containing ring specific data
 *
 * Configure the Tx descriptor ring after a reset.
 **/
void txgbe_configure_tx_ring(struct txgbe_adapter *adapter,
			     struct txgbe_ring *ring)
{
	struct txgbe_hw *hw = &adapter->hw;
	u64 tdba = ring->dma_addr;
	u32 txdctl = 0;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	wr32(hw, TXGBE_VXTXDCTL(reg_idx), TXGBE_VXTXDCTL_FLUSH);
	txgbe_flush(hw);

	wr32(hw, TXGBE_VXTDBAL(reg_idx), tdba & DMA_BIT_MASK(32));
	wr32(hw, TXGBE_VXTDBAH(reg_idx), tdba >> 32);

	/* enable relaxed ordering */
	pcie_capability_clear_and_set_word(adapter->pdev, PCI_EXP_DEVCTL,
					   0, PCI_EXP_DEVCTL_RELAX_EN);

	/* reset head and tail pointers */
	wr32(hw, TXGBE_VXTDH(reg_idx), 0);
	wr32(hw, TXGBE_VXTDT(reg_idx), 0);
	ring->tail = adapter->io_addr + TXGBE_VXTDT(reg_idx);

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;

	txdctl |= TXGBE_VXTXDCTL_BUFLEN(txgbe_buf_len(ring->count));
	txdctl |= TXGBE_VXTXDCTL_ENABLE;

	/* reinitialize tx_buffer_info */
	memset(ring->tx_buffer_info, 0,
	       sizeof(struct txgbe_tx_buffer) * ring->count);

	clear_bit(__TXGBE_HANG_CHECK_ARMED, &ring->state);
	clear_bit(__TXGBE_TX_XDP_RING_PRIMED, &ring->state);

	wr32(hw, TXGBE_VXTXDCTL(reg_idx), txdctl);
	/* poll to verify queue is enabled */
	if (po32m(hw, TXGBE_VXTXDCTL(reg_idx),
		  TXGBE_VXTXDCTL_ENABLE, TXGBE_VXTXDCTL_ENABLE, 1000, 10))
		e_err(drv, "Could not enable Tx Queue %d\n", reg_idx);
}

/**
 * txgbe_configure_tx - Configure Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
void txgbe_configure_tx(struct txgbe_adapter *adapter)
{
	u32 i;

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++)
		txgbe_configure_tx_ring(adapter, adapter->tx_ring[i]);
}

static void txgbe_set_rx_buffer_len(struct txgbe_adapter *adapter,
				    struct txgbe_ring *rx_ring)
{
	struct net_device *netdev = adapter->netdev;
	unsigned int max_frame = netdev->mtu + ETH_HLEN + ETH_FCS_LEN;

	/* set build_skb and buffer size flags */
	clear_ring_build_skb_enabled(rx_ring);
	clear_ring_uses_large_buffer(rx_ring);

	set_ring_build_skb_enabled(rx_ring);

	if (PAGE_SIZE < 8192) {
		if (max_frame <= TXGBE_MAX_FRAME_BUILD_SKB)
			return;

		set_ring_uses_large_buffer(rx_ring);
	}
}

void txgbe_setup_psrtype(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;

	/* PSRTYPE must be initialized */
	u32 psrtype = TXGBE_VXMRQC_PSR_L2HDR |
		      TXGBE_VXMRQC_PSR_L3HDR |
		      TXGBE_VXMRQC_PSR_L4HDR |
		      TXGBE_VXMRQC_PSR_TUNHDR |
		      TXGBE_VXMRQC_PSR_TUNMAC;

	if (adapter->num_rx_queues > 1)
		psrtype |= BIT(14);

	wr32m(hw, TXGBE_VXMRQC, TXGBE_VXMRQC_PSR(~0), TXGBE_VXMRQC_PSR(psrtype));
}

void txgbe_setup_vfmrqc(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 vfmrqc = 0, vfreta = 0;
	u16 rss_i = adapter->num_rx_queues;
	u8 i, j;

	/* Fill out hash function seeds */
	netdev_rss_key_fill(adapter->rss_key, sizeof(adapter->rss_key));
	for (i = 0; i < TXGBE_VFRSSRK_REGS; i++)
		wr32(hw, TXGBE_VXRSSRK(i), adapter->rss_key[i]);

	for (i = 0, j = 0; i < 128; i++, j++) {
		if (j == rss_i)
			j = 0;

		adapter->rss_indir_tbl[i] = j;

		vfreta |= j << (i & 0x3) * 8;
		if ((i & 3) == 3) {
			wr32(hw, TXGBE_VXRETA(i >> 2), vfreta);
			vfreta = 0;
		}
	}

	/* Perform hash on these packet types */
	vfmrqc |= TXGBE_VXMRQC_RSS_ALG_IPV4 |
		  TXGBE_VXMRQC_RSS_ALG_IPV4_TCP |
		  TXGBE_VXMRQC_RSS_ALG_IPV6 |
		  TXGBE_VXMRQC_RSS_ALG_IPV6_TCP;

	vfmrqc |= TXGBE_VXMRQC_RSS_EN;

	if (adapter->num_rx_queues > 3)
		vfmrqc |= TXGBE_VXMRQC_RSS_HASH(2);
	else if (adapter->num_rx_queues > 1)
		vfmrqc |= TXGBE_VXMRQC_RSS_HASH(1);

	wr32m(hw, TXGBE_VXMRQC, TXGBE_VXMRQC_RSS(~0), TXGBE_VXMRQC_RSS(vfmrqc));
}

void txgbe_configure_srrctl(struct txgbe_adapter *adapter,
			    struct txgbe_ring *ring, int index)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 srrctl;

	srrctl = rd32m(hw, TXGBE_VXRXDCTL(index),
		       ~(TXGBE_VXRXDCTL_HDRSZ(~0) | TXGBE_VXRXDCTL_BUFSZ(~0)));
	srrctl |= TXGBE_VXRXDCTL_DROP;
	srrctl |= TXGBE_VXRXDCTL_HDRSZ(txgbe_hdr_sz(TXGBE_RX_HDR_SIZE));
	if (ring_uses_large_buffer(ring))
		srrctl |= TXGBE_VXRXDCTL_BUFSZ(txgbe_buf_sz(3072));
	else
		srrctl |= TXGBE_VXRXDCTL_BUFSZ(txgbe_buf_sz(TXGBE_RX_BUF_SIZE));

	wr32(hw, TXGBE_VXRXDCTL(index), srrctl);
}

void txgbe_rx_desc_queue_enable(struct txgbe_adapter *adapter,
				struct txgbe_ring *ring)
{
	struct txgbe_hw *hw = &adapter->hw;
	u8 reg_idx = ring->reg_idx;

	if (TXGBE_REMOVED(hw->hw_addr))
		return;
	if (po32m(hw, TXGBE_VXRXDCTL(reg_idx),
		  TXGBE_VXRXDCTL_ENABLE, TXGBE_VXRXDCTL_ENABLE, 1000, 10))
		e_err(probe,
		      "RXDCTL.ENABLE queue %d not set while polling\n",
			reg_idx);
}

void txgbe_configure_rx_ring(struct txgbe_adapter *adapter,
			     struct txgbe_ring *ring)
{
	struct txgbe_hw *hw = &adapter->hw;
	union txgbe_rx_desc *rx_desc;
	u64 rdba = ring->dma_addr;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	rxdctl = rd32(hw, TXGBE_VXRXDCTL(reg_idx));
	txgbe_disable_rx_queue(adapter, ring);

	wr32(hw, TXGBE_VXRDBAL(reg_idx), rdba & DMA_BIT_MASK(32));
	wr32(hw, TXGBE_VXRDBAH(reg_idx), rdba >> 32);

	/* enable relaxed ordering */
	pcie_capability_clear_and_set_word(adapter->pdev, PCI_EXP_DEVCTL,
					   0, PCI_EXP_DEVCTL_RELAX_EN);

	/* reset head and tail pointers */
	wr32(hw, TXGBE_VXRDH(reg_idx), 0);
	wr32(hw, TXGBE_VXRDT(reg_idx), 0);
	ring->tail = adapter->io_addr + TXGBE_VXRDT(reg_idx);

	/* initialize rx_buffer_info */
	memset(ring->rx_buffer_info, 0,
	       sizeof(struct txgbe_rx_buffer) * ring->count);

	/* initialize Rx descriptor 0 */
	rx_desc = TXGBE_RX_DESC(ring, 0);
	rx_desc->wb.upper.length = 0;

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;
	ring->next_to_alloc = 0;

	txgbe_configure_srrctl(adapter, ring, reg_idx);

	/* allow any size packet since we can handle overflow */
	rxdctl &= ~TXGBE_VXRXDCTL_BUFLEN(~0);

	rxdctl |= TXGBE_VXRXDCTL_BUFLEN(txgbe_buf_len(ring->count));
	rxdctl |= TXGBE_VXRXDCTL_ENABLE | TXGBE_VXRXDCTL_VLAN;

	/* enable RSC */
	rxdctl &= ~TXGBE_VXRXDCTL_RSCMAX(~0);
	rxdctl |= TXGBE_VXRXDCTL_RSCMAX(TXGBE_RSCMAX_1);
	rxdctl |= TXGBE_VXRXDCTL_RSCEN;

	wr32(hw, TXGBE_VXRXDCTL(reg_idx), rxdctl);

	txgbe_rx_desc_queue_enable(adapter, ring);
	txgbe_alloc_rx_buffers(ring, txgbe_desc_unused(ring));
}

/**
 * txgbe_configure_rx - Configure Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
void txgbe_configure_rx(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int i, ret;

	txgbe_setup_psrtype(adapter);
	txgbe_setup_vfmrqc(adapter);

	spin_lock_bh(&adapter->mbx_lock);
	ret = txgbe_rlpml_set_vf(hw, netdev->mtu + ETH_HLEN + ETH_FCS_LEN);
	spin_unlock_bh(&adapter->mbx_lock);
	if (ret)
		e_info(drv, "Failed to set MTU at %d\n", netdev->mtu);

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct txgbe_ring *rx_ring = adapter->rx_ring[i];

		txgbe_set_rx_buffer_len(adapter, rx_ring);
		txgbe_configure_rx_ring(adapter, rx_ring);
	}
}

void txgbe_configure(struct txgbe_adapter *adapter)
{
	txgbe_configure_dcb(adapter);
	txgbe_set_rx_mode(adapter->netdev);
	txgbe_restore_vlan(adapter);
	txgbe_configure_tx(adapter);
	txgbe_configure_rx(adapter);
}

/**
 * txgbe_msix_rings - single unshared vector rx clean (all queues)
 * @irq: unused
 * @data: pointer to our q_vector struct for this interrupt vector
 **/
irqreturn_t txgbe_msix_rings(int __always_unused irq, void *data)
{
	struct txgbe_q_vector *q_vector = data;

	/* EIAM disabled interrupts (on this vector) for us */
	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_schedule_irqoff(&q_vector->napi);

	return IRQ_HANDLED;
}

irqreturn_t txgbe_msix_other(int __always_unused irq, void *data)
{
	struct txgbe_adapter *adapter = data;
	struct txgbe_hw *hw = &adapter->hw;

	hw->mac.get_link_status = 1;

	txgbe_service_event_schedule(adapter);

	wr32(hw, TXGBE_VXIMC, adapter->eims_other);

	return IRQ_HANDLED;
}

/**
 * txgbe_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * txgbe_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
int txgbe_request_msix_irqs(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int vector, err;
	int ri = 0, ti = 0;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct txgbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "TxRx", ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "rx", ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "tx", ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = request_irq(entry->vector, &txgbe_msix_rings, 0,
				  q_vector->name, q_vector);
		if (err) {
			e_err(drv, "request_irq failed for MSIX interrupt Error: %d\n", err);
			goto free_queue_irqs;
		}
	}

	err = request_irq(adapter->msix_entries[vector].vector,
			  &txgbe_msix_other, 0, netdev->name, adapter);
	if (err) {
		e_err(drv, "request_irq for msix_other failed: %d\n", err);
		goto free_queue_irqs;
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
		free_irq(adapter->msix_entries[vector].vector,
			 adapter->q_vector[vector]);
	}
	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	return err;
}

/**
 * txgbe_request_irq - initialize interrupts
 * @adapter: board private structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
int txgbe_request_irq(struct txgbe_adapter *adapter)
{
	int err;

	err = txgbe_request_msix_irqs(adapter);

	if (err)
		e_err(probe, "request_irq failed, Error %d\n", err);

	return err;
}

void txgbe_free_irq(struct txgbe_adapter *adapter)
{
	int vector;

	if (!adapter->msix_entries)
		return;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct txgbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		/* free only the irqs that were actually requested */
		if (!q_vector->rx.ring && !q_vector->tx.ring)
			continue;

		free_irq(entry->vector, q_vector);
	}

	free_irq(adapter->msix_entries[vector++].vector, adapter);
}

void txgbe_napi_enable_all(struct txgbe_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++)
		napi_enable(&adapter->q_vector[q_idx]->napi);
}

void txgbe_napi_disable_all(struct txgbe_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++)
		napi_disable(&adapter->q_vector[q_idx]->napi);
}

/**
 * txgbe_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
inline void txgbe_irq_enable(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;

	wr32(hw, TXGBE_VXIMC, adapter->eims_enable_mask);
}

void txgbe_save_reset_stats(struct txgbe_adapter *adapter)
{
	/* Only save pre-reset stats if there are some */
	if (adapter->stats.gprc || adapter->stats.gptc) {
		adapter->reset_stats.gprc = adapter->stats.gprc -
			adapter->base_stats.gprc;
		adapter->reset_stats.gptc = adapter->stats.gptc -
			adapter->base_stats.gptc;
		adapter->reset_stats.gorc = adapter->stats.gorc -
			adapter->base_stats.gorc;
		adapter->reset_stats.gotc = adapter->stats.gotc -
			adapter->base_stats.gotc;
		adapter->reset_stats.mprc = adapter->stats.mprc -
			adapter->base_stats.mprc;
	}
}

/**
 * txgbe_set_ivar - set IVAR registers - maps interrupt causes to vectors
 * @adapter: pointer to adapter struct
 * @direction: 0 for Rx, 1 for Tx, -1 for other causes
 * @queue: queue to map the corresponding interrupt to
 * @msix_vector: the vector to map to the corresponding queue
 *
 **/
void txgbe_set_ivar(struct txgbe_adapter *adapter, s8 direction,
		    u8 queue, u8 msix_vector)
{
	u32 ivar, index;
	struct txgbe_hw *hw = &adapter->hw;

	if (direction == -1) {
		/* other causes */
		msix_vector |= TXGBE_VXIVAR_MISC_VALID;
		ivar = rd32(hw, TXGBE_VXIVAR_MISC);
		ivar &= ~0xFF;
		ivar |= msix_vector;
		wr32(hw, TXGBE_VXIVAR_MISC, ivar);
	} else {
		/* tx or rx causes */
		msix_vector |= TXGBE_VXIVAR_MISC_VALID;
		index = ((16 * (queue & 1)) + (8 * direction));
		ivar = rd32(hw, TXGBE_VXIVAR(queue >> 1));
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		wr32(hw, TXGBE_VXIVAR(queue >> 1), ivar);
	}
}

/**
 * txgbe_configure_msix - Configure MSI-X hardware
 * @adapter: board private structure
 *
 * txgbe_configure_msix sets up the hardware to properly generate MSI-X
 * interrupts.
 **/
void txgbe_configure_msix(struct txgbe_adapter *adapter)
{
	struct txgbe_q_vector *q_vector;
	int v_idx;

	adapter->eims_enable_mask = 0;

	/* Populate the IVAR table and set the ITR values to the
	 * corresponding register.
	 */
	for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
		struct txgbe_ring *ring;

		q_vector = adapter->q_vector[v_idx];

		txgbe_for_each_ring(ring, q_vector->rx)
			txgbe_set_ivar(adapter, 0, ring->reg_idx, v_idx);

		txgbe_for_each_ring(ring, q_vector->tx)
			txgbe_set_ivar(adapter, 1, ring->reg_idx, v_idx);

		if (q_vector->tx.ring && !q_vector->rx.ring) {
			/* tx only vector */
			if (adapter->tx_itr_setting == 1)
				q_vector->itr = TXGBE_12K_ITR;
			else
				q_vector->itr = adapter->tx_itr_setting;
		} else {
			/* rx or rx/tx vector */
			if (adapter->rx_itr_setting == 1)
				q_vector->itr = TXGBE_20K_ITR;
			else
				q_vector->itr = adapter->rx_itr_setting;
		}

		/* add q_vector eims value to global eims_enable_mask */
		adapter->eims_enable_mask |= BIT(v_idx);

		txgbe_write_eitr(q_vector);
	}

	txgbe_set_ivar(adapter, -1, 1, v_idx);

	/* setup eims_other and add value to global eims_enable_mask */
	adapter->eims_other = BIT(v_idx);
	adapter->eims_enable_mask |= adapter->eims_other;
}

void txgbe_up_complete(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct txgbe_hw *hw = &adapter->hw;
	bool state;

	txgbe_configure_msix(adapter);
	spin_lock_bh(&adapter->mbx_lock);

	if (is_valid_ether_addr(hw->mac.addr))
		hw->mac.ops.set_rar(hw, 0, hw->mac.addr, 0, 0);
	else
		hw->mac.ops.set_rar(hw, 0, hw->mac.perm_addr, 0, 0);

	spin_unlock_bh(&adapter->mbx_lock);

	state = adapter->link_state;
	spin_lock_bh(&adapter->mbx_lock);
	hw->mac.ops.get_link_state(hw, &adapter->link_state);
	spin_unlock_bh(&adapter->mbx_lock);
	if (state && state != adapter->link_state)
		e_info(drv, "VF is administratively disabled\n");

	/* memory barrier */
	smp_mb__before_atomic();
	clear_bit(__TXGBE_DOWN, &adapter->state);
	txgbe_napi_enable_all(adapter);

	/* clear any pending interrupts, may auto mask */
	wr32(hw, TXGBE_VXICR, ~0);
	txgbe_irq_enable(adapter);

	msleep(1000);
	/* enable transmits */
	netif_tx_start_all_queues(netdev);
	txgbe_save_reset_stats(adapter);
	txgbe_init_last_counter_stats(adapter);

	hw->mac.get_link_status = 1;
	mod_timer(&adapter->service_timer, jiffies);
}

int txgbe_open(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	int err;

	/* A previous failure to open the device because of a lack of
	 * available MSIX vector resources may have reset the number
	 * of q vectors variable to zero.  The only way to recover
	 * is to unload/reload the driver and hope that the system has
	 * been able to recover some MSIX vector resources.
	 */
	if (!adapter->num_q_vectors)
		return -ENOMEM;

	if (hw->adapter_stopped) {
		txgbe_reset(adapter);
		/* if adapter is still stopped then PF isn't up and
		 * the vf can't start.
		 */
		if (hw->adapter_stopped) {
			err = TXGBE_ERR_MBX;
			e_err(drv, "Unable to start - perhaps PF isn't up yet\n");
			goto err_setup_reset;
		}
	}

	/* disallow open during test */
	if (test_bit(__TXGBE_TESTING, &adapter->state))
		return -EBUSY;

	netif_carrier_off(netdev);

	/* allocate transmit descriptors */
	err = txgbe_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = txgbe_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	txgbe_configure(adapter);
	err = txgbe_request_irq(adapter);
	if (err)
		goto err_req_irq;
	/* Notify the stack of the actual queue counts. */
	err = netif_set_real_num_tx_queues(netdev, adapter->num_tx_queues);
	if (err)
		goto err_set_queues;
	err = netif_set_real_num_rx_queues(netdev, adapter->num_rx_queues);
	if (err)
		goto err_set_queues;

	txgbe_up_complete(adapter);

	return 0;

err_set_queues:
	txgbe_free_irq(adapter);
err_req_irq:
	txgbe_free_all_rx_resources(adapter);
err_setup_rx:
	txgbe_free_all_tx_resources(adapter);
err_setup_tx:
	txgbe_reset(adapter);
err_setup_reset:

	return err;
}

void txgbe_disable_rx_queue(struct txgbe_adapter *adapter,
			    struct txgbe_ring *ring)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (TXGBE_REMOVED(hw->hw_addr))
		return;
	rxdctl = rd32(hw, TXGBE_VXRXDCTL(reg_idx));
	rxdctl &= ~TXGBE_VXRXDCTL_ENABLE;

	/* write value back with RXDCTL.ENABLE bit cleared */
	wr32(hw, TXGBE_VXRXDCTL(reg_idx), rxdctl);

	/* the hardware may take up to 100us to really disable the rx queue */
	if (po32m(hw, TXGBE_VXRXDCTL(reg_idx),
		  TXGBE_VXRXDCTL_ENABLE, 0, 10, 10))
		e_info(probe, "RXDCTL.ENABLE queue %d not cleared while polling\n", reg_idx);
}

/**
 * txgbe_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
inline void txgbe_irq_disable(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	int vector;

	wr32(hw, TXGBE_VXIMS, ~0);

	txgbe_flush(hw);

	for (vector = 0; vector < adapter->num_q_vectors; vector++)
		synchronize_irq(adapter->msix_entries[vector].vector);

	synchronize_irq(adapter->msix_entries[vector++].vector);
}

void txgbe_down(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct txgbe_hw *hw = &adapter->hw;
	int i;

	/* signal that we are down to the interrupt handler */
	if (test_and_set_bit(__TXGBE_DOWN, &adapter->state))
		return; /* do nothing if already down */

	/* disable all enabled rx queues */
	for (i = 0; i < adapter->num_rx_queues; i++)
		txgbe_disable_rx_queue(adapter, adapter->rx_ring[i]);

	usleep_range(10000, 20000);

	netif_tx_stop_all_queues(netdev);

	/* call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	txgbe_irq_disable(adapter);

	txgbe_napi_disable_all(adapter);

	del_timer_sync(&adapter->service_timer);

	/* disable transmits in the hardware now that interrupts are off */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		u8 reg_idx = adapter->tx_ring[i]->reg_idx;

		wr32(hw, TXGBE_VXTXDCTL(reg_idx),
		     TXGBE_VXTXDCTL_FLUSH);
	}

	if (!pci_channel_offline(adapter->pdev))
		txgbe_reset(adapter);

	txgbe_clean_all_tx_rings(adapter);
	txgbe_clean_all_rx_rings(adapter);
}

int txgbe_close(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	txgbe_down(adapter);
	txgbe_free_irq(adapter);

	txgbe_free_all_tx_resources(adapter);
	txgbe_free_all_rx_resources(adapter);

	return 0;
}

/**
 * txgbe_sw_init - Initialize general software structures (struct txgbe_adapter)
 * @adapter: board private structure to initialize
 **/
static int txgbe_sw_init(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	struct net_device *netdev = adapter->netdev;
	int err = 0;

	/* PCI config space info */
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;

	txgbe_init_ops_vf(hw);
	hw->mbx.ops.init_params(hw);
	err = txgbevf_init_rss_key(adapter);
	if (err)
		return err;

	/* assume legacy case in which PF would only give VF 2 queues */
	hw->mac.max_tx_queues = 4;
	hw->mac.max_rx_queues = 4;

	/* lock to protect mailbox accesses */
	spin_lock_init(&adapter->mbx_lock);
	spin_lock_init(&adapter->pf_count_lock);

	/*make sure PF is up*/
	if (adapter->bd_number == 0)
		msleep(1500);

	err = hw->mac.ops.reset_hw(hw);
	if (err) {
		dev_info(&pdev->dev,
			 "PF still in reset state.  Is the PF interface up?\n");
	} else {
		err = hw->mac.ops.init_hw(hw);
		if (err) {
			dev_err(&pdev->dev,
				"init_shared_code failed: %d\n", err);
			return err;
		}
		txgbe_negotiate_api(adapter);
		err = hw->mac.ops.get_mac_addr(hw, hw->mac.addr);
		if (err)
			dev_info(&pdev->dev, "Error reading MAC address\n");
		else if (is_zero_ether_addr(adapter->hw.mac.addr))
			dev_info(&pdev->dev,
				 "MAC address not assigned by administrator.\n");
		ether_addr_copy(netdev->dev_addr, hw->mac.addr);
	}

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		dev_info(&pdev->dev, "Assigning random MAC address\n");
		eth_hw_addr_random(netdev);
		ether_addr_copy(hw->mac.addr, netdev->dev_addr);
		ether_addr_copy(hw->mac.perm_addr, netdev->dev_addr);
	}

	/* Enable dynamic interrupt throttling rates */
	adapter->rx_itr_setting = 1;
	adapter->tx_itr_setting = 1;

	/* set default ring sizes */
	adapter->tx_ring_count = TXGBE_DEFAULT_TXD;
	adapter->rx_ring_count = TXGBE_DEFAULT_RXD;

	/* enable rx csum by default */
	adapter->flagsd |= TXGBE_F_CAP_RX_CSUM;

	adapter->link_state = true;

	set_bit(__TXGBE_DOWN, &adapter->state);

	return 0;
}

void txgbe_init_last_counter_stats(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	int i = 0;

	adapter->last_stats.gprc = 0;
	adapter->last_stats.gorc = 0;
	adapter->last_stats.gptc = 0;
	adapter->last_stats.gotc = 0;
	adapter->last_stats.mprc = 0;

	for (i = 0; i < MAX_RX_QUEUES; i++) {
		adapter->last_reg_stats[i].gprc = rd32(hw, TXGBE_VXGPRC(i));
		adapter->last_stats.gprc += adapter->last_reg_stats[i].gprc;

		adapter->last_reg_stats[i].gorc = rd32(hw, TXGBE_VXGORC_LSB(i));
		adapter->last_reg_stats[i].gorc = adapter->last_reg_stats[i].gorc |
			((u64)(rd32(hw, TXGBE_VXGORC_MSB(i))) << 32);
		adapter->last_stats.gorc += adapter->last_reg_stats[i].gorc;

		adapter->last_reg_stats[i].gptc = rd32(hw, TXGBE_VXGPTC(i));
		adapter->last_stats.gptc += adapter->last_reg_stats[i].gptc;

		adapter->last_reg_stats[i].gotc = rd32(hw, TXGBE_VXGOTC_LSB(i));
		adapter->last_reg_stats[i].gotc = adapter->last_reg_stats[i].gotc |
			((u64)(rd32(hw, TXGBE_VXGOTC_MSB(i))) << 32);
		adapter->last_stats.gotc += adapter->last_reg_stats[i].gotc;

		adapter->last_reg_stats[i].mprc = rd32(hw, TXGBE_VXMPRC(i));
		adapter->last_stats.mprc += adapter->last_reg_stats[i].mprc;

		adapter->reg_stats[i].gprc = 0;
		adapter->reg_stats[i].gorc = 0;
		adapter->reg_stats[i].gptc = 0;
		adapter->reg_stats[i].gotc = 0;
		adapter->reg_stats[i].mprc = 0;
	}

	adapter->base_stats.gprc = adapter->last_stats.gprc;
	adapter->base_stats.gorc = adapter->last_stats.gorc;
	adapter->base_stats.gptc = adapter->last_stats.gptc;
	adapter->base_stats.gotc = adapter->last_stats.gotc;
	adapter->base_stats.mprc = adapter->last_stats.mprc;
}

void txgbe_set_num_queues(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	unsigned int def_q = 0;
	unsigned int num_tcs = 0;
	int err;
	u16 rss;

	/* Start with base case */
	adapter->num_rx_queues = 1;
	adapter->num_tx_queues = 1;

	spin_lock_bh(&adapter->mbx_lock);

	/* fetch queue configuration from the PF */
	err = txgbe_get_queues(hw, &num_tcs, &def_q);

	spin_unlock_bh(&adapter->mbx_lock);

	if (err)
		return;

	/* we need as many queues as traffic classes */
	if (num_tcs > 1) {
		adapter->num_rx_queues = num_tcs;
	} else {
		if (def_q == 4)
			rss = min_t(u16, num_online_cpus(), 4);
		else
			rss = min_t(u16, num_online_cpus(), 2);

		switch (hw->api_version) {
		case txgbe_mbox_api_11:
		case txgbe_mbox_api_12:
		case txgbe_mbox_api_13:
			adapter->num_rx_queues = rss;
			adapter->num_tx_queues = rss;
		default:
			break;
		}
	}
}

int txgbe_acquire_msix_vectors(struct txgbe_adapter *adapter,
			       int vectors)
{
	int vector_threshold;

	vector_threshold = MIN_MSIX_COUNT;
	vectors = pci_enable_msix_range(adapter->pdev, adapter->msix_entries,
					vector_threshold, vectors);

	if (vectors < 0) {
		e_err(drv, "Unable to allocate MSI-X interrupts\n");
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
		return vectors;
	}

	adapter->num_q_vectors = min_t(u16, vectors - NON_Q_VECTORS, 2);

	return 0;
}

/**
 * txgbe_set_interrupt_capability - set MSI-X or FAIL if not supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 */
int txgbe_set_interrupt_capability(struct txgbe_adapter *adapter)
{
	int vector, v_budget;

	/* It's easy to be greedy for MSI-X vectors, but it really
	 * doesn't do us much good if we have a lot more vectors
	 * than CPU's.  So let's be conservative and only ask for
	 * (roughly) the same number of vectors as there are CPU's.
	 * The default is to use pairs of vectors.
	 */
	v_budget = max(adapter->num_rx_queues, adapter->num_tx_queues);
	v_budget = min_t(int, v_budget, num_online_cpus());
	v_budget += NON_Q_VECTORS;

	adapter->msix_entries = kcalloc(v_budget,
					sizeof(struct msix_entry), GFP_KERNEL);
	if (!adapter->msix_entries)
		return -ENOMEM;

	for (vector = 0; vector < v_budget; vector++)
		adapter->msix_entries[vector].entry = vector;

	/* A failure in MSI-X entry allocation isn't fatal, but the VF driver
	 * does not support any other modes, so we will simply fail here. Note
	 * that we clean up the msix_entries pointer else-where.
	 */
	return txgbe_acquire_msix_vectors(adapter, v_budget);
}

void txgbe_add_ring(struct txgbe_ring *ring,
		    struct txgbe_ring_container *head)
{
	ring->next = head->ring;
	head->ring = ring;
	head->count++;
}

/**
 * txgbe_alloc_q_vector - Allocate memory for a single interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: index of vector in adapter struct
 *
 * We allocate one q_vector.  If allocation fails we return -ENOMEM.
 **/
int txgbe_alloc_q_vector(struct txgbe_adapter *adapter, int v_idx,
			 int txr_count, int txr_idx,
				  int xdp_count, int xdp_idx,
				  int rxr_count, int rxr_idx)
{
	struct txgbe_q_vector *q_vector;
	int reg_idx = txr_idx + xdp_idx;
	struct txgbe_ring *ring;
	int ring_count, size;

	ring_count = txr_count + xdp_count + rxr_count;
	size = sizeof(*q_vector) + (sizeof(*ring) * ring_count);

	/* allocate q_vector and rings */
	q_vector = kzalloc(size, GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	/* initialize NAPI */
	netif_napi_add(adapter->netdev, &q_vector->napi, txgbe_poll, 64);

	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx] = q_vector;
	q_vector->adapter = adapter;
	q_vector->v_idx = v_idx;

	/* initialize pointer to rings */
	ring = q_vector->ring;

	while (txr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		txgbe_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_count;
		ring->que_idx = txr_idx;
		ring->reg_idx = reg_idx;

		/* assign ring to adapter */
		 adapter->tx_ring[txr_idx] = ring;

		/* update count and index */
		txr_count--;
		txr_idx++;
		reg_idx++;

		/* push pointer to next ring */
		ring++;
	}

	while (rxr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Rx values */
		txgbe_add_ring(ring, &q_vector->rx);

		/* errata: UDP frames with a 0 checksum
		 * can be marked as checksum errors.
		 */
		if (adapter->hw.mac.type == txgbe_mac_sp_vf)
			set_bit(__TXGBE_RX_CSUM_UDP_ZERO_ERR, &ring->state);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_count;
		ring->que_idx = rxr_idx;
		ring->reg_idx = rxr_idx;

		/* assign ring to adapter */
		adapter->rx_ring[rxr_idx] = ring;

		/* update count and index */
		rxr_count--;
		rxr_idx++;

		/* push pointer to next ring */
		ring++;
	}

	return 0;
}

/**
 * txgbe_free_q_vector - Free memory allocated for specific interrupt vector
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vector.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
void txgbe_free_q_vector(struct txgbe_adapter *adapter, int v_idx)
{
	struct txgbe_q_vector *q_vector = adapter->q_vector[v_idx];
	struct txgbe_ring *ring;

	txgbe_for_each_ring(ring, q_vector->tx)
		adapter->tx_ring[ring->que_idx] = NULL;

	txgbe_for_each_ring(ring, q_vector->rx)
		adapter->rx_ring[ring->que_idx] = NULL;

	adapter->q_vector[v_idx] = NULL;
	netif_napi_del(&q_vector->napi);

	/* txgbe_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	kfree_rcu(q_vector, rcu);
}

/**
 * txgbe_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
int txgbe_alloc_q_vectors(struct txgbe_adapter *adapter)
{
	int q_vectors = adapter->num_q_vectors;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int xdp_remaining = 0;
	int rxr_idx = 0, txr_idx = 0, xdp_idx = 0, v_idx = 0;
	int err;

	if (q_vectors >= (rxr_remaining + txr_remaining + xdp_remaining)) {
		for (; rxr_remaining; v_idx++, q_vectors--) {
			int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors);

			err = txgbe_alloc_q_vector(adapter, v_idx,
						   0, 0, 0, 0, rqpv, rxr_idx);
			if (err)
				goto err_out;

			/* update counts and index */
			rxr_remaining -= rqpv;
			rxr_idx += rqpv;
		}
	}

	for (; q_vectors; v_idx++, q_vectors--) {
		int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors);
		int tqpv = DIV_ROUND_UP(txr_remaining, q_vectors);
		int xqpv = DIV_ROUND_UP(xdp_remaining, q_vectors);

		err = txgbe_alloc_q_vector(adapter, v_idx,
					   tqpv, txr_idx,
					     xqpv, xdp_idx,
					     rqpv, rxr_idx);

		if (err)
			goto err_out;

		/* update counts and index */
		rxr_remaining -= rqpv;
		rxr_idx += rqpv;
		txr_remaining -= tqpv;
		txr_idx += tqpv;
	}

	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		txgbe_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

/**
 * txgbe_reset_interrupt_capability - Reset MSIX setup
 * @adapter: board private structure
 *
 **/
void txgbe_reset_interrupt_capability(struct txgbe_adapter *adapter)
{
	if (!adapter->msix_entries)
		return;
	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
}

/**
 * txgbe_init_interrupt_scheme - Determine if MSIX is supported and init
 * @adapter: board private structure to initialize
 *
 **/
int txgbe_init_interrupt_scheme(struct txgbe_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	int err;

	/* Number of supported queues */
	txgbe_set_num_queues(adapter);

	err = txgbe_set_interrupt_capability(adapter);
	if (err) {
		dev_err(&pdev->dev, "Unable to setup interrupt capabilities\n");
		goto err_set_interrupt;
	}

	err = txgbe_alloc_q_vectors(adapter);
	if (err) {
		dev_err(&pdev->dev, "Unable to allocate memory for queue vectors\n");
		goto err_alloc_q_vectors;
	}

	dev_info(&pdev->dev, "Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u\n",
		 (adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
		 adapter->num_rx_queues, adapter->num_tx_queues);

	set_bit(__TXGBE_DOWN, &adapter->state);

	return 0;
err_alloc_q_vectors:
	txgbe_reset_interrupt_capability(adapter);
err_set_interrupt:
	return err;
}

static void txgbe_set_features(struct txgbe_adapter *adapter, u8 fea_flags)
{
	struct net_device *netdev = adapter->netdev;
	netdev_features_t hw_features;

	netdev->features = NETIF_F_SG |
					   NETIF_F_TSO |
					   NETIF_F_TSO6 |
					   NETIF_F_RXCSUM |
					   NETIF_F_HW_CSUM |
					   NETIF_F_SCTP_CRC;

	netdev->gso_partial_features = NETIF_F_GSO_GRE |
								NETIF_F_GSO_GRE_CSUM |
								NETIF_F_GSO_IPXIP4 |

								NETIF_F_GSO_IPXIP6 |
								NETIF_F_GSO_UDP_TUNNEL |
								NETIF_F_GSO_UDP_TUNNEL_CSUM;

	netdev->features |= netdev->gso_partial_features |
				NETIF_F_GSO_PARTIAL;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX |
			NETIF_F_HW_VLAN_CTAG_RX;

	netdev->features |= NETIF_F_HW_VLAN_STAG_TX |
			NETIF_F_HW_VLAN_STAG_RX;

	hw_features = netdev->hw_features;
	hw_features |= netdev->features;
	netdev->hw_features = hw_features;

	netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	netdev->vlan_features |= netdev->features | NETIF_F_TSO_MANGLEID;
	netdev->mpls_features |= NETIF_F_HW_CSUM;
	netdev->hw_enc_features |= netdev->vlan_features;
}

void txgbe_update_itr(struct txgbe_q_vector *q_vector,
		      struct txgbe_ring_container *ring_container)
{
	int bytes = ring_container->total_bytes;
	int packets = ring_container->total_packets;
	u32 timepassed_us;
	u64 bytes_perint;
	u8 itr_setting = ring_container->itr;

	if (packets == 0)
		return;

	/* simple throttlerate management
	 * 0-20MB/s lowest (100000 ints/s)
	 * 20-100MB/s low   (20000 ints/s)
	 * 100-1249MB/s bulk (12000 ints/s)
	 */
	timepassed_us = q_vector->itr >> 2;
	bytes_perint = bytes / timepassed_us;

	switch (itr_setting) {
	case lowest_latency:
		if (bytes_perint > 10)
			itr_setting = low_latency;
		break;
	case low_latency:
		if (bytes_perint > 20)
			itr_setting = bulk_latency;
		else if (bytes_perint <= 10)
			itr_setting = lowest_latency;
		break;
	case bulk_latency:
		if (bytes_perint <= 20)
			itr_setting = low_latency;
		break;
	}

	/* clear work counters since we have the values we need */
	ring_container->total_bytes = 0;
	ring_container->total_packets = 0;

	/* write updated itr to ring container */
	ring_container->itr = itr_setting;
}

/**
 * txgbe_write_eitr - write VTEITR register in hardware specific way
 * @q_vector: structure containing interrupt and ring information
 */
void txgbe_write_eitr(struct txgbe_q_vector *q_vector)
{
	struct txgbe_adapter *adapter = q_vector->adapter;
	struct txgbe_hw *hw = &adapter->hw;
	int v_idx = q_vector->v_idx;
	u32 itr_reg = TXGBE_VXITR_INTERVAL(q_vector->itr);

	/* set the WDIS bit to not clear the timer bits and cause an
	 * immediate assertion of the interrupt
	 */
	itr_reg |= TXGBE_VXITR_CNT_WDIS;

	wr32(hw, TXGBE_VXITR(v_idx), itr_reg);
}

void txgbe_set_itr(struct txgbe_q_vector *q_vector)
{
	u32 new_itr = q_vector->itr;
	u8 current_itr;

	txgbe_update_itr(q_vector, &q_vector->tx);
	txgbe_update_itr(q_vector, &q_vector->rx);

	current_itr = max(q_vector->rx.itr, q_vector->tx.itr);

	switch (current_itr) {
	/* counts and packets in update_itr are dependent on these numbers */
	case lowest_latency:
		new_itr = TXGBE_100K_ITR;
		break;
	case low_latency:
		new_itr = TXGBE_20K_ITR;
		break;
	case bulk_latency:
		new_itr = TXGBE_12K_ITR;
		break;
	default:
		break;
	}

	if (new_itr != q_vector->itr) {
		/* do an exponential smoothing */
		new_itr = (10 * new_itr * q_vector->itr) /
			  ((9 * new_itr) + q_vector->itr);

		/* save the algorithm value here */
		q_vector->itr = new_itr;

		txgbe_write_eitr(q_vector);
	}
}

bool txgbe_alloc_mapped_page(struct txgbe_ring *rx_ring,
			     struct txgbe_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page))
		return true;

	/* alloc new page for storage */
	page = dev_alloc_pages(txgbe_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page_attrs(rx_ring->dev, page, 0,
				 txgbe_rx_pg_size(rx_ring),
				 DMA_FROM_DEVICE,
				 TXGBE_RX_DMA_ATTR);

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, txgbe_rx_pg_order(rx_ring));

		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	bi->dma_addr = dma;
	bi->page = page;
	bi->page_offset = txgbe_rx_offset(rx_ring);
	bi->pagecnt_bias = 1;
	rx_ring->rx_stats.alloc_rx_page++;

	return true;
}

/**
 * txgbe_alloc_rx_buffers - Replace used receive buffers; packet split
 * @rx_ring: rx descriptor ring (for a specific queue) to setup buffers on
 * @cleaned_count: number of buffers to replace
 **/
void txgbe_alloc_rx_buffers(struct txgbe_ring *rx_ring,
			    u16 cleaned_count)
{
	union txgbe_rx_desc *rx_desc;
	struct txgbe_rx_buffer *bi;
	unsigned int i = rx_ring->next_to_use;

	/* nothing to do or no valid netdev defined */
	if (!cleaned_count || !rx_ring->netdev)
		return;

	rx_desc = TXGBE_RX_DESC(rx_ring, i);
	bi = &rx_ring->rx_buffer_info[i];
	i -= rx_ring->count;

	do {
		if (!txgbe_alloc_mapped_page(rx_ring, bi))
			break;

		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, bi->dma_addr,
						 bi->page_offset,
						 txgbe_rx_bufsz(rx_ring),
						 DMA_FROM_DEVICE);

		/* Refresh the desc even if pkt_addr didn't change
		 * because each write-back erases this info.
		 */
		rx_desc->rd.pkt_addr = TXGBE_RXD_PKTADDR(bi->dma_addr + bi->page_offset);

		rx_desc++;
		bi++;
		i++;
		if (unlikely(!i)) {
			rx_desc = TXGBE_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_buffer_info;
			i -= rx_ring->count;
		}

		/* clear the hdr_addr for the next_to_use descriptor */
		rx_desc->rd.hdr_addr = 0;

		cleaned_count--;
	} while (cleaned_count);

	i += rx_ring->count;

	if (rx_ring->next_to_use != i) {
		/* record the next descriptor to use */
		rx_ring->next_to_use = i;

		/* update next to alloc since we have filled the ring */
		rx_ring->next_to_alloc = i;

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, rx_ring->tail);
	}
}

/**
 * txgbe_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @rx_desc: descriptor containing length of buffer written by hardware
 * @skb: sk_buff to place the data into
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 * This is done either through a direct copy if the data in the buffer is
 * less than the skb header size, otherwise it will just attach the page as
 * a frag to the skb.
 *
 * The function will then update the page offset if necessary and return
 * true if the buffer can be reused by the adapter.
 **/
static void txgbe_add_rx_frag(struct txgbe_ring __always_unused *rx_ring,
			      struct txgbe_rx_buffer *rx_buffer,
				struct sk_buff *skb,
				unsigned int size)
{
#if (PAGE_SIZE < 8192)
	unsigned int truesize = txgbe_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = ring_uses_build_skb(rx_ring) ?
				SKB_DATA_ALIGN(TXGBE_SKB_PAD + size) :
				SKB_DATA_ALIGN(size);
#endif

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->page,
			rx_buffer->page_offset, size, truesize);
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif
}

static struct sk_buff *txgbe_build_skb(struct txgbe_ring *rx_ring,
				       struct txgbe_rx_buffer *rx_buffer,
					 struct xdp_buff *xdp,
					 union txgbe_rx_desc *rx_desc)
{
	unsigned int metasize = xdp->data - xdp->data_meta;
	void *va = xdp->data_meta;

#if (PAGE_SIZE < 8192)
	unsigned int truesize = txgbe_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
				SKB_DATA_ALIGN(xdp->data_end -
					       xdp->data_hard_start);
#endif
	struct sk_buff *skb;

	/* Prefetch first cache line of first page. If xdp->data_meta
	 * is unused, this points to xdp->data, otherwise, we likely
	 * have a consumer accessing first few bytes of meta data,
	 * and then actual data.
	 */
	prefetch(va);
#if L1_CACHE_BYTES < 128
	prefetch(va + L1_CACHE_BYTES);
#endif

	/* build an skb around the page buffer */
	skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	/* update pointers within the skb to store the data */
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	__skb_put(skb, xdp->data_end - xdp->data);

	if (metasize)
		skb_metadata_set(skb, metasize);

	/* update buffer offset */
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif

	return skb;
}

static struct sk_buff *txgbe_construct_skb(struct txgbe_ring *rx_ring,
					   struct txgbe_rx_buffer *rx_buffer,
				      struct xdp_buff *xdp,
				      union txgbe_rx_desc *rx_desc)
{
	unsigned int size = xdp->data_end - xdp->data;
#if (PAGE_SIZE < 8192)
	unsigned int truesize = txgbe_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(xdp->data_end -
					       xdp->data_hard_start);
#endif
	unsigned int headlen;
	struct sk_buff *skb;

	/* prefetch first cache line of first page */
	prefetch(xdp->data);
#if L1_CACHE_BYTES < 128
	prefetch(xdp->data + L1_CACHE_BYTES);
#endif

	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rx_ring->q_vector->napi, TXGBE_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > TXGBE_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, xdp->data, TXGBE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), xdp->data,
	       ALIGN(headlen, sizeof(long)));

	/* update all of the pointers */
	size -= headlen;
	if (size) {
		skb_add_rx_frag(skb, 0, rx_buffer->page,
				(xdp->data + headlen) -
					page_address(rx_buffer->page),
				size, truesize);
#if (PAGE_SIZE < 8192)
		rx_buffer->page_offset ^= truesize;
#else
		rx_buffer->page_offset += truesize;
#endif
	} else {
		rx_buffer->pagecnt_bias++;
	}

	return skb;
}

static inline bool txgbe_page_is_reserved(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) || page_is_pfmemalloc(page);
}

static bool txgbe_can_reuse_rx_page(struct txgbe_rx_buffer *rx_buffer)
{
	unsigned int pagecnt_bias = rx_buffer->pagecnt_bias;
	struct page *page = rx_buffer->page;

	/* avoid re-using remote pages */
	if (unlikely(txgbe_page_is_reserved(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (unlikely((page_count(page) - pagecnt_bias) > 1))
		return false;

#else
#define TXGBE_LAST_OFFSET \
	(SKB_WITH_OVERHEAD(PAGE_SIZE) - TXGBE_RXBUFFER_2048)

	if (rx_buffer->page_offset > TXGBE_LAST_OFFSET)
		return false;

#endif

	/* Even if we own the page, we are not allowed to use atomic_set()
	 * This would break get_page_unless_zero() users.
	 */
	if (likely(!pagecnt_bias)) {
		page_ref_inc(page);
		rx_buffer->pagecnt_bias = 1;
	}

	return true;
}

/**
 * txgbe_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 **/
void txgbe_reuse_rx_page(struct txgbe_ring *rx_ring,
			 struct txgbe_rx_buffer *old_buff)
{
	struct txgbe_rx_buffer *new_buff;
	u16 nta = rx_ring->next_to_alloc;

	new_buff = &rx_ring->rx_buffer_info[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_buff->page = old_buff->page;
	new_buff->dma_addr = old_buff->dma_addr;
	new_buff->page_offset = old_buff->page_offset;
	new_buff->pagecnt_bias = old_buff->pagecnt_bias;
}

static void txgbe_put_rx_buffer(struct txgbe_ring *rx_ring,
				struct txgbe_rx_buffer *rx_buffer,
				  struct sk_buff *skb)
{
	if (txgbe_can_reuse_rx_page(rx_buffer)) {
		/* hand second half of page back to the ring */
		txgbe_reuse_rx_page(rx_ring, rx_buffer);
	} else {
		if (IS_ERR(skb))
			/* We are not reusing the buffer so unmap it and free
			 * any references we are holding to it
			 */
			dma_unmap_page_attrs(rx_ring->dev, rx_buffer->dma_addr,
					     txgbe_rx_pg_size(rx_ring),
					     DMA_FROM_DEVICE,
					     TXGBE_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_buffer->page,
					rx_buffer->pagecnt_bias);
	}

	/* clear contents of rx_buffer */
	rx_buffer->page = NULL;
}

static struct txgbe_rx_buffer *txgbe_get_rx_buffer(struct txgbe_ring *rx_ring,
						   const unsigned int size)
{
	struct txgbe_rx_buffer *rx_buffer;

	rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
	prefetchw(rx_buffer->page);

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev,
				      rx_buffer->dma_addr,
				      rx_buffer->page_offset,
				      size,
				      DMA_FROM_DEVICE);

	rx_buffer->pagecnt_bias--;

	return rx_buffer;
}

/**
 * txgbe_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: current socket buffer containing buffer in progress
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
bool txgbe_is_non_eop(struct txgbe_ring *rx_ring,
		      union txgbe_rx_desc *rx_desc)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(TXGBE_RX_DESC(rx_ring, ntc));

	if (likely(TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_STAT_EOP))
		return false;

	return true;
}

/**
 * txgbe_cleanup_headers - Correct corrupted or empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being fixed
 *
 * Check for corrupted packet headers caused by senders on the local L2
 * embedded NIC switch not setting up their Tx Descriptors right.  These
 * should be very rare.
 *
 * Also address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 **/
bool txgbe_cleanup_headers(struct txgbe_ring *rx_ring,
			   union txgbe_rx_desc *rx_desc,
				  struct sk_buff *skb)
{
	/* XDP packets use error pointer so abort at this point */
	if (IS_ERR(skb))
		return true;

	/* verify that the packet does not have any known errors */
	if (unlikely(TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_ERR_RXE)) {
		struct net_device *netdev = rx_ring->netdev;

		if (!(netdev->features & NETIF_F_RXALL)) {
			dev_kfree_skb_any(skb);
			return true;
		}
	}

	/* if eth_skb_pad returns an error the skb was freed */
	if (eth_skb_pad(skb))
		return true;

	return false;
}

#define TXGBE_RSS_L4_TYPES_MASK \
	((1ul << TXGBE_RSSTYPE_IPV4_TCP) | \
	 (1ul << TXGBE_RSSTYPE_IPV4_UDP) | \
	 (1ul << TXGBE_RSSTYPE_IPV6_TCP) | \
	 (1ul << TXGBE_RSSTYPE_IPV6_UDP))

inline void txgbe_rx_hash(struct txgbe_ring *ring,
				   union txgbe_rx_desc *rx_desc,
				   struct sk_buff *skb)
{
	u16 rss_type;

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	rss_type = TXGBE_RXD_RSSTYPE(rx_desc);

	if (!rss_type)
		return;

	skb_set_hash(skb, TXGBE_RXD_RSS_HASH(rx_desc),
		     (TXGBE_RSS_L4_TYPES_MASK & (1ul << rss_type)) ?
		     PKT_HASH_TYPE_L4 : PKT_HASH_TYPE_L3);
}

inline void txgbe_rx_checksum(struct txgbe_ring *ring,
				       union txgbe_rx_desc *rx_desc,
				       struct sk_buff *skb)
{
	struct txgbe_dec_ptype dptype;

	skb->ip_summed = CHECKSUM_NONE;

	/* Rx csum disabled */
	if (!(ring->netdev->features & NETIF_F_RXCSUM))
		return;

	dptype = txgbe_rx_decode_ptype(rx_desc);
	if (!dptype.known)
		return;

	if (dptype.etype)
		skb->encapsulation = 1;

	/* if IP and error */
	if ((TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_STAT_IPCS &&
	     TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_ERR_IPE) ||
	    (TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_STAT_EIPCS &&
	     TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_ERR_EIPERR)) {
		ring->rx_stats.csum_err++;
		return;
	}

	if (!(TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_STAT_TPCS))
		return;

	if (TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_ERR_TPE) {
		ring->rx_stats.csum_err++;
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

void txgbe_process_skb_fields(struct txgbe_ring *rx_ring,
			      union txgbe_rx_desc *rx_desc,
				       struct sk_buff *skb)
{
	txgbe_rx_hash(rx_ring, rx_desc, skb);
	txgbe_rx_checksum(rx_ring, rx_desc, skb);

	if (TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_STAT_VP) {
		u16 vid = TXGBE_RXD_VLAN(rx_desc);
		unsigned long *active_vlans = netdev_priv(rx_ring->netdev);

		if (test_bit(vid & VLAN_VID_MASK, active_vlans))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
	}

	skb->protocol = eth_type_trans(skb, rx_ring->netdev);
}

static void txgbe_rx_skb(struct txgbe_q_vector *q_vector,
			 struct sk_buff *skb)
{
	napi_gro_receive(&q_vector->napi, skb);
}

int txgbe_clean_rx_irq(struct txgbe_q_vector *q_vector,
		       struct txgbe_ring *rx_ring,
				 int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	u16 cleaned_count = txgbe_desc_unused(rx_ring);
	struct sk_buff *skb = rx_ring->skb;
	struct xdp_buff xdp;

	xdp.data = NULL;
	xdp.data_end = NULL;

	while (likely(total_rx_packets < budget)) {
		struct txgbe_rx_buffer *rx_buffer;
		union txgbe_rx_desc *rx_desc;
		unsigned int size;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= TXGBE_RX_BUFFER_WRITE) {
			txgbe_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = TXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);

		size = le16_to_cpu(rx_desc->wb.upper.length);
		if (!size)
			break;
		if (!(TXGBE_RXD_STATUS(rx_desc) & TXGBE_RXD_STAT_DD))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * RXD_STAT_DD bit is set
		 */
		rmb();

		/* retrieve a buffer from the ring */
		rx_buffer = txgbe_get_rx_buffer(rx_ring, size);

		if (!skb) {
			xdp.data = page_address(rx_buffer->page) +
				   rx_buffer->page_offset;

			xdp.data_meta = xdp.data;

			xdp.data_hard_start = xdp.data -
					      txgbe_rx_offset(rx_ring);
			xdp.data_end = xdp.data + size;
		}

		if (skb) {
			txgbe_add_rx_frag(rx_ring, rx_buffer, skb, size);
		} else if (ring_uses_build_skb(rx_ring)) {
			skb = txgbe_build_skb(rx_ring, rx_buffer,
					      &xdp, rx_desc);
		} else {
			skb = txgbe_construct_skb(rx_ring, rx_buffer,
						  &xdp, rx_desc);
		}

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			rx_buffer->pagecnt_bias++;
			break;
		}

		txgbe_put_rx_buffer(rx_ring, rx_buffer, skb);
		cleaned_count++;

		/* fetch next buffer in frame if non-eop */
		if (txgbe_is_non_eop(rx_ring, rx_desc))
			continue;

		/* verify the packet layout is correct */
		if (txgbe_cleanup_headers(rx_ring, rx_desc, skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* Workarouid hardware that can't do proper VEPA multicast
		 * source pruning.
		 */
		if ((skb->pkt_type == PACKET_BROADCAST ||
		     skb->pkt_type == PACKET_MULTICAST) &&
		    ether_addr_equal(rx_ring->netdev->dev_addr,
				     eth_hdr(skb)->h_source)) {
			dev_kfree_skb_irq(skb);
			continue;
		}

		/* populate checksum, VLAN, and protocol */
		txgbe_process_skb_fields(rx_ring, rx_desc, skb);

		txgbe_rx_skb(q_vector, skb);

		/* reset skb pointer */
		skb = NULL;

		/* update budget accounting */
		total_rx_packets++;
	}

	/* place incomplete frames back on ring for completion */
	rx_ring->skb = skb;

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;
	q_vector->netpoll_rx = false;

	return total_rx_packets;
}

inline void txgbe_irq_enable_queues(struct txgbe_adapter *adapter,
					     u32 qmask)
{
	struct txgbe_hw *hw = &adapter->hw;

	wr32(hw, TXGBE_VXIMC, qmask);
}

inline int txgbe_skb_pad_nonzero(struct sk_buff *skb, int pad)
{
	int err;
	int ntail;

	/* If the skbuff is non linear tailroom is always zero.. */
	if (!skb_cloned(skb) && skb_tailroom(skb) >= pad) {
		memset(skb->data + skb->len, 0x1, pad);
		return 0;
	}

	ntail = skb->data_len + pad - (skb->end - skb->tail);
	if (likely(skb_cloned(skb) || ntail > 0)) {
		err = pskb_expand_head(skb, 0, ntail, GFP_ATOMIC);
		if (unlikely(err))
			goto free_skb;
	}

	/* FIXME: The use of this function with non-linear skb's really needs
	 * to be audited.
	 */
	err = skb_linearize(skb);
	if (unlikely(err))
		goto free_skb;

	memset(skb->data + skb->len, 0x1, pad);
	return 0;

free_skb:
	kfree_skb(skb);
	return err;
}

static int __txgbe_maybe_stop_tx(struct txgbe_ring *tx_ring, int size)
{
	netif_stop_subqueue(tx_ring->netdev, tx_ring->que_idx);
	/* Herbert's original patch had:
	 * smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it.
	 */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	if (likely(txgbe_desc_unused(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(tx_ring->netdev, tx_ring->que_idx);
	++tx_ring->tx_stats.tx_restart_queue;

	return 0;
}

static inline int txgbe_maybe_stop_tx(struct txgbe_ring *tx_ring, int size)
{
	if (likely(txgbe_desc_unused(tx_ring) >= size))
		return 0;
	return __txgbe_maybe_stop_tx(tx_ring, size);
}

void txgbe_tx_ctxtdesc(struct txgbe_ring *tx_ring,
		       u32 vlan_macip_lens,
				u32 fcoe_sof_eof,
				u32 type_tucmd,
				u32 mss_l4len_idx)
{
	struct txgbe_adv_tx_context_desc *context_desc;
	u16 i = tx_ring->next_to_use;

	context_desc = TXGBE_TX_CTXTDESC(tx_ring, i);

	i++;
	tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

	/* set bits to identify this as an advanced context descriptor */
	type_tucmd |= TXGBE_TXD_DTYP_CTXT;

	context_desc->vlan_macip_lens   = cpu_to_le32(vlan_macip_lens);
	context_desc->seqnum_seed       = cpu_to_le32(fcoe_sof_eof);
	context_desc->type_tucmd_mlhl   = cpu_to_le32(type_tucmd);
	context_desc->mss_l4len_idx     = cpu_to_le32(mss_l4len_idx);
}

int txgbe_tso(struct txgbe_ring *tx_ring,
	      struct txgbe_tx_buffer *first, u8 *hdr_len, struct txgbe_dec_ptype dptype)
{
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens, type_tucmd;
	u32 mss_l4len_idx, l4len;
	struct tcphdr *tcph;
	struct iphdr *iph;
	u32 tunhdr_eiplen_tunlen = 0;
	int err = 0;
	u8 tun_prot = 0;
	bool enc = skb->encapsulation;
	struct ipv6hdr *ipv6h;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	if (skb_header_cloned(skb)) {
		err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (err)
			return err;
	}

	iph = enc ? inner_ip_hdr(skb) : ip_hdr(skb);

	if (iph->version == 4) {
		tcph = enc ? inner_tcp_hdr(skb) : tcp_hdr(skb);

		iph->tot_len = 0;
		iph->check = 0;
		tcph->check = ~csum_tcpudp_magic(iph->saddr,
						iph->daddr, 0,
						IPPROTO_TCP,
						0);
		first->tx_flags |= TXGBE_TX_FLAGS_TSO |
		   TXGBE_TX_FLAGS_CSUM |
		   TXGBE_TX_FLAGS_IPV4 |
		   TXGBE_TX_FLAGS_CC;
	} else if (iph->version == 6 && skb_is_gso_v6(skb)) {
		ipv6h = enc ? inner_ipv6_hdr(skb) : ipv6_hdr(skb);
		tcph = enc ? inner_tcp_hdr(skb) : tcp_hdr(skb);
		ipv6h->payload_len = 0;
		tcph->check =
		    ~csum_ipv6_magic(&ipv6h->saddr,
				     &ipv6h->daddr,
				     0, IPPROTO_TCP, 0);
		first->tx_flags |= TXGBE_TX_FLAGS_TSO |
				   TXGBE_TX_FLAGS_CSUM |
				   TXGBE_TX_FLAGS_CC;
	}

	/* compute header lengths */
	l4len = enc ? inner_tcp_hdrlen(skb) : tcp_hdrlen(skb);
	*hdr_len = enc ? (skb_inner_transport_header(skb) - skb->data)
		       : skb_transport_offset(skb);
	*hdr_len += l4len;

	/* update gso size and bytecount with header size */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * *hdr_len;

	/* mss_l4len_id: use 1 as index for TSO */
	mss_l4len_idx = l4len << TXGBE_TXD_L4LEN_SHIFT;
	mss_l4len_idx |= skb_shinfo(skb)->gso_size << TXGBE_TXD_MSS_SHIFT;
	mss_l4len_idx |= (1u << 0x4);

	/* vlan_macip_lens: HEADLEN, MACLEN, VLAN tag */
	if (enc) {
		switch (first->protocol) {
		case htons(ETH_P_IP):
			tun_prot = ip_hdr(skb)->protocol;
			first->tx_flags |= TXGBE_TX_FLAGS_OUTER_IPV4;
			break;
		case htons(ETH_P_IPV6):
			tun_prot = ipv6_hdr(skb)->nexthdr;
			break;
		default:
			break;
		}
		switch (tun_prot) {
		case IPPROTO_UDP:
			tunhdr_eiplen_tunlen = TXGBE_TXD_TUNNEL_UDP;
			tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					TXGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					TXGBE_TXD_TUNNEL_LEN_SHIFT);
			break;
		case IPPROTO_GRE:
			tunhdr_eiplen_tunlen = TXGBE_TXD_TUNNEL_GRE;
			tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					TXGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					TXGBE_TXD_TUNNEL_LEN_SHIFT);
			break;
		case IPPROTO_IPIP:
			tunhdr_eiplen_tunlen = (((char *)inner_ip_hdr(skb) -
						(char *)ip_hdr(skb)) >> 2) <<
						TXGBE_TXD_OUTER_IPLEN_SHIFT;
			break;
		default:
			break;
		}

		vlan_macip_lens = skb_inner_network_header_len(skb) >> 1;
	} else {
		vlan_macip_lens = skb_network_header_len(skb) >> 1;
	}
	vlan_macip_lens |= skb_network_offset(skb) << TXGBE_TXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & TXGBE_TX_FLAGS_VLAN_MASK;

	type_tucmd = dptype.ptype << 24;

	if (skb->vlan_proto == htons(ETH_P_8021AD))
		type_tucmd |= TXGBE_SET_FLAG(first->tx_flags,
					TXGBE_TX_FLAGS_VLAN,
					0x1 << TXGBE_TXD_TAG_TPID_SEL_SHIFT);

	txgbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, tunhdr_eiplen_tunlen,
			  type_tucmd, mss_l4len_idx);

	return 1;
}

void txgbe_tx_csum(struct txgbe_ring *tx_ring,
		   struct txgbe_tx_buffer *first, struct txgbe_dec_ptype dptype)
{
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens = 0;
	u32 mss_l4len_idx = 0;
	u32 tunhdr_eiplen_tunlen = 0;
	u8 tun_prot = 0;
	u32 type_tucmd;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		if (!(first->tx_flags & TXGBE_TX_FLAGS_VLAN) &&
		    !(first->tx_flags & TXGBE_TX_FLAGS_CC))
			return;
		vlan_macip_lens = skb_network_offset(skb) <<
				  TXGBE_TXD_MACLEN_SHIFT;
	} else {
		u8 l4_prot = 0;

		union {
			struct iphdr *ipv4;
			struct ipv6hdr *ipv6;
			u8 *raw;
		} network_hdr;
		union {
			struct tcphdr *tcphdr;
			u8 *raw;
		} transport_hdr;

		if (skb->encapsulation) {
			network_hdr.raw = skb_inner_network_header(skb);
			transport_hdr.raw = skb_inner_transport_header(skb);
			vlan_macip_lens = skb_network_offset(skb) <<
					  TXGBE_TXD_MACLEN_SHIFT;
			switch (first->protocol) {
			case htons(ETH_P_IP):
				tun_prot = ip_hdr(skb)->protocol;
				break;
			case htons(ETH_P_IPV6):
				tun_prot = ipv6_hdr(skb)->nexthdr;
				break;
			default:
				if (unlikely(net_ratelimit())) {
					dev_warn(tx_ring->dev,
						 "partial checksum but version=%d\n",
					 network_hdr.ipv4->version);
				}
				return;
			}
			switch (tun_prot) {
			case IPPROTO_UDP:
				tunhdr_eiplen_tunlen = TXGBE_TXD_TUNNEL_UDP;
				tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					TXGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					TXGBE_TXD_TUNNEL_LEN_SHIFT);
				break;
			case IPPROTO_GRE:
				tunhdr_eiplen_tunlen = TXGBE_TXD_TUNNEL_GRE;
				tunhdr_eiplen_tunlen |=
					((skb_network_header_len(skb) >> 2) <<
					TXGBE_TXD_OUTER_IPLEN_SHIFT) |
					(((skb_inner_mac_header(skb) -
					skb_transport_header(skb)) >> 1) <<
					TXGBE_TXD_TUNNEL_LEN_SHIFT);
				break;
			case IPPROTO_IPIP:
				tunhdr_eiplen_tunlen =
					(((char *)inner_ip_hdr(skb) -
					(char *)ip_hdr(skb)) >> 2) <<
					TXGBE_TXD_OUTER_IPLEN_SHIFT;
				break;
			default:
				break;
			}

		} else {
			network_hdr.raw = skb_network_header(skb);
			transport_hdr.raw = skb_transport_header(skb);
			vlan_macip_lens = skb_network_offset(skb) <<
					  TXGBE_TXD_MACLEN_SHIFT;
		}

		switch (network_hdr.ipv4->version) {
		case IPVERSION:
			vlan_macip_lens |=
				(transport_hdr.raw - network_hdr.raw) >> 1;
			l4_prot = network_hdr.ipv4->protocol;
			break;
		case 6:
			vlan_macip_lens |=
				(transport_hdr.raw - network_hdr.raw) >> 1;
			l4_prot = network_hdr.ipv6->nexthdr;
			break;
		default:
			break;
		}

		switch (l4_prot) {
		case IPPROTO_TCP:
		mss_l4len_idx = (transport_hdr.tcphdr->doff * 4) <<
				TXGBE_TXD_L4LEN_SHIFT;
			break;
		case IPPROTO_UDP:
			mss_l4len_idx = sizeof(struct udphdr) <<
					TXGBE_TXD_L4LEN_SHIFT;
			break;
		default:
			break;
		}

		/* update TX checksum flag */
		first->tx_flags |= TXGBE_TX_FLAGS_CSUM;
	}
	first->tx_flags |= TXGBE_TX_FLAGS_CC;
	/* vlan_macip_lens: MACLEN, VLAN tag */
	vlan_macip_lens |= skb_network_offset(skb) << TXGBE_TXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & TXGBE_TX_FLAGS_VLAN_MASK;

	type_tucmd = dptype.ptype << 24;

	if (skb->vlan_proto == htons(ETH_P_8021AD))
		type_tucmd |= TXGBE_SET_FLAG(first->tx_flags,
					TXGBE_TX_FLAGS_VLAN,
					0x1 << TXGBE_TXD_TAG_TPID_SEL_SHIFT);

	txgbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, tunhdr_eiplen_tunlen,
			  type_tucmd, mss_l4len_idx);
}

__le32 txgbe_tx_olinfo_status(struct txgbe_tx_desc *tx_desc,
			      u32 tx_flags, unsigned int paylen)
{
	__le32 status = TXGBE_TXD_PAYLEN(paylen);

	/* enable L4 checksum for TSO and TX checksum offload */
	if (tx_flags & TXGBE_TX_FLAGS_CSUM)
		status |= TXGBE_TXD_TPCS;

	/* enable IPv4 checksum for TSO */
	if (tx_flags & TXGBE_TX_FLAGS_IPV4)
		status |= TXGBE_TXD_IPCS;

	/* enable IPv4 checksum for TSO */
	if (tx_flags & TXGBE_TX_FLAGS_OUTER_IPV4)
		status |= TXGBE_TXD_EIPCS;

	/* use index 1 context for TSO/FSO/FCOE */
	if (tx_flags & TXGBE_TX_FLAGS_TSO)
		status |= TXGBE_TXD_BAK_DESC;

	/* Check Context must be set if Tx switch is enabled, which it
	 * always is for case where virtual functions are running
	 */
	if (tx_flags & TXGBE_TX_FLAGS_CC)
		status |= TXGBE_TXD_CC;

	return status;
}

__le32 txgbe_tx_cmd_type(u32 tx_flags)
{
	/* set type for advanced descriptor with frame checksum insertion */
	__le32 cmd_type = cpu_to_le32(TXGBE_TXD_FCS);

	/* set HW vlan bit if vlan is present */
	if (tx_flags & TXGBE_TX_FLAGS_VLAN)
		cmd_type |= cpu_to_le32(TXGBE_TXD_VLE);

	/* set segmentation enable bits for TSO/FSO */
	if (tx_flags & TXGBE_TX_FLAGS_TSO)
		cmd_type |= cpu_to_le32(TXGBE_TXD_TSE);

	return cmd_type;
}

void txgbe_unmap_and_free_tx_resource(struct txgbe_ring *tx_ring,
				      struct txgbe_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		dev_kfree_skb_any(tx_buffer->skb);
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(tx_ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(tx_ring->dev,
			       dma_unmap_addr(tx_buffer, dma),
			       dma_unmap_len(tx_buffer, len),
			       DMA_TO_DEVICE);
	}
	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
	/* tx_buffer must be completely set up in the transmit path */
}

void txgbe_tx_map(struct txgbe_ring *tx_ring,
		  struct txgbe_tx_buffer *first,
			   const u8 hdr_len)
{
	dma_addr_t dma_addr;
	struct sk_buff *skb = first->skb;
	struct txgbe_tx_buffer *tx_buffer;
	struct txgbe_tx_desc *tx_desc;
	skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int data_len = skb->data_len;
	unsigned int size = skb_headlen(skb);
	unsigned int paylen = skb->len - hdr_len;
	u32 tx_flags = first->tx_flags;
	__le32 cmd_type, status;
	u16 i = tx_ring->next_to_use;

	tx_desc = TXGBE_TX_DESC(tx_ring, i);

	status = txgbe_tx_olinfo_status(tx_desc, tx_flags, paylen);
	cmd_type = txgbe_tx_cmd_type(tx_flags);

	dma_addr = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(tx_ring->dev, dma_addr))
		goto dma_error;

	/* record length, and DMA address */
	dma_unmap_len_set(first, len, size);
	dma_unmap_addr_set(first, dma, dma_addr);

	tx_desc->pkt_addr = cpu_to_le64(dma_addr);
	tx_desc->status = status;
	for (;;) {
		if (size == 0)
			goto next_frag;

		while (unlikely(size > TXGBE_MAX_DATA_PER_TXD)) {
			tx_desc->cmd_type_len =
				cmd_type | cpu_to_le32(TXGBE_MAX_DATA_PER_TXD);

			i++;
			tx_desc++;
			if (i == tx_ring->count) {
				tx_desc = TXGBE_TX_DESC(tx_ring, 0);
				i = 0;
			}

			dma_addr += TXGBE_MAX_DATA_PER_TXD;
			size -= TXGBE_MAX_DATA_PER_TXD;

			tx_desc->pkt_addr = cpu_to_le64(dma_addr);
			tx_desc->status = status;
		}

		if (likely(!data_len))
			break;

		tx_desc->cmd_type_len = cmd_type | cpu_to_le32(size);
		i++;
		tx_desc++;
		if (i == tx_ring->count) {
			tx_desc = TXGBE_TX_DESC(tx_ring, 0);
			i = 0;
		}
next_frag:
		size = skb_frag_size(frag);
		data_len -= size;

		dma_addr = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
					    DMA_TO_DEVICE);
		if (dma_mapping_error(tx_ring->dev, dma_addr))
			goto dma_error;

		tx_buffer = &tx_ring->tx_buffer_info[i];
		dma_unmap_len_set(tx_buffer, len, size);
		dma_unmap_addr_set(tx_buffer, dma, dma_addr);

		tx_desc->pkt_addr = cpu_to_le64(dma_addr);
		tx_desc->status = status;

		frag++;
	}

	netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);

	/* write last descriptor with RS and EOP bits */
	cmd_type |= cpu_to_le32(size) | cpu_to_le32(TXGBE_TXD_EOP | TXGBE_TXD_RS);
	tx_desc->cmd_type_len = cmd_type;

	/* set the timestamp */
	first->time_stamp = jiffies;

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.  (Only applicable for weak-ordered
	 * memory model archs, such as IA-64).
	 *
	 * We also need this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	i++;
	if (i == tx_ring->count)
		i = 0;

	tx_ring->next_to_use = i;

	txgbe_maybe_stop_tx(tx_ring, DESC_NEEDED);

	if (netif_xmit_stopped(txring_txq(tx_ring)) || !netdev_xmit_more())
		writel(i, tx_ring->tail);

	return;
dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed\n");

	/* clear dma mappings for failed tx_buffer_info map */
	for (;;) {
		tx_buffer = &tx_ring->tx_buffer_info[i];
		txgbe_unmap_and_free_tx_resource(tx_ring, tx_buffer);
		if (tx_buffer == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;
}

static int txgbe_xmit_frame_ring(struct sk_buff *skb,
				 struct txgbe_ring *tx_ring)
{
	struct txgbe_tx_buffer *first;
	struct txgbe_dec_ptype dptype;
	int tso;
	u32 tx_flags = 0;
	u16 count = TXD_USE_COUNT(skb_headlen(skb));
	unsigned short f;
	__be16 protocol = skb->protocol;
	u8 hdr_len = 0;

	/* work around hw errata 3 */
	u16 _llclen, *llclen;

	llclen = skb_header_pointer(skb, ETH_HLEN - 2, sizeof(u16), &_llclen);
	if (*llclen == 0x3 || *llclen == 0x4 || *llclen == 0x5) {
		if (txgbe_skb_pad_nonzero(skb, ETH_ZLEN - skb->len))
			return -ENOMEM;
		__skb_put(skb, ETH_ZLEN - skb->len);
	}
	/* if this is an LLDP ether frame then drop it - VFs do not
	 * forward LLDP frames.
	 */
	if (ntohs(skb->protocol) == ETH_P_LLDP) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	/* need: 1 descriptor per page * PAGE_SIZE/TXGBE_MAX_DATA_PER_TXD,
	 *     + 1 desc for skb_headlen/TXGBE_MAX_DATA_PER_TXD,
	 *     + 2 desc gap to keep tail from touching head,
	 *     + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++)
		count += TXD_USE_COUNT(skb_frag_size(&skb_shinfo(skb)->
						     frags[f]));

	if (txgbe_maybe_stop_tx(tx_ring, count + 3)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

	if (skb_vlan_tag_present(skb)) {
		tx_flags |= skb_vlan_tag_get(skb) << TXGBE_TX_FLAGS_VLAN_SHIFT;
		tx_flags |= TXGBE_TX_FLAGS_VLAN;
	/* else if it is a SW VLAN check the next protocol and store the tag */
	} else if (protocol == htons(ETH_P_8021Q) ||
		   protocol == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr, _vhdr;

		vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto out_drop;

		protocol = vhdr->h_vlan_encapsulated_proto;
		tx_flags |= ntohs(vhdr->h_vlan_TCI) << TXGBE_TX_FLAGS_VLAN_SHIFT;
	}

	if (protocol == htons(ETH_P_8021Q) || protocol == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr, _vhdr;

		vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto out_drop;

		protocol = vhdr->h_vlan_encapsulated_proto;
	}

	/* record initial flags and protocol */
	first->tx_flags = tx_flags;
	first->protocol = protocol;

	/* encode packet type */
	dptype = txgbe_tx_encode_ptype(first);

	tso = txgbe_tso(tx_ring, first, &hdr_len, dptype);
	if (tso < 0)
		goto out_drop;
	else if (!tso)
		txgbe_tx_csum(tx_ring, first, dptype);

	txgbe_tx_map(tx_ring, first, hdr_len);

	netif_trans_update(tx_ring->netdev);

	txgbe_maybe_stop_tx(tx_ring, DESC_NEEDED);

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;

	return NETDEV_TX_OK;
}

static netdev_tx_t txgbe_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_ring *tx_ring;

	if (skb->len <= 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* The minimum packet size for olinfo paylen is 17 so pad the skb
	 * in order to meet this minimum size requirement.
	 */
	if (skb_put_padto(skb, 17))
		return NETDEV_TX_OK;

	tx_ring = adapter->tx_ring[skb->queue_mapping];

	return txgbe_xmit_frame_ring(skb, tx_ring);
}

u8 *txgbe_addr_list_itr(struct txgbe_hw __maybe_unused *hw, u8 **mc_addr_ptr,
			u32 *vmdq)
{
	struct netdev_hw_addr *mc_ptr;
	u8 *addr = *mc_addr_ptr;
	*vmdq = 0;

	mc_ptr = container_of(addr, struct netdev_hw_addr, addr[0]);
	if (mc_ptr->list.next) {
		struct netdev_hw_addr *ha;

		ha = list_entry(mc_ptr->list.next, struct netdev_hw_addr, list);
		*mc_addr_ptr = ha->addr;
	} else {
		*mc_addr_ptr = NULL;
	}

	return addr;
}

int txgbe_write_uc_addr_list(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	int count = 0;

	if (!netdev_uc_empty(netdev)) {
		struct netdev_hw_addr *ha;

		netdev_for_each_uc_addr(ha, netdev) {
			hw->mac.ops.set_uc_addr(hw, ++count, ha->addr);
			usleep_range(200, 300);
		}
	} else {
		/* If the list is empty then send message to PF driver to
		 * clear all macvlans on this VF.
		 */
		hw->mac.ops.set_uc_addr(hw, 0, NULL);
	}

	return count;
}

/**
 * txgbe_set_rx_mode - Multicast and unicast set
 * @netdev: network interface device structure
 *
 * The set_rx_method entry point is called whenever the multicast address
 * list, unicast address list or the network interface flags are updated.
 * This routine is responsible for configuring the hardware for proper
 * multicast mode and configuring requested unicast filters.
 **/
void txgbe_set_rx_mode(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	unsigned int flags = netdev->flags;
	int xcast_mode;
	u8 *addr_list = NULL;
	int addr_count = 0;

	xcast_mode = (flags & IFF_ALLMULTI) ? TXGBE_XCAST_MODE_ALLMULTI :
		     (flags & (IFF_BROADCAST | IFF_MULTICAST)) ?
		     TXGBE_XCAST_MODE_MULTI : TXGBE_XCAST_MODE_NONE;
		/* request the most inclusive mode we need */
	if (flags & IFF_PROMISC)
		xcast_mode = TXGBE_XCAST_MODE_PROMISC;
	else if (flags & IFF_ALLMULTI)
		xcast_mode = TXGBE_XCAST_MODE_ALLMULTI;
	else if (flags & (IFF_BROADCAST | IFF_MULTICAST))
		xcast_mode = TXGBE_XCAST_MODE_MULTI;
	else
		xcast_mode = TXGBE_XCAST_MODE_NONE;

	/* reprogram multicast list */
	addr_count = netdev_mc_count(netdev);
	if (addr_count) {
		struct netdev_hw_addr *ha;

		ha = list_first_entry(&netdev->mc.list,
				      struct netdev_hw_addr, list);
		addr_list = ha->addr;
	}

	spin_lock_bh(&adapter->mbx_lock);

	hw->mac.ops.update_xcast_mode(hw, xcast_mode);

	hw->mac.ops.update_mc_addr_list(hw, addr_list, addr_count,
					txgbe_addr_list_itr, false);

	txgbe_write_uc_addr_list(netdev);

	spin_unlock_bh(&adapter->mbx_lock);
}

void txgbe_get_stats64(struct net_device *netdev,
		       struct rtnl_link_stats64 *stats)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	u64 bytes, packets;
	const struct txgbe_ring *ring;
	int i;
	struct rtnl_link_stats64 *net_stats = &adapter->net_stats;

	rcu_read_lock();
	for (i = 0; i < adapter->num_rx_queues; i++) {
		unsigned int start;

		ring = adapter->rx_ring[i];
		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			bytes = ring->stats.bytes;
			packets = ring->stats.packets;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		stats->rx_bytes += bytes;
		stats->rx_packets += packets;
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		unsigned int start;

		ring = adapter->tx_ring[i];
		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			bytes = ring->stats.bytes;
			packets = ring->stats.packets;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		stats->tx_bytes += bytes;
		stats->tx_packets += packets;
	}
	rcu_read_unlock();

	/* following stats updated by txgbe_watchdog_subtask() */
	stats->multicast	= net_stats->multicast;
	stats->tx_errors	= net_stats->tx_errors;
	stats->tx_dropped	= net_stats->tx_dropped;
	stats->rx_errors	= net_stats->rx_errors;
	stats->rx_dropped	= net_stats->rx_dropped;
	stats->rx_crc_errors	= net_stats->rx_crc_errors;
	stats->rx_length_errors	= net_stats->rx_length_errors;
}

/**
 * txgbe_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
int txgbe_set_mac(struct net_device *netdev, void *p)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;
	int err;

	if (!is_valid_ether_addr((u8 *)addr->sa_data))
		return -EADDRNOTAVAIL;

	spin_lock_bh(&adapter->mbx_lock);

	err = hw->mac.ops.set_rar(hw, 0, (u8 *)addr->sa_data, 0, 1);

	spin_unlock_bh(&adapter->mbx_lock);

	if (err)
		return -EPERM;

	memcpy(hw->mac.addr, addr->sa_data, netdev->addr_len);
	memcpy(hw->mac.perm_addr, addr->sa_data, netdev->addr_len);
	ether_addr_copy(netdev->dev_addr, addr->sa_data);

	return 0;
}

void txgbe_reinit_locked(struct txgbe_adapter *adapter)
{
	WARN_ON(in_interrupt());

	while (test_and_set_bit(__TXGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);

	/*txgbe_down +  free_irq*/
	txgbe_down(adapter);
	txgbe_free_irq(adapter);

	/*txgbe_up +  request_irq*/
	txgbe_configure(adapter);
	txgbe_request_irq(adapter);
	txgbe_up_complete(adapter);

	clear_bit(__TXGBE_RESETTING, &adapter->state);
}

/**
 * txgbe_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
int txgbe_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;
	int ret;

	if (new_mtu < 68 || new_mtu > 9414)
		return -EINVAL;

	/* notify the PF of our intent to use this size of frame */
	ret = txgbe_rlpml_set_vf(hw, max_frame);
	if (ret)
		return -EINVAL;

	e_info(probe, "changing MTU from %d to %d\n",
	       netdev->mtu, new_mtu);

	/* set new MTU */
	netdev->mtu = new_mtu;
	if (netif_running(netdev))
		txgbe_reinit_locked(adapter);

	return 0;
}

void txgbe_tx_timeout_reset(struct txgbe_adapter *adapter)
{
	/* Do the reset outside of interrupt context */
	if (!test_bit(__TXGBE_DOWN, &adapter->state)) {
		adapter->flagsd |= TXGBE_F_REQ_RESET;
		txgbe_service_event_schedule(adapter);
	}
}

/**
 * txgbe_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void txgbe_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	txgbe_tx_timeout_reset(adapter);
}

int txgbe_vlan_rx_add_vid(struct net_device *netdev,
			  __always_unused __be16 proto, u16 vid)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;
	int err;

	spin_lock_bh(&adapter->mbx_lock);

	/* add VID to filter table */
	err = hw->mac.ops.set_vfta(hw, vid, 0, true, false);

	spin_unlock_bh(&adapter->mbx_lock);

	if (!err) {
		if (vid < VLAN_N_VID)
			set_bit(vid, adapter->active_vlans);
	} else {
		e_err(drv, "VF set VLAN failed\n");
		return -EIO;
	}

	return err;
}

int txgbe_vlan_rx_kill_vid(struct net_device *netdev,
			   __always_unused __be16 proto, u16 vid)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	struct txgbe_hw *hw = &adapter->hw;

	spin_lock_bh(&adapter->mbx_lock);

	/* remove VID from filter table */
	hw->mac.ops.set_vfta(hw, vid, 0, false, false);

	spin_unlock_bh(&adapter->mbx_lock);

	clear_bit(vid, adapter->active_vlans);

	return 0;
}

inline u32 txgbe_get_tx_pending(struct txgbe_ring *ring)
{
	struct txgbe_adapter *adapter = netdev_priv(ring->netdev);
	struct txgbe_hw *hw = &adapter->hw;

	u32 head = rd32(hw, TXGBE_VXTDH(ring->reg_idx));
	u32 tail = rd32(hw, TXGBE_VXTDT(ring->reg_idx));

	if (head != tail)
		return (head < tail) ?
			tail - head : (tail + ring->count - head);

	return 0;
}

inline bool txgbe_check_tx_hang(struct txgbe_ring *tx_ring)
{
	u32 tx_done = tx_ring->stats.packets;
	u32 tx_done_old = tx_ring->tx_stats.tx_done_old;
	u32 tx_pending = txgbe_get_tx_pending(tx_ring);

	clear_check_for_tx_hang(tx_ring);

	/* Check for a hung queue, but be thorough. This verifies
	 * that a transmit has been completed since the previous
	 * check AND there is at least one packet pending. The
	 * ARMED bit is set to indicate a potential hang. The
	 * bit is cleared if a pause frame is received to remove
	 * false hang detection due to PFC or 802.3x frames. By
	 * requiring this to fail twice we avoid races with
	 * pfc clearing the ARMED bit and conditions where we
	 * run the check_tx_hang logic with a transmit completion
	 * pending but without time to complete it yet.
	 */
	if (tx_done_old == tx_done && tx_pending)
		/* make sure it is true for two checks in a row */
		return test_and_set_bit(__TXGBE_HANG_CHECK_ARMED,
					&tx_ring->state);
	/* reset the countdown */
	clear_bit(__TXGBE_HANG_CHECK_ARMED, &tx_ring->state);
	/* update completed stats and continue */
	tx_ring->tx_stats.tx_done_old = tx_done;

	return false;
}

/**
 * txgbe_clean_tx_irq - Reclaim resources after transmit completes
 * @q_vector: board private structure
 * @tx_ring: tx ring to clean
 **/
bool txgbe_clean_tx_irq(struct txgbe_q_vector *q_vector,
			struct txgbe_ring *tx_ring, int napi_budget)
{
	struct txgbe_adapter *adapter = q_vector->adapter;
	struct txgbe_tx_buffer *tx_buffer;
	struct txgbe_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = tx_ring->count / 2;
	unsigned int i = tx_ring->next_to_clean;

	if (test_bit(__TXGBE_DOWN, &adapter->state))
		return true;

	tx_buffer = &tx_ring->tx_buffer_info[i];
	tx_desc = TXGBE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		struct txgbe_tx_desc *eop_desc = tx_buffer->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		/* if DD is not set pending work has not been completed */
		if (!(eop_desc->status & TXGBE_TXD_STAT_DD))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buffer->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buffer->bytecount;
		total_packets += tx_buffer->gso_segs;

		/* free the skb */
		napi_consume_skb(tx_buffer->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);

		/* clear tx_buffer data */
		//tx_buffer->skb = NULL;
		dma_unmap_len_set(tx_buffer, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = TXGBE_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buffer, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buffer, dma),
					       dma_unmap_len(tx_buffer, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buffer, len, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buffer++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buffer = tx_ring->tx_buffer_info;
			tx_desc = TXGBE_TX_DESC(tx_ring, 0);
		}

		/* issue prefetch for next Tx descriptor */
		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;
	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_packets;
	u64_stats_update_end(&tx_ring->syncp);
	q_vector->tx.total_bytes += total_bytes;
	q_vector->tx.total_packets += total_packets;

	if (check_for_tx_hang(tx_ring) && txgbe_check_tx_hang(tx_ring)) {
		struct txgbe_hw *hw = &adapter->hw;
		struct txgbe_tx_desc *eop_desc;

		eop_desc = tx_ring->tx_buffer_info[i].next_to_watch;

		pr_err("Detected Tx Unit Hang%s\n"
		       "  Tx Queue             <%d>\n"
		       "  TDH, TDT             <%x>, <%x>\n"
		       "  next_to_use          <%x>\n"
		       "  next_to_clean        <%x>\n"
		       "tx_buffer_info[next_to_clean]\n"
		       "  next_to_watch        <%p>\n"
		       "  eop_desc.status      <%x>\n"
		       "  time_stamp           <%lx>\n"
		       "  jiffies              <%lx>\n",
			   " ",
		       tx_ring->que_idx,
		       rd32(hw, TXGBE_VXTDH(tx_ring->reg_idx)),
		       rd32(hw, TXGBE_VXTDT(tx_ring->reg_idx)),
		       tx_ring->next_to_use, i,
		       eop_desc, (eop_desc ? eop_desc->status : 0),
		       tx_ring->tx_buffer_info[i].time_stamp, jiffies);

		netif_stop_subqueue(tx_ring->netdev,
				    tx_ring->que_idx);

		/* schedule immediate reset if we believe we hung */
		txgbe_tx_timeout_reset(adapter);

		return true;
	}

	netdev_tx_completed_queue(txring_txq(tx_ring), total_packets, total_bytes);

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_packets && netif_carrier_ok(tx_ring->netdev) &&
		     (txgbe_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();

		if (__netif_subqueue_stopped(tx_ring->netdev, tx_ring->que_idx) &&
		    !test_bit(__TXGBE_DOWN, &adapter->state)) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->que_idx);
			++tx_ring->tx_stats.tx_restart_queue;
		}
	}

	return !!budget;
}

/**
 * txgbe_poll - NAPI polling calback
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean more than one or more rings associated with a
 * q_vector.
 **/
int txgbe_poll(struct napi_struct *napi, int budget)
{
	struct txgbe_q_vector *q_vector =
		container_of(napi, struct txgbe_q_vector, napi);
	struct txgbe_adapter *adapter = q_vector->adapter;
	struct txgbe_ring *ring;
	int per_ring_budget, work_done = 0;
	bool clean_complete = true;

	txgbe_for_each_ring(ring, q_vector->tx) {
		if (!txgbe_clean_tx_irq(q_vector, ring, budget))
			clean_complete = false;
	}

	if (budget <= 0)
		return budget;

	/* attempt to distribute budget to each queue fairly, but don't allow
	 * the budget to go below 1 because we'll exit polling
	 */
	if (q_vector->rx.count > 1)
		per_ring_budget = max(budget / q_vector->rx.count, 1);
	else
		per_ring_budget = budget;

	txgbe_for_each_ring(ring, q_vector->rx) {
		int cleaned = txgbe_clean_rx_irq(q_vector, ring,
						   per_ring_budget);
		work_done += cleaned;
		if (cleaned >= per_ring_budget)
			clean_complete = false;
	}

	/* If all work not completed, return budget and keep polling */
	if (!clean_complete)
		return budget;

	/* all work done, exit the polling mode */
	napi_complete(napi);
	if (adapter->rx_itr_setting == 1)
		txgbe_set_itr(q_vector);
	if (!test_bit(__TXGBE_DOWN, &adapter->state)) {
		if (q_vector->v_idx > 2)
			txgbe_irq_enable_queues(adapter, 1 << (q_vector->v_idx >> 2));
		else
			txgbe_irq_enable_queues(adapter, 1 << q_vector->v_idx);
	}

	return 0;
}

void txgbe_service_event_schedule(struct txgbe_adapter *adapter)
{
	if (!test_bit(__TXGBE_DOWN, &adapter->state) &&
	    !test_bit(__TXGBE_REMOVING, &adapter->state) &&
	    !test_and_set_bit(__TXGBE_SERVICE_SCHED, &adapter->state))
		schedule_work(&adapter->service_task);
}

static void txgbe_service_event_complete(struct txgbe_adapter *adapter)
{
	WARN_ON(!test_bit(__TXGBE_SERVICE_SCHED, &adapter->state));

	/* flush memory to make sure
	 * state is correct before next watchdog
	 */
	smp_mb__before_atomic();
	clear_bit(__TXGBE_SERVICE_SCHED, &adapter->state);
}

/**
 * txgbe_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
void txgbe_free_q_vectors(struct txgbe_adapter *adapter)
{
	int v_idx = adapter->num_q_vectors;

	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		txgbe_free_q_vector(adapter, v_idx);
}

/**
 * txgbe_clear_interrupt_scheme - Clear the current interrupt scheme settings
 * @adapter: board private structure to clear interrupt scheme on
 *
 * We go through and clear interrupt specific resources and reset the structure
 * to pre-load conditions
 **/
void txgbe_clear_interrupt_scheme(struct txgbe_adapter *adapter)
{
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;

	txgbe_free_q_vectors(adapter);
	txgbe_reset_interrupt_capability(adapter);
}

static void txgbe_queue_reset_subtask(struct txgbe_adapter *adapter)
{
	struct net_device *dev = adapter->netdev;

	if (!(adapter->flagsd & TXGBE_F_REQ_QUEUE_RESET))
		return;

	adapter->flagsd &= ~TXGBE_F_REQ_QUEUE_RESET;

	/* if interface is down do nothing */
	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_RESETTING, &adapter->state))
		return;

	/* Hardware has to reinitialize queues and interrupts to
	 * match packet buffer alignment. Unfortunately, the
	 * hardware is not flexible enough to do this dynamically.
	 */
	rtnl_lock();

	/* disable running interface */
	if (netif_running(dev))
		txgbe_close(dev);

	/* free and reallocate queues */
	txgbe_clear_interrupt_scheme(adapter);
	txgbe_init_interrupt_scheme(adapter);

	/* reenable running interface */
	if (netif_running(dev))
		txgbe_open(dev);

	rtnl_unlock();
}

static void txgbe_reset_subtask(struct txgbe_adapter *adapter)
{
	if (!(adapter->flagsd & TXGBE_F_REQ_RESET))
		return;

	adapter->flagsd &= ~TXGBE_F_REQ_RESET;

	/* If we're already down or resetting, just bail */
	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_RESETTING, &adapter->state))
		return;

	adapter->sw_stats.tx_timeout_count++;

	txgbe_reinit_locked(adapter);
}

/**
 * txgbe_watchdog_update_link - update the link status
 * @adapter - pointer to the device adapter structure
 **/
static void txgbe_watchdog_update_link(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	s32 err;

	spin_lock_bh(&adapter->mbx_lock);

	err = hw->mac.ops.check_link(hw, &link_speed, &link_up, false);

	spin_unlock_bh(&adapter->mbx_lock);

	/* if check for link returns error we will need to reset */
	if (err && time_after(jiffies, adapter->last_reset + (10 * HZ))) {
		adapter->flagsd |= TXGBE_F_REQ_RESET;
		link_up = false;
	}

	adapter->link_up = link_up;
	adapter->link_speed = link_speed;
}

/**
 * txgbe_watchdog_link_is_up - update netif_carrier status and
 *                               print link up message
 * @adapter - pointer to the device adapter structure
 **/
static void txgbe_watchdog_link_is_up(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	/* only continue if link was previously down */
	if (netif_carrier_ok(netdev))
		return;

	dev_info(&adapter->pdev->dev, "NIC Link is Up %s\n",
		 (adapter->link_speed == TXGBE_LINK_SPEED_10GB_FULL) ?
		 "10 Gbps" :
		 (adapter->link_speed == TXGBE_LINK_SPEED_1GB_FULL) ?
		 "1 Gbps" :
		 (adapter->link_speed == TXGBE_LINK_SPEED_100_FULL) ?
		 "100 Mbps" :
		 "unknown speed");

	netif_carrier_on(netdev);
}

/**
 * txgbe_watchdog_link_is_down - update netif_carrier status and
 *                                 print link down message
 * @adapter - pointer to the adapter structure
 **/
static void txgbe_watchdog_link_is_down(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	adapter->link_speed = 0;

	/* only continue if link was up previously */
	if (!netif_carrier_ok(netdev))
		return;

	dev_info(&adapter->pdev->dev, "NIC Link is Down\n");

	netif_carrier_off(netdev);
}

void txgbe_update32(struct txgbe_hw *hw, u32 reg,
		    u64 *last, u64 *counter)
{
	u64 curr = rd32(hw, reg);

	if (curr < *last)
		*counter += 0x100000000LL;
	*last = curr;
	*counter &= 0xFFFFFFFF00000000LL;
	*counter |= curr;
}

void txgbe_update36(struct txgbe_hw *hw, u32 loreg, u32 hireg,
		    u64 *last, u64 *counter)
{
	u64 lo32 = rd32(hw, loreg); /* snapshot */
	u64 hi32 = rd32(hw, hireg);
	u64 curr = hi32 << 32 | lo32;

	if (curr < *last)
		*counter += 0x1000000000LL;
	*last = curr;
	*counter &= 0xFFFFFFF000000000LL;
	*counter |= curr;
}

/**
 * txgbe_update_stats - Update the board statistics counters.
 * @adapter: board private structure
 **/
void txgbe_update_stats(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct txgbe_ring *ring;
	struct rtnl_link_stats64 *net_stats = &adapter->net_stats;
	u64 tx_restart_queue = 0, tx_busy = 0;
	u64 rx_csum_bad = 0;
	u32 page_failed = 0, buff_failed = 0;
	u32 i;

	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_RESETTING, &adapter->state))
		return;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		rx_csum_bad += ring->rx_stats.csum_err;
		page_failed += ring->rx_stats.alloc_rx_page_failed;
		buff_failed += ring->rx_stats.alloc_rx_buff_failed;
	}
	adapter->sw_stats.rx_csum_bad = rx_csum_bad;
	adapter->sw_stats.rx_alloc_page_failed = page_failed;
	adapter->sw_stats.rx_alloc_buff_failed = buff_failed;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		ring = adapter->tx_ring[i];
		tx_restart_queue += ring->tx_stats.tx_restart_queue;
		tx_busy += ring->tx_stats.tx_busy;
	}
	adapter->sw_stats.tx_restart_queue = tx_restart_queue;
	adapter->sw_stats.tx_busy = tx_busy;

	/* update hardware counters */
	spin_lock(&adapter->pf_count_lock);
	adapter->last_stats.gprc = adapter->reset_stats.gprc;
	adapter->stats.gprc = adapter->reset_stats.gprc;

	adapter->last_stats.gptc = adapter->reset_stats.gptc;
	adapter->stats.gptc = adapter->reset_stats.gptc;

	adapter->last_stats.gorc = adapter->reset_stats.gorc;
	adapter->stats.gorc = adapter->reset_stats.gorc;

	adapter->last_stats.gotc = adapter->reset_stats.gotc;
	adapter->stats.gotc = adapter->reset_stats.gotc;

	adapter->last_stats.mprc = adapter->reset_stats.mprc;
	adapter->stats.mprc = adapter->reset_stats.mprc;

	for (i = 0; i < MAX_TX_QUEUES; i++) {
		adapter->last_stats.gprc += adapter->last_reg_stats[i].gprc;
		txgbe_update32(hw, TXGBE_VXGPRC(i), &adapter->last_reg_stats[i].gprc,
			       &adapter->reg_stats[i].gprc);
		adapter->stats.gprc += adapter->reg_stats[i].gprc;

		adapter->last_stats.gptc += adapter->last_reg_stats[i].gptc;
		txgbe_update32(hw, TXGBE_VXGPTC(i), &adapter->last_reg_stats[i].gptc,
			       &adapter->reg_stats[i].gptc);
		adapter->stats.gptc += adapter->reg_stats[i].gptc;

		adapter->last_stats.gorc += adapter->last_reg_stats[i].gorc;
		txgbe_update36(hw, TXGBE_VXGORC_LSB(i), TXGBE_VXGORC_MSB(i),
			       &adapter->last_reg_stats[i].gorc, &adapter->reg_stats[i].gorc);
		adapter->stats.gorc += adapter->reg_stats[i].gorc;

		adapter->last_stats.gotc += adapter->last_reg_stats[i].gotc;
		txgbe_update36(hw, TXGBE_VXGOTC_LSB(i), TXGBE_VXGOTC_MSB(i),
			       &adapter->last_reg_stats[i].gotc, &adapter->reg_stats[i].gotc);
		adapter->stats.gotc += adapter->reg_stats[i].gotc;

		adapter->last_stats.mprc += adapter->last_reg_stats[i].mprc;
		txgbe_update32(hw, TXGBE_VXMPRC(i), &adapter->last_reg_stats[i].mprc,
			       &adapter->reg_stats[i].mprc);
		adapter->stats.mprc += adapter->reg_stats[i].mprc;
	}
	spin_unlock(&adapter->pf_count_lock);

	/* update global counters */
	net_stats->multicast = adapter->stats.mprc - adapter->base_stats.mprc;
	net_stats->rx_crc_errors = rx_csum_bad;
}

static void txgbe_watchdog_subtask(struct txgbe_adapter *adapter)
{
	/* if interface is down do nothing */
	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_RESETTING, &adapter->state))
		return;

	txgbe_watchdog_update_link(adapter);
	if (adapter->link_up && adapter->link_state)
		txgbe_watchdog_link_is_up(adapter);
	else
		txgbe_watchdog_link_is_down(adapter);

	txgbe_update_stats(adapter);
}

/* txgbe_check_hang_subtask - check for hung queues and dropped interrupts
 * @adapter - pointer to the device adapter structure
 *
 * This function serves two purposes.  First it strobes the interrupt lines
 * in order to make certain interrupts are occurring.  Secondly it sets the
 * bits needed to check for TX hangs.  As a result we should immediately
 * determine if a hang has occurred.
 */
static void txgbe_check_hang_subtask(struct txgbe_adapter *adapter)
{
	int i;

	/* If we're down or resetting, just bail */
	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_RESETTING, &adapter->state))
		return;

	/* Force detection of hung controller */
	if (netif_carrier_ok(adapter->netdev)) {
		for (i = 0; i < adapter->num_tx_queues; i++)
			set_check_for_tx_hang(adapter->tx_ring[i]);
	}
}

/**
 * txgbe_service_task - manages and runs subtasks
 * @work: pointer to work_struct containing our data
 **/
void txgbe_service_task(struct work_struct *work)
{
	struct txgbe_adapter *adapter = container_of(work,
						       struct txgbe_adapter,
						       service_task);
	struct txgbe_hw *hw = &adapter->hw;

	if (unlikely(!hw->hw_addr)) {
		if (!test_bit(__TXGBE_DOWN, &adapter->state)) {
			rtnl_lock();
			txgbe_down(adapter);
			rtnl_unlock();
		}
		txgbe_service_event_complete(adapter);
		return;
	}

	txgbe_queue_reset_subtask(adapter);
	txgbe_reset_subtask(adapter);
	txgbe_watchdog_subtask(adapter);
	txgbe_check_hang_subtask(adapter);

	txgbe_service_event_complete(adapter);
}

#define TXGBE_MAX_TUNNEL_HDR_LEN 80
static netdev_features_t
txgbe_features_check(struct sk_buff *skb, struct net_device *dev,
		     netdev_features_t features)
{
	u32 vlan_num = 0;
	u16 vlan_depth = skb->mac_len;
	__be16 type = skb->protocol;
	struct vlan_hdr *vh;

	if (skb_vlan_tag_present(skb))
		vlan_num++;

	if (vlan_depth)
		vlan_depth -= VLAN_HLEN;
	else
		vlan_depth = ETH_HLEN;

	while (type == htons(ETH_P_8021Q) || type == htons(ETH_P_8021AD)) {
		vlan_num++;
		vh = (struct vlan_hdr *)(skb->data + vlan_depth);
		type = vh->h_vlan_encapsulated_proto;
		vlan_depth += VLAN_HLEN;
	}

	if (vlan_num > 2)
		features &= ~(NETIF_F_HW_VLAN_CTAG_TX |
			    NETIF_F_HW_VLAN_STAG_TX);

	if (skb->encapsulation) {
		if (unlikely(skb_inner_mac_header(skb) -
			     skb_transport_header(skb) >
			     TXGBE_MAX_TUNNEL_HDR_LEN)){
			return features & ~NETIF_F_CSUM_MASK;
			}
	}
	return features;
}

static const struct net_device_ops txgbe_netdev_ops = {
	.ndo_open               = txgbe_open,
	.ndo_stop               = txgbe_close,
	.ndo_start_xmit         = txgbe_xmit_frame,
	.ndo_set_rx_mode        = txgbe_set_rx_mode,
	.ndo_get_stats64        = txgbe_get_stats64,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_set_mac_address    = txgbe_set_mac,
	.ndo_change_mtu         = txgbe_change_mtu,
	.ndo_tx_timeout         = txgbe_tx_timeout,
	.ndo_vlan_rx_add_vid    = txgbe_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid   = txgbe_vlan_rx_kill_vid,
	.ndo_features_check     = txgbe_features_check,
};

void txgbe_assign_netdev_ops(struct net_device *dev)
{
	dev->netdev_ops = &txgbe_netdev_ops;
	txgbe_set_ethtool_ops(dev);
	dev->watchdog_timeo = 5 * HZ;
}

/**
 * txgbe_service_timer - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
void txgbe_service_timer(struct timer_list *t)
{
	struct txgbe_adapter *adapter = from_timer(adapter, t, service_timer);

	/* Reset the timer */
	mod_timer(&adapter->service_timer, (HZ * 2) + jiffies);

	txgbe_service_event_schedule(adapter);
}

/**
 * txgbe_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in txgbe_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * txgbe_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int txgbe_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct txgbe_adapter *adapter = NULL;
	struct net_device *netdev;
	int err;
	struct txgbe_hw *hw = NULL;
	const struct txgbe_info *ei = txgbe_info_tbl[ent->driver_data];
	static int cards_found;
	unsigned int min_mtu, max_mtu;
	u8 fea_flags = 0;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = pci_request_selected_regions(pdev,
					   pci_select_bars(pdev, IORESOURCE_MEM),
					   txgbe_driver_name);
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed 0x%x\n", err);
		goto err_pci_disable_dev;
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev,
			"No usable DMA configuration, aborting\n");
		goto err_pci_disable_dev;
	}
	fea_flags |= 0x1;

	netdev = devm_alloc_etherdev_mqs(&pdev->dev,
					 sizeof(struct txgbe_adapter),
					 TXGBE_VF_MAX_TX_QUEUES,
					 TXGBE_VF_MAX_RX_QUEUES);
	if (!netdev) {
		err = -ENOMEM;
		goto err_pci_release_regions;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;

	hw->back = adapter;
	hw->msg_enable = &adapter->msg_enable;
	hw->pdev = adapter->pdev;
	hw->mac.type = ei->mac;
	adapter->flagsd = ei->flags;
	adapter->msg_enable = DEFAULT_DEBUG_LEVEL;

	pci_save_state(pdev);

	adapter->io_addr = devm_ioremap(&pdev->dev,
					pci_resource_start(pdev, 0),
					pci_resource_len(pdev, 0));
	if (!adapter->io_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}

	adapter->b4_addr = devm_ioremap(&pdev->dev,
					pci_resource_start(pdev, 4),
					pci_resource_len(pdev, 4));
	if (!adapter->b4_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}
	hw->hw_addr = adapter->io_addr;
	hw->b4_addr = adapter->b4_addr;

	txgbe_assign_netdev_ops(netdev);
	adapter->bd_number = cards_found;

		/* setup the private structure */
	err = txgbe_sw_init(adapter);
	if (err)
		goto err_sw_init;

	/* netdev offload capabilities */
	txgbe_set_features(adapter, fea_flags);

	/* The HW MAC address was set and/or determined in sw_init */
	ether_addr_copy(netdev->dev_addr, adapter->hw.mac.addr);
	ether_addr_copy(netdev->perm_addr, adapter->hw.mac.addr);

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		dev_info(&pdev->dev,
			 "txgbe: invalid MAC address\n");
		err = -EIO;
		goto err_sw_init;
	}

	min_mtu = ETH_MIN_MTU;
	switch (adapter->hw.api_version) {
	case txgbe_mbox_api_11:
	case txgbe_mbox_api_12:
	case txgbe_mbox_api_13:
		max_mtu = TXGBE_MAX_JUMBO_FRAME_SIZE -
			  (ETH_HLEN + ETH_FCS_LEN);
		break;
	default:
		if (adapter->hw.mac.type != txgbe_mac_sp_vf)
			max_mtu = TXGBE_MAX_JUMBO_FRAME_SIZE -
				  (ETH_HLEN + ETH_FCS_LEN);
		else
			max_mtu = ETH_DATA_LEN + ETH_FCS_LEN;
		break;
	}

	netdev->min_mtu = min_mtu;
	netdev->max_mtu = max_mtu;

	timer_setup(&adapter->service_timer, txgbe_service_timer, 0);

	if (unlikely(!hw->hw_addr)) {
		err = -EIO;
		goto err_sw_init;
	}
	INIT_WORK(&adapter->service_task, txgbe_service_task);
	set_bit(__TXGBE_SERVICE_INITED, &adapter->state);
	clear_bit(__TXGBE_SERVICE_SCHED, &adapter->state);

	err = txgbe_init_interrupt_scheme(adapter);
	if (err)
		goto err_register;

	hw->mac.ops.get_fw_version(hw);

	strcpy(netdev->name, "eth%d");

	err = register_netdev(netdev);
	if (err)
		goto err_sw_init;

	pci_set_drvdata(pdev, netdev);
	netif_carrier_off(netdev);

	netif_tx_stop_all_queues(netdev);
	txgbe_init_last_counter_stats(adapter);
	if (netdev->features & NETIF_F_GRO)
		e_info(probe, "GRO is enabled\n");

	e_info(probe, "%s\n", txgbe_driver_string);
	cards_found++;

	return 0;

err_register:
	txgbe_clear_interrupt_scheme(adapter);
err_sw_init:
	txgbe_reset_interrupt_capability(adapter);
	iounmap(adapter->io_addr);
err_pci_release_regions:
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_disable_dev:
	if (!adapter)
		pci_disable_device(pdev);
	return err;
}

/**
 * txgbe_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * txgbe_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void txgbe_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct txgbe_adapter *adapter;
	bool disable_dev;

	if (!netdev)
		return;
	pdev->dev_flags = pdev->dev_flags & ~PCI_DEV_FLAGS_ASSIGNED;
	adapter = netdev_priv(netdev);

	set_bit(__TXGBE_REMOVING, &adapter->state);
	cancel_work_sync(&adapter->service_task);

	if (netdev->reg_state == NETREG_REGISTERED)
		unregister_netdev(netdev);

	txgbe_clear_interrupt_scheme(adapter);

	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
	e_info(probe, "Remove complete\n");

	disable_dev = !test_and_set_bit(__TXGBE_DISABLED, &adapter->state);

	pci_disable_pcie_error_reporting(pdev);

	if (disable_dev)
		pci_disable_device(pdev);
}

int txgbe_suspend(struct pci_dev *pdev, pm_message_t __maybe_unused state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	int retval = 0;

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		rtnl_lock();
		txgbe_down(adapter);
		txgbe_free_irq(adapter);
		txgbe_free_all_tx_resources(adapter);
		txgbe_free_all_rx_resources(adapter);
		rtnl_unlock();
	}

	txgbe_clear_interrupt_scheme(adapter);

	retval = pci_save_state(pdev);
	if (retval)
		return retval;

	if (!test_and_set_bit(__TXGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);

	return 0;
}

int txgbe_resume(struct pci_dev *pdev)
{
	struct txgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;
	u32 err;

	pci_restore_state(pdev);
	pci_save_state(pdev);

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device from suspend\n");
		return err;
	}

	adapter->hw.hw_addr = adapter->io_addr;

	/* protect context */
	smp_mb__before_atomic();
	clear_bit(__TXGBE_DISABLED, &adapter->state);
	pci_set_master(pdev);

	txgbe_reset(adapter);

	rtnl_lock();
	err = txgbe_init_interrupt_scheme(adapter);
	if (!err && netif_running(netdev))
		err = txgbe_open(netdev);
	rtnl_unlock();
	if (err)
		return err;

	netif_device_attach(netdev);

	return err;
}

static struct pci_driver txgbe_driver = {
	.name     = txgbe_driver_name,
	.id_table = txgbe_pci_tbl,
	.probe    = txgbe_probe,
	.remove   = txgbe_remove,
	.suspend  = txgbe_suspend,
	.resume   = txgbe_resume,
};

/**
 * txgbe_init_module - Driver Registration Routine
 *
 * txgbe_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init txgbe_init_module(void)
{
	int ret;

	ret = pci_register_driver(&txgbe_driver);
	return ret;
}

module_init(txgbe_init_module);

/**
 * txgbe_exit_module - Driver Exit Cleanup Routine
 *
 * txgbe_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit txgbe_exit_module(void)
{
	pci_unregister_driver(&txgbe_driver);
}

module_exit(txgbe_exit_module);

MODULE_DEVICE_TABLE(pci, txgbe_pci_tbl);
MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <software@trustnetic.com>");
MODULE_DESCRIPTION("WangXun(R) 10 Gigabit PCI Express Virtual Function Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
