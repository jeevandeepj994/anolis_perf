// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/aer.h>
#include <linux/etherdevice.h>

#include "txgbe.h"
#include "txgbe_hw.h"
#include "txgbe_phy.h"

char txgbe_driver_name[] = "txgbe";

static const char txgbe_overheat_msg[] =
	"Network adapter has been stopped because it has over heated."
	"If the problem persists, restart or power off the system and replace the adapter.";
static const char txgbe_underheat_msg[] =
	"Network adapter has been started again, the temperature has been back to normal state";

/* txgbe_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id txgbe_pci_tbl[] = {
	{ PCI_VDEVICE(WANGXUN, TXGBE_DEV_ID_SP1000), 0},
	{ PCI_VDEVICE(WANGXUN, TXGBE_DEV_ID_WX1820), 0},
	/* required last entry */
	{ .device = 0 }
};

#define DEFAULT_DEBUG_LEVEL_SHIFT 3

static struct workqueue_struct *txgbe_wq;

static bool txgbe_is_sfp(struct txgbe_hw *hw);

static void txgbe_check_minimum_link(struct txgbe_adapter *adapter,
				     int expected_gts)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev;

	/* Some devices are not connected over PCIe and thus do not negotiate
	 * speed. These devices do not have valid bus info, and thus any report
	 * we generate may not be correct.
	 */
	if (hw->bus.type == txgbe_bus_type_internal)
		return;

	pdev = adapter->pdev;
	pcie_print_link_status(pdev);
}

/**
 * txgbe_enumerate_functions - Get the number of ports this device has
 * @adapter: adapter structure
 *
 * This function enumerates the phsyical functions co-located on a single slot,
 * in order to determine how many ports a device has. This is most useful in
 * determining the required GT/s of PCIe bandwidth necessary for optimal
 * performance.
 **/
static inline int txgbe_enumerate_functions(struct txgbe_adapter *adapter)
{
	struct pci_dev *entry, *pdev = adapter->pdev;
	int physfns = 0;

	list_for_each_entry(entry, &pdev->bus->devices, bus_list) {
		/* When the devices on the bus don't all match our device ID,
		 * we can't reliably determine the correct number of
		 * functions. This can occur if a function has been direct
		 * attached to a virtual machine using VT-d, for example. In
		 * this case, simply return -1 to indicate this.
		 */
		if (entry->vendor != pdev->vendor ||
		    entry->device != pdev->device)
			return -1;

		physfns++;
	}

	return physfns;
}

void txgbe_service_event_schedule(struct txgbe_adapter *adapter)
{
	if (!test_bit(__TXGBE_DOWN, &adapter->state) &&
	    !test_bit(__TXGBE_REMOVING, &adapter->state) &&
	    !test_and_set_bit(__TXGBE_SERVICE_SCHED, &adapter->state))
		queue_work(txgbe_wq, &adapter->service_task);
}

static void txgbe_service_event_complete(struct txgbe_adapter *adapter)
{
	if (WARN_ON(!test_bit(__TXGBE_SERVICE_SCHED, &adapter->state)))
		return;

	/* flush memory to make sure state is correct before next watchdog */
	smp_mb__before_atomic();
	clear_bit(__TXGBE_SERVICE_SCHED, &adapter->state);
}

static void txgbe_remove_adapter(struct txgbe_hw *hw)
{
	struct txgbe_adapter *adapter = container_of(hw, struct txgbe_adapter, hw);

	if (!hw->hw_addr)
		return;
	hw->hw_addr = NULL;
	dev_info(&adapter->pdev->dev, "Adapter removed\n");
	if (test_bit(__TXGBE_SERVICE_INITED, &adapter->state))
		txgbe_service_event_schedule(adapter);
}

static bool txgbe_check_cfg_remove(struct txgbe_hw *hw, struct pci_dev *pdev)
{
	u16 value;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &value);
	if (value == TXGBE_FAILED_READ_CFG_WORD) {
		txgbe_remove_adapter(hw);
		return true;
	}
	return false;
}

static void txgbe_release_hw_control(struct txgbe_adapter *adapter)
{
	/* Let firmware take over control of hw */
	wr32m(&adapter->hw, TXGBE_CFG_PORT_CTL,
	      TXGBE_CFG_PORT_CTL_DRV_LOAD, 0);
}

static void txgbe_get_hw_control(struct txgbe_adapter *adapter)
{
	/* Let firmware know the driver has taken over */
	wr32m(&adapter->hw, TXGBE_CFG_PORT_CTL,
	      TXGBE_CFG_PORT_CTL_DRV_LOAD, TXGBE_CFG_PORT_CTL_DRV_LOAD);
}

/**
 * txgbe_set_ivar - set the IVAR registers, mapping interrupt causes to vectors
 * @adapter: pointer to adapter struct
 * @direction: 0 for Rx, 1 for Tx, -1 for other causes
 * @queue: queue to map the corresponding interrupt to
 * @msix_vector: the vector to map to the corresponding queue
 *
 **/
static void txgbe_set_ivar(struct txgbe_adapter *adapter, s8 direction,
			   u16 queue, u16 msix_vector)
{
	u32 ivar, index;
	struct txgbe_hw *hw = &adapter->hw;

	if (direction == -1) {
		/* other causes */
		msix_vector |= TXGBE_PX_IVAR_ALLOC_VAL;
		index = 0;
		ivar = rd32(&adapter->hw, TXGBE_PX_MISC_IVAR);
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		wr32(&adapter->hw, TXGBE_PX_MISC_IVAR, ivar);
	} else {
		/* tx or rx causes */
		msix_vector |= TXGBE_PX_IVAR_ALLOC_VAL;
		index = ((16 * (queue & 1)) + (8 * direction));
		ivar = rd32(hw, TXGBE_PX_IVAR(queue >> 1));
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		wr32(hw, TXGBE_PX_IVAR(queue >> 1), ivar);
	}
}

/**
 * txgbe_configure_msix - Configure MSI-X hardware
 * @adapter: board private structure
 *
 * txgbe_configure_msix sets up the hardware to properly generate MSI-X
 * interrupts.
 **/
static void txgbe_configure_msix(struct txgbe_adapter *adapter)
{
	u16 v_idx;

	/* Populate MSIX to EITR Select */
	wr32(&adapter->hw, TXGBE_PX_ITRSEL, 0);

	/* Populate the IVAR table and set the ITR values to the
	 * corresponding register.
	 */
	for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
		struct txgbe_q_vector *q_vector = adapter->q_vector[v_idx];
		struct txgbe_ring *ring;

		txgbe_for_each_ring(ring, q_vector->rx)
			txgbe_set_ivar(adapter, 0, ring->reg_idx, v_idx);

		txgbe_for_each_ring(ring, q_vector->tx)
			txgbe_set_ivar(adapter, 1, ring->reg_idx, v_idx);

		txgbe_write_eitr(q_vector);
	}

	txgbe_set_ivar(adapter, -1, 0, v_idx);

	wr32(&adapter->hw, TXGBE_PX_ITR(v_idx), 1950);
}

/**
 * txgbe_write_eitr - write EITR register in hardware specific way
 * @q_vector: structure containing interrupt and ring information
 *
 * This function is made to be called by ethtool and by the driver
 * when it needs to update EITR registers at runtime.  Hardware
 * specific quirks/differences are taken care of here.
 */
void txgbe_write_eitr(struct txgbe_q_vector *q_vector)
{
	struct txgbe_adapter *adapter = q_vector->adapter;
	struct txgbe_hw *hw = &adapter->hw;
	int v_idx = q_vector->v_idx;
	u32 itr_reg = q_vector->itr & TXGBE_MAX_EITR;

	itr_reg |= TXGBE_PX_ITR_CNT_WDIS;

	wr32(hw, TXGBE_PX_ITR(v_idx), itr_reg);
}

/**
 * txgbe_check_overtemp_subtask - check for over temperature
 * @adapter: pointer to adapter
 **/
static void txgbe_check_overtemp_subtask(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 eicr = adapter->interrupt_event;
	s32 temp_state;

	if (test_bit(__TXGBE_DOWN, &adapter->state))
		return;
	if (!(adapter->flags2 & TXGBE_FLAG2_TEMP_SENSOR_EVENT))
		return;

	adapter->flags2 &= ~TXGBE_FLAG2_TEMP_SENSOR_EVENT;

	/* Since the warning interrupt is for both ports
	 * we don't have to check if:
	 *  - This interrupt wasn't for our port.
	 *  - We may have missed the interrupt so always have to
	 *    check if we  got a LSC
	 */
	if (!(eicr & TXGBE_PX_MISC_IC_OVER_HEAT))
		return;

	temp_state = TCALL(hw, phy.ops.check_overtemp);
	if (!temp_state || temp_state == TXGBE_NOT_IMPLEMENTED)
		return;

	if (temp_state == TXGBE_ERR_UNDERTEMP &&
	    test_bit(__TXGBE_HANGING, &adapter->state)) {
		netif_crit(adapter, drv, adapter->netdev,
			   "%s\n", txgbe_underheat_msg);
		wr32m(&adapter->hw, TXGBE_RDB_PB_CTL,
		      TXGBE_RDB_PB_CTL_RXEN, TXGBE_RDB_PB_CTL_RXEN);
		netif_carrier_on(adapter->netdev);
		clear_bit(__TXGBE_HANGING, &adapter->state);
	} else if (temp_state == TXGBE_ERR_OVERTEMP &&
		!test_and_set_bit(__TXGBE_HANGING, &adapter->state)) {
		netif_crit(adapter, drv, adapter->netdev,
			   "%s\n", txgbe_overheat_msg);
		netif_carrier_off(adapter->netdev);
		wr32m(&adapter->hw, TXGBE_RDB_PB_CTL,
		      TXGBE_RDB_PB_CTL_RXEN, 0);
	}

	adapter->interrupt_event = 0;
}

static void txgbe_check_overtemp_event(struct txgbe_adapter *adapter, u32 eicr)
{
	if (!(eicr & TXGBE_PX_MISC_IC_OVER_HEAT))
		return;

	if (!test_bit(__TXGBE_DOWN, &adapter->state)) {
		adapter->interrupt_event = eicr;
		adapter->flags2 |= TXGBE_FLAG2_TEMP_SENSOR_EVENT;
		txgbe_service_event_schedule(adapter);
	}
}

static void txgbe_check_sfp_event(struct txgbe_adapter *adapter, u32 eicr)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 eicr_mask = TXGBE_PX_MISC_IC_GPIO;
	u32 reg;

	if (eicr & eicr_mask) {
		if (!test_bit(__TXGBE_DOWN, &adapter->state)) {
			wr32(hw, TXGBE_GPIO_INTMASK, 0xFF);
			reg = rd32(hw, TXGBE_GPIO_INTSTATUS);
			if (reg & TXGBE_GPIO_INTSTATUS_2) {
				adapter->flags2 |= TXGBE_FLAG2_SFP_NEEDS_RESET;
				wr32(hw, TXGBE_GPIO_EOI,
				     TXGBE_GPIO_EOI_2);
				adapter->sfp_poll_time = 0;
				txgbe_service_event_schedule(adapter);
			}
			if (reg & TXGBE_GPIO_INTSTATUS_3) {
				adapter->flags |= TXGBE_FLAG_NEED_LINK_CONFIG;
				wr32(hw, TXGBE_GPIO_EOI,
				     TXGBE_GPIO_EOI_3);
				txgbe_service_event_schedule(adapter);
			}

			if (reg & TXGBE_GPIO_INTSTATUS_6) {
				wr32(hw, TXGBE_GPIO_EOI,
				     TXGBE_GPIO_EOI_6);
				adapter->flags |=
					TXGBE_FLAG_NEED_LINK_CONFIG;
				txgbe_service_event_schedule(adapter);
			}
			wr32(hw, TXGBE_GPIO_INTMASK, 0x0);
		}
	}
}

static void txgbe_check_lsc(struct txgbe_adapter *adapter)
{
	adapter->lsc_int++;
	adapter->flags |= TXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;
	if (!test_bit(__TXGBE_DOWN, &adapter->state))
		txgbe_service_event_schedule(adapter);
}

/**
 * txgbe_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 * @queues: enable irqs for queues
 * @flush: flush register write
 **/
void txgbe_irq_enable(struct txgbe_adapter *adapter, bool queues, bool flush)
{
	u32 mask = 0;
	struct txgbe_hw *hw = &adapter->hw;
	u8 device_type = hw->subsystem_device_id & 0xF0;

	/* enable gpio interrupt */
	if (device_type != TXGBE_ID_MAC_XAUI &&
	    device_type != TXGBE_ID_MAC_SGMII) {
		mask |= TXGBE_GPIO_INTEN_2;
		mask |= TXGBE_GPIO_INTEN_3;
		mask |= TXGBE_GPIO_INTEN_6;
	}
	wr32(&adapter->hw, TXGBE_GPIO_INTEN, mask);

	if (device_type != TXGBE_ID_MAC_XAUI &&
	    device_type != TXGBE_ID_MAC_SGMII) {
		mask = TXGBE_GPIO_INTTYPE_LEVEL_2 | TXGBE_GPIO_INTTYPE_LEVEL_3 |
			TXGBE_GPIO_INTTYPE_LEVEL_6;
	}
	wr32(&adapter->hw, TXGBE_GPIO_INTTYPE_LEVEL, mask);

	/* enable misc interrupt */
	mask = TXGBE_PX_MISC_IEN_MASK;

	mask |= TXGBE_PX_MISC_IEN_OVER_HEAT;

	wr32(&adapter->hw, TXGBE_PX_MISC_IEN, mask);

	/* unmask interrupt */
	txgbe_intr_enable(&adapter->hw, TXGBE_INTR_MISC(adapter));
	if (queues)
		txgbe_intr_enable(&adapter->hw, TXGBE_INTR_QALL(adapter));

	/* flush configuration */
	if (flush)
		TXGBE_WRITE_FLUSH(&adapter->hw);
}

static irqreturn_t txgbe_msix_other(int __always_unused irq, void *data)
{
	struct txgbe_adapter *adapter = data;
	struct txgbe_hw *hw = &adapter->hw;
	u32 eicr;
	u32 ecc;

	eicr = txgbe_misc_isb(adapter, TXGBE_ISB_MISC);

	if (eicr & (TXGBE_PX_MISC_IC_ETH_LK | TXGBE_PX_MISC_IC_ETH_LKDN))
		txgbe_check_lsc(adapter);

	if (eicr & TXGBE_PX_MISC_IC_INT_ERR) {
		netif_info(adapter, link, adapter->netdev,
			   "Received unrecoverable ECC Err, initiating reset.\n");
		ecc = rd32(hw, TXGBE_MIS_ST);
		if (((ecc & TXGBE_MIS_ST_LAN0_ECC) && hw->bus.lan_id == 0) ||
		    ((ecc & TXGBE_MIS_ST_LAN1_ECC) && hw->bus.lan_id == 1))
			adapter->flags2 |= TXGBE_FLAG2_PF_RESET_REQUESTED;

		txgbe_service_event_schedule(adapter);
	}
	if (eicr & TXGBE_PX_MISC_IC_DEV_RST) {
		adapter->flags2 |= TXGBE_FLAG2_RESET_INTR_RECEIVED;
		txgbe_service_event_schedule(adapter);
	}
	if ((eicr & TXGBE_PX_MISC_IC_STALL) ||
	    (eicr & TXGBE_PX_MISC_IC_ETH_EVENT)) {
		adapter->flags2 |= TXGBE_FLAG2_PF_RESET_REQUESTED;
		txgbe_service_event_schedule(adapter);
	}

	txgbe_check_sfp_event(adapter, eicr);
	txgbe_check_overtemp_event(adapter, eicr);

	/* re-enable the original interrupt state, no lsc, no queues */
	if (!test_bit(__TXGBE_DOWN, &adapter->state))
		txgbe_irq_enable(adapter, false, false);

	return IRQ_HANDLED;
}

static irqreturn_t txgbe_msix_clean_rings(int __always_unused irq, void *data)
{
	struct txgbe_q_vector *q_vector = data;

	/* EIAM disabled interrupts (on this vector) for us */

	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_schedule_irqoff(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * txgbe_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * txgbe_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
static int txgbe_request_msix_irqs(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int vector, err;
	int ri = 0, ti = 0;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct txgbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-TxRx-%d", netdev->name, ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-rx-%d", netdev->name, ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-tx-%d", netdev->name, ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = request_irq(entry->vector, &txgbe_msix_clean_rings, 0,
				  q_vector->name, q_vector);
		if (err) {
			netif_err(adapter, probe, netdev,
				  "request_irq failed for MSIX interrupt '%s' Error: %d\n",
				  q_vector->name, err);
			goto free_queue_irqs;
		}
	}

	err = request_irq(adapter->msix_entries[vector].vector,
			  txgbe_msix_other, 0, netdev->name, adapter);
	if (err) {
		netif_err(adapter, probe, netdev,
			  "request_irq for msix_other failed: %d\n", err);
		goto free_queue_irqs;
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
		irq_set_affinity_hint(adapter->msix_entries[vector].vector,
				      NULL);
		free_irq(adapter->msix_entries[vector].vector,
			 adapter->q_vector[vector]);
	}
	adapter->flags &= ~TXGBE_FLAG_MSIX_ENABLED;
	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	return err;
}

/**
 * txgbe_intr - legacy mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t txgbe_intr(int __always_unused irq, void *data)
{
	struct txgbe_adapter *adapter = data;
	struct txgbe_q_vector *q_vector = adapter->q_vector[0];
	u32 eicr;
	u32 eicr_misc;

	eicr = txgbe_misc_isb(adapter, TXGBE_ISB_VEC0);
	if (!eicr) {
		/* shared interrupt alert!
		 * the interrupt that we masked before the EICR read.
		 */
		if (!test_bit(__TXGBE_DOWN, &adapter->state))
			txgbe_irq_enable(adapter, true, true);
		return IRQ_NONE;        /* Not our interrupt */
	}
	adapter->isb_mem[TXGBE_ISB_VEC0] = 0;
	if (!(adapter->flags & TXGBE_FLAG_MSI_ENABLED))
		wr32(&adapter->hw, TXGBE_PX_INTA, 1);

	eicr_misc = txgbe_misc_isb(adapter, TXGBE_ISB_MISC);
	if (eicr_misc & (TXGBE_PX_MISC_IC_ETH_LK | TXGBE_PX_MISC_IC_ETH_LKDN))
		txgbe_check_lsc(adapter);

	if (eicr_misc & TXGBE_PX_MISC_IC_INT_ERR) {
		netif_info(adapter, link, adapter->netdev,
			   "Received unrecoverable ECC Err, initiating reset.\n");
		adapter->flags2 |= TXGBE_FLAG2_GLOBAL_RESET_REQUESTED;
		txgbe_service_event_schedule(adapter);
	}

	if (eicr_misc & TXGBE_PX_MISC_IC_DEV_RST) {
		adapter->flags2 |= TXGBE_FLAG2_RESET_INTR_RECEIVED;
		txgbe_service_event_schedule(adapter);
	}
	txgbe_check_sfp_event(adapter, eicr_misc);
	txgbe_check_overtemp_event(adapter, eicr_misc);

	adapter->isb_mem[TXGBE_ISB_MISC] = 0;
	/* would disable interrupts here but it is auto disabled */
	napi_schedule_irqoff(&q_vector->napi);

	/* re-enable link(maybe) and non-queue interrupts, no flush.
	 * txgbe_poll will re-enable the queue interrupts
	 */
	if (!test_bit(__TXGBE_DOWN, &adapter->state))
		txgbe_irq_enable(adapter, false, false);

	return IRQ_HANDLED;
}

/**
 * txgbe_request_irq - initialize interrupts
 * @adapter: board private structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int txgbe_request_irq(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	if (adapter->flags & TXGBE_FLAG_MSIX_ENABLED)
		err = txgbe_request_msix_irqs(adapter);
	else if (adapter->flags & TXGBE_FLAG_MSI_ENABLED)
		err = request_irq(adapter->pdev->irq, &txgbe_intr, 0,
				  netdev->name, adapter);
	else
		err = request_irq(adapter->pdev->irq, &txgbe_intr, IRQF_SHARED,
				  netdev->name, adapter);

	if (err)
		netif_err(adapter, probe, adapter->netdev,
			  "request_irq failed, Error %d\n", err);

	return err;
}

static void txgbe_free_irq(struct txgbe_adapter *adapter)
{
	int vector;

	if (!(adapter->flags & TXGBE_FLAG_MSIX_ENABLED)) {
		free_irq(adapter->pdev->irq, adapter);
		return;
	}

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct txgbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		/* free only the irqs that were actually requested */
		if (!q_vector->rx.ring && !q_vector->tx.ring)
			continue;

		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(entry->vector, NULL);
		free_irq(entry->vector, q_vector);
	}

	free_irq(adapter->msix_entries[vector++].vector, adapter);
}

/**
 * txgbe_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
void txgbe_irq_disable(struct txgbe_adapter *adapter)
{
	wr32(&adapter->hw, TXGBE_PX_MISC_IEN, 0);
	txgbe_intr_disable(&adapter->hw, TXGBE_INTR_ALL);

	TXGBE_WRITE_FLUSH(&adapter->hw);
	if (adapter->flags & TXGBE_FLAG_MSIX_ENABLED) {
		int vector;

		for (vector = 0; vector < adapter->num_q_vectors; vector++)
			synchronize_irq(adapter->msix_entries[vector].vector);

		synchronize_irq(adapter->msix_entries[vector++].vector);
	} else {
		synchronize_irq(adapter->pdev->irq);
	}
}

/**
 * txgbe_configure_msi_and_legacy - Initialize PIN (INTA...) and MSI interrupts
 * @adapter: board private structure
 **/
static void txgbe_configure_msi_and_legacy(struct txgbe_adapter *adapter)
{
	struct txgbe_q_vector *q_vector = adapter->q_vector[0];
	struct txgbe_ring *ring;

	txgbe_write_eitr(q_vector);

	txgbe_for_each_ring(ring, q_vector->rx)
		txgbe_set_ivar(adapter, 0, ring->reg_idx, 0);

	txgbe_for_each_ring(ring, q_vector->tx)
		txgbe_set_ivar(adapter, 1, ring->reg_idx, 0);

	txgbe_set_ivar(adapter, -1, 0, 1);

	netif_info(adapter, hw, adapter->netdev,
		   "Legacy interrupt IVAR setup done\n");
}

static void txgbe_sync_mac_table(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	int i;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state & TXGBE_MAC_STATE_MODIFIED) {
			if (adapter->mac_table[i].state &
					TXGBE_MAC_STATE_IN_USE) {
				TCALL(hw, mac.ops.set_rar, i,
				      adapter->mac_table[i].addr,
				      adapter->mac_table[i].pools,
				      TXGBE_PSR_MAC_SWC_AD_H_AV);
			} else {
				TCALL(hw, mac.ops.clear_rar, i);
			}
			adapter->mac_table[i].state &=
				~(TXGBE_MAC_STATE_MODIFIED);
		}
	}
}

/* this function destroys the first RAR entry */
static void txgbe_mac_set_default_filter(struct txgbe_adapter *adapter,
					 u8 *addr)
{
	struct txgbe_hw *hw = &adapter->hw;

	memcpy(&adapter->mac_table[0].addr, addr, ETH_ALEN);
	adapter->mac_table[0].pools = 1ULL;
	adapter->mac_table[0].state = (TXGBE_MAC_STATE_DEFAULT |
				       TXGBE_MAC_STATE_IN_USE);
	TCALL(hw, mac.ops.set_rar, 0, adapter->mac_table[0].addr,
	      adapter->mac_table[0].pools,
	      TXGBE_PSR_MAC_SWC_AD_H_AV);
}

static void txgbe_flush_sw_mac_table(struct txgbe_adapter *adapter)
{
	u32 i;
	struct txgbe_hw *hw = &adapter->hw;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		adapter->mac_table[i].state |= TXGBE_MAC_STATE_MODIFIED;
		adapter->mac_table[i].state &= ~TXGBE_MAC_STATE_IN_USE;
		memset(adapter->mac_table[i].addr, 0, ETH_ALEN);
		adapter->mac_table[i].pools = 0;
	}
	txgbe_sync_mac_table(adapter);
}

static void txgbe_configure_isb(struct txgbe_adapter *adapter)
{
	/* set ISB Address */
	struct txgbe_hw *hw = &adapter->hw;

	wr32(hw, TXGBE_PX_ISB_ADDR_L,
	     adapter->isb_dma & DMA_BIT_MASK(32));
	wr32(hw, TXGBE_PX_ISB_ADDR_H, adapter->isb_dma >> 32);
}

static void txgbe_configure(struct txgbe_adapter *adapter)
{
	txgbe_configure_isb(adapter);
}

static bool txgbe_is_sfp(struct txgbe_hw *hw)
{
	switch (TCALL(hw, mac.ops.get_media_type)) {
	case txgbe_media_type_fiber:
		return true;
	default:
		return false;
	}
}

static bool txgbe_is_backplane(struct txgbe_hw *hw)
{
	switch (TCALL(hw, mac.ops.get_media_type)) {
	case txgbe_media_type_backplane:
		return true;
	default:
		return false;
	}
}

/**
 * txgbe_sfp_link_config - set up SFP+ link
 * @adapter: pointer to private adapter struct
 **/
static void txgbe_sfp_link_config(struct txgbe_adapter *adapter)
{
	/* We are assuming the worst case scenerio here, and that
	 * is that an SFP was inserted/removed after the reset
	 * but before SFP detection was enabled.  As such the best
	 * solution is to just start searching as soon as we start
	 */

	adapter->flags2 |= TXGBE_FLAG2_SFP_NEEDS_RESET;
	adapter->sfp_poll_time = 0;
}

static void txgbe_setup_gpie(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 gpie = 0;

	if (adapter->flags & TXGBE_FLAG_MSIX_ENABLED)
		gpie = TXGBE_PX_GPIE_MODEL;

	wr32(hw, TXGBE_PX_GPIE, gpie);
}

static void txgbe_up_complete(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 links_reg;

	txgbe_get_hw_control(adapter);
	txgbe_setup_gpie(adapter);

	if (adapter->flags & TXGBE_FLAG_MSIX_ENABLED)
		txgbe_configure_msix(adapter);
	else
		txgbe_configure_msi_and_legacy(adapter);

	/* enable the optics for SFP+ fiber */
	TCALL(hw, mac.ops.enable_tx_laser);

	/* make sure to complete pre-operations */
	smp_mb__before_atomic();
	clear_bit(__TXGBE_DOWN, &adapter->state);

	if (txgbe_is_sfp(hw)) {
		txgbe_sfp_link_config(adapter);
	} else if (txgbe_is_backplane(hw)) {
		adapter->flags |= TXGBE_FLAG_NEED_LINK_CONFIG;
		txgbe_service_event_schedule(adapter);
	}

	links_reg = rd32(hw, TXGBE_CFG_PORT_ST);
	if (links_reg & TXGBE_CFG_PORT_ST_LINK_UP) {
		if (links_reg & TXGBE_CFG_PORT_ST_LINK_10G) {
			wr32(hw, TXGBE_MAC_TX_CFG,
			     (rd32(hw, TXGBE_MAC_TX_CFG) &
			      ~TXGBE_MAC_TX_CFG_SPEED_MASK) |
			     TXGBE_MAC_TX_CFG_SPEED_10G);
		} else if (links_reg & (TXGBE_CFG_PORT_ST_LINK_1G | TXGBE_CFG_PORT_ST_LINK_100M)) {
			wr32(hw, TXGBE_MAC_TX_CFG,
			     (rd32(hw, TXGBE_MAC_TX_CFG) &
			      ~TXGBE_MAC_TX_CFG_SPEED_MASK) |
			     TXGBE_MAC_TX_CFG_SPEED_1G);
		}
	}

	/* clear any pending interrupts, may auto mask */
	rd32(hw, TXGBE_PX_IC(0));
	rd32(hw, TXGBE_PX_IC(1));
	rd32(hw, TXGBE_PX_MISC_IC);
	if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_XAUI)
		wr32(hw, TXGBE_GPIO_EOI, TXGBE_GPIO_EOI_6);
	txgbe_irq_enable(adapter, true, true);

	/* bring the link up in the watchdog, this could race with our first
	 * link up interrupt but shouldn't be a problem
	 */
	adapter->flags |= TXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;

	mod_timer(&adapter->service_timer, jiffies);

	if (hw->bus.lan_id == 0) {
		wr32m(hw, TXGBE_MIS_PRB_CTL,
		      TXGBE_MIS_PRB_CTL_LAN0_UP, TXGBE_MIS_PRB_CTL_LAN0_UP);
	} else if (hw->bus.lan_id == 1) {
		wr32m(hw, TXGBE_MIS_PRB_CTL,
		      TXGBE_MIS_PRB_CTL_LAN1_UP, TXGBE_MIS_PRB_CTL_LAN1_UP);
	} else {
		netif_err(adapter, probe, adapter->netdev,
			  "%s:invalid bus lan id %d\n",
			  __func__, hw->bus.lan_id);
	}

	/* Set PF Reset Done bit so PF/VF Mail Ops can work */
	wr32m(hw, TXGBE_CFG_PORT_CTL,
	      TXGBE_CFG_PORT_CTL_PFRSTD, TXGBE_CFG_PORT_CTL_PFRSTD);
}

void txgbe_reinit_locked(struct txgbe_adapter *adapter)
{
	/* put off any impending NetWatchDogTimeout */
	netif_trans_update(adapter->netdev);

	while (test_and_set_bit(__TXGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);
	txgbe_down(adapter);
	txgbe_up(adapter);
	clear_bit(__TXGBE_RESETTING, &adapter->state);
}

void txgbe_up(struct txgbe_adapter *adapter)
{
	/* hardware has been reset, we need to reload some things */
	txgbe_configure(adapter);

	txgbe_up_complete(adapter);
}

void txgbe_reset(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int err;
	u8 old_addr[ETH_ALEN];

	if (TXGBE_REMOVED(hw->hw_addr))
		return;
	/* lock SFP init bit to prevent race conditions with the watchdog */
	while (test_and_set_bit(__TXGBE_IN_SFP_INIT, &adapter->state))
		usleep_range(1000, 2000);

	/* clear all SFP and link config related flags while holding SFP_INIT */
	adapter->flags2 &= ~TXGBE_FLAG2_SFP_NEEDS_RESET;
	adapter->flags &= ~TXGBE_FLAG_NEED_LINK_CONFIG;

	err = TCALL(hw, mac.ops.init_hw);
	switch (err) {
	case 0:
	case TXGBE_ERR_SFP_NOT_PRESENT:
	case TXGBE_ERR_SFP_NOT_SUPPORTED:
		break;
	case TXGBE_ERR_MASTER_REQUESTS_PENDING:
		dev_err(&adapter->pdev->dev, "master disable timed out\n");
		break;
	default:
		dev_err(&adapter->pdev->dev, "Hardware Error: %d\n", err);
	}

	clear_bit(__TXGBE_IN_SFP_INIT, &adapter->state);
	/* do not flush user set addresses */
	memcpy(old_addr, &adapter->mac_table[0].addr, netdev->addr_len);
	txgbe_flush_sw_mac_table(adapter);
	txgbe_mac_set_default_filter(adapter, old_addr);

	/* update SAN MAC vmdq pool selection */
	TCALL(hw, mac.ops.set_vmdq_san_mac, 0);
}

void txgbe_disable_device(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct txgbe_hw *hw = &adapter->hw;
	u32 i;

	/* signal that we are down to the interrupt handler */
	if (test_and_set_bit(__TXGBE_DOWN, &adapter->state))
		return; /* do nothing if already down */

	txgbe_disable_pcie_master(hw);
	/* disable receives */
	TCALL(hw, mac.ops.disable_rx);

	/* call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	txgbe_irq_disable(adapter);

	adapter->flags2 &= ~(TXGBE_FLAG2_PF_RESET_REQUESTED |
			     TXGBE_FLAG2_GLOBAL_RESET_REQUESTED);
	adapter->flags &= ~TXGBE_FLAG_NEED_LINK_UPDATE;

	del_timer_sync(&adapter->service_timer);

	if (hw->bus.lan_id == 0)
		wr32m(hw, TXGBE_MIS_PRB_CTL, TXGBE_MIS_PRB_CTL_LAN0_UP, 0);
	else if (hw->bus.lan_id == 1)
		wr32m(hw, TXGBE_MIS_PRB_CTL, TXGBE_MIS_PRB_CTL_LAN1_UP, 0);
	else
		dev_err(&adapter->pdev->dev,
			"%s: invalid bus lan id %d\n",
			__func__, hw->bus.lan_id);

	if (!(((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP) ||
	      ((hw->subsystem_device_id & TXGBE_WOL_MASK) == TXGBE_WOL_SUP))) {
		/* disable mac transmiter */
		wr32m(hw, TXGBE_MAC_TX_CFG, TXGBE_MAC_TX_CFG_TE, 0);
	}
	/* disable transmits in the hardware now that interrupts are off */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		u8 reg_idx = adapter->tx_ring[i]->reg_idx;

		wr32(hw, TXGBE_PX_TR_CFG(reg_idx), TXGBE_PX_TR_CFG_SWFLSH);
	}

	/* Disable the Tx DMA engine */
	wr32m(hw, TXGBE_TDM_CTL, TXGBE_TDM_CTL_TE, 0);
}

void txgbe_down(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;

	txgbe_disable_device(adapter);
	txgbe_reset(adapter);

	if (!(((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP)))
		/* power down the optics for SFP+ fiber */
		TCALL(&adapter->hw, mac.ops.disable_tx_laser);
}

/**
 *  txgbe_init_shared_code - Initialize the shared code
 *  @hw: pointer to hardware structure
 *
 *  This will assign function pointers and assign the MAC type and PHY code.
 **/
s32 txgbe_init_shared_code(struct txgbe_hw *hw)
{
	s32 status;

	status = txgbe_init_ops(hw);
	return status;
}

static int txgbe_sw_init(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	u32 ssid = 0;
	int err = 0;

	/* PCI config space info */
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	hw->revision_id = pdev->revision;
	hw->oem_svid = pdev->subsystem_vendor;
	hw->oem_ssid = pdev->subsystem_device;

	if (hw->oem_svid == PCI_VENDOR_ID_WANGXUN) {
		hw->subsystem_vendor_id = pdev->subsystem_vendor;
		hw->subsystem_device_id = pdev->subsystem_device;
	} else {
		ssid = txgbe_flash_read_dword(hw, 0xfffdc);
		if (ssid == 0x1) {
			netif_err(adapter, probe, adapter->netdev,
				  "read of internal subsystem device id failed\n");
			return -ENODEV;
		}
		hw->subsystem_device_id = (u16)ssid >> 8 | (u16)ssid << 8;
	}

	err = txgbe_init_shared_code(hw);
	if (err) {
		netif_err(adapter, probe, adapter->netdev,
			  "init_shared_code failed: %d\n", err);
		return err;
	}
	adapter->mac_table = kzalloc(sizeof(*adapter->mac_table) *
				     hw->mac.num_rar_entries,
				     GFP_ATOMIC);
	if (!adapter->mac_table) {
		err = TXGBE_ERR_OUT_OF_MEM;
		netif_err(adapter, probe, adapter->netdev,
			  "mac_table allocation failed: %d\n", err);
		return err;
	}

	/* enable itr by default in dynamic mode */
	adapter->rx_itr_setting = 1;
	adapter->tx_itr_setting = 1;

	adapter->atr_sample_rate = 20;

	adapter->max_q_vectors = TXGBE_MAX_MSIX_Q_VECTORS_SAPPHIRE;

	set_bit(__TXGBE_DOWN, &adapter->state);

	return 0;
}

/**
 * txgbe_setup_isb_resources - allocate interrupt status resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
static int txgbe_setup_isb_resources(struct txgbe_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;

	adapter->isb_mem = dma_alloc_coherent(dev,
					      sizeof(u32) * TXGBE_ISB_MAX,
					      &adapter->isb_dma,
					      GFP_KERNEL);
	if (!adapter->isb_mem)
		return -ENOMEM;
	memset(adapter->isb_mem, 0, sizeof(u32) * TXGBE_ISB_MAX);
	return 0;
}

/**
 * txgbe_free_isb_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * Return 0 on success, negative on failure
 **/
static void txgbe_free_isb_resources(struct txgbe_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;

	dma_free_coherent(dev, sizeof(u32) * TXGBE_ISB_MAX,
			  adapter->isb_mem, adapter->isb_dma);
	adapter->isb_mem = NULL;
}

/**
 * txgbe_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 **/
int txgbe_open(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);
	int err;

	netif_carrier_off(netdev);

	err = txgbe_setup_isb_resources(adapter);
	if (err)
		goto err_req_isb;

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
	txgbe_free_isb_resources(adapter);
err_req_isb:
	return err;
}

/**
 * txgbe_close_suspend - actions necessary to both suspend and close flows
 * @adapter: the private adapter struct
 *
 * This function should contain the necessary work common to both suspending
 * and closing of the device.
 */
static void txgbe_close_suspend(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;

	txgbe_disable_device(adapter);
	if (!((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP))
		TCALL(hw, mac.ops.disable_tx_laser);
	txgbe_free_irq(adapter);

	txgbe_free_isb_resources(adapter);
}

/**
 * txgbe_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
int txgbe_close(struct net_device *netdev)
{
	struct txgbe_adapter *adapter = netdev_priv(netdev);

	txgbe_down(adapter);
	txgbe_free_irq(adapter);

	txgbe_free_isb_resources(adapter);

	txgbe_release_hw_control(adapter);

	return 0;
}

static void txgbe_dev_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct txgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;

	netif_device_detach(netdev);

	rtnl_lock();
	if (netif_running(netdev))
		txgbe_close_suspend(adapter);
	rtnl_unlock();

	txgbe_clear_interrupt_scheme(adapter);

	txgbe_release_hw_control(adapter);

	if (!test_and_set_bit(__TXGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);
}

static void txgbe_shutdown(struct pci_dev *pdev)
{
	bool wake = false;

	txgbe_dev_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wake);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

/**
 * txgbe_watchdog_update_link - update the link status
 * @adapter: pointer to the device adapter structure
 **/
static void txgbe_watchdog_update_link(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	u32 reg;
	u32 i = 1;

	if (!(adapter->flags & TXGBE_FLAG_NEED_LINK_UPDATE))
		return;

	link_speed = TXGBE_LINK_SPEED_10GB_FULL;
	link_up = true;
	TCALL(hw, mac.ops.check_link, &link_speed, &link_up, false);

	if (link_up || time_after(jiffies, (adapter->link_check_timeout +
		TXGBE_TRY_LINK_TIMEOUT))) {
		adapter->flags &= ~TXGBE_FLAG_NEED_LINK_UPDATE;
	}

	for (i = 0; i < 3; i++) {
		TCALL(hw, mac.ops.check_link, &link_speed, &link_up, false);
		msleep(20);
	}

	adapter->link_up = link_up;
	adapter->link_speed = link_speed;

	if (link_up) {
		if (link_speed & TXGBE_LINK_SPEED_10GB_FULL) {
			wr32(hw, TXGBE_MAC_TX_CFG,
			     (rd32(hw, TXGBE_MAC_TX_CFG) &
			      ~TXGBE_MAC_TX_CFG_SPEED_MASK) | TXGBE_MAC_TX_CFG_TE |
			     TXGBE_MAC_TX_CFG_SPEED_10G);
		} else if (link_speed & (TXGBE_LINK_SPEED_1GB_FULL |
			   TXGBE_LINK_SPEED_100_FULL | TXGBE_LINK_SPEED_10_FULL)) {
			wr32(hw, TXGBE_MAC_TX_CFG,
			     (rd32(hw, TXGBE_MAC_TX_CFG) &
			      ~TXGBE_MAC_TX_CFG_SPEED_MASK) | TXGBE_MAC_TX_CFG_TE |
			     TXGBE_MAC_TX_CFG_SPEED_1G);
		}

		/* Re configure MAC RX */
		reg = rd32(hw, TXGBE_MAC_RX_CFG);
		wr32(hw, TXGBE_MAC_RX_CFG, reg);
		wr32(hw, TXGBE_MAC_PKT_FLT, TXGBE_MAC_PKT_FLT_PR);
		reg = rd32(hw, TXGBE_MAC_WDG_TIMEOUT);
		wr32(hw, TXGBE_MAC_WDG_TIMEOUT, reg);
	}
}

/**
 * txgbe_watchdog_link_is_up - update netif_carrier status and
 *                             print link up message
 * @adapter: pointer to the device adapter structure
 **/
static void txgbe_watchdog_link_is_up(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct txgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool flow_rx, flow_tx;

	/* only continue if link was previously down */
	if (netif_carrier_ok(netdev))
		return;

	/* flow_rx, flow_tx report link flow control status */
	flow_rx = (rd32(hw, TXGBE_MAC_RX_FLOW_CTRL) & 0x101) == 0x1;
	flow_tx = !!(TXGBE_RDB_RFCC_RFCE_802_3X &
		     rd32(hw, TXGBE_RDB_RFCC));

	netif_info(adapter, drv, netdev,
		   "NIC Link is Up %s, Flow Control: %s\n",
		   (link_speed == TXGBE_LINK_SPEED_10GB_FULL ?
		    "10 Gbps" :
		    (link_speed == TXGBE_LINK_SPEED_1GB_FULL ?
		     "1 Gbps" :
		     (link_speed == TXGBE_LINK_SPEED_100_FULL ?
		      "100 Mbps" :
		      (link_speed == TXGBE_LINK_SPEED_10_FULL ?
		       "10 Mbps" :
		       "unknown speed")))),
		  ((flow_rx && flow_tx) ? "RX/TX" :
		   (flow_rx ? "RX" :
		    (flow_tx ? "TX" : "None"))));

	netif_carrier_on(netdev);
}

/**
 * txgbe_watchdog_link_is_down - update netif_carrier status and
 *                               print link down message
 * @adapter: pointer to the adapter structure
 **/
static void txgbe_watchdog_link_is_down(struct txgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	adapter->link_up = false;
	adapter->link_speed = 0;

	/* only continue if link was up previously */
	if (!netif_carrier_ok(netdev))
		return;

	netif_info(adapter, drv, netdev, "NIC Link is Down\n");
	netif_carrier_off(netdev);
}

/**
 * txgbe_watchdog_subtask - check and bring link up
 * @adapter: pointer to the device adapter structure
 **/
static void txgbe_watchdog_subtask(struct txgbe_adapter *adapter)
{
	/* if interface is down do nothing */
	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_REMOVING, &adapter->state) ||
	    test_bit(__TXGBE_RESETTING, &adapter->state))
		return;

	txgbe_watchdog_update_link(adapter);

	if (adapter->link_up)
		txgbe_watchdog_link_is_up(adapter);
	else
		txgbe_watchdog_link_is_down(adapter);
}

/**
 * txgbe_sfp_detection_subtask - poll for SFP+ cable
 * @adapter: the txgbe adapter structure
 **/
static void txgbe_sfp_detection_subtask(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	struct txgbe_mac_info *mac = &hw->mac;
	s32 err;

	/* not searching for SFP so there is nothing to do here */
	if (!(adapter->flags2 & TXGBE_FLAG2_SFP_NEEDS_RESET))
		return;

	if (adapter->sfp_poll_time &&
	    time_after(adapter->sfp_poll_time, jiffies))
		return; /* If not yet time to poll for SFP */

	/* someone else is in init, wait until next service event */
	if (test_and_set_bit(__TXGBE_IN_SFP_INIT, &adapter->state))
		return;

	adapter->sfp_poll_time = jiffies + TXGBE_SFP_POLL_JIFFIES - 1;

	err = TCALL(hw, phy.ops.identify_sfp);
	if (err == TXGBE_ERR_SFP_NOT_SUPPORTED)
		goto sfp_out;

	if (err == TXGBE_ERR_SFP_NOT_PRESENT) {
		/* If no cable is present, then we need to reset
		 * the next time we find a good cable.
		 */
		adapter->flags2 |= TXGBE_FLAG2_SFP_NEEDS_RESET;
	}

	/* exit on error */
	if (err)
		goto sfp_out;

	/* exit if reset not needed */
	if (!(adapter->flags2 & TXGBE_FLAG2_SFP_NEEDS_RESET))
		goto sfp_out;

	adapter->flags2 &= ~TXGBE_FLAG2_SFP_NEEDS_RESET;

	if (hw->phy.multispeed_fiber) {
		/* Set up dual speed SFP+ support */
		mac->ops.setup_link = txgbe_setup_mac_link_multispeed_fiber;
		mac->ops.setup_mac_link = txgbe_setup_mac_link;
		mac->ops.set_rate_select_speed = txgbe_set_hard_rate_select_speed;
	} else {
		mac->ops.setup_link = txgbe_setup_mac_link;
		mac->ops.set_rate_select_speed = txgbe_set_hard_rate_select_speed;
		hw->phy.autoneg_advertised = 0;
	}

	adapter->flags |= TXGBE_FLAG_NEED_LINK_CONFIG;
	netif_info(adapter, probe, adapter->netdev,
		   "detected SFP+: %d\n", hw->phy.sfp_type);

sfp_out:
	clear_bit(__TXGBE_IN_SFP_INIT, &adapter->state);

	if (err == TXGBE_ERR_SFP_NOT_SUPPORTED && adapter->netdev_registered)
		dev_err(&adapter->pdev->dev,
			"failed to initialize because an unsupported SFP+ module type was detected.\n");
}

/**
 * txgbe_sfp_link_config_subtask - set up link SFP after module install
 * @adapter: the txgbe adapter structure
 **/
static void txgbe_sfp_link_config_subtask(struct txgbe_adapter *adapter)
{
	struct txgbe_hw *hw = &adapter->hw;
	u32 speed;
	bool autoneg = false;
	u8 device_type = hw->subsystem_device_id & 0xF0;

	if (!(adapter->flags & TXGBE_FLAG_NEED_LINK_CONFIG))
		return;

	/* someone else is in init, wait until next service event */
	if (test_and_set_bit(__TXGBE_IN_SFP_INIT, &adapter->state))
		return;

	adapter->flags &= ~TXGBE_FLAG_NEED_LINK_CONFIG;

	if (device_type == TXGBE_ID_MAC_SGMII) {
		speed = TXGBE_LINK_SPEED_1GB_FULL;
	} else {
		speed = hw->phy.autoneg_advertised;
		if (!speed && hw->mac.ops.get_link_capabilities) {
			TCALL(hw, mac.ops.get_link_capabilities, &speed, &autoneg);
			/* setup the highest link when no autoneg */
			if (!autoneg) {
				if (speed & TXGBE_LINK_SPEED_10GB_FULL)
					speed = TXGBE_LINK_SPEED_10GB_FULL;
			}
		}
	}

	TCALL(hw, mac.ops.setup_link, speed, false);

	adapter->flags |= TXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;
	clear_bit(__TXGBE_IN_SFP_INIT, &adapter->state);
}

static void txgbe_service_timer(struct timer_list *t)
{
	struct txgbe_adapter *adapter = from_timer(adapter, t, service_timer);
	unsigned long next_event_offset;
	struct txgbe_hw *hw = &adapter->hw;

	/* poll faster when waiting for link */
	if (adapter->flags & TXGBE_FLAG_NEED_LINK_UPDATE) {
		if ((hw->subsystem_device_id & 0xF0) == TXGBE_ID_KR_KX_KX4)
			next_event_offset = HZ;
		else
			next_event_offset = HZ / 10;
	} else {
		next_event_offset = HZ * 2;
	}

	/* Reset the timer */
	mod_timer(&adapter->service_timer, next_event_offset + jiffies);

	txgbe_service_event_schedule(adapter);
}

static void txgbe_reset_subtask(struct txgbe_adapter *adapter)
{
	u32 reset_flag = 0;
	u32 value = 0;

	if (!(adapter->flags2 & (TXGBE_FLAG2_PF_RESET_REQUESTED |
				 TXGBE_FLAG2_GLOBAL_RESET_REQUESTED |
				 TXGBE_FLAG2_RESET_INTR_RECEIVED)))
		return;

	/* If we're already down, just bail */
	if (test_bit(__TXGBE_DOWN, &adapter->state) ||
	    test_bit(__TXGBE_REMOVING, &adapter->state))
		return;

	netdev_err(adapter->netdev, "Reset adapter\n");

	rtnl_lock();
	if (adapter->flags2 & TXGBE_FLAG2_GLOBAL_RESET_REQUESTED) {
		reset_flag |= TXGBE_FLAG2_GLOBAL_RESET_REQUESTED;
		adapter->flags2 &= ~TXGBE_FLAG2_GLOBAL_RESET_REQUESTED;
	}
	if (adapter->flags2 & TXGBE_FLAG2_PF_RESET_REQUESTED) {
		reset_flag |= TXGBE_FLAG2_PF_RESET_REQUESTED;
		adapter->flags2 &= ~TXGBE_FLAG2_PF_RESET_REQUESTED;
	}

	if (adapter->flags2 & TXGBE_FLAG2_RESET_INTR_RECEIVED) {
		/* If there's a recovery already waiting, it takes
		 * precedence before starting a new reset sequence.
		 */
		adapter->flags2 &= ~TXGBE_FLAG2_RESET_INTR_RECEIVED;
		value = rd32m(&adapter->hw, TXGBE_MIS_RST_ST,
			      TXGBE_MIS_RST_ST_DEV_RST_TYPE_MASK) >>
			TXGBE_MIS_RST_ST_DEV_RST_TYPE_SHIFT;
		if (value == TXGBE_MIS_RST_ST_DEV_RST_TYPE_SW_RST) {
			adapter->hw.reset_type = TXGBE_SW_RESET;
			/* errata 7 */
			if (txgbe_mng_present(&adapter->hw) &&
			    adapter->hw.revision_id == TXGBE_SP_MPW)
				adapter->flags2 |=
					TXGBE_FLAG2_MNG_REG_ACCESS_DISABLED;
		} else if (value == TXGBE_MIS_RST_ST_DEV_RST_TYPE_GLOBAL_RST) {
			adapter->hw.reset_type = TXGBE_GLOBAL_RESET;
		}
		adapter->hw.force_full_reset = true;
		txgbe_reinit_locked(adapter);
		adapter->hw.force_full_reset = false;
		goto unlock;
	}

	if (reset_flag & TXGBE_FLAG2_PF_RESET_REQUESTED) {
		/*debug to up*/
		txgbe_reinit_locked(adapter);
	} else if (reset_flag & TXGBE_FLAG2_GLOBAL_RESET_REQUESTED) {
		/* Request a Global Reset
		 *
		 * This will start the chip's countdown to the actual full
		 * chip reset event, and a warning interrupt to be sent
		 * to all PFs, including the requestor.  Our handler
		 * for the warning interrupt will deal with the shutdown
		 * and recovery of the switch setup.
		 */
		/*debug to up*/
		pci_save_state(adapter->pdev);
		if (txgbe_mng_present(&adapter->hw))
			txgbe_reset_hostif(&adapter->hw);
		else
			wr32m(&adapter->hw, TXGBE_MIS_RST,
			      TXGBE_MIS_RST_GLOBAL_RST,
			      TXGBE_MIS_RST_GLOBAL_RST);
	}

unlock:
	rtnl_unlock();
}

/**
 * txgbe_service_task - manages and runs subtasks
 * @work: pointer to work_struct containing our data
 **/
static void txgbe_service_task(struct work_struct *work)
{
	struct txgbe_adapter *adapter = container_of(work,
						     struct txgbe_adapter,
						     service_task);
	if (TXGBE_REMOVED(adapter->hw.hw_addr)) {
		if (!test_bit(__TXGBE_DOWN, &adapter->state)) {
			rtnl_lock();
			txgbe_down(adapter);
			rtnl_unlock();
		}
		txgbe_service_event_complete(adapter);
		return;
	}

	txgbe_reset_subtask(adapter);
	txgbe_sfp_detection_subtask(adapter);
	txgbe_sfp_link_config_subtask(adapter);
	txgbe_check_overtemp_subtask(adapter);
	txgbe_watchdog_subtask(adapter);

	txgbe_service_event_complete(adapter);
}

static netdev_tx_t txgbe_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev)
{
	return NETDEV_TX_OK;
}

/**
 * txgbe_add_sanmac_netdev - Add the SAN MAC address to the corresponding
 * netdev->dev_addr_list
 * @dev: network interface device structure
 *
 * Returns non-zero on failure
 **/
static int txgbe_add_sanmac_netdev(struct net_device *dev)
{
	int err = 0;
	struct txgbe_adapter *adapter = netdev_priv(dev);
	struct txgbe_hw *hw = &adapter->hw;

	if (is_valid_ether_addr(hw->mac.san_addr)) {
		rtnl_lock();
		err = dev_addr_add(dev, hw->mac.san_addr,
				   NETDEV_HW_ADDR_T_SAN);
		rtnl_unlock();

		/* update SAN MAC vmdq pool selection */
		TCALL(hw, mac.ops.set_vmdq_san_mac, 0);
	}
	return err;
}

/**
 * txgbe_del_sanmac_netdev - Removes the SAN MAC address to the corresponding
 * netdev->dev_addr_list
 * @dev: network interface device structure
 *
 * Returns non-zero on failure
 **/
static int txgbe_del_sanmac_netdev(struct net_device *dev)
{
	int err = 0;
	struct txgbe_adapter *adapter = netdev_priv(dev);
	struct txgbe_mac_info *mac = &adapter->hw.mac;

	if (is_valid_ether_addr(mac->san_addr)) {
		rtnl_lock();
		err = dev_addr_del(dev, mac->san_addr, NETDEV_HW_ADDR_T_SAN);
		rtnl_unlock();
	}
	return err;
}

static const struct net_device_ops txgbe_netdev_ops = {
	.ndo_open               = txgbe_open,
	.ndo_stop               = txgbe_close,
	.ndo_start_xmit         = txgbe_xmit_frame,
};

void txgbe_assign_netdev_ops(struct net_device *dev)
{
	dev->netdev_ops = &txgbe_netdev_ops;
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
static int txgbe_probe(struct pci_dev *pdev,
		       const struct pci_device_id __always_unused *ent)
{
	struct txgbe_adapter *adapter = NULL;
	struct txgbe_hw *hw = NULL;
	struct net_device *netdev;
	int err, expected_gts;
	u16 offset = 0;
	u16 eeprom_verh = 0, eeprom_verl = 0;
	u16 eeprom_cfg_blkh = 0, eeprom_cfg_blkl = 0;
	u32 etrack_id = 0;
	u16 build = 0, major = 0, patch = 0;
	u16 ctl = 0;
	u8 part_str[TXGBE_PBANUM_LENGTH];
	bool disable_dev = false;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev,
			"No usable DMA configuration, aborting\n");
		goto err_pci_disable_dev;
	}

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

	pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &ctl);
	if (((ctl & PCI_EXP_DEVCTL_READRQ) != PCI_EXP_DEVCTL_READRQ_128B) &&
	    ((ctl & PCI_EXP_DEVCTL_READRQ) != PCI_EXP_DEVCTL_READRQ_256B))
		pcie_capability_clear_and_set_word(pdev, PCI_EXP_DEVCTL,
						   PCI_EXP_DEVCTL_READRQ,
						   PCI_EXP_DEVCTL_READRQ_256B);

	netdev = devm_alloc_etherdev_mqs(&pdev->dev,
					 sizeof(struct txgbe_adapter),
					 TXGBE_MAX_TX_QUEUES,
					 TXGBE_MAX_RX_QUEUES);
	if (!netdev) {
		err = -ENOMEM;
		goto err_pci_release_regions;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;
	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

	adapter->io_addr = devm_ioremap(&pdev->dev,
					pci_resource_start(pdev, 0),
					pci_resource_len(pdev, 0));
	if (!adapter->io_addr) {
		err = -EIO;
		goto err_pci_release_regions;
	}
	hw->hw_addr = adapter->io_addr;

	txgbe_assign_netdev_ops(netdev);
	netdev->watchdog_timeo = 5 * HZ;
	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	/* setup the private structure */
	err = txgbe_sw_init(adapter);
	if (err)
		goto err_free_mac_table;

	TCALL(hw, mac.ops.set_lan_id);

	/* check if flash load is done after hw power up */
	err = txgbe_check_flash_load(hw, TXGBE_SPI_ILDR_STATUS_PERST);
	if (err)
		goto err_free_mac_table;
	err = txgbe_check_flash_load(hw, TXGBE_SPI_ILDR_STATUS_PWRRST);
	if (err)
		goto err_free_mac_table;

	err = TCALL(hw, mac.ops.reset_hw);
	if (err == TXGBE_ERR_SFP_NOT_PRESENT) {
		err = 0;
	} else if (err == TXGBE_ERR_SFP_NOT_SUPPORTED) {
		dev_err(&pdev->dev,
			"failed to load because an unsupported SFP+ module type was detected.\n");
		dev_err(&pdev->dev,
			"Reload the driver after installing a supported module.\n");
		goto err_free_mac_table;
	} else if (err) {
		dev_err(&pdev->dev, "HW Init failed: %d\n", err);
		goto err_free_mac_table;
	}

	netdev->features |= NETIF_F_HIGHDMA;

	/* make sure the EEPROM is good */
	if (TCALL(hw, eeprom.ops.validate_checksum, NULL)) {
		dev_err(&pdev->dev, "The EEPROM Checksum Is Not Valid\n");
		wr32(hw, TXGBE_MIS_RST, TXGBE_MIS_RST_SW_RST);
		err = -EIO;
		goto err_free_mac_table;
	}

	memcpy(netdev->dev_addr, hw->mac.perm_addr, netdev->addr_len);

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		dev_err(&pdev->dev, "invalid MAC address\n");
		err = -EIO;
		goto err_free_mac_table;
	}

	txgbe_mac_set_default_filter(adapter, hw->mac.perm_addr);

	timer_setup(&adapter->service_timer, txgbe_service_timer, 0);

	if (TXGBE_REMOVED(hw->hw_addr)) {
		err = -EIO;
		goto err_free_mac_table;
	}
	INIT_WORK(&adapter->service_task, txgbe_service_task);
	set_bit(__TXGBE_SERVICE_INITED, &adapter->state);
	clear_bit(__TXGBE_SERVICE_SCHED, &adapter->state);

	err = txgbe_init_interrupt_scheme(adapter);
	if (err)
		goto err_free_mac_table;

	/* Save off EEPROM version number and Option Rom version which
	 * together make a unique identify for the eeprom
	 */
	TCALL(hw, eeprom.ops.read,
	      hw->eeprom.sw_region_offset + TXGBE_EEPROM_VERSION_H,
	      &eeprom_verh);
	TCALL(hw, eeprom.ops.read,
	      hw->eeprom.sw_region_offset + TXGBE_EEPROM_VERSION_L,
	      &eeprom_verl);
	etrack_id = (eeprom_verh << 16) | eeprom_verl;

	TCALL(hw, eeprom.ops.read,
	      hw->eeprom.sw_region_offset + TXGBE_ISCSI_BOOT_CONFIG, &offset);

	/* Make sure offset to SCSI block is valid */
	if (!(offset == 0x0) && !(offset == 0xffff)) {
		TCALL(hw, eeprom.ops.read, offset + 0x84, &eeprom_cfg_blkh);
		TCALL(hw, eeprom.ops.read, offset + 0x83, &eeprom_cfg_blkl);

		/* Only display Option Rom if exist */
		if (eeprom_cfg_blkl && eeprom_cfg_blkh) {
			major = eeprom_cfg_blkl >> 8;
			build = (eeprom_cfg_blkl << 8) | (eeprom_cfg_blkh >> 8);
			patch = eeprom_cfg_blkh & 0x00ff;

			snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
				 "0x%08x, %d.%d.%d", etrack_id, major, build,
				 patch);
		} else {
			snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
				 "0x%08x", etrack_id);
		}
	} else {
		snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
			 "0x%08x", etrack_id);
	}

	/* reset the hardware with the new settings */
	err = TCALL(hw, mac.ops.start_hw);
	if (err) {
		dev_err(&pdev->dev, "HW init failed\n");
		goto err_release_hw;
	}

	/* pick up the PCI bus settings for reporting later */
	TCALL(hw, mac.ops.get_bus_info);

	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_release_hw;

	pci_set_drvdata(pdev, adapter);
	adapter->netdev_registered = true;

	if (!((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP))
		/* power down the optics for SFP+ fiber */
		TCALL(hw, mac.ops.disable_tx_laser);

	/* carrier off reporting is important to ethtool even BEFORE open */
	netif_carrier_off(netdev);

	/* calculate the expected PCIe bandwidth required for optimal
	 * performance. Note that some older parts will never have enough
	 * bandwidth due to being older generation PCIe parts. We clamp these
	 * parts to ensure that no warning is displayed, as this could confuse
	 * users otherwise.
	 */
	expected_gts = txgbe_enumerate_functions(adapter) * 10;

	/* don't check link if we failed to enumerate functions */
	if (expected_gts > 0)
		txgbe_check_minimum_link(adapter, expected_gts);

	if ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP)
		netif_info(adapter, probe, netdev, "NCSI : support");
	else
		netif_info(adapter, probe, netdev, "NCSI : unsupported");

	/* First try to read PBA as a string */
	err = txgbe_read_pba_string(hw, part_str, TXGBE_PBANUM_LENGTH);
	if (err)
		strncpy(part_str, "Unknown", TXGBE_PBANUM_LENGTH);
	if (txgbe_is_sfp(hw) && hw->phy.sfp_type != txgbe_sfp_type_not_present)
		netif_info(adapter, probe, netdev,
			   "PHY: %d, SFP+: %d, PBA No: %s\n",
			   hw->phy.type, hw->phy.sfp_type, part_str);
	else
		netif_info(adapter, probe, netdev,
			   "PHY: %d, PBA No: %s\n",
			   hw->phy.type, part_str);

	dev_info(&pdev->dev, "%02x:%02x:%02x:%02x:%02x:%02x\n",
		 netdev->dev_addr[0], netdev->dev_addr[1],
		 netdev->dev_addr[2], netdev->dev_addr[3],
		 netdev->dev_addr[4], netdev->dev_addr[5]);

	/* firmware requires blank driver version */
	TCALL(hw, mac.ops.set_fw_drv_ver, 0xFF, 0xFF, 0xFF, 0xFF);

	/* add san mac addr to netdev */
	txgbe_add_sanmac_netdev(netdev);

	netif_info(adapter, probe, netdev,
		   "WangXun(R) 10 Gigabit Network Connection\n");

	/* setup link for SFP devices with MNG FW, else wait for TXGBE_UP */
	if (txgbe_mng_present(hw) && txgbe_is_sfp(hw) &&
	    ((hw->subsystem_device_id & TXGBE_NCSI_MASK) == TXGBE_NCSI_SUP))
		TCALL(hw, mac.ops.setup_link,
		      TXGBE_LINK_SPEED_10GB_FULL | TXGBE_LINK_SPEED_1GB_FULL,
		      true);

	return 0;

err_release_hw:
	txgbe_clear_interrupt_scheme(adapter);
	txgbe_release_hw_control(adapter);
err_free_mac_table:
	kfree(adapter->mac_table);
err_pci_release_regions:
	disable_dev = !test_and_set_bit(__TXGBE_DISABLED, &adapter->state);
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_disable_dev:
	if (!adapter || disable_dev)
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
	struct txgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev;
	bool disable_dev;

	netdev = adapter->netdev;
	set_bit(__TXGBE_REMOVING, &adapter->state);
	cancel_work_sync(&adapter->service_task);

	/* remove the added san mac */
	txgbe_del_sanmac_netdev(netdev);

	if (adapter->netdev_registered) {
		unregister_netdev(netdev);
		adapter->netdev_registered = false;
	}

	txgbe_clear_interrupt_scheme(adapter);
	txgbe_release_hw_control(adapter);

	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

	kfree(adapter->mac_table);
	disable_dev = !test_and_set_bit(__TXGBE_DISABLED, &adapter->state);

	pci_disable_pcie_error_reporting(pdev);

	if (disable_dev)
		pci_disable_device(pdev);
}

u16 txgbe_read_pci_cfg_word(struct txgbe_hw *hw, u32 reg)
{
	struct txgbe_adapter *adapter = container_of(hw, struct txgbe_adapter, hw);
	u16 value;

	if (TXGBE_REMOVED(hw->hw_addr))
		return TXGBE_FAILED_READ_CFG_WORD;
	pci_read_config_word(adapter->pdev, reg, &value);
	if (value == TXGBE_FAILED_READ_CFG_WORD &&
	    txgbe_check_cfg_remove(hw, adapter->pdev))
		return TXGBE_FAILED_READ_CFG_WORD;
	return value;
}

static struct pci_driver txgbe_driver = {
	.name     = txgbe_driver_name,
	.id_table = txgbe_pci_tbl,
	.probe    = txgbe_probe,
	.remove   = txgbe_remove,
	.shutdown = txgbe_shutdown,
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

	txgbe_wq = create_singlethread_workqueue(txgbe_driver_name);
	if (!txgbe_wq) {
		pr_err("%s: Failed to create workqueue\n", txgbe_driver_name);
		return -ENOMEM;
	}

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
	if (txgbe_wq)
		destroy_workqueue(txgbe_wq);
}

module_exit(txgbe_exit_module);

MODULE_DEVICE_TABLE(pci, txgbe_pci_tbl);
MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <software@trustnetic.com>");
MODULE_DESCRIPTION("WangXun(R) 10 Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
