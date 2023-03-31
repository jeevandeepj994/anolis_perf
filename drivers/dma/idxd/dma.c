// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/dmaengine.h>
#include <uapi/linux/idxd.h>
#include "../dmaengine.h"
#include "registers.h"
#include "idxd.h"


#define DMA_COOKIE_BITS (sizeof(dma_cookie_t) * 8)
/*
 * The descriptor id takes the lower 16 bits of the cookie.
 */
#define DESC_ID_BITS 16
#define DESC_ID_MASK ((1 << DESC_ID_BITS) - 1)
/*
 * The 'generation' is in the upper half of the cookie. But dma_cookie_t
 * is signed, so we leave the upper-most bit for the sign. Further, we
 * need to flag whether a cookie corresponds to an operation that is
 * being completed via interrupt to avoid polling it, which takes
 * the second most upper bit. So we subtract two bits from the upper half.
 */
#define DESC_GEN_MAX ((1 << (DMA_COOKIE_BITS - DESC_ID_BITS - 2)) - 1)
#define DESC_INTERRUPT_FLAG (1 << (DMA_COOKIE_BITS - 2))

static inline struct idxd_wq *to_idxd_wq(struct dma_chan *c)
{
	struct idxd_dma_chan *idxd_chan;

	idxd_chan = container_of(c, struct idxd_dma_chan, chan);
	return idxd_chan->wq;
}

void idxd_dma_complete_txd(struct idxd_desc *desc,
			   enum idxd_complete_type comp_type,
			   bool free_desc)
{
	struct idxd_device *idxd = desc->wq->idxd;
	struct dma_async_tx_descriptor *tx;
	struct dmaengine_result res;
	int complete = 1;

	if (desc->completion->status == DSA_COMP_SUCCESS) {
		res.result = DMA_TRANS_NOERROR;
	} else if (desc->completion->status) {
		if (idxd->request_int_handles && comp_type != IDXD_COMPLETE_ABORT &&
		    desc->completion->status == DSA_COMP_INT_HANDLE_INVAL &&
		    idxd_queue_int_handle_resubmit(desc))
			return;
		res.result = DMA_TRANS_WRITE_FAILED;
	} else if (comp_type == IDXD_COMPLETE_ABORT) {
		res.result = DMA_TRANS_ABORTED;
	} else {
		complete = 0;
	}

	tx = &desc->txd;
	if (complete && tx->cookie) {
		dma_cookie_complete(tx);
		dma_descriptor_unmap(tx);
		dmaengine_desc_get_callback_invoke(tx, &res);
		tx->callback = NULL;
		tx->callback_result = NULL;
	}

	if (free_desc)
		idxd_free_desc(desc->wq, desc);
}

static inline void op_control_flag_setup(unsigned long flags, u32 *desc_flags, struct idxd_wq *wq)
{
	*desc_flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		*desc_flags |= IDXD_OP_FLAG_RCI;

	/*
	 * Set Block on Fault flag in the descriptor if
	 * Block on Fault bit in WQCFG register is set.
	 */
	if (wq->wqcfg->bof)
		*desc_flags |= IDXD_OP_FLAG_BOF;
}

static inline void op_mem_flag_setup(unsigned long flags, u32 *desc_flags)
{
	if (!(flags & DMA_PREP_NONTEMPORAL))
		*desc_flags |= IDXD_OP_FLAG_CC;
}

static inline void op_flag_setup(unsigned long flags, u32 *desc_flags, struct idxd_wq *wq)
{
	op_control_flag_setup(flags, desc_flags, wq);
	op_mem_flag_setup(flags, desc_flags);
}

static inline void set_completion_address(struct idxd_desc *desc,
					  u64 *compl_addr)
{
		*compl_addr = desc->compl_dma;
}

static inline void idxd_prep_desc_common(struct idxd_wq *wq,
					 struct dsa_hw_desc *hw, char opcode,
					 u64 addr_f1, u64 addr_f2, u64 len,
					 u64 compl, u32 flags)
{
	hw->flags = flags;
	hw->opcode = opcode;
	hw->src_addr = addr_f1;
	hw->dst_addr = addr_f2;
	hw->xfer_size = len;
	/*
	 * For dedicated WQ, this field is ignored and HW will use the WQCFG.priv
	 * field instead. This field should be set to 1 for kernel descriptors.
	 */
	hw->priv = 1;
	hw->completion_addr = compl;
}

static struct dma_async_tx_descriptor *
idxd_dma_prep_interrupt(struct dma_chan *c, unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(c);
	u32 desc_flags;
	struct idxd_desc *desc;

	if (wq->state != IDXD_WQ_ENABLED)
		return NULL;

	op_flag_setup(flags, &desc_flags, wq);
	desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(desc))
		return NULL;

	/*
	 * Cache Control and Block on Fault flags are not supported by No-op
	 * operation. We need to explicitly clear the flags in the descriptor.
	 */
	desc_flags &= ~IDXD_OP_FLAG_CC & ~IDXD_OP_FLAG_BOF;
	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_NOOP,
			      0, 0, 0, desc->compl_dma, desc_flags);
	desc->txd.flags = flags;
	return &desc->txd;
}

static struct dma_async_tx_descriptor *
idxd_dma_submit_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
		       dma_addr_t dma_src, size_t len, unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(c);
	u32 desc_flags;
	struct idxd_device *idxd = wq->idxd;
	struct idxd_desc *desc;

	if (wq->state != IDXD_WQ_ENABLED)
		return NULL;

	if (len > idxd->max_xfer_bytes)
		return NULL;

	op_flag_setup(flags, &desc_flags, wq);
	desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(desc))
		return NULL;

	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_MEMMOVE,
			      dma_src, dma_dest, len, desc->compl_dma,
			      desc_flags);

	desc->txd.flags = flags;

	return &desc->txd;
}

static inline int fetch_sg_and_pos(struct scatterlist **sg, size_t *remain,
				   unsigned int len)
{
	int count = 0;

	if (!sg)
		return 0;

	*remain -= len;

	while (*remain == 0 && *sg) {
		count++;
		*sg = sg_next(*sg);
		if (*sg)
			*remain = sg_dma_len(*sg);
	}

	return count;
}

/*
 * idxd_dma_prep_memcpy_sg - prepare descriptors for a memcpy_sg transcation
 *
 * @chan: DMA channel
 * @dst_sg: Destination scatter list
 * @dst_nents: Number of entries in destination scatter list
 * @src_sg: Source scatter list
 * @src_nents: Number of entries in source scatter list
 * @flags: DMA transcation flags
 *
 * Return: Async transcation descriptor on success and NULL in failure.
 *
 * DSA batch descriptor and work queue depth can provide large memcpy
 * operation. Combined batch descriptor with WQ depth to support scatter
 * list.
 */
static struct dma_async_tx_descriptor *
idxd_dma_prep_memcpy_sg(struct dma_chan *chan,
			struct scatterlist *dst_sg, unsigned int dst_nents,
			struct scatterlist *src_sg, unsigned int src_nents,
			unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct idxd_desc *desc;
	struct idxd_batch *batch;
	dma_addr_t dma_dst, dma_src;
	size_t dst_avail, src_avail, len;
	u32 desc_flags, sd_flags = 0;
	int i;

	/* sanity check */
	if (unlikely(!dst_sg || !src_sg))
		return NULL;
	if (unlikely(dst_nents == 0 || src_nents == 0))
		return NULL;

	if (min(dst_nents, src_nents) > wq->max_batch_size)
		return NULL;

	dst_avail = sg_dma_len(dst_sg);
	src_avail = sg_dma_len(src_sg);

	if (dst_nents == 1 && src_nents == 1) {
		if (unlikely(dst_avail != src_avail))
			return NULL;

		return idxd_dma_submit_memcpy(chan, sg_dma_address(dst_sg),
				sg_dma_address(src_sg), dst_avail, flags);
	}

	desc = idxd_alloc_desc(wq, IDXD_OP_NONBLOCK);
	if (IS_ERR(desc))
		return NULL;

	/*
	 * DSA Batch descriptor has a set of descriptors in array
	 * is called 'batch'. fill up 'batch' field with some
	 * descriptors of DSA_OPCODE_MEMMOVE until max_batch_size
	 * or scatter list is consumed.
	 */
	batch = desc->batch;

	/* Set flags for sub descriptors */
	op_mem_flag_setup(flags, &sd_flags);
	if (wq->wqcfg->bof)
		sd_flags |= IDXD_OP_FLAG_BOF;

	for (i = 0; i < wq->max_batch_size; i++) {
		dma_dst = sg_dma_address(dst_sg) + sg_dma_len(dst_sg) -
			dst_avail;
		dma_src = sg_dma_address(src_sg) + sg_dma_len(src_sg) -
			src_avail;

		len = min_t(size_t, dst_avail, src_avail);
		len = min_t(size_t, len, wq->idxd->max_xfer_bytes);

		memset(batch->descs + i, 0, sizeof(struct dsa_hw_desc));
		idxd_prep_desc_common(wq, batch->descs + i, DSA_OPCODE_MEMMOVE,
				dma_src, dma_dst, len, 0, sd_flags);
		batch->num++;

		dst_nents -= fetch_sg_and_pos(&dst_sg, &dst_avail, len);
		src_nents -= fetch_sg_and_pos(&src_sg, &src_avail, len);

		/* entries of src or dst consumed */
		if (!dst_nents || !src_nents)
			break;
	}

	/* fail if exceeds wq->max_batch_size */
	if (unlikely(dst_nents && src_nents)) {
		idxd_free_desc(wq, desc);
		return NULL;
	}

	/*
	 * prepare DSA_OPCODE_BATCH with some common flags. We need to
	 * explicitly clear Cache Control and Block on Fault flags in batch
	 * descriptor, since DSA hw don't allow these flags for batch descriptor
	 * - DSA Spec 5.5, otherwise HW reports Error Code: 0x11 (Invalid flags)
	 * - Spec 5.7
	 */
	op_flag_setup(flags, &desc_flags, wq);
	desc_flags &= ~IDXD_OP_FLAG_CC & ~IDXD_OP_FLAG_BOF;
	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_BATCH,
			batch->dma_descs, 0, batch->num,
			desc->compl_dma, desc_flags);

	return &desc->txd;
}

static struct dma_async_tx_descriptor *
idxd_dma_prep_memset(struct dma_chan *c, dma_addr_t dma_dest, int value,
		     size_t len, unsigned long flags)
{
	struct idxd_wq *wq = to_idxd_wq(c);
	u32 desc_flags;
	struct idxd_desc *desc;
	u64 pattern = 0;

	if (wq->state != IDXD_WQ_ENABLED)
		return NULL;

	if (len > wq->max_xfer_bytes)
		return NULL;

	op_flag_setup(flags, &desc_flags, wq);
	desc = idxd_alloc_desc(wq, IDXD_OP_BLOCK);
	if (IS_ERR(desc))
		return NULL;

	/*
	 * The dmaengine API provides an int 'value', but it is really an 8bit
	 * pattern. DSA supports a 64bit pattern, and therefore the 8bit pattern
	 * will be replicated to 64bits.
	 */
	if (value) {
		pattern = value & 0xff;
		pattern |= pattern << 8;
		pattern |= pattern << 16;
		pattern |= pattern << 32;
	}

	idxd_prep_desc_common(wq, desc->hw, DSA_OPCODE_MEMFILL,
			      pattern, dma_dest, len, desc->compl_dma,
			      desc_flags);

	desc->txd.flags = flags;

	return &desc->txd;
}

static int idxd_dma_alloc_chan_resources(struct dma_chan *chan)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct device *dev = &wq->idxd->pdev->dev;

	idxd_wq_get(wq);
	dev_dbg(dev, "%s: client_count: %d\n", __func__,
		idxd_wq_refcount(wq));
	return 0;
}

static void idxd_dma_free_chan_resources(struct dma_chan *chan)
{
	struct idxd_wq *wq = to_idxd_wq(chan);
	struct device *dev = &wq->idxd->pdev->dev;

	idxd_wq_put(wq);
	dev_dbg(dev, "%s: client_count: %d\n", __func__,
		idxd_wq_refcount(wq));
}


static enum dma_status idxd_dma_tx_status(struct dma_chan *dma_chan,
					  dma_cookie_t cookie,
					  struct dma_tx_state *txstate)
{
	u8 status;
	struct idxd_wq *wq;
	struct idxd_desc *desc;
	u32 idx;

	memset(txstate, 0, sizeof(*txstate));

	if (dma_submit_error(cookie))
		return DMA_ERROR;

	wq = to_idxd_wq(dma_chan);

	idx = cookie & DESC_ID_MASK;
	if (idx >= wq->num_descs)
		return DMA_ERROR;

	desc = wq->descs[idx];

	if (desc->txd.cookie != cookie) {
		/*
		 * The user asked about an old transaction
		 */
		return DMA_COMPLETE;
	}

	/*
	 * For descriptors completed via interrupt, we can't go
	 * look at the completion status directly because it races
	 * with the IRQ handler recyling the descriptor. However,
	 * since in this case we can rely on the interrupt handler
	 * to invalidate the cookie when the command completes we
	 * know that if we get here, the command is still in
	 * progress.
	 */
	if ((cookie & DESC_INTERRUPT_FLAG) != 0)
		return DMA_IN_PROGRESS;

	status = desc->completion->status & DSA_COMP_STATUS_MASK;

	if (status) {
		/*
		 * Check against the original status as ABORT is software defined
		 * and 0xff, which DSA_COMP_STATUS_MASK can mask out.
		 */
		if (unlikely(desc->completion->status == IDXD_COMP_DESC_ABORT))
			idxd_dma_complete_txd(desc, IDXD_COMPLETE_ABORT, true);
		else
			idxd_dma_complete_txd(desc, IDXD_COMPLETE_NORMAL, true);

		return DMA_COMPLETE;
	}

	return DMA_IN_PROGRESS;
}


/*
 * issue_pending() does not need to do anything since tx_submit() does the job
 * already.
 */
static void idxd_dma_issue_pending(struct dma_chan *dma_chan)
{
}

static dma_cookie_t idxd_dma_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct dma_chan *c = tx->chan;
	struct idxd_wq *wq = to_idxd_wq(c);
	dma_cookie_t cookie;
	int rc;
	struct idxd_desc *desc = container_of(tx, struct idxd_desc, txd);

	cookie = (desc->gen << DESC_ID_BITS) | (desc->id & DESC_ID_MASK);

	if ((desc->hw->flags & IDXD_OP_FLAG_RCI) != 0)
		cookie |= DESC_INTERRUPT_FLAG;

	if (desc->gen == DESC_GEN_MAX)
		desc->gen = 1;
	else
		desc->gen++;

	tx->cookie = cookie;

	rc = idxd_submit_desc(wq, desc);
	if (rc < 0) {
		idxd_free_desc(wq, desc);
		return rc;
	}

	return cookie;
}

static void idxd_dma_release(struct dma_device *device)
{
	struct idxd_dma_dev *idxd_dma = container_of(device, struct idxd_dma_dev, dma);

	kfree(idxd_dma);
}

int idxd_register_dma_device(struct idxd_device *idxd)
{
	struct idxd_dma_dev *idxd_dma;
	struct dma_device *dma;
	struct device *dev = &idxd->pdev->dev;
	int rc;

	idxd_dma = kzalloc_node(sizeof(*idxd_dma), GFP_KERNEL, dev_to_node(dev));
	if (!idxd_dma)
		return -ENOMEM;

	dma = &idxd_dma->dma;
	INIT_LIST_HEAD(&dma->channels);
	dma->dev = dev;

	/*
	 * claim device max_segment_size to HugePage/THP size, otherwise
	 * DMA-API debug code would complain it's longer than default.
	 */
	idxd_dma->dma_parms.max_segment_size = HPAGE_PMD_SIZE;
	dma->dev->dma_parms = &idxd_dma->dma_parms;

	dma_cap_set(DMA_INTERRUPT, dma->cap_mask);
	dma_cap_set(DMA_PRIVATE, dma->cap_mask);
	dma->device_release = idxd_dma_release;

	dma->device_prep_dma_interrupt = idxd_dma_prep_interrupt;
	if (idxd->hw.opcap.bits[0] & IDXD_OPCAP_MEMMOVE) {
		dma_cap_set(DMA_MEMCPY, dma->cap_mask);
		dma->device_prep_dma_memcpy = idxd_dma_submit_memcpy;
	}

	if (idxd->hw.opcap.bits[0] & IDXD_OPCAP_BATCH) {
		dma_cap_set(DMA_MEMCPY_SG, dma->cap_mask);
		dma->device_prep_dma_memcpy_sg = idxd_dma_prep_memcpy_sg;
	}

	if (idxd->hw.opcap.bits[0] & IDXD_OPCAP_MEMFILL) {
		dma_cap_set(DMA_MEMSET, dma->cap_mask);
		dma->device_prep_dma_memset = idxd_dma_prep_memset;
	}

	dma->device_tx_status = idxd_dma_tx_status;
	dma->device_issue_pending = idxd_dma_issue_pending;
	dma->device_alloc_chan_resources = idxd_dma_alloc_chan_resources;
	dma->device_free_chan_resources = idxd_dma_free_chan_resources;

	rc = dma_async_device_register(dma);
	if (rc < 0) {
		kfree(idxd_dma);
		return rc;
	}

	idxd_dma->idxd = idxd;
	/*
	 * This pointer is protected by the refs taken by the dma_chan. It will remain valid
	 * as long as there are outstanding channels.
	 */
	idxd->idxd_dma = idxd_dma;
	return 0;
}

void idxd_unregister_dma_device(struct idxd_device *idxd)
{
	dma_async_device_unregister(&idxd->idxd_dma->dma);
}

static int idxd_register_dma_channel(struct idxd_wq *wq)
{
	struct idxd_device *idxd = wq->idxd;
	struct dma_device *dma = &idxd->idxd_dma->dma;
	struct device *dev = &idxd->pdev->dev;
	struct idxd_dma_chan *idxd_chan;
	struct dma_chan *chan;
	int rc, i;

	idxd_chan = kzalloc_node(sizeof(*idxd_chan), GFP_KERNEL, dev_to_node(dev));
	if (!idxd_chan)
		return -ENOMEM;

	chan = &idxd_chan->chan;
	chan->device = dma;
	list_add_tail(&chan->device_node, &dma->channels);

	for (i = 0; i < wq->num_descs; i++) {
		struct idxd_desc *desc = wq->descs[i];

		dma_async_tx_descriptor_init(&desc->txd, chan);
		desc->txd.tx_submit = idxd_dma_tx_submit;
	}

	rc = dma_async_device_channel_register(dma, chan);
	if (rc < 0) {
		kfree(idxd_chan);
		return rc;
	}

	wq->idxd_chan = idxd_chan;
	idxd_chan->wq = wq;
	get_device(wq_confdev(wq));

	return 0;
}

static void idxd_unregister_dma_channel(struct idxd_wq *wq)
{
	struct idxd_dma_chan *idxd_chan = wq->idxd_chan;
	struct dma_chan *chan = &idxd_chan->chan;
	struct idxd_dma_dev *idxd_dma = wq->idxd->idxd_dma;

	dma_async_device_channel_unregister(&idxd_dma->dma, chan);
	list_del(&chan->device_node);
	kfree(wq->idxd_chan);
	wq->idxd_chan = NULL;
	put_device(wq_confdev(wq));
}

static int idxd_dmaengine_drv_probe(struct idxd_dev *idxd_dev)
{
	struct device *dev = &idxd_dev->conf_dev;
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);
	struct idxd_device *idxd = wq->idxd;
	int rc;

	if (idxd->state != IDXD_DEV_ENABLED)
		return -ENXIO;

	mutex_lock(&wq->wq_lock);
	if (!idxd_wq_driver_name_match(wq, dev)) {
		idxd->cmd_status = IDXD_SCMD_WQ_NO_DRV_NAME;
		rc = -ENODEV;
		goto err_drv_name;
	}

	wq->type = IDXD_WQT_KERNEL;

	rc = __drv_enable_wq(wq);
	if (rc < 0) {
		dev_dbg(dev, "Enable wq %d failed: %d\n", wq->id, rc);
		rc = -ENXIO;
		goto err;
	}

	rc = idxd_wq_request_irq(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_WQ_IRQ_ERR;
		dev_dbg(dev, "WQ %d irq setup failed: %d\n", wq->id, rc);
		goto err_irq;
	}

	rc = idxd_wq_alloc_resources(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_WQ_RES_ALLOC_ERR;
		dev_dbg(dev, "WQ resource alloc failed\n");
		goto err_res_alloc;
	}

	rc = idxd_wq_init_percpu_ref(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_PERCPU_ERR;
		dev_dbg(dev, "percpu_ref setup failed\n");
		goto err_ref;
	}

	rc = idxd_register_dma_channel(wq);
	if (rc < 0) {
		idxd->cmd_status = IDXD_SCMD_DMA_CHAN_ERR;
		dev_dbg(dev, "Failed to register dma channel\n");
		goto err_dma;
	}

	idxd->cmd_status = 0;
	mutex_unlock(&wq->wq_lock);
	return 0;

err_dma:
	__idxd_wq_quiesce(wq);
	percpu_ref_exit(&wq->wq_active);
err_ref:
	idxd_wq_free_resources(wq);
err_res_alloc:
	idxd_wq_free_irq(wq);
err_irq:
	__drv_disable_wq(wq);
err:
err_drv_name:
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
	return rc;
}

static void idxd_dmaengine_drv_remove(struct idxd_dev *idxd_dev)
{
	struct idxd_wq *wq = idxd_dev_to_wq(idxd_dev);

	mutex_lock(&wq->wq_lock);
	__idxd_wq_quiesce(wq);
	idxd_unregister_dma_channel(wq);
	idxd_wq_free_resources(wq);
	idxd_wq_free_irq(wq);
	__drv_disable_wq(wq);
	percpu_ref_exit(&wq->wq_active);
	wq->type = IDXD_WQT_NONE;
	mutex_unlock(&wq->wq_lock);
}

static enum idxd_dev_type dev_types[] = {
	IDXD_DEV_WQ,
	IDXD_DEV_NONE,
};

struct idxd_device_driver idxd_dmaengine_drv = {
	.probe = idxd_dmaengine_drv_probe,
	.remove = idxd_dmaengine_drv_remove,
	.name = "dmaengine",
	.type = dev_types,
};
EXPORT_SYMBOL_GPL(idxd_dmaengine_drv);
