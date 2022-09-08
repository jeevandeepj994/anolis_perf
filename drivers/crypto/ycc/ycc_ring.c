// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/dma-mapping.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "ycc_dev.h"
#include "ycc_ring.h"
#include "ycc_uio.h"

#define YCC_CMD_DESC_SIZE	64
#define YCC_RESP_DESC_SIZE	16
#define YCC_RING_CSR_STRIDE	0x1000

extern struct list_head ycc_table;
extern struct mutex ycc_mutex;

extern void ycc_resp_work_process(struct work_struct *work);

/*
 * Show the status of specified ring's command queue and
 * response queue.
 */
static int ycc_ring_debugfs_status_show(struct seq_file *s, void *p)
{
	struct ycc_ring *ring = (struct ycc_ring *)s->private;

	seq_printf(s, "Ring ID: %d\n", ring->ring_id);
	seq_printf(s, "Desscriptor Entry Size: %d, CMD Descriptor Size: %d, RESP Descriptor Size :%d\n",
		   ring->max_desc, YCC_CMD_DESC_SIZE, YCC_RESP_DESC_SIZE);
	seq_printf(s, "CMD base addr:%llx, RESP base addr:%llx\n",
		   ring->cmd_base_paddr, ring->resp_base_paddr);
	seq_printf(s, "CMD wr ptr:%d, CMD rd ptr: %d\n",
		   YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_WR_PTR),
		   YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR));
	seq_printf(s, "RESP rd ptr:%d, RESP wr ptr: %d\n",
		   YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_RD_PTR),
		   YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR));

	return 0;
}

static int ycc_ring_debugfs_status_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ycc_ring_debugfs_status_show, inode->i_private);
}

static const struct file_operations ycc_ring_status_fops = {
	.open		= ycc_ring_debugfs_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

/*
 * Dump the raw content of specified ring's command queue and
 * response queue.
 */
static int ycc_ring_debugfs_dump_show(struct seq_file *s, void *p)
{
	struct ycc_ring *ring = (struct ycc_ring *)s->private;

	seq_printf(s, "Ring ID: %d\n", ring->ring_id);
	seq_puts(s, "-------- Ring CMD Descriptors --------\n");
	seq_hex_dump(s, "", DUMP_PREFIX_ADDRESS, 32, 4, ring->cmd_base_vaddr,
		     YCC_CMD_DESC_SIZE * ring->max_desc, false);
	seq_puts(s, "-------- Ring RESP Descriptors --------\n");
	seq_hex_dump(s, "", DUMP_PREFIX_ADDRESS, 32, 4, ring->resp_base_vaddr,
		     YCC_RESP_DESC_SIZE * ring->max_desc, false);

	return 0;
}

static int ycc_ring_debugfs_dump_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ycc_ring_debugfs_dump_show, inode->i_private);
}

static const struct file_operations ycc_ring_dump_fops = {
	.open		= ycc_ring_debugfs_dump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

/*
 * Create debugfs for rings, only for KERN_RING
 * "/sys/kernel/debugfs/ycc_b:d.f/ring${x}"
 */
static int ycc_create_ring_debugfs(struct ycc_ring *ring)
{
	struct dentry *debugfs;
	char name[8];

	if (!ring || !ring->ydev || !ring->ydev->debug_dir)
		return -EINVAL;

	snprintf(name, sizeof(name), "ring%02d", ring->ring_id);
	debugfs = debugfs_create_dir(name, ring->ydev->debug_dir);
	if (IS_ERR_OR_NULL(debugfs))
		goto out;

	ring->debug_dir = debugfs;

	debugfs = debugfs_create_file("status", 0400, ring->debug_dir,
				      (void *)ring, &ycc_ring_status_fops);
	if (IS_ERR_OR_NULL(debugfs))
		goto remove_debugfs;

	debugfs = debugfs_create_file("dump", 0400, ring->debug_dir,
				      (void *)ring, &ycc_ring_dump_fops);
	if (IS_ERR_OR_NULL(debugfs))
		goto remove_debugfs;

	return 0;

remove_debugfs:
	debugfs_remove_recursive(ring->debug_dir);
out:
	ring->debug_dir = NULL;
	return PTR_ERR(debugfs);
}

static void ycc_remove_ring_debugfs(struct ycc_ring *ring)
{
	debugfs_remove_recursive(ring->debug_dir);
}

/*
 * 'base_r' is an anchor when selecting the right ring,
 * right means that the ring has the lowest reference
 * count.
 */
static struct ycc_ring *base_r;

/*
 * Allocate memory for rings and initiate basic fields
 */
static int ycc_alloc_rings(struct ycc_dev *ydev)
{
	int num = YCC_RINGPAIR_NUM;
	struct ycc_bar *abar;
	u32 i;

	if (ydev->rings)
		return 0;

	if (ydev->is_vf) {
		num = 1;
		abar = &ydev->ycc_bars[0];
	} else if (ydev->sec) {
		abar = &ydev->ycc_bars[YCC_SEC_Q_BAR];
	} else {
		abar = &ydev->ycc_bars[YCC_NSEC_Q_BAR];
	}

	ydev->rings = kzalloc_node(num * sizeof(struct ycc_ring),
				   GFP_KERNEL, ydev->node);
	if (!ydev->rings)
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		ydev->rings[i].ring_id = i;
		ydev->rings[i].ydev = ydev;
		ydev->rings[i].csr_vaddr = abar->vaddr + i * YCC_RING_CSR_STRIDE;
		ydev->rings[i].csr_paddr = abar->paddr + i * YCC_RING_CSR_STRIDE;
		ydev->rings[i].cmd_wr_ptr = 0;
		ydev->rings[i].cmd_rd_ptr = 0;
		ydev->rings[i].resp_wr_ptr = 0;
		ydev->rings[i].resp_rd_ptr = 0;
	}

	return 0;
}

/*
 * Free memory for rings
 */
static void ycc_free_rings(struct ycc_dev *ydev)
{
	kfree(ydev->rings);
	ydev->rings = NULL;
	base_r = NULL;
}

/*
 * Initiate ring and create command queue and response queue.
 */
static int ycc_init_ring(struct ycc_ring *ring, u32 max_desc)
{
	struct ycc_dev *ydev = ring->ydev;
	u32 cmd_ring_size, resp_ring_size;
	int order = 0;
	u32 val = 0;

	/* KERN_RING won't exposed to uio */
	ring->type = KERN_RING;
	ring->max_desc = max_desc;

	cmd_ring_size = ring->max_desc * YCC_CMD_DESC_SIZE;
	resp_ring_size = ring->max_desc * YCC_RESP_DESC_SIZE;

	ring->cmd_base_vaddr = dma_alloc_coherent(&ydev->pdev->dev,
						  cmd_ring_size,
						  &ring->cmd_base_paddr,
						  GFP_KERNEL);
	if (!ring->cmd_base_vaddr) {
		pr_err("Failed to alloc cmd dma memory\n");
		return -ENOMEM;
	}
	memset(ring->cmd_base_vaddr, CMD_INVALID_CONTENT_U8, cmd_ring_size);

	ring->resp_base_vaddr = dma_alloc_coherent(&ydev->pdev->dev,
						   resp_ring_size,
						   &ring->resp_base_paddr,
						   GFP_KERNEL);
	if (!ring->resp_base_vaddr) {
		pr_err("Failed to alloc resp dma memory\n");
		dma_free_coherent(&ydev->pdev->dev,
				  cmd_ring_size,
				  ring->cmd_base_vaddr,
				  ring->cmd_base_paddr);
		return -ENOMEM;
	}
	memset(ring->resp_base_vaddr, CMD_INVALID_CONTENT_U8, resp_ring_size);

	while (max_desc >>= 1)
		order++;

	/* Minimum order should be 8 */
	if (order < 8) {
		ring->max_desc = 256;
		order = 8;
	}

	/* Ring size */
	val |= ((order - 8) & 0x7);

	/* Ring interrupt threshold */
	val |= (ydev->is_polling ? 1 : 0xFFFF) << 16;

	YCC_CSR_WR(ring->csr_vaddr, REG_RING_CFG, val);
	YCC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_AFULL_TH, 0);
	YCC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_BASE_ADDR_LO,
					(u32)ring->cmd_base_paddr & 0xffffffff);
	YCC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_BASE_ADDR_HI,
					((u64)ring->cmd_base_paddr >> 32) & 0xffffffff);
	YCC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_BASE_ADDR_LO,
					(u32)ring->resp_base_paddr & 0xffffffff);
	YCC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_BASE_ADDR_HI,
					((u64)ring->resp_base_paddr >> 32) & 0xffffffff);

	if (ycc_create_ring_debugfs(ring))
		pr_warn("Failed to create debugfs entry for ring:%d\n", ring->ring_id);

	atomic_set(&ring->ref_cnt, 0);
	spin_lock_init(&ring->lock);
	return 0;
}

/*
 * Release dma memory for command queue and response queue.
 */
static void ycc_release_ring(struct ycc_ring *ring)
{
	u32 ring_size;

	BUG_ON(atomic_read(&ring->ref_cnt));

	if (ring->cmd_base_vaddr) {
		ring_size = ring->max_desc * YCC_CMD_DESC_SIZE;
		dma_free_coherent(&ring->ydev->pdev->dev, ring_size,
				  ring->cmd_base_vaddr,
				  ring->cmd_base_paddr);
		ring->cmd_base_vaddr = NULL;
	}
	if (ring->resp_base_vaddr) {
		ring_size = ring->max_desc * YCC_RESP_DESC_SIZE;
		dma_free_coherent(&ring->ydev->pdev->dev, ring_size,
				  ring->resp_base_vaddr,
				  ring->resp_base_paddr);
		ring->resp_base_vaddr = NULL;
	}

	ycc_remove_ring_debugfs(ring);
	ring->type = FREE_RING;
}

int ycc_dev_rings_init(struct ycc_dev *ydev, u32 max_desc, int user_rings)
{
	int kern_rings = YCC_RINGPAIR_NUM - user_rings;
	struct pci_dev *pdev = ydev->pdev;
	struct ycc_ring *ring;
	int kern_cnt, user_cnt;
	int ret = 0;
	int i;

	ret = ycc_alloc_rings(ydev);
	if (ret) {
		dev_err(&pdev->dev, "Probe failed when allocating rings\n");
		return ret;
	}

	for (i = 0; i < kern_rings; i++) {
		ring = &ydev->rings[i];
		ret = ycc_init_ring(ring, max_desc);
		if (ret) {
			kern_cnt = i;
			goto free_kern_rings;
		}
		INIT_WORK(&ring->work, ycc_resp_work_process);
	}
	kern_cnt = kern_rings;

	for (i = kern_rings; i < YCC_RINGPAIR_NUM; i++) {
		ring = &ydev->rings[i];
		ret = ycc_uio_register(ring);
		if (ret) {
			user_cnt = i - kern_rings;
			goto free_user_rings;
		}
	}

	return 0;

free_user_rings:
	for (i = 0; i < user_cnt; i++) {
		ring = &ydev->rings[i + kern_rings];
		ycc_uio_unregister(ring);
	}

free_kern_rings:
	for (i = 0; i < kern_cnt; i++) {
		ring = &ydev->rings[i];
		ycc_release_ring(ring);
	}

	ycc_free_rings(ydev);
	return ret;
}

void ycc_dev_rings_release(struct ycc_dev *ydev, int user_rings)
{
	int kern_rings = YCC_RINGPAIR_NUM - user_rings;
	struct ycc_ring *ring;
	int i;

	for (i = 0; i < kern_rings; i++) {
		ring = &ydev->rings[i];
		ycc_release_ring(ring);
	}

	for (i = 0; i < user_rings; i++) {
		ring = &ydev->rings[i + kern_rings];
		ycc_uio_unregister(ring);
	}

	ycc_free_rings(ydev);
}

/*
 * Check if the command queue is full.
 */
static inline bool ycc_ring_full(struct ycc_ring *ring)
{
	return ring->cmd_rd_ptr == (ring->cmd_wr_ptr + 1) % ring->max_desc;
}

/*
 * Check if the response queue is empty
 */
static inline bool ycc_ring_empty(struct ycc_ring *ring)
{
	return ring->resp_rd_ptr == ring->resp_wr_ptr;
}

static struct ycc_ring *ycc_select_ring(void)
{
	struct ycc_ring *cur_r;
	struct list_head *itr;
	struct ycc_dev *ydev;
	int i;

	if (list_empty(&ycc_table))
		return NULL;

	list_for_each(itr, &ycc_table) {
		ydev = list_entry(itr, struct ycc_dev, list);
		if (ydev->type != YCC_RCIEP ||
		    !test_bit(YDEV_STATUS_READY, &ydev->status))
			continue;

		for (i = 0; i < YCC_RINGPAIR_NUM; i++) {
			cur_r = ydev->rings + i;

			/* Ring is not for kernel */
			if (cur_r->type != KERN_RING)
				continue;

			if (!base_r) {
				/* It means ycc is first used */
				base_r = cur_r;
				ycc_ring_get(cur_r);
				return cur_r;
			}
			/* Compare to base ring */
			if (!atomic_read(&base_r->ref_cnt) ||
			    (atomic_read(&base_r->ref_cnt) <
			     atomic_read(&cur_r->ref_cnt))) {
				ycc_ring_get(base_r);
				return base_r;
			} else if (atomic_read(&base_r->ref_cnt) >
				   atomic_read(&cur_r->ref_cnt)) {
				ycc_ring_get(cur_r);
				return cur_r;
			}
		}
	}

	if (base_r)
		ycc_ring_get(base_r);

	return base_r;
}

/*
 * Bind the ring to crypto
 */
struct ycc_ring *ycc_crypto_get_ring(void)
{
	struct ycc_ring *ring = NULL;

	mutex_lock(&ycc_mutex);

	ring = ycc_select_ring();
	if (!ring)
		goto out;

	ycc_dev_get(ring->ydev);
	if (ring->ydev->is_polling && atomic_read(&ring->ref_cnt) == 1)
		schedule_work(&ring->work);

out:
	mutex_unlock(&ycc_mutex);
	return ring;
}

void ycc_crypto_free_ring(struct ycc_ring *ring)
{
	if (!ring)
		return;

	/* TODO: Replace it by ring's own mutex which
	 * will be added to protect ring->work to not be
	 * canceled when another process just schedule it.
	 */
	mutex_lock(&ycc_mutex);
	if (atomic_dec_and_test(&ring->ref_cnt))
		cancel_work_sync(&ring->work);

	mutex_unlock(&ycc_mutex);

	ycc_dev_put(ring->ydev);
}

/*
 * Submit command to ring's command queue.
 */
int ycc_enqueue(struct ycc_ring *ring, void *cmd)
{
	int ret = 0;

	if (!ring || !ring->ydev || !cmd)
		return -EINVAL;

	spin_lock_bh(&ring->lock);
	if (!test_bit(YDEV_STATUS_READY, &ring->ydev->status) || ycc_ring_stopped(ring)) {
		pr_debug("YCC: equeue error, device status: %ld, ring stopped: %d\n",
			 ring->ydev->status, ycc_ring_stopped(ring));

		/* Fallback to software */
		ret = -EAGAIN;
		goto out;
	}

	ring->cmd_rd_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR);
	if (ycc_ring_full(ring)) {
		pr_debug("Failed to enqueue cmd on ring:%d, due to ring full\n", ring->ring_id);
		ret = -EAGAIN;
		goto out;
	}

	memcpy(ring->cmd_base_vaddr + ring->cmd_wr_ptr * YCC_CMD_DESC_SIZE, cmd,
	       YCC_CMD_DESC_SIZE);

	/* Ensure that cmd_wr_ptr update after memcpy */
	dma_wmb();
	if (++ring->cmd_wr_ptr == ring->max_desc)
		ring->cmd_wr_ptr = 0;
	YCC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_WR_PTR, ring->cmd_wr_ptr);

out:
	spin_unlock_bh(&ring->lock);
	return ret;
}

static void ycc_cancel_cmd(struct ycc_ring *ring,
		struct ycc_cmd_desc *desc)
{
	struct ycc_flags *aflag;

	dma_rmb();

	aflag = (struct ycc_flags *)desc->private_ptr;
	if (!aflag || (u64)aflag == CMD_INVALID_CONTENT_U64) {
		pr_debug("YCC: Invalid aflag\n");
		return;
	}

	aflag->ycc_done_callback(aflag->ptr, CMD_CANCELLED);

	memset(desc, CMD_INVALID_CONTENT_U8, sizeof(*desc));
	kfree(aflag);
}

static inline void ycc_check_cmd_state(u16 state)
{
	switch (state) {
	case CMD_SUCCESS:
		break;
	case CMD_ILLEGAL:
		pr_debug("YCC response: Illegal cmd\n");
		break;
	case CMD_UNDERATTACK:
		pr_debug("YCC response: Attack is detected\n");
		break;
	case CMD_INVALID:
		pr_debug("YCC response: Invalid cmd\n");
		break;
	case CMD_ERROR:
		pr_debug("YCC response: Cmd error\n");
		break;
	case CMD_EXCESS:
		pr_debug("YCC response: Excess permission\n");
		break;
	case CMD_KEY_ERROR:
		pr_debug("YCC response: Invalid internal key\n");
		break;
	case CMD_VERIFY_ERROR:
		pr_debug("YCC response: Mac/tag verify failed\n");
		break;
	default:
		pr_debug("YCC response: Unknown error\n");
		break;
	}
}

void ycc_handle_resp(struct ycc_ring *ring, struct ycc_resp_desc *desc)
{
	struct ycc_flags *aflag;

	dma_rmb();

	aflag = (struct ycc_flags *)desc->private_ptr;
	if (!aflag || (u64)aflag == CMD_INVALID_CONTENT_U64) {
		pr_debug("YCC: Invalid aflag\n");
		return;
	}

	ycc_check_cmd_state(desc->state);
	aflag->ycc_done_callback(aflag->ptr, desc->state);

	memset(desc, CMD_INVALID_CONTENT_U8, sizeof(*desc));
	kfree(aflag);
}

/*
 * dequeue, read response descriptor
 */
void ycc_dequeue(struct ycc_ring *ring)
{
	struct ycc_resp_desc *resp;
	int cnt = 0;

	if (!test_bit(YDEV_STATUS_READY, &ring->ydev->status) || ycc_ring_stopped(ring))
		return;

	ring->resp_wr_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);
	while (!ycc_ring_empty(ring)) {
		resp = (struct ycc_resp_desc *)ring->resp_base_vaddr +
			ring->resp_rd_ptr;
		ycc_handle_resp(ring, resp);

		cnt++;
		if (++ring->resp_rd_ptr == ring->max_desc)
			ring->resp_rd_ptr = 0;
	}

	if (cnt)
		YCC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_RD_PTR, ring->resp_rd_ptr);
}

/*
 * Clear incompletion cmds in command queue while rollback cmd_wr_ptr.
 *
 * Note: Make sure been invoked when error occurs in YCC internal and
 * YCC status is not ready.
 */
void ycc_clear_cmd_ring(struct ycc_ring *ring)
{
	struct ycc_cmd_desc *desc = NULL;

	ring->cmd_rd_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR);
	ring->cmd_wr_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_WR_PTR);

	while (ring->cmd_rd_ptr != ring->cmd_wr_ptr) {
		desc = (struct ycc_cmd_desc *)ring->cmd_base_vaddr + ring->cmd_rd_ptr;
		ycc_cancel_cmd(ring, desc);

		if (--ring->cmd_wr_ptr == 0)
			ring->cmd_wr_ptr = ring->max_desc;
	}

	YCC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_WR_PTR, ring->cmd_wr_ptr);
}

/*
 * Clear response queue
 *
 * Note: Make sure been invoked when error occurs in YCC internal and
 * YCC status is not ready.
 */
void ycc_clear_resp_ring(struct ycc_ring *ring)
{
	struct ycc_resp_desc *resp;
	int retry;
	u32 pending_cmd;

	/*
	 * Check if the ring has been stopped. *stop* means no
	 * new transactions, No need to wait for pending_cmds
	 * been processed under this condition.
	 */
	retry = ycc_ring_stopped(ring) ? 0 : MAX_ERROR_RETRY;
	pending_cmd = YCC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);

	ring->resp_wr_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);
	while (!ycc_ring_empty(ring) || (retry && pending_cmd)) {
		if (!ycc_ring_empty(ring)) {
			resp = (struct ycc_resp_desc *)ring->resp_base_vaddr +
				ring->resp_rd_ptr;
			resp->state = CMD_CANCELLED;
			ycc_handle_resp(ring, resp);

			if (++ring->resp_rd_ptr == ring->max_desc)
				ring->resp_rd_ptr = 0;

			YCC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_RD_PTR, ring->resp_rd_ptr);
		} else {
			udelay(MAX_SLEEP_US_PER_CHECK);
			retry--;
		}

		pending_cmd = YCC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);
		ring->resp_wr_ptr = YCC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);
	}

	if (!retry && pending_cmd)
		ring->type = INVAL_RING;

	ring->status = 0;
}
