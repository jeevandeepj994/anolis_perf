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

#include "alicc_dev.h"
#include "alicc_ring.h"
#include "alicc_uio.h"

#define ALICC_CMD_DESC_SIZE	64
#define ALICC_RESP_DESC_SIZE	16
#define ALICC_RING_CSR_STRIDE	0x1000

extern struct list_head alicc_table;
extern struct mutex alicc_mutex;

extern void alicc_resp_work_process(struct work_struct *work);

/*
 * Show the status of specified ring's command queue and
 * response queue.
 */
static int alicc_ring_debugfs_status_show(struct seq_file *s, void *p)
{
	struct alicc_ring *ring = (struct alicc_ring *)s->private;

	seq_printf(s, "Ring ID: %d\n", ring->ring_id);
	seq_printf(s, "Desscriptor Entry Size: %d, CMD Descriptor Size: %d, RESP Descriptor Size :%d\n",
		   ring->max_desc, ALICC_CMD_DESC_SIZE, ALICC_RESP_DESC_SIZE);
	seq_printf(s, "CMD base addr:%llx, RESP base addr:%llx\n",
		   ring->cmd_base_paddr, ring->resp_base_paddr);
	seq_printf(s, "CMD wr ptr:%d, CMD rd ptr: %d\n",
		   ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_WR_PTR),
		   ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR));
	seq_printf(s, "RESP rd ptr:%d, RESP wr ptr: %d\n",
		   ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_RD_PTR),
		   ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR));

	return 0;
}

static int alicc_ring_debugfs_status_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, alicc_ring_debugfs_status_show, inode->i_private);
}

static const struct file_operations alicc_ring_status_fops = {
	.open		= alicc_ring_debugfs_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

/*
 * Dump the raw content of specified ring's command queue and
 * response queue.
 */
static int alicc_ring_debugfs_dump_show(struct seq_file *s, void *p)
{
	struct alicc_ring *ring = (struct alicc_ring *)s->private;

	seq_printf(s, "Ring ID: %d\n", ring->ring_id);
	seq_puts(s, "-------- Ring CMD Descriptors --------\n");
	seq_hex_dump(s, "", DUMP_PREFIX_ADDRESS, 32, 4, ring->cmd_base_vaddr,
		     ALICC_CMD_DESC_SIZE * ring->max_desc, false);
	seq_puts(s, "-------- Ring RESP Descriptors --------\n");
	seq_hex_dump(s, "", DUMP_PREFIX_ADDRESS, 32, 4, ring->resp_base_vaddr,
		     ALICC_RESP_DESC_SIZE * ring->max_desc, false);

	return 0;
}

static int alicc_ring_debugfs_dump_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, alicc_ring_debugfs_dump_show, inode->i_private);
}

static const struct file_operations alicc_ring_dump_fops = {
	.open		= alicc_ring_debugfs_dump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

/*
 * Create debugfs for rings, only for KERN_RING
 * "/sys/kernel/debugfs/alicc_b:d.f/ring${x}"
 */
static int alicc_create_ring_debugfs(struct alicc_ring *ring)
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
				      (void *)ring, &alicc_ring_status_fops);
	if (IS_ERR_OR_NULL(debugfs))
		goto remove_debugfs;

	debugfs = debugfs_create_file("dump", 0400, ring->debug_dir,
				      (void *)ring, &alicc_ring_dump_fops);
	if (IS_ERR_OR_NULL(debugfs))
		goto remove_debugfs;

	return 0;

remove_debugfs:
	debugfs_remove_recursive(ring->debug_dir);
out:
	ring->debug_dir = NULL;
	return PTR_ERR(debugfs);
}

static void alicc_remove_ring_debugfs(struct alicc_ring *ring)
{
	debugfs_remove_recursive(ring->debug_dir);
}

/*
 * 'base_r' is an anchor when selecting the right ring,
 * right means that the ring has the lowest reference
 * count.
 */
static struct alicc_ring *base_r;

/*
 * Allocate memory for rings and initiate basic fields
 */
static int alicc_alloc_rings(struct alicc_dev *ydev)
{
	int num = ALICC_RINGPAIR_NUM;
	struct alicc_bar *abar;
	u32 i;

	if (ydev->rings)
		return 0;

	if (ydev->is_vf) {
		num = 1;
		abar = &ydev->alicc_bars[0];
	} else if (ydev->sec) {
		abar = &ydev->alicc_bars[ALICC_SEC_Q_BAR];
	} else {
		abar = &ydev->alicc_bars[ALICC_NSEC_Q_BAR];
	}

	ydev->rings = kzalloc_node(num * sizeof(struct alicc_ring),
				   GFP_KERNEL, ydev->node);
	if (!ydev->rings)
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		ydev->rings[i].ring_id = i;
		ydev->rings[i].ydev = ydev;
		ydev->rings[i].csr_vaddr = abar->vaddr + i * ALICC_RING_CSR_STRIDE;
		ydev->rings[i].csr_paddr = abar->paddr + i * ALICC_RING_CSR_STRIDE;
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
static void alicc_free_rings(struct alicc_dev *ydev)
{
	kfree(ydev->rings);
	ydev->rings = NULL;
	base_r = NULL;
}

/*
 * Initiate ring and create command queue and response queue.
 */
static int alicc_init_ring(struct alicc_ring *ring, u32 max_desc)
{
	struct alicc_dev *ydev = ring->ydev;
	u32 cmd_ring_size, resp_ring_size;
	int order = 0;
	u32 val = 0;

	/* KERN_RING won't exposed to uio */
	ring->type = KERN_RING;
	ring->max_desc = max_desc;

	cmd_ring_size = ring->max_desc * ALICC_CMD_DESC_SIZE;
	resp_ring_size = ring->max_desc * ALICC_RESP_DESC_SIZE;

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

	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_CFG, val);
	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_AFULL_TH, 0);
	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_BASE_ADDR_LO,
					(u32)ring->cmd_base_paddr & 0xffffffff);
	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_BASE_ADDR_HI,
					((u64)ring->cmd_base_paddr >> 32) & 0xffffffff);
	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_BASE_ADDR_LO,
					(u32)ring->resp_base_paddr & 0xffffffff);
	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_BASE_ADDR_HI,
					((u64)ring->resp_base_paddr >> 32) & 0xffffffff);

	if (alicc_create_ring_debugfs(ring))
		pr_warn("Failed to create debugfs entry for ring:%d\n", ring->ring_id);

	atomic_set(&ring->ref_cnt, 0);
	spin_lock_init(&ring->lock);
	return 0;
}

/*
 * Release dma memory for command queue and response queue.
 */
static void alicc_release_ring(struct alicc_ring *ring)
{
	u32 ring_size;

	BUG_ON(atomic_read(&ring->ref_cnt));

	if (ring->cmd_base_vaddr) {
		ring_size = ring->max_desc * ALICC_CMD_DESC_SIZE;
		dma_free_coherent(&ring->ydev->pdev->dev, ring_size,
				  ring->cmd_base_vaddr,
				  ring->cmd_base_paddr);
		ring->cmd_base_vaddr = NULL;
	}
	if (ring->resp_base_vaddr) {
		ring_size = ring->max_desc * ALICC_RESP_DESC_SIZE;
		dma_free_coherent(&ring->ydev->pdev->dev, ring_size,
				  ring->resp_base_vaddr,
				  ring->resp_base_paddr);
		ring->resp_base_vaddr = NULL;
	}

	alicc_remove_ring_debugfs(ring);
	ring->type = FREE_RING;
}

int alicc_dev_rings_init(struct alicc_dev *ydev, u32 max_desc, int user_rings)
{
	int kern_rings = ALICC_RINGPAIR_NUM - user_rings;
	struct pci_dev *pdev = ydev->pdev;
	struct alicc_ring *ring;
	int kern_cnt, user_cnt;
	int ret = 0;
	int i;

	ret = alicc_alloc_rings(ydev);
	if (ret) {
		dev_err(&pdev->dev, "Probe failed when allocating rings\n");
		return ret;
	}

	for (i = 0; i < kern_rings; i++) {
		ring = &ydev->rings[i];
		ret = alicc_init_ring(ring, max_desc);
		if (ret) {
			kern_cnt = i;
			goto free_kern_rings;
		}
		INIT_WORK(&ring->work, alicc_resp_work_process);
	}
	kern_cnt = kern_rings;

	for (i = kern_rings; i < ALICC_RINGPAIR_NUM; i++) {
		ring = &ydev->rings[i];
		ret = alicc_uio_register(ring);
		if (ret) {
			user_cnt = i - kern_rings;
			goto free_user_rings;
		}
	}

	return 0;

free_user_rings:
	for (i = 0; i < user_cnt; i++) {
		ring = &ydev->rings[i + kern_rings];
		alicc_uio_unregister(ring);
	}

free_kern_rings:
	for (i = 0; i < kern_cnt; i++) {
		ring = &ydev->rings[i];
		alicc_release_ring(ring);
	}

	alicc_free_rings(ydev);
	return ret;
}

void alicc_dev_rings_release(struct alicc_dev *ydev, int user_rings)
{
	int kern_rings = ALICC_RINGPAIR_NUM - user_rings;
	struct alicc_ring *ring;
	int i;

	for (i = 0; i < kern_rings; i++) {
		ring = &ydev->rings[i];
		alicc_release_ring(ring);
	}

	for (i = 0; i < user_rings; i++) {
		ring = &ydev->rings[i + kern_rings];
		alicc_uio_unregister(ring);
	}

	alicc_free_rings(ydev);
}

/*
 * Check if the command queue is full.
 */
static inline bool alicc_ring_full(struct alicc_ring *ring)
{
	return ring->cmd_rd_ptr == (ring->cmd_wr_ptr + 1) % ring->max_desc;
}

/*
 * Check if the response queue is empty
 */
static inline bool alicc_ring_empty(struct alicc_ring *ring)
{
	return ring->resp_rd_ptr == ring->resp_wr_ptr;
}

static struct alicc_ring *alicc_select_ring(void)
{
	struct alicc_ring *cur_r;
	struct list_head *itr;
	struct alicc_dev *ydev;
	int i;

	if (list_empty(&alicc_table))
		return NULL;

	list_for_each(itr, &alicc_table) {
		ydev = list_entry(itr, struct alicc_dev, list);
		if (ydev->type != ALICC_RCIEP ||
		    !test_bit(YDEV_STATUS_READY, &ydev->status))
			continue;

		for (i = 0; i < ALICC_RINGPAIR_NUM; i++) {
			cur_r = ydev->rings + i;

			/* Ring is not for kernel */
			if (cur_r->type != KERN_RING)
				continue;

			if (!base_r) {
				/* It means alicc is first used */
				base_r = cur_r;
				alicc_ring_get(cur_r);
				return cur_r;
			}
			/* Compare to base ring */
			if (!atomic_read(&base_r->ref_cnt) ||
			    (atomic_read(&base_r->ref_cnt) <
			     atomic_read(&cur_r->ref_cnt))) {
				alicc_ring_get(base_r);
				return base_r;
			} else if (atomic_read(&base_r->ref_cnt) >
				   atomic_read(&cur_r->ref_cnt)) {
				alicc_ring_get(cur_r);
				return cur_r;
			}
		}
	}

	if (base_r)
		alicc_ring_get(base_r);

	return base_r;
}

/*
 * Bind the ring to crypto
 */
struct alicc_ring *alicc_crypto_get_ring(void)
{
	struct alicc_ring *ring = NULL;

	mutex_lock(&alicc_mutex);

	ring = alicc_select_ring();
	if (!ring)
		goto out;

	alicc_dev_get(ring->ydev);
	if (ring->ydev->is_polling && atomic_read(&ring->ref_cnt) == 1)
		schedule_work(&ring->work);

out:
	mutex_unlock(&alicc_mutex);
	return ring;
}

void alicc_crypto_free_ring(struct alicc_ring *ring)
{
	if (!ring)
		return;

	/* TODO: Replace it by ring's own mutex which
	 * will be added to protect ring->work to not be
	 * canceled when another process just schedule it.
	 */
	mutex_lock(&alicc_mutex);
	if (atomic_dec_and_test(&ring->ref_cnt))
		cancel_work_sync(&ring->work);

	mutex_unlock(&alicc_mutex);

	alicc_dev_put(ring->ydev);
}

/*
 * Submit command to ring's command queue.
 */
int alicc_enqueue(struct alicc_ring *ring, void *cmd)
{
	int ret = 0;

	if (!ring || !ring->ydev || !cmd)
		return -EINVAL;

	spin_lock_bh(&ring->lock);
	if (!test_bit(YDEV_STATUS_READY, &ring->ydev->status) || alicc_ring_stopped(ring)) {
		pr_debug("ALICC: equeue error, device status: %ld, ring stopped: %d\n",
			 ring->ydev->status, alicc_ring_stopped(ring));

		/* Fallback to software */
		ret = -EAGAIN;
		goto out;
	}

	ring->cmd_rd_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR);
	if (alicc_ring_full(ring)) {
		pr_debug("Failed to enqueue cmd on ring:%d, due to ring full\n", ring->ring_id);
		ret = -EAGAIN;
		goto out;
	}

	memcpy(ring->cmd_base_vaddr + ring->cmd_wr_ptr * ALICC_CMD_DESC_SIZE, cmd,
	       ALICC_CMD_DESC_SIZE);

	/* Ensure that cmd_wr_ptr update after memcpy */
	dma_wmb();
	if (++ring->cmd_wr_ptr == ring->max_desc)
		ring->cmd_wr_ptr = 0;
	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_WR_PTR, ring->cmd_wr_ptr);

out:
	spin_unlock_bh(&ring->lock);
	return ret;
}

static void alicc_cancel_cmd(struct alicc_ring *ring,
		struct alicc_cmd_desc *desc)
{
	struct alicc_flags *aflag;

	dma_rmb();

	aflag = (struct alicc_flags *)desc->private_ptr;
	if (!aflag || (u64)aflag == CMD_INVALID_CONTENT_U64) {
		pr_debug("ALICC: Invalid aflag\n");
		return;
	}

	aflag->alicc_done_callback(aflag->ptr, CMD_CANCELLED);

	memset(desc, CMD_INVALID_CONTENT_U8, sizeof(*desc));
	kfree(aflag);
}

static inline void alicc_check_cmd_state(u16 state)
{
	switch (state) {
	case CMD_SUCCESS:
		break;
	case CMD_ILLEGAL:
		pr_debug("ALICC response: Illegal cmd\n");
		break;
	case CMD_UNDERATTACK:
		pr_debug("ALICC response: Attack is detected\n");
		break;
	case CMD_INVALID:
		pr_debug("ALICC response: Invalid cmd\n");
		break;
	case CMD_ERROR:
		pr_debug("ALICC response: Cmd error\n");
		break;
	case CMD_EXCESS:
		pr_debug("ALICC response: Excess permission\n");
		break;
	case CMD_KEY_ERROR:
		pr_debug("ALICC response: Invalid internal key\n");
		break;
	case CMD_VERIFY_ERROR:
		pr_debug("ALICC response: Mac/tag verify failed\n");
		break;
	default:
		pr_debug("ALICC response: Unknown error\n");
		break;
	}
}

void alicc_handle_resp(struct alicc_ring *ring, struct alicc_resp_desc *desc)
{
	struct alicc_flags *aflag;

	dma_rmb();

	aflag = (struct alicc_flags *)desc->private_ptr;
	if (!aflag || (u64)aflag == CMD_INVALID_CONTENT_U64) {
		pr_debug("ALICC: Invalid aflag\n");
		return;
	}

	alicc_check_cmd_state(desc->state);
	aflag->alicc_done_callback(aflag->ptr, desc->state);

	memset(desc, CMD_INVALID_CONTENT_U8, sizeof(*desc));
	kfree(aflag);
}

/*
 * dequeue, read response descriptor
 */
void alicc_dequeue(struct alicc_ring *ring)
{
	struct alicc_resp_desc *resp;
	int cnt = 0;

	if (!test_bit(YDEV_STATUS_READY, &ring->ydev->status) || alicc_ring_stopped(ring))
		return;

	ring->resp_wr_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);
	while (!alicc_ring_empty(ring)) {
		resp = (struct alicc_resp_desc *)ring->resp_base_vaddr +
			ring->resp_rd_ptr;
		alicc_handle_resp(ring, resp);

		cnt++;
		if (++ring->resp_rd_ptr == ring->max_desc)
			ring->resp_rd_ptr = 0;
	}

	if (cnt)
		ALICC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_RD_PTR, ring->resp_rd_ptr);
}

/*
 * Clear incompletion cmds in command queue while rollback cmd_wr_ptr.
 *
 * Note: Make sure been invoked when error occurs in ALICC internal and
 * ALICC status is not ready.
 */
void alicc_clear_cmd_ring(struct alicc_ring *ring)
{
	struct alicc_cmd_desc *desc = NULL;

	ring->cmd_rd_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_RD_PTR);
	ring->cmd_wr_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_CMD_WR_PTR);

	while (ring->cmd_rd_ptr != ring->cmd_wr_ptr) {
		desc = (struct alicc_cmd_desc *)ring->cmd_base_vaddr + ring->cmd_rd_ptr;
		alicc_cancel_cmd(ring, desc);

		if (--ring->cmd_wr_ptr == 0)
			ring->cmd_wr_ptr = ring->max_desc;
	}

	ALICC_CSR_WR(ring->csr_vaddr, REG_RING_CMD_WR_PTR, ring->cmd_wr_ptr);
}

/*
 * Clear response queue
 *
 * Note: Make sure been invoked when error occurs in ALICC internal and
 * ALICC status is not ready.
 */
void alicc_clear_resp_ring(struct alicc_ring *ring)
{
	struct alicc_resp_desc *resp;
	int retry;
	u32 pending_cmd;

	/*
	 * Check if the ring has been stopped. *stop* means no
	 * new transactions, No need to wait for pending_cmds
	 * been processed under this condition.
	 */
	retry = alicc_ring_stopped(ring) ? 0 : MAX_ERROR_RETRY;
	pending_cmd = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);

	ring->resp_wr_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);
	while (!alicc_ring_empty(ring) || (retry && pending_cmd)) {
		if (!alicc_ring_empty(ring)) {
			resp = (struct alicc_resp_desc *)ring->resp_base_vaddr +
				ring->resp_rd_ptr;
			resp->state = CMD_CANCELLED;
			alicc_handle_resp(ring, resp);

			if (++ring->resp_rd_ptr == ring->max_desc)
				ring->resp_rd_ptr = 0;

			ALICC_CSR_WR(ring->csr_vaddr, REG_RING_RSP_RD_PTR, ring->resp_rd_ptr);
		} else {
			udelay(MAX_SLEEP_US_PER_CHECK);
			retry--;
		}

		pending_cmd = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_PENDING_CMD);
		ring->resp_wr_ptr = ALICC_CSR_RD(ring->csr_vaddr, REG_RING_RSP_WR_PTR);
	}

	if (!retry && pending_cmd)
		ring->type = INVAL_RING;

	ring->status = 0;
}
