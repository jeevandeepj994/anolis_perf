// SPDX-License-Identifier: GPL-2.0
#ifndef __YCC_RING_H
#define __YCC_RING_H
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#define CMD_ILLEGAL			0x15
#define CMD_UNDERATTACK			0x25
#define CMD_INVALID			0x35
#define CMD_ERROR			0x45
#define CMD_EXCESS			0x55
#define CMD_KEY_ERROR			0x65
#define CMD_VERIFY_ERROR		0x85
#define CMD_SUCCESS			0xa5
#define CMD_CANCELLED			0xff

#define CMD_INVALID_CONTENT_U8		0x7f
#define CMD_INVALID_CONTENT_U64		0x7f7f7f7f7f7f7f7fULL

enum ring_type {
	FREE_RING,
	USER_RING,
	KERN_RING,
	INVAL_RING,
};

struct ycc_ring {
	u16 ring_id;
	atomic_t ref_cnt;
	void __iomem *csr_vaddr;	/* config register address */
	resource_size_t csr_paddr;
	struct ycc_dev *ydev;		/* belongs to which ydev */
	struct uio_info *uio_info;
	struct dentry *debug_dir;

	u32 max_desc;		/* max desc entry numbers */
	u32 irq_th;
	spinlock_t lock;	/* used to send cmd, protect write ptr */
	enum ring_type type;	/* LKCF or UIO */

	void *cmd_base_vaddr;	/* base addr of cmd ring */
	dma_addr_t cmd_base_paddr;
	u16 cmd_wr_ptr;		/* current cmd write pointer */
	u16 cmd_rd_ptr;		/* current cmd read pointer */
	void *resp_base_vaddr;	/* base addr of resp ring */
	dma_addr_t resp_base_paddr;
	u16 resp_wr_ptr;	/* current resp write pointer */
	u16 resp_rd_ptr;	/* current resp read pointer */

	struct work_struct work;
};

struct ycc_flags {
	void *ptr;
	int (*ycc_done_callback)(void *ptr, u16 state);
};

struct ycc_resp_desc {
	u64 private_ptr;
	u16 state;
	u8 reserved[6];
};

struct ycc_skcipher_cmd {
	u8 cmd_id;
	u8 mode;
	u64 sptr:48;
	u64 dptr:48;
	u32 dlen;
	u16 key_idx;	/* key used to decrypt kek */
	u8 reserved[2];
	u64 keyptr:48;
	u8 padding;
} __packed;

struct ycc_aead_cmd {
	u8 cmd_id;
	u8 mode;
	u64 sptr:48;	/* include aad + payload */
	u64 dptr:48;	/* encrypted/decrypted + tag */
	u32 dlen;	/* data size */
	u16 key_idx;
	u16 kek_idx;
	u64 keyptr:48;
	u16 aadlen;
	u8 taglen;	/* authenc size */
} __packed;

union ycc_real_cmd {
	struct ycc_skcipher_cmd ske_cmd;
	struct ycc_aead_cmd aead_cmd;
	u8 padding[32];
};

struct ycc_cmd_desc {
	union ycc_real_cmd cmd;
	u64 private_ptr;
	u8 reserved0[16];
	u8 reserved1[8];
} __packed;

static inline void ycc_ring_get(struct ycc_ring *ring)
{
	atomic_inc(&ring->ref_cnt);
}

static inline void ycc_ring_put(struct ycc_ring *ring)
{
	atomic_dec(&ring->ref_cnt);
}

int ycc_enqueue(struct ycc_ring *ring, void *cmd);
void ycc_dequeue(struct ycc_ring *ring);
void ycc_clear_ring(struct ycc_ring *ring, u32 pending_cmd);
struct ycc_ring *ycc_crypto_get_ring(void);
void ycc_crypto_free_ring(struct ycc_ring *ring);
int ycc_dev_rings_init(struct ycc_dev *ydev, u32 max_desc, int user_rings);
void ycc_dev_rings_release(struct ycc_dev *ydev, int user_rings);
#endif
