/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright Alibaba Group. 2022
 *
 * Author(s): Xuan Zhuo <xuanzhuo@linux.alibaba.com>
 */

#ifndef _LINUX_VIRTIO_ISM_H
#define _LINUX_VIRTIO_ISM_H

#include <uapi/linux/virtio_ism.h>
#include <linux/miscdevice.h>

struct virtio_ism_config {
	u64 gid;
	u64 devid;
	u64 region_size;
	u64 notify_size;
};

struct virtio_ism_event {
	u64 num;
	u64 offset[];
};

enum virtio_ism_shm_id {
	VIRTIO_ISM_SHM_ID_UNDEFINED = 0,
	VIRTIO_ISM_SHM_ID_REGIONS   = 1,
	VIRTIO_ISM_SHM_ID_NOTIFY    = 2,
};

/* ack values */
#define VIRTIO_ISM_OK     0
#define VIRTIO_NET_ERR    1


struct virtio_ism_ctrl_alloc {
	u64 size;
};

struct virtio_ism_ctrl_alloc_reply {
	u64 token;
	u64 offset;
};

#define VIRTIO_ISM_CTRL_ALLOC  0
	#define VIRTIO_ISM_CTRL_ALLOC_REGION 0

struct virtio_ism_ctrl_attach {
	u64 token;
	u32 perm;
};

struct virtio_ism_ctrl_attach_reply {
	u64 offset;
	u64 size;
};

#define VIRTIO_ISM_CTRL_ATTACH  1
	#define VIRTIO_ISM_CTRL_ATTACH_REGION 0

struct virtio_ism_ctrl_detach {
	u64 token;
};

#define VIRTIO_ISM_CTRL_DETACH  2
	#define VIRTIO_ISM_CTRL_DETACH_REGION 0

struct virtio_ism_ctrl_grant {
	u64 token;
	u64 peer_devid;
	u64 permissions;
};

#define VIRTIO_ISM_CTRL_GRANT  3
	#define VIRTIO_ISM_CTRL_GRANT_SET 0

#define VIRTIO_ISM_PERM_READ       (1 << 0)
#define VIRTIO_ISM_PERM_WRITE      (1 << 1)
#define VIRTIO_ISM_PERM_ATTACH     (1 << 2)
#define VIRTIO_ISM_PERM_MANAGE     (1 << 3)
#define VIRTIO_ISM_PERM_DENY_OTHER (1 << 4)


struct virtio_ism_ctrl_irq_vector {
	u64 token;
	u64 vector;
};

#define VIRTIO_ISM_CTRL_EVENT_VECTOR  4
	#define VIRTIO_ISM_CTRL_EVENT_VECTOR_SET 0

#define VIRTIO_ISM_F_EVENT_IRQ 0

struct virtio_ism_ctrl_hdr {
	__u8 class;
	__u8 cmd;
} __packed;

struct control_buf {
	u8 status;

	struct virtio_ism_ctrl_hdr hdr;

	struct virtio_ism_ctrl_alloc alloc_out;
	struct virtio_ism_ctrl_alloc_reply alloc_in;

	struct virtio_ism_ctrl_attach attach_out;
	struct virtio_ism_ctrl_attach_reply attach_in;

	struct virtio_ism_ctrl_detach detach_out;


	struct virtio_ism_ctrl_irq_vector vector_out;
};

struct virtio_ism;

typedef int (*virtio_ism_callback)(struct virtio_ism *ism, void *p, void *data);

struct virtio_ism_ops {
	u64 (*get_cdid)(struct virtio_ism *ism);
	u64 (*get_devid)(struct virtio_ism *ism);
	void *(*alloc)(struct virtio_ism *ism, u64 *token, size_t size,
		       virtio_ism_callback cb, void *notify_data);
	void *(*attach)(struct virtio_ism *ism, u64 token, size_t *size,
			virtio_ism_callback cb, void *notify_data);
	void (*detach)(struct virtio_ism *ism, u64 token);
	void (*kick)(struct virtio_ism *ism, void *addr);
};

struct virtio_ism {
	struct list_head node;

	struct virtio_device *vdev;
	struct miscdevice miscdev;
	char devname[25];

	u64 gid;
	u64 devid;
	u64 region_size;
	u64 region_num;
	u64 notify_size;
	u64 ref;

	struct mutex mutex;

	struct control_buf *ctrl;

	struct virtqueue *cvq;

	struct virtio_shm_region notify_reg;
	struct virtio_shm_region shm_reg;

	void *shm_p;
	void __iomem *notify_p;

	u32 vector_start;
	u32 vector_num;

	struct rb_root rbtree;
	struct list_head *irq_ctx_heads;
	u32 irq_ctx_heads_n;
	u32 irq_ctx_min_index;

	const struct virtio_ism_ops *ops;
	struct virtio_ism_stat stats;
	struct virtio_ism_irq_ctx *irq_ctx;

};

enum {
	VIRTIO_ISM_NOTIFIER_EVENT_PROBE,
	VIRTIO_ISM_NOTIFIER_EVENT_REMOVE,
};

struct virtio_ism_notifier_info {
	struct virtio_ism *ism;
};

int virtio_ism_unregister_notifier(struct notifier_block *nb);
int virtio_ism_register_notifier(struct notifier_block *nb);
#endif /* _LINUX_VIRTIO_ISM_H */
