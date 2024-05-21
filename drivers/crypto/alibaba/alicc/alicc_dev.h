/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ALICC_DEV_H
#define __ALICC_DEV_H
#include <linux/platform_device.h>
#include <linux/pci.h>

#define ALICC_MAX_DEBUGFS_NAME		20

#define PCI_VENDOR_ID_ALICC		0x1DED
#define PCI_DEVICE_ID_RCEC		0x8003
#define PCI_DEVICE_ID_RCIEP		0x8001

#define ALICC_RINGPAIR_NUM		48
#define ALICC_IRQS			(ALICC_RINGPAIR_NUM + 1)

#define RING_STOP_BIT			BIT(15)
#define RING_CFG_RING_SZ		GENMASK(2, 0)
#define RING_CFG_INT_TH			GENMASK(15, 8)
#define RING_ERR_AXI			BIT(0)
#define RING_PENDING_CNT		GENMASK(9, 0)

#define ALICC_SEC_CFG_BAR			0
#define ALICC_NSEC_CFG_BAR		1
#define ALICC_SEC_Q_BAR			2
#define ALICC_NSEC_Q_BAR			3

/* alicc secure configuration register offset */
#define REG_ALICC_CTL			0x18
#define REG_ALICC_GO			0x50
#define REG_ALICC_HCLK_INT_STATUS		0x54
#define REG_ALICC_XCLK_INT_STATUS		0x58
#define REG_ALICC_XCLK_MEM_ECC_EN_0	0x5c
#define REG_ALICC_XCLK_MEM_ECC_EN_1	0x60
#define REG_ALICC_XCLK_MEM_ECC_COR_0	0x74
#define REG_ALICC_XCLK_MEM_ECC_COR_1	0x78
#define REG_ALICC_XCLK_MEM_ECC_UNCOR_0	0x80
#define REG_ALICC_XCLK_MEM_ECC_UNCOR_1	0x84
#define REG_ALICC_HCLK_MEM_ECC_EN		0x88
#define REG_ALICC_HCLK_MEM_ECC_COR	0x94
#define REG_ALICC_HCLK_MEM_ECC_UNCOR	0x98

#define REG_ALICC_DEV_INT_MASK		0xA4
#define REG_ALICC_HCLK_INT_MASK		0xE4
#define REG_ALICC_XCLK_INT_MASK		0xE8

/* ring register offset */
#define REG_RING_CMD_BASE_ADDR_LO	0x00
#define REG_RING_CMD_BASE_ADDR_HI	0x04
#define REG_RING_CMD_WR_PTR		0x08
#define REG_RING_CMD_RD_PTR		0x0C
#define REG_RING_RSP_BASE_ADDR_LO	0x10
#define REG_RING_RSP_BASE_ADDR_HI	0x14
#define REG_RING_RSP_WR_PTR		0x18
#define REG_RING_RSP_RD_PTR		0x1C
#define REG_RING_CFG			0x20
#define REG_RING_TO_TH			0x24
#define REG_RING_STATUS			0x28
#define REG_RING_PENDING_CMD		0x2C
#define REG_RING_RSP_WR_SHADOWN_PTR	0x30
#define REG_RING_RSP_AFULL_TH		0x34

#define ALICC_HCLK_AHB_ERR		BIT(0)
#define ALICC_HCLK_SHIELD_ERR		BIT(1)
#define ALICC_HCLK_TRNG_ERR		BIT(2)
#define ALICC_HCLK_EFUSE_ERR		BIT(3)
#define ALICC_HCLK_INIT_ERR		GENMASK(30, 16)
#define ALICC_HCLK_CB_TRNG_ERR		BIT(31)

#define ALICC_CTRL_IRAM_EN		BIT(1)
#define ALICC_CTRL_SEC_EN			BIT(3)

#define ALICC_GO_PWRON			BIT(0)
#define ALICC_GO_ENABLED			BIT(1)

#define PCI_EXR_DEVCTL_TRP		BIT(21)
#define PCI_EXP_DEVCTL_FLREN		BIT(15)

#define YDEV_STATUS_BIND		0
#define YDEV_STATUS_INIT		1
#define YDEV_STATUS_RESET		2
#define YDEV_STATUS_READY		3
#define YDEV_STATUS_ERR			4
#define YDEV_STATUS_SRIOV		5

struct alicc_bar {
	void __iomem *vaddr;
	resource_size_t paddr;
	resource_size_t size;
};

enum alicc_dev_type {
	ALICC_RCIEP,
	ALICC_RCEC,
};

struct alicc_dev {
	u8 type;
	bool is_vf;
	int id;
	int node;
	const char *dev_name;
	struct list_head list;
	struct pci_dev *pdev;
	struct alicc_bar alicc_bars[4];
	struct alicc_dev *assoc_dev;

	int max_desc;
	int user_rings;
	bool is_polling;
	unsigned long status;
	struct workqueue_struct *dev_err_q;
	char err_irq_name[32];
	struct alicc_ring *rings;
	struct work_struct work;
	char *msi_name[48];
	struct dentry *debug_dir;
	atomic_t refcnt;
	bool sec;
	bool enable_vf;
};

#define ALICC_CSR_WR(csr_base, csr_offset, val)		\
	__raw_writel(val, csr_base + csr_offset)
#define ALICC_CSR_RD(csr_base, csr_offset)		\
	__raw_readl(csr_base + csr_offset)

static inline void alicc_dev_get(struct alicc_dev *ydev)
{
	atomic_inc(&ydev->refcnt);
}

static inline void alicc_dev_put(struct alicc_dev *ydev)
{
	atomic_dec(&ydev->refcnt);
}

static inline bool alicc_dev_in_use(struct alicc_dev *ydev)
{
	return atomic_read(&ydev->refcnt) > 0;
}

static inline void alicc_g_err_mask(void *vaddr)
{
	/* This will mask all error interrupt */
	ALICC_CSR_WR(vaddr, REG_ALICC_DEV_INT_MASK, (u32)~0);
}

static inline void alicc_g_err_unmask(void *vaddr)
{
	/* This will unmask all error interrupt */
	ALICC_CSR_WR(vaddr, REG_ALICC_DEV_INT_MASK, 0);
}

int alicc_algorithm_register(void);
void alicc_algorithm_unregister(void);

#endif
