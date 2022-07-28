// SPDX-License-Identifier: GPL-2.0
#ifndef __YCC_UIO_H
#define __YCC_UIO_H

/* udma minimum allocated granularity is 1024B */
#define UNIT_SIZE		(1024)

#define MAX_ALLOC_SIZE		(32768)  /* max malloc size 32K */

#define LARGE_ALLOC_SIZE	(1 << 22) /* large alloc size 4M */

/* udma normal memblock is 2MB */
#define MEMBLOCK_SIZE_NORMAL	(2*1024*1024)  /* normal */
#define MEMBLOCK_SIZE_LARGE	(4*1024*1024)  /* not supported */
#define MEMBLOCK_SIZE_HUGE	(32*1024*1024)  /* not supported */

#define MASK_SIZE_2M (0x200000UL - 1)

#define UNITS_NUM		(MEMBLOCK_SIZE_NORMAL / UNIT_SIZE)
#define BITMAP_LEN		(UNITS_NUM / sizeof(__u64) / 8)

/* number of hash_key buckets is 4KB */
#define HASH_BUCKETS_SHIFT	12
#define HASH_BUCKETS		(1 << HASH_BUCKETS_SHIFT)
#define HASH_BUCKETS_MASK	(HASH_BUCKETS - 1)

#define YCC_CMD_MAGIC		'm'
#define YCC_CMD_MEM_ALLOC	(0)
#define YCC_CMD_MEM_FREE	(1)
#define YCC_CMD_LARGE_MEM_ALLOC	(2)
#define YCC_CMD_LARGE_MEM_FREE	(3)

#define YCC_IOC_MEM_ALLOC	\
	_IOWR(YCC_CMD_MAGIC, YCC_CMD_MEM_ALLOC, struct ycc_udma_info)
#define YCC_IOC_MEM_FREE	\
	_IOWR(YCC_CMD_MAGIC, YCC_CMD_MEM_FREE, struct ycc_udma_info)
#define YCC_IOC_LARGE_MEM_ALLOC	\
	_IOWR(YCC_CMD_MAGIC, YCC_CMD_LARGE_MEM_ALLOC, struct ycc_udma_large_info)
#define YCC_IOC_LARGE_MEM_FREE	\
	_IOWR(YCC_CMD_MAGIC, YCC_CMD_LARGE_MEM_FREE, struct ycc_udma_large_info)

struct ycc_udma_large_info {
	dma_addr_t dma_addr;
	void *virt_addr;
};

struct ycc_udma_info {
	int node;
	size_t size;
	int type;
	void *virt_addr;
	dma_addr_t dma_addr;

	char reserved[256];
};

#ifndef CONFIG_UIO
static inline int ycc_uio_register(struct ycc_ring *ring) { return 0; };
static inline void ycc_uio_unregister(struct ycc_ring *ring) { };
#else
int ycc_uio_register(struct ycc_ring *ring);
void ycc_uio_unregister(struct ycc_ring *ring);
#endif

int ycc_udma_init(void);
void ycc_udma_exit(void);
int ycc_bind_iommu_domain(struct pci_dev *pdev, int id);
void ycc_unbind_iommu_domain(struct pci_dev *pdev, int id);
#endif
