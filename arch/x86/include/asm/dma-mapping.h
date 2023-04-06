/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_DMA_MAPPING_H
#define _ASM_X86_DMA_MAPPING_H

/*
 * IOMMU interface. See Documentation/core-api/dma-api-howto.rst and
 * Documentation/core-api/dma-api.rst for documentation.
 */

#include <linux/scatterlist.h>
#include <asm/io.h>
#include <asm/swiotlb.h>

#ifdef CONFIG_PCI

#define ZHAOXIN_P2CW_NODE_CHECK         BIT(0)
#define ZHAOXIN_PATCH_CODE_DEFAULT   ZHAOXIN_P2CW_NODE_CHECK
#define ZHAOXIN_PATCH_CODE_MAX       ZHAOXIN_P2CW_NODE_CHECK
extern unsigned long zhaoxin_patch_code;
extern bool zhaoxin_p2cw_patch_en;

void patch_p2cw_single_map(struct device *dev, dma_addr_t paddr,
		enum dma_data_direction dir, const struct dma_map_ops *ops);
void patch_p2cw_sg_map(struct device *dev, struct scatterlist *sglist,
		int nelems, enum dma_data_direction dir, const struct dma_map_ops *ops);
#endif

extern int iommu_merge;
extern int panic_on_overflow;

extern const struct dma_map_ops *dma_ops;

static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return dma_ops;
}

#endif
