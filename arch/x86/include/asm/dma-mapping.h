/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_DMA_MAPPING_H
#define _ASM_X86_DMA_MAPPING_H

/*
 * IOMMU interface. See Documentation/DMA-API-HOWTO.txt and
 * Documentation/DMA-API.txt for documentation.
 */

#include <linux/scatterlist.h>
#include <linux/dma-debug.h>
#include <asm/io.h>
#include <asm/swiotlb.h>
#include <linux/dma-contiguous.h>

#ifdef CONFIG_PCI

 #define ZHAOXIN_P2CW_NODE_CHECK         BIT(0)
 #define ZHAOXIN_PATCH_CODE_DEFAULT      ZHAOXIN_P2CW_NODE_CHECK
 #define ZHAOXIN_PATCH_CODE_MAX          ZHAOXIN_P2CW_NODE_CHECK
extern unsigned long zhaoxin_patch_code;
extern bool zhaoxin_p2cw_patch_en;
#ifdef CONFIG_INTEL_IOMMU
extern phys_addr_t patch_get_real_paddr(struct device *dev, dma_addr_t paddr);
#else
 #define patch_get_real_paddr(dev, paddr) paddr
#endif
extern void patch_p2cw_single_map(struct device *dev, dma_addr_t paddr,
		enum dma_data_direction dir, bool is_iommu);
extern void patch_p2cw_sg_map(struct device *dev, struct scatterlist *sglist,
		int nelems, enum dma_data_direction dir, bool is_iommu);
#endif

#ifdef CONFIG_ISA
# define ISA_DMA_BIT_MASK DMA_BIT_MASK(24)
#else
# define ISA_DMA_BIT_MASK DMA_BIT_MASK(32)
#endif

extern int iommu_merge;
extern struct device x86_dma_fallback_dev;
extern int panic_on_overflow;

extern const struct dma_map_ops *dma_ops;

static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return dma_ops;
}

bool arch_dma_alloc_attrs(struct device **dev);
#define arch_dma_alloc_attrs arch_dma_alloc_attrs

#endif
