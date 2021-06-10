/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Intel IOMMU trace support
 *
 * Copyright (C) 2019 Intel Corporation
 *
 * Author: Lu Baolu <baolu.lu@linux.intel.com>
 */
#ifdef CONFIG_INTEL_IOMMU
#undef TRACE_SYSTEM
#define TRACE_SYSTEM intel_iommu

#if !defined(_TRACE_INTEL_IOMMU_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_INTEL_IOMMU_H

#include <linux/tracepoint.h>
#include <linux/intel-iommu.h>

#define MSG_MAX		256

DECLARE_EVENT_CLASS(dma_map,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, phys_addr_t phys_addr,
		 size_t size),

	TP_ARGS(dev, dev_addr, phys_addr, size),

	TP_STRUCT__entry(
		__string(dev_name, dev_name(dev))
		__field(dma_addr_t, dev_addr)
		__field(phys_addr_t, phys_addr)
		__field(size_t,	size)
	),

	TP_fast_assign(
		__assign_str(dev_name, dev_name(dev));
		__entry->dev_addr = dev_addr;
		__entry->phys_addr = phys_addr;
		__entry->size = size;
	),

	TP_printk("dev=%s dev_addr=0x%llx phys_addr=0x%llx size=%zu",
		  __get_str(dev_name),
		  (unsigned long long)__entry->dev_addr,
		  (unsigned long long)__entry->phys_addr,
		  __entry->size)
);

DEFINE_EVENT(dma_map, map_single,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, phys_addr_t phys_addr,
		 size_t size),
	TP_ARGS(dev, dev_addr, phys_addr, size)
);

DEFINE_EVENT(dma_map, bounce_map_single,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, phys_addr_t phys_addr,
		 size_t size),
	TP_ARGS(dev, dev_addr, phys_addr, size)
);

DECLARE_EVENT_CLASS(dma_unmap,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, size_t size),

	TP_ARGS(dev, dev_addr, size),

	TP_STRUCT__entry(
		__string(dev_name, dev_name(dev))
		__field(dma_addr_t, dev_addr)
		__field(size_t,	size)
	),

	TP_fast_assign(
		__assign_str(dev_name, dev_name(dev));
		__entry->dev_addr = dev_addr;
		__entry->size = size;
	),

	TP_printk("dev=%s dev_addr=0x%llx size=%zu",
		  __get_str(dev_name),
		  (unsigned long long)__entry->dev_addr,
		  __entry->size)
);

DEFINE_EVENT(dma_unmap, unmap_single,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, size_t size),
	TP_ARGS(dev, dev_addr, size)
);

DEFINE_EVENT(dma_unmap, unmap_sg,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, size_t size),
	TP_ARGS(dev, dev_addr, size)
);

DEFINE_EVENT(dma_unmap, bounce_unmap_single,
	TP_PROTO(struct device *dev, dma_addr_t dev_addr, size_t size),
	TP_ARGS(dev, dev_addr, size)
);

DECLARE_EVENT_CLASS(dma_map_sg,
	TP_PROTO(struct device *dev, int index, int total,
		 struct scatterlist *sg),

	TP_ARGS(dev, index, total, sg),

	TP_STRUCT__entry(
		__string(dev_name, dev_name(dev))
		__field(dma_addr_t, dev_addr)
		__field(phys_addr_t, phys_addr)
		__field(size_t,	size)
		__field(int, index)
		__field(int, total)
	),

	TP_fast_assign(
		__assign_str(dev_name, dev_name(dev));
		__entry->dev_addr = sg->dma_address;
		__entry->phys_addr = sg_phys(sg);
		__entry->size = sg->dma_length;
		__entry->index = index;
		__entry->total = total;
	),

	TP_printk("dev=%s [%d/%d] dev_addr=0x%llx phys_addr=0x%llx size=%zu",
		  __get_str(dev_name), __entry->index, __entry->total,
		  (unsigned long long)__entry->dev_addr,
		  (unsigned long long)__entry->phys_addr,
		  __entry->size)
);

DEFINE_EVENT(dma_map_sg, map_sg,
	TP_PROTO(struct device *dev, int index, int total,
		 struct scatterlist *sg),
	TP_ARGS(dev, index, total, sg)
);

DEFINE_EVENT(dma_map_sg, bounce_map_sg,
	TP_PROTO(struct device *dev, int index, int total,
		 struct scatterlist *sg),
	TP_ARGS(dev, index, total, sg)
);

TRACE_EVENT(prq_report,
	TP_PROTO(struct intel_iommu *iommu, struct device *dev,
		 u64 dw0, u64 dw1, u64 dw2, u64 dw3,
		 unsigned long seq),

	TP_ARGS(iommu, dev, dw0, dw1, dw2, dw3, seq),

	TP_STRUCT__entry(
		__field(u64, dw0)
		__field(u64, dw1)
		__field(u64, dw2)
		__field(u64, dw3)
		__field(unsigned long, seq)
		__string(iommu, iommu->name)
		__string(dev, dev_name(dev))
		__dynamic_array(char, buff, MSG_MAX)
	),

	TP_fast_assign(
		__entry->dw0 = dw0;
		__entry->dw1 = dw1;
		__entry->dw2 = dw2;
		__entry->dw3 = dw3;
		__entry->seq = seq;
		__assign_str(iommu, iommu->name);
		__assign_str(dev, dev_name(dev));
	),

	TP_printk("%s/%s seq# %ld: %s",
		__get_str(iommu), __get_str(dev), __entry->seq,
		decode_prq_descriptor(__get_str(buff), MSG_MAX, __entry->dw0,
				      __entry->dw1, __entry->dw2, __entry->dw3)
	)
);
#endif /* _TRACE_INTEL_IOMMU_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
#endif /* CONFIG_INTEL_IOMMU */
