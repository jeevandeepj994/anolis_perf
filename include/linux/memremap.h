/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMREMAP_H_
#define _LINUX_MEMREMAP_H_
#include <linux/ck_kabi.h>
#include <linux/range.h>
#include <linux/ioport.h>
#include <linux/percpu-refcount.h>

struct resource;
struct device;

/**
 * struct vmem_altmap - pre-allocated storage for vmemmap_populate
 * @base_pfn: base of the entire dev_pagemap mapping
 * @reserve: pages mapped, but reserved for driver use (relative to @base)
 * @free: free pages set aside in the mapping for memmap storage
 * @align: pages reserved to meet allocation alignments
 * @alloc: track pages consumed, private to vmemmap_populate()
 */
struct vmem_altmap {
	unsigned long base_pfn;
	const unsigned long end_pfn;
	const unsigned long reserve;
	unsigned long free;
	unsigned long align;
	unsigned long alloc;

	CK_KABI_RESERVE(1)
	CK_KABI_RESERVE(2)
};

/*
 * Specialize ZONE_DEVICE memory into multiple types each having differents
 * usage.
 *
 * MEMORY_DEVICE_PRIVATE:
 * Device memory that is not directly addressable by the CPU: CPU can neither
 * read nor write private memory. In this case, we do still have struct pages
 * backing the device memory. Doing so simplifies the implementation, but it is
 * important to remember that there are certain points at which the struct page
 * must be treated as an opaque object, rather than a "normal" struct page.
 *
 * A more complete discussion of unaddressable memory may be found in
 * include/linux/hmm.h and Documentation/vm/hmm.rst.
 *
 * MEMORY_DEVICE_FS_DAX:
 * Host memory that has similar access semantics as System RAM i.e. DMA
 * coherent and supports page pinning. In support of coordinating page
 * pinning vs other operations MEMORY_DEVICE_FS_DAX arranges for a
 * wakeup event whenever a page is unpinned and becomes idle. This
 * wakeup is used to coordinate physical address space management (ex:
 * fs truncate/hole punch) vs pinned pages (ex: device dma).
 *
 * MEMORY_DEVICE_GENERIC:
 * Host memory that has similar access semantics as System RAM i.e. DMA
 * coherent and supports page pinning. This is for example used by DAX devices
 * that expose memory using a character device.
 *
 * MEMORY_DEVICE_PCI_P2PDMA:
 * Device memory residing in a PCI BAR intended for use with Peer-to-Peer
 * transactions.
 */
enum memory_type {
	/* 0 is reserved to catch uninitialized type fields */
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_FS_DAX,
	MEMORY_DEVICE_GENERIC,
	MEMORY_DEVICE_PCI_P2PDMA,
};

struct dev_pagemap_ops {
	/*
	 * Called once the page refcount reaches 1.  (ZONE_DEVICE pages never
	 * reach 0 refcount unless there is a refcount bug. This allows the
	 * device driver to implement its own memory management.)
	 */
	void (*page_free)(struct page *page);

	/*
	 * Transition the refcount in struct dev_pagemap to the dead state.
	 */
	void (*kill)(struct dev_pagemap *pgmap);

	/*
	 * Wait for refcount in struct dev_pagemap to be idle and reap it.
	 */
	void (*cleanup)(struct dev_pagemap *pgmap);

	/*
	 * Used for private (un-addressable) device memory only.  Must migrate
	 * the page back to a CPU accessible page.
	 */
	vm_fault_t (*migrate_to_ram)(struct vm_fault *vmf);

	/*
	 * Handle the memory failure happens on a range of pfns.  Notify the
	 * processes who are using these pfns, and try to recover the data on
	 * them if necessary.  The mf_flags is finally passed to the recover
	 * function through the whole notify routine.
	 *
	 * When this is not implemented, or it returns -EOPNOTSUPP, the caller
	 * will fall back to a common handler called mf_generic_kill_procs().
	 */
	CK_KABI_USE(1,
		int (*memory_failure)(struct dev_pagemap *pgmap, unsigned long pfn,
			      unsigned long nr_pages, int mf_flags));
	CK_KABI_RESERVE(2)
};

#define PGMAP_ALTMAP_VALID	(1 << 0)
#define PGMAP_ON_DEMAND		(1 << 1)

/**
 * struct dev_pagemap - metadata for ZONE_DEVICE mappings
 * @altmap: pre-allocated/reserved memory for vmemmap allocations
 * @ref: reference count that pins the devm_memremap_pages() mapping
 * @internal_ref: internal reference if @ref is not provided by the caller
 * @done: completion for @internal_ref
 * @type: memory type: see MEMORY_* in memory_hotplug.h
 * @flags: PGMAP_* flags to specify defailed behavior
 * @ops: method table
 * @owner: an opaque pointer identifying the entity that manages this
 *	instance.  Used by various helpers to make sure that no
 *	foreign ZONE_DEVICE memory is accessed.
 * @nr_range: number of ranges to be mapped
 * @range: range to be mapped when nr_range == 1
 * @ranges: array of ranges to be mapped when nr_range > 1
 */
struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref *ref;
	struct percpu_ref internal_ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;

	CK_KABI_RESERVE(1)
	CK_KABI_RESERVE(2)
	CK_KABI_RESERVE(3)
	CK_KABI_RESERVE(4)
	CK_KABI_RESERVE(5)

	union {
		struct range range;
		struct range ranges[0];
	};
};

static inline bool pgmap_has_memory_failure(struct dev_pagemap *pgmap)
{
	return pgmap->ops && pgmap->ops->memory_failure;
}

static inline struct vmem_altmap *pgmap_altmap(struct dev_pagemap *pgmap)
{
	if (pgmap->flags & PGMAP_ALTMAP_VALID)
		return &pgmap->altmap;
	return NULL;
}

#ifdef CONFIG_ZONE_DEVICE
extern spinlock_t zdm_lock;
extern struct list_head zdm_list;
struct zdm_context {
	struct list_head	list;
	struct dev_pagemap      *pgmap;
	struct zone             *zone;
	unsigned long           start_pfn;
	unsigned long           nr_pages;
	spinlock_t		lock;
	struct rcu_head		rcu;
};
int zdm_insert(struct dev_pagemap *pgmap, struct zone *zone,
	       unsigned long start_pfn, unsigned long nr_pages);
void zdm_delete(unsigned long start_pfn, unsigned long nr_pages);
struct zdm_context *zdm_lookup(unsigned long addr);
void zdm_reinit_struct_pages(struct zdm_context *zdm,
			     unsigned long page_pfn,
			     unsigned long start_pfn,
			     unsigned long end_pfn);
void zdm_init_struct_pages(struct zone *zone,
			   struct dev_pagemap *pgmap,
			   unsigned long start_pfn,
			   unsigned long end_pfn);
int zdm_ondemand_enable(struct zone *zone,
			unsigned long start_pfn,
			unsigned long size,
			struct dev_pagemap *pgmap);

void *memremap_pages(struct dev_pagemap *pgmap, int nid);
void memunmap_pages(struct dev_pagemap *pgmap);
void *devm_memremap_pages(struct device *dev, struct dev_pagemap *pgmap);
void devm_memunmap_pages(struct device *dev, struct dev_pagemap *pgmap);
struct dev_pagemap *get_dev_pagemap(unsigned long pfn,
		struct dev_pagemap *pgmap);
bool pgmap_pfn_valid(struct dev_pagemap *pgmap, unsigned long pfn);

unsigned long vmem_altmap_offset(struct vmem_altmap *altmap);
void vmem_altmap_free(struct vmem_altmap *altmap, unsigned long nr_pfns);
unsigned long memremap_compat_align(void);
#else
static inline void *devm_memremap_pages(struct device *dev,
		struct dev_pagemap *pgmap)
{
	/*
	 * Fail attempts to call devm_memremap_pages() without
	 * ZONE_DEVICE support enabled, this requires callers to fall
	 * back to plain devm_memremap() based on config
	 */
	WARN_ON_ONCE(1);
	return ERR_PTR(-ENXIO);
}

static inline void devm_memunmap_pages(struct device *dev,
		struct dev_pagemap *pgmap)
{
}

static inline struct dev_pagemap *get_dev_pagemap(unsigned long pfn,
		struct dev_pagemap *pgmap)
{
	return NULL;
}

static inline bool pgmap_pfn_valid(struct dev_pagemap *pgmap, unsigned long pfn)
{
	return false;
}

static inline unsigned long vmem_altmap_offset(struct vmem_altmap *altmap)
{
	return 0;
}

static inline void vmem_altmap_free(struct vmem_altmap *altmap,
		unsigned long nr_pfns)
{
}

/* when memremap_pages() is disabled all archs can remap a single page */
static inline unsigned long memremap_compat_align(void)
{
	return PAGE_SIZE;
}
#endif /* CONFIG_ZONE_DEVICE */

static inline void put_dev_pagemap(struct dev_pagemap *pgmap)
{
	if (pgmap)
		percpu_ref_put(pgmap->ref);
}

#endif /* _LINUX_MEMREMAP_H_ */
