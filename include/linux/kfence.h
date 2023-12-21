/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel Electric-Fence (KFENCE). Public interface for allocator and fault
 * handler integration. For more info see Documentation/dev-tools/kfence.rst.
 *
 * Copyright (C) 2020, Google LLC.
 */

#ifndef _LINUX_KFENCE_H
#define _LINUX_KFENCE_H

#include <linux/mm.h>
#include <linux/types.h>
#include <linux/static_key.h>
#include <linux/percpu-refcount.h>
#include <linux/workqueue.h>

struct kfence_pool_area {
	struct rb_node rb_node; /* binary tree linked to root */
	struct kfence_metadata *meta; /* metadata per area */
	char *addr; /* start kfence pool address */
	unsigned long pool_size; /* size of kfence pool of this area */
	unsigned long nr_objects; /* max object number of this area, 0 marked as zombie area */
	int node; /* the numa node this area belongs to */
	struct list_head list; /* ready to be added to kfence_pool_root */
	struct percpu_ref refcnt; /* count in use objects */
	struct work_struct work; /* use workqueue to free unused area */
	bool on_rb_tree; /* whether this kpa is on rb tree */
};

#ifdef CONFIG_KFENCE

#ifdef CONFIG_KFENCE_STATIC_KEYS
DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
#else
#include <linux/atomic.h>
extern atomic_t kfence_allocation_gate;
#endif
DECLARE_STATIC_KEY_FALSE(kfence_once_inited);
#define GFP_KFENCE_NOT_ALLOC ((GFP_ZONEMASK & ~__GFP_HIGHMEM) | __GFP_NOKFENCE | __GFP_THISNODE)
DECLARE_STATIC_KEY_TRUE(kfence_order0_page);

extern unsigned long kfence_num_objects;
extern char *__kfence_pool_early_init;

/**
 * is_kfence_address_area() - check if an address belongs to KFENCE pool in given area
 * @addr: address to check
 * @kpa: area to check
 *
 * Return: true or false depending on whether the address is within the KFENCE
 * object range in given area.
 *
 * This function is used when you already know the nearest leftside area.
 */
static __always_inline bool is_kfence_address_area(const void *addr,
						   const struct kfence_pool_area *kpa)
{
	return unlikely(kpa && (unsigned long)((char *)addr - kpa->addr) < kpa->pool_size);
}

/**
 * is_kfence_address() - check if an address belongs to KFENCE pool
 * @addr: address to check
 *
 * Return: true or false depending on whether the address is within the KFENCE
 * object range.
 *
 * KFENCE objects live in a separate page range and are not to be intermixed
 * with regular heap objects (e.g. KFENCE objects must never be added to the
 * allocator freelists). Failing to do so may and will result in heap
 * corruptions, therefore is_kfence_address() must be used to check whether
 * an object requires specific handling.
 *
 * Note: This function may be used in fast-paths, and is performance critical.
 * Future changes should take this into account; for instance, we want to avoid
 * introducing another load and therefore need to keep KFENCE_POOL_SIZE a
 * constant (until immediate patching support is added to the kernel).
 */
static __always_inline bool is_kfence_address(const void *addr)
{
#if defined(CONFIG_KASAN) || defined(CONFIG_DEBUG_KMEMLEAK)
	/*
	 * KASAN functions such as kasan_record_aux_stack(),
	 * kasan_poison_shadow(), or kasan_unpoison_shadow()
	 * may give an invalid kaddr (direct mapping kernel address).
	 * We must add a check here.
	 */
	return static_branch_unlikely(&kfence_once_inited) &&
		virt_addr_valid(addr) && PageKfence(virt_to_page(addr));
#else
	return static_branch_unlikely(&kfence_once_inited) && PageKfence(virt_to_page(addr));
#endif
}

/**
 * kfence_alloc_pool() - allocate the KFENCE pool via memblock
 */
void __init kfence_alloc_pool(void);

/**
 * kfence_init() - perform KFENCE initialization at boot time
 *
 * Requires that kfence_alloc_pool() was called before. This sets up the
 * allocation gate timer, and requires that workqueues are available.
 */
void __init kfence_init(void);

/**
 * update_kfence_booting_max() - analyse the max num_objects from cmdline
 *
 * Read the config from boot cmdline and limit kfence pool size.
 * This function is called by kfence itself (e.g., kfence_alloc_pool()), or,
 * by specific arch alloc (e.g., arm64_kfence_alloc_pool()).
 *
 * Return: 1 if kfence_num_objects is changed, otherwise 0.
 */
int __init update_kfence_booting_max(void);

/**
 * kfence_shutdown_cache() - handle shutdown_cache() for KFENCE objects
 * @s: cache being shut down
 *
 * Before shutting down a cache, one must ensure there are no remaining objects
 * allocated from it. Because KFENCE objects are not referenced from the cache
 * directly, we need to check them here.
 *
 * Note that shutdown_cache() is internal to SL*B, and kmem_cache_destroy() does
 * not return if allocated objects still exist: it prints an error message and
 * simply aborts destruction of a cache, leaking memory.
 *
 * If the only such objects are KFENCE objects, we will not leak the entire
 * cache, but instead try to provide more useful debug info by making allocated
 * objects "zombie allocations". Objects may then still be used or freed (which
 * is handled gracefully), but usage will result in showing KFENCE error reports
 * which include stack traces to the user of the object, the original allocation
 * site, and caller to shutdown_cache().
 */
void kfence_shutdown_cache(struct kmem_cache *s);

/*
 * Allocate a KFENCE object. Allocators must not call this function directly,
 * use kfence_alloc() or kfence_alloc_node() instead.
 */
void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags, int node);
struct page *__kfence_alloc_page(int node, gfp_t flags);

/**
 * kfence_alloc() - allocate a KFENCE object with a low probability
 * @s:     struct kmem_cache with object requirements
 * @size:  exact size of the object to allocate (can be less than @s->size
 *         e.g. for kmalloc caches)
 * @flags: GFP flags
 *
 * Return:
 * * NULL     - must proceed with allocating as usual,
 * * non-NULL - pointer to a KFENCE object.
 *
 * kfence_alloc() should be inserted into the heap allocation fast path,
 * allowing it to transparently return KFENCE-allocated objects with a low
 * probability using a static branch (the probability is controlled by the
 * kfence.sample_interval boot parameter).
 */
static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
#ifdef CONFIG_KFENCE_STATIC_KEYS
	if (static_branch_unlikely(&kfence_allocation_key))
#else
	if (unlikely(!atomic_read(&kfence_allocation_gate)))
#endif
		return __kfence_alloc(s, size, flags, NUMA_NO_NODE);
	return NULL;
}

/**
 * kfence_alloc_node() - allocate a KFENCE object with a low probability
 * @s:     struct kmem_cache with object requirements
 * @size:  exact size of the object to allocate (can be less than @s->size
 *         e.g. for kmalloc caches)
 * @flags: GFP flags
 * @node:  alloc from kfence pool on which node
 *
 * Return:
 * * NULL     - must proceed with allocating as usual,
 * * non-NULL - pointer to a KFENCE object.
 *
 * kfence_alloc_node() should be inserted into the heap allocation fast path,
 * allowing it to transparently return KFENCE-allocated objects with a low
 * probability using a static branch (the probability is controlled by the
 * kfence.sample_interval boot parameter).
 */
static __always_inline void *kfence_alloc_node(struct kmem_cache *s, size_t size, gfp_t flags,
					       int node)
{
#ifdef CONFIG_KFENCE_STATIC_KEYS
	if (static_branch_unlikely(&kfence_allocation_key))
#else
	if (unlikely(!atomic_read(&kfence_allocation_gate)))
#endif
		return __kfence_alloc(s, size, flags, node);
	return NULL;
}

/**
 * kfence_alloc_page() - allocate a KFENCE page with a low probability
 * @node:  preferred nid
 * @flags: GFP flags
 *
 * Return:
 * * NULL     - must proceed with allocating as usual,
 * * non-NULL - pointer to a KFENCE page.
 *
 * the order-0 page version of kfence_alloc().
 */
static __always_inline struct page *kfence_alloc_page(unsigned int order, int node, gfp_t flags)
{
#ifdef CONFIG_KFENCE_STATIC_KEYS
	if (static_branch_unlikely(&kfence_allocation_key) &&
	    static_branch_likely(&kfence_order0_page) && !order &&
	    !((flags & GFP_KFENCE_NOT_ALLOC) || (flags & GFP_USER) == GFP_USER))
#else
	if (unlikely(!atomic_read(&kfence_allocation_gate)) &&
	    static_branch_likely(&kfence_order0_page) && !order &&
	    !((flags & GFP_KFENCE_NOT_ALLOC) || (flags & GFP_USER) == GFP_USER))
#endif
		return __kfence_alloc_page(node, flags);
	return NULL;
}

/**
 * kfence_ksize() - get actual amount of memory allocated for a KFENCE object
 * @addr: pointer to a heap object
 *
 * Return:
 * * 0     - not a KFENCE object, must call __ksize() instead,
 * * non-0 - this many bytes can be accessed without causing a memory error.
 *
 * kfence_ksize() returns the number of bytes requested for a KFENCE object at
 * allocation time. This number may be less than the object size of the
 * corresponding struct kmem_cache.
 */
size_t kfence_ksize(const void *addr);

/**
 * kfence_object_start() - find the beginning of a KFENCE object
 * @addr: address within a KFENCE-allocated object
 *
 * Return: address of the beginning of the object.
 *
 * SL[AU]B-allocated objects are laid out within a page one by one, so it is
 * easy to calculate the beginning of an object given a pointer inside it and
 * the object size. The same is not true for KFENCE, which places a single
 * object at either end of the page. This helper function is used to find the
 * beginning of a KFENCE-allocated object.
 */
void *kfence_object_start(const void *addr);

/**
 * __kfence_free() - release a KFENCE heap object to KFENCE pool
 * @addr: object to be freed
 *
 * Requires: is_kfence_address(addr)
 *
 * Release a KFENCE object and mark it as freed.
 */
void __kfence_free(void *addr);
void __kfence_free_page(struct page *page, void *addr);

/**
 * kfence_free() - try to release an arbitrary heap object to KFENCE pool
 * @addr: object to be freed
 *
 * Return:
 * * false - object doesn't belong to KFENCE pool and was ignored,
 * * true  - object was released to KFENCE pool.
 *
 * Release a KFENCE object and mark it as freed. May be called on any object,
 * even non-KFENCE objects, to simplify integration of the hooks into the
 * allocator's free codepath. The allocator must check the return value to
 * determine if it was a KFENCE object or not.
 */
static __always_inline __must_check bool kfence_free(void *addr)
{
	if (!is_kfence_address(addr))
		return false;
	__kfence_free(addr);
	return true;
}

/**
 * kfence_free_page() - try to release a page to KFENCE pool
 * @page:  page to be freed
 *
 * Return:
 * * false - page doesn't belong to KFENCE pool and was ignored,
 * * true  - page was released to KFENCE pool.
 *
 * Release a KFENCE page and mark it as freed. May be called on any page,
 * even non-KFENCE page. The allocator must check the return value to
 * determine if it was a KFENCE object or not.
 */
static __always_inline __must_check bool kfence_free_page(struct page *page)
{
	void *addr;

	if (!static_branch_unlikely(&kfence_once_inited) || !PageKfence(page))
		return false;

	addr = page_to_virt(page);
	__kfence_free_page(page, addr);
	return true;
}

/**
 * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
 * @addr: faulting address
 * @is_write: is access a write
 * @regs: current struct pt_regs (can be NULL, but shows full stack trace)
 *
 * Return:
 * * false - address outside KFENCE pool,
 * * true  - page fault handled by KFENCE, no additional handling required.
 *
 * A page fault inside KFENCE pool indicates a memory error, such as an
 * out-of-bounds access, a use-after-free or an invalid memory access. In these
 * cases KFENCE prints an error message and marks the offending page as
 * present, so that the kernel can proceed.
 */
bool __must_check kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs);

#else /* CONFIG_KFENCE */

static inline bool is_kfence_address_area(const void *addr, const struct kfence_pool_area *kpa)
{
	return false;
}
static inline bool is_kfence_address(const void *addr) { return false; }
static inline void kfence_alloc_pool(void) { }
static inline void kfence_init(void) { }
static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
static inline void *kfence_alloc_node(struct kmem_cache *s, size_t size, gfp_t flags, int node)
{
	return NULL;
}
static inline struct page *kfence_alloc_page(unsigned int order, int node, gfp_t flags)
{
	return NULL;
}
static inline size_t kfence_ksize(const void *addr) { return 0; }
static inline void *kfence_object_start(const void *addr) { return NULL; }
static inline void __kfence_free(void *addr) { }
static inline bool __must_check kfence_free(void *addr) { return false; }
static inline bool __must_check kfence_free_page(struct page *page) { return false; }
static inline bool __must_check kfence_handle_page_fault(unsigned long addr, bool is_write,
							 struct pt_regs *regs)
{
	return false;
}

#endif

#endif /* _LINUX_KFENCE_H */
