// SPDX-License-Identifier: GPL-2.0
/*
 * This implements mechanism to reclaim the clean page cache and anonymous
 * memory. The reclaimed page cache could be migrated to low speed storage
 * like persistent memory, or dropped. The reclaimed anonymous memory should
 * be saved somewhere and the possible targets can be persistent memory, zSwap,
 * normal swap partition or file.
 *
 * Copyright Gavin Shan, Alibaba Inc 2019
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/jump_label.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/frontswap.h>
#include <linux/swapfile.h>
#include <linux/swapops.h>
#include <linux/kidled.h>
#include <linux/sysfs.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>

#include "internal.h"
#include "coldpgs.h"

#define DRIVER_VERSION	"2.5.0"
#define DRIVER_AUTHOR	"Gavin Shan and Jiang Zhong"
#define DRIVER_DESC	"Reclaim Cold Pages and Slab"

static struct reclaim_coldpgs_global_control global_control;

/*
 * The module uses various functions or variables, which aren't exported
 * yet. So we look for and use their symbols directly.
 */
static struct mem_cgroup *(*my_mem_cgroup_iter)(struct mem_cgroup *,
	struct mem_cgroup *, struct mem_cgroup_reclaim_cookie *);
static void (*my_mem_cgroup_iter_break)(struct mem_cgroup *,
	struct mem_cgroup *);
static long (*my_mem_cgroup_get_nr_swap_pages)(struct mem_cgroup *);
static int (*my_add_to_swap)(struct page *page);
static int (*my_try_to_free_swap)(struct page *);
static void (*my_end_swap_bio_write)(struct bio *);
static int (*my___swap_writepage)(struct page *, struct writeback_control *,
	bio_end_io_t);
static void (*my_lru_add_drain)(void);
static int (*my_split_huge_page_to_list)(struct page *, struct list_head *);
static int (*my_can_split_huge_page)(struct page *, int *);
static int (*my_try_to_unmap)(struct page *, enum ttu_flags);
static int (*my___remove_mapping)(struct address_space *, struct page *, bool,
					struct mem_cgroup *);
static bool (*my_mem_cgroup_swap_full)(struct page *);
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
static void (*my_try_to_unmap_flush_dirty)(void);
static void (*my_try_to_unmap_flush)(void);
#endif
static void (*my_putback_lru_page)(struct page *page);
static struct lruvec *(*my_mem_cgroup_page_lruvec)(struct page *page,
							struct pglist_data *pgdat);
static void (*my_workingset_age_nonresident)(struct lruvec *lruvec, unsigned long nr_pages);
static void (*my_mem_cgroup_update_lru_size)(struct lruvec *,
	enum lru_list, int, int);
static void (*my_mem_cgroup_uncharge)(struct page *);
static void (*my_mem_cgroup_uncharge_list)(struct list_head *);
static void (*my_free_unref_page_list)(struct list_head *);
static struct vm_area_struct *(*my_vma_interval_tree_iter_first)(
	struct rb_root_cached *, unsigned long, unsigned long);
static struct vm_area_struct *(*my_vma_interval_tree_iter_next)(
	struct vm_area_struct *, unsigned long, unsigned long);
static int (*my_cgroup_add_dfl_cftypes)(struct cgroup_subsys *,
	struct cftype *);
static int (*my_cgroup_add_legacy_cftypes)(struct cgroup_subsys *,
	struct cftype *);
static int (*my_cgroup_rm_cftypes)(struct cftype *);
static compound_page_dtor **my_compound_page_dtors;
static int *my_vm_swappiness;
static struct swap_info_struct **my_swap_info;
static struct static_key_false *my_frontswap_enabled_key;
static struct frontswap_ops **my_frontswap_ops;
static struct frontswap_ops *my_zswap_frontswap_ops;
static bool *my_frontswap_writethrough_enabled;
static bool *my_coldpgs_enabled;
#ifdef CONFIG_DEBUG_FS
static u64 *my_frontswap_succ_stores;
static u64 *my_frontswap_failed_stores;
#endif
static struct list_head *my_shrinker_list;
static struct rw_semaphore *my_shrinker_rwsem;
static struct idr *my_shrinker_idr;
static struct mem_cgroup **my_root_mem_cgroup;
static int *my_shrinker_nr_max;
static void (*my_css_task_iter_start)(struct cgroup_subsys_state *,
	unsigned int, struct css_task_iter *);
static struct task_struct *(*my_css_task_iter_next)(struct css_task_iter *);
static void (*my_css_task_iter_end)(struct css_task_iter *);
#if CONFIG_PGTABLE_LEVELS > 4
#ifdef CONFIG_X86_5LEVEL
static unsigned int *my___pgtable_l5_enabled;
#endif
#endif
static void (*my_pgd_clear_bad)(pgd_t *);
#if CONFIG_PGTABLE_LEVELS > 4
static void (*my_p4d_clear_bad)(p4d_t *);
#else
#define my_p4d_clear_bad(p4d) do { } while (0)
#endif
#ifndef __PAGETABLE_PUD_FOLDED
static void (*my_pud_clear_bad)(pud_t *);
#else
#define my_pud_clear_bad(p4d) do { } while (0)
#endif
static void (*my_pmd_clear_bad)(pmd_t *);
static pmd_t *(*my_mm_find_pmd)(struct mm_struct *, unsigned long);
static int (*my_do_swap_page)(struct vm_fault *);
static unsigned long (*my_node_page_state)(struct pglist_data *pgdat,
				enum node_stat_item item);
static void (*my___mod_lruvec_state)(struct lruvec *,
		enum node_stat_item, int val);

static inline void enable_coldpgs(void)
{
	*my_coldpgs_enabled = true;
}

static inline void disable_coldpgs(void)
{
	*my_coldpgs_enabled = false;
}

static unsigned long my_lruvec_page_state_local(struct lruvec *lruvec,
							enum node_stat_item idx)
{
	struct mem_cgroup_per_node *pn;
	long x = 0;
	int cpu;

	if (mem_cgroup_disabled())
		return my_node_page_state(lruvec_pgdat(lruvec), idx);

	pn = container_of(lruvec, struct mem_cgroup_per_node, lruvec);
	for_each_possible_cpu(cpu)
		x += per_cpu(pn->lruvec_stat_local->count[idx], cpu);
#ifdef CONFIG_SMP
	if (x < 0)
		x = 0;
#endif
	return x;
}

static struct lruvec *my_mem_cgroup_lruvec(struct mem_cgroup *memcg,
						struct pglist_data *pgdat)
{
	struct mem_cgroup_per_node *mz;
	struct lruvec *lruvec;

	if (mem_cgroup_disabled()) {
		lruvec = &pgdat->__lruvec;
		goto out;
	}

	if (!memcg)
		memcg = *my_root_mem_cgroup;

	mz = mem_cgroup_nodeinfo(memcg, pgdat->node_id);
	lruvec = &mz->lruvec;
out:
	/*
	 * Since a node can be onlined after the mem_cgroup was created,
	 * we have to be prepared to initialize lruvec->pgdat here;
	 * and if offlined then reonlined, we need to reinitialize it.
	 */
	if (unlikely(lruvec->pgdat != pgdat))
		lruvec->pgdat = pgdat;
	return lruvec;
}

static void my__update_lru_size(struct lruvec *lruvec,
				enum lru_list lru, enum zone_type zid,
				int nr_pages)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	my___mod_lruvec_state(lruvec, NR_LRU_BASE + lru, nr_pages);
	__mod_zone_page_state(&pgdat->node_zones[zid],
				NR_ZONE_LRU_BASE + lru, nr_pages);
}

#define LRU_SLAB			(NR_LRU_LISTS + 1)
#define SHRINKER_REGISTERING		(((struct shrinker *)~0UL))

static inline void reclaim_coldpgs_update_stats(struct mem_cgroup *memcg,
						unsigned int index,
						unsigned long size)
{
	if (index >= RECLAIM_COLDPGS_STAT_MAX)
		return;

	__this_cpu_add(memcg->coldpgs_stats->counts[index], size);
}

static inline bool reclaim_coldpgs_has_mode(
			struct reclaim_coldpgs_filter *filter,
			unsigned int mode)
{
	unsigned int flag = (1 << mode);

	return !!(filter->mode & flag);
}

static inline bool reclaim_coldpgs_has_flag(
			struct reclaim_coldpgs_filter *filter,
			unsigned int flag)
{
	return !!(filter->flags & flag);
}

static inline int reclaim_coldpgs_memcg_swappiness(struct mem_cgroup *memcg)
{
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys))
		return *my_vm_swappiness;

	if (mem_cgroup_disabled() || !memcg->css.parent)
		return *my_vm_swappiness;

	return memcg->swappiness;
}

static bool page_is_exec(struct address_space *mapping,
			 struct page *page)
{
	struct vm_area_struct *vma;
	pgoff_t pgoff;

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_rwsem.
	 */
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	if (!page_mapped(page))
		return false;

	/*
	 * We don't check if the address in vma again like page_vma_mapped_walk.
	 * or page_check_address_transhuge, since we don't unmap for the page
	 */
	pgoff = page_to_index(page);
	i_mmap_lock_read(mapping);

	vma = my_vma_interval_tree_iter_first(&mapping->i_mmap, pgoff, pgoff);
	while (vma) {
		if (vma->vm_flags & VM_EXEC) {
			i_mmap_unlock_read(mapping);
			return true;
		}

		vma = my_vma_interval_tree_iter_next(vma, pgoff, pgoff);
	}

	i_mmap_unlock_read(mapping);

	return false;
}

/*
 * The function is called for twice to one specific page, isolation and
 * reclaiming phrase separately. During the period of isolation, the page's
 * age should be checked, but that's needn't validated again in reclaiming
 * phrase. @validate_age is used to distinguish the cases.
 */
static inline bool page_is_reclaimable(struct mem_cgroup *memcg,
			struct reclaim_coldpgs_filter *filter,
			pg_data_t *pgdat, struct page *page,
			bool validate_age)
{
	struct address_space *mapping;
	struct mem_cgroup *m = READ_ONCE(page->mem_cgroup);
	int age;

	if (m != memcg)
		return false;

	/*
	 * The page should be in LRU list in isolation phrase, but
	 * it should have been removed from LRU list in reclaim
	 * phrase.
	 */
	if (validate_age && !PageLRU(page))
		return false;

	if (page_is_file_lru(page)) {
		mapping = page_mapping(page);

		/* Bail if we're not allowed to reclaim */
		if (!reclaim_coldpgs_has_mode(filter, RECLAIM_MODE_PGCACHE_OUT))
			return false;

		/* Bail if the page isn't clean page cache */
		if (PageDirty(page) ||
		    PageWriteback(page))
			return false;

		/*
		 * The lazy free'd anonymous pages can be put to the inactive
		 * file LRU. Those pages don't have valid address space and
		 * should be marked as anonymous pages. For the page cache,
		 * it should have valid address space, but we bail if the
		 * address space isn't a evictable one.
		 */
		if (!mapping) {
			if (!PageAnon(page))
				return false;
		} else {
			if (page->mapping != mapping ||
			    mapping_unevictable(mapping))
				return false;
		}

		/*
		 * Bail if the pagecache has execution mode only when
		 * we needn't to validate the page's age.
		 */
		if (!validate_age &&
		    mapping       &&
		    page_is_exec(mapping, page))
			return false;
	} else {
		/* Bail if we're not allowed to reclaim */
		if (!reclaim_coldpgs_has_mode(filter, RECLAIM_MODE_ANON_OUT))
			return false;

		/* Bail if the anonymous page isn't backed by swap */
		if (!PageSwapBacked(page))
			return false;

		/* Bail if the anonymous page is being written back */
		if (PageWriteback(page))
			return false;

		/* Bail if there is no enough swap space */
		if (my_mem_cgroup_get_nr_swap_pages(memcg) <
		    thp_nr_pages(page))
			return false;
	}

	/*
	 * Bail on mlock'ed or unevictable page if we're not
	 * allowed to do so.
	 */
	if (PageUnevictable(page)) {
		if (!(filter->flags & FLAG_IGNORE_MLOCK))
			return false;
		else if (!PageMlocked(page))
			return false;
	}

	/*
	 * We need to validate the page's age if @threshold is bigger
	 * than 0. Otherwise, we're rechecking if the page is eligible
	 * for reclaim and no need to validate the page's age under the
	 * circumstance.
	 */
	if (validate_age) {
		age = kidled_get_page_age(pgdat, page_to_pfn(page));
		if (age < filter->threshold)
			return false;
	}

	return true;
}

static unsigned long isolate_coldpgs_from_lru(struct mem_cgroup *memcg,
				struct reclaim_coldpgs_filter *filter,
				pg_data_t *pgdat, struct lruvec *lruvec,
				enum lru_list lru, unsigned long nr_to_reclaim,
				struct list_head *dst)
{
	struct list_head *src = &lruvec->lists[lru];
	struct page *page;
	unsigned long nr_pages, nr_taken = 0;
	unsigned long scan, size = my_lruvec_page_state_local(lruvec, NR_LRU_BASE + lru);
	unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0, };
	int zid, batch = 0;

	spin_lock_irq(&lruvec->lru_lock);

	for (scan = 0;
	     !list_empty(src) && scan < size && nr_taken < nr_to_reclaim;
	     scan++) {
		page = lru_to_page(src);

		/*
		 * The pages in the LRU list are visited in reverse order.
		 * During the iteration, the pages that aren't eligible for
		 * reclaim are moved to the list head, so that they can be
		 * skipped safely. The eligible pages are moved to separate
		 * (local) list.
		 */
		if (!page_is_reclaimable(memcg, filter, pgdat, page, true) ||
		    !get_page_unless_zero(page)) {
			list_move(&page->lru, src);
			goto isolate_fail;
		}

		if (TestClearPageLRU(page)) {
			nr_pages = thp_nr_pages(page);
			nr_zone_taken[page_zonenum(page)] += nr_pages;
			nr_taken += nr_pages;
			list_move(&page->lru, dst);
		} else {
			/*
			 * This page may in other isolation path,
			 * but we still hold lru_lock.
			 */
			put_page(page);
			list_move(&page->lru, src);
		}

isolate_fail:
		/*
		 * To schedule out a moment when reaching filter->batch. This
		 * scheme mainly to avoid hold lru_lock long time if a huge
		 * nr_to_reclaim here.
		 *
		 * This mechanism can be disabled when zero limit is provided.
		 */
		if (filter->batch && ++batch >= filter->batch) {
			spin_unlock_irq(&lruvec->lru_lock);
			cond_resched();
			spin_lock_irq(&lruvec->lru_lock);

			batch = 0;
		}
	}

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		my__update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
		my_mem_cgroup_update_lru_size(lruvec, lru,
				zid, -nr_zone_taken[zid]);
	}

	spin_unlock_irq(&lruvec->lru_lock);

	return nr_taken;
}

static int swapout_page_to_zram(struct reclaim_coldpgs_filter *filter,
				struct page *page,
				int age)
{
	swp_entry_t entry = { .val = page_private(page), };
	int type = swp_type(entry);
	struct swap_info_struct *sis = my_swap_info[type];
	pgoff_t offset = swp_offset(entry);
	struct frontswap_ops *ops;
#ifdef CONFIG_DEBUG_FS
	u64 *stats;
#endif
	int ret;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(sis == NULL);

	/* Bail if frontswap is disabled */
	if (!atomic_read(&my_frontswap_enabled_key->key.enabled))
		return -ENXIO;

	/* Bail if zswap isn't preferred or the page isn't cold enough */
	if (!filter->thresholds[THRESHOLD_NONROT] ||
	    age > filter->thresholds[THRESHOLD_NONROT])
		return -ERANGE;

	/*
	 * If it's duplicated, we must remove the old page first. We can't
	 * leave the old page no matter if the store of the new page succeeds
	 * or fails, and we can't rely on the new page replacing the old page
	 * as we may not store to the same implementation that contains the
	 * old page.
	 */
	if (__frontswap_test(sis, offset)) {
		clear_bit(offset, sis->frontswap_map);
		atomic_dec(&sis->frontswap_pages);

		for_each_frontswap_ops(ops)
			ops->invalidate_page(type, offset);
	}

	/*
	 * Try swap the page by zswap. The page will be written back
	 * to disk if that fails.
	 */
	ret = my_zswap_frontswap_ops->store(type, offset, page);
	if (!ret) {
		set_bit(offset, sis->frontswap_map);
		atomic_inc(&sis->frontswap_pages);
	}

	/* Update frontswap statistics */
#ifdef CONFIG_DEBUG_FS
	stats = !ret ? my_frontswap_succ_stores : my_frontswap_failed_stores;
	(*stats)++;
#endif

	/*
	 * The page will be written back to disk as well if the
	 * write-through mode has been enabled.
	 */
	if (*my_frontswap_writethrough_enabled)
		ret = -EAGAIN;

	return ret;
}

static int swapout_page(struct reclaim_coldpgs_filter *filter,
			struct page *page, int age,
			struct writeback_control *wbc,
			bool *use_zswap)
{
	if (my_try_to_free_swap(page)) {
		unlock_page(page);
		return 0;
	}

	if (!swapout_page_to_zram(filter, page, age)) {
		set_page_writeback(page);
		unlock_page(page);
		end_page_writeback(page);
		if (use_zswap)
			*use_zswap = true;

		return 0;
	}

	return my___swap_writepage(page, wbc, my_end_swap_bio_write);
}

enum {
	PAGE_KEEP,	/* failed to write page out, page is locked */
	PAGE_ACTIVATE,	/* move page to the active list, page is locked */
	PAGE_SUCCESS,	/* page was sent to disk, page is unlocked */
	PAGE_CLEAN,	/* page is clean and locked */
};

static int pageout(struct mem_cgroup *memcg,
		   struct reclaim_coldpgs_filter *filter,
		   struct address_space *mapping,
		   struct page *page, int *nr_pages_ptr,
		   int age)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
		.nr_to_write = SWAP_CLUSTER_MAX,
		.range_start = 0,
		.range_end = LLONG_MAX,
		.for_reclaim = 1,
	};
	bool use_zswap = false;
	int radix_pins = PageTransHuge(page) && PageSwapCache(page) ?
			 HPAGE_PMD_NR : 1;
	int nr_pages = thp_nr_pages(page);
	int ret;

	/*
	 * A freeable page cache page is referenced only by the caller
	 * that isolated the page, the page cache radix tree and
	 * optional buffer heads at page->private.
	 */
	if (page_count(page) - page_has_private(page) != (radix_pins + 1))
		return PAGE_KEEP;

	/*
	 * If the page is dirty, only perform writeback if that write
	 * will be non-blocking.  To prevent this allocation from being
	 * stalled by pagecache activity.  But note that there may be
	 * stalls if we need to run get_block().  We could test
	 * PagePrivate for that.
	 *
	 * If this process is currently in __generic_file_write_iter() against
	 * this page's queue, we can perform writeback even if that
	 * will block.
	 *
	 * If the page is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	 *
	 * Some data journaling orphaned pages can have NULL address
	 * space, but it's obvious out of range to the anonymous pages.
	 * However, it's not harmful to check because it's useful when
	 * we start to reclaim dirty pagecache in future.
	 */
	if (!mapping) {
		if (page_has_private(page)) {
			if (try_to_free_buffers(page)) {
				ClearPageDirty(page);
				return PAGE_CLEAN;
			}
		}

		return PAGE_KEEP;
	}

	/*
	 * The anonymous pages that are mapped in shared mode is put to the
	 * anonymous lists, but associated with a special file from shmemfs
	 * or ramfs. For these shared anonymous pages, we didn't allocate
	 * slots in the swap pagecache and the writepage() of the address
	 * space does so.
	 */
	if (clear_page_dirty_for_io(page)) {
		SetPageReclaim(page);
		if (PageAnon(page)) {
			ret = swapout_page(filter, page, age,
					   &wbc, &use_zswap);
		} else {
			ret = mapping->a_ops->writepage(page, &wbc);
		}

		if (ret < 0) {
			lock_page(page);
			if (page_mapping(page) == mapping)
				mapping_set_error(mapping, ret);
			unlock_page(page);
		}

		if (ret == AOP_WRITEPAGE_ACTIVATE) {
			ClearPageReclaim(page);
			return PAGE_ACTIVATE;
		}

		if (!PageWriteback(page))
			ClearPageReclaim(page);

		/* Update statistics */
		if (nr_pages_ptr)
			*nr_pages_ptr = nr_pages;

		if (use_zswap) {
			reclaim_coldpgs_update_stats(memcg,
				RECLAIM_COLDPGS_STAT_ANON_OUT_ZSWAP,
				nr_pages << PAGE_SHIFT);
		} else {
			reclaim_coldpgs_update_stats(memcg,
				RECLAIM_COLDPGS_STAT_ANON_OUT_SWAP,
				nr_pages << PAGE_SHIFT);
		}

		return PAGE_SUCCESS;
	}

	return PAGE_CLEAN;
}

static void my_add_page_to_lru_list(struct page *page,
					struct lruvec *lruvec, enum lru_list lru)
{
	int nr_pages = thp_nr_pages(page);
	int zid = page_zonenum(page);

	my__update_lru_size(lruvec, lru, zid, nr_pages);
	my_mem_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
	list_add(&page->lru, &lruvec->lists[lru]);
}

static void my_del_page_from_lru_list(struct page *page,
					struct lruvec *lruvec, enum lru_list lru)
{
	int nr_pages = thp_nr_pages(page);
	int zid = page_zonenum(page);

	list_del(&page->lru);
	my__update_lru_size(lruvec, lru, zid, -nr_pages);
	my_mem_cgroup_update_lru_size(lruvec, lru, zid, -nr_pages);
}

static void my_putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
	LIST_HEAD(pages_to_free);
	compound_page_dtor *dtor;

	/*
	 * Put back any unfreeable pages.
	 */
	while (!list_empty(page_list)) {
		struct page *page = lru_to_page(page_list);
		int lru;

		VM_BUG_ON_PAGE(PageLRU(page), page);
		list_del(&page->lru);
		if (unlikely(!page_evictable(page))) {
			spin_unlock_irq(&lruvec->lru_lock);
			my_putback_lru_page(page);
			spin_lock_irq(&lruvec->lru_lock);
			continue;
		}

		lruvec = my_mem_cgroup_page_lruvec(page, pgdat);

		SetPageLRU(page);
		lru = page_lru(page);
		my_add_page_to_lru_list(page, lruvec, lru);

		if (put_page_testzero(page)) {
			__ClearPageLRU(page);
			__ClearPageActive(page);
			my_del_page_from_lru_list(page, lruvec, lru);

			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&lruvec->lru_lock);
				dtor = my_compound_page_dtors[page[1].compound_dtor];
				(*dtor)(page);
				spin_lock_irq(&lruvec->lru_lock);
			} else
				list_add(&page->lru, &pages_to_free);
		} else {
			if (PageActive(page))
				my_workingset_age_nonresident(lruvec, thp_nr_pages(page));
		}
	}

	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	list_splice(&pages_to_free, page_list);
}

static unsigned long reclaim_coldpgs_from_list(struct mem_cgroup *memcg,
				struct reclaim_coldpgs_filter *filter,
				pg_data_t *pgdat, struct lruvec *lruvec,
				enum lru_list lru, struct list_head *list)
{
	struct page *page;
	struct address_space *mapping;
	enum ttu_flags flags = (filter->flags & FLAG_IGNORE_MLOCK) &&
		(lru == LRU_UNEVICTABLE) ?
		(TTU_BATCH_FLUSH | TTU_IGNORE_MLOCK) : TTU_BATCH_FLUSH;
	LIST_HEAD(keep_pages); LIST_HEAD(free_pages);
	enum compound_dtor_id dtor_id;
	compound_page_dtor *dtor;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_pagecache_dropped = 0;
	bool is_pagecache;
	int age, nr_pages, batch, ret;

	while (!list_empty(list)) {
		cond_resched();

		page = lru_to_page(list);
		list_del(&page->lru);
		if (!trylock_page(page))
			goto keep;

		nr_pages = thp_nr_pages(page);
		is_pagecache = page_is_file_lru(page) ? true : false;
		mapping = page_mapping(page);
		age = kidled_get_page_age(pgdat, page_to_pfn(page));
		if (age < 0)
			goto keep_unlocked;

		if (!page_is_reclaimable(memcg, filter, pgdat, page, false))
			goto keep_unlocked;

		if (PageAnon(page) && PageSwapBacked(page)) {
			if (!PageSwapCache(page)) {
				if (PageTransHuge(page)) {
					if (!my_can_split_huge_page(page, NULL))
						goto keep_unlocked;

					if (!compound_mapcount(page) &&
					    my_split_huge_page_to_list(page,
								       list))
						goto keep_unlocked;
				}

				if (!my_add_to_swap(page)) {
					if (!PageTransHuge(page))
						goto keep_unlocked;

					if (my_split_huge_page_to_list(page,
								       list))
						goto keep_unlocked;

					if (!my_add_to_swap(page))
						goto keep_unlocked;
				}

				/* Update address space */
				mapping = page_mapping(page);
			}
		} else if (PageTransHuge(page)) {
			if (my_split_huge_page_to_list(page, list))
				goto keep_unlocked;
		}

		/*
		 * The compound page might have been split up, we need
		 * update @nr_pages accordingly.
		 */
		if (!PageTransHuge(page))
			nr_pages = 1;

		if (page_mapped(page)) {
			if (PageTransHuge(page)) {
				ret = my_try_to_unmap(page,
						(flags | TTU_SPLIT_HUGE_PMD));
			} else {
				ret = my_try_to_unmap(page, flags);
			}

			if (!ret)
				goto keep_unlocked;
		}

		if (PageDirty(page)) {
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
			my_try_to_unmap_flush_dirty();
#endif
			ret = pageout(memcg, filter, mapping, page,
				      &nr_pages, age);
			switch (ret) {
			case PAGE_KEEP:
				goto keep_unlocked;
			case PAGE_ACTIVATE:
				goto activate_unlocked;
			case PAGE_SUCCESS:
				/* Wait until the writeback is completed */
				wait_on_page_writeback(page);

				/*
				 * A synchronous write - probably a ramdisk.
				 * Go ahead and try to reclaim the page.
				 */
				if (!trylock_page(page))
					goto keep;

				if (PageDirty(page) || PageWriteback(page))
					goto keep_unlocked;
				mapping = page_mapping(page);
			case PAGE_CLEAN:
				;
			}
		}

		if (page_has_private(page)) {
			if (!try_to_release_page(page, 0))
				goto keep_unlocked;

			if (!mapping && page_count(page) == 1) {
				unlock_page(page);
				if (put_page_testzero(page)) {
					__ClearPageUnevictable(page);
					goto free_it;
				}

				nr_reclaimed += nr_pages;
				continue;
			}
		}

		/* Handle the lazy free'd pages */
		if (PageAnon(page) && !PageSwapBacked(page)) {
			/* Follow __remove_mapping() for reference */
			if (atomic_cmpxchg(&page->_refcount, 1, 0) != 1)
				goto keep_unlocked;

			if (PageDirty(page)) {
				atomic_set_release(&page->_refcount, 1);
				goto keep_unlocked;
			}
		} else if (!mapping ||
			   !my___remove_mapping(mapping, page, true, memcg)) {
			goto keep_unlocked;
		}

		/*
		 * There shouldn't be anyone referring the page. It's safe
		 * to clear the unevictable flag, to avoid complaints spew
		 * out on freeing the page.
		 */
		unlock_page(page);
		__ClearPageUnevictable(page);
		__ClearPageActive(page);

free_it:
		if (unlikely(PageTransHuge(page))) {
			my_mem_cgroup_uncharge(page);

			dtor_id = page[1].compound_dtor;
			VM_BUG_ON(dtor_id >= NR_COMPOUND_DTORS);
			dtor = my_compound_page_dtors[dtor_id];
			(*dtor)(page);
		} else {
			list_add(&page->lru, &free_pages);
		}

		nr_reclaimed += nr_pages;
		kidled_mem_cgroup_move_stats(memcg, NULL, page, nr_pages << PAGE_SHIFT);
		if (is_pagecache)
			nr_pagecache_dropped += nr_pages;

		continue;

activate_unlocked:
		/* Not a candidate for swapping, so reclaim swap space. */
		if (PageSwapCache(page) &&
		    (my_mem_cgroup_swap_full(page) || PageMlocked(page)))
			my_try_to_free_swap(page);
		if (!PageMlocked(page))
			SetPageActive(page);
keep_unlocked:
		unlock_page(page);
keep:
		list_add(&page->lru, &keep_pages);
	}

	/* Update page cache reclaim statistics */
	reclaim_coldpgs_update_stats(memcg,
		RECLAIM_COLDPGS_STAT_PCACHE_OUT_DROP,
		nr_pagecache_dropped << PAGE_SHIFT);

	/* Free pages that are eligible for releasing */
	my_mem_cgroup_uncharge_list(&free_pages);
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	my_try_to_unmap_flush();
#endif

	if (filter->batch) {
		/* Free pages in batch */
		LIST_HEAD(batch_free_pages);

		batch = 0;

		while (!list_empty(&free_pages)) {
			page = lru_to_page(&free_pages);
			list_move(&page->lru, &batch_free_pages);

			if (++batch >= filter->batch) {
				my_free_unref_page_list(&batch_free_pages);

				cond_resched();
				batch = 0;
				INIT_LIST_HEAD(&batch_free_pages);
			}
		}

		/* Don't forget the remaining pages */
		if (!list_empty(&batch_free_pages))
			my_free_unref_page_list(&batch_free_pages);
	} else {
		/* Free pages in one shot */
		my_free_unref_page_list(&free_pages);
	}

	/* Put all pages back to the list */
	list_splice(&keep_pages, list);

	/*
	 * The pages that can't be released will be chained up to the
	 * corresponding LRU list. The system might not survive if the
	 * node's LRU lock is taken with interrupt disabled for long
	 * time, so we release the pages in batch mode.
	 */
	batch = 0;
	INIT_LIST_HEAD(&free_pages);
	while (!list_empty(list)) {
		page = lru_to_page(list);
		list_move(&page->lru, &free_pages);

		if (filter->batch && ++batch >= filter->batch) {
			spin_lock_irq(&lruvec->lru_lock);
			my_putback_inactive_pages(lruvec, &free_pages);
			spin_unlock_irq(&lruvec->lru_lock);

			my_mem_cgroup_uncharge_list(&free_pages);
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
			my_try_to_unmap_flush();
#endif
			my_free_unref_page_list(&free_pages);

			cond_resched();
			batch = 0;
			INIT_LIST_HEAD(&free_pages);
		}
	}

	/* Release the remaining pages */
	if (!list_empty(&free_pages)) {
		spin_lock_irq(&lruvec->lru_lock);
		my_putback_inactive_pages(lruvec, &free_pages);
		spin_unlock_irq(&lruvec->lru_lock);

		my_mem_cgroup_uncharge_list(&free_pages);
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
		my_try_to_unmap_flush();
#endif
		my_free_unref_page_list(&free_pages);
	}

	return nr_reclaimed;
}

static unsigned long reclaim_coldpgs_from_lru(struct mem_cgroup *memcg,
				struct reclaim_coldpgs_filter *filter,
				pg_data_t *pgdat, struct lruvec *lruvec,
				enum lru_list lru, unsigned long nr_to_reclaim)
{
	unsigned long nr_isolated;
	LIST_HEAD(list);

	my_lru_add_drain();

	nr_isolated = isolate_coldpgs_from_lru(memcg, filter, pgdat,
				lruvec, lru, nr_to_reclaim, &list);
	if (!nr_isolated)
		return 0;

	return reclaim_coldpgs_from_list(memcg, filter, pgdat, lruvec, lru,
					 &list);
}

#define SHRINK_BATCH 128

static unsigned long reclaim_coldslab_from_shrinker(struct shrinker *shrinker,
						    struct shrink_control *sc,
						    unsigned long nr_to_reclaim)
{
	unsigned long batch_size = shrinker->batch ?: SHRINK_BATCH;
	unsigned long freeable;
	unsigned long nr_reclaimed = 0;

	if (!shrinker->reap_objects)
		return SHRINK_STOP;

	freeable = shrinker->count_objects(shrinker, sc);
	if (freeable == 0 || freeable == SHRINK_EMPTY)
		return nr_reclaimed;

	while (freeable > 0) {
		unsigned long ret;
		unsigned long nr_scanned = min(freeable, batch_size);

		sc->nr_to_scan = nr_scanned;
		ret =  shrinker->reap_objects(shrinker, sc);
		if (ret == SHRINK_STOP)
			break;
		nr_reclaimed += ret;
		if (nr_reclaimed >= nr_to_reclaim)
			break;
		freeable -= nr_scanned;
		cond_resched();
	}

	return nr_reclaimed;
}

static unsigned long
reclaim_coldslab_from_memcg_lru(struct shrink_control *sc,
				unsigned long nr_to_reclaim)
{
	unsigned long nr_reclaimed = 0;
	struct memcg_shrinker_map *map;
	struct mem_cgroup *memcg = sc->memcg;
	int i;

	if (!mem_cgroup_online(memcg))
		return nr_reclaimed;

	if (!down_read_trylock(my_shrinker_rwsem))
		return nr_reclaimed;

	map = rcu_dereference_protected(memcg->nodeinfo[sc->nid]->shrinker_map,
					true);
	if (unlikely(map))
		goto out;
	for_each_set_bit(i, map->map, *my_shrinker_nr_max) {
		struct shrinker *shrinker;
		unsigned long ret;

		shrinker = idr_find(my_shrinker_idr, i);
		if (unlikely(!shrinker || shrinker == SHRINKER_REGISTERING)) {
			if (!shrinker)
				clear_bit(i, map->map);
			continue;
		}

		ret = reclaim_coldslab_from_shrinker(shrinker, sc,
						     nr_to_reclaim);
		if (ret == SHRINK_STOP)
			continue;
		nr_reclaimed += ret;
		if (nr_reclaimed >= nr_to_reclaim)
			break;
		if (rwsem_is_contended(my_shrinker_rwsem))
			break;
	}
out:
	up_read(my_shrinker_rwsem);
	return nr_reclaimed;
}

static unsigned long reclaim_coldslab_from_lru(struct mem_cgroup *memcg,
					       int node, unsigned int threshold,
					       unsigned long nr_to_reclaim)
{
	struct shrinker *shrinker;
	unsigned long nr_reclaimed = 0;
	struct shrink_control sc = {
		.gfp_mask = GFP_KERNEL,
		.nid = node,
		.memcg = memcg,
		.threshold = threshold,
	};

	if (!mem_cgroup_disabled() && memcg != *my_root_mem_cgroup)
		return reclaim_coldslab_from_memcg_lru(&sc, nr_to_reclaim);

	if (!down_read_trylock(my_shrinker_rwsem))
		goto out;
	list_for_each_entry(shrinker, my_shrinker_list, list) {
		unsigned long ret;

		ret = reclaim_coldslab_from_shrinker(shrinker, &sc,
						     nr_to_reclaim);
		if (ret == SHRINK_STOP)
			continue;
		nr_reclaimed += ret;
		if (nr_reclaimed >= nr_to_reclaim)
			break;
		if (rwsem_is_contended(my_shrinker_rwsem))
			break;
	}
	up_read(my_shrinker_rwsem);
out:
	return nr_reclaimed;
}

static void reclaim_coldpgs_from_memcg(struct mem_cgroup *memcg,
				       struct reclaim_coldpgs_filter *memcg_orig)
{
	pg_data_t *pgdat;
	struct lruvec *lruvec;
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	struct reclaim_coldpgs_filter memcg_filter;
	struct reclaim_coldpgs_filter *filter = &memcg_filter;
	unsigned long bitmap;
	unsigned long nr_reclaimed = 0;
	int nid, lru;

	memcpy(filter, memcg_orig, sizeof(struct reclaim_coldpgs_filter));
	/*
	 * Filter out the useless mode and flags.
	 */
	filter->mode &= FLAG_MODE(control->flags);
	filter->flags &= FLAG_MLOCK(control->flags);

	/*
	 * Figure out the eligible LRUs. Here we have a bitmap to track the
	 * eligible LRUs, to have thing a bit easier. Note that the pages
	 * resident in the unevictable list can't be reclaimed until the
	 * ignored mlock flag is globablly set.
	 */
	bitmap_zero(&bitmap, BITS_PER_LONG);
	if (reclaim_coldpgs_has_mode(filter, RECLAIM_MODE_PGCACHE_OUT)) {
		bitmap_set(&bitmap, LRU_INACTIVE_FILE, 1);
		bitmap_set(&bitmap, LRU_ACTIVE_FILE, 1);
	}

	/*
	 * When no available swap space, the swapout won't be issued.
	 */
	if (reclaim_coldpgs_has_mode(filter, RECLAIM_MODE_ANON_OUT) &&
	    my_mem_cgroup_get_nr_swap_pages(memcg) > 0) {
		bitmap_set(&bitmap, LRU_INACTIVE_ANON, 1);
		bitmap_set(&bitmap, LRU_ACTIVE_ANON, 1);
	}

	/*
	 * It's pointless to scan the child memcg when memcg_kmem is diabled.
	 */
	if (reclaim_coldpgs_has_mode(filter, RECLAIM_MODE_SLAB)) {
		if (memcg_kmem_enabled())
			bitmap_set(&bitmap, LRU_SLAB, 1);
		else if (memcg == *my_root_mem_cgroup)
			bitmap_set(&bitmap, LRU_SLAB, 1);
	}

	/*
	 * It's pointless to scan the pages in unevictable LRU list without
	 * reclaiming them. The pages in the unevictable LRU list won't be
	 * iterated until the valid reclaim mode has been given.
	 */
	if (!bitmap_empty(&bitmap, BITS_PER_LONG) &&
	    reclaim_coldpgs_has_flag(filter, FLAG_IGNORE_MLOCK))
		bitmap_set(&bitmap, LRU_UNEVICTABLE, 1);

	/* Reclaim cold memory from LRU list */
	for_each_node_state(nid, N_MEMORY) {
		pgdat = NODE_DATA(nid);
		lruvec = my_mem_cgroup_lruvec(memcg, pgdat);

		for (lru = find_first_bit(&bitmap, BITS_PER_LONG);
		     lru < NR_LRU_LISTS && nr_reclaimed < filter->size;
		     lru = find_next_bit(&bitmap, BITS_PER_LONG, (lru + 1))) {
			unsigned long reclaim, nr_page_reclaimed;

			/*
			 * User specify the size in bytes to break the loop, but
			 * reclaim_coldpgs_from_lru reclaim the memory at the
			 * granularity of a page.
			 */
			reclaim = (filter->size - nr_reclaimed) >> PAGE_SHIFT;
			nr_page_reclaimed = reclaim_coldpgs_from_lru(memcg,
							filter, pgdat, lruvec,
							lru, reclaim);

			if (lru == LRU_UNEVICTABLE)
				reclaim_coldpgs_update_stats(memcg,
					RECLIMA_COLDPGS_STAT_MLOCK_DROP,
					nr_page_reclaimed << PAGE_SHIFT);

			nr_reclaimed += nr_page_reclaimed << PAGE_SHIFT;
		}

		if (test_bit(LRU_SLAB, &bitmap) &&
				nr_reclaimed < filter->size) {
			unsigned long nr_slab_size, nr_to_reclaim;

			/*
			 * The user specified "nr_reclaimed" means it is used
			 * to break the loop rather than the actual numbers
			 * need to free to the system. Because the reclaimed
			 * slab objects maybe are not freed to buddy system,
			 * hence we will reclaim cold slab can be controlled
			 * separately by idlemd tool.
			 */
			nr_to_reclaim = filter->size - nr_reclaimed;
			nr_slab_size = reclaim_coldslab_from_lru(memcg,
							pgdat->node_id,
							filter->threshold,
							nr_to_reclaim);
			nr_reclaimed += nr_slab_size;
			reclaim_coldpgs_update_stats(memcg,
				RECLAIM_COLDPGS_STAT_SLAB_DROP, nr_slab_size);
		}
	}
}

static void reclaim_coldpgs_action(struct mem_cgroup *memcg,
				   unsigned long threshold,
				   unsigned long size)
{
	struct mem_cgroup *m;
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	struct reclaim_coldpgs_filter filter;

	/*
	 * Populate the filter used in reclaiming. The global control could
	 * be modified when the reclaiming is in progress. So we partially
	 * copy over the global control to gurantee the consistency.
	 */
	down_read(&global_control.rwsem);
	filter.flags = global_control.flags;
	filter.batch = global_control.batch;
	filter.mode = global_control.mode;
	filter.threshold = threshold;
	filter.size = size;
	memcpy(filter.thresholds, global_control.thresholds,
	       sizeof(filter.thresholds));
	up_read(&global_control.rwsem);

	/*
	 * The memory cgroup might have offlined subordinate memory cgroups,
	 * whose cgroup files have been removed. It means there is no way to
	 * reclaim the cold memory from the offlined memory cgroups through
	 * the cgroup files. So the cold memory of the offlined memory cgroups
	 * is reclaimed. The coldness threshold is inherited from the parent,
	 * but the amount isn't limited.
	 */
	for_each_memcg_tree(memcg, m) {
		if (m != memcg && mem_cgroup_online(m))
			continue;

		if (m == memcg) {
			filter.size = size;
			reclaim_coldpgs_from_memcg(m, &filter);
		} else {
			filter.size = 0xFFFFFFFFFF;
			reclaim_coldpgs_from_memcg(m, &filter);
		}
	}

	/*
	 * Clear the threshold and size, preparing for next round of reclaim.
	 * The fields are untained and no need to be cleared out for the
	 * offlined subordinate memory cgroups.
	 */
	down_write(&control->rwsem);
	control->threshold = 0;
	control->size = 0;
	up_write(&control->rwsem);
}

static int reclaim_coldpgs_read_threshold(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	unsigned long threshold;

	down_read(&control->rwsem);
	threshold = control->threshold;
	up_read(&control->rwsem);

	seq_printf(m, "%lu\n", threshold);

	return 0;
}

static ssize_t reclaim_coldpgs_write_threshold(struct kernfs_open_file *of,
					       char *buf, size_t count,
					       loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	unsigned long threshold, size;
	int ret;

	buf = strstrip(buf);
	ret = kstrtoul(buf, 10, &threshold);
	if (ret || threshold > U8_MAX)
		return -EINVAL;

	down_write(&control->rwsem);
	control->threshold = threshold;
	size = control->size;
	up_write(&control->rwsem);

	if (threshold > 0 && size > 0)
		reclaim_coldpgs_action(memcg, threshold, size);

	return count;
}

static int reclaim_coldpgs_read_size(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	unsigned long size;

	down_read(&control->rwsem);
	size = control->size;
	up_read(&control->rwsem);

	seq_printf(m, "%lu\n", size);

	return 0;
}

static ssize_t reclaim_coldpgs_write_size(struct kernfs_open_file *of,
					  char *buf, size_t count,
					  loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	unsigned long threshold, size;
	int ret;

	buf = strstrip(buf);
	ret = kstrtoul(buf, 10, &size);
	if (ret)
		return -EINVAL;

	down_write(&control->rwsem);
	threshold = control->threshold;
	control->size = size;
	up_write(&control->rwsem);

	if (threshold > 0 && size > 0)
		reclaim_coldpgs_action(memcg, threshold, size);

	return count;
}

static int reclaim_coldpgs_read_flags(struct seq_file *m, void *v)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(seq_css(m));
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	unsigned long flags;

	down_read(&control->rwsem);
	flags = control->flags;
	up_read(&control->rwsem);

	seq_printf(m, "0x%lx\n", flags);

	return 0;
}

static ssize_t reclaim_coldpgs_write_flags(struct kernfs_open_file *of,
					  char *buf, size_t count,
					  loff_t off)
{
	struct mem_cgroup *memcg = mem_cgroup_from_css(of_css(of));
	struct reclaim_coldpgs_control *control = &memcg->coldpgs_control;
	unsigned long flags;
	int ret;

	buf = strstrip(buf);
	ret = kstrtoul(buf, 16, &flags);
	if (ret)
		return -EINVAL;

	down_write(&control->rwsem);
	control->flags = flags;
	up_write(&control->rwsem);

	return count;
}

static int reclaim_coldpgs_read_stats(struct seq_file *m, void *v)
{
	struct mem_cgroup *iter, *memcg = mem_cgroup_from_css(seq_css(m));
	struct reclaim_coldpgs_stats *self, *stats, *total;
	unsigned int hierarchy, cpu, i;
	static char * const coldpgs_stats_desc[] = {
		"pagecache migrate in",
		"pagecache migrate out",
		"pagecache dropped",
		"anon migrate in",
		"anon zswap in",
		"anon swap in",
		"anon migrate out",
		"anon zswap out",
		"anon swap out",
		"slab drop",
		"mlock dropped",
		"mlock refault",
	};

	self = kzalloc(sizeof(*self) * 3, GFP_KERNEL);
	if (!self)
		return -ENOMEM;

	stats = self + 1;
	total = self + 2;
	down_read(&global_control.rwsem);
	hierarchy = global_control.hierarchy;
	up_read(&global_control.rwsem);

	/*
	 * Bail early if hierarchy mode is disabled. The iteration works
	 * perfectly because the root memory cgroup is iterated firstly.
	 */
	for_each_memcg_tree(memcg, iter) {
		if (!hierarchy && iter != memcg) {
			my_mem_cgroup_iter_break(memcg, iter);
			break;
		}

		memset(stats, 0, sizeof(*stats));
		for_each_possible_cpu(cpu) {
			for (i = 0; i < RECLAIM_COLDPGS_STAT_MAX; i++) {
				stats->counts[i] +=
				per_cpu_ptr(iter->coldpgs_stats,
					    cpu)->counts[i];
			}
		}

		/* Save the counter of current memory cgroup */
		if (iter == memcg)
			memcpy(self, stats, sizeof(*stats));

		/*
		 * The current memory cgroup is always accounted, regardless
		 * of the hierarchy mode.
		 */
		for (i = 0; i < RECLAIM_COLDPGS_STAT_MAX; i++)
			total->counts[i] += stats->counts[i];

		/* Avoid taking up CPU too long time. */
		cond_resched();
	}

	for (i = 0; i < RECLAIM_COLDPGS_STAT_MAX; i++) {
		seq_printf(m, "%-32s: %20lu kB\n",
			   coldpgs_stats_desc[i], self->counts[i] >> 10);
	}

	for (i = 0; i < RECLAIM_COLDPGS_STAT_MAX; i++) {
		seq_printf(m, "Total %-26s: %20lu kB\n",
			   coldpgs_stats_desc[i], total->counts[i] >> 10);
	}

	kfree(self);

	return 0;
}

static ssize_t reclaim_coldpgs_write_stats(struct kernfs_open_file *of,
					   char *buf, size_t count,
					   loff_t off)
{
	struct mem_cgroup *iter, *memcg = mem_cgroup_from_css(of_css(of));
	unsigned int hierarchy;
	unsigned long val;
	int cpu, i, ret;

	down_read(&global_control.rwsem);
	hierarchy = global_control.hierarchy;
	up_read(&global_control.rwsem);

	/* Only zero is accepted */
	buf = strstrip(buf);
	ret = kstrtoul(buf, 0, &val);
	if (ret || val)
		return -EINVAL;

	for_each_memcg_tree(memcg, iter) {
		if (!hierarchy && iter != memcg) {
			my_mem_cgroup_iter_break(memcg, iter);
			break;
		}

		for_each_possible_cpu(cpu) {
			for (i = 0; i < RECLAIM_COLDPGS_STAT_MAX; i++) {
				per_cpu_ptr(iter->coldpgs_stats,
					    cpu)->counts[i] = 0;
			}
		}
	}

	return count;
}

static int reclaim_coldpgs_read_swapin(struct seq_file *m, void *v)
{
	const char *magic = "swapin";

	seq_printf(m, "%s\n", magic);

	return 0;
}

static inline bool rcp_pgd_bad(pgd_t pgd)
{
#if CONFIG_PGTABLE_LEVELS > 4
	unsigned long ignore_flags = _PAGE_USER;

#ifdef CONFIG_X86_5LEVEL
	if (!my___pgtable_l5_enabled)
		return false;
#endif

	if (IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION))
		ignore_flags |= _PAGE_NX;

	return ((pgd_flags(pgd) & ~ignore_flags) != _KERNPG_TABLE);

#else
	return false;
#endif /* CONFIG_PGTABLE_LEVELS > 4 */
}

static inline bool rcp_pgd_none_or_clear_bad(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return true;

	if (rcp_pgd_bad(*pgd)) {
		my_pgd_clear_bad(pgd);
		return true;
	}

	return false;
}

static inline bool rcp_p4d_none_or_clear_bad(p4d_t *p4d)
{
	if (p4d_none(*p4d))
		return true;

	if (p4d_bad(*p4d)) {
		my_p4d_clear_bad(p4d);
		return true;
	}

	return false;
}

static inline bool rcp_pud_none_or_clear_bad(pud_t *pud)
{
	if (pud_none(*pud))
		return true;

	if (pud_bad(*pud)) {
		my_pud_clear_bad(pud);
		return true;
	}

	return false;
}

static inline bool rcp_pmd_non_or_trans_huge_or_clear_bad(pmd_t *pmd)
{
	pmd_t pmdval = pmd_read_atomic(pmd);

	/*
	 * The barrier will stabilize the pmdval in a register or on
	 * the stack so that it will stop changing under the code.
	 *
	 * When CONFIG_TRANSPARENT_HUGEPAGE=y on x86 32bit PAE,
	 * pmd_read_atomic is allowed to return a not atomic pmdval
	 * (for example pointing to an hugepage that has never been
	 * mapped in the pmd). The below checks will only care about
	 * the low part of the pmd with 32bit PAE x86 anyway, with the
	 * exception of pmd_none(). So the important thing is that if
	 * the low part of the pmd is found null, the high part will
	 * be also null or the pmd_none() check below would be
	 * confused.
	 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	barrier();
#endif
	if (pmd_none(pmdval) ||
	    pmd_trans_huge(pmdval))
		return true;

	if (pmd_bad(pmdval)) {
		my_pmd_clear_bad(pmd);
		return true;
	}

	return false;
}

#define SWAPIN_SKIP_VMA	1
#define SWAPIN_SKIP_PMD	2

static int swapin_pte(struct vm_fault *vmf)
{
	struct task_struct *task;
	struct mm_struct *mm = vmf->vma->vm_mm;
	struct vm_area_struct *vma;
	bool is_write = (vmf->vma->vm_flags & VM_WRITE);
	int ret;

	/* Allow to receive signals while issuing page IO */
	vmf->flags = (FAULT_FLAG_ALLOW_RETRY |
		      FAULT_FLAG_KILLABLE);
	if (is_write)
		vmf->flags |= FAULT_FLAG_WRITE;

	/* Try to do swapin */
	ret = my_do_swap_page(vmf);
	if (ret & VM_FAULT_ERROR) {
		task = mm->owner;
		pr_warn("reclaim_coldpgs: [%d][%s] Error %d on swapin 0x%lx\n",
			task->pid, task->comm, ret, vmf->address);

		ret = (ret == VM_FAULT_OOM) ? -ENOMEM : -EFAULT;
	}

	if (ret < 0)
		return ret;

	/* Bail if we're not allowed to retry */
	if (!(ret & VM_FAULT_RETRY))
		return 0;

	if (signal_pending(current))
		return -EINTR;

	/* Recheck the vma */
	down_read(&mm->mmap_lock);
	vma = find_vma(mm, vmf->address);
	if (!vma) {
		up_read(&mm->mmap_lock);
		return -EAGAIN;
	}

	if (vmf->vma != vma || !vma->anon_vma) {
		vmf->vma = vma;
		return SWAPIN_SKIP_VMA;
	}

	if (!my_mm_find_pmd(mm, vmf->address))
		return SWAPIN_SKIP_PMD;

	return 0;
}

static int swapin_pmd(struct vm_fault *vmf,
		      unsigned long addr, unsigned long end)
{
	pte_t *pte;
	int ret = 0;

	do {
		pte = pte_offset_map(vmf->pmd, addr);
		vmf->orig_pte = *pte;
		if (!is_swap_pte(*pte))
			continue;

		vmf->address = addr;
		vmf->pte = pte;
		ret = swapin_pte(vmf);
		if (ret)
			break;
	} while (addr += PAGE_SIZE, addr != end);

	return ret;
}

static int swapin_pud(struct vm_fault *vmf, pud_t *pud,
		      unsigned long addr, unsigned long end)
{
	pmd_t *pmd = pmd_offset(pud, addr);
	unsigned long next;
	int ret = 0;

	do {
		next = pmd_addr_end(addr, end);
		if (rcp_pmd_non_or_trans_huge_or_clear_bad(pmd))
			continue;

		vmf->pmd = pmd;
		ret = swapin_pmd(vmf, addr, next);
		if (!ret)
			continue;

		/* Ignore SWAPIN_SKIP_PMD */
		if (ret != SWAPIN_SKIP_PMD)
			break;

		ret = 0;
	} while (pmd++, addr = next, addr != end);

	return ret;
}

static int swapin_p4d(struct vm_fault *vmf, p4d_t *p4d,
		      unsigned long addr, unsigned long end)
{
	pud_t *pud = pud_offset(p4d, addr);
	unsigned long next;
	int ret = 0;

	do {
		next = pud_addr_end(addr, end);
		if (rcp_pud_none_or_clear_bad(pud))
			continue;

		ret = swapin_pud(vmf, pud, addr, next);
		if (ret)
			break;
	} while (pud++, addr = next, addr != end);

	return ret;
}

static int swapin_pgd(struct vm_fault *vmf, pgd_t *pgd,
		      unsigned long addr, unsigned long end)
{
	p4d_t *p4d = p4d_offset(pgd, addr);
	unsigned long next;
	int ret = 0;

	do {
		next = p4d_addr_end(addr, end);
		if (rcp_p4d_none_or_clear_bad(p4d))
			continue;

		ret = swapin_p4d(vmf, p4d, addr, next);
		if (ret)
			break;
	} while (p4d++, addr = next, addr != end);

	return ret;
}

static int swapin_vma(struct vm_fault *vmf)
{
	unsigned long addr = vmf->vma->vm_start;
	unsigned long end = vmf->vma->vm_end;
	pgd_t *pgd = pgd_offset(vmf->vma->vm_mm, addr);
	unsigned long next;
	int ret = 0;

	do {
		next = pgd_addr_end(addr, end);
		if (rcp_pgd_none_or_clear_bad(pgd))
			continue;

		ret = swapin_pgd(vmf, pgd, addr, next);
		if (ret)
			break;
	} while (pgd++, addr = next, addr != end);

	return ret;
}

static int reclaim_coldpgs_swapin_from_task(struct task_struct *task)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct vm_fault vmf = { };
	int ret = 0;

	mm = get_task_mm(task);
	if (!mm)
		return 0;

	/*
	 * Bail if we're not the owner because memory is charged to the
	 * owner. Also threads can be assigned to different memory cgroups.
	 */
	if (mm->owner != task)
		goto out;

	down_read(&mm->mmap_lock);
again:
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!vma->anon_vma)
			continue;

		vmf.vma = vma;
		ret = swapin_vma(&vmf);
		if (!ret) {
			cond_resched();
			continue;
		}

		/* Interrupted without taking the lock */
		if (ret == -EINTR)
			goto out;

		/* Skip the vma which has been changed */
		if (ret == SWAPIN_SKIP_VMA) {
			ret = 0;
			vma = vmf.vma;
			continue;
		}

		/* Start over in case the vma is gone */
		if (ret == -EAGAIN)
			goto again;

		/* Abort on serious errors OOM/SIGBUS etc */
		break;
	}

	up_read(&mm->mmap_lock);
out:
	mmput(mm);
	return ret;
}

static int reclaim_coldpgs_swapin_from_memcg(struct mem_cgroup *memcg)
{
	struct task_struct *task;
	struct css_task_iter it;
	int ret = 0;

	my_css_task_iter_start(&memcg->css, 0, &it);

	while (!ret && (task = my_css_task_iter_next(&it))) {
		/* Ignore the tasks which are exiting */
		if (task->flags & PF_EXITING)
			continue;

		ret = reclaim_coldpgs_swapin_from_task(task);
	}

	my_css_task_iter_end(&it);

	return ret;
}

static ssize_t reclaim_coldpgs_write_swapin(struct kernfs_open_file *of,
					    char *buf, size_t count,
					    loff_t off)
{
	struct mem_cgroup *iter, *memcg = mem_cgroup_from_css(of_css(of));
	const char *magic = "swapin\n";
	int ret = 0;

	if (count != strlen(magic) || strcmp(buf, magic))
		return -EINVAL;

	for_each_memcg_tree(memcg, iter) {
		ret = reclaim_coldpgs_swapin_from_memcg(iter);
		if (ret) {
			my_mem_cgroup_iter_break(memcg, iter);
			break;
		}
	}

	return ret ? -EIO : count;
}

static struct cftype reclaim_coldpgs_files[] = {
	{ .name		= "coldpgs.threshold",
	  .seq_show	= reclaim_coldpgs_read_threshold,
	  .write	= reclaim_coldpgs_write_threshold,
	},
	{ .name		= "coldpgs.size",
	  .seq_show	= reclaim_coldpgs_read_size,
	  .write	= reclaim_coldpgs_write_size,
	},
	{ .name		= "coldpgs.flags",
	  .seq_show	= reclaim_coldpgs_read_flags,
	  .write	= reclaim_coldpgs_write_flags,
	},
	{ .name		= "coldpgs.stats",
	  .seq_show	= reclaim_coldpgs_read_stats,
	  .write	= reclaim_coldpgs_write_stats,
	},
	{ .name		= "coldpgs.swapin",
	  .seq_show	= reclaim_coldpgs_read_swapin,
	  .write	= reclaim_coldpgs_write_swapin,
	},
	{ }	/* terminate */
};

static ssize_t reclaim_coldpgs_show_threshold(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      char *buf)
{
	unsigned int val;
	int ret;

	down_read(&global_control.rwsem);
	val = global_control.thresholds[THRESHOLD_BASE];
	up_read(&global_control.rwsem);

	ret = sprintf(buf, "%u\n", val);

	return ret;
}

static ssize_t reclaim_coldpgs_store_threshold(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       const char *buf,
					       size_t count)
{
	struct mem_cgroup *memcg;
	struct reclaim_coldpgs_filter filter;
	unsigned int val;
	int ret;

	ret = kstrtouint(buf, 10, &val);
	if (ret || val < 1 || val > U8_MAX)
		return -EINVAL;

	/*
	 * We needn't access the global control block exclusively when copying
	 * over the information. However, it doesn't matter. It can avoid make
	 * double locking calls and simplify the code at least.
	 */
	down_write(&global_control.rwsem);
	global_control.thresholds[THRESHOLD_BASE] = val;
	filter.flags = global_control.flags;
	filter.batch = global_control.batch;
	filter.mode = global_control.mode;
	filter.threshold = val;
	filter.size = 0xFFFFFFFFFF;
	memcpy(filter.thresholds, global_control.thresholds,
	       sizeof(filter.thresholds));
	up_write(&global_control.rwsem);

	for_each_memcg_tree(NULL, memcg) {
		reclaim_coldpgs_from_memcg(memcg, &filter);
	}

	return count;
}

static ssize_t reclaim_coldpgs_show_swapin(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	const char *magic = "swapin";
	int ret;

	ret = sprintf(buf, "%s\n", magic);

	return ret;
}

static ssize_t reclaim_coldpgs_store_swapin(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf,
					    size_t count)
{
	struct mem_cgroup *memcg;
	const char *magic = "swapin\n";
	int ret = 0;

	if (count != strlen(magic) || strcmp(buf, magic))
		return -EINVAL;

	for_each_memcg_tree(NULL, memcg) {
		ret = reclaim_coldpgs_swapin_from_memcg(memcg);
		if (ret) {
			my_mem_cgroup_iter_break(NULL, memcg);
			break;
		}
	}

	return ret ? -EIO : count;
}

/*
 * Define handlers for the sysfs files. Their pattern is fixed. So we
 * leverage the macro to define them as below.
 */
RECLAIM_COLDPGS_SYSFS_HANDLER(version, version, true, 0, UINT_MAX);
RECLAIM_COLDPGS_SYSFS_HANDLER(hierarchy, hierarchy, false, 0, 1);
RECLAIM_COLDPGS_SYSFS_HANDLER(batch, batch, false, 1, UINT_MAX);
RECLAIM_COLDPGS_SYSFS_HANDLER(flags, flags, true,  0, UINT_MAX);
RECLAIM_COLDPGS_SYSFS_HANDLER(mode, mode, true,  0, UINT_MAX);
RECLAIM_COLDPGS_SYSFS_HANDLER(threshold_nonrot, thresholds[THRESHOLD_NONROT],
			      false, 0, U8_MAX);

RECLAIM_COLDPGS_ATTR(version, 0400);
RECLAIM_COLDPGS_ATTR(hierarchy, 0600);
RECLAIM_COLDPGS_ATTR(batch, 0600);
RECLAIM_COLDPGS_ATTR(flags, 0600);
RECLAIM_COLDPGS_ATTR(mode, 0600);
RECLAIM_COLDPGS_ATTR(threshold, 0600);
RECLAIM_COLDPGS_ATTR(threshold_nonrot, 0600);
RECLAIM_COLDPGS_ATTR(swapin, 0600);

static struct attribute *reclaim_coldpgs_attrs[] = {
	&reclaim_coldpgs_attr_version.attr,
	&reclaim_coldpgs_attr_hierarchy.attr,
	&reclaim_coldpgs_attr_batch.attr,
	&reclaim_coldpgs_attr_flags.attr,
	&reclaim_coldpgs_attr_mode.attr,
	&reclaim_coldpgs_attr_threshold.attr,
	&reclaim_coldpgs_attr_threshold_nonrot.attr,
	&reclaim_coldpgs_attr_swapin.attr,
	NULL
};

static struct attribute_group reclaim_coldpgs_attr_group = {
	.name	= "coldpgs",
	.attrs	= reclaim_coldpgs_attrs,
};

static int __init reclaim_coldpgs_resolve_symbols(void)
{
	reclaim_coldpgs_resolve_symbol(mem_cgroup_iter);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_iter_break);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_get_nr_swap_pages);
	reclaim_coldpgs_resolve_symbol(add_to_swap);
	reclaim_coldpgs_resolve_symbol(try_to_free_swap);
	reclaim_coldpgs_resolve_symbol(end_swap_bio_write);
	reclaim_coldpgs_resolve_symbol(__swap_writepage);
	reclaim_coldpgs_resolve_symbol(lru_add_drain);
	reclaim_coldpgs_resolve_symbol(can_split_huge_page);
	reclaim_coldpgs_resolve_symbol(split_huge_page_to_list);
	reclaim_coldpgs_resolve_symbol(try_to_unmap);
	reclaim_coldpgs_resolve_symbol(__remove_mapping);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_swap_full);
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	reclaim_coldpgs_resolve_symbol(try_to_unmap_flush);
	reclaim_coldpgs_resolve_symbol(try_to_unmap_flush_dirty);
#endif
	reclaim_coldpgs_resolve_symbol(putback_lru_page);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_page_lruvec);
	reclaim_coldpgs_resolve_symbol(workingset_age_nonresident);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_update_lru_size);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_uncharge);
	reclaim_coldpgs_resolve_symbol(mem_cgroup_uncharge_list);
	reclaim_coldpgs_resolve_symbol(free_unref_page_list);
	reclaim_coldpgs_resolve_symbol(vma_interval_tree_iter_first);
	reclaim_coldpgs_resolve_symbol(vma_interval_tree_iter_next);
	reclaim_coldpgs_resolve_symbol(cgroup_add_dfl_cftypes);
	reclaim_coldpgs_resolve_symbol(cgroup_add_legacy_cftypes);
	reclaim_coldpgs_resolve_symbol(cgroup_rm_cftypes);
	reclaim_coldpgs_resolve_symbol(compound_page_dtors);
	reclaim_coldpgs_resolve_symbol(vm_swappiness);
	reclaim_coldpgs_resolve_symbol(swap_info);
	reclaim_coldpgs_resolve_symbol(frontswap_enabled_key);
	reclaim_coldpgs_resolve_symbol(frontswap_ops);
	reclaim_coldpgs_resolve_symbol(zswap_frontswap_ops);
	reclaim_coldpgs_resolve_symbol(frontswap_writethrough_enabled);
	reclaim_coldpgs_resolve_symbol(coldpgs_enabled);
#ifdef CONFIG_DEBUG_FS
	reclaim_coldpgs_resolve_symbol(frontswap_succ_stores);
	reclaim_coldpgs_resolve_symbol(frontswap_failed_stores);
#endif
	reclaim_coldpgs_resolve_symbol(shrinker_list);
	reclaim_coldpgs_resolve_symbol(shrinker_rwsem);
	reclaim_coldpgs_resolve_symbol(shrinker_idr);
	reclaim_coldpgs_resolve_symbol(root_mem_cgroup);
	reclaim_coldpgs_resolve_symbol(shrinker_nr_max);
	reclaim_coldpgs_resolve_symbol(css_task_iter_start);
	reclaim_coldpgs_resolve_symbol(css_task_iter_next);
	reclaim_coldpgs_resolve_symbol(css_task_iter_end);
#if CONFIG_PGTABLE_LEVELS > 4
#ifdef CONFIG_X86_5LEVEL
	reclaim_coldpgs_resolve_symbol(__pgtable_l5_enabled);
#endif
#endif
	reclaim_coldpgs_resolve_symbol(pgd_clear_bad);
#if CONFIG_PGTABLE_LEVELS > 4
	reclaim_coldpgs_resolve_symbol(p4d_clear_bad);
#endif
#ifndef __PAGETABLE_PUD_FOLDED
	reclaim_coldpgs_resolve_symbol(pud_clear_bad);
#endif
	reclaim_coldpgs_resolve_symbol(pmd_clear_bad);
	reclaim_coldpgs_resolve_symbol(mm_find_pmd);
	reclaim_coldpgs_resolve_symbol(do_swap_page);
	reclaim_coldpgs_resolve_symbol(node_page_state);
	reclaim_coldpgs_resolve_symbol(__mod_lruvec_state);

	return 0;
}

static int __init reclaim_coldpgs_init(void)
{
	unsigned int major, minor, revision;
	int ret;

	if (mem_cgroup_disabled())
		return -ENXIO;

	/* Resolve symbols required by the driver */
	ret = reclaim_coldpgs_resolve_symbols();
	if (ret)
		return ret;

	if (lru_gen_enabled()) {
		pr_warn("%s: Failed to load coldpgs due to MGLRU enabled\n",
			__func__);
		return -EPERM;
	}

	/*
	 * Initialize global control. The version is figured out from the
	 * pre-defined string so that we needn't define another one with
	 * different type, to ensure the consistence.
	 */
	ret = sscanf(DRIVER_VERSION, "%d.%d.%d", &major, &minor, &revision);
	if (ret != 3 || major > U8_MAX || minor > U8_MAX || revision > U8_MAX) {
		pr_warn("%s: Invalid version [%s] detected\n",
			__func__, DRIVER_VERSION);
		return -EINVAL;
	}

	init_rwsem(&global_control.rwsem);
	global_control.version = ((major << 16) | (minor << 8) | revision);
	global_control.batch = 32;

	/* Populate the sysfs files */
	ret = sysfs_create_group(mm_kobj, &reclaim_coldpgs_attr_group);
	if (ret) {
		pr_warn("%s: Error %d to populate the sysfs files\n",
			__func__, ret);
		return ret;
	}

	/*
	 * Populate the cgroup files. We need different APIs to do that in
	 * cgroup v1/v2
	 */
	if (cgroup_subsys_on_dfl(memory_cgrp_subsys)) {
		ret = my_cgroup_add_dfl_cftypes(&memory_cgrp_subsys,
						reclaim_coldpgs_files);
	} else {
		ret = my_cgroup_add_legacy_cftypes(&memory_cgrp_subsys,
						   reclaim_coldpgs_files);
	}

	if (ret) {
		pr_warn("%s: Error %d to populate the cgroup files\n",
			__func__, ret);
		sysfs_remove_group(mm_kobj, &reclaim_coldpgs_attr_group);
		return ret;
	}

	enable_coldpgs();

	pr_info("%s (%s) loaded\n", DRIVER_DESC, DRIVER_VERSION);

	return 0;
}

static void __exit reclaim_coldpgs_exit(void)
{
	my_cgroup_rm_cftypes(reclaim_coldpgs_files);
	sysfs_remove_group(mm_kobj, &reclaim_coldpgs_attr_group);

	disable_coldpgs();

	pr_info("%s (%s) unloaded\n", DRIVER_DESC, DRIVER_VERSION);
}

module_init(reclaim_coldpgs_init);
module_exit(reclaim_coldpgs_exit);

MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
