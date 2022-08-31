// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_inline.h>
#include <linux/freezer.h>
#include <linux/kthread.h>

#include <linux/prezero.h>
#include "internal.h"

DEFINE_STATIC_KEY_FALSE(prezero_enabled_key);
unsigned long prezero_enabled_flag;
static unsigned int prezero_min_order = 9;
static unsigned int prezero_max_percent = 50;
static unsigned int prezero_batch_pages = 4096;
static unsigned int prezero_sleep_msecs = 1000;
static struct task_struct *prezero_kthread[MAX_NUMNODES];
static wait_queue_head_t kprezerod_wait[MAX_NUMNODES];
static unsigned long kprezerod_sleep_expire[MAX_NUMNODES];

static void my_clear_page(struct page *page, unsigned int order)
{
	int i, numpages = 1 << order;

	for (i = 0; i < numpages; i++)
		clear_highpage(page + i);
}

static int prezero_one_page(struct zone *zone, unsigned int order, int mtype)
{
	struct free_area *area = &zone->free_area[order];
	struct list_head *list = &area->free_list[mtype];
	struct page *page_to_zero = NULL, *page, *next;
	int err = -ENOMEM;

	/*
	 * Perform early check, if free area is empty there is
	 * nothing to process so we can skip this free_list.
	 */
	if (list_empty(list))
		return err;

	/* Isolate a non-zeroed page */
	spin_lock_irq(&zone->lock);
	list_for_each_entry_safe(page, next, list, lru) {
		/* We are going to skip over the pre-zeroed pages. */
		if (PageZeroed(page))
			continue;

		if (__isolate_free_page(page, order))
			page_to_zero = page;
		else
			next = page;

		/*
		 * Make the next page in the free list the new head
		 * of the free list before we release the zone lock.
		 */
		if (&next->lru != list && !list_is_first(&next->lru, list))
			list_rotate_to_front(&next->lru, list);

		break;
	}
	spin_unlock_irq(&zone->lock);

	/* Failed to isolate non-zeroed page */
	if (!page_to_zero)
		return err;

	/* Clear the page */
	my_clear_page(page, order);
	__SetPageZeroed(page);

	/* Putback the pre-zeroed page */
	spin_lock_irq(&zone->lock);
	mtype = get_pageblock_migratetype(page);
	__putback_isolated_page(page, order, mtype);
	spin_unlock_irq(&zone->lock);

	return err;
}

static void prezero_do_work(pg_data_t *pgdat)
{
	struct zone *zone = &pgdat->node_zones[ZONE_NORMAL];
	/* NOTE only MIGRATE_MOVABLE is supported currently */
	int mtype = MIGRATE_MOVABLE;
	unsigned int order;
	unsigned long nr_free, nr_zeroed;
	unsigned int nr_done;

	for (order = prezero_min_order; order < MAX_ORDER; order++) {
		/*
		 * Use data_race to avoid KCSAN warning since access
		 * to nr_free and nr_zeroed is lockless here.
		 *
		 * Since only MIGRATE_MOVABLE is supported at present,
		 * to set prezero_max_percent too high could prevent
		 * kprezerod from early bailing out.
		 */
		nr_free = data_race(zone->free_area[order].nr_free);
		/* Ditto. */
		nr_zeroed = data_race(zone->free_area[order].nr_zeroed);

		if (nr_zeroed >= nr_free * prezero_max_percent / 100)
			continue;

		nr_done = 0;
		while (nr_done < prezero_batch_pages) {
			if (prezero_one_page(zone, order, mtype) < 0)
				break;
			nr_done += 1 << order;
		}
	}
}

static bool kprezerod_should_wakeup(int nid)
{
	return kthread_should_stop() ||
	       time_after_eq(jiffies, kprezerod_sleep_expire[nid]);
}

static int prezero(void *data)
{
	pg_data_t *pgdat = (pg_data_t *)data;
	int nid = pgdat->node_id;

	set_freezable();

	while (!kthread_should_stop()) {
		unsigned long sleep_jiffies =
			msecs_to_jiffies(prezero_sleep_msecs);

		kprezerod_sleep_expire[nid] = jiffies + sleep_jiffies;
		if (wait_event_freezable_timeout(kprezerod_wait[nid],
						 kprezerod_should_wakeup(nid),
						 sleep_jiffies))
			prezero_do_work(pgdat);
	}

	return 0;
}

static void __start_stop_kprezerod(int nid)
{
	if (prezero_enabled()) {
		if (!prezero_kthread[nid])
			prezero_kthread[nid] = kthread_run(prezero,
					NODE_DATA(nid), "kprezerod%d", nid);
		if (IS_ERR(prezero_kthread[nid])) {
			pr_err("failed to run kprezerod on node %d\n", nid);
			prezero_kthread[nid] = NULL;
		}
	} else if (prezero_kthread[nid]) {
		kthread_stop(prezero_kthread[nid]);
		prezero_kthread[nid] = NULL;
	}
}

static void start_stop_kprezerod(void)
{
	int nid;

	for_each_node_state(nid, N_MEMORY)
		__start_stop_kprezerod(nid);
}

static int __init setup_prezero(char *str)
{
	unsigned long val;
	int err;

	if (!str)
		return 0;

	err = kstrtoul(str, 0, &val);
	if (err < 0 || val > (1UL << PREZERO_MAX_FLAG) - 1)
		return 0;

	prezero_enabled_flag = val;

	return 1;
}
__setup("prezero=", setup_prezero);

#ifdef CONFIG_SYSFS
static ssize_t prezero_show_enabled(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lu\n", prezero_enabled_flag);
}
static ssize_t prezero_store_enabled(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	static DEFINE_MUTEX(mutex);
	unsigned long val;
	int err;
	ssize_t ret = count;

	mutex_lock(&mutex);

	err = kstrtoul(buf, 0, &val);
	if (err < 0 || val > (1UL << PREZERO_MAX_FLAG) - 1) {
		ret = -EINVAL;
		goto out;
	}

	prezero_enabled_flag = val;

	if (prezero_enabled_flag)
		static_branch_enable(&prezero_enabled_key);
	else
		static_branch_disable(&prezero_enabled_key);

	start_stop_kprezerod();

out:
	mutex_unlock(&mutex);
	return ret;
}
static struct kobj_attribute prezero_attr_enabled =
	__ATTR(enabled, 0644, prezero_show_enabled,
	       prezero_store_enabled);

#define PREZERO_SYSFS_ATTR(name, field, min_val, max_val, store_cb)	\
static ssize_t prezero_show_##name(struct kobject *kobj,		\
	struct kobj_attribute *attr, char *buf)				\
{									\
	return sprintf(buf, "%u\n", field);				\
}									\
static ssize_t prezero_store_##name(struct kobject *kobj,		\
	struct kobj_attribute *attr, const char *buf, size_t count)	\
{									\
	unsigned long val;						\
	int ret;							\
									\
	ret = kstrtoul(buf, 0, &val);					\
	if (ret || val < min_val || val > max_val)			\
		return -EINVAL;						\
									\
	field = val;							\
	store_cb();							\
	return count;							\
}									\
static struct kobj_attribute prezero_attr_##name =			\
	__ATTR(name, 0644, prezero_show_##name, prezero_store_##name)

static void dummy_store_cb(void)
{
}

static void prezero_sleep_msecs_store_cb(void)
{
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		kprezerod_sleep_expire[nid] = 0;
		wake_up_interruptible(&kprezerod_wait[nid]);
	}
}

PREZERO_SYSFS_ATTR(min_order, prezero_min_order, 0, MAX_ORDER - 1,
		   dummy_store_cb);
PREZERO_SYSFS_ATTR(max_percent, prezero_max_percent, 0, 100,
		   dummy_store_cb);
PREZERO_SYSFS_ATTR(batch_pages, prezero_batch_pages, 0, UINT_MAX,
		   dummy_store_cb);
PREZERO_SYSFS_ATTR(sleep_msecs, prezero_sleep_msecs, 0, UINT_MAX,
		   prezero_sleep_msecs_store_cb);

static struct attribute *prezero_attrs[] = {
	&prezero_attr_enabled.attr,
	&prezero_attr_min_order.attr,
	&prezero_attr_max_percent.attr,
	&prezero_attr_batch_pages.attr,
	&prezero_attr_sleep_msecs.attr,
	NULL,
};

static struct attribute_group prezero_attr_group = {
	.attrs = prezero_attrs,
	.name = "prezero",
};

static int __init prezero_sysfs_init(void)
{
	int err;

	err = sysfs_create_group(mm_kobj, &prezero_attr_group);
	if (err)
		pr_err("failed to register prezero group\n");

	return err;
}
#else
static inline int __init prezero_sysfs_init(void)
{
	return 0;
}
#endif /* CONFIG_SYSFS */

static int __init prezero_init(void)
{
	int ret;
	int nid;

	ret = prezero_sysfs_init();
	if (ret < 0)
		return ret;

	for_each_node_state(nid, N_MEMORY) {
		init_waitqueue_head(&kprezerod_wait[nid]);
		__start_stop_kprezerod(nid);
	}

	return 0;
}
module_init(prezero_init);
