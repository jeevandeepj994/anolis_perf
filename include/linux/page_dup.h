/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGE_DUP_H_
#define _LINUX_PAGE_DUP_H_

#include <linux/types.h>

struct page;
struct vm_area_struct;

#ifdef CONFIG_DUPTEXT
DECLARE_STATIC_KEY_FALSE(duptext_enabled_key);
static inline bool duptext_enabled(void)
{
	return static_branch_unlikely(&duptext_enabled_key);
}
static inline bool page_dup_any(struct page *page)
{
	return PageDup(page);
}
static inline bool page_dup_master(struct page *page)
{
	return PageDup(page) && !PagePrivate(page);
}
static inline bool page_dup_slave(struct page *page)
{
	return PageDup(page) && PagePrivate(page);
}
#else
static inline bool duptext_enabled(void)
{
	return false;
}
static inline bool page_dup_any(struct page *page)
{
	return false;
}
static inline bool page_dup_master(struct page *page)
{
	return false;
}
static inline bool page_dup_slave(struct page *page)
{
	return false;
}
#endif /* CONFIG_DUPTEXT */

/*
 * Only text vma is suitable for dup pages
 */
extern bool __dup_page_suitable(struct vm_area_struct *vma, struct mm_struct *mm);

/*
 * Find get or create a dup page
 * @page: master page
 */
extern struct page *__dup_page(struct page *page, struct vm_area_struct *vma);

/*
 * Return the master page
 * @page: master page, or slave page
 */
extern struct page *__dup_page_master(struct page *page);

/*
 * Has any dup pages mapped
 * @page: master page
 */
extern bool __dup_page_mapped(struct page *page);

/*
 * Remove all the dup pages
 * @page: master page
 * @locked: hold rmap_lock or not
 * @ignore_mlock: ignore mlock or not
 */
extern bool __dedup_page(struct page *page, bool locked, bool ignore_mlock);

static inline bool dup_page_suitable(struct vm_area_struct *vma, struct mm_struct *mm)
{
	if (duptext_enabled())
		return __dup_page_suitable(vma, mm);
	return false;
}

static inline struct page *dup_page(struct page *page, struct vm_area_struct *vma)
{
	if (duptext_enabled())
		return __dup_page(page, vma);
	return NULL;
}

/*
 * NOTE This does not guarantee that the master page exists when
 * dup_page_master returns. Caller should first verify and get a
 * reference of the master page.
 */
static inline struct page *dup_page_master(struct page *page)
{
	if (page_dup_any(page))
		return __dup_page_master(page);
	return page;
}

static inline bool dup_page_mapped(struct page *page)
{
	if (page_dup_master(page))
		return __dup_page_mapped(page);
	return false;
}

/*
 * Return false if the duplicated slave page can not be released successfully.
 */
static inline bool dedup_page(struct page *page, bool locked)
{
	if (page_dup_master(page))
		return __dedup_page(page, locked, true);
	return true;
}

static inline bool dedup_page2(struct page *page, bool locked, bool ignore_mlock)
{
	if (page_dup_master(page))
		return __dedup_page(page, locked, ignore_mlock);
	return true;
}
#endif /* _LINUX_PAGE_DUP_H_ */
