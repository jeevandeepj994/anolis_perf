/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PREZERO_H
#define _LINUX_PREZERO_H

#include <linux/types.h>
#include <linux/mmzone.h>

#ifdef CONFIG_PAGE_PREZERO
DECLARE_STATIC_KEY_FALSE(prezero_enabled_key);

static inline bool prezero_enabled(void)
{
	return static_branch_unlikely(&prezero_enabled_key);
}

#else
static inline bool prezero_enabled(void)
{
	return false;
}
#endif /* CONFIG_KZEROPAGED */

#endif /* _LINUX_PREZERO_H */
