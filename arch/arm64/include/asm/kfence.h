/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64 KFENCE support.
 *
 * Copyright (C) 2020, Google LLC.
 */

#ifndef __ASM_KFENCE_H
#define __ASM_KFENCE_H

#include <linux/kfence.h>

#include <asm/set_memory.h>

static inline bool arch_kfence_init_pool(struct kfence_pool_area *kpa)
{
	unsigned long addr = (unsigned long)kpa->addr;

	/*
	 * If the allocated range is block and contiguous mapping, split it
	 * to pte level before re-initializing kfence pages.
	 */
	if (can_set_block_and_cont_map())
		split_linear_mapping_after_init(addr, kpa->pool_size, PAGE_KERNEL);

	return true;
}

static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	set_memory_valid(addr, 1, !protect);

	return true;
}

static inline bool arch_kfence_free_pool(unsigned long addr) { return false; }

#ifdef CONFIG_KFENCE
extern bool kfence_early_init;
#endif

#endif /* __ASM_KFENCE_H */
