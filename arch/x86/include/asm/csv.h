/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hygon China Secure Virtualization (CSV)
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 *
 * Author: Jiang Xin <jiangxin@hygon.cn>
 */

#ifndef _ASM_X86_CSV_H
#define _ASM_X86_CSV_H

#ifdef CONFIG_HYGON_CSV

#define CSV_MR_ALIGN_BITS		(28)

struct csv_mem {
	uint64_t start;
	uint64_t size;
};

extern struct csv_mem *csv_smr;
extern unsigned int csv_smr_num;

void __init early_csv_reserve_mem(void);
phys_addr_t csv_alloc_from_contiguous(size_t size, nodemask_t *nodes_allowed,
				unsigned int align);
void csv_release_to_contiguous(phys_addr_t pa, size_t size);
uint32_t csv_get_smr_entry_shift(void);

#endif

#endif
