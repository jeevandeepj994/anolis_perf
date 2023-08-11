/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#ifndef __CSV_COMMAND_H__
#define __CSV_COMMAND_H__

#ifdef CONFIG_HYGON_CSV

bool csv_active(void);
bool csv_enable(void);

void __init csv_early_reset_memory(struct boot_params *bp);
void __init csv_early_update_memory_enc(u64 vaddr, u64 pages);
void __init csv_early_update_memory_dec(u64 vaddr, u64 pages);

#else	/* !CONFIG_HYGON_CSV */

static inline bool csv_active(void) { return false; }
static inline bool csv_enable(void) { return false; }

static inline void __init csv_early_reset_memory(struct boot_params *bp) { }
static inline void __init csv_early_update_memory_enc(u64 vaddr, u64 pages) { }
static inline void __init csv_early_update_memory_dec(u64 vaddr, u64 pages) { }

#endif	/* CONFIG_HYGON_CSV */

#endif
