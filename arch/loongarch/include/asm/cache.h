/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_CACHE_H
#define _ASM_CACHE_H

#define L1_CACHE_SHIFT		CONFIG_L1_CACHE_SHIFT
#define L1_CACHE_BYTES		(1 << L1_CACHE_SHIFT)

#define __read_mostly __section(".data..read_mostly")

extern struct loongson_system_configuration loongson_sysconf;
extern char __weak except_vec_cex;

#endif /* _ASM_CACHE_H */
