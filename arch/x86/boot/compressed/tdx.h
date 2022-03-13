/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Intel Corporation */
#ifndef BOOT_COMPRESSED_TDX_H
#define BOOT_COMPRESSED_TDX_H

#include <linux/types.h>

#ifdef CONFIG_INTEL_TDX_GUEST
void early_tdx_detect(void);
bool early_is_tdx_guest(void);
#else
static inline void early_tdx_detect(void) { };
static inline bool early_is_tdx_guest(void) { return false; }
#endif

#endif
