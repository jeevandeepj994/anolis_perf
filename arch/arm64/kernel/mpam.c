/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Arm Ltd. */

#include <asm/mpam.h>

#include <linux/arm_mpam.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>

DEFINE_STATIC_KEY_FALSE(arm64_mpam_has_hcr);
EXPORT_SYMBOL(arm64_mpam_has_hcr);
DEFINE_PER_CPU(u64, arm64_mpam_default);
DEFINE_PER_CPU(u64, arm64_mpam_current);

