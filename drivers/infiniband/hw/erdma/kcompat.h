/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

/*
 * Copyright 2018-2021 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#ifndef __KCOMPAT_H__
#define __KCOMPAT_H__

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/types.h>

#define ERDMA_MAJOR_VER 0
#define ERDMA_MEDIUM_VER 2
#define ERDMA_MINOR_VER 36

#include <rdma/ib_verbs.h>
#ifndef RDMA_DRIVER_ERDMA
#define RDMA_DRIVER_ERDMA 19
#endif

#ifndef upper_16_bits
#define upper_16_bits(n) ((u16)((n) >> 16))
#define lower_16_bits(n) ((u16)((n) & 0xffff))
#endif

typedef u8 port_t;

#include <rdma/ib_verbs.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/sched/signal.h>

#endif
