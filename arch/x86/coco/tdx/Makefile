# SPDX-License-Identifier: GPL-2.0
CFLAGS_REMOVE_tdx.o	= -pg
KASAN_SANITIZE_tdx.o	:= n
CFLAGS_tdx.o		+= -fno-stack-protector

obj-y += tdx.o tdcall.o tdx-filter.o
