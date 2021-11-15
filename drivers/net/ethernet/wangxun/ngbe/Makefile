# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019 - 2022 Beijing WangXun Technology Co., Ltd.
#
# Makefile for the Wangxun(R) GbE PCI Express ethernet driver
#

obj-$(CONFIG_NGBE) += ngbe.o

ngbe-objs := ngbe_main.o \
	     ngbe_hw.o   \
	     ngbe_phy.o  \
	     ngbe_lib.o  \
	     ngbe_ptp.o	 \
	     ngbe_ethtool.o

ngbe-$(CONFIG_DEBUG_FS) += ngbe_debugfs.o
ngbe-$(CONFIG_SYSFS) += ngbe_sysfs.o
