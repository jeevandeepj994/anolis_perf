# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_YCC) += ycc.o
ycc-objs := ycc_drv.o ycc_isr.o ycc_cdev.o ycc_ring.o ycc_ske.o ycc_aead.o \
	ycc_pke.o

ifndef CONFIG_CRYPTO_SM2
ycc-objs += sm2signature_asn1.o
endif

ifdef CONFIG_UIO
ycc-objs += ycc_uio.o
ccflags-y += -DCONFIG_UIO
endif
