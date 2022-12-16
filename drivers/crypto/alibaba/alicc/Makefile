# SPDX-License-Identifier: GPL-2.0
obj-m += alicc.o
alicc-objs := alicc_drv.o alicc_isr.o alicc_cdev.o alicc_ring.o alicc_ske.o alicc_aead.o \
	alicc_pke.o sm2signature_asn1.o

ifdef CONFIG_UIO
alicc-objs += alicc_uio.o
ccflags-y += -DCONFIG_UIO
endif
