# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_CRYPTO_DEV_CCP_DD) += ccp.o
ccp-objs  := sp-dev.o sp-platform.o
ccp-$(CONFIG_CRYPTO_DEV_SP_CCP) += ccp-dev.o \
	    ccp-ops.o \
	    ccp-dev-v3.o \
	    ccp-dev-v5.o \
	    ccp-dmaengine.o \
	    hygon/ccp-dev-v5.o
ccp-$(CONFIG_CRYPTO_DEV_CCP_DEBUGFS) += ccp-debugfs.o
ccp-$(CONFIG_PCI) += sp-pci.o
ccp-$(CONFIG_CRYPTO_DEV_SP_PSP) += psp-dev.o \
                                   sev-dev.o \
                                   tee-dev.o \
                                   platform-access.o \
                                   dbc.o \
                                   psp-ringbuf.o \
                                   csv-dev.o \
                                   vpsp.o

ccp-$(CONFIG_TDM_DEV_HYGON) += tdm-dev.o
obj-$(CONFIG_CRYPTO_DEV_HCT) += hygon/hct.o

obj-$(CONFIG_CRYPTO_DEV_CCP_CRYPTO) += ccp-crypto.o
ccp-crypto-objs := ccp-crypto-main.o \
		   ccp-crypto-aes.o \
		   ccp-crypto-aes-cmac.o \
		   ccp-crypto-aes-xts.o \
		   ccp-crypto-aes-galois.o \
		   ccp-crypto-des3.o \
		   ccp-crypto-rsa.o \
		   ccp-crypto-sha.o
obj-$(CONFIG_TDM_KERNEL_GUARD) += tdm-kernel-guard.o

$(obj)/ccp_sm2_sign.asn1.o: $(obj)/ccp_sm2_sign.asn1.c $(obj)/ccp_sm2_sign.asn1.h
$(obj)/ccp-crypto-sm2-hygon.o: $(obj)/ccp_sm2_sign.asn1.h

ccp-crypto-$(CONFIG_HYGON_GM) += ccp-crypto-sm2-hygon.o \
		   ccp-crypto-sm3-hygon.o \
		   ccp-crypto-sm4-hygon.o \
		   ccp_sm2_sign.asn1.o
