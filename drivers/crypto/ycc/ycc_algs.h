// SPDX-License-Identifier: GPL-2.0
#ifndef __YCC_ALG_H
#define __YCC_ALG_H

#include <crypto/skcipher.h>

#include "ycc_ring.h"
#include "ycc_dev.h"

enum ycc_gcm_mode {
	YCC_AES_128_GCM = 0,
	YCC_AES_192_GCM,
	YCC_AES_256_GCM,
	YCC_SM4_GCM,
};

enum ycc_ccm_mode {
	YCC_AES_128_CCM = 0,
	YCC_AES_192_CCM,
	YCC_AES_256_CCM,
	YCC_SM4_CCM,
};

enum ycc_ske_alg_mode {
	YCC_DES_ECB = 26,
	YCC_DES_CBC,
	YCC_DES_CFB,
	YCC_DES_OFB,
	YCC_DES_CTR, /* 30 */

	YCC_TDES_128_ECB = 31,
	YCC_TDES_128_CBC,
	YCC_TDES_128_CFB,
	YCC_TDES_128_OFB,
	YCC_TDES_128_CTR,
	YCC_TDES_192_ECB,
	YCC_TDES_192_CBC,
	YCC_TDES_192_CFB,
	YCC_TDES_192_OFB,
	YCC_TDES_192_CTR, /* 40 */

	YCC_AES_128_ECB = 41,
	YCC_AES_128_CBC,
	YCC_AES_128_CFB,
	YCC_AES_128_OFB,
	YCC_AES_128_CTR,
	YCC_AES_128_XTS, /* 46 */

	YCC_AES_192_ECB = 48,
	YCC_AES_192_CBC,
	YCC_AES_192_CFB,
	YCC_AES_192_OFB,
	YCC_AES_192_CTR, /* 52 */

	YCC_AES_256_ECB = 55,
	YCC_AES_256_CBC,
	YCC_AES_256_CFB,
	YCC_AES_256_OFB,
	YCC_AES_256_CTR,
	YCC_AES_256_XTS, /* 60 */

	YCC_SM4_ECB = 62,
	YCC_SM4_CBC,
	YCC_SM4_CFB,
	YCC_SM4_OFB,
	YCC_SM4_CTR,
	YCC_SM4_XTS, /* 67 */
};

enum ycc_cmd_id {
	YCC_CMD_SKE_ENC = 0x23,
	YCC_CMD_SKE_DEC,
};

struct ycc_crypto_ctx {
	struct ycc_ring *ring;
	void *soft_tfm;

	u32 keysize;
	u32 key_dma_size; /* dma memory size for key/key+iv */

	u8 mode;
	u8 *cipher_key;
	u8 reserved[4];
};

struct ycc_crypto_req {
	int mapped_src_nents;
	int mapped_dst_nents;

	void *key_vaddr;
	dma_addr_t key_paddr;

	struct ycc_cmd_desc desc;
	struct skcipher_request *ske_req;
	struct skcipher_request ske_subreq;

	void *src_vaddr;
	dma_addr_t src_paddr;
	void *dst_vaddr;
	dma_addr_t dst_paddr;

	int in_len;
	int out_len;
	int aad_offset;
	struct ycc_crypto_ctx *ctx;
	u8 last_block[16]; /* used to store iv out when decrypt */
};

#define YCC_DEV(ctx)		(&(ctx)->ring->ydev->pdev->dev)

int ycc_sym_register(void);
void ycc_sym_unregister(void);
#endif
