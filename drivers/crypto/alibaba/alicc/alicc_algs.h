// SPDX-License-Identifier: GPL-2.0
#ifndef __ALICC_ALG_H
#define __ALICC_ALG_H

#include <crypto/skcipher.h>
#include <crypto/aead.h>

#include "alicc_ring.h"
#include "alicc_dev.h"

enum alicc_gcm_mode {
	ALICC_AES_128_GCM = 0,
	ALICC_AES_192_GCM,
	ALICC_AES_256_GCM,
	ALICC_SM4_GCM,
};

enum alicc_ccm_mode {
	ALICC_AES_128_CCM = 0,
	ALICC_AES_192_CCM,
	ALICC_AES_256_CCM,
	ALICC_SM4_CCM,
};

enum alicc_ske_alg_mode {
	ALICC_DES_ECB = 26,
	ALICC_DES_CBC,
	ALICC_DES_CFB,
	ALICC_DES_OFB,
	ALICC_DES_CTR, /* 30 */

	ALICC_TDES_128_ECB = 31,
	ALICC_TDES_128_CBC,
	ALICC_TDES_128_CFB,
	ALICC_TDES_128_OFB,
	ALICC_TDES_128_CTR,
	ALICC_TDES_192_ECB,
	ALICC_TDES_192_CBC,
	ALICC_TDES_192_CFB,
	ALICC_TDES_192_OFB,
	ALICC_TDES_192_CTR, /* 40 */

	ALICC_AES_128_ECB = 41,
	ALICC_AES_128_CBC,
	ALICC_AES_128_CFB,
	ALICC_AES_128_OFB,
	ALICC_AES_128_CTR,
	ALICC_AES_128_XTS, /* 46 */

	ALICC_AES_192_ECB = 48,
	ALICC_AES_192_CBC,
	ALICC_AES_192_CFB,
	ALICC_AES_192_OFB,
	ALICC_AES_192_CTR, /* 52 */

	ALICC_AES_256_ECB = 55,
	ALICC_AES_256_CBC,
	ALICC_AES_256_CFB,
	ALICC_AES_256_OFB,
	ALICC_AES_256_CTR,
	ALICC_AES_256_XTS, /* 60 */

	ALICC_SM4_ECB = 62,
	ALICC_SM4_CBC,
	ALICC_SM4_CFB,
	ALICC_SM4_OFB,
	ALICC_SM4_CTR,
	ALICC_SM4_XTS, /* 67 */
};

enum alicc_cmd_id {
	ALICC_CMD_SKE_ENC = 0x23,
	ALICC_CMD_SKE_DEC,

	ALICC_CMD_GCM_ENC = 0x25,
	ALICC_CMD_GCM_DEC,
	ALICC_CMD_CCM_ENC,
	ALICC_CMD_CCM_DEC, /* 0x28 */

	ALICC_CMD_SM2_VERIFY = 0x47,

	ALICC_CMD_RSA_ENC = 0x83,
	ALICC_CMD_RSA_DEC,
	ALICC_CMD_RSA_CRT_DEC,
	ALICC_CMD_RSA_CRT_SIGN,
	ALICC_CMD_RSA_SIGN,
	ALICC_CMD_RSA_VERIFY, /* 0x88 */
};

struct alicc_crypto_ctx {
	struct alicc_ring *ring;
	void *soft_tfm;

	u32 keysize;
	u32 key_dma_size; /* dma memory size for key/key+iv */

	u8 mode;
	u8 *cipher_key;
	u8 reserved[4];
};

struct alicc_crypto_req {
	int mapped_src_nents;
	int mapped_dst_nents;

	void *key_vaddr;
	dma_addr_t key_paddr;

	struct alicc_cmd_desc desc;
	union {
		struct skcipher_request *ske_req;
		struct aead_request *aead_req;
	};

	void *src_vaddr;
	dma_addr_t src_paddr;
	void *dst_vaddr;
	dma_addr_t dst_paddr;

	int in_len;
	int out_len;
	int aad_offset;
	struct alicc_crypto_ctx *ctx;
	u8 last_block[16]; /* used to store iv out when decrypt */

	/* soft request for fallback, keep at the end */
	union {
		struct skcipher_request ske_subreq;
		struct aead_request aead_subreq;
	};
};

#define ALICC_RSA_KEY_SZ_512	64
#define ALICC_RSA_KEY_SZ_1536	192
#define ALICC_RSA_CRT_PARAMS	5
#define ALICC_RSA_E_SZ_MAX	8
#define ALICC_CMD_DATA_ALIGN_SZ	64
#define ALICC_PIN_SZ		16

struct alicc_pke_ctx {
	struct rsa_key *rsa_key;

	void *priv_key_vaddr;
	dma_addr_t priv_key_paddr;
	void *pub_key_vaddr;
	dma_addr_t pub_key_paddr;

	unsigned int key_len;
	unsigned int e_len;
	bool crt_mode;
	struct alicc_ring *ring;
	struct crypto_akcipher *soft_tfm;
};

struct alicc_pke_req {
	void *src_vaddr;
	dma_addr_t src_paddr;
	void *dst_vaddr;
	dma_addr_t dst_paddr;

	struct alicc_cmd_desc desc;
	union {
		struct alicc_pke_ctx *ctx;
	};
	struct akcipher_request *req;
};

#define ALICC_DEV(ctx)		(&(ctx)->ring->ydev->pdev->dev)

int alicc_sym_register(void);
void alicc_sym_unregister(void);
int alicc_aead_register(void);
void alicc_aead_unregister(void);
int alicc_pke_register(void);
void alicc_pke_unregister(void);
#endif
