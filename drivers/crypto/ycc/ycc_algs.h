// SPDX-License-Identifier: GPL-2.0
#ifndef __YCC_ALG_H
#define __YCC_ALG_H

#include <crypto/skcipher.h>
#include <crypto/aead.h>

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

#define MAX_DIGEST_SIZE		64

enum ycc_hash_alg_mode {
	YCC_HASH_SM3 = 0,
	YCC_HASH_MD5,
	YCC_HASH_SHA_256,
	YCC_HASH_SHA_384,
	YCC_HASH_SHA_512,
	YCC_HASH_SHA_1,
	YCC_HASH_SHA_224,
	YCC_HASH_SHA_512_224,
	YCC_HASH_SHA_512_256,
	YCC_HASH_SHA_3_224,
	YCC_HASH_SHA_3_256,
	YCC_HASH_SHA_3_384,
	YCC_HASH_SHA_3_512,
};

enum ycc_hmac_alg_mode {
	YCC_HMAC_SM3 = 0,
	YCC_HMAC_MD5,
	YCC_HMAC_SHA_256,
	YCC_HMAC_SHA_384,
	YCC_HMAC_SHA_512,
	YCC_HMAC_SHA_1,
	YCC_HMAC_SHA_224,
	YCC_HMAC_SHA_512_224,
	YCC_HMAC_SHA_512_256,
};

enum ycc_cmac_alg_mode {
	YCC_CBC_MAC_AES_128 = 18,
	YCC_CBC_MAC_AES_192,
	YCC_CBC_MAC_AES_256,
	YCC_CBC_MAC_SM4,

	YCC_CMAC_AES_128,
	YCC_CMAC_AES_192,
	YCC_CMAC_AES_256,
	YCC_CMAC_SM4,
};

enum ycc_cmd_id {
	YCC_CMD_GEN_HMAC_LEN0 = 0x17,
	YCC_CMD_VERIFY_HMAC_LEN0,
	YCC_CMD_GEN_CMAC_LEN0,
	YCC_CMD_VERIFY_CMAC_LEN0, /* 0x1a */

	YCC_CMD_GEN_CMAC = 0x21,
	YCC_CMD_VERIFY_CMAC,

	YCC_CMD_SKE_ENC = 0x23,
	YCC_CMD_SKE_DEC,

	YCC_CMD_GCM_ENC = 0x25,
	YCC_CMD_GCM_DEC,
	YCC_CMD_CCM_ENC,
	YCC_CMD_CCM_DEC, /* 0x28 */

	YCC_CMD_SM2_VERIFY = 0x47,

	YCC_CMD_RSA_ENC = 0x83,
	YCC_CMD_RSA_DEC,
	YCC_CMD_RSA_CRT_DEC,
	YCC_CMD_RSA_CRT_SIGN,
	YCC_CMD_RSA_SIGN,
	YCC_CMD_RSA_VERIFY, /* 0x88 */

	YCC_CMD_HASH = 0xa1,
	YCC_CMD_GEN_HMAC,
	YCC_CMD_VERIFY_HMAC, /* 0xa3 */
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
	struct ycc_crypto_ctx *ctx;
	u8 last_block[16]; /* used to store iv out when decrypt */

	/* soft request for fallback, keep at the end */
	union {
		struct skcipher_request ske_subreq;
		struct aead_request aead_subreq;
	};
};

#define YCC_RSA_KEY_SZ_512	64
#define YCC_RSA_KEY_SZ_1536	192
#define YCC_RSA_CRT_PARAMS	5
#define YCC_RSA_E_SZ_MAX	8
#define YCC_CMD_DATA_ALIGN_SZ	64
#define YCC_PIN_SZ		16

struct ycc_pke_ctx {
	struct rsa_key *rsa_key;

	void *priv_key_vaddr;
	dma_addr_t priv_key_paddr;
	void *pub_key_vaddr;
	dma_addr_t pub_key_paddr;

	unsigned int key_len;
	unsigned int e_len;
	bool crt_mode;
	struct ycc_ring *ring;
	struct crypto_akcipher *soft_tfm;
};

struct ycc_pke_req {
	void *src_vaddr;
	dma_addr_t src_paddr;
	void *dst_vaddr;
	dma_addr_t dst_paddr;

	struct ycc_cmd_desc desc;
	union {
		struct ycc_pke_ctx *ctx;
	};
	struct akcipher_request *req;
};

struct ycc_ahash_ctx {
	u8 mode;
	u8 *auth_key;
	dma_addr_t auth_key_paddr;
	u32 authsize;
	u8 key_type; /* reserved for kek */
	struct filling_data *filling_data;
	bool is_mac;
	struct shash_desc *shash;
	struct ycc_ring *ring;
};

struct filling_data {
	struct scatterlist *src_sg;
	struct page *sp; /* page for holding formatted plaintext */
	int snents;
	int sorder;
};

struct ycc_ahash_req {
	int mapped_src_nents;
	int mapped_dst_nents;
	void *source_vaddr;
	dma_addr_t source_paddr;
	void *result_vaddr; /* store digest */
	dma_addr_t result_paddr;
	struct ycc_cmd_desc desc;
	struct ahash_request *ahash_req;
	struct ycc_ahash_ctx *ctx;
};

#define YCC_DEV(ctx)		(&(ctx)->ring->ydev->pdev->dev)

int ycc_sym_register(void);
void ycc_sym_unregister(void);
int ycc_aead_register(void);
void ycc_aead_unregister(void);
int ycc_pke_register(void);
void ycc_pke_unregister(void);
int ycc_hash_register(void);
void ycc_hash_unregister(void);
#endif
