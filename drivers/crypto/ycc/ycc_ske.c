// SPDX-License-Identifier: GPL-2.0
#include <crypto/internal/des.h>
#include <crypto/scatterwalk.h>
#include <linux/dma-mapping.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/xts.h>
#include <crypto/sm4.h>
#include "ycc_algs.h"

static int ycc_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
			       unsigned int key_size, int mode,
			       unsigned int key_dma_size)
{
	struct ycc_crypto_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (ctx->cipher_key) {
		memset(ctx->cipher_key, 0, ctx->keysize);
	} else {
		ctx->cipher_key = kzalloc(key_size, GFP_KERNEL);
		if (!ctx->cipher_key)
			return -ENOMEM;
	}
	memcpy(ctx->cipher_key, key, key_size);
	ctx->mode = mode;
	ctx->keysize = key_size;
	ctx->key_dma_size = key_dma_size;

	if (ctx->soft_tfm && crypto_skcipher_setkey(ctx->soft_tfm, key, key_size))
		pr_warn("Failed to setkey for soft skcipher tfm\n");

	return 0;
}

#define DEFINE_YCC_SKE_AES_SETKEY(name, mode, size)			\
int ycc_skcipher_aes_##name##_setkey(struct crypto_skcipher *tfm,	\
				     const u8 *key,			\
				     unsigned int key_size)		\
{									\
	int alg_mode;							\
	switch (key_size) {						\
	case AES_KEYSIZE_128:						\
		alg_mode = YCC_AES_128_##mode;				\
		break;							\
	case AES_KEYSIZE_192:						\
		alg_mode = YCC_AES_192_##mode;				\
		break;							\
	case AES_KEYSIZE_256:						\
		alg_mode = YCC_AES_256_##mode;				\
		break;							\
	default:							\
		return -EINVAL;						\
	}								\
	return ycc_skcipher_setkey(tfm, key, key_size, alg_mode, size);	\
}

#define DEFINE_YCC_SKE_SM4_SETKEY(name, mode, size)			\
int ycc_skcipher_sm4_##name##_setkey(struct crypto_skcipher *tfm,	\
				     const u8 *key,			\
				     unsigned int key_size)		\
{									\
	int alg_mode = YCC_SM4_##mode;					\
	if (key_size != SM4_KEY_SIZE)					\
		return -EINVAL;						\
	return ycc_skcipher_setkey(tfm, key, key_size, alg_mode, size);	\
}

#define DEFINE_YCC_SKE_DES_SETKEY(name, mode, size)			\
int ycc_skcipher_des_##name##_setkey(struct crypto_skcipher *tfm,	\
				     const u8 *key,			\
				     unsigned int key_size)		\
{									\
	int alg_mode = YCC_DES_##mode;					\
	int ret;							\
	if (key_size != DES_KEY_SIZE)					\
		return -EINVAL;						\
	ret = verify_skcipher_des_key(tfm, key);			\
	if (ret)							\
		return ret;						\
	return ycc_skcipher_setkey(tfm, key, key_size, alg_mode, size);	\
}

#define DEFINE_YCC_SKE_3DES_SETKEY(name, mode, size)			\
int ycc_skcipher_3des_##name##_setkey(struct crypto_skcipher *tfm,	\
				      const u8 *key,			\
				      unsigned int key_size)		\
{									\
	int alg_mode = YCC_TDES_192_##mode;				\
	int ret;							\
	if (key_size != DES3_EDE_KEY_SIZE)				\
		return -EINVAL;						\
	ret = verify_skcipher_des3_key(tfm, key);			\
	if (ret)							\
		return ret;						\
	return ycc_skcipher_setkey(tfm, key, key_size, alg_mode, size);	\
}

/*
 * ECB: Only has 1 key, without IV, at least 32 bytes.
 * Others except XTS: |key|iv|, at least 48 bytes.
 */
DEFINE_YCC_SKE_AES_SETKEY(ecb, ECB, 32);
DEFINE_YCC_SKE_AES_SETKEY(cbc, CBC, 48);
DEFINE_YCC_SKE_AES_SETKEY(ctr, CTR, 48);
DEFINE_YCC_SKE_AES_SETKEY(cfb, CFB, 48);
DEFINE_YCC_SKE_AES_SETKEY(ofb, OFB, 48);

DEFINE_YCC_SKE_SM4_SETKEY(ecb, ECB, 32);
DEFINE_YCC_SKE_SM4_SETKEY(cbc, CBC, 48);
DEFINE_YCC_SKE_SM4_SETKEY(ctr, CTR, 48);
DEFINE_YCC_SKE_SM4_SETKEY(cfb, CFB, 48);
DEFINE_YCC_SKE_SM4_SETKEY(ofb, OFB, 48);

DEFINE_YCC_SKE_DES_SETKEY(ecb, ECB, 32);
DEFINE_YCC_SKE_DES_SETKEY(cbc, CBC, 48);
DEFINE_YCC_SKE_DES_SETKEY(ctr, CTR, 48);
DEFINE_YCC_SKE_DES_SETKEY(cfb, CFB, 48);
DEFINE_YCC_SKE_DES_SETKEY(ofb, OFB, 48);

DEFINE_YCC_SKE_3DES_SETKEY(ecb, ECB, 32);
DEFINE_YCC_SKE_3DES_SETKEY(cbc, CBC, 48);
DEFINE_YCC_SKE_3DES_SETKEY(ctr, CTR, 48);
DEFINE_YCC_SKE_3DES_SETKEY(cfb, CFB, 48);
DEFINE_YCC_SKE_3DES_SETKEY(ofb, OFB, 48);

int ycc_skcipher_aes_xts_setkey(struct crypto_skcipher *tfm,
				const u8 *key,
				unsigned int key_size)
{
	int alg_mode;
	int ret;

	ret = xts_verify_key(tfm, key, key_size);
	if (ret)
		return ret;

	switch (key_size) {
	case AES_KEYSIZE_128 * 2:
		alg_mode = YCC_AES_128_XTS;
		break;
	case AES_KEYSIZE_256 * 2:
		alg_mode = YCC_AES_256_XTS;
		break;
	default:
		return -EINVAL;
	}

	/* XTS: |key1|key2|iv|, at least 32 + 32 + 16 bytes */
	return ycc_skcipher_setkey(tfm, key, key_size, alg_mode, 80);
}

int ycc_skcipher_sm4_xts_setkey(struct crypto_skcipher *tfm,
				const u8 *key,
				unsigned int key_size)
{
	int alg_mode;
	int ret;

	ret = xts_verify_key(tfm, key, key_size);
	if (ret)
		return ret;

	if (key_size != SM4_KEY_SIZE * 2)
		return -EINVAL;

	alg_mode = YCC_SM4_XTS;
	return ycc_skcipher_setkey(tfm, key, key_size, alg_mode, 80);
}

static int ycc_skcipher_fill_key(struct ycc_crypto_req *req)
{
	struct ycc_crypto_ctx *ctx = req->ctx;
	struct device *dev = YCC_DEV(ctx);
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req->ske_req);
	u32 ivsize = crypto_skcipher_ivsize(tfm);

	if (!req->key_vaddr) {
		req->key_vaddr = dma_alloc_coherent(dev, ALIGN(ctx->key_dma_size, 64),
						    &req->key_paddr, GFP_ATOMIC);
		if (!req->key_vaddr)
			return -ENOMEM;
	}

	memset(req->key_vaddr, 0, ALIGN(ctx->key_dma_size, 64));
	/* XTS Mode has 2 keys & 1 iv */
	if (ctx->key_dma_size == 80) {
		memcpy(req->key_vaddr + (32 - ctx->keysize / 2),
		       ctx->cipher_key, ctx->keysize / 2);
		memcpy(req->key_vaddr + (64 - ctx->keysize / 2),
		       ctx->cipher_key + ctx->keysize / 2, ctx->keysize / 2);
	} else {
		memcpy(req->key_vaddr + (32 - ctx->keysize), ctx->cipher_key,
		       ctx->keysize);
	}

	if (ivsize) {
		if (ctx->mode == YCC_DES_ECB ||
		    ctx->mode == YCC_TDES_128_ECB ||
		    ctx->mode == YCC_TDES_192_ECB ||
		    ctx->mode == YCC_AES_128_ECB ||
		    ctx->mode == YCC_AES_192_ECB ||
		    ctx->mode == YCC_AES_256_ECB ||
		    ctx->mode == YCC_SM4_ECB) {
			pr_err("Illegal ivsize for ECB mode, should be zero");
			goto clear_key;
		}

		/* DES or 3DES */
		if (ctx->mode >= YCC_DES_ECB && ctx->mode <= YCC_TDES_192_CTR) {
			if (ivsize > 8)
				goto clear_key;
			memcpy(req->key_vaddr + ctx->key_dma_size - 8,
			       req->ske_req->iv, ivsize);
		} else {
			memcpy(req->key_vaddr + ctx->key_dma_size - 16,
			       req->ske_req->iv, ivsize);
		}
	}

	return 0;
clear_key:
	memset(req->key_vaddr, 0, ALIGN(ctx->key_dma_size, 64));
	dma_free_coherent(dev, ctx->key_dma_size, req->key_vaddr, req->key_paddr);
	req->key_vaddr = NULL;
	return -EINVAL;
}

static int ycc_skcipher_sg_map(struct ycc_crypto_req *req)
{
	struct device *dev = YCC_DEV(req->ctx);
	struct skcipher_request *ske_req = req->ske_req;
	int src_nents;

	src_nents = sg_nents_for_len(ske_req->src, ske_req->cryptlen);
	if (unlikely(src_nents <= 0)) {
		pr_err("Failed to get src sg len\n");
		return -EINVAL;
	}

	req->src_vaddr = dma_alloc_coherent(dev, ALIGN(req->in_len, 64),
					    &req->src_paddr, GFP_ATOMIC);
	if (!req->src_vaddr)
		return -ENOMEM;

	req->dst_vaddr = dma_alloc_coherent(dev, ALIGN(req->in_len, 64),
					    &req->dst_paddr, GFP_ATOMIC);
	if (!req->dst_vaddr) {
		dma_free_coherent(dev, ALIGN(req->in_len, 64),
				  req->src_vaddr, req->src_paddr);
		return -ENOMEM;
	}

	sg_copy_to_buffer(ske_req->src, src_nents, req->src_vaddr, ske_req->cryptlen);
	return 0;
}

static inline void ycc_skcipher_sg_unmap(struct ycc_crypto_req *req)
{
	struct device *dev = YCC_DEV(req->ctx);

	dma_free_coherent(dev, ALIGN(req->in_len, 64), req->src_vaddr, req->src_paddr);
	dma_free_coherent(dev, ALIGN(req->in_len, 64), req->dst_vaddr, req->dst_paddr);
}

/*
 * For CBC & CTR
 */
static void ycc_skcipher_iv_out(struct ycc_crypto_req *req, void *dst)
{
	struct skcipher_request *ske_req = req->ske_req;
	struct crypto_skcipher *stfm = crypto_skcipher_reqtfm(ske_req);
	u8 bs = crypto_skcipher_blocksize(stfm);
	u8 mode = req->ctx->mode;
	u8 cmd = req->desc.cmd.ske_cmd.cmd_id;
	u32 nb = (ske_req->cryptlen + bs - 1) / bs;

	switch (mode) {
	case YCC_DES_CBC:
	case YCC_TDES_128_CBC:
	case YCC_TDES_192_CBC:
	case YCC_AES_128_CBC:
	case YCC_AES_192_CBC:
	case YCC_AES_256_CBC:
	case YCC_SM4_CBC:
		if (cmd == YCC_CMD_SKE_DEC)
			memcpy(ske_req->iv, req->last_block, bs);
		else
			memcpy(ske_req->iv,
			       (u8 *)dst + ALIGN(ske_req->cryptlen, bs) - bs,
			       bs);
		break;
	case YCC_DES_CTR:
	case YCC_TDES_128_CTR:
	case YCC_TDES_192_CTR:
	case YCC_AES_128_CTR:
	case YCC_AES_192_CTR:
	case YCC_AES_256_CTR:
	case YCC_SM4_CTR:
		for ( ; nb-- ; )
			crypto_inc(ske_req->iv, bs);
		break;
	default:
		return;
	}
}

static int ycc_skcipher_callback(void *ptr, u16 state)
{
	struct ycc_crypto_req *req = (struct ycc_crypto_req *)ptr;
	struct skcipher_request *ske_req = req->ske_req;
	struct ycc_crypto_ctx *ctx = req->ctx;
	struct device *dev = YCC_DEV(ctx);

	sg_copy_from_buffer(ske_req->dst,
			    sg_nents_for_len(ske_req->dst, ske_req->cryptlen),
			    req->dst_vaddr, ske_req->cryptlen);

	if (state == CMD_SUCCESS)
		ycc_skcipher_iv_out(req, req->dst_vaddr);

	ycc_skcipher_sg_unmap(req);

	if (req->key_vaddr) {
		memset(req->key_vaddr, 0, ALIGN(ctx->key_dma_size, 64));
		dma_free_coherent(dev, ALIGN(ctx->key_dma_size, 64),
				  req->key_vaddr, req->key_paddr);
		req->key_vaddr = NULL;
	}
	if (ske_req->base.complete)
		ske_req->base.complete(&ske_req->base,
				       state == CMD_SUCCESS ? 0 : -EBADMSG);

	return 0;
}

static inline bool ycc_skcipher_do_soft(struct ycc_dev *ydev)
{
	return !test_bit(YDEV_STATUS_READY, &ydev->status);
}

static int ycc_skcipher_submit_desc(struct skcipher_request *ske_req, u8 cmd)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(ske_req);
	struct ycc_crypto_req *req = skcipher_request_ctx(ske_req);
	struct ycc_skcipher_cmd *ske_cmd = &req->desc.cmd.ske_cmd;
	struct ycc_crypto_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct ycc_flags *aflags;
	u8 bs = crypto_skcipher_blocksize(tfm);
	int ret;

	memset(req, 0, sizeof(*req));
	req->ctx = ctx;
	req->ske_req = ske_req;
	req->in_len = ALIGN(ske_req->cryptlen, bs);

	/*
	 * The length of request, 64n + bs, may lead the device hung.
	 * So append one bs here. This is a workaround for hardware issue.
	 */
	if (req->in_len % 64 == bs)
		req->in_len += bs;

	ret = ycc_skcipher_fill_key(req);
	if (ret)
		return ret;

	ret = ycc_skcipher_sg_map(req);
	if (ret)
		goto free_key;

	ret = -ENOMEM;
	aflags = kzalloc(sizeof(struct ycc_flags), GFP_ATOMIC);
	if (!aflags)
		goto sg_unmap;

	aflags->ptr = (void *)req;
	aflags->ycc_done_callback = ycc_skcipher_callback;

	req->desc.private_ptr = (u64)aflags;
	ske_cmd->cmd_id  = cmd;
	ske_cmd->mode    = ctx->mode;
	ske_cmd->sptr    = req->src_paddr;
	ske_cmd->dptr    = req->dst_paddr;
	ske_cmd->dlen    = req->in_len;
	ske_cmd->keyptr  = req->key_paddr;
	ske_cmd->padding = 0;

	/* LKCF will check iv output, for decryption, the iv is its last block */
	if (cmd == YCC_CMD_SKE_DEC)
		memcpy(req->last_block,
		       req->src_vaddr + ALIGN(ske_req->cryptlen, bs) - bs, bs);

	ret = ycc_enqueue(ctx->ring, &req->desc);
	if (!ret)
		return -EINPROGRESS;

	pr_debug("Failed to submit desc to ring\n");
	kfree(aflags);

sg_unmap:
	ycc_skcipher_sg_unmap(req);
free_key:
	memset(req->key_vaddr, 0, ALIGN(ctx->key_dma_size, 64));
	dma_free_coherent(YCC_DEV(ctx),
			  ALIGN(ctx->key_dma_size, 64),
			  req->key_vaddr, req->key_paddr);
	req->key_vaddr = NULL;
	return ret;
}

static int ycc_skcipher_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct ycc_crypto_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_request *subreq =
		&((struct ycc_crypto_req *)skcipher_request_ctx(req))->ske_subreq;

	if (ycc_skcipher_do_soft(ctx->ring->ydev)) {
		skcipher_request_set_tfm(subreq, ctx->soft_tfm);
		skcipher_request_set_callback(subreq, req->base.flags,
					      req->base.complete, req->base.data);
		skcipher_request_set_crypt(subreq, req->src, req->dst,
					   req->cryptlen, req->iv);
		return crypto_skcipher_encrypt(subreq);
	}

	return ycc_skcipher_submit_desc(req, YCC_CMD_SKE_ENC);
}

static int ycc_skcipher_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct ycc_crypto_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_request *subreq =
		&((struct ycc_crypto_req *)skcipher_request_ctx(req))->ske_subreq;

	if (ycc_skcipher_do_soft(ctx->ring->ydev)) {
		skcipher_request_set_tfm(subreq, ctx->soft_tfm);
		skcipher_request_set_callback(subreq, req->base.flags,
					      req->base.complete, req->base.data);
		skcipher_request_set_crypt(subreq, req->src, req->dst,
					   req->cryptlen, req->iv);
		return crypto_skcipher_encrypt(subreq);
	}

	return ycc_skcipher_submit_desc(req, YCC_CMD_SKE_DEC);
}

static int ycc_skcipher_init(struct crypto_skcipher *tfm)
{
	struct ycc_crypto_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct ycc_ring *ring;

	ctx->soft_tfm = crypto_alloc_skcipher(crypto_tfm_alg_name(crypto_skcipher_tfm(tfm)), 0,
					      CRYPTO_ALG_NEED_FALLBACK | CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->soft_tfm)) {
		pr_warn("Failed to allocate soft tfm for:%s, software fallback is limited\n",
			crypto_tfm_alg_name(crypto_skcipher_tfm(tfm)));
		ctx->soft_tfm = NULL;
		crypto_skcipher_set_reqsize(tfm, sizeof(struct ycc_crypto_req));
	} else {
		/*
		 * If it's software fallback, store meta data of soft request.
		 */
		crypto_skcipher_set_reqsize(tfm, sizeof(struct ycc_crypto_req) +
					    crypto_skcipher_reqsize(ctx->soft_tfm));
	}

	ring = ycc_crypto_get_ring();
	if (!ring)
		return -ENOMEM;

	ctx->ring = ring;
	return 0;
}

static void ycc_skcipher_exit(struct crypto_skcipher *tfm)
{
	struct ycc_crypto_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (ctx->ring)
		ycc_crypto_free_ring(ctx->ring);

	kfree(ctx->cipher_key);

	if (ctx->soft_tfm)
		crypto_free_skcipher((struct crypto_skcipher *)ctx->soft_tfm);
}


static struct skcipher_alg ycc_skciphers[] = {
	{
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "ycc_cbc(aes)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_aes_cbc_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ecb(aes)",
			.cra_driver_name = "ycc_ecb(aes)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_aes_ecb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = 0,
	},
	{
		.base = {
			.cra_name = "ctr(aes)",
			.cra_driver_name = "ycc_ctr(aes)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_aes_ctr_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cfb(aes)",
			.cra_driver_name = "ycc_cfb(aes)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_aes_cfb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ofb(aes)",
			.cra_driver_name = "ycc_ofb(aes)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_aes_ofb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "xts(aes)",
			.cra_driver_name = "ycc_xts(aes)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_aes_xts_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE * 2,
		.max_keysize = AES_MAX_KEY_SIZE * 2,
		.ivsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cbc(sm4)",
			.cra_driver_name = "ycc_cbc(sm4)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_sm4_cbc_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ecb(sm4)",
			.cra_driver_name = "ycc_ecb(sm4)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_sm4_ecb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = 0,
	},
	{
		.base = {
			.cra_name = "ctr(sm4)",
			.cra_driver_name = "ycc_ctr(sm4)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_sm4_ctr_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cfb(sm4)",
			.cra_driver_name = "ycc_cfb(sm4)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_sm4_cfb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ofb(sm4)",
			.cra_driver_name = "ycc_ofb(sm4)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_sm4_ofb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = SM4_KEY_SIZE,
		.max_keysize = SM4_KEY_SIZE,
		.ivsize = SM4_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "xts(sm4)",
			.cra_driver_name = "ycc_xts(sm4)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = SM4_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_sm4_xts_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = SM4_KEY_SIZE * 2,
		.max_keysize = SM4_KEY_SIZE * 2,
		.ivsize = SM4_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "ycc_cbc(des)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_des_cbc_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ecb(des)",
			.cra_driver_name = "ycc_ecb(des)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_des_ecb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = 0,
	},
	{
		.base = {
			.cra_name = "ctr(des)",
			.cra_driver_name = "ycc_ctr(des)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_des_ctr_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cfb(des)",
			.cra_driver_name = "ycc_cfb(des)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_des_cfb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ofb(des)",
			.cra_driver_name = "ycc_ofb(des)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_des_ofb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "ycc_cbc(des3_ede)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_3des_cbc_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ecb(des3_ede)",
			.cra_driver_name = "ycc_ecb(des3_ede)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_3des_ecb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = 0,
	},
	{
		.base = {
			.cra_name = "ctr(des3_ede)",
			.cra_driver_name = "ycc_ctr(des3_ede)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_3des_ctr_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "cfb(des3_ede)",
			.cra_driver_name = "ycc_cfb(des3_ede)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_3des_cfb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ofb(des3_ede)",
			.cra_driver_name = "ycc_ofb(des3_ede)",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct ycc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = ycc_skcipher_init,
		.exit = ycc_skcipher_exit,
		.setkey = ycc_skcipher_3des_ofb_setkey,
		.encrypt = ycc_skcipher_encrypt,
		.decrypt = ycc_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
	},
};

int ycc_sym_register(void)
{
	return crypto_register_skciphers(ycc_skciphers, ARRAY_SIZE(ycc_skciphers));
}

void ycc_sym_unregister(void)
{
	crypto_unregister_skciphers(ycc_skciphers, ARRAY_SIZE(ycc_skciphers));
}
