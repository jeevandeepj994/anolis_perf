// SPDX-License-Identifier: GPL-2.0
#include <crypto/internal/aead.h>
#include <crypto/internal/des.h>
#include <crypto/scatterwalk.h>
#include <linux/dma-mapping.h>
#include <linux/crypto.h>
#include <crypto/aes.h>
#include <crypto/gcm.h>
#include <crypto/sm4.h>
#include "alicc_algs.h"

static int alicc_aead_init(struct crypto_aead *tfm)
{
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct alicc_ring *ring;

	ctx->soft_tfm = crypto_alloc_aead(crypto_tfm_alg_name(crypto_aead_tfm(tfm)),
					  0,
					  CRYPTO_ALG_NEED_FALLBACK | CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->soft_tfm)) {
		pr_warn("Failed to allocate soft tfm for:%s, software fallback is limited\n",
			crypto_tfm_alg_name(crypto_aead_tfm(tfm)));
		ctx->soft_tfm = NULL;
		crypto_aead_set_reqsize(tfm, sizeof(struct alicc_crypto_req));
	} else {
		/*
		 * If it's software fallback, store meta data of soft request.
		 */
		crypto_aead_set_reqsize(tfm, sizeof(struct alicc_crypto_req) +
					crypto_aead_reqsize(ctx->soft_tfm));
	}

	ring = alicc_crypto_get_ring();
	if (!ring)
		return -ENOMEM;

	ctx->ring = ring;
	return 0;
}

static void alicc_aead_exit(struct crypto_aead *tfm)
{
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);

	if (ctx->ring)
		alicc_crypto_free_ring(ctx->ring);

	kfree(ctx->cipher_key);

	if (ctx->soft_tfm)
		crypto_free_aead((struct crypto_aead *)ctx->soft_tfm);
}

static int alicc_aead_setkey(struct crypto_aead *tfm, const u8 *key,
			   unsigned int key_size)
{
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	const char *alg_name = crypto_tfm_alg_name(&tfm->base);

	if (!strncmp("gcm(sm4)", alg_name, strlen("gcm(sm4)"))) {
		if (key_size != SM4_KEY_SIZE)
			return -EINVAL;
		ctx->mode = ALICC_SM4_GCM;
	} else if (!strncmp("ccm(sm4)", alg_name, strlen("ccm(sm4)"))) {
		ctx->mode = ALICC_SM4_CCM;
	} else if (!strncmp("gcm(aes)", alg_name, strlen("gcm(aes)"))) {
		switch (key_size) {
		case AES_KEYSIZE_128:
			ctx->mode = ALICC_AES_128_GCM;
			break;
		case AES_KEYSIZE_192:
			ctx->mode = ALICC_AES_192_GCM;
			break;
		case AES_KEYSIZE_256:
			ctx->mode = ALICC_AES_256_GCM;
			break;
		default:
			return -EINVAL;
		}
	} else if (!strncmp("ccm(aes)", alg_name, strlen("ccm(aes)"))) {
		switch (key_size) {
		case AES_KEYSIZE_128:
			ctx->mode = ALICC_AES_128_CCM;
			break;
		case AES_KEYSIZE_192:
			ctx->mode = ALICC_AES_192_CCM;
			break;
		case AES_KEYSIZE_256:
			ctx->mode = ALICC_AES_256_CCM;
			break;
		default:
			return -EINVAL;
		}
	}

	if (ctx->cipher_key) {
		memset(ctx->cipher_key, 0, ctx->keysize);
	} else {
		ctx->cipher_key = kzalloc(key_size, GFP_KERNEL);
		if (!ctx->cipher_key)
			return -ENOMEM;
	}

	memcpy(ctx->cipher_key, key, key_size);
	ctx->keysize = key_size;
	if (ctx->soft_tfm) {
		if (crypto_aead_setkey(ctx->soft_tfm, key, key_size))
			pr_warn("Failed to setkey for soft aead tfm\n");
	}

	return 0;
}

static int alicc_aead_fill_key(struct alicc_crypto_req *req)
{
	struct alicc_crypto_ctx *ctx = req->ctx;
	struct device *dev = ALICC_DEV(ctx);
	struct aead_request *aead_req = req->aead_req;
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	const char *alg_name = crypto_tfm_alg_name(&tfm->base);
	int iv_len = 12;

	if (!strncmp("ccm", alg_name, strlen("ccm")))
		iv_len = 16;

	if (!req->key_vaddr) {
		req->key_vaddr = dma_alloc_coherent(dev, 64, &req->key_paddr,
						    GFP_ATOMIC);
		if (!req->key_vaddr)
			return -ENOMEM;
	}

	memset(req->key_vaddr, 0, 64);
	memcpy(req->key_vaddr + (32 - ctx->keysize), ctx->cipher_key, ctx->keysize);
	memcpy(req->key_vaddr + 32, req->aead_req->iv, iv_len);
	ctx->key_dma_size = 64;

	return 0;
}

static int alicc_aead_sg_map(struct alicc_crypto_req *req)
{
	struct device *dev = ALICC_DEV(req->ctx);
	int ret = -ENOMEM;

	req->src_paddr = dma_map_single(dev, req->src_vaddr,
					ALIGN(req->in_len, 64), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, req->src_paddr)) {
		pr_err("Failed to map src dma memory\n");
		goto out;
	}

	req->dst_vaddr = dma_alloc_coherent(dev, ALIGN(req->out_len, 64),
					    &req->dst_paddr, GFP_ATOMIC);
	if (!req->dst_vaddr)
		goto unmap_src;

	return 0;
unmap_src:
	dma_unmap_single(dev, req->src_paddr,
			 ALIGN(req->in_len, 64), DMA_TO_DEVICE);
out:
	return ret;
}

static void alicc_aead_sg_unmap(struct alicc_crypto_req *req)
{
	struct device *dev = ALICC_DEV(req->ctx);

	dma_unmap_single(dev, req->src_paddr, ALIGN(req->in_len, 64), DMA_TO_DEVICE);
	dma_free_coherent(dev, ALIGN(req->in_len, 64),
			  req->dst_vaddr, req->dst_paddr);
}

static inline void alicc_aead_unformat_data(struct alicc_crypto_req *req)
{
	kfree(req->src_vaddr);
}

static int alicc_aead_callback(void *ptr, u16 state)
{
	struct alicc_crypto_req *req = (struct alicc_crypto_req *)ptr;
	struct aead_request *aead_req = req->aead_req;
	struct alicc_crypto_ctx *ctx = req->ctx;
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	int taglen = crypto_aead_authsize(tfm);
	struct device *dev = ALICC_DEV(ctx);

	/* TODO: workaround for GCM/CCM with junk bytes between ctext and tag */
	if ((req->desc.cmd.aead_cmd.cmd_id == ALICC_CMD_GCM_ENC ||
	     req->desc.cmd.aead_cmd.cmd_id == ALICC_CMD_CCM_ENC) &&
	     aead_req->cryptlen % 16 != 0)
		memcpy(req->dst_vaddr + aead_req->cryptlen,
		       req->dst_vaddr + ALIGN(aead_req->cryptlen, 16), taglen);
	scatterwalk_map_and_copy(req->src_vaddr + req->aad_offset, aead_req->dst, 0,
				 aead_req->assoclen, 1);
	if (req->desc.cmd.aead_cmd.cmd_id == ALICC_CMD_GCM_ENC ||
	    req->desc.cmd.aead_cmd.cmd_id == ALICC_CMD_CCM_ENC) {
		scatterwalk_map_and_copy(req->dst_vaddr, aead_req->dst,
					 aead_req->assoclen,
					 aead_req->cryptlen + taglen, 1);
	} else {
		scatterwalk_map_and_copy(req->dst_vaddr, aead_req->dst,
					 aead_req->assoclen,
					 aead_req->cryptlen - taglen, 1);
	}

	alicc_aead_sg_unmap(req);
	alicc_aead_unformat_data(req);
	if (req->key_vaddr) {
		memset(req->key_vaddr, 0, 64);
		dma_free_coherent(dev, 64, req->key_vaddr, req->key_paddr);
		req->key_vaddr = NULL;
	}

	if (aead_req->base.complete)
		aead_req->base.complete(&aead_req->base, state == CMD_SUCCESS ? 0 : -EBADMSG);

	return 0;
}

#define aead_blob_len(x, y, z)	ALIGN(((x) + (y) + (z)), 16)

static void *__alicc_aead_format_data(struct alicc_crypto_req *req, u8 *b0, u8 *b1,
				    int alen, u8 cmd)
{
	struct aead_request *aead_req = req->aead_req;
	int aad_len = aead_req->assoclen;
	int cryptlen = aead_req->cryptlen;
	int taglen = crypto_aead_authsize(crypto_aead_reqtfm(aead_req));
	int src_len = cryptlen;
	int b0_len = 0;
	void *vaddr;
	int size;

	/* b0 != NULL means ccm, b0 len is 16 bytes */
	if (b0)
		b0_len = 16;

	size = aead_blob_len(b0_len, alen, aad_len);
	if (cmd == ALICC_CMD_GCM_DEC || cmd == ALICC_CMD_CCM_DEC) {
		/*
		 * LKCF format is not aligned |cipher_text|tag_text|
		 * while alicc request |16-align cipher_text|16-align tag_text|
		 */
		src_len = cryptlen - taglen;
		size += ALIGN(src_len, 16) + ALIGN(taglen, 16);
	} else {
		size += ALIGN(cryptlen, 16);
	}

	vaddr = kzalloc(ALIGN(size, 64), GFP_ATOMIC);
	if (!vaddr)
		return NULL;

	if (b0)
		memcpy(vaddr, b0, b0_len);
	if (b1)
		memcpy(vaddr + b0_len, b1, alen);
	scatterwalk_map_and_copy(vaddr + b0_len + alen, aead_req->src, 0,
				 aad_len, 0);
	scatterwalk_map_and_copy(vaddr + aead_blob_len(b0_len, alen, aad_len),
				 aead_req->src, aad_len,
				 src_len, 0);
	if (cmd == ALICC_CMD_GCM_DEC || cmd == ALICC_CMD_CCM_DEC)
		scatterwalk_map_and_copy(vaddr +
					 aead_blob_len(b0_len, alen, aad_len) +
					 ALIGN(src_len, 16),
					 aead_req->src, aad_len + cryptlen - taglen,
					 taglen, 0);

	req->in_len = size;
	req->aad_offset = b0_len + alen;
	return vaddr;
}

static void *alicc_aead_format_ccm_data(struct alicc_crypto_req *req,
				      u16 *new_aad_len, u8 cmd)
{
	struct aead_request *aead_req = req->aead_req;
	int aad_len = aead_req->assoclen;
	int cryptlen = aead_req->cryptlen;
	int taglen = crypto_aead_authsize(crypto_aead_reqtfm(aead_req));
	u8 b0[16] = {0};
	u8 b1[10] = {0}; /* Store encoded aad length */
	u8 alen = 0;
	int l;
	__be32 msglen;

	/* 1. check iv value aead_req->iv[0] = L - 1 */
	/* TODO: may need also check tag length: 4,6,8,10,12,14,16 */
	if (aead_req->iv[0] < 1 || aead_req->iv[0] > 7) {
		pr_err("L value is not valid for CCM\n");
		return NULL;
	}

	l = aead_req->iv[0] + 1;

	/* 2. format control infomration and nonce */
	memcpy(b0, aead_req->iv, 16); /* iv max size is 15 - L */
	b0[0] |= (((taglen - 2) / 2) << 3);
	if (aad_len) {
		b0[0] |= (1 << 6);
		if (aad_len < 65280) {
			/* 2 bytes encode aad length */
			*(__be16 *)b1 = cpu_to_be16(aad_len);
			alen = 2;
		} else if (aad_len < (2 << 31)) {
			*(__be16 *)b1 = cpu_to_be16(0xfffe);
			*(__be32 *)&b1[2] = cpu_to_be32(aad_len);
			alen = 6;
		} else {
			*(__be16 *)b1 = cpu_to_be16(0xffff);
			*(__be64 *)&b1[2] = cpu_to_be64(aad_len);
			alen = 10;
		}
		*new_aad_len = ALIGN((16 + alen + aad_len), 16);
	} else {
		*new_aad_len = 16;
	}
	b0[0] |= aead_req->iv[0];

	/* 3. set msg length. L - 1 Bytes store msg length */
	if (l >= 4)
		l = 4;
	else if (cryptlen > (1 << (8 * l)))
		return NULL;
	if (cmd == ALICC_CMD_CCM_DEC)
		msglen = cpu_to_be32(cryptlen - taglen);
	else
		msglen = cpu_to_be32(cryptlen);
	memcpy(&b0[16 - l], (u8 *)&msglen + 4 - l, l);

	return __alicc_aead_format_data(req, b0, b1, alen, cmd);
}

static void *alicc_aead_format_data(struct alicc_crypto_req *req, u16 *new_aad_len,
				  u32 *new_cryptlen, u8 cmd)
{
	struct aead_request *aead_req = req->aead_req;
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	int taglen = crypto_aead_authsize(tfm);

	if (cmd == ALICC_CMD_GCM_ENC || cmd == ALICC_CMD_GCM_DEC) {
		/* CCM */
		*new_aad_len = aead_req->assoclen;
		*new_cryptlen = aead_req->cryptlen;
		req->out_len = *new_cryptlen + taglen;
		return __alicc_aead_format_data(req, NULL, NULL, 0, cmd);
	}

	/* GCM */
	*new_cryptlen = ALIGN(aead_req->cryptlen, 16);
	req->out_len = *new_cryptlen + taglen;
	return alicc_aead_format_ccm_data(req, new_aad_len, cmd);
}

/*
 * This is workaround: If alicc output len is outlen % 64 == 16, it
 * might hang. taglen is 16 or 0
 */
static inline bool alicc_aead_do_soft(struct aead_request *aead_req, int taglen)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct alicc_dev *ydev = ctx->ring->ydev;

	if ((ALIGN(aead_req->cryptlen, 64) + taglen) % 64 == 16 ||
	    !test_bit(YDEV_STATUS_READY, &ydev->status))
		return true;

	return false;
}

static int alicc_aead_submit_desc(struct aead_request *aead_req, u8 cmd)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct alicc_crypto_req *req = aead_request_ctx(aead_req);
	struct alicc_flags *aflags;
	int taglen = crypto_aead_authsize(tfm);
	u16 new_aad_len;
	u32 new_cryptlen;
	struct crypto_aes_ctx aes_ctx;
	u8 tag[16];
	u8 ziv[16] = {0};
	__be32 counter = cpu_to_be32(1);
	int ret = 0;

	/*
	 * alicc hw does not support gcm zero length plaintext. According to spec
	 * if cryptlen is 0, just do aes_encrypt against IV
	 */
	if (aead_req->cryptlen == 0 && cmd == ALICC_CMD_GCM_ENC) {
		ret = aes_expandkey(&aes_ctx, ctx->cipher_key, ctx->keysize);
		if (ret)
			return ret;
		memcpy(ziv, aead_req->iv, 12);
		memcpy(ziv + 12, &counter, 4);
		aes_encrypt(&aes_ctx, tag, ziv);
		sg_copy_from_buffer(aead_req->dst,
				    sg_nents_for_len(aead_req->dst, taglen),
				    tag, taglen);
		return 0;
	}

	if (aead_req->cryptlen == taglen && cmd == ALICC_CMD_GCM_DEC) {
		ret = aes_expandkey(&aes_ctx, ctx->cipher_key, ctx->keysize);
		if (ret)
			return ret;
		/* Skip aad */
		sg_copy_buffer(aead_req->src,
			       sg_nents_for_len(aead_req->src, taglen),
			       tag, taglen, aead_req->assoclen, 1);
		aes_decrypt(&aes_ctx, ziv, tag);
		sg_copy_from_buffer(aead_req->dst,
				    sg_nents_for_len(aead_req->dst, taglen),
				    ziv, taglen);
		return 0;
	}

	memset(req, 0, sizeof(*req));
	req->ctx = ctx;
	req->aead_req = aead_req;

	ret = alicc_aead_fill_key(req);
	if (ret)
		return ret;

	req->src_vaddr = alicc_aead_format_data(req, &new_aad_len, &new_cryptlen, cmd);
	if (!req->src_vaddr)
		goto free_key;

	ret = alicc_aead_sg_map(req);
	if (ret)
		goto unformat;

	ret = -ENOMEM;
	aflags = kzalloc(sizeof(struct alicc_flags), GFP_ATOMIC);
	if (!aflags)
		goto sg_unmap;

	memset(&req->desc.cmd, 0, sizeof(union alicc_real_cmd));
	aflags->ptr = (void *)req;
	aflags->alicc_done_callback = alicc_aead_callback;
	req->desc.private_ptr = (u64)aflags;
	req->desc.cmd.aead_cmd.cmd_id = cmd;
	req->desc.cmd.aead_cmd.mode = ctx->mode;
	req->desc.cmd.aead_cmd.sptr = req->src_paddr;
	req->desc.cmd.aead_cmd.dptr = req->dst_paddr;
	if (cmd == ALICC_CMD_GCM_DEC || cmd == ALICC_CMD_CCM_DEC)
		new_cryptlen = aead_req->cryptlen - taglen;
	req->desc.cmd.aead_cmd.dlen = new_cryptlen;
	req->desc.cmd.aead_cmd.keyptr = req->key_paddr;
	req->desc.cmd.aead_cmd.aadlen = new_aad_len;
	req->desc.cmd.aead_cmd.taglen = taglen;

	/* 4. submit desc to cmd queue */
	ret = alicc_enqueue(ctx->ring, &req->desc);
	if (!ret)
		return -EINPROGRESS;

	pr_err("Failed to submit desc to ring\n");
	kfree(aflags);

sg_unmap:
	alicc_aead_sg_unmap(req);
unformat:
	alicc_aead_unformat_data(req);
free_key:
	memset(req->key_vaddr, 0, 64);
	dma_free_coherent(ALICC_DEV(ctx), 64, req->key_vaddr, req->key_paddr);
	req->key_vaddr = NULL;
	return ret;
}

static int alicc_aead_ccm_encrypt(struct aead_request *aead_req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct aead_request *subreq =
		&((struct alicc_crypto_req *)aead_request_ctx(aead_req))->aead_subreq;

	if (alicc_aead_do_soft(aead_req, 16)) {
		if (!ctx->soft_tfm)
			return -ENOENT;
		aead_request_set_tfm(subreq, ctx->soft_tfm);
		aead_request_set_callback(subreq, aead_req->base.flags,
					  aead_req->base.complete, aead_req->base.data);
		aead_request_set_crypt(subreq, aead_req->src, aead_req->dst,
				       aead_req->cryptlen, aead_req->iv);
		aead_request_set_ad(subreq, aead_req->assoclen);
		crypto_aead_setauthsize(ctx->soft_tfm, crypto_aead_authsize(tfm));
		return crypto_aead_encrypt(subreq);
	}

	return alicc_aead_submit_desc(aead_req, ALICC_CMD_CCM_ENC);
}

static int alicc_aead_gcm_encrypt(struct aead_request *aead_req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct aead_request *subreq =
			&((struct alicc_crypto_req *)aead_request_ctx(aead_req))->aead_subreq;

	if (alicc_aead_do_soft(aead_req, 16)) {
		if (!ctx->soft_tfm)
			return -ENOENT;
		aead_request_set_tfm(subreq, ctx->soft_tfm);
		aead_request_set_callback(subreq, aead_req->base.flags,
					  aead_req->base.complete, aead_req->base.data);
		aead_request_set_crypt(subreq, aead_req->src, aead_req->dst,
				       aead_req->cryptlen, aead_req->iv);
		aead_request_set_ad(subreq, aead_req->assoclen);
		crypto_aead_setauthsize(ctx->soft_tfm, crypto_aead_authsize(tfm));
		return crypto_aead_encrypt(subreq);
	}

	return alicc_aead_submit_desc(aead_req, ALICC_CMD_GCM_ENC);
}

static int alicc_aead_gcm_decrypt(struct aead_request *aead_req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct aead_request *subreq =
		&((struct alicc_crypto_req *)aead_request_ctx(aead_req))->aead_subreq;

	if (alicc_aead_do_soft(aead_req, 0)) {
		if (!ctx->soft_tfm)
			return -ENOENT;
		aead_request_set_tfm(subreq, ctx->soft_tfm);
		aead_request_set_callback(subreq, aead_req->base.flags,
					  aead_req->base.complete, aead_req->base.data);
		aead_request_set_crypt(subreq, aead_req->src, aead_req->dst,
				       aead_req->cryptlen, aead_req->iv);
		aead_request_set_ad(subreq, aead_req->assoclen);
		crypto_aead_setauthsize(ctx->soft_tfm, crypto_aead_authsize(tfm));
		return crypto_aead_decrypt(subreq);
	}

	return alicc_aead_submit_desc(aead_req, ALICC_CMD_GCM_DEC);
}

static int alicc_aead_ccm_decrypt(struct aead_request *aead_req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(aead_req);
	struct alicc_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct aead_request *subreq =
		&((struct alicc_crypto_req *)aead_request_ctx(aead_req))->aead_subreq;

	if (alicc_aead_do_soft(aead_req, 0)) {
		if (!ctx->soft_tfm)
			return -ENOENT;
		aead_request_set_tfm(subreq, ctx->soft_tfm);
		aead_request_set_callback(subreq, aead_req->base.flags,
					  aead_req->base.complete, aead_req->base.data);
		aead_request_set_crypt(subreq, aead_req->src, aead_req->dst,
				       aead_req->cryptlen, aead_req->iv);
		aead_request_set_ad(subreq, aead_req->assoclen);
		crypto_aead_setauthsize(ctx->soft_tfm, crypto_aead_authsize(tfm));
		return crypto_aead_decrypt(subreq);
	}

	return alicc_aead_submit_desc(aead_req, ALICC_CMD_CCM_DEC);
}

static struct aead_alg alicc_aeads[] = {
	{
		.base = {
			.cra_name = "gcm(aes)",
			.cra_driver_name = "gcm-aes-alicc",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct alicc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = alicc_aead_init,
		.exit = alicc_aead_exit,
		.setkey = alicc_aead_setkey,
		.decrypt = alicc_aead_gcm_decrypt,
		.encrypt = alicc_aead_gcm_encrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "gcm(sm4)",
			.cra_driver_name = "gcm-sm4-alicc",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct alicc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = alicc_aead_init,
		.exit = alicc_aead_exit,
		.setkey = alicc_aead_setkey,
		.decrypt = alicc_aead_gcm_decrypt,
		.encrypt = alicc_aead_gcm_encrypt,
		.ivsize = SM4_BLOCK_SIZE,
		.maxauthsize = SM4_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ccm(aes)",
			.cra_driver_name = "ccm-aes-alicc",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct alicc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = alicc_aead_init,
		.exit = alicc_aead_exit,
		.setkey = alicc_aead_setkey,
		.decrypt = alicc_aead_ccm_decrypt,
		.encrypt = alicc_aead_ccm_encrypt,
		.ivsize = AES_BLOCK_SIZE,
		.maxauthsize = AES_BLOCK_SIZE,
	},
	{
		.base = {
			.cra_name = "ccm(sm4)",
			.cra_driver_name = "ccm-sm4-alicc",
			.cra_priority = 4001,
			.cra_flags = CRYPTO_ALG_ASYNC,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct alicc_crypto_ctx),
			.cra_module = THIS_MODULE,
		},
		.init = alicc_aead_init,
		.exit = alicc_aead_exit,
		.setkey = alicc_aead_setkey,
		.decrypt = alicc_aead_ccm_decrypt,
		.encrypt = alicc_aead_ccm_encrypt,
		.ivsize = SM4_BLOCK_SIZE,
		.maxauthsize = SM4_BLOCK_SIZE,
	},
};

int alicc_aead_register(void)
{
	return crypto_register_aeads(alicc_aeads, ARRAY_SIZE(alicc_aeads));
}

void alicc_aead_unregister(void)
{
	crypto_unregister_aeads(alicc_aeads, ARRAY_SIZE(alicc_aeads));
}
