// SPDX-License-Identifier: GPL-2.0
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <linux/dma-mapping.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha3.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/sm4.h>
#include <crypto/sm3.h>
#include <crypto/md5.h>
#include <crypto/sha.h>

#include "ycc_algs.h"

const u8 sha512_224_zero_message_hash[SHA224_DIGEST_SIZE] = {
	0x6e, 0xd0, 0xdd, 0x02, 0x80, 0x6f, 0xa8, 0x9e,
	0x25, 0xde, 0x06, 0x0c, 0x19, 0xd3, 0xac, 0x86,
	0xca, 0xbb, 0x87, 0xd6, 0xa0, 0xdd, 0xd0, 0x5c,
	0x33, 0x3b, 0x84, 0xf4
};

const u8 sha512_256_zero_message_hash[SHA256_DIGEST_SIZE] = {
	0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28,
	0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06,
	0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74,
	0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a
};

const u8 sha3_224_zero_message_hash[SHA3_224_DIGEST_SIZE] = {
	0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7,
	0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab,
	0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f,
	0x5b, 0x5a, 0x6b, 0xc7
};

const u8 sha3_256_zero_message_hash[SHA3_256_DIGEST_SIZE] = {
	0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
	0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
	0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
	0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

const u8 sha3_384_zero_message_hash[SHA3_384_DIGEST_SIZE] = {
	0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d,
	0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
	0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61,
	0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
	0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
	0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04
};

const u8 sha3_512_zero_message_hash[SHA3_512_DIGEST_SIZE] = {
	0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
	0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
	0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
	0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
	0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
	0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
	0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
	0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
};

#ifndef CONFIG_CRYPTO_SM3
const u8 sm3_zero_message_hash[SM3_DIGEST_SIZE] = {
	0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
	0x8e, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
	0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74,
	0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
};
#endif

#ifndef CONFIG_CRYPTO_MD5
const u8 md5_zero_message_hash[MD5_DIGEST_SIZE] = {
	0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
	0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
};
#endif

#ifndef CONFIG_CRYPTO_SHA256
const u8 sha224_zero_message_hash[SHA224_DIGEST_SIZE] = {
	0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47,
	0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2,
	0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4,
	0x2f
};

const u8 sha256_zero_message_hash[SHA256_DIGEST_SIZE] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
#endif

#ifndef CONFIG_CRYPTO_SHA512
const u8 sha384_zero_message_hash[SHA384_DIGEST_SIZE] = {
	0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
	0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
	0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
	0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
	0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
	0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

const u8 sha512_zero_message_hash[SHA512_DIGEST_SIZE] = {
	0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
	0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
	0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
	0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
	0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
	0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
	0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
	0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};
#endif

#ifndef CONFIG_CRYPTO_SHA1
const u8 sha1_zero_message_hash[SHA1_DIGEST_SIZE] = {
	0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
	0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
	0xaf, 0xd8, 0x07, 0x09
};
#endif

/* Used by export/import APIs. */
struct ycc_ahash_state {
	/*
	 * Incremental HASH in the feature. Though ahash_request has
	 * a field "result", but cannot be stored in it. As it
	 * may be truncated.
	 */
	u8 inc_hash[MAX_DIGEST_SIZE];
};

struct ycc_ahash_template {
	struct ahash_alg ycc_hash_info;
	u8 cmd_id;
	u8 mode;
};

#define SET_AHASH_ALG(my_cra_name, my_cra_driver_name, my_cra_blocksize,	\
		      my_digestsize, my_cmd_id, my_mode, my_setkey)		\
{										\
	.ycc_hash_info = {							\
		.init = ycc_ahash_init,						\
		.update = ycc_ahash_update,					\
		.final = ycc_ahash_final,					\
		.finup = ycc_ahash_finup,					\
		.digest = ycc_ahash_digest,					\
		.export = ycc_ahash_export,					\
		.import = ycc_ahash_import,					\
		.setkey = my_setkey,						\
		.halg = {							\
			.base = {						\
				.cra_name = my_cra_name,			\
				.cra_driver_name = my_cra_driver_name,		\
				.cra_priority = 4001,				\
				.cra_flags = CRYPTO_ALG_ASYNC,			\
				.cra_blocksize = my_cra_blocksize,		\
				.cra_ctxsize = sizeof(struct ycc_ahash_ctx),	\
				.cra_init = ycc_ahash_cra_init,			\
				.cra_exit = ycc_ahash_cra_exit,			\
				.cra_module = THIS_MODULE,			\
			},							\
			.digestsize = my_digestsize,				\
			.statesize = sizeof(struct ycc_ahash_ctx),		\
		},								\
	},									\
	.cmd_id = my_cmd_id,							\
	.mode = my_mode,							\
}

#define SET_CMAC_ALG(my_cra_name, my_cra_driver_name, my_cra_blocksize,		\
		     my_digestsize, my_cmd_id, my_mode)				\
{										\
	.ycc_hash_info = {							\
		.init = ycc_ahash_init,						\
		.update = ycc_ahash_update,					\
		.final = ycc_ahash_final,					\
		.finup = ycc_ahash_finup,					\
		.digest = ycc_ahash_digest,					\
		.export = ycc_ahash_export,					\
		.import = ycc_ahash_import,					\
		.setkey = ycc_ahash_cmac_setkey,				\
		.halg = {							\
			.base = {						\
				.cra_name = my_cra_name,			\
				.cra_driver_name = my_cra_driver_name,		\
				.cra_priority = 300,				\
				.cra_flags = CRYPTO_ALG_ASYNC,			\
				.cra_blocksize = my_cra_blocksize,		\
				.cra_ctxsize = sizeof(struct ycc_ahash_ctx),	\
				.cra_init = ycc_ahash_cra_init,			\
				.cra_exit = ycc_ahash_cra_exit,			\
				.cra_module = THIS_MODULE,			\
			},							\
			.digestsize = my_digestsize,				\
			.statesize = sizeof(struct ycc_ahash_ctx),		\
		},								\
	},									\
	.cmd_id = my_cmd_id,							\
	.mode = my_mode,							\
}

static inline struct ycc_ahash_template *__crypto_ahash_template(struct crypto_alg *alg)
{
	return container_of(__crypto_ahash_alg(alg), struct ycc_ahash_template, ycc_hash_info);
}

static int ycc_ahash_init(struct ahash_request *ahash_req)
{
	struct crypto_ahash *atfm = crypto_ahash_reqtfm(ahash_req);
	const char *alg_name = crypto_tfm_alg_name(crypto_ahash_tfm(atfm));
	struct ycc_ahash_req *req = ahash_request_ctx(ahash_req);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(atfm);
	struct crypto_shash *stfm;
	int ret;

	req->ctx = ctx;
	req->ahash_req = ahash_req;

	/*
	 * As YCC does not support increment hash, if this interface is
	 * called, use software shash instead
	 */
	stfm = crypto_alloc_shash(alg_name, 0, 0);
	if (IS_ERR(stfm)) {
		ret = PTR_ERR(stfm);
		pr_err("Failed to allocate shash :%s\n", alg_name);
		goto err;
	}

	ctx->shash = kmalloc(sizeof(struct shash_desc) +
			     crypto_shash_descsize(stfm), GFP_ATOMIC);
	if (!ctx->shash)
		goto free_stfm;

	ctx->shash->tfm = stfm;
	if (ctx->authsize > 0) {
		if (ctx->mode >= YCC_CBC_MAC_AES_128 && ctx->mode <= YCC_CMAC_SM4)
			ret = crypto_shash_setkey(stfm,
					ctx->auth_key + 32 - ctx->authsize,
					ctx->authsize);
		else
			ret = crypto_shash_setkey(stfm, ctx->auth_key, ctx->authsize);
		if (ret) {
			pr_err("Failed to set shash key:%s\n", alg_name);
			goto free_shash;
		}
	}

	ret = crypto_shash_init(ctx->shash);
	if (ret) {
		pr_err("Failed to do shash init:%s\n", alg_name);
		goto free_shash;
	}

	return ret;

free_shash:
	kfree(ctx->shash);
free_stfm:
	crypto_free_shash(stfm);
err:
	return ret;
}

static int ycc_ahash_update(struct ahash_request *ahash_req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(ahash_req);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	int nents;
	u8 *buf;
	int ret;

	if (!ahash_req->src)
		return -EINVAL;

	nents = sg_nents(ahash_req->src);
	buf = kzalloc(ahash_req->nbytes, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	if (sg_copy_to_buffer(ahash_req->src, nents, buf, ahash_req->nbytes) !=
			      ahash_req->nbytes) {
		pr_err("Failed to copy sg to memory for shash update\n");
		kfree(buf);
		return -EINVAL;
	}

	ret = crypto_shash_update(ctx->shash, buf, ahash_req->nbytes);
	if (ret)
		pr_err("Failed to do shash update\n");

	kfree(buf);
	return ret;
}

static int ycc_ahash_final(struct ahash_request *ahash_req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(ahash_req);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	int ret;

	memset(ahash_req->result, 0, AES_BLOCK_SIZE);
	ret = crypto_shash_final(ctx->shash, ahash_req->result);
	if (ret)
		pr_err("Failed to do shash final\n");

	crypto_free_shash(ctx->shash->tfm);
	kfree(ctx->shash);
	return ret;
}

static int ycc_ahash_finup(struct ahash_request *ahash_req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(ahash_req);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	int nents;
	u8 *buf;
	int ret;

	if (!ahash_req->src)
		return -EINVAL;

	nents = sg_nents(ahash_req->src);
	buf = kmalloc(ahash_req->nbytes, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	if (sg_copy_to_buffer(ahash_req->src, nents, buf, ahash_req->nbytes) !=
			      ahash_req->nbytes) {
		pr_err("Failed to copy sg to memory for shash update\n");
		kfree(buf);
		return -EINVAL;
	}

	ret = crypto_shash_finup(ctx->shash, buf, ahash_req->nbytes,
				 ahash_req->result);
	if (ret)
		pr_err("Failed to do shash finup\n");

	kfree(buf);
	crypto_free_shash(ctx->shash->tfm);
	kfree(ctx->shash);
	return ret;
}

static int ycc_ahash_done(void *ptr, u16 state)
{
	struct ycc_ahash_req *req = (struct ycc_ahash_req *)ptr;
	struct ahash_request *ahash_req = req->ahash_req;
	struct ycc_ahash_ctx *ctx = req->ctx;
	struct device *dev = YCC_DEV(ctx);
	u32 digestsize = crypto_ahash_digestsize(crypto_ahash_reqtfm(ahash_req));

	memcpy(ahash_req->result, req->result_vaddr, digestsize);
	if (ahash_req->nbytes)
		dma_free_coherent(dev, ALIGN(ahash_req->nbytes, 64),
				  req->source_vaddr, req->source_paddr);

	dma_free_coherent(dev, ALIGN(digestsize, 64), req->result_vaddr,
			  req->result_paddr);

	if (ctx->filling_data) {
		kfree(ctx->filling_data->src_sg);
		__free_pages(ctx->filling_data->sp, ctx->filling_data->sorder);
		kfree(ctx->filling_data);
	}

	if (ahash_req->base.complete)
		ahash_req->base.complete(&ahash_req->base, state == CMD_SUCCESS ? 0 : -EBADMSG);

	return 0;
}

static int ycc_filling_source_data(struct ahash_request *ahash_req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(ahash_req);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	struct filling_data *fd = ctx->filling_data;
	void *tmpbuf;
	int i;

	fd = kmalloc(sizeof(struct filling_data), GFP_ATOMIC);
	ahash_req->nbytes = 16;
	fd->sorder = get_order(ahash_req->nbytes);
	fd->sp = alloc_pages(GFP_ATOMIC, fd->sorder);
	if (!fd->sp)
		goto free_fd;

	tmpbuf = page_address(fd->sp);
	memset(tmpbuf, 0, (1 << fd->sorder) * PAGE_SIZE);
	fd->snents = (ahash_req->nbytes + PAGE_SIZE - 1) / PAGE_SIZE;
	fd->src_sg = kmalloc_array(fd->snents, sizeof(struct scatterlist), GFP_ATOMIC);
	if (!fd->src_sg)
		goto free_sp;

	sg_init_table(fd->src_sg, fd->snents);
	for (i = 0; i < fd->snents; i++)
		sg_set_buf(&fd->src_sg[i], tmpbuf + i * PAGE_SIZE, PAGE_SIZE);

	ahash_req->src = fd->src_sg;
	return 0;

free_sp:
	__free_pages(fd->sp, fd->sorder);
free_fd:
	kfree(fd);
	return -ENOMEM;
}

static void ycc_ahash_prepare_cmd(struct ahash_request *ahash_req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(ahash_req);
	struct ycc_ahash_template *tmpl = __crypto_ahash_template(tfm->base.__crt_alg);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	struct ycc_ahash_req *req = ahash_request_ctx(ahash_req);
	struct ycc_hash_cmd *hash_cmd;
	struct ycc_mac_cmd *mac_cmd;
	u32 digestsize = crypto_ahash_digestsize(tfm); /* Mac size */

	switch (tmpl->cmd_id) {
	case YCC_CMD_HASH:
		hash_cmd         = &req->desc.cmd.hash_cmd;
		hash_cmd->cmd_id = tmpl->cmd_id;
		hash_cmd->mode   = tmpl->mode;
		hash_cmd->sptr   = req->source_paddr;
		hash_cmd->dptr   = req->result_paddr;
		hash_cmd->dlen   = ahash_req->nbytes;
		break;
	case YCC_CMD_GEN_HMAC:
		mac_cmd          = &req->desc.cmd.mac_cmd;
		mac_cmd->cmd_id  = ahash_req->nbytes ? tmpl->cmd_id : YCC_CMD_GEN_HMAC_LEN0;
		mac_cmd->mode    = tmpl->mode;
		mac_cmd->sptr    = req->source_paddr;
		mac_cmd->dptr    = req->result_paddr;
		mac_cmd->dlen    = ahash_req->nbytes;
		mac_cmd->key_idx = 0;
		mac_cmd->kek_idx = 0;
		mac_cmd->keyptr  = (u64)ctx->auth_key_paddr;
		mac_cmd->keylen  = ctx->authsize;
		mac_cmd->digestlen = digestsize;
		break;
	case YCC_CMD_GEN_CMAC:
		mac_cmd          = &req->desc.cmd.mac_cmd;
		if (ahash_req->nbytes == 0 &&
		    ctx->mode >= YCC_CMAC_AES_128 &&
		    ctx->mode <= YCC_CMAC_SM4)
			mac_cmd->cmd_id = YCC_CMD_GEN_CMAC_LEN0;
		else
			mac_cmd->cmd_id = tmpl->cmd_id;

		mac_cmd->mode     = ctx->mode;
		mac_cmd->sptr     = req->source_paddr;
		mac_cmd->dptr     = req->result_paddr;
		mac_cmd->dlen     = ahash_req->nbytes;
		mac_cmd->key_idx  = 0;
		mac_cmd->kek_idx  = 0;
		mac_cmd->keyptr   = (u64)ctx->auth_key_paddr;
		mac_cmd->keylen   = ctx->authsize;
		mac_cmd->digestlen = digestsize;
		break;
	default:
		break;
	}
}

static int ycc_ahash_digest(struct ahash_request *ahash_req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(ahash_req);
	struct ycc_ahash_template *tmpl = __crypto_ahash_template(tfm->base.__crt_alg);
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	struct ycc_ahash_req *req = ahash_request_ctx(ahash_req);
	struct device *dev = YCC_DEV(ctx);
	u32 digestsize = crypto_ahash_digestsize(tfm); /* Mac size */
	struct ycc_flags *aflag;
	int ret = -ENOMEM;

	memset(req, 0, sizeof(struct ycc_ahash_req));
	req->ahash_req = ahash_req;
	req->ctx = ctx;

	if (unlikely(!ahash_req->nbytes)) {
		switch (tmpl->cmd_id) {
		case YCC_CMD_HASH:
			switch (tmpl->mode) {
			case YCC_HASH_SM3:
				memcpy(ahash_req->result,
				       sm3_zero_message_hash, SM3_DIGEST_SIZE);
				return 0;
			case YCC_HASH_MD5:
				memcpy(ahash_req->result,
				       md5_zero_message_hash, MD5_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_256:
				memcpy(ahash_req->result,
				       sha256_zero_message_hash, SHA256_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_384:
				memcpy(ahash_req->result,
				       sha384_zero_message_hash, SHA384_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_512:
				memcpy(ahash_req->result,
				       sha512_zero_message_hash, SHA512_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_1:
				memcpy(ahash_req->result,
				       sha1_zero_message_hash, SHA1_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_224:
				memcpy(ahash_req->result,
				       sha224_zero_message_hash, SHA224_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_512_224:
				memcpy(ahash_req->result,
				       sha512_224_zero_message_hash, SHA224_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_512_256:
				memcpy(ahash_req->result,
				       sha512_256_zero_message_hash, SHA256_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_3_224:
				memcpy(ahash_req->result,
				       sha3_224_zero_message_hash, SHA3_224_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_3_256:
				memcpy(ahash_req->result,
				       sha3_256_zero_message_hash, SHA3_256_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_3_384:
				memcpy(ahash_req->result,
				       sha3_384_zero_message_hash, SHA3_384_DIGEST_SIZE);
				return 0;
			case YCC_HASH_SHA_3_512:
				memcpy(ahash_req->result,
				       sha3_512_zero_message_hash, SHA3_512_DIGEST_SIZE);
				return 0;
			default:
				ret = -EINVAL;
				goto out;
			}
		case YCC_CMD_GEN_HMAC:
			goto alloc_result_vaddr;
		case YCC_CMD_GEN_CMAC:
			if (ctx->mode >= YCC_CBC_MAC_AES_128 && ctx->mode <= YCC_CBC_MAC_SM4) {
				ret = ycc_filling_source_data(ahash_req);
				if (ret)
					goto out;
			} else if (ctx->mode >= YCC_CMAC_AES_128 && ctx->mode <= YCC_CMAC_SM4) {
				goto alloc_result_vaddr;
			} else {
				ret = -EINVAL;
				goto out;
			}
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
	}

	ret = -ENOMEM;
	req->source_vaddr = dma_alloc_coherent(dev, ALIGN(ahash_req->nbytes, 64),
					       &req->source_paddr, GFP_ATOMIC);
	if (!req->source_vaddr)
		goto out;

	scatterwalk_map_and_copy(req->source_vaddr, ahash_req->src, 0, ahash_req->nbytes, 0);

alloc_result_vaddr:
	req->result_vaddr = dma_alloc_coherent(dev, ALIGN(digestsize, 64),
					       &req->result_paddr, GFP_ATOMIC);
	if (!req->result_vaddr)
		goto free_source;

	aflag = kzalloc(sizeof(struct ycc_flags), GFP_ATOMIC);
	if (!aflag)
		goto free_result;

	aflag->ycc_done_callback = ycc_ahash_done;
	aflag->ptr = req;

	req->desc.private_ptr = (u64)aflag;
	ycc_ahash_prepare_cmd(ahash_req);

	ret = ycc_enqueue(ctx->ring, &req->desc);
	if (ret)
		goto free_aflag;

	return -EINPROGRESS;

free_aflag:
	kfree(aflag);
free_result:
	dma_free_coherent(dev, ALIGN(digestsize, 64), req->result_vaddr,
			  req->result_paddr);
free_source:
	dma_free_coherent(dev, ALIGN(ahash_req->nbytes, 64), req->source_vaddr,
			  req->source_paddr);
out:
	return ret;
}

static int ycc_ahash_export(struct ahash_request *ahash_req, void *out)
{
	return 0;
}

static int ycc_ahash_import(struct ahash_request *ahash_req, const void *in)
{
	return 0;
}

static int ycc_ahash_hmac_setkey(struct crypto_ahash *tfm, const u8 *key,
				 unsigned int keylen)
{
	struct ycc_ahash_ctx *ctx = crypto_ahash_ctx(tfm);
	struct device *dev = YCC_DEV(ctx);

	ctx->auth_key = dma_alloc_coherent(dev, ALIGN(keylen, 64),
					   &ctx->auth_key_paddr, GFP_KERNEL);
	if (!ctx->auth_key)
		return -ENOMEM;

	memset(ctx->auth_key, 0, ALIGN(keylen, 64));
	/*
	 * The hardware doesn't support the key whose length is zero,
	 * but this scenario is necessary. Consider that the result of
	 * hmac with null key is equal to the result of hmac with key
	 * 0x00, if a key is null, we change it into 0x00.
	 */
	memcpy(ctx->auth_key, key, keylen);
	ctx->authsize = (keylen == 0 ? 1 : keylen);
	return 0;
}

static int ycc_ahash_cra_init(struct crypto_tfm *tfm)
{
	struct ycc_ahash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_ahash *atfm = __crypto_ahash_cast(tfm);

	memset(ctx, 0, sizeof(struct ycc_ahash_ctx));
	ctx->ring = ycc_crypto_get_ring();
	if (!ctx->ring) {
		pr_err("Failed to bind ring to ahash tfm\n");
		return -EINVAL;
	}

	crypto_ahash_set_reqsize(atfm, sizeof(struct ycc_ahash_req));
	return 0;
}

static void ycc_ahash_cra_exit(struct crypto_tfm *tfm)
{
	struct ycc_ahash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct device *dev = YCC_DEV(ctx);

	if (ctx->auth_key)
		dma_free_coherent(dev, ALIGN(ctx->authsize, 64),
				  ctx->auth_key, ctx->auth_key_paddr);

	if (ctx->ring)
		ycc_crypto_free_ring(ctx->ring);
}

static struct ycc_ahash_template ycc_hashes[] = {
	SET_AHASH_ALG("sm3", "ycc_hash(sm3)", SM3_BLOCK_SIZE,
		SM3_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SM3, NULL),
	SET_AHASH_ALG("md5", "ycc_hash(md5)", MD5_HMAC_BLOCK_SIZE,
		MD5_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_MD5, NULL),
	SET_AHASH_ALG("sha256", "ycc_hash(sha256)", SHA256_BLOCK_SIZE,
		SHA256_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_256, NULL),
	SET_AHASH_ALG("sha384", "ycc_hash(sha384)", SHA384_BLOCK_SIZE,
		SHA384_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_384, NULL),
	SET_AHASH_ALG("sha512", "ycc_hash(sha512)", SHA512_BLOCK_SIZE,
		SHA512_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_512, NULL),
	SET_AHASH_ALG("sha1", "ycc_hash(sha1)", SHA1_BLOCK_SIZE,
		SHA1_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_1, NULL),
	SET_AHASH_ALG("sha224", "ycc_hash(sha224)", SHA224_BLOCK_SIZE,
		SHA224_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_224, NULL),
	SET_AHASH_ALG("sha512/224", "ycc_hash(sha512/224)", SHA512_BLOCK_SIZE,
		SHA224_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_512_224, NULL),
	SET_AHASH_ALG("sha512/256", "ycc_hash(sha512/256)", SHA512_BLOCK_SIZE,
		SHA256_DIGEST_SIZE, YCC_CMD_HASH, YCC_HMAC_SHA_512_256, NULL),
	SET_AHASH_ALG("sha3-224", "ycc_hash(sha3-224)", SHA3_224_BLOCK_SIZE,
		SHA3_224_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_3_224, NULL),
	SET_AHASH_ALG("sha3-256", "ycc_hash(sha3-256)", SHA3_256_BLOCK_SIZE,
		SHA3_256_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_3_256, NULL),
	SET_AHASH_ALG("sha3-384", "ycc_hash(sha3-384)", SHA3_384_BLOCK_SIZE,
		SHA3_384_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_3_384, NULL),
	SET_AHASH_ALG("sha3-512", "ycc_hash(sha3-512)", SHA3_512_BLOCK_SIZE,
		SHA3_512_DIGEST_SIZE, YCC_CMD_HASH, YCC_HASH_SHA_3_512, NULL),

	SET_AHASH_ALG("hmac(sm3)", "ycc_hmac(sm3)", SM3_BLOCK_SIZE,
		SM3_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SM3, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(md5)", "ycc_hmac(md5)", MD5_HMAC_BLOCK_SIZE,
		MD5_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_MD5, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha256)", "ycc_hmac(sha256)", SHA256_BLOCK_SIZE,
		SHA256_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_256, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha384)", "ycc_hmac(sha384)", SHA384_BLOCK_SIZE,
		SHA384_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_384, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha512)", "ycc_hmac(sha512)", SHA512_BLOCK_SIZE,
		SHA512_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_512, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha1)", "ycc_hmac(sha1)", SHA1_BLOCK_SIZE,
		SHA1_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_1, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha224)", "ycc_hmac(sha224)", SHA224_BLOCK_SIZE,
		SHA224_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_224, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha512/224)", "ycc_hmac(sha512/224)", SHA512_BLOCK_SIZE,
		SHA224_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_512_224, ycc_ahash_hmac_setkey),
	SET_AHASH_ALG("hmac(sha512/256)", "ycc_hmac(sha512/256)", SHA512_BLOCK_SIZE,
		SHA256_DIGEST_SIZE, YCC_CMD_GEN_HMAC, YCC_HMAC_SHA_512_256, ycc_ahash_hmac_setkey),
};

int ycc_hash_register(void)
{
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(ycc_hashes); i++) {
		ret = crypto_register_ahash(&(ycc_hashes[i].ycc_hash_info));
		if (ret)
			goto out;
	}

	return 0;

out:
	i--;
	for (; i >= 0; i--)
		crypto_unregister_ahash(&(ycc_hashes[i].ycc_hash_info));

	return ret;
}

void ycc_hash_unregister(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ycc_hashes); i++)
		crypto_unregister_ahash(&(ycc_hashes[i].ycc_hash_info));
}
