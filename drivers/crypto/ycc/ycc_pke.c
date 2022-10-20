// SPDX-License-Identifier: GPL-2.0
#include <crypto/internal/akcipher.h>
#include <crypto/internal/rsa.h>
#include <crypto/scatterwalk.h>
#include <linux/dma-mapping.h>
#include <linux/crypto.h>
#include <linux/mpi.h>

#include "sm2signature_asn1.h"
#include "ycc_algs.h"

static int ycc_rsa_done_callback(void *ptr, u16 state)
{
	struct ycc_pke_req *rsa_req = (struct ycc_pke_req *)ptr;
	struct ycc_pke_ctx *ctx = rsa_req->ctx;
	struct akcipher_request *req = rsa_req->req;
	struct device *dev = YCC_DEV(ctx);
	unsigned int dma_length = ctx->key_len;

	if (rsa_req->desc.cmd.rsa_enc_cmd.cmd_id == YCC_CMD_RSA_VERIFY)
		dma_length = ctx->key_len << 1;

	/* For signature verify, dst is NULL */
	if (rsa_req->dst_vaddr) {
		sg_copy_from_buffer(req->dst, sg_nents_for_len(req->dst, req->dst_len),
				    rsa_req->dst_vaddr, req->dst_len);
		dma_free_coherent(dev, ALIGN(ctx->key_len, 64),
				  rsa_req->dst_vaddr, rsa_req->dst_paddr);
	}
	dma_free_coherent(dev, ALIGN(dma_length, 64),
			  rsa_req->src_vaddr, rsa_req->src_paddr);

	if (req->base.complete)
		req->base.complete(&req->base, state == CMD_SUCCESS ? 0 : -EBADMSG);

	return 0;
}

static int ycc_prepare_dma_buf(struct ycc_pke_req *rsa_req, int is_src)
{
	struct ycc_pke_ctx *ctx = rsa_req->ctx;
	struct akcipher_request *req = rsa_req->req;
	struct device *dev = YCC_DEV(ctx);
	unsigned int dma_length = ctx->key_len;
	dma_addr_t tmp;
	void *ptr;
	int shift;

	/*
	 * Ycc requires 2 key_len blocks, the first block stores
	 * message pre-padding with 0, the second block stores signature.
	 * LCKF akcipher verify, the first sg contains signature and
	 * the second contains message while src_len is signature
	 * length, dst len is message length
	 */
	if (rsa_req->desc.cmd.rsa_enc_cmd.cmd_id == YCC_CMD_RSA_VERIFY) {
		dma_length = ctx->key_len << 1;
		shift = ctx->key_len - req->dst_len;
	} else {
		shift = ctx->key_len - req->src_len;
	}

	if (unlikely(shift < 0))
		return -EINVAL;

	ptr = dma_alloc_coherent(dev, ALIGN(dma_length, 64), &tmp, GFP_ATOMIC);
	if (unlikely(!ptr)) {
		pr_err("Failed to alloc dma for %s data\n", is_src ? "src" : "dst");
		return -ENOMEM;
	}

	memset(ptr, 0, ALIGN(dma_length, 64));
	if (is_src) {
		if (rsa_req->desc.cmd.rsa_enc_cmd.cmd_id ==
		    YCC_CMD_RSA_VERIFY) {
			/* Copy msg first with prepadding 0 */
			sg_copy_buffer(req->src, sg_nents(req->src), ptr + shift,
				       req->dst_len, req->src_len, 1);
			/* Copy signature */
			sg_copy_buffer(req->src, sg_nents(req->src), ptr + ctx->key_len,
				       req->src_len, 0, 1);
		} else {
			sg_copy_buffer(req->src, sg_nents(req->src), ptr + shift,
				       req->src_len, 0, 1);
		}
		rsa_req->src_vaddr = ptr;
		rsa_req->src_paddr = tmp;
	} else {
		rsa_req->dst_vaddr = ptr;
		rsa_req->dst_paddr = tmp;
	}

	return 0;
}

/*
 * Using public key to encrypt or verify
 */
static int ycc_rsa_submit_pub(struct akcipher_request *req, bool is_enc)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ycc_pke_req *rsa_req = akcipher_request_ctx(req);
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ycc_rsa_enc_cmd *rsa_enc_cmd;
	struct ycc_ring *ring = ctx->ring;
	struct device *dev = YCC_DEV(ctx);
	struct ycc_flags *aflags;
	int ret = -ENOMEM;

	if (req->dst_len > ctx->key_len || req->src_len > ctx->key_len)
		return -EINVAL;

	rsa_req->ctx = ctx;
	rsa_req->req = req;

	if (unlikely(!ctx->pub_key_vaddr))
		return -EINVAL;

	aflags = kzalloc(sizeof(struct ycc_flags), GFP_ATOMIC);
	if (!aflags)
		goto out;

	aflags->ptr = (void *)rsa_req;
	aflags->ycc_done_callback = ycc_rsa_done_callback;

	memset(&rsa_req->desc, 0, sizeof(rsa_req->desc));
	rsa_req->desc.private_ptr = (u64)(void *)aflags;

	rsa_enc_cmd         = &rsa_req->desc.cmd.rsa_enc_cmd;
	rsa_enc_cmd->cmd_id = is_enc ? YCC_CMD_RSA_ENC : YCC_CMD_RSA_VERIFY;
	rsa_enc_cmd->keyptr = ctx->pub_key_paddr;
	rsa_enc_cmd->elen   = ctx->e_len << 3;
	rsa_enc_cmd->nlen   = ctx->key_len << 3;

	ret = ycc_prepare_dma_buf(rsa_req, 1);
	if (unlikely(ret))
		goto free_aflags;

	rsa_enc_cmd->sptr = rsa_req->src_paddr;
	if (is_enc) {
		ret = ycc_prepare_dma_buf(rsa_req, 0);
		if (unlikely(ret))
			goto free_src;

		rsa_enc_cmd->dptr = rsa_req->dst_paddr;
	} else {
		rsa_req->dst_vaddr = NULL;
	}

	ret = ycc_enqueue(ring, (u8 *)&rsa_req->desc);
	if (!ret)
		return -EINPROGRESS;

	if (rsa_req->dst_vaddr)
		dma_free_coherent(dev, ALIGN(ctx->key_len, 64),
				  rsa_req->dst_vaddr, rsa_req->dst_paddr);

free_src:
	dma_free_coherent(dev, ALIGN(is_enc ? ctx->key_len : ctx->key_len << 1, 64),
			  rsa_req->src_vaddr, rsa_req->src_paddr);
free_aflags:
	kfree(aflags);
out:
	return ret;
}

/*
 * Using private key to decrypt or signature
 */
static int ycc_rsa_submit_priv(struct akcipher_request *req, bool is_dec)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ycc_pke_req *rsa_req = akcipher_request_ctx(req);
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ycc_rsa_dec_cmd *rsa_dec_cmd;
	struct ycc_ring *ring = ctx->ring;
	struct device *dev = YCC_DEV(ctx);
	struct ycc_flags *aflags;
	int ret = -ENOMEM;

	if (req->dst_len > ctx->key_len || req->src_len > ctx->key_len)
		return -EINVAL;

	rsa_req->ctx = ctx;
	rsa_req->req = req;

	if (unlikely(!ctx->priv_key_vaddr))
		return -EINVAL;

	aflags = kzalloc(sizeof(struct ycc_flags), GFP_ATOMIC);
	if (!aflags)
		goto out;

	aflags->ptr = (void *)rsa_req;
	aflags->ycc_done_callback = ycc_rsa_done_callback;

	memset(&rsa_req->desc, 0, sizeof(rsa_req->desc));
	rsa_req->desc.private_ptr = (u64)(void *)aflags;

	rsa_dec_cmd         = &rsa_req->desc.cmd.rsa_dec_cmd;
	rsa_dec_cmd->keyptr = ctx->priv_key_paddr;
	rsa_dec_cmd->elen   = ctx->e_len << 3;
	rsa_dec_cmd->nlen   = ctx->key_len << 3;
	if (ctx->crt_mode)
		rsa_dec_cmd->cmd_id = is_dec ? YCC_CMD_RSA_CRT_DEC : YCC_CMD_RSA_CRT_SIGN;
	else
		rsa_dec_cmd->cmd_id = is_dec ? YCC_CMD_RSA_DEC : YCC_CMD_RSA_SIGN;

	ret = ycc_prepare_dma_buf(rsa_req, 1);
	if (unlikely(ret))
		goto free_aflags;

	ret = ycc_prepare_dma_buf(rsa_req, 0);
	if (unlikely(ret))
		goto free_src;

	rsa_dec_cmd->sptr = rsa_req->src_paddr;
	rsa_dec_cmd->dptr = rsa_req->dst_paddr;

	ret = ycc_enqueue(ring, (u8 *)&rsa_req->desc);
	if (!ret)
		return -EINPROGRESS;

	dma_free_coherent(dev, ALIGN(ctx->key_len, 64), rsa_req->dst_vaddr,
			  rsa_req->dst_paddr);
free_src:
	dma_free_coherent(dev, ALIGN(ctx->key_len, 64), rsa_req->src_vaddr,
			  rsa_req->src_paddr);
free_aflags:
	kfree(aflags);
out:
	return ret;
}

static inline bool ycc_rsa_do_soft(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ycc_dev *ydev = ctx->ring->ydev;

	if (ctx->key_len == YCC_RSA_KEY_SZ_512 ||
	    ctx->key_len == YCC_RSA_KEY_SZ_1536 ||
	    !test_bit(YDEV_STATUS_READY, &ydev->status))
		return true;

	return false;
}

enum rsa_ops {
	RSA_ENC,
	RSA_DEC,
	RSA_SIGN,
	RSA_VERIFY,
};

static inline int ycc_rsa_soft_fallback(struct akcipher_request *req, int ops)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret = -EINVAL;

	akcipher_request_set_tfm(req, ctx->soft_tfm);

	switch (ops) {
	case RSA_ENC:
		ret = crypto_akcipher_encrypt(req);
		break;
	case RSA_DEC:
		ret = crypto_akcipher_decrypt(req);
		break;
	case RSA_SIGN:
		ret = crypto_akcipher_sign(req);
		break;
	case RSA_VERIFY:
		ret = crypto_akcipher_verify(req);
		break;
	default:
		break;
	}

	akcipher_request_set_tfm(req, tfm);
	return ret;
}

static int ycc_rsa_encrypt(struct akcipher_request *req)
{
	if (ycc_rsa_do_soft(req))
		return ycc_rsa_soft_fallback(req, RSA_ENC);

	return ycc_rsa_submit_pub(req, true);
}

static int ycc_rsa_decrypt(struct akcipher_request *req)
{
	if (ycc_rsa_do_soft(req))
		return ycc_rsa_soft_fallback(req, RSA_DEC);

	return ycc_rsa_submit_priv(req, true);
}

static int ycc_rsa_verify(struct akcipher_request *req)
{
	if (ycc_rsa_do_soft(req))
		return ycc_rsa_soft_fallback(req, RSA_VERIFY);

	return ycc_rsa_submit_pub(req, false);
}

static int ycc_rsa_sign(struct akcipher_request *req)
{
	if (ycc_rsa_do_soft(req))
		return ycc_rsa_soft_fallback(req, RSA_SIGN);

	return ycc_rsa_submit_priv(req, false);
}

static int ycc_rsa_validate_n(unsigned int len)
{
	unsigned int bitslen = len << 3;

	switch (bitslen) {
	case 512:
	case 1024:
	case 1536:
	case 2048:
	case 3072:
	case 4096:
		return 0;
	default:
		return -EINVAL;
	}
}

static void __ycc_rsa_drop_leading_zeros(const u8 **ptr, size_t *len)
{
	if (!*ptr)
		return;

	while (!**ptr && *len) {
		(*ptr)++;
		(*len)--;
	}
}

static int ycc_rsa_set_n(struct ycc_pke_ctx *ctx, const char *value,
			 size_t value_len, bool private)
{
	const char *ptr = value;

	/* e should be set before n as we need e_len */
	if (!ctx->e_len || !value_len)
		return -EINVAL;

	if (!ctx->key_len)
		ctx->key_len = value_len;

	if (private && !ctx->crt_mode)
		memcpy(ctx->priv_key_vaddr + ctx->e_len + YCC_PIN_SZ +
		       ctx->rsa_key->d_sz, ptr, value_len);

	memcpy(ctx->pub_key_vaddr + ctx->e_len, ptr, value_len);
	return 0;
}

static int ycc_rsa_set_e(struct ycc_pke_ctx *ctx, const char *value,
			 size_t value_len, bool private)
{
	const char *ptr = value;

	if (!ctx->key_len || !value_len || value_len > YCC_RSA_E_SZ_MAX)
		return -EINVAL;

	ctx->e_len = value_len;
	if (private)
		memcpy(ctx->priv_key_vaddr, ptr, value_len);

	memcpy(ctx->pub_key_vaddr, ptr, value_len);
	return 0;
}

static int ycc_rsa_set_d(struct ycc_pke_ctx *ctx, const char *value,
			 size_t value_len)
{
	const char *ptr = value;

	if (!ctx->key_len || !value_len || value_len > ctx->key_len)
		return -EINVAL;

	memcpy(ctx->priv_key_vaddr + ctx->e_len + YCC_PIN_SZ, ptr, value_len);
	return 0;
}

static int ycc_rsa_set_crt_param(char *param, size_t half_key_len,
				 const char *value, size_t value_len)
{
	const char *ptr = value;
	size_t len = value_len;

	if (!len || len > half_key_len)
		return -EINVAL;

	memcpy(param, ptr, len);
	return 0;
}

static int ycc_rsa_setkey_crt(struct ycc_pke_ctx *ctx, struct rsa_key *rsa_key)
{
	unsigned int half_key_len = ctx->key_len >> 1;
	u8 *tmp = (u8 *)ctx->priv_key_vaddr;
	int ret;

	tmp += ctx->rsa_key->e_sz + 16;
	/* TODO: rsa_key is better to be kept original */
	ret = ycc_rsa_set_crt_param(tmp, half_key_len, rsa_key->p, rsa_key->p_sz);
	if (ret)
		goto err;

	tmp += half_key_len;
	ret = ycc_rsa_set_crt_param(tmp, half_key_len, rsa_key->q, rsa_key->q_sz);
	if (ret)
		goto err;

	tmp += half_key_len;
	ret = ycc_rsa_set_crt_param(tmp, half_key_len, rsa_key->dp, rsa_key->dp_sz);
	if (ret)
		goto err;

	tmp += half_key_len;
	ret = ycc_rsa_set_crt_param(tmp, half_key_len, rsa_key->dq, rsa_key->dq_sz);
	if (ret)
		goto err;

	tmp += half_key_len;
	ret = ycc_rsa_set_crt_param(tmp, half_key_len, rsa_key->qinv, rsa_key->qinv_sz);
	if (ret)
		goto err;

	ctx->crt_mode = true;
	return 0;

err:
	ctx->crt_mode = false;
	return ret;
}

static void ycc_rsa_clear_ctx(struct ycc_pke_ctx *ctx)
{
	struct device *dev = YCC_DEV(ctx);
	size_t size;

	if (ctx->pub_key_vaddr) {
		size = ALIGN(ctx->rsa_key->e_sz + ctx->key_len, YCC_CMD_DATA_ALIGN_SZ);
		dma_free_coherent(dev, size, ctx->pub_key_vaddr, ctx->pub_key_paddr);
		ctx->pub_key_vaddr = NULL;
	}

	if (ctx->priv_key_vaddr) {
		size = ALIGN(ctx->rsa_key->e_sz + YCC_PIN_SZ + ctx->rsa_key->d_sz +
			     ctx->key_len, YCC_CMD_DATA_ALIGN_SZ);
		memzero_explicit(ctx->priv_key_vaddr, size);
		dma_free_coherent(dev, size, ctx->priv_key_vaddr, ctx->priv_key_paddr);
		ctx->priv_key_vaddr = NULL;
	}

	if (ctx->rsa_key) {
		memzero_explicit(ctx->rsa_key, sizeof(struct rsa_key));
		kfree(ctx->rsa_key);
		ctx->rsa_key = NULL;
	}

	ctx->key_len = 0;
	ctx->e_len = 0;
	ctx->crt_mode = false;
}

static void ycc_rsa_drop_leading_zeros(struct rsa_key *rsa_key)
{
	__ycc_rsa_drop_leading_zeros(&rsa_key->n, &rsa_key->n_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->e, &rsa_key->e_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->d, &rsa_key->d_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->p, &rsa_key->p_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->q, &rsa_key->q_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->dp, &rsa_key->dp_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->dq, &rsa_key->dq_sz);
	__ycc_rsa_drop_leading_zeros(&rsa_key->qinv, &rsa_key->qinv_sz);
}

static int ycc_rsa_alloc_key(struct ycc_pke_ctx *ctx, bool priv)
{
	struct device *dev = YCC_DEV(ctx);
	struct rsa_key *rsa_key = ctx->rsa_key;
	unsigned int half_key_len;
	size_t size;
	int ret;

	ycc_rsa_drop_leading_zeros(rsa_key);
	ctx->key_len = rsa_key->n_sz;

	ret = ycc_rsa_validate_n(ctx->key_len);
	if (ret) {
		pr_err("Invalid n size:%d bits\n", ctx->key_len << 3);
		goto out;
	}

	ret = -ENOMEM;
	if (priv) {
		if (!(rsa_key->p_sz + rsa_key->q_sz + rsa_key->dp_sz +
		      rsa_key->dq_sz + rsa_key->qinv_sz)) {
			size = ALIGN(rsa_key->e_sz + YCC_PIN_SZ + rsa_key->d_sz +
				     ctx->key_len, YCC_CMD_DATA_ALIGN_SZ);
		} else {
			half_key_len = ctx->key_len >> 1;
			size = ALIGN(rsa_key->e_sz + YCC_PIN_SZ + half_key_len *
				     YCC_RSA_CRT_PARAMS, YCC_CMD_DATA_ALIGN_SZ);
			ctx->crt_mode = true;
		}
		ctx->priv_key_vaddr = dma_alloc_coherent(dev, size,
							 &ctx->priv_key_paddr,
							 GFP_KERNEL);
		if (!ctx->priv_key_vaddr)
			goto out;
		memset(ctx->priv_key_vaddr, 0, size);
	}

	if (!ctx->pub_key_vaddr) {
		size = ALIGN(ctx->key_len + rsa_key->e_sz, YCC_CMD_DATA_ALIGN_SZ);
		ctx->pub_key_vaddr = dma_alloc_coherent(dev, size,
							&ctx->pub_key_paddr,
							GFP_KERNEL);
		if (!ctx->pub_key_vaddr)
			goto out;
		memset(ctx->pub_key_vaddr, 0, size);
	}

	ret = ycc_rsa_set_e(ctx, rsa_key->e, rsa_key->e_sz, priv);
	if (ret) {
		pr_err("Failed to set e for rsa %s key\n", priv ? "private" : "public");
		goto out;
	}

	ret = ycc_rsa_set_n(ctx, rsa_key->n, rsa_key->n_sz, priv);
	if (ret) {
		pr_err("Failed to set n for rsa private key\n");
		goto out;
	}

	if (priv) {
		if (ctx->crt_mode) {
			ret = ycc_rsa_setkey_crt(ctx, rsa_key);
			if (ret) {
				pr_err("Failed to set private key for rsa crt key\n");
				goto out;
			}
		} else {
			ret = ycc_rsa_set_d(ctx, rsa_key->d, rsa_key->d_sz);
			if (ret) {
				pr_err("Failed to set d for rsa private key\n");
				goto out;
			}
		}
	}

	return 0;

out:
	ycc_rsa_clear_ctx(ctx);
	return ret;
}

static int ycc_rsa_setkey(struct crypto_akcipher *tfm, const void *key,
			  unsigned int keylen, bool priv)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key *rsa_key;
	int ret;

	if (priv)
		ret = crypto_akcipher_set_priv_key(ctx->soft_tfm, key, keylen);
	else
		ret = crypto_akcipher_set_pub_key(ctx->soft_tfm, key, keylen);
	if (ret)
		return ret;

	ycc_rsa_clear_ctx(ctx);

	rsa_key = kzalloc(sizeof(struct rsa_key), GFP_KERNEL);
	if (!rsa_key)
		return -ENOMEM;

	if (priv)
		ret = rsa_parse_priv_key(rsa_key, key, keylen);
	else if (!ctx->pub_key_vaddr)
		ret = rsa_parse_pub_key(rsa_key, key, keylen);
	if (ret) {
		pr_err("Failed to parse %s key\n", priv ? "private" : "public");
		kfree(rsa_key);
		return ret;
	}

	ctx->rsa_key = rsa_key;
	return ycc_rsa_alloc_key(ctx, priv);
}

static int ycc_rsa_setpubkey(struct crypto_akcipher *tfm, const void *key,
			     unsigned int keylen)
{
	return ycc_rsa_setkey(tfm, key, keylen, false);
}

static int ycc_rsa_setprivkey(struct crypto_akcipher *tfm, const void *key,
			      unsigned int keylen)
{
	return ycc_rsa_setkey(tfm, key, keylen, true);
}

static unsigned int ycc_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);

	/*
	 * 512 and 1536 bits key size are not supported by YCC,
	 * we use soft tfm instead
	 */
	if (ctx->key_len == YCC_RSA_KEY_SZ_512 ||
	    ctx->key_len == YCC_RSA_KEY_SZ_1536)
		return crypto_akcipher_maxsize(ctx->soft_tfm);

	return ctx->rsa_key ? ctx->key_len : 0;
}

static int ycc_rsa_init(struct crypto_akcipher *tfm)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ycc_ring *ring;

	ctx->soft_tfm = crypto_alloc_akcipher("rsa-generic", 0, 0);
	if (IS_ERR(ctx->soft_tfm)) {
		pr_err("Can not alloc_akcipher!\n");
		return PTR_ERR(ctx->soft_tfm);
	}

	/* Reserve enough space if soft request reqires additional space */
	akcipher_set_reqsize(tfm, sizeof(struct ycc_pke_req) +
			     crypto_akcipher_alg(ctx->soft_tfm)->reqsize);

	ring = ycc_crypto_get_ring();
	if (!ring) {
		crypto_free_akcipher(ctx->soft_tfm);
		return -EINVAL;
	}

	ctx->ring = ring;
	ctx->key_len = 0;
	return 0;
}

static void ycc_rsa_exit(struct crypto_akcipher *tfm)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);

	if (ctx->ring)
		ycc_crypto_free_ring(ctx->ring);

	ycc_rsa_clear_ctx(ctx);
	crypto_free_akcipher(ctx->soft_tfm);
}

#define MPI_NBYTES(m)	((mpi_get_nbits(m) + 7) / 8)

static int ycc_sm2_done_callback(void *ptr, u16 state)
{
	struct ycc_pke_req *sm2_req = (struct ycc_pke_req *)ptr;
	struct ycc_pke_ctx *ctx = sm2_req->ctx;
	struct akcipher_request *req = sm2_req->req;
	struct device *dev = YCC_DEV(ctx);

	dma_free_coherent(dev, 128, sm2_req->src_vaddr, sm2_req->src_paddr);

	if (req->base.complete)
		req->base.complete(&req->base, state == CMD_SUCCESS ? 0 : -EBADMSG);
	return 0;
}

struct sm2_signature_ctx {
	MPI sig_r;
	MPI sig_s;
};

#ifndef CONFIG_CRYPTO_SM2
int sm2_get_signature_r(void *context, size_t hdrlen, unsigned char tag,
			const void *value, size_t vlen)
{
	struct sm2_signature_ctx *sig = context;

	if (!value || !vlen)
		return -EINVAL;

	sig->sig_r = mpi_read_raw_data(value, vlen);
	if (!sig->sig_r)
		return -ENOMEM;

	return 0;
}

int sm2_get_signature_s(void *context, size_t hdrlen, unsigned char tag,
			const void *value, size_t vlen)
{
	struct sm2_signature_ctx *sig = context;

	if (!value || !vlen)
		return -EINVAL;

	sig->sig_s = mpi_read_raw_data(value, vlen);
	if (!sig->sig_s)
		return -ENOMEM;

	return 0;
}
#endif

static int ycc_sm2_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ycc_pke_req *sm2_req = akcipher_request_ctx(req);
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ycc_sm2_verify_cmd *sm2_verify_cmd;
	struct ycc_dev *ydev = ctx->ring->ydev;
	struct ycc_ring *ring = ctx->ring;
	struct device *dev = YCC_DEV(ctx);
	struct sm2_signature_ctx sig;
	struct ycc_flags *aflags;
	u8 buffer[80] = {0};
	int ret;

	/* Do software fallback */
	if (!test_bit(YDEV_STATUS_READY, &ydev->status) || ctx->key_len) {
		akcipher_request_set_tfm(req, ctx->soft_tfm);
		ret = crypto_akcipher_verify(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}

	if (req->src_len > 72 || req->src_len < 70 || req->dst_len != 32)
		return -EINVAL;

	sm2_req->ctx = ctx;
	sm2_req->req = req;

	sg_copy_buffer(req->src, sg_nents(req->src), buffer, req->src_len, 0, 1);
	sig.sig_r = NULL;
	sig.sig_s = NULL;
	ret = asn1_ber_decoder(&sm2signature_decoder, &sig, buffer, req->src_len);
	if (ret)
		return -EINVAL;

	ret = mpi_print(GCRYMPI_FMT_USG, buffer, MPI_NBYTES(sig.sig_r),
			(size_t *)NULL, sig.sig_r);
	if (ret)
		return -EINVAL;

	ret = mpi_print(GCRYMPI_FMT_USG, buffer + MPI_NBYTES(sig.sig_r),
			MPI_NBYTES(sig.sig_s), (size_t *)NULL, sig.sig_s);
	if (ret)
		return -EINVAL;

	ret = -ENOMEM;
	/* Alloc dma for src, as verify has no output */
	sm2_req->src_vaddr = dma_alloc_coherent(dev, 128, &sm2_req->src_paddr,
						GFP_ATOMIC);
	if (!sm2_req->src_vaddr)
		goto out;

	sg_copy_buffer(req->src, sg_nents(req->src), sm2_req->src_vaddr,
		       req->dst_len, req->src_len, 1);
	memcpy(sm2_req->src_vaddr + 32, buffer, 64);

	sm2_req->dst_vaddr = NULL;

	aflags = kzalloc(sizeof(struct ycc_flags), GFP_ATOMIC);
	if (!aflags)
		goto free_src;

	aflags->ptr = (void *)sm2_req;
	aflags->ycc_done_callback = ycc_sm2_done_callback;

	memset(&sm2_req->desc, 0, sizeof(sm2_req->desc));
	sm2_req->desc.private_ptr = (u64)(void *)aflags;

	sm2_verify_cmd         = &sm2_req->desc.cmd.sm2_verify_cmd;
	sm2_verify_cmd->cmd_id = YCC_CMD_SM2_VERIFY;
	sm2_verify_cmd->sptr   = sm2_req->src_paddr;
	sm2_verify_cmd->keyptr = ctx->pub_key_paddr;

	ret = ycc_enqueue(ring, (u8 *)&sm2_req->desc);
	if (!ret)
		return -EINPROGRESS;

	kfree(aflags);
free_src:
	dma_free_coherent(dev, 128, sm2_req->src_vaddr, sm2_req->src_paddr);
out:
	return ret;
}

static unsigned int ycc_sm2_max_size(struct crypto_akcipher *tfm)
{
	return PAGE_SIZE;
}

static int ycc_sm2_setpubkey(struct crypto_akcipher *tfm, const void *key,
			     unsigned int keylen)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct device *dev = YCC_DEV(ctx);
	int ret;

	ret = crypto_akcipher_set_pub_key(ctx->soft_tfm, key, keylen);
	if (ret)
		return ret;

	/* Always alloc 64 bytes for pub key */
	ctx->pub_key_vaddr = dma_alloc_coherent(dev, 64, &ctx->pub_key_paddr,
						GFP_KERNEL);
	if (!ctx->pub_key_vaddr)
		return -ENOMEM;

	/*
	 * Uncompressed key 65 bytes with 0x04 flag
	 * Compressed key 33 bytes with 0x02 or 0x03 flag
	 */
	switch (keylen) {
	case 65:
		if (*(u8 *)key != 0x04)
			return -EINVAL;
		memcpy(ctx->pub_key_vaddr, key + 1, 64);
		break;
	case 64:
		memcpy(ctx->pub_key_vaddr, key, 64);
		break;
	case 33:
		return 0; /* TODO: use sw temporary */
	default:
		return -EINVAL;
	}

	return 0;
}

static int ycc_sm2_init(struct crypto_akcipher *tfm)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct ycc_ring *ring;

	ctx->soft_tfm = crypto_alloc_akcipher("sm2-generic", 0, 0);
	if (IS_ERR(ctx->soft_tfm))
		return PTR_ERR(ctx->soft_tfm);

	/* Reserve enough space if soft request reqires additional space */
	akcipher_set_reqsize(tfm, sizeof(struct ycc_pke_req) +
			     crypto_akcipher_alg(ctx->soft_tfm)->reqsize);

	ring = ycc_crypto_get_ring();
	if (!ring) {
		crypto_free_akcipher(ctx->soft_tfm);
		return -ENODEV;
	}

	ctx->ring = ring;
	return 0;
}

static void ycc_sm2_exit(struct crypto_akcipher *tfm)
{
	struct ycc_pke_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct device *dev = YCC_DEV(ctx);

	if (ctx->ring)
		ycc_crypto_free_ring(ctx->ring);

	if (ctx->pub_key_vaddr)
		dma_free_coherent(dev, 64, ctx->pub_key_vaddr, ctx->pub_key_paddr);

	crypto_free_akcipher(ctx->soft_tfm);
}

static struct akcipher_alg ycc_rsa = {
	.base = {
		.cra_name = "rsa",
		.cra_driver_name = "ycc-rsa",
		.cra_priority = 1000,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ycc_pke_ctx),
	},
	.sign = ycc_rsa_sign,
	.verify = ycc_rsa_verify,
	.encrypt = ycc_rsa_encrypt,
	.decrypt = ycc_rsa_decrypt,
	.set_pub_key = ycc_rsa_setpubkey,
	.set_priv_key = ycc_rsa_setprivkey,
	.max_size = ycc_rsa_max_size,
	.init = ycc_rsa_init,
	.exit = ycc_rsa_exit,
};

static struct akcipher_alg ycc_sm2 = {
	.base = {
		.cra_name = "sm2",
		.cra_driver_name = "ycc-sm2",
		.cra_priority = 1000,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct ycc_pke_ctx),
	},
	.verify = ycc_sm2_verify,
	.set_pub_key = ycc_sm2_setpubkey,
	.max_size = ycc_sm2_max_size,
	.init = ycc_sm2_init,
	.exit = ycc_sm2_exit,
};

int ycc_pke_register(void)
{
	int ret;

	ret = crypto_register_akcipher(&ycc_rsa);
	if (ret) {
		pr_err("Failed to register rsa\n");
		return ret;
	}

	ret = crypto_register_akcipher(&ycc_sm2);
	if (ret) {
		crypto_unregister_akcipher(&ycc_rsa);
		pr_err("Failed to register sm2\n");
	}

	return ret;
}

void ycc_pke_unregister(void)
{
	crypto_unregister_akcipher(&ycc_rsa);
	crypto_unregister_akcipher(&ycc_sm2);
}
