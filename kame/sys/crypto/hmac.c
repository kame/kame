/*	$KAME: hmac.c,v 1.3 2002/07/08 09:52:09 t-momose Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* RFC2104   HMAC: Keyed-Hashing for Message Authentication */

/* Some of operating systems have standard crypto checksum library */
#ifdef __NetBSD__
#define HAVE_MD5
#define HAVE_SHA1
#endif
#ifdef __FreeBSD__
#define HAVE_MD5
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#ifdef HAVE_MD5
#include <sys/md5.h>
#else
#include <crypto/md5.h>
#endif
#ifdef HAVE_SHA1
#include <sys/sha1.h>
#define SHA1_RESULTLEN	20
#else
#include <crypto/sha1.h>
#endif
#include <crypto/sha2/sha2.h>

#include <crypto/hmac.h>

#define	HMACSIZE	16

static void md5_init_stub(HMAC_CTX *);
static void md5_update_stub(HMAC_CTX *, u_int8_t *, u_int);
static void md5_result_stub(HMAC_CTX *, u_int8_t *);
static void sha1_init_stub(HMAC_CTX *);
static void sha1_update_stub(HMAC_CTX *, u_int8_t *, u_int);
static void sha1_result_stub(HMAC_CTX *, u_int8_t *);
static void sha2_256_init_stub(HMAC_CTX *);
static void sha2_256_update_stub(HMAC_CTX *, u_int8_t *, u_int);
static void sha2_256_result_stub(HMAC_CTX *, u_int8_t *);
static void sha2_384_init_stub(HMAC_CTX *);
static void sha2_384_update_stub(HMAC_CTX *, u_int8_t *, u_int);
static void sha2_384_result_stub(HMAC_CTX *, u_int8_t *);
static void sha2_512_init_stub(HMAC_CTX *);
static void sha2_512_update_stub(HMAC_CTX *, u_int8_t *, u_int);
static void sha2_512_result_stub(HMAC_CTX *, u_int8_t *);

struct hmac_hash hmac_hash[] = {
	{sizeof(MD5_CTX), 16,
		md5_init_stub, md5_update_stub, md5_result_stub},
	{sizeof(SHA1_CTX), SHA1_RESULTLEN,
		sha1_init_stub, sha1_update_stub, sha1_result_stub},
	{sizeof(SHA256_CTX), SHA256_DIGEST_LENGTH,
		sha2_256_init_stub, sha2_256_update_stub, sha2_256_result_stub},
	{sizeof(SHA384_CTX), SHA384_DIGEST_LENGTH,
		sha2_384_init_stub, sha2_384_update_stub, sha2_384_result_stub},
	{sizeof(SHA512_CTX), SHA512_DIGEST_LENGTH,
		sha2_512_init_stub, sha2_512_update_stub, sha2_512_result_stub},
};

static void
md5_init_stub(hmac_ctx)
	HMAC_CTX *hmac_ctx;
{
	MD5Init((MD5_CTX *)hmac_ctx->hash_ctx);
}

static void
md5_update_stub(hmac_ctx, addr, len)
	HMAC_CTX *hmac_ctx;
	u_int8_t *addr;
	u_int len;
{
	MD5Update((MD5_CTX *)hmac_ctx->hash_ctx, addr, len);
}

static void
md5_result_stub(hmac_ctx, result)
	HMAC_CTX *hmac_ctx;
	u_int8_t *result;
{
	MD5Final(result, (MD5_CTX *)hmac_ctx->hash_ctx);
}

static void
sha1_init_stub(hmac_ctx)
	HMAC_CTX *hmac_ctx;
{
	SHA1Init((SHA1_CTX *)hmac_ctx->hash_ctx);
}

static void
sha1_update_stub(hmac_ctx, addr, len)
	HMAC_CTX *hmac_ctx;
	u_int8_t *addr;
	u_int len;
{
	SHA1Update((SHA1_CTX *)hmac_ctx->hash_ctx, addr, len);
}

static void
sha1_result_stub(hmac_ctx, result)
	HMAC_CTX *hmac_ctx;
	u_int8_t *result;
{
	SHA1Final(result, (SHA1_CTX *)hmac_ctx->hash_ctx);
}

static void
sha2_256_init_stub(hmac_ctx)
	HMAC_CTX *hmac_ctx;
{
	SHA256_Init((SHA256_CTX *)hmac_ctx->hash_ctx);
}

static void
sha2_256_update_stub(hmac_ctx, addr, len)
	HMAC_CTX *hmac_ctx;
	u_int8_t *addr;
	u_int len;
{
	SHA256_Update((SHA256_CTX *)hmac_ctx->hash_ctx, addr, len);
}

static void
sha2_256_result_stub(hmac_ctx, result)
	HMAC_CTX *hmac_ctx;
	u_int8_t *result;
{
	SHA256_Final(result, (SHA256_CTX *)hmac_ctx->hash_ctx);
}

static void
sha2_384_init_stub(hmac_ctx)
	HMAC_CTX *hmac_ctx;
{
	SHA384_Init((SHA384_CTX *)hmac_ctx->hash_ctx);
}

static void
sha2_384_update_stub(hmac_ctx, addr, len)
	HMAC_CTX *hmac_ctx;
	u_int8_t *addr;
	u_int len;
{
	SHA384_Update((SHA384_CTX *)hmac_ctx->hash_ctx, addr, len);
}

static void
sha2_384_result_stub(hmac_ctx, result)
	HMAC_CTX *hmac_ctx;
	u_int8_t *result;
{
	SHA384_Final(result, (SHA384_CTX *)hmac_ctx->hash_ctx);
}

static void
sha2_512_init_stub(hmac_ctx)
	HMAC_CTX *hmac_ctx;
{
	SHA512_Init((SHA512_CTX *)hmac_ctx->hash_ctx);
}

static void
sha2_512_update_stub(hmac_ctx, addr, len)
	HMAC_CTX *hmac_ctx;
	u_int8_t *addr;
	u_int len;
{
	SHA512_Update((SHA512_CTX *)hmac_ctx->hash_ctx, addr, len);
}

static void
sha2_512_result_stub(hmac_ctx, result)
	HMAC_CTX *hmac_ctx;
	u_int8_t *result;
{
	SHA512_Final(result, (SHA512_CTX *)hmac_ctx->hash_ctx);
}

int
hmac_init(ctx, hmac_key, hmac_keylen, hash)
	HMAC_CTX *ctx;
	u_int8_t *hmac_key;
	int hmac_keylen;
	struct hmac_hash *hash;
{
	u_char *ipad;
	u_char *opad;
	int error = 0;
	u_char *tk = NULL;
	u_char *key;
	size_t keylen;
	size_t i;

	if (!ctx || !hmac_key || hmac_keylen == 0 || !hash)
		return (EINVAL);

	bzero(ctx, sizeof(*ctx));
	ctx->key = malloc(hmac_keylen, M_TEMP, M_NOWAIT);
	if (!ctx->key) {
		error = ENOBUFS;
		goto bad;
	}
	bcopy(hmac_key, ctx->key, hmac_keylen);
	ctx->keylen = hmac_keylen;
	ctx->foo = (void *)malloc(64 + 64 + hash->ctx_size, M_TEMP, M_NOWAIT);
	if (!ctx->foo) {
		error = ENOBUFS;
		goto bad;
	}

	ipad = (u_char *)ctx->foo;
	opad = (u_char *)(ipad + 64);
	ctx->hash_ctx = (void *)(opad + 64);

	ctx->hash = hash;

	if (hmac_keylen > 64) {
		tk = (u_char *)malloc(hash->hash_resultlen, M_TEMP, M_NOWAIT);
		if (!tk) {
			error = ENOBUFS;
			goto bad;
		}
		hash->init(ctx);
		hash->loop(ctx, ctx->key, ctx->keylen);
		hash->result(ctx, tk);
		key = tk;
		keylen = hash->hash_resultlen;
	} else {
		key = ctx->key;
		keylen = ctx->keylen;
	}

	bzero(ipad, 64);
	bzero(opad, 64);
	bcopy(key, ipad, keylen);
	bcopy(key, opad, keylen);
	for (i = 0; i < 64; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	hash->init(ctx);
	hash->loop(ctx, ipad, 64);

	if (tk)
		free(tk, M_TEMP);

	return (0);
bad:
	if (ctx->key)
		free(ctx->key, M_TEMP);
	if (ctx->foo);
		free(ctx->foo, M_TEMP);
	return (error);
}

int
hmac_loop(ctx, addr, len)
	HMAC_CTX *ctx;
	u_int8_t *addr;
	int len;
{
	if (!ctx || !ctx->foo)
		return (EINVAL);

	ctx->hash_ctx = ((caddr_t)ctx->foo) + 128;
	ctx->hash->loop(ctx, addr, len);
	
	return (0);
}

int
hmac_result(ctx, addr)
	HMAC_CTX *ctx;
	u_int8_t *addr;
{
	u_char *digest;
	u_char *ipad;
	u_char *opad;
	int error = 0;

	if (!ctx || !ctx->foo)
		return (EINVAL);

	ipad = (u_char *)ctx->foo;
	opad = (u_char *)(ipad + 64);

	digest = (u_char *)malloc(ctx->hash->hash_resultlen, M_TEMP, M_NOWAIT);
	if (!digest) {
		error = ENOBUFS;
		goto bad;
	}

	ctx->hash->result(ctx, digest);

	ctx->hash->init(ctx);
	ctx->hash->loop(ctx, opad, 64);
	ctx->hash->loop(ctx, digest, ctx->hash->hash_resultlen);
	ctx->hash->result(ctx, digest);

	bcopy(digest, (void *)addr, HMACSIZE);

	free(digest, M_TEMP);

bad:
	free(ctx->foo, M_TEMP);
	free(ctx->key, M_TEMP);

	return (error);
}
