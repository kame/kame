/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
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
/* YIPS $Id: crypto_openssl.c,v 1.21 2000/02/23 06:13:55 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>

/* get openssl/ssleay version number */
#ifdef INCLUDE_PATH_OPENSSL
# ifdef HAVE_OPENSSL_OPENSSLV_H
#  include <openssl/opensslv.h>
#  define SSLVER	OPENSSL_VERSION_NUMBER
# endif
#else
# ifdef HAVE_OPENSSLV_H
#  include <opensslv.h>
#  define SSLVER	OPENSSL_VERSION_NUMBER
# else
#  ifdef HAVE_CVERSION_H
#   include <cversion.h>
#   define SSLVER	SSLEAY_VERSION_NUMBER
#  endif
# endif
#endif

#ifdef INCLUDE_PATH_OPENSSL
#ifdef HAVE_OPENSSL_PEM_H
#include <openssl/pem.h>
#endif
#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif
#ifdef HAVE_OPENSSL_X509_H
#include <openssl/x509.h>
#endif
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/crypto.h>
#ifdef HAVE_OPENSSL_IDEA_H
#include <openssl/idea.h>
#endif
#include <openssl/blowfish.h>
#ifdef HAVE_OPENSSL_RC5_H
#include <openssl/rc5.h>
#endif
#include <openssl/cast.h>
#include <openssl/err.h>
#else /* INCLUDE_PATH_OPENSSL */
#ifdef HAVE_PEM_H
#include <pem.h>
#endif
#ifdef HAVE_EVP_H
#include <evp.h>
#endif
#ifdef HAVE_X509_H
#include <x509.h>
#endif
#include <bn.h>
#include <dh.h>
#include <md5.h>
#include <sha.h>
#include <des.h>
#include <crypto.h>
#ifdef HAVE_IDEA_H
#include <idea.h>
#endif
#include <blowfish.h>
#ifdef HAVE_RC5_H
#include <rc5.h>
#endif
#include <cast.h>
#include <err.h>
#endif /* INCLUDE_PATH_OPENSSL */

#include "var.h"
#include "vmbuf.h"
#include "oakley.h"
#include "crypto_openssl.h"
#include "debug.h"

/*
 * I hate to cast every parameter to des_xx into void *, but it is
 * necessary for SSLeay/OpenSSL portability.  It sucks.
 */

#ifdef HAVE_SIGNING_C
/* X509 Certificate */
/*
 * get a X509 certificate from local file.
 * a certificate must be PEM format.
 * Input:
 *	path to a certificate.
 * Output:
 *	NULL if error occured
 *	other is the cert.
 */
vchar_t *
eay_get_x509cert(path)
	char *path;
{
	FILE *fp;
	X509 *x509;
	vchar_t *cert;
	u_char *bp;
	int len;
	int error;

	/* Read private key */
	fp = fopen (path, "r");
	if (fp == NULL)
		return NULL;
#if (defined(SSLVER) && SSLVER >= 0x0940)
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#else
	x509 = PEM_read_X509(fp, NULL, NULL);
#endif
	fclose (fp);

	if (x509 == NULL)
		return NULL;

	len = i2d_X509(x509, NULL);
	cert = vmalloc(len);
	if (cert == NULL) {
		X509_free(x509);
		return NULL;
	}
	bp = cert->v;
	error = i2d_X509(x509, &bp);
	X509_free(x509);

	if (error == 0)
		return NULL;

	return cert;
}

/*
 * sign a souce by X509 signature.
 * XXX: to be get hash type from my cert ?
 *	to be handled EVP_dss().
 */
vchar_t *
eay_get_x509sign(source, privkey, cert)
	vchar_t *source;
	vchar_t *privkey;
	vchar_t *cert;
{
	EVP_MD_CTX md_ctx;
	EVP_PKEY *evp;
	u_char *bp;
	char sigbuf[BUFSIZE];
	int siglen;
	vchar_t *sig = NULL;
	int error;

	bp = privkey->v;

	/* XXX to be handled EVP_PKEY_DSA */
	evp = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &bp, privkey->l);
	if (evp == NULL)
		return NULL;

	/* XXX: to be handled EVP_dss() */
	/* XXX: Where can I get such parameters ?  From my cert ? */
	/* XXX: How can I get a length of signed buffer */
	EVP_SignInit(&md_ctx, EVP_sha1());
	EVP_SignUpdate(&md_ctx, source->v, source->l);
	siglen = sizeof(sigbuf);
	error = EVP_SignFinal(&md_ctx, sigbuf, &siglen, evp);

	EVP_PKEY_free(evp);

	if (error != 1)
		return NULL;

	sig = vmalloc(siglen);
	if (sig == NULL)
		return NULL;
	memcpy(sig->v, sigbuf, siglen);

	return sig;
}

/*
 * check a X509 signature
 *	XXX: to be get hash type from my cert ?
 *		to be handled EVP_dss().
 * OUT: return -1 when error.
 *	0
 */
int
eay_check_x509sign(source, sig, cert)
	vchar_t *source;
	vchar_t *sig;
	vchar_t *cert;
{
	X509 *x509;
	EVP_MD_CTX md_ctx;
	EVP_PKEY *evp;
	u_char *bp;
	int error;

	bp = cert->v;
	x509 = d2i_X509(NULL, &bp, cert->l);
	if (x509 == NULL)
		return -1;

	evp = X509_get_pubkey(x509);
	X509_free(x509);
	if (evp == NULL)
		return -1;

	/* Verify the signature */
	/* XXX: to be handled EVP_dss() */
	EVP_VerifyInit(&md_ctx, EVP_sha1());
	EVP_VerifyUpdate(&md_ctx, source->v, source->l);
	error = EVP_VerifyFinal(&md_ctx, sig->v, sig->l, evp);

	EVP_PKEY_free(evp);

	if (error != 1)
		return -1;

	return 0;
}

/*
 * get PKCS#1 Private Key of PEM format from local file.
 */
vchar_t *
eay_get_pkcs1privkey(path)
	char *path;
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	vchar_t *pkey = NULL;
	u_char *bp;
	int pkeylen;
	int error = -1;

	/* Read private key */
	fp = fopen (path, "r");
	if (fp == NULL)
		return NULL;

#if (defined(SSLVER) && SSLVER >= 0x0940)
	evp = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
#else
	evp = PEM_read_PrivateKey(fp, NULL, NULL);
#endif
	fclose (fp);

	if (evp == NULL)
		return NULL;

	pkeylen = i2d_PrivateKey(evp, NULL);
	if (pkeylen == 0)
		goto end;
	pkey = vmalloc(pkeylen);
	if (pkey == NULL)
		goto end;
	bp = pkey->v;
	pkeylen = i2d_PrivateKey(evp, &bp);
	if (pkeylen == 0)
		goto end;

	error = 0;

end:
	if (evp != NULL)
		EVP_PKEY_free(evp);
	if (error != 0 && pkey != NULL) {
		vfree(pkey);
		pkey = NULL;
	}

	return pkey;
}

/*
 * get PKCS#1 Public Key of PEM format from local file.
 */
vchar_t *
eay_get_pkcs1pubkey(path)
	char *path;
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	vchar_t *pkey = NULL;
	X509 *x509 = NULL;
	u_char *bp;
	int pkeylen;
	int error = -1;

	/* Read private key */
	fp = fopen (path, "r");
	if (fp == NULL)
		return NULL;

#if (defined(SSLVER) && SSLVER >= 0x0940)
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#else
	x509 = PEM_read_X509(fp, NULL, NULL);
#endif
	fclose (fp);

	if (x509 == NULL)
		return NULL;
  
	/* Get public key - eay */
	evp = X509_get_pubkey(x509);
	if (evp == NULL)
		return NULL;

	pkeylen = i2d_PublicKey(evp, NULL);
	if (pkeylen == 0)
		goto end;
	pkey = vmalloc(pkeylen);
	if (pkey == NULL)
		goto end;
	bp = pkey->v;
	pkeylen = i2d_PublicKey(evp, &bp);
	if (pkeylen == 0)
		goto end;

	error = 0;
end:
	if (evp != NULL)
		EVP_PKEY_free(evp);
	if (error != 0 && pkey != NULL) {
		vfree(pkey);
		pkey = NULL;
	}

	return pkey;
}
#endif
  
/*
 * get error string
 * MUST load ERR_load_crypto_strings() first.
 */
char *
eay_strerror()
{
	static char ebuf[512];
	int len = 0;
	unsigned long l;
	char buf[200];
#if SSLVER >= 0x0940
	const char *file, *data;
#else
	char *file, *data;
#endif
	int line, flags;
	unsigned long es;

	es = CRYPTO_thread_id();

	while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0){
		len += snprintf(ebuf + len, sizeof(ebuf) - len,
				"%lu:%s:%s:%d:%s ",
				es, ERR_error_string(l, buf), file, line,
				(flags & ERR_TXT_STRING) ? data : "");
		if (sizeof(ebuf) < len)
			break;
	}

	return ebuf;
}

void
eay_init_error()
{
	ERR_load_crypto_strings();
}

/*
 * DES-CBC
 */
vchar_t *
eay_des_encrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	des_key_schedule ks;

	if (des_key_sched((void *)key->v, ks) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	des_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
	                ks, (void *)iv, DES_ENCRYPT);

	return res;
}

vchar_t *
eay_des_decrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	des_key_schedule ks;

	if (des_key_sched((void *)key->v, ks) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	des_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
	                ks, (void *)iv, DES_DECRYPT);

	return res;
}

int
eay_des_weakkey(key)
	vchar_t *key;
{
	return des_is_weak_key((void *)key->v);
}

#ifdef HAVE_IDEA_H
/*
 * IDEA-CBC
 */
vchar_t *
eay_idea_encrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	IDEA_KEY_SCHEDULE ks;

	idea_set_encrypt_key(key->v, &ks);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	idea_cbc_encrypt(data->v, res->v, data->l,
	                &ks, iv, IDEA_ENCRYPT);

	return res;
}

vchar_t *
eay_idea_decrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	IDEA_KEY_SCHEDULE ks, dks;

	idea_set_encrypt_key(key->v, &ks);
	idea_set_decrypt_key(&ks, &dks);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	idea_cbc_encrypt(data->v, res->v, data->l,
	                &dks, iv, IDEA_DECRYPT);

	return res;
}

int
eay_idea_weakkey(key)
	vchar_t *key;
{
	return 0;	/* XXX */
}
#endif

/*
 * BLOWFISH-CBC
 */
vchar_t *
eay_bf_encrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	BF_KEY ks;

	BF_set_key(&ks, key->l, key->v);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	BF_cbc_encrypt(data->v, res->v, data->l,
		&ks, iv, BF_ENCRYPT);

	return res;
}

vchar_t *
eay_bf_decrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	BF_KEY ks;

	BF_set_key(&ks, key->l, key->v);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	BF_cbc_encrypt(data->v, res->v, data->l,
		&ks, iv, BF_DECRYPT);

	return res;
}

int
eay_bf_weakkey(key)
	vchar_t *key;
{
	return 0;	/* XXX to be done. refer to RFC 2451 */
}

#ifdef HAVE_RC5_H
/*
 * RC5-CBC
 */
vchar_t *
eay_rc5_encrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	RC5_32_KEY ks;

	/* in RFC 2451, there is information about the number of round. */
	RC5_32_set_key(&ks, key->l, key->v, 16);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	RC5_32_cbc_encrypt(data->v, res->v, data->l,
		&ks, iv, RC5_ENCRYPT);

	return res;
}

vchar_t *
eay_rc5_decrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	RC5_32_KEY ks;

	/* in RFC 2451, there is information about the number of round. */
	RC5_32_set_key(&ks, key->l, key->v, 16);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	RC5_32_cbc_encrypt(data->v, res->v, data->l,
		&ks, iv, RC5_DECRYPT);

	return res;
}

int
eay_rc5_weakkey(key)
	vchar_t *key;
{
	return 0;	/* No known weak keys when used with 16 rounds. */

}
#endif

/*
 * 3DES-CBC
 */
vchar_t *
eay_3des_encrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	des_key_schedule ks1, ks2, ks3;

	if (key->l < 24)
		return NULL;

	if (des_key_sched((void *)key->v, ks1) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 8), ks2) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 16), ks3) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	des_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
	                ks1, ks2, ks3, (void *)iv, DES_ENCRYPT);

	return res;
}

vchar_t *
eay_3des_decrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	des_key_schedule ks1, ks2, ks3;

	if (key->l < 24)
		return NULL;

	if (des_key_sched((void *)key->v, ks1) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 8), ks2) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 16), ks3) != 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	des_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
	                ks1, ks2, ks3, (void *)iv, DES_DECRYPT);

	return res;
}

int
eay_3des_weakkey(key)
	vchar_t *key;
{
	if (key->l < 24)
		return NULL;

	return (des_is_weak_key((void *)key->v)
		|| des_is_weak_key((void *)(key->v + 8))
		|| des_is_weak_key((void *)(key->v + 16)));
}

/*
 * CAST-CBC
 */
vchar_t *
eay_cast_encrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	CAST_KEY ks;

	CAST_set_key(&ks, key->l, key->v);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	CAST_cbc_encrypt(data->v, res->v, data->l,
	                &ks, iv, DES_ENCRYPT);

	return res;
}

vchar_t *
eay_cast_decrypt(data, key, iv)
	vchar_t *data, *key;
	caddr_t iv;
{
	vchar_t *res;
	CAST_KEY ks;

	CAST_set_key(&ks, key->l, key->v);

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	CAST_cbc_encrypt(data->v, res->v, data->l,
	                &ks, iv, DES_DECRYPT);

	return res;
}

int
eay_cast_weakkey(key)
	vchar_t *key;
{
	return 0;	/* No known weak keys. */
}

/*
 * HMAC-SHA1
 */
vchar_t *
eay_hmacsha1_oneX(key, data, data2)
	vchar_t *key, *data, *data2;
{
	vchar_t *res;
	SHA_CTX c;
	u_char k_ipad[65], k_opad[65];
	u_char *nkey;
	int nkeylen;
	int i;
	u_char tk[SHA_DIGEST_LENGTH];

	/* initialize */
	if ((res = vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return(0);

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	nkey = key->v;
	nkeylen = key->l;

	if (nkeylen > 64) {
		SHA_CTX      ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, nkey, nkeylen);
		SHA1_Final(tk, &ctx);

		nkey = tk;
		nkeylen = SHA_DIGEST_LENGTH;
	}

	/* start out by string key in pads */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, nkey, nkeylen);
	memcpy(k_opad, nkey, nkeylen);

	/* XOR key with ipad and opad values */
	for (i=0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* key */
	SHA1_Init(&c);
	SHA1_Update(&c, k_ipad, 64);

	/* finish up 1st pass */
	SHA1_Update(&c, data->v, data->l);
	SHA1_Update(&c, data2->v, data2->l);
	SHA1_Final(res->v, &c);

	/* perform outer SHA1 */
	SHA1_Init(&c);
	SHA1_Update(&c, k_opad, 64);
	SHA1_Update(&c, res->v, SHA_DIGEST_LENGTH);
	SHA1_Final(res->v, &c);

	return(res);
};

/*
 * HMAC SHA1
 */
vchar_t *
eay_hmacsha1_one(key, data)
	vchar_t *key, *data;
{
	vchar_t *res;
	SHA_CTX c;
	u_char k_ipad[65], k_opad[65];
	u_char *nkey;
	int nkeylen;
	int i;
	u_char tk[SHA_DIGEST_LENGTH];

	/* initialize */
	if ((res = vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return(0);

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	nkey = key->v;
	nkeylen = key->l;

	if (nkeylen > 64) {
		SHA_CTX      ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, nkey, nkeylen);
		SHA1_Final(tk, &ctx);

		nkey = tk;
		nkeylen = SHA_DIGEST_LENGTH;
	}

	/* start out by string key in pads */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, nkey, nkeylen);
	memcpy(k_opad, nkey, nkeylen);

	/* XOR key with ipad and opad values */
	for (i=0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* key */
	SHA1_Init(&c);
	SHA1_Update(&c, k_ipad, 64);

	/* finish up 1st pass */
	SHA1_Update(&c, data->v, data->l);
	SHA1_Final(res->v, &c);

	/* perform outer SHA1 */
	SHA1_Init(&c);
	SHA1_Update(&c, k_opad, 64);
	SHA1_Update(&c, res->v, SHA_DIGEST_LENGTH);
	SHA1_Final(res->v, &c);

	return(res);
};

/*
 * HMAC MD5
 */
vchar_t *
eay_hmacmd5_one(key, data)
	vchar_t *key, *data;
{
	vchar_t *res;
	MD5_CTX c;
	u_char k_ipad[65], k_opad[65];
	u_char *nkey;
	int nkeylen;
	int i;
	u_char tk[MD5_DIGEST_LENGTH];

	/* initialize */
	if ((res = vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return(0);

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	nkey = key->v;
	nkeylen = key->l;

	if (nkeylen > 64) {
		MD5_CTX      ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, nkey, nkeylen);
		MD5_Final(tk, &ctx);

		nkey = tk;
		nkeylen = MD5_DIGEST_LENGTH;
	}

	/* start out by string key in pads */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, nkey, nkeylen);
	memcpy(k_opad, nkey, nkeylen);

	/* XOR key with ipad and opad values */
	for (i=0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* key */
	MD5_Init(&c);
	MD5_Update(&c, k_ipad, 64);

	/* finish up 1st pass */
	MD5_Update(&c, data->v, data->l);
	MD5_Final(res->v, &c);

	/* perform outer MD5 */
	MD5_Init(&c);
	MD5_Update(&c, k_opad, 64);
	MD5_Update(&c, res->v, MD5_DIGEST_LENGTH);
	MD5_Final(res->v, &c);

	return(res);
};

/*
 * SHA functions
 */
caddr_t
eay_sha1_init()
{
	SHA_CTX *c = malloc(sizeof(*c));

	SHA1_Init(c);

	return((caddr_t)c);
}

void
eay_sha1_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	SHA1_Update((SHA_CTX *)c, data->v, data->l);

	return;
}

vchar_t *
eay_sha1_final(c)
	caddr_t c;
{
	vchar_t *res;

	if ((res = vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return(0);

	SHA1_Final(res->v, (SHA_CTX *)c);
	(void)free(c);

	return(res);
}

vchar_t *
eay_sha1_one(data)
	vchar_t *data;
{
	caddr_t ctx;
	vchar_t *res;

	ctx = eay_sha1_init();
	eay_sha1_update(ctx, data);
	res = eay_sha1_final(ctx);

	return(res);
}

/*
 * MD5 functions
 */
caddr_t
eay_md5_init()
{
	MD5_CTX *c = malloc(sizeof(*c));

	MD5_Init(c);

	return((caddr_t)c);
}

void
eay_md5_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	MD5_Update((MD5_CTX *)c, data->v, data->l);

	return;
}

vchar_t *
eay_md5_final(c)
	caddr_t c;
{
	vchar_t *res;

	if ((res = vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return(0);

	MD5_Final(res->v, (MD5_CTX *)c);
	(void)free(c);

	return(res);
}

vchar_t *
eay_md5_one(data)
	vchar_t *data;
{
	caddr_t ctx;
	vchar_t *res;

	ctx = eay_md5_init();
	eay_md5_update(ctx, data);
	res = eay_md5_final(ctx);

	return(res);
}

/*
 * eay_set_random
 *   size: number of bytes.
 */
vchar_t *
eay_set_random(size)
	u_int32_t size;
{
	BIGNUM *r = NULL;
	vchar_t *res = 0;

	if ((r = BN_new()) == NULL)
		goto end;
	BN_rand(r, size * 8, 0, 0);
	eay_bn2v(&res, r);

end:
	if (r)
		BN_free(r);
	return(res);
}

/* DH */
int
eay_dh_generate(prime, g, publen, pub, priv)
	vchar_t *prime, **pub, **priv;
	u_int publen;
	u_int32_t g;
{
	BIGNUM *p = NULL;
	DH *dh = NULL;
	int error = -1;

	/* initialize */
	/* pre-process to generate number */
	if (eay_v2bn(&p, prime) < 0)
		goto end;

	if ((dh = DH_new()) == NULL)
		goto end;
	dh->p = p;
	p = NULL;	/* p is now part of dh structure */
	dh->g = NULL;
	if ((dh->g = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(dh->g, g))
		goto end;

	if (publen != 0)
		dh->length = publen;

	/* generate public and private number */
	if (!DH_generate_key(dh))
		goto end;

	/* copy results to buffers */
	if (eay_bn2v(pub, dh->pub_key) < 0)
		goto end;
	if (eay_bn2v(priv, dh->priv_key) < 0) {
		vfree(*pub);
		goto end;
	}

	error = 0;

end:
	if (dh != NULL)
		DH_free(dh);
	if (p != 0)
		BN_free(p);
	return(error);
}

int
eay_dh_compute(prime, g, pub, priv, pub2, key)
	vchar_t *prime, *pub, *priv, *pub2, **key;
	u_int32_t g;
{
	BIGNUM *dh_pub = NULL;
	DH *dh = NULL;
#if 0
	vchar_t *gv = 0;
#endif
	int error = -1;

	/* make public number to compute */
	if (eay_v2bn(&dh_pub, pub2) < 0)
		goto end;

	/* make DH structure */
	if ((dh = DH_new()) == NULL)
		goto end;
	if (eay_v2bn(&dh->p, prime) < 0)
		goto end;
	if (eay_v2bn(&dh->pub_key, pub) < 0)
		goto end;
	if (eay_v2bn(&dh->priv_key, priv) < 0)
		goto end;
	dh->length = pub2->l * 8;

#if 1
	dh->g = NULL;
	if ((dh->g = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(dh->g, g))
		goto end;
#else
	if ((gv = vmalloc(sizeof(g))) == 0)
		goto end;
	memcpy(gv->v, (caddr_t)&g, sizeof(g));
	if (eay_v2bn(&dh->g, gv) < 0)
		goto end;
#endif

	DH_compute_key((*key)->v, dh_pub, dh);

	error = 0;

end:
#if 0
	if (gv) vfree(gv);
#endif
	if (dh_pub != NULL)
		BN_free(dh_pub);
	if (dh != NULL)
		DH_free(dh);
	return(error);
}

#if 1
int
eay_v2bn(bn, var)
	BIGNUM **bn;
	vchar_t *var;
{
	if ((*bn = BN_bin2bn(var->v, var->l, NULL)) == NULL)
		return -1;

	return 0;
}
#else
/*
 * convert vchar_t <-> BIGNUM.
 *
 * vchar_t: unit is u_char, network endian, most significant byte first.
 * BIGNUM: unit is BN_ULONG, each of BN_ULONG is in host endian,
 *	least significant BN_ULONG must come first.
 *
 * hex value of "0x3ffe050104" is represented as follows:
 *	vchar_t: 3f fe 05 01 04
 *	BIGNUM (BN_ULONG = u_int8_t): 04 01 05 fe 3f
 *	BIGNUM (BN_ULONG = u_int16_t): 0x0104 0xfe05 0x003f
 *	BIGNUM (BN_ULONG = u_int32_t_t): 0xfe050104 0x0000003f
 */
int
eay_v2bn(bn, var)
	BIGNUM **bn;
	vchar_t *var;
{
	u_char *p;
	u_char *q;
	BN_ULONG *r;
	int l;
	BN_ULONG num;

	*bn = BN_new();
	if (*bn == NULL)
		goto err;
	l = (var->l * 8 + BN_BITS2 - 1) / BN_BITS2;
	if (bn_expand(*bn, l * BN_BITS2) == NULL)
		goto err;
	(*bn)->top = l;

	/* scan from least significant byte */
	p = (u_char *)var->v;
	q = (u_char *)(var->v + var->l);
	r = (*bn)->d;
	num = 0;
	l = 0;
	do {
		q--;
		num = num | ((BN_ULONG)*q << (l++ * 8));
		if (l == BN_BYTES) {
			*r++ = num;
			num = 0;
			l = 0;
		}
	} while (p < q);
	if (l)
		*r = num;
	return 0;

err:
	if (*bn)
		BN_free(*bn);
	return -1;
}
#endif

#if 1
int
eay_bn2v(var, bn)
	vchar_t **var;
	BIGNUM *bn;
{
	*var = vmalloc(bn->top * BN_BYTES);
	if (*var == NULL)
		return(-1);

	(*var)->l = BN_bn2bin(bn, (*var)->v);

	return 0;
}
#else
int
eay_bn2v(var, bn)
	vchar_t **var;
	BIGNUM *bn;
{
	int i;
	BN_ULONG *p;

	*var = vmalloc(bn->top * BN_BYTES);
	if (*var == NULL)
		return(-1);
	p = (BN_ULONG *)(*var)->v;

	/* scan from most significant word (BN_ULONG) */
	for (i = bn->top - 1; 0 <= i; i--) {
#if BN_BYTES == 2
		*p++ = htons(bn->d[i]);
#else
# if BN_BYTES == 4
		*p++ = htonl(bn->d[i]);
# else
	    {
		u_char *q;
		int j;
		q = (u_char *)p;
		for (j = BN_BYTES - 1; 0 <= j; j++) {
			*q++ = (bn->d[i] >> (j * 8)) & 0xff;
		}
		p++;
	    }
# endif
#endif
	}

	return(0);
}
#endif
