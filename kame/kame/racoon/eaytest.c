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
/* YIPS @(#)$Id: eaytest.c,v 1.1 1999/08/08 23:31:20 itojun Exp $ */

#include <sys/types.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define TEST_RAND	0x00000001
#define TEST_DH		0x00000002
#define TEST_MD5	0x00000004
#define TEST_SHA1	0x00000008
#define TEST_HMAC	0x00000010
#define TEST_CIPHER	0x00000020

#include "var.h"
#include "vmbuf.h"
#include "oakley.h"
#include "crypto.h"
#include "misc.h"
#include "debug.h"

unsigned long debug = 0;

/* test */
void
ciphertest()
{
	vchar_t data;
	vchar_t key;
	vchar_t *res1, *res2;
	char iv[8];

	data.v = strtob("a7c3a855 a328a6d4 b1bd9c06 c5bd5c17 b8c5f657 bd8ea245 2a6726d0 ce3689f5", 16, &data.l);
	key.v = strtob("fadc3844 61d6114e fadc3844 61d6114e fadc3844 61d6114e", 16, &key.l);

	/* des */
	printf("DES\n");
	printf("data:\n");
	pvdump(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_des_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	pvdump(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_des_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	pvdump(res2);

	vfree(res1);
	vfree(res2);

	/* idea */
	printf("IDEA\n");
	printf("data:\n");
	pvdump(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_idea_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	pvdump(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_idea_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	pvdump(res2);

	vfree(res1);
	vfree(res2);

	/* blowfish */
	printf("BLOWFISH\n");
	printf("data:\n");
	pvdump(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_bf_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	pvdump(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_bf_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	pvdump(res2);

	vfree(res1);
	vfree(res2);

	/* rc5 */
	printf("RC5\n");
	printf("data:\n");
	pvdump(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_bf_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	pvdump(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_bf_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	pvdump(res2);

	vfree(res1);
	vfree(res2);

	/* 3des */
	printf("3DES\n");
	printf("data:\n");
	pvdump(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_3des_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	pvdump(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_3des_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	pvdump(res2);

	vfree(res1);
	vfree(res2);

	/* cast */
	printf("CAST\n");
	printf("data:\n");
	pvdump(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_cast_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	pvdump(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_cast_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	pvdump(res2);

	vfree(res1);
	vfree(res2);
}

void
hmactest()
{
	u_char *keyword = "hehehe test secret!";
	vchar_t kir, ki, kr;
	vchar_t *key, *data, *res, *data2;

	kir.v = strtob("d7e6a6c1876ef0488bb74958b9fee94efdb563d4e18de4ec03a4a1842d432985", 16, &kir.l);
	ki.v = strtob("d7e6a6c1876ef0488bb74958b9fee94e", 16, &ki.l);
	kr.v = strtob("fdb563d4e18de4ec03a4a1842d432985", 16, &kr.l);

	key = vmalloc(strlen(keyword));
	memcpy(key->v, keyword, key->l);

	data = vmalloc(kir.l);
	memcpy(data->v, kir.v, kir.l);

	/* HMAC MD5 */
	printf("HMAC MD5\n");
	res = eay_hmacmd5_one(key, data);
	pvdump(res);
	vfree(res);

	/* HMAC SHA1 */
	printf("HMAC SHA1\n");
	res = eay_hmacsha1_one(key, data);
	pvdump(res);
	vfree(res);

	vfree(data);

	/* HMAC SHA1 */
	data = vmalloc(ki.l);
	memcpy(data->v, ki.v, ki.l);
	data2 = vmalloc(kr.l);
	memcpy(data2->v, kr.v, kr.l);

	printf("HMAC SHA1\n");
	res = (vchar_t *)eay_hmacsha1_oneX(key, data, data2);
	pvdump(res);
	vfree(res);

	vfree(key);
}

void
sha1test()
{
	char *word1 = "1234567890", *word2 = "12345678901234567890";
	caddr_t ctx;
	vchar_t *buf, *res;

	ctx = eay_sha1_init();
	buf = vmalloc(strlen(word1));
	memcpy(buf->v, word1, buf->l);
	eay_sha1_update(ctx, buf);
	eay_sha1_update(ctx, buf);
	res = eay_sha1_final(ctx);
	pvdump(res);
	vfree(res);
	vfree(buf);

	ctx = eay_sha1_init();
	buf = vmalloc(strlen(word2));
	memcpy(buf->v, word2, buf->l);
	eay_sha1_update(ctx, buf);
	res = eay_sha1_final(ctx);
	pvdump(res);
	vfree(res);

	res = eay_sha1_one(buf);
	pvdump(res);
	vfree(res);
	vfree(buf);
}

void
md5test()
{
	char *word1 = "1234567890", *word2 = "12345678901234567890";
	caddr_t ctx;
	vchar_t *buf, *res;

	ctx = eay_md5_init();
	buf = vmalloc(strlen(word1));
	memcpy(buf->v, word1, buf->l);
	eay_md5_update(ctx, buf);
	eay_md5_update(ctx, buf);
	res = eay_md5_final(ctx);
	pvdump(res);
	vfree(res);
	vfree(buf);

	ctx = eay_md5_init();
	buf = vmalloc(strlen(word2));
	memcpy(buf->v, word2, buf->l);
	eay_md5_update(ctx, buf);
	res = eay_md5_final(ctx);
	pvdump(res);
	vfree(res);

	res = eay_md5_one(buf);
	pvdump(res);
	vfree(res);
	vfree(buf);
}

int
dhtest(f)
	int f;
{
	vchar_t p1, p2, *pub1, *priv1, *pub2, *priv2, *key;

	switch (f) {
	case 0:
		p1.v = strtob(OAKLEY_PRIME_MODP768, 16, &p1.l);
		p2.v = strtob(OAKLEY_PRIME_MODP768, 16, &p2.l);
		break;
	case 1:
		p1.v = strtob(OAKLEY_PRIME_MODP1024, 16, &p1.l);
		p2.v = strtob(OAKLEY_PRIME_MODP1024, 16, &p2.l);
		break;
	case 2:
	default:
		p1.v = strtob(OAKLEY_PRIME_MODP1536, 16, &p1.l);
		p2.v = strtob(OAKLEY_PRIME_MODP1536, 16, &p2.l);
		break;
	}
	printf("prime number = \n"); pvdump(&p1);

	key = vmalloc(p1.l);

	if (eay_dh_generate(&p1, 2, 96, &pub1, &priv1) < 0) {
		printf("error\n");
		return(-1);
	}

	printf("private key for user 1 = \n"); pvdump(priv1);
	printf("public key for user 1  = \n"); pvdump(pub1);

	if (eay_dh_generate(&p2, 2, 96, &pub2, &priv2) < 0) {
		printf("error\n");
		return(-1);
	}

	printf("private key for user 2 = \n"); pvdump(priv2);
	printf("public key for user 2  = \n"); pvdump(pub2);

	/* process to generate key for user 1 */
	memset(key->v, 0, key->l);
	eay_dh_compute(&p1, 2, pub1, priv1, pub2, &key);
	printf("sharing key of user 1 = \n"); pvdump(key);

	/* process to generate key for user 2 */
	memset(key->v, 0, key->l);
	eay_dh_compute(&p2, 2, pub2, priv2, pub1, &key);
	printf("sharing key of user 2 = \n"); pvdump(key);

	vfree(pub1);
	vfree(priv1);
	vfree(priv2);
	vfree(key);

	return 0;
}

void
bntest()
{
	vchar_t *rn;

	rn = eay_set_random((u_int32_t)96);
	pvdump(rn);
	vfree(rn);
}

int
main(ac, av)
	int ac;
	char **av;
{
	int mode = 0;

	if (ac == 1)
		mode = ~0;
	else {
		for (av++; ac-- > 0; av++) {
			if (strcmp(*av, "random") == 0)
				mode |= TEST_RAND;
			else if (strcmp(*av, "dh") == 0)
				mode |= TEST_DH;
			else if (strcmp(*av, "md5") == 0)
				mode |= TEST_MD5;
			else if (strcmp(*av, "sha1") == 0)
				mode |= TEST_SHA1;
			else if (strcmp(*av, "hmac") == 0)
				mode |= TEST_HMAC;
			else if (strcmp(*av, "cipher") == 0)
				mode |= TEST_CIPHER;
		}
	}

	if (mode & TEST_RAND) {
		printf("\n**Test for generate a random number.**\n");
		bntest();
	}

	if (mode & TEST_DH) {
		printf("\n**Test for DH.**\n");
		dhtest(0);
	}

	if (mode & TEST_MD5) {
		printf("\n**Test for MD5.**\n");
		md5test();
	}

	if (mode & TEST_SHA1) {
		printf("\n**Test for SHA1.**\n");
		sha1test();
	}

	if (mode & TEST_HMAC) {
		printf("\n**Test for HMAC MD5 & SHA1.**\n");
		hmactest();
	}

	if (mode & TEST_CIPHER) {
		printf("\n**Test for CIPHER.**\n");
		ciphertest();
	}

	exit(0);
}
