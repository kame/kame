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
/* YIPS @(#)$Id: eaytest.c,v 1.5 2000/08/10 12:27:47 sakane Exp $ */

#include <sys/types.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "var.h"
#include "vmbuf.h"
#include "misc.h"
#include "debug.h"
#include "str2val.h"

#include "oakley.h"
#include "crypto_openssl.h"

u_int32_t debug = 0;

char *capath = "/usr/local/openssl/certs";
char cert1[] =
"-----BEGIN X509 CERTIFICATE-----\n"
"MIICzDCCAjWgAwIBAgIEOXGTAjANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJG\n"
"STEkMCIGA1UEChMbU1NIIENvbW11bmljYXRpb25zIFNlY3VyaXR5MREwDwYDVQQL\n"
"EwhXZWIgdGVzdDESMBAGA1UEAxMJVGVzdCBDQSAxMB4XDTAwMDcxNjAwMDAwMFoX\n"
"DTAwMDkwMTAwMDAwMFowgZsxCzAJBgNVBAYTAkpQMREwDwYDVQQIEwhLYW5hZ2F3\n"
"YTERMA8GA1UEBxMIRnVqaXNhd2ExFTATBgNVBAoTDFdJREUgUHJvamVjdDEVMBMG\n"
"A1UECxMMS0FNRSBQcm9qZWN0MRcwFQYDVQQDEw5TaG9pY2hpIFNha2FuZTEfMB0G\n"
"CSqGSIb3DQEJAQwQc2FrYW5lQHlkYy5jby5qcDCBnzANBgkqhkiG9w0BAQEFAAOB\n"
"jQAwgYkCgYEAuWE1jKVD8AvuM5x8Z6JzJlYeR+V+FZkFxv65Y8TQGyiZPOlvlb9J\n"
"acaLJFYBjSuuno/t111tu3thggQwC80SUos0irG31i6SSusQMGmkoT1m/QHckZ4d\n"
"lfxHyFLqwkV97qYGp/h55PuG8WwW+Imcbtd/RJHqD7gEWxPFhy9rmsMCAwEAAaNd\n"
"MFswCwYDVR0PBAQDAgWgMBoGA1UdEQQTMBGBD3Nha2FuZUBrYW1lLm5ldDAwBgNV\n"
"HR8EKTAnMCWgI6Ahhh9odHRwOi8vbGRhcC5zc2guZmkvY3Jscy9jYTEuY3JsMA0G\n"
"CSqGSIb3DQEBBQUAA4GBAFVbX9xotcHmtI96iXGNuzXqAObUBDAg4hDymi2RLitv\n"
"uVJYPH5t6qDqu499FbwPsatoRc/l62cmc0qmFStmvg0p5s+/dW2gtBeV1+cfdv+O\n"
"1GrjSmhAPPiwQFarhJzJeNo5PHplcj9ICNzDfcLZtqhiZFLq0wl5pNQM4UqWuFNl\n"
"-----END X509 CERTIFICATE-----\n\n"
;

/* test */

void
certtest()
{
	int error;
	vchar_t CApath, c;

	printf("\n**Test for Certificate.**\n");

	eay_init_error();

	CApath.v = capath;
	CApath.l = strlen(capath);
	c.v = cert1;
	c.l = strlen(cert1);

	error = eay_check_x509cert(&c, &CApath);
	printf("cert is %s\n", error ? "bad" : "good");
}

void
ciphertest()
{
	vchar_t data;
	vchar_t key;
	vchar_t *res1, *res2;
	char iv[8];

	printf("\n**Test for CIPHER.**\n");

	data.v = str2val("a7c3a855 a328a6d4 b1bd9c06 c5bd5c17 b8c5f657 bd8ea245 2a6726d0 ce3689f5", 16, &data.l);
	key.v = str2val("fadc3844 61d6114e fadc3844 61d6114e fadc3844 61d6114e", 16, &key.l);

	/* des */
	printf("DES\n");
	printf("data:\n");
	PVDUMP(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_des_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	PVDUMP(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_des_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	PVDUMP(res2);

	vfree(res1);
	vfree(res2);

#ifdef HAVE_IDEA_H
	/* idea */
	printf("IDEA\n");
	printf("data:\n");
	PVDUMP(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_idea_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	PVDUMP(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_idea_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	PVDUMP(res2);

	vfree(res1);
	vfree(res2);
#endif

	/* blowfish */
	printf("BLOWFISH\n");
	printf("data:\n");
	PVDUMP(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_bf_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	PVDUMP(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_bf_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	PVDUMP(res2);

	vfree(res1);
	vfree(res2);

	/* rc5 */
	printf("RC5\n");
	printf("data:\n");
	PVDUMP(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_bf_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	PVDUMP(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_bf_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	PVDUMP(res2);

	vfree(res1);
	vfree(res2);

	/* 3des */
	printf("3DES\n");
	printf("data:\n");
	PVDUMP(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_3des_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	PVDUMP(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_3des_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	PVDUMP(res2);

	vfree(res1);
	vfree(res2);

	/* cast */
	printf("CAST\n");
	printf("data:\n");
	PVDUMP(&data);

	memset(iv, 0, sizeof(iv));
	res1 = eay_cast_encrypt(&data, &key, (caddr_t)iv);
	printf("encrypto:\n");
	PVDUMP(res1);

	memset(iv, 0, sizeof(iv));
	res2 = eay_cast_decrypt(res1, &key, (caddr_t)iv);
	printf("decrypto:\n");
	PVDUMP(res2);

	vfree(res1);
	vfree(res2);
}

void
hmactest()
{
	u_char *keyword = "hehehe test secret!";
	vchar_t kir, ki, kr;
	vchar_t *key, *data, *res, *data2;

	printf("\n**Test for HMAC MD5 & SHA1.**\n");

	kir.v = str2val("d7e6a6c1876ef0488bb74958b9fee94efdb563d4e18de4ec03a4a1842d432985", 16, &kir.l);
	ki.v = str2val("d7e6a6c1876ef0488bb74958b9fee94e", 16, &ki.l);
	kr.v = str2val("fdb563d4e18de4ec03a4a1842d432985", 16, &kr.l);

	key = vmalloc(strlen(keyword));
	memcpy(key->v, keyword, key->l);

	data = vmalloc(kir.l);
	memcpy(data->v, kir.v, kir.l);

	/* HMAC MD5 */
	printf("HMAC MD5\n");
	res = eay_hmacmd5_one(key, data);
	PVDUMP(res);
	vfree(res);

	/* HMAC SHA1 */
	printf("HMAC SHA1\n");
	res = eay_hmacsha1_one(key, data);
	PVDUMP(res);
	vfree(res);

	vfree(data);

	/* HMAC SHA1 */
	data = vmalloc(ki.l);
	memcpy(data->v, ki.v, ki.l);
	data2 = vmalloc(kr.l);
	memcpy(data2->v, kr.v, kr.l);

	printf("HMAC SHA1\n");
	res = (vchar_t *)eay_hmacsha1_oneX(key, data, data2);
	PVDUMP(res);
	vfree(res);

	vfree(key);
}

void
sha1test()
{
	char *word1 = "1234567890", *word2 = "12345678901234567890";
	caddr_t ctx;
	vchar_t *buf, *res;

	printf("\n**Test for SHA1.**\n");

	ctx = eay_sha1_init();
	buf = vmalloc(strlen(word1));
	memcpy(buf->v, word1, buf->l);
	eay_sha1_update(ctx, buf);
	eay_sha1_update(ctx, buf);
	res = eay_sha1_final(ctx);
	PVDUMP(res);
	vfree(res);
	vfree(buf);

	ctx = eay_sha1_init();
	buf = vmalloc(strlen(word2));
	memcpy(buf->v, word2, buf->l);
	eay_sha1_update(ctx, buf);
	res = eay_sha1_final(ctx);
	PVDUMP(res);
	vfree(res);

	res = eay_sha1_one(buf);
	PVDUMP(res);
	vfree(res);
	vfree(buf);
}

void
md5test()
{
	char *word1 = "1234567890", *word2 = "12345678901234567890";
	caddr_t ctx;
	vchar_t *buf, *res;

	printf("\n**Test for MD5.**\n");

	ctx = eay_md5_init();
	buf = vmalloc(strlen(word1));
	memcpy(buf->v, word1, buf->l);
	eay_md5_update(ctx, buf);
	eay_md5_update(ctx, buf);
	res = eay_md5_final(ctx);
	PVDUMP(res);
	vfree(res);
	vfree(buf);

	ctx = eay_md5_init();
	buf = vmalloc(strlen(word2));
	memcpy(buf->v, word2, buf->l);
	eay_md5_update(ctx, buf);
	res = eay_md5_final(ctx);
	PVDUMP(res);
	vfree(res);

	res = eay_md5_one(buf);
	PVDUMP(res);
	vfree(res);
	vfree(buf);
}

int
dhtest(f)
	int f;
{
	vchar_t p1, p2, *pub1, *priv1, *pub2, *priv2, *key;

	printf("\n**Test for DH.**\n");

	switch (f) {
	case 0:
		p1.v = str2val(OAKLEY_PRIME_MODP768, 16, &p1.l);
		p2.v = str2val(OAKLEY_PRIME_MODP768, 16, &p2.l);
		break;
	case 1:
		p1.v = str2val(OAKLEY_PRIME_MODP1024, 16, &p1.l);
		p2.v = str2val(OAKLEY_PRIME_MODP1024, 16, &p2.l);
		break;
	case 2:
	default:
		p1.v = str2val(OAKLEY_PRIME_MODP1536, 16, &p1.l);
		p2.v = str2val(OAKLEY_PRIME_MODP1536, 16, &p2.l);
		break;
	}
	printf("prime number = \n"); PVDUMP(&p1);

	key = vmalloc(p1.l);

	if (eay_dh_generate(&p1, 2, 96, &pub1, &priv1) < 0) {
		printf("error\n");
		return(-1);
	}

	printf("private key for user 1 = \n"); PVDUMP(priv1);
	printf("public key for user 1  = \n"); PVDUMP(pub1);

	if (eay_dh_generate(&p2, 2, 96, &pub2, &priv2) < 0) {
		printf("error\n");
		return(-1);
	}

	printf("private key for user 2 = \n"); PVDUMP(priv2);
	printf("public key for user 2  = \n"); PVDUMP(pub2);

	/* process to generate key for user 1 */
	memset(key->v, 0, key->l);
	eay_dh_compute(&p1, 2, pub1, priv1, pub2, &key);
	printf("sharing key of user 1 = \n"); PVDUMP(key);

	/* process to generate key for user 2 */
	memset(key->v, 0, key->l);
	eay_dh_compute(&p2, 2, pub2, priv2, pub1, &key);
	printf("sharing key of user 2 = \n"); PVDUMP(key);

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

	printf("\n**Test for generate a random number.**\n");

	rn = eay_set_random((u_int32_t)96);
	PVDUMP(rn);
	vfree(rn);
}

int
main(ac, av)
	int ac;
	char **av;
{
	if (strcmp(*av, "-h") == 0) {
		printf("Usage: eaytest [dh|md5|sha1|hmac|cipher|cert]\n");
		exit(0);
	}

	if (ac == 1) {
		bntest();
		dhtest();
		md5test();
		sha1test();
		hmactest();
		ciphertest();
		certtest();
	} else {
		for (av++; *av != '\0'; av++) {
			if (strcmp(*av, "random") == 0)
				bntest();
			else if (strcmp(*av, "dh") == 0)
				dhtest(0);
			else if (strcmp(*av, "md5") == 0)
				md5test();
			else if (strcmp(*av, "sha1") == 0)
				sha1test();
			else if (strcmp(*av, "hmac") == 0)
				hmactest();
			else if (strcmp(*av, "cipher") == 0)
				ciphertest();
			else if (strcmp(*av, "cert") == 0)
				certtest();
		}
	}

	exit(0);
}
