/*	$KAME: twofishtest.c,v 1.4 2001/05/27 01:56:45 itojun Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#include <sys/cdefs.h>
#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

#include <crypto/twofish/twofish.h>

/* decrypt test */
struct {
	const char *key;
	const char *pt;
	const char *ct;
} vector[] = {
    {
	"00000000000000000000000000000000",
	"00000000000000000000000000000000",
	"9F589F5CF6122C32B6BFEC2F2AE8C35A",
    },
    {
	"0123456789ABCDEFFEDCBA98765432100011223344556677",
	"00000000000000000000000000000000",
	"CFD1D2E5A9BE9CDF501F13B892BD2248",
    },
    {
	"0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
	"00000000000000000000000000000000",
	"37527BE0052334B89F0CFCCAE87CFA20",
    },
    {
	NULL, NULL, NULL,
    },
};

static void hex2key __P((u_int8_t *, size_t, const char *));
int main __P((int, char **));

static void
hex2key(p, l, s)
	u_int8_t *p;
	size_t l;
	const char *s;
{
	int i;
	u_int v;

	for (i = 0; i < l && *s; i++) {
		sscanf(s, "%02x", &v);
		*p++ = v & 0xff;
		s += 2;
	}

	if (*s) {
		errx(1, "hex2key overrun");
		/*NOTREACHED*/
	}
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	int i;
	keyInstance k;
	cipherInstance c;
	int error;
	const char *test;
	u_int8_t key[32], ct[16], pt[16], ct0[16], pt0[16];
	int nrounds, rounds;

	if (argc > 1)
		nrounds = atoi(argv[1]);
	else
		nrounds = 1;

	error = 0;

	rounds = nrounds;
again:
	for (i = 0; vector[i].key; i++) {
		hex2key(key, sizeof(key), vector[i].key);
		hex2key(pt0, sizeof(pt0), vector[i].pt);
		hex2key(ct0, sizeof(ct0), vector[i].ct);
		memcpy(pt, pt0, sizeof(pt));
		memset(ct, 0, sizeof(ct));

		test = "encrypt test";

		memset(&k, 0, sizeof(k));
		/* LINTED const cast */
		if (twofish_makeKey(&k, DIR_ENCRYPT,
		    strlen(vector[i].key) * 4, key) < 0) {
			printf("makeKey failed for %s %d\n", test, i);
			error++;
			continue;
		}
		if (twofish_cipherInit(&c, MODE_ECB, NULL) < 0) {
			printf("cipherInit failed for %s %d\n", test, i);
			error++;
			continue;
		}

		if (twofish_blockEncrypt(&c, &k, pt, sizeof(pt) * 8, ct) < 0) {
			printf("blockEncrypt failed for %s %d\n", test, i);
			error++;
			continue;
		}

		if (memcmp(ct, ct0, sizeof(ct)) != 0) {
			printf("result mismatch failed for %s %d\n", test, i);
			error++;
			continue;
		}

		if (nrounds == 1)
			printf("%s %d successful\n", test, i);

		memset(pt, 0, sizeof(pt));

		test = "decrypt test";

		memset(&k, 0, sizeof(k));
		/* LINTED const cast */
		if (twofish_makeKey(&k, DIR_DECRYPT,
		    strlen(vector[i].key) * 4, key) < 0) {
			printf("makeKey failed for %s %d\n", test, i);
			error++;
			continue;
		}
		if (twofish_cipherInit(&c, MODE_ECB, NULL) < 0) {
			printf("cipherInit failed for %s %d\n", test, i);
			error++;
			continue;
		}

		if (twofish_blockDecrypt(&c, &k, ct, sizeof(ct) * 8, pt) < 0) {
			printf("blockDecrypt failed for %s %d\n", test, i);
			error++;
			continue;
		}

		if (memcmp(pt, pt0, sizeof(pt)) != 0) {
			printf("result mismatch failed for %s %d\n", test, i);
			error++;
			continue;
		}

		if (nrounds == 1)
			printf("%s %d successful\n", test, i);
	}
	if (--rounds > 0)
		goto again;

	exit(error);
}
