/*	$KAME: md5test.c,v 1.1 2000/11/02 00:06:26 itojun Exp $	*/

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

#include <crypto/md5.h>

struct {
	const char *src;
	const char *digest;
} test[] = {
    {
	"",
	"d41d8cd98f00b204e9800998ecf8427e",
    },
    {
	"a",
	"0cc175b9c0f1b6a831c399e269772661",
    },
    {
	"abc",
	"900150983cd24fb0d6963f7d28e17f72",
    },
    {
	"message digest",
	"f96b697d7cb7938d525a2f31aaf161d0",
    },
    {
	"abcdefghijklmnopqrstuvwxyz",
	"c3fcd3d76192e4007dfb496cca67e13b",
    },
    {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"d174ab98d277d9f5a5611c2c9f419d9f",
    },
    {
	"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	"57edf4a22be3c955ac49da2e2107b67a",
    },
    {
	NULL, NULL,
    },
};

static void hex2digest __P((u_int8_t *, const char *));
int main __P((int, char **));

static void
hex2digest(p, s)
	u_int8_t *p;
	const char *s;
{
	int i;
	u_int v;

	for (i = 0; i < 16; i++) {
		sscanf(s, "%02x", &v);
		*p++ = v & 0xff;
		s += 2;
	}
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	int i;
	MD5_CTX c;
	int error;
	u_int8_t digest[16], ndigest[16];

	error = 0;

	printf("starting md5 tests\n");

	for (i = 0; test[i].src; i++) {
		hex2digest(digest, test[i].digest);
		memset(ndigest, 0, sizeof(ndigest));

		MD5Init(&c);
		/* LINTED const cast */
		MD5Update(&c, (char *)test[i].src, strlen(test[i].src));
		MD5Final(ndigest, &c);

		if (memcmp(digest, ndigest, sizeof(digest)) != 0) {
			printf("digest mismatch on test %d\n", i);
			error++;
		}
	}

	exit(error);
}
