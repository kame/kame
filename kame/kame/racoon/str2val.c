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
/* YIPS @(#)$Id: str2val.c,v 1.2 2000/02/07 11:24:49 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>

#include "str2val.h"

/*
 * exchange a value to a hex string.
 * must free buffer allocated later.
 */
caddr_t
val2str(buf, mlen)
	const char *buf;
	size_t mlen;
{
	caddr_t new;
	size_t len = (mlen * 2) + mlen / 8 + 10;
	size_t i, j;

	if ((new = malloc(len)) == 0) return(0);

	for (i = 0, j = 0; i < mlen; i++) {
		snprintf(&new[j], len - j, "%02x", buf[i]);
		j += 2;
		if (i % 8 == 7) {
			new[j++] = ' ';
			new[j] = '\0';
		}
	}
	new[j] = '\0';

	return(new);
}

/*
 * exchange a string based "base" to a value.
 */
char *
str2val(str, base, len)
	char *str;
	int base;
	size_t *len;
{
	int f;
	size_t i;
	char *dst;
	char *rp;
	char *p, b[3], *bp;

	for (i = 0, p = str; *p != '\0'; p++) {
		if ( (*p >= '0' && *p <= '9')
		  || (*p >= 'a' && *p <= 'f')
		  || (*p >= 'A' && *p <= 'F')) {
			i++;
		} 
	}
	i = i/2;
	if (i == 0) return(0);

	if ((dst = malloc(i)) == 0) {
		return(0);
	}

	i = 0;
	f = 0;
	for (rp = dst, p = str; *p != '\0'; p++) {
		if ( (*p >= '0' && *p <= '9')
		  || (*p >= 'a' && *p <= 'f')
		  || (*p >= 'A' && *p <= 'F')) {
			if (!f) {
				b[0] = *p;
				f = 1;
			} else {
				b[1] = *p;
				b[2] = '\0';
				*rp++ = (char)strtol(b, &bp, base);
				i++;
				f = 0;
			}
		} 
	}

	*len = i;

	return(dst);
}

#if 0
/*
 * exchange hex string to value.
 */
caddr_t
hexstr2val(buf, len)
	caddr_t buf;
	size_t len;
{
	caddr_t res, bp;
	caddr_t p = buf;

	if ((res = malloc(len)) == 0)
		return(0);
	memset(res, 0, len);

	bp = res;
	while (*p) {
		*bp = (ATOX(p[0]) << 4) | ATOX(p[1]);
		p += 2, bp++;
	}

	return(res);
}
#endif
