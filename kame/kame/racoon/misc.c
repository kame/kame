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
/* YIPS @(#)$Id: misc.c,v 1.12 2000/02/23 06:56:39 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "var.h"
#include "misc.h"
#include "debug.h"

#ifndef NOUSE_PLOG
#include "plog.h"
#define PLOG(p, l, a, f, v)	plog((p), (l), (a), (f), (v))
#define PLOGNL()		plognl()
#define PLOGSP()		plogsp()
#define PLOGC(p, c)		plogc((p), (c));
#define PLOGH(p, c)		plogh((p), (c));
#else
#define PLOG(p, l, a, f, v)	printf((f), (v))
#define PLOGNL()		printf("\n")
#define PLOGSP()		printf(" ")
#define PLOGC(p, c)		printf("%c", (c))
#define PLOGH(p, c)		printf("%02x", (c));
#endif

int
bindump(buf0, len)
	void *buf0;
	size_t len;
{
	caddr_t buf = (caddr_t)buf0;
	size_t i;

	for (i = 0; i < len; i++) {
		PLOGC(logp, (unsigned char)buf[i]);
	}
	PLOGNL();

	return 0;
}

int
hexdump(buf0, len)
	void *buf0;
	size_t len;
{
	caddr_t buf = (caddr_t)buf0;
	size_t i;

	for (i = 0; i < len; i++) {
		if (i != 0 && i % 32 == 0)
			PLOGNL();
		if (i % 4 == 0)
			PLOGSP();
		PLOGH(logp, (unsigned char)buf[i]);
	}
	PLOGNL();

	return 0;
}

char *
bit2str(n, bl)
	int n, bl;
{
#define MAXBITLEN 128
	static char b[MAXBITLEN + 1];
	int i;

	if (bl > MAXBITLEN)
		return "Failed to convert.";	/* NG */
	memset(b, '0', bl);
	b[bl] = '\0';

	for (i = 0; i < bl; i++) {
		if (n & (1 << i))
			b[bl - 1 - i] = '1';
	}

	return b;
}

/*
 * copy the buffer into new allocated buffer.
 * NOTE: may be used by GET_NEWBUF();
 */
void *
get_newbuf(src, len)
	void *src;
	size_t len;
{
	caddr_t new;

	if ((new = CALLOC(len, caddr_t)) == NULL) {
		PLOG(logp, LOCATION, NULL,
			"calloc (%s)\n", strerror(errno));
		return NULL;
	}
	memcpy(new, src, len);

	return new;
}

const char *
debug_location(file, line, func)
	char *file;
	int line;
	char *func;
{
	static char buf[1024];
	char *p;

#ifdef YIPS_DEBUG
	if (!(debug & DEBUG_FUNC))
		return "";
#endif

	/* truncate pathname */
	p = strrchr(file, '/');
	if (p)
		p++;
	else
		p = file;

	if (func)
		snprintf(buf, sizeof(buf), "%s:%d:%s()", p, line, func);
	else
		snprintf(buf, sizeof(buf), "%s:%d", p, line);

	return buf;
}

/*
 * get file size.
 * -1: error occured.
 */
int
getfsize(path)
	char *path;
{
        struct stat st;

        if (stat(path, &st) != 0)
                return -1;
        else
                return st.st_size;
}

