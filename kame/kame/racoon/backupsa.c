/*	$KAME: backupsa.c,v 1.3 2001/01/31 05:54:49 sakane Exp $	*/

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

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <netinet/in.h>
#ifdef IPV6_INRIA_VERSION
#include <netinet/ipsec.h>
#else
#include <netinet6/ipsec.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "str2val.h"
#include "plog.h"
#include "debug.h"

#include "localconf.h"
#include "sockmisc.h"
#include "safefile.h"
#include "backupsa.h"
#include "libpfkey.h"

/*
 * (time string)%(sa parameter)
 * (time string) := ex. Nov 24 18:22:48 1986
 * (sa parameter) :=
 *    src dst satype spi mode reqid wsize \
 *    e_type e_keylen a_type a_keylen flags \
 *    l_alloc l_bytes l_addtime l_usetime seq keymat
 */
static char *format = "%b %d %T %Y";	/* time format */

/*
 * output the sa parameter.
 */
int
backupsa_to_file(satype, mode, src, dst, spi, reqid, wsize,
                keymat, e_type, e_keylen, a_type, a_keylen, flags,
                l_alloc, l_bytes, l_addtime, l_usetime, seq)
        u_int satype, mode, wsize;
        struct sockaddr *src, *dst;
        u_int32_t spi, reqid;
        caddr_t keymat;
        u_int e_type, e_keylen, a_type, a_keylen, flags;
        u_int32_t l_alloc;
        u_int64_t l_bytes, l_addtime, l_usetime;
        u_int32_t seq;
{
	char buf[1024];
	struct tm *tm;
	time_t t;
	char *p, *k;
	int len, l, i;
	FILE *fp;

	p = buf;
	len = sizeof(buf);

	t = time(NULL);
	tm = localtime(&t);
	l = strftime(p, len, format, tm);
	p += l;
	len -= l;
	if (len < 0)
		goto err;

	l = snprintf(p, len, "%%");
	p += l;
	len -= l;
	if (len < 0)
		goto err;

        i = getnameinfo(src, src->sa_len, p, len, NULL, 0, NIFLAGS);
	if (i != 0)
		goto err;
	l = strlen(p);
	p += l;
	len -= l;
	if (len < 0)
		goto err;

	l = snprintf(p, len, " ");
	p += l;
	len -= l;
	if (len < 0)
		goto err;

        i = getnameinfo(dst, dst->sa_len, p, len, NULL, 0, NIFLAGS);
	if (i != 0)
		goto err;
	l = strlen(p);
	p += l;
	len -= l;
	if (len < 0)
		goto err;

	l = snprintf(p, len,
		" %u %lu %u %u %u "
		"%u %u %u %u %u "
		"%u %qu %qu %qu %u",
		satype, ntohl(spi), mode, reqid, wsize,
		e_type, e_keylen, a_type, a_keylen, flags,
		l_alloc, l_bytes, l_addtime, l_usetime, seq);
	p += l;
	len -= l;
	if (len < 0)
		goto err;

	k = val2str(keymat, e_keylen + a_keylen);
	l = snprintf(p, len, " %s", k);
	free(k);
	p += l;
	len -= l;
	if (len < 0)
		goto err;

	/* open the file and write the SA parameter */
	fp = fopen(lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], "a");
	if (fp == NULL
	 || safefile(lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], 1) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to open the backup file %s.\n",
			lcconf->pathinfo[LC_PATHTYPE_BACKUPSA]);
		fclose(fp);
		return -1;
	}
	fprintf(fp, "%s\n", buf);
	fclose(fp);

	return 0;

err:
	plog(LLV_ERROR, LOCATION, NULL,
		"SA cannot be saved to a file.\n");
	return -1;
}

int
backupsa_from_file()
{
	FILE *fp;
	char buf[512];
	struct tm tm;
	time_t created, current;
	char *p, *q;
        u_int satype, mode;
        struct sockaddr *src, *dst;
        u_int32_t spi, reqid;
        caddr_t keymat;
	int keymatlen;
        u_int wsize, e_type, e_keylen, a_type, a_keylen, flags;
        u_int32_t l_alloc;
        u_int64_t l_bytes, l_addtime, l_usetime;
        u_int32_t seq;
	int line;

	if (safefile(lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], 1) == 0)
		fp = fopen(lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], "r");
	else
		fp = NULL;
	if (fp == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to open the backup file %s.\n",
			lcconf->pathinfo[LC_PATHTYPE_BACKUPSA]);
		return -1;
	}

	current = time(NULL);

	for(line = 1; fgets(buf, sizeof(buf), fp) != NULL; line++) {
		/* comment line */
		if (buf[0] == '#')
			continue;

		memset(&tm, 0, sizeof(tm));
		p = strptime(buf, format, &tm);
		if (*p != '%') {
	err:
			plog(LLV_ERROR, LOCATION, NULL,
				"illegal format line#%d in %s: %s\n",
				line, lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], buf);
			continue;
		}
		created = mktime(&tm);
		p++;

		for (q = p; *q != '\0' && !isspace(*q); q++)
			;
		*q = '\0';
		src = str2saddr(p, NULL);
		if (src == NULL)
			goto err;
		p = q + 1;

		for (q = p; *q != '\0' && !isspace(*q); q++)
			;
		*q = '\0';
		dst = str2saddr(p, NULL);
		if (dst == NULL) {
			free(src);
			goto err;
		}
		p = q + 1;

#define GETNEXTNUM(value, function) \
do { \
	char *y; \
	for (q = p; *q != '\0' && !isspace(*q); q++) \
		; \
	*q = '\0'; \
	(value) = function(p, &y, 10); \
	if ((value) == 0 && *y != '\0') \
		goto err; \
	p = q + 1; \
} while (0);

		GETNEXTNUM(satype, strtoul);
		GETNEXTNUM(spi, strtoul);
		spi = ntohl(spi);
		GETNEXTNUM(mode, strtoul);
		GETNEXTNUM(reqid, strtoul);
		GETNEXTNUM(wsize, strtoul);
		GETNEXTNUM(e_type, strtoul);
		GETNEXTNUM(e_keylen, strtoul);
		GETNEXTNUM(a_type, strtoul);
		GETNEXTNUM(a_keylen, strtoul);
		GETNEXTNUM(flags, strtoul);
		GETNEXTNUM(l_alloc, strtoul);
		GETNEXTNUM(l_bytes, strtouq);
		GETNEXTNUM(l_addtime, strtouq);
		GETNEXTNUM(l_usetime, strtouq);
		GETNEXTNUM(seq, strtoul);

#undef GETNEXTNUM(n)

		keymat = str2val(p, 16, &keymatlen);
		if (keymat == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
				"illegal format(keymat) line#%d in %s: %s\n",
				line, lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], buf);
			free(src);
			free(dst);
			continue;
		}

		if (created + l_addtime < current) {
			plog(LLV_DEBUG, LOCATION, NULL,
				"ignore this line#%d in %s due to expiration\n",
				line, lcconf->pathinfo[LC_PATHTYPE_BACKUPSA]);
			free(src);
			free(dst);
			free(keymat);
			continue;
		}

		if (pfkey_send_add(
				lcconf->sock_pfkey,
				satype,
				mode,
				src,
				dst,
				spi,
				reqid,
				wsize,
				keymat,
				e_type, e_keylen, a_type, a_keylen, flags,
				0, l_bytes, l_addtime, 0, seq) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"restore SA filed line#%d in %s: %s\n",
				line, lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], ipsec_strerror());
		}
		free(src);
		free(dst);
		free(keymat);
	}

	fclose(fp);

	/*
	 * There is a possibility that an abnormal system down will happen
	 * again.  Any old SA will not be installed because racoon checks
	 * the lifetime and compare with current time.
	 */
#if 0
	/* clean the file if SA installation succeed. */
	backupsa_clean();
#endif

	return 0;
}

int
backupsa_clean()
{
	FILE *fp;

	fp = fopen(lcconf->pathinfo[LC_PATHTYPE_BACKUPSA], "w+");
	if (fp == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to clean the backup file %s.\n",
			lcconf->pathinfo[LC_PATHTYPE_BACKUPSA]);
		return -1;
	}
	return 0;
}
