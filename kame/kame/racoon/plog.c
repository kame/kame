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
/* YIPS @(#)$Id: plog.c,v 1.2 2000/01/10 22:38:39 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
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
#include <ctype.h>

#include "var.h"
#include "misc.h"
#include "plog.h"
#include "logger.h"
#include "debug.h"

/* logging pointer */
struct log *logp;
static char *logfile = NULL;

static void plog_common
	__P((struct log *lp, const char *func, struct sockaddr *sa));

extern void warn();	/* XXX redeclared type mismatched in openssl. */

static void
plog_common(struct log *lp, const char *func, struct sockaddr *sa)
{
	time_t t;
	char tbuf[56];
	struct tm *tm;
	char addr[NI_MAXHOST], port[NI_MAXSERV];

	t = time(0);
	tm = localtime(&t);
	strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %T", tm);

	YIPSDEBUG(DEBUG_DEBUG, printf("%s: ", tbuf));
	if (log_vprint(lp, "%s: ", tbuf) < 0)
		warn("logging failed.");

	YIPSDEBUG(DEBUG_FUNC|DEBUG_DEBUG, printf("%s: ", func));
	YIPSDEBUG(DEBUG_FUNC, log_vprint(lp, "%s: ", func));

	if (sa != NULL) {
		/* don't use saddr2str() in order not to buffer overwrite */
		GETNAMEINFO(sa, addr, port);
	        YIPSDEBUG(DEBUG_DEBUG, printf("%s[%s] ", addr, port));
	        if (log_vprint(lp, "%s ", addr, port) < 0)
			warn("logging failed.");
	};
}

void
plog(struct log *lp, const char *func, struct sockaddr *sa,
	const char *fmt, ...)
{
	va_list ap;

	plog_common(lp, func, sa);

	va_start(ap, fmt);
        YIPSDEBUG(DEBUG_DEBUG, vprintf(fmt, ap));
	log_vaprint(lp, fmt, ap);
	va_end(ap);

	return;
}

void
plogv(struct log *lp, const char *func, struct sockaddr *sa,
	const char *fmt, va_list ap)
{
	plog_common(lp, func, sa);

        YIPSDEBUG(DEBUG_DEBUG, vprintf(fmt, ap));
	log_vaprint(lp, fmt, ap);

	return;
}

void
plognl()
{
	YIPSDEBUG(DEBUG_DEBUG, printf("\n"));
	if (log_print(logp, "\n") < 0)
		warn("logging failed.");
}

void
plogsp()
{
	YIPSDEBUG(DEBUG_DEBUG, printf(" "));
	if (log_print(logp, " ") < 0)
		warn("logging failed.");
}

void
plogc(struct log *lp, unsigned char c)
{
	YIPSDEBUG(DEBUG_DEBUG, printf("%c", c));
	if (log_vprint(lp, "%c", c) < 0)
		warn("logging failed.");
}

void
plogh(struct log *lp, unsigned char c)
{
	YIPSDEBUG(DEBUG_DEBUG, printf("%02x", c));
	if (log_vprint(lp, "%02x", c) < 0)
		warn("logging failed.");
}

void
ploginit()
{
	if (logfile == NULL)
		logfile = strdup(LC_DEFAULT_LOGF);

	logp = log_open(250, logfile);
	if (logp == NULL) {
		fprintf(stderr, "failed to open log file %s.", logfile);
		exit(1);
	}
}

void
plogset(file)
	char *file;
{
	if (logfile != NULL)
		free(logfile);
	logfile = strdup(file);
}
