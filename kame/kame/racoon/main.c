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
/* YIPS @(#)$Id: main.c,v 1.1 1999/08/08 23:31:23 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "var.h"
#include "vmbuf.h"
#include "cfparse.h"
#include "isakmp.h"
#include "handler.h"
#include "admin.h"
#include "debug.h"
#include "misc.h"
#include "pfkey.h"
#include "session.h"

static char version[] = "@(#)racoon $Revision: 1.1 $ sakane@ydc.co.jp";

char *pname;

unsigned long debug = 0;
int f_debug = 0;
int f_local = 0;	/* local test mode as to behave like a wall. */
int af = AF_INET;	/* default address family */

/* for print-isakmp.c */
int vflag = 1;

static void Usage __P((void));
static int parse __P((int, char **));

extern int cfparse __P((void));
extern int isakmp_init __P((void));
extern int admin_init __P((void));

void
Usage()
{
	printf("Usage: %s [-hv] [-p (port)] [-a (port)] [-f (file)] [-d (level)]\n", pname);
	printf("   -h: shows these helps.\n");
	printf("   -v: be more verbose\n");
	printf("   -p: The daemon always use a port %d of UDP to send\n", PORT_ISAKMP);
	printf("       unless you specify a port by using this option.\n");
	printf("   -a: You can specify a explicit port for administration.\n");
	printf("   -f: specify the configuration file.\n");
	printf("   -d: is specified debug mode. i.e. excuted foreground.\n");
}

int
main(ac, av)
	int ac;
	char **av;
{
	plog(LOCATION, "%s\n", version);
	plog(LOCATION, "@(#)This program includes cryptographic software written by Eric Young.\n");
	plog(LOCATION, "@(#)His e-mail address is `eay@cryptsoft.com'.\n");

	dh_init();

	/* get both configuration file name and debug level */
	if (parse(ac, av) < 0) {
		exit(1);
	}

	if (cfparse() != 0) {
		exit(1);
	}

	/* re-parse to prefer to parameters specified. */
	if (parse(ac, av) < 0) {
		exit(1);
	}

	if (!f_debug) {
		if (daemon(0, 0) < 0) {
			perror("daemon");
			exit(1);
		}
	} else
		close(0);

	signal_handler(0);

	if (isakmp_init() < 0) {
		exit(1);
	}

	if (pfkey_init() < 0) {
		exit(1);
	}

	if (admin_init() < 0) {
		exit(1);
	}

	session();
	exit(0);
}

static int
parse(ac, av)
	int ac;
	char **av;
{
	extern char *optarg;
	extern int optind;
	char *p;
	int c;
#ifdef YYDEBUG
	extern int yydebug;
#endif

	pname = *av;

	while ((c = getopt(ac, av, "hd:p:a:f:vZ"
#ifdef YYDEBUG
			"y"
#endif
#ifdef INET6
			"46"
#endif
			)) != EOF) {
		switch (c) {
		case 'd':
			debug = strtoul(optarg, &p, 16);
			f_debug = 1;
			if (*p != '\0') return(-1);
			YIPSDEBUG(DEBUG_INFO,
				plog(LOCATION, "debug=0x%08x\n", debug));
			break;
		case 'p':
			port_isakmp = atoi(optarg);
			break;
		case 'a':
			port_admin = atoi(optarg);
				return(-1);
			break;
		case 'f':
			racoon_conf = optarg;
			break;
		case 'v':
			vflag++;
			break;
		case 'Z': /* only to use local test */
			printf("Local test mode.\n");
			f_local = 1;
			break;
#ifdef YYDEBUG
		case 'y':
			yydebug = 1;
			break;
#endif
#ifdef INET6
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
#endif
		default:
			Usage();
			exit(1);
			break;
		}
	}
	ac -= optind;
	av += optind;

	optind = 1;
	optarg = 0;

	return(0);
}

