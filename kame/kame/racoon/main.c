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
/* YIPS @(#)$Id: main.c,v 1.4 2000/02/16 07:29:41 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"

#include "cfparse.h"
#include "isakmp_var.h"
#include "remoteconf.h"
#include "localconf.h"
#include "session.h"
#include "oakley.h"
#include "crypto_openssl.h"

/* debug flags */
u_int32_t debug = 0;
int f_debugcmd = 0;	/* specifyed debug level by command line. */
int f_local = 0;	/* local test mode.  behave like a wall. */
int vflag = 1;		/* for print-isakmp.c */

static char version[] = "@(#)racoon 2.0 sakane@ydc.co.jp";
static char *pname;

static void Usage __P((void));
static void parse __P((int, char **));

void
Usage()
{
	printf("Usage: %s [-hv] [-p (port)] [-a (port)] "
#ifdef INET6
		"[-4|-6] "
#endif
		"[-f (file)] [-d (level)] [-l (file)]\n", pname);
	printf("   -h: shows these helps.\n");
	printf("   -v: be more verbose\n");
	printf("   -p: The daemon always use a port %d of UDP to send\n",
		PORT_ISAKMP);
	printf("       unless you specify a port by using this option.\n");
	printf("   -a: You can specify a explicit port for administration.\n");
	printf("   -f: specify a configuration file.\n");
	printf("   -l: specify a log file.\n");
	printf("   -d: is specified debug mode. i.e. excuted foreground.\n");
#ifdef INET6
	printf("   -6: is specified IPv6 mode.\n");
	printf("   -4: is specified IPv4 mode.\n");
#endif
	exit(1);
}

int
main(ac, av)
	int ac;
	char **av;
{
	int error;

	initlcconf();
	initrmconf();
	oakley_dhinit();
	eay_init_error();

	parse(ac, av);

	ploginit();

	plog(logp, LOCATION, NULL,
		"%s\n", version);
	plog(logp, LOCATION, NULL,
	"@(#)"
	"This product linked software developed by the OpenSSL Project"
	"for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
	"\n");

	error = cfparse();
	if (error != 0) {
		plog(logp, LOCATION, NULL,
			"failed to parse configuration file.\n");
		exit(1);
	}

	/* re-parse to prefer to command line parameters. */
	parse(ac, av);

#if 0
	if (!f_debugcmd) {
		if (daemon(0, 0) < 0) {
			plog(logp, LOCATION, NULL,
				"failed to be daemon. (%s)\n", strerror(errno));
			exit(1);
		}
	} else
		close(0);
#endif

	session();

	exit(0);
}

static void
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

	while ((c = getopt(ac, av, "hd:p:a:f:l:vZ"
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
			f_debugcmd = 1;
			if (*p != '\0') {
				printf("invalid flag (%s)\n", optarg);
				exit(1);
			}
			YIPSDEBUG(DEBUG_INFO,
				printf("debug = 0x%08x\n", debug));
			break;
		case 'p':
			lcconf->port_isakmp = atoi(optarg);
			break;
		case 'a':
			lcconf->port_admin = atoi(optarg);
			break;
		case 'f':
			lcconf->racoon_conf = optarg;
			break;
		case 'l':
			plogset(optarg);
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
			lcconf->default_af = AF_INET;
			break;
		case '6':
			lcconf->default_af = AF_INET6;
			break;
#endif
		default:
			Usage();
			break;
		}
	}
	ac -= optind;
	av += optind;

	optind = 1;
	optarg = 0;

	return;
}

