/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 and 2000 WIDE Project.
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

/*
 * Copyright (c) 1999 and 2000 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Magnus Braathen <magnus.braathen@era.ericsson.se>
 *
 * TODO: This program should only print/clear automaticly created lists,
 *       like Binding cache, HA list, BU list. Other functions should be
 *       moved to config program.
 *
 * $Id: mip6stat.c,v 1.5 2000/02/09 16:02:20 itojun Exp $
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#if 0
#include <sys/linker.h>
#endif
#include <fcntl.h>
#include <kvm.h>
#include <err.h>
#include <limits.h>
#if 0
#include <sys/module.h>
#endif
#include <netinet6/mip6_common.h>
#include "mip6stat.h"

int aflag, cflag, fflag, hflag, lflag, mflag, nflag, pflag, uflag;
int Aflag, Cflag, Fflag, Mflag, Pflag, Uflag;

kvm_t *kd;
int s;

struct nlist namelist[] = {
#define BCACHE      0
    { "_mip6_bcq" },
#define FORADDR     1
    { "_mip6_config" },
#define HADDR       2
    { "_mip6_esmq" },
#define HALIST      3
    { "_mip6_llq" },
#define CONFIG      4
    { "_mip6_config" },
#define BULIST      5
    { "_mip6_bulq" },
#define NEND        5
    { NULL },
};

static int
upd_kernel(u_long cmd, void *args)
{
    struct mip6_input_data dummy;

    if (args == NULL) {
        bzero(&dummy, sizeof(dummy));
        args = &dummy;    /* ioctl() third argument must be non-NULL */
    }

    /* Note: max transfer size is PAGE_SIZE (4096 bytes?) */
    if (ioctl(s, cmd, (caddr_t)args) < 0)
	perror("ioctl");

    return 0;
}

/*
 * Read kernel memory, return 0 on success.
 */
int
kread(u_long addr, char *buf, int size)
{
    if(kd == NULL)
        return -1;

	if(kvm_read(kd, addr, buf, size) != size) {
		printf("%s\n", kvm_geterr(kd));
		return -1;
	}
	return size;
}

static void
usage()
{
	fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
"usage: mip6stat -a[nl]\tprint home agent list.",
"       mip6stat -A\tclear home agent list.",
"       mip6stat -c[nl]\tprint binding cache.",
"       mip6stat -C\tclear binding cache.",
"       mip6stat -f[nl]\tprint static address list.",
"       mip6stat -F\tclear static address list.",
"       mip6stat -m[nl]\tprint home address.",
"       mip6stat -M\tclear home address.",
"       mip6stat -p[l]\tprint configuration.",
"       mip6stat -P\trestore default configuration.",
"       mip6stat -u[nl]\tprint binding update list.",
"       mip6stat -U\tclear binding update list.",
"       mip6stat -h\tprint this help text.");
	exit(1);
}

void
trimdomain(char *cp)
{
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1;
	char *s;

	if (first) {
		first = 0;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		    (s = strchr(domain, '.')))
			strcpy(domain, s + 1);
		else
			domain[0] = 0;
	}

	if (domain[0]) {
		while ((cp = strchr(cp, '.'))) {
			if (!strcasecmp(cp + 1, domain)) {
				*cp = 0;	/* hit it */
				break;
			} else {
				cp++;
			}
		}
	}
}

char *
ip6addr_print(struct in6_addr *in6, int plen)
{
	register char *cp = 0;
	static char line[MAXHOSTNAMELEN + 5];
	struct hostent *hp;
    char ntop_buf[INET6_ADDRSTRLEN];

	if (!nflag) {
		hp = gethostbyaddr((char *)in6, sizeof(*in6), AF_INET6);
		if (hp) {
			cp = hp->h_name;
			trimdomain(cp);
		}
	}
	if (cp)
		strncpy(line, cp, sizeof(line) - 1);
	else
		sprintf(line, "%s", inet_ntop(AF_INET6, in6, ntop_buf,
					      sizeof(ntop_buf)));
		
    if(plen >= 0) {
        char plen_str[5];

        sprintf(plen_str, "/%d", plen);
        strcat(line, plen_str);
    }
    
	return line;
}

int main(int argc,
         char *argv[])
{
    int  ch, s = 0;
    char buf[_POSIX2_LINE_MAX];

	while ((ch = getopt(argc, argv, "aAcCfFhlmMnpPuU")) != -1)
		switch(ch) {
		case 'a':
            aflag = 1;
			break;
		case 'A':
            Aflag = 1;
			break;
		case 'c':
            cflag = 1;
			break;
		case 'C':
            Cflag = 1;
			break;
		case 'f':
            fflag = 1;
			break;
		case 'F':
            Fflag = 1;
			break;
		case 'h':
            hflag = 1;
			break;
		case 'm':
            mflag = 1;
			break;
		case 'M':
            Mflag = 1;
			break;
		case 'l':
            lflag = 1;
			break;
		case 'n':
            nflag = 1;
			break;
		case 'p':
            pflag = 1;
			break;
		case 'P':
            Pflag = 1;
			break;
		case 'u':
            uflag = 1;
			break;
		case 'U':
            Uflag = 1;
			break;
		case '?':
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

    if(optind < 2 || hflag)
        usage();

    if (getuid() != 0) {
		printf("Premission denied.\n");
		exit(1);
    }

    if(aflag + cflag + fflag + mflag + pflag + uflag +
       Aflag + Cflag + Fflag + Mflag + Pflag + Uflag == 0)
        usage();

    if(aflag + cflag + fflag + mflag + pflag + uflag > 0) {
        if((kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, buf)) == NULL) {
            errx(1, "error opening kernel: %s\n", buf);
        }
        if (kvm_nlist(kd, namelist) == -1) {
            fprintf(stderr, "kvm_nlist: %s", kvm_geterr(kd));
            exit(1);
        }
    }

    if(Aflag + Cflag + Fflag + Mflag + Pflag + Uflag > 0)
        if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
            err(1, "socket");

    if(aflag)
        halistpr(namelist[HALIST].n_value);
    if(cflag)
        bcachepr(namelist[BCACHE].n_value);
    if(fflag)
        foraddrpr(namelist[FORADDR].n_value);
    if(mflag)
        haddrpr(namelist[HADDR].n_value);
    if(pflag)
        configpr(namelist[CONFIG].n_value);
    if(uflag)
        bulistpr(namelist[BULIST].n_value);

    if(Aflag)
        upd_kernel(SIOCSHALISTFLUSH_MIP6, NULL);
    if(Cflag)
        upd_kernel(SIOCSBCFLUSH_MIP6, NULL);
    if(Fflag)
        upd_kernel(SIOCSFORADDRFLUSH_MIP6, NULL);
    if(Mflag)
        upd_kernel(SIOCSHADDRFLUSH_MIP6, NULL);
    if(Pflag)
        upd_kernel(SIOCSDEFCONFIG_MIP6, NULL);
    if(Uflag)
        upd_kernel(SIOCSBULISTFLUSH_MIP6, NULL);

    if(kd)
        kvm_close(kd);

    if(s)
        close(s);

    return 0;
}
