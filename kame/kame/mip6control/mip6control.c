/*	$KAME: mip6control.c,v 1.10 2001/12/14 09:48:13 k-sugyou Exp $	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <err.h>
#include <string.h>
#include <netdb.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <net/if_hif.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <netinet6/mip6.h>

#define IOC_ENTRY_COUNT 100 /* XXX */

static int getaddress(char *, struct in6_addr *);
static const char *ip6_sprintf(const struct in6_addr *);
static const char *raflg_sprintf(u_int8_t);
static const char *buflg_sprintf(u_int8_t);

static const char *pfx_desc[] = {
	"prefix\t\tplen\tvltime\tvlrem\tpltime\tplrem\thaddr\n",
	"prefix\t\t\t\tplen\tvltime\tvlrem\tpltime\tplrem\thaddr\n"
};
static const char *bu_desc[] = {
	"paddr\t\thaddr\t\tcoa\t\tlifetim\tltrem\trefresh\trefrem\tacktimo\tackrem\tseqno\tflags\trstate\tstate\tdontsnd\tcoafb\n",
	"paddr\t\t\t\thaddr\t\t\t\tcoa\t\t\t\tlifetim\tltrem\trefresh\trefrem\tacktimo\tackrem\tseqno\tflags\trstate\tstate\tdontsnd\tcoafb\n"
};
static const char *ha_desc[] = {
	"lladdr\t\tgaddr\t\tflags\tpref\tlifetim\tltrem\n",
	"lladdr\t\t\t\tgaddr\t\t\t\tflags\tpref\tlifetim\tltrem\n"
};
#ifdef MIP6_DRAFT13
static const char *bc_desc[] = {
	"phaddr\t\tpcoa\t\taddr\t\tflags\tplen\tseqno\tlifetim\tltrem\tstats\n",
	"phaddr\t\t\t\tpcoa\t\t\t\taddr\t\t\t\tflags\tplen\tseqno\tlifetim\tltrem\tstats\n"
};
#else
static const char *bc_desc[] = {
	"phaddr\t\tpcoa\t\taddr\t\tflags\tseqno\tlifetim\tltrem\tstats\n",
	"phaddr\t\t\t\tpcoa\t\t\t\taddr\t\t\t\tflags\tseqno\tlifetim\tltrem\tstats\n"
};
#endif /* MIP6_DRAFT13 */
static const char *ipaddr_fmt[] = {
	"%-15.15s ",
	"%-31s "
};

int numerichost = 0;

int
main(argc, argv)
     int argc;
     char **argv;
{
	int ch, s;
	int enablemn = 0;
	int disablemn = 0;
	int enableha = 0;
	int longdisp = 0;
	char *ifnarg = "hif0";
	int pfx = 0;
	char *pfxarg = NULL;
	int smhp = 0, gmhp = 0;
	char *smhparg = NULL;
	int sha = 0, sll = 0, gha = 0;
	char *shaarg = NULL, *sllarg = NULL;
	int gbu = 0;
	int gbc = 0;

	while ((ch = getopt(argc, argv, "mMngli:H:hP:A:L:abc")) != -1) {
		switch(ch) {
		case 'm':
			enablemn = 1;
			break;
		case 'M':
			disablemn = 1;
			break;
		case 'n':
			numerichost = 1;
			break;
		case 'g':
			enableha = 1;
			break;
		case 'l':
			longdisp = 1;
			break;
		case 'i':
			ifnarg = optarg;
			break;
		case 'H':
			smhp = 1;
			smhparg = optarg;
			break;
		case 'P':
			pfx = 1;
			pfxarg = optarg;
			break;
		case 'A':
			sha = 1;
			shaarg = optarg;
			break;
		case 'a':
			gha = 1;
			break;
		case 'L':
			sll = 1;
			sllarg = optarg;
			break;
		case 'h':
			gmhp = 1;
			break;
		case 'b':
			gbu = 1;
			break;
		case 'c':
			gbc = 1;
			break;
		}
	}

	if((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(-1);
	}

	if (enablemn) {
		int enable = 1;
		if(ioctl(s, SIOCENABLEMN, (caddr_t)&enable) == -1) {
			perror("ioctl");
			exit(-1);
		}
	}

	if (disablemn) {
		int enable = 0;
		if(ioctl(s, SIOCENABLEMN, (caddr_t)&enable) == -1) {
			perror("ioctl");
			exit(-1);
		}
	}

	if (enableha) {
		int enable = 1;
		if(ioctl(s, SIOCENABLEHA, (caddr_t)&enable) == -1) {
			perror("ioctl");
			exit(-1);
		}
	}

	if (smhparg && pfxarg) {
		struct hif_ifreq *ifr;
		struct mip6_prefix *mpfx;

		ifr = malloc(sizeof(struct hif_ifreq) + sizeof(*mpfx));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 1;
		mpfx = (struct mip6_prefix *)((caddr_t)ifr 
					      + sizeof(struct hif_ifreq));
		ifr->ifr_ifru.ifr_mpfx = mpfx;
		getaddress(smhparg, &mpfx->mpfx_prefix);
		mpfx->mpfx_prefixlen = atoi(pfxarg);
		mpfx->mpfx_vltime = 0xffff; /* XXX */
		mpfx->mpfx_pltime = 0xff00; /* XXX */
		if(ioctl(s, SIOCAHOMEPREFIX_HIF, (caddr_t)ifr) == -1) {
			perror("ioctl");
			exit(-1);
		}
	}

	if (gmhp) {
		struct hif_ifreq *ifr;
		struct mip6_prefix *mpfx;
		int i;

		ifr = malloc(sizeof(struct hif_ifreq)
			     + IOC_ENTRY_COUNT * sizeof(struct mip6_prefix));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(ifr, sizeof(sizeof(struct hif_ifreq)
				  + IOC_ENTRY_COUNT * sizeof(struct mip6_prefix)));

		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = IOC_ENTRY_COUNT;
		mpfx = (struct mip6_prefix *)((caddr_t)ifr 
					   + sizeof(struct hif_ifreq));
		ifr->ifr_ifru.ifr_mpfx = mpfx;
		if (ioctl(s, SIOCGHOMEPREFIX_HIF, (caddr_t)ifr) == -1) {
			perror("ioctl");
			exit(-1);
		}

		printf(pfx_desc[longdisp]);
		for (i = 0; i < ifr->ifr_count; i++) {
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mpfx->mpfx_prefix));
			printf("%7u %7u %7qd %7u %7qd ",
			       mpfx->mpfx_prefixlen,
			       mpfx->mpfx_vltime,
			       mpfx->mpfx_vlremain,
			       mpfx->mpfx_pltime,
			       mpfx->mpfx_plremain);
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mpfx->mpfx_haddr));
			printf("\n");
			mpfx++;
		}
	}

	if(shaarg && sllarg) {
		struct hif_ifreq *ifr;
		struct mip6_ha *mha;

		printf("set homeagent to %s (%s)\n",
		       ifnarg, shaarg);
		ifr = malloc(sizeof(struct hif_ifreq) + sizeof(*mha));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 1;
		mha = (struct mip6_ha *)((caddr_t)ifr 
					 + sizeof(struct hif_ifreq));
		ifr->ifr_ifru.ifr_mha = mha;
		getaddress(sllarg, &mha->mha_lladdr);
		getaddress(shaarg, &mha->mha_gaddr);
		mha->mha_flags = ND_RA_FLAG_HOME_AGENT;
		mha->mha_pref = 0;
		mha->mha_lifetime = 0xffff;
		if(ioctl(s, SIOCAHOMEAGENT_HIF, (caddr_t)ifr) == -1) {
			perror("ioctl");
			exit(-1);
		}
	}

	if (gha) {
		struct hif_ifreq *ifr;
		struct mip6_ha *mha;
		int i;

		ifr = malloc(sizeof(struct hif_ifreq)
			     + IOC_ENTRY_COUNT * sizeof(struct mip6_ha));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(ifr, sizeof(sizeof(struct hif_ifreq)
				  + IOC_ENTRY_COUNT * sizeof(struct mip6_ha)));

		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = IOC_ENTRY_COUNT;
		mha = (struct mip6_ha *)((caddr_t)ifr 
					 + sizeof(struct hif_ifreq));
		ifr->ifr_ifru.ifr_mha = mha;
		if (ioctl(s, SIOCGHOMEAGENT_HIF, (caddr_t)ifr) == -1) {
			perror("ioctl");
			exit(-1);
		}

		printf(ha_desc[longdisp]);
		for (i = 0; i < ifr->ifr_count; i++) {
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mha->mha_lladdr));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mha->mha_gaddr));
			printf("%-7s %7d %7d %7d\n",
			       raflg_sprintf(mha->mha_flags),
			       mha->mha_pref,
			       mha->mha_lifetime,
			       mha->mha_remain);
			mha++;
		}
		
	}

	if (gbu) {
		struct hif_ifreq *ifr;
		struct mip6_bu *mbu;
		int i;

		ifr = malloc(sizeof(struct hif_ifreq)
			     + IOC_ENTRY_COUNT * sizeof(struct mip6_bu));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(ifr, sizeof(sizeof(struct hif_ifreq)
				  + IOC_ENTRY_COUNT * sizeof(struct mip6_bu)));

		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = IOC_ENTRY_COUNT;
		mbu = (struct mip6_bu *)((caddr_t)ifr 
					 + sizeof(struct hif_ifreq));
		ifr->ifr_ifru.ifr_mbu = mbu;
		if (ioctl(s, SIOCGBU_HIF, (caddr_t)ifr) == -1) {
			perror("ioctl");
			exit(-1);
		}
		printf(bu_desc[longdisp]);
		for (i = 0; i < ifr->ifr_count; i++) {
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mbu->mbu_paddr));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mbu->mbu_haddr));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mbu->mbu_coa));
			printf("%7u %7qd %7u %7qd %7u %7qd %7u %-7s %7x %7x %7u %7u\n",
			       mbu->mbu_lifetime,
			       mbu->mbu_remain,
			       mbu->mbu_refresh,
			       mbu->mbu_refremain,
			       mbu->mbu_acktimeout,
			       mbu->mbu_ackremain,
			       mbu->mbu_seqno,
			       buflg_sprintf(mbu->mbu_flags),
			       mbu->mbu_reg_state,
			       mbu->mbu_state,
			       mbu->mbu_dontsend,
			       mbu->mbu_coafallback);
			mbu++;
		}
	}

	if (gbc) {
		struct mip6_req *mr;
		struct mip6_bc *mbc;
		int i;

		mr = malloc(sizeof(struct mip6_req)
			    + IOC_ENTRY_COUNT * sizeof(struct mip6_bc));
		if (mr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(mr, sizeof(*mr) + IOC_ENTRY_COUNT * sizeof(*mbc));

		mr->mip6r_count = IOC_ENTRY_COUNT;
		mbc = (struct mip6_bc *)((caddr_t)mr
					 + sizeof(*mr));
		mr->mip6r_ru.mip6r_mbc = mbc;
		if (ioctl(s, SIOCGBC, (caddr_t)mr) == -1) {
			perror("ioctl");
			exit(-1);
		}
		printf(bc_desc[longdisp]);
		for (i = 0; i < mr->mip6r_count; i++) {
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mbc->mbc_phaddr));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mbc->mbc_pcoa));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mbc->mbc_addr));
			printf(
#ifdef MIP6_DRAFT13
			       "%-7s %7u %7u %7u %7qd %5x\n",
#else
			       "%-7s %7u %7u %7qd %5x\n",
#endif /* MIP6_DRAFT13 */
			       buflg_sprintf(mbc->mbc_flags),
#ifdef MIP6_DRAFT13
			       mbc->mbc_prefixlen,
#endif /* MIP6_DRAFT13 */
			       mbc->mbc_seqno,
			       mbc->mbc_lifetime,
			       mbc->mbc_remain,
			       mbc->mbc_state);
			mbc++;
		}

	}
	
	exit(0);
}

/* Returns the address in network order */
static int
getaddress(char *address, struct in6_addr *in6addr)
{
	struct addrinfo hints, *res;
	int ai_errno;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;

	ai_errno = getaddrinfo(address, NULL, &hints, &res);
	if (ai_errno)
		errx(1, "%s: %s", address, gai_strerror(ai_errno));
	memcpy(in6addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
	       sizeof(struct in6_addr));
	freeaddrinfo(res);

        return 0;
}

static int ip6round = 0;
const char *
ip6_sprintf(addr)
	const struct in6_addr *addr;
{
	static char ip6buf[8][NI_MAXHOST];
	static struct sockaddr_in6 sin6 = { sizeof(struct sockaddr_in6),
					    AF_INET6 };
	int flags = 0;

	if (numerichost)
		flags |= NI_NUMERICHOST;
	sin6.sin6_addr = *addr;

	ip6round = (ip6round + 1) & 7;

	if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6),
			ip6buf[ip6round], NI_MAXHOST, NULL, 0, flags) != 0)
		return "?";

	return ip6buf[ip6round];
}

static const char *
raflg_sprintf(flags)
	u_int8_t flags;
{
	static char buf[] = "MOH";

	snprintf(buf, sizeof(buf), "%s%s%s",
		 (flags & ND_RA_FLAG_MANAGED ? "M" : ""),
		 (flags & ND_RA_FLAG_OTHER ? "O" : ""),
		 (flags & ND_RA_FLAG_HOME_AGENT ? "H" : ""));

	return buf;
}

static const char *
buflg_sprintf(flags)
	u_int8_t flags;
{
	static char buf[] = "AHSO";

	snprintf(buf, sizeof(buf), "%s%s%s%s",
		 (flags & IP6_BUF_ACK ? "A" : ""),
		 (flags & IP6_BUF_HOME ? "H" : ""),
#ifdef MIP6_DRAFT13
		 (flags & IP6_BUF_ROUTER ? "R" : ""),
#else
		 (flags & IP6_BUF_SINGLE ? "S" : ""),
#endif
		 (flags & IP6_BUF_DAD ? "D" : ""));

	return buf;
}
