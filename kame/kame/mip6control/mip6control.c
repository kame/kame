/*	$KAME: mip6control.c,v 1.3 2001/10/24 07:10:34 keiichi Exp $	*/

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
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <netinet6/mip6.h>

static int getaddress(char *, struct in6_addr *);
static char *ip6addr_print(struct in6_addr *in6, int plen, char *);
static char *ip6_sprintf(const struct in6_addr *);

static const char *pfx_desc[] = {
	"prefix\t\tplen\tlifetim\tltrem\thaddr\n",
	"prefix\t\t\t\tplen\tlifetim\tltrem\thaddr\n"
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
	"%15.15s ",
	"%31.31s "
};

int
main(argc, argv)
     int argc;
     char **argv;
{
	int ch, s;
	int enablemn = 0;
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

	while ((ch = getopt(argc, argv, "mgli:H:hP:A:L:abc")) != -1) {
		switch(ch) {
		case 'm':
			enablemn = 1;
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

	if (enableha) {
		int enable = 1;
		if(ioctl(s, SIOCENABLEHA, (caddr_t)&enable) == -1) {
			perror("ioctl");
			exit(-1);
		}
	}

	if (smhparg && pfxarg) {
		struct hif_ifreq *ifr;

		ifr = malloc(sizeof(struct hif_ifreq) + sizeof(struct mip6_prefix));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 1;
		ifr->ifr_ifru.ifr_mpfx =
			(struct mip6_prefix *)((caddr_t)ifr 
					    + sizeof(struct hif_ifreq));
		getaddress(smhparg, &ifr->ifrmpfx_prefix);
		ifr->ifrmpfx_prefixlen = atoi(pfxarg);
		ifr->ifrmpfx_lifetime = 0xffff;
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
			     + 10 * sizeof(struct mip6_prefix));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(ifr, sizeof(sizeof(struct hif_ifreq)
				  + 10 * sizeof(struct mip6_prefix)));

		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 10;
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
			printf("%7u %7u %7qd",
			       mpfx->mpfx_prefixlen,
			       mpfx->mpfx_lifetime,
			       mpfx->mpfx_remain);
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mpfx->mpfx_haddr));
			printf("\n");
			mpfx++;
		}
	}

	if(shaarg && sllarg) {
		struct hif_ifreq *ifr;

		printf("set homeagent to %s (%s)\n",
		       ifnarg, shaarg);
		ifr = malloc(sizeof(struct hif_ifreq)
			     + sizeof(struct mip6_ha));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 1;
		ifr->ifr_ifru.ifr_mha =
			(struct mip6_ha *)((caddr_t)ifr 
					   + sizeof(struct hif_ifreq));
		getaddress(sllarg, &ifr->ifrmha_lladdr);
		getaddress(shaarg, &ifr->ifrmha_gaddr);
		ifr->ifrmha_flags = ND_RA_FLAG_HOME_AGENT;
		ifr->ifrmha_pref = 0;
		ifr->ifrmha_lifetime = 0xffff;
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
			     + 10 * sizeof(struct mip6_ha));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(ifr, sizeof(sizeof(struct hif_ifreq)
				  + 10 * sizeof(struct mip6_ha)));

		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 10;
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
			printf("%7x %7d %7d %7d\n",
			       mha->mha_flags,
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
			     + 10 * sizeof(struct mip6_bu));
		if (ifr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(ifr, sizeof(sizeof(struct hif_ifreq)
				  + 10 * sizeof(struct mip6_bu)));

		strcpy(ifr->ifr_name, ifnarg);
		ifr->ifr_count = 10;
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
			printf("%7u %7qd %7u %7qd %7u %7qd %7u %7x %7x %7x %7u %7u\n",
			       mbu->mbu_lifetime,
			       mbu->mbu_remain,
			       mbu->mbu_refresh,
			       mbu->mbu_refremain,
			       mbu->mbu_acktimeout,
			       mbu->mbu_ackremain,
			       mbu->mbu_seqno,
			       mbu->mbu_flags,
			       mbu->mbu_reg_state,
			       mbu->mbu_state,
			       mbu->mbu_dontsend,
			       mbu->mbu_coafallback);
			mbu++;
		}
	}

	if (gbc) {
		struct mip6_req *mr;
		struct mip6_rbc *mrbc;
		int i;

		mr = malloc(sizeof(struct mip6_req)
			    + 10 * sizeof(struct mip6_rbc));
		if (mr == NULL) {
			perror("malloc");
			exit(-1);
		}
		bzero(mr, sizeof(*mr) + 10 * sizeof(*mrbc));

		mr->mip6r_count = 10;
		mrbc = (struct mip6_rbc *)((caddr_t)mr
					   + sizeof(*mr));
		mr->mip6r_ru.mip6r_rbc = mrbc;
		if (ioctl(s, SIOCGBC, (caddr_t)mr) == -1) {
			perror("ioctl");
			exit(-1);
		}
		printf(bc_desc[longdisp]);
		for (i = 0; i < mr->mip6r_count; i++) {
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mrbc->phaddr.sin6_addr));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mrbc->pcoa.sin6_addr));
			printf(ipaddr_fmt[longdisp],
			       ip6_sprintf(&mrbc->addr.sin6_addr));
			printf(
#ifdef MIP6_DRAFT13
			       "%7x %7u %7u %7u %7qd %7x\n",
#else
			       "%7x %7u %7u %7qd %7x\n",
#endif /* MIP6_DRAFT13 */
			       mrbc->flags,
#ifdef MIP6_DRAFT13
			       mrbc->prefixlen,
#endif /* MIP6_DRAFT13 */
			       mrbc->seqno,
			       mrbc->lifetime,
			       mrbc->remain,
			       mrbc->state);
			mrbc++;
		}

	}
	
	exit(0);
}

/* Returns the address in network order */
static int
getaddress(char *address, struct in6_addr *in6addr)
{
        if (inet_pton(AF_INET6, address, in6addr) == NULL) {
                struct hostent *hp;
                if ((hp = gethostbyname2(address, AF_INET6)) == NULL)
                        return -1;
                else
                        memcpy(in6addr, hp->h_addr_list[0], 
                               sizeof(struct in6_addr));
        }
        return 0;
}

static char *
ip6addr_print(struct in6_addr *in6, int plen, char *ifname)
{
	static char line[NI_MAXHOST + 5];
	struct sockaddr_in6 sa6;
	int niflags = 0;

	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_addr = *in6;
	if (IN6_IS_ADDR_LINKLOCAL(&sa6.sin6_addr) && ifname != NULL) {
		/*
		 * Deal with KAME's embedded link ID.
		 * XXX: this function should take sockaddr_in6 with
		 * an appropriate sin6_scope_id value.
		 * XXX: this part assumes one-to-one mapping between
		 * links and interfaces, but it is not always true.
		 */
		sa6.sin6_addr.s6_addr[2] = 0;
		sa6.sin6_addr.s6_addr[3] = 0;
		sa6.sin6_scope_id = if_nametoindex(ifname);
	}

	/*
	if (!nflag)
		niflags |= NI_NUMERICHOST;
	*/
	if (getnameinfo((struct sockaddr *)&sa6, sizeof(sa6), line, NI_MAXHOST,
			NULL, 0, niflags) != 0)
		strcpy(line, "???"); /* XXX */

	if(plen >= 0) {
		char plen_str[5];

		sprintf(plen_str, "/%d", plen);
		strcat(line, plen_str);
	}
    
	return line;
}

static char digits[] = "0123456789abcdef";
static int ip6round = 0;
char *
ip6_sprintf(addr)
	const struct in6_addr *addr;
{
	static char ip6buf[8][48];
	int i;
	char *cp;
	u_short *a = (u_short *)addr;
	u_char *d;
	int dcolon = 0;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (u_char *)a;
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d++ & 0xf];
		*cp++ = digits[*d >> 4];
		*cp++ = digits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return(ip6buf[ip6round]);
}
