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

#include "common.h"

#define MUSTHAVE(var, cap, pb)	\
    {								\
	int t;							\
	if ((t = tgetnum(cap,pb)) < 0) {			\
		fprintf(stderr, "v6test: need %s\n", cap);	\
		exit(1);					\
	}							\
	var = t;						\
     }

#define MAYHAVE(var, cap, def, pb)			\
     {							\
	if ((var = tgetnum(cap,pb)) < 0)		\
		var = def;				\
     }

#define nextopt nexthdr
#define TBUFSIZ 2048

#include "testcap.h"

static u_char *pacbuf;
static char tbuf[BUFSIZ];
static u_char *pbp;
static uint8_t *nxthdrp = 0;
static int ip6plenauto;

static void make_ether(char *);
static void make_ip6(char *);
static void make_hbh(char *);
static void make_dstopts(char *);
static void make_padnopt(char *);
static void make_jumboopt(char *);
static void make_unknownopt(char *);
static void make_rthdr(char *);
static void make_frghdr(char *);
#ifdef IPSEC
static void make_ah(char *);
#endif
static void make_icmp6echo(char *, u_char);
static void make_icmperr(char *);
static void make_rtsol(char *);
static void make_rtadv(char *);
static void make_nsol(char *);
static void make_nadv(char *);
static void make_redirect(char *);
static void make_ndopt(char *);
static void make_ndopt_lladdr(char *, u_char);
static void copylladdr(char *, char *);
static void make_ndopt_prefix(char *);
static void make_ndopt_mtu(char *);
static void make_ndopt_unknown(char *);
static char *gettest(char *, char *);

extern char *nexthdr(char **bufp);
extern char *opthdr(char **bufp);

void
make_ether(char *name)
{
	char etherbuf[BUFSIZ], area[BUFSIZ], *addr, *bp = area;
	static char srcbuf[6], dstbuf[6];
	extern char *srceaddr, *dsteaddr;

	if (tgetent(etherbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}
	if (addr = tgetstr("esrc", &bp, etherbuf)) {
		copylladdr(addr, srcbuf);
		srceaddr = srcbuf;
	}
	if (addr = tgetstr("edst", &bp, etherbuf)) {
		copylladdr(addr, dstbuf);
		dsteaddr = dstbuf;
	}
}

void
make_ip6(char *name)
{
	char ip6buf[BUFSIZ], area[BUFSIZ], optionbuf[BUFSIZ];
	char *bp = area, *addr;
	struct ip6_hdr *ip6 = (struct ip6_hdr *)pbp;
	char val8;
	short val16;
	long val32;		/* XXX */
	extern char *optsrc, *optdst;
	extern struct in6_addr *optsrcn, *optdstn;

	if (tgetent(ip6buf, name) <= 0)
		errx(1, "unknown header %s\n", name);
	MUSTHAVE(ip6->ip6_flow, "ip6_flow", ip6buf);
	HTONL(ip6->ip6_flow);
	MAYHAVE(val16, "ip6_ver", 6, ip6buf);
	if (val16 < 0 || val16 > 15)
		errx(1, "IPv6 version field must be between 0 and 15"); 
	ip6->ip6_vfc = (val16 << 4) & 0xf0;
	MAYHAVE(val32, "ip6_tc", 0, ip6buf);
	if (val32 < 0 || val32 > 255)
		errx(1,
		     "IPv6 version traffic class must be between 0 and 255");
	ip6->ip6_vfc |= (val32 >> 4) & 0x0f;
	*(&ip6->ip6_vfc + 1) |= (val32 & 0x0f) << 4; /* XXX: ugly... */
	if ((val16 = tgetnum("ip6_plen", ip6buf)) < 0) {
		if ((addr = tgetstr("ip6_plen", &bp, ip6buf)) &&
		    strcmp(addr, "auto") == 0)
			ip6plenauto = 1;
		else {
			fprintf(stderr, "v6test: needs ip6_plen for IP6\n");
			exit(1);
		}
	} else
		ip6->ip6_plen = (u_int16_t)val16;
	HTONS(ip6->ip6_plen);
	if ((val8 = tgetnum("ip6_nxt", ip6buf)) < 0) {
		if ((addr = tgetstr("ip6_nxt", &bp, ip6buf)) &&
		    strcmp(addr, "auto") == 0)
			nxthdrp = &ip6->ip6_nxt;
		else {
			fprintf(stderr, "v6test: needs ip6_nxt for IP6\n");
			exit(1);
		}
	} else
		ip6->ip6_nxt = (u_int8_t)val8;
	MAYHAVE(val16, "ip6_hlim", 64, ip6buf);
	ip6->ip6_hlim = (u_char)val16;
	if (optsrcn)
		ip6->ip6_src = *optsrcn;
	else {
		if (optsrc) {
			if (tgetent(optionbuf, "optaddr") <= 0) {
				fprintf(stderr, "v6test: needs optaddr config entry for -s option\n");
				exit(1);
			}
			if ((addr = tgetstr(optsrc, &bp, optionbuf)) == NULL) {
				fprintf(stderr, "v6test: no address for %s\n",
					optsrc);
				exit(1);
			}
		} else if ((addr = tgetstr("ip6_src", &bp, ip6buf)) == NULL) {
			fprintf(stderr, "v6test: need addr for ip6_src\n");
			exit(1);
		}

		if (inet_pton(AF_INET6, addr, &ip6->ip6_src) != 1) {
			perror("inet_pton");
			exit(1);
		}
	}
	if (optdstn)
		ip6->ip6_dst = *optdstn;
	else {
		if (optdst) {
			if (tgetent(optionbuf, "optaddr") <= 0) {
				fprintf(stderr,
					"v6test: needs optaddr config entry for -d option\n");
				exit(1);
			}
			if ((addr = tgetstr(optdst, &bp, optionbuf)) == NULL) {
				fprintf(stderr,
					"v6test: no address for %s\n", optdst);
				exit(1);
			}
		}
		else if ((addr = tgetstr("ip6_dst", &bp, ip6buf)) == NULL) {
			fprintf(stderr, "v6test: needs addr for ip6_dst\n");
			exit(1);
		}
		if (inet_pton(AF_INET6, addr, &ip6->ip6_dst) != 1) {
			perror("inet_pton");
			exit(1);
		}
	}

	pbp += sizeof(*ip6);
}

void
make_hbh(char *name)
{
	char area[BUFSIZ], opttbuf[BUFSIZ];
	char *bp = area, *addr, *opts, *opttype, *bbp;
	struct ip6_hbh *hbh = (struct ip6_hbh *)pbp;

	bbp = gettest(name, opttbuf);
	if ((addr = tgetstr("hbh_nxt", &bp, bbp)) && strcmp(addr, "auto") == 0)
		nxthdrp = &hbh->ip6h_nxt;
	else
		MUSTHAVE(hbh->ip6h_nxt, "hbh_nxt", bbp);
	MUSTHAVE(hbh->ip6h_len, "hbh_len", bbp);
	pbp += sizeof(*hbh);
	if ((opts = tgetstr("hbh_opts", &bp, bbp)) == NULL) {
		fprintf(stderr, "v6test: need opts for HBH\n");
		exit(1);
	}
	bp = gettest(opts, opttbuf);
	while(opttype = nextopt(&bp)) {
		if (strncmp("pad1", opttype, 4) == 0) {
			*pbp = 0;
			pbp++;
		} else if (strncmp("padn", opttype, 4) == 0)
			make_padnopt(opttype);
		else if (strncmp("jumbo", opttype, 5) == 0)
			make_jumboopt(opttype);
		else if (strncmp("unknownopt", opttype, 10) == 0)
			make_unknownopt(opttype);
		else {
			fprintf(stderr,
				"v6test: unknown option type %s\n", opttype);
			exit(1);
		}
	}
}

void
make_dstopts(char *name)
{
	char area[BUFSIZ], opttbuf[BUFSIZ];
	char *bp = area, *addr, *opts, *opttype, *dp;
	struct ip6_dest *dopts = (struct ip6_dest *)pbp;

	dp = gettest(name, opttbuf);
	if ((addr = tgetstr("dst_nxt", &bp, dp)) && strcmp(addr, "auto") == 0)
		nxthdrp = &dopts->ip6d_nxt;
	else
		MUSTHAVE(dopts->ip6d_nxt, "dst_nxt", dp);
	MUSTHAVE(dopts->ip6d_len, "dst_len", dp);
	pbp += sizeof(*dopts);
	if ((opts = tgetstr("dst_opts", &bp, dp)) == NULL) {
		fprintf(stderr, "v6test: need opts for HBH\n");
		exit(1);
	}
	bp = gettest(opts, opttbuf);
	while(opttype = nextopt(&bp)) {
		if (strncmp("pad1", opttype, 4) == 0) {
			*pbp = 0;
			pbp++;
		}
		else if (strncmp("padn", opttype, 4) == 0)
			make_padnopt(opttype);
		else if (strncmp("unknownopt", opttype, 10) == 0)
			make_unknownopt(opttype);
		else {
			fprintf(stderr,
				"v6test: unknown option type %s\n", opttype);
			exit(1);
		}
	}
}

void
make_padnopt(char *name)
{
	char optbuf[BUFSIZ];
	u_char len;
	short reallen;

	if (tgetent(optbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
	*pbp = 1;		/* PadN option */
	MUSTHAVE(len, "padoptlen", optbuf);
	MAYHAVE(reallen, "padoptreallen", len, optbuf);
	*(pbp + 1) = len;
	bzero(pbp + 2, reallen);
	pbp += (reallen + 2);
}

void
make_jumboopt(char *name)
{
	char optbuf[BUFSIZ];
	u_char *optp = pbp;
	u_int32_t jumbolen;
    
	if (tgetent(optbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
#ifdef IP6OPT_JUMBO
	*optp = IP6OPT_JUMBO;
#else
	*optp = 0xc2;
#endif
	*(optp + 1) = 4;
	MUSTHAVE(jumbolen, "jumbolen", optbuf);
	HTONL(jumbolen);
	bcopy((caddr_t)&jumbolen, optp + 2, 4); /* XXX */

	pbp += 6;		/* size of jumbo payload option */
}

void
make_unknownopt(char *name)
{
	char optbuf[BUFSIZ];
	char val8;

	if (tgetent(optbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
	MUSTHAVE(val8, "opttype", optbuf);
	*pbp = val8;
	pbp++;
	MUSTHAVE(val8, "optlen", optbuf);
	*pbp = val8;
	pbp++;
	bzero(pbp, *(pbp - 1));
	pbp += *(pbp - 1);
}

void
make_rthdr(char *name)
{
	char rtbuf[BUFSIZ], area[BUFSIZ], hopstr[16];
	char *bp = area, *addr;
	struct ip6_rthdr *rthdr = (struct ip6_rthdr *)pbp;
	struct ip6_rthdr0 *rthdr0;
	int hops, i;
	int rthdrlen = 0;

	if (tgetent(rtbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	if ((addr = tgetstr("rthdr_nxt", &bp, rtbuf)) &&
	    strcmp(addr, "auto") == 0)
		nxthdrp = &rthdr->ip6r_nxt;
	else
		MUSTHAVE(rthdr->ip6r_nxt, "rthdr_nxt", rtbuf);
	MAYHAVE(rthdrlen, "rthdr_len", 0, rtbuf);
	MUSTHAVE(rthdr->ip6r_type, "rthdr_type", rtbuf);
	MUSTHAVE(rthdr->ip6r_segleft, "rthdr_segleft", rtbuf);

	switch(rthdr->ip6r_type) {
	case 0:
		MAYHAVE(hops, "rthdr0_hops", 0, rtbuf);
		if (hops == 0 && rthdrlen == 0) {
			fprintf(stderr,
				"v6test: needs rthdrlen or number of hops\n");
			exit(1);
		}
		else if (hops == 0)
			hops = (rthdrlen - 8) / sizeof(struct ip6_hdr);
		rthdr0 = (struct ip6_rthdr0 *)rthdr;
		rthdr0->ip6r0_reserved = 0;
#ifdef COMPAT_RFC1883
		bzero(rthdr0->ip6r0_slmap, 3);
		for (i = 0; i < hops; i++) {
			int slflag = 1;

			sprintf(hopstr, "hops%d", i);
			addr = tgetstr(hopstr, &bp, rtbuf);
			if (addr == NULL) {
				slflag = 0;
				sprintf(hopstr, "hopl%d", i);
				addr = tgetstr(hopstr, &bp, rtbuf);
			}
			if (addr == NULL) {
				fprintf(stderr,
					"v6test: needs %dth addr for rthdr\n", i);
				exit(1);
			}
			if (inet_pton(AF_INET6, addr,
				      ((struct in6_addr *)rthdr0 + 1) + i) != 1) {
				perror("inet_pton for %s", addr);
				exit(1);
			}
			if (slflag && i < 24) {
				int c, b;
				c = i / 8; b = i % 8;
				rthdr0->ip6r0_slmap[c] |= (1 << (7 - b));
			}
		}
#endif
		if (rthdrlen == 0)
			rthdrlen = sizeof(struct ip6_rthdr0) +
				sizeof(struct in6_addr) * (hops - 1);
		break;
	default:
		if (rthdrlen == 0)
			rthdrlen = 8;
		break;
	}

	rthdr->ip6r_len = (rthdrlen >> 3) - 1;
	pbp += rthdrlen;
}

void
make_frghdr(char *name)
{
	char frgbuf[BUFSIZ], area[BUFSIZ];
	char *addr, *bp = area;
	struct ip6_frag *frghdr = (struct ip6_frag *)pbp;
	int moreflag, id;
	short val16;

	if (tgetent(frgbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	if ((addr = tgetstr("frghdr_nxt", &bp, frgbuf)) &&
	    strcmp(addr, "auto") == 0)
		nxthdrp = &frghdr->ip6f_nxt;
	else
		MUSTHAVE(frghdr->ip6f_nxt, "frghdr_nxt", frgbuf);
	MAYHAVE(val16, "frghdr_rsv", 0, frgbuf);
	frghdr->ip6f_reserved = (u_int8_t)val16;
	MUSTHAVE(frghdr->ip6f_offlg, "frghdr_off", frgbuf);
	MAYHAVE(moreflag, "frghdr_more", 1, frgbuf);
	HTONS(frghdr->ip6f_offlg);
	if (moreflag)
		frghdr->ip6f_offlg |= IP6F_MORE_FRAG;
	MAYHAVE(id, "frghdr_id", 0, frgbuf);
	frghdr->ip6f_ident = htonl(id);

	pbp += sizeof(struct ip6_frag);
}

#ifdef IPSEC
void
make_ah(char *name)
{
	char ahbuf[BUFSIZ], area[BUFSIZ];
	char *addr, *bp = area;
	struct newah *ah = (struct newah *)pbp;	/* XXX: support older version? */
	char val8;
	short val16;
	long val32;

	if (tgetent(ahbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	if ((addr = tgetstr("ah_nxt", &bp, ahbuf)) &&
	    strcmp(addr, "auto") == 0)
		nxthdrp = &ah->ah_nxt;
	else
		MUSTHAVE(ah->ah_nxt, "ah_nxt", ahbuf);

	MAYHAVE(val8, "ah_len", 4, ahbuf);
	ah->ah_len = val8;
	MAYHAVE(val16, "ah_rsv", 0, ahbuf);
	ah->ah_reserve = val16;
	MUSTHAVE(val32, "ah_spi", ahbuf);
	ah->ah_spi = (u_int32_t)htonl(val32);
	MUSTHAVE(val32, "ah_seq", ahbuf);
	ah->ah_seq = (u_int32_t)htonl(val32);

	/* XXX: zero-clear the authentication data field */
	memset((char *)(ah + 1), 0, ((ah->ah_len + 2) << 2) - sizeof(ah));

	pbp += (ah->ah_len + 2) << 2;
}
#endif

void
make_icmp6echo(char *name, u_char type)
{
	char icmp6buf[BUFSIZ];
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)pbp;
	short val16;

	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	icmp6->icmp6_type = type;
	MUSTHAVE(icmp6->icmp6_code, "icmp6_code", icmp6buf);
	icmp6->icmp6_cksum = 0;	/* XXX */
	MUSTHAVE(icmp6->icmp6_id, "icmp6_id", icmp6buf);
	HTONS(icmp6->icmp6_id);
	MUSTHAVE(icmp6->icmp6_seq, "icmp6_seq", icmp6buf);
	HTONS(icmp6->icmp6_seq);
	MAYHAVE(val16, "icmp6_len", sizeof(*icmp6), icmp6buf);
    
	pbp += val16;
}

void
make_icmperr(char *name)
{
	char icmp6buf[BUFSIZ];
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)pbp;
    
	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}
	MUSTHAVE(icmp6->icmp6_type, "icmp6_type", icmp6buf);
	MUSTHAVE(icmp6->icmp6_code, "icmp6_code", icmp6buf);

	switch(icmp6->icmp6_type) {
	case ICMP6_PACKET_TOO_BIG:
		MUSTHAVE(icmp6->icmp6_mtu, "icmp6_mtu", icmp6buf);
		HTONL(icmp6->icmp6_mtu);
		break;
	case ICMP6_PARAM_PROB:
		MUSTHAVE(icmp6->icmp6_pptr, "icmp6_param", icmp6buf);
		HTONL(icmp6->icmp6_pptr);
		break;
	default:
		icmp6->icmp6_data32[0] = 0;
		break;
	}
	pbp += sizeof(*icmp6);
}

void
make_rtsol(char *name)
{
	char icmp6buf[BUFSIZ], area[BUFSIZ];
	char *bp = area, *optstr;
	struct nd_router_solicit *rs = (struct nd_router_solicit *)pbp;
	char code;
	int rsv;

	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	MAYHAVE(code, "icmp6_type", 0, icmp6buf);
	rs->nd_rs_code = code;
	MAYHAVE(rsv, "rs_rsv", 0, icmp6buf);
	rs->nd_rs_reserved = htonl(rsv);

	pbp += sizeof(*rs);

	optstr = tgetstr("rs_opts", &bp, icmp6buf);
	if (optstr)
		make_ndopt(optstr);
}

void
make_rtadv(char *name)
{
	char icmp6buf[BUFSIZ], area[BUFSIZ];
	char *bp = area, *optstr;
	char val8;
	short val16;
	int val32;

	struct nd_router_advert *ra = (struct nd_router_advert *)pbp;

	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	ra->nd_ra_type = ND_ROUTER_ADVERT;
	MAYHAVE(val8, "ra_code", 0, icmp6buf);
	ra->nd_ra_code = val8;
	MAYHAVE(val16, "ra_cksum", 0, icmp6buf);
	ra->nd_ra_cksum = htons(val16);
	MUSTHAVE(val8, "ra_curhop", icmp6buf);
	ra->nd_ra_curhoplimit = val8;
	MAYHAVE(val8, "ra_flag", 0, icmp6buf);
	ra->nd_ra_flags_reserved = val8;
	MUSTHAVE(val16, "ra_rltime", icmp6buf);
	ra->nd_ra_router_lifetime = htons(val16);
	MUSTHAVE(val32, "ra_rtime", icmp6buf);
	ra->nd_ra_reachable = htonl(val32);
	MUSTHAVE(val32, "ra_retrans", icmp6buf);
	ra->nd_ra_retransmit = htonl(val32);

	pbp += sizeof(*ra);

	optstr = tgetstr("ra_opts", &bp, icmp6buf);
	if (optstr)
		make_ndopt(optstr);
}

void
make_nsol(char *name)
{
	char icmp6buf[BUFSIZ], area[BUFSIZ];
	char *bp = area, *optstr, *target;
	struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)pbp;
	char val8;
	short val16;
	int val32;

	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	MAYHAVE(val8, "ns_code", 0, icmp6buf);
	ns->nd_ns_code = val8;
	MAYHAVE(val16, "ns_chksum", 0, icmp6buf);
	ns->nd_ns_cksum = htons(val16);
	MAYHAVE(val32, "ns_rsv", 0, icmp6buf);
	ns->nd_ns_reserved = htonl(val32);
	if ((target = tgetstr("ns_tgt", &bp, icmp6buf)) == NULL) {
		fprintf(stderr, "v6test: needs target addr for NS\n");
		exit(1);
	}
	if (strcmp(target, "auto") == 0) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)pacbuf;	/* XXX */

		ns->nd_ns_target = ip6->ip6_dst;
	}
	else if (inet_pton(AF_INET6, target, &ns->nd_ns_target) != 1) {
		perror("inet_pton");
		exit(1);
	}

	pbp += sizeof(*ns);
	optstr = tgetstr("ns_opts", &bp, icmp6buf);
	if (optstr)
		make_ndopt(optstr);
}

void
make_nadv(char *name)
{
	char icmp6buf[BUFSIZ], area[BUFSIZ];
	char *bp = area, *optstr, *target;
	struct nd_neighbor_advert *na = (struct nd_neighbor_advert *)pbp;
	char val8;
	short val16;

	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	MAYHAVE(val8, "na_code", 0, icmp6buf);
	na->nd_na_code = val8;
	MAYHAVE(val16, "na_cksum", 0, icmp6buf);
	na->nd_na_cksum = htons(val16);
	MAYHAVE(val8, "na_rflg", 0, icmp6buf);
	if (val8)
		na->nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;
	MAYHAVE(val8, "na_sflg", 0, icmp6buf);
	if (val8)
		na->nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
	MAYHAVE(val8, "na_oflg", 0, icmp6buf);
	if (val8)
		na->nd_na_flags_reserved |= ND_NA_FLAG_OVERRIDE;
	if ((target = tgetstr("na_tgt", &bp, icmp6buf)) == NULL) {
		fprintf(stderr, "v6test: needs target addr for NA\n");
		exit(1);
	}
	if (inet_pton(AF_INET6, target, &na->nd_na_target) != 1) {
		perror("inet_pton");
		exit(1);
	}

	pbp += sizeof(*na);
	optstr = tgetstr("na_opts", &bp, icmp6buf);
	if (optstr)
		make_ndopt(optstr);
}

void
make_redirect(name)
char *name;
{
	char icmp6buf[BUFSIZ], area[BUFSIZ];
	char *bp = area, *optstr, *addr;
	struct nd_redirect *rd = (struct nd_redirect *)pbp;
	char val8;
	short val16;
	int val32;

	if (tgetent(icmp6buf, name) <= 0) {
		fprintf(stderr, "v6test: unknown header %s\n", name);
		exit(1);
	}

	rd->nd_rd_type = ND_REDIRECT;
	MAYHAVE(val8, "rd_code", 0, icmp6buf);
	rd->nd_rd_code = val8;
	MAYHAVE(val16, "rd_cksum", 0, icmp6buf);
	rd->nd_rd_cksum = htons(val16);
	MAYHAVE(val32, "rd_rsv", 0, icmp6buf);
	rd->nd_rd_reserved = htonl(val32);
	if ((addr = tgetstr("rd_tgt", &bp, icmp6buf)) == NULL) {
		fprintf(stderr, "v6test: needs target addr for RD\n");
		exit(1);
	}
	if (inet_pton(AF_INET6, addr, &rd->nd_rd_target) != 1) {
		perror("inet_pton");
		exit(1);
	}
	if ((addr = tgetstr("rd_dst", &bp, icmp6buf)) == NULL) {
		fprintf(stderr, "v6test: needs dst addr for RD\n");
		exit(1);
	}
	if (inet_pton(AF_INET6, addr, &rd->nd_rd_dst) != 1) {
		perror("inet_pton");
		exit(1);
	}

	pbp += sizeof(*rd);
	optstr = tgetstr("rd_opts", &bp, icmp6buf);
	if (optstr)
		make_ndopt(optstr);
}

void
make_ndopt(char *name)
{
	char ndoptbuf[BUFSIZ];
	char *bp, *opttype;

	bp = gettest(name, ndoptbuf);
	while(opttype = nextopt(&bp)) {
		if (strncmp("srclladdr", opttype, 9) == 0)
			make_ndopt_lladdr(opttype, ND_OPT_SOURCE_LINKADDR);
		else if (strncmp("tgtlladdr", opttype, 9) == 0)
			make_ndopt_lladdr(opttype, ND_OPT_TARGET_LINKADDR);
		else if (strncmp("prefix", opttype, 6) == 0)
			make_ndopt_prefix(opttype);
#if 0
		else if (strncmp("redirect", opttype, 8) == 0)
			make_ndopt_redirect(opttype);
#endif
		else if (strncmp("mtu", opttype, 3) == 0)
			make_ndopt_mtu(opttype);
		else if (strncmp("ndopt", opttype, 5) == 0)
			make_ndopt_unknown(opttype);
		else {
			fprintf(stderr, "v6test: unknown nd option %s\n");
			exit(1);
		}
	}
}

void
make_ndopt_lladdr(char *name, u_char type)
{
	char area[BUFSIZ], ndoptbuf[BUFSIZ];
	char *bp = area, *eaddr;
	struct nd_opt_hdr *opthdr = (struct nd_opt_hdr *)pbp;
	u_int8_t *lladdr = (u_int8_t *)(opthdr + 1);
	char val8;

	if (tgetent(ndoptbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
	opthdr->nd_opt_type = type;
	MAYHAVE(val8, "len", 1, ndoptbuf);
	opthdr->nd_opt_len = val8;
	if ((eaddr = tgetstr("lladdr", &bp, ndoptbuf)) == NULL) {
		fprintf(stderr, "v6test: lladdr opt needs lladdr string\n");
		exit(1);
	}
	copylladdr(eaddr, (char *)lladdr);
	pbp += (opthdr->nd_opt_len << 3);
}

void
copylladdr(char *eaddr, char *buf)
{
	char *bp, *cp;
	char eaddrbuf[18];
	int i;

	bcopy(eaddr, eaddrbuf, 18);
	eaddrbuf[18] = ':';
	bp = eaddrbuf;
	for (i = 0; i < 6; i++) {
		cp = index(bp, ':');
		if (cp)
			*cp = '\0';
		sscanf(bp, "%02x", buf + i);
		if (cp == 0)
			break;
		bp = cp + 1;
	}
}

void
make_ndopt_prefix(char *name)
{
	char area[BUFSIZ], ndoptbuf[BUFSIZ];
	char *bp = area, *pfxstr;
	struct nd_opt_prefix_info *pfx = (struct nd_opt_prefix_info *)pbp;
	char val8;
	int val32;

	if (tgetent(ndoptbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
	pfx->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	MAYHAVE(val8, "len", 4, ndoptbuf);
	pfx->nd_opt_pi_len = val8;
	MUSTHAVE(val8, "pfxlen", ndoptbuf);
	pfx->nd_opt_pi_prefix_len = val8;
	MAYHAVE(val8, "lflg", 0, ndoptbuf);
	if (val8)
		pfx->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
	MAYHAVE(val8, "aflg", 0, ndoptbuf);
	if (val8)
		pfx->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	MUSTHAVE(val32, "vltime", ndoptbuf);
	pfx->nd_opt_pi_valid_time = htonl(val32);
	MUSTHAVE(val32, "pltime", ndoptbuf);
	pfx->nd_opt_pi_preferred_time = htonl(val32);
	MAYHAVE(val32, "rsv", 0, ndoptbuf);
	pfx->nd_opt_pi_reserved2 = htonl(val32);
	if ((pfxstr = tgetstr("prefix", &bp, ndoptbuf)) == NULL) {
		fprintf(stderr, "v6test: needs prefix for prefix info opt\n");
		exit(1);
	}
	if (inet_pton(AF_INET6, pfxstr, &pfx->nd_opt_pi_prefix) != 1) {
		perror("inet_pton");
		exit(1);
	}

	pbp += pfx->nd_opt_pi_len << 3;
}

void
make_ndopt_mtu(char *name)
{
	char ndoptbuf[BUFSIZ];
	struct nd_opt_mtu *mtu = (struct nd_opt_mtu *)pbp;
	char val8;
	int val32;

	if (tgetent(ndoptbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
	mtu->nd_opt_mtu_type = ND_OPT_MTU;
	MAYHAVE(val8, "len", 1, ndoptbuf);
	mtu->nd_opt_mtu_len = val8;
	MAYHAVE(val8, "rsv", 0, ndoptbuf);
	mtu->nd_opt_mtu_reserved = val8;
	MUSTHAVE(val32, "mtu", ndoptbuf);
	mtu->nd_opt_mtu_mtu = htonl(val32);

	pbp += mtu->nd_opt_mtu_len << 3;
}

void
make_ndopt_unknown(char *name)
{
	char ndoptbuf[BUFSIZ];
	char val8;
	int optlen;

	if (tgetent(ndoptbuf, name) <= 0) {
		fprintf(stderr, "v6test: unknown option %s\n", name);
		exit(1);
	}
	MUSTHAVE(val8, "opttype", ndoptbuf);
	*pbp = val8;
	pbp++;
	MUSTHAVE(val8, "optlen", ndoptbuf);
	optlen = *pbp = val8;
	if (optlen == 0)
		optlen = 1;
	pbp++;
	bzero(pbp, optlen * 8 - 2);
	pbp += optlen * 8 - 2;
}

void
make_tcp(char *name)
{
    char tcpbuf[BUFSIZ], area[BUFSIZ];
    char *addr, *bp = area;
    struct tcphdr *th = (struct tcphdr *)pbp;
    char val8;
    short val16;
    int val32;

    if (tgetent(tcpbuf, name) <= 0) {
	fprintf(stderr, "v6test: unknown header %s\n", name);
	exit(1);
    }

    MUSTHAVE(th->th_sport, "tcp_sport", tcpbuf);
    HTONS(th->th_sport);
    MUSTHAVE(th->th_dport, "tcp_dport", tcpbuf);
    HTONS(th->th_dport);
    MAYHAVE(val32, "tcp_seq", 0, tcpbuf);
    th->th_seq = htonl(val32);
    MAYHAVE(val32, "tcp_ack", 0, tcpbuf);
    th->th_ack = htonl(val32);
    MAYHAVE(val8, "tcp_off", sizeof(struct tcphdr) >> 2, tcpbuf);
    th->th_off = val8;
    MAYHAVE(val8, "tcp_flags", 0, tcpbuf);
    th->th_flags = val8;
    MAYHAVE(val16, "tcp_win", 8192, tcpbuf);
    th->th_win = htons(val16);
    MAYHAVE(val16, "tcp_sum", 0, tcpbuf);
    th->th_win = htons(val16);
    MAYHAVE(val16, "tcp_urp", 0, tcpbuf);
    th->th_urp = htons(val16);

    pbp += th->th_off << 2;
}

void
make_udp(char *name)
{
    char udpbuf[BUFSIZ], area[BUFSIZ];
    char *addr, *bp = area;
    struct udphdr *uh = (struct udphdr *)pbp;
    char val8;
    short val16;
    int val32;

    if (tgetent(udpbuf, name) <= 0) {
	fprintf(stderr, "v6test: unknown header %s\n", name);
	exit(1);
    }

    MUSTHAVE(uh->uh_sport, "udp_sport", udpbuf);
    HTONS(uh->uh_sport);
    MUSTHAVE(uh->uh_dport, "udp_dport", udpbuf);
    HTONS(uh->uh_dport);
    MAYHAVE(val16, "udp_len", 8, udpbuf);
    uh->uh_ulen = htons(val16);

    pbp += sizeof(*uh);
}

char *
gettest(char *testitem, char *buf)
{
	char *bp;

	if (tgetent(buf, testitem) <= 0) {
		fprintf(stderr, "v6test: unknown testitem %s\n", testitem);
		exit(1);
	}
	bp = buf;
	(void)nexthdr(&bp);	/* skip testitem */

	return(bp);
}

int
getconfig(char *testname, u_char *buf)
{
	char *hdrtype, *bp;

	pacbuf = pbp = buf;
	ip6plenauto = 0;
	bp = gettest(testname, tbuf);
	while(hdrtype = nexthdr(&bp)) {
		if (strncmp("interval", hdrtype, 8) == 0) {
			struct timeval sleeptm;
			u_long ival;

			ival = (u_long)atoi(hdrtype + 9);
			sleeptm.tv_sec = (ival * 1000) / 1000000;
			sleeptm.tv_usec = (ival * 1000) % 1000000;
			select(0, NULL, NULL, NULL, &sleeptm);
		} else if (strncmp("ether", hdrtype, 5) == 0) {
			make_ether(hdrtype);
		} else if (strncmp("ip6", hdrtype, 3) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_IPV6;
			nxthdrp = 0;
			make_ip6(hdrtype);
		} else if (strncmp("hbh", hdrtype, 3) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_HOPOPTS;
			nxthdrp = 0;
			make_hbh(hdrtype);
		} else if (strncmp("icmp6echorpl", hdrtype, 12) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_icmp6echo(hdrtype, ICMP6_ECHO_REPLY);
		} else if (strncmp("icmp6echo", hdrtype, 9) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_icmp6echo(hdrtype, ICMP6_ECHO_REQUEST);
		} else if (strncmp("icmp6err", hdrtype, 8) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_icmperr(hdrtype);
		} else if (strncmp("rtsol", hdrtype, 5) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_rtsol(hdrtype);
		} else if (strncmp("rtadv", hdrtype, 5) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_rtadv(hdrtype);
		} else if (strncmp("nsol", hdrtype, 4) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_nsol(hdrtype);
		} else if (strncmp("nadv", hdrtype, 4) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_nadv(hdrtype);
		} else if (strncmp("redirect", hdrtype, 8) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ICMPV6;
			nxthdrp = 0;
			make_redirect(hdrtype);
		} else if (strncmp("rthdr", hdrtype, 5) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_ROUTING;
			nxthdrp = 0;
			make_rthdr(hdrtype);
		} else if (strncmp("frghdr", hdrtype, 6) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_FRAGMENT;
			nxthdrp = 0;
			make_frghdr(hdrtype);
		}
#ifdef IPSEC
		else if (strncmp("authhdr", hdrtype, 7) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_AH;
			nxthdrp = 0;
			make_ah(hdrtype);
		}
#endif
		else if (strncmp("dstopt", hdrtype, 6) == 0) {
			if (nxthdrp)
				*nxthdrp = IPPROTO_DSTOPTS;
			nxthdrp = 0;
			make_dstopts(hdrtype);
		} else if (strncmp("tcp", hdrtype, 3) == 0) {
		    if (nxthdrp)
			*nxthdrp = IPPROTO_TCP;
		    nxthdrp = 0;
		    make_tcp(hdrtype);
		} else if (strncmp("udp", hdrtype, 3) == 0) {
		    if (nxthdrp)
			*nxthdrp = IPPROTO_UDP;
		    nxthdrp = 0;
		    make_udp(hdrtype);
		} else {
			fprintf(stderr, "v6test: unknown packet type %s\n",
				hdrtype);
			exit(1);
		}
	}
	if (ip6plenauto) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
		/* XXX: ignore the case of jumbo payload */
		ip6->ip6_plen = htons(pbp - pacbuf - sizeof(struct ip6_hdr));
	}
	return(pbp - pacbuf);
}
