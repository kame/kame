/*
 * Copyright (C) 1998 WIDE Project.
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

#ifdef INET6
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <netinet6/in6_var.h>
#include <netinet6/mip6.h>

#include <stdio.h>

#include "interface.h"
#include "addrtoname.h"

void
ip6_subopt_print(const u_char *bp, int len)
{
    int i, j;
    int optlen;
    struct mip6_subopt_id *id;
    struct mip6_subopt_hal *hal;
    struct mip6_subopt_coa *coa;

    for (i = 0; i < len; i += optlen) {
	switch (bp[i]) {
	case IP6OPT_PAD1:
	    optlen = 1;
	    break;
	case IP6OPT_PADN:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(padn: trunc)");
		goto trunc;
	    }
	    optlen = bp[i + 1] + 2;
	    break;
	case IP6SUBOPT_UNIQUEID:      /* Untested */
	    if (len - i < IP6OPT_UIDLEN + IP6OPT_MINLEN) {
		printf("(UniqueId: trunc)");
		goto trunc;
	    }
	    optlen = bp[i + 1] + 2;
	    id = (struct mip6_subopt_id *)&id[i];
	    printf("(UniqueId: %d)", ntohs(id->id));
	    break;
	case IP6SUBOPT_HALIST:
	    if (len - i < IP6OPT_HAMINLEN) {
		printf("(HAList: trunc)");
		goto trunc;
	    }
	    optlen = bp[i + 1] + 2;
	    printf("(HAList:");
	    hal = (struct mip6_subopt_hal *)&hal[i];
	    for (j = 0; j < bp[i + 1]; j += sizeof(struct in6_addr))
		printf(" %s", ip6addr_string(&hal->halist[j]));
	    printf(")");
	    break;
	case IP6SUBOPT_ALTCOA:
	    if (len - i < IP6OPT_COALEN + IP6OPT_MINLEN) {
		printf("(AltCOA: trunc)");
		goto trunc;
	    }
	    optlen = bp[i + 1] + 2;
	    coa = (struct mip6_subopt_coa *)&bp[i];
	    printf("(AltCOA: %s)", ip6addr_string(&coa->coa));
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(type %d: trunc)", bp[i]);
		goto trunc;
	    }
	    printf("(type 0x%02x: len=%d) ", bp[i], bp[i + 1]);
	    optlen = bp[i + 1] + 2;
	    break;
	}
    }

#if 0
end:
#endif
    return;

trunc:
    printf("[trunc] ");
}


void
ip6_opt_print(const u_char *bp, int len)
{
    int i;
    int optlen;
    struct mip6_opt_bu *bu;
    struct mip6_opt_ba *ba;
    struct mip6_opt_ha *ha;

    for (i = 0; i < len; i += optlen) {
	switch (bp[i]) {
	case IP6OPT_PAD1:
	    optlen = 1;
	    break;
	case IP6OPT_PADN:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(padn: trunc)");
		goto trunc;
	    }
	    optlen = bp[i + 1] + 2;
	    break;
	case IP6OPT_RTALERT:
	    if (len - i < IP6OPT_RTALERT_LEN) {
		printf("(rtalert: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_RTALERT_LEN - 2) {
		printf("(rtalert: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(rtalert: 0x%04x) ", ntohs(*(u_short *)&bp[i + 2]));
	    optlen = IP6OPT_RTALERT_LEN;
	    break;
	case IP6OPT_JUMBO:
	    if (len - i < IP6OPT_JUMBO_LEN) {
		printf("(jumbo: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_JUMBO_LEN - 2) {
		printf("(jumbo: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(jumbo: %u) ", (u_int32_t)ntohl(*(u_int *)&bp[i + 2]));
	    optlen = IP6OPT_JUMBO_LEN;
	    break;
	case IP6OPT_BINDING_UPDATE:
	    if (len - i < IP6OPT_BUMINLEN) {
		printf("(bindupdate: trunc)");
		goto trunc;
	    }

	    bu = (struct mip6_opt_bu *)&bp[i];
	    printf("(BindUpd flg=%s%s%s/%x plen=%d",	/*)*/
		   (bu->flags & MIP6_BU_AFLAG) ? "A" : "",
		   (bu->flags & MIP6_BU_HFLAG) ? "H" : "",
		   (bu->flags & MIP6_BU_RFLAG) ? "R" : "",
		   bu->flags, bu->prefix_len);
	    printf(" seq=%u", ntohs(bu->seqno));
	    printf(" life=%u", (u_int32_t)ntohl(bu->lifetime));

	    if (bp[i + 1] > IP6OPT_BUMINLEN) {
		printf(" subopt ");
		ip6_subopt_print(bp + IP6OPT_BUMINLEN, 
		     MIN(bp[i + 1] - IP6OPT_BUMINLEN + IP6OPT_MINLEN, len - i));
	    }
	    /*(*/
	    printf(")");

	    optlen = bp[i + 1] + 2;
	    break;
	case IP6OPT_BINDING_ACK:
	    if (len - i < IP6OPT_BAMINLEN) {
		printf("(bindack: trunc)");
		goto trunc;
	    }

	    ba = (struct mip6_opt_ba *)&bp[i];
	    printf("(BindAck status=%d", ba->status);	/*)*/
	    printf(" seq=%d", ntohs(ba->seqno));
	    printf(" life=%u", (u_int32_t)ntohl(ba->lifetime));
	    printf(" refresh=%u", (u_int32_t)ntohl(ba->refresh));

	    if (bp[i + 1] > IP6OPT_BAMINLEN) {
		printf(" subopt ");
		ip6_subopt_print(bp + IP6OPT_BAMINLEN, 
				 MIN(bp[i + 1] - IP6OPT_BAMINLEN,
				     len - i));
	    }
	    /*(*/
	    printf(")");

	    optlen = bp[i + 1] + 2;
	    break;
	case IP6OPT_BINDING_REQ:
	    if (len - i < IP6OPT_BRMINLEN) {
		printf("(bindreq: trunc)");
		goto trunc;
	    }

	    printf("(BindReq");	/*)*/

	    if (bp[i + 1] > IP6OPT_BRMINLEN) {
		printf(" subopt ");
		ip6_subopt_print(bp + IP6OPT_BRMINLEN, 
				 MIN(bp[i + 1] - IP6OPT_BRMINLEN,
				     len - i));
	    }
	    /*(*/
	    printf(")");
	    optlen = bp[i + 1] + 2;
	    break;
	case IP6OPT_HOME_ADDRESS:
	    if (len - i < IP6OPT_HAMINLEN) {
		printf("(homeaddr: trunc)");
		goto trunc;
	    }

	    ha = (struct mip6_opt_ha *)&bp[i];
	    printf("(HomeAddr %s",	/*)*/
		   ip6addr_string((struct in6_addr *)&ha->home_addr));

	    if (bp[i + 1] > IP6OPT_HAMINLEN) {
		printf(" subopt ");
		ip6_subopt_print(bp + IP6OPT_HAMINLEN, 
				 MIN(bp[i + 1] - IP6OPT_HAMINLEN,
				     len - i));
	    }
	    /*(*/
	    printf(")");
	    optlen = bp[i + 1] + 2;
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(type %d: trunc)", bp[i]);
		goto trunc;
	    }
	    printf("(type 0x%02x: len=%d) ", bp[i], bp[i + 1]);
	    optlen = bp[i + 1] + 2;
	    break;
	}
    }

#if 0
end:
#endif
    return;

trunc:
    printf("[trunc] ");
}

int
hbhopt_print(register const u_char *bp)
{
    const struct ip6_hbh *dp = (struct ip6_hbh *)bp;
    register const u_char *ep;
    int hbhlen = 0;

    /* 'ep' points to the end of avaible data. */
    ep = snapend;
    TCHECK(dp->ip6h_len);
    hbhlen = (int)((dp->ip6h_len + 1) << 3);
    TCHECK2(dp, hbhlen);
    printf("HBH ");
    if (vflag)
	ip6_opt_print((const u_char *)dp + sizeof(*dp), hbhlen - sizeof(*dp));

    return(hbhlen);

  trunc:
    fputs("[|HBH]", stdout);
    return(hbhlen);
}

int
dstopt_print(register const u_char *bp)
{
    const struct ip6_dest *dp = (struct ip6_dest *)bp;
    register const u_char *ep;
    int dstoptlen = 0;

    /* 'ep' points to the end of avaible data. */
    ep = snapend;
    TCHECK(dp->ip6d_len);
    dstoptlen = (int)((dp->ip6d_len + 1) << 3);
    TCHECK2(*dp, dstoptlen);
    printf("DSTOPT ");
    if (vflag) {
	ip6_opt_print((const u_char *)dp + sizeof(*dp),
	    dstoptlen - sizeof(*dp));
    }

    return(dstoptlen);

  trunc:
    fputs("[|DSTOPT]", stdout);
    return(dstoptlen);
}
#endif /* INET6 */
