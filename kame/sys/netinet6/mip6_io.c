/*	$KAME: mip6_io.c,v 1.12 2001/03/29 05:34:32 itojun Exp $	*/

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
 * Copyright (c) 1999, 2000 and 2001 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Authors: Conny Larsson <Conny.Larsson@era.ericsson.se>
 *          Mattias Pettersson <Mattias.Pettersson@era.ericsson.se>
 *
 */

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#endif

#ifdef __NetBSD__
#include "opt_inet.h"
#include "opt_ipsec.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_gif.h>
#include <net/if_dl.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet/ip_encap.h>
#include <netinet/icmp6.h>

#include <netinet6/ip6_var.h>
#include <netinet6/ip6protosw.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

#ifdef MIP6_DEBUG
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <machine/stdarg.h>
#include <sys/syslog.h>
#endif

#include <net/net_osdep.h>

/*
 ##############################################################################
 #
 # FUNCTIONS FOR CHECKING OF INCOMING IPV6 PACKETS
 # Used for checking of incoming packets, which does not necessarily contains
 # any MIP6 options, to make sure that route optimization is done.
 # 
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_route_optimize
 * Description: When a tunneled packet is received a BU shall be sent to the
 *              CN if no Binding Update List entry exist or if the rate limit
 *              for sending BUs for an existing BUL entry is not exceded
 *              (see 10.11).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_route_optimize(m)
struct mbuf *m;    /* Mbuf containing the IPv6 packet */
{
	struct ip6_opt_binding_update *bu_opt;
	struct ip6_hdr                *ip6;
	struct ip6aux                 *ip6a = NULL;
	struct mbuf                   *n;
	struct mip6_esm               *esp;
	struct mip6_bul               *bulp, *bulp_ha;
	struct mip6_buffer             subbuf;
	struct mip6_subopt_altcoa      altcoa;
	struct in6_addr                src_addr;
	u_int8_t                       bu_flags;
	time_t                         t;
	int                            size, free_bul = 0;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	/* Make sure that all requirements are meet for sending a BU to
	   the original sender of the packet. */
	if (!MIP6_IS_MN_ACTIVE)
		return 0;

	if (!(m->m_flags & M_MIP6TUNNEL))
		return 0;

	ip6 = mtod(m, struct ip6_hdr *);
	esp = mip6_esm_find(&ip6->ip6_dst, 0);
	if (esp == NULL)
		return 0;

	bulp_ha = mip6_bul_find(NULL, &esp->home_addr);
	if (bulp_ha == NULL)
		return 0;

	/* Find the correct source address */
	n = ip6_findaux(m);
	if (!n) return -1;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return -1;
	ip6 = mtod(m, struct ip6_hdr *);

	if (ip6a->ip6a_flags & IP6A_HASEEN)
		src_addr = ip6a->ip6a_home;
	else
		src_addr = ip6->ip6_src;

	/* Try to find an existing BUL entry. */
	bu_flags = 0;
	bulp = mip6_bul_find(&src_addr, &ip6->ip6_dst);
	if (bulp == NULL) {
		/* Create Binding Update list entry */
		bulp = mip6_bul_create(&src_addr, &esp->home_addr, &esp->coa,
				       bulp_ha->lifetime, bu_flags);
		if (bulp == NULL) return -1;
		free_bul = 1;
	} else {
		/* If the existing BUL entry is waiting for an ack or
		   has disabled sending BU, no BU shall be sent. */
		if ((bulp->flags & IP6_BUF_ACK) || (bulp->send_flag == 0))
			return 0;

		/* Check the rate limiting for sending Binding Updates */
		t = (time_t)time_second;
		if ((t - bulp->lasttime) < bulp->bul_rate)
			return 0;

		/* Update existing BUL entry */
		bulp->peer_home = src_addr;
		bulp->local_coa = esp->coa;
		bulp->lifetime = bulp_ha->lifetime;
		bulp->refresh = bulp_ha->lifetime;
	}

	/* Create Binding Update option */
	bu_opt = mip6_create_bu(esp->prefixlen, bu_flags,
				bulp_ha->lifetime);
	if (bu_opt == NULL) {
		if (free_bul) mip6_bul_delete(bulp);
		return -1;
	}

	/* Create necessary sub-options */
	bzero((caddr_t)&subbuf, sizeof(struct mip6_buffer));

	altcoa.type = IP6SUBOPT_ALTCOA;
	altcoa.len = IP6OPT_COALEN;
	size = sizeof(struct in6_addr);
	bcopy((caddr_t)&esp->coa, &altcoa.coa, size);
	mip6_add_subopt2buf((u_int8_t *)&altcoa, &subbuf);

	/* Send BU to CN */
	if (mip6_send_bu(bulp, bu_opt, &subbuf)) {
		free(bu_opt, M_TEMP);
		return -1;
	}

	free(bu_opt, M_TEMP);
	return 0;
}



/*
 ##############################################################################
 #
 # FUNCTIONS FOR PROCESSING OF INCOMING MIPV6 OPTIONS
 # Below are functions used for processing of received MIPv6 options (BU, BA
 # and BR) and its sub-options. These options are received by the dest6_input()
 # function, which calls the mip6_dstopt() function. The mip6_dstopt() function
 # is a dispatcher function.
 # As a result of processing an option other functions will be called which
 # eventually results in either a response or an action. The functions for
 # sending responses are also defined under this section.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_dstopt
 * Description: Decides which MIPv6 option that was received and processes it
 *              accordingly.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_dstopt(m, dh, opt, dhlen)
struct mbuf     *m;      /* Ptr to beginning of mbuf */
struct ip6_dest *dh;     /* Ptr to beginning of DH */
u_int8_t        *opt;    /* Ptr to current option in DH */
int              dhlen;  /* Remaining DH length */
{
	u_int8_t *subopt;   /* Ptr to first sub-option in current option */
	u_int8_t  optlen;   /* Remaining option length */
	int       res;
	
	optlen = *(opt + 1);
	if (dhlen < (optlen + IP6OPT_MINLEN)) {
		ip6stat.ip6s_toosmall++;
		return -1;
	}

	switch (*opt) {
		case IP6OPT_BINDING_UPDATE:
			/* Verify BU alignment requirement: 4n+2 */
			if ((opt - (u_int8_t *)dh) % 4 != 2) {
				ip6stat.ip6s_badoptions++;
				log(LOG_ERR, "%s: BU alignment failure\n",
				    __FUNCTION__);
				return -1;
			}

			if (mip6_validate_bu(m, opt) == -1) return -1;
			if (optlen > IP6OPT_BULEN) {
				subopt = opt + IP6OPT_MINLEN + IP6OPT_BULEN;
				optlen -= IP6OPT_BULEN;
				if (mip6_validate_subopt(dh, subopt,
							 optlen) == -1)
					return -1;
			}
			if (mip6_process_bu(m, opt) == -1) return -1;
			break;

		case IP6OPT_BINDING_ACK:
			if (!MIP6_IS_MN_ACTIVE) return 0;

			/* Verify BA alignment requirement: 4n+3 */
			if ((opt - (u_int8_t *)dh) % 4 != 3) {
				ip6stat.ip6s_badoptions++;
				log(LOG_ERR, "%s: BA alignment failure\n",
				    __FUNCTION__);
				return -1;
			}

			res = mip6_validate_ba(m, opt);
			if (res == -1) return -1;
			else if (res == -2) return 0;
			
			if (mip6_process_ba(m, opt) == -1) return -1;
			break;

		case IP6OPT_BINDING_REQ:
			if (!MIP6_IS_MN_ACTIVE) return 0;

			if (optlen > IP6OPT_BRLEN) {
				subopt = opt + IP6OPT_MINLEN + IP6OPT_BRLEN;
				optlen -= IP6OPT_BRLEN;
				if (mip6_validate_subopt(dh, subopt,
							 optlen) == -1)
					return -1;
			}
			if (mip6_process_br(m, opt) == -1) return -1;
			break;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_print_subopt
 * Description: Print sub-options included in MIPv6 options.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_print_subopt(subopt, optlen)
u_int8_t  *subopt;   /* Ptr to first sub-option in current option */
u_int8_t   optlen;   /* Remaining option length */
{
	struct mip6_subopt_altcoa *altcoa;
	struct mip6_subopt_uid    *uid;
	struct in6_addr           *addr;

	/* Search all sub-options for current option */
	while (optlen > 0) {
		switch (*subopt) {
			case IP6OPT_PAD1:
				optlen -= 1;
				subopt += 1;
				break;
			case IP6OPT_PADN:
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
			case IP6SUBOPT_UNIQUEID:
				uid = (struct mip6_subopt_uid *)subopt;
				mip6_debug("Unique Identifier sub-option\n");
				mip6_debug("Type/Length/Id:     %x "
					   "/ %u / %u\n",
					   uid->type, uid->len,
					   ntohs(*(u_int16_t *)uid->uid));
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
			case IP6SUBOPT_ALTCOA:
				altcoa = (struct mip6_subopt_altcoa *)subopt;
				addr = (struct in6_addr *)altcoa->coa;
				mip6_debug("Alternate coa sub-option\n");
				mip6_debug("Type/Length:        %x / %u\n",
					   altcoa->type, altcoa->len);
				mip6_debug("Care-of address:    %s\n",
					   ip6_sprintf(addr));
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
			default:
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
		}
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_print_opt
 * Description: Print MIPv6 options included in an incoming  destination
 *              header.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_print_opt(m, opt)
struct mbuf *m;     /* Ptr to beginning of mbuf */
u_int8_t    *opt;   /* Ptr to MIP6 option in DH */
{
	struct ip6_opt_binding_update   *bu_opt;
	struct ip6_opt_binding_ack      *ba_opt;
	struct ip6_opt_binding_request  *br_opt;
	struct ip6_hdr                  *ip6;
	struct ip6aux                   *ip6a = NULL;
	struct mbuf                     *n;
	u_int8_t                        *subopt;

	ip6 = mtod(m, struct ip6_hdr *);

	/* Search all sub-options for current option */
	if (*opt == IP6OPT_BINDING_UPDATE) {
		n = ip6_findaux(m);
		if (!n) return;
		ip6a = mtod(n, struct ip6aux *);
		if (ip6a == NULL) return;

		bu_opt = (struct ip6_opt_binding_update *)opt;

		mip6_debug("\nReceived Binding Update\n");
		mip6_debug("Src home address    %s\n",
			   ip6_sprintf(&ip6a->ip6a_home));
		mip6_debug("Src Care-of address %s\n",
			   ip6_sprintf(&ip6a->ip6a_careof));
		mip6_debug("Dst address         %s\n",
			   ip6_sprintf(&ip6->ip6_dst));
		mip6_debug("Type/Length/Flags:  %x / %u / ",
			   bu_opt->ip6ou_type, bu_opt->ip6ou_len);
		if (bu_opt->ip6ou_flags & IP6_BUF_ACK)    mip6_debug("A ");
		if (bu_opt->ip6ou_flags & IP6_BUF_HOME)   mip6_debug("H ");
		if (bu_opt->ip6ou_flags & IP6_BUF_ROUTER) mip6_debug("R ");
		if (bu_opt->ip6ou_flags & IP6_BUF_DAD)    mip6_debug("D ");
		mip6_debug("\n");
		mip6_debug("Prefix length:      %u\n",
			   bu_opt->ip6ou_prefixlen);
		mip6_debug("Sequence number:    %u\n",
			   ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno));
		mip6_debug("Life time:          ");
		mip6_print_sec(ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime));
		if (bu_opt->ip6ou_len > IP6OPT_BULEN) {
			subopt = opt + IP6OPT_MINLEN + IP6OPT_BULEN;
			mip6_print_subopt(subopt , *(opt + 1) - IP6OPT_BULEN);
		}
		return;
	}

	if (*opt == IP6OPT_BINDING_ACK) {
		ba_opt = (struct ip6_opt_binding_ack *)opt;

		mip6_debug("\nReceived Binding Acknowledgement\n");
		mip6_debug("IP Header Src:      %s\n",
			   ip6_sprintf(&ip6->ip6_src));
		mip6_debug("IP Header Dst:      %s\n",
			   ip6_sprintf(&ip6->ip6_dst));
		mip6_debug("Type/Length/Status: %x / %u / %u\n",
			   ba_opt->ip6oa_type, ba_opt->ip6oa_len,
			   ba_opt->ip6oa_status);
		mip6_debug("Sequence number:    %u\n",
			   ntohs(*(u_int16_t *)ba_opt->ip6oa_seqno));
		mip6_debug("Life time:          ");
		mip6_print_sec(ntohl(*(u_int32_t *)ba_opt->ip6oa_lifetime));
		mip6_debug("Refresh time:       ");
		mip6_print_sec(ntohl(*(u_int32_t *)ba_opt->ip6oa_refresh));
		if (ba_opt->ip6oa_len > IP6OPT_BALEN) {
			subopt = opt + IP6OPT_MINLEN + IP6OPT_BALEN;
			mip6_print_subopt(subopt , *(opt + 1) - IP6OPT_BALEN);
		}
		return;
	}
	
	if (*opt == IP6OPT_BINDING_REQ) {
		br_opt = (struct ip6_opt_binding_request *)opt;
		
		mip6_debug("\nReceived Binding Request\n");
		mip6_debug("IP Header Src:   %s\n",
			   ip6_sprintf(&ip6->ip6_src));
		mip6_debug("IP Header Dst:   %s\n",
			   ip6_sprintf(&ip6->ip6_dst));
		mip6_debug("Type/Length:     %x / %u\n",
			   br_opt->ip6or_type, br_opt->ip6or_len);
		if (br_opt->ip6or_len > IP6OPT_BRLEN) {
			subopt = opt + IP6OPT_MINLEN + IP6OPT_BRLEN;
			mip6_print_subopt(subopt , *(opt + 1) - IP6OPT_BRLEN);
		}
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_find_offset
 * Description: If the Destination header contains data it may already have
 *              an 8 octet alignment. The last alignment bytes in the header
 *              might be possible to remove and instead use it for options.
 *              This function adjusts the buffer offset, if possible.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_find_offset(buf)
struct mip6_buffer *buf;  /* Destination header with options */
{
	int       ii;
	u_int8_t  new_off;

	/* Verify input */
	if ((buf == NULL) || (buf->off < 2)) return;

	/* Check the buffer for unnecessary padding */
	new_off = 2;
	for (ii = 2; ii < buf->off;) {
		if (*(buf->buf + ii) == IP6OPT_PAD1) {
			new_off = ii;
			ii += 1;
		} else if (*(buf->buf + ii) == IP6OPT_PADN) {
			new_off = ii;
			ii += *(buf->buf + ii + 1) + 2;
		} else {
			ii += *(buf->buf + ii + 1) + 2;
			new_off = ii;
		}
	}
	buf->off = new_off;
}



/*
 ******************************************************************************
 * Function:    mip6_add_subopt2buf
 * Description: Add one sub-option to the internal buffer. This buffer may
 *              include several consecutive sub-options. All sub-options must
 *              belong to the same MIPv6 option. The sub-options are not
 *              aligned in this function. Alignment is done in function
 *              mip6_add_subopt2dh().
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_add_subopt2buf(subopt, buf)
u_int8_t            *subopt;   /* Sub-option to add */
struct mip6_buffer  *buf;      /* Buffer holding all sub-options */
{
	struct mip6_subopt_altcoa *altcoa;
	struct mip6_subopt_uid    *uid;
	u_int16_t                  var16;
	u_int8_t                   len;

	/* Verify input */
	if (subopt == NULL || buf == NULL) return;

	/* Add sub-option to the internal sub-option buffer */
	switch (*subopt) {
		case IP6SUBOPT_UNIQUEID:
			uid = (struct mip6_subopt_uid *)subopt;
			if (uid->len != IP6OPT_UIDLEN) return;

			/* Append sub-option to buffer */
			len = IP6OPT_UIDLEN + IP6OPT_MINLEN;
			bzero((caddr_t)buf->buf + buf->off, len);
			bcopy((caddr_t)uid, (caddr_t)buf->buf + buf->off, len);

			uid = (struct mip6_subopt_uid *)(buf->buf + buf->off);
			var16 = htons(*(u_int16_t *)uid->uid);
			bcopy((caddr_t)&var16, uid->uid, sizeof(u_int16_t));
			buf->off += len;
			break;
		case IP6SUBOPT_ALTCOA:
			altcoa = (struct mip6_subopt_altcoa *)subopt;
			if (altcoa->len != IP6OPT_COALEN) return;

			/* Append sub-option to buffer */
			len = IP6OPT_COALEN + IP6OPT_MINLEN;
			bzero((caddr_t)buf->buf + buf->off, len);
			bcopy((caddr_t)altcoa,
			      (caddr_t)buf->buf + buf->off, len);
			buf->off += len;
			break;
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_add_opt2dh
 * Description: Add Binding Update, Binding Acknowledgement, Binding Request
 *              or Home Address option to a Destination Header. The option
 *              must be aligned when added.
 * Ret value:   Ptr where the MIPv6 option is located in the Destination header
 *              or NULL.
 ******************************************************************************
 */
u_int8_t *
mip6_add_opt2dh(opt, dh)
u_int8_t            *opt;   /* BU, BR, BA or Home Address option */
struct mip6_buffer  *dh;    /* Buffer containing the IPv6 DH  */
{
	struct ip6_opt_binding_update  *bu;
	struct ip6_opt_binding_ack     *ba;
	struct ip6_opt_binding_request *br;
	struct ip6_opt_home_address    *ha;
	u_int8_t                       *pos, len, padn, off;
	u_int16_t                       seqno;
	u_int32_t                       t;
	int                             rest;

	/* Verify input */
	pos = NULL;
	if (opt == NULL || dh == NULL) return pos;
	if (dh->off < 2) {
		bzero((caddr_t)dh->buf, 2);
		dh->off = 2;
	}

	/* Add option to Destination header */
	padn = IP6OPT_PADN;
	switch (*opt) {
		case IP6OPT_BINDING_UPDATE:
			/* BU alignment requirement (4n + 2) */
			rest = dh->off % 4;
			if (rest == 0) {
				/* Add a PADN option with length 0 */
				bzero((caddr_t)dh->buf + dh->off, 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				dh->off += 2;
			} else if (rest == 1) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
			} else if (rest == 3) {
				/* Add a PADN option with length 1 */
				len = 1;
				bzero((caddr_t)dh->buf + dh->off, 3);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += 3;
			}

			/* Copy option to DH */
			len = IP6OPT_BULEN + IP6OPT_MINLEN;
			off = dh->off;
			bu = (struct ip6_opt_binding_update *)opt;

			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)bu, (caddr_t)dh->buf + off, len);

			bu = (struct ip6_opt_binding_update *)(dh->buf + off);
#ifdef DIAGNOSTIC
			if (sizeof(seqno) != sizeof(bu->ip6ou_seqno))
				panic("bcopy problem");
#endif
			seqno = htons(*(u_int16_t *)bu->ip6ou_seqno);
			bcopy((caddr_t)&seqno, bu->ip6ou_seqno, sizeof(seqno));
#ifdef DIAGNOSTIC
			if (sizeof(t) != sizeof(bu->ip6ou_lifetime))
				panic("bcopy problem");
#endif
			t = htonl(*(u_int32_t *)bu->ip6ou_lifetime);
			bcopy((caddr_t)&t, bu->ip6ou_lifetime, sizeof(t));
			
			pos = dh->buf + off;
			dh->off += len;
			break;
		case IP6OPT_BINDING_ACK:
			/* BA alignment requirement (4n + 3) */
			rest = dh->off % 4;
			if (rest == 1) {
				/* Add a PADN option with length 0 */
				bzero((caddr_t)dh->buf + dh->off, 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				dh->off += 2;
			} else if (rest == 2) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
			} else if (rest == 0) {
				/* Add a PADN option with length 1 */
				len = 1;
				bzero((caddr_t)dh->buf + dh->off, 3);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += 3;
			}

			/* Copy option to DH */
			len = IP6OPT_BALEN + IP6OPT_MINLEN;
			off = dh->off;
			ba = (struct ip6_opt_binding_ack *)opt;

			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)ba, (caddr_t)dh->buf + off, len);

			ba = (struct ip6_opt_binding_ack *)(dh->buf + off);
#ifdef DIAGNOSTIC
			if (sizeof(seqno) != sizeof(ba->ip6oa_seqno))
				panic("bcopy problem");
#endif
			seqno = htons(*(u_int16_t *)ba->ip6oa_seqno);
			bcopy((caddr_t)&seqno, ba->ip6oa_seqno, sizeof(seqno));
#ifdef DIAGNOSTIC
			if (sizeof(t) != sizeof(ba->ip6oa_lifetime))
				panic("bcopy problem");
#endif
			t = htonl(*(u_int32_t *)ba->ip6oa_lifetime);
			bcopy((caddr_t)&time, ba->ip6oa_lifetime,sizeof(time));
#ifdef DIAGNOSTIC
			if (sizeof(t) != sizeof(ba->ip6oa_refresh))
				panic("bcopy problem");
#endif
			t = htonl(*(u_int32_t *)ba->ip6oa_refresh);
			bcopy((caddr_t)&time, ba->ip6oa_refresh, sizeof(time));
			
			pos = dh->buf + off;
			dh->off += len;
			break;
		case IP6OPT_BINDING_REQ:
			/* Copy option to DH */
			len = IP6OPT_BRLEN + IP6OPT_MINLEN;
			off = dh->off;
			br = (struct ip6_opt_binding_request *)opt;

			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)br, (caddr_t)dh->buf + off, len);
			
			pos = dh->buf + off;
			dh->off += len;
			break;
		case IP6OPT_HOME_ADDRESS:
			/* HA alignment requirement (8n + 6) */
			rest = dh->off % 8;
			if (rest <= 4) {
				/* Add a PADN option with length X */
				len = 6 - rest - 2;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += len + 2;
			} else if (rest == 5) {
				/* Add a PAD1 option */
				bzero((caddr_t)dh->buf + dh->off, 1);
				dh->off += 1;
			} else if (rest == 7) {
				/* Add a PADN option with length 5 */
				len = 5;
				bzero((caddr_t)dh->buf + dh->off, len + 2);
				bcopy(&padn, (caddr_t)dh->buf + dh->off, 1);
				bcopy(&len, (caddr_t)dh->buf + dh->off + 1, 1);
				dh->off += len + 2;
			}

			/* Copy option to DH */
			len = IP6OPT_HALEN + IP6OPT_MINLEN;
			off = dh->off;
			ha = (struct ip6_opt_home_address *)opt;
			
			bzero((caddr_t)dh->buf + off, len);
			bcopy((caddr_t)ha, (caddr_t)dh->buf + off, len);
			
			pos = dh->buf + off;
			dh->off += len;
			break;
	}
	return pos;
}



/*
 ******************************************************************************
 * Function:    mip6_add_subopt2dh
 * Description: Add the internal list of sub-options to an MIPv6 option. The
 *              MIPv6 option has been copied to the destination header buffer.
 *              For each sub-option added, alignment must be done.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_add_subopt2dh(subopt, dh, optpos)
struct mip6_buffer  *subopt;  /* Buffer including all sub-options */
struct mip6_buffer  *dh;      /* Destination header buffer */
u_int8_t            *optpos;  /* Position for MIPv6 option */
{
	struct ip6_opt   *opt_hdr;
	u_int8_t          padn, len, ii, off, added_bytes;
	int               rest;

	/* Verify input */
	if (subopt == NULL || dh == NULL || optpos == NULL) return;
	if (dh->off < 4) return;
	
	/* Add sub-option to Destination header */
	padn = IP6OPT_PADN;
	added_bytes = 0;
	for (ii = 0; ii < subopt->off; ii += len) {
		switch (*(subopt->buf + ii)) {
			case IP6SUBOPT_UNIQUEID:
				/* Unique Identifier (2n) */
				rest = dh->off % 2;
				if (rest == 1) {
					/* Add a PAD1 option */
					bzero((caddr_t)dh->buf + dh->off, 1);
					dh->off += 1;
					added_bytes += 1;
				}

				/* Append sub-option to buffer */
				len = IP6OPT_UIDLEN + IP6OPT_MINLEN;
				off = dh->off;
				bzero((caddr_t)dh->buf + off, len);
				bcopy((caddr_t)subopt->buf + ii,
				      (caddr_t)dh->buf + off, len);
				dh->off += len;
				added_bytes += len;
				break;
			case IP6SUBOPT_ALTCOA:
				/* Alternate Care-of Address (8n + 6) */
				rest = dh->off % 8;
				if (rest <= 4) {
				/* Add a PADN option with length 0 */
					len = 6 - rest - 2;
					off = dh->off;
					bzero((caddr_t)dh->buf+off, len+2);
					bcopy(&padn, (caddr_t)dh->buf+off, 1);
					bcopy(&len, (caddr_t)dh->buf+off+1, 1);
					dh->off += len + 2;
					added_bytes += len + 2;
				} else if (rest == 5) {
					/* Add a PAD1 option */
					bzero((caddr_t)dh->buf + dh->off, 1);
					dh->off += 1;
					added_bytes += 1;
				} else if (rest == 7) {
					/* Add a PADN option with length 5 */
					len = 5;
					off = dh->off;
					bzero((caddr_t)dh->buf+off, len+2);
					bcopy(&padn, (caddr_t)dh->buf+off, 1);
					bcopy(&len, (caddr_t)dh->buf+off+1, 1);
					dh->off += len + 2;
					added_bytes += len + 2;
				}

				/* Append sub-option to buffer */
				len = IP6OPT_COALEN + IP6OPT_MINLEN;
				off = dh->off;
				bzero((caddr_t)dh->buf + off, len);
				bcopy((caddr_t)subopt->buf + ii,
				      (caddr_t)dh->buf + off, len);
				dh->off += len;
				added_bytes += len;
				break;
		}
	}

	/* Adjust the option length to include the sub-option(s) */
	opt_hdr = (struct ip6_opt *)optpos;
	opt_hdr->ip6o_len += added_bytes;
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_align
 * Description: Align a destination header to a multiple of 8 octets.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_align(buf)
struct mip6_buffer *buf;     /* IPv6 destination header to align */
{
	struct ip6_ext  *ext_hdr;
	int              rest;     /* Rest of modulo division */
	u_int8_t         padlen;   /* Number of bytes to pad */
	u_int8_t         padn;     /* Number for option type PADN */

	padn = IP6OPT_PADN;
	rest = buf->off % 8;

	if (rest == 7) {
		/* Add a PAD1 option */
		bzero((caddr_t)buf->buf + buf->off, 1);
		buf->off += 1;
	} else if (rest > 0 && rest < 7) {
		/* Add a PADN option */
		padlen = 8 - rest;
		bzero((caddr_t)buf->buf + buf->off, padlen);
		bcopy(&padn, (caddr_t)buf->buf + buf->off, 1);
		padlen = padlen - 2;
		bcopy(&padlen, (caddr_t)buf->buf + buf->off + 1, 1);
		buf->off += padlen + 2;
	}

	/* Adjust the extension header length */
	ext_hdr = (struct ip6_ext *)buf->buf;
	ext_hdr->ip6e_len = (buf->off >> 3) - 1;
	return;
}



/*
 ##############################################################################
 #
 # IP6 OUTPUT FUNCTIONS
 # Functions used for processing of the outgoing IPv6 packet. These functions
 # are called by using the mip6_output() function, when necesary, from the
 # ip6_output() function.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_output
 * Description: This function is always called by function ip6_output(). A Home
 *              Address option MUST be added if the MN is roaming and a Routing
 *              Header type 0 MUST be added if the node has a Binding Cache
 *              entry for the destination node. Otherwise nothing is done.
 * Ret value:    0  Everything is OK.
 *                  Otherwise appropriate error code
 ******************************************************************************
 */
int
mip6_output(m, pktopts)
struct mbuf          *m;        /* Includes IPv6 header */
struct ip6_pktopts  **pktopts;  /* Packet Extension headers */
{
	struct mip6_esm     *esp;       /* Ptr to entry in event state list */
	struct ip6_hdr      *ip6;       /* IPv6 header */
	struct mip6_bc      *bcp;       /* Binding Cache list entry */
	struct in6_addr     *peer_home; /* Original dst address for packet */
	int                  error;

	ip6 = mtod(m, struct ip6_hdr *);
	peer_home = &ip6->ip6_dst;

	/* We have to maintain a list of all prefixes announced by the
	   rtadvd deamon (for on-link determination). */
	if (MIP6_IS_HA_ACTIVE) {
		if (ip6->ip6_nxt == IPPROTO_ICMPV6)
			mip6_icmp6_output(m);
	}

	/* If packet is being sent to a link-local or loop-back addresses,
	   don't do anything. */
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst))
		return 0;

	/* If a COA for the destination address exist, i.e a BC entry
	   is found, then add a Routing Header. */
	bcp = mip6_bc_find(&ip6->ip6_src, &ip6->ip6_dst);
	if (bcp != NULL) {
		if ((error = mip6_add_rh(pktopts, bcp)) != 0)
			return error;
	}

	/* If the MN is roaiming and the source address is one of the
	   home addresses for the MN then a Home Address option must
	   be inserted. */
	if (!MIP6_IS_MN_ACTIVE) return 0;

	esp = mip6_esm_find(&ip6->ip6_src, 0);	
	if ((esp == NULL) || (esp->state < MIP6_STATE_DEREG))
		return 0;

	if ((error = mip6_add_ha(m, pktopts, esp)) != 0)
		return error;

	/* If the MN initiate the traffic it should add a BU option
	   to the packet if no BUL entry exist and there is a BUL
	   "home registration" entry. */
	if ((error = mip6_add_bu(pktopts, esp, peer_home)) != 0)
		return error;

	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_add_rh
 * Description: Add a Routing Header type 0 to the outgoing packet, if its not
 *              already present, and add the COA for the MN.
 *              If a Routing Header type 0 exist, but contains no data, or the
 *              COA for the MN is missing it is added to the Routing Header.
 *              If the Routing Header is not of type 0 the function returns.
 * Note:        The destination address for the outgoing packet is not changed
 *              since this is taken care of in the ip6_output function.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_add_rh(pktopts, bcp)
struct ip6_pktopts  **pktopts;  /* Packet Ext headers, options and data */
struct mip6_bc       *bcp;      /* Binding Cache list entry */
{
	struct ip6_pktopts *opts;       /* Pkt Ext headers, options & data */
	struct ip6_rthdr0  *rthdr0;     /* Routing header type 0 */
	struct in6_addr    *ip6rt_addr; /* IPv6 routing address(es) */
	caddr_t             ptr;        /* Temporary pointer */
	int                 size, len, new_len, idx;

	/* A Multicast address must not appear in a Routing Header. */
	if (IN6_IS_ADDR_MULTICAST(&bcp->peer_coa)) return 0;

	opts = *pktopts;
	if (opts == NULL) {
		/* No Packet options present at all. */
		opts = (struct ip6_pktopts *)malloc(sizeof(struct ip6_pktopts),
						    M_TEMP, M_NOWAIT);
		if (opts == NULL) return -1;
		init_ip6pktopts(opts);
		opts->ip6po_flags |= IP6PO_MIP6OPT;

		opts->ip6po_rthdr = mip6_create_rh(&bcp->peer_coa,
						   IPPROTO_DSTOPTS);
		if(opts->ip6po_rthdr == NULL) {
			free(opts, M_TEMP);
			return -1;
		}
		opts->ip6po_flags |= IP6PO_NEWRH0;
		opts->ip6po_orgrh0 = NULL;
	} else if (opts->ip6po_rthdr == NULL) {
		/* Packet extension header allocated but no RH present */
		opts->ip6po_rthdr = mip6_create_rh(&bcp->peer_coa,
						   IPPROTO_DSTOPTS);
		if(opts->ip6po_rthdr == NULL) return -1;
		opts->ip6po_flags |= IP6PO_NEWRH0;
		opts->ip6po_orgrh0 = NULL;
	} else {
		/* A RH exist. Don't do anything if the type is not 0. */
		if (opts->ip6po_rthdr->ip6r_type != IPV6_RTHDR_TYPE_0)
			return 0;

		if (opts->ip6po_rthdr->ip6r_len % 2)
			return 0;

		/* A routing header exist. If the last segment is not
		   equal to the MN's COA, add it. */
		len = opts->ip6po_rthdr->ip6r_len;
		if (len == 0)
			new_len = 2;
		else {
			new_len = len + 2;
			idx = (len / 2) - 1;
			rthdr0 = (struct ip6_rthdr0 *)opts->ip6po_rthdr;
			ptr = (caddr_t)rthdr0 + sizeof(struct ip6_rthdr0);
			ip6rt_addr = (struct in6_addr *)ptr + idx;
			if (IN6_ARE_ADDR_EQUAL(&bcp->peer_coa, ip6rt_addr))
				return 0;
		}

		/* Save pointer to original header */
		opts->ip6po_orgrh0 = opts->ip6po_rthdr;

		/* Allocate new RH and add one extra address */
		size = sizeof(struct ip6_rthdr0);
		size += (new_len / 2) * sizeof(struct in6_addr);
		rthdr0 = (struct ip6_rthdr0 *)malloc(size, M_TEMP, M_NOWAIT);
		if (rthdr0 == NULL) return -1;

		bcopy((caddr_t)opts->ip6po_rthdr, (caddr_t)rthdr0, (len+1)*8);
		bcopy((caddr_t)&bcp->peer_coa, (caddr_t)rthdr0 + (len+1)*8,
		      sizeof(struct in6_addr));
		rthdr0->ip6r0_len = new_len;
		rthdr0->ip6r0_segleft = new_len / 2;

		opts->ip6po_rthdr = (struct ip6_rthdr *)rthdr0;
		opts->ip6po_flags |= IP6PO_NEWRH0;
	}

	*pktopts = opts;
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_add_ha
 * Description: Add Home Address option to the Destination Header.
 * Note:        According to 10.2, IPsec processing of outbound packets, the
 *              IPv6 source address in the IPv6 header must contain the MNs
 *              home address and the Home Address option must include the
 *              care-of address.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_add_ha(m, pktopts, esp)
struct mbuf          *m;        /* Includes IPv6 header */
struct ip6_pktopts  **pktopts;  /* Packet Ext headers, options and data */
struct mip6_esm      *esp;      /* Event-state machine */
{
	struct ip6_opt_home_address  *ha_opt;
	struct mip6_buffer           *dh1;
	struct ip6_pktopts           *opts;
	int                           size;

	size = sizeof(struct mip6_buffer);
	dh1 = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
	if (dh1 == NULL) return -1;
	bzero((caddr_t)dh1, size);

	size = sizeof(struct ip6_opt_home_address);
	ha_opt = (struct ip6_opt_home_address *)malloc(size, M_TEMP, M_NOWAIT);
	if (ha_opt == NULL) {
		free(dh1, M_TEMP);
		return -1;
	}
	ha_opt->ip6oh_type = IP6OPT_HOME_ADDRESS;
	ha_opt->ip6oh_len = IP6OPT_HALEN;

	size = sizeof(struct in6_addr);
	bcopy((u_int8_t *)&esp->coa, ha_opt->ip6oh_addr, size);

	opts = *pktopts;
	if (opts == NULL) {
		/* No Packet options present at all. */
		opts = (struct ip6_pktopts *)malloc(sizeof(struct ip6_pktopts),
						    M_TEMP, M_NOWAIT);
		if (opts == NULL) {
			free(dh1, M_TEMP);
			free(ha_opt, M_TEMP);
			return -1;
		}
		init_ip6pktopts(opts);
		opts->ip6po_flags |= IP6PO_MIP6OPT;
		opts->ip6po_orgdh1 = NULL;
	} else if (opts->ip6po_dest1 == NULL) {
		/* Packet extension header allocated but no DH present */
		opts->ip6po_orgdh1 = NULL;
	} else {
		/* Destination Header exist */
		opts->ip6po_orgdh1 = opts->ip6po_dest1;
		size = (opts->ip6po_dest1->ip6d_len + 1) << 3;
		bcopy((caddr_t)opts->ip6po_dest1, (caddr_t)dh1->buf, size);
		
		dh1->off = size;
		mip6_find_offset(dh1);
	}

	/* Add Home Address option to DH1 */
	mip6_add_opt2dh((u_int8_t *)ha_opt, dh1);
	mip6_align(dh1);

	opts->ip6po_dest1 = (struct ip6_dest *)dh1->buf;
	opts->ip6po_flags |= IP6PO_NEWDH1;

	free(ha_opt, M_TEMP);
	*pktopts = opts;
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_addr_exchange
 * Description: Exchange IPv6 header source address with contents in Home
 *              Address option address field.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_addr_exchange(m, dstm)
struct mbuf   *m;       /* Includes IPv6 header */
struct mbuf   *dstm;    /* Includes Destination Header 1 */
{
	struct ip6_opt_home_address  *ha_opt;
	struct ip6_dest              *dh;
	struct ip6_hdr               *ip6;
	struct in6_addr               ip6_src;
	u_int8_t                     *opt;
	int                           ii, len;

	/* Sanity check */
	if (!MIP6_IS_MN_ACTIVE)
		return;

	if (dstm == NULL)
		return;
	
	/* Find Home Address option */
	dh = mtod(dstm, struct ip6_dest *);
	len = (dh->ip6d_len + 1) << 3;
	if (len > dstm->m_len)
		return;	

	ha_opt = NULL;
	ii = 2;
	
	opt = (u_int8_t *)dh + ii;
	while (ii < len) {
		switch (*opt) {
			case IP6OPT_PAD1:
				ii += 1;
				opt += 1;
				break;
			case IP6OPT_HOME_ADDRESS:
				ha_opt = (struct ip6_opt_home_address *)opt;
				break;
			default:
				ii += *(opt + 1) + 2;
				opt += *(opt + 1) + 2;
				break;
		}
		if (ha_opt) break;
	}

	if (ha_opt == NULL) return;

	/* Change the IP6 source address to the care-of address */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6_src = ip6->ip6_src;

	ip6->ip6_src = *(struct in6_addr *)ha_opt->ip6oh_addr;
	bcopy((caddr_t)&ip6_src, ha_opt->ip6oh_addr, sizeof(struct in6_addr));
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_add_bu
 * Description: Add Binding Update option to outgoing packet if we are
 *              initiating the traffic and there exist no Binding Update
 *              list entry already.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_add_bu(pktopts, esp, peer_home)
struct ip6_pktopts  **pktopts;    /* Packet Ext headers, options and data */
struct mip6_esm      *esp;        /* Event-state machine */
struct in6_addr      *peer_home;  /* Original packet destination */
{

	struct ip6_opt_binding_update  *bu_opt;
	struct ip6_pktopts             *opts;
	struct mip6_bul                *bulp_cn, *bulp_ha;
	struct mip6_buffer             *dh2;
	u_int16_t                       seqno;
	u_int8_t                        bu_flags;
	int                             size;

	bulp_cn = mip6_bul_find(peer_home, &esp->home_addr);
	bulp_ha = mip6_bul_find(NULL, &esp->home_addr);
	if ((bulp_cn == NULL) && (bulp_ha != NULL)) {
		/* Create BU option and BUL entry. */
		bu_flags = 0;
		bu_opt = mip6_create_bu(0, bu_flags, bulp_ha->lifetime);
		if (bu_opt == NULL) return -1;
		
		bulp_cn = mip6_bul_create(peer_home, &esp->home_addr,
					  &esp->coa, bulp_ha->lifetime,
					  bu_flags);
		if (bulp_cn == NULL) return -1;

		seqno = 1;
		bcopy((caddr_t)&seqno, bu_opt->ip6ou_seqno, sizeof(seqno));
		bulp_cn->seqno = seqno;
	} else
		return 0;

	/* Allocate new memory for DH2. Copy existing data */
	size = sizeof(struct mip6_buffer);
	dh2 = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
	if (dh2 == NULL) {
		free(bu_opt, M_TEMP);
		mip6_bul_delete(bulp_cn);
		return -1;
	}
	bzero((caddr_t)dh2, sizeof(struct mip6_buffer));
	dh2->off = 2;

	opts = *pktopts;
	if (opts == NULL) {
		/* No Packet options present at all. */
		opts = (struct ip6_pktopts *)malloc(sizeof(struct ip6_pktopts),
						    M_TEMP, M_NOWAIT);
		if (opts == NULL) {
			free(bu_opt, M_TEMP);
			mip6_bul_delete(bulp_cn);
			free(dh2, M_TEMP);
			return -1;
		}
		init_ip6pktopts(opts);
		opts->ip6po_flags |= IP6PO_MIP6OPT;
		opts->ip6po_orgdh2 = NULL;
	} else if (opts->ip6po_dest2 == NULL) {
		/* Packet extension header allocated but no DH present */
		opts->ip6po_orgdh2 = NULL;
	} else {
		/* Destination Header exist */
		opts->ip6po_orgdh2 = opts->ip6po_dest2;
		size = (opts->ip6po_dest2->ip6d_len + 1) << 3;
		bcopy((caddr_t)opts->ip6po_dest2, (caddr_t)dh2->buf, size);

		dh2->off = size;
		mip6_find_offset(dh2);
	}

	/* Add Binding Update option to DH2 */
	mip6_add_opt2dh((u_int8_t *)bu_opt, dh2);
	mip6_align(dh2);
	
	opts->ip6po_dest2 = (struct ip6_dest *)dh2->buf;
	opts->ip6po_flags |= IP6PO_NEWDH2;
	free(bu_opt, M_TEMP);
	*pktopts = opts;
	return 0;
}



/*
 ##############################################################################
 #
 # MIP6 TUNNELLING FUNCTIONS
 # Functions used for tunnelling of packets. The mip6_tunnel_output() function
 # encapsulate an IPv6 header in a new IPv6 header and the mip6_tunnel_input()
 # function decapsulate the packet.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_tunnel_input
 * Description: similar to gif_input() and in6_gif_input().
 * Ret value:	standard error codes.
 ******************************************************************************
 */
int
mip6_tunnel_input(mp, offp, proto)
struct mbuf **mp;
int          *offp, proto;
{
	struct mbuf    *m = *mp;
	struct ip6_hdr *ip6;
	int             s, af = 0;
	u_int32_t       otos;

	ip6 = mtod(m, struct ip6_hdr *);
	otos = ip6->ip6_flow;
	m_adj(m, *offp);

	switch (proto) {
	case IPPROTO_IPV6:
	{
		struct ip6_hdr *ip6;
		af = AF_INET6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return IPPROTO_DONE;
		}
		m->m_flags |= M_MIP6TUNNEL;	/* Tell MN that this packet
						   was tunnelled. */
		ip6 = mtod(m, struct ip6_hdr *);

		s = splimp();
		if (IF_QFULL(&ip6intrq)) {
			IF_DROP(&ip6intrq);	/* update statistics */
			m_freem(m);
			splx(s);
			return IPPROTO_DONE;
		}
		IF_ENQUEUE(&ip6intrq, m);
#if 0
		/* we don't need it as we tunnel IPv6 in IPv6 only. */
		schednetisr(NETISR_IPV6);
#endif
		splx(s);
		break;
	}
	default:
#ifdef MIP6_DEBUG
		mip6_debug("%s: protocol %d not supported.\n", __FUNCTION__,
			   proto);
#endif
		m_freem(m);
		return IPPROTO_DONE;
	}

	return IPPROTO_DONE;
}



/*
 ******************************************************************************
 * Function:    mip6_tunnel_output
 * Description: Encapsulates packet in an outer header which is determined
 *		of the Binding Cache entry provided. Note that packet is
 *		(currently) not sent here, but should be sent by the caller.
 * Ret value:   != 0 if failure. It's up to the caller to free the mbuf chain.
 ******************************************************************************
 */
int
mip6_tunnel_output(mp, bc)
struct mbuf     **mp;
struct mip6_bc   *bc;
{
	struct sockaddr_in6 dst;
	const struct encaptab *ep = bc->ep;
	struct mbuf *m = *mp;
	struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)&ep->src;
	struct sockaddr_in6 *sin6_dst = (struct sockaddr_in6 *)&ep->dst;
	struct ip6_hdr *ip6;
	u_int8_t itos;
	int len;

	bzero(&dst, sizeof(dst));
	dst.sin6_len = sizeof(struct sockaddr_in6);
	dst.sin6_family = AF_INET6;
	dst.sin6_addr = bc->peer_coa;

	if (ep->af != AF_INET6 || ep->dst.ss_len != dst.sin6_len ||
	    bcmp(&ep->dst, &dst, dst.sin6_len) != 0 )
		return EFAULT;

	/* Recursion problems? */

	if (IN6_IS_ADDR_UNSPECIFIED(&sin6_src->sin6_addr)) {
		return EFAULT;
	}

	len = m->m_pkthdr.len;

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return ENOBUFS;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;


	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
#ifdef MIP6_DEBUG
		printf("ENOBUFS in mip6_tunnel_output %d\n", __LINE__);
#endif
		return ENOBUFS;
	}

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
	ip6->ip6_plen	= htons((u_short)len);
	ip6->ip6_nxt	= IPPROTO_IPV6;
	ip6->ip6_hlim	= ip6_gif_hlim;   /* Same? */
	ip6->ip6_src	= sin6_src->sin6_addr;

	/* bidirectional configured tunnel mode */
	if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
		ip6->ip6_dst = sin6_dst->sin6_addr;
	else {
		m_freem(m);
		return ENETUNREACH;
	}
#ifdef IPV6_MINMTU
	/*
	 * force fragmentation to minimum MTU, to avoid path MTU discovery.
	 * it is too painful to ask for resend of inner packet, to achieve
	 * path MTU discovery for encapsulated packets.
	 */
	return(ip6_output(m, 0, 0, IPV6_MINMTU, 0, NULL));
#else
	return(ip6_output(m, 0, 0, 0, 0, NULL));
#endif
}

#ifdef OLDMIP6
int
mip6_tunnel_output(mp, bc)
struct mbuf     **mp;
struct mip6_bc   *bc;
{
	struct sockaddr_in6 dst;
	const struct encaptab *ep = bc->ep;
	struct mbuf *m = *mp;
	struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)&ep->src;
	struct sockaddr_in6 *sin6_dst = (struct sockaddr_in6 *)&ep->dst;
	struct ip6_hdr *ip6;
	u_int8_t itos;
	int len;

	bzero(&dst, sizeof(dst));
	dst.sin6_len = sizeof(struct sockaddr_in6);
	dst.sin6_family = AF_INET6;
	dst.sin6_addr = bc->peer_coa;

	if (ep->af != AF_INET6 || ep->dst.ss_len != dst.sin6_len ||
	    bcmp(&ep->dst, &dst, dst.sin6_len) != 0 )
		return EFAULT;

	/* Recursion problems? */

	if (IN6_IS_ADDR_UNSPECIFIED(&sin6_src->sin6_addr)) {
		return EFAULT;
	}

	len = m->m_pkthdr.len;

	if (m->m_len < sizeof(*ip6)) {
		m = m_pullup(m, sizeof(*ip6));
		if (!m)
			return ENOBUFS;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;


	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
#ifdef MIP6_DEBUG
		printf("ENOBUFS in mip6_tunnel_output %d\n", __LINE__);
#endif
		return ENOBUFS;
	}

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
	ip6->ip6_plen	= htons((u_short)len);
	ip6->ip6_nxt	= IPPROTO_IPV6;
	ip6->ip6_hlim	= ip6_gif_hlim;   /* Same? */
	ip6->ip6_src	= sin6_src->sin6_addr;

	/* bidirectional configured tunnel mode */
	if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
		ip6->ip6_dst = sin6_dst->sin6_addr;
	else
		return ENETUNREACH;

	*mp = m;
	return 0;
}
#endif /* OLDMIP6 */
