/*
 * $KAME: mld6v2.c,v 1.2 2001/07/11 14:41:30 itojun Exp $
 */

/*
 * Copyright (C) 1999 LSIIT Laboratory.
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
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip_mroute.h>
#include <netinet6/ip6_mroute.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include "defs.h"
#include "vif.h"
#include "debug.h"
#include "inet6.h"
#include "mld6.h"
#include "mld6v2.h"

#ifndef USE_RFC2292BIS
extern u_int8_t raopt[IP6OPT_RTALERT_LEN];
#endif

/* uses buffer in mld6.c */
extern char    *sndcmsgbuf;
extern int      ctlbuflen;
extern struct iovec sndiov[2];
extern struct msghdr sndmh;


/*
 * initialisation, and reading are done in mld6.c (it's just another icmp6 filtering) 
 */
/*
 * only used for mldv2 query messages 
 */

void
make_mld6v2_msg(int type, int code, struct sockaddr_in6 *src,
		struct sockaddr_in6 *dst, struct in6_addr *group, int ifindex,
		unsigned int delay, int datalen, int alert, int sflag,
		int qrv, int qqic, struct listaddr *sources)
{
    static struct sockaddr_in6 dst_sa = { sizeof(dst_sa), AF_INET6 };
    struct mld6v2_hdr *mhp = (struct mld6v2_hdr *) mld6_send_buf;
    int             ctllen, hbhlen = 0;
    int             nbsrc = 0;
    struct listaddr *lstsrc;
    u_int8_t        misc = 0;	/*Resv+S flag + QRV */
    int             i;
    unsigned int    realnbr;

    if (IN6_IS_ADDR_UNSPECIFIED(group))
	dst_sa.sin6_addr = allnodes_group.sin6_addr;
    else
	dst_sa.sin6_addr = *group;
    sndmh.msg_name = (caddr_t) & dst_sa;

    /*
     * fill the misc field 
     */
    misc |= sflag;
    if (qrv <= 7)
	misc |= qrv;

    /*
     * compute number of src 
     */
    lstsrc = sources;
    while (lstsrc)
    {
	nbsrc++;
	lstsrc = lstsrc->al_next;
    }

    /*
     * XXX : hard-coding , 28 is the minimal size of the mldv2 query header
     */

    datalen = 28 + nbsrc * sizeof(struct in6_addr);
    bzero(mhp, datalen);
    mhp->mld6v2_type = type;
    mhp->mld6v2_code = code;
    mhp->mld6v2_maxrc = htons(codafloat(delay, &realnbr, 3, 12));
    mhp->mld6v2_addr = *group;
    mhp->mld6v2_misc = misc;
    mhp->mld6v2_qqi = codafloat(qqic, &realnbr, 3, 4);
    mhp->mld6v2_numsrc = htons(nbsrc);

    lstsrc = sources;
    for (i = 0; i < nbsrc; i++)
    {
	mhp->mld6v2_sources[i] = lstsrc->al_addr.sin6_addr;
	lstsrc = lstsrc->al_next;
    }

    sndiov[0].iov_len = datalen;

    /*
     * estimate total ancillary data length 
     */
    ctllen = 0;
    if (ifindex != -1 || src)
	ctllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
    if (alert)
    {
#ifdef USE_RFC2292BIS
	if ((hbhlen = inet6_opt_init(NULL, 0)) == -1)
	    log(LOG_ERR, 0, "inet6_opt_init(0) failed");
	if ((hbhlen =
	     inet6_opt_append(NULL, 0, hbhlen, IP6OPT_ROUTER_ALERT, 2, 2,
			      NULL)) == -1)
	    log(LOG_ERR, 0, "inet6_opt_append(0) failed");
	if ((hbhlen = inet6_opt_finish(NULL, 0, hbhlen)) == -1)
	    log(LOG_ERR, 0, "inet6_opt_finish(0) failed");
	ctllen += CMSG_SPACE(hbhlen);
#else				/* old advanced API */
	hbhlen = inet6_option_space(sizeof(raopt));
	ctllen += hbhlen;
#endif
    }
    /*
     * extend ancillary data space (if necessary) 
     */
    if (ctlbuflen < ctllen)
    {
	if (sndcmsgbuf)
	    free(sndcmsgbuf);
	if ((sndcmsgbuf = malloc(ctllen)) == NULL)
	    log(LOG_ERR, 0, "make_mld6_msg: malloc failed");	/* assert */
	ctlbuflen = ctllen;
    }
    /*
     * store ancillary data 
     */
    if ((sndmh.msg_controllen = ctllen) > 0)
    {
	struct cmsghdr *cmsgp;

	sndmh.msg_control = sndcmsgbuf;
	cmsgp = CMSG_FIRSTHDR(&sndmh);

	if (ifindex != -1 || src)
	{
	    struct in6_pktinfo *pktinfo;

	    cmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	    cmsgp->cmsg_level = IPPROTO_IPV6;
	    cmsgp->cmsg_type = IPV6_PKTINFO;
	    pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsgp);
	    memset((caddr_t) pktinfo, 0, sizeof(*pktinfo));
	    if (ifindex != -1)
		pktinfo->ipi6_ifindex = ifindex;
	    if (src)
		pktinfo->ipi6_addr = src->sin6_addr;
	    cmsgp = CMSG_NXTHDR(&sndmh, cmsgp);
	}
	if (alert)
	{
#ifdef USE_RFC2292BIS
	    int             currentlen;
	    void           *hbhbuf, *optp = NULL;
	    u_int16_t rtalert_code;

	    rtalert_code = htons(IP6OPT_RTALERT_MLD);

	    cmsgp->cmsg_len = CMSG_LEN(hbhlen);
	    cmsgp->cmsg_level = IPPROTO_IPV6;
	    cmsgp->cmsg_type = IPV6_HOPOPTS;
	    hbhbuf = CMSG_DATA(cmsgp);

	    if ((currentlen = inet6_opt_init(hbhbuf, hbhlen)) == -1)
		log(LOG_ERR, 0, "inet6_opt_init(len = %d) failed", hbhlen);
	    if ((currentlen = inet6_opt_append(hbhbuf, hbhlen,
					       currentlen,
					       IP6OPT_ROUTER_ALERT, 2,
					       2, &optp)) == -1)
		log(LOG_ERR, 0,
		    "inet6_opt_append(len = %d) failed", currentlen, hbhlen);
	    (void) inet6_opt_set_val(optp, 0, &rtalert_code,
				     sizeof(rtalert_code));
	    if (inet6_opt_finish(hbhbuf, hbhlen, currentlen) == -1)
		log(LOG_ERR, 0, "inet6_opt_finish(buf) failed");
#else				/* old advanced API */
	    if (inet6_option_init((void *) cmsgp, &cmsgp, IPV6_HOPOPTS))
		log(LOG_ERR, 0,	/* assert */
		    "make_mld6_msg: inet6_option_init failed");
	    if (inet6_option_append(cmsgp, raopt, 4, 0))
		log(LOG_ERR, 0,	/* assert */
		    "make_mld6_msg: inet6_option_append failed");
#endif
	    cmsgp = CMSG_NXTHDR(&sndmh, cmsgp);
	}
    }
    else
	sndmh.msg_control = NULL;	/* clear for safety */
}

void
send_mld6v2(int type, int code, struct sockaddr_in6 *src,
	    struct sockaddr_in6 *dst, struct in6_addr *group, int index,
	    unsigned int delay, int datalen, int alert, int sflag, int qrv,
	    int qqic, struct listaddr *sources)
{
    struct sockaddr_in6 *dstp;

    make_mld6v2_msg(type, code, src, dst, group, index, delay, datalen, alert,
		    sflag, qrv, qqic, sources);

    dstp = (struct sockaddr_in6 *) sndmh.msg_name;

    if (sendmsg(mld6_socket, &sndmh, 0) < 0)
    {
	if (errno == ENETDOWN)
	    check_vif_state();
	else
	    log(log_level(IPPROTO_ICMPV6, type, 0), errno,
		"sendmsg to %s with src %s on %s",
		inet6_fmt(&dstp->sin6_addr),
		src ? inet6_fmt(&src->sin6_addr) : "(unspec)",
		ifindex2str(index));

	return;
    }
    IF_DEBUG(DEBUG_PKT | debug_kind(IPPROTO_IGMP, type, 0))
	log(LOG_DEBUG, 0, "SENT %s from %-15s to %s",
	    packet_kind(IPPROTO_ICMPV6, type, 0),
	    src ? inet6_fmt(&src->sin6_addr) : "unspec",
	    inet6_fmt(&dstp->sin6_addr));
}


/*
 * given a number,an exp. size in bits and a mantisse size in bits, return 
 * the coded number value according to the code described in draft_vida_mldv2_00.txt 
 * used to compute the Maximum Response Code (sizeexp=3 bits,sizemant=12 bits ) and the 
 * Querier Query interval Code  (sizeexp=3 bits ,sizmant=4 bits ) 
 * format  : |1|...exp...|...mant...|                   
 * if the number isn't representable there is a difference between realnbr and nbr 
 * if the number is too big return the max code value with a warning 
 */

unsigned int
codafloat(unsigned int nbr, unsigned int *realnbr, unsigned int sizeexp,
	  unsigned int sizemant)
{
    unsigned int    mask = 0x1;
    unsigned int    max = 0x0;
    unsigned int    exp = 1;	/*exp value */
    unsigned int    tmax;	/*max code value */
    unsigned int    mantmask = 1;	/*mantisse mask */
    unsigned int    onebit = 1;
    unsigned int    mant;
    u_int16_t       code = 1;	/* code */
    int             i;


    /*
     * compute maximal exp value 
     */
    for (i = 1; i < sizeexp; i++)
	exp = (exp << 1) | 1;

    /*
     * maximum size of this number in bits (after decoding)
     */

    tmax = exp + 3 + sizemant + 1;

    /*
     * minimum value of this number 
     */

    code <<= sizeexp + sizemant;

    mask <<= tmax - 1;

    /*
     * maximum value of this number 
     * + a mantisse masque 
     */

    for (i = 0; i <= sizemant; i++)
	max = max | mask >> i;

    for (i = 0; i < sizemant; i++)
	mantmask = mantmask | (onebit << i);

    if (nbr >= code)
    {
	if (nbr <= max)
	{
	    while (!(nbr & mask))
	    {
		mask >>= 1;
		tmax--;
	    }
	    exp = tmax - (sizemant + 1);
	    mant = nbr >> exp;
	    exp -= 3;

	    /*
	     * build code 
	     */

	    mant &= mantmask;
	    code |= mant;
	    code |= exp << sizemant;

	    /*
	     * compute effective value ( draft-vida-mldv2 p.11 ) 
	     */

	    onebit <<= sizemant;
	    *realnbr = (mant | onebit) << (exp + 3);
	}
	else
	{
	    *realnbr = max;
	    return codafloat(max, realnbr, sizeexp, sizemant);
	}
    }
    else
	code = *realnbr = nbr;

    return code;
}

unsigned int
decodeafloat(unsigned int nbr,unsigned int sizeexp,unsigned int sizemant)
{
	unsigned int onebit=1;
	unsigned int mantmask=0;
	unsigned int mant=0;
	unsigned int exp=0;
	int i;
	
    	for (i = 0; i < sizemant; i++)
		mantmask = mantmask | (onebit << i);
	mant=nbr&mantmask;
	exp=(nbr&~(onebit<<(sizemant+sizeexp)))>>sizemant;
	onebit <<= sizemant;
	return (mant|onebit)<<(exp+3);
}
