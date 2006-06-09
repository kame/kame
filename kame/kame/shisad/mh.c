/*      $KAME: mh.c,v 1.55 2006/06/09 11:29:58 t-momose Exp $  */
/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <ifaddrs.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>

#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/mipsock.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#ifdef DSMIP
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#endif /* DSMIP */
#include <netinet/ip6mh.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>

#include <openssl/rand.h>

#include "callout.h"
#include "shisad.h"
#include "fsm.h"
#include "stat.h"

#define SS2SIN6(ss) ((struct sockaddr_in6 *)(ss))
#define SS2SIN(ss) ((struct sockaddr_in *)(ss))

#ifdef MIP_CN
extern int homeagent_mode;
#endif /* MIP_CN */
#ifdef MIP_MN
#ifdef MIP_NEMO
extern int ipv4mnpsupport;
#endif /* MIP_NEMO */
#endif /* MIP_MN */
#ifdef MIP_HA
extern int keymanagement;
#endif

static int sendmessage(char *, int, u_int, struct in6_addr *, struct in6_addr *, 
	struct in6_addr *, struct in6_addr *);

u_int16_t checksum_p(u_int16_t *, u_int16_t *, u_int16_t *, int, int);
 
char *mh_name[] = {
	"Binding Refresh Request Message", 
	"Home Test Init Message",
	"Care-of Test Init Message", 
	"Home Test Message", 
	"Care-of Test Message",
	"Binding Update Message", 
	"Binding Acknowledgement Message", 
	"Binding Error Message",
	"Unknown MH Message"
};

char *mhopt_name[] = {
	"Pad1", 
	"PadN", 
	"Binding Refresh Advice", 
	"Alternate Care-of Address", 
	"Nonce Indices", 
	"Binding Authorization Data",
	"Mobile Network Prefix (NEMO)",
	"Binding Unique Identifier",
	"Mobile Node ID",
	"Authentication",
	"Replay Protection",
	"IPv4 prefix",
	"IPv4 Home Address Option",
	"Unknown option"
};

static struct ip6_opt_home_address *mip6_search_hoa_in_destopt(u_int8_t *);

/* Socket open and close */
void
mhsock_open()
{
        int on = 1;
        int error = 0;
        
        mhsock = socket(AF_INET6, SOCK_RAW, IPPROTO_MH);
        if (mhsock < 0) {
                perror("socket for MH");
                exit(-1);
        }
#ifdef IPV6_RECVPKTINFO	
        error = setsockopt(mhsock,
			   IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
        if (error < 0) {
                perror("setsockopt IPV6_RECVPKTINFO");
/* Is it enough just quit ? should tell to caller the status ? and close the socket ?*/
                exit(1);
        }
#else
        error = setsockopt(mhsock,
			   IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));
        if (error < 0) {
                perror("setsockopt IPV6_PKTINFO");
                exit(1);
        }
#endif /* IPV6_RECVPKTINFO */

#ifdef IPV6_RECVDSTOPTS
        error = setsockopt(mhsock, 
			   IPPROTO_IPV6, IPV6_RECVDSTOPTS, &on, sizeof(on));
        if (error < 0) {
                perror("setsockopt IPV6_RECVDSTOPTS");
                exit(1);
        }
#else
        error = setsockopt(mhsock, 
			   IPPROTO_IPV6, IPV6_DSTOPTS, &on, sizeof(on));
        if (error < 0) {
                perror("setsockopt IPV6_RECVDSTOPTS");
                exit(1);
        }
#endif

#ifdef IPV6_RECVRTHDR
        error = setsockopt(mhsock,
			   IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on));
        if (error < 0) {
                perror("setsockopt IPV6_RECVRTHDR");
                exit(1);
        }
#else
        error = setsockopt(mhsock,
			   IPPROTO_IPV6, IPV6_RTHDR, &on, sizeof(on));
        if (error < 0) {
                perror("setsockopt IPV6_RTHDR");
                exit(1);
        }
#endif /* IPV6_RECVRTHDR */	

	syslog(LOG_INFO, "MH socket is %d.", mhsock);
        return;
}

void
mhsock_close()
{
	close(mhsock);
}

/*
 * below all are verified in the Kernel. No need to re-check them here.
 * - Payload Proto (IPPROTO_NONE) 
 * - MH Length
 * - MH Checksum
 * - IPsec protection
 */
int
mh_input_common(fd)
	int fd;
{
	struct msghdr msg;
	struct iovec iov;
	register struct cmsghdr  *cmsgptr = NULL;

	struct ip6_dest *dest;
	struct ip6_rthdr2 *rthdr2 = NULL; 
	struct ip6_opt_home_address *hoaopt = NULL;
	struct ip6_mh *mh;
	register struct in6_pktinfo *pkt = NULL;

	struct sockaddr_in6 from;
	u_int receivedifindex;
	struct in6_addr dst;
	struct in6_addr hoa;
	struct in6_addr rtaddr;
	char rthdr_on = 0;
	char adata[1024], buf[1024];
	int i, mhlen;

#ifdef MIP_MN
#define mh_input(src, dst, hoa, rtaddr, mh, mhlen)	\
	bul_kick_fsm_by_mh(src, dst, hoa, rtaddr, mh, mhlen)
#endif

syslog(LOG_INFO, "XXXX %s:%d", __FILE__, __LINE__);

	memset(&iov, 0, sizeof(iov));
	memset(buf, 0, sizeof(buf));
	memset(&msg, 0, sizeof(msg));
	memset(&from, 0, sizeof(from));

        msg.msg_name = (caddr_t)&from;
        msg.msg_namelen = sizeof(from);
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (void *) adata;
        msg.msg_controllen = sizeof(adata);

	/* If recvmsg fail return -1 */
	i = recvmsg(fd, &msg, 0);
	if (i < 0) {
		perror("recvmsg");
		return (-1);
	}

	for (cmsgptr = CMSG_FIRSTHDR(&msg); 
	     cmsgptr != NULL;
	     cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {

		/* 
		 * Getting Destination Address and ifindex of the
		 * received interface 
		 */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
		    cmsgptr->cmsg_type == IPV6_PKTINFO) {
			pkt = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
			receivedifindex = pkt->ipi6_ifindex;
			dst = pkt->ipi6_addr;
		}

		/* Getting Home Address Option */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
		    cmsgptr->cmsg_type == IPV6_DSTOPTS) {
			dest = (struct ip6_dest *)(CMSG_DATA(cmsgptr));
			hoaopt = mip6_search_hoa_in_destopt((u_int8_t *)dest);

			if (hoaopt) {
				/* Shisa Statistics: Home Address Option */
				mip6stat.mip6s_hao++;
				memcpy(&hoa, hoaopt->ip6oh_addr, sizeof(hoa));
			} else {
				/* Shisa Statistics: unverified Home Address Option */
				mip6stat.mip6s_unverifiedhao++;
			}
		}

		/* Getting Routing Header Type 2 */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
		    cmsgptr->cmsg_type == IPV6_RTHDR) {

			rthdr2 = (struct ip6_rthdr2 *)(CMSG_DATA(cmsgptr));
			if (rthdr2->ip6r2_type == 2) { 
				/* Shisa Statistics: Routing Header type 2 */
				mip6stat.mip6s_rthdr2++;

				memcpy(&rtaddr, (rthdr2 + 1),sizeof(struct in6_addr));
				rthdr_on = 1;
			}
		}
	}

	/* Switch HoA and CoA */
	if (hoaopt) {
		struct in6_addr hoa2;

		memset((void *)&hoa2, 0, sizeof(struct in6_addr));
		memcpy((void *)&hoa2, (const void *)&hoa,
		    sizeof(struct in6_addr));

		memcpy((void *)&hoa, (const void *)&from.sin6_addr,
		    sizeof(struct in6_addr));
		memcpy((void *)&from.sin6_addr, (const void *)&hoa2,
		    sizeof(struct in6_addr));
	}


	mh = (struct ip6_mh *)buf;
	mhlen = (mh->ip6mh_len + 1) << 3; 

	if (debug) {
		int mhtype;
		
		if ((mhtype = mh->ip6mh_type) > IP6_MH_TYPE_MAX)
			mhtype = IP6_MH_TYPE_MAX + 1; /* '+1' is for 'unknown mh type' message */
		syslog(LOG_INFO, "%s is received", mh_name[mhtype]);
		syslog(LOG_INFO, "  from:[%s] -> dst:[%s]",
		       ip6_sprintf(&from.sin6_addr), ip6_sprintf(&dst));

		if (hoaopt) 
			syslog(LOG_INFO, "  hoa:  %s", ip6_sprintf(&hoa));
		if (rthdr_on) 
			syslog(LOG_INFO, "  coa:  %s", ip6_sprintf(&rtaddr));
	}

	if (mh->ip6mh_type > IP6_MH_TYPE_MAX)
		mip6stat.mip6s_unknowntype++;
	else
		mip6stat.mip6s_mobility[mh->ip6mh_type]++;
	
	if (mh_input(&from.sin6_addr, &dst, hoaopt ? &hoa : NULL,
		     rthdr_on ? &rtaddr : NULL, mh, mhlen)) {
		return (-1);
	}

	return (0);
}

int
get_mobility_options(ip6mh, hlen, ip6mhlen, mopt)
        struct ip6_mh *ip6mh;
        int hlen, ip6mhlen;
        struct mip6_mobility_options *mopt;
{
	u_int8_t *mhopt, *mhend;

	mhopt = (caddr_t)(ip6mh) + hlen;
	mhend = (caddr_t)(ip6mh) + ip6mhlen;

	/* Reset Mobility Options */
	memset(mopt, 0, sizeof(*mopt));

#define check_mopt_len(mopt_len)        \
        if (*(mhopt + 1) != mopt_len) goto bad;
#define check_bauth_last() \
	if (mopt->opt_bauth) goto bad;

        while (mhopt < mhend) {
		if (debug) {
			syslog(LOG_INFO, "  %s is found",
			       mhopt_name[(*mhopt <= IP6_MHOPT_MAX) ? *mhopt : IP6_MHOPT_MAX + 1]);
		}

#ifdef MIP_CN
		if (*mhopt != IP6_MHOPT_BAUTH)	/* Always bind. auth. opt. should be the last option */
			check_bauth_last();
#endif /* MIP_CN */
		
                switch (*mhopt) {
		case IP6_MHOPT_PAD1:
			mhopt++;
			continue;
		case IP6_MHOPT_PADN:
			break;
		case IP6_MHOPT_ALTCOA:
			check_mopt_len(16);
			mopt->opt_altcoa = (struct ip6_mh_opt_altcoa *)mhopt;
			break;
		case IP6_MHOPT_NONCEID:
			check_mopt_len(4);
			mopt->opt_nonce = (struct ip6_mh_opt_nonce_index *)mhopt;
			break;
		case IP6_MHOPT_BAUTH:
			mopt->opt_bauth = (struct ip6_mh_opt_auth_data *)mhopt;
			break;
		case IP6_MHOPT_BREFRESH:
			check_mopt_len(2);
			mopt->opt_refresh = (struct ip6_mh_opt_refresh_advice *)mhopt;
			break;
#ifdef MIP_NEMO
		case IP6_MHOPT_PREFIX:
			if (mopt->opt_prefix_count >= 
			    NEMO_MAX_ALLOW_PREFIX)
				break;
			mopt->opt_prefix[mopt->opt_prefix_count] = 
				(struct ip6_mh_opt_prefix *)mhopt;
			mopt->opt_prefix_count ++;
			break;
#endif /* MIP_NEMO */
#ifdef MIP_MCOA
		case IP6_MHOPT_BID:
			mopt->opt_bid = (struct ip6_mh_opt_bid *)mhopt;
			break;
#endif /* MIP_MCOA */
#ifdef DSMIP
		case IP6_MHOPT_IPV4_HOA:
			mopt->opt_v4hoa = (struct ip6_mh_opt_ipv4_hoa *)mhopt;
			break;
#endif /* DSMIP */
#ifdef AUTHID
		case IP6_MHOPT_MN_ID:
			mopt->opt_mnid = (struct p6_mh_opt_mn_id *)mhopt;
			break;

		case IP6_MHOPT_AUTH_OPT:
			switch (((struct ip6_mh_opt_authentication *)mhopt)->ip6moauth_subtype) {
			case IP6_MH_AUTHOPT_SUBTYPE_MNHA:
				mopt->mnha_auth = 
					(struct ip6_mh_opt_authentication *)mhopt;
				break;
			case IP6_MH_AUTHOPT_SUBTYPE_MNAAA:
				mopt->mnaaa_auth = 
					(struct ip6_mh_opt_authentication *)mhopt;
				break;
			default:
				syslog(LOG_ERR, "Unknown authentication AAA");
				break;
			}
			break;
			
		case IP6_MHOPT_REPLAY_PROTECTION:
			break;
#endif /* AUTHID */
		default:
			syslog(LOG_INFO,
			    "invalid mobility option (%02x).", *mhopt);
			break;
                }

		mhopt += *(mhopt + 1) + 2;
        }

#undef check_mopt_len
#undef check_bauth_last
        return (0);

 bad:
        return (-1);
}

#ifdef MIP_MCOA
int
get_bid_option(ip6mh, hlen, ip6mhlen)
        struct ip6_mh *ip6mh;
        int hlen, ip6mhlen;
{
	struct mip6_mobility_options mopts;

	if (get_mobility_options(ip6mh, hlen, ip6mhlen, &mopts) < 0)
		return (0);
	if (mopts.opt_bid)
		return (ntohs(mopts.opt_bid->ip6mobid_bid));
	else
		return (0);
}
#endif /* MIP_MCOA */

/* search hoa destination option */
static struct ip6_opt_home_address *
mip6_search_hoa_in_destopt(optbuf)
	register u_int8_t *optbuf;
{
	register int optlen = 0;
	int destoptlen = (((struct ip6_dest *)optbuf)->ip6d_len + 1) << 3;
	
 	optbuf += sizeof(struct ip6_dest);
	destoptlen -= sizeof(struct ip6_dest);

 	for (optlen = 0; destoptlen > 0; 
	     destoptlen -= optlen, optbuf += optlen) {
		if (*optbuf == IP6OPT_HOME_ADDRESS)
			return ((struct ip6_opt_home_address *)optbuf);

		if (*optbuf == IP6OPT_PAD1)
			optlen = 1;
		else
			optlen = *(optbuf + 1) + 2;
        }

	return (NULL);	/* Not found */
}

#ifndef MIP_MN
int receive_bu(struct in6_addr *, struct in6_addr *, 
   struct in6_addr *, struct in6_addr *, struct ip6_mh_binding_update *, int);

/*
 * This function is for CN and HA only.
 */
int
mh_input(src, dst, hoa, rtaddr, mh, mhlen) 
	struct in6_addr *src, *dst, *hoa, *rtaddr;
	struct ip6_mh *mh;
	int mhlen;
{
#ifdef MIP_CN
	struct ip6_mh_home_test_init *hoti = NULL;
	struct ip6_mh_careof_test_init *coti = NULL;
#endif /* MIP_CN */

	/* Processing HOTI, COTI, BU, BE */
	switch(mh->ip6mh_type) {
	case IP6_MH_TYPE_HOTI:
#ifdef MIP_CN
		/* section 9.4.1 Check Home Address Option */
		if (hoa != NULL) 
			return (-1);

		hoti = (struct ip6_mh_home_test_init *)mh;
		
		/* section 6.1.3: Reserved field must be set to zero
		   However, it must be recived even if the reserved
		   field isn't zero . Found by v6pc testtool */
		
		if (send_hot(hoti, src, dst) > 0)
			return (-1);
#endif /* MIP_CN */
		break;
	case IP6_MH_TYPE_COTI:
#ifdef MIP_CN
		/* section 9.4.2 Check Home Address Option */
		if (hoa != NULL) 
			return (-1);

		coti = (struct ip6_mh_careof_test_init *)mh;

		/* section 6.1.4: Reserved field must be set to zero.
		   However, it must be recived even if the reserved
		   field isn't zero . Found by v6pc testtool */
                
		if (send_cot(coti, src, dst) > 0) 
			return (0);
#endif /* MIP_CN */
		break;
	case IP6_MH_TYPE_BACK:
	case IP6_MH_TYPE_COT:
	case IP6_MH_TYPE_HOT:
	case IP6_MH_TYPE_BRR:
		/* CN and HA just ignore */
		break;
	case IP6_MH_TYPE_BU:
		return (receive_bu(src, dst, hoa, rtaddr, (struct ip6_mh_binding_update *)mh, mhlen));
		break;
	case IP6_MH_TYPE_BERROR:
		break;
	default:
		send_be(src, dst, hoa, IP6_MH_BES_UNKNOWN_MH);
		break;
	}

	return (0);
}

/*
 * TODO: must revisit this function.
 * see KAME-snap 9418, 9422, 9423, 9424 from Daniel Jungbluth and
 * Christian Vogt for more detail
 */
int
receive_bu(src, dst, hoa, rtaddr, bu, mhlen) 
	struct in6_addr *src, *dst, *hoa, *rtaddr;
	struct ip6_mh_binding_update *bu;
	int mhlen;
{
	struct mip6_mobility_options mopt;
	struct binding_cache *bc = NULL;
	struct in6_addr *coa = NULL, *retcoa = NULL;
#ifdef MIP_CN
	mip6_token_t home_token, careof_token;
	struct mip6_nonces_info *home_nonces = NULL, *careof_nonces = NULL;
#endif /* MIP_CN */
	mip6_kbm_t *kbm = NULL;
	u_int16_t flags;
	u_int16_t seqno;
	u_int32_t lifetime;
	int retcode = -1;
	int statuscode = IP6_MH_BAS_ACCEPTED;
	u_int16_t bid = 0;
	int authmethod = BC_AUTH_NONE, authmethod_done = BC_AUTH_NONE;
	u_int32_t mobility_spi = 0;

	/* 
	 * If home address option is not present, home address
	 * is retrieved from the source address field of IPv6
	 * header.
	 */
	if (hoa == NULL)
		hoa = src;
		
	/* 
	 * point src as CoA. If an acoa option is present, coa
	 * will point an address in the acoa option 
	 */
	coa = src;

	/* If coa is not global, ignore */
	if (IN6_IS_ADDR_LINKLOCAL(coa)
	    || IN6_IS_ADDR_MULTICAST(coa)
	    || IN6_IS_ADDR_LOOPBACK(coa)
#ifndef DSMIP
	    || IN6_IS_ADDR_V4MAPPED(coa)
#endif /* DSMIP */
	    || IN6_IS_ADDR_UNSPECIFIED(coa))
		return (-1);

	/* If hoa is not global, ignore */
	if (IN6_IS_ADDR_LINKLOCAL(hoa)
	    || IN6_IS_ADDR_MULTICAST(hoa)
	    || IN6_IS_ADDR_LOOPBACK(hoa)
#ifndef DSMIP
	    || IN6_IS_ADDR_V4MAPPED(hoa)
#endif /* DSMIP */
	    || IN6_IS_ADDR_UNSPECIFIED(hoa))
		return (-1);

	seqno = ntohs(bu->ip6mhbu_seqno);
	lifetime = ntohs(bu->ip6mhbu_lifetime) << 2;
	flags = bu->ip6mhbu_flags;

	/* retrieve Mobility Options */
	if (get_mobility_options((struct ip6_mh *)bu, sizeof(*bu), mhlen, &mopt)) {
		mip6stat.mip6s_invalidopt++;
		syslog(LOG_ERR, "bad mobility option in BU.");
		return (-1);
	}

	/* 
	 * Check whether there is alternate CoA option 
	 */
	retcoa = coa;
	if (mopt.opt_altcoa) {
		coa = (struct in6_addr *)&mopt.opt_altcoa->ip6moa_addr;
		if (IN6_IS_ADDR_LINKLOCAL(coa)
		    || IN6_IS_ADDR_MULTICAST(coa)
		    || IN6_IS_ADDR_LOOPBACK(coa)
		    || IN6_IS_ADDR_V4MAPPED(coa)
		    || IN6_IS_ADDR_UNSPECIFIED(coa))
			return (-1);
	}

#ifdef MIP_CN
	authmethod |= BC_AUTH_RR;
#endif /* MIP_CN */
#ifdef MIP_HA
#ifdef AUTHID
	if (use_authid)
		authmethod |= BC_AUTH_MNHA;
#else /* AUTHID */
	authmethod |= BC_AUTH_IPSEC;
#endif /* AUTHID */
#endif /* MIP_HA */

	/* 
	 * Authenticator check if available. BU is protected
	 * by IPsec when it is sent to Home Agent. Otherwise, all
	 * packets SHOULD have a binding authorization and a nonce
	 * indices options.
	 */
	if (mopt.opt_bauth && mopt.opt_nonce) {
#ifdef MIP_CN
		int cnnonce = 0;
		u_int16_t cksum;
		mip6_authenticator_t authenticator;

/* 9.5.1
   If the Home Registration (H) bit is set, the Nonce Indices mobility
   option MUST NOT be present.
		:
   Packets carrying Binding Updates that fail to satisfy all of these
   tests for any reason other than insufficiency of the Sequence Number,
   registration type change, or expired nonce index values, MUST be
   silently discarded.
 */
		if (!homeagent_mode && (flags & IP6_MH_BU_HOME))
			return (-1);
		
		home_nonces =
			get_nonces(ntohs(mopt.opt_nonce->ip6moni_home_nonce));
		if (home_nonces == NULL) {
			statuscode = IP6_MH_BAS_HOME_NI_EXPIRED;
		} else {
			create_keygentoken(hoa, home_nonces, (u_int8_t *)&home_token, 0);
		}

		if (lifetime != 0 
		    && !IN6_ARE_ADDR_EQUAL(coa, hoa)) {
			careof_nonces = get_nonces(ntohs(mopt.opt_nonce->ip6moni_coa_nonce));
			if (careof_nonces == NULL) {
				if (home_nonces == NULL)
					statuscode = IP6_MH_BAS_NI_EXPIRED;
				else
					statuscode = IP6_MH_BAS_COA_NI_EXPIRED;
			} else {
				create_keygentoken(coa, careof_nonces, (u_int8_t *)careof_token, 1);
			}
			cnnonce = 1;
		}
		
		if ((home_nonces && check_nonce_reuse(home_nonces, hoa, coa)) ||
		    (careof_nonces && check_nonce_reuse(careof_nonces, hoa, coa)))
			statuscode = IP6_MH_BAS_NI_EXPIRED;

		if (statuscode != IP6_MH_BAS_ACCEPTED)
			goto sendba;

		/* Create Kbm = Hash(home keygen token | care-of keygen token) */
		kbm = alloca(sizeof(*kbm));
		mip6_calculate_kbm(&home_token, (cnnonce) ? &careof_token : NULL, kbm);
		
		/* Compare Calculated Authentication Data into Authenticator field */ 
		cksum = bu->ip6mhbu_hdr.ip6mh_cksum;
		bu->ip6mhbu_hdr.ip6mh_cksum = 0;
		
		/* Calculate authenticator */
		mip6_calculate_authenticator(kbm, coa, dst, (caddr_t)bu, mhlen, 
					     (u_int8_t *)mopt.opt_bauth + 
					     sizeof(struct ip6_mh_opt_auth_data) - (u_int8_t *)bu,
					     MIP6_AUTHENTICATOR_SIZE, &authenticator);
		bu->ip6mhbu_hdr.ip6mh_cksum = cksum;
		
		/* Authentication is failed, silently discard */
		if (memcmp(&authenticator, 
			   ((u_int8_t *)mopt.opt_bauth + 2), MIP6_AUTHENTICATOR_SIZE) != 0) {
			syslog(LOG_ERR, "Authenticator comparison failed");
			if (debug) { 
				syslog(LOG_INFO, "HomeIndex 0x%x",
				       ntohs(mopt.opt_nonce->ip6moni_home_nonce));
				syslog(LOG_INFO, "Home Token= %s",
				       hexdump(&home_token, MIP6_TOKEN_SIZE));
				syslog(LOG_INFO, "CareofIndex 0x%x",
				       ntohs(mopt.opt_nonce->ip6moni_coa_nonce));
				syslog(LOG_INFO, "Careof Token= %s", 
				       hexdump(&careof_token, MIP6_TOKEN_SIZE));
				syslog(LOG_INFO, "kbm: %s",
				       hexdump(kbm, MIP6_KBM_SIZE));
			}
			
			return (EINVAL);
		}
		if (lifetime > MIP6_MAX_RR_BINDING_LIFE)
			lifetime = MIP6_MAX_RR_BINDING_LIFE;
		authmethod_done = BC_AUTH_RR;
#endif /* MIP_CN */
	} else {
#ifdef MIP_CN
		/*
		 * According to the TAHI conformance test tool,
		 * the judgement of 'H' bit should be done proior
		 * authentic confirmation.
		 */
		if (!homeagent_mode && (flags & IP6_MH_BU_HOME)) {
			if (mip6_bc_lookup(hoa, dst, bid))
				statuscode = IP6_MH_BAS_REG_NOT_ALLOWED;
			else
				statuscode = IP6_MH_BAS_HA_NOT_SUPPORTED;
			goto sendba;
		}
	
		/* 
		 * If an authenticator is not present, just
		 * silently drop this BU 
		 */
		if (!(homeagent_mode && (flags & IP6_MH_BU_HOME))) {
			syslog(LOG_ERR, "No authenticator found in BU");
			return (-1);
		} else {
			return (0);
		}
#elif defined(MIP_HA)
#ifdef AUTHID
		if (authmethod & BC_AUTH_MNHA) {
			if (mopt.mnha_auth == NULL) {
				/*
				 * RFC 4285 section 5 says, "When a Binding
				 * Update or Binding Acknowledgement is
				 * received without a mobility message
				 * authentication option ... , the entity
				 * should silently discard the received
				 * message."
				 */
				syslog(LOG_ERR, "No mobility message authentication option is found");
				return (-1);
			}

			auth_opt(hoa, coa, (struct ip6_mh *)bu, &mopt,
				 &authmethod, &authmethod_done);
			mobility_spi = mopt.mnha_auth->ip6moauth_mobility_spi;
		}
#else /* AUTHID */
		/* go thorough (assuming IPsec protection in the kernel) */
		authmethod_done = BC_AUTH_IPSEC;
#endif /* AUTHID */
#endif /* MIP_CN */ 
	}

#ifdef MIP_MCOA
	/* 
	 * Check whether there is Binding Unique Identifier option 
	 */
	if (mopt.opt_bid) {
		bid = ntohs(mopt.opt_bid->ip6mobid_bid);
		syslog(LOG_INFO, "BID Option is found %d", bid);
		/* zero bid is invalid */
		if (bid == 0) 
			return (-1); /* XXX */
	}
#endif /* MIP_MCOA */

	/* Circular Registering check */
	/* 6.1.7
	   ... the Binding Update MUST be silently discarded
	   if the care-of address appears as a home address
	   in an exsiting Binding Cache entry, ...
	 */
	if (!IN6_ARE_ADDR_EQUAL(coa, hoa) &&
	    mip6_bc_lookup(coa, NULL, bid))
		return (-1);

	/* Get Binding Cache entry */
	bc = mip6_bc_lookup(hoa, dst, bid);

	/* sequence number comparison */
	if (bc && MIP6_LEQ(seqno, bc->bc_seqno)) {
		statuscode = IP6_MH_BAS_SEQNO_BAD;
		syslog(LOG_ERR,
		       "Received sequence number from [%s] is out of window. "
		       "[%u] should be larger than [%u]",
		       ip6_sprintf(hoa), seqno, bc->bc_seqno);
		seqno = bc->bc_seqno;
		goto sendba;
	}

#ifdef MIP_HA
	/* if flags are changed during registration, sending BA with 139 */
	if (bc && ((bc->bc_flags ^ flags) & (IP6_MH_BU_HOME
#ifdef MIP_NEMO
					     | IP6_MH_BU_ROUTER
#endif /* MIP_NEMO */
			   ))) {
		statuscode = IP6_MH_BAS_REG_NOT_ALLOWED;
		goto sendba;
	}

	/* 
	 * requesting node's HoA is belong to its Home
	 * Agent or not. 
	 */
	if (flags & IP6_MH_BU_HOME) {
#ifndef MIP_NEMO /* NEMO must be releaxed with this */
		struct mip6_hpfxl *hpfxlist;
		
		hpfxlist = had_is_myhomenet(hoa);
		if (hpfxlist == NULL) {
			statuscode = IP6_MH_BAS_NOT_HOME_SUBNET;
			goto sendba;
		}

		/* Should lifetime be limited by vltime ? */
		if ((hpfxlist->hpfx_vltime > 0) &&
		    (lifetime >= hpfxlist->hpfx_vltime))
			lifetime = hpfxlist->hpfx_vltime;
#if 0
		if (lifetime >= 420)
			lifetime = 420;	/* Suck Hack for USAGI MIP */
#endif
#endif /* !MIP_NEMO */
		/* Home Agent does not process BU w/RR protection */ 
		if (mopt.opt_nonce) 
			return (-1);

	} else if (flags & IP6_MH_BU_LLOCAL) {
		/* Nothing todo here */
	} else if (flags & IP6_MH_BU_KEYM) {
		/* Not Implemented yet */
	} 
#ifdef MIP_NEMO
	else if (flags & IP6_MH_BU_ROUTER) {
		/* When R flag is set, H flag is mandated */
		if ((flags & IP6_MH_BU_HOME) == 0) {
			/* send_ba with 140 */
			statuscode = IP6_MH_BAS_MR_NOT_PERMIT;
			retcode = -1; /* XXX */
			goto sendba;
		}
	}
#endif /* MIP_NEMO */

	/* If nonce Indices opt. was found, it must be silently discarded */
	/* 9.5.1 */
	/* XXX This check might not be mandatory. Should consider later */
	if (mopt.opt_nonce)
		return (-1);

#ifdef MIP_NEMO
	/* Mobile Network Prefix Verfication */
	if (mopt.opt_prefix_count > 0) {
		struct nemo_hptable *hpt;
		int r = 0;
		struct sockaddr_in6 prefix;
		
		/* when flags are incorrect,  just ignore this BU?? */
		if (((flags & IP6_MH_BU_HOME) == 0) &&
		    ((flags & IP6_MH_BU_ROUTER) == 0))
			return (-1); 

		/*
		 *  verify prefix with prefixtable (explicit mode only)
		 */
		for (r = 0; r < mopt.opt_prefix_count; r ++) {
			memset(&prefix, 0, sizeof(struct sockaddr_in6));
			prefix.sin6_len = sizeof(struct sockaddr_in6);
			prefix.sin6_family = AF_INET6;
			prefix.sin6_addr = mopt.opt_prefix[r]->ip6mopfx_pfx;
			hpt = nemo_hpt_get((struct sockaddr_storage*)&prefix,
			    mopt.opt_prefix[r]->ip6mopfx_pfxlen, hoa);

			/* 
			 * The requesting prefix is not
			 * authorized. discard this BU.  
			 */
			if (hpt == NULL) {
				statuscode = IP6_MH_BAS_NOT_AUTHORIZED;
				goto sendba;
			}

			/* check whether MR has authority for MNP */
			if (!IN6_ARE_ADDR_EQUAL(hoa, &hpt->hpt_hoa)) {
				statuscode = IP6_MH_BAS_NOT_AUTHORIZED;
				goto sendba;
			}

			if (hpt->hpt_regmode !=  NEMO_EXPLICIT) {
				statuscode = IP6_MH_BAS_INVALID_PREFIX /* XXX */;
				goto sendba;
			}
		}
	}
#endif /* MIP_NEMO */

#endif /* MIP_HA */

	/* Requesting to delete a binding (de-registration) */
	if (lifetime == 0 
	    || IN6_ARE_ADDR_EQUAL(coa, hoa)) {
		if (bc) {
			bc->bc_coa = *coa;
			/* The above hack is necessary to pass the new CoA.
			   the address is used for updating tunnel SA 
			   Does it work on MCOA case ?
			 */
#ifdef MIP_CN
			if (home_nonces && (authmethod & BC_AUTH_RR))
				retain_bc_to_nonce(home_nonces, bc);
			if (careof_nonces && (authmethod & BC_AUTH_RR))
				retain_bc_to_nonce(careof_nonces, bc);
			if (!home_nonces && !careof_nonces)
				mip6_bc_delete(bc);
#endif /* MIP_CN */
			mip6_bc_delete(bc);
			syslog(LOG_INFO,
			       "binding cache has been deleted. HoA:[%s], CoA[%s] lifetime=%d",
			       ip6_sprintf(hoa), ip6_sprintf(coa), lifetime);
		} else {
#ifdef MIP_HA
			/* 10.3.2 */
/*
   o  If the receiving node has no entry marked as a home registration
      in its Binding Cache for this mobile node, then this node MUST
      reject the Binding Update and SHOULD return a Binding
      Acknowledgement to the mobile node, in which the Status field is
      set to 133 (not home agent for this mobile node).
*/
			statuscode = IP6_MH_BAS_NOT_HA;
#endif /* MIP_HA */
		}
			
		lifetime = 0;	/* Returned lifetime in BA must be zero */
	} else {
		/* Requesitng to cache binding (registration) */
		bc = mip6_bc_add(hoa, coa, dst, lifetime, flags, seqno, bid, authmethod, authmethod_done, mobility_spi);
		if (bc == NULL) {
			statuscode = IP6_MH_BAS_INSUFFICIENT;
			goto sendba;
		}
		if (flags & IP6_MH_BU_LLOCAL) {
			struct in6_addr llhoa;

			memset(&llhoa, 0, sizeof(llhoa));
			llhoa.s6_addr[0] = 0xfe;
			llhoa.s6_addr[1] = 0x80;
			llhoa.s6_addr[3] = ha_if() & 0xff;
			memcpy(&llhoa.s6_addr[8], &hoa->s6_addr[8], 8);
			bc->bc_llmbc = mip6_bc_add(&llhoa, coa, dst, lifetime, flags, seqno, bid, authmethod, authmethod_done, 0);
			bc->bc_llmbc->bc_glmbc = bc;
		}

		bc->bc_realcoa = *retcoa;
		if (bc->bc_state & BC_STATE_UNDER_DAD)
			return (0);
	}
	retcode = 0;

 sendba:
	if (statuscode != IP6_MH_BAS_ACCEPTED ||
	    (flags & (IP6_MH_BU_ACK | IP6_MH_BU_HOME))) {
		send_ba(dst, retcoa, coa, hoa, flags, kbm, 
			statuscode, seqno, lifetime, 0 /* refresh */, bid, mobility_spi);
	}

	return (retcode);
}
#endif /* !MIP_MN */


/* BRR */
int 
send_brr(src, dst)
	struct in6_addr *src;
	struct in6_addr *dst;
{
        struct ip6_mh_binding_request brr;
	int error;

	if (debug) {
		syslog(LOG_INFO, "BRR is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(src));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(dst));
	}

        memset(&brr, 0, sizeof(brr));

        brr.ip6mhbr_hdr.ip6mh_proto = IPPROTO_NONE;
        brr.ip6mhbr_hdr.ip6mh_len = (sizeof(brr) >> 3) - 1;
        brr.ip6mhbr_hdr.ip6mh_type = IP6_MH_TYPE_BRR;
        brr.ip6mhbr_hdr.ip6mh_cksum = checksum_p((u_int16_t *)src, (u_int16_t *)dst, 
						 (u_int16_t *)&brr, sizeof(brr), IPPROTO_MH);

	error = sendmessage((char *)&brr, sizeof(brr), 0, src, dst, NULL, NULL);
	return (error);
}

#ifdef MIP_MN
/* HoTI */
int 
send_hoti(bul)
	struct binding_update_list *bul;
{ 
	struct ip6_mh_home_test_init hoti;
	int err = 0;

	if (debug) {
		syslog(LOG_INFO, "HoTI is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(&bul->bul_peeraddr));
	}

	memset(&hoti, 0, sizeof(hoti));
	hoti.ip6mhhti_hdr.ip6mh_proto = IPPROTO_NONE;
	hoti.ip6mhhti_hdr.ip6mh_len =  (sizeof(hoti) >> 3) - 1;
	hoti.ip6mhhti_hdr.ip6mh_type = IP6_MH_TYPE_HOTI;

	(void)RAND_pseudo_bytes((u_char *)bul->bul_home_cookie,
	    MIP6_COOKIE_SIZE);

	memcpy((void *)hoti.ip6mhhti_cookie,
	    (const void *)bul->bul_home_cookie, 
		 sizeof(hoti.ip6mhhti_cookie)); 

	hoti.ip6mhhti_hdr.ip6mh_cksum = 
		checksum_p((u_int16_t *)&bul->bul_hoainfo->hinfo_hoa, 
			(u_int16_t *)&bul->bul_peeraddr, (u_int16_t *)&hoti, 
				sizeof(hoti), IPPROTO_MH);

	err = sendmessage((char *)&hoti, sizeof(hoti), 0,
	    &bul->bul_hoainfo->hinfo_hoa, &bul->bul_peeraddr, NULL, NULL);

	return (err);
}

/* CoTI */
int 
send_coti(bul)
	struct binding_update_list *bul;
{ 
	struct ip6_mh_careof_test_init coti;
	int err = 0;

	if (debug) {
		syslog(LOG_INFO, "CoTI is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(&bul->bul_coa));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(&bul->bul_peeraddr));
	}

	memset(&coti, 0, sizeof(coti));
	coti.ip6mhcti_hdr.ip6mh_proto = IPPROTO_NONE;
	coti.ip6mhcti_hdr.ip6mh_len = (sizeof(coti) >> 3) - 1;
	coti.ip6mhcti_hdr.ip6mh_type = IP6_MH_TYPE_COTI;

	(void)RAND_pseudo_bytes((u_char *)bul->bul_careof_cookie,
	    MIP6_COOKIE_SIZE);

	memcpy((void *)coti.ip6mhcti_cookie,
	       (const void *)bul->bul_careof_cookie,
	       sizeof(coti.ip6mhcti_cookie));

	coti.ip6mhcti_hdr.ip6mh_cksum = 
		checksum_p((u_int16_t *)&bul->bul_coa, 
			(u_int16_t *)&bul->bul_peeraddr, (u_int16_t *)&coti, 
				sizeof(coti), IPPROTO_MH);

	err = sendmessage((char *)&coti, sizeof(coti),
		0, &bul->bul_coa, &bul->bul_peeraddr, NULL, NULL);

	return (err);
}
#endif /* MIP_MN */


#ifdef MIP_CN
/* HoT */
int 
send_hot(hoti, dst, src) 
	struct ip6_mh_home_test_init *hoti;
	struct in6_addr *dst;
	struct in6_addr *src;
{
	struct ip6_mh_home_test hot; 
	struct mip6_nonces_info *nonce = NULL;
	int err = 0;

	if (debug) {
		syslog(LOG_INFO, "HoT is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(src));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(dst));
	}

	memset(&hot, 0, sizeof(hot));
	hot.ip6mhht_hdr.ip6mh_proto = IPPROTO_NONE;
	hot.ip6mhht_hdr.ip6mh_len =  (sizeof(hot) >> 3) - 1;
	hot.ip6mhht_hdr.ip6mh_type = IP6_MH_TYPE_HOT;
	hot.ip6mhht_hdr.ip6mh_reserved = 0;
	bcopy(hoti->ip6mhhti_cookie,  hot.ip6mhht_cookie, sizeof(hot.ip6mhht_cookie));
	memcpy((void *)hot.ip6mhht_cookie, (const void *)hoti->ip6mhhti_cookie,
	    sizeof(hot.ip6mhht_cookie));

	/* get nonces set */

	nonce = get_nonces(0);
	if (nonce == NULL)
		return (EINVAL);
	hot.ip6mhht_nonce_index = htons(nonce->nonce_index);
	create_keygentoken(dst, nonce, (u_int8_t *)hot.ip6mhht_keygen, 0);

	hot.ip6mhht_hdr.ip6mh_cksum = 
		checksum_p((u_int16_t *)src, 
			   (u_int16_t *)dst, (u_int16_t *)&hot, 
			   sizeof(hot), IPPROTO_MH);

	err = sendmessage((char *)&hot, sizeof(hot), 0, src, dst, NULL, NULL);

	return (err);
}

/* CoT */
int 
send_cot(coti, dst, src) 
	struct ip6_mh_careof_test_init *coti;
	struct in6_addr *dst;
	struct in6_addr *src;
{
	struct ip6_mh_careof_test cot; 
	struct mip6_nonces_info *nonce = NULL;
	int err = 0;

	if (debug) {
		syslog(LOG_INFO, "CoT is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(src));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(dst));
	}

	memset(&cot, 0, sizeof(cot));

	cot.ip6mhct_hdr.ip6mh_proto = IPPROTO_NONE;
	cot.ip6mhct_hdr.ip6mh_len = (sizeof(cot) >> 3) - 1;
	cot.ip6mhct_hdr.ip6mh_type = IP6_MH_TYPE_COT;
	cot.ip6mhct_hdr.ip6mh_reserved = 0;
	memcpy((void *)cot.ip6mhct_cookie, (const void *)coti->ip6mhcti_cookie,
	       sizeof(cot.ip6mhct_cookie));

	/* get nonces set */
	nonce = get_nonces(0);
	if (nonce == NULL)
		return (EINVAL);
	cot.ip6mhct_nonce_index = htons(nonce->nonce_index);
	create_keygentoken(dst, nonce, (u_int8_t *)cot.ip6mhct_keygen, 1);

	/*cot.ip6mhct_hdr.ip6mh_cksum = 0a*/
	cot.ip6mhct_hdr.ip6mh_cksum = 
		checksum_p((u_int16_t *)src, 
			   (u_int16_t *)dst, (u_int16_t *)&cot, 
			   sizeof(cot), IPPROTO_MH);

	err = sendmessage((char *)&cot, sizeof(cot), 0, src, dst, NULL, NULL);

	return (err);
}
#endif

#ifdef MIP_MN
int
send_bu(bul)
	struct binding_update_list *bul;
{
	char buf[1024];
	register char *bufp = buf; 
	int buflen = 0, pad = 0, error = 0;

	struct ip6_mh_binding_update *bup;
	struct ip6_mh_opt_auth_data auth_opt;
	struct ip6_mh_opt_nonce_index nonce_opt; 
	mip6_kbm_t kbm;
	mip6_authenticator_t authenticator;
#ifdef MIP_NEMO
	struct ip6_mh_opt_prefix prefix_opt;
#ifdef MIP_IPV4MNPSUPPORT
	struct ip6_mh_opt_ipv4_prefix v4prefix_opt;
#endif /* MIP_IPV4MNPSUPPORT */
#endif /* MIP_NEMO */
#ifdef DSMIP
	struct ip6_mh_opt_ipv4_hoa v4hoa_opt;
	struct home_agent_list *hal;
#endif /* DSMIP */
#ifdef MIP_MCOA
	struct ip6_mh_opt_bid bid_opt;

	if (!LIST_EMPTY(&bul->bul_mcoa_head)) {
		/*syslog(LOG_INFO, "this bul has multiple CoAs, ignore root %d", bul->bul_bid);*/
		return (0);
	} 
#endif /* MIP_MCOA */

	if (debug) {
		syslog(LOG_INFO, "BU is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(&bul->bul_peeraddr));
		syslog(LOG_INFO, "  via  %s", ip6_sprintf(&bul->bul_coa));
		syslog(LOG_INFO, "  seq  %d", bul->bul_seqno);
		syslog(LOG_INFO, "  life %d", bul->bul_lifetime);
		syslog(LOG_INFO, "  flgs %x", bul->bul_flags);
	}

	memset(buf, 0, sizeof(buf));
	bup = (struct ip6_mh_binding_update *)buf;

	/* Adding Binding Update */
	buflen += sizeof(struct ip6_mh_binding_update);

	bup->ip6mhbu_hdr.ip6mh_proto = IPPROTO_NONE;
	bup->ip6mhbu_hdr.ip6mh_type = IP6_MH_TYPE_BU;
	bup->ip6mhbu_hdr.ip6mh_reserved = 0;
	bup->ip6mhbu_seqno = htons(++bul->bul_seqno);
	bup->ip6mhbu_flags = bul->bul_flags;

	/*
	 * The lifetime for CNs should not set less than the remaining
	 * lifetime of the home registration.  
	 */
	if (!(bul->bul_flags & IP6_MH_BU_HOME)) {
		struct binding_update_list *homebul = NULL;
		struct timeval now;

		gettimeofday(&now, NULL);

		homebul = bul_get_homeflag(&bul->bul_hoainfo->hinfo_hoa);
		if (homebul == NULL)
			return (EINVAL);
		
		if (homebul->bul_expire &&
		    TIMESUB(&homebul->bul_expire->exptime, &now) <= (bul->bul_lifetime << 2))
			bup->ip6mhbu_lifetime = htons(TIMESUB(&homebul->bul_expire->exptime, &now) >> 2);
		else 
			bup->ip6mhbu_lifetime = htons(bul->bul_lifetime);
	} else
		bup->ip6mhbu_lifetime = htons(bul->bul_lifetime);

	/* Adding Alternate Care-of Address Option */	
	if ((bul->bul_flags & IP6_MH_BU_HOME)
#ifdef DSMIP
	    && !IN6_IS_ADDR_V4MAPPED(&bul->bul_coa)
#endif /* DSMIP */
		) {
		struct ip6_mh_opt_altcoa *acoa_opt;
		
		pad = MIP6_PADLEN(buflen, 8, 6);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		acoa_opt = (struct ip6_mh_opt_altcoa *)(bufp + buflen);
		acoa_opt->ip6moa_type = IP6_MHOPT_ALTCOA;
		acoa_opt->ip6moa_len = 16; 
		memcpy((void *)acoa_opt->ip6moa_addr,
		    (const void *)&bul->bul_coa, sizeof(acoa_opt->ip6moa_addr));
		buflen += sizeof(struct ip6_mh_opt_altcoa);
        }

#ifdef MIP_MCOA 
	/* Adding Binding Unique Identifier Option */
	if (bul->bul_bid) {
		pad = MIP6_PADLEN(buflen, 2, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		memset(&bid_opt, 0, sizeof(bid_opt));
		
		bid_opt.ip6mobid_type = IP6_MHOPT_BID;
		bid_opt.ip6mobid_len = 4;
		bid_opt.ip6mobid_bid = htons(bul->bul_bid);
		bid_opt.ip6mobid_reserved = 0;
		syslog(LOG_INFO, "BID option is added %d", bul->bul_bid);

		memcpy((bufp + buflen), &bid_opt, sizeof(bid_opt));
		buflen += sizeof(struct ip6_mh_opt_bid);
	}
#endif /* MIP_MCOA */

#ifdef MIP_NEMO
	/* Adding Mobile Network Prefix Option */	
	if (bul->bul_flags & IP6_MH_BU_ROUTER) {
		struct nemo_mptable *mpt, *mptn;

		/* R flag MUST be always set only to Home Registration */
		if ((bul->bul_flags & IP6_MH_BU_HOME) == (int)NULL) 
			return (EINVAL);

		mpt = LIST_FIRST(&bul->bul_hoainfo->hinfo_mpt_head); 
		for (; mpt; mpt = mptn) {
			mptn = LIST_NEXT(mpt, mpt_entry);

			/* when not explicit mode, nothing to append */
			if (mpt->mpt_regmode != NEMO_EXPLICIT)
				continue;

			if (mpt->mpt_ss_prefix.ss_family == AF_INET6) {
				pad = MIP6_PADLEN(buflen, 8, 4);  /* 8n+4 */
				MIP6_FILL_PADDING(bufp + buflen, pad);
				buflen += pad;

				memset(&prefix_opt, 0, sizeof(prefix_opt));

				prefix_opt.ip6mopfx_type = IP6_MHOPT_PREFIX;
				prefix_opt.ip6mopfx_len = 18;
				prefix_opt.ip6mopfx_pfxlen
				    = mpt->mpt_prefixlen;
				prefix_opt.ip6mopfx_pfx
				    = SS2SIN6(&mpt->mpt_ss_prefix)->sin6_addr;

				memcpy((bufp + buflen), &prefix_opt, sizeof(prefix_opt));
				buflen += sizeof(struct ip6_mh_opt_prefix);
			}
#ifdef MIP_IPV4MNPSUPPORT
			else if (ipv4mnpsupport
			    && (mpt->mpt_ss_prefix.ss_family == AF_INET)) {
				pad = MIP6_PADLEN(buflen, 4, 0);  /* 4n */
				MIP6_FILL_PADDING(bufp + buflen, pad);
				buflen += pad;

				memset(&v4prefix_opt, 0, sizeof(v4prefix_opt));

				v4prefix_opt.ip6mov4pfx_type = IP6_MHOPT_IPV4_PREFIX;
				v4prefix_opt.ip6mov4pfx_len = 6;
				v4prefix_opt.ip6mov4pfx_pfxlen
				    = mpt->mpt_prefixlen;
				v4prefix_opt.ip6mov4pfx_pfx
				    = SS2SIN(&mpt->mpt_ss_prefix)->sin_addr;

				memcpy((bufp + buflen), &v4prefix_opt,
				    sizeof(v4prefix_opt));
				buflen += sizeof(struct ip6_mh_opt_ipv4_prefix);
			}
#endif /* MIP_IPV4MNPSUPPORT */
		}
	}
#endif /* MIP_NEMO */

#ifdef DSMIP
	if (IN6_IS_ADDR_V4MAPPED(&bul->bul_coa) &&
			IN6_IS_ADDR_V4MAPPED(&bul->bul_peeraddr)) {
		pad = MIP6_PADLEN(buflen, 2, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		memset(&v4hoa_opt, 0, sizeof(v4hoa_opt));

		v4hoa_opt.ip6mov4hoa_type = IP6_MHOPT_IPV4_HOA;
		v4hoa_opt.ip6mov4hoa_len = 5;
		v4hoa_opt.ip6mov4hoa_pfxlen = 32; /* XXX */
		memcpy(&v4hoa_opt.ip6mov4hoa_v4hoa,
				&bul->bul_hoainfo->hinfo_v4hoa,
				sizeof(struct in_addr));

		syslog(LOG_INFO, "IPv4 Home Address option is added %s/%d", 
				inet_ntoa(v4hoa_opt.ip6mov4hoa_v4hoa),
				v4hoa_opt.ip6mov4hoa_pfxlen);

		memcpy((bufp + buflen), &v4hoa_opt, sizeof(v4hoa_opt));
		buflen += sizeof(struct ip6_mh_opt_ipv4_hoa);
	}
#endif /* DSMIP */ 

	if (bul->bul_flags & IP6_MH_BU_HOME) {
		/* Alignment 8n */
		pad = MIP6_PADLEN(buflen, 8, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

#ifdef MIP_NEMO
		/* R flag MUST be always set to Home Registration */
		if ((bul->bul_flags & IP6_MH_BU_ROUTER) == (int)NULL) 
			return (EINVAL);
#endif /* MIP_NEMO */

		goto skip_rr;
	} 

	/* Adding Binding Nonce Index */ 
	/* padding */
	pad = MIP6_PADLEN(buflen, 2, 0);
	MIP6_FILL_PADDING(bufp + buflen, pad);
	buflen += pad;

	/* fililng nonce index option */
	memset(&nonce_opt, 0, sizeof(nonce_opt));
	nonce_opt.ip6moni_type = IP6_MHOPT_NONCEID;
	nonce_opt.ip6moni_len = 4; 
	nonce_opt.ip6moni_home_nonce = htons(bul->bul_home_nonce_index);
	nonce_opt.ip6moni_coa_nonce = htons(bul->bul_careof_nonce_index);
	memcpy((bufp + buflen), &nonce_opt, sizeof(nonce_opt));
	buflen += sizeof(nonce_opt);

	/* Add Binding Authorization */
	/* padding */
	pad = MIP6_PADLEN(buflen, 8, 2);
	MIP6_FILL_PADDING(bufp + buflen, pad);
	buflen += pad;

	/* filling authorization data option */
	memset(&auth_opt, 0, sizeof(auth_opt));
	auth_opt.ip6moad_type = IP6_MHOPT_BAUTH;
	auth_opt.ip6moad_len = 12; 
	memcpy((bufp + buflen), &auth_opt, sizeof(auth_opt));
	buflen += (sizeof(auth_opt) + MIP6_AUTHENTICATOR_SIZE);

	/* Alignment 8n */
	pad = MIP6_PADLEN(buflen, 8, 0);
	MIP6_FILL_PADDING(bufp + buflen, pad);
	buflen += pad;

	/* 
	 * This is not final length, but mobileip6_authentication_data() needs 
	 * correct bu length for authentication data calculation 
	 */
	bup->ip6mhbu_hdr.ip6mh_len = (buflen >> 3) - 1;
	bup->ip6mhbu_hdr.ip6mh_cksum = 0;

	/* Create Kbm = Hash(home keygen token | care-of keygen token) */
	mip6_calculate_kbm(&bul->bul_home_token,
	    bul->bul_hoainfo->hinfo_location != MNINFO_MN_HOME ?
	    &bul->bul_careof_token : NULL, &kbm);

#if 0
	if (debug) { 
		int r = 0;
		char msg[256];
	
		syslog(LOG_ERR, "homeindex=0x%x", bul->bul_home_nonce_index);

		memset(msg, 0, sizeof(msg));
		sprintf(msg, "hometoken=");
		syslog(LOG_ERR, "hometoken=");

		for (r = 0; r < MIP6_HOME_TOKEN_SIZE; r++)
			sprintf(msg + strlen(msg), "0x%x:",
				bul->bul_home_token[r]);
		syslog(LOG_ERR, msg);
	
		syslog(LOG_ERR, "careofindex=0x%x",
		       bul->bul_careof_nonce_index);

		memset(msg, 0, sizeof(msg));	
		sprintf(msg, "careoftoken= ");
		for (r = 0; r < MIP6_HOME_TOKEN_SIZE; r++)
			sprintf(msg + strlen(msg), "0x%x:",
			       bul->bul_careof_token[r]);
		syslog(LOG_ERR, msg);
	
		memset(msg, 0, sizeof(msg));	
		sprintf(msg, "kbm: ");
		for (r = 0; r < MIP6_KBM_SIZE; r++)
			sprintf(msg + strlen(msg), "0x%x:", kbm[r]);
		syslog(LOG_ERR, msg);
	}
#endif

	/* (6.2.7) The Binding Authorization Data option does not have
	 * alignment requirements as such.  However, since this option
	 * must be the last mobility option, an implicit alignment
	 * requirement is 8n + 2.  
	 */
	/* Adding Calculated Authentication Data into Authenticator field */ 
	mip6_calculate_authenticator(&kbm,
				     &bul->bul_coa,
				     &bul->bul_peeraddr, 
				     (caddr_t)bufp,
				     buflen, 
				     buflen - pad - MIP6_AUTHENTICATOR_SIZE, 
				     MIP6_AUTHENTICATOR_SIZE,
				     &authenticator);

	memcpy((bufp + (buflen - MIP6_AUTHENTICATOR_SIZE - pad)), 
		&authenticator, MIP6_AUTHENTICATOR_SIZE);

   skip_rr:

	/* Finalize */
	bup->ip6mhbu_hdr.ip6mh_len = (buflen >> 3) - 1;
	bup->ip6mhbu_hdr.ip6mh_cksum = 0;
	bup->ip6mhbu_hdr.ip6mh_cksum = 	
		checksum_p((u_int16_t *)&bul->bul_hoainfo->hinfo_hoa, 
			(u_int16_t *)&bul->bul_peeraddr,
		   	(u_int16_t *)bufp, buflen, IPPROTO_MH);
	if (bul->bul_hoainfo->hinfo_location == MNINFO_MN_HOME) 
		error = sendmessage((char *)bufp, buflen, bul->bul_home_ifindex,
		    &bul->bul_hoainfo->hinfo_hoa, &bul->bul_peeraddr,
		    &bul->bul_hoainfo->hinfo_hoa, NULL);
	else
#ifdef DSMIP
		if (IN6_IS_ADDR_V4MAPPED(&bul->bul_coa) &&
			IN6_IS_ADDR_V4MAPPED(&bul->bul_peeraddr)) {
			hal = mip6_find_hal_v6(bul->bul_hoainfo);
			if (hal == NULL) {
				syslog(LOG_ERR, "no IPv6 home agent found");
				return(-1);
			}

			/* create tunnel */
# if 0
/* DON'T LEAVE SUCH ADHOC CODE ONLY FOR YOUR SPECIFIC DEBUGGING ENVIRONMENT SO LONG TIME */
system("ifconfig nemo0 tunnel 203.178.128.64 203.178.128.50 up");
#endif

			error = v4_sendmessage((char *)bufp, buflen, 0,
					&bul->bul_peeraddr, &bul->bul_coa,
					&hal->hal_ip6addr,
					&bul->bul_hoainfo->hinfo_hoa,
					NULL);
		} else
			error = sendmessage((char *)bufp, buflen, 0, 
		    		&bul->bul_hoainfo->hinfo_hoa,
				&bul->bul_peeraddr,
		    		&bul->bul_coa, NULL);
#else
		error = sendmessage((char *)bufp, buflen, 0, 
		    &bul->bul_hoainfo->hinfo_hoa, &bul->bul_peeraddr,
		    &bul->bul_coa, NULL);
#endif /* DSMIP */

	if (error == 0) {
		time(&bul->bul_bu_lastsent);
	}

	return (error);
}
#endif

#ifndef MIP_MN
int
send_ba(src, coa, acoa, hoa, flags, kbm_p, status, seqno, lifetime, refresh, bid, mobility_spi)
	struct in6_addr *src, *coa, *acoa, *hoa;
	u_int16_t flags;
	mip6_kbm_t *kbm_p;
	u_int8_t status;
	u_int16_t seqno;
	u_int16_t lifetime;
	int refresh;
	u_int16_t bid;
	u_int32_t mobility_spi;
{
	int err = 0;
	char buf[1024];
	int buflen = 0;
	int pad = 0;
	register char *bufp = buf; 
	struct ip6_mh_binding_ack *bap;
#ifdef MIP_MCOA
	struct ip6_mh_opt_bid bid_opt;
#endif /* MIP_MCOA */
#ifdef DSMIP
	struct ip6_mh_opt_ipv4_ack v4ack_opt;
#endif /* DSMIP */

	if (hoa == NULL)
		hoa = coa;

	/* section 9.5.4 if hoa is not unicast global, BA should not be sent */
        if (hoa && (IN6_IS_ADDR_LINKLOCAL(hoa)
            || IN6_IS_ADDR_MULTICAST(hoa)
            || IN6_IS_ADDR_LOOPBACK(hoa)
            || IN6_IS_ADDR_V4MAPPED(hoa)
            || IN6_IS_ADDR_UNSPECIFIED(hoa)))
		return (EINVAL);

	memset(buf, 0, sizeof(buf));
	bap = (struct ip6_mh_binding_ack *)buf;

	/* Adding BA */
	buflen = sizeof(struct ip6_mh_binding_ack);

	bap->ip6mhba_hdr.ip6mh_proto = IPPROTO_NONE;
	bap->ip6mhba_hdr.ip6mh_type = IP6_MH_TYPE_BACK;
	bap->ip6mhba_status = status;
	bap->ip6mhba_seqno = htons(seqno);
	bap->ip6mhba_lifetime = htons(lifetime >> 2);

#ifdef MIP_HA
	if (keymanagement
	    && (flags & IP6_MH_BU_KEYM))
		bap->ip6mhba_flags |= IP6_MH_BA_KEYM;
#ifdef MIP_NEMO
	/* When BU has R flag, BA must be returned with Rflag */
	if ((flags & IP6_MH_BU_HOME) &&
	    (flags & IP6_MH_BU_ROUTER))
		bap->ip6mhba_flags |= IP6_MH_BA_ROUTER;
#endif /* MIP_NEMO */
#endif /* MIP_HA */

	/* section 10.3.1 MAY put Binding Refresh Advice mobility option */
	if (refresh && (ntohs(bap->ip6mhba_lifetime) != 0)) {
		;
	}

#ifdef MIP_MCOA
	/* Adding Binding Unique Identifier Option */
	if (bid) {
		pad = MIP6_PADLEN(buflen, 2, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		memset(&bid_opt, 0, sizeof(bid_opt));
                
		bid_opt.ip6mobid_type = IP6_MHOPT_BID;
		bid_opt.ip6mobid_len = 4;
		bid_opt.ip6mobid_bid = htons(bid);
		bid_opt.ip6mobid_reserved = 0;
		syslog(LOG_INFO, "BID option is added %d", bid);

		memcpy((bufp + buflen), &bid_opt, sizeof(bid_opt));
		buflen += sizeof(struct ip6_mh_opt_bid);
	}
#endif /* MIP_MCOA */

#ifdef DSMIP
	if (IN6_IS_ADDR_V4MAPPED(coa)) {
		pad = MIP6_PADLEN(buflen, 2, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		memset(&v4ack_opt, 0, sizeof(v4ack_opt));

		v4ack_opt.ip6mov4ack_type = IP6_MHOPT_IPV4_HOA;
		v4ack_opt.ip6mov4ack_len = 6;
		v4ack_opt.ip6mov4ack_status = htons(0);
		v4ack_opt.ip6mov4ack_pfxlen = 32;
		memcpy(&v4ack_opt.ip6mov4ack_v4hoa, &coa->s6_addr[12],
					sizeof(v4ack_opt.ip6mov4ack_v4hoa));
		syslog(LOG_INFO, "IPv4 Addr Ack option is added");

		memcpy((bufp + buflen), &v4ack_opt, sizeof(v4ack_opt));
		buflen += sizeof(struct ip6_mh_opt_ipv4_ack);
	}
#endif /* DSMIP */

#ifdef MIP_CN
	/* Retrun Routability */
	if (kbm_p) {
		struct ip6_mh_opt_auth_data *auth_opt;
		mip6_authenticator_t *authenticator;
		 
		/* section 9.5.4 Should not include auth data subopt 
		 * Even if BA does not contain auth data, 
		 * BA should be sent to MN to notify invalid nonce. 
		 */
		if ((status == IP6_MH_BAS_NI_EXPIRED) || 
		    (status == IP6_MH_BAS_COA_NI_EXPIRED) || 
		    (status == IP6_MH_BAS_HOME_NI_EXPIRED)) {
			goto skip_auth;
		}

		/* Add authentication suboption if security flag is enable */
		pad = MIP6_PADLEN(buflen, 8, 2);	/* 8n+2 */
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		auth_opt = (struct ip6_mh_opt_auth_data *)(bufp + buflen);
		auth_opt->ip6moad_type = IP6_MHOPT_BAUTH;
		auth_opt->ip6moad_len = MIP6_AUTHENTICATOR_SIZE;
		buflen += sizeof(*auth_opt);
		buflen += MIP6_AUTHENTICATOR_SIZE;

		/* Alignment 8n */
		pad = MIP6_PADLEN(buflen, 8, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		/* 
		 * This is not final length, but
		 * mobileip6_authentication_data() needs correct bu
		 * length for authentication data calculation 
		 */
		bap->ip6mhba_hdr.ip6mh_len = (buflen >> 3) - 1;
		bap->ip6mhba_hdr.ip6mh_cksum = 0;

		authenticator = (mip6_authenticator_t *)
			(bufp + (buflen - MIP6_AUTHENTICATOR_SIZE - pad));
		mip6_calculate_authenticator(kbm_p,
					     (acoa) ? acoa : coa,
					     src, 
					     (caddr_t)bufp,
					     buflen, 
					     buflen - pad - MIP6_AUTHENTICATOR_SIZE, 
					     MIP6_AUTHENTICATOR_SIZE,
					     authenticator);
	}  

 skip_auth:
#endif /* MIP_CN */

#if defined(MIP_HA) && defined(AUTHID)
	if (mobility_spi != 0) {
		struct haauth_users *hausers;
		struct ip6_mh_opt_authentication *auth_opt;
		mip6_authenticator_t *authenticator;

		pad = MIP6_PADLEN(buflen, 8, 2);	/* 8n+2 */
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		auth_opt = (struct ip6_mh_opt_authentication *)(bufp + buflen);
		auth_opt->ip6moauth_type = IP6_MHOPT_AUTH_OPT;
		auth_opt->ip6moauth_len =
			sizeof(struct ip6_mh_opt_authentication)
			- sizeof(struct ip6_mh_opt) + MIP6_AUTHENTICATOR_SIZE;
		buflen += sizeof(*auth_opt);
		buflen += MIP6_AUTHENTICATOR_SIZE;

		/* 
		 * This is not final length, but
		 * mobileip6_authentication_data() needs correct bu
		 * length for authentication data calculation 
		 */
		bap->ip6mhba_hdr.ip6mh_len = (buflen >> 3) - 1;
		bap->ip6mhba_hdr.ip6mh_cksum = 0;

		/* Alignment 8n to sit the end of the packet */
		pad = MIP6_PADLEN(buflen, 8, 0);
		MIP6_FILL_PADDING(bufp + buflen, pad);
		buflen += pad;

		authenticator = (mip6_authenticator_t *)
			(bufp + (buflen - MIP6_AUTHENTICATOR_SIZE - pad));

		hausers = find_haauth_users(mobility_spi);
		mip6_calculate_authenticator((mip6_kbm_t *)hausers->sharedkey,
					     (acoa) ? acoa : coa,
					     src, 
					     (caddr_t)bufp,
					     buflen, 
					     buflen - pad - MIP6_AUTHENTICATOR_SIZE, 
					     MIP6_AUTHENTICATOR_SIZE,
					     authenticator);
		/* MN-AAA isn't needed as described RFC4285 5.2 */
	}
#endif /* MIP_HA && AUTHID */

	/* Alignment 8n */
	pad = MIP6_PADLEN(buflen, 8, 0);
	MIP6_FILL_PADDING(bufp + buflen, pad);
	buflen += pad;

	/* Finish */
	bap->ip6mhba_hdr.ip6mh_len = (buflen >> 3) - 1;
	bap->ip6mhba_hdr.ip6mh_cksum = 0;
	bap->ip6mhba_hdr.ip6mh_cksum = 
		checksum_p((u_int16_t *)src, (u_int16_t *)hoa,
			   (u_int16_t *)bufp, buflen, IPPROTO_MH);

	if (debug) {
		syslog(LOG_INFO, "BA is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(src));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(hoa));
		syslog(LOG_INFO, "  via  %s", ip6_sprintf(coa));
		syslog(LOG_INFO, "  status=%d seqno=%d", status, seqno);
	}

	if (IN6_ARE_ADDR_EQUAL(hoa, coa))
	 	err = sendmessage(bufp, buflen, 0, src, hoa, NULL, NULL);
	else
#ifdef DSMIP
		if (IN6_IS_ADDR_V4MAPPED(coa))
			err = v4_sendmessage(bufp, buflen, 0, coa, src, coa,
					NULL, hoa);
		else
#endif /* DSMIP */
		err = sendmessage(bufp, buflen, 0, src, hoa, NULL, coa);

	if (err == 0) {
		mip6stat.mip6s_oba_hist[status]++;
	}

	return (err);
}
#endif /* MIP_MN */

int
send_be(dst, src, home, status)
	struct in6_addr *dst;
	struct in6_addr *src;
	struct in6_addr *home;
	u_int8_t status;
{
	struct ip6_mh_binding_error be;
	int err = 0;

	if (debug) {
		syslog(LOG_INFO, "BE is sent");
		syslog(LOG_INFO, "  from %s", ip6_sprintf(src));
		syslog(LOG_INFO, "  to   %s", ip6_sprintf(dst));
		syslog(LOG_INFO, "  for  %s",
		    home ? ip6_sprintf(home) : "::");
	}

	memset(&be, 0, sizeof(be));
	be.ip6mhbe_hdr.ip6mh_proto = IPPROTO_NONE;
	be.ip6mhbe_hdr.ip6mh_len = (sizeof(be) >> 3) - 1;
	be.ip6mhbe_hdr.ip6mh_type = IP6_MH_TYPE_BERROR;
	be.ip6mhbe_status = status;

	if (home)
		memcpy(&be.ip6mhbe_homeaddr, 
		       home, sizeof(struct in6_addr));
	else /* section 9.3.3 Set unspecified addr */
		memset(&be.ip6mhbe_homeaddr, 
		       0, sizeof(struct in6_addr));

	be.ip6mhbe_hdr.ip6mh_cksum = 
		checksum_p((u_int16_t *)src, (u_int16_t *)dst,
		(u_int16_t *)&be, (be.ip6mhbe_hdr.ip6mh_len + 1) << 3, IPPROTO_MH);

	err =  sendmessage((char *)&be, sizeof(be), 
			   0, src, dst, NULL, NULL);
	if (err == 0) {
		mip6stat.mip6s_obe_hist[status]++;
	}

	return (err);
}


u_int16_t
checksum_p(src, dst, addr, len, nxt)
	u_int16_t *src, *dst, *addr;
	int len, nxt;
{
        int sum;
        u_int16_t s;

	if (src == NULL || dst == NULL || addr == NULL)
		return (-1);

        sum = 0;

        /* add pseudo ip header */
        s = 8;
        while (s--) {
                sum += *src++;
                sum += *dst++;
        }

        sum += htons(len >> 16);
        sum += htons(len & 0xffff);
        sum += htons(nxt);

        /* add payload data */
        while (len > 1) {
                sum += *addr++;
                len -= 2;
        }

        if (len) {
                s = 0;
                *(unsigned char *)(&s) = *(unsigned char *)addr;
                sum += s;
        }

        /* add overflow counts */
        while (sum >> 16)
                sum  = (sum >> 16) + (sum & 0xffff);

        return (~sum);
}


static int
sendmessage(mhdata, mhdatalen, ifindex, src, dst, haoaddr, rtaddr) 
	char *mhdata;
	int mhdatalen;
	u_int ifindex;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *haoaddr;
	struct in6_addr *rtaddr;
{
	struct sockaddr_in6 addr;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr  *cmsgptr = NULL;
	register struct in6_pktinfo *pi;
	struct ip6_opt_home_address *hoadst;
        struct ip6_rthdr2 *rtopt = NULL;
	struct ip6_dest *dest;
        char adata [1024];
#if defined(MIP_MN) && defined(MIP_NEMO)
	struct sockaddr_in6 *ar_sin6, ar_sin6_orig;
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin6_addr = *dst;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = 0;
	addr.sin6_scope_id = 0;
	addr.sin6_len = sizeof (struct sockaddr_in6);

	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *) adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	if (haoaddr)  
		msg.msg_controllen += 
			CMSG_SPACE(sizeof(struct ip6_opt_home_address) 
				+ sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN);
	if (rtaddr)
		msg.msg_controllen += 
			CMSG_SPACE(sizeof(struct ip6_rthdr2) + sizeof(struct in6_addr));
#if defined(MIP_MN) && defined(MIP_NEMO)
	ar_sin6 = nemo_ar_get(haoaddr, &ar_sin6_orig);
	if (ar_sin6) 
		msg.msg_controllen += 
			CMSG_SPACE(sizeof(struct sockaddr_in6));
#endif /*MIP_NEMO */
        iov.iov_base = mhdata;
        iov.iov_len = mhdatalen;
	
	/* Packet Information i.e. Source Address */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	memset(pi, 0, sizeof(*pi));
	pi->ipi6_ifindex = ifindex;
	pi->ipi6_addr = *src;
       	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

#if defined(MIP_MN) && defined(MIP_NEMO)
	if (ar_sin6) { 
		if (debug) 
			syslog(LOG_INFO, "sendmsg via %s/%d", 
				ip6_sprintf(&ar_sin6->sin6_addr), ar_sin6->sin6_scope_id);
		cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct sockaddr_in6));
		cmsgptr->cmsg_level = IPPROTO_IPV6;
		cmsgptr->cmsg_type = IPV6_NEXTHOP;
		memcpy(CMSG_DATA(cmsgptr), ar_sin6, sizeof(struct sockaddr_in6));
		cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
	}
#endif

	/* Destination Option */
	if (haoaddr) {
		dest = (struct ip6_dest *)(CMSG_DATA(cmsgptr));

		/* padding */
/*		mhopt_add_pads((char *)(dest + 1), MIP6_HOAOPT_PADLEN); */
		MIP6_FILL_PADDING((char *)(dest + 1), MIP6_HOAOPT_PADLEN);

		dest->ip6d_nxt = 0;
		dest->ip6d_len = ((sizeof(struct ip6_opt_home_address) +
			sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN) >> 3) - 1;

		hoadst = (struct ip6_opt_home_address *)
			((char *)(dest + 1) + MIP6_HOAOPT_PADLEN);
		memset(hoadst, 0, sizeof(*hoadst));
		hoadst->ip6oh_type = 0xc9;
		hoadst->ip6oh_len = sizeof(struct ip6_opt_home_address) - 
			sizeof(struct ip6_dest);
		memcpy(hoadst->ip6oh_addr, haoaddr, sizeof(struct in6_addr));
		
		cmsgptr->cmsg_level = IPPROTO_IPV6;
		cmsgptr->cmsg_type = IPV6_DSTOPTS;
		cmsgptr->cmsg_len = 
			CMSG_LEN(sizeof(struct ip6_opt_home_address) + 
			sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN);
		cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
	}

	/* Routing Header */
	if (rtaddr) {

		rtopt = (struct ip6_rthdr2 *)(CMSG_DATA(cmsgptr));
		memset(rtopt, 0, sizeof(*rtopt));

		rtopt->ip6r2_nxt = 0;
		rtopt->ip6r2_len = 2;
		rtopt->ip6r2_type = 2;
		rtopt->ip6r2_segleft = 1;  
		rtopt->ip6r2_reserved = 0;
		memcpy((rtopt + 1), rtaddr, sizeof(struct in6_addr));

		cmsgptr->cmsg_level = IPPROTO_IPV6;
		cmsgptr->cmsg_type = IPV6_RTHDR;
		cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct ip6_rthdr2) + 
			sizeof(struct in6_addr));
		cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
	}

	if (sendmsg(mhsock, &msg, 0) < 0){
		perror("mh sendmsg ()");
		syslog(LOG_ERR, "sendmsg error %s", strerror(errno));
		fprintf(stderr, "%s -> %s\n",
			ip6_sprintf(src), ip6_sprintf(dst));
	} else {
		mip6stat.mip6s_omobility[((struct ip6_mh *)mhdata)->ip6mh_type]++;
	}

	return (0);
}

#ifdef DSMIP
#ifndef MIP_MN
int
v4_sendmessage(mhdata, mhdatalen, ifindex, v4dst, src, dst, hoa, rtaddr)
	char *mhdata;
	int mhdatalen;
	u_int ifindex;
	struct in6_addr *v4dst;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *hoa;
	struct in6_addr *rtaddr;
{
	struct sockaddr_in addr;
	char buf[1024];
	int buflen = 0;

	struct ip *ip;
	struct ip6_hdr *ip6;
	struct ip6_dest *dest;
	struct ip6_opt_home_address *hoadst;
	struct ip6_rthdr2 *rtopt;

	memset(&addr, 0, sizeof(addr));
	memset(&buf, 0, sizeof(buf));

	memcpy(&addr.sin_addr, &v4dst->s6_addr[12], sizeof(addr.sin_addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(5555);
	addr.sin_len = sizeof(addr);

	ip = (struct ip *)buf;
	ip->ip_v   = IPVERSION;
	ip->ip_hl  = sizeof(struct ip) >> 2;
	ip->ip_tos = 0;
	ip->ip_id  = htons(getpid() & 0xFFFF);
	ip->ip_off = 0;
	ip->ip_ttl = MAXTTL;
	ip->ip_p   = IPPROTO_IPV6;
	ip->ip_sum = 0;
	memcpy(&ip->ip_dst, &v4dst->s6_addr[12], sizeof(struct in_addr));
	buflen += sizeof(struct ip);

	ip6 = (struct ip6_hdr *)(ip + 1);
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_hlim = 64;
	memcpy(&ip6->ip6_src, src, sizeof(struct in6_addr));
	memcpy(&ip6->ip6_dst, dst, sizeof(struct in6_addr));
	buflen += sizeof(struct ip6_hdr);

	if (hoa) {
		ip6->ip6_nxt = IPPROTO_MH;

		dest = (struct ip6_dest *)(ip6 + 1);
		MIP6_FILL_PADDING((char *)(dest + 1), MIP6_HOAOPT_PADLEN);
		dest->ip6d_nxt = 0;
		dest->ip6d_len = ((sizeof(struct ip6_opt_home_address) +
			sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN) >> 3) - 1;
		hoadst = (struct ip6_opt_home_address *)
			((char *)(dest + 1) + MIP6_HOAOPT_PADLEN);
		hoadst->ip6oh_type = 0xc9;
		hoadst->ip6oh_len = sizeof(struct ip6_opt_home_address) - 
				sizeof(struct ip6_dest);
		memcpy(hoadst->ip6oh_addr, hoa, sizeof(struct in6_addr));
		buflen += sizeof(struct ip6_opt_home_address) + 
				sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN;
	}

        /* Routing Header */
        if (rtaddr) { 
		ip6->ip6_nxt = IPPROTO_ROUTING;

		rtopt = (struct ip6_rthdr2 *)(ip6 + 1);
		rtopt->ip6r2_nxt = IPPROTO_MH;
		rtopt->ip6r2_len = 2;
		rtopt->ip6r2_type = 2;
		rtopt->ip6r2_segleft = 1;
		rtopt->ip6r2_reserved = 0;
		memcpy((rtopt + 1), rtaddr, sizeof(struct in6_addr));
		buflen += sizeof(struct ip6_rthdr2) + sizeof(struct in6_addr);
        }

	memcpy(buf+buflen, mhdata, mhdatalen);
	buflen += mhdatalen;

	ip->ip_len = buflen;
	ip6->ip6_plen = htons(buflen - sizeof(struct ip)
					- sizeof(struct ip6_hdr));

	if (sendto(raw4sock, buf, buflen, 0, (struct sockaddr *)&addr,
	    sizeof(addr)) < 0){
		syslog(LOG_ERR, "sendto error %s", strerror(errno));
	} else {
		mip6stat.mip6s_omobility[
				((struct ip6_mh *)mhdata)->ip6mh_type]++;
	}

	return (0);
}
#else
int
v4_sendmessage(mhdata, mhdatalen, ifindex, v4dst, src, dst, hoa, rtaddr)
	char *mhdata;
	int mhdatalen;
	u_int ifindex;
	struct in6_addr *v4dst;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *hoa;
	struct in6_addr *rtaddr;
{
	struct sockaddr_in addr;
	struct msghdr msg;
	struct iovec iov;
	char buf[1024];
	int buflen = 0;

	struct ip6_hdr *ip6;
	struct ip6_dest *dest;
	struct ip6_opt_home_address *hoadst;
	struct ip6_rthdr2 *rtopt;

	memset(&addr, 0, sizeof(addr));
	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	memset(&buf, 0, sizeof(buf));

	memcpy(&addr.sin_addr, &v4dst->s6_addr[12], sizeof(addr.sin_addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(5555);
	addr.sin_len = sizeof(addr);

	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_hlim = 64;
	memcpy(&ip6->ip6_src, src, sizeof(struct in6_addr));
	memcpy(&ip6->ip6_dst, dst, sizeof(struct in6_addr));
	buflen += sizeof(struct ip6_hdr);

	if (hoa) {
		ip6->ip6_nxt = IPPROTO_MH;

		dest = (struct ip6_dest *)(ip6 + 1);
		MIP6_FILL_PADDING((char *)(dest + 1), MIP6_HOAOPT_PADLEN);
		dest->ip6d_nxt = 0;
		dest->ip6d_len = ((sizeof(struct ip6_opt_home_address) +
			sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN) >> 3) - 1;
		hoadst = (struct ip6_opt_home_address *)
			((char *)(dest + 1) + MIP6_HOAOPT_PADLEN);
		hoadst->ip6oh_type = 0xc9;
		hoadst->ip6oh_len = sizeof(struct ip6_opt_home_address) - 
				sizeof(struct ip6_dest);
		memcpy(hoadst->ip6oh_addr, hoa, sizeof(struct in6_addr));
		buflen += sizeof(struct ip6_opt_home_address) + 
				sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN;
	}

        /* Routing Header */
        if (rtaddr) { 
		ip6->ip6_nxt = IPPROTO_ROUTING;

		rtopt = (struct ip6_rthdr2 *)(ip6 + 1);
		rtopt->ip6r2_nxt = IPPROTO_MH;
		rtopt->ip6r2_len = 2;
		rtopt->ip6r2_type = 2;
		rtopt->ip6r2_segleft = 1;
		rtopt->ip6r2_reserved = 0;
		memcpy((rtopt + 1), rtaddr, sizeof(struct in6_addr));
		buflen += sizeof(struct ip6_rthdr2) + sizeof(struct in6_addr);
        }

	memcpy(buf+buflen, mhdata, mhdatalen);
	buflen += mhdatalen;

	ip6->ip6_plen = htons(buflen - sizeof(struct ip6_hdr));
	iov.iov_base = buf;
	iov.iov_len = buflen;

	if (sendmsg(udp4sock, &msg, 0) < 0){
		syslog(LOG_ERR, "sendmsg error %s", strerror(errno));
	} else {
		mip6stat.mip6s_omobility[
				((struct ip6_mh *)mhdata)->ip6mh_type]++;
	}

	return (0);
}
#endif /* !MIP_MN */

#endif /* DSMIP */
