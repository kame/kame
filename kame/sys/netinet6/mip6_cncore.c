/*	$KAME: mip6_cncore.c,v 1.65 2004/05/26 07:41:31 itojun Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.  All rights reserved.
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
#include "opt_ipsec.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif

/* Some of operating systems have standard crypto checksum library */
#ifdef __NetBSD__
#define HAVE_SHA1
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syslog.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_encap.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <netinet/in_pcb.h>
#endif
#ifdef __NetBSD__
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/scope6_var.h>

#if defined(IPSEC) && !defined(__OpenBSD__)
#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#endif /* IPSEC && !__OpenBSD__ */

#ifdef __OpenBSD__
#include <netinet/ip_ipsp.h>
#endif

#ifdef HAVE_SHA1
#include <sys/sha1.h>
#define SHA1_RESULTLEN	20
#else
#include <crypto/sha1.h>
#ifdef __OpenBSD__
#define SHA1_RESULTLEN	20
#endif
#endif
#ifdef __OpenBSD__
#include <crypto/cryptodev.h>
#else
#include <crypto/hmac.h>
#endif

#include <netinet/ip6mh.h>
#include <net/if_hif.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <netinet6/mip6_cncore.h>
#ifdef MIP6_HOME_AGENT
#include <netinet6/mip6_hacore.h>
#endif /* MIP6_HOME_AGENT */
#ifdef MIP6_MOBILE_NODE
#include <netinet6/mip6_mncore.h>
#endif /* MIP6_MOBILE_NODE */

#ifdef __OpenBSD__
#undef IPSEC
#endif

struct mip6_bc_list mip6_bc_list;
#ifdef __NetBSD__
struct callout mip6_bc_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_bc_ch;
#elif defined(__OpenBSD__)
struct timeout mip6_bc_ch;
#endif
#ifndef MIP6_BC_HASH_SIZE
#define MIP6_BC_HASH_SIZE 35			/* XXX */
#endif
#define MIP6_IN6ADDR_HASH(addr)					\
	((addr)->s6_addr32[0] ^ (addr)->s6_addr32[1] ^		\
	 (addr)->s6_addr32[2] ^ (addr)->s6_addr32[3])
#define MIP6_BC_HASH_ID(addr) (MIP6_IN6ADDR_HASH(addr) % MIP6_BC_HASH_SIZE)
struct mip6_bc *mip6_bc_hash[MIP6_BC_HASH_SIZE];

#define HMACSIZE 16
#define NONCE_UPDATE_PERIOD	(MIP6_MAX_NONCE_LIFE / MIP6_NONCE_HISTORY)
mip6_nonce_t mip6_nonce[MIP6_NONCE_HISTORY];
mip6_nodekey_t mip6_nodekey[MIP6_NONCE_HISTORY];	/* this is described as 'Kcn' in the spec */
u_int16_t nonce_index;		/* the idx value pointed by nonce_head */
mip6_nonce_t *nonce_head;	/* Current position of nonce on the array mip6_nonce */
#ifdef __NetBSD__
struct callout mip6_nonce_upd_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_nonce_upd_ch;
#elif defined(__OpenBSD__)
struct timeout mip6_nonce_upd_ch;
#endif

/*
 * configuration knobs.
 */
int mip6ctl_nodetype = 0;
int mip6ctl_use_ipsec = 1;
#ifdef MIP6_DEBUG
int mip6ctl_debug = 1;
#else
int mip6ctl_debug = 0;
#endif
u_int32_t mip6ctl_bc_maxlifetime = 420;
u_int32_t mip6ctl_hrbc_maxlifetime = 420;
u_int32_t mip6ctl_bu_maxlifetime = 420;
u_int32_t mip6ctl_hrbu_maxlifetime = 420;

struct mip6stat mip6stat;

static int mip6_brr_maxtries = 2;	/* times */
static int mip6_brr_tryinterval = 10;	/* second */
#define MIP6_BRR_SEND_EXPONENT	0
#define MIP6_BRR_SEND_LINIER	1
static int mip6_brr_mode = MIP6_BRR_SEND_EXPONENT;

/* IPv6 extension header processing. */
static int mip6_rthdr_create_withdst(struct ip6_rthdr **, struct in6_addr *,
    struct ip6_pktopts *);

/* binding cache entry processing. */
static int mip6_bc_delete(struct mip6_bc *);
static int mip6_bc_list_insert(struct mip6_bc_list *, struct mip6_bc *);
static int mip6_bc_register(struct in6_addr *, struct in6_addr *,
    struct in6_addr *, u_int16_t, u_int16_t, u_int32_t);
static int mip6_bc_update(struct mip6_bc *, struct in6_addr *,
    struct in6_addr *, u_int16_t, u_int16_t, u_int32_t);
static int mip6_bc_send_brr(struct mip6_bc *);
static int mip6_bc_need_brr(struct mip6_bc *);
static void mip6_bc_timer(void *);

/* return routability processing. */
static void mip6_create_nonce(mip6_nonce_t *);
static void mip6_create_nodekey(mip6_nodekey_t *);
static void mip6_update_nonce_nodekey(void *);

/* Mobility Header processing. */
static int mip6_ip6mh_create(struct ip6_mh **, struct in6_addr *,
    struct in6_addr *, u_int8_t *);
static int mip6_ip6mc_create(struct ip6_mh **, struct in6_addr *,
    struct in6_addr *, u_int8_t *);
static int mip6_ip6mr_create(struct ip6_mh **, struct in6_addr *,
    struct in6_addr *);

/* core functions for mobile node and home agent. */
#if !defined(MIP6_NOHAIPSEC)
#if defined(MIP6_HOME_AGENT) || defined(MIP6_MOBILE_NODE)
static int mip6_update_ipsecdb(struct sockaddr_in6 *,
    struct sockaddr_in6 *, struct sockaddr_in6 *, struct sockaddr_in6 *);
#endif /* MIP6_HOME_AGENT || MIP6_MOBILE_NODE */
#endif /* !MIP6_NOHAIPSEC */

void
mip6_init()
{
	/* initialization as a correspondent node. */
	mip6_bc_init(); /* binding cache routine initailize */

	/* Initialize nonce, key, and something else for CN */
	nonce_head = mip6_nonce;
	nonce_index = 0;
	mip6_create_nonce(mip6_nonce);
	mip6_create_nodekey(mip6_nodekey);
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&mip6_nonce_upd_ch, NULL);
	callout_reset(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD,
		      mip6_update_nonce_nodekey, NULL);
#elif defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_init(&mip6_nonce_upd_ch);
	callout_reset(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD,
		      mip6_update_nonce_nodekey, NULL);
#elif defined(__OpenBSD__)
	timeout_set(&mip6_nonce_upd_ch, mip6_update_nonce_nodekey, NULL);
	timeout_add(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD);
#else
	timeout(mip6_update_nonce_nodekey, (caddr_t)0,
		hz * NONCE_UPDATE_PERIOD);
#endif

#ifdef MIP6_MOBILE_NODE
	mip6_mn_init();
#endif /* MIP6_MOBILE_NODE */
}

int
mip6_ioctl(cmd, data)
	u_long cmd;
	caddr_t data;
{
	int subcmd;
	struct mip6_req *mr = (struct mip6_req *)data;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
			s = splsoftnet();
#else
			s = splnet();
#endif

	switch (cmd) {
	case SIOCSMIP6CFG:
		subcmd = *(int *)data;
		switch (subcmd) {
#ifdef MIP6_MOBILE_NODE
		case SIOCSMIP6CFG_ENABLEMN:
		{
			int error;
			error = mip6_mobile_node_start();
			if (error) {
				splx(s);
				return (error);
			}
		}
			break;

		case SIOCSMIP6CFG_DISABLEMN:
			mip6_mobile_node_stop();
			break;
#endif /* MIP6_MOBILE_NODE */

#ifdef MIP6_HOME_AGENT
		case SIOCSMIP6CFG_ENABLEHA:
			mip6log((LOG_INFO,
				 "%s:%d: HA function enabled\n",
				 __FILE__, __LINE__));
			mip6ctl_nodetype = MIP6_NODETYPE_HOME_AGENT;
			break;
#endif /* MIP6_HOME_AGENT */

		case SIOCSMIP6CFG_ENABLEIPSEC:
			mip6log((LOG_INFO,
				 "%s:%d: IPsec protection enabled\n",
				 __FILE__, __LINE__));
			mip6ctl_use_ipsec = 1;
			break;

		case SIOCSMIP6CFG_DISABLEIPSEC:
			mip6log((LOG_INFO,
				 "%s:%d: IPsec protection disabled\n",
				 __FILE__, __LINE__));
			mip6ctl_use_ipsec = 0;
			break;

		case SIOCSMIP6CFG_ENABLEDEBUG:
			mip6log((LOG_INFO,
				 "%s:%d: debug message enabled\n",
				 __FILE__, __LINE__));
			mip6ctl_debug = 1;
			break;

		case SIOCSMIP6CFG_DISABLEDEBUG:
			mip6log((LOG_INFO,
				 "%s:%d: debug message disabled\n",
				 __FILE__, __LINE__));
			mip6ctl_debug = 0;
			break;

		default:
			splx(s);
			return (EINVAL);
		}
		break;

	case SIOCGBC:
		{
			struct mip6_bc *mbc, *rmbc;
			int i;

			rmbc = mr->mip6r_ru.mip6r_mbc;
			i = 0;
			for (mbc = LIST_FIRST(&mip6_bc_list);
			     mbc;
			     mbc = LIST_NEXT(mbc, mbc_entry)) {
				*rmbc = *mbc;
				i++;
				if (i > mr->mip6r_count)
					break;
				rmbc++;
			}
			mr->mip6r_count = i;
		}
		break;

	case SIOCDBC:
		if (IN6_IS_ADDR_UNSPECIFIED(&mr->mip6r_ru.mip6r_in6)) {
			struct mip6_bc *mbc;

			/* remove all binding cache entries. */
			while ((mbc = LIST_FIRST(&mip6_bc_list)) != NULL) {
				(void)mip6_bc_list_remove(&mip6_bc_list, mbc);
			}
		} else {
			struct mip6_bc *mbc;

			/* remove a specified binding cache entry. */
			mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, 
			    &mr->mip6r_ru.mip6r_in6);
			if (mbc != NULL) {
				(void)mip6_bc_list_remove(&mip6_bc_list, mbc);
			}
		}
		break;

#ifdef MIP6_MOBILE_NODE
	case SIOCSUNUSEHA:
		{
			struct mip6_unuse_hoa *uh;

			for (uh = LIST_FIRST(&mip6_unuse_hoa);
			     uh;
			     uh = LIST_NEXT(uh, unuse_entry)) {
				if (IN6_ARE_ADDR_EQUAL(&uh->unuse_addr,
				    &mr->mip6r_ru.mip6r_ssin6.sin6_addr) &&
				    uh->unuse_port
				    == mr->mip6r_ru.mip6r_ssin6.sin6_port) {
					splx(s);
					return (EEXIST);
				}
			}

			MALLOC(uh, struct mip6_unuse_hoa *,
			       sizeof(struct mip6_unuse_hoa), M_IP6OPT, M_WAIT);
			if (uh == NULL) {
				splx(s);
				return (ENOBUFS);
			}

			uh->unuse_addr = mr->mip6r_ru.mip6r_ssin6.sin6_addr;
			uh->unuse_port = mr->mip6r_ru.mip6r_ssin6.sin6_port;
			LIST_INSERT_HEAD(&mip6_unuse_hoa, uh, unuse_entry);
		}
		break;

	case SIOCGUNUSEHA:
			/* Not yet */
		break;

	case SIOCDUNUSEHA:
		{
			struct mip6_unuse_hoa *uh, *nxt;

			for (uh = LIST_FIRST(&mip6_unuse_hoa); uh; uh = nxt) {
				nxt = LIST_NEXT(uh, unuse_entry);
				if (IN6_ARE_ADDR_EQUAL(&uh->unuse_addr,
				    &mr->mip6r_ru.mip6r_ssin6.sin6_addr) &&
				    uh->unuse_port
				    == mr->mip6r_ru.mip6r_ssin6.sin6_port) {
					LIST_REMOVE(uh, unuse_entry);
					FREE(uh, M_IP6OPT);
					break;
				}
			}
			if (uh == NULL) {
				splx(s);
				return (ENOENT);
			}
		}
		break;

	case SIOCSPREFERREDIFNAMES:
	{
		/*
		 * set preferrable ifps for selecting CoA.  we must
		 * keep the name as a string because other information
		 * (such as a pointer, interface index) may be changed
		 * when removing the devices.
		 */
		bcopy(&mr->mip6r_ru.mip6r_ifnames, &mip6_preferred_ifnames,
		    sizeof(mr->mip6r_ru.mip6r_ifnames));
		mip6_process_movement();
	}

		break;
#endif /* MIP6_MOBILE_NODE */
	}

	splx(s);

	return (0);
}

/*
 ******************************************************************************
 * Function:    mip6_create_ip6hdr
 * Description: Create and fill in data for an IPv6 header to be used by
 *              packets originating from MIPv6.  In addition to this memory
 *              is reserved for payload, if necessary.
 * Ret value:   NULL if a IPv6 header could not be created.
 *              Otherwise, pointer to a mbuf including the IPv6 header.
 ******************************************************************************
 */
struct mbuf *
mip6_create_ip6hdr(src, dst, nxt, plen)
	struct in6_addr *src;
	struct in6_addr *dst;
	u_int8_t nxt;
	u_int32_t plen;
{
	struct ip6_hdr *ip6; /* ipv6 header. */
	struct mbuf *m; /* a pointer to the mbuf containing ipv6 header. */
	u_int32_t maxlen;

	maxlen = sizeof(*ip6) + plen;
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m && (max_linkhdr + maxlen >= MHLEN)) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (NULL);
		}
	}
	if (m == NULL)
		return (NULL);
	m->m_pkthdr.rcvif = NULL;
	m->m_data += max_linkhdr;

	/* set mbuf length. */
	m->m_pkthdr.len = m->m_len = maxlen;

	/* fill an ipv6 header. */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = htons((u_int16_t)plen);
	ip6->ip6_nxt = nxt;
	ip6->ip6_hlim = ip6_defhlim;
	ip6->ip6_src = *src;
	ip6->ip6_dst = *dst;

	return (m);
}

int
mip6_exthdr_create(m, opt, mip6opt)
	struct mbuf *m;                   /* ip datagram */
	struct ip6_pktopts *opt;          /* pktopt passed to ip6_output */
	struct mip6_pktopts *mip6opt;
{
	struct ip6_hdr *ip6;
	int s, error = 0;
#ifdef MIP6_MOBILE_NODE
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	int need_hao = 0;
#endif /* MIP6_MOBILE_NODE */

	mip6opt->mip6po_rthdr2 = NULL;
	mip6opt->mip6po_haddr = NULL;

	ip6 = mtod(m, struct ip6_hdr *);

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	/*
	 * From section 6.1: "Mobility Header messages MUST NOT be
	 * sent with a type 2 routing header, except as described in
	 * Section 9.5.4 for Binding Acknowledgement".
	*/
	if ((opt != NULL)
	    && (opt->ip6po_mh != NULL)
	    && (opt->ip6po_mh->ip6mh_type != IP6_MH_TYPE_BACK)) {
		goto skip_rthdr2;
	}

	/*
	 * create rthdr2 only if the caller of ip6_output() doesn't
	 * specify rthdr2 adready.
	 */
	if ((opt != NULL) &&
	    (opt->ip6po_rthdr2 != NULL))
		goto skip_rthdr2;

	/*
	 * add the routing header for the route optimization if there
	 * exists a valid binding cache entry for this destination
	 * node.
	 */
	error = mip6_rthdr_create_withdst(&mip6opt->mip6po_rthdr2,
	    &ip6->ip6_dst, opt);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: rthdr creation failed.\n",
		    __FILE__, __LINE__));
		goto bad;
	}
 skip_rthdr2:

#ifdef MIP6_MOBILE_NODE
	/* the following stuff is applied only for a mobile node. */
	if (!MIP6_IS_MN) {
		goto skip_hao;
	}

	/*
	 * find hif that has a home address that is the same
	 * to the source address of this sending ip packet
	 */
	sc = hif_list_find_withhaddr(&ip6->ip6_src);
	if (sc == NULL) {
		/*
		 * this source addrss is not one of our home addresses.
		 * we don't need any special care about this packet.
		 */
		goto skip_hao;
	}

	/*
	 * check home registration status for this destination
	 * address.
	 */
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, &ip6->ip6_dst,
	    &ip6->ip6_src);
	if (mbu == NULL) {
		/* no registration action has been started yet. */
		goto skip_hao;
	}

	if ((opt != NULL) && (opt->ip6po_mh != NULL)) {
		if (opt->ip6po_mh->ip6mh_type == IP6_MH_TYPE_BU)
			need_hao = 1;
		else {
			/*
			 * From 6.1 Mobility Header: "Mobility Header
			 * messages also MUST NOT be used with a Home
			 * Address destination option, except as
			 * described in Section 11.7.1 and Section
			 * 11.7.2 for Binding Update."
			 */
			goto skip_hao;
		}
	}
	if ((mbu->mbu_flags & IP6MU_HOME) != 0) {
		/* to my home agent. */
		if (!need_hao &&
		    (mbu->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_IDLE ||
		     mbu->mbu_pri_fsm_state == MIP6_BU_PRI_FSM_STATE_WAITD))
			goto skip_hao;
	} else {
		/* to any of correspondent nodes. */
		if (!need_hao && !MIP6_IS_BU_BOUND_STATE(mbu))
			goto skip_hao;
	}
	/* create a home address destination option. */
	error = mip6_haddr_destopt_create(&mip6opt->mip6po_haddr,
	    &ip6->ip6_src, &ip6->ip6_dst, sc);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: homeaddress insertion failed.\n",
		    __FILE__, __LINE__));
		goto bad;
	}
 skip_hao:
	error = 0; /* normal exit. */
#endif /* MIP6_MOBILE_NODE */

 bad:
	splx(s);
	return (error);
}

int
mip6_rthdr_create(pktopt_rthdr, coa, opt)
	struct ip6_rthdr **pktopt_rthdr;
	struct in6_addr *coa;
	struct ip6_pktopts *opt;
{
	struct ip6_rthdr2 *rthdr2;
	size_t len;

	/*
	 * Mobile IPv6 uses type 2 routing header for route
	 * optimization. if the packet has a type 1 routing header
	 * already, we must add a type 2 routing header after the type
	 * 1 routing header.
	 */

	len = sizeof(struct ip6_rthdr2)	+ sizeof(struct in6_addr);
	MALLOC(rthdr2, struct ip6_rthdr2 *, len, M_IP6OPT, M_NOWAIT);
	if (rthdr2 == NULL) {
		return (ENOMEM);
	}
	bzero(rthdr2, len);

	/* rthdr2->ip6r2_nxt = will be filled later in ip6_output */
	rthdr2->ip6r2_len = 2;
	rthdr2->ip6r2_type = 2;
	rthdr2->ip6r2_segleft = 1;
	rthdr2->ip6r2_reserved = 0;
	bcopy((caddr_t)coa, (caddr_t)(rthdr2 + 1), sizeof(struct in6_addr));
	*pktopt_rthdr = (struct ip6_rthdr *)rthdr2;

	mip6stat.mip6s_orthdr2++;

	return (0);
}

static int
mip6_rthdr_create_withdst(pktopt_rthdr, dst, opt)
	struct ip6_rthdr **pktopt_rthdr;
	struct in6_addr *dst;
	struct ip6_pktopts *opt;
{
	struct mip6_bc *mbc;
	int error = 0;

	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
	if (mbc == NULL) {
		/* no binding cache entry for this dst is found. */
		return (0);
	}

	error = mip6_rthdr_create(pktopt_rthdr, &mbc->mbc_pcoa, opt);
	if (error) {
		return (error);
	}

	return (0);
}

int
mip6_exthdr_size(src, dst)
	struct in6_addr *src;
	struct in6_addr *dst;
{
	int hdrsiz;
	struct mip6_bc *mbc;

	hdrsiz = 0;
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
	if (mbc != NULL) {
		/* a packet will have RTHDR2. */
		hdrsiz += sizeof(struct ip6_rthdr2) + sizeof(struct in6_addr);
	}

#ifdef MIP6_MOBILE_NODE
	hdrsiz += mip6_mobile_node_exthdr_size(src, dst);
#endif /* MIP6_MOBILE_NODE */

	return (hdrsiz);
}

void
mip6_destopt_discard(mip6opt)
	struct mip6_pktopts *mip6opt;
{
	if (mip6opt->mip6po_rthdr2)
		FREE(mip6opt->mip6po_rthdr2, M_IP6OPT);

	if (mip6opt->mip6po_haddr)
		FREE(mip6opt->mip6po_haddr, M_IP6OPT);

	return;
}

void
mip6_bc_init()
{
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
        callout_init(&mip6_bc_ch, NULL);
#elif defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
        callout_init(&mip6_bc_ch);
#endif
	bzero(&mip6_bc_hash, sizeof(mip6_bc_hash));
}

struct mip6_bc *
mip6_bc_create(phaddr, pcoa, addr, flags, seqno, lifetime, ifp)
	struct in6_addr *phaddr;
	struct in6_addr *pcoa;
	struct in6_addr *addr;
	u_int8_t flags;
	u_int16_t seqno;
	u_int32_t lifetime;
	struct ifnet *ifp;
{
	struct mip6_bc *mbc;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	MALLOC(mbc, struct mip6_bc *, sizeof(struct mip6_bc),
	       M_TEMP, M_NOWAIT);
	if (mbc == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: memory allocation failed.\n",
			 __FILE__, __LINE__));
		return (NULL);
	}
	bzero(mbc, sizeof(*mbc));

	mbc->mbc_phaddr = *phaddr;
	mbc->mbc_pcoa = *pcoa;
	mbc->mbc_addr = *addr;
	mbc->mbc_flags = flags;
	mbc->mbc_seqno = seqno;
	mbc->mbc_lifetime = lifetime;
	mbc->mbc_state = MIP6_BC_FSM_STATE_BOUND;
	mbc->mbc_mpa_exp = time_second;	/* set to current time to send mpa as soon as created it */
	mbc->mbc_ifp = ifp;
	mbc->mbc_llmbc = NULL;
	mbc->mbc_refcnt = 0;
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&mbc->mbc_timer_ch, NULL);
#elif defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_init(&mbc->mbc_timer_ch);
#elif defined(__OpenBSD__)
	timeout_set(&mbc->mbc_timer_ch, mip6_mbc_timer, NULL);
#endif
	mbc->mbc_expire = time_second + lifetime;
	/* sanity check for overflow */
	if (mbc->mbc_expire < time_second)
		mbc->mbc_expire = 0x7fffffff;
	mip6_bc_settimer(mbc, mip6_brr_time(mbc));

	if (mip6_bc_list_insert(&mip6_bc_list, mbc)) {
		FREE(mbc, M_TEMP);
		return (NULL);
	}

	return (mbc);
}


/*
 *  |<---------------------------->|
 *        lifetime                 ^
 *  |<--------------->             mbc->mbc_expire
 *       brrtime
 *
 */
void
mip6_bc_settimer(mbc, t)
	struct mip6_bc *mbc;
	int t;	/* unit: second */
{
	long tick;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	if (t != 0) {
		tick = t * hz;
		if (t < 0) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
			callout_stop(&mbc->mbc_timer_ch);
#elif defined(__OpenBSD__)
			timeout_del(&mbc->mbc_timer_ch);
#else
			untimeout(mip6_bc_timer, mbc;)
#endif
		} else {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
			callout_reset(&mbc->mbc_timer_ch, tick,
			    mip6_bc_timer, mbc);
#elif defined(__OpenBSD__)
			timeout_add(&mbc->mbc_timer_ch, tick);
#else
			timeout(mip6_bc_timer, mbc, tick);
#endif
		}
	}

	splx(s);
}

static int
mip6_bc_delete(mbc)
	struct mip6_bc *mbc;
{
	int error;

	/* a request to delete a binding. */
	if (mbc) {
		error = mip6_bc_list_remove(&mip6_bc_list, mbc);
		if (error) {
			mip6log((LOG_ERR,
				 "%s:%d: can't remove BC.\n",
				 __FILE__, __LINE__));
			return (error);
		}
	} else {
		/* There was no Binding Cache entry */
		/* Is there someting to do ? */
	}

	return (0);
}

static int
mip6_bc_list_insert(mbc_list, mbc)
	struct mip6_bc_list *mbc_list;
	struct mip6_bc *mbc;
{
	int id = MIP6_BC_HASH_ID(&mbc->mbc_phaddr);

	if (mip6_bc_hash[id] != NULL) {
		LIST_INSERT_BEFORE(mip6_bc_hash[id], mbc, mbc_entry);
	} else {
		LIST_INSERT_HEAD(mbc_list, mbc, mbc_entry);
	}
	mip6_bc_hash[id] = mbc;

	mbc->mbc_refcnt++;

	return (0);
}

int
mip6_bc_list_remove(mbc_list, mbc)
	struct mip6_bc_list *mbc_list;
	struct mip6_bc *mbc;
{
	int error = 0;
	int id;

	if ((mbc_list == NULL) || (mbc == NULL)) {
		return (EINVAL);
	}

	id = MIP6_BC_HASH_ID(&mbc->mbc_phaddr);
	if (mip6_bc_hash[id] == mbc) {
		struct mip6_bc *next = LIST_NEXT(mbc, mbc_entry);
		if (next != NULL &&
		    id == MIP6_BC_HASH_ID(&next->mbc_phaddr)) {
			mip6_bc_hash[id] = next;
		} else {
			mip6_bc_hash[id] = NULL;
		}
	}

	mbc->mbc_refcnt--;
	if (mbc->mbc_flags & IP6MU_CLONED) {
		if (mbc->mbc_refcnt > 1)
			return (0);
	} else {
		if (mbc->mbc_refcnt > 0)
			return (0);
	}
	mip6_bc_settimer(mbc, -1);
	LIST_REMOVE(mbc, mbc_entry);
#ifdef MIP6_HOME_AGENT
	if (mbc->mbc_flags & IP6MU_HOME) {
		if (MIP6_IS_BC_DAD_WAIT(mbc)) {
			mip6_dad_stop(mbc);
		} else {
			error = mip6_bc_proxy_control(&mbc->mbc_phaddr,
			    &mbc->mbc_addr, RTM_DELETE);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: can't delete a proxy ND entry "
				    "for %s.\n",
				    __FILE__, __LINE__,
				    ip6_sprintf(&mbc->mbc_phaddr)));
			}
			error = mip6_tunnel_control(MIP6_TUNNEL_DELETE,
			    mbc, mip6_bc_encapcheck, &mbc->mbc_encap);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: tunnel control error (%d)"
				    "for %s.\n",
				    __FILE__, __LINE__, error,
				    ip6_sprintf(&mbc->mbc_phaddr)));
			}
		}
	}
#endif /* MIP6_HOME_AGENT */
	FREE(mbc, M_TEMP);

	return (error);
}

struct mip6_bc *
mip6_bc_list_find_withphaddr(mbc_list, haddr)
	struct mip6_bc_list *mbc_list;
	struct in6_addr *haddr;
{
	struct mip6_bc *mbc;
	int id = MIP6_BC_HASH_ID(haddr);

	for (mbc = mip6_bc_hash[id]; mbc;
	     mbc = LIST_NEXT(mbc, mbc_entry)) {
		if (MIP6_BC_HASH_ID(&mbc->mbc_phaddr) != id)
			return NULL;
		if (IN6_ARE_ADDR_EQUAL(&mbc->mbc_phaddr, haddr))
			break;
	}

	return (mbc);
}

static int
mip6_bc_register(hoa, coa, dst, flags, seqno, lifetime)
	struct in6_addr *hoa;
	struct in6_addr *coa;
	struct in6_addr *dst;
	u_int16_t flags;
	u_int16_t seqno;
	u_int32_t lifetime;
{
	struct mip6_bc *mbc;

	/* create a binding cache entry. */
	mbc = mip6_bc_create(hoa, coa, dst, flags, seqno, lifetime,
	    NULL);
	if (mbc == NULL) {
		mip6log((LOG_ERR,
		    "mip6_bc_register:%d: "
		    "mip6_bc memory allocation failed.\n",
		    __LINE__));
		return (ENOMEM);
	}

	return (0);
}

static int
mip6_bc_update(mbc, coa, dst, flags, seqno, lifetime)
	struct mip6_bc *mbc;
	struct in6_addr *coa;
	struct in6_addr *dst;
	u_int16_t flags;
	u_int16_t seqno;
	u_int32_t lifetime;
{
#ifdef __FreeBSD__
	struct timeval mono_time;
#endif /* __FreeBSD__ */

#if __FreeBSD__
	microtime(&mono_time);
#endif
	/* update a binding cache entry. */
	mbc->mbc_pcoa = *coa;
	mbc->mbc_flags = flags;
	mbc->mbc_seqno = seqno;
	mbc->mbc_lifetime = lifetime;
	mbc->mbc_expire	= mono_time.tv_sec + mbc->mbc_lifetime;
	/* sanity check for overflow */
	if (mbc->mbc_expire < mono_time.tv_sec)
		mbc->mbc_expire = 0x7fffffff;
	mbc->mbc_state = MIP6_BC_FSM_STATE_BOUND;
	mip6_bc_settimer(mbc, -1);
	mip6_bc_settimer(mbc, mip6_brr_time(mbc));

	return (0);
}

int
mip6_bc_send_ba(src, dst, dstcoa, status, seqno, lifetime, refresh, mopt)
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *dstcoa;
	u_int8_t status;
	u_int16_t seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
	struct mip6_mobility_options *mopt;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	struct m_tag *mtag;
	struct ip6aux *ip6a;
	struct ip6_rthdr *pktopt_rthdr;
	int error = 0;

	ip6_initpktopts(&opt);

	m = mip6_create_ip6hdr(src, dst, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: creating ip6hdr failed.\n",
			 __FILE__, __LINE__));
		return (ENOMEM);
	}

	error =  mip6_ip6ma_create(&opt.ip6po_mh, src, dst, dstcoa,
				   status, seqno, lifetime, refresh, mopt);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: ba destopt creation error (%d)\n",
			 __FILE__, __LINE__, error));
		m_freem(m);
		goto free_ip6pktopts;
	}

	/*
	 * when sending a binding ack, we use rthdr2 except when
	 * we are on the home link.
	 */
	if (!IN6_ARE_ADDR_EQUAL(dst, dstcoa)) {
		error = mip6_rthdr_create(&pktopt_rthdr, dstcoa, NULL);
		if (error) {
			mip6log((LOG_ERR,
			    "%s:%d: ba rthdr creation error (%d)\n",
			    __FILE__, __LINE__, error));
			m_freem(m);
			goto free_ip6pktopts;
		}
		opt.ip6po_rthdr2 = pktopt_rthdr;
	}

	mtag = ip6_findaux(m);
	if (mtag) {
		ip6a = (struct ip6aux *)(mtag + 1);
		ip6a->ip6a_flags |= IP6A_NOTUSEBC;
	}

#ifdef MIP6_HOME_AGENT
	/* delete proxy nd entry temprolly */
	if ((status >= IP6_MH_BAS_ERRORBASE) &&
	     IN6_ARE_ADDR_EQUAL(dst, dstcoa)) {
		struct mip6_bc *mbc;

		mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, dst);
		if (mtag && mbc && mbc->mbc_flags & IP6MU_HOME &&
		    (mip6_bc_proxy_control(&mbc->mbc_phaddr, &mbc->mbc_addr, RTM_DELETE) == 0)) {
			ip6a->ip6a_flags |= IP6A_TEMP_PROXYND_DEL;
		}
	}
#endif

	mip6stat.mip6s_oba++;
	mip6stat.mip6s_oba_hist[status]++;
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  );
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: sending ip packet error. (%d)\n",
			 __FILE__, __LINE__, error));
		goto free_ip6pktopts;
	}
 free_ip6pktopts:
	if (opt.ip6po_rthdr2)
		FREE(opt.ip6po_rthdr2, M_IP6OPT);
	if (opt.ip6po_mh)
		FREE(opt.ip6po_mh, M_IP6OPT);

	return (error);
}

static int
mip6_bc_send_brr(mbc)
	struct mip6_bc *mbc;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error;

	ip6_initpktopts(&opt);

	m = mip6_create_ip6hdr(&mbc->mbc_addr, &mbc->mbc_phaddr, IPPROTO_NONE,
	    0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: creating ip6hdr failed.\n",
		    __FILE__, __LINE__));
		return (ENOMEM);
	}

	error = mip6_ip6mr_create(&opt.ip6po_mh, &mbc->mbc_addr,
	    &mbc->mbc_phaddr);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: a binding refresh reqeust message creation error "
		    "(%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
		goto free_ip6pktopts;
	}

	error = ip6_output(m, &opt, NULL, 0, NULL, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  );
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mh)
		FREE(opt.ip6po_mh, M_IP6OPT);

	return (error);
}

#ifdef __FreeBSD__
extern struct inpcbhead tcb;
#endif
#ifdef __NetBSD__
extern struct in6pcb tcb6;
#endif
static int
mip6_bc_need_brr(mbc)
	struct mip6_bc *mbc;
{
	int found;
	struct in6_addr *src, *dst;
#ifdef __FreeBSD__
	struct inpcb *inp;
#endif
#ifdef __NetBSD__
	struct in6pcb *inp;
#endif

	found = 0;
	src = &mbc->mbc_addr;
	dst = &mbc->mbc_phaddr;

#ifdef __FreeBSD__
	for (inp = LIST_FIRST(&tcb); inp; inp = LIST_NEXT(inp, inp_list)) {
		if ((inp->inp_vflag & INP_IPV6) == 0)
			continue;
		if (IN6_ARE_ADDR_EQUAL(src, &inp->in6p_laddr)
		    && IN6_ARE_ADDR_EQUAL(dst, &inp->in6p_faddr)) {
			found++;
			break;
		}
	}
#endif
#ifdef __NetBSD__
	for (inp = &tcb6; inp != &tcb6; inp = inp->in6p_next) {
		if (IN6_ARE_ADDR_EQUAL(src, &inp->in6p_laddr)
		    && IN6_ARE_ADDR_EQUAL(dst, &inp->in6p_faddr)) {
			found++;
			break;
		}
	}
#endif

	return (found);
}

u_int
mip6_brr_time(mbc)
	struct mip6_bc *mbc;
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	switch (mbc->mbc_state) {
	case MIP6_BC_FSM_STATE_BOUND:
		if (mip6_brr_mode == MIP6_BRR_SEND_EXPONENT) 
			return ((mbc->mbc_expire - mbc->mbc_lifetime / 2) - time_second);
		else
			return ((mbc->mbc_expire - 
				mip6_brr_tryinterval * mip6_brr_maxtries) - time_second);
		break;
	case MIP6_BC_FSM_STATE_WAITB:
		if (mip6_brr_mode == MIP6_BRR_SEND_EXPONENT) 
			return (mbc->mbc_expire - time_second) / 2;
		else
			return (mip6_brr_tryinterval < mbc->mbc_expire - time_second 
				? mip6_brr_tryinterval : mbc->mbc_expire - time_second);
		break;
	}

	return (0); /* XXX; not reach */
}

static void
mip6_bc_timer(arg)
	void *arg;
{
	int s;
	u_int brrtime;
	struct mip6_bc *mbc = arg;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	switch (mbc->mbc_state) {
	case MIP6_BC_FSM_STATE_BOUND:
		mbc->mbc_state = MIP6_BC_FSM_STATE_WAITB;
		mbc->mbc_brr_sent = 0;
		/* No break; */
	case MIP6_BC_FSM_STATE_WAITB:
		if (mip6_bc_need_brr(mbc) &&
		    (mbc->mbc_brr_sent < mip6_brr_maxtries)) {
			brrtime = mip6_brr_time(mbc);
			if (brrtime == 0) {
				mbc->mbc_state = MIP6_BC_FSM_STATE_WAITB2;
			} else {
				mip6_bc_send_brr(mbc);
			}
			mip6_bc_settimer(mbc, mip6_brr_time(mbc));
			mbc->mbc_brr_sent++;
		} else {
			mbc->mbc_state = MIP6_BC_FSM_STATE_WAITB2;
			mip6_bc_settimer(mbc, mbc->mbc_expire - time_second);
		}
		break;
	case MIP6_BC_FSM_STATE_WAITB2:
#ifdef MIP6_HOME_AGENT
		if (mbc->mbc_flags & IP6MU_CLONED) {
			/*
			 * cloned entry is removed
			 * when the last referring mbc
			 * is removed.
			 */
			break;
		}
		if (mbc->mbc_llmbc != NULL) {
			/* remove a cloned entry. */
			if (mip6_bc_list_remove(
			    &mip6_bc_list, mbc->mbc_llmbc) != 0) {
				mip6log((LOG_ERR,
				    "%s:%d: failed to remove "
				    "a cloned binding cache entry.\n",
				    __FILE__, __LINE__));
			}
		}
#endif /* MIP6_HOME_AGENT */
		mip6_bc_list_remove(&mip6_bc_list, mbc);
		break;
	}

	splx(s);
}

static void
mip6_create_nonce(nonce)
	mip6_nonce_t *nonce;
{
	int i;

	for (i = 0; i < MIP6_NONCE_SIZE / sizeof(u_long); i++)
		((u_long *)nonce)[i] = random();
}

static void
mip6_create_nodekey(nodekey)
	mip6_nodekey_t *nodekey;
{
	int i;

	for (i = 0; i < MIP6_NODEKEY_SIZE / sizeof(u_long); i++)
		((u_long *)nodekey)[i] = random();
}

/* This function should be called periodically */
static void
mip6_update_nonce_nodekey(ignored_arg)
	void	*ignored_arg;
{
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_reset(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD,
		      mip6_update_nonce_nodekey, NULL);
#elif defined(__OpenBSD__)
	timeout_add(&mip6_nonce_upd_ch, hz * NONCE_UPDATE_PERIOD);
#else
	timeout(mip6_update_nonce_nodekey, (caddr_t)0,
		hz * NONCE_UPDATE_PERIOD);
#endif

	nonce_index++;
	if (++nonce_head >= mip6_nonce + MIP6_NONCE_HISTORY)
		nonce_head = mip6_nonce;

	mip6_create_nonce(nonce_head);
	mip6_create_nodekey(mip6_nodekey + (nonce_head - mip6_nonce));

	splx(s);
}

int
mip6_get_nonce(index, nonce)
	u_int16_t index;	/* nonce index */
	mip6_nonce_t *nonce;
{
	int32_t offset;

	offset = index - nonce_index;
	if (offset > 0) {
		/* nonce_index was wrapped. */
		offset = offset - 0xffff;
	}

	if (offset <= -MIP6_NONCE_HISTORY) {
		/* too old index. */
		return (-1);
	}
		
	if (nonce_head + offset < mip6_nonce)
		offset = nonce_head - mip6_nonce - offset;

	bcopy(nonce_head + offset, nonce, sizeof(mip6_nonce_t));
	return (0);
}

int
mip6_get_nodekey(index, nodekey)
	u_int16_t index;	/* nonce index */
	mip6_nodekey_t *nodekey;
{
	int32_t offset;
	mip6_nodekey_t *nodekey_head;

	offset = index - nonce_index;
	if (offset > 0) {
		/* nonce_index was wrapped. */
		offset = offset - 0xffff;
	}

	if (offset <= -MIP6_NONCE_HISTORY) {
		/* too old index. */
		return (-1);
	}
		
	if (nonce_head + offset < mip6_nonce)
		offset = nonce_head - mip6_nonce - offset;

	nodekey_head = mip6_nodekey + (nonce_head - mip6_nonce);
	bcopy(nodekey_head + offset, nodekey, sizeof(mip6_nodekey_t));

	return (0);
}

/* Generate keygen */
#ifndef __OpenBSD__
int
mip6_create_keygen_token(addr, nodekey, nonce, hc, token)
	struct in6_addr *addr;
	mip6_nodekey_t *nodekey;
	mip6_nonce_t *nonce;
	u_int8_t hc;
	void *token;		/* 64 bit */
{
	/* keygen token = HMAC_SHA1(Kcn, addr | nonce | hc) */
	HMAC_CTX hmac_ctx;
	u_int8_t result[HMACSIZE];

	hmac_init(&hmac_ctx, (u_int8_t *)nodekey,
		  sizeof(mip6_nodekey_t), HMAC_SHA1);
	hmac_loop(&hmac_ctx, (u_int8_t *)addr, sizeof(struct in6_addr));
	hmac_loop(&hmac_ctx, (u_int8_t *)nonce, sizeof(mip6_nonce_t));
	hmac_loop(&hmac_ctx, (u_int8_t *)&hc, sizeof(hc));
	hmac_result(&hmac_ctx, result, sizeof(result));
	/* First64 */
	bcopy(result, token, 8);

	return (0);
}
#else /* OpenBSD */
int
mip6_create_keygen_token(addr, nodekey, nonce, hc, token)
	struct in6_addr *addr;
	mip6_nodekey_t *nodekey;
	mip6_nonce_t *nonce;
	u_int8_t hc;
	void *token;		/* 64 bit */
{
	struct cryptoini cria;
	struct cryptop *crp;
	u_int64_t sid = 0;
	int error = 0;
	static int mip6_create_keygen_token_cb(void *);

	bzero(&cria, sizeof(cria));
	cria.cri_alg = CRYPTO_SHA1_HMAC;
	cria.cri_klen = sizeof(mip6_nodekey_t) * 8;	/* bit */
	cria.cri_key = (caddr_t)nodekey;

	if ((error = crypto_newsession(&sid, &cria, 0))) {
		return (error);
	}

	if ((crp = malloc(sizeof(struct cryptop), M_TEMP, M_WAITOK)) == NULL) {
		error = ENOMEM;
		goto done;
	}
	bzero(crp, sizeof(crp));
	crp->crp_ilen = sizeof(*addr) + sizeof(*nonce) + sizeof(hc);
	crp->crp_olen = HMACSIZE;
	crp->crp_flags = 0;
	if ((crp->crp_buf = malloc(crp->crp_ilen, M_TEMP, M_WAITOK)) == NULL) {
		free(crp, M_TEMP);
		error = ENOMEM;
		goto done;
	}
	bzero(crp->crp_buf, crp->crp_ilen);
	bcopy(addr, crp->crp_buf, sizeof(*addr));
	bcopy(nonce, crp->crp_buf + sizeof(*addr), sizeof(*nonce));
	bcopy(&hc, crp->crp_buf + sizeof(*addr) + sizeof(*nonce), sizeof(hc));
	crp->crp_callback = (int (*) (struct cryptop *)) mip6_create_keygen_token_cb;
	crp->crp_sid = sid;
	crp->crp_opaque = NULL;
	crypto_dispatch(crp);

	if (tsleep(crp, PSOCK, "mip6keygen", 0)) {
		free(crp->crp_buf, M_TEMP);
		free(crp, M_TEMP);
		error = EINVAL;
	}

	/* First64 */
	bcopy(crp->crp_buf, token, 8);

done:
	
	crypto_freesession(sid);
	return (error);
}

static int
mip6_create_keygen_token_cb(void *op)
{
	struct cryptop *crp;

	crp = (struct cryptop *)op;
	wakeup(crp);
	return (0);
}
#endif

/*
 *	Check a Binding Update packet whether it is valid 
 */
int
mip6_is_valid_bu(ip6, ip6mu, ip6mulen, mopt, hoa, coa, cache_req, status)
	struct ip6_hdr *ip6;
	struct ip6_mh_binding_update *ip6mu;
	int ip6mulen;
	struct mip6_mobility_options *mopt;
	struct in6_addr *hoa, *coa;
	int cache_req;	/* true if this request is cacheing */
	u_int8_t *status;
{
	u_int8_t key_bm[MIP6_KBM_LEN]; /* Stated as 'Kbm' in the spec */
	u_int8_t authdata[SHA1_RESULTLEN];
	u_int16_t cksum_backup;

	*status = IP6_MH_BAS_ACCEPTED;
	/* Nonce index & Auth. data mobility options are required */
	if ((mopt->valid_options & (MOPT_NONCE_IDX | MOPT_AUTHDATA)) 
	     != (MOPT_NONCE_IDX | MOPT_AUTHDATA)) {
		mip6log((LOG_ERR,
		    "mip6_is_valid_bu:%d: "
		    "Nonce or Authdata is missed. (%02x)\n",
		    __LINE__, mopt->valid_options));
		return (EINVAL);
	}
	if ((*status = mip6_calculate_kbm_from_index(hoa, coa,
	    mopt->mopt_ho_nonce_idx, mopt->mopt_co_nonce_idx,
	    !cache_req, key_bm))) {
		return (EINVAL);
	}

	cksum_backup = ip6mu->ip6mhbu_cksum;
	ip6mu->ip6mhbu_cksum = 0;
	/* Calculate authenticator */
	if (mip6_calculate_authenticator(key_bm, authdata, coa, &ip6->ip6_dst,
	    (caddr_t)ip6mu, ip6mulen,
	    (u_int8_t *)mopt->mopt_auth + sizeof(struct ip6_mh_opt_auth_data) - (u_int8_t *)ip6mu, 
	    MOPT_AUTH_LEN(mopt) + 2)) {
		return (EINVAL);
	}

	ip6mu->ip6mhbu_cksum = cksum_backup;

	return (bcmp(mopt->mopt_auth + 2, authdata, MOPT_AUTH_LEN(mopt)));
}

int
mip6_calculate_kbm_from_index(hoa, coa, ho_nonce_idx, co_nonce_idx, ignore_co_nonce, key_bm)
	struct in6_addr *hoa;
	struct in6_addr *coa;
	u_int16_t ho_nonce_idx;	/* Home Nonce Index */
	u_int16_t co_nonce_idx;	/* Care-of Nonce Index */
	int ignore_co_nonce;
	u_int8_t *key_bm;	/* needs at least MIP6_KBM_LEN bytes */
{
	int stat = IP6_MH_BAS_ACCEPTED;
	mip6_nonce_t home_nonce, careof_nonce;
	mip6_nodekey_t home_nodekey, coa_nodekey;
	mip6_home_token_t home_token;
	mip6_careof_token_t careof_token;

	if (mip6_get_nonce(ho_nonce_idx, &home_nonce) != 0) {
		mip6log((LOG_ERR,
		    "mip6_calculate_kbm_from_index:%d: "
		    "Home Nonce cannot be acquired.\n",
		    __LINE__));
		stat =IP6_MH_BAS_HOME_NI_EXPIRED;
	}
	if (!ignore_co_nonce && 
	    mip6_get_nonce(co_nonce_idx, &careof_nonce) != 0) {
		mip6log((LOG_ERR,
		    "mip6_calculate_kbm_from_index:%d: "
		    "Care-of Nonce cannot be acquired.\n",
		    __LINE__));
		stat = (stat == IP6_MH_BAS_ACCEPTED) ? 
		    IP6_MH_BAS_COA_NI_EXPIRED : IP6_MH_BAS_NI_EXPIRED;
	}
	if (stat != IP6_MH_BAS_ACCEPTED)
		return (stat);
#ifdef RR_DBG
	mip6_hexdump("CN: Home   Nonce: ", sizeof(home_nonce), &home_nonce);
	mip6_hexdump("CN: Careof Nonce: ", sizeof(careof_nonce), &careof_nonce);
#endif

	if ((mip6_get_nodekey(ho_nonce_idx, &home_nodekey) != 0) ||
	    (!ignore_co_nonce && 
		(mip6_get_nodekey(co_nonce_idx, &coa_nodekey) != 0))) {
		mip6log((LOG_ERR,
		    "mip6_calculate_kbm_from_index:%d: "
		    "home or care-of node key cannot be acquired.\n",
		    __LINE__));
		return (IP6_MH_BAS_NI_EXPIRED);
	}
#ifdef RR_DBG
mip6_hexdump("CN: Home   Nodekey: ", sizeof(home_nodekey), &home_nodekey);
mip6_hexdump("CN: Careof Nodekey: ", sizeof(coa_nodekey), &coa_nodekey);
#endif

	/* Calculate home keygen token */
	if (mip6_create_keygen_token(hoa, &home_nodekey, &home_nonce, 0,
		&home_token)) {
		mip6log((LOG_ERR,
		    "mip6_calculate_kbm_from_index:%d: "
		    "Failed of creation of home keygen token\n",
		    __LINE__));
		return (IP6_MH_BAS_UNSPECIFIED);
	}
#ifdef RR_DBG
mip6_hexdump("CN: Home keygen token: ", sizeof(home_token), (u_int8_t *)&home_token);
#endif

	if (!ignore_co_nonce) {
		/* Calculate care-of keygen token */
		if (mip6_create_keygen_token(coa, &coa_nodekey, &careof_nonce,
			1, &careof_token)) {
			mip6log((LOG_ERR,
			    "mip6_calculate_kbm_from_index:%d: "
			    "Failed of creation of care-of keygen token\n",
			    __LINE__));
			return (IP6_MH_BAS_UNSPECIFIED);
		}
#ifdef RR_DBG
mip6_hexdump("CN: Care-of keygen token: ", sizeof(careof_token), (u_int8_t *)&careof_token);
#endif
	}

	/* Calculate K_bm */
	mip6_calculate_kbm(&home_token, ignore_co_nonce ? NULL : &careof_token,
	    key_bm);
#ifdef RR_DBG
mip6_hexdump("CN: K_bm: ", sizeof(key_bm), key_bm);
#endif

	return (IP6_MH_BAS_ACCEPTED);
}

void
mip6_calculate_kbm(home_token, careof_token, key_bm)
	mip6_home_token_t *home_token;
	mip6_careof_token_t *careof_token;	/* could be null */
	u_int8_t *key_bm;	/* needs at least MIP6_KBM_LEN bytes */
{
	SHA1_CTX sha1_ctx;
	u_int8_t result[SHA1_RESULTLEN];

	SHA1Init(&sha1_ctx);
	SHA1Update(&sha1_ctx, (caddr_t)home_token, sizeof(*home_token));
	if (careof_token)
		SHA1Update(&sha1_ctx, (caddr_t)careof_token, sizeof(*careof_token));
	SHA1Final(result, &sha1_ctx);
	/* First 128 bit */
	bcopy(result, key_bm, MIP6_KBM_LEN);
}

/*
 *   <------------------ datalen ------------------->
 *                  <-- exclude_data_len ---> 
 *   ---------------+-----------------------+--------
 *   ^              <--                   -->
 *   data     The area excluded from calculation Auth.
 *   - - - - - - - ->
 *     exclude_offset
 */
#ifndef __OpenBSD__
int
mip6_calculate_authenticator(key_bm, result, addr1, addr2, data, datalen,
    exclude_offset, exclude_data_len)
	u_int8_t *key_bm;		/* Kbm */
	u_int8_t *result;
	struct in6_addr *addr1, *addr2;
	caddr_t data;
	size_t datalen;
	int exclude_offset;
	size_t exclude_data_len;
{
	HMAC_CTX hmac_ctx;
	int restlen;
	u_int8_t sha1_result[SHA1_RESULTLEN];

	/* Calculate authenticator (5.5.6) */
	/* MAC_Kbm(addr1, | addr2 | (BU|BA) ) */
	hmac_init(&hmac_ctx, key_bm, MIP6_KBM_LEN, HMAC_SHA1);
	hmac_loop(&hmac_ctx, (u_int8_t *)addr1, sizeof(*addr1));
#ifdef RR_DBG
	mip6_hexdump("Auth: ", sizeof(*addr1), addr1);
#endif
	hmac_loop(&hmac_ctx, (u_int8_t *)addr2, sizeof(*addr2));
#ifdef RR_DBG
	mip6_hexdump("MN: Auth: ", sizeof(*addr2), addr2);
#endif
	hmac_loop(&hmac_ctx, (u_int8_t *)data, exclude_offset);
#ifdef RR_DBG
	mip6_hexdump("MN: Auth: ", exclude_offset, data);
#endif

	/* Exclude authdata field in the mobility option to calculate authdata 
	   But it should be included padding area */
	restlen = datalen - (exclude_offset + exclude_data_len);
	if (restlen > 0) {
		hmac_loop(&hmac_ctx,
			  data + exclude_offset + exclude_data_len,
			  restlen);
#ifdef RR_DBG
		mip6_hexdump("MN: Auth: ", restlen, 
			data + exclude_offset + exclude_data_len);
#endif
	}
	hmac_result(&hmac_ctx, sha1_result, sizeof(sha1_result));
	/* First(96, sha1_result) */
	bcopy(sha1_result, result, MIP6_AUTHENTICATOR_LEN);
#ifdef RR_DBG
	mip6_hexdump("MN: Authdata: ", MIP6_AUTHENTICATOR_LEN, result);
#endif

	return (0);
}
#else	/* !__OpenBSD __*/
int
mip6_calculate_authenticator(key_bm, result, addr1, addr2, data, datalen,
    exclude_offset, exclude_data_len)
	u_int8_t *key_bm;		/* Kbm */
	u_int8_t *result;
	struct in6_addr *addr1, *addr2;
	caddr_t data;
	size_t datalen;
	int exclude_offset;
	size_t exclude_data_len;
{
	struct cryptoini cria;
	struct cryptop *crp;
	u_int64_t sid = 0;
	int error = 0;
	int restlen;
	caddr_t p;
	static int mip6_calculate_authenticator_cb(void *);

	bzero(&cria, sizeof(cria));
	cria.cri_alg = CRYPTO_SHA1_HMAC;
	cria.cri_klen = MIP6_KBM_LEN * 8;	/* bit */
	cria.cri_key = key_bm;

	if ((error = crypto_newsession(&sid, &cria, 0))) {
		return (error);
	}

	if ((crp = malloc(sizeof(struct cryptop), M_TEMP, M_WAITOK)) == NULL) {
		error = ENOMEM;
		goto done;
	}
	restlen = datalen - (exclude_offset + exclude_data_len);
	bzero(crp, sizeof(crp));
	crp->crp_ilen = sizeof(*addr1) + sizeof(*addr2) + exclude_offset + restlen;
	crp->crp_olen = HMACSIZE;
	crp->crp_flags = 0;
	if ((crp->crp_buf = malloc(crp->crp_ilen, M_TEMP, M_WAITOK)) == NULL) {
		free(crp, M_TEMP);
		error = ENOMEM;
		goto done;
	}
	bzero(crp->crp_buf, crp->crp_ilen);

	p = crp->crp_buf;
	bcopy(addr1, p, sizeof(*addr1)); p += sizeof(*addr1);
	bcopy(addr2, p, sizeof(*addr2)); p += sizeof(*addr2);
	bcopy(data, p, exclude_offset); p += exclude_offset;
	/* Exclude authdata field in the mobility option to calculate authdata 
	   But it should be included padding area */
	if (restlen > 0) {
		bcopy(data + exclude_offset + exclude_data_len, p, restlen); p += restlen;
	}
	crp->crp_callback = (int (*) (struct cryptop *)) mip6_calculate_authenticator_cb;
	crp->crp_sid = sid;
	crp->crp_opaque = NULL;
	crypto_dispatch(crp);

	if (tsleep(crp, PSOCK, "mip6keygen", 0)) {
		/* Never happen ... */
		free(crp->crp_buf, M_TEMP);
		free(crp, M_TEMP);
		error = EINVAL;
	}
	/* First(96, sha1_result) */
	bcopy(crp->crp_buf, result, MIP6_AUTHENTICATOR_LEN);

done:
	crypto_freesession(sid);
	return (error);
}

static int
mip6_calculate_authenticator_cb(void *op)
{
	struct cryptop *crp;

	crp = (struct cryptop *)op;
	wakeup(crp);
	return (0);
}
#endif	/* !__OpenBSD__ */

int
mip6_ip6mhi_input(m0, ip6mhi, ip6mhilen)
	struct mbuf *m0;
	struct ip6_mh_home_test_init *ip6mhi;
	int ip6mhilen;
{
	struct ip6_hdr *ip6;
	struct mbuf *m;
	struct m_tag *mtag;
	struct ip6aux *ip6a;
	struct ip6_pktopts opt;
	int error = 0;

	mip6stat.mip6s_hoti++;

	ip6 = mtod(m0, struct ip6_hdr *);

	/* packet length check. */
	if (ip6mhilen < sizeof(struct ip6_mh_home_test_init)) {
		mip6log((LOG_NOTICE,
		    "mip6_ip6mhi_input:%d: "
		    "too short home test init (len = %d) from host %s.\n",
		    __LINE__, ip6mhilen, ip6_sprintf(&ip6->ip6_src)));
		ip6stat.ip6s_toosmall++;
		/* send an ICMP parameter problem. */
		icmp6_error(m0, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
		    (caddr_t)&ip6mhi->ip6mhhti_len - (caddr_t)ip6);
		return (EINVAL);
	}

	/* a home address destination option must not exist. */
	mtag = ip6_findaux(m0);
	if (mtag) {
		ip6a = (struct ip6aux *) (mtag + 1);
		if ((ip6a->ip6a_flags & IP6A_HASEEN) != 0) {
			mip6log((LOG_NOTICE,
			    "mip6_ip6mhi_input:%d: "
			    "recieved a home test init with "
			    "a home address destination option.\n",
			    __LINE__));
			m_freem(m0);
			/* stat? */
			return (EINVAL);
		}
	}

	m = mip6_create_ip6hdr(&ip6->ip6_dst, &ip6->ip6_src, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "mip6_ip6mhi_input:%d: creating ip6hdr failed.\n",
		    __LINE__));
 		goto free_ip6pktopts;
	}

	ip6_initpktopts(&opt);
	error = mip6_ip6mh_create(&opt.ip6po_mh, &ip6->ip6_dst, &ip6->ip6_src,
	    ip6mhi->ip6mhhti_cookie8);
	if (error) {
		mip6log((LOG_ERR,
		    "mip6_ip6mhi_input:%d: HoT creation error (%d)\n",
		    __LINE__, error));
		m_freem(m);
 		goto free_ip6pktopts;
	}

	mip6stat.mip6s_ohot++;
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  );
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
 		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mh != NULL)
		FREE(opt.ip6po_mh, M_IP6OPT);

	return (0);
}

int
mip6_ip6mci_input(m0, ip6mci, ip6mcilen)
	struct mbuf *m0;
	struct ip6_mh_careof_test_init *ip6mci;
	int ip6mcilen;
{
	struct ip6_hdr *ip6;
	struct mbuf *m;
	struct m_tag *mtag;
	struct ip6aux *ip6a;
	struct ip6_pktopts opt;
	int error = 0;

	mip6stat.mip6s_coti++;

	ip6 = mtod(m0, struct ip6_hdr *);

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src)) {
		m_freem(m0);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6mcilen < sizeof(struct ip6_mh_careof_test_init)) {
		mip6log((LOG_NOTICE,
		    "mip6_ip6mci_input:%d: "
		    "too short care-of test init (len = %d) from host %s.\n",
		    __LINE__, ip6mcilen, ip6_sprintf(&ip6->ip6_src)));
		ip6stat.ip6s_toosmall++;
		/* send ICMP parameter problem. */
		icmp6_error(m0, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
		    (caddr_t)&ip6mci->ip6mhcti_len - (caddr_t)ip6);
		return (EINVAL);
	}

	/* a home address destination option must not exist. */
	mtag = ip6_findaux(m0);
	if (mtag) {
		ip6a = (struct ip6aux *) (mtag + 1);
		if ((ip6a->ip6a_flags & IP6A_HASEEN) != 0) {
			mip6log((LOG_NOTICE,
			    "mip6_ip6mci_input:%d: "
			    "recieved a care-of test init with "
			    "a home address destination option.\n",
			    __LINE__));
			m_freem(m0);
			/* stat? */
			return (EINVAL);
		}
	}

	m = mip6_create_ip6hdr(&ip6->ip6_dst, &ip6->ip6_src, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "mip6_ip6mci_input:%d: creating ip6hdr failed.\n",
		    __LINE__));
 		goto free_ip6pktopts;
	}

	ip6_initpktopts(&opt);
	error = mip6_ip6mc_create(&opt.ip6po_mh, &ip6->ip6_dst, &ip6->ip6_src,
	    ip6mci->ip6mhcti_cookie8);
	if (error) {
		mip6log((LOG_ERR,
		    "mip6_ip6mci_input:%d: HoT creation error (%d)\n",
		    __LINE__, error));
		m_freem(m);
 		goto free_ip6pktopts;
	}

	mip6stat.mip6s_ocot++;
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL
#if defined(__FreeBSD__) && __FreeBSD_version >= 480000
			   , NULL
#endif
			  );
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
 		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mh != NULL)
		FREE(opt.ip6po_mh, M_IP6OPT);

	return (0);
}

#define IS_REQUEST_TO_CACHE(lifetime, hoa, coa)	\
	(((lifetime) != 0) &&			\
	 (!IN6_ARE_ADDR_EQUAL((hoa), (coa))))
int
mip6_ip6mu_input(m, ip6mu, ip6mulen)
	struct mbuf *m;
	struct ip6_mh_binding_update *ip6mu;
	int ip6mulen;
{
	struct ip6_hdr *ip6;
	struct m_tag *mtag;
	struct ip6aux *ip6a = NULL;
	u_int8_t isprotected = 0;
	struct mip6_bc *mbc;

	int error = 0;
	u_int8_t bu_safe = 0;	/* To accept bu always without authentication, this value is set to non-zero */
	struct mip6_mobility_options mopt;
	struct mip6_bc bi;

	mip6stat.mip6s_bu++;
	bzero(&bi, sizeof(bi));
	bi.mbc_status = IP6_MH_BAS_ACCEPTED;
	/*
	 * we send a binding ack immediately when this binding update
	 * is not a request for home registration and has an ACK bit
	 * on.
	 */
	bi.mbc_send_ba = ((ip6mu->ip6mhbu_flags & IP6MU_ACK)
	    && !(ip6mu->ip6mhbu_flags & IP6MU_HOME));

#ifdef IPSEC
	/*
	 * Check ESP(IPsec)
	 */
	if (ipsec6_in_reject(m, NULL)) {
		ipsec6stat.in_polvio++;
		m_freem(m);
		mip6stat.mip6s_unprotected++;
		return (EINVAL);	/* XXX */
	}
#endif /* IPSEC */

	ip6 = mtod(m, struct ip6_hdr *);
	bi.mbc_addr = ip6->ip6_dst;

	/* packet length check. */
	if (ip6mulen < sizeof(struct ip6_mh_binding_update)) {
		mip6log((LOG_NOTICE,
		    "mip6_ip6mu_input:%d: too short binding update (len = %d) "
		    "from host %s.\n",
		    __LINE__, ip6mulen, ip6_sprintf(&ip6->ip6_src)));
		ip6stat.ip6s_toosmall++;
		/* send ICMP parameter problem. */
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
		    (caddr_t)&ip6mu->ip6mhbu_len - (caddr_t)ip6);
		return (EINVAL);
	}

	bi.mbc_flags = ip6mu->ip6mhbu_flags;

#ifdef M_DECRYPTED	/* not openbsd */
	if (((m->m_flags & M_DECRYPTED) != 0)
	    || ((m->m_flags & M_AUTHIPHDR) != 0)) {
		isprotected = 1;
	}
#endif
#ifdef __OpenBSD__
	if ((m->m_flags & M_AUTH) != 0) {
		isprotected = 1;
	}
#endif

	bi.mbc_pcoa = ip6->ip6_src;
	mtag = ip6_findaux(m);
	if (mtag == NULL) {
		m_freem(m);
		return (EINVAL);
	}
	ip6a = (struct ip6aux *) (mtag + 1);
	if (((ip6a->ip6a_flags & IP6A_HASEEN) != 0) && 
	    ((ip6a->ip6a_flags & IP6A_SWAP) != 0)) {
		bi.mbc_pcoa = ip6a->ip6a_coa;
	}

	if (!mip6ctl_use_ipsec && (bi.mbc_flags & IP6MU_HOME)) {
		bu_safe = 1;
		goto accept_binding_update;
	}

	if (isprotected) {
		bu_safe = 1;
		goto accept_binding_update;
	}
	if ((bi.mbc_flags & IP6MU_HOME) == 0)
		goto accept_binding_update;	/* Must be checked its safety
						 * with RR later */

	/* otherwise, discard this packet. */
	m_freem(m);
	mip6stat.mip6s_haopolicy++;
	return (EINVAL);

 accept_binding_update:

	/* get home address. */
	bi.mbc_phaddr = ip6->ip6_src;

	if ((error = mip6_get_mobility_options((struct ip6_mh *)ip6mu,
		 sizeof(*ip6mu), ip6mulen, &mopt))) {
		/* discard. */
		m_freem(m);
		mip6stat.mip6s_invalidopt++;
		return (EINVAL);
	}

	if (mopt.valid_options & MOPT_ALTCOA)
		bi.mbc_pcoa = mopt.mopt_altcoa;

	if (IN6_IS_ADDR_MULTICAST(&bi.mbc_pcoa) ||
	    IN6_IS_ADDR_UNSPECIFIED(&bi.mbc_pcoa) ||
	    IN6_IS_ADDR_V4MAPPED(&bi.mbc_pcoa) ||
	    IN6_IS_ADDR_V4COMPAT(&bi.mbc_pcoa) ||
	    IN6_IS_ADDR_LOOPBACK(&bi.mbc_pcoa)) {
		/* discard. */
		m_freem(m);
		mip6stat.mip6s_invalidcoa++;
		return (EINVAL);
	}

	if ((mopt.valid_options & MOPT_AUTHDATA) &&
	    ((mopt.mopt_auth + IP6MOPT_AUTHDATA_SIZE) - (caddr_t)ip6mu < ip6mulen)) {
		/* Auth. data options is not the last option */
		/* discard. */
		m_freem(m);
		/* XXX Statistics */
		return (EINVAL);
	}


	if ((mopt.valid_options & (MOPT_AUTHDATA | MOPT_NONCE_IDX)) &&
	    (ip6mu->ip6mhbu_flags & IP6MU_HOME)) {
		/* discard. */
		m_freem(m);
		mip6stat.mip6s_invalidopt++;	/* XXX */
		return (EINVAL);
	}

	bi.mbc_seqno = ntohs(ip6mu->ip6mhbu_seqno);
	bi.mbc_lifetime = ntohs(ip6mu->ip6mhbu_lifetime) << 2;	/* units of 4 secs */
	/* XXX Should this check be done only when this bu is confirmed with RR ? */
	if (bi.mbc_lifetime > MIP6_MAX_RR_BINDING_LIFE)
		bi.mbc_lifetime = MIP6_MAX_RR_BINDING_LIFE;

	if (IS_REQUEST_TO_CACHE(bi.mbc_lifetime, &bi.mbc_phaddr, &bi.mbc_pcoa)
	    && mip6_bc_list_find_withphaddr(&mip6_bc_list, &bi.mbc_pcoa)) {
		/* discard */
		m_freem(m);
		mip6stat.mip6s_circularrefered++;	/* XXX */
		return (EINVAL);
	}
	if (!bu_safe && 
	    mip6_is_valid_bu(ip6, ip6mu, ip6mulen, &mopt, &bi.mbc_phaddr,
		&bi.mbc_pcoa, IS_REQUEST_TO_CACHE(bi.mbc_lifetime,
		    &bi.mbc_phaddr, &bi.mbc_pcoa), &bi.mbc_status)) {
		mip6log((LOG_ERR,
		    "mip6_ip6mu_input:%d: RR authentication was failed.\n",
		    __LINE__));
		/* discard. */
		m_freem(m);
		mip6stat.mip6s_rrauthfail++;
		if (bi.mbc_status >= IP6_MH_BAS_HOME_NI_EXPIRED &&
		    bi.mbc_status <= IP6_MH_BAS_NI_EXPIRED) {
			bi.mbc_send_ba = 1;
	 		error = EINVAL;
			goto send_ba;
		}
		return (EINVAL);
	}

	/* ip6_src and HAO has been already swapped at this point. */
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &bi.mbc_phaddr);
	if (mbc != NULL) {
		/* check a sequence number. */
		if (MIP6_LEQ(bi.mbc_seqno, mbc->mbc_seqno)) {
			mip6log((LOG_NOTICE,
			    "%s:%d: received sequence no (%d) <= current "
			    "seq no (%d) in BU from host %s.\n",
			    __FILE__, __LINE__, bi.mbc_seqno, mbc->mbc_seqno,
			    ip6_sprintf(&ip6->ip6_src)));
			/*
			 * the seqno of this binding update is smaller than the
			 * corresponding binding cache.  we send TOO_SMALL
			 * binding ack as an error.  in this case, we use the
			 * coa of the incoming packet instead of the coa
			 * stored in the binding cache as a destination
			 * addrress.  because the sending mobile node's coa
			 * might have changed after it had registered before.
			 */
			bi.mbc_status = IP6_MH_BAS_SEQNO_BAD;
			bi.mbc_seqno = mbc->mbc_seqno;
			bi.mbc_send_ba = 1;
			error = EINVAL;

			/* discard. */
			m_freem(m);
			mip6stat.mip6s_seqno++;
			goto send_ba;
		}
		if ((bi.mbc_flags & IP6MU_HOME) ^ (mbc->mbc_flags & IP6MU_HOME)) {
			/* 9.5.1 */
			bi.mbc_status = IP6_MH_BAS_REG_NOT_ALLOWED;
			bi.mbc_send_ba = 1;
			error = EINVAL;

			/* discard. */
			m_freem(m);
			goto send_ba;
		}
	}

	if (ip6mu->ip6mhbu_flags & IP6MU_HOME) {
		/* request for the home (un)registration. */
		if (!MIP6_IS_HA) {
			/* this is not a homeagent. */
			/* XXX */
			bi.mbc_status = IP6_MH_BAS_HA_NOT_SUPPORTED;
			bi.mbc_send_ba = 1;
			goto send_ba;
		}

#ifdef MIP6_HOME_AGENT
		/* limit the max duration of bindings. */
		if (mip6ctl_hrbc_maxlifetime > 0 &&
		    bi.mbc_lifetime > mip6ctl_hrbc_maxlifetime)
			bi.mbc_lifetime = mip6ctl_hrbc_maxlifetime;

		if (IS_REQUEST_TO_CACHE(bi.mbc_lifetime, &bi.mbc_phaddr, &bi.mbc_pcoa)) {
			if (mbc != NULL && (mbc->mbc_flags & IP6MU_CLONED)) {
				mip6log((LOG_ERR,
					 "%s:%d: invalied home re-registration\n",
					 __FILE__, __LINE__));
				/* XXX */
			}
			if (mip6_process_hrbu(&bi)) {
				mip6log((LOG_ERR,
					 "%s:%d: home registration failed\n",
					 __FILE__, __LINE__));
				/* continue. */
			}
		} else {
			if (mbc == NULL || (mbc->mbc_flags & IP6MU_CLONED)) {
				bi.mbc_status = IP6_MH_BAS_NOT_HA;
				bi.mbc_send_ba = 1;
				goto send_ba;
			}
#if 0
			/*
			 * ignore 'S'&'L' bit (issue #66)
			 */
			bi.mbc_flags |= ~(IP6MU_SINGLE|IP6MU_LINK);
			bi.mbc_flags |= (mbc->mbc_flags && (IP6MU_SINGLE|IP6MU_LINK));
#endif
			if (mip6_process_hurbu(&bi)) {
				mip6log((LOG_ERR,
					 "%s:%d: home unregistration failed\n",
					 __FILE__, __LINE__));
				/* continue. */
			}
		}
#endif /* MIP6_HOME_AGENT */
	} else {
		/* request to cache/remove a binding for CN. */
		if (IS_REQUEST_TO_CACHE(bi.mbc_lifetime, &bi.mbc_phaddr, &bi.mbc_pcoa)) {
			int bc_error;

			if (mbc == NULL)
				bc_error = mip6_bc_register(&bi.mbc_phaddr,
							&bi.mbc_pcoa,
							&bi.mbc_addr,
							ip6mu->ip6mhbu_flags,
							bi.mbc_seqno,
							bi.mbc_lifetime);
			else
			  /* Update a cache entry */
				bc_error = mip6_bc_update(mbc, &bi.mbc_pcoa,
							&bi.mbc_addr,
					 		ip6mu->ip6mhbu_flags,
					 		bi.mbc_seqno,
							bi.mbc_lifetime);
		} else {
			mip6_bc_delete(mbc);
		}
	}

send_ba:
	if (bi.mbc_send_ba) {
		int ba_error;

		ba_error = mip6_bc_send_ba(&bi.mbc_addr, &bi.mbc_phaddr,
			    &bi.mbc_pcoa, bi.mbc_status, bi.mbc_seqno,
			    bi.mbc_lifetime, bi.mbc_refresh, &mopt);
		if (ba_error) {
			mip6log((LOG_ERR,
			    "%s:%d: sending a binding ack failed (%d)\n",
			    __FILE__, __LINE__, ba_error));
		}
	}

	return (error);
}

static int
mip6_ip6mh_create(pktopt_mobility, src, dst, cookie)
	struct ip6_mh **pktopt_mobility;
	struct in6_addr *src, *dst;
	u_int8_t *cookie;		/* home init cookie */
{
	struct ip6_mh_home_test *ip6mh;
	int ip6mh_size;
	mip6_nodekey_t home_nodekey;
	mip6_nonce_t home_nonce;

	*pktopt_mobility = NULL;

	ip6mh_size = sizeof(struct ip6_mh_home_test);

	if ((mip6_get_nonce(nonce_index, &home_nonce) != 0) ||
	    (mip6_get_nodekey(nonce_index, &home_nodekey) != 0))
		return (EINVAL);

	MALLOC(ip6mh, struct ip6_mh_home_test *, ip6mh_size,
	    M_IP6OPT, M_NOWAIT);
	if (ip6mh == NULL)
		return (ENOMEM);

	bzero(ip6mh, ip6mh_size);
	ip6mh->ip6mhht_proto = IPPROTO_NONE;
	ip6mh->ip6mhht_len = (ip6mh_size >> 3) - 1;
	ip6mh->ip6mhht_type = IP6_MH_TYPE_HOT;
	ip6mh->ip6mhht_nonce_index = htons(nonce_index);
	bcopy(cookie, ip6mh->ip6mhht_cookie8, sizeof(ip6mh->ip6mhht_cookie8));
	if (mip6_create_keygen_token(dst, &home_nodekey,
	    &home_nonce, 0, ip6mh->ip6mhht_keygen8)) {
		mip6log((LOG_ERR,
		 	"%s:%d: Failed of creation of home keygen token\n",
		 	__FILE__, __LINE__));
		 return (EINVAL);
	}

	/* calculate checksum. */
	ip6mh->ip6mhht_cksum = mip6_cksum(src, dst, ip6mh_size, IPPROTO_MH,
	    (char *)ip6mh);

	*pktopt_mobility = (struct ip6_mh *)ip6mh;

	return (0);
}

static int
mip6_ip6mc_create(pktopt_mobility, src, dst, cookie)
	struct ip6_mh **pktopt_mobility;
	struct in6_addr *src, *dst;
	u_int8_t *cookie;		/* careof init cookie */
{
	struct ip6_mh_careof_test *ip6mc;
	int ip6mc_size;
	mip6_nodekey_t careof_nodekey;
	mip6_nonce_t careof_nonce;

	*pktopt_mobility = NULL;

	ip6mc_size = sizeof(struct ip6_mh_careof_test);

	if ((mip6_get_nonce(nonce_index, &careof_nonce) != 0) ||
	    (mip6_get_nodekey(nonce_index, &careof_nodekey) != 0))
		return (EINVAL);

	MALLOC(ip6mc, struct ip6_mh_careof_test *, ip6mc_size,
	    M_IP6OPT, M_NOWAIT);
	if (ip6mc == NULL)
		return (ENOMEM);

	bzero(ip6mc, ip6mc_size);
	ip6mc->ip6mhct_proto = IPPROTO_NONE;
	ip6mc->ip6mhct_len = (ip6mc_size >> 3) - 1;
	ip6mc->ip6mhct_type = IP6_MH_TYPE_COT;
	ip6mc->ip6mhct_nonce_index = htons(nonce_index);
	bcopy(cookie, ip6mc->ip6mhct_cookie8, sizeof(ip6mc->ip6mhct_cookie8));
	if (mip6_create_keygen_token(dst, &careof_nodekey, &careof_nonce, 1,
		ip6mc->ip6mhct_keygen8)) {
		mip6log((LOG_ERR,
		    "mip6_ip6mc_create:%d: "
		    "Failed of creation of home keygen token\n",
		    __LINE__));
		 return (EINVAL);
	}

	/* calculate checksum. */
	ip6mc->ip6mhct_cksum = mip6_cksum(src, dst, ip6mc_size, IPPROTO_MH,
	    (char *)ip6mc);

	*pktopt_mobility = (struct ip6_mh *)ip6mc;

	return (0);
}

int
mip6_ip6ma_create(pktopt_mobility, src, dst, dstcoa, status, seqno, lifetime,
    refresh, mopt)
	struct ip6_mh **pktopt_mobility;
	struct in6_addr *src;
	struct in6_addr *dst;
	struct in6_addr *dstcoa;
	u_int8_t status;
	u_int16_t seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
	struct mip6_mobility_options *mopt;
{
	struct ip6_mh_binding_ack *ip6ma;
	struct ip6_mh_opt_refresh_advice *mopt_refresh = NULL;
	struct ip6_mh_opt_auth_data *mopt_auth = NULL;
	int need_refresh = 0;
	int need_auth = 0;
	int ip6ma_size, pad;
	int ba_size = 0, refresh_size = 0, auth_size = 0;
	u_int8_t key_bm[MIP6_KBM_LEN]; /* Stated as 'Kbm' in the spec */
	u_int8_t *p;

	*pktopt_mobility = NULL;

	ba_size = sizeof(struct ip6_mh_binding_ack);
	if (refresh > 3 && refresh < lifetime) {
		need_refresh = 1;
		ba_size += MIP6_PADLEN(ba_size, 2, 0);
		refresh_size = sizeof(struct ip6_mh_opt_refresh_advice);
	} else {
		refresh_size = 0;
	}
	if (mopt && 
	    ((mopt->valid_options & (MOPT_NONCE_IDX | MOPT_AUTHDATA)) == (MOPT_NONCE_IDX | MOPT_AUTHDATA)) &&
	    mip6_calculate_kbm_from_index(dst, dstcoa, 
		mopt->mopt_ho_nonce_idx, mopt->mopt_co_nonce_idx, 
		!IS_REQUEST_TO_CACHE(lifetime, dst, dstcoa), key_bm) == 0) {
		need_auth = 1;
		/* Since Binding Auth Option must be the last mobility option,
		   an implicit alignment requirement is 8n + 2.
		   (6.2.7) */
		if (refresh_size)
			refresh_size += MIP6_PADLEN(ba_size + refresh_size, 8, 2);
		else
			ba_size += MIP6_PADLEN(ba_size, 8, 2);
		auth_size = IP6MOPT_AUTHDATA_SIZE;
	}
	ip6ma_size = ba_size + refresh_size + auth_size;
	ip6ma_size += MIP6_PADLEN(ip6ma_size, 8, 0);

	MALLOC(ip6ma, struct ip6_mh_binding_ack *,
	       ip6ma_size, M_IP6OPT, M_NOWAIT);
	if (ip6ma == NULL)
		return (ENOMEM);
	if (need_refresh) {
		mopt_refresh = (struct ip6_mh_opt_refresh_advice *)((u_int8_t *)ip6ma + ba_size);
	}
	if (need_auth)
		mopt_auth = (struct ip6_mh_opt_auth_data *)((u_int8_t *)ip6ma + ba_size + refresh_size);

	bzero(ip6ma, ip6ma_size);

	ip6ma->ip6mhba_proto = IPPROTO_NONE;
	ip6ma->ip6mhba_len = (ip6ma_size >> 3) - 1;
	ip6ma->ip6mhba_type = IP6_MH_TYPE_BACK;
	ip6ma->ip6mhba_status = status;
	ip6ma->ip6mhba_seqno = htons(seqno);
	ip6ma->ip6mhba_lifetime =
		htons((u_int16_t)(lifetime >> 2));	/* units of 4 secs */

	/* padN */
	p = (u_int8_t *)ip6ma + sizeof(struct ip6_mh_binding_ack);
	if ((pad = ba_size - sizeof(struct ip6_mh_binding_ack)) >= 2) {
		*p = IP6_MHOPT_PADN;
		*(p + 1) = pad - 2;
	}
	if (refresh_size && 
	    ((p = (u_int8_t *)ip6ma + ba_size + sizeof(struct ip6_mh_opt_refresh_advice)),
	     (pad = refresh_size - sizeof(struct ip6_mh_opt_refresh_advice)) >= 2)) {
		*p = IP6_MHOPT_PADN;
		*(p + 1) = pad - 2;
	}
	if (auth_size && 
	    ((p = (u_int8_t *)ip6ma + ba_size + refresh_size +IP6MOPT_AUTHDATA_SIZE),
	     (pad = auth_size - IP6MOPT_AUTHDATA_SIZE) >= 2)) {
		*p = IP6_MHOPT_PADN;
		*(p + 1) = pad - 2;
	}
	if (pad + (ip6ma_size - (ba_size + refresh_size + auth_size)) >= 2) {
		*p = IP6_MHOPT_PADN;
		*(p + 1) += ip6ma_size - (ba_size + refresh_size + auth_size) - 2;
	}

	/* binding refresh advice option */
	if (need_refresh) {
		mopt_refresh->ip6mora_type = IP6_MHOPT_BREFRESH;
		mopt_refresh->ip6mora_len
		    = sizeof(struct ip6_mh_opt_refresh_advice) - 2;
		SET_NETVAL_S(&mopt_refresh->ip6mora_interval, refresh >> 2);
	}

	if (need_auth) {
		/* authorization data processing. */
		mopt_auth->ip6moad_type = IP6_MHOPT_BAUTH;
		mopt_auth->ip6moad_len = IP6MOPT_AUTHDATA_SIZE - 2;
		mip6_calculate_authenticator(key_bm, (caddr_t)(mopt_auth + 1),
		    dstcoa, src, (caddr_t)ip6ma, ip6ma_size,
		    ba_size + refresh_size + sizeof(struct ip6_mh_opt_auth_data),
		    IP6MOPT_AUTHDATA_SIZE - 2);
	}

#if 0
	/* padN */
	if (refresh_size) {
		if ((pad = refresh_size - sizeof(struct ip6m_opt_refresh)) >= 2) {
			u_char *p = (u_int8_t *)ip6ma + ba_size
				+ sizeof(struct ip6m_opt_refresh);
			*p = IP6_MHOPT_PADN;
			*(p + 1) = pad - 2;
		}
	}
#endif

	/* calculate checksum. */
	ip6ma->ip6mhba_cksum = mip6_cksum(src, dst, ip6ma_size, IPPROTO_MH,
	    (char *)ip6ma);

	*pktopt_mobility = (struct ip6_mh *)ip6ma;

	return (0);
}

static int
mip6_ip6mr_create(pktopt_mobility, src, dst)
	struct ip6_mh **pktopt_mobility;
	struct in6_addr *src;
	struct in6_addr *dst;
{
	struct ip6_mh_binding_request *ip6mr;
	int ip6mr_size;

	*pktopt_mobility = NULL;

	ip6mr_size = sizeof(struct ip6_mh_binding_request);

	MALLOC(ip6mr, struct ip6_mh_binding_request *,
	       ip6mr_size, M_IP6OPT, M_NOWAIT);
	if (ip6mr == NULL)
		return (ENOMEM);

	bzero(ip6mr, ip6mr_size);
	ip6mr->ip6mhbr_proto = IPPROTO_NONE;
	ip6mr->ip6mhbr_len = (ip6mr_size >> 3) - 1;
	ip6mr->ip6mhbr_type = IP6_MH_TYPE_BRR;

	/* calculate checksum. */
	ip6mr->ip6mhbr_cksum = mip6_cksum(src, dst, ip6mr_size, IPPROTO_MH,
	    (char *)ip6mr);

	*pktopt_mobility = (struct ip6_mh *)ip6mr;

	return (0);
}

int
mip6_ip6me_create(pktopt_mobility, src, dst, status, addr)
	struct ip6_mh **pktopt_mobility;
	struct in6_addr *src;
	struct in6_addr *dst;
	u_int8_t status;
	struct in6_addr *addr;
{
	struct ip6_mh_binding_error *ip6me;
	int ip6me_size;

	*pktopt_mobility = NULL;

	ip6me_size = sizeof(struct ip6_mh_binding_error);

	MALLOC(ip6me, struct ip6_mh_binding_error *,
	       ip6me_size, M_IP6OPT, M_NOWAIT);
	if (ip6me == NULL)
		return (ENOMEM);

	bzero(ip6me, ip6me_size);
	ip6me->ip6mhbe_proto = IPPROTO_NONE;
	ip6me->ip6mhbe_len = (ip6me_size >> 3) - 1;
	ip6me->ip6mhbe_type = IP6_MH_TYPE_BERROR;
	ip6me->ip6mhbe_status = status;
	ip6me->ip6mhbe_homeaddr = *addr;
	in6_clearscope(&ip6me->ip6mhbe_homeaddr);

	/* calculate checksum. */
	ip6me->ip6mhbe_cksum = mip6_cksum(src, dst, ip6me_size, IPPROTO_MH,
	    (char *)ip6me);

	*pktopt_mobility = (struct ip6_mh *)ip6me;

	return (0);
}

int
mip6_get_mobility_options(ip6mh, hlen, ip6mhlen, mopt)
	struct ip6_mh *ip6mh;
	int hlen, ip6mhlen;
	struct mip6_mobility_options *mopt;
{
	u_int8_t *mh, *mhend;
	u_int16_t valid_option;

	mh = (caddr_t)(ip6mh) + hlen;
	mhend = (caddr_t)(ip6mh) + ip6mhlen;
	mopt->valid_options = 0;

#define check_mopt_len(mopt_len)	\
	if (*(mh + 1) != mopt_len) goto bad;

	while (mh < mhend) {
		valid_option = 0;
		switch (*mh) {
			case IP6_MHOPT_PAD1:
				mh++;
				continue;
			case IP6_MHOPT_PADN:
				break;
			case IP6_MHOPT_ALTCOA:
				check_mopt_len(16);
				valid_option = MOPT_ALTCOA;
				bcopy(mh + 2, &mopt->mopt_altcoa,
				      sizeof(mopt->mopt_altcoa));
				break;
			case IP6_MHOPT_NONCEID:
				check_mopt_len(4);
				valid_option = MOPT_NONCE_IDX;
				GET_NETVAL_S(mh + 2, mopt->mopt_ho_nonce_idx);
				GET_NETVAL_S(mh + 4, mopt->mopt_co_nonce_idx);
				break;
			case IP6_MHOPT_BAUTH:
				valid_option = MOPT_AUTHDATA;
				mopt->mopt_auth = mh;
				break;
			case IP6_MHOPT_BREFRESH:
				check_mopt_len(2);
				valid_option = MOPT_REFRESH;
				GET_NETVAL_S(mh + 2, mopt->mopt_refresh);
				break;
			default:
				/*	'... MUST quietly ignore ... (6.2.1)'
				mip6log((LOG_ERR,
					 "%s:%d: invalid mobility option (%02x). \n",
				 __FILE__, __LINE__, *mh));
				 */
				break;
		}

		mh += *(mh + 1) + 2;
		mopt->valid_options |= valid_option;
	}

#undef check_mopt_len

	return (0);

 bad:
	return (EINVAL);
}

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE do {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);} while(0);
int
mip6_cksum(src, dst, plen, nh, mobility)
	struct in6_addr *src;
	struct in6_addr *dst;
	u_int32_t plen;
	u_int8_t nh;
	char *mobility;
{
	int sum, i;
	u_int16_t *payload;
	union {
		u_int16_t uphs[20];
		struct {
			struct in6_addr uph_src;
			struct in6_addr uph_dst;
			u_int32_t uph_plen;
			u_int8_t uph_zero[3];
			u_int8_t uph_nh;
		} uph_un __attribute__((__packed__));
	} uph;
	union {
		u_int16_t s[2];
		u_int32_t l;
	} l_util;

	bzero(&uph, sizeof(uph));
	uph.uph_un.uph_src = *src;
	in6_clearscope(&uph.uph_un.uph_src);
	uph.uph_un.uph_dst = *dst;
	in6_clearscope(&uph.uph_un.uph_dst);
	uph.uph_un.uph_plen = htonl(plen);
	uph.uph_un.uph_nh = nh;

	sum = 0;
	for (i = 0; i < 20; i++) {
		REDUCE;
		sum += uph.uphs[i];
	}
	payload = (u_int16_t *)mobility;
	for (i = 0; i < (plen / 2); i++) {
		REDUCE;
		sum += *payload++;
	}
	if (plen % 2) {
		union {
			u_int16_t s;
			u_int8_t c[2];
		} last;
		REDUCE;
		last.c[0] = *(char *)payload;
		last.c[1] = 0;
		sum += last.s;
	}

	REDUCE;
	return (~sum & 0xffff);
}
#undef ADDCARRY
#undef REDUCE

#if defined(MIP6_HOME_AGENT) || defined(MIP6_MOBILE_NODE)
void
mip6_create_addr(addr, ifid, ndpr)
	struct in6_addr *addr;
	const struct in6_addr *ifid;
	struct nd_prefix *ndpr;
{
	int i, bytelen, bitlen;
	u_int8_t mask;
	struct in6_addr *prefix = &ndpr->ndpr_prefix.sin6_addr;
	u_int8_t prefixlen = ndpr->ndpr_plen;
	struct sockaddr_in6 sin6;

	bzero(addr, sizeof(*addr));

	bytelen = prefixlen / 8;
	bitlen = prefixlen % 8;
	for (i = 0; i < bytelen; i++)
		addr->s6_addr8[i] = prefix->s6_addr8[i];
	if (bitlen) {
		mask = 0;
		for (i = 0; i < bitlen; i++)
			mask |= (0x80 >> i);
		addr->s6_addr8[bytelen] = (prefix->s6_addr8[bytelen] & mask)
		    | (ifid->s6_addr8[bytelen] & ~mask);

		for (i = bytelen + 1; i < 16; i++)
			addr->s6_addr8[i] = ifid->s6_addr8[i];
	} else {
		for (i = bytelen; i < 16; i++)
			addr->s6_addr8[i] = ifid->s6_addr8[i];
	}

	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *addr;
	if (ndpr->ndpr_ifp) {
		int error;

		error = in6_addr2zoneid(ndpr->ndpr_ifp, &sin6.sin6_addr,
		    &sin6.sin6_scope_id);
		if (error == 0)
			error = in6_embedscope(addr, &sin6);
		if (error != 0)
			mip6log((LOG_ERR,
			    "mip6_create_addr:%d: can't set scope correctly\n",
			    __LINE__));
	} else {
		/* no ifp is specified. */
		if (scope6_check_id(&sin6, ip6_use_defzone))
			mip6log((LOG_ERR,
			    "mip6_create_addr:%d: can't set scope correctly\n",
			    __LINE__));
		*addr = sin6.sin6_addr;
	}
}

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
	int *offp, proto;
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;
#if !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
	int s;
#endif

	m_adj(m, *offp);

	switch (proto) {
	case IPPROTO_IPV6:
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return (IPPROTO_DONE);
		}

		ip6 = mtod(m, struct ip6_hdr *);

		mip6stat.mip6s_revtunnel++;

#ifdef __NetBSD__
		s = splnet();
#elif !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
		s = splimp();
#endif

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
		if (!IF_HANDOFF(&ip6intrq, m, NULL))
			goto bad;
#else
		if (IF_QFULL(&ip6intrq)) {
			IF_DROP(&ip6intrq);	/* update statistics */
			splx(s);
			goto bad;
		}
		IF_ENQUEUE(&ip6intrq, m);
#endif

#if 0
		/* we don't need it as we tunnel IPv6 in IPv6 only. */
		schednetisr(NETISR_IPV6);
#endif
#if !(defined(__FreeBSD__) && __FreeBSD_version >= 500000)
		splx(s);
#endif
		break;
	default:
		mip6log((LOG_ERR,
			 "%s:%d: protocol %d not supported.\n",
			 __FILE__, __LINE__,
			 proto));
		goto bad;
	}

	return (IPPROTO_DONE);

 bad:
	m_freem(m);
	return (IPPROTO_DONE);
}

int
mip6_tunnel_control(action, entry, func, ep)
	int action;
	void *entry;
	int (*func)(const struct mbuf *, int, int, void *);
	const struct encaptab **ep;
{
#if !defined(MIP6_NOHAIPSEC)
#ifdef MIP6_MOBILE_NODE
	struct mip6_bu *mbu;
	struct sockaddr_in6 haddr_sa, coa_sa, paddr_sa;
#endif
#ifdef MIP6_HOME_AGENT
	struct mip6_bc *mbc;
	struct sockaddr_in6 phaddr_sa, pcoa_sa, addr_sa;
#endif
#endif /* !MIP6_NOHAIPSEC */
	if ((entry == NULL) && (ep == NULL)) {
		return (EINVAL);
	}

#if !defined(MIP6_NOHAIPSEC)
	/* XXX */
#ifdef MIP6_MOBILE_NODE
	if (func == mip6_bu_encapcheck) {
		mbu = (struct mip6_bu *)entry;

		bzero(&haddr_sa, sizeof(haddr_sa));
		haddr_sa.sin6_len = sizeof(haddr_sa);
		haddr_sa.sin6_family = AF_INET6;
		haddr_sa.sin6_addr = mbu->mbu_haddr;
		/* XXX scope_id? */

		bzero(&coa_sa, sizeof(coa_sa));
		coa_sa.sin6_len = sizeof(coa_sa);
		coa_sa.sin6_family = AF_INET6;
		coa_sa.sin6_addr = mbu->mbu_coa;
		/* XXX scope_id? */

		bzero(&paddr_sa, sizeof(paddr_sa));
		paddr_sa.sin6_len = sizeof(paddr_sa);
		paddr_sa.sin6_family = AF_INET6;
		paddr_sa.sin6_addr = mbu->mbu_paddr;
		/* XXX scope_id? */

		if (mip6_update_ipsecdb(&haddr_sa, NULL, &coa_sa, &paddr_sa)) {
			mip6log((LOG_ERR,
			    "%s:%d: failed to update ipsec database.\n",
			    __FILE__, __LINE__));
			/* what shoud we do? */
			return (EINVAL);
			
		}
	}
#endif
#ifdef MIP6_HOME_AGENT
	if (func == mip6_bc_encapcheck) {
		mbc = (struct mip6_bc *)entry;

		bzero(&phaddr_sa, sizeof(phaddr_sa));
		phaddr_sa.sin6_len = sizeof(phaddr_sa);
		phaddr_sa.sin6_family = AF_INET6;
		phaddr_sa.sin6_addr = mbc->mbc_phaddr;
		/* XXX scope_id? */

		bzero(&pcoa_sa, sizeof(pcoa_sa));
		pcoa_sa.sin6_len = sizeof(pcoa_sa);
		pcoa_sa.sin6_family = AF_INET6;
		pcoa_sa.sin6_addr = mbc->mbc_pcoa;
		/* XXX scope_id? */

		bzero(&addr_sa, sizeof(addr_sa));
		addr_sa.sin6_len = sizeof(addr_sa);
		addr_sa.sin6_family = AF_INET6;
		addr_sa.sin6_addr = mbc->mbc_addr;
		/* XXX scope_id? */

		if (mip6_update_ipsecdb(&phaddr_sa, NULL, &pcoa_sa,
			&addr_sa)) {
			mip6log((LOG_ERR,
			    "%s:%d: failed to update ipsec database.\n",
			    __FILE__, __LINE__));
			/* what shoud we do? */
			return (EINVAL);
			
		}
	}
#endif
#endif /* !MIP6_NOHAIPSEC */

	/* before doing anything, remove an existing encap entry. */
	switch (action) {
	case MIP6_TUNNEL_ADD:
	case MIP6_TUNNEL_CHANGE:
	case MIP6_TUNNEL_DELETE:
		if (*ep != NULL) {
			encap_detach(*ep);
			*ep = NULL;
		}
	}

	switch (action) {
	case MIP6_TUNNEL_ADD:
	case MIP6_TUNNEL_CHANGE:
		*ep = encap_attach_func(AF_INET6, IPPROTO_IPV6,
					func,
					(struct protosw *)&mip6_tunnel_protosw,
					(void *)entry);
		if (*ep == NULL) {
			mip6log((LOG_ERR,
				 "%s:%d: "
				 "encap entry create failed.\n",
				 __FILE__, __LINE__));
			return (EINVAL);
		}
		break;
	}

	return (0);
}

#if !defined(MIP6_NOHAIPSEC) && (defined(IPSEC) || defined(__OpenBSD__))
static int
mip6_update_ipsecdb(haddr, ocoa, ncoa, haaddr)
	struct sockaddr_in6 *haddr;
	struct sockaddr_in6 *ocoa;
	struct sockaddr_in6 *ncoa;
	struct sockaddr_in6 *haaddr;
{
	/*
	 * if i am a home agent, update the entries bellow:
	 *  policy: inbound HoA -> :: mobility tunnel (1)
	 *          outbound :: -> HoA mobility tunnel (2)
	 *  sa: CoA-HA related to (1)
	 *      HA-CoA related to (2)
	 * if i am a mobile node,
	 *  policy: inbound :: -> HoA mobility tunnel (3)
	 *          outbound HoA -> :: mobility tunnel (4)
	 *  sa: HA-CoA related to (3)
	 *      CoA-HA related to (4)
	 */
	if (MIP6_IS_HA) {
		key_mip6_update_home_agent_ipsecdb(haddr, ocoa, ncoa, haaddr);
	}
	if (MIP6_IS_MN) {
		key_mip6_update_mobile_node_ipsecdb(haddr, ocoa, ncoa, haaddr);
	}
	return (0);
}
#endif /* !MIP6_NOHAIPSEC */

#endif /* MIP6_HOME_AGENT || MIP6_MOBILE_NODE */

#if defined(__NetBSD__) || defined(__OpenBSD__)
int
mip6_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	/* All sysctl names at this level are terminal. */
	if (namelen != 1)
		return ENOTDIR;

	switch (name[0]) {
	case MIP6CTL_DEBUG:
		return sysctl_int(oldp, oldlenp, newp, newlen, &mip6ctl_debug);
	case MIP6CTL_USE_IPSEC:
		return sysctl_int(oldp, oldlenp, newp, newlen,
		    &mip6ctl_use_ipsec);
	case MIP6CTL_BC_MAXLIFETIME:
		return sysctl_int(oldp, oldlenp, newp, newlen,
		    &mip6ctl_bc_maxlifetime);
	case MIP6CTL_HRBC_MAXLIFETIME:
		return sysctl_int(oldp, oldlenp, newp, newlen,
		    &mip6ctl_hrbc_maxlifetime);
	case MIP6CTL_BU_MAXLIFETIME:
		return sysctl_int(oldp, oldlenp, newp, newlen,
		    &mip6ctl_bu_maxlifetime);
	case MIP6CTL_HRBU_MAXLIFETIME:
		return sysctl_int(oldp, oldlenp, newp, newlen,
		    &mip6ctl_hrbu_maxlifetime);
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}
#endif /* __NetBSD__ || __OpenBSD__ */

#ifdef __FreeBSD__
SYSCTL_DECL(_net_inet6_mip6);

SYSCTL_INT(_net_inet6_mip6, MIP6CTL_DEBUG, debug, CTLFLAG_RW,
    &mip6ctl_debug, 0, "");
SYSCTL_INT(_net_inet6_mip6, MIP6CTL_USE_IPSEC, use_ipsec, CTLFLAG_RW,
    &mip6ctl_use_ipsec, 0, "");
SYSCTL_INT(_net_inet6_mip6, MIP6CTL_BC_MAXLIFETIME, bc_maxlifetime, CTLFLAG_RW,
    &mip6ctl_bc_maxlifetime, 0, "");
SYSCTL_INT(_net_inet6_mip6, MIP6CTL_HRBC_MAXLIFETIME, hrbc_maxlifetime,
    CTLFLAG_RW, &mip6ctl_hrbc_maxlifetime, 0, "");
SYSCTL_INT(_net_inet6_mip6, MIP6CTL_BU_MAXLIFETIME, bu_maxlifetime, CTLFLAG_RW,
    &mip6ctl_bu_maxlifetime, 0, "");
SYSCTL_INT(_net_inet6_mip6, MIP6CTL_HRBU_MAXLIFETIME, hrbu_maxlifetime,
    CTLFLAG_RW, &mip6ctl_hrbu_maxlifetime, 0, "");
#endif /* __FreeBSD__ */
