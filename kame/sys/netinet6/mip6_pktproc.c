/*	$KAME: mip6_pktproc.c,v 1.42 2002/08/13 05:31:59 k-sugyou Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.  All rights reserved.
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

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_ipsec.h"
#include "opt_inet6.h"
#include "opt_mip6.h"
#endif
#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>

#include <net/if_hif.h>

#ifdef __OpenBSD__ /* KAME IPSEC */
#undef IPSEC
#endif

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /* IPSEC */

#include <netinet6/mip6_var.h>
#include <netinet6/mip6.h>
#include <crypto/hmac.h>
#include <net/net_osdep.h>

#define SHA1_RESULTLEN	20


/* xn + y; x must be 2^m */
#define PADLEN(cur_offset, x, y)	\
	((x + y) - ((cur_offset) % (x))) % (x)

extern struct mip6_bc_list mip6_bc_list;
extern struct mip6_prefix_list mip6_prefix_list;

static int mip6_ip6mh_create __P((struct ip6_mobility **,
				  struct sockaddr_in6 *,
				  struct sockaddr_in6 *,
				  u_int8_t *));
static int mip6_ip6mc_create __P((struct ip6_mobility **,
				  struct sockaddr_in6 *,
				  struct sockaddr_in6 *,
				  u_int8_t *));
static int mip6_ip6mhi_create __P((struct ip6_mobility **,
				   struct mip6_bu *));
static int mip6_ip6mci_create __P((struct ip6_mobility **,
				   struct mip6_bu *));

static int mip6_cksum __P((struct sockaddr_in6 *,
			   struct sockaddr_in6 *,
			   u_int32_t, u_int8_t,	char *));

int
mip6_ip6mhi_input(m0, ip6mhi, ip6mhilen)
	struct mbuf *m0;
	struct ip6m_home_test_init *ip6mhi;
	int ip6mhilen;
{
	struct sockaddr_in6 *src_sa, *dst_sa;
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	if (ip6_getpktaddrs(m0, &src_sa, &dst_sa)) {
		/* must not happen. */
		m_freem(m0);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6mhilen < sizeof(struct ip6m_home_test_init)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: too short home test init (len = %d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 ip6mhilen,
			 ip6_sprintf(&src_sa->sin6_addr)));
		/* discard */
		m_freem(m0);
		return (EINVAL);
	}

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(dst_sa, src_sa, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: creating ip6hdr failed.\n",
		    __FILE__, __LINE__));
 		goto free_ip6pktopts;
	}

	error = mip6_ip6mh_create(&opt.ip6po_mobility, dst_sa, src_sa,
	    ip6mhi->ip6mhi_hot_cookie);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: HoT creation error (%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
 		goto free_ip6pktopts;
	}

	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
 		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mobility != NULL)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (0);
}

int
mip6_ip6mh_create(pktopt_mobility, src, dst, cookie)
	struct ip6_mobility **pktopt_mobility;
	struct sockaddr_in6 *src, *dst;
	u_int8_t *cookie;
{
	struct ip6m_home_test *ip6mh;
	int ip6mh_size;
	mip6_nodekey_t home_nodekey;
	mip6_nonce_t home_nonce;

	*pktopt_mobility = NULL;

	ip6mh_size = sizeof(struct ip6m_home_test);

	if ((mip6_get_nonce(nonce_index, &home_nonce) != 0) ||
	    (mip6_get_nodekey(nonce_index, &home_nodekey) != 0))
		return (EINVAL);
	    
	MALLOC(ip6mh, struct ip6m_home_test *, ip6mh_size,
	    M_IP6OPT, M_NOWAIT);
	if (ip6mh == NULL)
		return (ENOMEM);

	bzero(ip6mh, ip6mh_size);
	ip6mh->ip6mh_pproto = IPPROTO_NONE;
	ip6mh->ip6mh_len = ip6mh_size >> 3;
	ip6mh->ip6mh_type = IP6M_HOME_TEST;
	ip6mh->ip6mh_nonce_index = htons(nonce_index);
	bcopy(cookie, ip6mh->ip6mh_hot_cookie, sizeof(ip6mh->ip6mh_hot_cookie));
	mip6_create_cookie(&dst->sin6_addr,
			   &home_nodekey, &home_nonce, ip6mh->ip6mh_cookie);

	/* calculate checksum. */
	ip6mh->ip6mh_cksum = mip6_cksum(src, dst,
	    ip6mh_size, IPPROTO_MOBILITY, (char *)ip6mh);

	*pktopt_mobility = (struct ip6_mobility *)ip6mh;

	return (0);
}

int
mip6_ip6mci_input(m0, ip6mci, ip6mcilen)
	struct mbuf *m0;
	struct ip6m_careof_test_init *ip6mci;
	int ip6mcilen;
{
	struct sockaddr_in6 *src_sa, *dst_sa;
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	if (ip6_getpktaddrs(m0, &src_sa, &dst_sa)) {
		/* must not happen. */
		m_freem(m0);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6mcilen < sizeof(struct ip6m_careof_test_init)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: too short care-of test init (len = %d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 ip6mcilen,
			 ip6_sprintf(&src_sa->sin6_addr)));
		/* discard */
		m_freem(m0);
		return (EINVAL);
	}

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(dst_sa, src_sa, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: creating ip6hdr failed.\n",
		    __FILE__, __LINE__));
 		goto free_ip6pktopts;
	}

	error = mip6_ip6mc_create(&opt.ip6po_mobility, dst_sa, src_sa,
	    ip6mci->ip6mci_cot_cookie);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: HoT creation error (%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
 		goto free_ip6pktopts;
	}

	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
 		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mobility != NULL)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (0);
}

int
mip6_ip6mc_create(pktopt_mobility, src, dst, cookie)
	struct ip6_mobility **pktopt_mobility;
	struct sockaddr_in6 *src, *dst;
	u_int8_t *cookie;
{
	struct ip6m_careof_test *ip6mc;
	int ip6mc_size;
	mip6_nodekey_t careof_nodekey;
	mip6_nonce_t careof_nonce;

	*pktopt_mobility = NULL;

	ip6mc_size = sizeof(struct ip6m_careof_test);

	if ((mip6_get_nonce(nonce_index, &careof_nonce) != 0) ||
	    (mip6_get_nodekey(nonce_index, &careof_nodekey) != 0))
		return (EINVAL);
	    
	MALLOC(ip6mc, struct ip6m_careof_test *, ip6mc_size,
	    M_IP6OPT, M_NOWAIT);
	if (ip6mc == NULL)
		return (ENOMEM);

	bzero(ip6mc, ip6mc_size);
	ip6mc->ip6mc_pproto = IPPROTO_NONE;
	ip6mc->ip6mc_len = ip6mc_size >> 3;
	ip6mc->ip6mc_type = IP6M_CAREOF_TEST;
	ip6mc->ip6mc_nonce_index = htons(nonce_index);
	bcopy(cookie, ip6mc->ip6mc_cot_cookie, sizeof(ip6mc->ip6mc_cot_cookie));
	mip6_create_cookie(&dst->sin6_addr,
			   &careof_nodekey, &careof_nonce,
			   ip6mc->ip6mc_cookie);
	
	/* calculate checksum. */
	ip6mc->ip6mc_cksum = mip6_cksum(src, dst,
	    ip6mc_size, IPPROTO_MOBILITY, (char *)ip6mc);

	*pktopt_mobility = (struct ip6_mobility *)ip6mc;

	return (0);
}

int
mip6_ip6mh_input(m, ip6mh, ip6mhlen)
	struct mbuf *m;
	struct ip6m_home_test *ip6mh;
	int ip6mhlen;
{
	struct sockaddr_in6 *src_sa, *dst_sa;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	int error = 0;

	if (ip6_getpktaddrs(m, &src_sa, &dst_sa)) {
		/* must not happen. */
		m_freem(m);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6mhlen < sizeof(struct ip6m_home_test)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: too short home test (len = %d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 ip6mhlen,
			 ip6_sprintf(&src_sa->sin6_addr)));
		/* discard */
		m_freem(m);
		return (EINVAL);
	}

	sc = hif_list_find_withhaddr(dst_sa);
	if (sc == NULL) {
                mip6log((LOG_NOTICE,
		    "%s:%d: no related hif interface found with this HoT "
		    "for %s.\n",
		    __FILE__, __LINE__, ip6_sprintf(&dst_sa->sin6_addr)));
		m_freem(m);
                return (EINVAL);
	}
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, src_sa, dst_sa);
	if (mbu == NULL) {
		mip6log((LOG_NOTICE,
		    "%s:%d: no related binding update entry found with "
		    "this HoT for %s.\n",
		    __FILE__, __LINE__, ip6_sprintf(&src_sa->sin6_addr)));
		m_freem(m);
		return (EINVAL);
	}

	/* check mobile cookie. */
	if (bcmp(&mbu->mbu_mobile_cookie, ip6mh->ip6mh_hot_cookie,
	    sizeof(ip6mh->ip6mh_hot_cookie)) != 0) {
		mip6log((LOG_INFO,
		    "%s:%d: HoT mobile cookie mismatch from %s.\n",
		    __FILE__, __LINE__, ip6_sprintf(&src_sa->sin6_addr)));
		m_freem(m);
		return (EINVAL);
	}

	error = mip6_bu_fsm(mbu, MIP6_BU_FSM_EVENT_HOT_RECEIVED, ip6mh);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: state transition failed. (%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
		return (error);
	}

	mbu->mbu_home_nonce_index = ntohs(ip6mh->ip6mh_nonce_index);
	mip6log((LOG_INFO,
		 "%s:%d: Got HoT Nonce index: %d.\n",
		 __FILE__, __LINE__,mbu->mbu_home_nonce_index));

	return (0);
}

int
mip6_ip6mc_input(m, ip6mc, ip6mclen)
	struct mbuf *m;
	struct ip6m_careof_test *ip6mc;
	int ip6mclen;
{
	struct sockaddr_in6 *src_sa, *dst_sa;
	struct hif_softc *sc;
	struct mip6_bu *mbu = NULL;
	int error = 0;

	if (ip6_getpktaddrs(m, &src_sa, &dst_sa)) {
		/* must not happen. */
		m_freem(m);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6mclen < sizeof(struct ip6m_careof_test)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: too short care-of test (len = %d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 ip6mclen,
			 ip6_sprintf(&src_sa->sin6_addr)));
		/* discard */
		m_freem(m);
		return (EINVAL);
	}

	/* too ugly... */
	for (sc = TAILQ_FIRST(&hif_softc_list);
	     sc;
	     sc = TAILQ_NEXT(sc, hif_entry)) {
		for (mbu = LIST_FIRST(&sc->hif_bu_list);
		     mbu;
		     mbu = LIST_NEXT(mbu, mbu_entry)) {
			if (SA6_ARE_ADDR_EQUAL(dst_sa, &mbu->mbu_coa))
				break;
		}
	}
	if (mbu == NULL) {
		mip6log((LOG_NOTICE,
		    "%s:%d: no related binding update entry found with "
		    "this CoT for %s.\n",
		    __FILE__, __LINE__, ip6_sprintf(&src_sa->sin6_addr)));
		m_freem(m);
		return (EINVAL);
	}

	/* check mobile cookie. */
	if (bcmp(&mbu->mbu_mobile_cookie, ip6mc->ip6mc_cot_cookie,
	    sizeof(ip6mc->ip6mc_cot_cookie)) != 0) {
		mip6log((LOG_INFO,
		    "%s:%d: CoT mobile cookie mismatch from %s.\n",
		    __FILE__, __LINE__, ip6_sprintf(&src_sa->sin6_addr)));
		m_freem(m);
		return (EINVAL);
	}

	error = mip6_bu_fsm(mbu, MIP6_BU_FSM_EVENT_COT_RECEIVED, ip6mc);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: state transition failed. (%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
		return (error);
	}

	mbu->mbu_careof_nonce_index = ntohs(ip6mc->ip6mc_nonce_index);
	mip6log((LOG_INFO,
		 "%s:%d: Got CoT Nonce index: %d.\n",
		 __FILE__, __LINE__, mbu->mbu_careof_nonce_index));

	return (0);
}

int
mip6_ip6mu_input(m, ip6mu, ip6mulen)
	struct mbuf *m;
	struct ip6m_binding_update *ip6mu;
	int ip6mulen;
{
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *src_sa, *dst_sa, coa_sa, hoa_sa;
	struct mbuf *n;
	struct ip6aux *ip6a = NULL;
	u_int8_t ip6mu_flags;
	u_int8_t isprotected;
	u_int8_t haseen;
	struct mip6_bc *mbc;
	u_int16_t seqno;
	u_int32_t lifetime;

	int error = 0;
	u_int8_t bu_safe = 0;	/* To accept bu always without authentication, this value is set to non-zero */
	struct mip6_mobility_options mopt;

#ifdef IPSEC
	/*
	 * Check ESP(IPsec)
	 */
	if (ipsec6_in_reject(m, NULL)) {
		ipsec6stat.in_polvio++;
		m_freem(m);
		return (EINVAL);	/* XXX */
	}
#endif /* IPSEC */

	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6_getpktaddrs(m, &src_sa, &dst_sa)) {
		/* must not happen. */
		m_freem(m);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6mulen < sizeof(struct ip6m_binding_update)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: too short binding update (len = %d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 ip6mulen,
			 ip6_sprintf(&src_sa->sin6_addr)));
		/* discard */
		m_freem(m);
		return (EINVAL);
	}

	ip6mu_flags = isprotected = haseen = 0;

	ip6mu_flags = ip6mu->ip6mu_flags;

	if (((m->m_flags & M_DECRYPTED) != 0)
	    || ((m->m_flags & M_AUTHIPHDR) != 0)) {
		isprotected = 1;
	}

	coa_sa = *src_sa;
	n = ip6_findaux(m);
	if (n == NULL) {
		m_freem(m);
		return (EINVAL);
	}
	ip6a = mtod(n, struct ip6aux *);
	if ((ip6a->ip6a_flags & IP6A_HASEEN) == 0) {
		m_freem(m);
		return (EINVAL);
	}
	if ((ip6a->ip6a_flags & IP6A_SWAP) != 0) {
		haseen = 1;
		coa_sa.sin6_addr = ip6a->ip6a_coa;
	}
		
	/*
	 *              HAO          no HAO
	 * IPseced      HR     -> o  HR     -> x
	 *              not HR -> o  not HR -> o
	 * not IPseced  HR     -> x  HR     -> x
	 *              not HR -> x  not HR -> o
	 */
#if 1 /* XXX temporally */
	if (ip6mu_flags & IP6MU_HOME) {
		bu_safe = 1;
		goto accept_binding_update;
	}
#endif
	if (isprotected
	    && haseen) {
		bu_safe = 1;
		goto accept_binding_update;
	}
	if ((haseen == 1)
	    && ((ip6mu_flags & IP6MU_HOME) == 0))
		goto accept_binding_update;	/* Must be checked its safety
						 * with RR later */

	/* otherwise, discard this packet. */
	m_freem(m);
	return (EINVAL);

 accept_binding_update:

	/* get home address. */
	if (haseen) {
		hoa_sa = *src_sa;
	} else {
		hoa_sa = *src_sa;
		hoa_sa.sin6_addr = ip6a->ip6a_coa;
	}

	if ((error = mip6_get_mobility_options(ip6mu, ip6mulen, &mopt))) {
		m_freem(m);
		return (error);
	}
	mip6log((LOG_INFO, "%s:%d: Mobility options: %b\n", 
			 __FILE__, __LINE__, mopt.valid_options,
		 "\20\4AUTH\3NONCE\2ALTCOA\1UID\n"));

	if (mopt.valid_options & MOPT_ALTCOA)
		coa_sa.sin6_addr = mopt.mopt_altcoa;

	seqno = ntohs(ip6mu->ip6mu_seqno);
	lifetime = ntohs(ip6mu->ip6mu_lifetime) << 2;	/* units of 4secs */

	/* ip6_src and HAO has been already swapped at this point. */
	mbc = mip6_bc_list_find_withphaddr(&mip6_bc_list, &hoa_sa);
	if (mbc == NULL) {
		if (!bu_safe && mip6_is_valid_bu(ip6, ip6mu, ip6mulen, &mopt, &hoa_sa, &coa_sa)) {
			mip6log((LOG_ERR,
				 "%s:%d: RR authentication was failed.\n",
				 __FILE__, __LINE__));
			m_freem(m);
			return (EINVAL);
		}
	} else {
		/* check a sequence number. */
		if (MIP6_LEQ(seqno, mbc->mbc_seqno)) {
			mip6log((LOG_NOTICE,
			    "%s:%d: received sequence no (%d) <= current "
			    "seq no (%d) in BU from host %s.\n",
			    __FILE__, __LINE__, seqno, mbc->mbc_seqno,
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
			error = mip6_bc_send_ba(&mbc->mbc_addr, &mbc->mbc_phaddr,
			    &coa_sa, IP6MA_STATUS_SEQNO_TOO_SMALL, mbc->mbc_seqno,
			    0, 0);
			if (error) {
				mip6log((LOG_ERR,
				    "%s:%d: sending a binding ack failed (%d)\n",
				    __FILE__, __LINE__, error));
			}

			/* discard. */
			m_freem(m);
			return (EINVAL);
		}
	}

#define IS_REQUEST_TO_CACHE(lifetime, hoa, coa)	\
	(((lifetime) != 0) &&			\
	 (!SA6_ARE_ADDR_EQUAL((hoa), (coa))))

	if (ip6mu->ip6mu_flags & IP6MU_HOME) {
		/* request for the home (un)registration. */
		if (!MIP6_IS_HA) {
			/* this is not a homeagent. */
			/* XXX */
			mip6_bc_send_ba(dst_sa, src_sa, &coa_sa,
					IP6MA_STATUS_NOT_SUPPORTED,
					seqno, 0, 0);
			return (0);
		}

		/* limit the max duration of bindings. */
		if (mip6_config.mcfg_hrbc_lifetime_limit > 0 &&
		    lifetime > mip6_config.mcfg_hrbc_lifetime_limit)
			lifetime = mip6_config.mcfg_hrbc_lifetime_limit;

		if (IS_REQUEST_TO_CACHE(lifetime, &hoa_sa, &coa_sa)) {
			if (mbc != NULL && (mbc->mbc_flags & IP6MU_CLONED)) {
				mip6log((LOG_ERR,
					 "%s:%d: invalied home re-registration\n",
					 __FILE__, __LINE__));
				/* XXX */
			}
			error = mip6_process_hrbu(&hoa_sa,
						  &coa_sa,
						  ip6mu->ip6mu_flags,
						  seqno,
						  lifetime,
						  dst_sa);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: home registration failed\n",
					 __FILE__, __LINE__));
				/* continue. */
			}
		} else {
			if (mbc == NULL || (mbc->mbc_flags & IP6MU_CLONED)) {
				mip6_bc_send_ba(dst_sa, src_sa, &coa_sa,
						IP6MA_STATUS_NOT_HOME_AGENT,
						seqno, 0, 0);
				return (0);
			}
			/*
			 * ignore 'S' bit (issue #66)
			 * XXX 'L'?
			 */
			error = mip6_process_hurbu(&hoa_sa,
						   &coa_sa,
						   mbc->mbc_flags,
						   seqno,
						   lifetime,
						   dst_sa);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: home unregistration failed\n",
					 __FILE__, __LINE__));
				/* continue. */
			}
		}
	} else {
		/* request to cache/remove a binding for CN. */
		if (IS_REQUEST_TO_CACHE(lifetime, &hoa_sa, &coa_sa)) {
			if (mbc == NULL)
				error = mip6_bc_register(&hoa_sa, &coa_sa, dst_sa,
							 ip6mu->ip6mu_flags,
							 seqno, lifetime);
			else
			  /* Update a cache */
				error = mip6_bc_update(mbc, &coa_sa, dst_sa,
						       ip6mu->ip6mu_flags,
						       seqno, lifetime);
		} else {
			mip6_bc_delete(mbc);
		}

		if (ip6mu->ip6mu_flags & IP6MU_ACK) {
			if (mip6_bc_send_ba(dst_sa,
					    &hoa_sa,
					    &coa_sa,
					    IP6MA_STATUS_ACCEPTED, /* XXX */
					    seqno,
					    lifetime,
					    lifetime)) {
				mip6log((LOG_ERR,
					 "%s:%d: sending BA to %s(%s) failed. "
					 "send it later.\n",
					 __FILE__, __LINE__,
					 ip6_sprintf(&hoa_sa.sin6_addr),
					 ip6_sprintf(&coa_sa.sin6_addr)));
			}
		}
	}

	return (0);
}

int
mip6_ip6ma_input(m, ip6ma, ip6malen)
	struct mbuf *m;
	struct ip6m_binding_ack *ip6ma;
	int ip6malen;
{
	struct ip6_hdr *ip6;
	struct sockaddr_in6 *src_sa, *dst_sa;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	u_int16_t seqno;
	u_int32_t lifetime;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif
	int error = 0;

#ifdef IPSEC
	/*
	 * Check ESP(IPsec)
	 */
	if (ipsec6_in_reject(m, NULL)) {
		ipsec6stat.in_polvio++;
		m_freem(m);
		return (EINVAL);	/* XXX */
	}
#endif /* IPSEC */

	ip6 = mtod(m, struct ip6_hdr *);
	if (ip6_getpktaddrs(m, &src_sa, &dst_sa)) {
		/* must not happen. */
		m_freem(m);
		return (EINVAL);
	}

	/* packet length check. */
	if (ip6malen < sizeof(struct ip6m_binding_ack)) {
		mip6log((LOG_NOTICE,
			 "%s:%d: too short binding ack (len = %d) "
			 "from host %s.\n",
			 __FILE__, __LINE__,
			 ip6malen,
			 ip6_sprintf(&src_sa->sin6_addr)));
		/* discard */
		m_freem(m);
		return (EINVAL);
	}

	/* XXX autorization */

	/*
         * check if the sequence number of the binding update sent ==
         * the sequence number of the binding ack received.
         */
	sc = hif_list_find_withhaddr(dst_sa);
	if (sc == NULL) {
                /*
                 * if we receive a binding ack before sending binding
                 * updates(!), sc will be NULL.
                 */
                mip6log((LOG_NOTICE,
                         "%s:%d: no hif interface found.\n",
                         __FILE__, __LINE__));
                /* silently ignore. */
		m_freem(m);
                return (EINVAL);
	}
	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, src_sa, dst_sa);
	if (mbu == NULL) {
		mip6log((LOG_NOTICE,
                         "%s:%d: no matching binding update entry found.\n",
                         __FILE__, __LINE__));
                /* silently ignore */
		m_freem(m);
                return (EINVAL);
	}
	seqno = htons(ip6ma->ip6ma_seqno);
	if (ip6ma->ip6ma_status == IP6MA_STATUS_SEQNO_TOO_SMALL) {
                /*
                 * our home agent has a greater sequence number in its
                 * binging cache entriy of mine.  we should resent
                 * binding update with greater than the sequence
                 * number of the binding cache already exists in our
                 * home agent.  this binding ack is valid though the
                 * sequence number doesn't match.
                 */
		goto check_mobility_options;
	}
	if (seqno != mbu->mbu_seqno) {
                mip6log((LOG_NOTICE,
                         "%s:%d: unmached sequence no "
                         "(%d recv, %d sent) from host %s.\n",
                         __FILE__, __LINE__,
                         seqno,
                         mbu->mbu_seqno,
                         ip6_sprintf(&ip6->ip6_src)));
                /* silently ignore. */
                /* discard */
		m_freem(m);
                return (EINVAL);
	}

 check_mobility_options:


	if (ip6ma->ip6ma_status >= IP6MA_STATUS_ERRORBASE) {
                mip6log((LOG_NOTICE,
                         "%s:%d: a binding update was rejected "
			 "(error code %d).\n",
                         __FILE__, __LINE__, ip6ma->ip6ma_status));
		if (ip6ma->ip6ma_status == IP6MA_STATUS_NOT_HOME_AGENT &&
		    mbu->mbu_flags & IP6MU_HOME &&
		    mbu->mbu_fsm_state == MIP6_BU_FSM_STATE_WAITA) {
			/* XXX no registration? */
			goto success;
		}
		if (ip6ma->ip6ma_status == IP6MA_STATUS_SEQNO_TOO_SMALL) {
			/* seqno is too small.  adjust it and resend. */
			mbu->mbu_seqno = ntohs(ip6ma->ip6ma_seqno) + 1;
			mbu->mbu_state |= MIP6_BU_STATE_WAITSENT;
			return (0);
		}

                /* sending binding update failed. */
                error = mip6_bu_list_remove(&sc->hif_bu_list, mbu);
                if (error) {
                        mip6log((LOG_ERR,
                                 "%s:%d: can't remove BU.\n",
                                 __FILE__, __LINE__));
			m_freem(m);
                        return (error);
                }
                /* XXX some error recovery process needed. */
                return (0);
        }

 success:
	/*
	 * the binding update has been accepted.
	 */

	/* reset WAIT_ACK state. */
	mbu->mbu_state &= ~MIP6_BU_STATE_WAITACK;

	/* update lifetime and refresh time. */
	lifetime = htons(ip6ma->ip6ma_lifetime) << 2;	/* units of 4 secs */
	if (lifetime < mbu->mbu_lifetime) {
		mbu->mbu_expire -= (mbu->mbu_lifetime - lifetime);
		if (mbu->mbu_expire < time_second)
			mbu->mbu_expire = time_second;
	}
	/* XXX binding refresh advice option */
	mbu->mbu_refresh = lifetime;		/* XXX */
	mbu->mbu_refexpire = time_second + mbu->mbu_refresh;
	/* sanity check for overflow */
        if (mbu->mbu_refexpire < time_second)
                mbu->mbu_refexpire = 0x7fffffff;
        if (mbu->mbu_refresh > mbu->mbu_expire)
                mbu->mbu_refresh = mbu->mbu_expire;
	if (mbu->mbu_flags & IP6MU_HOME) {
		/* this is from our home agent. */
		if (mbu->mbu_fsm_state == MIP6_BU_FSM_STATE_WAITD) {
			/* home unregsitration has completed. */

			/* notify all the CNs that we are home. */
			error = mip6_bu_list_notify_binding_change(sc);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: removing the bining cache entries of all CNs failed.\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (error);
			}

			/* remove a tunnel to our homeagent. */
			error = mip6_tunnel_control(MIP6_TUNNEL_DELETE,
						   mbu,
						   mip6_bu_encapcheck,
						   &mbu->mbu_encap);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: tunnel removal failed.\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (error);
			}

			error = mip6_bu_list_remove_all(&sc->hif_bu_list);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: BU remove all failed.\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (error);
			}

			/* XXX: send a unsolicited na. */
		{
			struct sockaddr_in6 sa6, daddr, taddr; /* XXX */
			struct ifaddr *ifa;

			bzero(&sa6, sizeof(sa6));
			sa6.sin6_family = AF_INET6;
			sa6.sin6_len = sizeof(sa6);
			/* XXX or mbu_haddr.  XXX scope consideration  */
			sa6_copy_addr(&mbu->mbu_coa, &sa6);
#ifndef SCOPEDROUTING
			sa6.sin6_scope_id = 0;
#endif

			if ((ifa = ifa_ifwithaddr((struct sockaddr *)&sa6))
			    == NULL) {
				mip6log((LOG_ERR,
					 "%s:%d: can't find CoA interface\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return(EINVAL);	/* XXX */
			}

			bzero(&daddr, sizeof(daddr));
			daddr.sin6_family = AF_INET6;
			daddr.sin6_len = sizeof(daddr);
			daddr.sin6_addr = in6addr_linklocal_allnodes;
			if (in6_addr2zoneid(ifa->ifa_ifp, &daddr.sin6_addr,
					    &daddr.sin6_scope_id)) {
				/* XXX: should not happen */
				mip6log((LOG_ERR,
					 "%s:%d: in6_addr2zoneid failed\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return(EIO);
			}
			if ((error = in6_embedscope(&daddr.sin6_addr,
						    &daddr))) {
				/* XXX: should not happen */
				mip6log((LOG_ERR,
					 "%s:%d: in6_embedscope failed\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return(error);
			}

			bzero(&taddr, sizeof(taddr));
			taddr.sin6_family = AF_INET6;
			taddr.sin6_len = sizeof(taddr);
			sa6_copy_addr(&mbu->mbu_haddr, &taddr);

			nd6_na_output(ifa->ifa_ifp, &daddr,
					      &taddr,
					      ND_NA_FLAG_OVERRIDE,
					      1, NULL);
			mip6log((LOG_INFO,
				 "%s:%d: send a unsolicited na to %s\n",
				 __FILE__, __LINE__, if_name(ifa->ifa_ifp)));
		}
		} else if (mbu->mbu_fsm_state
			   == MIP6_BU_FSM_STATE_WAITA) {
			if (lifetime == 0) {
				mip6log((LOG_WARNING,
					 "%s:%d: lifetime are zero.\n",
					 __FILE__, __LINE__));
				/* XXX ignored */
			}
			/* home registration completed */
			mbu->mbu_fsm_state = MIP6_BU_FSM_STATE_BOUND;

			/* create tunnel to HA */
			error = mip6_tunnel_control(MIP6_TUNNEL_CHANGE,
						    mbu,
						    mip6_bu_encapcheck,
						    &mbu->mbu_encap);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: tunnel move failed.\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (error);
			}

			/* notify all the CNs that we have a new coa. */
			error = mip6_bu_list_notify_binding_change(sc);
			if (error) {
				mip6log((LOG_ERR,
					 "%s:%d: updating the bining cache entries of all CNs failed.\n",
					 __FILE__, __LINE__));
				m_freem(m);
				return (error);
			}
		} else if (mbu->mbu_fsm_state == MIP6_BU_FSM_STATE_BOUND) {
			/* nothing to do. */
		} else {
			mip6log((LOG_NOTICE,
				 "%s:%d: unexpected condition.\n",
				 __FILE__, __LINE__));
		}
	}

	return (0);
}

int
mip6_bu_send_hoti(mbu)
	struct mip6_bu *mbu;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(&mbu->mbu_haddr, &mbu->mbu_paddr,
	    IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: creating ip6hdr failed.\n",
		    __FILE__, __LINE__));
		return (ENOMEM);
	}

	error = mip6_ip6mhi_create(&opt.ip6po_mobility, mbu);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: HoTI creation error (%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
 		goto free_ip6pktopts;
	}

	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
 		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mobility)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (0);
}

int
mip6_bu_send_coti(mbu)
	struct mip6_bu *mbu;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	init_ip6pktopts(&opt);
	opt.ip6po_flags |= IP6PO_USECOA;

	m = mip6_create_ip6hdr(&mbu->mbu_coa, &mbu->mbu_paddr,
	    IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: creating ip6hdr failed.\n",
		    __FILE__, __LINE__));
		return (ENOMEM);
	}

	error = mip6_ip6mci_create(&opt.ip6po_mobility, mbu);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: CoTI creation error (%d)\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
 		goto free_ip6pktopts;
	}
	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending ip packet error. (%d)\n",
		    __FILE__, __LINE__, error));
		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mobility)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (0);
}

int
mip6_bu_send_cbu(mbu)
	struct mip6_bu *mbu;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	int error = 0;

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(&mbu->mbu_haddr, &mbu->mbu_paddr, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
		    "%s:%d: creating ip6hdr failed.\n", __FILE__, __LINE__));
		return (ENOMEM);
	}

	error = mip6_ip6mu_create(&opt.ip6po_mobility, &mbu->mbu_haddr,
	    &mbu->mbu_paddr, mbu->mbu_hif);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: a binding update mobility header "
		    "creation failed (%d).\n",
		    __FILE__, __LINE__, error));
		m_freem(m);
		goto free_ip6pktopts;
	}

	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
		    "%s:%d: sending a binding update falied. (%d)\n",
		    __FILE__, __LINE__, error));
 		goto free_ip6pktopts;
	}

 free_ip6pktopts:
	if (opt.ip6po_mobility)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (error);
}

int
mip6_bc_send_ba(src, dst, dstcoa, status, seqno, lifetime, refresh)
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	struct sockaddr_in6 *dstcoa;
	u_int8_t status;
	u_int16_t seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
{
	struct mbuf *m;
	struct ip6_pktopts opt;
	struct ip6_rthdr *pktopt_rthdr;
	int error = 0;

	init_ip6pktopts(&opt);

	m = mip6_create_ip6hdr(src, dst, IPPROTO_NONE, 0);
	if (m == NULL) {
		mip6log((LOG_ERR,
			 "%s:%d: creating ip6hdr failed.\n",
			 __FILE__, __LINE__));
		return (ENOMEM);
	}

	error =  mip6_ip6ma_create(&opt.ip6po_mobility, src, dst,
				   status, seqno, lifetime, refresh);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: ba destopt creation error (%d)\n",
			 __FILE__, __LINE__, error));
		m_freem(m);
		goto free_ip6pktopts;
	}

	/*
	 * a rthdr must be added when sending back a binding ack to
	 * the mobilenode.  otherwise, the binding ack never reach to
	 * the mobilenode.  for example, the case that an error occurs
	 * when the first home registration.
	 */
	if (!SA6_ARE_ADDR_EQUAL(dst, dstcoa) &&
	    mip6_bc_list_find_withphaddr(&mip6_bc_list, dst) == NULL) {
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

	error = ip6_output(m, &opt, NULL, 0, NULL, NULL);
	if (error) {
		mip6log((LOG_ERR,
			 "%s:%d: sending ip packet error. (%d)\n",
			 __FILE__, __LINE__, error));
		goto free_ip6pktopts;
	}
 free_ip6pktopts:
	if (opt.ip6po_rthdr)
		free(opt.ip6po_rthdr, M_IP6OPT);
	if (opt.ip6po_mobility)
		free(opt.ip6po_mobility, M_IP6OPT);

	return (error);
}

int
mip6_ip6mhi_create(pktopt_mobility, mbu)
	struct ip6_mobility **pktopt_mobility;
	struct mip6_bu *mbu;
{
	struct ip6m_home_test_init *ip6mhi;
	int ip6mhi_size;

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

	*pktopt_mobility = NULL;

	ip6mhi_size =
	    ((sizeof(struct ip6m_home_test_init) +7) >> 3) * 8;

	MALLOC(ip6mhi, struct ip6m_home_test_init *,
	    ip6mhi_size, M_IP6OPT, M_NOWAIT);
	if (ip6mhi == NULL)
		return (ENOMEM);

	bzero(ip6mhi, ip6mhi_size);
	ip6mhi->ip6mhi_pproto = IPPROTO_NONE;
	ip6mhi->ip6mhi_len = ip6mhi_size >> 3;
	ip6mhi->ip6mhi_type = IP6M_HOME_TEST_INIT;
	bcopy(mbu->mbu_mobile_cookie, ip6mhi->ip6mhi_hot_cookie,
	      sizeof(ip6mhi->ip6mhi_hot_cookie));

	/* calculate checksum. */
	ip6mhi->ip6mhi_cksum = mip6_cksum(&mbu->mbu_haddr, &mbu->mbu_paddr,
	    ip6mhi_size, IPPROTO_MOBILITY, (char *)ip6mhi);

	*pktopt_mobility = (struct ip6_mobility *)ip6mhi;

	return (0);
}

int
mip6_ip6mci_create(pktopt_mobility, mbu)
	struct ip6_mobility **pktopt_mobility;
	struct mip6_bu *mbu;
{
	struct ip6m_careof_test_init *ip6mci;
	int ip6mci_size;

	/* sanity check. */
	if (mbu == NULL)
		return (EINVAL);

	*pktopt_mobility = NULL;

	ip6mci_size =
	    ((sizeof(struct ip6m_careof_test_init) + 7) >> 3) * 8;

	MALLOC(ip6mci, struct ip6m_careof_test_init *,
	    ip6mci_size, M_IP6OPT, M_NOWAIT);
	if (ip6mci == NULL)
		return (ENOMEM);

	bzero(ip6mci, ip6mci_size);
	ip6mci->ip6mci_pproto = IPPROTO_NONE;
	ip6mci->ip6mci_len = ip6mci_size >> 3;
	ip6mci->ip6mci_type = IP6M_CAREOF_TEST_INIT;
	bcopy(mbu->mbu_mobile_cookie, ip6mci->ip6mci_cot_cookie,
	      sizeof(ip6mci->ip6mci_cot_cookie));

	/* calculate checksum. */
	ip6mci->ip6mci_cksum = mip6_cksum(&mbu->mbu_coa, &mbu->mbu_paddr,
	    ip6mci_size, IPPROTO_MOBILITY, (char *)ip6mci);

	*pktopt_mobility = (struct ip6_mobility *)ip6mci;

	return (0);
}

#define AUTH_SIZE	(sizeof(struct ip6m_opt_authdata) + SHA1_RESULTLEN)

int
mip6_ip6mu_create(pktopt_mobility, src, dst, sc)
	struct ip6_mobility **pktopt_mobility;
	struct sockaddr_in6 *src, *dst;
	struct hif_softc *sc;
{
	struct ip6m_binding_update *ip6mu;
	struct ip6m_opt_nonce *mopt_nonce = NULL;
	struct ip6m_opt_authdata *mopt_auth = NULL;
	int ip6mu_size;
	int bu_size, nonce_size, auth_size;
	struct mip6_bu *mbu, *hrmbu;
	int need_rr = 0;
	HMAC_CTX hmac_ctx;
	u_int8_t key_bu[SHA1_RESULTLEN]; /* Stated as 'Kbu' in the spec */
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif
#ifdef RR_DBG
	extern void ipsec_hexdump __P((caddr_t, int));
#define mip6_hexdump(m,l,a)			\
		do {				\
			printf("%s", (m));	\
			ipsec_hexdump((caddr_t)(a),(l)); \
			printf("\n");		\
		} while (0)
#endif

	*pktopt_mobility = NULL;

	mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list, dst, src);
	hrmbu = mip6_bu_list_find_home_registration(&sc->hif_bu_list, src);
	if ((mbu == NULL) &&
	    (hrmbu != NULL) &&
	    (hrmbu->mbu_fsm_state == MIP6_BU_FSM_STATE_BOUND)) {
		/* XXX */
		/* create a binding update entry and send CoTI/HoTI. */
		return (0);
	}
	if (mbu == NULL) {
		/*
		 * this is the case that the home registration is on
		 * going.  that is, (mbu == NULL) && (hrmbu != NULL)
		 * but hrmbu->mbu_fsm_state != STATE_REG.
		 */
		return (0);
	}
	if ((mbu->mbu_state & MIP6_BU_STATE_BUNOTSUPP) != 0) {
		/*
		 * MIP6_BU_STATE_NOBUSUPPORT is set when we receive
		 * ICMP6_PARAM_PROB against the binding update sent
		 * before.  this means the peer doesn't support MIP6
		 * (at least the BU destopt).  we should not send any
		 * BU to such a peer.
		 */
		return (0);
	}
	if (SA6_IS_ADDR_UNSPECIFIED(&mbu->mbu_paddr)) {
		/*
		 * the peer addr is unspecified.  this happens when
		 * home registration occurs but no home agent address
		 * is known.
		 */
		mip6log((LOG_INFO,
			 "%s:%d: the peer addr is unspecified.\n",
			 __FILE__, __LINE__));
		mip6_icmp6_ha_discov_req_output(sc);
		return (0);
	}
	if ((mbu->mbu_state & MIP6_BU_STATE_WAITSENT) == 0) {
		/* no need to send. */
		return (0);
	}

	if (!(mbu->mbu_flags & IP6MU_HOME)) {
		need_rr = 1;
	}

	bu_size = sizeof(struct ip6m_binding_update);
	if (need_rr) {
		bu_size += PADLEN(bu_size, 2, 0);
		nonce_size = sizeof(struct ip6m_opt_nonce);
		nonce_size += PADLEN(bu_size + nonce_size, 4, 2);
		auth_size = AUTH_SIZE;
		auth_size += PADLEN(bu_size + nonce_size + auth_size, 8, 0);
#ifdef RR_DBG
printf("MN: bu_size = %d, nonce_size= %d, auth_size = %d(AUTHSIZE:%d)\n", bu_size, nonce_size, auth_size, AUTH_SIZE);
#endif
	} else {
		bu_size += PADLEN(bu_size, 8, 0);
		nonce_size = auth_size = 0;
	}
	ip6mu_size = bu_size + nonce_size + auth_size;

	MALLOC(ip6mu, struct ip6m_binding_update *,
	       ip6mu_size, M_IP6OPT, M_NOWAIT);
	if (ip6mu == NULL)
		return (ENOMEM);

	if (need_rr) {
		mopt_nonce = (struct ip6m_opt_nonce *)((u_int8_t *)ip6mu + bu_size);
		mopt_auth = (struct ip6m_opt_authdata *)((u_int8_t *)mopt_nonce + nonce_size);
	}

	/* update sequence number of this binding update entry. */
	mbu->mbu_seqno++;

	bzero(ip6mu, ip6mu_size);

	if (bu_size - sizeof(struct ip6m_binding_update) >= 2) {
		*((u_int8_t *)ip6mu + sizeof(struct ip6m_binding_update))
			= IP6MOPT_PADN;
		*((u_int8_t *)ip6mu + sizeof(struct ip6m_binding_update) + 1)
			= bu_size - sizeof(struct ip6m_binding_update) - 2;
	}

	ip6mu->ip6mu_pproto = IPPROTO_NONE;
	ip6mu->ip6mu_len = ip6mu_size >> 3;
	ip6mu->ip6mu_type = IP6M_BINDING_UPDATE;
	ip6mu->ip6mu_flags = mbu->mbu_flags;
	ip6mu->ip6mu_seqno = htons(mbu->mbu_seqno);
	if (SA6_ARE_ADDR_EQUAL(&mbu->mbu_haddr, &mbu->mbu_coa)) {
		/* this binding update is for home un-registration. */
		ip6mu->ip6mu_lifetime = 0;
	} else {
		struct mip6_prefix *mpfx;
		u_int32_t haddr_lifetime, coa_lifetime, lifetime;

		mpfx = mip6_prefix_list_find_withhaddr(&mip6_prefix_list,
						       src);
		haddr_lifetime = mpfx->mpfx_pltime;
		coa_lifetime = mip6_coa_get_lifetime(&mbu->mbu_coa.sin6_addr);
		lifetime = haddr_lifetime < coa_lifetime ?
			haddr_lifetime : coa_lifetime;
		if ((mbu->mbu_flags & IP6MU_HOME) == 0) {
			if (mip6_config.mcfg_bu_maxlifetime > 0 &&
			    lifetime > mip6_config.mcfg_bu_maxlifetime)
				lifetime = mip6_config.mcfg_bu_maxlifetime;
		} else {
			if (mip6_config.mcfg_hrbu_maxlifetime > 0 &&
			    lifetime > mip6_config.mcfg_hrbu_maxlifetime)
				lifetime = mip6_config.mcfg_hrbu_maxlifetime;
		}
#ifdef MIP6_SYNC_SA_LIFETIME
		/* XXX k-sugyou */
		if (sav != NULL) {
			u_int32_t sa_lifetime = 0;
			if (sav->lft_h != NULL &&
			    sav->lft_h->sadb_lifetime_addtime != 0) {
				sa_lifetime = sav->lft_h->sadb_lifetime_addtime
					      - (time_second - sav->created);
			}
			if (sa_lifetime > 0 && lifetime > sa_lifetime)
				lifetime = sa_lifetime;
		}
#endif /* MIP6_SYNC_SA_LIFETIME */
		mbu->mbu_lifetime = lifetime;
		mbu->mbu_expire = time_second + mbu->mbu_lifetime;
		mbu->mbu_refresh = mbu->mbu_lifetime;
		mbu->mbu_refexpire = time_second + mbu->mbu_refresh;
		ip6mu->ip6mu_lifetime =
		    htons((u_int16_t)(mbu->mbu_lifetime >> 2));	/* units 4 secs */
	}

	if (need_rr) {
		/* nonce indices and authdata insersion. */
		/* Nonce Indicies */
		mopt_nonce->ip6mon_type = IP6MOPT_NONCE;
		mopt_nonce->ip6mon_len = sizeof(struct ip6m_opt_nonce) - 2;
		SET_NETVAL_S(&mopt_nonce->ip6mon_home_nonce_index,
			     mbu->mbu_home_nonce_index);
		SET_NETVAL_S(&mopt_nonce->ip6mon_careof_nonce_index,
			     mbu->mbu_careof_nonce_index);

		/* Auth. data */
		mopt_auth->ip6moau_type = IP6MOPT_AUTHDATA;
		mopt_auth->ip6moau_len = AUTH_SIZE - 2;

#ifdef RR_DBG
mip6_hexdump("MN: Home Cookie: ", sizeof(mbu->mbu_home_cookie), (caddr_t)&mbu->mbu_home_cookie);
mip6_hexdump("MN: Care-of Cookie: ", sizeof(mbu->mbu_careof_cookie), (caddr_t)&mbu->mbu_careof_cookie);
#endif
		/* Calculate K_bu */
		mip6_calculate_kbu(&mbu->mbu_home_cookie, &mbu->mbu_careof_cookie, key_bu);
#ifdef RR_DBG
mip6_hexdump("MN: K_bu: ", sizeof(key_bu), key_bu);
#endif

		/* Calculate authenticator (5.5.6) */
		/* MAC_Kbu(coa, | cn | BU) */
		hmac_init(&hmac_ctx, key_bu, sizeof(key_bu), HMAC_SHA1);
		hmac_loop(&hmac_ctx, (u_int8_t *)&mbu->mbu_coa.sin6_addr,
			  sizeof(mbu->mbu_coa.sin6_addr));
#ifdef RR_DBG
mip6_hexdump("MN: Auth: ", sizeof(mbu->mbu_coa.sin6_addr), &mbu->mbu_coa.sin6_addr);
#endif
		hmac_loop(&hmac_ctx, (u_int8_t *)&dst->sin6_addr,
			  sizeof(dst->sin6_addr));
#ifdef RR_DBG
mip6_hexdump("MN: Auth: ", sizeof(dst->sin6_addr), &dst->sin6_addr);
#endif
		hmac_loop(&hmac_ctx, (u_int8_t *)ip6mu, bu_size + nonce_size);
#ifdef RR_DBG
mip6_hexdump("MN: Auth: ", bu_size + nonce_size, ip6mu);
#endif
		/* Eliminate authdata mobility option to calculate authdata 
		   But it should be included padding area */
		if (auth_size > AUTH_SIZE) {
			*((u_int8_t *)ip6mu + bu_size + nonce_size + AUTH_SIZE)
			    = IP6MOPT_PADN;
			*((u_int8_t *)ip6mu + bu_size + nonce_size + AUTH_SIZE + 1)
			    = auth_size - AUTH_SIZE - 2;
			hmac_loop(&hmac_ctx,
				  (u_int8_t *)ip6mu + bu_size + nonce_size
				  + AUTH_SIZE, auth_size - AUTH_SIZE);
#ifdef RR_DBG
mip6_hexdump("MN: Auth: ", auth_size - AUTH_SIZE, (u_int8_t *)ip6mu + bu_size + nonce_size + AUTH_SIZE);
#endif
		}
		hmac_result(&hmac_ctx, (u_int8_t *)(mopt_auth + 1));
#ifdef RR_DBG
mip6_hexdump("MN: Authdata: ", SHA1_RESULTLEN, (u_int8_t *)(mopt_auth + 1));
#endif
	}

	/* calculate checksum. */
	ip6mu->ip6mu_cksum = mip6_cksum(&mbu->mbu_haddr, dst, ip6mu_size,
					IPPROTO_MOBILITY, (char *)ip6mu);

	*pktopt_mobility = (struct ip6_mobility *)ip6mu;

	/* hoping that the binding update will be sent with no accident. */
	mbu->mbu_state &= ~MIP6_BU_STATE_WAITSENT;

	return (0);
}

int
mip6_ip6ma_create(pktopt_mobility, src, dst, status, seqno, lifetime, refresh)
	struct ip6_mobility **pktopt_mobility;
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	u_int8_t status;
	u_int16_t seqno;
	u_int32_t lifetime;
	u_int32_t refresh;
{
	struct ip6m_binding_ack *ip6ma;
	int ip6ma_size, pad;

	*pktopt_mobility = NULL;

	ip6ma_size = sizeof(struct ip6m_binding_ack);
	pad = (ip6ma_size + 8) & 7;
	ip6ma_size += pad;	/* XXX */

	MALLOC(ip6ma, struct ip6m_binding_ack *,
	       ip6ma_size, M_IP6OPT, M_NOWAIT);
	if (ip6ma == NULL)
		return (ENOMEM);

	bzero(ip6ma, ip6ma_size);
	ip6ma->ip6ma_pproto = IPPROTO_NONE;
	ip6ma->ip6ma_len = ip6ma_size >> 3;
	ip6ma->ip6ma_type = IP6M_BINDING_ACK;
	ip6ma->ip6ma_status = status;
	ip6ma->ip6ma_seqno = htons(seqno);
	ip6ma->ip6ma_lifetime =
		htons((u_int16_t)(lifetime >> 2));	/* units of 4 secs */

	/* XXX binding refresh advice option */

	/* XXX authorization data processing. */

	/* XXX padN */
	if (pad > 1) {
		u_char *p = ((u_char *)ip6ma) + ip6ma_size - pad;
		*p++ = IP6MOPT_PADN;
		*p = pad - 2;
	}

	/* calculate checksum. */
	ip6ma->ip6ma_cksum = mip6_cksum(src, dst, ip6ma_size,
					IPPROTO_MOBILITY, (char *)ip6ma);

	*pktopt_mobility = (struct ip6_mobility *)ip6ma;

	return (0);
}


int
mip6_ip6me_input(m, ip6me, ip6melen)
	struct mbuf *m;
	struct ip6m_binding_error *ip6me;
	int ip6melen;
{
	struct sockaddr_in6 *src_sa, *dst_sa;
	struct sockaddr_in6 hoa;
	u_int32_t hoazone;
	struct hif_softc *sc;
	struct mip6_bu *mbu;
	int error = 0;

	/* get packet source and destination addrresses. */
	if (ip6_getpktaddrs(m, &src_sa, &dst_sa)) {
		/* must not happen. */
		goto bad;
	}

	/* packet length check. */
	if (ip6melen < sizeof (struct ip6m_binding_error)) {
		mip6log((LOG_NOTICE,
		    "%s:%d: too short binding error (len = %d) "
		    "from host %s.\n",
		    __FILE__, __LINE__,
		    ip6melen, ip6_sprintf(&src_sa->sin6_addr)));
		/* discard. */
		goto bad;
	}

	/* extract the home address of the sending node. */
	bzero (&hoa, sizeof (hoa));
	hoa.sin6_len = sizeof (hoa);
	hoa.sin6_family = AF_INET6;
	bcopy(&ip6me->ip6me_addr, &hoa.sin6_addr,
	    sizeof(struct in6_addr));
	if (in6_addr2zoneid(m->m_pkthdr.rcvif, &hoa.sin6_addr, &hoazone)) {
		ip6stat.ip6s_badscope++;
		goto bad;
	}
	hoa.sin6_scope_id = hoazone;
	if (in6_embedscope(&hoa.sin6_addr, &hoa)) {
		ip6stat.ip6s_badscope++;
		goto bad;
	}

	/* find hif corresponding to the home address. */
	sc = hif_list_find_withhaddr(&hoa);
	if (sc == NULL) {
		/* we have no such home address. */
		goto bad;
	}

	/* find the corresponding binding update entry. */
	switch (ip6me->ip6me_status) {
	case IP6ME_STATUS_NO_BINDING:
	case IP6ME_STATUS_UNKNOWN_MH_TYPE:
		mbu = mip6_bu_list_find_withpaddr(&sc->hif_bu_list,
		    src_sa, &hoa);
		if (mbu == NULL) {
			/* we have no binding update entry for the CN. */
			goto bad;
		}
		break;

	default:
		mip6log((LOG_INFO,
		    "%s:%d: unknown BE status code (status = %u) "
		    "from host %s.\n",
		    __FILE__, __LINE__,
		    ip6me->ip6me_status, ip6_sprintf(&src_sa->sin6_addr)));
		goto bad;
		break;
	}

	switch (ip6me->ip6me_status) {
	case IP6ME_STATUS_NO_BINDING:
		/* the CN doesn't have a binding cache entry.  start RR. */
		error = mip6_bu_fsm(mbu, MIP6_BU_FSM_EVENT_BE_1_RECEIVED,
		    ip6me);
		if (error) {
			mip6log((LOG_ERR,
			    "%s:%d: state transition failed. (%d)\n",
			    __FILE__, __LINE__, error));
			goto bad;
		}

		break;

	case IP6ME_STATUS_UNKNOWN_MH_TYPE:
		/* XXX future extension? */
		error = mip6_bu_fsm(mbu, MIP6_BU_FSM_EVENT_BE_2_RECEIVED,
		    ip6me);
		if (error) {
			mip6log((LOG_ERR,
			    "%s:%d: state transition failed. (%d)\n",
			    __FILE__, __LINE__, error));
			goto bad;
		}

		break;

	default:
		mip6log((LOG_INFO,
		    "%s:%d: unknown BE status code (status = %u) "
		    "from host %s.\n",
		    __FILE__, __LINE__,
		    ip6me->ip6me_status, ip6_sprintf(&src_sa->sin6_addr)));

		/* XXX what to do? */
	}

	return (0);

 bad:
	m_freem(m);
	return (EINVAL);
}

int
mip6_ip6me_create(pktopt_mobility, src, dst, status, addr)
	struct ip6_mobility **pktopt_mobility;
	struct sockaddr_in6 *src;
	struct sockaddr_in6 *dst;
	u_int8_t status;
	struct sockaddr_in6 *addr;
{
	struct ip6m_binding_error *ip6me;
	int ip6me_size;

	*pktopt_mobility = NULL;

	ip6me_size = sizeof(struct ip6m_binding_error);

	MALLOC(ip6me, struct ip6m_binding_error *,
	       ip6me_size, M_IP6OPT, M_NOWAIT);
	if (ip6me == NULL)
		return (ENOMEM);

	bzero(ip6me, ip6me_size);
	ip6me->ip6me_pproto = IPPROTO_NONE;
	ip6me->ip6me_len = ip6me_size >> 3;
	ip6me->ip6me_type = IP6M_BINDING_ERROR;
	ip6me->ip6me_status = status;
	ip6me->ip6me_addr = addr->sin6_addr;
	in6_clearscope(&ip6me->ip6me_addr);

	/* calculate checksum. */
	ip6me->ip6me_cksum = mip6_cksum(src, dst, ip6me_size,
					IPPROTO_MOBILITY, (char *)ip6me);

	*pktopt_mobility = (struct ip6_mobility *)ip6me;
	return (0);
}

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE do {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);} while(0);
static int
mip6_cksum(src_sa, dst_sa, plen, nh, mobility)
	struct sockaddr_in6 *src_sa;
	struct sockaddr_in6 *dst_sa;
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
	uph.uph_un.uph_src = src_sa->sin6_addr;
	in6_clearscope(&uph.uph_un.uph_src);
	uph.uph_un.uph_dst = dst_sa->sin6_addr;
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
	return(~sum & 0xffff);
}
#undef ADDCARRY
#undef REDUCE

