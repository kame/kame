/*	$KAME: mip6.c,v 1.38 2001/03/29 05:34:31 itojun Exp $	*/

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
#include <sys/syslog.h>
#include <sys/ioccom.h>

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

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

#ifdef MIP6_DEBUG
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <machine/stdarg.h>
#include <sys/syslog.h>
#endif

#include <net/net_osdep.h>

int  (*mip6_write_config_data_ha_hook)(u_long, void *) = 0;
int  (*mip6_clear_config_data_ha_hook)(u_long, void *) = 0;
int  (*mip6_enable_func_ha_hook)(u_long, caddr_t) = 0;
int  (*mip6_write_config_data_mn_hook)(u_long, void *) = 0;
int  (*mip6_clear_config_data_mn_hook)(u_long, caddr_t) = 0;
int  (*mip6_enable_func_mn_hook)(u_long, caddr_t) = 0;


#ifdef MIP6_DEBUG
int mip6_debug_is_enabled = 0;
#endif


/* Declaration of Global variables. */
struct mip6_bc     *mip6_bcq = NULL;  /* First entry in BC list */
struct mip6_na     *mip6_naq = NULL;  /* First entry in NA list */
struct mip6_prefix *mip6_prq = NULL;  /* First entry in prefix list */
struct mip6_halst  *mip6_haq = NULL;  /* First entry in Home Agents */
struct mip6_config  mip6_config;      /* Config parameters for MIPv6 */


u_int8_t mip6_module = 0;             /* Info about loaded modules */

extern struct ip6protosw mip6_tunnel_protosw;

#ifdef __NetBSD__
struct callout mip6_timer_bc_ch = CALLOUT_INITIALIZER;
struct callout mip6_timer_na_ch = CALLOUT_INITIALIZER;
struct callout mip6_timer_pr_ch = CALLOUT_INITIALIZER;
struct callout mip6_timer_ha_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_timer_bc_ch;
struct callout mip6_timer_na_ch;
struct callout mip6_timer_pr_ch;
struct callout mip6_timer_ha_ch;
#elif defined(__OpenBSD__)
struct timeout mip6_timer_bc_ch;
struct timeout mip6_timer_na_ch;
struct timeout mip6_timer_pr_ch;
struct timeout mip6_timer_ha_ch;
#endif


/* Definitions of some costant IP6 addresses. */
struct in6_addr in6addr_linklocal;
struct in6_addr in6addr_aha_64;
struct in6_addr in6addr_aha_nn;


/*
 ##############################################################################
 #
 # INITIALIZATION AND EXIT FUNCTIONS
 # These functions are executed when either the mobile node specific MIPv6
 # code or the home agent specific MIPv6 code is activated and deactivated
 # respectively.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_init
 * Description: Initialization of MIPv6 variables that must be initialized
 *              before the code is executed.
 ******************************************************************************
 */
void
mip6_init(void)
{
	static int mip6_init_done = 0;

	if (mip6_init_done)
		return;

	/* Initialize global addresses. */
	in6addr_linklocal.s6_addr32[0] = MIP6_ADDR_INT32_ULL;
	in6addr_linklocal.s6_addr32[1] = 0x00000000;
	in6addr_linklocal.s6_addr32[2] = 0x00000000;
	in6addr_linklocal.s6_addr32[3] = 0x00000000;

	in6addr_aha_64.s6_addr32[0] = 0x00000000;
	in6addr_aha_64.s6_addr32[1] = 0xffffffff;
	in6addr_aha_64.s6_addr32[2] = MIP6_ADDR_INT32_AHA2;
	in6addr_aha_64.s6_addr32[3] = MIP6_ADDR_INT32_AHA1;

	in6addr_aha_nn.s6_addr32[0] = 0x00000000;
	in6addr_aha_nn.s6_addr32[1] = 0xffffffff;
	in6addr_aha_nn.s6_addr32[2] = 0xffffffff;
	in6addr_aha_nn.s6_addr32[3] = MIP6_ADDR_INT32_AHA1;

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	/* Initialize handle for timer functions. */
	callout_init(&mip6_timer_bc_ch);
	callout_init(&mip6_timer_na_ch);
	callout_init(&mip6_timer_pr_ch);
	callout_init(&mip6_timer_ha_ch);
#endif

	/* Initialize global variable */
	bzero(&mip6_config, sizeof(struct mip6_config));

	/* Set default values for MIP6 configuration parameters. */
	LIST_INIT(&mip6_config.fna_list);

	mip6_config.bu_lifetime = 600;
	mip6_config.br_update = 60;
	mip6_config.hr_lifetime = 3600;

	mip6_hifp = ifunit("lo0");

	printf("Mobile Node initialized\n");
	mip6_enable_hooks(MIP6_GENERIC_HOOKS);
	mip6_enable_hooks(MIP6_CONFIG_HOOKS);

	mip6_init_done = 1;
	printf("Initializing Mobile IPv6\n");
}



/*
 ******************************************************************************
 * Function:    mip6_exit
 * Description: This function is called when the module is unloaded (relesed)
 *              from the kernel.
 ******************************************************************************
 */
void
mip6_exit(void)
{
	struct mip6_na     *nap, *nap_tmp;
	struct mip6_bc     *bcp, *bcp_nxt;
	struct mip6_prefix *pfx;
	struct mip6_halst  *hap;
	int                 s;

	/* Cancel outstanding timeout function calls. */
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&mip6_timer_bc_ch);
	callout_stop(&mip6_timer_na_ch);
	callout_stop(&mip6_timer_pr_ch);
	callout_stop(&mip6_timer_ha_ch);
#else
	untimeout(mip6_timer_bc, (void *)NULL);
	untimeout(mip6_timer_na, (void *)NULL);
	untimeout(mip6_timer_prefix, (void *)NULL);
	untimeout(mip6_timer_hal, (void *)NULL);
#endif

	/* Remove each entry in every queue. */
	s = splnet();
	for (bcp = mip6_bcq; bcp;) {
		mip6_bc_delete(bcp, &bcp_nxt);
		bcp = bcp_nxt;
	}
	mip6_bcq = NULL;

	for (nap = mip6_naq; nap;) {
		nap_tmp = nap;
		nap = nap->next;
		free(nap_tmp, M_TEMP);
	}
	mip6_naq = NULL;

	for (pfx = mip6_prq; pfx;) {
		pfx = mip6_prefix_delete(pfx);
	}
	mip6_prq = NULL;

	for (hap = mip6_haq; hap;) {
		hap = mip6_hal_delete(hap);
	}
	mip6_haq = NULL;
	splx(s);
}



/*
 ##############################################################################
 #
 # FUNCTIONS FOR PROCESSING OF INBOUND MIPV6 OPTIONS
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
 * Function:    mip6_validate_bu
 * Description: Validate received Binding Update option (see 8.2).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_validate_bu(m, opt)
struct mbuf  *m;      /* Ptr to beginning of mbuf */
u_int8_t     *opt;    /* Ptr to BU option in DH */
{
	struct ip6_opt_binding_update  *bu_opt;
	struct ip6aux                  *ip6a = NULL;
	struct ip6_hdr                 *ip6;
	struct mip6_bc                 *bcp;
	struct mbuf                    *n;

	bu_opt = (struct ip6_opt_binding_update *)(opt);
	ip6 = mtod(m, struct ip6_hdr *);
	    
	/* Make sure that the BU is protected by an AH (see 4.4). */
#ifdef IPSEC
#ifndef __OpenBSD__
	if ( !(m->m_flags & M_AUTHIPHDR && m->m_flags & M_AUTHIPDGM)) {
		log(LOG_ERR,
		    "%s: BU not protected by AH from host %s\n",
		    __FUNCTION__, ip6_sprintf(&ip6->ip6_src));
		return -1;
	}
#endif
#endif

	/* Make sure that the BU contains a valid Home Address option. */
	n = ip6_findaux(m);
	if (!n) return -1;

	ip6a = mtod(n, struct ip6aux *);
	if ((ip6a == NULL) || (ip6a->ip6a_flags & IP6A_HASEEN) == 0) {
		log(LOG_ERR,
		    "%s: No Home Address option found for BU from host %s\n",
		    __FUNCTION__, ip6_sprintf(&ip6->ip6_src));
		return -1;
	}

	/* Make sure that the length field in the BU is >= IP6OPT_BULEN. */
	if (bu_opt->ip6ou_len < IP6OPT_BULEN) {
		ip6stat.ip6s_badoptions++;
		log(LOG_ERR,
		    "%s: Length field to short (%d) in BU from host %s\n",
		    __FUNCTION__, bu_opt->ip6ou_len,
		    ip6_sprintf(&ip6->ip6_src));
		return -1;
	}

	/* The sequence no in the BU must be greater than the sequence
	    number in the previous BU recieved (modulo 2^^16). */
	bcp = mip6_bc_find(&ip6->ip6_dst, &ip6a->ip6a_home);
	if (bcp != NULL) {
		if (MIP6_LEQ(ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno),
			     bcp->seqno)) {
			ip6stat.ip6s_badoptions++;
			log(LOG_ERR,
			    "%s: Received sequence no (%d) <= current "
			    "seq no (%d) in BU from host %s\n",
			    __FUNCTION__,
			    ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno),
			    bcp->seqno, ip6_sprintf(&ip6->ip6_src));
			return -1;
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_validate_subopt
 * Description: Validates sub-options included in MIPv6 options (see 5.5).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_validate_subopt(dh, subopt, optlen)
struct ip6_dest *dh;       /* Ptr to beginning of DH */
u_int8_t        *subopt;   /* Ptr to first sub-option in current option */
u_int8_t         optlen;   /* Remaining option length */
{
	/* Validate all sub-options for current option */
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
				/* Verify alignment requirement: 2n */
				if ((subopt - (u_int8_t *)dh) % 2 != 0) {
					ip6stat.ip6s_badoptions++;
					log(LOG_ERR,
					    "%s: Alignment failure in Unique "
					    "Identifier sub-option\n",
					    __FUNCTION__);
					return -1;
				}

				if (*(subopt + 1) != IP6OPT_UIDLEN)
					return -1;

				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
			case IP6SUBOPT_ALTCOA:
				/* Verify alignment requirement: 8n+6 */
				if ((subopt - (u_int8_t *)dh) % 8 != 6) {
					ip6stat.ip6s_badoptions++;
					log(LOG_ERR,
					    "%s: Alignment failure in "
					    "Alternate COA sub-option\n",
					    __FUNCTION__);
					return -1;
				}

				if (*(subopt + 1) != IP6OPT_COALEN)
					return -1;

				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
			default:
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_process_bu
 * Description: Process a received Binding Update option (see 8.2).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_process_bu(m, opt)
struct mbuf  *m;    /* Ptr to beginning of mbuf */
u_int8_t     *opt;  /* Ptr to BU option in DH */
{
	struct ip6_opt_binding_update  *bu_opt;
	struct in6_addr                *coa;
	struct ip6_hdr                 *ip6;
	struct mip6_subopt_altcoa      *altcoa;
	struct mip6_bc                 *bcp, *bcp_nxt;
	struct ip6aux                  *ip6a = NULL;
	struct mbuf                    *n;
	u_int8_t                       *subopt, optlen;
	u_long                          flags = 0;
	int                             res;

	bu_opt = (struct ip6_opt_binding_update *)(opt);
	ip6 = mtod(m, struct ip6_hdr *);

	n = ip6_findaux(m);
	if (!n) return -1;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return -1;

	/* Find the care-of address used by the MN when sending the BU. */
	subopt = opt + IP6OPT_MINLEN + IP6OPT_BULEN;
	optlen = *(opt + 1) - IP6OPT_BULEN;
	altcoa = mip6_find_subopt_altcoa(subopt, optlen);
	if (altcoa == NULL)
		coa = &ip6a->ip6a_careof;
	else
		coa = (struct in6_addr *)&altcoa->coa;

#ifdef MIP6_DEBUG
	mip6_print_opt(m, opt);
#endif

	/* Shall Dynamic Home Agent Address Discovery be performed? */

	/* Check if BU includes Unique Identifier sub-option is present. */
	/* XXX Code have to be added. */

	/* Is this a request to cache a binding for the MN? (see 8.2) */
	if ((ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime) != 0) &&
	    (! IN6_ARE_ADDR_EQUAL(&ip6a->ip6a_home, coa))) {
		/* Request to cache a binding. Processing depends on H-bit. */
		if (bu_opt->ip6ou_flags & IP6_BUF_HOME) {
			/* According to section 9.3. */
			res = mip6_accept_bu(m, opt);
			if (res == -1) return -1;
			else if (res == -2) return 0;

#ifdef MIP6_TBD
			if (bu_opt->ip6ou_flags & IP6_BUF_DAD) {
				/* Reply will be returned once the DAD has
				   been completed. */
				return 0;
			}
#endif

			bcp = mip6_cache_binding(m, opt, coa);
			if (bcp)
				res = MIP6_BA_STATUS_ACCEPT;
			else
				res = MIP6_BA_STATUS_UNSPEC;

			if (mip6_build_send_ba(m, opt, bcp, NULL, res) == -1)
				return -1;
			if (bcp == NULL) return 0;

			/* Create a new or move existing tunnel to the MN. */
			res = mip6_tunnel(&ip6->ip6_dst, &bcp->peer_coa,
					  MIP6_TUNNEL_MOVE, MIP6_NODE_HA,
					  (void *)bcp);
			if (res) return -1;
			
			/* The HA should act as proxy for the MN and inter-
			   cept packets while it is at a FN. (see 9.5) */
			mip6_proxy_control(bcp, RTM_ADD);

			if (bcp->flags & IP6_BUF_ROUTER)
				flags |= ND_NA_FLAG_ROUTER;
			flags |= ND_NA_FLAG_OVERRIDE;
			mip6_intercept_control(&bcp->peer_home,
					       bcp->prefixlen, flags);
		} else {
			/* According to section 8.3. */
			bcp = mip6_cache_binding(m, opt, coa);
			if (bcp)
				res = MIP6_BA_STATUS_ACCEPT;
			else
				res = MIP6_BA_STATUS_UNSPEC;
			
			if (mip6_build_send_ba(m, opt, bcp, NULL, res) == -1)
				return -1;
		}
		return 0;
	}		

	/* Check if this is a request to delete a binding for the MN. */
	if ((ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime) == 0) ||
	    (IN6_ARE_ADDR_EQUAL(&ip6a->ip6a_home, coa))) {
		/* Request to delete a binding. Processing depends on H-bit. */
		if (bu_opt->ip6ou_flags & IP6_BUF_HOME) {
			/* According to section 9.4. */
			bcp = mip6_bc_find(&ip6->ip6_dst, &ip6a->ip6a_home);

			/* Validation before deletion of BC entry. */
			if (bcp == NULL || !(bcp->flags & IP6_BUF_HOME)) {
				if (mip6_build_send_ba(m, opt, bcp, NULL,
						       MIP6_BA_STATUS_NOTHA)
				                       == -1)
					return -1;
				else
					return 0;
			}

			/* Stop acting as a proxy for the MN, i.e. remove
			   address(es) from the routing table (see 9.5) */
			mip6_proxy_control(bcp, RTM_DELETE);
			
			/* Send BA back to the MN. */
			if (mip6_build_send_ba(m, opt, bcp, NULL,
					       MIP6_BA_STATUS_ACCEPT) == -1)
				return -1;

			/* Remove the existing tunnel to the MN. This is
			   handled by the mip6_bc_delete() function */
			res = mip6_bc_delete(bcp, &bcp_nxt);
			if (res) return -1;
		} else {
			/* According to section 8.4. */
			bcp = mip6_bc_find(&ip6->ip6_dst, &ip6a->ip6a_home);

			if (!(bu_opt->ip6ou_flags & IP6_BUF_ACK) &&
			    (bcp == NULL)) {
				/* Accepted and no BC entry to delete and
				   no requirement to send a BA. */
				return 0;
			}

			if (bcp)
				res = MIP6_BA_STATUS_ACCEPT;
			else
				res = MIP6_BA_STATUS_UNSPEC;

			/* Send BA back to the MN. */
			if (mip6_build_send_ba(m, opt, bcp, NULL, res) == -1)
				return -1;
			if (bcp == NULL) return 0;

			/* Delete BC entry */
			res = mip6_bc_delete(bcp, &bcp_nxt);
			if (res) return -1;
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_find_subopt_uid
 * Description: Find the Unique Identifier sub-option in the BU option.
 * Ret value:   Ptr to uid sub-option or NULL
 ******************************************************************************
 */
struct mip6_subopt_uid *
mip6_find_subopt_uid(subopt, optlen)
u_int8_t  *subopt;   /* Ptr to first sub-option in current option */
u_int8_t   optlen;   /* Remaining option length */
{
	struct mip6_subopt_uid  *uid = NULL;

	/* Search all sub-options for current option */
	while (optlen > 0) {
		switch (*subopt) {
			case IP6OPT_PAD1:
				optlen -= 1;
				subopt += 1;
				break;
			case IP6SUBOPT_UNIQUEID:
				uid = (struct mip6_subopt_uid *)subopt;
				return uid;
			default:
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
		}
	}
	return uid;
}



/*
 ******************************************************************************
 * Function:    mip6_find_subopt_altcoa
 * Description: Find the Alternate care-of address sub-option in the BU option.
 * Ret value:   Ptr to Alternate care-of address sub-option or NULL
 ******************************************************************************
 */
struct mip6_subopt_altcoa *
mip6_find_subopt_altcoa(subopt, optlen)
u_int8_t  *subopt;   /* Ptr to first sub-option in current option */
u_int8_t   optlen;   /* Remaining option length */
{
	struct mip6_subopt_altcoa  *altcoa = NULL;

	/* Search all sub-options for current option */
	while (optlen > 0) {
		switch (*subopt) {
			case IP6OPT_PAD1:
				optlen -= 1;
				subopt += 1;
				break;
			case IP6SUBOPT_ALTCOA:
				altcoa = (struct mip6_subopt_altcoa *)subopt;
				return altcoa;
			default:
				optlen -= *(subopt + 1) + 2;
				subopt += *(subopt + 1) + 2;
				break;
		}
	}
	return altcoa;
}



/*
 ******************************************************************************
 * Function:    mip6_cache_binding
 * Description: As a result of receiving a BU the node will cache the mobile
 *              node's binding. The receiving node should create a new BC
 *              entry or update its existing BC entry (see 8.3 and 9.3).
 * Ret value:   Pointer to BC entry or NULL
 ******************************************************************************
 */
struct mip6_bc *
mip6_cache_binding(m, opt, coa)
struct mbuf     *m;    /* Ptr to beginning of mbuf */
u_int8_t        *opt;  /* Ptr to BU option in DH */
struct in6_addr *coa;  /* Care-of address for peer node */
{
	struct ip6_opt_binding_update  *bu_opt;
	struct ip6_hdr                 *ip6;
	struct mip6_bc                 *bcp;
	struct ip6aux                  *ip6a = NULL;
	struct mbuf                    *n;
	u_int32_t                       lifetime;

	n = ip6_findaux(m);
	if (!n) return NULL;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return NULL;
	ip6 = mtod(m, struct ip6_hdr *);

	/* Find out which lifetime to use in the BA */
	bu_opt = (struct ip6_opt_binding_update *)opt;
	if (bu_opt->ip6ou_flags & IP6_BUF_HOME) {
		lifetime = mip6_min_lifetime(&ip6a->ip6a_home,
					     bu_opt->ip6ou_prefixlen);
		lifetime = min(lifetime,
			       ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime));
	} else {
		lifetime = ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime);
	}

	/* Create a new or update an existing BC entry. */
	bcp = mip6_bc_find(&ip6->ip6_dst, &ip6a->ip6a_home);
	if (bcp)
		mip6_bc_update(opt, bcp, coa, lifetime);
	else
		bcp = mip6_bc_create(m, opt, coa, lifetime);
	return bcp;
}



/*
 ******************************************************************************
 * Function:    mip6_build_send_ba
 * Description: As a result of receiving a BU the node must send a BA if the
 *              A-bit is set in the BU. If the node rejects the BU and does
 *              not create or update a BC entry a BA must be sent, even if the
 *              A-bit was not set in the BU (see section 8.5, 5.2, 8.9, 9.4).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_build_send_ba(m, opt, bcp, subbuf, status)
struct mbuf        *m;       /* Ptr to beginning of mbuf */
u_int8_t           *opt;     /* Ptr to BU option in DH */
struct mip6_bc     *bcp;     /* BC entry if accept, NULL if reject */
struct mip6_buffer *subbuf;  /* Buffer of BA sub-options or NULL */
u_int8_t            status;  /* Result of the Binding Update request */
{
	struct ip6_opt_binding_update  *bu_opt;
	struct ip6_opt_binding_ack     *ba_opt;
	struct mip6_subopt_altcoa      *altcoa;
	struct mip6_buffer              dh2;
	struct ip6_rthdr               *ip6_rthdr = NULL;
	struct ip6_ext                 *ext_hdr;
	struct in6_addr                *coa;
	struct ip6_hdr                 *ip6;
	struct ip6aux                  *ip6a = NULL;
	struct mbuf                    *n, *mo = NULL;
	u_int8_t                       *subopt, *ba_pos, optlen;
	u_int16_t                       seqno;
	int                             res;

	bu_opt = (struct ip6_opt_binding_update *)opt;
	ba_opt = NULL;
	ip6 = mtod(m, struct ip6_hdr *);

	n = ip6_findaux(m);
	if (!n) return -1;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return -1;

	/* Find the care-of address used by the MN when sending the BU. */
	subopt = opt + IP6OPT_MINLEN + IP6OPT_BULEN;
	optlen = *(opt + 1) - IP6OPT_BULEN;
	altcoa = mip6_find_subopt_altcoa(subopt, optlen);
	if (altcoa == NULL)
		coa = &ip6a->ip6a_careof;
	else
		coa = (struct in6_addr *)&altcoa->coa;

	/* Send a BA to the MN if the A-bit is set and it was accepted. */
	if ((bu_opt->ip6ou_flags & IP6_BUF_ACK) && bcp) {
		mo = mip6_create_ip6hdr(&ip6->ip6_dst, &bcp->peer_home,
					IPPROTO_NONE, 0);
		if (mo == NULL) return -1;

		if ((ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime) == 0) ||
		    (IN6_ARE_ADDR_EQUAL(&ip6a->ip6a_home, coa))) {
			/* If de-registration of primary care-of address */
			ip6_rthdr = mip6_create_rh(coa, IPPROTO_DSTOPTS);
		} else {
			/* If registration of primary care-of address */
			ip6_rthdr = mip6_create_rh(&bcp->peer_coa,
						   IPPROTO_DSTOPTS);
		}
		if (ip6_rthdr == NULL) {
			free(mo, M_TEMP);
			return -1;
		}

		if (status >= MIP6_BA_STATUS_UNSPEC)
			status = MIP6_BA_STATUS_ACCEPT;
		
		if ((ntohl(*(u_int32_t *)bu_opt->ip6ou_lifetime) == 0) ||
		    (IN6_ARE_ADDR_EQUAL(&ip6a->ip6a_home, coa))) {
			/* If de-registration of primary care-of address */
			seqno = ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno);
			ba_opt = mip6_create_ba(status, seqno, 0);
		} else {
			/* If registration of primary care-of address */
			ba_opt = mip6_create_ba(status, bcp->seqno,
						bcp->lifetime);
		}	
		if (ba_opt == NULL) {
			free(mo, M_TEMP);
			free(ip6_rthdr, M_TEMP);
			return -1;
		}

		bzero((caddr_t)&dh2, sizeof(dh2));
		ba_pos = mip6_add_opt2dh((u_int8_t *)ba_opt, &dh2);
		mip6_add_subopt2dh(subbuf, &dh2, ba_pos);
		mip6_align(&dh2);
		ext_hdr = (struct ip6_ext *)&dh2.buf;
		ext_hdr->ip6e_nxt = IPPROTO_NONE;

		res = mip6_send_ba(mo, ip6_rthdr, (struct ip6_dest *)dh2.buf);
		if (res == -1) {
			if (mo) free(mo, M_TEMP);
			if (ip6_rthdr) free(ip6_rthdr, M_TEMP);
			free(ba_opt, M_TEMP);
			return -1;
		}
	}

	if (bcp == NULL) {
		mo = mip6_create_ip6hdr(&ip6->ip6_dst, &ip6a->ip6a_home,
					IPPROTO_NONE, 0);
		if (mo == NULL) return -1;

		ip6_rthdr = mip6_create_rh(coa, IPPROTO_DSTOPTS);
		if (ip6_rthdr == NULL) {
			free(mo, M_TEMP);
			return -1;
		}

		if (status < MIP6_BA_STATUS_UNSPEC)
			status = MIP6_BA_STATUS_UNSPEC;

		seqno = ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno);
		ba_opt = mip6_create_ba(status, seqno, 0);
		if (ba_opt == NULL) {
			free(mo, M_TEMP);
			free(ip6_rthdr, M_TEMP);
			return -1;
		}

		bzero((caddr_t)&dh2, sizeof(dh2));
		ba_pos = mip6_add_opt2dh((u_int8_t *)ba_opt, &dh2);
		mip6_add_subopt2dh(subbuf, &dh2, ba_pos);
		mip6_align(&dh2);
		ext_hdr = (struct ip6_ext *)&dh2.buf;
		ext_hdr->ip6e_nxt = IPPROTO_NONE;
		
		res = mip6_send_ba(mo, ip6_rthdr, (struct ip6_dest *)dh2.buf);
		if (res == -1) {
			if (ip6_rthdr) free(ip6_rthdr, M_TEMP);
			free(ba_opt, M_TEMP);
			return -1;
		}
	}

	/* Remove allocated memory (mo is removed by ip6_output). */
	if (ip6_rthdr) free(ip6_rthdr, M_TEMP);
	if (ba_opt) free(ba_opt, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_create_ip6hdr
 * Description: Create and fill in data for an IPv6 header to be used by
 *              packets originating from MIPv6. In addition to this memory
 *              is reserved for payload, if necessary.
 * Ret value:   NULL if a IPv6 header could not be created.
 *              Otherwise, pointer to a mbuf including the IPv6 header.
 ******************************************************************************
 */
struct mbuf *
mip6_create_ip6hdr(ip6_src, ip6_dst, next, plen)
struct in6_addr *ip6_src;  /* Source address for packet */
struct in6_addr *ip6_dst;  /* Destination address for packet */
u_int8_t         next;     /* Next header following the IPv6 header */
u_int32_t        plen;     /* Payload length (zero if no payload */
{
	struct ip6_hdr  *ip6;    /* IPv6 header */
	struct mbuf     *mo;     /* Ptr to mbuf allocated for output data */
	u_int32_t        maxlen;

	/* Allocate memory for the IPv6 header and fill it with data */
	ip6 = (struct ip6_hdr *)malloc(sizeof(struct ip6_hdr),
				       M_TEMP, M_NOWAIT);
	if (ip6 == NULL) return NULL;
	bzero(ip6, sizeof(struct ip6_hdr));

	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_plen = 0;
	ip6->ip6_nxt = next;
	ip6->ip6_hlim = IPV6_DEFHLIM;

	ip6->ip6_src = *ip6_src;
	ip6->ip6_dst = *ip6_dst;

	/* Allocate memory for mbuf and copy IPv6 header to mbuf. */
	maxlen = sizeof(struct ip6_hdr) + plen;
	MGETHDR(mo, M_DONTWAIT, MT_DATA);
	if (mo && (maxlen >= MHLEN)) {
		MCLGET(mo, M_DONTWAIT);
		if ((mo->m_flags & M_EXT) == 0) {
			m_free(mo);
			mo = NULL;
		}
	}
	if (mo == NULL) {
		free(ip6, M_TEMP);
		return NULL;
	}

	mo->m_len = maxlen;
	mo->m_pkthdr.len = mo->m_len;
	mo->m_pkthdr.rcvif = NULL;
	bcopy((caddr_t)ip6, mtod(mo, caddr_t), sizeof(*ip6));
	free(ip6, M_TEMP);
	return mo;
}



/*
 ******************************************************************************
 * Function:    mip6_create_rh
 * Description: Create a routing header of type 0 and add the COA for the MN.
 * Ret value:   A pointer to the ip6_rthdr structure if everything is OK.
 *              Otherwise NULL.
 ******************************************************************************
 */
struct ip6_rthdr *
mip6_create_rh(coa, next)
struct in6_addr  *coa;   /* Care-of address for the MN */
u_int8_t          next;  /* Next header following the routing header */
{
	struct ip6_rthdr0  *rthdr0;  /* Routing header type 0 */
	int                 len;

	len = sizeof(struct ip6_rthdr0) + sizeof(struct in6_addr);
	rthdr0 = (struct ip6_rthdr0 *)malloc(len, M_TEMP, M_NOWAIT);
	if (rthdr0 == NULL) return NULL;
	bzero(rthdr0, len);

	rthdr0->ip6r0_nxt = next;
	rthdr0->ip6r0_len = 2;
	rthdr0->ip6r0_type = 0;
	rthdr0->ip6r0_segleft = 1;
	rthdr0->ip6r0_reserved = 0;
	bcopy((caddr_t)coa, (caddr_t)rthdr0 + sizeof(struct ip6_rthdr0),
	      sizeof(struct in6_addr));
	return (struct ip6_rthdr *)rthdr0;
}



/*
 ******************************************************************************
 * Function:    mip6_create_ba
 * Description: Create a Binding Acknowledgement option for transmission.
 * Ret value:   NULL if a BA option could not be created.
 *              Otherwise, pointer to the BA option.
 ******************************************************************************
 */
struct ip6_opt_binding_ack *
mip6_create_ba(status, seqno, lifetime)
u_int8_t   status;    /* Result of the Binding Update request */
u_int16_t  seqno;     /* Sequence number in the BU being acknowledged */
u_int32_t  lifetime;  /* Proposed lifetime in the BU */
{
	struct ip6_opt_binding_ack  *ba_opt;  /* BA option */
	u_int32_t                    rtime;
	int                          len;

	/* Allocate a Binding Aknowledgement option and set values */
	len = sizeof(struct ip6_opt_binding_ack);
	ba_opt = (struct ip6_opt_binding_ack *)malloc(len, M_TEMP, M_NOWAIT);
	if (ba_opt == NULL) return NULL;
	bzero(ba_opt, sizeof(*ba_opt));

	ba_opt->ip6oa_type = IP6OPT_BINDING_ACK;
	ba_opt->ip6oa_len = IP6OPT_BALEN;
	ba_opt->ip6oa_status = status;
	bcopy((caddr_t)&seqno, ba_opt->ip6oa_seqno, sizeof(seqno));
	bcopy((caddr_t)&lifetime, ba_opt->ip6oa_lifetime, sizeof(lifetime));

	/* Calculate value for refresh time */
	if (MIP6_IS_HA_ACTIVE)
		rtime = (lifetime * 8) / 10;
	else
		rtime = lifetime;

	bcopy((caddr_t)&rtime, ba_opt->ip6oa_refresh, sizeof(rtime));
	return ba_opt;
}



/*
 ******************************************************************************
 * Function:    mip6_send_ba
 * Description: Sends a BA back to the MN sending the BU. The packet includes
 *              a routing header a destination header where the BA is stored.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_send_ba(mo, ip6_rthdr, dh2)
struct mbuf      *mo;         /* Ptr to beginning of outgoing mbuf */
struct ip6_rthdr *ip6_rthdr;  /* Routing header (type 0) */
struct ip6_dest  *dh2;        /* Destination Header 2 */
{
	struct ip6_pktopts  *pktopts;   /* Options for IPv6 packet */
	struct ip6_hdr      *ip6;
	u_int8_t            *ptr;
	int                  res, ii;

	pktopts = (struct ip6_pktopts *)malloc(sizeof(struct ip6_pktopts),
					       M_TEMP, M_NOWAIT);
	if (pktopts == NULL) return -1;
	init_ip6pktopts(pktopts);

	pktopts->ip6po_rhinfo.ip6po_rhi_rthdr = ip6_rthdr;
	pktopts->ip6po_dest2 = dh2;

	res = ip6_output(mo, pktopts, NULL, 0, NULL, NULL);
	if (res) {
		free(pktopts, M_TEMP);
		log(LOG_ERR,
		    "%s: ip6_output function failed to send BA, error = %d\n",
		    __FUNCTION__, res);
		return -1;
	}

#ifdef MIP6_DEBUG
	ip6 = mtod(mo, struct ip6_hdr *);

	mip6_debug("\nSent Binding Acknowledgement\n");
	mip6_debug("IP Header Src:     %s\n", ip6_sprintf(&ip6->ip6_src));
	mip6_debug("IP Header Dst:     %s\n", ip6_sprintf(&ip6->ip6_dst));
	mip6_debug("Destination Header 2 Contents\n");

	ptr = (u_int8_t *)dh2;
	for (ii = 0; ii < ((dh2->ip6d_len + 1) << 3); ii++, ptr++) {
		if (ii % 16 == 0) mip6_debug("\t0x:");
		if (ii % 4 == 0) mip6_debug("   ");
		mip6_debug("%02x ", *ptr);
		if ((ii + 1) % 16 == 0) mip6_debug("\n");
	}
	if (ii % 16) mip6_debug("\n");
#endif

	free(pktopts, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_in6addr
 * Description: Build an in6 address from a prefix and the interface id. The
 *              length of the different parts is decided by the prefix length.
 * Ret value:   Pointer to address or NULL
 ******************************************************************************
 */
struct in6_addr *
mip6_in6addr(prefix, id, prefixlen)
const struct in6_addr  *prefix;     /* Prefix part of the address */
struct in6_addr        *id;         /* Interface id part of the address */
int                     prefixlen;  /* Prefix length (bits) */
{
	struct in6_addr *new_addr;  /* New address built in this function */
	u_int8_t         byte_pr;
	u_int8_t         byte_id;
	int              ii, jj;

	new_addr = (struct in6_addr *)malloc(sizeof(struct in6_addr),
					     M_TEMP, M_NOWAIT);
	if (new_addr == NULL) return NULL;

	for (ii = 0; ii < prefixlen / 8; ii++)
		new_addr->s6_addr8[ii] = prefix->s6_addr8[ii];

	if (prefixlen % 8) {
		/* Add the last bits of the prefix to the common byte. */
		byte_pr = prefix->s6_addr8[ii];
		byte_pr = byte_pr >> (8 - (prefixlen % 8));
		byte_pr = byte_pr << (8 - (prefixlen % 8));

		/* Then, add the first bits of the interface id to the
		   common byte. */
		byte_id = id->s6_addr8[ii];
		byte_id = byte_id << (prefixlen % 8);
		byte_id = byte_id >> (prefixlen % 8);
		new_addr->s6_addr8[ii] = byte_pr | byte_id;
		ii += 1;
	}

	for (jj = ii; jj < 16; jj++)
		new_addr->s6_addr8[jj] = id->s6_addr8[jj];
	return new_addr;
}



/*
 ******************************************************************************
 * Function:    mip6_intercept_control
 * Description: When a home agent becomes proxy for a mobile node or when a
 *              mobile node returns to its home link, the home agent or the
 *              mobile node must multicast onto the home link a Neighbor
 *              Advertisement.
 *              If the home agent sends the NA it must be multicasted for
 *              each prefix of the mobile node if the prefix length is non-
 *              zero, otherwise only for the mobile nodes home address.
 *              If the mobile node sends the NA it must be sent for each of
 *              its home addresses, as defined by the current on-link prefixes.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_intercept_control(taddr, prefixlen, flags)
struct in6_addr *taddr;      /* Target address for MN */
u_int8_t         prefixlen;  /* Prefix length for MN address */
u_long           flags;      /* Flags for the NA message */
{
	struct mip6_prefix  *prr;   /* Prefix list kept by router (HA) */
	struct nd_prefix    *prh;   /* Prefix list kept by host (MN) */
	struct ifnet        *ifp;
	struct ifaddr       *ifa;
	struct in6_ifaddr   *ifa6;
	struct in6_addr     *laddr, *prefix, *naddr;
	int                  ifa_plen;
	u_int8_t             plen, sent_for_ll_addr;

	if (MIP6_IS_HA_ACTIVE) {
		/* Intercepting packets for mobile node (see 9.5) */
		sent_for_ll_addr = 0;

		for (prr = mip6_prq; prr; prr = prr->next) {
			prefix = &prr->prefix;
			plen = prr->prefixlen;
			ifp = prr->ifp;

			/* Should this only be done for the home address */
			if (prefixlen == 0) {
				/* Find interface for sending NA */
				if (in6_are_prefix_equal(taddr, prefix, plen)){
					mip6_intercept_packet(taddr, flags,
							      ifp);
					break;
				}
				continue;
			}

			/* The prefix length must be equal */
			if (plen != prefixlen) continue;

			/* Build home address to send NA for */
			naddr = mip6_in6addr(prefix, taddr, plen);
			if (naddr == NULL) continue;

			/* Start intercept packet for home address */
			mip6_intercept_packet(naddr, flags, ifp);

			/* Send for link-local address if prefix len == 64 */
			if ((plen == 64) && !sent_for_ll_addr) {
				laddr = mip6_in6addr(&in6addr_linklocal,
						     taddr, plen);
				if (laddr == NULL) {
					free(naddr, M_TEMP);
					continue;
				}

				mip6_intercept_packet(laddr, flags, ifp);
				sent_for_ll_addr = 1;
				free(laddr, M_TEMP);
			}
			free(naddr, M_TEMP);
		}
	}

	if (MIP6_IS_MN_ACTIVE) {
		/* Returning home (see 10.20) */

		/* All home addresses are located at the loopback
		   interface. */
		ifp = mip6_hifp;
		if (ifp == NULL) return;

		/* Loop through all addresses at "lo0" */
		sent_for_ll_addr = 0;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
#else
		for (ifa = ifp->if_addrlist.tqh_first; ifa;
		     ifa = ifa->ifa_list.tqe_next)
#endif
		{
			/* Find addresses of interest. */
			if (ifa->ifa_addr->sa_family != AF_INET6)
				continue;

			ifa6 = (struct in6_ifaddr *)ifa;
			if ((ifa6->ia6_flags & IN6_IFF_HOME) == 0)
				continue;
		
			/* The prefix length must be equal */
			ifa_plen = in6_mask2len(&ifa6->ia_prefixmask.sin6_addr,
						NULL);
			if (ifa_plen != prefixlen)
				continue;

			/* Finf outgoing interface */
			for (prh = nd_prefix.lh_first; prh;
			     prh = prh->ndpr_next) {
				if (prh->ndpr_stateflags & NDPRF_HOME && 
				    prh->ndpr_stateflags & NDPRF_ONLINK)
					ifp = prh->ndpr_ifp;
			}
			
			/* Start intercept packet for home address */
			mip6_intercept_packet(&ifa6->ia_addr.sin6_addr,
					      flags, ifp);

			/* Send for link-local address if prefix len == 64 */
			if ((ifa_plen == 64) && !sent_for_ll_addr) {
				laddr = mip6_in6addr(&in6addr_linklocal,
						     &ifa6->ia_addr.sin6_addr,
						     ifa_plen);
				if (laddr == NULL)
					continue;

				mip6_intercept_packet(laddr, flags, ifp);
				sent_for_ll_addr = 1;
				free(laddr, M_TEMP);
			}
		}
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_intercept_packet
 * Description: Create a NA entry and add it to the internal MIPv6 list of
 *              Neighbor Advertisements that should be sent.
 *              The NA will be repeateadly sent (MIP6_MAX_ADVERT_REXMIT times)
 *              by either the Mobile Node when returning to its home link or
 *              by the Home Agent when acting as a proxy for a Mobile Node
 *              while away from its home network.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_intercept_packet(taddr, flags, ifp)
struct in6_addr *taddr;   /* Target address to send NA for */
u_long           flags;   /* Flags for the NA message */
struct ifnet    *ifp;     /* Use this interface when sending the NA */
{
	struct mip6_na  *nap;
	int              s, start_timer = 0;

	nap = (struct mip6_na *)malloc(sizeof(struct mip6_na),
				       M_TEMP, M_NOWAIT);
	if (nap == NULL) return ;
	bzero(nap, sizeof(struct mip6_na));

	nap->next = NULL;
	nap->ifp = ifp;
	nap->target_addr = *taddr;
	nap->flags = flags;
	nap->link_opt = 1;
	nap->no = MIP6_MAX_ADVERT_REXMIT;

	/* Add the new na entry first to the list. */
	if (mip6_naq == NULL) start_timer = 1;
	s = splnet();
	nap->next = mip6_naq;
	mip6_naq = nap;
	splx(s);
	
#ifdef MIP6_DEBUG
	mip6_debug("\nCreated NA List entry (0x%x)\n", nap);
	mip6_debug("Interface:       %s\n", if_name(nap->ifp));
	mip6_debug("Target Address:  %s\n", ip6_sprintf(&nap->target_addr));
	mip6_debug("Flags:           ");
	if (nap->flags & ND_NA_FLAG_OVERRIDE)  mip6_debug("O ");
	if (nap->flags & ND_NA_FLAG_ROUTER)    mip6_debug("R ");
	if (nap->flags & ND_NA_FLAG_SOLICITED) mip6_debug("S ");
	mip6_debug("\n");
	mip6_debug("Target link layer address option: TRUE\n");
#endif

	if (start_timer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_na_ch, hz, mip6_timer_na, NULL);
#else
		timeout(mip6_timer_na, (void *)0, hz);
#endif
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_tunnel
 * Description: Create, move or delete a tunnel from the Home Agent to the MN
 *              or from the Mobile Node to the Home Agent.
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_tunnel(ip6_src, ip6_dst, action, start, entry)
struct in6_addr  *ip6_src;   /* Tunnel start point */
struct in6_addr  *ip6_dst;   /* Tunnel end point */
int               action;    /* Action: MIP6_TUNNEL_{ADD,MOVE,DEL} */
int               start;     /* Either the Home Agent or the Mobile Node */
void             *entry;     /* BC or ESM depending on start variable */
{
	const struct encaptab  *ep;	   /* Encapsulation entry */
	const struct encaptab **ep_store;  /* Where to store encap reference */
	struct sockaddr_in6     src, srcm;
	struct sockaddr_in6     dst, dstm;
	struct in6_addr         mask;
	int                     mask_len = 128;

	ep_store = NULL;
	if ((start == MIP6_NODE_MN) && (entry != NULL))
		ep_store = &((struct mip6_esm *)entry)->ep;
	else if ((start == MIP6_NODE_HA) && (entry != NULL))
		ep_store = &((struct mip6_bc *)entry)->ep;
	else {
#ifdef MIP6_DEBUG
		mip6_debug("%s: Tunnel not modified\n", __FUNCTION__);
#endif
		return 0;
	}

	if (action == MIP6_TUNNEL_DEL) {
		/* Moving to Home network. Remove tunnel. */
		if (ep_store && *ep_store) {
			encap_detach(*ep_store);
			*ep_store = NULL;
		}
		return 0;
	}

	if ((action == MIP6_TUNNEL_ADD) || (action == MIP6_TUNNEL_MOVE)) {
		if (action == MIP6_TUNNEL_MOVE && ep_store && *ep_store) {
			/* Remove the old encapsulation entry first. */
			encap_detach(*ep_store);
			*ep_store = NULL;
		}

		bzero(&src, sizeof(src));
		src.sin6_family = AF_INET6;
		src.sin6_len = sizeof(struct sockaddr_in6);
		src.sin6_addr = *ip6_src;

		in6_prefixlen2mask(&mask, mask_len);
		bzero(&srcm, sizeof(srcm));
		srcm.sin6_family = AF_INET6;
		srcm.sin6_len = sizeof(struct sockaddr_in6);
		srcm.sin6_addr = mask;

		bzero(&dst, sizeof(dst));
		dst.sin6_family = AF_INET6;
		dst.sin6_len = sizeof(struct sockaddr_in6);
		dst.sin6_addr = *ip6_dst;

		in6_prefixlen2mask(&mask, mask_len);
		bzero(&dstm, sizeof(dstm));
		dstm.sin6_family = AF_INET6;
		dstm.sin6_len = sizeof(struct sockaddr_in6);
		dstm.sin6_addr = mask;

		ep = encap_attach(AF_INET6, -1,
				  (struct sockaddr *)&src,
				  (struct sockaddr *)&srcm,
				  (struct sockaddr *)&dst,
				  (struct sockaddr *)&dstm,
				  (struct protosw *)&mip6_tunnel_protosw,
				  NULL);
		if (ep == NULL) return EINVAL;
		*ep_store = ep;
		return 0;
	}
	return EINVAL;
}



/*
 ##############################################################################
 #
 # FUNCTIONS FOR PROCESSING OF ICMP6 MESSAGES
 # Below are functions used for processing of icmp6 messages. Both sent and
 # received messages are handled by these functions.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_icmp6_input
 * Description: Some icmp6 messages are of interest for MIPv6 and must be
 *              taken care of accordingly. Once such a message is discoverd
 *              in function icmp6_input() a call to this function is done.
 *              Further processing depends on the message type.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_icmp6_input(m, off, icmp6len)
struct mbuf *m;         /* Ptr to beginning of mbuf */
int          off;       /* Offset from start of mbuf to ICMP6 message */
int          icmp6len;  /* Total ICMP6 payload length */
{
	struct ip6_hdr           *ip6;      /* IPv6 header */
	struct icmp6_hdr         *icmp6;    /* ICMP6 header */
	struct mip6_bc           *bcp;      /* Binding Cache list entry */
	struct mip6_bc           *bcp_nxt;  /* Binding Cache list entry */
	struct in6_addr          *lhome;    /* Local home address (sent pkg) */
	struct in6_addr          *phome;    /* Peer home address (sent pkg) */
	struct nd_router_advert  *ra;       /* Router Advertisement */
	struct mip6_bul          *bulp;     /* Binding Update List entry */
	u_int8_t                 *pp;
	int                       offset;

	ip6 = mtod(m, struct ip6_hdr *);
	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
	pp = (u_int8_t *)ip6 + off;

	switch (icmp6->icmp6_type) {
		case ICMP6_DST_UNREACH:
			/* Receiving ICMP error messages (see 8.8) */
			mip6_icmp6_find_addr(pp, icmp6len, &lhome, &phome);
			bcp = mip6_bc_find(lhome, phome);
			if (bcp) mip6_bc_delete(bcp, &bcp_nxt);
			break;
		case ICMP6_PARAM_PROB:
			/* Receiving ICMP error messages (see 10.14) */
			if (!MIP6_IS_MN_ACTIVE) return 0;

			if (icmp6->icmp6_code != ICMP6_PARAMPROB_OPTION)
				break;

			offset = sizeof(struct icmp6_hdr);
			offset += ntohl(*(u_int32_t *)icmp6->icmp6_data32);
			if ((offset + 1) > icmp6len) break;

			mip6_icmp6_find_addr(pp, icmp6len, &lhome, &phome);
			if (*(pp + offset) == IP6OPT_BINDING_UPDATE) {
				bulp = mip6_bul_find(phome, lhome);
				if (bulp) bulp->send_flag = 0;
			} else if (*(pp + offset) == IP6OPT_HOME_ADDRESS) {
				log(LOG_ERR,
				    "Node %s does not recognize Home "
				    "Address option\n",
				    ip6_sprintf(phome));
			}
			break;
		case ND_ROUTER_ADVERT:
			/* Receiving Router Advertisement (see 9.1, 10.15) */
			if (!(MIP6_IS_HA_ACTIVE || MIP6_IS_MN_ACTIVE))
				return 0;

			if (!IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)) {
				log(LOG_ERR,
				    "%s: Src %s is not link-local\n",
				    __FUNCTION__, ip6_sprintf(&ip6->ip6_src));
				return -1;
			}

			ra = (struct nd_router_advert *)icmp6;
			if (!(ra->nd_ra_flags_reserved & ND_RA_FLAG_HA))
				return 0;

			if (mip6_icmp6_ra(m, off, icmp6len))
				return -1;
			break;
		case ICMP6_HADISCOV_REQUEST:
			/* XXX Add code */
			break;
		case ICMP6_HADISCOV_REPLY:
			/* XXX Add code */
			break;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_icmp6_find_addr
 * Description: If a correspondent node receives an ICMPv6 Destination
 *              Unreachable after sending packets to a mobile node, based on
 *              an entry in its Binding Cache, it should remove that entry.
 *              The correspondent node my itself be a mobile node.
 * Ret value:   local_home  Local home address in ICMP IPv6 packet
 *              peer_home   Peer home address in ICMP IPv6 packet
 ******************************************************************************
 */
void
mip6_icmp6_find_addr(pp, plen, local_home, peer_home)
u_int8_t          *pp;         /* Pointer to beginning of icmp6 payload */
int                plen;       /* Total icmp6 payload length */
struct in6_addr  **local_home; /* Local home address */
struct in6_addr  **peer_home;  /* Peer home address */
{
	struct ip6_opt_home_address *ha;       /* Home Address option */
	struct ip6_hdr              *ip6;      /* IPv6 header */
	struct ip6_ext              *ehdr;     /* Extension header */
	struct in6_addr             *lh;       /* Local home address */
	struct in6_addr             *ph;       /* Peer home address */
	struct ip6_rthdr0           *rh;
	u_int8_t                    *eopt, nxt, olen;     
	int                          off, elen, eoff;
	int                          rlen, addr_off;

	off = sizeof(struct icmp6_hdr);
	ip6 = (struct ip6_hdr *)(pp + off);
	nxt = ip6->ip6_nxt;
	off += sizeof(struct ip6_hdr);

	lh = &ip6->ip6_src;
	ph = &ip6->ip6_dst;

	/* Search original IPv6 header extensions for Routing Header type 0
	   and for home address option (if I'm a mobile node). */
	while ((off + 2) < plen) {
		if (nxt == IPPROTO_HOPOPTS) {
			ehdr = (struct ip6_ext *)(pp + off);
			nxt = ehdr->ip6e_nxt;
			off += (ehdr->ip6e_len + 1) << 3;
			continue;
		}

		if (nxt == IPPROTO_DSTOPTS) {
			ehdr = (struct ip6_ext *)(pp + off);
			elen = (ehdr->ip6e_len + 1) << 3;
			eoff = 2;
			eopt = pp + off + eoff;
			while ((eoff + 2) < elen) {
				if (*eopt == IP6OPT_PAD1) {
					eoff += 1;
					eopt += 1;
					continue;
				}
				if (*eopt == IP6OPT_HOME_ADDRESS) {
					olen = *(eopt + 1) + 2;
					if ((off + eoff + olen) > plen)
						break;

					ha = (struct ip6_opt_home_address *)
						eopt;
					lh = (struct in6_addr *)ha->ip6oh_addr;
					eoff += olen;
					eopt += olen;
					continue;
				}
				eoff += *(eopt + 1) + 2;
				eopt += *(eopt + 1) + 2;
			}
			nxt = ehdr->ip6e_nxt;
			off += (ehdr->ip6e_len + 1) << 3;
			continue;
		}

		if (nxt == IPPROTO_ROUTING) {
			rh = (struct ip6_rthdr0 *)(pp + off);
			rlen = (rh->ip6r0_len + 1) << 3;
			if ((off + rlen) > plen) break;
			if (rh->ip6r0_type != 0) break;
			if ((rh->ip6r0_type != 0) || (rh->ip6r0_len % 2)) {
				nxt = rh->ip6r0_nxt;
				off += (rh->ip6r0_len + 1) << 3;
				continue;
			}

			addr_off = 8 + (((rh->ip6r0_len / 2) - 1) << 3);
			ph = (struct in6_addr *)(pp + off + addr_off);

			nxt = rh->ip6r0_nxt;
			off += (rh->ip6r0_len + 1) << 3;
			continue;
		}
		
		/* Only look at the unfragmentable part. Other headers
		   may be present but they are of no interest. */
		break;
	}

	*local_home = lh;
	*peer_home = ph;
}



/*
 ******************************************************************************
 * Function:    mip6_icmp6_ra
 * Description: Processes an incoming Router Advertisement with a H-bit set
 *              in the flags variable (checked by the calling function), see
 *              9.1 and 10.15.
 * Note:        The Home Agent uses the information for sending RAs to mobile
 *              nodes currently located at a foreign network for which it has
 *              a "home registration" entry.
 *              It is also used by the mobile node when sending a BU to a
 *              home agent at a previous foreign network, which is the only
 *              thing that the mobile node uses this information for.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_icmp6_ra(m, off, icmp6len)
struct mbuf *m;         /* Ptr to beginning of mbuf */
int          off;       /* Offset from start of mbuf to ICMP6 message */
int          icmp6len;  /* Total ICMP6 payload length */
{
	struct ifnet            *ifp;    /* Receiving interface */
	struct ip6_hdr          *ip6;    /* IPv6 header */
	struct nd_router_advert *ra;     /* Router Advertisement */

	ip6 = mtod(m, struct ip6_hdr *);
	ra = (struct nd_router_advert *)((u_int8_t *)ip6 + off);
	ifp = m->m_pkthdr.rcvif;

	/* Look through the RA options and do appropriate updates */
	if (mip6_icmp6_ra_options(ifp, &ip6->ip6_src, ra, icmp6len))
		return -1;
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_icmp6_ra_options
 * Description: Search through all the options in the Router Advertisement
 *              and store them in the Home Agent list and Prefix list (see
 *              9.1 and 10.15).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_icmp6_ra_options(ifp, ll_addr, ra, icmp6len)
struct ifnet             *ifp;       /* Receiving/sending interface */
struct in6_addr          *ll_addr;   /* Link local address of Home Agent */
struct nd_router_advert  *ra;        /* Ptr to beginning of RA message */
int                       icmp6len;  /* Total ICMP6 payload length */
{
	struct nd_opt_homeagent_info *hai;    /* Home Agent info option */
	struct nd_opt_prefix_info    *pi;     /* Ptr to prefix information */
	u_int8_t                     *opt;    /* Ptr to current option in RA */
	struct mip6_prefix           *prp;    /* Prefix list entry */
	struct in6_addr              *anyadr; /* Anycast address for HA */
	struct in6_addr              *pfx;
	struct mip6_halst            *halp;
	int                           off;    /* Offset from start of RA */
	u_int32_t                     pfxvt, pfxpt;
	u_int16_t                     lifetime, pref;
	u_int8_t                      pfxlen, pfxflags;
	int                           err;

	/* First, see if there is a Home Agent information option
	   included in the RA. */
	lifetime = ntohs(ra->nd_ra_router_lifetime);
	pref = 0;

	hai = NULL;
	off = sizeof(struct nd_router_advert);
	while (off < icmp6len) {
		opt = (u_int8_t *)ra + off;
		if (*opt == ND_OPT_HOMEAGENT_INFO) {
			/* Check the home agent information option */
			hai = (struct nd_opt_homeagent_info *)opt;
			if (hai->nd_opt_hai_len != 1) {
				ip6stat.ip6s_badoptions++;
				return -1;
			}

			pref = ntohs(hai->nd_opt_hai_preference);
			lifetime = ntohs(hai->nd_opt_hai_lifetime);
			off += 8;
			continue;
		} else {
			if (*(opt + 1) == 0) {
				ip6stat.ip6s_badoptions++;
				return -1;
			}
			off += *(opt + 1) << 3;
		}
	}

	/* Should the HA list entry be removed? */
	halp = mip6_hal_find(ifp, ll_addr);
	if (halp && hai && (lifetime == 0)) {
		mip6_hal_delete(halp);
		return 0;
	}

	/* Update Home Agent list entry */
	if ((halp == NULL) && (lifetime == 0))
		return 0;

	if (halp == NULL) {
		halp = mip6_hal_create(ifp, ll_addr, lifetime, pref);
		if (halp == NULL) return -1;
	} else {
		halp->lifetime = lifetime;
		halp->pref = pref;
		mip6_hal_sort(halp);
	}
	
	/* Update Prefix Information list for Home Agent */
	off = sizeof(struct nd_router_advert);
	while (off < icmp6len) {
		opt = (u_int8_t *)ra + off;
		if (*opt == ND_OPT_PREFIX_INFORMATION) {
			/* Check the prefix information option */
			pi = (struct nd_opt_prefix_info *)opt;
			if (pi->nd_opt_pi_len != 4) {
				ip6stat.ip6s_badoptions++;
				return -1;
			}

			if (!(pi->nd_opt_pi_flags_reserved &
			      ND_OPT_PI_FLAG_ROUTER)) {
				off += 4 * 8;
				continue;
			}

			if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix) ||
			    IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix)) {
				off += 4 * 8;
				continue;
			}

			/* Aggregatable unicast address, RFC 2374 */
			if (((pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) > 0x10)
			    && (pi->nd_opt_pi_prefix_len != 64)) {
				off += 4 * 8;
				continue;
			}

			/* Store the address if not already present */
			pfx = &pi->nd_opt_pi_prefix;
			pfxlen = pi->nd_opt_pi_prefix_len;
			pfxvt = ntohl(pi->nd_opt_pi_valid_time);
			pfxpt = ntohl(pi->nd_opt_pi_preferred_time);
			pfxflags = pi->nd_opt_pi_flags_reserved;

			prp = mip6_prefix_find(ifp, pfx, pfxlen);
			if (prp == NULL) {
				prp = mip6_prefix_create(ifp, pfx, pfxlen,
							 pfxflags, pfxvt,
							 pfxpt);
				if (prp == NULL) return -1;

				if (MIP6_IS_HA_ACTIVE) {
					/* Add HA anycast address to i/f */
					anyadr = mip6_in6addr_any(pfx, pfxlen);
					err = mip6_add_ifaddr(anyadr, ifp,
							      pfxlen,
							      IN6_IFF_ANYCAST);
					if (err) {
						log(LOG_ERR,
						    "%s: address assignment "
						    " error (errno = %d).\n",
						    __FUNCTION__, err);
					}
				}
			} else
				mip6_prefix_update(prp, pfxflags,
						   pfxvt, pfxpt);

			if (mip6_prefix_add_addr(prp, pfx, halp)) return -1;
			off += 4 * 8;
			continue;
		} else {
			if (*(opt + 1) == 0) {
				ip6stat.ip6s_badoptions++;
				return -1;
			}
			off += *(opt + 1) << 3;
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_add_ifaddr
 * Description: Similar to "ifconfig <ifp> <addr> prefixlen <plen>".
 * Ret value:   Standard error codes.
 ******************************************************************************
 */
int
mip6_add_ifaddr(struct in6_addr *addr,
		struct ifnet *ifp,
		int plen,
		int flags) /* Note: IN6_IFF_NODAD available flag */
{
	struct in6_aliasreq    *ifra, dummy;
	struct sockaddr_in6    *sa6;
	struct in6_ifaddr      *ia;
	int	                s, error = 0;

	bzero(&dummy, sizeof(dummy));
	ifra = &dummy;

	ifra->ifra_addr.sin6_len = sizeof(ifra->ifra_addr);
	ifra->ifra_addr.sin6_family = AF_INET6;
	ifra->ifra_addr.sin6_addr = *addr;

	if (plen != 0) {
		ifra->ifra_prefixmask.sin6_len =
			sizeof(ifra->ifra_prefixmask);
		ifra->ifra_prefixmask.sin6_family = AF_INET6;
		in6_prefixlen2mask(&ifra->ifra_prefixmask.sin6_addr, plen);
		/* XXXYYY Should the prefix also change its prefixmask? */
	}

	ifra->ifra_flags = flags;
	ifra->ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifra->ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	sa6 = &ifra->ifra_addr;

	/* "ifconfig ifp inet6 Home_Address prefixlen 64/128 (alias?)" */
	if (ifp == 0) return EOPNOTSUPP;

	s = splnet();		/* necessary? */

	/*
	 * Find address for this interface, if it exists.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
		if (sa6->sin6_addr.s6_addr16[1] == 0) {
			/* interface ID is not embedded by the user */
			sa6->sin6_addr.s6_addr16[1] = htons(ifp->if_index);
		}
		else if (sa6->sin6_addr.s6_addr16[1] != htons(ifp->if_index)) {
			splx(s);
			return EINVAL;	/* ifid is contradict */
		}
		if (sa6->sin6_scope_id) {
			if (sa6->sin6_scope_id != (u_int32_t)ifp->if_index) {
				splx(s);
				return EINVAL;
			}
			sa6->sin6_scope_id = 0; /* XXX: good way? */
		}
	}
 	ia = in6ifa_ifpwithaddr(ifp, &sa6->sin6_addr);

	error = in6_update_ifa(ifp, ifra, ia);

	splx(s);
	return error;
}




#if 0

/* Move this function to mip6_ha.c. Copy the same "section" header as its
   current location. */

/*
 ******************************************************************************
 * Function:    mip6_icmp6_hadiscov_request
 * Description: Processing of an incoming ICMP6 message requesting "Dynamic
 *              Home Agent Address Discovery", see 9.2.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_icmp6_hadiscov_request(m, off, icmp6len)
struct mbuf *m;         /* Ptr to beginning of mbuf */
int          off;       /* Offset from start of mbuf to ICMP6 message */
int          icmp6len;  /* Total ICMP6 payload length */
{
	struct ifnet            *ifp;    /* Receiving interface */
	struct ip6_hdr          *ip6;    /* IPv6 header */
	struct ip6aux           *ip6a = NULL;
	struct mbuf             *n;
	struct mip6_halst       *halp;   /* Home Agent list entry */
	u_int16_t                lifetime;
	int                      s;

	ip6 = mtod(m, struct ip6_hdr *);
	ifp = m->m_pkthdr.rcvif;

	/* Find the home agent that sent the RA */
	ra = (struct nd_router_advert *)((u_int8_t *)ip6 + off);
	lifetime = ntohs(ra->nd_ra_router_lifetime);


	n = ip6_findaux(m);
	if (!n) return NULL;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return NULL;


	
	/* Find the home agent that sent the RA */


	bzero((caddr_t)&discov_rep, sizeof(struct ha_discov_rep))
	discov_rep.type = ICMP6_HADISCOV_REPLY;
	discov_rep.code = 0;
	discov_rep.id = discov_req.id;


	/* XXX If my own home address is the first one it should not
	   be in the list. */
	
	/* Calculate checksum !!!! (when everything has been added */
	/* increase space for mip6_buffer 2048 */
	discov_buf.off = sizeof(struct ha_discov_rep);
	for (halp = mip6_haq; halp; halp = halp->next) {
		size = discov_buf.off + sizeof(struct ip6_hdr);
		size += (struct in6_addr);
		if (size > MIN_MTU) break;
		
		/* Search the prefix list for a global HA address */
		addr_found = 0;
		for (pr = mip6_prq; pr; pr = pr->next) {
			for (ap = pr->addrlst; ap; ap = ap->next) {
				if (ap->hap == halp) {
					size = sizeof(struct in6_addr);
					bcopy((caddr_t)&ap->ip6_addr,
					      discov_buf.buf + discov_buf.off,
					      size);
					discov_buf.off += size;
					addr_found = 1
					break;
				}
			}
			if (addr_found) break;
		}
	}

	
	if ((sum = in6_cksum(m, IPPROTO_ICMPV6, off, icmp6len)) != 0) {
		nd6log((LOG_ERR,
		    "ICMP6 checksum error(%d|%x) %s\n",
		    icmp6->icmp6_type, sum, ip6_sprintf(&ip6->ip6_src)));
		icmp6stat.icp6s_checksum++;
		goto freeit;
	}
		
	res = ip6_output(mo, pktopts, NULL, 0, NULL, NULL);
	if (res) {
		free(pktopts, M_TEMP);
		log(LOG_ERR,
		    "%s: ip6_output function failed to send BA, error = %d\n",
		    __FUNCTION__, res);
		return -1;
	}
				

	return 0;
}

#endif







/*
 ##############################################################################
 #
 # LIST FUNCTIONS
 # The correspondent node maintains a Binding Cache list for each node from
 # which it has received a BU.
 # It also maintains a list of Neighbor Advertisements that shall be sent
 # either by the home agent when start acting as a proxy for the mobile node
 # or by the mobile node when returning to the home network.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_bc_find
 * Description: Find an entry in the Binding Cache list. If variable local_home
 *              is NULL an entry for which only the peer_home address match is
 *              searched for.
 * Ret value:   Pointer to Binding Cache entry or NULL if no entry found.
 ******************************************************************************
 */
struct mip6_bc *
mip6_bc_find(local_home, peer_home)
struct in6_addr  *local_home; /* Local nodes home address */
struct in6_addr  *peer_home;  /* Home Address for peer MN  */
{
	struct mip6_bc  *bcp;     /* Entry in the Binding Cache list */

	for (bcp = mip6_bcq; bcp; bcp = bcp->next) {
		if (local_home == NULL) {
			if (IN6_ARE_ADDR_EQUAL(peer_home, &bcp->peer_home))
				return bcp;
			else
				continue;
		}
		
		if (IN6_ARE_ADDR_EQUAL(local_home, &bcp->local_home) &&
		    IN6_ARE_ADDR_EQUAL(peer_home, &bcp->peer_home))
			return bcp;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_bc_create
 * Description: Create a new Binding Cache entry as a result of receiving a
 *              Binding Update option. Add it first to the Binding Cache list
 *              and set parameters for the entry.
 * Ret value:   Pointer to the created BC entry or NULL.
 * Note 1:      If the BC timeout function has not been started it is started.
 *              The BC timeout function will be called once every second until
 *              there are no more entries in the BC list.
 * Note 2:      The gif i/f is created/updated in function mip6_tunnel and
 *              should not be taken care of here.
 ******************************************************************************
 */
struct mip6_bc *
mip6_bc_create(m, opt, coa, lifetime)
struct mbuf      *m;         /* Ptr to beginning of mbuf */
u_int8_t         *opt;       /* Ptr to BU option in DH */
struct in6_addr  *coa;       /* COA for the mobile node (peer) */
u_int32_t         lifetime;  /* Remaining lifetime for this BC entry */
{
	struct ip6_opt_binding_update  *bu_opt;
	struct ip6aux                  *ip6a = NULL;
	struct ip6_hdr                 *ip6;
	struct mip6_bc                 *bcp;
	struct mbuf                    *n;
	int                             s;

	bcp = (struct mip6_bc *)malloc(sizeof(struct mip6_bc),
				       M_TEMP, M_NOWAIT);
	if (bcp == NULL) return NULL;
	bzero((caddr_t)bcp, sizeof(struct mip6_bc));

	bu_opt = (struct ip6_opt_binding_update *)(opt);
	ip6 = mtod(m, struct ip6_hdr *);

	n = ip6_findaux(m);
	if (!n) return NULL;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return NULL;

	bcp->next = NULL;
	bcp->local_home = ip6->ip6_dst;
	bcp->peer_home = ip6a->ip6a_home;
	bcp->peer_coa = *coa;
	bcp->lifetime = lifetime;
	bcp->flags |= bu_opt->ip6ou_flags & IP6_BUF_HOME;
	bcp->seqno = ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno);
	bcp->ep = NULL;

	if (bcp->flags & IP6_BUF_HOME) {
		bcp->prefixlen = bu_opt->ip6ou_prefixlen;
		bcp->flags |= bu_opt->ip6ou_flags & IP6_BUF_ROUTER;
	} else {
		bcp->prefixlen = 0;
		
		if (mip6_config.br_update > 60)
			bcp->info.br_interval = 60;
		else if (mip6_config.br_update < 2)
			bcp->info.br_interval = 2;
		else
			bcp->info.br_interval = mip6_config.br_update;
	}

	/* Insert the entry as the first entry in the Binding Cache list. */
	s = splnet();
	if (mip6_bcq == NULL) {
		mip6_bcq = bcp;
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_bc_ch, hz, mip6_timer_bc, NULL);
#else
		timeout(mip6_timer_bc, (void *)0, hz);
#endif
	} else {
		bcp->next = mip6_bcq;
		mip6_bcq = bcp;
	}
	splx(s);

#ifdef MIP6_DEBUG
	mip6_debug("\nBinding Cache Entry created (0x%x)\n", bcp);
	mip6_debug("Local home address: %s\n", ip6_sprintf(&bcp->local_home));
	mip6_debug("Peer home address:  %s\n", ip6_sprintf(&bcp->peer_home));
	mip6_debug("Peer c/o address:   %s\n", ip6_sprintf(&bcp->peer_coa));
	mip6_debug("Remaining lifetime: %u\n", bcp->lifetime);
	mip6_debug("Sequence number:    %u\n", bcp->seqno);
	mip6_debug("Prefix length:      %u\n", bcp->prefixlen);
	mip6_debug("Flags:              ");
	if (bcp->flags & IP6_BUF_HOME) mip6_debug("H ");
	if (bcp->flags & IP6_BUF_ROUTER) mip6_debug("R ");
	mip6_debug("\n");
#endif
	return bcp;
}



/*
 ******************************************************************************
 * Function:    mip6_bc_update
 * Description: Update an existing Binding Cache entry as a result of receiving
 *              a Binding Update option.
 * Ret value:   Void
 * Note:        The gif i/f is created/updated in function mip6_tunnel and
 *              should not be taken care of here.
 ******************************************************************************
 */
void
mip6_bc_update(opt, bcp, coa, lifetime)
u_int8_t         *opt;      /* Ptr to BU option in DH */
struct mip6_bc   *bcp;      /* BC entry being updated */
struct in6_addr  *coa;      /* COA for the mobile node (peer) */
u_int32_t         lifetime; /* Remaining lifetime for this BC entry */
{
	struct ip6_opt_binding_update  *bu_opt;

	bu_opt = (struct ip6_opt_binding_update *)(opt);

	bcp->peer_coa = *coa;
	bcp->lifetime = lifetime;
	bcp->flags |= bu_opt->ip6ou_flags & IP6_BUF_HOME;
	bcp->seqno = ntohs(*(u_int16_t *)bu_opt->ip6ou_seqno);

	if (bcp->flags & IP6_BUF_HOME) {
		bcp->prefixlen = bu_opt->ip6ou_prefixlen;
		bcp->flags |= bu_opt->ip6ou_flags & IP6_BUF_ROUTER;;
		bzero((caddr_t)&bcp->info, sizeof(struct mip6_bc_info));
	} else {
		bcp->prefixlen = 0;
		bcp->flags &= ~IP6_BUF_ROUTER;

		if (bcp->info.br_interval > 60)
			bcp->info.br_interval = 60;
		if (bcp->info.br_interval < 2)
			bcp->info.br_interval = 2;
		bcp->info.sent_brs = 0;
		bcp->info.lasttime = 0;
	}
	
#ifdef MIP6_DEBUG
	mip6_debug("\nBinding Cache Entry updated (0x%x)\n", bcp);
	mip6_debug("Local home address: %s\n", ip6_sprintf(&bcp->local_home));
	mip6_debug("Peer home address:  %s\n", ip6_sprintf(&bcp->peer_home));
	mip6_debug("Peer c/o address:   %s\n", ip6_sprintf(&bcp->peer_coa));
	mip6_debug("Remaining lifetime: %u\n", bcp->lifetime);
	mip6_debug("Sequence number:    %u\n", bcp->seqno);
	mip6_debug("Prefix length:      %u\n", bcp->prefixlen);
	mip6_debug("Flags:              ");
	if (bcp->flags & IP6_BUF_HOME)   mip6_debug("H ");
	if (bcp->flags & IP6_BUF_ROUTER) mip6_debug("R ");
	mip6_debug("\n");
#endif
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_bc_delete
 * Description: Delete an entry in the Binding Cache list.
 * Ret value:   Error code
 *              Pointer to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
int
mip6_bc_delete(bcp_del, bcp_nxt)
struct mip6_bc  *bcp_del;  /* Pointer to BC entry to delete */
struct mip6_bc **bcp_nxt;  /* Returns next entry in the list */
{
	struct mip6_bc  *bcp;       /* Current entry in the BC list */
	struct mip6_bc  *bcp_prev;  /* Previous entry in the BC list */
	struct mip6_bc  *bcp_next;  /* Next entry in the BC list */
	int              s, error = 0;

	if (bcp_del == NULL) {
		*bcp_nxt = NULL;
		return error;
	}

	s = splnet();
	bcp_prev = NULL;
	bcp_next = NULL;
	for (bcp = mip6_bcq; bcp; bcp = bcp->next) {
		bcp_next = bcp->next;
		if (bcp != bcp_del) {
			bcp_prev = bcp;
			continue;
		}
		
		/* Make sure that the list pointers are correct. */
		if (bcp_prev == NULL)
			mip6_bcq = bcp->next;
		else
			bcp_prev->next = bcp->next;

		if (bcp->flags & IP6_BUF_HOME) {	
			/* The HA should stop acting as a proxy for the MN. */
			mip6_proxy_control(bcp, RTM_DELETE);

			/* Delete the existing tunnel to the MN. */
			error = mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL,
					    MIP6_NODE_HA, (void *)bcp);
			if (error) {
				*bcp_nxt = bcp_next;
				return error;
			}
		}

#ifdef MIP6_DEBUG
		mip6_debug("\nBinding Cache Entry deleted (0x%x)\n", bcp);
#endif
		free(bcp, M_TEMP);

		/* Remove the timer if the BC queue is empty */
		if (mip6_bcq == NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
			callout_stop(&mip6_timer_bc_ch);
#else
			untimeout(mip6_timer_bc, (void *)NULL);
#endif
		}
		break;
	}
	splx(s);
	
	*bcp_nxt = bcp_next;
	return error;
}



/*
 ******************************************************************************
 * Function:    mip6_na_delete
 * Description: Delete an entry in the NA list.
 * Ret value:   Pointer to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_na *
mip6_na_delete(nap_del)
struct mip6_na  *nap_del;  /* Pointer to NA entry to delete */
{
	struct mip6_na   *nap;       /* Current entry in the NA list */
	struct mip6_na   *nap_prev;  /* Previous entry in the NA list */
	struct mip6_na   *nap_next;  /* Next entry in the NA list */
	int               s;

	s = splnet();
	nap_prev = NULL;
	nap_next = NULL;
	for (nap = mip6_naq; nap; nap = nap->next) {
		nap_next = nap->next;
		if (nap == nap_del) {
			if (nap_prev == NULL)
				mip6_naq = nap->next;
			else
				nap_prev->next = nap->next;

#ifdef MIP6_DEBUG
			mip6_debug("\nNeighbor Advertisement Entry "
				   "deleted (0x%x)\n", nap);
#endif
			free(nap, M_TEMP);

			/* Remove the timer if the NA queue is empty */
			if (mip6_naq == NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
				callout_stop(&mip6_timer_na_ch);
#else
				untimeout(mip6_timer_na, (void *)NULL);
#endif
			}
			break;
		}
		nap_prev = nap;
	}
	splx(s);
	return nap_next;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_find
 * Description: Finds an existing prefix entry in the prefix list.
 * Ret value:   Pointer to found prefix list entry or NULL.
 ******************************************************************************
 */
struct mip6_prefix *
mip6_prefix_find(ifp, prefix, prefixlen)
struct ifnet     *ifp;         /* Interface */
struct in6_addr  *prefix;      /* Prefix to search for */
u_int8_t          prefixlen;   /* Prefix length */
{
	struct mip6_prefix  *prq;

	for (prq = mip6_prq; prq; prq = prq->next) {
		if (in6_are_prefix_equal(&prq->prefix, prefix, prefixlen) &&
		    (prq->ifp == ifp))
			return prq;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_create
 * Description: Create a prefix and add it as the first entry in the list.
 *              Start the timer if not started already.
 * Ret value:   Pointer to created prefix list entry or NULL.
 ******************************************************************************
 */
struct mip6_prefix *
mip6_prefix_create(ifp, prefix, prefixlen, flags, validtime, preftime)
struct ifnet     *ifp;          /* Interface */
struct in6_addr  *prefix;       /* Prefix */
u_int8_t          prefixlen;    /* Prefix length */
u_int8_t          flags;        /* Flags in Prefix information option */
u_int32_t         validtime;    /* Valid lifetime (s) */
u_int32_t         preftime;     /* Preferred lifetime (s) */
{
	struct mip6_prefix  *prq;
	int                  s, start_timer = 0;

	if (mip6_prq == NULL) start_timer = 1;

	prq = (struct mip6_prefix *)malloc(sizeof(struct mip6_prefix),
					   M_TEMP, M_NOWAIT);
	if (prq == NULL) return NULL;
	bzero(prq, sizeof(struct mip6_prefix));

	s = splnet();
	prq->next = mip6_prq;
	prq->ifp = ifp;
	prq->prefix = *prefix;
	prq->prefixlen = prefixlen;
	prq->flags = flags;
	prq->timecnt = validtime;
	prq->validtime = validtime;
	prq->preftime = preftime;
	prq->addrlst = NULL;
	mip6_prq = prq;
	splx(s);

#ifdef MIP6_DEBUG
	mip6_debug("\nMIP6 Prefix list entry created (0x%x)\n", prq);
	mip6_debug("Interface:          %s\n", if_name(ifp));
	mip6_debug("Prefix:             %s\n", ip6_sprintf(&prq->prefix));
	mip6_debug("Prefix len:         %d\n", prq->prefixlen);
	mip6_debug("Flags:              ");
	if (prq->flags & ND_OPT_PI_FLAG_ONLINK) mip6_debug("L ");
	if (prq->flags & ND_OPT_PI_FLAG_AUTO)   mip6_debug("A ");
	if (prq->flags & ND_OPT_PI_FLAG_ROUTER) mip6_debug("R ");
	mip6_debug("\n");
	mip6_debug("Valid Lifetime:     ");
	mip6_print_sec(prq->validtime);
	mip6_debug("Preferred Lifetime: ");
	mip6_print_sec(prq->preftime);
#endif

	if (start_timer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_pr_ch, hz, mip6_timer_prefix, NULL);
#else
		timeout(mip6_timer_prefix, (void *)0, hz);
#endif
	}
	return prq;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_update
 * Description: Update an existing prefix.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_prefix_update(prp, flags, validtime, preftime)
struct mip6_prefix  *prp;        /* Prefix list entry */
u_int8_t             flags;      /* Flags in Prefix information option */
u_int32_t            validtime;  /* Valid lifetime (s) */
u_int32_t            preftime;   /* Preferred lifetime (s) */
{
	if (prp == NULL) return;

	if ((prp->flags == flags) && (prp->preftime == preftime) &&
	    (prp->validtime == validtime)) {
		prp->timecnt = validtime;
		return;
	}
		
	/* XXX Add code
	   Set some kind om "flag" to indicate that a RA
	   must be sent to the mobile node.
	*/

	prp->flags = flags;
	prp->timecnt = validtime;
	prp->validtime = validtime;
	prp->preftime = preftime;

#if 0
#ifdef MIP6_DEBUG
	mip6_debug("\nMIP6 Prefix list entry updated (0x%x)\n", prp);
	mip6_debug("Flags:              ");
	if (prp->flags & ND_OPT_PI_FLAG_ONLINK) mip6_debug("L ");
	if (prp->flags & ND_OPT_PI_FLAG_AUTO)   mip6_debug("A ");
	if (prp->flags & ND_OPT_PI_FLAG_ROUTER) mip6_debug("R ");
	mip6_debug("\n");
	mip6_debug("Valid Lifetime:     ");
	mip6_print_sec(prp->validtime);
	mip6_debug("Preferred Lifetime: ");
	mip6_print_sec(prp->preftime);
#endif
#endif
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_add_addr
 * Description: Add a global address to the list of global addresses that a
 *              prefix is keeping
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_prefix_add_addr(prefix, global_addr, hap)
struct mip6_prefix  *prefix;       /* Add address to this prefix */
struct in6_addr     *global_addr;  /* Global home agent address */
struct mip6_halst   *hap;          /* HA list that the address came from */
{
	struct mip6_prefix  *pfx;
	struct mip6_addrlst *addrp;
	int                  s, size;

	for (pfx = mip6_prq; pfx; pfx = pfx->next) {
		if (prefix != pfx) continue;

		size = sizeof(struct mip6_addrlst);
		addrp = (struct mip6_addrlst *)malloc(size, M_TEMP,M_NOWAIT);
		if (addrp == NULL) return -1;
		addrp->hap = hap;
		addrp->ip6_addr = *global_addr;
		
		/* Add the global address as the first entry */
		s = splnet();
		addrp->next = pfx->addrlst;
		pfx->addrlst = addrp;
		splx(s);
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_prefix_delete
 * Description: Delete the requested prefix list entry.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_prefix *
mip6_prefix_delete(pfx_del)
struct mip6_prefix  *pfx_del;    /* Prefix list entry to be deleted */
{
	struct mip6_prefix  *pfx;       /* Current entry in the list */
	struct mip6_prefix  *pfx_prev;  /* Previous entry in the list */
	struct mip6_prefix  *pfx_next;  /* Next entry in the list */
	struct mip6_addrlst *ap, *ap_next;
	int                  s;

	/* Find the requested entry in the link list. */
	s = splnet();
	pfx_next = NULL;
	pfx_prev = NULL;
	for (pfx = mip6_prq; pfx; pfx = pfx->next) {
		pfx_next = pfx->next;
		if (pfx == pfx_del) {
			if (pfx_prev == NULL)
				mip6_prq = pfx->next;
			else
				pfx_prev->next = pfx->next;

			for (ap = pfx->addrlst; ap;) {
				ap_next = ap->next;
				free(ap, M_TEMP);
				ap = ap_next;
			}
#ifdef MIP6_DEBUG
			mip6_debug("\nPrefix entry deleted (0x%x)\n", pfx);
#endif
			free(pfx, M_TEMP);

			/* Remove the timer if the prefix queue is empty */
			if (mip6_prq == NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
				callout_stop(&mip6_timer_pr_ch);
#else
				untimeout(mip6_timer_prefix, (void *)NULL);
#endif
			}
			break;
		}
		pfx_prev = pfx;
	}
	splx(s);
	return pfx_next;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_find
 * Description: Find a Home Agent list entry at a specific link. There will
 *              be one entry for each node sending a Router Advertisement
 *              with the H-bit set including a Prefix Information option
 *              with the R-bit set, for which the Router lifetime or the
 *              Home Agent lifetime (included in a separate option) is not 0.
 * Ret value:   Pointer to found Home Agent list entry or NULL.
 ******************************************************************************
 */
struct mip6_halst *
mip6_hal_find(ifp, ll_addr)
struct ifnet     *ifp;       /* Receiving/sending interface */
struct in6_addr  *ll_addr;   /* Link local address to search for */
{
	struct mip6_halst  *halp;

	for (halp = mip6_haq; halp; halp = halp->next) {
		if (ifp != halp->ifp) continue;
		if (!IN6_ARE_ADDR_EQUAL(&halp->ll_addr, ll_addr)) continue;
		return halp;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_create
 * Description: Create a Home Agent list entry for a specific link.
 * Ret value:   Pointer to created Home Agent list entry or NULL.
 ******************************************************************************
 */
struct mip6_halst *
mip6_hal_create(ifp, ll_addr, lifetime, pref)
struct ifnet     *ifp;        /* Receiving/sending interface */
struct in6_addr  *ll_addr;    /* Link local address for Home Agent */
u_int16_t         lifetime;   /* Home Agent lifetime */
u_int16_t         pref;       /* Home Agent Preference */
{
	struct mip6_halst  *halp;
	int                 s, size;
	int                 start_timer = 0;

	if (mip6_haq == NULL) start_timer = 1;
	
	size = sizeof(struct mip6_halst);
	halp = (struct mip6_halst *)malloc(size, M_TEMP, M_NOWAIT);
	if (halp == NULL) return NULL;
	bzero(halp, sizeof(struct mip6_halst));

	/* Fill in data. */
	halp->ifp = ifp;
	halp->ll_addr = *ll_addr;
	halp->lifetime = lifetime;
	halp->pref = pref;

	if (mip6_haq == NULL) {
		s = splnet();
		halp->next = NULL;
		mip6_haq = halp;
		splx(s);
	} else {
		/* Add the HA list entry to the list in decending order */
		mip6_hal_sort(halp);
	}
	
#ifdef MIP6_DEBUG
	mip6_debug("\nMIP6 HA list entry created (0x%x)\n", halp);
	mip6_debug("Interface:          %s\n", if_name(ifp));
	mip6_debug("Link-local address: %s\n", ip6_sprintf(&halp->ll_addr));
	mip6_debug("Lifetime:           ");
	mip6_print_sec((u_int32_t)halp->lifetime);
	mip6_debug("Preference:         %d\n", halp->pref);
#endif

	if (start_timer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_ha_ch, hz, mip6_timer_hal, NULL);
#else
		timeout(mip6_timer_hal, (void *)0, hz);
#endif
	}
	return halp;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_sort
 * Description: Add a new entry to the HA list in decending order or move an
 *              existing entry. This might be necessary if the preference for
 *              an existing HA list entry changes.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_hal_sort(halp_entry)
struct mip6_halst *halp_entry;  /* Home Agent list entry to sort */
{
	struct mip6_halst   *halp;         /* Current HA list entry */
	struct mip6_halst   *halp_prev;    /* Previous HA list entry */
	int                  s;

	/* If the HA list entry is empty, just add the new entry. */
	s = splnet();
	if (mip6_haq == NULL) {
		mip6_haq = halp_entry;
		halp_entry->next = NULL;
		splx(s);
		return;
	}

	/* Check if the entry already exist in the HA list. */
	halp_prev = NULL;
	for (halp = mip6_haq; halp; halp = halp->next) {
		if (halp == halp_entry) break;
		halp_prev = halp;
	}

	if (halp) {
		/* Entry found, detach it. */
		if (halp_prev == NULL)
			mip6_haq = halp->next;
		else
			halp_prev->next = halp->next;
	}

	/* Add HA list entry to the list. */
	if (mip6_haq == NULL) {
		mip6_haq = halp_entry;
		halp_entry->next = NULL;
		splx(s);
		return;
	}

	halp_prev = NULL;
	for (halp = mip6_haq; halp; halp = halp->next) {
		if (halp->pref > halp_entry->pref) {
			halp_prev = halp;
			if (halp->next == NULL) {
				/* Add as last entry */
				halp->next = halp_entry;
				halp_entry->next = NULL;
				break;
			}
			continue;
		}

		/* Add entry to HA list. */
		if (halp_prev == NULL) {
			mip6_haq = halp_entry;
			halp_entry->next = halp;
		} else {
			halp_prev->next = halp_entry;
			halp_entry->next = halp;
		}
		break;
	}
	splx(s);
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_hal_delete
 * Description: Delete a Home Agent list entry. If there are any address list
 *              entries associated with the Home Agent entry they are deleted
 *              as well.
 * Ret value:   Pointer to the next Home Agent list entry.
 *              NULL if the remaining list is empty or end of list reached.
 ******************************************************************************
 */
struct mip6_halst *
mip6_hal_delete(halp_del)
struct mip6_halst *halp_del;  /* Home Agent entry to delete */
{
	struct mip6_halst    *halp;         /* Current HA list entry */
	struct mip6_halst    *halp_prev;    /* Previous HA list entry */
	struct mip6_halst    *halp_next;    /* Next HA list entry */
	struct mip6_prefix   *pfx;          /* Prefix list entry */
	struct mip6_addrlst  *ap;           /* Address list entry */
	int                   s;

	s = splnet();
	halp_next = NULL;
	halp_prev = NULL;
	for (halp = mip6_haq; halp; halp = halp->next) {
		halp_next = halp->next;
		if (halp == halp_del) {
			if (halp_prev == NULL)
				mip6_haq = halp->next;
			else
				halp_prev->next = halp->next;

			/* Remove all references to this entry */
			for (pfx = mip6_prq; pfx; pfx = pfx->next) {
				for (ap = pfx->addrlst; ap; ap = ap->next) {
					if (ap->hap == halp) ap->hap = NULL;
				}
			}			
#ifdef MIP6_DEBUG
			mip6_debug("\nHA list entry deleted (0x%x)\n", halp);
#endif
			free(halp, M_TEMP);

			/* Remove the timer if the prefix queue is empty */
			if (mip6_haq == NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
				callout_stop(&mip6_timer_ha_ch);
#else
				untimeout(mip6_timer_hal, (void *)NULL);
#endif
			}
			break;
		}
		halp_prev = halp;
	}
	splx(s);
	return halp_next;
}



/*
 ##############################################################################
 #
 # TIMER FUNCTIONS
 # These functions are called at regular basis. They operate on the lists, e.g.
 # reducing timer counters and removing entries from the list if needed.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_timer_na
 * Description: Called once every second. For each entry in the list a Neighbor
 *              Advertisement is sent until the counter value reaches 0. Then
 *              the entry is removed.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_na(arg)
void  *arg;  /* Not used */
{
	struct mip6_na  *nap;   /* Neighbor Advertisement entry */
	int              s;

	/* Go through the entire list of Neighbor Advertisement entries. */
	s = splnet();
	for (nap = mip6_naq; nap;) {
		nd6_na_output(nap->ifp, &in6addr_linklocal_allnodes,
			      &nap->target_addr, nap->flags,
			      nap->link_opt, NULL);
		nap->no -= 1;
		if (nap->no <= 0)
			nap = mip6_na_delete(nap);
		else
			nap = nap->next;
	}
	splx(s);

	/* Call timer function again if more entries in the list. */
	if (mip6_naq != NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_na_ch, hz, mip6_timer_na, NULL);
#else
		timeout(mip6_timer_na, (void *)0, hz);
#endif
	}
}



/*
 ******************************************************************************
 * Function:    mip6_timer_bc
 * Description: Called once every second. For each entry in the BC list, a
 *              counter is reduced by 1 until it reaches the value of zero,
 *              then the entry is removed.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_bc(arg)
void  *arg;  /* Not used */
{
	struct mip6_bc  *bcp;      /* Current entry in the BC list */
	struct mip6_bc  *bcp_nxt;  /* Next BC list entry */
	int              s;

	/* Go through the entire list of Binding Cache entries. */
	s = splnet();
	for (bcp = mip6_bcq; bcp;) {
		bcp->lifetime -= 1;
		if (bcp->lifetime == 0) {
			mip6_bc_delete(bcp, &bcp_nxt);
			bcp = bcp_nxt;
		} else
			bcp = bcp->next;
	}
	splx(s);

	/* XXX */
	/* Code have to be added to take care of bc_info.br_interval
	   variable. */
	/* We have to send a BR when the mip6_bc.lifetime ==
	   mip6_bc.bc_info.br_interval. */
	if (mip6_bcq != NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_bc_ch, hz, mip6_timer_bc, NULL);
#else
		timeout(mip6_timer_bc, (void *)0, hz);
#endif
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_timer_prefix
 * Description: Called once every second. Search the list of prefixes and if
 *              a prefix has timed out it is removed from the list.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_prefix(arg)
void  *arg;  /* Not used */
{
	struct mip6_prefix  *pfxp;   /* Current entry in the prefix list */
	int                  s;

	/* Go through the entire list of prefix entries. */
	s = splnet();
	for (pfxp = mip6_prq; pfxp;) {
		pfxp->timecnt -= 1;
		if (pfxp->timecnt == 0)
			pfxp = mip6_prefix_delete(pfxp);
		else
			pfxp = pfxp->next;
	}
	splx(s);

	if (mip6_prq != NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_pr_ch, hz, mip6_timer_prefix, NULL);
#else
		timeout(mip6_timer_prefix, (void *)0, hz);
#endif
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_timer_hal
 * Description: Called once every second. Search the list of home agents and
 *              if a home agent has timed out it is removed from the list.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_timer_hal(arg)
void  *arg;  /* Not used */
{
	struct mip6_halst  *halp;   /* Current entry in home agent list */
	int                 s;

	/* Go through the entire list of home agents. */
	s = splnet();
	for (halp = mip6_haq; halp;) {
		halp->lifetime -= 1;
		if (halp->lifetime <= 0)
			halp = mip6_hal_delete(halp);
		else
			halp = halp->next;
	}
	splx(s);

	if (mip6_haq != NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_ha_ch, hz, mip6_timer_hal, NULL);
#else
		timeout(mip6_timer_hal, (void *)0, hz);
#endif
	}
	return;
}



/*
 ##############################################################################
 #
 # IOCTL AND DEBUG FUNCTIONS
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_ioctl
 * Description: The ioctl handler for MIPv6. These are used by the
 *              configuration program to set and get various parameters.
 * Ret value:   0 or error code
 ******************************************************************************
 */
int
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
mip6_ioctl(so, cmd, data, ifp, p)
struct  socket *so;
u_long          cmd;
caddr_t         data;
struct ifnet   *ifp;
struct proc    *p;
#else
mip6_ioctl(so, cmd, data, ifp)
struct  socket *so;
u_long          cmd;
caddr_t         data;
struct ifnet   *ifp;
#endif
{
	int res;

	/* Note: privileges already checked in in6_control(). */

	res = 0;

	if (MIP6_IS_HA_ACTIVE) {
		switch (cmd) {
		case SIOCSHALISTFLUSH_MIP6:
			if (mip6_clear_config_data_ha_hook)
				res = (*mip6_clear_config_data_ha_hook)
					(cmd, data);
			return res;
		}
	}

	if (MIP6_IS_MN_ACTIVE) {
		switch (cmd) {
		case SIOCSFORADDRFLUSH_MIP6:
		case SIOCSHADDRFLUSH_MIP6:
		case SIOCSBULISTFLUSH_MIP6:
			if (mip6_clear_config_data_mn_hook)
				res = (*mip6_clear_config_data_mn_hook)
					(cmd, data);
			return res;
		}
	}
	switch (cmd) {
	case SIOCSBCFLUSH_MIP6:
	case SIOCSDEFCONFIG_MIP6:
		res = mip6_clear_config_data(cmd, data);
		return res;

	case SIOCSBRUPDATE_MIP6:
		res = mip6_write_config_data(cmd, data);
		return res;

	case SIOCSHAPREF_MIP6:
		/* Note: this one can be run before attach. */
		if (mip6_write_config_data_ha_hook)
			res = (*mip6_write_config_data_ha_hook)
				(cmd, data);
		return res;

	case SIOCACOADDR_MIP6:
	case SIOCAHOMEADDR_MIP6:
	case SIOCAHOMEPREF_MIP6:
	case SIOCSBULIFETIME_MIP6:
	case SIOCSHRLIFETIME_MIP6:
	case SIOCDCOADDR_MIP6:
	case SIOCSEAGERMD_MIP6:
		/* Note: these can be run before attach. */
		if (mip6_write_config_data_mn_hook)
			res = (*mip6_write_config_data_mn_hook)
				(cmd, data);
		return res;

	case SIOCSDEBUG_MIP6:
	case SIOCSENABLEBR_MIP6:
	case SIOCSATTACH_MIP6:
		res = mip6_enable_func(cmd, data);
		return res;

	case SIOCSFWDSLUNICAST_MIP6:
	case SIOCSFWDSLMULTICAST_MIP6:
		/* Note: these can be run before attach. */
		if (mip6_enable_func_ha_hook)
			res = (*mip6_enable_func_ha_hook)(cmd, data);
		return res;

	case SIOCSPROMMODE_MIP6:
	case SIOCSBU2CN_MIP6:
	case SIOCSREVTUNNEL_MIP6:
	case SIOCSAUTOCONFIG_MIP6:
		/* Note: these can be run before attach. */
		if (mip6_enable_func_mn_hook)
			res = (*mip6_enable_func_mn_hook)(cmd, data);
		return res;

	case SIOCSRELEASE_MIP6:
		mip6_release();
		return res;

	default:
		res = EOPNOTSUPP;
#ifdef MIP6_DEBUG
		printf("%s: unknown command: %lx\n", __FUNCTION__,(u_long)cmd);
#endif
		return res;
	}
}



/*
 ******************************************************************************
 * Function:    mip6_debug
 * Description: This function displays MIPv6 debug messages to the console
 *              if activated with the configuration program. Note that this
 *              is included only when "options MIP6_DEBUG" is defined.
 * Ret value:   -
 ******************************************************************************
 */
#ifdef MIP6_DEBUG
void
#if __STDC__
mip6_debug(char *fmt, ...)
#else
mip6_debug(fmt, va_alist)
	char *fmt;
	va_dcl
#endif
{
#ifndef __bsdi__
	va_list ap;

	if (!mip6_debug_is_enabled)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
#endif
}



void
mip6_enable_debug(int status)
{
	mip6_debug_is_enabled = status;
}
#endif /* MIP6_DEBUG */



/*
 ******************************************************************************
 * Function:    mip6_print_sec
 * Description: Converts an integer of seconds into hours, minutes and seconds.
 * Ret value:   void
 ******************************************************************************
 */
void
mip6_print_sec(seconds)
u_int32_t  seconds;
{
	u_int32_t  sec;
	int        f;

	sec = seconds;
	f = 0;
	if (sec >= 86400) {
		printf("%dd ", sec / 86400);
		sec %= 86400;
		f = 1;
	}
	if (f || sec >= 3600) {
		printf("%dh ", sec / 3600);
		sec %= 3600;
		f = 1;
	}
	if (f || sec >= 60) {
		printf("%dm ", sec / 60);
		sec %= 60;
		f = 1;
	}
	printf("%ds\n", sec);
}



/*
 ******************************************************************************
 * Function:    mip6_write_config_data
 * Description: This function is called to write certain config values for
 *              MIPv6. The data is written into the global config structure.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_write_config_data(u_long cmd, caddr_t data)
{
	int  retval = 0;

	switch (cmd) {
        case SIOCSBRUPDATE_MIP6:
		mip6_config.br_update = *(u_int8_t *)data;
		break;
	}
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_config_data
 * Description: This function is called to clear internal lists handled by
 *              MIPv6.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_clear_config_data(u_long cmd, caddr_t data)
{
	int             s, retval = 0;
	struct mip6_bc *bcp, *bcp_nxt;

	s = splnet();
	switch (cmd) {
	case SIOCSBCFLUSH_MIP6:
		for (bcp = mip6_bcq; bcp;) {
			if(!(bcp->flags & IP6_BUF_HOME)) {
				mip6_bc_delete(bcp, &bcp_nxt);
				bcp = bcp_nxt;
			} else
				bcp = bcp->next;
		}
		break;

	case SIOCSDEFCONFIG_MIP6:
		mip6_config.bu_lifetime = 600;
		mip6_config.br_update = 60;
		mip6_config.hr_lifetime = 3600;

		/* XXX Extra action needed? */
		mip6_config.fwd_sl_unicast = 0;
		mip6_config.fwd_sl_multicast = 0;
		mip6_config.enable_prom_mode = 0;
		mip6_config.enable_bu_to_cn = 0;
		mip6_config.enable_rev_tunnel = 0;
		mip6_config.enable_br = 0;
		mip6_eager_md(0);
		break;
	}
	splx(s);
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_enable_func
 * Description: This function is called to enable or disable certain functions
 *              in mip6. The data is written into the global config struct.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_enable_func(u_long cmd, caddr_t data)
{
	int enable;
	int retval = 0;

	enable = ((struct mip6_input_data *)data)->value;

	switch (cmd) {
	case SIOCSDEBUG_MIP6:
#ifdef MIP6_DEBUG
		mip6_enable_debug(enable);
#else
		printf("No Mobile IPv6 debug information available!\n");
#endif
		break;

	case SIOCSENABLEBR_MIP6:
		mip6_config.enable_br = enable;
		break;

	case SIOCSATTACH_MIP6:
		printf("%s: attach %d\n", __FUNCTION__, enable); /* RM */
		retval = mip6_attach(enable);
		break;
	}
	return retval;
}
