/*	$KAME: mip6_mn.c,v 1.25 2001/05/03 14:51:48 itojun Exp $	*/

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
 *	    Mattias Pettersson <Mattias.Pettersson@era.ericsson.se>
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

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/net_osdep.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

/* Declaration of Global variables. */
struct mip6_bul  *mip6_bulq = NULL;  /* First entry in Binding Update list */
struct mip6_esm  *mip6_esmq = NULL;  /* List of event-state machines */

#ifdef __NetBSD__
struct callout mip6_timer_bul_ch = CALLOUT_INITIALIZER;
struct callout mip6_timer_esm_ch = CALLOUT_INITIALIZER;
#elif (defined(__FreeBSD__) && __FreeBSD__ >= 3)
struct callout mip6_timer_bul_ch;
struct callout mip6_timer_esm_ch;
#endif


/*
 ##############################################################################
 #
 # INITIALIZATION AND EXIT FUNCTIONS
 # These functions are executed when the mobile node specific MIPv6 code is
 # activated and deactivated respectively.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_mn_init
 * Description: Initialization of MIPv6 variables that must be initialized
 *              before the MN code is executed.
 ******************************************************************************
 */
void
mip6_mn_init(void)
{
	mip6_hadiscov_id = 0;
	
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	/* Initialize handle for timer functions. */
	callout_init(&mip6_timer_bul_ch);
	callout_init(&mip6_timer_esm_ch);
#endif
	printf("Mobile Node initialized\n");
}



/*
 ******************************************************************************
 * Function:    mip6_mn_exit
 * Description: This function is called when the MN module is unloaded
 *              (relesed) from the kernel.
 ******************************************************************************
 */
void
mip6_mn_exit()
{
	struct mip6_bul  *bulp;
	struct mip6_esm  *esp;
	int               s;

	/* Cancel outstanding timeout function calls. */
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
	callout_stop(&mip6_timer_bul_ch);
	callout_stop(&mip6_timer_esm_ch);
#else
	untimeout(mip6_timer_bul, (void *)NULL);
	untimeout(mip6_timer_esm, (void *)NULL);
#endif

	/* Remove each entry in every queue. */
	s = splnet();
	for (bulp = mip6_bulq; bulp;)
		bulp = mip6_bul_delete(bulp);
	mip6_bulq = NULL;

	for (esp = mip6_esmq; esp;)
		esp = mip6_esm_delete(esp);
	mip6_esmq = NULL;
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
 * Function:    mip6_validate_ba
 * Description: Validate received Binding Acknowledgement option (see 10.12).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 *              -2  Silently ignore. Process rest of packet.
 ******************************************************************************
 */
int
mip6_validate_ba(m, opt)
struct mbuf  *m;      /* Ptr to beginning of mbuf */
u_int8_t     *opt;    /* Ptr to BA option in DH */
{
	struct ip6_opt_binding_ack  *ba_opt;
	struct ip6_hdr              *ip6;
	struct mip6_bul             *bulp;

	ba_opt = (struct ip6_opt_binding_ack *)(opt);
	ip6 = mtod(m, struct ip6_hdr *);
	    
	/* Make sure that the BA is protected by an AH (see 4.4). */
#ifdef IPSEC
#ifndef __OpenBSD__
	if ( !(m->m_flags & M_AUTHIPHDR && m->m_flags & M_AUTHIPDGM)) {
		log(LOG_ERR,
		    "%s: BA not protected by AH from host %s\n",
		    __FUNCTION__, ip6_sprintf(&ip6->ip6_src));
		return -2;
	}
#endif
#endif

	/* Make sure that the length field in the BA is >= IP6OPT_BALEN. */
	if (ba_opt->ip6oa_len < IP6OPT_BALEN) {
		ip6stat.ip6s_badoptions++;
		log(LOG_ERR,
		    "%s: Length field to short (%d) in BA from host %s\n",
		    __FUNCTION__, ba_opt->ip6oa_len,
		    ip6_sprintf(&ip6->ip6_src));
		return -2;
	}

	/* The sent BU sequence number == received BA sequence number. */
	bulp = mip6_bul_find(&ip6->ip6_src, &ip6->ip6_dst);
	if (bulp == NULL) {
		log(LOG_ERR, "%s: No Binding Update List entry found\n",
		    __FUNCTION__);
		return -2;
	}

	if (ntohs(*(u_int16_t *)ba_opt->ip6oa_seqno) != bulp->seqno) {
		ip6stat.ip6s_badoptions++;
		log(LOG_ERR,
		    "%s: Received sequence # (%d) not equal to sent (%d)\n",
		    __FUNCTION__, ntohs(*(u_int16_t *)ba_opt->ip6oa_seqno),
		    bulp->seqno);
		return -2;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_process_ba
 * Description: Process a received Binding Acknowledgement option, see 10.12.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_process_ba(m, opt)
struct mbuf  *m;    /* Ptr to beginning of mbuf */
u_int8_t     *opt;  /* Ptr to BA option in DH */
{
	struct ip6_opt_binding_update *bu_opt;
	struct ip6_opt_binding_ack    *ba_opt;
	struct ip6_hdr                *ip6;
	struct mip6_esm               *esp;
	struct mip6_bul               *bulp;
	u_int32_t                      lt_update, lt_ack;
	u_int32_t                      lt_remain, lt_refresh;
	u_int8_t                       flags;
	int                            res;

#ifdef MIP6_DEBUG
	mip6_print_opt(m, opt);
#endif

	ba_opt = (struct ip6_opt_binding_ack *)opt;
	ip6 = mtod(m, struct ip6_hdr *);
	
	bulp = mip6_bul_find(&ip6->ip6_src, &ip6->ip6_dst);
	if (bulp == NULL) return -1;

	/* Check the status field in the BA. */
	if (ba_opt->ip6oa_status >= MIP6_BA_STATUS_UNSPEC) {
		/* Remove BUL entry. Process error (order is important). */
		mip6_bul_delete(bulp);
		res = mip6_ba_error(m, opt);
		if (res == -1) return -1;
		return 0;
	}
	
	/* BA was accepted. Update corresponding entry in the BUL.
	   Stop retransmitting the BU. */
	mip6_bul_clear_state(bulp);

	lt_update = bulp->sent_lifetime;
	lt_ack = ntohl(*(u_int32_t *)ba_opt->ip6oa_lifetime);
	lt_remain = bulp->lifetime;
	if (lt_ack < lt_update)
		lt_remain = max(lt_remain - (lt_update - lt_ack), 0);
	else
		lt_remain = ntohl(*(u_int32_t *)ba_opt->ip6oa_lifetime);

	bulp->lifetime = lt_remain;
	bulp->refresh = lt_remain;

	if (bulp->flags & IP6_BUF_HOME) {
		lt_refresh = ntohl(*(u_int32_t *)ba_opt->ip6oa_refresh);
		if ((lt_refresh > 0) && (lt_refresh < lt_remain))
			bulp->refresh = lt_refresh;
	}

	/* If the BA was received from the Home Agent the state
	   of the event state machine shall be updated. */
	if (bulp->flags & IP6_BUF_HOME) {
		esp = mip6_esm_find(&bulp->local_home, 0);
		if (esp == NULL) {
			log(LOG_ERR, "%s: No ESM found\n", __FUNCTION__);
			return -1;
		}

		if (esp->state == MIP6_STATE_DEREG) {
			/* Returning home (see 10.20) */
			mip6_bul_delete(bulp);

			/* Remove tunnel from MN to HA */
			mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL,
				    MIP6_NODE_MN, (void *)esp);

			/* Send BU to each CN in the BUL to remove its
			   BC entry. */
			flags = 0;
			bu_opt = mip6_create_bu(0, flags, 0);
			if (bu_opt == NULL) return 0;
			
			mip6_update_cns(bu_opt, NULL, &esp->home_addr,
					&esp->home_addr, 0);

			/* Don't set the state until BUs have been sent to
			   all CNs, otherwise the Home Address option will
			   not be added for the outgoing packet. */
			esp->state = MIP6_STATE_HOME;
			esp->coa = in6addr_any;
		} else {
			esp->state = MIP6_STATE_REG;

			/* Create or modify a tunnel used by the MN to
			   receive incoming tunneled packets. */
			if (mip6_tunnel(&esp->coa, &esp->ha_hn,
					MIP6_TUNNEL_MOVE, MIP6_NODE_MN,
					(void *)esp))
				return -1;

			/* Send BU to each CN in the BUL to update BC entry. */
			flags = 0;
			bu_opt = mip6_create_bu(0, flags, bulp->lifetime);
			if (bu_opt == NULL) return -1;

			mip6_update_cns(bu_opt, NULL, &esp->home_addr,
					&esp->coa, bulp->lifetime);
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_ba_error
 * Description: Each incoming BA error is taken care of by this function.
 *              If a registration to the Home Agent failed then dynamic home
 *              agent address discovery shall be performed. If a de-regi-
 *              stration failed then perform the same actions as when a
 *              BA with status equals to 0 is received.
 *              If a registration or de-registration to the CN failed then
 *              the error is logged, no further action is taken.
 *              If dynamic home agent address discovery already has been
 *              done then take the next entry in the list. If its just one
 *              entry in the list discard it and send a BU with destination
 *              address equals to Home Agents anycast address.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_ba_error(m, opt)
struct mbuf  *m;      /* Ptr to beginning of mbuf */
u_int8_t     *opt;    /* Ptr to BA option in DH */
{
	struct ip6_opt_binding_ack  *ba_opt;
	struct ip6_hdr              *ip6;

	ba_opt = (struct ip6_opt_binding_ack *)opt;
	ip6 = mtod(m, struct ip6_hdr *);

	if (ba_opt->ip6oa_status == MIP6_BA_STATUS_UNSPEC) {
		/* Reason unspecified
		   Received when either a Home Agent or Correspondent Node
		   was not able to process the BU. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Reason unspecified) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_PROHIBIT) {
		/* Administratively prohibited */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Administratively prohibited) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_RESOURCE) {
		/* Insufficient resources
		   Received when a Home Agent receives a BU with the H-bit
		   set and insufficient space exist or can be reclaimed
		   (sec. 8.7). */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Insufficient resources) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_HOMEREGNOSUP) {
		/* Home registration not supported
		   Received when a primary care-of address registration
		   (sec. 9.3) is done and the node is not a router
		   implementing Home Agent functionality. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Home registration not supported) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_SUBNET) {
		/* Not home subnet
		   Received when a primary care-of address registration
		   (sec. 9.3) is done and the home address for the binding
		   is not an on-link IPv6 address with respect to the Home
		   Agent's current prefix list. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Not home subnet) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_IFLEN) {
		/* Incorrect subnet prefix length
		   Received when a primary care-of address registration
		   (sec. 9.3) is done and the prefix length in the BU
		   differs from the length of the home agent's own knowledge
		   of the subnet prefix length on the home link. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Incorrect subnet prefix length) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_NOTHA) {
		/* Not Home Agent for this Mobile Node
		   Received when a primary care-of address de-registration
		   (sec. 9.4) is done and the Home Agent has no entry for
		   this mobil node marked as "home registration" in its
		   Binding Cache. */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Not Home Agent for this Mobile Node) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else if (ba_opt->ip6oa_status == MIP6_BA_STATUS_DAD) {
		/* Duplicate Address Detection failed
		   Received when the Mobile Node's home address already is
		   in use at the home network (see X.X). */
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Duplicate Address Detection failed) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	} else {
		log(LOG_INFO,
		    "\nBinding Acknowledgement error = %d "
		    "(Unknown) from host %s\n",
		    ba_opt->ip6oa_status, ip6_sprintf(&ip6->ip6_src));
	}

	/* Furthr processing according to the desription in the header. */
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_process_br
 * Description: Process a Binding Request option (see 10.13).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_process_br(m, opt)
struct mbuf *m;     /* Ptr to beginning of mbuf */
u_int8_t    *opt;   /* Ptr to BR option in DH */
{
	struct ip6_opt_binding_request *br_opt;
	struct ip6_opt_binding_update  *bu_opt;
	struct ip6_hdr                 *ip6;
	struct ip6aux                  *ip6a = NULL;
	struct mbuf                    *n;
	struct mip6_bul                *bulp_cn;  /* CN entry in BU list */
	struct mip6_bul                *bulp_ha;  /* HA entry in BU list */
	struct mip6_buffer             *subbuf;   /* Sub-options for BU */
	struct mip6_subopt_altcoa       altcoa;
	struct mip6_subopt_uid         *uid = NULL, bruid;
	struct mip6_esm                *esp;
	u_int16_t                       var16;
	u_int8_t                       *subopt, flags;
	int                             size;

#ifdef MIP6_DEBUG
	mip6_print_opt(m, opt);
#endif

	br_opt = (struct ip6_opt_binding_request *)opt;
	ip6 = mtod(m, struct ip6_hdr *);

	n = ip6_findaux(m);
	if (!n) return -1;
	ip6a = mtod(n, struct ip6aux *);
	if (ip6a == NULL) return -1;

	/* If the BR came from the home agent it was included in a RA
	   and is processed by the MIPv6 icmp code. */
	esp = mip6_esm_find(&ip6->ip6_dst, 0);
	if (esp == NULL) return -1;

	if (br_opt->ip6or_len > IP6OPT_BRLEN) {
		subopt = opt + IP6OPT_MINLEN + IP6OPT_BRLEN;
		uid = mip6_find_subopt_uid(subopt, *(opt + 1) - IP6OPT_BRLEN);
	}

	if (IN6_ARE_ADDR_EQUAL(&esp->ha_hn, &ip6->ip6_dst)) {
		if (uid == NULL) return -1;

		ip6a->ip6a_flags |= IP6A_BRUID;
		ip6a->ip6a_bruid = ntohs(*(u_int16_t *)uid->uid);
		return 0;
	}

	/* A CN is requesting the MN to send a BU to update its BC.
	   Find out which lifetime to use in the BU */
	bulp_cn = mip6_bul_find(&ip6->ip6_src, &ip6->ip6_dst);
	if (bulp_cn == NULL) return -1;

	bulp_ha = mip6_bul_find(&esp->ha_hn, &ip6->ip6_dst);
	if (bulp_ha == NULL) return -1;

	if (bulp_ha->lifetime > bulp_cn->lifetime) {
		size = sizeof(struct mip6_buffer);
		subbuf = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
		if (subbuf == NULL) return -1;
		bzero((caddr_t)subbuf, sizeof(struct mip6_buffer));

		flags = 0;
		bu_opt = mip6_create_bu(esp->prefixlen, flags,
					bulp_ha->lifetime);
		if (bu_opt == NULL) {
			free(subbuf, M_TEMP);
			return 0;
		}

		altcoa.type = IP6SUBOPT_ALTCOA;
		altcoa.len = IP6OPT_COALEN;
		size = sizeof(struct in6_addr);
		bcopy((caddr_t)&bulp_cn->local_coa, altcoa.coa, size);
		mip6_add_subopt2buf((u_int8_t *)&altcoa, subbuf);

		if (uid != NULL) {
			bruid.type = IP6SUBOPT_UNIQUEID;
			bruid.len = IP6OPT_UIDLEN;
			var16 = ntohs(*(u_int16_t *)uid->uid);
			bcopy((caddr_t)&var16, &bruid.uid, sizeof(var16));
			mip6_add_subopt2buf((u_int8_t *)&bruid, subbuf);
		}

		/* Send BU to CN */
		if (mip6_send_bu(bulp_cn, bu_opt, subbuf)) {
			free(subbuf, M_TEMP);
			free(bu_opt, M_TEMP);
			return -1;
		}

		/* Update BUL entry */
		bulp_cn->sent_lifetime = bulp_ha->lifetime;
		bulp_cn->lifetime = bulp_ha->lifetime;
		bulp_cn->refresh = bulp_ha->lifetime;
		bulp_cn->flags = 0;
		mip6_bul_clear_state(bulp_cn);
		free(subbuf, M_TEMP);
		free(bu_opt, M_TEMP);
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_send_bu
 * Description: Send a Binding Update option to a node (CN, HA or MN). A new
 *              IPv6 packet is built including an IPv6 header and a Destination
 *              header (where the BU is stored).
 * Arguments:   bulp   - BUL entry for which the BU is sent.
 *              bu_opt - BU option to send. NULL if the BU option stored in
 *                       the BUL entry is used.
 *              subbuf - Sub-options for the BU. NULL if the BU sub-options
 *                       stored in the BUL entry is used.
 * Note:        The following combinations of indata are possible:
 *              bu_opt == NULL && subbuf == NULL Use existing data, i.e used
 *                                               for retransmission
 *              bu_opt != NULL && subbuf == NULL Clear existing data and send
 *                                               a new BU without sub-options
 *              bu_opt != NULL && subbuf != NULL Clear existing data and send
 *                                               a new BU with new sub-options
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_send_bu(bulp, bu_opt, subbuf)
struct mip6_bul                *bulp;    /* BUL entry used when sending BU */
struct ip6_opt_binding_update  *bu_opt;  /* Binding Update option */
struct mip6_buffer             *subbuf;  /* Buffer with BU options or NULL */
{
	struct mbuf         *mo;         /* IPv6 header stored in a mbuf */
	struct ip6_pktopts  *pktopts;    /* Options for IPv6 packet */
	struct mip6_esm     *esp;        /* Home address entry */
	struct ip6_ext      *ext_hdr;
	struct mip6_buffer   dh2;
	u_int8_t            *bu_pos, *ptr;
	int                  error, ii, len, size;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
	long time_second = time.tv_sec;
#endif

	/* Make sure that it's allowed to send a BU */
	if (bulp == NULL) return 0;

	if (!bulp->send_flag) {
		log(LOG_INFO,
		    "%s: BU not sent to host %s due to an ICMP Parameter "
		    "Problem, Code 2, when a BU was sent previously\n",
		    __FUNCTION__, ip6_sprintf(&bulp->peer_home));
		return 0;
	}

	/* Only send BU if we are not in state UNDEFINED */
	esp = mip6_esm_find(&bulp->local_home, 0);
	if (esp == NULL) {
		log(LOG_ERR, "%s: We should never come here\n", __FUNCTION__);
		return 0;
	} else if (esp->state == MIP6_STATE_UNDEF) {
		log(LOG_INFO,
		    "%s: Mobile Node with home address %s not connected to "
		    "any network. Binding Update could not be sent.\n",
		    __FUNCTION__, ip6_sprintf(&bulp->local_home));
		return 0;
	}

	/* Evaluate parameters according to the note in the function header */
	if ((bu_opt == NULL) && (subbuf == NULL)) {
		if (!(bulp->flags & IP6_BUF_ACK) && bulp->bul_opt == NULL) {
			log(LOG_ERR,
			    "%s: No existing BU option to send\n",
			    __FUNCTION__);
			return 0;
		}

		bulp->seqno += 1;
		bcopy((caddr_t)&bulp->seqno, bulp->bul_opt->ip6ou_seqno,
		      sizeof(bulp->seqno));
		bcopy((caddr_t)&bulp->lifetime, bulp->bul_opt->ip6ou_lifetime,
		      sizeof(bulp->lifetime));
		bu_opt = bulp->bul_opt;
		subbuf = bulp->bul_subopt;
	} else if (bu_opt != NULL) {
		mip6_bul_clear_state(bulp);
		bulp->seqno += 1;
		bcopy((caddr_t)&bulp->seqno, bu_opt->ip6ou_seqno,
		      sizeof(bulp->seqno));
		bcopy((caddr_t)&bulp->lifetime, bu_opt->ip6ou_lifetime,
		      sizeof(bulp->lifetime));

		if (bu_opt->ip6ou_flags & IP6_BUF_ACK) {
			size = sizeof(struct ip6_opt_binding_update);
			bulp->bul_opt = (struct ip6_opt_binding_update *)
				malloc(size, M_TEMP, M_NOWAIT);
			if (bulp->bul_opt == NULL) return -1;
			bcopy((caddr_t)bu_opt, (caddr_t)bulp->bul_opt, size);

			if (subbuf != NULL) {
				size = sizeof(struct mip6_buffer);
				bulp->bul_subopt = (struct mip6_buffer *)
					malloc(size, M_TEMP, M_NOWAIT);
				if (bulp->bul_subopt == NULL) {
					free(bulp->bul_opt, M_TEMP);
					return -1;
				}
				bcopy((caddr_t)subbuf,
				      (caddr_t)bulp->bul_subopt,size);
			}

			bulp->flags |= IP6_BUF_ACK;
			if (bu_opt->ip6ou_flags & IP6_BUF_DAD) {
				bulp->bul_timeout = 4;
				bulp->bul_timeleft = 4;
			} else {
				bulp->bul_timeout = 2;
				bulp->bul_timeleft = 2;
			}
			bu_opt = bulp->bul_opt;
			subbuf = bulp->bul_subopt;
		}
	} else {
		log(LOG_ERR,
		    "%s: Function parameter error. We should not come here\n",
		    __FUNCTION__);
		return 0;
	}

	/* Allocate necessary memory and send the BU */
	pktopts = (struct ip6_pktopts *)malloc(sizeof(struct ip6_pktopts),
					       M_TEMP, M_NOWAIT);
	if (pktopts == NULL) return -1;
	init_ip6pktopts(pktopts);

	mo = mip6_create_ip6hdr(&bulp->local_home, &bulp->peer_home,
				IPPROTO_NONE, 0);
	if (mo == NULL) {
		free(pktopts, M_TEMP);
		return -1;
	}

	bzero((caddr_t)&dh2, sizeof(dh2));
	bu_pos = mip6_add_opt2dh((u_int8_t *)bu_opt, &dh2);
	mip6_add_subopt2dh(subbuf, &dh2, bu_pos);
	mip6_align(&dh2);
	ext_hdr = (struct ip6_ext *)dh2.buf;
	ext_hdr->ip6e_nxt = IPPROTO_NONE;
	pktopts->ip6po_dest2 = (struct ip6_dest *)dh2.buf;

	error = ip6_output(mo, pktopts, NULL, 0, NULL, NULL);
	if (error) {
		free(pktopts, M_TEMP);
		log(LOG_ERR,
		    "%s: ip6_output function failed to send BU, error = %d\n",
		    __FUNCTION__, error);
		return -1;
	}

	/* Update Binding Update List variables. */
	bulp->lasttime = time_second;

	if (!(bu_opt->ip6ou_flags & IP6_BUF_ACK)) {
		bulp->bul_sent += 1;
		if (bulp->bul_sent >= MIP6_MAX_FAST_UPDATES)
			bulp->bul_rate = MIP6_SLOW_UPDATE_RATE;
	}

#ifdef MIP6_DEBUG
	mip6_debug("\nSent Binding Update option (0x%x)\n", bu_opt);
	mip6_debug("IP Header Src:     %s\n", ip6_sprintf(&bulp->local_home));
	mip6_debug("IP Header Dst:     %s\n", ip6_sprintf(&bulp->peer_home));
	mip6_debug("Type/Length/Flags: %x / %u / ",
		   bu_opt->ip6ou_type, bu_opt->ip6ou_len);
	if (bu_opt->ip6ou_flags & IP6_BUF_ACK)    mip6_debug("A ");
	if (bu_opt->ip6ou_flags & IP6_BUF_HOME)   mip6_debug("H ");
	if (bu_opt->ip6ou_flags & IP6_BUF_ROUTER) mip6_debug("R ");
	if (bu_opt->ip6ou_flags & IP6_BUF_DAD)    mip6_debug("D ");
	mip6_debug("\n");
	mip6_debug("Prefix length:     %u\n", bu_opt->ip6ou_prefixlen);
	mip6_debug("Sequence number:   %u\n",
		   *(u_int16_t *)bu_opt->ip6ou_seqno);
	mip6_debug("Life time:         ");
	mip6_print_sec(*(u_int32_t *)bu_opt->ip6ou_lifetime);
	mip6_debug("Destination Header 2 Contents\n");

	ptr = (u_int8_t *)dh2.buf;
	len = (*(ptr + 1) + 1) << 3;
	for (ii = 0; ii < len; ii++, ptr++) {
		if (ii % 16 == 0) mip6_debug("\t0x:");
		if (ii % 4 == 0) mip6_debug(" ");
		mip6_debug("%02x ", *ptr);
		if ((ii + 1) % 16 == 0) mip6_debug("\n");
	}
	if (ii % 16) mip6_debug("\n");
#endif

	/* Remove allocated memory (mo is removed by ip6_output). */
	free(pktopts, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_update_cns
 * Description: Search the BUL for each entry with a matching home address for
 *              which no Binding Update has been sent for the new COA.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_update_cns(bu_opt, subbuf, local_home, local_coa, lifetime)
struct ip6_opt_binding_update *bu_opt;     /* BU option */
struct mip6_buffer            *subbuf;     /* List of sub-options or NULL */
struct in6_addr               *local_home; /* Home address for MN */
struct in6_addr               *local_coa;  /* New coa for MN */
u_int32_t                      lifetime;
{
	struct mip6_bul  *bulp;
	
	/* Search the Binding Update list for entries for which a BU
	   option have to be sent. */
	for (bulp = mip6_bulq; bulp;) {
		if (IN6_ARE_ADDR_EQUAL(local_home, &bulp->local_home) &&
		    !IN6_ARE_ADDR_EQUAL(local_coa, &bulp->local_coa)) {
			bulp->lifetime = lifetime;
			bulp->refresh = lifetime;
			bulp->sent_lifetime = lifetime;
			if (mip6_send_bu(bulp, bu_opt, subbuf) == -1)
				return;
			
			/* Remove BUL entry if de-registration and A-bit
			   was not set. */
			if (!(bu_opt->ip6ou_flags & IP6_BUF_ACK) &&
			    (IN6_ARE_ADDR_EQUAL(local_home, local_coa) ||
			     (bu_opt->ip6ou_lifetime == 0)))
				bulp = mip6_bul_delete(bulp);
			else
				bulp = bulp->next;
		} else
			bulp = bulp->next;
	}
}



/*
 ******************************************************************************
 * Function:    mip6_create_bu
 * Description: Create a Binding Update option for transmission.
 * Ret value:   Pointer to the BU option or NULL.
 * Note:        Variable seqno is set in function mip6_update_bul_entry().
 *              Variables are stored in host byte order.
 ******************************************************************************
 */
struct ip6_opt_binding_update *
mip6_create_bu(prefixlen, flags, lifetime)
u_int8_t   prefixlen;   /* Prefix length for Home Address */
u_int8_t   flags;       /* Flags for BU option */
u_int32_t  lifetime;    /* Suggested lifetime for the BU registration */
{
	struct ip6_opt_binding_update  *bu_opt;
	int                             len;

	/* Allocate and store Binding Update option data */
	len = sizeof(struct ip6_opt_binding_update);
	bu_opt = (struct ip6_opt_binding_update *)malloc(len,M_TEMP,M_NOWAIT);
	if (bu_opt == NULL) return NULL;
	bzero(bu_opt, sizeof(struct ip6_opt_binding_update));

	bu_opt->ip6ou_type = IP6OPT_BINDING_UPDATE;
	bu_opt->ip6ou_len = IP6OPT_BULEN;
	bu_opt->ip6ou_flags = flags;
	bcopy((caddr_t)&lifetime, bu_opt->ip6ou_lifetime, sizeof(lifetime));

	/* Validate semantics according to 5.1 */
	if (bu_opt->ip6ou_flags & IP6_BUF_HOME)
		bu_opt->ip6ou_prefixlen = prefixlen;
	else {
		bu_opt->ip6ou_prefixlen = 0;
		bu_opt->ip6ou_flags &= ~IP6_BUF_ROUTER;
	}

	if (!(bu_opt->ip6ou_flags & IP6_BUF_HOME &&
	      bu_opt->ip6ou_flags & IP6_BUF_ACK))
		bu_opt->ip6ou_flags &= ~IP6_BUF_DAD;

	return bu_opt;
}



/*
 ##############################################################################
 #
 # EVENT TRIGGED FUNCTIONS
 # These functions are called when a mobile node change its point of attach-
 # ment, i.e. it moves from a home network to a foreign network or from one
 # foreign network to another or from a foreign network back to the home
 # network.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_move
 * Description: Called from the move detection algorithm when it has decided
 *              to change default router, i.e the network that we were
 *              connected to has changed.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_move(state, home_prefix, home_plen, prim_prefix, prim_coa)
int                state;        /* State from move detection algorithm */
struct in6_addr   *home_prefix;  /* Prefix for home address for MN  */
u_int8_t           home_plen;    /* Prefix length for home address */
struct nd_prefix  *prim_prefix;  /* Prefix for primary care-of address */
struct in6_ifaddr *prim_coa;     /* Primary care-of address */
{
	struct in6_addr     *prim_addr;   /* Primary Care-of Adress for MN */
	struct mip6_esm     *esp;

#if 0
	/* Check incoming parameters */
	if (prim_prefix == NULL)
		prim_addr = NULL;
	else
		prim_addr = &prim_prefix->ndpr_addr;
#else
	/* Check incoming parameters */
	if (prim_coa == NULL)
		prim_addr = NULL;
	else
		prim_addr = &prim_coa->ia_addr.sin6_addr;
#endif /* 0 */

	/* Find event-state machine and update it */
	esp = mip6_esm_find(home_prefix, home_plen);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return;
	}

	/* Decide how the mobile node has moved. */
	if ((prim_prefix == NULL) && (state == MIP6_MD_UNDEFINED)) {
		/* The Mobile Node is not connected to a network */
		esp->state = MIP6_STATE_UNDEF;
		esp->coa = in6addr_any;
		if (mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL,
				MIP6_NODE_MN, (void *)esp))
			return;
	} else if ((prim_prefix == NULL) && (state == MIP6_MD_HOME)) {
		/* The Mobile Node is returning to the home link. */
		mip6_move_home(home_prefix, home_plen, prim_addr);
	} else if ((prim_prefix != NULL) && (state == MIP6_MD_FOREIGN)) {
		if ((esp->state == MIP6_STATE_UNDEF) ||
		    (esp->state == MIP6_STATE_HOME) ||
		    (esp->state == MIP6_STATE_DEREG))
			/* Home Network --> Foreign Network */
			mip6_move_hn2fn(home_prefix, home_plen, prim_addr);
		else if (esp->state == MIP6_STATE_REG ||
			   esp->state == MIP6_STATE_REREG ||
			   esp->state == MIP6_STATE_REGNEWCOA ||
			   esp->state == MIP6_STATE_NOTREG) 
			/* Foreign Network --> New Foreign Network */
			mip6_move_fn2fn(home_prefix, home_plen, prim_addr);
	} else
		esp->state = MIP6_STATE_UNDEF;
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_move_home
 * Description: Called from the move detection function when a mobile node is
 *              returning to its home network (see 10.6, 10.20).
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_move_home(home_prefix, home_plen, prim_addr)
struct in6_addr   *home_prefix;  /* Prefix for home address for MN  */
u_int8_t           home_plen;    /* Prefix length for home address */
struct in6_addr   *prim_addr;    /* Primary Care-of Adress for MN */
{
	struct ip6_opt_binding_update *bu_opt;    /* BU option */
	struct mip6_esm               *esp;       /* Home address entry */
	struct mip6_bul               *bulp;      /* Entry in the BU list */
	struct ifaddr                 *if_addr;   /* Interface address */
	struct in6_addr                old_coa;
	struct sockaddr_in6            sin6;
	u_int8_t                       bu_flags;  /* Flags for BU */
	u_long                         na_flags;  /* Flags for NA */

	/* Find event-state machine and update it */
	esp = mip6_esm_find(home_prefix, home_plen);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return -1;
	}

	esp->state = MIP6_STATE_DEREG;
	old_coa = esp->coa;
	esp->coa = esp->home_addr;

	/* Send a BU de-registration to the Home Agent. */
	bulp = mip6_bul_find(NULL, &esp->home_addr);
	if (bulp == NULL) {
		/* The event-state machine was in state undefined. */
		esp->state = MIP6_STATE_HOME;

		/* When returning home and no home registration exist
		   we can not assume the home address to be unique.
		   Perform DAD, but find the i/f address first. */
		bzero(&sin6, sizeof(struct sockaddr_in6));
		sin6.sin6_len = sizeof(struct sockaddr_in6);
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = esp->home_addr;

		if_addr = ifa_ifwithaddr((struct sockaddr *)&sin6);
		if (if_addr == NULL) return -1;

		((struct in6_ifaddr *)if_addr)->ia6_flags |= IN6_IFF_TENTATIVE;
		nd6_dad_start(if_addr, NULL);
		return 0;
	}

	/* Update BUL entry and send BU to home agent */
	bulp->lifetime = mip6_prefix_lifetime(&esp->home_addr, esp->prefixlen);
	bulp->refresh = bulp->lifetime;
	bulp->sent_lifetime = bulp->lifetime;
	bulp->local_coa = bulp->local_home;
	bulp->peer_home = esp->ha_hn;

	bu_flags = 0;
	bu_flags |= IP6_BUF_HOME;
	bu_flags |= IP6_BUF_ACK;
	bu_opt = mip6_create_bu(esp->prefixlen, bu_flags, bulp->lifetime);
	if (bu_opt == NULL) return -1;

	if (mip6_send_bu(bulp, bu_opt, NULL)) return -1;

	/* Update home agent on previous foreign network. */
	mip6_update_fn(home_prefix, home_plen, prim_addr, &old_coa);
	
	/* Make the HA stop intercepting packets */
	na_flags = 0;
	na_flags |= ND_NA_FLAG_OVERRIDE;
	mip6_intercept_control(home_prefix, esp->prefixlen, na_flags);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_move_hn2fn
 * Description: Called from the move detection algorithm when a mobile node
 *              moves from the home network to a foreign network, see 10.6.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_move_hn2fn(home_prefix, home_plen, prim_addr)
struct in6_addr   *home_prefix;  /* Prefix for home address for MN  */
u_int8_t           home_plen;    /* Prefix length for home address */
struct in6_addr   *prim_addr;    /* Primary Care-of Adress for MN */
{
	struct ip6_opt_binding_update *bu_opt;    /* BU option */
	struct mip6_esm               *esp;       /* Home address entry */
	struct mip6_bul               *bulp;      /* Entry in the BU list */
	u_int32_t                      lifetime;  /* Lifetime used in BU */
	u_int8_t                       bu_flags;  /* Flags for BU */

	/* Find event-state machine and update it */
	esp = mip6_esm_find(home_prefix, home_plen);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return -1;
	}

	esp->state = MIP6_STATE_NOTREG;
	esp->coa = *prim_addr;

	/* There are three different ways of sending the packet.
	   1. HA address unspecified    --> Dynamic HA Address Discovery
	   2. Home Address unspecified  --> Send tunneled RS to HA
	   3. Otherwise                 --> Send BU to Home agent
	*/
	if (IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn)) {
		/* Perform Dynamic Home Agent Address Discovery */
		if (mip6_send_hadiscov(esp)) return -1;
		return 0;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)) {
		/* Send tunneled Router Solicitation to home agent */
		mip6_send_rs(esp, 1);
		return 0;
	}

	/* Make sure that the lifetime is correct
	   - Less or equal to lifetime for home address
	   - Less or equal to lifetime for coa
	*/
	lifetime = mip6_prefix_lifetime(&esp->home_addr, esp->prefixlen);
	lifetime = min(lifetime, mip6_prefix_lifetime(&esp->coa,
						      esp->prefixlen));
#ifdef MIP6_DEBUG
	lifetime = min(lifetime, MIP6_BU_LIFETIME);
#endif

	/* Create or Update BUL entry and send BU to home agent */
	bu_flags = 0;
	bu_flags |= IP6_BUF_HOME;
	bu_flags |= IP6_BUF_ACK;

	bulp = mip6_bul_find(NULL, &esp->home_addr);
	if (bulp == NULL) {
		bu_flags |= IP6_BUF_DAD;
		bulp = mip6_bul_create(&esp->ha_hn, &esp->home_addr,
				       &esp->coa, lifetime, bu_flags);
		if (bulp == NULL) return -1;
	}

	bulp->peer_home = esp->ha_hn;
	bulp->local_coa = esp->coa;
	bulp->lifetime = lifetime;
	bulp->refresh = lifetime;
	bulp->sent_lifetime = lifetime;
	
	if (ip6_forwarding) bu_flags |= IP6_BUF_ROUTER;
	bu_opt = mip6_create_bu(esp->prefixlen, bu_flags, lifetime);
	if (bu_opt == NULL) return -1;

	/* Send a BU registration to the Home Agent. */
	if (mip6_send_bu(bulp, bu_opt, NULL)) {
		free(bu_opt, M_TEMP);
		return -1;
	}

	free(bu_opt, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_move_fn2fn
 * Description: Called from the move detection algorithm when a mobile node
 *              moves from one foreign network to another foreign network,
 *              see 10.6.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_move_fn2fn(home_prefix, home_plen, prim_addr)
struct in6_addr   *home_prefix;  /* Prefix for home address for MN  */
u_int8_t           home_plen;    /* Prefix length for home address */
struct in6_addr   *prim_addr;    /* Primary Care-of Adress for MN */
{
	struct ip6_opt_binding_update *bu_opt;    /* BU option */
	struct mip6_esm               *esp;       /* Home address entry */
	struct mip6_bul               *bulp;      /* Entry in the BU list */
	struct in6_addr                old_coa;
	u_int32_t                      lifetime;  /* Lifetime used in BU */
	u_int8_t                       bu_flags;  /* Flags for BU */

	/* Find event-state machine and update it */
	esp = mip6_esm_find(home_prefix, home_plen);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return -1;
	}

	esp->state = MIP6_STATE_REGNEWCOA;
	old_coa = esp->coa;
	esp->coa = *prim_addr;

	/* There are three different ways of sending the packet.
	   1. HA address unspecified    --> Dynamic HA Address Discovery
	   2. Home Address unspecified  --> Send tunneled RS to HA
	   3. Otherwise                 --> Send BU to Home agent
	*/
	if (IN6_IS_ADDR_UNSPECIFIED(&esp->ha_hn)) {
		/* Perform Dynamic Home Agent Address Discovery */
		if (mip6_send_hadiscov(esp)) return -1;
		return 0;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)) {
		/* Send tunneled Router Solicitation to home agent */
		mip6_send_rs(esp, 1);
		return 0;
	}

	/* Make sure that the lifetime is correct
	   - Less or equal to lifetime for home address
	   - Less or equal to lifetime for coa
	*/
	lifetime = mip6_prefix_lifetime(&esp->home_addr, esp->prefixlen);
	lifetime = min(lifetime, mip6_prefix_lifetime(&esp->coa,
						      esp->prefixlen));
#ifdef MIP6_DEBUG
	lifetime = min(lifetime, MIP6_BU_LIFETIME);
#endif

	/* Create or Update BUL entry and send BU to home agent */
	bu_flags = 0;
	bu_flags |= IP6_BUF_HOME;
	bu_flags |= IP6_BUF_ACK;

	bulp = mip6_bul_find(NULL, &esp->home_addr);
	if (bulp == NULL) {
		bulp = mip6_bul_create(&esp->ha_hn,
				       &esp->home_addr,
				       prim_addr,
				       lifetime,
				       bu_flags);
		if (bulp == NULL) return -1;
		bu_flags |= IP6_BUF_DAD;
	}

	bulp->peer_home = esp->ha_hn;
	bulp->local_coa = esp->coa;
	bulp->lifetime = lifetime;
	bulp->refresh = lifetime;
	bulp->sent_lifetime = lifetime;
	
	if (ip6_forwarding) bu_flags |= IP6_BUF_ROUTER;
	bu_opt = mip6_create_bu(esp->prefixlen, bu_flags, lifetime);
	if (bu_opt == NULL) return -1;			

	/* Send a BU registration to the Home Agent. */
	if (mip6_send_bu(bulp, bu_opt, NULL)) return -1;

	/* Update home agent on previous foreign network. */
	mip6_update_fn(home_prefix, home_plen, prim_addr, &old_coa);

	/* Do not remove bu_opt. Needed for retransmission of BU option */
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_update_fn
 * Description: When a mobile node connects to a new link it sends a Binding
 *              Update to its previous link to establish forwarding of packets
 *              from a previous care-of address to the new care-of address,
 *              see 10.9.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_update_fn(home_prefix, home_plen, prim_addr, old_coa)
struct in6_addr   *home_prefix;  /* Prefix for home address for MN  */
u_int8_t           home_plen;    /* Prefix length for home address */
struct in6_addr   *prim_addr;    /* Primary Care-of Adress for MN */
struct in6_addr   *old_coa;      /* Previous care-of address */
{
	struct ip6_opt_binding_update *bu_opt;     /* BU option */
	struct mip6_prefix            *pfxp;       /* MIP6 prefix entry */
	struct mip6_halst             *oldha;      /* Old home agent */
	struct mip6_esm               *esp;        /* Home address entry */
	struct mip6_bul               *bulp;       /* Entry in the BU list */
	struct ifaddr                 *if_addr;    /* Interface address */
	struct in6_addr               *oldha_addr; /* Address for old HA */
	struct mip6_addrlst           *addrp;
	struct sockaddr_in6            sin6;
	u_int32_t                      lifetime;   /* Lifetime used in BU */
	u_int8_t                       bu_flags;   /* Flags for BU */

	if (IN6_IS_ADDR_UNSPECIFIED(old_coa)) return 0;

	/* Find event-state machine for home address */
	esp = mip6_esm_find(home_prefix, home_plen);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return -1;
	}

	/* Find interface where the previous coa is stored */
	bzero(&sin6, sizeof(struct sockaddr_in6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *old_coa;

	if_addr = ifa_ifwithaddr((struct sockaddr *)&sin6);
	if (if_addr == NULL) return -1;

	/* Find a home agent on previous foreign network */
	pfxp = mip6_prefix_find(if_addr->ifa_ifp, old_coa, home_plen);
	if (pfxp == NULL) return -1;

	oldha = NULL;
	oldha_addr = NULL;
	for (addrp = pfxp->addrlst; addrp; addrp = addrp->next) {
		if (addrp->hap == NULL) continue;
		oldha_addr = &addrp->ip6_addr;
		oldha = addrp->hap;
	}

	if ((oldha_addr == NULL) || (oldha == NULL)) return -1;
	
	/* Make sure that the lifetime is correct
	   1. Less or equal to lifetime for home address (here old_coa)
	   2. Less or equal to lifetime for coa (here esp->coa)
	   3. Less or equal to lifetime for home agent.
	*/
	lifetime = mip6_prefix_lifetime(old_coa, esp->prefixlen);
	lifetime = min(lifetime, mip6_prefix_lifetime(&esp->coa,
						      esp->prefixlen));
	lifetime = min(lifetime, oldha->lifetime);
#ifdef MIP6_DEBUG
	lifetime = min(lifetime, MIP6_BU_LIFETIME_HAFN);
#endif

	/* Create or Update BUL entry and send BU to home agent */
	bu_flags = 0;
	bu_flags |= IP6_BUF_HOME;

	bulp = mip6_bul_find(NULL, old_coa);
	if (bulp == NULL) {
		bulp = mip6_bul_create(oldha_addr, old_coa, &esp->coa,
				       lifetime, bu_flags);
		if (bulp == NULL) return -1;
	}

	bulp->peer_home = *oldha_addr;
	bulp->local_coa = esp->coa;
	bulp->lifetime = lifetime;
	bulp->refresh = lifetime;
	bulp->sent_lifetime = lifetime;
	
	if (ip6_forwarding) bu_flags |= IP6_BUF_ROUTER;
	bu_opt = mip6_create_bu(0, bu_flags, lifetime);
	if (bu_opt == NULL) return -1;			

	/* Create an event-state machine to be used when the home address
	   option is created for outgoing packets. The event-state machine
	   must be removed when the BUL entry is removed. */
	esp = mip6_esm_create(if_addr->ifa_ifp, oldha_addr, &esp->coa,
			      prim_addr, prim_addr, home_plen,
			      MIP6_STATE_NOTREG, TEMPORARY, lifetime);
	if (esp == NULL) {
		free(bu_opt, M_TEMP);
		return -1;
	}

	/* Create a tunnel used by the MN to receive
	   incoming tunneled packets. */
	if (mip6_tunnel(prim_addr, oldha_addr, MIP6_TUNNEL_ADD,
			MIP6_NODE_MN, (void *)esp)) {
		free(bu_opt, M_TEMP);
		return -1;
	}

	/* Send a BU registration to the Home Agent. */
	if (mip6_send_bu(bulp, bu_opt, NULL)) return -1;

	free(bu_opt, M_TEMP);
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_send_hadiscov
 * Description: When the home agents unicast address is unknown an ICMP6
 *              "Dynamic Home Agent Address Discovery", packet must be sent
 *              from the mobile node to the home agents anycast address, see
 *              10.7.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_send_hadiscov(esp)
struct mip6_esm   *esp;  /* Event-state machine for MN home address */
{
	struct ha_discov_req  *hadiscov;
	struct in6_addr       *ha_anyaddr;
	struct ip6_hdr        *ip6;
	struct mbuf           *mo;
	u_int32_t              icmp6len, off;
	int                    res, size;

	/* Build home agents anycast address */
	ha_anyaddr = mip6_in6addr_any(&esp->home_pref, esp->prefixlen);
	if (ha_anyaddr == NULL) return -1;
	esp->ha_hn = *ha_anyaddr;

	/* Create the mbuf and copy the ICMP6 message to the mbuf */
	icmp6len = sizeof(struct ha_discov_req);
	mo = mip6_create_ip6hdr(&esp->coa, ha_anyaddr,
				IPPROTO_ICMPV6, icmp6len);
	if (mo == NULL) {
		log(LOG_ERR, "%s: mbuf allocation failure\n", __FUNCTION__);
		return -1;
	}

	/* Allocate memory to hold HA Discovery information. */
	if (esp->hadiscov) {
		if (esp->hadiscov->hal)
			free(esp->hadiscov->hal, M_TEMP);
		free(esp->hadiscov, M_TEMP);
	}
	size = sizeof(struct mip6_hadiscov);
	esp->hadiscov = (struct mip6_hadiscov *)malloc(size, M_TEMP, M_NOWAIT);
	bzero((caddr_t)esp->hadiscov, size);
	mip6_hadiscov_id += 1;
	esp->hadiscov->sent_hadiscov_id = mip6_hadiscov_id;

	/* Build the ICMP6 message. */
	ip6 = mtod(mo, struct ip6_hdr *);
	hadiscov = (struct ha_discov_req *)(ip6 + 1);
	bzero((caddr_t)hadiscov, sizeof(struct ha_discov_req));
	hadiscov->discov_req_type = ICMP6_HADISCOV_REQUEST;
	hadiscov->discov_req_code = 0;

	hadiscov->discov_req_id = htons(esp->hadiscov->sent_hadiscov_id);
	hadiscov->ha_dreq_home = esp->home_pref;

	/* Calculate checksum for ICMP6 packet */
	off = sizeof(struct ip6_hdr);
	hadiscov->discov_req_cksum = in6_cksum(mo, IPPROTO_ICMPV6,
					       off, icmp6len);
	
	/* Send the ICMP6 packet to the home agent */
	res = ip6_output(mo, NULL, NULL, 0, NULL, NULL);
	if (res) {
		log(LOG_ERR,
		    "%s: ip6_output function failed to send ICMP6 "
		    "Dynamic Home Agent Address Discovery request message, "
		    "error = %d\n",
		    __FUNCTION__, res);
		return -1;
	}

	/* mo is removed by ip6_output() */
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_icmp6_hadiscov_reply
 * Description: Processing of an incoming ICMP6 message replying to a
 *              previously sent "Dynamic Home Agent Address Discovery",
 *              see 10.7.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_icmp6_hadiscov_reply(m, off, icmp6len)
struct mbuf *m;         /* Ptr to beginning of mbuf */
int          off;       /* Offset from start of mbuf to ICMP6 message */
int          icmp6len;  /* Total ICMP6 payload length */
{
	struct ip6_opt_binding_update *bu_opt;     /* BU option */
	struct ha_discov_rep          *hadiscov;
	struct mip6_esm               *esp;        /* Home address entry */
	struct mip6_bul               *bulp;       /* Entry in the BU list */
	struct ip6_hdr                *ip6;        /* IPv6 header */
	struct in6_addr               *addr;
	u_int8_t                      *ptr;
	u_int32_t                      lifetime;   /* Lifetime used in BU */
	u_int8_t                       bu_flags;   /* Flags for BU */
	u_int16_t                      sum, id;
	u_int16_t                      size, offset;
	int                            found;

	ip6 = mtod(m, struct ip6_hdr *);
	hadiscov = (struct ha_discov_rep *)(ip6 + 1);

	/* Find event-state machine */
	esp = mip6_esm_find(&ip6->ip6_dst, 0);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: No event-state machine found\n", __FUNCTION__);
		return -1;
	}	

	/* Validation of ICMP6 HA Discovery message */
	if (hadiscov->discov_rep_type != ICMP6_HADISCOV_REPLY) {
		log(LOG_ERR,
		    "%s: Wrong reply type (%d) for ICMP6 HA Discovery\n",
		    __FUNCTION__, hadiscov->discov_rep_type);
		return -1;
	}

	if (hadiscov->discov_rep_code != 0) {
		log(LOG_ERR,
		    "%s: Wrong reply code (%d) for ICMP6 HA Discovery\n",
		    __FUNCTION__, hadiscov->discov_rep_code);		
		return -1;
	}

	if (icmp6len < sizeof(struct ha_discov_rep)) {
		log(LOG_ERR,
		    "%s: Size (%d) to short for ICMP6 HA Discovery reply\n",
		    __FUNCTION__, icmp6len);		
		return -1;
	}

	if (icmp6len % 16) {
		log(LOG_ERR,
		    "%s: Size (%d) must be a multiple of 16\n",
		    __FUNCTION__, icmp6len);
		return -1;
	}
	
	off = sizeof(struct ip6_hdr);
	if ((sum = in6_cksum(m, IPPROTO_ICMPV6, off, icmp6len)) != 0) {
		log(LOG_ERR,
		    "%s: ICMP6 checksum error(%d|%x) %s\n",
		    __FUNCTION__, hadiscov->discov_rep_type, sum,
		    ip6_sprintf(&ip6->ip6_src));
		icmp6stat.icp6s_checksum++;
		return -1;
	}

	if (esp->hadiscov == NULL) {
		log(LOG_ERR,
		    "%s: MN did not expect ICMP6 HA Discovery reply\n",
		    __FUNCTION__);
		return -1;
	}

	id = ntohs(hadiscov->discov_rep_id);
	if (id != esp->hadiscov->sent_hadiscov_id) {
		log(LOG_ERR,
		    "%s: Wrong id (%d) for ICMP6 HA Discovery reply\n",
		    __FUNCTION__, id);
		return -1;
	}

	/* Allocate memory for holding the HA addresses */
	if (esp->hadiscov->hal != NULL)
		free(esp->hadiscov->hal, M_TEMP);
	
	size = sizeof(struct mip6_buffer);
	esp->hadiscov->hal = (struct mip6_buffer *)malloc(size, M_TEMP,
							  M_NOWAIT);
	if (esp->hadiscov->hal == NULL) return -1;
	bzero((caddr_t)esp->hadiscov->hal, size);
		
	/* Save the received home address(es) */
	if (icmp6len == sizeof(struct ha_discov_rep)) {
		/* Use the source address of the packet */
		size = sizeof(struct in6_addr);
		bcopy((caddr_t)&ip6->ip6_src, esp->hadiscov->hal->buf, size);
		esp->hadiscov->hal->off = size;
	} else {
		/* See if the packet source address is included in the
		   list of home agent addresses. */
		found = 0;
		offset = sizeof(struct ha_discov_rep);
		while (offset < icmp6len) {
			ptr = (u_int8_t *)hadiscov + offset;
			addr = (struct in6_addr *)ptr;
			if (IN6_ARE_ADDR_EQUAL(addr, &ip6->ip6_src)) {
				found = 1;
				break;
			}
			offset += sizeof(struct in6_addr);
		}

		if (!found) {
			/* Add the source address of the packet */
			size = sizeof(struct in6_addr);
			bcopy((caddr_t)&ip6->ip6_src,
			      esp->hadiscov->hal->buf, size);
			esp->hadiscov->hal->off = size;
		}

		/* Copy received addresses to the buffer */
		offset = sizeof(struct ha_discov_rep);
		bcopy((caddr_t)hadiscov + offset,
		      esp->hadiscov->hal->buf + esp->hadiscov->hal->off,
		      icmp6len - offset);
		
		esp->hadiscov->hal->off += icmp6len - offset;
	}
	esp->hadiscov->pos = 0;

	/* If no home address available, send Router Solicitation */
	if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)) {
		mip6_send_rs(esp, 1);
		return 0;
	}

	/* Create a BUL entry and a BU option. */
	bulp = mip6_bul_find(NULL, &esp->home_addr);
	if (bulp != NULL) {
		log(LOG_ERR,
		    "%s: A BUL entry found but it shouldn't have been. "
		    "Internal error that must be looked into\n", __FUNCTION__);
		return -1;
	}

	bu_flags = 0;
	bu_flags |= IP6_BUF_HOME;
	bu_flags |= IP6_BUF_ACK;
	bu_flags |= IP6_BUF_DAD;
	if (ip6_forwarding) bu_flags |= IP6_BUF_ROUTER;

	lifetime = MIP6_BU_LIFETIME_HADISCOV;
	esp->ha_hn = *(struct in6_addr *)(esp->hadiscov->hal->buf);
	bulp = mip6_bul_create(&esp->ha_hn, &esp->home_addr,
			       &esp->coa, lifetime, bu_flags);
	if (bulp == NULL) return -1;

	bu_opt = mip6_create_bu(esp->prefixlen, bu_flags, lifetime);
	if (bu_opt == NULL) return -1;

	/* Send a BU registration to the Home Agent. */
	if (mip6_send_bu(bulp, bu_opt, NULL)) {
		free(bu_opt, M_TEMP);
		return -1;
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_send_rs
 * Description: Sends a tunneled Router Solicitation to the home agent, see
 *              10.16.
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */



/*
 ******************************************************************************
 * Function:    mip6_prefix_lifetime
 * Description: Decide the remaining valid lifetime for a home address. Search
 *              the prefix list for a match and use this lifetime value.
 * Note:        This function is used by the MN since no test of the on-link
 *              flag is done.
 * Ret value:   Lifetime
 ******************************************************************************
 */
u_int32_t
mip6_prefix_lifetime(addr, prefixlen)
struct in6_addr  *addr;       /* IPv6 address to check */
u_int8_t          prefixlen;  /* Prefix length for address */
{
	struct nd_prefix  *pr;        /* Entries in the prexix list */
	u_int32_t          min_time;  /* Minimum life time */

	min_time = 0xffffffff;
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		if (pr->ndpr_plen != prefixlen) continue;

#if 0
		if (IN6_ARE_ADDRESS_EQUAL(x,y));
#endif
		
		if (in6_are_prefix_equal(addr, &pr->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)) {
			
			return pr->ndpr_vltime;
		}
	}
	return min_time;
}



/*
 ******************************************************************************
 * Function:    mip6_in6addr_any
 * Description: Build a mobile IPv6 Home Agents anycast address from a prefix
 *              and the prefix length. The interface id is according to
 *              RFC2526.
 * Ret value:   Pointer to HA anycast address or NULL.
 ******************************************************************************
 */
struct in6_addr *
mip6_in6addr_any(prefix, prefixlen)
const struct in6_addr *prefix;     /* Prefix part of the address */
int                    prefixlen;  /* Prefix length (bits) */
{
	struct in6_addr  *new_addr;   /* New address built in this function */
	struct in6_addr   id;         /* ID part of address */

	if (prefix->s6_addr8[0] == 0xff) return NULL;

	if (((prefix->s6_addr8[0] & 0xe0) != 0) && (prefixlen != 64))
		return NULL;

	if (((prefix->s6_addr8[0] & 0xe0) != 0) && (prefixlen == 64))
		id = in6addr_aha_64;
	else
		id = in6addr_aha_nn;

	new_addr = mip6_in6addr(prefix, &id, prefixlen);
	return new_addr;
}



/*
 ##############################################################################
 #
 # LIST FUNCTIONS
 # The Mobile Node maintains a Bindig Update List (BUL) for each node to which
 # a BU has been sent.
 # Besides from this a list of event-state machines, one for each home address
 # is handled by the Mobile Node and the Correspondent Node since it may
 # become mobile at any time.
 # An output queue for piggybacking of options (BU, BA, BR) on the first
 # outgoing packet sent to the node is also maintained. If the option has not
 # been sent with a packet within MIP6_OUTQ_LIFETIME it will be sent in a
 # separate packet.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_bul_find
 * Description: Find a Binding Update List entry for which a matching can be
 *              found for both the local and peer home address.
 *              If variable peer_home is NULL an entry for home registration
 *              will be searched for.
 * Ret value:   Pointer to Binding Update List entry or NULL
 ******************************************************************************
 */
struct mip6_bul *
mip6_bul_find(peer_home, local_home)
struct in6_addr  *peer_home;   /* Destination Address for Binding Update */
struct in6_addr  *local_home;  /* Home Address for MN or previous COA */
{
	struct mip6_bul  *bulp;   /* Entry in the Binding Update list */

	if (peer_home == NULL) {
		for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
			if (IN6_ARE_ADDR_EQUAL(local_home,&bulp->local_home) &&
			    (bulp->flags & IP6_BUF_HOME))
				break;
		}
	} else {
		for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
			if (IN6_ARE_ADDR_EQUAL(peer_home, &bulp->peer_home) &&
			    IN6_ARE_ADDR_EQUAL(local_home, &bulp->local_home))
				break;
		}
		if (bulp != NULL) return bulp;

		/* It might be that the dest address for the BU was the Home
		   Agent anycast address and in that case we try to find it. */
		for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
			if ((bulp->peer_home.s6_addr8[15] & 0x7f) ==
			    MIP6_ADDR_ANYCAST_HA &&
			    IN6_ARE_ADDR_EQUAL(local_home, &bulp->local_home)){
				break;
			}
		}
	}
	return bulp;
}




/*
 ******************************************************************************
 * Function:    mip6_bul_create
 * Description: Create a new Binding Update List entry and insert it as the
 *              first entry in the list.
 * Ret value:   Pointer to Binding Update List entry or NULL.
 * Note:        If the BUL timeout function has not been started it is started.
 *              The BUL timeout function will be called once every second until
 *              there are no more entries in the BUL.
 ******************************************************************************
 */
struct mip6_bul *
mip6_bul_create(peer_home, local_home, local_coa, lifetime, flags)
struct in6_addr      *peer_home;   /* Dst address for Binding Update */
struct in6_addr      *local_home;  /* Home Address for MN or previous COA */
struct in6_addr      *local_coa;   /* Primary COA for MN */
u_int32_t             lifetime;    /* Lifetime for BU */
u_int8_t              flags;       /* Flags for sent BU */
{
	struct mip6_bul  *bulp;    /* New Binding Update list entry */
	int               s;

	bulp = (struct mip6_bul *)malloc(sizeof(struct mip6_bul),
					 M_TEMP, M_NOWAIT);
	if (bulp == NULL) return NULL;
	bzero(bulp, sizeof(struct mip6_bul));

	bulp->next = NULL;
	bulp->peer_home = *peer_home;
	bulp->local_home = *local_home;
	bulp->local_coa = *local_coa;
	bulp->sent_lifetime = lifetime;
	bulp->lifetime = lifetime;
	bulp->refresh = lifetime;
	bulp->seqno = 0;
	bulp->lasttime = 0;
	bulp->send_flag = 1;
	bulp->flags = flags;

	if (bulp->flags & IP6_BUF_ACK) {
		bulp->bul_opt = NULL;
		bulp->bul_subopt = NULL;
		bulp->bul_timeout = 2;
		bulp->bul_timeleft = 2;
	} else {
		bulp->bul_sent = 0;
		bulp->bul_rate = MIP6_MAX_UPDATE_RATE;
	}
	
	/* Insert the entry as the first entry in the BUL. */
	s = splnet();
	if (mip6_bulq == NULL) {
		mip6_bulq = bulp;
	} else {
		bulp->next = mip6_bulq;
		mip6_bulq = bulp;
	}
	splx(s);

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_bul_ch, hz, mip6_timer_bul, NULL);
#else
		timeout(mip6_timer_bul, (void *)0, hz);
#endif

#ifdef MIP6_DEBUG
	mip6_debug("\nBinding Update List Entry created (0x%x)\n", bulp);
	mip6_debug("Dst Address:     %s\n", ip6_sprintf(&bulp->peer_home));
	mip6_debug("Home Address:    %s\n", ip6_sprintf(&bulp->local_home));
	mip6_debug("Care-of Address: %s\n", ip6_sprintf(&bulp->local_coa));
	mip6_debug("Lifetime:        ");
	mip6_print_sec(bulp->lifetime);
	mip6_debug("Refresh time:    ");
	mip6_print_sec(bulp->refresh);
	mip6_debug("Seq no/Flags:    %u / ", bulp->seqno);
	if (bulp->flags & IP6_BUF_HOME) mip6_debug("H ");
	if (bulp->flags & IP6_BUF_ACK)  mip6_debug("A ");
	mip6_debug("\n");
#endif
	return bulp;
}



/*
 ******************************************************************************
 * Function:    mip6_bul_delete
 * Description: Delete the requested Binding Update list entry.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_bul *
mip6_bul_delete(bul_remove)
struct mip6_bul  *bul_remove;    /* BUL entry to be deleted */
{
	struct mip6_bul  *bulp;       /* Current entry in the BU list */
	struct mip6_bul  *bulp_prev;  /* Previous entry in the BU list */
	struct mip6_bul  *bulp_next;  /* Next entry in the BU list */
	int               s;

	/* Find the requested entry in the BUL. */
	s = splnet();
	bulp_next = NULL;
	bulp_prev = NULL;
	for (bulp = mip6_bulq; bulp; bulp = bulp->next) {
		bulp_next = bulp->next;
		if (bulp == bul_remove) {
			if (bulp_prev == NULL)
				mip6_bulq = bulp->next;
			else
				bulp_prev->next = bulp->next;
#ifdef MIP6_DEBUG
			mip6_debug("\nBU List Entry deleted (0x%x)\n", bulp);
#endif
			mip6_bul_clear_state(bulp);
			free(bulp, M_TEMP);

			/* Remove the timer if the BUL queue is empty */
			if (mip6_bulq == NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
				callout_stop(&mip6_timer_bul_ch);
#else
				untimeout(mip6_timer_bul, (void *)NULL);
#endif
			}
			break;
		}
		bulp_prev = bulp;
	}
	splx(s);
	return bulp_next;
}



/*
 ******************************************************************************
 * Function:    mip6_bul_clear_state
 * Description: Removes the current content of the bulp->state variable.
 * Ret value:   Void
 ******************************************************************************
 */
void
mip6_bul_clear_state(bulp)
struct mip6_bul    *bulp;
{
	if (bulp == NULL) return;

	if (bulp->flags & IP6_BUF_ACK) {
		if (bulp->bul_opt) free(bulp->bul_opt, M_TEMP);
		if (bulp->bul_subopt) free(bulp->bul_subopt, M_TEMP);
		bulp->flags &= ~IP6_BUF_ACK;
		bulp->bul_opt = NULL;
		bulp->bul_subopt = NULL;
		bulp->bul_timeout = 2;
		bulp->bul_timeleft = 2;
	} else {
		bulp->bul_sent = 0;
		bulp->bul_rate = MIP6_MAX_UPDATE_RATE;
	}
	return;
}



/*
 ******************************************************************************
 * Function:    mip6_esm_find
 * Description: Find an event-state machine. If the home address is known, set
 *              the prefix variable equal to the home address and prefixlen
 *              equals to 0. Otherwise, if the home address is not known, set
 *              the prefixlen to the length of the prefix and the prefix
 *              variable equal to the prefix.
 * Ret value:   Pointer to event-state machine entry or NULL
 ******************************************************************************
 */
struct mip6_esm *
mip6_esm_find(prefix, prefixlen)
struct in6_addr  *prefix;      /* Mobile nodes home prefix */
u_int8_t          prefixlen;
{
	struct mip6_esm  *esp;

	for (esp = mip6_esmq; esp; esp = esp->next) {
		if (prefixlen == 0) {
			if (IN6_ARE_ADDR_EQUAL(prefix, &esp->home_addr))
				return esp;
			else
				continue;
		}

		if (esp->prefixlen != prefixlen) continue;
		if (in6_are_prefix_equal(&esp->home_pref, prefix, prefixlen))
			return esp;
	}
	return NULL;
}



/*
 ******************************************************************************
 * Function:    mip6_esm_create
 * Description: Create an event-state machine entry and add it first to the
 *              list. If type is PERMANENT the lifetime will be set to 0xFFFF,
 *              otherwise it will be set to the specified lifetime. If type is
 *              TEMPORARY the timer will be started if not already started.
 * Ret value:   Pointer to an event-state machine or NULL.
 ******************************************************************************
 */
struct mip6_esm *
mip6_esm_create(ifp, ha_hn, coa, home_addr, home_pref, prefixlen, state,
                type, lifetime)
struct ifnet    *ifp;        /* Physical i/f used by this home address */
struct in6_addr *ha_hn;      /* Home agent address (home network) */
struct in6_addr *coa;        /* Current care-of address */
struct in6_addr *home_addr;  /* Home address */
struct in6_addr *home_pref;  /* Home prefix */
u_int8_t         prefixlen;  /* Prefix length for the home address */
int              state;      /* State of the home address */
enum esm_type    type;       /* Permanent or Temporary esm */
u_int16_t        lifetime;   /* Lifetime for event-state machine */
{
	struct mip6_esm  *esp, *esp_tmp;
	int               start_timer, s;

	esp = (struct mip6_esm *)malloc(sizeof(struct mip6_esm),
					M_TEMP, M_WAITOK);
	if (esp == NULL) {
		log(LOG_ERR,
		    "%s: Could not create an event-state machine\n",
		    __FUNCTION__);
		return NULL;
	}
	bzero(esp, sizeof(struct mip6_esm));

	esp->next = NULL;
	esp->ifp = ifp;
	esp->ep = NULL;
	esp->state = state;
	esp->type = type;
	esp->home_addr = *home_addr;
	esp->home_pref = *home_pref;
	esp->prefixlen = prefixlen;
	esp->ha_hn = *ha_hn;
	esp->coa = *coa;
	esp->hadiscov = NULL;

	if (type == PERMANENT) {
		esp->lifetime = 0xFFFF;
		start_timer = 0;
	} else {
		esp->lifetime = lifetime;
		start_timer = 1;
	}

	/* If no TEMPORARY already exist and the new is TEMPORARY, start
	   the timer. */
	for (esp_tmp = mip6_esmq; esp_tmp; esp_tmp = esp_tmp->next) {
		if (esp_tmp->type == TEMPORARY)
			start_timer = 0;
	}

	/* Insert entry as the first entry in the event-state machine list */
	s = splnet();
	if (mip6_esmq == NULL)
		mip6_esmq = esp;
	else {
		esp->next = mip6_esmq;
		mip6_esmq = esp;
	}
	splx(s);

	if (start_timer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_esm_ch, hz, mip6_timer_esm, NULL);
#else
		timeout(mip6_timer_esm, (void *)0, hz);
#endif
	}
	return esp;
}



/*
 ******************************************************************************
 * Function:    mip6_esm_delete
 * Description: Delete the requested event-state machine.
 * Ret value:   Ptr to next entry in list or NULL if last entry removed.
 ******************************************************************************
 */
struct mip6_esm *
mip6_esm_delete(esm_remove)
struct mip6_esm  *esm_remove;    /* Event-state machine to be deleted */
{
	struct mip6_esm  *esp;       /* Current entry in event-state list */
	struct mip6_esm  *esp_prev;  /* Previous entry in event-state list */
	struct mip6_esm  *esp_next;  /* Next entry in the event-state list */
	int               s;

	/* Find the requested entry in the event-state list. */
	s = splnet();
	esp_next = NULL;
	esp_prev = NULL;
	for (esp = mip6_esmq; esp; esp = esp->next) {
		esp_next = esp->next;
		if (esp == esm_remove) {
			if (esp_prev == NULL)
				mip6_esmq = esp->next;
			else
				esp_prev->next = esp->next;

			mip6_tunnel(NULL, NULL, MIP6_TUNNEL_DEL, MIP6_NODE_MN,
				    (void *)esp);

			if (esp->hadiscov) {
				if (esp->hadiscov->hal)
					free(esp->hadiscov->hal, M_TEMP);
				free(esp->hadiscov, M_TEMP);
			}

#ifdef MIP6_DEBUG
			mip6_debug("\nEvent-state machine deleted (0x%x)\n",
				   esp);
#endif
			free(esp, M_TEMP);

			/* Remove the timer if the ESM queue is empty */
			if (mip6_esmq == NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
				callout_stop(&mip6_timer_esm_ch);
#else
				untimeout(mip6_timer_esm, (void *)NULL);
#endif
			}
			break;
		}
		esp_prev = esp;
	}
	splx(s);
	return esp_next;
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
 * Function:    mip6_timer_bul
 * Description: Search the Binding Update list for entries for which the life-
 *              time or refresh time has expired.
 *              If there are more entries left in the output queue, call this
 *              fuction again once every second until the queue is empty.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_bul(arg)
void  *arg;   /* Not used */
{
	struct mip6_bul               *bulp;      /* Current BUL element */
	struct mip6_bul               *new_bulp;  /* New BUL entry */
	struct mip6_esm               *esp;       /* Home address entry */
	struct ip6_opt_binding_update *bu_opt;    /* BU option to be sent */
	struct in6_addr               *dst_addr;  /* Dst address for BU */
	struct mip6_buffer            *subbuf;    /* Buffer BU sub-options */
	u_int32_t                      ltime;
	u_int8_t                       bu_flags;
	int                            s;

	/* Go through the entire BUL and check if any BU have to be sent. */
	esp = NULL;
	subbuf = NULL;
	s = splnet();
	for (bulp = mip6_bulq; bulp;) {
		/* Find the correct event-state machine */
		esp = mip6_esm_find(&bulp->local_home, 0);
		if (esp == NULL) {
			bulp = bulp->next;
			continue;
		}

		/* If infinity lifetime, don't decrement it. */
		if (bulp->lifetime == 0xffffffff) {
			bulp = bulp->next;
			continue;
		}

		bulp->lifetime -= 1;
		if (bulp->lifetime <= 0) {
			/* If the BUL entry is associated with a none
			   permanent ESM or not a home registration it
			   MUST be deleted. */
			if ((esp->type != PERMANENT) ||
			    !(bulp->flags & IP6_BUF_HOME)) {
				bulp = mip6_bul_delete(bulp);
				continue;
			}			

			/* This BUL entry is for a Home Agent. Create a new
			   BUL entry and remove the existing. */
			if ((esp->state == MIP6_STATE_REG) ||
			    (esp->state == MIP6_STATE_REREG) ||
			    (esp->state == MIP6_STATE_REGNEWCOA) ||
			    (esp->state == MIP6_STATE_NOTREG))
				esp->state = MIP6_STATE_NOTREG;
			else if ((esp->state == MIP6_STATE_HOME) ||
				 (esp->state == MIP6_STATE_DEREG))
				esp->state = MIP6_STATE_DEREG;
			else
				esp->state = MIP6_STATE_UNDEF;

			/* If Dynamic Home Agent Address Discovery,
			   pick the dst address from the esp->dad list
			   and set index. */
#if 0
			if (esp->hadiscov && esp->hadiscov->hal) {
				/* Set position to next entry to be used
				   in the list. */
				max_pos = esp->hadiscov->hal->off;
				if ((esp->hadiscov->hal->off / 16) == 1) 
					esp->hadiscov->pos = 0;
				else
					esp->hadiscov->pos += 16;

				pos += esp->hadiscov->pos;
				if (esp->hadiscov->hal->off == pos
				
				dst_addr = esp->hadiscov->hal->buf + pos
				dst_addr = &esp->dad->hal->
					halist[esp->dad->index];
				max_index = (esp->dad->hal->len /
					     IP6OPT_HALEN) - 1;
				if (esp->dad->index == max_index)
					esp->dad->index = 0;
				else
					esp->dad->index += 1;
				ltime = MIP6_BU_LIFETIME_DHAAD;
			} else
#endif
			{
				dst_addr = &esp->ha_hn;
				ltime = mip6_prefix_lifetime(&esp->home_addr,
							     esp->prefixlen);
			}

			/* Send BU to the decided destination */
			bu_flags = 0;
			bu_flags |= IP6_BUF_ACK;
			bu_flags |= IP6_BUF_HOME;
			bu_flags |= IP6_BUF_DAD;
			if (ip6_forwarding) bu_flags |= IP6_BUF_ROUTER;
			
			bu_opt = mip6_create_bu(esp->prefixlen, bu_flags,
						ltime);
			if (bu_opt == NULL) break;
			
			new_bulp = mip6_bul_create(dst_addr, &esp->home_addr,
						   &bulp->local_coa,
						   ltime, bu_flags);
			if (new_bulp == NULL) {
				free(bu_opt, M_TEMP);
				break;
			}

			if (mip6_send_bu(new_bulp, bu_opt, NULL)) break;
			
			bulp = mip6_bul_delete(bulp);
			continue;
		}

		if (bulp->refresh > 0)
			bulp->refresh -= 1;

		/* Skip the bul entry if its not allowed to send any further
		   BUs to the host. */
		if (bulp->send_flag == 0) {
			bulp = bulp->next;
			continue;
		}

		/* Check if a BU has already been sent to the destination. */
		if (bulp->flags & IP6_BUF_ACK) {
			if (mip6_bul_retransmit(bulp))
				break;
			else
				bulp = bulp->next;
			continue;
		}
		
		/* Refreshtime has expired and no BU has been sent to the HA
		   so far. Then we do it. */
		if (bulp->refresh <= 0) {
			if (mip6_bul_refresh(bulp, esp))
				break;
			else
				bulp = bulp->next;
			continue;
		}
		bulp = bulp->next;
	}

	/* Set the timer if there are more entries in the list */
	if (mip6_bulq != NULL) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_bul_ch, hz, mip6_timer_bul, NULL);
#else
		timeout(mip6_timer_bul, (void *)0, hz);
#endif
	}
	splx(s);
}



/*
 ******************************************************************************
 * Function:    mip6_bul_retransmit
 * Description: This function is called by mip6_timer_bul() function for
 *              retransmission of Binding Updates that have not been
 *              acknowledged yet
 * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_bul_retransmit(bulp)
struct mip6_bul  *bulp;
{
	/* Check if a BU has already been sent to the destination. */
	if (!(bulp->flags & IP6_BUF_ACK))
		return 0;
	
	bulp->bul_timeleft -= 1;
	if (bulp->bul_timeleft == 0) {
		if (bulp->flags & IP6_BUF_HOME) {
			/* This is a BUL entry for the HA */
			if (mip6_send_bu(bulp, NULL, NULL)) return -1;

			if (bulp->bul_timeout < MIP6_MAX_BINDACK_TIMEOUT)
				bulp->bul_timeout = 2 * bulp->bul_timeout;
			else
				bulp->bul_timeout = MIP6_MAX_BINDACK_TIMEOUT;

			bulp->bul_timeleft = bulp->bul_timeout;
		} else {
			/* This is a BUL entry for a Correspondent Node */
			if (bulp->bul_timeout >= MIP6_MAX_BINDACK_TIMEOUT) {
				/* Do NOT continue to retransmit the BU */
				mip6_bul_clear_state(bulp);
			} else {
				if (mip6_send_bu(bulp, NULL, NULL)) return -1;

				bulp->bul_timeout = 2 * bulp->bul_timeout;
				bulp->bul_timeleft = bulp->bul_timeout;
			}
		}
	}
	return 0;
}



/*
 ******************************************************************************
 * Function:    mip6_bul_refresh
 * Description: This function is called by mip6_timer_bul() function for
 *              refresh of an existing binding before it times out.
  * Ret value:    0  Everything is OK.
 *              -1  Error code used when something went wrong.
 ******************************************************************************
 */
int
mip6_bul_refresh(bulp, esp)
struct mip6_bul  *bulp;
struct mip6_esm  *esp;
{
	struct ip6_opt_binding_update *bu_opt;    /* BU option to be sent */
	struct mip6_subopt_altcoa      altcoa;
	struct mip6_buffer            *subbuf;
	u_int32_t                      lifetime;
	u_int8_t                       bu_flags;
	int                            size;
	
	if (bulp->refresh > 0) return 0;
	
	/* Store sub-option for BU option. */
	size = sizeof(struct mip6_buffer);
	subbuf = (struct mip6_buffer *)malloc(size, M_TEMP, M_NOWAIT);
	if (subbuf == NULL) return -1;
	bzero((caddr_t)subbuf, sizeof(struct mip6_buffer));

	altcoa.type = IP6SUBOPT_ALTCOA;
	altcoa.len = IP6OPT_COALEN;
	size = sizeof(struct in6_addr);
	bcopy((caddr_t)&bulp->local_coa, altcoa.coa, size);
	mip6_add_subopt2buf((u_int8_t *)&altcoa, subbuf);

	lifetime = mip6_prefix_lifetime(&esp->home_addr, esp->prefixlen);
	bu_flags = 0;
	
	if (bulp->flags & IP6_BUF_HOME) {
		/* Since this is an entry for the Home Agent a new BU
		   is being sent for which we require the receiver to
		   respond with a BA. */
		bu_flags |= IP6_BUF_ACK;
		bu_flags |= IP6_BUF_HOME;
		if (ip6_forwarding) bu_flags |= IP6_BUF_ROUTER;
	}

	bu_opt = mip6_create_bu(esp->prefixlen, bu_flags, lifetime);
	if (bu_opt == NULL) {
		free(subbuf, M_TEMP);
		return -1;
	}

	if (mip6_send_bu(bulp, bu_opt, subbuf)) {
		free(bu_opt, M_TEMP);
		free(subbuf, M_TEMP);
		return -1;
	}

	free(bu_opt, M_TEMP);
	free(subbuf, M_TEMP);
	return 0;
}	



/*
 ******************************************************************************
 * Function:    mip6_timer_esm
 * Description: This function is called when an event-state machine has been
 *              created for sending a BU to the previous default router. The
 *              event-state machine entry is needed for the correct addition
 *              of the home address option for outgoing packets.
 *              When the life time for the BU expires the event-state machine
 *              is removed as well.
 * Ret value:   -
 ******************************************************************************
 */
void
mip6_timer_esm(arg)
void  *arg;  /* Not used */
{
	struct mip6_esm  *esp;       /* Current event-state machine entry */
	int               s, start_timer;
	
	/* Go through the entire list of event-state machines. */
	s = splnet();
for (esp = mip6_esmq; esp;) {
if (esp->type == TEMPORARY) {
			esp->lifetime -= 1;
			
			if (esp->lifetime == 0)
				esp = mip6_esm_delete(esp);
            else
		    esp = esp->next;
			continue;
		}
		esp = esp->next;
	}
	
	/* Only start the timer if there is a TEMPORARY machine in the list. */
	start_timer = 0;
	for (esp = mip6_esmq; esp; esp = esp->next) {
		if (esp->type == TEMPORARY) {
			start_timer = 1;
			break;
		}
	}
	
	if (start_timer) {
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
		callout_reset(&mip6_timer_esm_ch, hz, mip6_timer_esm, NULL);
#else
		timeout(mip6_timer_esm, (void *)0, hz);
#endif
	}
	splx(s);
}



/*
 ##############################################################################
 #
 # IOCTL FUNCTIONS
 # These functions are called from mip6_ioctl.
 #
 ##############################################################################
 */

/*
 ******************************************************************************
 * Function:    mip6_write_config_data_mn
 * Description: This function is called to write certain config values for
 *              MIPv6. The data is written into the global config structure.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_write_config_data_mn(u_long cmd, void *arg)
{
	struct mip6_esm         *p;
	struct ifnet            *ifp;
	struct mip6_input_data  *input;
	struct mip6_static_addr *np;
	char                     ifn[10];
	int                      i, retval = 0;
	struct in6_addr          any = in6addr_any;
	struct in6_addr		 mask, pfx;

	switch (cmd) {
	case SIOCACOADDR_MIP6:
		input = (struct mip6_input_data *) arg;
		np = (struct mip6_static_addr *)
			malloc(sizeof(struct mip6_static_addr),
			       M_TEMP, M_WAITOK);
		if (np == NULL)
			return ENOBUFS;

		np->ip6_addr = input->ip6_addr;
		np->prefix_len = input->prefix_len;
		np->ifp = ifunit(input->if_name);
		if (np->ifp == NULL) {
			strncpy(ifn, input->if_name, sizeof(ifn));
			return EINVAL;
		}
		LIST_INSERT_HEAD(&mip6_config.fna_list, np, addr_entry);
		break;

	case SIOCAHOMEADDR_MIP6:
		input = (struct mip6_input_data *) arg;
		ifp = mip6_hifp;
#ifdef MIP6_DEBUG
		if (ifp != ifunit(input->if_name))
			mip6_debug("%s: warning - home addresses must be on "
				   "lo0. Using lo0, ignoring %s.\n",
				   __FUNCTION__, input->if_name);
#endif
		if (ifp == NULL)
			return EINVAL;

		in6_prefixlen2mask(&mask, input->prefix_len);
		/* make prefix in the canonical form */
		pfx = input->ip6_addr;
		for (i = 0; i < 4; i++)
			pfx.s6_addr32[i] &=
				mask.s6_addr32[i];

		/*
		 * Home address is given, home prefix is derived from that.
		 * Home agent's address can be given or be unspecified.
		 */
		p = mip6_esm_create(ifp, &input->ha_addr, &any,
				    &input->ip6_addr, &pfx,
				    input->prefix_len,
				    MIP6_STATE_UNDEF, PERMANENT, 0xFFFF);
		if (p == NULL)
			return EINVAL;	/*XXX*/

		/* Set interface ID */
		bzero(&p->ifid, sizeof(p->ifid));
		p->ifid.s6_addr32[0] |= (p->home_addr.s6_addr32[0] &
					   ~mask.s6_addr32[0]);
		p->ifid.s6_addr32[1] |= (p->home_addr.s6_addr32[1] &
					   ~mask.s6_addr32[1]);
		p->ifid.s6_addr32[2] |= (p->home_addr.s6_addr32[2] &
					   ~mask.s6_addr32[2]);
		p->ifid.s6_addr32[3] |= (p->home_addr.s6_addr32[3] &
					   ~mask.s6_addr32[3]);
#ifdef MIP6_DEBUG
		mip6_debug("%s: will use this ifid: %s\n",__FUNCTION__,
			   ip6_sprintf(&p->ifid));
#endif
		break;

	case SIOCAHOMEPREF_MIP6:
		input = (struct mip6_input_data *) arg;
		ifp = mip6_hifp;
		if (ifp == NULL)
			return EINVAL;

		in6_prefixlen2mask(&mask, input->prefix_len);
#define prefix input->ip6_addr
		/* make prefix in the canonical form */
		for (i = 0; i < 4; i++)
			prefix.s6_addr32[i] &=
				mask.s6_addr32[i];

		/*
		 * Note: input->ha_addr should be empty.
		 */
		p = mip6_esm_create(ifp, &input->ha_addr, &any, &any,
				    &prefix, input->prefix_len,
				    MIP6_STATE_UNDEF, PERMANENT, 0xFFFF);
		if (p == NULL)
			return EINVAL;	/*XXX*/

		break;

	case SIOCSBULIFETIME_MIP6:
		mip6_config.bu_lifetime = ((struct mip6_input_data *)arg)->value;
		break;

	case SIOCSHRLIFETIME_MIP6:
		mip6_config.hr_lifetime = ((struct mip6_input_data *)arg)->value;
		break;

	case SIOCDCOADDR_MIP6:
		input = (struct mip6_input_data *) arg;
		for (np = mip6_config.fna_list.lh_first; np != NULL;
		     np = np->addr_entry.le_next){
			if (IN6_ARE_ADDR_EQUAL(&input->ip6_addr, &np->ip6_addr))
				break;
		}
		if (np == NULL){
			retval = EADDRNOTAVAIL;
			return retval;
		}
		LIST_REMOVE(np, addr_entry);
		break;

	case SIOCSEAGERMD_MIP6:
		/* Note: value = 0, 1 or 2. */
		mip6_eager_md(((struct mip6_input_data *)arg)->value);
		break;
	}
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_clear_config_data_mn
 * Description: This function is called to clear internal lists handled by
 *              MIPv6.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_clear_config_data_mn(u_long cmd, caddr_t data)
{
	int retval = 0;
	int s;

	struct mip6_static_addr *np;
	struct mip6_bul         *bulp;

	s = splnet();
	switch (cmd) {
	case SIOCSFORADDRFLUSH_MIP6:
		for (np = LIST_FIRST(&mip6_config.fna_list); np;
		     np = LIST_NEXT(np, addr_entry)) {
			LIST_REMOVE(np, addr_entry);
		}
		break;

	case SIOCSHADDRFLUSH_MIP6:
		retval = EINVAL;
		break;

	case SIOCSBULISTFLUSH_MIP6:
		for (bulp = mip6_bulq; bulp;)
			bulp = mip6_bul_delete(bulp);
		break;
	}
	splx(s);
	return retval;
}



/*
 ******************************************************************************
 * Function:    mip6_enable_func_mn
 * Description: This function is called to enable or disable certain functions
 *              in mip6. The data is written into the global config struct.
 * Ret value:   -
 ******************************************************************************
 */
int mip6_enable_func_mn(u_long cmd, caddr_t data)
{
	int enable;
	int retval = 0;

	enable = ((struct mip6_input_data *)data)->value;

	switch (cmd) {
	case SIOCSPROMMODE_MIP6:
		mip6_config.enable_prom_mode = enable;
		break;

	case SIOCSBU2CN_MIP6:
		mip6_config.enable_bu_to_cn = enable;
		break;

	case SIOCSREVTUNNEL_MIP6:
		mip6_config.enable_rev_tunnel = enable;
		break;

	case SIOCSAUTOCONFIG_MIP6:
		mip6_config.autoconfig = enable;
		break;
	}
	return retval;
}



/*
 ##############################################################################
 #
 # XXXXXXXXXXX
 # These functions are functioning but some further is required.
 #
 ##############################################################################
 */
int
mip6_incl_br(struct mbuf *m)
{
	struct mbuf *n;

	if (MIP6_IS_MN_ACTIVE) {
		n = ip6_findaux(m);
		if (n && (mtod(n, struct ip6aux *)->ip6a_flags &
			  IP6A_BRUID) == IP6A_BRUID) return 1;
	}
	return 0;
}



void
mip6_send_rs(struct mip6_esm *esp,
	     int tunneled)
{
	struct ifnet *ifp;

/* 
   Called from:
     -  mip6_md_init_with_prefix()
     -	mip6_select_defrtr() ?
     -  mip6_timer_list() ?
     -  ...

   From an esp, there might be pending RSes to be sent, both local and
   tunneled.
   If timer says so, send RSes.
   Also check against overall policy of max transmission (static variable).
   
   Local RS:
   Create packet. Nothing special. Update timers.

   Tunneled RS:
   Create packet. Take information for addresses from esp. Update timers.
*/

/* 
 * TODO: Rate limit this.
 */

	if (!tunneled) {
		/*
		 * Find all useful outgoing interfaces.
		 */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ifp = ifnet; ifp; ifp = ifp->if_next)
#else
		for (ifp = TAILQ_FIRST(&ifnet); ifp; 
		     ifp = TAILQ_NEXT(ifp, if_list))
#endif
		{
			if (ifp->if_flags & IFF_LOOPBACK)
				continue;

			if ((ifp->if_flags & IFF_UP) == 0)
				continue;

#ifdef MIP6_DEBUG
			mip6_debug("%s: sending RS on %s\n", __FUNCTION__,
				   if_name(ifp));
#endif
			mip6_rs_output(ifp);
		}
	}
	else {
		/* Send tunneled RS */
	}
}



/*
 * Output a Router Solicitation Message. Caller specifies:
 *	- ifp for outgoing interface
 *
 * No rate limiting is done here.
 * Based on RFC 2461
 */
void
mip6_rs_output(ifp)
	struct ifnet *ifp;
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct nd_router_solicit *nd_rs;
	struct in6_ifaddr *ia6 = NULL; 
	struct ip6_moptions im6o;
	int icmp6len;
	int maxlen;
/*  	caddr_t mac; */
	struct ifnet *outif = NULL;
	int error;

/* TODO: add support for tunneled RSes. */

	if (ifp == NULL)
	       return;

	/* estimate the size of message */
	maxlen = sizeof(*ip6) + sizeof(*nd_rs);
	maxlen += (sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7;
	if (max_linkhdr + maxlen >= MCLBYTES) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: max_linkhdr + maxlen >= MCLBYTES "
			   "(%d + %d > %d)\n", __FUNCTION__, max_linkhdr,
			   maxlen, MCLBYTES);
#endif
		return;
	}

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: error - no mbuf\n", __FUNCTION__);
#endif
 		return;
	}
	m->m_pkthdr.rcvif = NULL;

	m->m_flags |= M_MCAST;
	im6o.im6o_multicast_ifp = ifp;
	im6o.im6o_multicast_hlim = 255;
	im6o.im6o_multicast_loop = 0;

	icmp6len = sizeof(*nd_rs);
	m->m_pkthdr.len = m->m_len = sizeof(*ip6) + icmp6len;
	m->m_data += max_linkhdr;	/*or MH_ALIGN() equivalent?*/

	/* fill router solicitation packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;

	ip6->ip6_dst = in6addr_linklocal_allrouters;
	ip6->ip6_dst.s6_addr16[1] = htons(ifp->if_index);

	ia6 = in6ifa_ifpforlinklocal(ifp, 0);

	if (ia6 == NULL) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: error - no ifa for source addr found.\n",
			   __FUNCTION__);
		return;
#endif
	}
	ip6->ip6_src = ia6->ia_addr.sin6_addr;

	nd_rs = (struct nd_router_solicit *)(ip6 + 1);
	nd_rs->nd_rs_type = ND_ROUTER_SOLICIT;
	nd_rs->nd_rs_code = 0;
	nd_rs->nd_rs_reserved = 0;

#if 0
/* Will we ever add source link-layer address option? /Mattias */
	/*
	 * Add source link-layer address option.
	 *
	 *				spec		implementation
	 *				---		---
	 * DAD packet			MUST NOT	do not add the option
	 * there's no link layer address:
	 *				impossible	do not add the option
	 * there's link layer address:
	 *	Multicast NS		MUST add one	add the option
	 *	Unicast NS		SHOULD add one	add the option
	 */
	if (!dad && (mac = nd6_ifptomac(ifp))) {
		int optlen = sizeof(struct nd_opt_hdr) + ifp->if_addrlen;
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
		/* 8 byte alignments... */
		optlen = (optlen + 7) & ~7;
		
		m->m_pkthdr.len += optlen;
		m->m_len += optlen;
		icmp6len += optlen;
		bzero((caddr_t)nd_opt, optlen);
		nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		nd_opt->nd_opt_len = optlen >> 3;
		bcopy(mac, (caddr_t)(nd_opt + 1), ifp->if_addrlen);
	}
#endif /* 0 */

	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_rs->nd_rs_cksum = 0;
	nd_rs->nd_rs_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), icmp6len);

#ifdef IPSEC
	/* Don't lookup socket */
	(void)ipsec_setsocket(m, NULL);
#endif
	error = ip6_output(m, NULL, NULL, 0, &im6o, &outif);

	if (error) {
#ifdef MIP6_DEBUG
		mip6_debug("%s: ip6_output failed (errno = %d)\n",
			   __FUNCTION__, error);
#endif
		return;
	}
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_routersolicit);
	}
	icmp6stat.icp6s_outhist[ND_ROUTER_SOLICIT]++;
}



/*
 * Output a tunneled Router Solicitation Message. Caller specifies:
 *	- Outer source IP address
 *	- Outer and inner (identical) destination IP address
 *
 * Used for a Mobile Node to send tunneled Router Solicitation according
 * to section 10.16 in draft-ietf-mobileip-ipv6-13.txt.
 *
 * Based on RFC 2461 and Mobile IPv6.
 */
int
mip6_tunneled_rs_output(src, dst)
	struct in6_addr *src, *dst;
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct nd_router_solicit *nd_rs;
/*  	struct in6_ifaddr *ia = NULL; */
/*  	struct ip6_moptions im6o; */
	int icmp6len;
	int maxlen;
/*  	caddr_t mac; */
/*  	struct ifnet *outif = NULL; */

/* TODO: add support for tunneled RSes. */
	
	/* estimate the size of message */
	maxlen = 2 * sizeof(*ip6) + sizeof(*nd_rs);
	maxlen += (sizeof(struct nd_opt_hdr) + 6 + 7) & ~7;
	if (max_linkhdr + maxlen >= MCLBYTES) {
#ifdef DIAGNOSTIC
		printf("%s: max_linkhdr + maxlen >= MCLBYTES "
		    "(%d + %d > %d)\n", __FUNCTION__,
		       max_linkhdr, maxlen, MCLBYTES);
#endif
		return ENOMEM;
	}

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return ENOBUFS;
	m->m_pkthdr.rcvif = NULL;

/*	m->m_flags |= M_MCAST;
	im6o.im6o_multicast_ifp = ifp;
	im6o.im6o_multicast_hlim = 255;
	im6o.im6o_multicast_loop = 0;
*/
	icmp6len = sizeof(*nd_rs);
	m->m_pkthdr.len = m->m_len = sizeof(*ip6) + icmp6len;
	m->m_data += max_linkhdr;	/*or MH_ALIGN() equivalent?*/

	/* fill router solicitation packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;

	ip6->ip6_dst = *dst;		/* Inner dst and src */
	ip6->ip6_src = in6addr_any;

	nd_rs = (struct nd_router_solicit *)(ip6 + 1);
	nd_rs->nd_rs_type = ND_ROUTER_SOLICIT;
	nd_rs->nd_rs_code = 0;
	nd_rs->nd_rs_reserved = 0;

#if 0
/* Will we ever add source link-layer address option? /Mattias */
	/*
	 * Add source link-layer address option.
	 *
	 *				spec		implementation
	 *				---		---
	 * DAD packet			MUST NOT	do not add the option
	 * there's no link layer address:
	 *				impossible	do not add the option
	 * there's link layer address:
	 *	Multicast NS		MUST add one	add the option
	 *	Unicast NS		SHOULD add one	add the option
	 */
	if (!dad && (mac = nd6_ifptomac(ifp))) {
		int optlen = sizeof(struct nd_opt_hdr) + ifp->if_addrlen;
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
		/* 8 byte alignments... */
		optlen = (optlen + 7) & ~7;
		
		m->m_pkthdr.len += optlen;
		m->m_len += optlen;
		icmp6len += optlen;
		bzero((caddr_t)nd_opt, optlen);
		nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		nd_opt->nd_opt_len = optlen >> 3;
		bcopy(mac, (caddr_t)(nd_opt + 1), ifp->if_addrlen);
	}
#endif /* 0 */

	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_rs->nd_rs_cksum = 0;
	nd_rs->nd_rs_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), icmp6len);

#ifdef IPSEC
	/* Don't lookup socket */
	(void)ipsec_setsocket(m, NULL);
#endif
/*	ip6_output(m, NULL, NULL, 0, &im6o, &outif);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_routersolicit);
	}
	icmp6stat.icp6s_outhist[ND_ROUTER_SOLICIT]++;
*/

/*	if (sin6_src == NULL || sin6_dst == NULL ||
	    sin6_src->sin6_family != AF_INET6 ||
	    sin6_dst->sin6_family != AF_INET6) {
		m_freem(m);
		return EAFNOSUPPORT;
	}
*/
/*		struct ip6_hdr *ip6;
		proto = IPPROTO_IPV6;
		if (m->m_len < sizeof(*ip6)) {
			m = m_pullup(m, sizeof(*ip6));
			if (!m)
				return ENOBUFS;
		}
		ip6 = mtod(m, struct ip6_hdr *);
		itos = (ntohl(ip6->ip6_flow) >> 20) & 0xff;
*/	

	/* prepend new IP header */
	M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
	if (m && m->m_len < sizeof(struct ip6_hdr))
		m = m_pullup(m, sizeof(struct ip6_hdr));
	if (m == NULL) {
		printf("ENOBUFS in %s %d\n", __FUNCTION__, __LINE__);
		return ENOBUFS;
	}

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;
	ip6->ip6_plen	= htons((u_short)m->m_pkthdr.len);
	ip6->ip6_nxt	= IPPROTO_IPV6;
	ip6->ip6_hlim	= ip6_gif_hlim;
	ip6->ip6_src	= *src;		/* Outer src and dst */
	ip6->ip6_dst	= *dst;
/*	if (ifp->if_flags & IFF_LINK0) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
			ip6->ip6_dst = sin6_dst->sin6_addr;
		else if (rt) {
			if (family != AF_INET6) {
				m_freem(m);
				return EINVAL;	
			}
			ip6->ip6_dst = ((struct sockaddr_in6 *)(rt->rt_gateway))->sin6_addr;
		} else {
			m_freem(m);
			return ENETUNREACH;
		}
	} else {
*/		/* bidirectional configured tunnel mode */
/*		if (!IN6_IS_ADDR_UNSPECIFIED(&sin6_dst->sin6_addr))
			ip6->ip6_dst = sin6_dst->sin6_addr;
		else  {
			m_freem(m);
			return ENETUNREACH;
		}
	}
*/
/*
	if (ifp->if_flags & IFF_LINK1)
		ip_ecn_ingress(ECN_ALLOWED, &otos, &itos);
	else
		ip_ecn_ingress(ECN_NOCARE, &otos, &itos);
	ip6->ip6_flow &= ~htonl(0x0ff00000);
	ip6->ip6_flow |= htonl((u_int32_t)otos << 20);
*/
/*	if (dst->sin6_family != sin6_dst->sin6_family ||
	     !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &sin6_dst->sin6_addr)) {
		bzero(dst, sizeof(*dst));
		dst->sin6_family = sin6_dst->sin6_family;
		dst->sin6_len = sizeof(struct sockaddr_in6);
		dst->sin6_addr = sin6_dst->sin6_addr;
		if (sc->gif_ro6.ro_rt) {
			RTFREE(sc->gif_ro6.ro_rt);
			sc->gif_ro6.ro_rt = NULL;
		}
#if 0
		sc->gif_if.if_mtu = GIF_MTU;
#endif
	}
*/
/*	if (sc->gif_ro6.ro_rt == NULL) {
		rtalloc((struct route *)&sc->gif_ro6);
		if (sc->gif_ro6.ro_rt == NULL) {
			m_freem(m);
			return ENETUNREACH;
		}
*/
		/* if it constitutes infinite encapsulation, punt. */
/*		if (sc->gif_ro.ro_rt->rt_ifp == ifp) {
			m_freem(m);
			return ENETUNREACH;
		}
#if 0
		ifp->if_mtu = sc->gif_ro6.ro_rt->rt_ifp->if_mtu
			- sizeof(struct ip6_hdr);
#endif
	}
*/	
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



#if 0 /* no more */
void
mip6_tunneled_ra_input()
{
/*
  Find esp.
  Stop peding outgoing tunneled RSes in the esp.

  See if we can reuse prelist_update().
  RtrAdvInt should be saved if included.
  Do we have a default router from this RA? Probably no.
*/
}
#endif


/*
 * Todo: This is a conceptual function. May be implemented elsewhere.
 */
void
mip6_dhaad_reply(void *arg)
{
	struct mip6_esm *esp;

	/* Todo: Find esp */
	esp = NULL;

	if (IN6_IS_ADDR_UNSPECIFIED(&esp->home_addr)) {
		mip6_send_rs(esp, 1);
	}
}
