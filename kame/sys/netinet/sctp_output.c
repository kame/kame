/*	$KAME: sctp_output.c,v 1.18 2003/02/07 09:34:37 jinmei Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_output.c, v 1.308 2002/04/04 18:47:03 randall Exp	*/

/*
 * Copyright (C) 2002 Cisco Systems Inc,
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

#ifndef __OpenBSD__
#include "opt_ipsec.h"
#endif
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_compat.h"
#include "opt_inet6.h"
#include "opt_inet.h"
#endif
#if defined(__NetBSD__)
#include "opt_inet.h"
#endif
#ifndef __OpenBSD__
#include "opt_sctp.h"
#endif
#include <sys/param.h>
#include <sys/systm.h>
#if defined (__OpenBSD__)
#include <netinet/sctp_callout.h>
#else
#include <sys/callout.h>
#endif
#include <sys/malloc.h>
#include <sys/mbuf.h>
#ifndef __OpenBSD__
#include <sys/domain.h>
#endif
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#ifdef INET6
#include <sys/domain.h>
#endif

#include <machine/limits.h>
#include <machine/cpu.h>

#if defined(__FreeBSD__)
#include <vm/vm_zone.h>
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/pool.h>
#endif


#include <net/if.h>
#include <net/if_types.h>

#if defined(__FreeBSD__)
#include <net/if_var.h>
#endif

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>


#if defined(__FreeBSD__) || (__NetBSD__)
#include <netinet6/in6_pcb.h>
#elif defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet/in_pcb.h>
#endif

#include <netinet/icmp6.h>

#endif /* INET6 */
#include <net/net_osdep.h>

#if defined(HAVE_NRL_INPCB) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#ifndef in6pcb
#define in6pcb		inpcb
#endif
#endif

#include "faith.h"

#include <netinet/sctp_pcb.h>

#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif
#endif /* IPSEC */

#include <netinet/sctp_header.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_hashdriver.h>
#include <netinet/sctp_timer.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_indata.h>

#ifdef SCTP_DEBUG
extern u_int32_t sctp_debug_on;
#endif

static int
sctp_find_cmsg(int c_type,
	       void *data,
	       struct mbuf *control,
	       int cpsize)
{
	struct cmsghdr cmh;
	int tlen, at;
	tlen = control->m_len;
	at = 0;
	/*
	 * Independent of how many mbufs, find the c_type inside the control
	 * structure and copy out the data.
	 */
	while (at < tlen) {
		if ((tlen-at) < CMSG_ALIGN(sizeof(cmh))) {
			/* not enough room for one more we are done. */
			return (0);
		}
		m_copydata(control, at, sizeof(cmh), (caddr_t)&cmh);
		if ((cmh.cmsg_len + at) > tlen) {
			/*
			 * this is real messed up since there is not enough
			 * data here to cover the cmsg header. We are done.
			 */
			return (0);
		}
		if ((cmh.cmsg_level == IPPROTO_SCTP) &&
		    (c_type == cmh.cmsg_type)) {
			/* found the one we want, copy it out */
			at += CMSG_ALIGN(sizeof(struct cmsghdr));
			if ((cmh.cmsg_len -
			     CMSG_ALIGN(sizeof(struct cmsghdr))) < cpsize) {
				/*
				 * space of cmsg_len after header not
				 * big enough
				 */
				return (0);
			}
			m_copydata(control, at, cpsize, data);
			return (1);
		 } else {
			at += CMSG_ALIGN(cmh.cmsg_len);
			if (cmh.cmsg_len == 0) {
				break;
			}
		}
	}
	/* not found */
	return (0);
}

static struct mbuf *
sctp_add_addr_to_mbuf(struct mbuf *m,
		      struct ifaddr *ifa)
{
	struct sctp_paramhdr *parmh;
	struct mbuf *mret;
	int len;
	if (ifa->ifa_addr->sa_family == AF_INET) {
		len = sizeof(struct sctp_ipv4addr_param);
	} else if (ifa->ifa_addr->sa_family == AF_INET6) {
		len = sizeof(struct sctp_ipv6addr_param);
	} else
		/* unknown type */
		return (m);

	if (M_TRAILINGSPACE(m) >= len) {
		/* easy side we just drop it on the end */
		parmh = (struct sctp_paramhdr *)(m->m_data + m->m_len);
		mret = m;
	} else {
		/* Need more space */
		mret = m;
		while (mret->m_next != NULL) {
			mret = mret->m_next;
		}
		MGET(mret->m_next, M_DONTWAIT, MT_DATA);
		if (mret->m_next == NULL) {
			/* We are hosed, can't add more addresses */
			return (m);
		}
		mret = mret->m_next;
		parmh = mtod(mret, struct sctp_paramhdr *);
	}
	/* now add the parameter */
	if (ifa->ifa_addr->sa_family == AF_INET) {
		struct sctp_ipv4addr_param *ipv4p;
		struct sockaddr_in *sin;
		sin = (struct sockaddr_in *)ifa->ifa_addr;
		ipv4p = (struct sctp_ipv4addr_param *)parmh;
		parmh->param_type = htons(SCTP_IPV4_ADDRESS);
		parmh->param_length = htons(len);
		ipv4p->addr = sin->sin_addr.s_addr;
		mret->m_len += len;
	} else {
		struct sctp_ipv6addr_param *ipv6p;
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		ipv6p = (struct sctp_ipv6addr_param *)parmh;
		parmh->param_type = htons(SCTP_IPV6_ADDRESS);
		parmh->param_length = htons(len);
		memcpy(ipv6p->addr, sin6->sin6_addr.s6_addr8,
		       sizeof(ipv6p->addr));
		/* clear embedded scope in the address */
		in6_clearscope((struct in6_addr *)ipv6p->addr);
		mret->m_len += len;
	}
	return (mret);
}

static struct mbuf *
sctp_add_cookie(struct sctp_inpcb *inp,
		struct mbuf *init,
		int iphlen,
		struct mbuf *init_ack,
		struct sctp_state_cookie *stc_in,
		int init_sz)
{
	struct mbuf *copy_init, *copy_initack, *m_at, *sig, *mret;
	struct sctp_state_cookie *stc;
	struct sctp_paramhdr *ph;
	u_int8_t *signature;
	int reuse_mbuf;
	u_short siz_of;
	mret = NULL;

	MGET(mret, M_DONTWAIT, MT_DATA);
	if (mret == NULL) {
		return (NULL);
	}
	copy_init = m_copym(init, (iphlen+sizeof(struct sctphdr)), init_sz,
			    M_DONTWAIT);
	if (copy_init == NULL) {
		m_freem(mret);
		return (NULL);
	}

	copy_initack = m_copym(init_ack, sizeof(struct sctphdr), M_COPYALL,
			       M_DONTWAIT);
	if (copy_initack == NULL) {
		m_freem(mret);
		m_freem(copy_init);
		return (NULL);
	}
	m_at = copy_initack;
	while (m_at->m_next != NULL) {
		m_at = m_at->m_next;
	}
	if (M_TRAILINGSPACE(m_at) >= SCTP_SIGNATURE_SIZE) {
		sig = m_at;
		reuse_mbuf = 1;
	} else {
		MGET(sig, M_DONTWAIT, MT_DATA);
		if (sig == NULL) {
			/* no space */
			m_freem(mret);
			m_freem(copy_init);
			m_freem(copy_initack);
			return (NULL);
		}
		reuse_mbuf = 0;
	}

	/* easy side we just drop it on the end */
	ph = mtod(mret, struct sctp_paramhdr *);
	mret->m_len = sizeof(struct sctp_state_cookie) +
		sizeof(struct sctp_paramhdr);
	stc = (struct sctp_state_cookie *)((caddr_t)ph +
					   sizeof(struct sctp_paramhdr));
	ph->param_type = htons(SCTP_STATE_COOKIE);
	ph->param_length = 0;	/* fill in at the end */
	/* tack the INIT and then the INIT-ACK onto the chain */
	if (mret->m_next == NULL) {
		/* easy way */
		mret->m_next = copy_init;
	} else {
		/* hard way should be rate */
		for (m_at = mret; m_at; m_at = m_at->m_next) {
			if (m_at->m_next == NULL) {
				mret->m_next = copy_init;
				break;
			}
		}
	}
	/* Now on to the end of the copy_init */
	for (m_at = copy_init; m_at; m_at = m_at->m_next) {
		if (m_at->m_next == NULL) {
			/* found it */
			m_at->m_next = copy_initack;
			break;
		}
	}
	/* Fill in the stc cookie data */
	*stc = *stc_in;
	if (reuse_mbuf) {
		signature = (u_int8_t *)(mtod(sig, caddr_t) + sig->m_len);
	} else {
		signature = mtod(sig, u_int8_t *);
		sig->m_len = SCTP_SIGNATURE_SIZE;
	}
	/* Time to sign the cookie */
	sctp_hash_digest_m((char *)inp->sctp_ep.secret_key[(int)(inp->sctp_ep.current_secret_number)],
			   SCTP_SECRET_SIZE,
			   mret, sizeof(struct sctp_paramhdr),
			   (unsigned char *)signature);
	if (reuse_mbuf) {
		sig->m_len += SCTP_SIGNATURE_SIZE;
	} else {
		/* add signature mbuf to end */
		for (m_at = copy_initack; m_at; m_at = m_at->m_next) {
			if (m_at->m_next == NULL) {
				/* found it */
				m_at->m_next = sig;
				break;
			}
		}
	}
	siz_of = 0;
	m_at = mret;
	while (m_at != NULL) {
		siz_of += m_at->m_len;
		m_at = m_at->m_next;
	}
	ph->param_length = htons(siz_of);
	return (mret);
}

int
sctp_is_addr_restricted(register struct sctp_tcb *tcb,
			struct sockaddr *addr)
{
	/*
	 * This treats the address list on the ep as a restricted list
	 * (negative list). If a the passed address is listed, then
	 * the address is NOT allowed on the association.
	 */
	struct sctp_laddr *laddr;

	if (tcb == NULL)
		/* There are no restrictions, no TCB :-) */
		return (0);

	LIST_FOREACH(laddr, &tcb->asoc.sctp_local_addr_list, sctp_nxt_addr) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Help I have fallen and I can't get up!\n");
			}
#endif
			continue;
		}
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		if (laddr->ifa->ifa_addr->sa_family != addr->sa_family) {
			continue;
		}
		if (memcmp(addr->sa_data,
			   laddr->ifa->ifa_addr->sa_data,
			   addr->sa_len) == 0) {
			/* Yes it is restricted */
			return (1);
		}
	}
	return (0);
}

static int
sctp_is_addr_in_ep(register struct sctp_inpcb *inp,
		   struct sockaddr *addr)
{
	struct sctp_laddr *laddr;
	LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Help I have fallen and I can't get up!\n");
			}
#endif
			continue;
		}
		if (laddr->ifa->ifa_addr == NULL)
			continue;
		if (laddr->ifa->ifa_addr->sa_family != addr->sa_family) {
			/* skip non compatible address comparison */
			continue;
		}
		if (memcmp(addr->sa_data,
			   laddr->ifa->ifa_addr->sa_data,
			   addr->sa_len) == 0) {
			/* Yes it is restricted */
			return (1);
		}
	}
	return (0);
}

struct in_addr
sctp_ipv4_source_address_selection(register struct sctp_inpcb *inp,
				   register struct sctp_tcb *tcb,
				   struct sockaddr_in *to,
				   struct route *rtp,
				   struct sctp_nets *net,
				   int non_asoc_addr_ok)
     /* tcb may be NULL */
{
	struct in_addr ans;
	struct rtentry *rt;
	struct sctp_laddr *laddr;
	struct sockaddr_in *out;
	u_int8_t ipv4_scope, loopscope;
	/*
	 * Rules:
	 * - Find the route if needed, cache if I can.
	 * - Look at interface address in route, Is it
	 *   in the bound list. If so we have the best source.
	 * - If not we must rotate amongst the addresses.
	 */

	/*
	 * Find the route, if possible we end up caching it via the way
	 * the caller sends it to us.
	 */
	if (rtp->ro_rt == NULL) {
		/*
		 * first look at the next one and see if it has a ro_rt
		 * structure.
		 */
		if (net) {
			/*
			 * There is a NET structure that may have next/prev
			 * entries that may have a route already.  If so we
			 * want to find a DIFFERENT route/interface if
			 * possible. Now we prioritize the NEXT first since
			 * net's are added to the head of the list so it is
			 * more likely a next entry will have a route.
			 */
			struct sctp_nets *f_net;
			struct rtentry *t_rt;
			f_net = TAILQ_NEXT(net, sctp_next);
			t_rt = NULL;
			while (f_net) {
				if (((struct sockaddr *)(&f_net->ra._l_addr))->sa_family != AF_INET) {
					f_net = TAILQ_NEXT(f_net, sctp_next);
					continue;
				}
				if (f_net->ra.ro_rt) {
					t_rt = f_net->ra.ro_rt;
					break;
				}
				f_net = TAILQ_NEXT(f_net, sctp_next);
			}
			if (t_rt == NULL) {
				/* Forward search failed. */
				f_net = TAILQ_PREV(net, sctpnetlisthead,
						   sctp_next);
				while (f_net) {
					if (((struct sockaddr *)(&f_net->ra._l_addr))->sa_family != AF_INET) {
						f_net = TAILQ_PREV(f_net, sctpnetlisthead, sctp_next);
						continue;
					}
					if (f_net->ra.ro_rt) {
						t_rt = f_net->ra.ro_rt;
						break;
					}
					f_net = TAILQ_PREV(f_net, sctpnetlisthead, sctp_next);
				}
			}
			/* Now get the route for this guy */
#ifdef SCTP_ALTERNATE_ROUTE
			rtp->ro_rt = rtalloc_alternate(&rtp->ro_dst, NULL, 0);
			/* is it the same as my kin network dest */
			if (rtp->ro_rt && (rtp->ro_rt == t_rt)) {
				/* Yep so we need to free this and try
				 * for a more diverse route.
				 */
				RTFREE(rtp->ro_rt);
				rtp->ro_rt = rtalloc_alternate(&rtp->ro_dst, t_rt, 0);
			}
#else
#ifdef __FreeBSD__
			rtp->ro_rt = rtalloc1(&rtp->ro_dst, 1, 0UL);
#else
			rtp->ro_rt = rtalloc1(&rtp->ro_dst, 1);
#endif
#endif
		} else {
			rtp->ro_rt = rtalloc_alternate(&rtp->ro_dst, NULL, 0);
		}
	}
	rt = rtp->ro_rt;
	if (rt == NULL) {
		/* No route to host .. punt */
		memset(&ans, 0, sizeof(ans));
		return (ans);
	}
	/* Setup our scopes */
	if (tcb) {
		ipv4_scope = tcb->asoc.ipv4_local_scope;
		loopscope = tcb->asoc.loopback_scope;
	} else {
		/* Scope based on outbound address */
		if ((IN4_ISPRIVATE_ADDRESS(&to->sin_addr))) {
			ipv4_scope = 1;
			loopscope = 0;
		} else if (IN4_ISLOOPBACK_ADDRESS(&to->sin_addr)) {
			ipv4_scope = 1;
			loopscope = 1;
		} else {
			ipv4_scope = 0;
			loopscope = 0;
		}
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
		printf("Scope setup loop:%d ipv4_scope:%d\n",
		       loopscope, ipv4_scope);
	}
#endif
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* When bound to all if the address list is set
		 * it is a negative list.
		 */
		struct ifnet *ifn;
		struct ifaddr *ifa;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("we are bound all - check restricted\n");
		}
#endif
		if (!sctp_is_addr_restricted(tcb, rt->rt_ifa->ifa_addr)) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Not on restricted, out goes intf addr %x\n",
				       (u_int)((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr.s_addr);
			}
#endif
			return (((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr);
		}
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("Ok, we will see what we come up with in rr\n");
		}
#endif
		/* If cant_use got set we head for source address selection
		 * via round robin. However we don't have a list as
		 * in our specific binding case. So we just need to
		 * rotate amongst the interfaces, choosing an address
		 * from them.
		 */
		if (inp->next_ifn_touse == NULL) {
			inp->next_ifn_touse = TAILQ_FIRST(&ifnet);
		}
		/* Hunt for an address amongst the interfaces not on the
		 * negative list and rotate amongst them.
		 */
		for (ifn = inp->next_ifn_touse; ifn; ifn = TAILQ_NEXT(ifn, if_list)) {
			if ((loopscope == 0) && (ifn->if_type == IFT_LOOP)) {
				/* wrong base scope */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if (ifa->ifa_addr->sa_family == AF_INET) {
					struct sockaddr_in *ifa_a;
					ifa_a = (struct sockaddr_in *)(ifa->ifa_addr);
					if ((ipv4_scope == 0) &&
					    (IN4_ISPRIVATE_ADDRESS(&ifa_a->sin_addr))) {
						/* wrong scope */
						continue;
					}
					/* make sure it's not restricted */
					if (sctp_is_addr_restricted(tcb, ifa->ifa_addr))
						continue;
					/* we can use it !! */
					/* set to start with next intf */
					inp->next_ifn_touse = TAILQ_NEXT(ifn, if_list);
					return (ifa_a->sin_addr);
				}
			}
		}
		/* Ok nothing turned up in the next_ifn_touse to the next
		 * lets check the beginning up to next_ifn_touse.
		 */
		for (ifn = TAILQ_FIRST(&ifnet);
		     (ifn && (ifn != inp->next_ifn_touse));
		     ifn=TAILQ_NEXT(ifn, if_list)) {
			if ((loopscope == 0) &&
			    (ifn->if_type == IFT_LOOP)) {
				/* wrong base scope */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if (ifa->ifa_addr->sa_family == AF_INET) {
					struct sockaddr_in *ifa_a;
					ifa_a = (struct sockaddr_in *)(ifa->ifa_addr);
					if ((ipv4_scope == 0) &&
					    (IN4_ISPRIVATE_ADDRESS(&ifa_a->sin_addr))) {
						/* wrong scope */
						continue;
					}
					/* make sure it is not restricted */
					if (sctp_is_addr_restricted(tcb, ifa->ifa_addr))
						continue;
					/* we can use it !! */
					/* set to start with next intf */
					inp->next_ifn_touse = TAILQ_NEXT(ifn, if_list);
					return (ifa_a->sin_addr);
				}
			}
		}
		/*
		 * Ok we can find NO address to source from that is
		 * not on our negative list. It is either the special
		 * ASCONF case where we are sourceing from a intf that
		 * has been ifconfig'd to a different address (i.e.
		 * it holds a ADD/DEL/SET-PRIM and the proper lookup
		 * address. OR we are hosed, and this baby is going
		 * to abort the association.
		 */
		if (non_asoc_addr_ok) {
			return (((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr);
		} else {
			memset(&ans, 0, sizeof(ans));
			return (ans);
		}
	}

	/*
	 * This is the sub-set bound case. One of two possiblities.
	 * if flag on pcb says NO asconf then the list in the asoc (if
	 * present) is the only addresses that can be sources. Otherwise
	 * the list (if present) is a negative address list, i.e.
	 * addresses can be any one on the inp structure EXCEPT the one
	 * listed in the TCB. If no TCB exists then we just get what is
	 * in the pcb list (i.e. we are sending an INIT-ACK).
	 */
	if (tcb) {
		if (inp->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) {
			/* The list on the tcb is a negative list */
			if ((!sctp_is_addr_restricted(tcb, rt->rt_ifa->ifa_addr)) &&
			    (sctp_is_addr_in_ep(inp, rt->rt_ifa->ifa_addr))) {
				/*
				 * We can use it since it is not on the
				 * negative list and it is on the positive
				 * list.
				 */
				return (((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr);
			}
			/*
			 * Src address selection is in order, here we use the
			 * EP list and don't use any in the negative list on
			 * the tcb.
			 */
			if (tcb->asoc.last_used_address == NULL) {
				tcb->asoc.last_used_address = LIST_FIRST(&inp->sctp_addr_list);
			}
			/* start with the next address to use */
			for (laddr = tcb->asoc.last_used_address; laddr;
			     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;

				if (laddr->ifa->ifa_addr->sa_family != AF_INET)
					/* wrong type */
					continue;
				out = (struct sockaddr_in *)laddr->ifa->ifa_addr;
				if ((ipv4_scope == 0) &&
				    (IN4_ISPRIVATE_ADDRESS(&out->sin_addr))) {
					/* wrong scope */
					continue;
				}
				if ((loopscope == 0) &&
				    (IN4_ISLOOPBACK_ADDRESS(&out->sin_addr))) {
					/* wrong scope */
					continue;
				}
				if (sctp_is_addr_restricted(tcb, laddr->ifa->ifa_addr)) {
					/* on the no-no list */
					continue;
				}
				tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
				return (out->sin_addr);
			}
			/* didn't find one, so start from the top */
			for (laddr = LIST_FIRST(&inp->sctp_addr_list);
			     (laddr && (laddr != tcb->asoc.last_used_address));
			     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;
				if (laddr->ifa->ifa_addr->sa_family != AF_INET)
					/* wrong type */
					continue;
				out = (struct sockaddr_in *)laddr->ifa->ifa_addr;
				if ((ipv4_scope == 0) &&
				    (IN4_ISPRIVATE_ADDRESS(&out->sin_addr))) {
					/* wrong scope */
					continue;
				}
				if ((loopscope == 0) &&
				    (IN4_ISLOOPBACK_ADDRESS(&out->sin_addr))) {
					/* wrong scope */
					continue;
				}
				if (sctp_is_addr_restricted(tcb, laddr->ifa->ifa_addr)) {
					/* on the no-no list */
					continue;
				}
				tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
				return (out->sin_addr);
			}
			/*
			 * didn't find an appropriate source address!
			 * return a NULL address, and a NULL route
			 */
			if (rtp->ro_rt) {
				RTFREE(rtp->ro_rt);
				rtp->ro_rt = NULL;
			}
			if (!non_asoc_addr_ok) {
				memset(&ans, 0, sizeof(ans));
				return (ans);
			} else {
				/*
				 * Ok if we reach here we are back in same
				 * condition in BOUND all.. maybe the special
				 * case of ASCONF.
				 * So we just need to return any asoc address
				 * and hope things work.
				 */
				LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
					if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
						if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
							printf("Help I have fallen and I can't get up!\n");
						}
#endif
						continue;
					}
					if (laddr->ifa->ifa_addr == NULL)
						continue;

					if (laddr->ifa->ifa_addr->sa_family != AF_INET)
						/* wrong type */
						continue;
					out = (struct sockaddr_in *)laddr->ifa->ifa_addr;
					if ((ipv4_scope == 0) &&
					    (IN4_ISPRIVATE_ADDRESS(&out->sin_addr))) {
						/* wrong scope */
						continue;
					}
					if ((loopscope == 0) &&
					    (IN4_ISLOOPBACK_ADDRESS(&out->sin_addr))) {
						/* wrong scope */
						continue;
					}
					/* Ok here it is */
					tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
					return (out->sin_addr);
				}
				/* no address in scope.. egad.. I guess you
				 * will get the interface and we will abort.
				 */
			}
		} else {
			/* This list on the tcb is a positive list. */
			if (sctp_is_addr_restricted(tcb, rt->rt_ifa->ifa_addr)) {
				/* usable since it IS on the negative list */
				return (((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr);
			}
			/* src address selection is in order, here
			 * we use the TCB list and rotate amongst them.
			 */
			if (tcb->asoc.last_used_address == NULL) {
				tcb->asoc.last_used_address = LIST_FIRST(&tcb->asoc.sctp_local_addr_list);
			}
			for (laddr = tcb->asoc.last_used_address; laddr;
			     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {

				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;

				if (laddr->ifa->ifa_addr->sa_family != AF_INET)
					continue;
				out = (struct sockaddr_in *)laddr->ifa->ifa_addr;
				if ((ipv4_scope == 0) &&
				    (IN4_ISPRIVATE_ADDRESS(&out->sin_addr))) {
					/* wrong scope */
					continue;
				}
				if ((loopscope == 0) &&
				    (IN4_ISLOOPBACK_ADDRESS(&out->sin_addr))) {
					/* wrong scope */
					continue;
				}
				/* Ok here it is */
				tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
				return (out->sin_addr);
			}
			/* Ok, nothing to give out in the right scope? Punt! */
		}
		/*
		 * The Punt action here is you get the intf we put the packet
		 * out anyway, even though you will probably get an ABORT. And
		 * you may not even recognize it :> sigh..
		 */
		if (non_asoc_addr_ok) {
			return (((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr);
		} else {
			memset(&ans, 0, sizeof(ans));
			return (ans);
		}
	}
	/* Only list we have to go on is in the EP, must be
	 * an INIT going out since no TCB is formed.
	 */
	if (sctp_is_addr_in_ep(inp, rt->rt_ifa->ifa_addr)) {
		/* We are good, the interface address IS bound to this ep */
		return (((struct sockaddr_in *)
			(rt->rt_ifa->ifa_addr))->sin_addr);
	}
	/* Ok, not lucky, instead lets do src addr selection */
	if (inp->next_addr_touse == NULL)
		inp->next_addr_touse = LIST_FIRST(&inp->sctp_addr_list);

	for (laddr = inp->next_addr_touse; laddr;
	     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Help I have fallen and I can't get up!\n");
			}
#endif
			continue;
		}
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		if (laddr->ifa->ifa_addr->sa_family != AF_INET) {
			/* skip non IPv4 addresses */
			continue;
		}
		out = (struct sockaddr_in *)laddr->ifa->ifa_addr;
		if ((ipv4_scope == 0) &&
		    (IN4_ISPRIVATE_ADDRESS(&out->sin_addr))) {
			/* wrong scope */
			continue;
		}
		if ((loopscope == 0) &&
		    (IN4_ISLOOPBACK_ADDRESS(&out->sin_addr))) {
			/* wrong scope */
			continue;
		}
		inp->next_addr_touse = LIST_NEXT(laddr, sctp_nxt_addr);
		return (out->sin_addr);
	}
	/* ok check the front end */
	for (laddr = LIST_FIRST(&inp->sctp_addr_list);
	     (laddr && (laddr != inp->next_addr_touse));
	     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Help I have fallen and I can't get up!\n");
			}
#endif
			continue;
		}
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		if (laddr->ifa->ifa_addr->sa_family != AF_INET) {
			/* skip non IPv4 addresses */
			continue;
		}
		out = (struct sockaddr_in *)laddr->ifa->ifa_addr;
		if ((ipv4_scope == 0) &&
		    (IN4_ISPRIVATE_ADDRESS(&out->sin_addr))) {
			/* wrong scope */
			continue;
		}
		if ((loopscope == 0) &&
		    (IN4_ISLOOPBACK_ADDRESS(&out->sin_addr))) {
			/* wrong scope */
			continue;
		}
		inp->next_addr_touse = LIST_NEXT(laddr, sctp_nxt_addr);
		return (out->sin_addr);
	}
	/*
	 * Ok we must be in a bad situation where no address know matches
	 * our ep. We will fire off using the ifn address and let the ABORTs
	 * land where they may :>
	 */
	if (non_asoc_addr_ok) {
		return (((struct sockaddr_in *)(rt->rt_ifa->ifa_addr))->sin_addr);
	} else {
		memset(&ans, 0, sizeof(ans));
		return (ans);
	}
}

static struct sockaddr_in6 *
sctp_choose_correctv6_scope(struct rtentry *rt,
			    int site_scope, int loc_scope,
			    struct sctp_tcb *tcb,
			    struct sctp_inpcb *inp,
			    int is_negative_list, int *are_done)
{
	struct ifnet *ifn;
	struct sockaddr_in6 *sin6;
	struct ifaddr *ifa;
	struct in6_ifaddr *ifa6;
	int ok;
	sin6 = (struct sockaddr_in6 *)rt->rt_ifa->ifa_addr;
	ok = 1;
	if (sin6->sin6_family == AF_INET6) {
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) && !loc_scope) {
			/* Its linklocal and we don't have link local scope */
			ok = 0;
		}
		if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) && !site_scope) {
			/* Its sitelocal and we don't have site local scope */
			ok = 0;
		}
		ifa6 = (struct in6_ifaddr *)rt->rt_ifa;
		/* ok to use deprecated addresses? */
		if (!ip6_use_deprecated) {
			if (ifa6->ia6_flags & IN6_IFF_DEPRECATED) {
				/* can't use this type */
				ok = 0;
			}
		}
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
				       IN6_IFF_NOTREADY |
				       IN6_IFF_ANYCAST)) {
			/* Can't use these types */
			ok = 0;
		}
		if (ok) {
			return (sin6);
		}
	}
	/* Must find a better scope */
	ifn = rt->rt_ifp;
	if (ifn == NULL) {
		return (sin6);
	}
	TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		ifa6 = (struct in6_ifaddr *)ifa;
		/* ok to use deprecated addresses? */
		if (!ip6_use_deprecated) {
			if (ifa6->ia6_flags & IN6_IFF_DEPRECATED) {
				/* can't use this type */
				continue;
			}
		}
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
				       IN6_IFF_NOTREADY |
				       IN6_IFF_ANYCAST)) {
			/* Can't use these types */
			continue;
		}
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		/* Is address ok to consider */
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) && !loc_scope) {
			continue;
		}
		if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) && !site_scope) {
			continue;
		}
		/* Ok, now are we done? */
		if (is_negative_list) {
			/* TCB must be set */
			if (sctp_is_addr_restricted(tcb, ifa->ifa_addr))
				continue;
			if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL)
				*are_done = 1;
			return (sin6);
			if (sctp_is_addr_in_ep(inp, ifa->ifa_addr)) {
				*are_done = 1;
				return (sin6);
			}
		} else if (tcb) {
			/* postive list on the tcb only */
			if (sctp_is_addr_restricted(tcb, ifa->ifa_addr))
				*are_done = 1;
			return (sin6);
		} else {
			/* Use inp list and its positive */
			if (sctp_is_addr_in_ep(inp, ifa->ifa_addr)) {
				*are_done = 1;
				return (sin6);
			}
		}
	}
	/* Ok, if we fell out here, we will be hunting for
	 * an alternative in the src addr selection. We
	 * send back a default, i.e. one that is the right
	 * scope.
	 */
	TAILQ_FOREACH(ifa,&ifn->if_addrlist, ifa_list) {
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		ifa6 = (struct in6_ifaddr *)ifa;
		/* ok to use deprecated addresses? */
		if (!ip6_use_deprecated) {
			if (ifa6->ia6_flags & IN6_IFF_DEPRECATED) {
				/* can't use this type */
				continue;
			}
		}
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
				       IN6_IFF_NOTREADY |
				       IN6_IFF_ANYCAST)) {
			/* Can't use these types */
			continue;
		}
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		/* Is address ok to consider */
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) && !loc_scope) {
			continue;
		}
		if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) && !site_scope) {
			continue;
		}
		return (sin6);
	}
	sin6 = (struct sockaddr_in6 *)rt->rt_ifa->ifa_addr;

	return (sin6);
}

struct in6_addr
sctp_ipv6_source_address_selection(register struct sctp_inpcb *inp,
				   register struct sctp_tcb *tcb,
				   struct sockaddr_in6 *to,
				   struct route *rtp,
				   struct sctp_nets *net,
				   int non_asoc_addr_ok)
/* tcb may be NULL */
{
	/*
	 * This is quite tricky. We can't use the normal
	 * in6_selectsrc() function since this really does
	 * not do what we want.
	 */
	struct in6_addr ans;
	struct rtentry *rt;
	struct sctp_laddr *laddr;
	struct sockaddr_in6 *out6, *rt_addr;
	struct ifnet *ifn;
	struct ifaddr *ifa;
	struct in6_ifaddr *ifa6;
	u_int8_t loc_scope, site_scope, loopscope;
	int list_type, are_done;
	/*
	 * Rules:
	 * - Find the route if needed, cache if I can.
	 * - Look at interface address in route, Is it
	 *   in the bound list. If so we have the best source.
	 * - If not we must rotate amongst the addresses.
	 */

	/* Find the route */
	if (rtp->ro_rt == NULL) {
		/*
		 * Not sure if I should clone a new route or not.
		 * For now we won't.
		 */
		if (net) {
			/*
			 * There is a NET structure that may have next/prev
			 * entry's that may have a route already.
			 * If so we want to find a DIFFERENT route/interface
			 * if possible. Now we prioritize the NEXT first since
			 * net's are added to the head of the list so it is
			 * more likely a next entry will have a route.
			 */
			struct sctp_nets *f_net;
			struct rtentry *t_rt;
			f_net = TAILQ_NEXT(net, sctp_next);
			t_rt = NULL;
			while (f_net) {
				if (((struct sockaddr *)(&f_net->ra._l_addr))->sa_family != AF_INET6) {
					f_net = TAILQ_NEXT(f_net, sctp_next);
					continue;
				}
				if (f_net->ra.ro_rt) {
					t_rt = f_net->ra.ro_rt;
					break;
				}
				f_net = TAILQ_NEXT(f_net, sctp_next);

			}
			if (t_rt == NULL) {
				/* Forward search failed */
				f_net = TAILQ_PREV(net, sctpnetlisthead, sctp_next);
				while (f_net) {
					if (((struct sockaddr *)(&f_net->ra._l_addr))->sa_family != AF_INET6) {
						f_net = TAILQ_PREV(f_net, sctpnetlisthead, sctp_next);
						continue;
					}
					if (f_net->ra.ro_rt) {
						t_rt = f_net->ra.ro_rt;
						break;
					}
					f_net = TAILQ_PREV(f_net, sctpnetlisthead, sctp_next);
				}
			}
#ifdef SCTP_ALTERNATE_ROUTE
			rtp->ro_rt = rtalloc_alternate(&rtp->ro_dst, NULL, 0);
			if (rtp->ro_rt && (rtp->ro_rt == t_rt)) {
				/* Now we need a better route if one exits */
				RTFREE(rtp->ro_rt);
				rtp->ro_rt = rtalloc_alternate(&rtp->ro_dst, t_rt, 0);
			}
#else
#ifdef __FreeBSD__
			rtp->ro_rt = rtalloc1(&rtp->ro_dst, 1, 0UL);
#else
			rtp->ro_rt = rtalloc1(&rtp->ro_dst, 1);
#endif
#endif
		} else {
  		        rtp->ro_rt = rtalloc_alternate(&rtp->ro_dst, NULL, 0);
		}
	}
	loc_scope = site_scope = loopscope = 0;
	rt = rtp->ro_rt;
	if (rt == NULL) {
		/*
		 * no route to host. this packet is going no-where.
		 * We probably should make sure we arrange to send back
		 * an error.
		 */
		memset(&ans, 0, sizeof(ans));
		return (ans);
	}
	/*
	 * We base our scope on the outbound packet scope.
	 * Not the TCB. This way in local scope we will only
	 * use a local scope src address when we send to the
	 * one local address on the assoc.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&to->sin6_addr)) {
		site_scope = 1;
		loc_scope = 1;
		loopscope = 0;
	} else if (IN6_IS_ADDR_SITELOCAL(&to->sin6_addr)) {
		site_scope = 1;
		loc_scope = 0;
		loopscope = 0;
	} else if (IN6_IS_ADDR_LOOPBACK(&to->sin6_addr)) {
		site_scope = 1;
		loc_scope = 1;
		loopscope = 1;
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* negative list */
		list_type = 1;
	} else if (tcb) {
		if (inp->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) {
			list_type = 1;
		} else {
			list_type = 0;
		}
	} else {
		list_type = 0;
	}
	are_done = 0;
	rt_addr = sctp_choose_correctv6_scope(rt, site_scope, loc_scope, tcb,
					      inp, list_type, &are_done);
	if (are_done) {
		/* Short cut, the selector says we have it */
		return (rt_addr->sin6_addr);
	}
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/*
		 * Hunt through the interface and find an address not
		 * restricted with a scope good enough to pass muster.
		 */
		/* Ok bound to all but not sure what to do
		 * since we are not allowed to use
		 * an address on the interface.
		 */
		if (inp->next_ifn_touse == NULL) {
			inp->next_ifn_touse = TAILQ_FIRST(&ifnet);
		}
		/* Hunt for an address amongst the interfaces not on the
		 * negative list and rotate amongst them.
		 */
		for (ifn = inp->next_ifn_touse; ifn; ifn = TAILQ_NEXT(ifn, if_list)) {
			if ((loopscope == 0) &&
			    (ifn->if_type == IFT_LOOP)) {
				/* wrong base scope */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if (ifa->ifa_addr->sa_family == AF_INET6) {
					struct sockaddr_in6 *ifa_a;
					ifa_a = (struct sockaddr_in6 *)(ifa->ifa_addr);
					if (IN6_IS_ADDR_UNSPECIFIED(&ifa_a->sin6_addr)) {
						/* skip unspecifed addresses */
						continue;
					}
					if (IN6_IS_ADDR_LINKLOCAL(&ifa_a->sin6_addr)) {
						if (loc_scope == 0)
							/* link local scopes not allowed */
							continue;
						if (!sctp_is_same_scope(ifa_a, to))
							continue;
					}
					if ((site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&ifa_a->sin6_addr))) {
						/* can't use it wrong scope */
						continue;
					}
					/* make sure it is not restricted */
					if (sctp_is_addr_restricted(tcb, ifa->ifa_addr))
						continue;
					/* is the interface address valid */
					ifa6 = (struct in6_ifaddr *)ifa;
					/* ok to use deprecated addresses? */
					if (!ip6_use_deprecated) {
						if (ifa6->ia6_flags &
						    IN6_IFF_DEPRECATED) {
							continue;
						}
					}
					if (ifa6->ia6_flags &
					    (IN6_IFF_DETACHED |
					     IN6_IFF_ANYCAST |
					     IN6_IFF_NOTREADY))
						continue;
					/* we can use it !! */
					/* set to start with next intf */
					inp->next_ifn_touse = TAILQ_NEXT(ifn, if_list);
					return (ifa_a->sin6_addr);
				}
			}
		}
		/* Ok nothing turned up in the next_ifn_touse to the next
		 * lets check the beginning up to next_ifn_touse.
		 */
		for (ifn = TAILQ_FIRST(&ifnet);
		     (ifn && (ifn != inp->next_ifn_touse));
		     ifn = TAILQ_NEXT(ifn, if_list)) {
			if ((loopscope == 0) &&
			    (ifn->if_type == IFT_LOOP)) {
				/* wrong base scope */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if (ifa->ifa_addr->sa_family == AF_INET6) {
					struct sockaddr_in6 *ifa_a;
					ifa_a = (struct sockaddr_in6 *)(ifa->ifa_addr);
					if (IN6_IS_ADDR_UNSPECIFIED(&ifa_a->sin6_addr)) {
						/* skip unspecifed addresses */
						continue;
					}
					if (IN6_IS_ADDR_LINKLOCAL(&ifa_a->sin6_addr)) {
						if (loc_scope == 0)
							/* link local scopes not allowed */
							continue;
						if (!sctp_is_same_scope(ifa_a, to))
							continue;
					}
					if ((site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&ifa_a->sin6_addr))) {
						/* can't use it wrong scope */
						continue;
					}
					/* make sure it is not restricted */
					if (sctp_is_addr_restricted(tcb, ifa->ifa_addr))
						continue;
					/* is the interface address valid */
					ifa6 = (struct in6_ifaddr *)ifa;
					/* ok to use deprecated addresses? */
					if (!ip6_use_deprecated) {
						if (ifa6->ia6_flags &
						    IN6_IFF_DEPRECATED) {
							continue;
						}
					}
					if (ifa6->ia6_flags &
					    (IN6_IFF_DETACHED |
					     IN6_IFF_ANYCAST |
					     IN6_IFF_NOTREADY))
						continue;
					/* we can use it !! */
					/* set to start with next intf */
					inp->next_ifn_touse = TAILQ_NEXT(ifn, if_list);
					return (ifa_a->sin6_addr);
				}
			}
		}

		if (!non_asoc_addr_ok) {
			memset(&ans, 0, sizeof(ans));
			return (ans);
		}
		/* see if we can just get an address of the right scope
		 * without worrying about restrictions.
		 */
		for (ifn = TAILQ_FIRST(&ifnet); ifn;
		     ifn = TAILQ_NEXT(ifn, if_list)) {
			if ((loopscope == 0) &&
			    (ifn->if_type == IFT_LOOP)) {
				/* wrong base scope */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if (ifa->ifa_addr->sa_family == AF_INET6) {
					struct sockaddr_in6 *ifa_a;
					ifa_a = (struct sockaddr_in6 *)(ifa->ifa_addr);
					if (IN6_IS_ADDR_UNSPECIFIED(&ifa_a->sin6_addr)) {
						/* skip unspecifed addresses */
						continue;
					}
					if (IN6_IS_ADDR_LINKLOCAL(&ifa_a->sin6_addr)) {
						if (loc_scope == 0)
							/* link local scopes not allowed */
							continue;
						if (!sctp_is_same_scope(ifa_a, to))
							continue;
					}
					if ((site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&ifa_a->sin6_addr))) {
						/* can't use it wrong scope */
						continue;
					}
					/* is the interface address valid */
					ifa6 = (struct in6_ifaddr *)ifa;
					/* ok to use deprecated addresses? */
					if (!ip6_use_deprecated) {
						if (ifa6->ia6_flags &
						    IN6_IFF_DEPRECATED) {
							continue;
						}
					}
					if (ifa6->ia6_flags &
					    (IN6_IFF_DETACHED |
					     IN6_IFF_ANYCAST |
					     IN6_IFF_NOTREADY))
						continue;
					/* we can use it !! */
					/* set to start with next intf */
					inp->next_ifn_touse = TAILQ_NEXT(ifn, if_list);
					return (ifa_a->sin6_addr);
				}
			}
		}
		/*
		 * Can't find a single address of the right scope,
		 * you get the address on the route...  This could
		 * be due to bad scope OR it could be due to our
		 * strange ASCONF case where we are doing the ADD/DEL
		 * after a ifconfig that changed an address. Less likely
		 * on IPv6 but always possible.
		 */
		return (rt_addr->sin6_addr);
	}
	/* Now here we have specific BOUND addresses cases */
	if (tcb) {
		/* Ok, we have a local list on the association level
		 * If asconf is enabled then my list is a reverse composite
		 * of the addresses allowed.
		 */
		if (inp->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) {
			/* first is the destination on the bound list for
			 * the ep but not restricted?
			 */
			if (tcb->asoc.last_used_address == NULL) {
				tcb->asoc.last_used_address = LIST_FIRST(&inp->sctp_addr_list);
			}
			/* search beginning with the last used address */
			for (laddr = tcb->asoc.last_used_address; laddr;
			     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;

				if (laddr->ifa->ifa_addr->sa_family != AF_INET6)
					/* wrong type */
					continue;
				out6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
				if (IN6_IS_ADDR_UNSPECIFIED(&out6->sin6_addr)) {
					/* we skip unspecifed addresses */
					continue;
				}
				if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr)) {
					if (loc_scope == 0)
						/* link local scopes not allowed */
						continue;
					if (!sctp_is_same_scope(out6, to))
						continue;
				}
				if ((site_scope == 0) &&
				    (IN6_IS_ADDR_SITELOCAL(&out6->sin6_addr))) {
					/* can't use it wrong scope */
					continue;
				}
				if ((loopscope == 0) &&
				    (IN6_IS_ADDR_LOOPBACK(&out6->sin6_addr))) {
					continue;
				}
				if (sctp_is_addr_restricted(tcb, laddr->ifa->ifa_addr)) {
					/* on the no-no list */
					continue;
				}
				/* is the interface address valid */
				ifa6 = (struct in6_ifaddr *)laddr->ifa;
				/* ok to use deprecated addresses? */
				if (!ip6_use_deprecated) {
					if (ifa6->ia6_flags &
					    IN6_IFF_DEPRECATED) {
				                /* can't use this type */
						continue;
					}
				}
				if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
						       IN6_IFF_ANYCAST |
						       IN6_IFF_NOTREADY))
					continue;
				tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
				return (out6->sin6_addr);
			}
			/*
			 * didn't find it, so expand search and start from
			 * the top
			 */
			for (laddr = LIST_FIRST(&inp->sctp_addr_list);
			     (laddr && (laddr != tcb->asoc.last_used_address));
			     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
				out6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
				if (IN6_IS_ADDR_UNSPECIFIED(&out6->sin6_addr)) {
					/* we skip unspecifed addresses */
					continue;
				}
				if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr)) {
					if (loc_scope == 0)
						/* link local scopes not allowed */
						continue;
					if (!sctp_is_same_scope(out6, to))
						continue;
				}
				if ((site_scope == 0) &&
				    (IN6_IS_ADDR_SITELOCAL(&out6->sin6_addr))) {
					/* can't use it wrong scope */
					continue;
				}
				if ((loopscope == 0) &&
				    (IN6_IS_ADDR_LOOPBACK(&out6->sin6_addr))) {
					continue;
				}
				if (sctp_is_addr_restricted(tcb, laddr->ifa->ifa_addr)) {
					/* on the no-no list */
					continue;
				}
				/* is the interface address valid */
				ifa6 = (struct in6_ifaddr *)laddr->ifa;
				/* ok to use deprecated addresses? */
				if (!ip6_use_deprecated) {
					if (ifa6->ia6_flags &
					    IN6_IFF_DEPRECATED) {
						continue;
					}
				}
				if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
						       IN6_IFF_ANYCAST |
						       IN6_IFF_NOTREADY))
					continue;
				tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
				return (out6->sin6_addr);
			}
			/*
			 * didn't find an appropriate source address!
			 * return a NULL address, and a NULL route
			 */
			if (rtp->ro_rt) {
				RTFREE(rtp->ro_rt);
				rtp->ro_rt = NULL;
			}

			if (!non_asoc_addr_ok) {
				memset(&ans, 0, sizeof(ans));
				return (ans);
			} else {
				/*
				 * Ok if we reach here we are back in same
				 * condition in BOUND all.. maybe the special
				 * case of ASCONF.  So we just need to return
				 * any asoc address and hope things work.
				 */
				LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
					if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
						if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
							printf("Help I have fallen and I can't get up!\n");
						}
#endif
						continue;
					}
					if (laddr->ifa->ifa_addr == NULL)
						continue;

					if (laddr->ifa->ifa_addr->sa_family != AF_INET6)
						/* wrong type */
						continue;
					out6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
					if (IN6_IS_ADDR_UNSPECIFIED(&out6->sin6_addr)) {
						/* skip unspecifed addresses */
						continue;
					}
					if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr)) {
						if (loc_scope == 0)
							/* link local scopes not allowed */
							continue;
						if (!sctp_is_same_scope(out6, to))
							continue;
					}
					if ((site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&out6->sin6_addr))) {
						/* can't use it wrong scope */
						continue;
					}
					if ((loopscope == 0) &&
					    (IN6_IS_ADDR_LOOPBACK(&out6->sin6_addr))) {
						continue;
					}
					/* Ok here it is */
					tcb->asoc.last_used_address = LIST_NEXT(laddr, sctp_nxt_addr);
					return (out6->sin6_addr);
				}
				/*
				 * no address in scope.. egad.. I guess you
				 * will get the interface and we will abort.
				 */
			}
		} else {
			/*
			 * This is the opposite case, where the list is
			 * the only list of addresses on the assoc.
			 */

			/* Ok look on the list for one we can give out */
			LIST_FOREACH(laddr, &tcb->asoc.sctp_local_addr_list, sctp_nxt_addr) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;

				if (laddr->ifa->ifa_addr->sa_family != AF_INET6)
					/* must be IPv6 */
					continue;
				out6 = (struct sockaddr_in6 *)(laddr->ifa->ifa_addr);
				if (IN6_IS_ADDR_UNSPECIFIED(&out6->sin6_addr)) {
					/* we skip unspecifed addresses */
					continue;
				}
				if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr)) {
					if (loc_scope == 0)
						/* link local scopes not allowed */
						continue;
					if (!sctp_is_same_scope(out6, to))
						continue;
				}
				if ((site_scope == 0) &&
				    (IN6_IS_ADDR_SITELOCAL(&out6->sin6_addr))) {
					/* can't use it wrong scope */
					continue;
				}
				if ((loopscope == 0) &&
				    (IN6_IS_ADDR_LOOPBACK(&out6->sin6_addr))) {
					continue;
				}
				/* is the interface address valid */
				ifa6 = (struct in6_ifaddr *)laddr->ifa;
				/* ok to use deprecated addresses? */
				if (!ip6_use_deprecated) {
					if (ifa6->ia6_flags &
					    IN6_IFF_DEPRECATED) {
						continue;
					}
				}
				if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
						       IN6_IFF_ANYCAST |
						       IN6_IFF_NOTREADY))
					continue;
				return (out6->sin6_addr);
			}
		}
		if (!non_asoc_addr_ok) {
			memset(&ans, 0, sizeof(ans));
			return (ans);
		}
		return (rt_addr->sin6_addr);
	}
	/* If we reach here there is NO TCB and the EP has a bound sub-set */

	/* Nope src address rotation on the ep is in order */
	if (inp->next_addr_touse == NULL) {
		inp->next_addr_touse = LIST_FIRST(&inp->sctp_addr_list);
	}
	for (laddr = inp->next_addr_touse; laddr;
	     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Help I have fallen and I can't get up!\n");
			}
#endif
			continue;
		}
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		if (laddr->ifa->ifa_addr->sa_family != AF_INET6)
			/* wrong type */
			continue;
		out6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
		if (IN6_IS_ADDR_UNSPECIFIED(&out6->sin6_addr)) {
			/* we skip unspecifed addresses */
			continue;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr)) {
			if (loc_scope == 0)
				/* link local scopes not allowed */
				continue;
			if (!sctp_is_same_scope(out6, to))
				continue;
		}
		if ((site_scope == 0) &&
		    (IN6_IS_ADDR_SITELOCAL(&out6->sin6_addr))) {
			/* can't use it wrong scope */
			continue;
		}
		if ((loopscope == 0) &&
		    (IN6_IS_ADDR_LOOPBACK(&out6->sin6_addr))) {
			continue;
		}
		/* is the interface address valid */
		ifa6 = (struct in6_ifaddr *)laddr->ifa;
	        /* ok to use deprecated addresses? */
		if (!ip6_use_deprecated) {
			if (ifa6->ia6_flags & IN6_IFF_DEPRECATED) {
				continue;
			}
		}
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
				       IN6_IFF_ANYCAST |
				       IN6_IFF_NOTREADY))
			continue;
		inp->next_addr_touse = LIST_NEXT(laddr, sctp_nxt_addr);
		return (out6->sin6_addr);
	}
	/* Check the front part of the list */
	for (laddr = LIST_FIRST(&inp->sctp_addr_list);
	     (laddr && (laddr != inp->next_addr_touse));
	     laddr = LIST_NEXT(laddr, sctp_nxt_addr)) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Help I have fallen and I can't get up!\n");
			}
#endif
			continue;
		}
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		if (laddr->ifa->ifa_addr->sa_family != AF_INET6)
			/* wrong type */
			continue;
		out6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
		if (IN6_IS_ADDR_UNSPECIFIED(&out6->sin6_addr)) {
			/* we skip unspecifed addresses */
			continue;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&out6->sin6_addr)) {
			if (loc_scope == 0)
				/* link local scopes not allowed */
				continue;
			if (!sctp_is_same_scope(out6, to))
				continue;
		}
		if ((site_scope == 0) &&
		    (IN6_IS_ADDR_SITELOCAL(&out6->sin6_addr))) {
			/* can't use it wrong scope */
			continue;
		}
		if ((loopscope == 0) &&
		    (IN6_IS_ADDR_LOOPBACK(&out6->sin6_addr))) {
			continue;
		}
		/* is the interface address valid */
		ifa6 = (struct in6_ifaddr *)laddr->ifa;
		/* ok to use deprecated addresses? */
		if (!ip6_use_deprecated) {
			if (ifa6->ia6_flags & IN6_IFF_DEPRECATED) {
				continue;
			}
		}
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
				       IN6_IFF_ANYCAST |
				       IN6_IFF_NOTREADY))
			continue;
		inp->next_addr_touse = LIST_NEXT(laddr, sctp_nxt_addr);
		return (out6->sin6_addr);
	}
	/* Drop back to the 40 */
	if (!non_asoc_addr_ok) {
		memset(&ans, 0, sizeof(ans));
		return (ans);
	}
	return (rt_addr->sin6_addr);
}

#include <netinet6/nd6.h>

static u_int8_t
sctp_get_ect(struct sctp_tcb *tcb,
	     struct sctp_tmit_chunk *chk)
{
	u_int8_t this_random;
	if (((tcb->asoc.hb_random_idx == 3) && (tcb->asoc.hb_ect_randombit > 7)) ||
	     (tcb->asoc.hb_random_idx > 3)
	     ) {
		u_int32_t rndval;
		rndval = sctp_select_initial_TSN(&tcb->sctp_ep->sctp_ep);
		memcpy(tcb->asoc.hb_random_values,&rndval,
		       sizeof(tcb->asoc.hb_random_values));
		this_random = tcb->asoc.hb_random_values[0];
		tcb->asoc.hb_random_idx = 0;
		tcb->asoc.hb_ect_randombit = 0;
	} else {
		if (tcb->asoc.hb_ect_randombit > 7) {
		  tcb->asoc.hb_ect_randombit = 0;
		  tcb->asoc.hb_random_idx++;
		}
		this_random = tcb->asoc.hb_random_values[tcb->asoc.hb_random_idx];
		tcb->asoc.hb_ect_randombit++;
	}
	if ((this_random >> tcb->asoc.hb_ect_randombit) & 0x01) {
		if (chk != NULL)
			/*
			 * we track the nonce sum in the chk even though we
			 * currently have no way to get back in the sack the
			 * nonce sum to validate it.
			 */
			chk->rec.data.ect_nonce = SCTP_ECT1_BIT;
		return (SCTP_ECT1_BIT);
	} else {
		return (SCTP_ECT0_BIT);
	}
}

static int
sctp_lowlevel_chunk_output(register struct sctp_inpcb *inp,
			   register struct sctp_tcb *tcb,    /* may be NULL */
			   struct sctp_nets *net,
			   struct sockaddr *to,
			   struct mbuf *m,
			   int nofragment_flag,
			   int ecn_ok,
			   struct sctp_tmit_chunk *chk,
			   int out_of_asoc_ok)
	/* nofragment_flag to tell if IP_DF should be set (IPv4 only) */
{
	/*
	 * Given a mbuf chain (via m_next) that holds a packet header
	 * WITH a SCTPHDR but no IP header, endpoint inp and sa structure.
	 * - calculate SCTP checksum and fill in
	 * - prepend a IP address header
	 * - if boundall use INADDR_ANY
	 * - if boundspecific do source address selection
	 * - set fragmentation option for ipV4
	 * - On return from IP output, check/adjust mtu size
	 * - of output interface and smallest_mtu size as well.
	 */
	struct sctphdr *sctphdr;
	int o_flgs;
	u_int32_t csum;
	int ret;
	struct route ro, *rtp;

	if ((net) && (net->dest_state & SCTP_ADDR_OUT_OF_SCOPE)) {
		m_freem(m);
		return (EFAULT);
	}
	if ((m->m_flags & M_PKTHDR) == 0) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("Software error: sctp_lowlevel_chunk_output() called with non pkthdr!\n");
		}
#endif
		m_freem(m);
		return (EFAULT);
	}
	/* Calculate the csum and fill in the length of the packet */
	sctphdr = mtod(m, struct sctphdr *);
	sctphdr->checksum = 0;
	csum = sctp_calculate_sum(m, &m->m_pkthdr.len, 0);
	sctphdr->checksum = csum;
	if (to->sa_family == AF_INET) {
		struct ip *ip;
		M_PREPEND(m, sizeof(struct ip), M_DONTWAIT);
		if (m == NULL) {
			/* failed to prepend data, give up */
			return (ENOMEM);
		}
		ip = mtod(m, struct ip *);
		ip->ip_v = IPVERSION;
		ip->ip_hl = (sizeof(struct ip) >> 2);
		if (nofragment_flag)
			ip->ip_off = IP_DF;
		else
			ip->ip_off = 0;
#ifdef __OpenBSD__
		ip->ip_id = htons(ip_randomid());
#else
		ip->ip_id = htons(ip_id++);
#endif

#if defined(__FreeBSD__)
		ip->ip_ttl = inp->ip_inp.inp.inp_ip_ttl;
#else
		ip->ip_ttl = inp->inp_ip_ttl;
#endif
		ip->ip_len = m->m_pkthdr.len;
		if (tcb) {
			if ((tcb->asoc.ecn_allowed) && ecn_ok) {
				/* Enable ECN */
#if defined(__FreeBSD__)
				ip->ip_tos = (u_char)((inp->ip_inp.inp.inp_ip_tos & 0x000000fc) |
						      sctp_get_ect(tcb, chk));
#else
				ip->ip_tos = (u_char)((inp->inp_ip_tos & 0x000000fc) |
						      sctp_get_ect(tcb, chk));
#endif
			} else {
				/* No ECN */
#if defined(__FreeBSD__)
				ip->ip_tos = inp->ip_inp.inp.inp_ip_tos;
#else
				ip->ip_tos = inp->inp_ip_tos;
#endif
			}
		} else {
			/* no association at all */
#if defined(__FreeBSD__)
			ip->ip_tos = inp->ip_inp.inp.inp_ip_tos;
#else
			ip->ip_tos = inp->inp_ip_tos;
#endif
		}
		ip->ip_p = IPPROTO_SCTP;
		ip->ip_sum = 0;
		if (net == NULL) {
			rtp = &ro;
			memcpy(&ro.ro_dst, to, to->sa_len);
			ro.ro_rt = 0;
		} else {
			rtp = (struct route *)&net->ra;
		}
		/* Now the address selection part */
		ip->ip_dst.s_addr = ((struct sockaddr_in *)to)->sin_addr.s_addr;

		/* call the routine to select the src address */
		ip->ip_src = sctp_ipv4_source_address_selection(inp, tcb,
								(struct sockaddr_in *)to,
								rtp, net, out_of_asoc_ok);
		/*
		 * If source address selection fails and we find no route then
		 * the ip_ouput should fail as well with a NO_ROUTE_TO_HOST
		 * type error. We probably should catch that somewhere and
		 * abort the association right away (assuming this is an INIT
		 * being sent).
		 */
		if ((rtp->ro_rt == NULL)) {
			/*
			 * src addr selection failed to find a route (or valid
			 * source addr), so we can't get there from here!
			 */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("low_level_output: dropped v4 packet- no valid source addr\n");
				printf("Destination was %x\n", (u_int)(ntohl(ip->ip_dst.s_addr)));
			}
#endif /* SCTP_DEBUG */
			if (net) {
				if ((net->dest_state & SCTP_ADDR_REACHABLE) && tcb)
					sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
							tcb,
							SCTP_FAILED_THRESHOLD,
							(void *)net);
				net->dest_state &= ~SCTP_ADDR_REACHABLE;
				net->dest_state |= SCTP_ADDR_NOT_REACHABLE;
				if (tcb) {
					if (net == tcb->asoc.primary_destination) {
						/* need a new primary */
						struct sctp_nets *alt;
						alt = sctp_find_alternate_net(tcb, net);
						if (alt != net) {
							net->dest_state |= SCTP_ADDR_WAS_PRIMARY;
							tcb->asoc.primary_destination = alt;
						}
					}
				}
			}
			m_freem(m);
			return (EHOSTUNREACH);
		}

		o_flgs = (IP_RAWOUTPUT | (inp->sctp_socket->so_options & (SO_DONTROUTE | SO_BROADCAST)));
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("Calling ipv4 output routine from low level src addr:%x\n",
			       (u_int)(ntohl(ip->ip_src.s_addr)));
			printf("Destination is %x\n",(u_int)(ntohl(ip->ip_dst.s_addr)));
			printf("RTP route is %x through\n",(u_int)rtp->ro_rt);
		}
#endif
		ret = ip_output(m, inp->ip_inp.inp.inp_options,
				rtp, o_flgs, inp->ip_inp.inp.inp_moptions
#if defined(__OpenBSD__) && defined(IPSEC)
				,(struct inpcb *)NULL
#endif
);

		sctp_pegs[SCTP_DATAGRAMS_SENT]++;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("Ip output returns %d\n", ret);
		}
#endif
		if (net == NULL) {
			/* free tempy routes */
			if (ro.ro_rt)
				RTFREE(ro.ro_rt);
		} else {
			/* PMTU check versus smallest asoc MTU goes here */
			if (rtp->ro_rt != NULL) {
				if (rtp->ro_rt->rt_rmx.rmx_mtu &&
				    (tcb->asoc.smallest_mtu > rtp->ro_rt->rt_rmx.rmx_mtu)) {
					sctp_mtu_size_reset(inp,
							    &tcb->asoc, 
							    rtp->ro_rt->rt_rmx.rmx_mtu);
				}
			}
		}
		return (ret);
	}
#ifdef INET6
	else if (to->sa_family == AF_INET6) {
		struct ip6_hdr *ip6h;
		struct ifnet *ifp;
		u_char flowTop;
		u_short flowBottom;
		u_char tosBottom, tosTop;
		struct sockaddr_in6 *sin6, tmp, *lsa6, lsa6_tmp, lsa6_storage;
		int error;

		M_PREPEND(m, sizeof(struct ip6_hdr), M_DONTWAIT);
		if (m == NULL) {
			/* failed to prepend data, give up */
			return (ENOMEM);
		}
		if (net == NULL) {
			rtp = &ro;
			memcpy(&ro.ro_dst, to, to->sa_len);
			ro.ro_rt = 0;
		} else {
			rtp = (struct route *)&net->ra;
		}
		ip6h = mtod(m, struct ip6_hdr *);

		/*
		 * We assume here that inp_flow is in host byte order within
		 * the TCB!
		 */
		flowBottom = ((struct in6pcb *)inp)->in6p_flowinfo & 0x0000ffff;
		flowTop = ((((struct in6pcb *)inp)->in6p_flowinfo & 0x000f0000) >> 16);

		tosTop = (((((struct in6pcb *)inp)->in6p_flowinfo & 0xf0) >> 4) | IPV6_VERSION);

		/* protect *sin6 from overwrite */
		sin6 = (struct sockaddr_in6 *)to;
		tmp = *sin6;
		sin6 = &tmp;
		/* KAME hack: embed scopeid */
		if ((error = scope6_check_id(sin6, ip6_use_defzone)) != 0)
			return (error);

		if (tcb != NULL) {
			if ((tcb->asoc.ecn_allowed) && ecn_ok) {
				/* Enable ECN */
				tosBottom = (((((struct in6pcb *)inp)->in6p_flowinfo & 0x0c) | sctp_get_ect(tcb, chk)) << 4);
			} else {
				/* No ECN */
				tosBottom = ((((struct in6pcb *)inp)->in6p_flowinfo & 0x0c) << 4);
			}
		} else {
			/* we could get no assoc if it is a O-O-T-B packet */
			tosBottom = ((((struct in6pcb *)inp)->in6p_flowinfo & 0x0c) << 4);
		}
		ip6h->ip6_flow = htonl(((tosTop << 24) | ((tosBottom|flowTop) << 16) | flowBottom));
		ip6h->ip6_nxt = IPPROTO_SCTP;
		ip6h->ip6_plen = m->m_pkthdr.len;
		ip6h->ip6_dst = ((struct sockaddr_in6 *)to)->sin6_addr;

		/*
		 * Add SRC address selection here:
		 * we can only reuse to a limited degree the kame src-addr-sel,
		 * since we can try their selection but it may not be bound.
		 */
		bzero(&lsa6_tmp, sizeof(lsa6_tmp));
		lsa6_tmp.sin6_family = AF_INET6;
		lsa6_tmp.sin6_len = sizeof(lsa6_tmp);
		lsa6 = &lsa6_tmp;
		lsa6->sin6_addr = sctp_ipv6_source_address_selection(inp, tcb,
								     (struct sockaddr_in6 *)to,
								     rtp, net,
								     out_of_asoc_ok);
		if ((rtp->ro_rt == NULL)) {
			/*
			 * src addr selection failed to find a route (or valid
			 * source addr), so we can't get there from here!
			 */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("low_level_output: dropped v6 pkt- no valid source addr\n");
			}
#endif
			/*#endif*/
			m_freem(m);
			if (net) {
				if ((net->dest_state & SCTP_ADDR_REACHABLE) && tcb)
					sctp_ulp_notify(SCTP_NOTIFY_INTERFACE_DOWN,
							tcb,
							SCTP_FAILED_THRESHOLD,
							(void *)net);
				net->dest_state &= ~SCTP_ADDR_REACHABLE;
				net->dest_state |= SCTP_ADDR_NOT_REACHABLE;
				if (tcb) {
					if (net == tcb->asoc.primary_destination) {
						/* need a new primary */
						struct sctp_nets *alt;
						alt = sctp_find_alternate_net(tcb, net);
						if (alt != net) {
							net->dest_state |= SCTP_ADDR_WAS_PRIMARY;
							tcb->asoc.primary_destination = alt;
						}
					}
				}
			}
			return (EHOSTUNREACH);
		}
#ifndef SCOPEDROUTING
		/*
		 * XXX: sa6 may not have a valid sin6_scope_id in
		 * the non-SCOPEDROUTING case.
		 */
		bzero(&lsa6_storage, sizeof(lsa6_storage));
		lsa6_storage.sin6_family = AF_INET6;
		lsa6_storage.sin6_len = sizeof(lsa6_storage);
		if ((error = in6_recoverscope(&lsa6_storage, &lsa6->sin6_addr, NULL)) != 0) {
			m_freem(m);
			return (error);
		}
		/* XXX */
		lsa6_storage.sin6_addr = lsa6->sin6_addr;
		lsa6 = &lsa6_storage;
#endif /* SCOPEDROUTING */
		ip6h->ip6_src = lsa6->sin6_addr;

		/* We set the hop limit now since there is a good chance that
		 * our rtp pointer is now filled
		 */
		ip6h->ip6_hlim = in6_selecthlim((struct in6pcb *)&inp->ip_inp.inp,
						(rtp ?
						 (rtp->ro_rt ? (rtp->ro_rt->rt_ifp) : (NULL)) :
						 (NULL)));
		o_flgs = 0;
		ifp = NULL;

		/* make sure destination scope_id is available */
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) &&
		    (sin6->sin6_scope_id == 0)) {
			sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
		}
		/* attach the full sockaddr_in6 addresses to the packet */
		if (!ip6_setpktaddrs(m, lsa6, sin6)) {
			m_freem(m);
			return (ENOBUFS);
		}

#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("Calling ipv6 output routine from low level\n");
			printf("src: ");
			sctp_print_address((struct sockaddr *)lsa6);
			printf("dst: ");
			sctp_print_address((struct sockaddr *)sin6);
		}
#endif /* SCTP_DEBUG */

		ret = ip6_output(m,((struct in6pcb *)inp)->in6p_outputopts,
#ifdef NEW_STRUCT_ROUTE
				 rtp,
#else
				 (struct route_in6 *)rtp,
#endif
				 o_flgs,
				 ((struct in6pcb *)inp)->in6p_moptions,
				 &ifp);
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("return from send is %d\n", ret);
		}
#endif /* SCTP_DEBUG_OUTPUT */
		sctp_pegs[SCTP_DATAGRAMS_SENT]++;
		if (net == NULL) {
			/* Now if we had a temp route free it */
			if (ro.ro_rt)
				RTFREE(ro.ro_rt);
		} else {
			/* PMTU check versus smallest asoc MTU goes here */
			if (rtp->ro_rt != NULL) {
				if (rtp->ro_rt->rt_rmx.rmx_mtu &&
				    (tcb->asoc.smallest_mtu > rtp->ro_rt->rt_rmx.rmx_mtu)) {
					sctp_mtu_size_reset(inp,
							    &tcb->asoc,
							    rtp->ro_rt->rt_rmx.rmx_mtu);
				}
			} else if (ifp) {
				if (ND_IFINFO(ifp)->linkmtu &&
				    (tcb->asoc.smallest_mtu > ND_IFINFO(ifp)->linkmtu)) {
					sctp_mtu_size_reset(inp,
							    &tcb->asoc, 
							    ND_IFINFO(ifp)->linkmtu);
				}
			}
		}
		return (ret);
	}
#endif
	else {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("Unknown protocol (TSNH) type %d\n",((struct sockaddr *)to)->sa_family);
		}
#endif
		m_freem(m);
		return (EFAULT);
	}
}

void
sctp_send_initiate(inp, tcb)
     register struct sctp_inpcb *inp;
     struct sctp_tcb *tcb;
{
	struct mbuf *m,*m_at,*m_last;
	struct sctp_nets *net;
	struct sctp_init_msg *initm;
	struct sctp_supported_addr_param *sup_addr;
	struct sctp_paramhdr *ecn;
	int padval;

	/* INIT's always go to the primary (and usually ONLY address) */
	m_last = NULL;
	net = tcb->asoc.primary_destination;
	if (net == NULL) {
		tcb->asoc.primary_destination = net = TAILQ_FIRST(&tcb->asoc.nets);
		if (net == NULL) {
			return;
		}
	}
	if (callout_pending(&net->rxt_timer.timer)) {
		/* This case should not happen */
		return;
	}
	/* start the INIT timer */
	if (sctp_timer_start(SCTP_TIMER_TYPE_INIT, inp, tcb, net)) {
		/* we are hosed since I can't start the INIT timer? */
		return;
	}
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL) {
		/* No memory, INIT timer will re-attempt. */
		return;
	}
	/* make it into a M_EXT */
	MCLGET(m, M_DONTWAIT);
	if ((m->m_flags & M_EXT) != M_EXT) {
		/* Failed to get cluster buffer */
		m_freem(m);
		return;
	}
	m->m_len = sizeof(struct sctp_init_msg);
	/* Now lets put the SCTP header in place */
	initm = mtod(m, struct sctp_init_msg *);
	initm->sh.src_port = inp->sctp_lport;
	initm->sh.dest_port = tcb->rport;
	initm->sh.v_tag = 0;
	initm->sh.checksum = 0;	/* calculate later */
	/* now the chunk header */
	initm->msg.ch.chunk_type = SCTP_INITIATION;
	initm->msg.ch.chunk_flags = 0;
	/* fill in later from mbuf we build */
	initm->msg.ch.chunk_length = 0;
	/* place in my tag */
	initm->msg.init.initiate_tag = htonl(tcb->asoc.my_vtag);
	/* set up some of the credits. */
	initm->msg.init.a_rwnd = htonl(inp->sctp_socket->so_rcv.sb_hiwat);

	initm->msg.init.num_outbound_streams = htons(tcb->asoc.pre_open_streams);
	initm->msg.init.num_inbound_streams = htons(tcb->asoc.max_inbound_streams);
	initm->msg.init.initial_tsn = htonl(tcb->asoc.init_seq_number);
	/* now the address restriction */
	sup_addr = (struct sctp_supported_addr_param *)((caddr_t)initm +
							sizeof(*initm));
	sup_addr->ph.param_type = htons(SCTP_SUPPORTED_ADDRTYPE);
	/* we support 2 types IPv6/IPv4 */
	sup_addr->ph.param_length = htons(sizeof(*sup_addr)+2);
	sup_addr->addr_type[0] = htons(SCTP_IPV4_ADDRESS);
	sup_addr->addr_type[1] = htons(SCTP_IPV6_ADDRESS);
	m->m_len += sizeof(*sup_addr)+2;

	if (inp->sctp_flags & SCTP_PCB_FLAGS_ADAPTIONEVNT) {
		struct sctp_adaption_layer_indication *ali;
		ali = (struct sctp_adaption_layer_indication *)((caddr_t)sup_addr +
								sizeof(*sup_addr)+2);
		ali->ph.param_type = htons(SCTP_ULP_ADAPTION);
		ali->ph.param_length = htons(sizeof(struct sctp_adaption_layer_indication));
		ali->indication = ntohl(inp->sctp_ep.adaption_layer_indicator);
		m->m_len += sizeof(*ali);
		ecn = (struct sctp_paramhdr *)((caddr_t)ali + sizeof(*ali));
	} else {
		ecn = (struct sctp_paramhdr *)((caddr_t)sup_addr + sizeof(*sup_addr)+2);
	}
	/* now any cookie time extensions */
	if (tcb->asoc.cookie_preserve_req) {
		struct sctp_cookie_perserve_param *cookie_preserve;
		cookie_preserve = (struct sctp_cookie_perserve_param *)(ecn);
		cookie_preserve->ph.param_type = htons(SCTP_COOKIE_PRESERVE);
		cookie_preserve->ph.param_length = htons(sizeof(*cookie_preserve));
		cookie_preserve->time = htonl(tcb->asoc.cookie_preserve_req);
		m->m_len += sizeof(*cookie_preserve);
		ecn = (struct sctp_paramhdr *)(cookie_preserve++);
		tcb->asoc.cookie_preserve_req = 0;
	}
	/* ECN parameter */
	ecn->param_type = htons(SCTP_ECN_CAPABLE);
	ecn->param_length = htons(sizeof(*ecn));
	m->m_len += sizeof(*ecn);
	ecn++;

	/* And now tell the peer we do  pr-sctp */
	{
		struct sctp_unrel_streams_param *usctp;
		int i;
		usctp = (struct sctp_unrel_streams_param *)ecn;
		usctp->ph.param_type = htons(SCTP_UNRELIABLE_STREAM);
		/* Calculate the size */
		i = sizeof(struct sctp_paramhdr);
		/* set it in the mbuf */
		m->m_len += i;
		/* and the param len */
		usctp->ph.param_length = htons(i);
	}
	m_at = m;
	/* now the addresses */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		struct ifnet *ifn;
		struct ifaddr *ifa;
		TAILQ_FOREACH(ifn,&ifnet, if_list) {
			if ((tcb->asoc.loopback_scope == 0) &&
			    (ifn->if_type == IFT_LOOP)) {
				/*
				 * Skip loopback devices if loopback_scope
				 * not set
				 */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if ((ifa->ifa_addr->sa_family == AF_INET) &&
				    (tcb->asoc.ipv4_addr_legal)) {
					struct sockaddr_in *sin;
					sin = (struct sockaddr_in *)ifa->ifa_addr;
					if (sin->sin_addr.s_addr == 0) {
						/* skip unspecifed addresses */
						continue;
					}
					if ((tcb->asoc.ipv4_local_scope == 0) &&
					    (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr))) {
						continue;
					}
					m_at = sctp_add_addr_to_mbuf(m_at, ifa);
				} else if ((ifa->ifa_addr->sa_family == AF_INET6) &&
					   (tcb->asoc.ipv6_addr_legal)) {
					struct sockaddr_in6 *sin6;
					struct in6_ifaddr *ifa6;

					ifa6 = (struct in6_ifaddr *)ifa;
				        /* ok to use deprecated addresses? */
					if (!ip6_use_deprecated) {
						if (ifa6->ia6_flags &
						    IN6_IFF_DEPRECATED) {
							continue;
						}
					}
					if (ifa6->ia6_flags &
					    (IN6_IFF_DETACHED |
					     IN6_IFF_ANYCAST |
					     IN6_IFF_NOTREADY)) {
						continue;
					}

					sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
						/* skip unspecifed addresses */
						continue;
					}
					if ((tcb->asoc.local_scope == 0) &&
					    (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))) {
						continue;
					}
					if ((tcb->asoc.site_scope == 0) &&
					    (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr))) {
						continue;
					}
					m_at = sctp_add_addr_to_mbuf(m_at, ifa);
				}
			}
		}
	} else {
		struct sctp_laddr *laddr;
		int cnt;
		cnt = 0;
		/* First, how many ? */
		LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa == NULL) {
				continue;
			}
			if (laddr->ifa->ifa_addr == NULL)
				continue;
			cnt++;
		}
		/* To get through a NAT we only list addresses if
		 * we have more than one. That way if you just
		 * bind a single address we let the source of the init
		 * dictate our address.
		 */
		if (cnt > 1) {
			LIST_FOREACH(laddr,&inp->sctp_addr_list, sctp_nxt_addr) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;
				m_at = sctp_add_addr_to_mbuf(m_at, laddr->ifa);
			}
		}
	}
	/* calulate the size and update pkt header and chunk header */
	m->m_pkthdr.len = 0;
	for (m_at = m; m_at; m_at = m_at->m_next) {
		if (m_at->m_next == NULL)
			m_last = m_at;
		m->m_pkthdr.len += m_at->m_len;
	}
	initm->msg.ch.chunk_length = htons((m->m_pkthdr.len-sizeof(struct sctphdr)));
	/* We pass 0 here to NOT set IP_DF if its IPv4, we
	 * ignore the return here since the timer will drive
	 * a retranmission.
	 */

	/* I don't expect this to execute but we will be safe here */
	padval = m->m_pkthdr.len % 4;
	if ((padval) && (m_last)) {
		/* The compiler worries that m_last may not be
		 * set even though I think it is impossible :->
		 * however we add m_last here just in case.
		 */
		int ret;
		ret = sctp_add_pad_tombuf(m_last, (4-padval));
		if (ret) {
			/* Houston we have a problem, no space */
			m_freem(m);
			return;
		}
		m->m_pkthdr.len += padval;
	}
	sctp_lowlevel_chunk_output(inp, tcb, net,
				   (struct sockaddr *)&net->ra._l_addr,
				   m, 0, 0, NULL, 0);
	sctp_timer_start(SCTP_TIMER_TYPE_INIT, inp, tcb, net);
	SCTP_GETTIME_TIMEVAL(&net->last_sent_time);
}

struct mbuf *
sctp_arethere_unrecognized_parameters(struct mbuf *in_initpkt,
				      int param_offset,
				      int *abort_processing)
{
	/* Given a mbuf containing an INIT or INIT-ACK
	 * with the param_offset being equal to the
	 * beginning of the params i.e. (iphlen + sizeof(struct sctp_init_msg)
	 * parse through the parameters to the end of the mbuf verifying
	 * that all parameters are known.
	 *
	 * For unknown parameters build and return a mbuf with
	 * UNRECOGNIZED_PARAMETER errors. If the flags indicate
	 * to stop processing this chunk stop, and set *abort_processing
	 * to 1.
	 *
	 * By having param_offset be pre-set to where parameters begin
	 * it is hoped that this routine may be reused in the future
	 * by new features.
	 */
	struct sctp_paramhdr *phdr, params;
	struct mbuf *mat,*op_err;
	int at;
	u_int16_t ptype, plen;
	int err_at;

	*abort_processing = 0;
	mat = in_initpkt;
	err_at = 0;
	at = param_offset;
	op_err = NULL;

	phdr = sctp_get_next_param(mat, at,&params, sizeof(params));
	while (phdr != NULL) {
		ptype = ntohs(phdr->param_type);
		plen = ntohs(phdr->param_length);
		if (plen == 0) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("sctp_output.c:Impossible length in parameter - 0\n");
			}
#endif
			break;
		}
		if ((ptype == SCTP_HEARTBEAT_INFO) ||
		    (ptype == SCTP_IPV4_ADDRESS) ||
		    (ptype == SCTP_IPV6_ADDRESS) ||
		    (ptype == SCTP_STATE_COOKIE) ||
		    (ptype == SCTP_UNRECOG_PARAM) ||
		    (ptype == SCTP_COOKIE_PRESERVE) ||
		    (ptype == SCTP_SUPPORTED_ADDRTYPE) ||
		    (ptype == SCTP_UNRELIABLE_STREAM) ||
		    (ptype == SCTP_ADD_IP_ADDRESS) ||
		    (ptype == SCTP_DEL_IP_ADDRESS) ||
		    (ptype == SCTP_ECN_CAPABLE) ||
		    (ptype == SCTP_ULP_ADAPTION) ||
		    (ptype == SCTP_ERROR_CAUSE_IND) ||
		    (ptype == SCTP_SET_PRIM_ADDR) ||
		    (ptype == SCTP_SUCCESS_REPORT) ||
		    (ptype == SCTP_ULP_ADAPTION)
			) {
			/* no skip it */
			at += SCTP_SIZE32(plen);
		} else if (ptype == SCTP_HOSTNAME_ADDRESS) {
			/* We can NOT handle HOST NAME addresses!! */
			struct sctp_unresolv_addr ura;
			*abort_processing = 1;
			if (op_err == NULL) {
				/* Ok need to try to get a mbuf */
				MGETHDR(op_err, M_DONTWAIT, MT_DATA);
				if (op_err) {
					op_err->m_len = 0;
					op_err->m_data += sizeof(struct sctp_chunkhdr);
				}
			}
			if (op_err) {
				ura.cause = htons(SCTP_CAUSE_UNRESOLV_ADDR);
				ura.length = htons(sizeof(ura) - 2);
				ura.addr_type = htons(SCTP_HOSTNAME_ADDRESS);
				ura.reserved = 0;
				m_copyback(op_err, err_at, sizeof(ura),(caddr_t)&ura);
				err_at += sizeof(ura);
			}
		} else {
			/* we do not recognize the parameter
			 * figure out what we do.
			 */
			if ((ptype & 0xc000) == 0x8000) {
				/* skip this chunk and continue processing */
				at += SCTP_SIZE32(plen);
			} else if ((ptype & 0xc000) == 0x0000) {
				/* Not recognized and I don't report */
				*abort_processing = 1;
				return (op_err);
			} else if ((ptype & 0xc000) == 0x4000) {
				/* Report and stop.
				 */
				*abort_processing = 1;
				if (op_err == NULL) {
					/* Ok need to try to get a mbuf */
					MGETHDR(op_err, M_DONTWAIT, MT_DATA);
					if (op_err) {
						op_err->m_len = 0;
						op_err->m_data += sizeof(struct sctp_chunkhdr);
					}
				}
				if (op_err) {
					/* If we have space */
					struct sctp_paramhdr s;
					s.param_type = htons(SCTP_UNRECOG_PARAM);
					s.param_length = htons(sizeof(struct sctp_paramhdr) + plen);
					m_copyback(op_err, err_at, sizeof(struct sctp_paramhdr), (caddr_t)&s);
					err_at += sizeof(struct sctp_paramhdr);
					m_copyback(op_err, err_at, plen,(caddr_t)phdr);
					err_at += plen;
					if (err_at % 4) {
						if (sctp_pad_lastmbuf(op_err,(4-(err_at % 4)))) {
							/* dump error */
							err_at = 0;
							m_freem(op_err);
							op_err = NULL;
						}
						err_at += (4-(err_at % 4));
					}
				}
				return (op_err);
			} else if ((ptype & 0xc000) == 0xc000) {
				/* Report and continue */
				if (op_err == NULL) {
					/* Ok need to try to get a mbuf */
					MGETHDR(op_err, M_DONTWAIT, MT_DATA);
					if (op_err) {
						op_err->m_len = 0;
						op_err->m_data += sizeof(struct sctp_chunkhdr);
					}
				}
				if (op_err) {
					/* If we have space */
					struct sctp_paramhdr s;
					s.param_type = htons(SCTP_UNRECOG_PARAM);
					s.param_length = htons(sizeof(struct sctp_paramhdr) + plen);
					m_copyback(op_err, err_at, sizeof(struct sctp_paramhdr),(caddr_t)&s);
					err_at += sizeof(struct sctp_paramhdr);
					m_copyback(op_err, err_at, plen,(caddr_t)phdr);
					err_at += plen;
					if (err_at % 4) {
						if (sctp_pad_lastmbuf(op_err, (4-(err_at % 4)))) {
							/* dump error */
							err_at = 0;
							m_freem(op_err);
							op_err = NULL;
						}
						err_at += (4-(err_at % 4));
					}
				}
				at += SCTP_SIZE32(plen);
			}
		}
		phdr = sctp_get_next_param(mat, at,&params, sizeof(params));
	}
	return (op_err);
}

static int
sctp_are_there_new_addresses(struct sctp_association *asoc,
			     struct mbuf *in_initpkt,
			     int iphlen)
{
	/*
	 * Given a INIT packet, look through the packet to verify that
	 * there are NO new addresses. As we go through the parameters
	 * add reports of any un-understood parameters that require an
	 * error.  Also we must return (1) to drop the packet if we see
	 * a un-understood parameter that tells us to drop the chunk.
	 */
	struct sockaddr_in sin4,*sa4;
	struct sockaddr_in6 sin6,*sa6;
	struct sockaddr *sa_touse;
	struct sockaddr *sa;
	struct sctp_paramhdr *phdr, params;
	struct ip *iph;
	struct mbuf *mat;
	int at;
	u_int16_t ptype, plen;
	int err_at, cmp_len;
	u_int8_t *addrp, fnd;
	struct sctp_nets *net;

	sin4.sin_family = AF_INET;
	sin6.sin6_family = AF_INET6;

	/* First what about the src address of the pkt ? */
	iph = mtod(in_initpkt, struct ip *);
	if (iph->ip_v == IPVERSION) {
		/* source addr is IPv4 */
		cmp_len = sizeof(struct in_addr);
		memcpy(&sin4.sin_addr,&iph->ip_src, cmp_len);
		sa_touse = (struct sockaddr *)&sin4;
	} else {
		/* source addr is IPv6 */
		struct ip6_hdr *ip6h;
		ip6h = mtod(in_initpkt, struct ip6_hdr *);
		cmp_len = sizeof(struct in6_addr);
		memcpy(&sin6.sin6_addr,&ip6h->ip6_src, cmp_len);
		sa_touse = (struct sockaddr *)&sin6;
	}
	fnd = 0;
	TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
		sa = (struct sockaddr *)&net->ra._l_addr;
		if (sa->sa_family == sa_touse->sa_family) {
			if (sa->sa_family == AF_INET) {
				sa4 = (struct sockaddr_in *)sa;
				if (memcmp(&sa4->sin_addr, &sin4.sin_addr,
					   cmp_len) == 0) {
					fnd = 1;
					break;
				}
			} else if (sa->sa_family == AF_INET6) {
				sa6 = (struct sockaddr_in6 *)sa;
				if (memcmp(&sa6->sin6_addr, &sin6.sin6_addr,
					   cmp_len) == 0) {
					fnd = 1;
					break;
				}
			}
		}
	}
	if (!fnd) {
		/* New address added! no need to look futher. */
		return (1);
	}
	/* Ok so far lets munge through the rest of the packet */
	mat = in_initpkt;
	err_at = 0;
	at = iphlen + sizeof(struct sctphdr) + sizeof(struct sctp_init_chunk);
	phdr = sctp_get_next_param(mat, at,&params, sizeof(params));
	while (phdr) {
		phdr = sctp_get_next_param(mat, at, &params, sizeof(params));
		ptype = ntohs(phdr->param_type);
		plen = ntohs(phdr->param_length);
		if ((ptype == SCTP_IPV4_ADDRESS) ||
		    (ptype == SCTP_IPV6_ADDRESS)) {
			at += SCTP_SIZE32(plen);
			addrp = (u_int8_t *)((caddr_t)phdr +
					     sizeof(struct sctp_paramhdr));
			if (ptype == SCTP_IPV4_ADDRESS) {
				cmp_len = sizeof(struct in_addr);
				memcpy(&sin4.sin_addr, addrp, cmp_len);
				sa_touse = (struct sockaddr *)&sin4;
			} else if (ptype == SCTP_IPV6_ADDRESS) {
				cmp_len = sizeof(struct in6_addr);
				memcpy(&sin6.sin6_addr, addrp, cmp_len);
				sa_touse = (struct sockaddr *)&sin6;
			} else {
				/* This should NEVER happen unless the
				 * compiler blows it :-)
				 */
				return (1);
			}
			/* ok, sa_touse points to one to check */
			fnd = 0;
			TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
				struct sockaddr *sa;
				sa = (struct sockaddr *)&net->ra._l_addr;
				if (sa->sa_family == sa_touse->sa_family) {
					if (sa->sa_family == AF_INET) {
						sa4 = (struct sockaddr_in *)sa;
						if (memcmp(&sa4->sin_addr,
							   &sin4.sin_addr,
							   cmp_len) == 0) {
							fnd = 1;
							break;
						}
					} else if (sa->sa_family == AF_INET6) {
						sa6 = (struct sockaddr_in6 *)sa;
						if (memcmp(&sa6->sin6_addr,
							   &sin6.sin6_addr,
							   cmp_len) == 0) {
							fnd = 1;
							break;
						}
					}
				}
			}
			if (!fnd) {
				/* New addr added! no need to look further */
				return (1);
			}
		} else {
			/* no skip it */
			at += SCTP_SIZE32(plen);
		}
		phdr = sctp_get_next_param(mat, at, &params, sizeof(params));
	}
	return (0);
}

/*
 * Given a MBUF chain that was sent into us containing an
 * INIT. Build a INIT-ACK with COOKIE and send back.
 * We assume that the in_initpkt has done a pullup to
 * include IPv6/4header, SCTP header and initial part of
 * INIT message (i.e. the struct sctp_init_msg).
 */
void
sctp_send_initiate_ack(struct sctp_inpcb *inp,
		       struct sctp_association *asoc,	/* may be NULL */
		       struct mbuf *in_initpkt,
		       int iphlen)
{
	struct mbuf *m,*m_at,*m_tmp,*m_cookie,*op_err,*m_last;
	struct sctp_init_msg *initm_in;
	struct sctp_init_msg *initack_mout;
	struct sctp_paramhdr *ecn;
	struct sockaddr_storage store;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ip *iph;
	struct ip6_hdr *ip6;
	struct sockaddr *to;
	struct sctp_state_cookie stc;
	u_short his_limit, i_want;
	int abort_flag, padval, sz_of, init_sz;

	m_last = NULL;
	if ((asoc != NULL) &&
	    ((asoc->state & SCTP_STATE_MASK) != SCTP_STATE_COOKIE_WAIT) &&
	    (sctp_are_there_new_addresses(asoc, in_initpkt, iphlen))) {
		/* new addresses, out of here in non-cookie-wait states */
		return;
	}
	abort_flag = 0;
	op_err = sctp_arethere_unrecognized_parameters(in_initpkt,
						       (iphlen +
							sizeof(struct sctp_init_msg)),
						       &abort_flag);
	if (abort_flag) {
		/* Ok, we have been asked to abort processing.
		 * For now we DO NOT send the op_err but free
		 * it instead. We probably should send it.
		 */
		if (op_err) {
			sctp_abort_association((struct sctp_inpcb *)NULL,
					       (struct sctp_tcb *)NULL,
					       in_initpkt,
					       iphlen, op_err);
		}
		return;
	}
	MGETHDR(m, M_DONTWAIT, MT_HEADER);
	if (m == NULL) {
		/* No memory, INIT timer will re-attempt. */
		if (op_err)
			m_freem(op_err);
		return;
	}
	MCLGET(m, M_DONTWAIT);
	if ((m->m_flags & M_EXT) != M_EXT) {
		/* Failed to get cluster buffer */
		if (op_err)
			m_freem(op_err);
		m_freem(m);
		return;
	}
	m->m_pkthdr.rcvif = 0;
	m->m_len = sizeof(struct sctp_init_msg);

	/* the time I built cookie */
	SCTP_GETTIME_TIMEVAL(&stc.time_entered);

	/* populate any tie tags */
	if (asoc != NULL) {
		stc.tie_tag_my_vtag = asoc->my_vtag;
		stc.tie_tag_peer_vtag = asoc->peer_vtag;
		stc.cookie_life = asoc->cookie_life;
	} else {
		stc.tie_tag_my_vtag = 0;
		stc.tie_tag_peer_vtag = 0;
		/* life I will award this cookie */
		stc.cookie_life = inp->sctp_ep.def_cookie_life;
	}
	/* If we wanted to honor cookie life extenstions
	 * we would add to stc.cookie_life. For now
	 * I think we should NOT honor any extension
	 */
	stc.site_scope = stc.local_scope = stc.loopback_scope = 0;
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
		struct inpcb *in_inp;
		/* Its a V6 socket */
		in_inp = (struct inpcb *)inp;
		stc.ipv6_addr_legal = 1;
		/* Now look at the binding flag to see if V4 will be legal */
		if (
#if defined(__FreeBSD__)
			(in_inp->inp_flags & IN6P_IPV6_V6ONLY)
#else
#if defined(__OpenBSD__)
			(0)	/* For openbsd we do dual bind only */
#else
			(((struct in6pcb *)in_inp)->in6p_flags & IN6P_IPV6_V6ONLY)
#endif
#endif
			== 0) {
			stc.ipv4_addr_legal = 1;
		} else {
			/* V4 addresses are NOT legal on the association */
			stc.ipv4_addr_legal = 0;
		}
	} else {
		/* Its a V4 socket, no - V6 */
		stc.ipv4_addr_legal = 1;
		stc.ipv6_addr_legal = 0;
	}

#ifdef SCTP_DONT_DO_PRIVADDR_SCOPE
	stc.ipv4_scope = 1;
#else
	stc.ipv4_scope = 0;
#endif
	initm_in = (struct sctp_init_msg *)(mtod(in_initpkt, caddr_t) + iphlen);
	/* now for scope setup */
	memset((caddr_t)&store, 0, sizeof(store));
	sin = (struct sockaddr_in *)&store;
	sin6 = (struct sockaddr_in6 *)&store;
	to = (struct sockaddr *)&store;
	iph = mtod(in_initpkt, struct ip *);
	if (iph->ip_v == IPVERSION) {
		struct in_addr addr;
		struct route rt;

		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);
		sin->sin_port = initm_in->sh.src_port;
		sin->sin_addr = iph->ip_src;
		/* lookup address */
		stc.address[0] = sin->sin_addr.s_addr;
		stc.address[1] = 0;
		stc.address[2] = 0;
		stc.address[3] = 0;
		stc.addr_type = SCTP_IPV4_ADDRESS;
		/* local from address */
		memset(&rt, 0, sizeof(rt));
		memcpy(&rt.ro_dst, sin, sizeof(*sin));
		addr = sctp_ipv4_source_address_selection(inp, NULL, sin, &rt,
							  NULL, 0);
		if (rt.ro_rt) {
			RTFREE(rt.ro_rt);
		}
		stc.laddress[0] = addr.s_addr;
		stc.laddress[1] = 0;
		stc.laddress[2] = 0;
		stc.laddress[3] = 0;
		stc.laddr_type = SCTP_IPV4_ADDRESS;
		/* scope_id is only for v6 */
		stc.scope_id = 0;
#ifndef SCTP_DONT_DO_PRIVADDR_SCOPE
		if (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr)) {
			stc.ipv4_scope = 1;
		}
#else
		stc.ipv4_scope = 1;
#endif
		/* Must use the address in this case */
		if (IN4_ISLOOPBACK_ADDRESS(&sin->sin_addr)) {
			stc.loopback_scope = 1;
			stc.ipv4_scope = 1;
			stc.site_scope = 1;
			stc.local_scope = 1;
		}
	} else {
		struct in6_addr addr;
		struct route rt;

		ip6 = mtod(in_initpkt, struct ip6_hdr *);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		sin6->sin6_port = initm_in->sh.src_port;
		sin6->sin6_addr = ip6->ip6_src;
		/* lookup address */
		memcpy((caddr_t)stc.address, (caddr_t)&sin6->sin6_addr,
		       sizeof(struct in6_addr));
		sin6->sin6_scope_id = 0;
		stc.addr_type = SCTP_IPV6_ADDRESS;
		stc.scope_id = 0;
		/* local from address */
		memset(&rt, 0, sizeof(rt));
		memcpy(&rt.ro_dst, sin6, sizeof(*sin6));
		addr = sctp_ipv6_source_address_selection(inp, NULL, sin6, &rt,
							  NULL, 0);
		if (rt.ro_rt) {
			RTFREE(rt.ro_rt);
		}
		memcpy((caddr_t)stc.laddress, (caddr_t)&addr,
		       sizeof(struct in6_addr));
		stc.laddr_type = SCTP_IPV6_ADDRESS;
		if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
			stc.loopback_scope = 1;
			stc.local_scope = 1;
			stc.site_scope = 1;
			stc.ipv4_scope = 1;
		} else if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			struct sockaddr_in6 src;
			/*
			 * If the new destination is a LINK_LOCAL we must have
			 * common both site and local scope. Don't set local
			 * scope though since we must depend on the source to
			 * be added implicitly. We cannot assure just because
			 * we share one link that all links are common.
			 */
			stc.local_scope = 0;
			stc.site_scope = 1;
			/* pull out the scope_id from the incoming packet */
			if (ip6_getpktaddrs(in_initpkt, src, NULL)) {
				/* hmm... this is bad- can't get the scope! */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
					printf("send_initiate_ack: can't get scope of link-local addr\n");
				}
#endif /* SCTP_DEBUG */
				return;	/* FIX: ??? send op_err? */
			}
			sin6->sin6_scope_id = src.sin6_scope_id;
			stc.scope_id = src.sin6_scope_id;
		} else if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
			/* If the new destination is SITE_LOCAL
			 * then we must have site scope in common.
			 */
			stc.site_scope = 1;
		}
	}
	/* Now lets put the SCTP header in place */
	initack_mout = mtod(m, struct sctp_init_msg *);
	initack_mout->sh.src_port = inp->sctp_lport;
	initack_mout->sh.dest_port = initm_in->sh.src_port;
	initack_mout->sh.v_tag = initm_in->msg.init.initiate_tag;
	/* Save it off for quick ref */
	stc.peers_vtag = initm_in->msg.init.initiate_tag;
	initack_mout->sh.checksum = 0;	/* calculate later */

	/* now the chunk header */
	initack_mout->msg.ch.chunk_type = SCTP_INITIATION_ACK;
	initack_mout->msg.ch.chunk_flags = 0;
	/* fill in later from mbuf we build */
	initack_mout->msg.ch.chunk_length = 0;
	/* place in my tag */
	if ((asoc != NULL) &&
	    (((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_WAIT) ||
	     ((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_ECHOED))) {
		/* re-use the v-tags and init-seq here */
		initack_mout->msg.init.initiate_tag = htonl(asoc->my_vtag);
		initack_mout->msg.init.initial_tsn = htonl(asoc->init_seq_number);
	} else {
		initack_mout->msg.init.initiate_tag = htonl(sctp_select_a_tag(inp));
		/* get a TSN to use too */
		initack_mout->msg.init.initial_tsn = htonl(sctp_select_initial_TSN(&inp->sctp_ep));
	}

	/* set up some of the credits. */
	initack_mout->msg.init.a_rwnd = htonl(inp->sctp_socket->so_rcv.sb_hiwat);
	/* set what I want */
	his_limit = ntohs(initm_in->msg.init.num_inbound_streams);
	/* choose what I want */
	if (asoc != NULL) {
		if (asoc->streamoutcnt > inp->sctp_ep.pre_open_stream_count) {
			i_want = asoc->streamoutcnt;
		} else {
			i_want = inp->sctp_ep.pre_open_stream_count;
		}
	} else {
		i_want = inp->sctp_ep.pre_open_stream_count;
	}
	if (his_limit < i_want) {
		/* I Want more :< */
		initack_mout->msg.init.num_outbound_streams = initm_in->msg.init.num_inbound_streams;
	} else {
		/* I can have what I want :> */
		initack_mout->msg.init.num_outbound_streams = htons(i_want);
	}
	/* tell him his limt. */
	initack_mout->msg.init.num_inbound_streams = htons(inp->sctp_ep.max_open_streams_intome);
	/* setup the ECN pointer */

	if (inp->sctp_flags & SCTP_PCB_FLAGS_ADAPTIONEVNT) {
		struct sctp_adaption_layer_indication *ali;
		ali = (struct sctp_adaption_layer_indication *)((caddr_t)initack_mout +
								sizeof(struct sctp_init_msg));
		ali->ph.param_type = htons(SCTP_ULP_ADAPTION);
		ali->ph.param_length = htons(sizeof(struct sctp_adaption_layer_indication));
		ali->indication = ntohl(inp->sctp_ep.adaption_layer_indicator);
		m->m_len += sizeof(*ali);
		ecn = (struct sctp_paramhdr *)((caddr_t)ali + sizeof(*ali));
	} else {
		ecn = (struct sctp_paramhdr *)((caddr_t)initack_mout +
					       sizeof(struct sctp_init_msg));
	}
	ecn->param_type = htons(SCTP_ECN_CAPABLE);
	ecn->param_length = htons(sizeof(*ecn));
	m->m_len += sizeof(*ecn);
	ecn++;
	{
		struct sctp_unrel_streams_param *usctp;
		int i;
		usctp = (struct sctp_unrel_streams_param *)ecn;
		usctp->ph.param_type = htons(SCTP_UNRELIABLE_STREAM);
		/* Calculate the size */
		i = sizeof(struct sctp_paramhdr);
		/* set it in the mbuf */
		m->m_len += i;
		/* and the param len */
		usctp->ph.param_length = htons(i);
	}
	m_at = m;
	/* tack on the operational error if present */
	if (op_err) {
		while (m_at->m_next != NULL) {
			m_at = m_at->m_next;
		}
		m_at->m_next = op_err;
		while (m_at->m_next != NULL) {
			m_at = m_at->m_next;
		}
	}
	/* now the addresses */
	if (inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		struct ifnet *ifn;
		struct ifaddr *ifa;
		TAILQ_FOREACH(ifn,&ifnet, if_list) {
			if ((stc.loopback_scope == 0) &&
			   (ifn->if_type == IFT_LOOP)) {
				/*
				 * Skip loopback devices if loopback_scope
				 * not set
				 */
				continue;
			}
			TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
				if ((ifa->ifa_addr->sa_family == AF_INET) &&
				   (stc.ipv4_addr_legal)) {
					struct sockaddr_in *sin;
					sin = (struct sockaddr_in *)ifa->ifa_addr;
					if (sin->sin_addr.s_addr == 0) {
						/* skip unspecifed addresses */
						continue;
					}
					if ((stc.ipv4_scope == 0) &&
					   (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr))) {
						continue;
					}
					m_at = sctp_add_addr_to_mbuf(m_at, ifa);
				} else if ((ifa->ifa_addr->sa_family == AF_INET6) &&
					 (stc.ipv6_addr_legal)) {
					struct sockaddr_in6 *sin6;
					struct in6_ifaddr *ifa6;

					ifa6 = (struct in6_ifaddr *)ifa;
				        /* ok to use deprecated addresses? */
					if (!ip6_use_deprecated) {
						if (ifa6->ia6_flags &
						    IN6_IFF_DEPRECATED) {
							continue;
						}
					}
					if (ifa6->ia6_flags &
					    (IN6_IFF_DETACHED |
					     IN6_IFF_ANYCAST |
					     IN6_IFF_NOTREADY))
						continue;
					sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
						/* skip unspecifed addresses */
						continue;
					}
					if ((stc.local_scope == 0) &&
					   (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))) {
						continue;
					}
					if ((stc.site_scope == 0) &&
					   (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr))) {
						continue;
					}
					m_at = sctp_add_addr_to_mbuf(m_at, ifa);
				}
			}
		}
	} else {
		struct sctp_laddr *laddr;
		int cnt;
		cnt = 0;
		/* First, how many ? */
		LIST_FOREACH(laddr,&inp->sctp_addr_list, sctp_nxt_addr) {
			if (laddr->ifa == NULL) {
				continue;
			}
			if (laddr->ifa->ifa_addr == NULL)
				continue;
			cnt++;
		}
		/* If we bind a single address only we won't list
		 * any. This way you can get through a NAT
		 */
		if (cnt > 1) {
			LIST_FOREACH(laddr,&inp->sctp_addr_list, sctp_nxt_addr) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
						printf("Help I have fallen and I can't get up!\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr == NULL)
					continue;
				m_at = sctp_add_addr_to_mbuf(m_at, laddr->ifa);
			}
		}
	}
	/* Get total size of init packet */

	init_sz = sz_of = ntohs(initm_in->msg.ch.chunk_length);
	/* pre-calulate the size and update pkt header and chunk header */
	m->m_pkthdr.len = 0;
	for (m_tmp = m; m_tmp; m_tmp = m_tmp->m_next) {
		m->m_pkthdr.len += m_tmp->m_len;
		if (m_tmp->m_next == NULL) {
			/* m_tmp should now point to last one */
			break;
		}
	}
	/*
	 * Figure now the size of the cookie. We know the size of the
	 * INIT-ACK. The Cookie is going to be the size of INIT, INIT-ACK,
	 * COOKIE-STRUCTURE and SIGNATURE.
	 */

	/*
	 * take our earlier INIT calc and add in the sz we just calculated
	 * minus the size of the sctphdr (its not included in chunk size
	 */

	/* add once for the INIT-ACK */
	sz_of += (m->m_pkthdr.len - sizeof(struct sctphdr));

	/* add a second time for the INIT-ACK in the cookie */
	sz_of += (m->m_pkthdr.len - sizeof(struct sctphdr));

	/* Now add the cookie header and cookie message struct */
	sz_of += sizeof(struct sctp_state_cookie_param);
	/* ...and add the size of our signature */
	sz_of += SCTP_SIGNATURE_SIZE;
	initack_mout->msg.ch.chunk_length = htons(sz_of);

	/* Now we must build a cookie */
	m_cookie = sctp_add_cookie(inp, in_initpkt, iphlen, m_at, &stc,
				   init_sz);
	if (m_cookie == NULL) {
		/* memory problem */
		m_freem(m);
		return;
	}
	/* Now append the cookie to the end and update the space/size */
	m_tmp->m_next = m_cookie;
	/* now a walk back through all of the mbufs to count size */
	m->m_pkthdr.len = 0;
	for (m_tmp = m; m_tmp; m_tmp = m_tmp->m_next) {
		if (m_tmp->m_next == NULL)
			m_last = m_tmp;
		m->m_pkthdr.len += m_tmp->m_len;
	}
	/*
	 * set the init ack chunk size
	 * note, this is also for the init ack in the cookie!
	 */
	initack_mout->msg.ch.chunk_length = htons(m->m_pkthdr.len -
						  sizeof(struct sctphdr));

	/*
	 * We pass 0 here to NOT set IP_DF if its IPv4, we ignore the
	 * return here since the timer will drive a retranmission.
	 */
	padval = m->m_pkthdr.len % 4;
	if ((padval) && (m_last)) {
		/* see my previous comments on m_last */
		int ret;
		ret = sctp_add_pad_tombuf(m_last, (4-padval));
		if (ret) {
			/* Houston we have a problem, no space */
			m_freem(m);
			return;
		}
		m->m_pkthdr.len += padval;
	}
	sctp_lowlevel_chunk_output(inp, NULL, NULL, to, m, 0, 0, NULL, 0);
}


static void
sctp_insert_on_wheel(struct sctp_association *asoc,
		     struct sctp_stream_out *strq)
{
	struct sctp_stream_out *stre,*strn;
	stre = TAILQ_FIRST(&asoc->out_wheel);
	if (stre == NULL) {
		/* only one on wheel */
		TAILQ_INSERT_HEAD(&asoc->out_wheel, strq, next_spoke);
		return;
	}
	for (; stre; stre = strn) {
		strn = TAILQ_NEXT(stre, next_spoke);
		if (stre->stream_no > strq->stream_no) {
			TAILQ_INSERT_BEFORE(stre, strq, next_spoke);
			return;
		} else if (stre->stream_no == strq->stream_no) {
			/* huh, should not happen */
			return;
		} else if (strn == NULL) {
			/* next one is null */
			TAILQ_INSERT_AFTER(&asoc->out_wheel, stre, strq,
					   next_spoke);
		}
	}
}

static void
sctp_remove_from_wheel(struct sctp_association *asoc,
		       struct sctp_stream_out *strq)
{
	/* take off and then setup so we know it is not on the wheel */
	TAILQ_REMOVE(&asoc->out_wheel, strq, next_spoke);
	strq->next_spoke.tqe_next = NULL;
	strq->next_spoke.tqe_prev = NULL;
}

extern struct sctp_epinfo sctppcbinfo;

static int
sctp_msg_append(struct sctp_tcb *tcb,
		struct sctp_nets *net,
		struct mbuf *m,
		struct sctp_sndrcvinfo *srcv)
{
	struct sctp_association *asoc;
	struct sctp_stream_out *strq;
	struct sctp_tmit_chunk *chk;
	struct sctpchunk_listhead tmp;
	struct sctp_tmit_chunk template;
	struct mbuf *n,*f;
	struct mbuf *mm;
	int dataout, siz;
	int mbcnt=0;

	if ((tcb == NULL) || (net == NULL) || (m == NULL) || (srcv == NULL)) {
		/* Software fault, you blew it on the call */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("software error in sctp_msg_append:1\n");
			printf("tcb:%x net:%x m:%x srcv:%x\n",
			       (u_int)tcb,
			       (u_int)net,
			       (u_int)m,
			       (u_int)srcv);
		}
#endif
		if (m)
			m_freem(m);
		return (EFAULT);
	}
	asoc = &tcb->asoc;
	if (srcv->sinfo_flags & MSG_ABORT) {
		if (((asoc->state & SCTP_STATE_MASK) != SCTP_STATE_COOKIE_WAIT) &&
		    ((asoc->state & SCTP_STATE_MASK) != SCTP_STATE_COOKIE_ECHOED)) {
			/* It has to be up before we abort */
			/* how big is the user initiated abort? */
			if ((m->m_flags & M_PKTHDR) && (m->m_pkthdr.len)) {
				dataout = m->m_pkthdr.len;
			} else {
				/* we must count */
				dataout = 0;
				for (n = m; n; n = n->m_next) {
					dataout += n->m_len;
				}
			}
			M_PREPEND(m, sizeof(struct sctp_paramhdr), M_DONTWAIT);
			if (m) {
				struct sctp_paramhdr *ph;
				ph = mtod(m, struct sctp_paramhdr *);
				ph->param_type = htons(SCTP_CAUSE_USER_INITIATED_ABT);
				ph->param_length = htons((sizeof(struct sctp_paramhdr) + dataout));
			}
			sctp_abort_an_association(tcb->sctp_ep, tcb, SCTP_RESPONSE_TO_USER_REQ, m);
		} else {
			/* Only free if we don't send an abort */
			if (m)
				m_freem(m);
		}
		return (0);
	}
	if (((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_SENT) ||
	    ((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_ACK_SENT) ||
	    ((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_RECEIVED) ||
	    (asoc->state & SCTP_STATE_SHUTDOWN_PENDING)) {
		/* got data while shutting down */
		if (m)
			m_freem(m);
		return (ECONNRESET);
	}

	if (srcv->sinfo_stream >= asoc->streamoutcnt) {
		/* Invalid stream number */
		if (m)
			m_freem(m);
		return (EINVAL);
	}
	if (asoc->strmout == NULL) {
		/* huh? software error */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("software error in sctp_msg_append:2\n");
		}
#endif
		if (m)
			m_freem(m);
		return (EFAULT);
	}
	strq = &asoc->strmout[srcv->sinfo_stream];
	/* how big is it ? */
	if ((m->m_flags & M_PKTHDR) && (m->m_pkthdr.len)) {
		dataout = m->m_pkthdr.len;
	} else {
		/* we must count */
		dataout = 0;
		for (n = m; n; n = n->m_next) {
			dataout += n->m_len;
		}
	}
	if (dataout > tcb->sctp_socket->so_snd.sb_hiwat) {
		/* It will NEVER fit */
		return (EMSGSIZE);
	}
	if ((srcv->sinfo_flags & MSG_EOF) &&
	    (tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE) &&
	    (dataout == 0)
		) {
		goto zap_by_it_all;
	}
	if ((sbspace(&tcb->sctp_socket->so_snd) <
	     (dataout + asoc->total_output_queue_size)) ||
	    (asoc->total_output_mbuf_queue_size >
	     tcb->sctp_socket->so_snd.sb_mbmax)
		) {
		/* XXX Buffer space hunt for data to skip */
		if ((asoc->peer_supports_usctp) && (asoc->sent_queue_cnt_removeable > 0)) {
			TAILQ_FOREACH(chk,&asoc->sent_queue, sctp_next) {
				/*
				 * Look for chunks marked with the PR_SCTP
				 * flag AND the buffer space flag. If the one
				 * being sent is equal or greater priority then
				 * purge the old one and free some space.
				 */
				if ((chk->flags & (SCTP_PR_SCTP_ENABLED |
						   SCTP_PR_SCTP_BUFFER)) ==
				    (SCTP_PR_SCTP_ENABLED|SCTP_PR_SCTP_BUFFER)) {
					/*
					 * This one is PR-SCTP AND buffer space
					 * limited type
					 */
					if (chk->rec.data.timetodrop.tv_sec >= srcv->sinfo_timetolive) {
						/* Lower numbers equates to
						 * higher priority so if the
						 * one we are looking at has a
						 * larger or equal priority we
						 * want to drop the data and
						 * NOT retransmit it.
						 */
						if (chk->data) {
							/* We release the
							 * book_size if the
							 * mbuf is here
							 */
							sctp_free_bufspace(tcb,
									   asoc, chk);
#ifdef SCTP_DEBUG
							if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
								printf("--total out:%d total_mbuf_out:%d\n",
								       (int)asoc->total_output_queue_size,
								       (int)asoc->total_output_mbuf_queue_size);
							}
#endif
							sctp_ulp_notify(SCTP_NOTIFY_DG_FAIL, tcb,
									(SCTP_RESPONSE_TO_USER_REQ|SCTP_NOTIFY_DATAGRAM_SENT),
									chk);
							m_freem(chk->data);
							sctp_sowwakeup(tcb->sctp_ep, tcb->sctp_socket);
						}
						chk->data = NULL;
					}
				}
			}
		}
		if ((sbspace(&tcb->sctp_socket->so_snd) <
		     (dataout + asoc->total_output_queue_size)) ||
		    (asoc->total_output_mbuf_queue_size >
		     tcb->sctp_socket->so_snd.sb_mbmax)) {
			/* Now did we free up enough room? */
			if ((tcb->sctp_socket->so_state & SS_NBIO) == 0) {
				struct socket *so;
				struct sctp_inpcb *inp;
				/*
				 * We store off a pointer to the endpoint.
				 * Since on return from this we must check to
				 * see if an so_error is set. If so we may have
				 * been reset and our tcb destroyed. Returning
				 * an error will cause the correct error return
				 * through and fix this all.
				 */
				so = tcb->sctp_socket;
				inp = tcb->sctp_ep;
				while ((sbspace(&tcb->sctp_socket->so_snd) <
					(dataout + asoc->total_output_queue_size)) ||
				       (asoc->total_output_mbuf_queue_size >
					tcb->sctp_socket->so_snd.sb_mbmax)) {
					int err, ret;
					/*
					 * Not sure how else to do this since
					 * the level we suspended at is not
					 * known deep down where we are. I will
					 * drop to spl0() so that others can
					 * get in.
					 */
					ret = err = 0;
					inp->sctp_tcb_at_block = (void *)tcb;
					inp->error_on_block = 0;
					sbunlock(&so->so_snd);
					err = sbwait(&tcb->sctp_socket->so_snd);
					/*
					 * XXX: This is ugly but I have
					 * recreated most of what goes on to
					 * block in the sb. UGHH
					 * May want to add the bit about being
					 * no longer connected.. but this then
					 * further dooms the UDP model NOT to
					 * allow this.
					 */
					inp->sctp_tcb_at_block = 0;
					if (inp->error_on_block) {
						err = inp->error_on_block;
						goto out;
					}
					if (so->so_error) {
						ret = so->so_error;
					} else if (err) {
					out:
						ret = err;
					}
					if (so->so_error || err) {
						if (m)
							m_freem(m);
						return (err);
					}
					err = sblock(&so->so_snd, M_WAITOK);
					if (err)
						goto out;
					/*
					 * Otherwise we cycle back and recheck
					 * the space
					 */
					if (so->so_state & SS_CANTSENDMORE) {
						err = EPIPE;
						goto out;
					}
					if (so->so_error) {
						err = so->so_error;
						goto out;
					}
				}
			} else {
				if (m)
					/* nope */
					m_freem(m);
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
					printf("EAGAIN:sbspace:%d < (%d + %d) || (%d > %d)\n",
					       (int)sbspace(&tcb->sctp_socket->so_snd),
					       (int)dataout,(int)asoc->total_output_queue_size,
					       (int)asoc->total_output_mbuf_queue_size,
					       (int)tcb->sctp_socket->so_snd.sb_mbmax);
				}
#endif
				return (EAGAIN);
			}
		}
	}
	/* If we have a packet header fix it if it was broke */
	if (m->m_flags & M_PKTHDR) {
		m->m_pkthdr.len = dataout;
	}
	/* use the smallest one, user set value or 
	 * smallest mtu of the assoc
	 */
	if (tcb->sctp_ep->sctp_frag_point >= asoc->smallest_mtu) {
		siz = asoc->smallest_mtu - SCTP_MAX_OVERHEAD;
	} else {
		siz = tcb->sctp_ep->sctp_frag_point - SCTP_MAX_OVERHEAD;
	}
	if (siz % 4) {
		/* make it an even word boundary please */
		siz -= (siz % 4);
	}
	if ((dataout) && (dataout <= siz)) {
		/* Fast path */
#if defined(__FreeBSD__)
		chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
							 PR_NOWAIT);
#endif
		if (chk == NULL) {
			m_freem(m);
			return (ENOMEM);
		}
		if ((tcb->asoc.peer_supports_usctp) &&
		    (srcv->sinfo_flags & MSG_PR_SCTP) &&
		    (srcv->sinfo_timetolive > 0)
			) {
		        chk->flags = SCTP_PR_SCTP_ENABLED;
			if (srcv->sinfo_flags & MSG_PR_BUFFER) {
				/*
				 * Time to live is a priority stored in tv_sec
				 * when doing the buffer drop thing.
				 */
			        chk->flags |= SCTP_PR_SCTP_BUFFER;
				asoc->sent_queue_cnt_removeable++;
				chk->rec.data.timetodrop.tv_sec = srcv->sinfo_timetolive;
			} else {
				int sec, usec;
				SCTP_GETTIME_TIMEVAL(&chk->rec.data.timetodrop);
				sec = (srcv->sinfo_timetolive/1000000);
				chk->rec.data.timetodrop.tv_sec += sec;
				/* Add in the micro seconds */
				usec = (srcv->sinfo_timetolive % 1000000);
				chk->rec.data.timetodrop.tv_usec += usec;
				if (chk->rec.data.timetodrop.tv_usec > 1000000) {
			        /* add in the carry over */
					chk->rec.data.timetodrop.tv_usec -= 1000000;
					chk->rec.data.timetodrop.tv_sec++;
				}
			}
		} else {
			chk->flags = 0;
		}
		chk->rec.data.stream_seq = strq->next_sequence_sent;
		chk->rec.data.TSN_seq = 0;	/* not yet assigned */
		chk->rec.data.stream_number = srcv->sinfo_stream;
		chk->rec.data.payloadtype = srcv->sinfo_ppid;
		chk->rec.data.context = srcv->sinfo_context;
		chk->rec.data.doing_fast_retransmit = 0;
		chk->rec.data.ect_nonce = 0;
		if (srcv->sinfo_flags & MSG_ADDR_OVER) {
			chk->whoTo = net;
		} else {
			if (asoc->primary_destination)
				chk->whoTo = asoc->primary_destination;
			else {
				/* TSNH */
				chk->whoTo = net;
			}
		}
		/* the actual chunk flags */
		if (srcv->sinfo_flags & MSG_UNORDERED) {
			chk->rec.data.rcv_flags = (SCTP_DATA_FIRST_FRAG|
						   SCTP_DATA_LAST_FRAG|
						   SCTP_DATA_UNORDERED);
		} else {
			chk->rec.data.rcv_flags = (SCTP_DATA_FIRST_FRAG|
						   SCTP_DATA_LAST_FRAG);
		}

		/* no flags yet, FRAGMENT_OK goes here */
		sctppcbinfo.ipi_count_chunk++;
		sctppcbinfo.ipi_gencnt_chunk++;
		chk->whoTo->ref_count++;
		chk->data = m;
		/* Total in the MSIZE */
		for (mm = chk->data; mm; mm = mm->m_next) {
			mbcnt += MSIZE;
			if (mm->m_flags & M_EXT) {
				mbcnt += chk->data->m_ext.ext_size;;
			}
		}
		/* fix up the send_size if it is not present */
		chk->send_size = dataout;
		chk->book_size = chk->send_size;
		/* ok, we are commited */
		if ((srcv->sinfo_flags & MSG_UNORDERED) == 0) {
			/* bump the ssn if we are unordered. */
			strq->next_sequence_sent++;
		}
		/* Mark the first/last flags. This will
		 * result int a 3 for a single item on the list
		 */
		/* now break any chains on the queue and
		 * move it to the streams actual queue.
		 */
		chk->data->m_nextpkt = 0;
		TAILQ_INSERT_TAIL(&strq->outqueue, chk, sctp_next);
		/* now check if this stream is on the wheel */
		if ((strq->next_spoke.tqe_next == NULL) &&
		    (strq->next_spoke.tqe_prev == NULL)) {
			/* Insert it on the wheel since it is not
			 * on it currently
			 */
			sctp_insert_on_wheel(asoc, strq);
		}
	} else if ((dataout) && (dataout > siz)) {
		/* Slow path */
		if ((tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_NO_FRAGMENT) &&
		    (dataout > siz)) {
			m_freem(m);
			return (ENOBUFS);
		}
		/* setup the template */
		bzero(&template, sizeof(template));
		template.sent = SCTP_DATAGRAM_UNSENT;
		if ((tcb->asoc.peer_supports_usctp) &&
		    (srcv->sinfo_flags & MSG_PR_SCTP) &&
		    (srcv->sinfo_timetolive > 0)
			) {
			/* If:
			 *  Peer supports PR-SCTP
			 *  The flags is set against this send for PR-SCTP
			 *  And timetolive is a postive value, zero is reserved
			 *     to mean a reliable send for both buffer/time
			 *     related one.
			 */
			if (srcv->sinfo_flags & MSG_PR_BUFFER) {
				/*
				 * Time to live is a priority stored in tv_sec
				 * when doing the buffer drop thing.
				 */
				template.rec.data.timetodrop.tv_sec = srcv->sinfo_timetolive;
			} else {
				u_int32_t sec, usec;
				SCTP_GETTIME_TIMEVAL(&template.rec.data.timetodrop);
				sec = (srcv->sinfo_timetolive/1000000);
				template.rec.data.timetodrop.tv_sec += sec;
				/* Add in the micro seconds */
				usec = (srcv->sinfo_timetolive % 1000000);
				template.rec.data.timetodrop.tv_usec += usec;
				if (template.rec.data.timetodrop.tv_usec > 1000000) {
					/* add in the carry over */
					template.rec.data.timetodrop.tv_usec -= 1000000;
					template.rec.data.timetodrop.tv_sec++;
				}
			}
		}
		template.rec.data.stream_seq = strq->next_sequence_sent;
		template.rec.data.TSN_seq = 0;	/* not yet assigned */
		template.rec.data.stream_number = srcv->sinfo_stream;
		template.rec.data.payloadtype = srcv->sinfo_ppid;
		template.rec.data.context = srcv->sinfo_context;
		template.rec.data.doing_fast_retransmit = 0;
		template.rec.data.ect_nonce = 0;
		n = m;
		while (dataout > siz) {
			/*
			 * We can wait since this is called from the user
			 * send side
			 */
			n->m_nextpkt = m_split(n, siz, M_WAIT);
			if (m->m_nextpkt == NULL) {
				goto no_membad;
			}
			dataout -= siz;
			n = n->m_nextpkt;
		}
		/*
		 * ok, now we have a chain on m where m->m_nextpkt points to
		 * the next chunk and m/m->m_next chain is the piece to send.
		 * We must go through the chains and thread them on to
		 * sctp_tmit_chunk chains and place them all on the stream
		 * queue, breaking the m->m_nextpkt pointers as we go.
		 */
		n = m;
		TAILQ_INIT(&tmp);

		if (srcv->sinfo_flags & MSG_ADDR_OVER) {
			template.whoTo = net;
		} else {
			if (asoc->primary_destination)
				template.whoTo = asoc->primary_destination;
			else {
				/* TSNH */
				template.whoTo = net;
			}
		}
		/* the actual chunk flags */
		if (srcv->sinfo_flags & MSG_UNORDERED) {
			template.rec.data.rcv_flags = SCTP_DATA_UNORDERED;
		} else {
			template.rec.data.rcv_flags = 0;
		}
		/* no flags yet, FRAGMENT_OK goes here */
		template.flags = 0;
		/* PR sctp flags */
		if (tcb->asoc.peer_supports_usctp) {
			if (srcv->sinfo_timetolive > 0) {
				/*
				 * We only set the flag if timetolive (or
				 * priority) was set to a positive number.
				 * Zero is reserved specifically to be
				 * EXCLUDED and sent reliable.
				 */
				if (srcv->sinfo_flags & MSG_PR_SCTP) {
					template.flags |= SCTP_PR_SCTP_ENABLED;
				}
				if (srcv->sinfo_flags & MSG_PR_BUFFER) {
					template.flags |= SCTP_PR_SCTP_BUFFER;
				}
			}
		}
		template.asoc = asoc;

		while (n) {
			/*
			 * first go through and allocate a sctp_tmit chunk
			 * for each chunk piece
			 */
#if defined(__FreeBSD__)
			chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
								 PR_NOWAIT);
#endif

			if (chk == NULL) {
				/*
				 * ok we must spin through and dump anything
				 * we have allocated and then jump to the
				 * no_membad
				 */
				chk = TAILQ_FIRST(&tmp);
				while (chk) {
					TAILQ_REMOVE(&tmp, chk, sctp_next);
#if defined(__FreeBSD__)
					zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
					pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
					sctppcbinfo.ipi_count_chunk--;
					if ((int)sctppcbinfo.ipi_count_chunk < 0) {
						panic("Chunk count is negative");
					}
					sctppcbinfo.ipi_gencnt_chunk++;
					chk = TAILQ_FIRST(&tmp);
				}
				goto no_membad;
			}
			sctppcbinfo.ipi_count_chunk++;
			sctppcbinfo.ipi_gencnt_chunk++;
			*chk = template;
			chk->whoTo->ref_count++;
			chk->data = n;
			/* Total in the MSIZE */
			for (mm = chk->data; mm; mm = mm->m_next) {
				mbcnt += MSIZE;
				if (mm->m_flags & M_EXT) {
					mbcnt += chk->data->m_ext.ext_size;;
				}
			}
			/* now fix the chk->send_size */
			if (chk->data->m_flags & M_PKTHDR) {
				chk->send_size = chk->data->m_pkthdr.len;
			} else {
				struct mbuf *nn;
				chk->send_size = 0;
				for (nn = chk->data; nn; nn = nn->m_next) {
					chk->send_size += nn->m_len;
				}
			}
			chk->book_size = chk->send_size;
			if (chk->flags && SCTP_PR_SCTP_BUFFER) {
				asoc->sent_queue_cnt_removeable++;
			}
			n = n->m_nextpkt;
			TAILQ_INSERT_TAIL(&tmp, chk, sctp_next);
		}
		/* now that we have enough space for all de-couple the
		 * chain of mbufs by going through our temp array
		 * and breaking the pointers.
		 */
		/* ok, we are commited */
		if ((srcv->sinfo_flags & MSG_UNORDERED) == 0) {
			/* bump the ssn if we are unordered. */
			strq->next_sequence_sent++;
		}
		/* Mark the first/last flags. This will
		 * result int a 3 for a single item on the list
		 */
		chk = TAILQ_FIRST(&tmp);
		chk->rec.data.rcv_flags |= SCTP_DATA_FIRST_FRAG;
		chk = TAILQ_LAST(&tmp, sctpchunk_listhead);
		chk->rec.data.rcv_flags |= SCTP_DATA_LAST_FRAG;
		/* now break any chains on the queue and
		 * move it to the streams actual queue.
		 */
		chk = TAILQ_FIRST(&tmp);
		while (chk) {
			chk->data->m_nextpkt = 0;
			TAILQ_REMOVE(&tmp, chk, sctp_next);
			TAILQ_INSERT_TAIL(&strq->outqueue, chk, sctp_next);
			chk = TAILQ_FIRST(&tmp);
		}
		/* now check if this stream is on the wheel */
		if ((strq->next_spoke.tqe_next == NULL) &&
		    (strq->next_spoke.tqe_prev == NULL)) {
			/* Insert it on the wheel since it is not
			 * on it currently
			 */
			sctp_insert_on_wheel(asoc, strq);
		}
	} else {
		if (m)
			m_freem(m);
		m = NULL;
	}
	/* has a SHUTDOWN been (also) requested by the user on this assoc? */
 zap_by_it_all:
	if ((srcv->sinfo_flags & MSG_EOF) &&
	    (tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_UDPTYPE)) {
	  
		int some_on_streamwheel = 0;

		if (!TAILQ_EMPTY(&asoc->out_wheel)) {
			/* Check to see if some data queued */
			struct sctp_stream_out *outs;
			TAILQ_FOREACH(outs,&asoc->out_wheel, next_spoke) {
				if (!TAILQ_EMPTY(&outs->outqueue)) {
					some_on_streamwheel = 1;
					break;
				}
			}
		}

		if (TAILQ_EMPTY(&asoc->send_queue) &&
		    TAILQ_EMPTY(&asoc->sent_queue) &&
		    (some_on_streamwheel == 0)) {
			/* there is nothing queued to send, so I'm done... */
			if ((asoc->state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_SENT) {
				/* only send SHUTDOWN the first time through */
				sctp_send_shutdown(tcb, tcb->asoc.primary_destination);
				asoc->state = SCTP_STATE_SHUTDOWN_SENT;
				sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN, tcb->sctp_ep, tcb,
						 asoc->primary_destination);
				sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD, tcb->sctp_ep, tcb,
						 asoc->primary_destination);
			}
		} else {
			/*
			 * we still got (or just got) data to send, so set
			 * SHUTDOWN_PENDING
			 */
			/*
			 * XXX sockets draft says that MSG_EOF should be sent
			 * with no data.  currently, we will allow user data
			 * to be sent first and move to SHUTDOWN-PENDING
			 */
			asoc->state |= SCTP_STATE_SHUTDOWN_PENDING;
		}
	}
	asoc->total_output_queue_size += dataout;
	asoc->total_output_mbuf_queue_size += mbcnt;
#ifdef  SCTP_TCP_MODEL_SUPPORT
	if ((tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) ||
	   (tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL)) {
		tcb->sctp_socket->so_snd.sb_cc += dataout;
		tcb->sctp_socket->so_snd.sb_mbcnt += mbcnt;
	}
#endif
	
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
		printf("++total out:%d total_mbuf_out:%d\n",
		       (int)asoc->total_output_queue_size,
		       (int)asoc->total_output_mbuf_queue_size);
	}
#endif

	return (0);
 no_membad:
	n = m;
	while (n) {
		f = n;
		n = n->m_nextpkt;
		f->m_nextpkt = NULL;
		m_freem(f);
	}
	return (ENOMEM);
}

static struct mbuf *
sctp_copy_mbufchain(struct mbuf *clonechain,
		    struct mbuf *outchain)
{
	struct mbuf *appendchain;
	appendchain = m_copy(clonechain, 0, M_COPYALL);
	if (appendchain == NULL) {
		/* error */
		if (outchain)
			m_freem(outchain);
		return (NULL);
	}
	if (outchain) {
		/* tack on to the end */
		struct mbuf *m;
		m = outchain;
		while (m) {
			if (m->m_next == NULL) {
				m->m_next = appendchain;
				break;
			}
			m = m->m_next;
		}
		if (outchain->m_flags & M_PKTHDR) {
			int append_tot;
			struct mbuf *t;
			t = appendchain;
			append_tot = 0;
			while (t) {
				append_tot += t->m_len;
				t = t->m_next;
			}
			outchain->m_pkthdr.len += append_tot;
		}
		return (outchain);
	} else {
		return (appendchain);
	}
}

void
sctp_toss_old_cookies(struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk,*nchk;
	chk = TAILQ_FIRST(&asoc->control_send_queue);
	while (chk) {
		nchk = TAILQ_NEXT(chk, sctp_next);
		if (chk->rec.chunk_id == SCTP_COOKIE_ECHO) {
			TAILQ_REMOVE(&asoc->control_send_queue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
			asoc->ctrl_queue_cnt--;
			if (chk->whoTo)
				sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = nchk;
		}
	}
}

void
sctp_toss_old_asconf(struct sctp_tcb *tcb)
{
	struct sctp_association *assoc;
	struct sctp_tmit_chunk *chk, *chk_tmp;

	assoc = &tcb->asoc;
	for (chk = TAILQ_FIRST(&assoc->control_send_queue); chk != NULL;
	     chk = chk_tmp) {
		/* get next chk */
		chk_tmp = TAILQ_NEXT(chk, sctp_next);
		/* find SCTP_ASCONF chunk in queue (only one ever in queue) */
		if (chk->rec.chunk_id == SCTP_ASCONF) {
			TAILQ_REMOVE(&assoc->control_send_queue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
			assoc->ctrl_queue_cnt--;
			if (chk->whoTo)
				sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
		}
	}
}


static void
sctp_clean_up_datalist(struct sctp_tcb *stcb,
		       struct sctp_association *asoc,
		       struct sctp_tmit_chunk **data_list,
		       int bundle_at,
		       struct sctp_nets *net)
{
	int i;
	struct mbuf *mm;
	int mbcnt, mb_extcnt;
	for (i = 0; i < bundle_at; i++) {
		/* off of the send queue */
		TAILQ_REMOVE(&asoc->send_queue,
			     data_list[i],
			     sctp_next);
		/* on to the sent queue */
		TAILQ_INSERT_TAIL(&asoc->sent_queue,
				  data_list[i],
				  sctp_next);
		for (mbcnt=0, mb_extcnt=0, mm = data_list[i]->data; mm; mm = mm->m_next) {
			mbcnt++;
			if (mm->m_flags & M_EXT) {
				mb_extcnt++;
			}
		}
		/* This does not lower until the cum-ack passes it */
		asoc->sent_queue_cnt++;
		if ((asoc->peers_rwnd <= 0) &&
		   (asoc->total_flight == 0) &&
		   (bundle_at == 1)) {
			/* Mark the chunk as being a window probe */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("WINDOW PROBE SET\n");
			}
#endif
			sctp_pegs[SCTP_WINDOW_PROBES]++;
			data_list[i]->rec.data.state_flags = SCTP_WINDOW_PROBE;
		} else {
			data_list[i]->rec.data.state_flags = 0;
		}
		data_list[i]->sent = SCTP_DATAGRAM_SENT;
		data_list[i]->snd_count = 1;
		net->flight_size += data_list[i]->send_size;
		asoc->total_flight += data_list[i]->send_size;
		asoc->peers_rwnd -= data_list[i]->send_size;
		if (asoc->peers_rwnd < stcb->sctp_ep->sctp_ep.sctp_sws_sender) {
			/* SWS sender side engages */
			asoc->peers_rwnd = 0;
		}
	}
}

static void
sctp_clean_up_ctl(register struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk,*nchk;
	for (chk = TAILQ_FIRST(&asoc->control_send_queue);
	    chk; chk = nchk) {
		nchk = TAILQ_NEXT(chk, sctp_next);
		if ((chk->rec.chunk_id == SCTP_SELECTIVE_ACK) ||
		    (chk->rec.chunk_id == SCTP_HEARTBEAT_REQUEST) ||
		    (chk->rec.chunk_id == SCTP_HEARTBEAT_ACK) ||
		    (chk->rec.chunk_id == SCTP_SHUTDOWN) ||
		    (chk->rec.chunk_id == SCTP_SHUTDOWN_ACK) ||
		    (chk->rec.chunk_id == SCTP_OPERATION_ERROR) ||
		    (chk->rec.chunk_id == SCTP_COOKIE_ACK) ||
		    (chk->rec.chunk_id == SCTP_ECN_CWR) ||
		    (chk->rec.chunk_id == SCTP_ASCONF_ACK)) {
			/* Stray chunks must be cleaned up */
			TAILQ_REMOVE(&asoc->control_send_queue,
				     chk,
				     sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
			asoc->ctrl_queue_cnt--;
			sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			sctppcbinfo.ipi_gencnt_chunk++;
		}
	}
}

static int
sctp_move_to_outqueue(struct sctp_tcb *tcb,
		      struct sctp_stream_out *strq)
{
	/* Move from the stream to the send_queue keeping track of the total */
	struct sctp_association *asoc;
	int tot_moved=0;
	int failed=0;
	int padval;
	struct sctp_tmit_chunk *chk,*nchk;
	struct sctp_data_chunk *dchkh;
	struct sctpchunk_listhead tmp;
	struct mbuf *orig;

	asoc = &tcb->asoc;
	TAILQ_INIT(&tmp);
	chk = TAILQ_FIRST(&strq->outqueue);
	while (chk) {
		nchk = TAILQ_NEXT(chk, sctp_next);
		/* now put in the chunk header */
		orig = chk->data;
		M_PREPEND(chk->data, sizeof(struct sctp_data_chunk), M_DONTWAIT);
		if (chk->data == NULL) {
			/* HELP */
			failed++;
		}
		if (orig != chk->data) {
			/* A new mbuf was added  account for it */

#ifdef  SCTP_TCP_MODEL_SUPPORT
			if ((tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) ||
			   (tcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL)) {
				tcb->sctp_socket->so_snd.sb_mbcnt += MSIZE;
			}
#endif
			tcb->asoc.total_output_mbuf_queue_size += MSIZE;
		}
		chk->send_size += sizeof(struct sctp_data_chunk);
		/* This should NOT have to do anything, but
		 * I would rather be cautious
		 */
		if (!failed && (chk->data->m_len < sizeof(struct sctp_data_chunk))) {
			m_pullup(chk->data, sizeof(struct sctp_data_chunk));
			if (chk->data == NULL) {
				failed++;
			}
		}
		dchkh = mtod(chk->data, struct sctp_data_chunk *);
		dchkh->ch.chunk_length = htons(chk->send_size);
		/* Chunks must be padded to even word boundary */
		padval = chk->send_size % 4;
		if (padval) {
			/* For fragmented messages this should not
			 * run except possibly on the last chunk
			 */
			if (sctp_pad_lastmbuf(chk->data,(4-padval))) {
				/* we are in big big trouble no mbufs :< */
				failed++;
			}
			chk->send_size += (4-padval);
		}
		/* pull from stream queue */
		TAILQ_REMOVE(&strq->outqueue, chk, sctp_next);
		TAILQ_INSERT_TAIL(&tmp, chk, sctp_next);

		/* add it in to the size of moved chunks */
		if (chk->rec.data.rcv_flags & SCTP_DATA_LAST_FRAG) {
			/* we pull only one chunk */
			break;
		}
		chk = nchk;
	}
	if (failed) {
		/* Gak, we just lost the user message */
		chk = TAILQ_FIRST(&tmp);
		while (chk) {
			nchk = TAILQ_NEXT(chk, sctp_next);
			TAILQ_REMOVE(&tmp, chk, sctp_next);

			sctp_ulp_notify(SCTP_NOTIFY_DG_FAIL, tcb,
					(SCTP_NOTIFY_DATAGRAM_UNSENT|SCTP_INTERNAL_ERROR),
					chk);

			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
			if (chk->whoTo) {
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = NULL;
			}
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = nchk;
		}
		return (0);
	}
	/* now pull them off of temp wheel */
	chk = TAILQ_FIRST(&tmp);
	while (chk) {
		nchk = TAILQ_NEXT(chk, sctp_next);
		/* insert on send_queue */
		TAILQ_REMOVE(&tmp, chk, sctp_next);
		TAILQ_INSERT_TAIL(&asoc->send_queue, chk, sctp_next);
		/* assign TSN */
		chk->rec.data.TSN_seq = asoc->sending_seq++;
		dchkh = mtod(chk->data, struct sctp_data_chunk *);
		/* Put the rest of the things in place now. Size
		 * was done earlier in previous loop prior to
		 * padding.
		 */
		dchkh->ch.chunk_type = SCTP_DATA;
		dchkh->ch.chunk_flags = chk->rec.data.rcv_flags;
		dchkh->dp.tsn = htonl(chk->rec.data.TSN_seq);
		dchkh->dp.stream_id = htons(strq->stream_no);
		dchkh->dp.stream_sequence = htons(chk->rec.data.stream_seq);
		dchkh->dp.protocol_id = chk->rec.data.payloadtype;
		/* total count moved */
		tot_moved += chk->send_size;
		chk = nchk;
	}
	return (tot_moved);
}

static void
sctp_fill_outqueue(struct sctp_tcb *tcb,
		   struct sctp_nets *net)
{
	struct sctp_association *asoc;
	struct sctp_tmit_chunk *chk;
	struct sctp_stream_out *strq,*strqn;
	int mtu_fromwheel;
	int moved, seenend;

	asoc = &tcb->asoc;
	/* Attempt to move at least 1 MTU's worth
	 * onto the wheel for each destination address
	 */
	seenend = moved = mtu_fromwheel = 0;
	if (asoc->last_out_stream == NULL) {
		asoc->last_out_stream = TAILQ_FIRST(&asoc->out_wheel);
		if (asoc->last_out_stream == NULL)
			/* huh nothing on the wheel, TSNH */
			return;
	}
	strq = TAILQ_NEXT(asoc->last_out_stream, next_spoke);
	if (strq == NULL) {
		asoc->last_out_stream = TAILQ_FIRST(&asoc->out_wheel);
	}
	while (mtu_fromwheel < net->mtu) {
		if (strq == NULL) {
			if (seenend == 0) {
				seenend = 1;
				strq = TAILQ_FIRST(&asoc->out_wheel);
			} else if ((moved == 0) && (seenend)) {
				/* none left on the wheel */
				return;
			} else if (moved) {
				/*
				 * clear the flags and rotate back through
				 * again
				 */
				moved = 0;
				seenend = 0;
				strq = TAILQ_FIRST(&asoc->out_wheel);
			}
			continue;
		}
		strqn = TAILQ_NEXT(strq, next_spoke);
		if ((chk = TAILQ_FIRST(&strq->outqueue)) == NULL) {
			/* none left on this queue, prune a spoke?  */
			if (asoc->last_out_stream != strq) {
				/* if it is not our current last one it
				 * is safe to remove it.
				 */
				sctp_remove_from_wheel(asoc, strq);
			}
			strq = strqn;
			continue;
		}
		if (chk->whoTo != net) {
			/* Skip this stream, first one on stream
			 * does not head to our current destination.
			 */
			strq = strqn;
			continue;
		}
		mtu_fromwheel += sctp_move_to_outqueue(tcb, strq);
		moved++;
		asoc->last_out_stream = strq;
		strq = strqn;
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
		printf("Ok we moved %d chunks to send queue\n",
		       moved);
	}
#endif

}

void
sctp_fix_ecn_echo(struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk;
	TAILQ_FOREACH(chk,&asoc->control_send_queue, sctp_next) {
		if (chk->rec.chunk_id == SCTP_ECN_ECHO) {
			chk->sent = SCTP_DATAGRAM_UNSENT;
		}
	}
}

static void
sctp_move_to_an_alt(struct sctp_tcb *tcb,
		    struct sctp_association *asoc,
		    struct sctp_nets *net)
{
	struct sctp_tmit_chunk *chk;
	struct sctp_nets *a_net;
	a_net = sctp_find_alternate_net(tcb, net);
	if ((a_net != net) &&
	   ((a_net->dest_state & SCTP_ADDR_REACHABLE) == SCTP_ADDR_REACHABLE)) {
		/*
		 * We only proceed if a valid alternate is found that is
		 * not this one and is reachable. Here we must move all
		 * chunks queued in the send queue off of the destination
		 * address to our alternate.
		 */
		TAILQ_FOREACH(chk,&asoc->send_queue, sctp_next) {
			if (chk->whoTo == net) {
				/* Move the chunk to our alternate */
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = a_net;
				a_net->ref_count++;
			}
		}
	}
}


static int
sctp_med_chunk_output(struct sctp_inpcb *inp,
		      struct sctp_tcb *tcb,
		      struct sctp_association *asoc,
		      int *num_out,
		      int *reason_code)
{
	/* Ok this is the generic chunk service queue.
	 * we must do the following:
	 *  - Service the stream queue that is next,
	 *    moving any message (note I must get a complete
	 *    message i.e. FIRST/MIDDLE and LAST to the out
	 *    queue in one pass) and assigning TSN's
	 *  - Check to see if the cwnd/rwnd allows any output, if
	 *	so we go ahead and fomulate and send the low level
	 *    chunks. Making sure to combine any control in the
	 *    control chunk queue also.
	 */
	register struct sctp_nets *net;
	struct mbuf *outchain;
	struct sctp_tmit_chunk *chk,*nchk;
	struct sctphdr *shdr;
	/* temp arrays for unlinking */
	struct sctp_tmit_chunk *data_list[SCTP_MAX_DATA_BUNDLING];
	int no_fragmentflg, error;
	int one_chunk, hbflag;
	int asconf, cookie, no_out_cnt, r_mtu;
	int mtu, bundle_at, ctl_cnt, no_data_chunks;

	*num_out = 0;
	ctl_cnt = no_out_cnt = asconf = cookie = 0;
	/*
	 * First lets prime the pump. For each destination, if there
	 * is room in the flight size, attempt to pull an MTU's worth
	 * out of the stream queues into the general send_queue
	 */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
		printf("***********************\n");
	}
#endif
	hbflag = no_data_chunks = 0;
	TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
		if (net->flight_size >= net->cwnd) {
			/* skip this network, no room */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
				printf("Ok skip fillup->fs:%d > cwnd:%d\n",
				       net->flight_size,
				       net->cwnd);
			}
#endif
			sctp_pegs[SCTP_CWND_NOFILL]++;
			continue;
		}
		/* spin through the stream queues moving one message and assign
		 * TSN's as appropriate.
		 */
		if (!TAILQ_EMPTY(&asoc->out_wheel)) {
			sctp_fill_outqueue(tcb, net);
		} else {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
				printf("Ok skip net:%x out_wheel is empty\n",(u_int)net);
			}
#endif
		}
	}
	/* now we must service each destination and send out what
	 * we can for it.
	 */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
		int chk_cnt = 0;
		TAILQ_FOREACH(chk,&asoc->send_queue, sctp_next) {
			chk_cnt++;
		}
		printf("We have %d chunks on the send_queue\n", chk_cnt);
		chk_cnt = 0;
		TAILQ_FOREACH(chk,&asoc->sent_queue, sctp_next) {
			chk_cnt++;
		}
		printf("We have %d chunks on the sent_queue\n", chk_cnt);
	}
#endif
	if (asoc->peers_rwnd <= 0) {
		/* No room in peers rwnd */
	        *reason_code = 1;
		if (asoc->total_flight > 0) {
			/* we are allowed one chunk in flight */
			no_data_chunks = 1;
			sctp_pegs[SCTP_RWND_BLOCKED]++;
		}
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
		printf("Ok we have done the fillup no_data_chunk=%d tf=%d prw:%d\n",
		       (int)no_data_chunks,
		       (int)asoc->total_flight,(int)asoc->peers_rwnd);
	}
#endif
	/* If we have data to send, and DSACK is running, stop it
	 * and build a SACK to dump on to bundle with output. This
	 * actually MAY make it so the bundling does not occur if
	 * the SACK is big but I think this is ok because basic SACK
	 * space is pre-reserved in our fragmentation size choice.
	 */
	if ((TAILQ_FIRST(&asoc->send_queue) != NULL) &&
	   (no_data_chunks == 0)) {
		/* We will be sending something */
		if (callout_pending(&tcb->asoc.dack_timer.timer)) {
			/* Yep a callout is pending */
			sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
					tcb->sctp_ep,
					tcb, NULL);
			sctp_send_sack(tcb);
		}
	}
	TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
		/* how much can we send? */
		ctl_cnt = bundle_at = 0;
		outchain = NULL;
		no_fragmentflg = 1;
		one_chunk = 0;
		mtu = (net->mtu - SCTP_MIN_OVERHEAD);
		if (mtu > asoc->peers_rwnd) {
			if (asoc->total_flight > 0) {
				/* We have a packet in flight somewhere */
				r_mtu = asoc->peers_rwnd;
			} else {
				/* We are always allowed to send one MTU out */
				one_chunk = 1;
				r_mtu = mtu;
			}
		} else {
			r_mtu = mtu;
		}
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("Ok r_mtu is %d mtu is %d for this net:%x one_chunk:%d\n",
			       r_mtu,
			       mtu,
			       (u_int)net,
			       one_chunk);
		}
#endif
		/************************/
		/* Control transmission */
		/************************/
		/* Now first lets go through the control queue */
		for (chk = TAILQ_FIRST(&asoc->control_send_queue);
		    chk; chk = nchk) {
			nchk = TAILQ_NEXT(chk, sctp_next);
			if (chk->whoTo != net) {
				/*
				 * No, not sent to the network we are
				 * looking at
				 */
				continue;
			}
			if (chk->data == NULL) {
				continue;
			}
			if ((chk->data->m_flags & M_PKTHDR) == 0) {
				/*
				 * NOTE: the chk queue MUST have the PKTHDR
				 * flag set on it with a total in the
				 * m_pkthdr.len field!! else the chunk will
				 * ALWAYS be skipped
				 */
				continue;
			}
			if (chk->sent != SCTP_DATAGRAM_UNSENT) {
				/*
				 * It must be unsent. Cookies and ASCONF's
				 * hang around but there timers will force
				 * when marked for resend.
				 */
				continue;
			}
			/* Here we do NOT factor the r_mtu */
			if ((chk->data->m_pkthdr.len < mtu) || (chk->flags & CHUNK_FLAGS_FRAGMENT_OK)) {
				/*
				 * We probably should glom the mbuf chain from
				 * the chk->data for control but the problem
				 * is it becomes yet one more level of
				 * tracking to do if for some reason output
				 * fails. Then I have got to reconstruct the
				 * merged control chain.. el yucko.. for now
				 * we take the easy way and do the copy
				 */
				outchain = sctp_copy_mbufchain(chk->data,
							       outchain);
				if (outchain == NULL) {
					return (ENOMEM);
				}
				/* update our MTU size */
				mtu -= chk->data->m_pkthdr.len;
				if (mtu < 0) {
					mtu = 0;
				}
				/* Do clear IP_DF ? */
				if (chk->flags & CHUNK_FLAGS_FRAGMENT_OK) {
					no_fragmentflg = 0;
				}
				/* Mark things to be removed, if needed */
				if ((chk->rec.chunk_id == SCTP_SELECTIVE_ACK) ||
				    (chk->rec.chunk_id == SCTP_HEARTBEAT_REQUEST) ||
				    (chk->rec.chunk_id == SCTP_HEARTBEAT_ACK) ||
				    (chk->rec.chunk_id == SCTP_SHUTDOWN) ||
				    (chk->rec.chunk_id == SCTP_SHUTDOWN_ACK) ||
				    (chk->rec.chunk_id == SCTP_OPERATION_ERROR) ||
				    (chk->rec.chunk_id == SCTP_COOKIE_ACK) ||
				    (chk->rec.chunk_id == SCTP_ECN_CWR) ||
				    (chk->rec.chunk_id == SCTP_ASCONF_ACK)) {

					if (chk->rec.chunk_id == SCTP_HEARTBEAT_REQUEST)
						hbflag = 1;
					/* remove these chunks at the end */
					if (chk->rec.chunk_id == SCTP_SELECTIVE_ACK) {
						/* turn off the timer */
						if (callout_pending(&tcb->asoc.dack_timer.timer)) {
							sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
									inp, tcb, net);
						}
					}
					ctl_cnt++;
				} else {
					/*
					 * Other chunks, since they have
					 * timers running (i.e. COOKIE or
					 * ASCONF) we just "trust" that it
					 * gets sent or retransmitted.
					 */
					ctl_cnt++;
					if (chk->rec.chunk_id == SCTP_COOKIE_ECHO) {
						cookie = 1;
						no_out_cnt = 1;
					} else if (chk->rec.chunk_id == SCTP_ASCONF) {
						/*
						 * set hb flag since we can use
						 * these for RTO
						 */
						hbflag = 1;
						asconf = 1;
					}
					chk->sent = SCTP_DATAGRAM_SENT;
					chk->snd_count++;
				}
				if (mtu == 0) {
					/*
					 * Ok we are out of room but we can
					 * output without effecting the flight
					 * size since this little guy is a
					 * control only packet.
					 */
					if (asconf) {
						sctp_timer_start(SCTP_TIMER_TYPE_ASCONF, inp, tcb, net);
						asconf = 0;
					}
					if (cookie) {
						sctp_timer_start(SCTP_TIMER_TYPE_COOKIE, inp, tcb, net);
						cookie = 0;
					}
					if (outchain->m_len == 0) {
						/*
						 * Special case for when you
						 * get a 0 len mbuf at the
						 * head due to the lack of a
						 * MHDR at the beginning.
						 */
						outchain->m_len = sizeof(struct sctphdr);
					} else {
						M_PREPEND(outchain, sizeof(struct sctphdr), M_DONTWAIT);
					}
					shdr = mtod(outchain, struct sctphdr *);
					shdr->src_port = inp->sctp_lport;
					shdr->dest_port = tcb->rport;
					shdr->v_tag = htonl(tcb->asoc.peer_vtag);
					shdr->checksum = 0;

					if ((error = sctp_lowlevel_chunk_output(inp, tcb, net,
									       (struct sockaddr *)&net->ra._l_addr,
									       outchain,
									       no_fragmentflg, 0, NULL, asconf))) {
#ifdef SCTP_DEBUG
						if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
							printf("Gak got ctrl error %d\n", error);
						}
#endif
						/* error, could not output */
						if (hbflag) {
#ifdef SCTP_DEBUG
							if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
								printf("Update HB anyway\n");
							}
#endif
							SCTP_GETTIME_TIMEVAL(&net->last_sent_time);
							hbflag = 0;
						}
						if (error == EHOSTUNREACH) {
							/*
							 * Destination went
							 * unreachable during
							 * this send
							 */
#ifdef SCTP_DEBUG
							if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
								printf("Moving data to an alterante\n");
							}
#endif
							sctp_move_to_an_alt(tcb, asoc, net);
						}
						sctp_clean_up_ctl(asoc);
						return (error);
					}
					/* Only HB or ASCONF advances time */
					if (hbflag) {
						SCTP_GETTIME_TIMEVAL(&net->last_sent_time);
						hbflag = 0;
					}
					/*
					 * increase the number we sent, if a
					 * cookie is sent we don't tell them
					 * any was sent out.
					 */
					if (!no_out_cnt)
						*num_out +=  ctl_cnt;
					/* recalc a clean slate and setup */
					mtu = (net->mtu - SCTP_MIN_OVERHEAD);
					no_fragmentflg = 1;
				}
			}
		}
		/*********************/
		/* Data transmission */
		/*********************/
		/* now lets add any data within the MTU constraints */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("Now to data transmission\n");
		}
#endif

		if (((asoc->state & SCTP_STATE_OPEN) == SCTP_STATE_OPEN) ||
		    (cookie)) {
			for (chk = TAILQ_FIRST(&asoc->send_queue); chk; chk = nchk) {
				if (no_data_chunks) {
					/* let only control go out */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("Either nothing to send or we are full\n");
					}
#endif
					break;
				}
				if (net->flight_size >= net->cwnd) {
					/* skip this net, no room for data */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("fs:%d > cwnd:%d\n",
						       net->flight_size, net->cwnd);
					}
#endif
					sctp_pegs[SCTP_CWND_BLOCKED]++;
					*reason_code = 2;
					break;
				}
				nchk = TAILQ_NEXT(chk, sctp_next);
				if (chk->whoTo != net) {
					/* No, not sent to this net */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("chk->whoTo:%x not %x\n",
						       (u_int)chk->whoTo,
						       (u_int)net);
					}
#endif
					continue;
				}
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
					printf("Can we pick up a chunk?\n");
				}
#endif
				if (((chk->send_size < mtu) && (chk->send_size < r_mtu)) ||
				    ((chk->flags & CHUNK_FLAGS_FRAGMENT_OK) && (chk->send_size < asoc->peers_rwnd))) {
					/* ok we will add this one */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("Picking up the chunk\n");
					}
#endif
					outchain = sctp_copy_mbufchain(chk->data, outchain);
					if (outchain == NULL) {
#ifdef SCTP_DEBUG
						if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
							printf("Gakk no memory\n");
						}
#endif
						if (!callout_pending(&net->rxt_timer.timer)) {
							sctp_timer_start(SCTP_TIMER_TYPE_SEND, inp, tcb, net);
						}
						return (ENOMEM);
					}
					/* upate our MTU size */
					/* Do clear IP_DF ? */
					if (chk->flags & CHUNK_FLAGS_FRAGMENT_OK) {
						no_fragmentflg = 0;
					}
					mtu -= chk->send_size;
					r_mtu -= chk->send_size;
					data_list[bundle_at++] = chk;
					if (mtu <= 0) {
						mtu = 0;
						break;
					}
					if ((r_mtu <= 0) || one_chunk) {
						r_mtu = 0;
						break;
					}
				} else {
					/*
					 * Must be sent in order of the TSN's
					 * (on a network)
					 */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("ok no more chk:%d > mtu:%d || < r_mtu:%d\n",
						       chk->send_size, mtu, r_mtu);
					}
#endif
					break;
				}
			}
		} /* if asoc.state OPEN */
		/* Is there something to send for this destination? */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
			printf("ok now is chain assembled? %x\n",
			       (u_int)outchain);
		}
#endif

		if (outchain) {
			/* We may need to start a control timer or two */
			if (asconf) {
				sctp_timer_start(SCTP_TIMER_TYPE_ASCONF, inp, tcb, net);
				asconf = 0;
			}
			if (cookie) {
				sctp_timer_start(SCTP_TIMER_TYPE_COOKIE, inp, tcb, net);
				cookie = 0;
			}
			/* must start a send timer if data is being sent */
			if (bundle_at && (!callout_pending(&net->rxt_timer.timer))) {
				/* no timer running on this destination
				 * restart it.
				 */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
					printf("ok lets start a send timer .. we will transmit %x\n",
					       (u_int)outchain);
				}
#endif
				sctp_timer_start(SCTP_TIMER_TYPE_SEND, inp, tcb, net);
			}
			/* Now send it, if there is anything to send :> */
			if ((outchain->m_flags & M_PKTHDR) == 0) {
				struct mbuf *t;

				MGETHDR(t, M_DONTWAIT, MT_HEADER);
				if (t == NULL) {
					m_freem(outchain);
					return (ENOMEM);
				}
				t->m_next = outchain;
				t->m_pkthdr.len = 0;
				t->m_pkthdr.rcvif = 0;
				t->m_len = 0;

				outchain = t;
				while (t) {
					outchain->m_pkthdr.len += t->m_len;
					t = t->m_next;
				}
			}
			if (outchain->m_len == 0) {
				/* Special case for when you get a 0 len
				 * mbuf at the head due to the lack
				 * of a MHDR at the beginning.
				 */
				outchain->m_len = sizeof(struct sctphdr);
			} else {
				M_PREPEND(outchain, sizeof(struct sctphdr), M_DONTWAIT);
			}
			shdr = mtod(outchain, struct sctphdr *);
			shdr->src_port = inp->sctp_lport;
			shdr->dest_port = tcb->rport;
			shdr->v_tag = htonl(tcb->asoc.peer_vtag);
			shdr->checksum = 0;
			if ((error = sctp_lowlevel_chunk_output(inp, tcb, net,
							       (struct sockaddr *)&net->ra._l_addr,
							       outchain,
							       no_fragmentflg, bundle_at, data_list[0], asconf))) {
				/* error, we could not output */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
					printf("Gak send error %d\n", error);
				}
#endif
				if (hbflag) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("Update HB time anyway\n");
					}
#endif
					SCTP_GETTIME_TIMEVAL(&net->last_sent_time);
					hbflag = 0;
				}
				if (error == EHOSTUNREACH) {
					/*
					 * Destination went unreachable during
					 * this send
					 */
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
						printf("Calling the movement routine\n");
					}
#endif
					sctp_move_to_an_alt(tcb, asoc, net);
				}
				sctp_clean_up_ctl(asoc);
				return (error);
			}
			if (bundle_at || hbflag)
				/* For data/asconf and hb set time */
				SCTP_GETTIME_TIMEVAL(&net->last_sent_time);

			if (!no_out_cnt) {
				*num_out += (ctl_cnt + bundle_at);
			}
			if (bundle_at) {
				if (!net->rto_pending) {
					/* setup for a RTO measurement */
					net->rto_pending = 1;
					data_list[0]->sent_rcv_time = net->last_sent_time;
				}
				sctp_pegs[SCTP_PEG_TSNS_SENT] += bundle_at;
				sctp_clean_up_datalist(tcb, asoc, data_list, bundle_at, net);
			}
		}
	}
	/* At the end there should be no NON timed
	 * chunks hanging on this queue.
	 */
	if ((*num_out == 0) && (*reason_code == 0)) {
	  *reason_code = 3;
	}
	sctp_clean_up_ctl(asoc);
	return (0);
}

void
sctp_queue_op_err(struct sctp_tcb *stcb, struct mbuf *op_err)
{
	/* Prepend a OPERATIONAL_ERROR chunk header
	 * and put on the end of the control chunk queue.
	 */
	/* Sender had better have gotten a MGETHDR or else
	 * the control chunk will be forever skipped
	 */
	struct sctp_chunkhdr *hdr;
	struct sctp_tmit_chunk *chk;
	struct mbuf *mat;

#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		m_freem(op_err);
		return;
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;
	M_PREPEND(op_err, sizeof(struct sctp_chunkhdr), M_DONTWAIT);
	if (op_err == NULL) {
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		return;
	}
	chk->send_size = 0;
	mat = op_err;
	while (mat != NULL) {
		chk->send_size += mat->m_len;
		mat = mat->m_next;
	}
	chk->rec.chunk_id = SCTP_OPERATION_ERROR;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->data = op_err;
	chk->whoTo = chk->asoc->primary_destination;
	chk->whoTo->ref_count++;
	hdr = mtod(op_err, struct sctp_chunkhdr *);
	hdr->chunk_type = SCTP_OPERATION_ERROR;
	hdr->chunk_flags = 0;
	hdr->chunk_length = htons(chk->send_size);
	TAILQ_INSERT_TAIL(&chk->asoc->control_send_queue,
			  chk,
			  sctp_next);
	chk->asoc->ctrl_queue_cnt++;
}

int
sctp_send_cookie_echo(struct mbuf *m,
		      int offset,
		      struct sctp_tcb *stcb,
		      struct sctp_nets *netp)
{
	/* pull out the cookie and put it at
	 * the front of the control chunk queue.
	 */
	int at;
	struct mbuf *cookie,*mat;
	struct sctp_paramhdr parm,*phdr;
	struct sctp_chunkhdr *hdr;
	struct sctp_tmit_chunk *chk;
	u_int16_t ptype, plen;
	/* First find the cookie in the param area */
	cookie = NULL;
	at = offset + sizeof(struct sctp_init_chunk);

	do{
		phdr = sctp_get_next_param(m, at,&parm, sizeof(parm));
		if (phdr == NULL) {
			return (-3);
		}
		ptype = ntohs(phdr->param_type);
		plen = ntohs(phdr->param_length);
		if (ptype == SCTP_STATE_COOKIE) {
			int pad;
			/* found the cookie */
			if ((pad = (plen % 4))) {
				plen += 4 - pad;
			}
			cookie = m_copym(m, at, plen, M_DONTWAIT);
			if (cookie == NULL) {
				/* No memory */
				return (-2);
			}
			break;
		}
		at += plen;
	} while (phdr);
	if (cookie == NULL) {
		/* Did not find the cookie */
		return (-3);
	}
	/* ok, we got the cookie lets change it
	 * into a cookie echo chunk.
	 */

	/* first the change from param to cookie */
	hdr = mtod(cookie, struct sctp_chunkhdr *);
	hdr->chunk_type = SCTP_COOKIE_ECHO;
	hdr->chunk_flags = 0;
	/* now we MUST have a PKTHDR on it */
	if ((cookie->m_flags & M_PKTHDR) != M_PKTHDR) {
		/* we hope this happens rarely */
		MGETHDR(mat, M_DONTWAIT, MT_HEADER);
		if (mat == NULL) {
			m_freem(cookie);
			return (-4);
		}
		mat->m_len = 0;
		mat->m_pkthdr.rcvif = 0;
		mat->m_next = cookie;
		cookie = mat;
	}
	cookie->m_pkthdr.len = plen;
	/* ok, now lets get the chunk stuff and place
	 * it in the FRONT of the queue.
	 */
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		m_freem(cookie);
		return (-5);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;
	chk->send_size = cookie->m_pkthdr.len;
	chk->rec.chunk_id = SCTP_COOKIE_ECHO;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->data = cookie;
	chk->whoTo = chk->asoc->primary_destination;
	chk->whoTo->ref_count++;
	TAILQ_INSERT_HEAD(&chk->asoc->control_send_queue,
			  chk,
			  sctp_next);
	chk->asoc->ctrl_queue_cnt++;
	return (0);
}

void
sctp_send_heartbeat_ack(struct sctp_tcb *stcb,
			struct mbuf *m,
			int offset,
			int chk_length,
			struct sctp_nets *netp)
{
	/* take a HB request and make it into a
	 * HB ack and send it.
	 */
	struct mbuf *outchain;
	struct sctp_chunkhdr *chdr;
	struct sctphdr *shdr;

	outchain = m_copym(m, offset, chk_length, M_DONTWAIT);
	if (outchain == NULL) {
		/* gak out of memory */
		return;
	}
	chdr = mtod(outchain, struct sctp_chunkhdr *);
	chdr->chunk_type = SCTP_HEARTBEAT_ACK;
	chdr->chunk_flags = 0;
	if ((outchain->m_flags & M_PKTHDR) != M_PKTHDR) {
		/* should not happen but we are cautious. */
		struct mbuf *tmp;
		MGETHDR(tmp, M_DONTWAIT, MT_HEADER);
		if (tmp == NULL) {
			return;
		}
		tmp->m_len = 0;
		tmp->m_pkthdr.rcvif = 0;
		tmp->m_next = outchain;
		outchain = tmp;
	}
	outchain->m_pkthdr.len = chk_length;
	if (outchain->m_len == 0) {
		outchain->m_len = sizeof(struct sctphdr);
	} else {
		M_PREPEND(outchain, sizeof(struct sctphdr), M_DONTWAIT);
	}
	shdr = mtod(outchain, struct sctphdr *);
	shdr->src_port = stcb->sctp_ep->sctp_lport;
	shdr->dest_port = stcb->rport;
	shdr->v_tag = htonl(stcb->asoc.peer_vtag);
	shdr->checksum = 0;
	sctp_lowlevel_chunk_output(stcb->sctp_ep, stcb, netp,
				   (struct sockaddr *)&netp->ra._l_addr,
				   outchain, 0, 0, NULL, 0);

}

int
sctp_send_cookie_ack(struct sctp_tcb *stcb) {
	/* formulate and queue a cookie-ack back to sender */
	struct mbuf *cookie_ack;
	struct sctp_chunkhdr *hdr;
	struct sctp_tmit_chunk *chk;

	cookie_ack = NULL;
	MGETHDR(cookie_ack, M_DONTWAIT, MT_HEADER);
	if (cookie_ack == NULL) {
		/* no mbuf's */
		return (-1);
	}
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		m_freem(cookie_ack);
		return (-1);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;

	chk->send_size = sizeof(struct sctp_chunkhdr);
	chk->rec.chunk_id = SCTP_COOKIE_ACK;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->data = cookie_ack;
	if (chk->asoc->last_control_chunk_from != NULL) {
		chk->whoTo = chk->asoc->last_control_chunk_from;
	} else {
		chk->whoTo = chk->asoc->primary_destination;
	}
	chk->whoTo->ref_count++;
	hdr = mtod(cookie_ack, struct sctp_chunkhdr *);
	hdr->chunk_type = SCTP_COOKIE_ACK;
	hdr->chunk_flags = 0;
	hdr->chunk_length = htons(chk->send_size);
	cookie_ack->m_pkthdr.len = cookie_ack->m_len = chk->send_size;
	cookie_ack->m_pkthdr.rcvif = 0;
	TAILQ_INSERT_TAIL(&chk->asoc->control_send_queue, chk, sctp_next);
	chk->asoc->ctrl_queue_cnt++;
	return (0);
}


int
sctp_send_shutdown_ack(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	/* formulate and queue a SHUTDOWN-ACK back to the sender */
	struct mbuf *m_shutdown_ack;
	struct sctp_shutdown_ack_chunk *ack_cp;
	struct sctp_tmit_chunk *chk;

	m_shutdown_ack = NULL;
	MGETHDR(m_shutdown_ack, M_DONTWAIT, MT_HEADER);
	if (m_shutdown_ack == NULL) {
		/* no mbuf's */
		return (-1);
	}
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		m_freem(m_shutdown_ack);
		return (-1);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;

	chk->send_size = sizeof(struct sctp_chunkhdr);
	chk->rec.chunk_id = SCTP_SHUTDOWN_ACK;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->data = m_shutdown_ack;
	chk->whoTo = net;
	net->ref_count++;

	ack_cp = mtod(m_shutdown_ack, struct sctp_shutdown_ack_chunk *);
	ack_cp->ch.chunk_type = SCTP_SHUTDOWN_ACK;
	ack_cp->ch.chunk_flags = 0;
	ack_cp->ch.chunk_length = htons(chk->send_size);
	m_shutdown_ack->m_pkthdr.len = m_shutdown_ack->m_len = chk->send_size;
	m_shutdown_ack->m_pkthdr.rcvif = 0;
	TAILQ_INSERT_TAIL(&chk->asoc->control_send_queue, chk, sctp_next);
	chk->asoc->ctrl_queue_cnt++;
	return (0);
}

int
sctp_send_shutdown(struct sctp_tcb *stcb, struct sctp_nets *net)
{
	/* formulate and queue a SHUTDOWN to the sender */
	struct mbuf *m_shutdown;
	struct sctp_shutdown_chunk *shutdown_cp;
	struct sctp_tmit_chunk *chk;

	m_shutdown = NULL;
	MGETHDR(m_shutdown, M_DONTWAIT, MT_HEADER);
	if (m_shutdown == NULL) {
		/* no mbuf's */
		return (-1);
	}
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		m_freem(m_shutdown);
		return (-1);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;

	chk->send_size = sizeof(struct sctp_shutdown_chunk);
	chk->rec.chunk_id = SCTP_SHUTDOWN;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->data = m_shutdown;
	chk->whoTo = net;
	net->ref_count++;

	shutdown_cp = mtod(m_shutdown, struct sctp_shutdown_chunk *);
	shutdown_cp->ch.chunk_type = SCTP_SHUTDOWN;
	shutdown_cp->ch.chunk_flags = 0;
	shutdown_cp->ch.chunk_length = htons(chk->send_size);
	shutdown_cp->cumulative_tsn_ack = htonl(stcb->asoc.cumulative_tsn);
	m_shutdown->m_pkthdr.len = m_shutdown->m_len = chk->send_size;
	m_shutdown->m_pkthdr.rcvif = 0;
	TAILQ_INSERT_TAIL(&chk->asoc->control_send_queue, chk, sctp_next);
	chk->asoc->ctrl_queue_cnt++;

	if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) ||
	    (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL)) {
		soisdisconnecting(stcb->sctp_ep->sctp_socket);
	}
	return (0);
}

int
sctp_send_asconf(struct sctp_tcb *stcb, struct sctp_nets *netp)
{
	/*
	 * formulate and queue an ASCONF to the peer
	 * ASCONF parameters should be queued on the assoc queue
	 */
	struct sctp_tmit_chunk *chk;
	struct mbuf *m_asconf;
	struct sctp_asconf_chunk *acp;


	/* compose an ASCONF chunk, maximum length is PMTU */
	m_asconf = sctp_compose_asconf(stcb);
	if (m_asconf == NULL) {
		return (-1);
	}
	acp = mtod(m_asconf, struct sctp_asconf_chunk *);
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		m_freem(m_asconf);
		return (-1);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;

	chk->data = m_asconf;
	chk->send_size = m_asconf->m_pkthdr.len;
	chk->rec.chunk_id = SCTP_ASCONF;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->whoTo = chk->asoc->primary_destination;
#if 0 /* done in sctp_asconf.c now */
	if (acp->address_type == 0) {
		/* We did not fill in the address */
		struct sockaddr *to;
		struct sctp_nets *net;
		net = chk->asoc->primary_destination;
		to = (struct sockaddr *)&net->ra._l_addr;
		if (to->sa_family == AF_INET6) {
			struct in6_addr src, cmp;
			memset(&src, 0, sizeof(src));
			memset(&cmp, 0, sizeof(cmp));
			src = sctp_ipv6_source_address_selection(stcb->sctp_ep,
								 stcb,
								 (struct sockaddr_in6 *)to,
								 (struct route *)&net->ra,
								 net, 0);
			if (memcmp(&src,&cmp, sizeof(cmp))) {
				acp->address_type = SCTP_IPV6_ADDRESS;
				memcpy(acp->address,&src, sizeof(struct in6_addr));
			}
		} else {
			struct in_addr src;
			memset(&src, 0, sizeof(src));
			src = sctp_ipv4_source_address_selection(stcb->sctp_ep,
								 stcb,
								 (struct sockaddr_in *)to,
								 (struct route *)&net->ra,
								 net, 0);
			if (src.s_addr) {
				memcpy(acp->address,&src, sizeof(struct in_addr));
				acp->address_type = SCTP_IPV4_ADDRESS;
			}
		}
	}
#endif /* #if 0 */
	chk->whoTo->ref_count++;
	TAILQ_INSERT_TAIL(&chk->asoc->control_send_queue, chk, sctp_next);
	chk->asoc->ctrl_queue_cnt++;
	return (0);
}

int
sctp_send_asconf_ack(struct sctp_tcb *stcb, uint32_t retrans)
{
	/*
	 * formulate and queue a asconf-ack back to sender
	 * the asconf-ack must be stored in the tcb
	 */
	struct sctp_tmit_chunk *chk;
	struct mbuf *m_ack;

	/* is there a asconf-ack mbuf chain to send? */
	if (stcb->asoc.last_asconf_ack_sent == NULL) {
		return (-1);
	}

	/* copy the asconf_ack */
	m_ack = m_copym(stcb->asoc.last_asconf_ack_sent, 0, M_COPYALL, M_DONTWAIT);
	if (m_ack == NULL) {
		/* couldn't copy it */

		return (-1);
	}
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		/* no memory */
		if (m_ack)
			m_freem(m_ack);
		return (-1);
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;

	/* figure out where it goes to */
	if (retrans) {
		/* we're doing a retransmission */
		if (stcb->asoc.used_alt_asconfack > 2) {
			/* tried alternate nets already, go back */
			chk->whoTo = NULL;
		} else {
			/* need to try and alternate net */
			chk->whoTo = sctp_find_alternate_net(stcb, stcb->asoc.last_control_chunk_from);
			stcb->asoc.used_alt_asconfack++;
		}
		if (chk->whoTo == NULL) {
			/* no alternate */
			if (stcb->asoc.last_control_chunk_from == NULL)
				chk->whoTo = stcb->asoc.primary_destination;
			else
				chk->whoTo = stcb->asoc.last_control_chunk_from;
			stcb->asoc.used_alt_asconfack = 0;
		}
	} else {
		/* normal case */
		if (stcb->asoc.last_control_chunk_from == NULL)
			chk->whoTo = stcb->asoc.primary_destination;
		else
			chk->whoTo = stcb->asoc.last_control_chunk_from;
		stcb->asoc.used_alt_asconfack = 0;
	}
	chk->data = m_ack;
	chk->send_size = m_ack->m_pkthdr.len;
	chk->rec.chunk_id = SCTP_ASCONF_ACK;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->flags = 0;
	chk->asoc = &stcb->asoc;
	chk->whoTo->ref_count++;
	TAILQ_INSERT_TAIL(&chk->asoc->control_send_queue, chk, sctp_next);
	chk->asoc->ctrl_queue_cnt++;
	return (0);
}

static int
sctp_chunk_retransmission(struct sctp_inpcb *inp,
			  struct sctp_tcb *tcb,
			  struct sctp_association *asoc,
			  int *cnt_out)
{
	/*
	 * send out one MTU of retransmission.
	 * If fast_retransmit is happening we ignore the cwnd.
	 * Otherwise we obey the cwnd and rwnd.
	 * For a Cookie or Asconf in the control chunk queue we retransmit
	 * them by themselves.
	 *
	 * For data chunks we will pick out the lowest TSN's in the
	 * sent_queue marked for resend and bundle them all together
	 * (up to a MTU of destination). The address to send to should
	 * have been selected/changed where the retransmission was
	 * marked (i.e. in FR or t3-timeout routines).
	 */
	struct sctp_tmit_chunk *data_list[SCTP_MAX_DATA_BUNDLING];
	struct sctp_tmit_chunk *chk,*fwd;
	struct mbuf *m;
	struct sctphdr *shdr;
	int asconf;
	struct sctp_nets *net;
	int no_fragmentflg, bundle_at, mtu;
	int error, i, one_chunk, fwd_tsn, ctl_cnt, tmr_started;

	tmr_started = ctl_cnt = bundle_at =  error = 0;
	no_fragmentflg = 1;
	asconf = 0;
	fwd_tsn = 0;
	*cnt_out = 0;
	fwd = NULL;
	m = NULL;
	if (TAILQ_EMPTY(&asoc->sent_queue)) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("SCTP hits empty queue with cnt set to %d?\n",
			       asoc->sent_queue_retran_cnt);
		}
#endif
		asoc->sent_queue_retran_cnt = 0;
		asoc->sent_queue_cnt = 0;
		asoc->sent_queue_cnt_removeable = 0;
	}
	TAILQ_FOREACH(chk,&asoc->control_send_queue, sctp_next) {
		if (chk->sent != SCTP_DATAGRAM_RESEND) {
			/* we only worry about things marked for resend */
			continue;
		}
		if ((chk->rec.chunk_id == SCTP_COOKIE_ECHO) ||
		   (chk->rec.chunk_id == SCTP_ASCONF) ||
		   (chk->rec.chunk_id == SCTP_FORWARD_CUM_TSN)) {
			ctl_cnt++;
			if (chk->rec.chunk_id == SCTP_ASCONF) {
				no_fragmentflg = 1;
				asconf = 1;
			}
			if (chk->rec.chunk_id == SCTP_FORWARD_CUM_TSN) {
				fwd_tsn = 1;
				fwd = chk;
			}
			m = sctp_copy_mbufchain(chk->data, m);
			if (!fwd_tsn)
				break;
		}
	}
	one_chunk = 0;
	/* do we have control chunks to retransmit? */
	if (m != NULL) {
		/* Start a timer no matter if we suceed or fail */
		if (chk->rec.chunk_id == SCTP_COOKIE_ECHO)
			sctp_timer_start(SCTP_TIMER_TYPE_COOKIE, inp, tcb, chk->whoTo);
		else if (chk->rec.chunk_id == SCTP_ASCONF)
			sctp_timer_start(SCTP_TIMER_TYPE_ASCONF, inp, tcb, chk->whoTo);

		if (m->m_len == 0) {
			/* Special case for when you get a 0 len
			 * mbuf at the head due to the lack
			 * of a MHDR at the beginning.
			 */
			m->m_len = sizeof(struct sctphdr);
		} else {
			M_PREPEND(m, sizeof(struct sctphdr), M_DONTWAIT);
		}
		shdr = mtod(m, struct sctphdr *);
		shdr->src_port = inp->sctp_lport;
		shdr->dest_port = tcb->rport;
		shdr->v_tag = htonl(tcb->asoc.peer_vtag);
		shdr->checksum = 0;
		chk->snd_count++;		/* update our count */

		if ((error = sctp_lowlevel_chunk_output(inp, tcb, chk->whoTo,
						       (struct sockaddr *)&chk->whoTo->ra._l_addr,
						       m, no_fragmentflg, 0, NULL, asconf))) {
			return (error);
		}
		/*
		 *We don't want to mark the net->sent time here since this
		 * we use this for HB and retrans cannot measure RTT
		 */
		/*    SCTP_GETTIME_TIMEVAL(&chk->whoTo->last_sent_time);*/
		*cnt_out += 1;
		asoc->sent_queue_retran_cnt--;
		chk->sent = SCTP_DATAGRAM_SENT;
		if (!fwd_tsn)
			return (0);
		else {
			/* Clean up the fwd-tsn list */
			sctp_clean_up_ctl(asoc);
			if (ctl_cnt > 1) {
				return (0);
			}
		}
	}
	m = NULL;
	/* Ok, it is just data retransmission we need to do or
	 * that and a fwd-tsn with it all.
	 */
	if (TAILQ_EMPTY(&asoc->sent_queue)) {
		return (-1);
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
		printf("Normal chunk retransmission cnt:%d\n",
		       asoc->sent_queue_retran_cnt);
	}
#endif
	TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
		if ((asoc->peers_rwnd <= 0) && (asoc->total_flight > 0)) {
			/* No room in peers rwnd */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("peers_rwnd:%d tf:%d\n",
				       (int)asoc->peers_rwnd,
				       (int)asoc->total_flight);
			}
#endif
			sctp_pegs[SCTP_RWND_BLOCKED]++;
			return (1);
		}
		mtu = (net->mtu - SCTP_MIN_OVERHEAD);
		if (asoc->peers_rwnd > 0) {
			if (mtu > asoc->peers_rwnd) {
				mtu = asoc->peers_rwnd;
			}
		} else {
			one_chunk = 1;
		}
		net->fast_retran_ip = 0;
		TAILQ_FOREACH(chk,&asoc->sent_queue, sctp_next) {
			if ((chk->whoTo != net) ||
			   (chk->sent != SCTP_DATAGRAM_RESEND)) {
				/* No, not sent to this net  or not
				 * ready for re-transmission.
				 */
				continue;
			}
			if (chk->rec.data.doing_fast_retransmit == 0) {
				/* if no FR in progress skip destination that
				 * have flight_size > cwnd.
				 */
				if (net->flight_size >= net->cwnd) {
					sctp_pegs[SCTP_CWND_BLOCKED]++;
					continue;
				}
			} else {
				/* Mark the destination net to have FR recovery
				 * limits put on it.
				 */
				net->fast_retran_ip = 1;
			}
			if ((chk->send_size <= mtu) || (chk->flags & CHUNK_FLAGS_FRAGMENT_OK)) {
				/* ok we will add this one */
				m = sctp_copy_mbufchain(chk->data, m);
				if (m == NULL) {
					return (ENOMEM);
				}
				/* upate our MTU size */
				/* Do clear IP_DF ? */
				if (chk->flags & CHUNK_FLAGS_FRAGMENT_OK) {
					no_fragmentflg = 0;
				}
				mtu -= chk->send_size;
				data_list[bundle_at++] = chk;
				if (one_chunk) {
					sctp_pegs[SCTP_WINDOW_PROBES]++;
					chk->rec.data.state_flags |= SCTP_WINDOW_PROBE;
				}
				if ((mtu <= 0) || one_chunk) {
					mtu = 0;
					break;
				}
			}
		}
		/* Is there something to send for this destination? */
		if (m) {
			/* No matter if we fail/or suceed we should
			 * start a timer. A failure is like a lost
			 * IP packet :-)
			 */
			if (!callout_pending(&net->rxt_timer.timer)) {
				/* no timer running on this destination
				 * restart it.
				 */
				sctp_timer_start(SCTP_TIMER_TYPE_SEND, inp, tcb, net);
				tmr_started = 1;
			}
			if (m->m_len == 0) {
				/* Special case for when you get a 0 len
				 * mbuf at the head due to the lack
				 * of a MHDR at the beginning.
				 */
				m->m_len = sizeof(struct sctphdr);
			} else {
				M_PREPEND(m, sizeof(struct sctphdr), M_DONTWAIT);
			}
			shdr = mtod(m, struct sctphdr *);
			shdr->src_port = inp->sctp_lport;
			shdr->dest_port = tcb->rport;
			shdr->v_tag = htonl(tcb->asoc.peer_vtag);
			shdr->checksum = 0;

			/* Now lets send it, if there is anything to send :> */
			if ((error = sctp_lowlevel_chunk_output(inp, tcb, net,
							       (struct sockaddr *)&net->ra._l_addr,
							       m,
							       no_fragmentflg, 0, NULL, asconf))) {
				/* error, we could not output */
				return (error);
			}
			/* For HB's */
			/*
			 * We don't want to mark the net->sent time here since
			 * this we use this for HB and retrans cannot measure
			 * RTT
			 */
			/*      SCTP_GETTIME_TIMEVAL(&net->last_sent_time);*/

			/* For auto-close */
			SCTP_GETTIME_TIMEVAL(&asoc->time_last_sent);
			*cnt_out += bundle_at;
			sctp_pegs[SCTP_RETRANTSN_SENT]++;
			for (i = 0; i < bundle_at; i++) {
				if (data_list[i]->rec.data.doing_fast_retransmit) {
					/*
					 * We bump above RESEND so we don't
					 * get picked up again until a t3-rxt
					 * goes off.
					 */
					data_list[i]->sent++;
				} else {
					data_list[i]->sent = SCTP_DATAGRAM_SENT;
				}

				data_list[i]->snd_count++;
				asoc->sent_queue_retran_cnt--;
				net->flight_size += data_list[i]->send_size;
				asoc->total_flight += data_list[i]->send_size;
				asoc->peers_rwnd -= data_list[i]->send_size;
				if (asoc->peers_rwnd < tcb->sctp_ep->sctp_ep.sctp_sws_sender) {
					/* SWS sender side engages */
					asoc->peers_rwnd = 0;
				}
				if ((data_list[i]->rec.data.state_flags & SCTP_FWDTSN_MARKED_DOWN) ==
				   SCTP_FWDTSN_MARKED_DOWN) {
					/*
					 * turn off flag so another strike can
					 * happen on it
					 */
					data_list[i]->rec.data.state_flags &= ~SCTP_FWDTSN_MARKED_DOWN;
				}
				if (data_list[i]->rec.data.doing_fast_retransmit) {
					sctp_pegs[SCTP_FAST_RETRAN]++;
					if ((data_list[i] == TAILQ_FIRST(&asoc->sent_queue)) &&
					   (tmr_started == 0)) {
						/*
						 * ok we just fast-retrans'd
						 * the lowest TSN, i.e the
						 * first on the list. In this
						 * case we want to give some
						 * more time to get a SACK
						 * back without a t3-expiring.
						 */
						sctp_timer_stop(SCTP_TIMER_TYPE_SEND, inp, tcb, net);
						sctp_timer_start(SCTP_TIMER_TYPE_SEND, inp, tcb, net);
					}
				}
			}
			m = NULL;
		}
		if (asoc->sent_queue_retran_cnt <= 0) {
			/* all done we have no more to retran */
			asoc->sent_queue_retran_cnt = 0;
			break;
		}
	}
	return (0);
}


static int
sctp_timer_validation(struct sctp_inpcb *inp,
		      struct sctp_tcb *tcb,
		      struct sctp_association *asoc,
		      int ret)
{
	struct sctp_nets *net;
	/* Validate that a timer is running somewhere */
	TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
		if (callout_pending(&net->rxt_timer.timer)) {
			/* Here is a timer */
			return (ret);
		}
	}
	/* Gak, we did not have a timer somewhere */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT3) {
		printf("Deadlock avoided starting timer on a dest at retran\n");
	}
#endif
	sctp_timer_start(SCTP_TIMER_TYPE_SEND, inp, tcb, asoc->primary_destination);
	return (ret);
}

int
sctp_chunk_output(struct sctp_inpcb *inp,
		  struct sctp_tcb *tcb,
		  int from_where)
{
	/* Ok this is the generic chunk service queue.
	 * we must do the following:
	 *  - See if there are retransmits pending, if so we
	 *   	must do these first and return.
	 *  - Service the stream queue that is next,
	 *    moving any message (note I must get a complete
	 *    message i.e. FIRST/MIDDLE and LAST to the out
	 *    queue in one pass) and assigning TSN's
	 *  - Check to see if the cwnd/rwnd allows any output, if
	 *	so we go ahead and fomulate and send the low level
	 *    chunks. Making sure to combine any control in the
	 *    control chunk queue also.
	 */
	struct sctp_association *asoc;
	struct sctp_nets *net;
	int error, num_out, tot_out, ret, reason_code;

	asoc = &tcb->asoc;
	tot_out = 0;
	num_out = 0;
	reason_code = 0;
	sctp_pegs[SCTP_CALLS_TO_CO]++;
	while (asoc->sent_queue_retran_cnt) {
		/* Ok, it is retransmission time only, we send out only ONE
		 * packet with a single call off to the retran code.
		 */
		ret = sctp_chunk_retransmission(inp, tcb, asoc,&num_out);
		if (ret > 0) {
			/* Can't send anymore */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("retransmission ret:%d -- full\n", ret);
			}
#endif
			/*
			 * now lets push out control by calling med-level
			 * output once. this assures that we WILL send HB's
			 * if queued too.
			 */
			(void)sctp_med_chunk_output(inp, tcb, asoc,&num_out,&reason_code);
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Control send outputs:%d@full\n", num_out);
			}
#endif
			return (sctp_timer_validation(inp, tcb, asoc, ret));
		}
		if (ret < 0) {
			/*
			 * The count was off.. retran is not happening so do
			 * the normal retransmission.
			 */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Done with retrans, none left fill up window\n");
			}
#endif
			break;
		}
		if (from_where == 1) {
			/* Only one transmission allowed out of a timeout */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("Only one packet allowed out\n");
			}
#endif
			return (ret);
		}
		if ((num_out == 0) && (ret == 0)) {
			if (asoc->sent_queue_retran_cnt) {
				sctp_audit_retranmission_queue(asoc);
			}
			break;
		}
	}
	/* Check for bad destinations, if they exist move chunks around. */
	TAILQ_FOREACH(net,&asoc->nets, sctp_next) {
/*		if (net->fast_retran_ip) {
 * New method from Allman is we ALWAYS do this, not just on FR.
 */
		/* Ok a FR cycle just completed on this guy we
		 * have exited recovery. Apply the Allman MaxBurst
		 * by using it to adjust cwnd if needed.
		 */

		if (from_where >= 2) {
			/* We only do this when we are sending based on
			 * a SACK or other protocol event. Not the user
			 * sending.
			 */
			if (((net->mtu * asoc->max_burst) + net->flight_size) < net->cwnd) {
				net->cwnd = ((net->mtu * 4)+net->flight_size);
			}
		}
/*			net->fast_retran_ip = 0;*/
/*		}*/
		if ((net->dest_state & SCTP_ADDR_NOT_REACHABLE) ==
		    SCTP_ADDR_NOT_REACHABLE) {
			/*
			 * if possible move things off of this address
			 * we still may send below due to the dormant state
			 * but we try to find an alternate address to send
			 * to and if we have one we move all queued data on
			 * the out wheel to this alternate address.
			 */
			sctp_move_to_an_alt(tcb, asoc, net);
		}
	}
	/* Fill up what we can to the destination */
	do {
		error = sctp_med_chunk_output(inp, tcb, asoc, &num_out,
					      &reason_code);
		if (error)
			break;
		tot_out += num_out;
	} while (num_out);
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
		printf("Ok, we have put out %d chunks\n", tot_out);
	}
#endif
	if (tot_out == 0) {
		sctp_pegs[SCTP_CO_NODATASNT]++;
	}
	/* Now we need to clean up the control chunk chain if
	 * a ECNE is on it. It must be marked as UNSENT again
	 * so next call will continue to send it until
	 * such time that we get a CWR, to remove it.
	 */
	sctp_fix_ecn_echo(asoc);
	return (error);
}

int
sctp_output(inp, m, addr, control, p)
     register struct sctp_inpcb *inp;
     struct mbuf *m;
     struct sockaddr *addr;
     struct mbuf *control;
     struct proc *p;
{
	struct inpcb *ip_inp;
	struct sctp_inpcb *t_inp;
	struct sctp_tcb *tcb;
	struct sctp_nets *net;
	struct sctp_association *asoc;
	int queue_only, error=0;
	int s;
	struct sctp_sndrcvinfo srcv;
	int use_rcvinfo = 0;
	t_inp = inp;
	/*  struct route ro;*/

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	queue_only = 0;
	ip_inp = (struct inpcb *)inp;
	tcb = NULL;
	asoc = NULL;
	net = NULL;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
		printf("USR Send BEGINS\n");
	}
#endif

#ifdef SCTP_TCP_MODEL_SUPPORT
	if ((inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) &&
	   (inp->sctp_flags & SCTP_PCB_FLAGS_ACCEPTING)) {
		/* The listner can NOT send */
		if (control) {
			sctppcbinfo.mbuf_track--;
			m_freem(control);
			control = NULL;
		}
		m_freem(m);
		splx(s);
		return (EFAULT);
	}
#endif
	/* Can't allow a V6 address on a non-v6 socket */
	if (addr) {
		if (((inp->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) == 0) &&
		   (addr->sa_family == AF_INET6)) {
			splx(s);
			return (EINVAL);
		}
	}
	if (control) {
		sctppcbinfo.mbuf_track++;
		if (sctp_find_cmsg(SCTP_SNDRCV, (void *)&srcv, control,
				   sizeof(srcv))) {
			if (srcv.sinfo_assoc_id) {
#ifdef SCTP_TCP_MODEL_SUPPORT
				if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
					tcb = LIST_FIRST(&inp->sctp_asoc_list);
					if (tcb == NULL) {
						splx(s);
						return (ENOTCONN);
					}
					net = tcb->asoc.primary_destination;
				}
				else
#endif
					tcb = sctp_findassociation_ep_asocid(inp, srcv.sinfo_assoc_id);
				/*
				 * Question: Should I error here if the
				 * assoc_id is no longer valid?
				 * i.e. I can't find it?
				 */
				if ((tcb) &&
				    (srcv.sinfo_flags & MSG_ADDR_OVER) &&
				    (addr != NULL)) {
					/* Must locate the net structure */
					if (addr)
						net = sctp_findnet(tcb, addr);
				}
				if (net == NULL)
					net = tcb->asoc.primary_destination;
			}
			use_rcvinfo = 1;
		}
	}
	if (tcb == NULL) {
#ifdef SCTP_TCP_MODEL_SUPPORT
		if (inp->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
			tcb = LIST_FIRST(&inp->sctp_asoc_list);
			if (tcb == NULL) {
				splx(s);
				return (ENOTCONN);
			}
			if (addr == NULL) {
				net = tcb->asoc.primary_destination;
			} else {
				net = sctp_findnet(tcb, addr);
				if (net == NULL) {
					net = tcb->asoc.primary_destination;
				}
			}
		}
		else
#endif
			if (addr != NULL)
				tcb = sctp_findassociation_ep_addr(&t_inp, addr,&net, NULL);
	}
	if ((tcb == NULL) &&
	   (inp->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE)) {
		if (control) {
			sctppcbinfo.mbuf_track--;
			m_freem(control);
			control = NULL;
		}
		m_freem(m);
		splx(s);
		return (ENOTCONN);
	} else if ((tcb == NULL) &&
		 (addr == NULL)) {
		if (control) {
			sctppcbinfo.mbuf_track--;
			m_freem(control);
			control = NULL;
		}
		m_freem(m);
		splx(s);
		return (ENOENT);
	} else if (tcb == NULL) {
		/* UDP mode, we must go ahead and start the INIT process */
		tcb = sctp_aloc_assoc(inp, addr, 1,&error);
		if (tcb == NULL) {
			if (control) {
				sctppcbinfo.mbuf_track--;
				m_freem(control);
				control = NULL;
			}
			m_freem(m);
			splx(s);
			return (error);
		}
		queue_only = 1;
		asoc = &tcb->asoc;
		asoc->state = SCTP_STATE_COOKIE_WAIT;
		SCTP_GETTIME_TIMEVAL(&asoc->time_entered);
		if (control) {
			/* see if a init structure exists in cmsg headers */
			struct sctp_initmsg initm;
			int i;
			if (sctp_find_cmsg(SCTP_INIT,(void *)&initm, control, sizeof(initm))) {
				/* we have an INIT override of the default */
				if (initm.sinit_max_attempts)
					asoc->max_init_times = initm.sinit_max_attempts;
				if (initm.sinit_num_ostreams)
					asoc->pre_open_streams = initm.sinit_num_ostreams;
				if (initm.sinit_max_instreams)
					asoc->max_inbound_streams = initm.sinit_max_instreams;
				if (initm.sinit_max_init_timeo)
					asoc->initial_init_rto_max = initm.sinit_max_init_timeo;
			}
			if (asoc->streamoutcnt < asoc->pre_open_streams) {
				/* Default is NOT correct */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
					printf("Ok, defout:%d pre_open:%d\n",
					       asoc->streamoutcnt, asoc->pre_open_streams);
				}
#endif
				free(asoc->strmout, M_PCB);
				asoc->strmout = NULL;
				asoc->streamoutcnt = asoc->pre_open_streams;
				asoc->strmout = malloc((asoc->streamoutcnt *
							sizeof(struct sctp_stream_out)),
						       M_PCB,
						       M_WAIT);
				for (i = 0; i < asoc->streamoutcnt; i++) {
					/*
					 * inbound side must be set to 0xffff,
					 * also NOTE when we get the INIT-ACK
					 * back (for INIT sender) we MUST
					 * reduce the count (streamoutcnt) but
					 * first check if we sent to any of the
					 * upper streams that were dropped (if
					 * some were). Those that were dropped
					 * must be notified to the upper layer
					 * as failed to send.
					 */
					asoc->strmout[i].next_sequence_sent = 0x0;
					TAILQ_INIT(&asoc->strmout[i].outqueue);
					asoc->strmout[i].stream_no = i;
					asoc->strmout[i].next_spoke.tqe_next = 0;
					asoc->strmout[i].next_spoke.tqe_prev = 0;
				}
			}
		}
		sctp_send_initiate(inp, tcb);
		/*
		 * we may want to dig in after this call and adjust the MTU
		 * value. It defaulted to 1500 (constant) but the ro structure
		 * may now have an update and thus we may need to change it
		 * BEFORE we append the message.
		 */
		net = tcb->asoc.primary_destination;
	} else {
		asoc = &tcb->asoc;
		if (((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_WAIT) ||
		    ((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_ECHOED)) {
			queue_only = 1;
		}
		if (((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_SENT) ||
		    ((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_RECEIVED) ||
		    ((asoc->state & SCTP_STATE_MASK) == SCTP_STATE_SHUTDOWN_ACK_SENT) ||
		    (asoc->state & SCTP_STATE_SHUTDOWN_PENDING)) {
			if (control) {
				sctppcbinfo.mbuf_track--;
				m_freem(control);
				control = NULL;
			}
			if ((use_rcvinfo) &&
			   (srcv.sinfo_flags & MSG_ABORT)) {
				sctp_msg_append(tcb, net, m,&srcv);
				error = 0;
			} else {
				if (m)
					m_freem(m);
				error = ECONNRESET;
			}
			splx(s);
			return (error);
		}
	}
	if (use_rcvinfo == 0) {
		srcv = tcb->asoc.def_send;
	}
#ifdef SCTP_DEBUG
	else {
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT5) {
			printf("stream:%d\n", srcv.sinfo_stream);
			printf("flags:%x\n",(u_int)srcv.sinfo_flags);
			printf("ppid:%d\n", srcv.sinfo_ppid);
			printf("context:%d\n", srcv.sinfo_context);
		}
	}
#endif
	if (control) {
		sctppcbinfo.mbuf_track--;
		m_freem(control);
		control = NULL;
	}
	if ((error = sctp_msg_append(tcb, net, m,&srcv))) {
		splx(s);
		return (error);
	}
	if (((inp->sctp_flags & SCTP_PCB_FLAGS_NODELAY) == 0) &&
	   (tcb->asoc.total_flight > 0)) {
	   
		/* Ok, Nagle is set on and we have
		 * data outstanding. Don't send anything
		 * and let the SACK drive out the data.
		 */
		queue_only = 1;
	}
	if (queue_only == 0) {
		/* we can attempt to send too.*/
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("USR Send calls sctp_chunk_output\n");
		}
#endif
		sctp_chunk_output(inp, tcb, 0);
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
		printf("USR Send complete\n");
	}
#endif
	splx(s);
	return (0);
}

void
send_forward_tsn(struct sctp_tcb *stcb,
		 struct sctp_association *asoc)
{
	struct sctp_tmit_chunk *chk;
	struct sctp_forward_tsn_chunk *fwdtsn;

	TAILQ_FOREACH(chk,&asoc->control_send_queue, sctp_next) {
		if (chk->rec.chunk_id == SCTP_FORWARD_CUM_TSN) {
			/* mark it to unsent */
			chk->sent = SCTP_DATAGRAM_UNSENT;
			chk->snd_count = 0;
			/* Do we correct its output location? */
			if (chk->whoTo != asoc->primary_destination) {
				sctp_free_remote_addr(chk->whoTo);
				chk->whoTo = asoc->primary_destination;
				chk->whoTo->ref_count++;
			}
			goto sctp_fill_in_rest;
		}
	}
	/* Ok if we reach here we must build one */
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		return;
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;
	chk->rec.chunk_id = SCTP_FORWARD_CUM_TSN;
	chk->asoc = asoc;
	MGETHDR(chk->data, M_DONTWAIT, MT_DATA);
	if (chk->data == NULL) {
		chk->whoTo->ref_count--;
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		return;
	}
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->whoTo = asoc->primary_destination;
	chk->whoTo->ref_count++;
	TAILQ_INSERT_TAIL(&asoc->control_send_queue,
			  chk,
			  sctp_next);
	asoc->ctrl_queue_cnt++;
 sctp_fill_in_rest:
	/* Here we go through and fill out the part that
	 * deals with stream/seq of the ones we skip.
	 */
	chk->data->m_pkthdr.len = chk->data->m_len = 0;
	{
		struct sctp_tmit_chunk *at,*tp1,*last;
		struct sctp_strseq *strseq;
		int cnt_of_space, i;
		int space_needed;
		int cnt_of_skipped=0;
		TAILQ_FOREACH(at,&asoc->sent_queue, sctp_next) {
			if (at->sent != SCTP_FORWARD_TSN_SKIP) {
				/* no more to look at */
				break;
			}
			cnt_of_skipped++;
		}
		space_needed = (sizeof(struct sctp_forward_tsn_chunk) +  
				(cnt_of_skipped * sizeof(struct sctp_strseq)));
		if ((M_TRAILINGSPACE(chk->data) < space_needed) &&
		   ((chk->data->m_flags & M_EXT) == 0)) {
			/* Need a M_EXT, get one and move 
			 * fwdtsn to data area.
			 */
			MCLGET(chk->data, M_DONTWAIT);
		}
		cnt_of_space = M_TRAILINGSPACE(chk->data);
		if (cnt_of_space > (asoc->smallest_mtu-SCTP_MIN_OVERHEAD)) {
			/* trim to a mtu size */
			cnt_of_space = asoc->smallest_mtu - SCTP_MIN_OVERHEAD;
		}
		if (cnt_of_space < space_needed) {
			/* ok we must trim down the chunk by lowering
			 * the advance peer ack point.
			 */
			cnt_of_skipped = (cnt_of_space-
					  ((sizeof(struct sctp_forward_tsn_chunk))/
 					    sizeof(struct sctp_strseq)));
			/* Go through and find the TSN that
			 * will be the one we report.
			 */
			at = TAILQ_FIRST(&asoc->sent_queue);
			for (i = 0; i < cnt_of_skipped; i++) {
				tp1 = TAILQ_NEXT(at, sctp_next);
				at = tp1;
			}
			last = at;
			/* last now points to last one I can report, update peer ack point */
			asoc->advanced_peer_ack_point = last->rec.data.TSN_seq;
			space_needed -= (cnt_of_skipped * sizeof(struct sctp_strseq));
		}
		chk->send_size = space_needed;
		/* Setup the chunk */
		fwdtsn = mtod(chk->data, struct sctp_forward_tsn_chunk *);
		fwdtsn->ch.chunk_length = htons(chk->send_size);
		fwdtsn->ch.chunk_flags = 0;
		fwdtsn->ch.chunk_type = SCTP_FORWARD_CUM_TSN;
		fwdtsn->new_cumulative_tsn = htonl(asoc->advanced_peer_ack_point);
		chk->send_size = (sizeof(struct sctp_forward_tsn_chunk) + 
				  (cnt_of_skipped * sizeof(struct sctp_strseq)));
		chk->data->m_pkthdr.len = chk->data->m_len = chk->send_size;
		fwdtsn++;
		/* Move pointer to after the fwdtsn and transfer to
		 * the strseq pointer.
		 */
		strseq = (struct sctp_strseq *)fwdtsn;
		/* Now populate the strseq list. This is done
		 * blindly without pullingout duplicate stream info.
		 * This is inefficent but won't harm the process since
		 * the peer will look at these in sequence and will thus
		 * release anything. It could mean we exceed the PMTU and
		 * chop off some that we could have included.. but this
		 * is unlikely (aka 1432/4 would mean 300+ stream seq's would
		 * have to be reported in one FWD-TSN. With a bit of work
		 * we can later FIX this to optimize and pull out duplcates..
		 * but it does add more overhead. So for now... not!
		 */
		at = TAILQ_FIRST(&asoc->sent_queue);
		for (i = 0; i < cnt_of_skipped; i++) {
			tp1 = TAILQ_NEXT(at, sctp_next);
			strseq->stream = ntohs(at->rec.data.stream_number);
			strseq->sequence = ntohs(at->rec.data.stream_seq);
			at = tp1;
		}
	}
	return;

}

void
sctp_send_sack(struct sctp_tcb *stcb)
{
	/*
	 * Queue up a SACK in the control queue. We must first check to
	 * see if a SACK is somehow on the control queue. If so, we will
	 * take and and remove the old one.
	 */
	struct sctp_association *asoc;
	struct sctp_tmit_chunk *chk,*a_chk;
	struct sctp_sack_chunk *sack;
	struct sctp_gap_ack_block *gap_descriptor;
	u_int32_t *dup;
	int maxi, start, i, seeing_ones;
	int num_gap_blocks, space;

	start = maxi = 0;
	seeing_ones = 1;
	a_chk = NULL;
	asoc = &stcb->asoc;
	if (asoc->last_data_chunk_from == NULL) {
		/* Hmm we never received anything */
		return;
	}
	sctp_set_rwnd(stcb, asoc);
	TAILQ_FOREACH(chk,&asoc->control_send_queue, sctp_next) {
		if (chk->rec.chunk_id == SCTP_SELECTIVE_ACK) {
			/* Hmm, found a sack already on queue, remove it */
			TAILQ_REMOVE(&asoc->control_send_queue, chk, sctp_next);
			asoc->ctrl_queue_cnt++;
			a_chk = chk;
			if (a_chk->data)
				m_freem(a_chk->data);
			a_chk->data = NULL;
			sctp_free_remote_addr(a_chk->whoTo);
			a_chk->whoTo = NULL;
			break;
		}
	}
	if (a_chk == NULL) {
#if defined(__FreeBSD__)
		a_chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		a_chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
							   PR_NOWAIT);
#endif
		if (a_chk == NULL) {
			/* No memory so we drop the idea, and set a timer */
			sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
					stcb->sctp_ep, stcb, NULL);
			sctp_timer_start(SCTP_TIMER_TYPE_RECV,
					 stcb->sctp_ep, stcb, NULL);
			return;
		}
		sctppcbinfo.ipi_count_chunk++;
		sctppcbinfo.ipi_gencnt_chunk++;
		a_chk->rec.chunk_id = SCTP_SELECTIVE_ACK;
	}
	a_chk->asoc = asoc;
	a_chk->snd_count = 0;
	a_chk->send_size = 0;	/* fill in later */
	a_chk->sent = SCTP_DATAGRAM_UNSENT;


	if ((asoc->numduptsns) ||
	   (asoc->last_data_chunk_from->dest_state & SCTP_ADDR_NOT_REACHABLE)
		) {
		/* Ok, we have some duplicates or the destination for the
		 * sack is unreachable, lets see if we can select an alternate
		 * than asoc->last_data_chunk_from
		 */
		if ((!(asoc->last_data_chunk_from->dest_state &
		      SCTP_ADDR_NOT_REACHABLE)) &&
		   (asoc->used_alt_onsack > 2)) {
			/* We used an alt last time, don't this time */
			a_chk->whoTo = NULL;
		} else {
			asoc->used_alt_onsack++;
			a_chk->whoTo = sctp_find_alternate_net(stcb, asoc->last_data_chunk_from);
		}
		if (a_chk->whoTo == NULL) {
			/* Nope, no alternate */
			a_chk->whoTo = asoc->last_data_chunk_from;
			asoc->used_alt_onsack = 0;
		}
	} else {
		/* No duplicates so we use the last
		 * place we received data from.
		 */
#ifdef SCTP_DEBUG
		if (asoc->last_data_chunk_from == NULL) {
			printf("Huh, last_data_chunk_from is null when we want to sack??\n");
		}
#endif
		asoc->used_alt_onsack = 0;
		a_chk->whoTo = asoc->last_data_chunk_from;
	}
	if (a_chk->whoTo)
		a_chk->whoTo->ref_count++;

	/* Ok now lets formulate a MBUF with our sack */
	MGETHDR(a_chk->data, M_DONTWAIT, MT_DATA);
	if ((a_chk->data == NULL) ||
	   (a_chk->whoTo == NULL)) {
		/* rats, no mbuf memory */
		if (a_chk->data) {
			/* was a problem with the destination */
			m_freem(a_chk->data);
			a_chk->data = NULL;
		}
		a_chk->whoTo->ref_count--;
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, a_chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, a_chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
				stcb->sctp_ep, stcb, NULL);
		sctp_timer_start(SCTP_TIMER_TYPE_RECV,
				 stcb->sctp_ep, stcb, NULL);
		return;
	}
	/* First count the number of gap ack blocks we need */
	if (asoc->highest_tsn_inside_map == asoc->cumulative_tsn) {
		/* We know if there are none above the cum-ack we
		 * have everything with NO gaps
		 */
		num_gap_blocks = 0;
	} else {
		/* Ok we must count how many gaps we
		 * have.
		 */
		num_gap_blocks = 0;
		if (asoc->highest_tsn_inside_map >= asoc->mapping_array_base_tsn) {
			maxi = (asoc->highest_tsn_inside_map - asoc->mapping_array_base_tsn);
		} else {
			maxi = (asoc->highest_tsn_inside_map  + (MAX_TSN - asoc->mapping_array_base_tsn) + 1);
		}
		if (asoc->cumulative_tsn >= asoc->mapping_array_base_tsn) {
			start = (asoc->cumulative_tsn - asoc->mapping_array_base_tsn);
		} else {
			/* Set it so we start at 0 */
			start = -1;
		}
		/* Ok move start up one to look at the NEXT past the cum-ack */
		start++;
		for (i = start; i <= maxi; i++) {
			if (seeing_ones) {
				/* while seeing ones I must
				 * transition back to 0 before
				 * finding the next gap and
				 * counting the segment.
				 */
				if (SCTP_IS_TSN_PRESENT(asoc->mapping_array, i) == 0) {
					seeing_ones = 0;
				}
			} else {
				if (SCTP_IS_TSN_PRESENT(asoc->mapping_array, i)) {
					seeing_ones = 1;
					num_gap_blocks++;
				}
			}
		}
		if (num_gap_blocks == 0) {
			/*
			 * Traveled all of the bits and NO one,
			 * must have reneged
			 */
			asoc->highest_tsn_inside_map = asoc->cumulative_tsn;
		}
	}
	/* Now calculate the space needed */
	space = (sizeof(struct sctp_sack_chunk) +
		 (num_gap_blocks * sizeof(struct sctp_gap_ack_block)) +
		 (asoc->numduptsns * sizeof(int32_t))
		);
	if (space > (asoc->smallest_mtu-SCTP_MAX_OVERHEAD)) {
		/* Reduce the size of the sack to fit */
		int calc, fit;
		calc = (asoc->smallest_mtu - SCTP_MAX_OVERHEAD);
		calc -= sizeof(struct sctp_gap_ack_block);
		fit = calc/sizeof(struct sctp_gap_ack_block);
		if (fit > num_gap_blocks) {
			/* discard some dups */
			asoc->numduptsns = (fit - num_gap_blocks);
		} else {
			/* discard all dups and some gaps */
			num_gap_blocks = fit;
			asoc->numduptsns = 0;
		}
		/* recalc space */
		space = (sizeof(struct sctp_sack_chunk) +
			 (num_gap_blocks * sizeof(struct sctp_gap_ack_block)) +
			 (asoc->numduptsns * sizeof(int32_t))
			);

	}
	if (space > MHLEN) {
		/* We need a cluster */
		MCLGET(a_chk->data, M_DONTWAIT);
		if ((a_chk->data->m_flags & M_EXT) != M_EXT) {
			/* can't get a cluster
			 * give up and try later.
			 */
			if (a_chk->data)
				m_freem(a_chk->data);
			a_chk->data = NULL;
			a_chk->whoTo->ref_count--;
#if defined(__FreeBSD__)
			zfreei(sctppcbinfo.ipi_zone_chunk, a_chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, a_chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			sctp_timer_stop(SCTP_TIMER_TYPE_RECV,
					stcb->sctp_ep, stcb, NULL);
			sctp_timer_start(SCTP_TIMER_TYPE_RECV,
					 stcb->sctp_ep, stcb, NULL);
			return;
		}
	}
	/* ok, lets go through and fill it in */
	sack = mtod(a_chk->data, struct sctp_sack_chunk *);
	sack->ch.chunk_type = SCTP_SELECTIVE_ACK;
	sack->ch.chunk_flags = 0;
	sack->sack.cum_tsn_ack = htonl(asoc->cumulative_tsn);
	sack->sack.a_rwnd = htonl(asoc->my_rwnd);
	sack->sack.num_gap_ack_blks = htons(num_gap_blocks);
	sack->sack.num_dup_tsns = htons(asoc->numduptsns);

	a_chk->send_size = (sizeof(struct sctp_sack_chunk) +
			    (num_gap_blocks * sizeof(struct sctp_gap_ack_block)) +
			    (asoc->numduptsns * sizeof(int32_t)));
	a_chk->data->m_pkthdr.len = a_chk->data->m_len = a_chk->send_size;
	sack->ch.chunk_length = htons(a_chk->send_size);

	gap_descriptor = (struct sctp_gap_ack_block *)((caddr_t)sack + sizeof(struct sctp_sack_chunk));
	seeing_ones = 0;
	for (i = start; i <= maxi; i++) {
		if (num_gap_blocks == 0) {
			break;
		}
		if (seeing_ones) {
			/* while seeing Ones I must
			 * transition back to 0 before
			 * finding the next gap
			 */
			if (SCTP_IS_TSN_PRESENT(asoc->mapping_array, i) == 0) {
				gap_descriptor->end = htons(((u_short)(i-start)));
				gap_descriptor++;
				seeing_ones = 0;
				num_gap_blocks--;
			}
		} else {
			if (SCTP_IS_TSN_PRESENT(asoc->mapping_array, i)) {
				gap_descriptor->start = htons(((u_short)(i+1-start)));
				/* advance struct to next pointer */
				seeing_ones = 1;
			}
		}
	}
	if (num_gap_blocks) {
		/* special case where the array is all 1's
		 * to the end of the array.
		 */
		gap_descriptor->end = htons(((u_short)((i-start))));
		gap_descriptor++;
	}
	/* now we must add any dups we are going to report. */
	if (asoc->numduptsns) {
		dup = (u_int32_t *)gap_descriptor;
		for (i = 0; i < asoc->numduptsns; i++) {
			*dup = htonl(asoc->dup_tsns[i]);
			dup++;
		}
		asoc->numduptsns = 0;
	}
	/* now that the chunk is prepared queue it to the control
	 * chunk queue.
	 */
	TAILQ_INSERT_TAIL(&asoc->control_send_queue,
			  a_chk,
			  sctp_next);
	asoc->ctrl_queue_cnt++;
	sctp_pegs[SCTP_PEG_SACKS_SENT]++;
	return;
}

void
sctp_send_abort_tcb(struct sctp_tcb *stcb, struct mbuf *operr)
{
	struct mbuf *m_abort;
	struct sctp_abort_msg *abort_m;
	int sz;
	abort_m = NULL;
	MGETHDR(m_abort, M_DONTWAIT, MT_HEADER);
	if (m_abort == NULL) {
		/* no mbuf's */
		return;
	}
	abort_m = mtod(m_abort, struct sctp_abort_msg *);
	m_abort->m_len = sizeof(struct sctp_abort_msg);
	m_abort->m_next = operr;
	sz = 0;
	if (operr) {
		struct mbuf *n;
		n = operr;
		while (n) {
			sz += n->m_len;
			n = n->m_next;
		}
	}
	abort_m->msg.ch.chunk_type = SCTP_ABORT_ASSOCIATION;
	abort_m->msg.ch.chunk_flags = 0;
	abort_m->msg.ch.chunk_length = htons(sizeof(struct sctp_abort_chunk) +
					     sz);
	abort_m->sh.src_port = stcb->sctp_ep->sctp_lport;
	abort_m->sh.dest_port = stcb->rport;
	abort_m->sh.v_tag = htonl(stcb->asoc.peer_vtag);
	abort_m->sh.checksum = 0;
	m_abort->m_pkthdr.len = m_abort->m_len + sz;

	m_abort->m_pkthdr.rcvif = 0;
	sctp_lowlevel_chunk_output(stcb->sctp_ep,
				   stcb,
				   stcb->asoc.primary_destination,
				   (struct sockaddr *)&stcb->asoc.primary_destination->ra._l_addr,
				   m_abort,
				   1, 0, NULL, 0);
}

int
sctp_send_shutdown_complete(struct sctp_tcb *stcb,
			    struct sctp_nets *net)

{
	/* formulate and SEND a SHUTDOWN-COMPLETE */
	struct mbuf *m_shutdown_comp;
	struct sctp_shutdown_complete_msg *comp_cp;

	m_shutdown_comp = NULL;
	MGETHDR(m_shutdown_comp, M_DONTWAIT, MT_HEADER);
	if (m_shutdown_comp == NULL) {
		/* no mbuf's */
		return (-1);
	}
	comp_cp = mtod(m_shutdown_comp, struct sctp_shutdown_complete_msg *);
	comp_cp->shut_cmp.ch.chunk_type = SCTP_SHUTDOWN_COMPLETE;
	comp_cp->shut_cmp.ch.chunk_flags = 0;
	comp_cp->shut_cmp.ch.chunk_length = htons(sizeof(struct sctp_shutdown_complete_chunk));
	comp_cp->sh.src_port = stcb->sctp_ep->sctp_lport;
	comp_cp->sh.dest_port = stcb->rport;
	comp_cp->sh.v_tag = htonl(stcb->asoc.peer_vtag);
	comp_cp->sh.checksum = 0;

	m_shutdown_comp->m_pkthdr.len = m_shutdown_comp->m_len = sizeof(struct sctp_shutdown_complete_msg);
	m_shutdown_comp->m_pkthdr.rcvif = 0;
	sctp_lowlevel_chunk_output(stcb->sctp_ep,
				   stcb,
				   net,
				   (struct sockaddr *)&net->ra._l_addr,
				   m_shutdown_comp,
				   1, 0, NULL, 0);
	if ((stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) ||
	    (stcb->sctp_ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL)) {
		stcb->sctp_ep->sctp_flags &= ~SCTP_PCB_FLAGS_CONNECTED;
		soisdisconnected(stcb->sctp_ep->sctp_socket);
	}
	return (0);
}

int
sctp_send_shutdown_complete2(struct sctp_inpcb *ep,
			     struct sockaddr *to,
			     u_int32_t vtag
			     )
{
	/* formulate and SEND a SHUTDOWN-COMPLETE */
	struct mbuf *m_shutdown_comp;
	struct sctp_shutdown_complete_msg *comp_cp;

	m_shutdown_comp = NULL;
	MGETHDR(m_shutdown_comp, M_DONTWAIT, MT_HEADER);
	if (m_shutdown_comp == NULL) {
		/* no mbuf's */
		return (-1);
	}
	comp_cp = mtod(m_shutdown_comp, struct sctp_shutdown_complete_msg *);
	comp_cp->shut_cmp.ch.chunk_type = SCTP_SHUTDOWN_COMPLETE;
	comp_cp->shut_cmp.ch.chunk_flags = SCTP_HAD_NO_TCB;
	comp_cp->shut_cmp.ch.chunk_length = htons(sizeof(struct sctp_shutdown_complete_chunk));
	comp_cp->sh.src_port = ep->sctp_lport;
	comp_cp->sh.dest_port = ((struct sockaddr_in *)to)->sin_port;
	comp_cp->sh.v_tag = vtag;
	comp_cp->sh.checksum = 0;

	m_shutdown_comp->m_pkthdr.len = m_shutdown_comp->m_len = sizeof(struct sctp_shutdown_complete_msg);
	m_shutdown_comp->m_pkthdr.rcvif = 0;
	sctp_lowlevel_chunk_output(ep,
				   NULL,
				   NULL,
				   to,
				   m_shutdown_comp,
				   1, 0, NULL, 0);

	return (0);

}


static struct sctp_nets *
sctp_select_hb_destination(struct sctp_tcb *tcb, struct timeval *now)
{
	struct sctp_nets *net, *hnet;
	int ticks_goneby, highest_ticks;

	SCTP_GETTIME_TIMEVAL(now);
	highest_ticks = 0;
	hnet = NULL;
	TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
		if ((net->dest_state & SCTP_ADDR_NOHB) ||
		    (net->dest_state & SCTP_ADDR_OUT_OF_SCOPE)) {
			/* Skip this guy from consideration */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
				printf("Skipping net:%x state:%d nohb/out-of-scope\n",
				       (u_int)net, net->dest_state);
			}
#endif
			continue;
		}
		if (sctp_destination_is_reachable(tcb, (struct sockaddr *)&net->ra._l_addr) == 0) {
			/* skip this dest net from consideration */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
				printf("Skipping net:%x reachable NOT\n",
				       (u_int)net);
			}
#endif
			continue;
		}
		if (net->last_sent_time.tv_sec) {
			/* Sent to so we subtract */
			ticks_goneby = (now->tv_sec - net->last_sent_time.tv_sec) * hz;
			/* Check to see if this guy needs a cwnd reduction */
			/* With the Allman change above we no longer
			 * need this since we are ALWAYS limited to
			 * 4 * MTU over flightsize (for idle this means
			 * we are limited to 4 * MTU
			 */
			/*
			  if ((ticks_goneby > net->RTO) &&
			  (net->cwnd > (net->mtu*2))) {
			*/
				/* Cut the cwnd in 1/2 */
			/*
			  net->cwnd /= 2;
			  if (net->cwnd < (net->mtu * 2))
			*/
			/* limit its degrade to 2 MTU */
			/*net->cwnd = (net->mtu * 2);*/
/*			}*/
		} else
			/* Never been sent to */
			ticks_goneby = 0x7fffffff;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
			printf("net:%x ticks_goneby:%d\n",
			       (u_int)net, ticks_goneby);
		}
#endif

		if ((ticks_goneby >= tcb->asoc.heart_beat_delay) &&
		    (ticks_goneby > highest_ticks)) {
			highest_ticks = ticks_goneby;
			hnet = net;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
				printf("net:%x is the new high\n",
				       (u_int)net);
			}
#endif
		}
	}
	if (highest_ticks && (highest_ticks > tcb->asoc.heart_beat_delay)) {
		/* Found the one with longest delay bounds */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
			printf("net:%x is the hb winner -",
			       (u_int)hnet);
			if (hnet)
				sctp_print_address((struct sockaddr *)&hnet->ra._l_addr);
			else
				printf(" none\n");
		}
#endif
		return (hnet);
	}
	/* Nothing to HB */
	return (NULL);
}

void
sctp_send_hb(struct sctp_tcb *tcb, int user_req, struct sctp_nets *u_net)
{
	struct sctp_tmit_chunk *chk;
	struct sctp_nets *net;
	struct sctp_heartbeat_chunk *hb;
	struct timeval now;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (user_req == 0) {
		net = sctp_select_hb_destination(tcb,&now);
		if (net == NULL) {
			/* All our busy none to send to, just
			 * start the timer again.
			 */
			if (tcb->asoc.state == 0) {
				return;
			}
			sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT,
					 tcb->sctp_ep,
					 tcb,
					 net);
			return;
		}
	} else {
		net = u_net;
		if (net == NULL) {
			return;
		}
		SCTP_GETTIME_TIMEVAL(&now);
	}
	sin = (struct sockaddr_in *)&net->ra._l_addr;
	if (sin->sin_family != AF_INET) {
		if (sin->sin_family != AF_INET6) {
			/* huh */
			return;
		}
	}
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
			printf("Gak, can't get a chunk for hb\n");
		}
#endif
		return;
	}
	sctppcbinfo.ipi_gencnt_chunk++;
	sctppcbinfo.ipi_count_chunk++;
	chk->rec.chunk_id = SCTP_HEARTBEAT_REQUEST;
	chk->asoc = &tcb->asoc;
	chk->send_size = sizeof(struct sctp_heartbeat_chunk);
	MGETHDR(chk->data, M_DONTWAIT, MT_DATA);
	if (chk->data == NULL) {
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		return;
	}
	chk->data->m_pkthdr.len = chk->data->m_len = chk->send_size;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->whoTo = net;
	chk->whoTo->ref_count++;
	/* Now we have a mbuf that we can fill in with the details */
	hb = mtod(chk->data, struct sctp_heartbeat_chunk *);

	/* fill out chunk header */
	hb->ch.chunk_type = SCTP_HEARTBEAT_REQUEST;
	hb->ch.chunk_flags = 0;
	hb->ch.chunk_length = htons(chk->send_size);
	/* Fill out hb parameter */
	hb->heartbeat.hb_info.ph.param_type = htons(SCTP_HEARTBEAT_INFO);
	hb->heartbeat.hb_info.ph.param_length = htons(sizeof(struct sctp_heartbeat_info_param));
	hb->heartbeat.hb_info.time_value_1 = now.tv_sec;
	hb->heartbeat.hb_info.time_value_2 = now.tv_usec;
	/* Did our user request this one, put it in */
	hb->heartbeat.hb_info.user_req = user_req;
	hb->heartbeat.hb_info.addr_family = sin->sin_family;
	hb->heartbeat.hb_info.addr_len = sin->sin_len;
	if (sin->sin_family == AF_INET) {
		memcpy(hb->heartbeat.hb_info.address,&sin->sin_addr, sizeof(sin->sin_addr));
	} else if (sin->sin_family == AF_INET6) {
		/* We leave the scope the way it is in our lookup table. */
		sin6 = (struct sockaddr_in6 *)&net->ra._l_addr;
		memcpy(hb->heartbeat.hb_info.address,&sin6->sin6_addr, sizeof(sin6->sin6_addr));
	} else {
		/* huh compiler bug */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
			printf("Compiler bug bleeds a mbuf and a chunk\n");
		}
#endif
		return;
	}
	/* ok we have a destination that needs a beat */
	/* lets do the theshold managment Qiaobing style */
	if (sctp_threshold_management(tcb->sctp_ep,
				     tcb,
				     net,
				     tcb->asoc.max_send_times)) {
		/* we have lost the association, in a way this
		 * is quite bad since we really are one less time
		 * since we really did not send yet. This is the
		 * down side to the Dr. Xie style as defined in the RFC
		 * and not my alternate style defined in the RFC.
		 */
		if (chk->data != NULL) {
			m_freem(chk->data);
			chk->data = NULL;
		}
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		return;
	}
	net->hb_responded = 0;
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT4) {
		printf("Inserting chunk for HB\n");
	}
#endif
	TAILQ_INSERT_TAIL(&tcb->asoc.control_send_queue,
			  chk,
			  sctp_next);
	tcb->asoc.ctrl_queue_cnt++;
	sctp_pegs[SCTP_HB_SENT]++;
	/* Call directly med level routine to put out the chunk. It will
	 * always tumble out control chunks aka HB but it may even tumble
	 * out data too.
	 */

	if (user_req == 0) {
		/* Ok now lets start the HB timer if it is NOT a user req */
		sctp_timer_start(SCTP_TIMER_TYPE_HEARTBEAT,
				 tcb->sctp_ep,
				 tcb,
				 net);
	}
}

void
sctp_send_ecn_echo(struct sctp_tcb *tcb, struct sctp_nets *net, u_int32_t high_tsn)
{
	struct sctp_association *asoc;
	struct sctp_ecne_chunk *ecne;
	struct sctp_tmit_chunk *chk;
	asoc = &tcb->asoc;
	TAILQ_FOREACH(chk,&asoc->control_send_queue, sctp_next) {
		if (chk->rec.chunk_id == SCTP_ECN_ECHO) {
			/* Hmm, found a previous ECN_ECHO
			 * update it if needed.
			 */
			ecne = mtod(chk->data, struct sctp_ecne_chunk *);
			ecne->tsn = htonl(high_tsn);
			return;
		}
	}
	/* nope could not find one to update so we must build one */
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		return;
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;
	chk->rec.chunk_id = SCTP_ECN_ECHO;
	chk->asoc = &tcb->asoc;
	chk->send_size = sizeof(struct sctp_ecne_chunk);
	MGETHDR(chk->data, M_DONTWAIT, MT_DATA);
	if (chk->data == NULL) {
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		return;
	}
	chk->data->m_pkthdr.len = chk->data->m_len = chk->send_size;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->whoTo = net;
	chk->whoTo->ref_count++;
	ecne = mtod(chk->data, struct sctp_ecne_chunk *);
	ecne->ch.chunk_type = SCTP_ECN_ECHO;
	ecne->ch.chunk_flags = 0;
	ecne->ch.chunk_length = htons(sizeof(struct sctp_ecne_chunk));
	ecne->tsn = htonl(high_tsn);
	TAILQ_INSERT_TAIL(&tcb->asoc.control_send_queue,
			  chk,
			  sctp_next);
	asoc->ctrl_queue_cnt++;
}

void
sctp_send_cwr(struct sctp_tcb *tcb, struct sctp_nets *net, u_int32_t high_tsn)
{
	struct sctp_association *asoc;
	struct sctp_cwr_chunk *cwr;
	struct sctp_tmit_chunk *chk;

	asoc = &tcb->asoc;
	TAILQ_FOREACH(chk,&asoc->control_send_queue, sctp_next) {
		if (chk->rec.chunk_id == SCTP_ECN_CWR) {
			/* Hmm, found a previous ECN_CWR
			 * update it if needed.
			 */
			cwr = mtod(chk->data, struct sctp_cwr_chunk *);
			if (compare_with_wrap(high_tsn, ntohl(cwr->tsn),
					      MAX_TSN)) {
				cwr->tsn = htonl(high_tsn);
			}
			return;
		}
	}
	/* nope could not find one to update so we must build one */
#if defined(__FreeBSD__)
	chk = (struct sctp_tmit_chunk *)zalloci(sctppcbinfo.ipi_zone_chunk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	chk = (struct sctp_tmit_chunk *)pool_get(&sctppcbinfo.ipi_zone_chunk,
						 PR_NOWAIT);
#endif
	if (chk == NULL) {
		return;
	}
	sctppcbinfo.ipi_count_chunk++;
	sctppcbinfo.ipi_gencnt_chunk++;
	chk->rec.chunk_id = SCTP_ECN_CWR;
	chk->asoc = &tcb->asoc;
	chk->send_size = sizeof(struct sctp_cwr_chunk);
	MGETHDR(chk->data, M_DONTWAIT, MT_DATA);
	if (chk->data == NULL) {
#if defined(__FreeBSD__)
		zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
		sctppcbinfo.ipi_count_chunk--;
		if ((int)sctppcbinfo.ipi_count_chunk < 0) {
			panic("Chunk count is negative");
		}
		sctppcbinfo.ipi_gencnt_chunk++;
		return;
	}
	chk->data->m_pkthdr.len = chk->data->m_len = chk->send_size;
	chk->sent = SCTP_DATAGRAM_UNSENT;
	chk->snd_count = 0;
	chk->whoTo = net;
	chk->whoTo->ref_count++;
	cwr = mtod(chk->data, struct sctp_cwr_chunk *);
	cwr->ch.chunk_type = SCTP_ECN_CWR;
	cwr->ch.chunk_flags = 0;
	cwr->ch.chunk_length = htons(sizeof(struct sctp_cwr_chunk));
	cwr->tsn = htonl(high_tsn);
	TAILQ_INSERT_TAIL(&tcb->asoc.control_send_queue,
			  chk,
			  sctp_next);
	asoc->ctrl_queue_cnt++;
}


void
sctp_handle_ecn_cwr(struct sctp_cwr_chunk *cwr,
		    struct sctp_tcb *tcb)
{
	/* Here we get a CWR from the peer. We must look in
	 * the outqueue and make sure that we have a covered
	 * ECNE in teh control chunk part. If so remove it.
	 */
	struct sctp_tmit_chunk *chk;
	struct sctp_ecne_chunk *ecne;

	TAILQ_FOREACH(chk,&tcb->asoc.control_send_queue, sctp_next) {
		if (chk->rec.chunk_id == SCTP_ECN_ECHO) {
			/* Look for and remove if it is the right TSN. Since
			 * there is only ONE ECNE on the control queue at
			 * any one time we don't need to worry about more than
			 * one!
			 */
			ecne = mtod(chk->data, struct sctp_ecne_chunk *);
			if (compare_with_wrap(ntohl(cwr->tsn), ntohl(ecne->tsn),
					     MAX_TSN) ||
			   (cwr->tsn == ecne->tsn)) {
				/* this covers this ECNE, we can remove it */
				TAILQ_REMOVE(&tcb->asoc.control_send_queue,
					     chk, sctp_next);
				if (chk->data) {
					m_freem(chk->data);
					chk->data = NULL;
				}
				tcb->asoc.ctrl_queue_cnt--;
				sctp_free_remote_addr(chk->whoTo);
#if defined(__FreeBSD__)
				zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
				pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
				sctppcbinfo.ipi_count_chunk--;
				if ((int)sctppcbinfo.ipi_count_chunk < 0) {
					panic("Chunk count is negative");
				}
				sctppcbinfo.ipi_gencnt_chunk++;
				break;
			}
		}
	}
}

void
sctp_send_abort(struct mbuf *m,
		struct ip *oip,
		struct sctphdr *osh,
		int off,
		u_int32_t vtag,
		struct mbuf *err_cause)
{
	/*
	 * Formulate the abort message, and send it back down.
	 */
	register struct mbuf *mout;
	register struct sctp_abort_msg *abm;
	register struct ip *iph;
	struct route ro;
	int abtlen;
	unsigned int val;

	/* don't respond to ABORT with ABORT */
	if (sctp_is_there_an_abort_here(m, off)) {
		if (err_cause)
			m_freem(err_cause);
		return;
	}
	MGETHDR(mout, M_DONTWAIT, MT_HEADER);
	if (mout == NULL) {
		if (err_cause)
			m_freem(err_cause);
		return;
	}
	mout->m_len = sizeof(struct ip) + sizeof(struct sctp_abort_msg);
	mout->m_next = err_cause;
	iph = mtod(mout, struct ip *);
	/* Fill in the IP header for the ABORT */
	iph->ip_v = IPVERSION;
	iph->ip_hl = (sizeof(struct ip)/4);
	iph->ip_tos = (u_char)0;
	iph->ip_id = 0;
	iph->ip_off = 0;
	iph->ip_ttl = MAXTTL;

	iph->ip_p = IPPROTO_SCTP;
	iph->ip_src.s_addr = oip->ip_dst.s_addr;
	iph->ip_dst.s_addr = oip->ip_src.s_addr;

	/* let IP layer calculate this */
	iph->ip_sum = 0;

	/* Now copy in and fill in the ABORT tags etc. */
	/*  osh = (struct sctphdr *) ((caddr_t)oip + (oip->ip_hl << 2));*/
	abm = (struct sctp_abort_msg *)((caddr_t)iph + (sizeof(struct ip)));

	abm->sh.src_port = osh->dest_port;
	abm->sh.dest_port = osh->src_port;
	abm->sh.checksum = 0;
	if (vtag == 0) {
		abm->sh.v_tag = osh->v_tag;
		abm->msg.ch.chunk_flags = SCTP_HAD_NO_TCB;
	} else {
		abm->sh.v_tag = htonl(vtag);
		abm->msg.ch.chunk_flags = 0;
	}
	abm->msg.ch.chunk_type = SCTP_ABORT_ASSOCIATION;
	if (err_cause) {
		struct mbuf *m_tmp = err_cause;
		int err_len = 0;
		/* get length of the err_cause chain */
		while (m_tmp != NULL) {
			err_len += m_tmp->m_len;
			m_tmp = m_tmp->m_next;
		}
		mout->m_pkthdr.len = mout->m_len + err_len;
		abm->msg.ch.chunk_length = htons(sizeof(struct sctp_chunkhdr) +
						 err_len);
		abtlen = sizeof(struct sctp_abort_msg) + err_len;
	} else {
		mout->m_pkthdr.len = mout->m_len;
		abm->msg.ch.chunk_length = htons(sizeof(struct sctp_chunkhdr));
		abtlen = sizeof(struct sctp_abort_msg);
	}
	/* add checksum */
	val = sctp_calculate_sum(mout, NULL,(sizeof(struct ip)));
	abm->sh.checksum = val;
	/* set IPv4 length */
	iph->ip_len = mout->m_pkthdr.len;
	/* zap the rcvif, it should be null */
	mout->m_pkthdr.rcvif = 0;
	/* zap the stack pointer to the route */
	bzero(&ro, sizeof ro);
	/* out it goes */
	(void) ip_output(mout, 0, &ro, IP_RAWOUTPUT, NULL);
	sctp_pegs[SCTP_DATAGRAMS_SENT]++;
	/* Free the route if we got one back */
	if (ro.ro_rt)
		RTFREE(ro.ro_rt);
}

#ifdef INET6
void
sctp6_send_abort(struct mbuf *m,
		 struct ip6_hdr *oip,
		 struct sctphdr *osh,
		 int off,
		 u_int32_t vtag,
		 struct mbuf *err_cause)
{
	/*
	 * Formulate the abort message, and send it back down.
	 */
	register struct mbuf *mout;
	register struct sctp_abort_msg *abm;
	register struct ip6_hdr *iph6;
	struct sockaddr_in6 lsa6, fsa6;
#ifdef NEW_STRUCT_ROUTE
	struct route ro;
#else
	struct route_in6 ro;
#endif
	int abtlen;
	unsigned int val;

	/* don't respond to ABORT with ABORT */
	if (sctp_is_there_an_abort_here(m, off)) {
		return;
	}
#if 0
	/*
	 * Use ICMP rate limit since this is the equivalent of
	 * sending a no listener ICMP message
	 */
	if (icmp6_ratelimit(&oip->ip6_dst, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_NOPORT)) {
		/* Rate limit in effect */
		return;
	}
#endif
	MGETHDR(mout, M_DONTWAIT, MT_HEADER);
	if (mout == NULL) {
		return;
	}
	mout->m_next = err_cause;
	mout->m_len = sizeof(struct ip6_hdr) + sizeof(struct sctp_abort_msg);

	iph6 = mtod(mout, struct ip6_hdr *);

	/* Fill in the IP6 header for the ABORT */
	iph6->ip6_flow = oip->ip6_flow;
	iph6->ip6_hlim = ip6_defhlim;
	iph6->ip6_nxt = IPPROTO_SCTP;
	iph6->ip6_src = oip->ip6_dst;
	iph6->ip6_dst = oip->ip6_src;
	/* Now copy in and fill in the ABORT tags etc. */
	/*  osh = (struct sctphdr *) ((caddr_t)oip + (oip->ip_hl << 2));*/
	abm = (struct sctp_abort_msg *)((caddr_t)iph6 +
					sizeof(struct ip6_hdr));

	abm->sh.src_port = osh->dest_port;
	abm->sh.dest_port = osh->src_port;
	abm->sh.checksum = 0;
	abm->msg.ch.chunk_type = SCTP_ABORT_ASSOCIATION;
	if (vtag == 0) {
		abm->msg.ch.chunk_flags = SCTP_HAD_NO_TCB;
		abm->sh.v_tag = osh->v_tag;
	} else {
		abm->msg.ch.chunk_flags = 0;
		abm->sh.v_tag = htonl(vtag);
	}
	if (err_cause) {
		struct mbuf *m_tmp = err_cause;
		int err_len = 0;
		/* get length of the err_cause chain */
		while (m_tmp != NULL) {
			err_len += m_tmp->m_len;
			m_tmp = m_tmp->m_next;
		}
		mout->m_pkthdr.len = mout->m_len + err_len;
		abm->msg.ch.chunk_length = htons(sizeof(struct sctp_abort_chunk) + err_len);
		abtlen = sizeof(struct sctp_abort_msg) + err_len;
	} else {
		mout->m_pkthdr.len = mout->m_len;
		abm->msg.ch.chunk_length = htons(sizeof(struct sctp_abort_chunk));
		abtlen = sizeof(struct sctp_abort_msg);
	}
	/* add checksum */
	val = sctp_calculate_sum(mout, NULL,(sizeof(struct ip6_hdr)));
	abm->sh.checksum = val;
	/* set IPv6 payload length */
	iph6->ip6_plen = htons(abtlen);
	/* zap the rcvif, it should be null */
	mout->m_pkthdr.rcvif = 0;

	/* attach the full sockaddr_in6 addresses to the packet. */
	bzero(&lsa6, sizeof(lsa6));
	lsa6.sin6_family = AF_INET6;
	lsa6.sin6_len = sizeof(lsa6);
	lsa6.sin6_addr = oip->ip6_dst;

	bzero(&fsa6, sizeof(fsa6));
	fsa6.sin6_family = AF_INET6;
	fsa6.sin6_len = sizeof(fsa6);
	fsa6.sin6_addr = oip->ip6_src;

	if (IN6_IS_ADDR_LINKLOCAL(&oip->ip6_src)) {
		struct sockaddr_in6 src, dst;
		/* pull out the scope_id from the incoming packet */
		if (ip6_getpktaddrs(m, &src, &dst)) {
			/* hmm... this is bad- can't get the scope! */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_OUTPUT1) {
				printf("send_abort: can't get scope of link-local addr\n");
			}
#endif /* SCTP_DEBUG */
			return;	/* FIX: ??? send op_err? */
		}
		lsa6.sin6_scope_id = dst.sin6_scope_id;
		fsa6.sin6_scope_id = src.sin6_scope_id;
	}

	/* make sure scope is embedded */
	if (scope6_check_id(&lsa6, ip6_use_defzone) != 0) {
		m_freem(mout);
		return;
	}
	if (scope6_check_id(&fsa6, ip6_use_defzone) != 0) {
		m_freem(mout);
		return;
	}

	if (!ip6_setpktaddrs(mout, &lsa6, &fsa6)) {
		m_freem(mout);
		return;
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_OUTPUT2) {
		printf("sctp_abort calling ipv6 output:\n");
		printf("src: ");
		sctp_print_address((struct sockaddr *)&lsa6);
		printf("dst ");
		sctp_print_address((struct sockaddr *)&fsa6);
	}
#endif /* SCTP_DEBUG */
	/* zap the stack pointer to the route */
	bzero(&ro, sizeof ro);
	/* out it goes */
	ip6_output(mout, NULL, &ro, 0, NULL, NULL);
	sctp_pegs[SCTP_DATAGRAMS_SENT]++;
	/* Free the route if we got one back */
	if (ro.ro_rt)
		RTFREE(ro.ro_rt);
}
#endif

void
sctp_send_operr_to(struct mbuf *m, int iphlen,
		   struct mbuf *scm,
		   struct sctphdr *ohdr,
		   u_int32_t vtag)
{
	struct sctphdr *ihdr;
	struct ip *iph;
	u_int32_t val;
	iph = mtod(m, struct ip *);
	ihdr = (struct sctphdr *)((caddr_t)iph + iphlen);
	ohdr->src_port = ihdr->dest_port;
	ohdr->dest_port = ihdr->src_port;
	ohdr->v_tag = vtag;
	ohdr->checksum = 0;
	val = sctp_calculate_sum(scm, NULL, 0);
	ohdr->checksum = val;
	if (iph->ip_v == IPVERSION) {
		/* V4 */
		struct ip *out;
		struct route ro;
		M_PREPEND(scm, sizeof(struct ip), M_DONTWAIT);
		if (scm == NULL)
			return;
		bzero(&ro, sizeof ro);
		out = mtod(scm, struct ip *);
		out->ip_v = iph->ip_v;
		out->ip_hl = (sizeof(struct ip)/4);
		out->ip_tos = iph->ip_tos;
		out->ip_id = iph->ip_id;
		out->ip_off = 0;
		out->ip_ttl = MAXTTL;
		out->ip_p = IPPROTO_SCTP;
		out->ip_sum = 0;
		out->ip_src = iph->ip_dst;
		out->ip_dst = iph->ip_src;
		out->ip_len = scm->m_len;
		(void) ip_output(scm, 0, &ro, IP_RAWOUTPUT, NULL);
		sctp_pegs[SCTP_DATAGRAMS_SENT]++;
		/* Free the route if we got one back */
		if (ro.ro_rt)
			RTFREE(ro.ro_rt);
	} else {
		/* V6 */
#ifdef NEW_STRUCT_ROUTE
		struct route ro;
#else
		struct route_in6 ro;
#endif
		struct ip6_hdr *out6, *in6;

		M_PREPEND(scm, sizeof(struct ip6_hdr), M_DONTWAIT);
		if (scm == NULL)
			return;
		bzero(&ro, sizeof ro);
		in6 = mtod(m, struct ip6_hdr *);
		out6 = mtod(scm, struct ip6_hdr *);
		out6->ip6_flow = in6->ip6_flow;
		out6->ip6_hlim = ip6_defhlim;
		out6->ip6_nxt = IPPROTO_SCTP;
		out6->ip6_src = in6->ip6_dst;
		out6->ip6_dst = in6->ip6_src;

		ip6_output(scm, NULL, &ro, 0, NULL, NULL);
		sctp_pegs[SCTP_DATAGRAMS_SENT]++;
		/* Free the route if we got one back */
		if (ro.ro_rt)
			RTFREE(ro.ro_rt);
	}
}
