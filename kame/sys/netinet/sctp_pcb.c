/*	$KAME: sctp_pcb.c,v 1.34 2004/05/26 07:51:28 itojun Exp $	*/

/*
 * Copyright (c) 2001, 2002, 2003, 2004 Cisco Systems, Inc.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Cisco Systems, Inc.
 * 4. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CISCO SYSTEMS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CISCO SYSTEMS OR CONTRIBUTORS BE LIABLE
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
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#if defined(__FreeBSD__)
#include <sys/random.h>
#endif
#if defined(__NetBSD__)
#include <sys/rnd.h>
#endif
#if defined(__OpenBSD__)
#include <dev/rndvar.h>
#endif

#if defined(__OpenBSD__)
#include <netinet/sctp_callout.h>
#else
#include <sys/callout.h>
#endif

#if (defined(__FreeBSD__) && __FreeBSD_version >= 500000)
#include <sys/limits.h>
#else
#include <machine/limits.h>
#endif
#include <machine/cpu.h>

#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
#include <vm/uma.h>
#else
#include <vm/vm_zone.h>
#endif
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/pool.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
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
#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <netinet6/in6_pcb.h>
#else
#include <netinet/in_pcb.h>
#endif
#endif /* INET6 */

#include "faith.h"

#include <netinet/sctp_pcb.h>

#ifdef IPSEC
#ifndef __OpenBSD__
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#else
#undef IPSEC
#endif
#endif /* IPSEC */

#include <netinet/sctputil.h>
#include <netinet/sctp_var.h>
#include <netinet/sctp.h>
#include <netinet/sctp_header.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_output.h>
#include <netinet/sctp_timer.h>

#ifndef SCTP_PCBHASHSIZE
/* default number of association hash buckets in each endpoint */
#define SCTP_PCBHASHSIZE 256
#endif

#ifdef SCTP_DEBUG
u_int32_t sctp_debug_on = 0;
#endif /* SCTP_DEBUG */

u_int32_t sctp_pegs[SCTP_NUMBER_OF_PEGS];

int sctp_pcbtblsize = SCTP_PCBHASHSIZE;

struct sctp_epinfo sctppcbinfo;

/* FIX: we don't handle multiple link local scopes */
/* "scopeless" replacement IN6_ARE_ADDR_EQUAL */
int
SCTP6_ARE_ADDR_EQUAL(struct in6_addr *a, struct in6_addr *b)
{
	struct in6_addr tmp_a, tmp_b;
	tmp_a = *a;
	tmp_b = *b;
	in6_clearscope(&tmp_a);
	in6_clearscope(&tmp_b);
	return (IN6_ARE_ADDR_EQUAL(&tmp_a, &tmp_b));
}

#ifdef __OpenBSD__
extern int ipport_firstauto;
extern int ipport_lastauto;
extern int ipport_hifirstauto;
extern int ipport_hilastauto;
#endif

caddr_t sctp_lowest_tcb = (caddr_t)0xffffffff;
caddr_t sctp_highest_tcb = 0;

void
sctp_fill_pcbinfo(struct sctp_pcbinfo *spcb)
{
	spcb->ep_count = sctppcbinfo.ipi_count_ep;
	spcb->asoc_count = sctppcbinfo.ipi_count_asoc;
	spcb->laddr_count = sctppcbinfo.ipi_count_laddr;
	spcb->raddr_count = sctppcbinfo.ipi_count_raddr;
	spcb->chk_count = sctppcbinfo.ipi_count_chunk;
	spcb->sockq_count = sctppcbinfo.ipi_count_sockq;
	spcb->mbuf_track = sctppcbinfo.mbuf_track;
}


/*
 * Given a endpoint, look and find in its association list any association
 * with the "to" address given. This can be a "from" address, too, for
 * inbound packets. For outbound packets it is a true "to" address.
 */
static struct sctp_tcb *
sctp_tcb_special_locate(struct sctp_inpcb **p_ep,
			struct sockaddr *from,
			struct sockaddr *to,
			struct sctp_nets **netp)
{
	/* Note for this module care must be taken when observing
	 * what to is for. In most of the rest of the code the TO
	 * field represents my peer and the FROM field represents
	 * my address. For this module it is revered of that.
	 */

#ifdef SCTP_TCP_MODEL_SUPPORT
	/*
	 * If we support the TCP model, then we must now dig through to
	 * see if we can find our endpoint in the list of tcp ep's.
	 */
	u_short lport, rport;
	struct sctppcbhead *ephead;
	struct sctp_inpcb *inp;
	struct sctp_laddr *laddr;
	struct sctp_tcb *tcb;
	struct sctp_nets *net;

	lport = ((struct sockaddr_in *)to)->sin_port;
	rport = ((struct sockaddr_in *)from)->sin_port;

	ephead = &sctppcbinfo.sctp_tcpephash[SCTP_PCBHASH_ALLADDR((lport+rport),
								  sctppcbinfo.hashtcpmark)];
	/*
	 * Ok now for each of the guys in this bucket we must look
	 * and see:
	 *  - Does the remote port match.
	 *  - Does there single association's addresses match this
	 *    address (to).
	 * If so we update p_ep to point to this ep and return the
	 * tcb from it.
	 */
	LIST_FOREACH(inp, ephead, sctp_hash) {
		if (lport != inp->sctp_lport) {
			continue;
		}

		/* check to see if the ep has one of the addresses */
		if ((inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) {
			/* We are NOT bound all, so look further */
			int match = 0;

			LIST_FOREACH(laddr, &inp->sctp_addr_list, sctp_nxt_addr) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_PCB1) {
						printf("An ounce of prevention is worth a pound of cure\n");
					}
#endif

					continue;
				}
				if (laddr->ifa->ifa_addr == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_PCB1) {
						printf("ifa with a NULL address\n");
					}
#endif
					continue;
				}
				if (laddr->ifa->ifa_addr->sa_family == to->sa_family) {
					/* see if it matches */
					struct sockaddr_in *intf_addr, *sin;
					intf_addr = (struct sockaddr_in *)laddr->ifa->ifa_addr;
					sin = (struct sockaddr_in *)to;
					if (from->sa_family == AF_INET) {
						if (sin->sin_addr.s_addr ==
						    intf_addr->sin_addr.s_addr) {
							match = 1;
							break;
						}
					} else {
						struct sockaddr_in6 *intf_addr6, *sin6;
						sin6 = (struct sockaddr_in6 *)to;
						intf_addr6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
						if (SCTP6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
									 &intf_addr6->sin6_addr)) {
							match = 1;
							break;
						}
					}
				}
			}
			if (match == 0)
				/* This endpoint does not have this address */
				continue;
		}
		/*
		 * Ok if we hit here the ep has the address, does it hold the
		 * 
		 */
		tcb = LIST_FIRST(&inp->sctp_asoc_list);
		if (tcb == NULL)
			continue;

		if (tcb->rport != rport)
			/* remote port does not match. */
			continue;

		/* Does this TCB have a matching address? */
		TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
			if (((struct sockaddr *)(&net->ra._l_addr))->sa_family !=
			    from->sa_family) {
				/* not the same family, can't be a match */
				continue;
			}
			if (from->sa_family == AF_INET) {
				struct sockaddr_in *sin, *rsin;
				sin = (struct sockaddr_in *)&net->ra._l_addr;
				rsin = (struct sockaddr_in *)from;
				if (sin->sin_addr.s_addr == rsin->sin_addr.s_addr) {
					/* found it */
					if (netp != NULL) {
						*netp = net;
					}
					/* Update the endpoint pointer */
					*p_ep = inp;
					return (tcb);
				}
			} else {
				struct sockaddr_in6 *sin6, *rsin6;
				sin6 = (struct sockaddr_in6 *)&net->ra._l_addr;
				rsin6 = (struct sockaddr_in6 *)from;
				if (SCTP6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
							 &rsin6->sin6_addr)) {
					/* found it */
					if (netp != NULL) {
						*netp = net;
					}
					/* Update the endpoint pointer */
					*p_ep = inp;
					return (tcb);
				}
			}
		}
	}
#endif /* SCTP_TCP_MODEL_SUPPORT */
	return (NULL);
}



struct sctp_tcb *
sctp_findassociation_ep_addr(struct sctp_inpcb **p_ep,
			     struct sockaddr *to,
			     struct sctp_nets **netp,
			     struct sockaddr *from)
{
	struct sctpasochead *head;
	struct sctp_tcb *tcb;
	struct sctp_nets *net;
	struct sctp_inpcb *ep;
	u_short rport;

	ep = *p_ep;
	if (to->sa_family == AF_INET) {
		rport = (((struct sockaddr_in *)to)->sin_port);
	} else {
		rport = (((struct sockaddr_in6 *)to)->sin6_port);
	}
	if (ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		/* Now either this guy is our listner or
		 * its the connector. If it is the one that issued
		 * the connect, then it's only chance is to 
		 * be the first TCB in the list. On the other hand
		 * if it is the acceptor, then we must do the
		 * special_lookup to hash and find the real ep.
		 */
		if (ep->sctp_flags & SCTP_PCB_FLAGS_ACCEPTING) {
			tcb = sctp_tcb_special_locate(p_ep,
						       to,  /* this is my peer address */
						       from, /* this is my address */
						       netp);
			return (tcb);
		} else {
			tcb = LIST_FIRST(&ep->sctp_asoc_list);
			if (tcb) {
				if (tcb->rport != rport)
					/* remote port does not match. */
					return (NULL);
				/* now look at the list of remote addresses */
				TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
					if (((struct sockaddr *)(&net->ra._l_addr))->sa_family !=
					    to->sa_family) {
						/* not the same family */
						continue;
					}
					if (to->sa_family == AF_INET) {
						struct sockaddr_in *sin, *rsin;
						sin = (struct sockaddr_in *)&net->ra._l_addr;
						rsin = (struct sockaddr_in *)to;
						if (sin->sin_addr.s_addr == rsin->sin_addr.s_addr) {
							/* found it */
							if (netp != NULL) {
								*netp = net;
							}
							return (tcb);
						}
					} else {
						struct sockaddr_in6 *sin6, *rsin6;
						sin6 = (struct sockaddr_in6 *)&net->ra._l_addr;
						rsin6 = (struct sockaddr_in6 *)to;
						if (SCTP6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
									 &rsin6->sin6_addr)) {
							/* found it */
							if (netp != NULL) {
								*netp = net;
							}
							return (tcb);
						}
					}
				}
			}
		}
	} else {
		head = &ep->sctp_tcbhash[SCTP_PCBHASH_ALLADDR(rport,
							      ep->sctp_hashmark)];
		if (head == NULL) {
			return (NULL);
		}
		LIST_FOREACH(tcb, head, sctp_tcbhash) {
			if (tcb->rport != rport) {
				/* remote port does not match */
				continue;
			}
			/* now look at the list of remote addresses */
			TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
				if (((struct sockaddr *)(&net->ra._l_addr))->sa_family !=
				    to->sa_family) {
					/* not the same family */
					continue;
				}
				if (to->sa_family == AF_INET) {
					struct sockaddr_in *sin, *rsin;
					sin = (struct sockaddr_in *)&net->ra._l_addr;
					rsin = (struct sockaddr_in *)to;
					if (sin->sin_addr.s_addr == rsin->sin_addr.s_addr) {
						/* found it */
						if (netp != NULL) {
							*netp = net;
						}
						return (tcb);
					}
				} else {
					struct sockaddr_in6 *sin6, *rsin6;
					sin6 = (struct sockaddr_in6 *)&net->ra._l_addr;
					rsin6 = (struct sockaddr_in6 *)to;
					if (SCTP6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
								 &rsin6->sin6_addr)) {
						/* found it */
						if (netp != NULL) {
							*netp = net;
						}
						return (tcb);
					}
				}
			}
		}
	}
	/* not found */
	return (NULL);
}

/*
 * Find an association for a specific endpoint using the association id
 * given out in the COMM_UP notification
 */
struct sctp_tcb *
sctp_findassociation_ep_asocid(struct sctp_inpcb *ep, caddr_t asoc_id)
{
	struct sctp_tcb *rtcb;

	if ((asoc_id == 0) || (ep == NULL))
		return (NULL);

	if (ep->highest_tcb == 0) {
		/* can't be never allocated a association yet */
		return (NULL);
	}
	if (((u_long)asoc_id % 4) != 0) {
	       /* Must be aligned to 4 byte boundary */
	       return (NULL);
	}

	if ((ep->highest_tcb >= asoc_id) && (ep->lowest_tcb <= asoc_id)) {
		/* it is possible lets have a look */
		rtcb = (struct sctp_tcb *)asoc_id;
		if ((rtcb->sctp_ep == ep) && rtcb->asoc.state) {
			return (rtcb);
		}
	}
	return (NULL);
}

struct sctp_tcb *
sctp_findassociation_associd(caddr_t asoc_id)
{
	/* This is allows you to look at another sockets info */
	struct sctp_tcb *tcb;
	if ((asoc_id < sctp_lowest_tcb) && (asoc_id > sctp_highest_tcb)) {
		return (NULL);
	}
	tcb = (struct sctp_tcb *)asoc_id;
	if (tcb->asoc.state == 0)
		return (NULL);
	else
		return (tcb);

}

static struct sctp_inpcb *
sctp_endpoint_probe(struct sockaddr *nam,
		    struct sctppcbhead *head,
		    u_short lport)

{
	struct sctp_inpcb *ep;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (nam->sa_family == AF_INET) {
		sin = (struct sockaddr_in *)nam;
		sin6 = NULL;
	} else if (nam->sa_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)nam;
		sin = NULL;
	} else {
		/* unsupported family */
		return ((struct sctp_inpcb *)NULL);
	}
	LIST_FOREACH(ep, head, sctp_hash) {
		if ((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) &&
		    (ep->sctp_lport == lport)) {
			/* got it */
			if ((nam->sa_family == AF_INET) &&
			    (ep->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) &&
#if defined(__FreeBSD__)
			    (((struct inpcb *)ep)->inp_flags & IN6P_IPV6_V6ONLY)
#else
#if defined(__OpenBSD__)
			    (0)	/* For open bsd we do dual bind only */
#else
			    (((struct in6pcb *)ep)->in6p_flags & IN6P_IPV6_V6ONLY)
#endif
#endif
				) {
				/* IPv4 on a IPv6 socket with ONLY IPv6 set */
				continue;
			}
			/* A V6 address and the endpoint is NOT bound V6 */
			if ((nam->sa_family == AF_INET6) &&
			    ((ep->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) == 0)) {
				continue;
			}
			return (ep);
		}
	}
	if ((nam->sa_family == AF_INET) &&
	    (sin->sin_addr.s_addr == INADDR_ANY)) {
		/* Can't hunt for one that has no address specified */
		return (NULL);
	} else if ((nam->sa_family == AF_INET6) &&
		   (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))) {
		/* Can't hunt for one that has no address specified */
		return (NULL);
	}
	/*
	 * ok, not bound to all so see if we can find a EP bound to this
	 * address.
	 */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Ok, there is NO bound-all available for port:%x\n", ntohs(lport));
	}
#endif
	LIST_FOREACH(ep, head, sctp_hash) {
		if ((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) {
			struct sctp_laddr *laddr;
			/*
			 * Ok this could be a likely candidate, look at all of
			 * its addresses
			 */
			if (ep->sctp_lport != lport)
				continue;
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_PCB1) {
				printf("Ok, found maching local port\n");
			}
#endif

			LIST_FOREACH(laddr, &ep->sctp_addr_list, sctp_nxt_addr) {
				if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_PCB1) { 
						printf("An ounce of prevention is worth a pound of cure\n");
					}
#endif
					continue;
				}
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_PCB1) {
					printf("Ok laddr->ifa:%p is possible, ", laddr->ifa);
				}
#endif
				if (laddr->ifa->ifa_addr == NULL) {
#ifdef SCTP_DEBUG
					if (sctp_debug_on & SCTP_DEBUG_PCB1) {
						printf("Huh IFA as an ifa_addr=NULL, ");
					}
#endif
					continue;
				}
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_PCB1) {
					printf("Ok laddr->ifa:%p is possible, ", laddr->ifa->ifa_addr);
					sctp_print_address(laddr->ifa->ifa_addr);
					printf("looking for ");
					sctp_print_address(nam);
				}
#endif
				if (laddr->ifa->ifa_addr->sa_family == nam->sa_family) {
					/* possible, see if it matches */
					struct sockaddr_in *intf_addr;
					intf_addr = (struct sockaddr_in *)laddr->ifa->ifa_addr;
					if (nam->sa_family == AF_INET) {
						if (sin->sin_addr.s_addr ==
						    intf_addr->sin_addr.s_addr) {
#ifdef SCTP_DEBUG
							if (sctp_debug_on & SCTP_DEBUG_PCB1) {
								printf("YES, return ep:%p\n", ep);
							}
#endif
							return (ep);
						}
					} else {
						struct sockaddr_in6 *intf_addr6;
						intf_addr6 = (struct sockaddr_in6 *)laddr->ifa->ifa_addr;
						if (SCTP6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
									 &intf_addr6->sin6_addr)) {
#ifdef SCTP_DEBUG
							if (sctp_debug_on & SCTP_DEBUG_PCB1) {
								printf("YES, return ep:%p\n", ep);
							}
#endif
							return (ep);
						}
					}
				}
			}
		}
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("NO, Falls out to NULL\n");
	}
#endif
	return (NULL);
}


struct sctp_inpcb *
sctp_pcb_findep(struct sockaddr *nam, int find_tcp_pool)
{
	/*
	 * First we check the hash table to see if someone has this port
	 * bound with just the port.
	 */
	struct sctp_inpcb *ep;
	struct sctppcbhead *head;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int lport;
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Looking for endpoint %d :",
		       ntohs(((struct sockaddr_in *)nam)->sin_port));
		sctp_print_address(nam);
	}
#endif
	if (nam->sa_family == AF_INET) {
		sin = (struct sockaddr_in *)nam;
		lport = ((struct sockaddr_in *)nam)->sin_port;
	} else if (nam->sa_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)nam;
		lport = ((struct sockaddr_in6 *)nam)->sin6_port;
	} else {
		/* unsupported family */
		return ((struct sctp_inpcb *)NULL);
	}
	/*
	 * I could cheat here and just cast to one of the types but we will
	 * do it right. It also provides the check against an Unsupported
	 * type too.
	 */
	/* Find the head of the ALLADDR chain */
	head = &sctppcbinfo.sctp_ephash[SCTP_PCBHASH_ALLADDR(lport, sctppcbinfo.hashmark)];
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Main hash to lookup at head:%p\n", head);
	}
#endif
 	ep = sctp_endpoint_probe(nam, head, lport);

#ifdef SCTP_TCP_MODEL_SUPPORT
	/*
	 * If the TCP model exists it could be that the main listening
	 * endpoint is gone but there exists a connected socket for this
	 * guy yet. If so we can return the first one that we find. This
	 * may NOT be the correct one but the sctp_findassociation_ep_addr
	 * has further code to look at all TCP models.
	 */
	if (ep == NULL && find_tcp_pool) {
		int i;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB1) {
			printf("EP was NULL and TCP model is supported\n");
		}
#endif
		for (i = 0; i < sctppcbinfo.hashtblsize; i++) {
			/*
			 * This is real gross, but we do NOT have a remote
			 * port at this point depending on who is calling. We
			 * must therefore look for ANY one that matches our
			 * local port :/
			 */
			head = &sctppcbinfo.sctp_tcpephash[i];
			if (LIST_FIRST(head)) {
				ep = sctp_endpoint_probe(nam, head, lport);
				if (ep) {
					/* Found one */
					break;
				}
			}
		}
	}
#endif /* SCTP_TCP_MODEL_SUPPORT */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("EP to return is %p\n", ep);
	}
#endif
	return (ep);
}

/*
 * Find an association for an endpoint with the pointer to whom you want
 * to send to and the endpoint pointer. The address can be IPv4 or IPv6.
 * We may need to change the *to to some other struct like a mbuf...
 */
struct sctp_tcb *
sctp_findassociation_addr_sa(struct sockaddr *to, struct sockaddr *from,
			     struct sctp_inpcb **inp,
			     struct sctp_nets **netp,
			     int find_tcp_pool)
{
	struct sctp_inpcb *ep;
#ifdef SCTP_TCP_MODEL_SUPPORT
	struct sctp_tcb *tcb;

	if (find_tcp_pool) {
		if (inp != NULL) {
			tcb = sctp_tcb_special_locate(inp, from, to, netp);
		} else {
			tcb = sctp_tcb_special_locate(&ep, from, to, netp);
		}
		if (tcb != NULL) {
			return (tcb);
		}
	}
#endif
	ep = sctp_pcb_findep(to, 0);
	if (inp != NULL) {
		*inp = ep;
	}
	if (ep == NULL) {
		return (NULL);
	}

	/*
	 * ok, we have an endpoint, now lets find the assoc for it (if any)
	 * we now place the source address or from in the to of the find
	 * endpoint call. Since in reality this chain is used from the
	 * inbound packet side.
	 */
	if (inp != NULL) {
		return (sctp_findassociation_ep_addr(inp, from, netp, to));
	} else {
		return (sctp_findassociation_ep_addr(&ep, from, netp, to));
	}
}


/*
 * This routine will grub through the mbuf that is a INIT or INIT-ACK and
 * find all addresses that the sender has specified in any address list.
 * Each address will be used to lookup the TCB and see if one exits.
 */
static struct sctp_tcb *
sctp_findassociation_special_addr(struct sctp_inpcb **ep,
				  struct sctp_nets **netp,
				  struct mbuf *mpkt,
				  int iphlen,
				  u_short port,
				  struct sockaddr *dest)

{
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa_touse;
	struct sctp_paramhdr *phdr;
	struct sctp_ipv6addr_param parms;
	struct sctp_tcb *ret;
	u_int8_t *addrp;
	u_int32_t at;
	u_int32_t ptype, plen;

	sin4.sin_len = sizeof(sin4);
	sin4.sin_family = AF_INET;
	sin4.sin_port = port;
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = port;

	ret = NULL;
	at = iphlen + sizeof(struct sctphdr) + sizeof(struct sctp_init_chunk);

	phdr = sctp_get_next_param(mpkt, at, (struct sctp_paramhdr *)&parms,
				   sizeof(struct sctp_paramhdr));
	while (phdr != NULL) {
		/* now we must see if we want the parameter */
		ptype = ntohs(phdr->param_type);
		plen = ntohs(phdr->param_length);
		if (plen == 0) {
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_PCB1) {
				printf("sctp_pcb.c:0:Impossible length in parameter - 0\n");
			}
#endif /* SCTP_DEBUG */
			break;
		}
		if (ptype == SCTP_IPV4_ADDRESS) {
			/* Get the rest of the address */
			phdr = sctp_get_next_param(mpkt, at,
			    (struct sctp_paramhdr *)&parms, plen);
			addrp = (u_int8_t *)((caddr_t)phdr +
			    sizeof(struct sctp_paramhdr));
			memcpy(&sin4.sin_addr, addrp, sizeof(struct in_addr));
			sa_touse = (struct sockaddr *)&sin4;
			/* look it up */
			ret = sctp_findassociation_ep_addr(ep, sa_touse, netp,
							   dest);
			if (ret != NULL) {
				return (ret);
			}
			at += SCTP_SIZE32(plen);
		} else if (ptype == SCTP_IPV6_ADDRESS) {
			/* Get the rest of the address */
			phdr = sctp_get_next_param(mpkt, at,
			    (struct sctp_paramhdr *)&parms, plen);
			addrp = (u_int8_t *)((caddr_t)phdr +
			    sizeof(struct sctp_paramhdr));
			memcpy(&sin6.sin6_addr, addrp, sizeof(struct in6_addr));
			sa_touse = (struct sockaddr *)&sin6;
			/* look it up */
			ret = sctp_findassociation_ep_addr(ep, sa_touse, netp,
			    dest);
			if (ret != NULL) {
				return (ret);
			}
			at += SCTP_SIZE32(plen);
		} else {
			/* no skip it */
			at += SCTP_SIZE32(plen);
		}
		phdr = sctp_get_next_param(mpkt, at,
		    (struct sctp_paramhdr *)&parms,
		    sizeof(struct sctp_paramhdr));
	}
	return (NULL);
}

static struct sctp_tcb *
sctp_findassoc_by_vtag(struct sockaddr *from,
		       uint32_t vtag, 
		       struct sctp_inpcb **inp,
		       struct sctp_nets **netp,
		       uint16_t port,
		       uint16_t myport)
{
	/* Use my vtag to hash. If we find
	 * it we then verify the source addr is
	 * in the assoc. If all goes well we save
	 * a bit on rec of a packet.
	 */
	struct sctpasochead *head;
	struct sctp_nets *tnet;
	struct sctp_tcb *tcb;

	head = &sctppcbinfo.sctp_asochash[SCTP_PCBHASH_ASOC(vtag, sctppcbinfo.hashasocmark)];
	if (head == NULL) {
		/* invalid vtag */
		return (NULL);
	}
	LIST_FOREACH(tcb, head, sctp_asocs) {
		if (tcb->asoc.my_vtag == vtag) {
			/* candidate */
			if (tcb->rport != port) {
				/* we could remove this if vtags are 
				 * unique across the system.
				 */
				continue;
			}
			if (tcb->sctp_ep->sctp_lport != myport) {
				/* we could remove this if vtags are 
				 * unique across the system.
				 */
				continue;
			}

			tnet = sctp_findnet(tcb, from);
			if (tnet) {
				/* yep its him. */
				*netp = tnet;
				sctp_pegs[SCTP_VTAG_EXPR]++;
				*inp = tcb->sctp_ep;
				return (tcb);
			} else {
				/* bogus 
				sctp_pegs[SCTP_VTAG_BOGUS]++;
				return (NULL);
				*/
				/* we could uncomment the above
				 * if vtags were unique across
				 * the system.
				 */
				continue;
			}
		}
	}
	return (NULL);
}

/*
 * Find an association with the pointer to the inbound IP packet. This
 * can be a IPv4 or IPv6 packet, it is assumed that a pullup was done up
 * to at least the SCTP common header.
 */
struct sctp_tcb *
sctp_findassociation_addr(struct mbuf *pkt, int iphlen,
			  struct sctp_inpcb **inp,
			  struct sctp_nets **netp,
			  uint32_t vtag)
{
	int find_tcp_pool;
	struct ip *iph;
	struct sctphdr *sh;
	struct sctp_chunkhdr *chdr;
	struct sctp_tcb *ret;
	struct sockaddr_in6 to6, from6;
	struct sockaddr_in to4, from4;
	struct sockaddr *to, *from;
	struct sctp_inpcb *linp;
	u_short port, my_port;

	iph = mtod(pkt, struct ip *);
	if (iph->ip_v == IPVERSION) {
		/* its IPv4 */
/*
  I think we don't need to bzero these 
		bzero(&to4, sizeof(to4));
		bzero(&from4, sizeof(from4));
*/
		from4.sin_family = to4.sin_family = AF_INET;
		from4.sin_len = to4.sin_len = sizeof(struct sockaddr_in);
		sh = (struct sctphdr *)((caddr_t)iph + iphlen);
		port = from4.sin_port = sh->src_port;
		my_port = to4.sin_port = sh->dest_port;
		from4.sin_addr.s_addr  = iph->ip_src.s_addr;
		to4.sin_addr.s_addr = iph->ip_dst.s_addr ;
		to = (struct sockaddr *)&to4;
		from = (struct sockaddr *)&from4;
	} else {
		/* its IPv6 */
		struct ip6_hdr *ip6;
/*
  I think we don't need to bzero these
		bzero(&to, sizeof(to6));
		bzero(&from6, sizeof(from6));
*/
		from6.sin6_family = to6.sin6_family = AF_INET6;
		from6.sin6_len = to6.sin6_len = sizeof(struct sockaddr_in6);
		ip6 = mtod(pkt, struct ip6_hdr *);
		sh = (struct sctphdr *)((caddr_t)ip6 + iphlen);
		port = from6.sin6_port = sh->src_port;
		my_port = to6.sin6_port = sh->dest_port;
		to6.sin6_addr = ip6->ip6_dst;
		from6.sin6_addr = ip6->ip6_src;
		to = (struct sockaddr *)&to6;
		from = (struct sockaddr *)&from6;
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Looking for port %d address :",
		       ntohs(((struct sockaddr_in *)to)->sin_port));
		sctp_print_address(to);
		printf("From for port %d address :",
		       ntohs(((struct sockaddr_in *)from)->sin_port));
		sctp_print_address(from);
	}
#endif
	if (vtag) {
		/* we only go down this path if vtag is non-zero */
		ret = sctp_findassoc_by_vtag(from, ntohl(vtag), inp, netp, port, my_port);
		if (ret) {
			return (ret);
		}
	}

	find_tcp_pool = 0;
#ifdef SCTP_TCP_MODEL_SUPPORT
	chdr = (struct sctp_chunkhdr *)((caddr_t)sh +
					sizeof(struct sctphdr));
	if ((chdr->chunk_type != SCTP_INITIATION) &&
	    (chdr->chunk_type != SCTP_INITIATION_ACK) &&
	    (chdr->chunk_type != SCTP_COOKIE_ACK) &&
	    (chdr->chunk_type != SCTP_COOKIE_ECHO))
		/* Other chunk types go to the tcp pool. */
		find_tcp_pool = 1;
#endif
	if (inp) {
		ret = sctp_findassociation_addr_sa(to, from,
						   inp, netp, find_tcp_pool);
		linp = *inp;
	} else {
		ret = sctp_findassociation_addr_sa(to, from,
						   &linp, netp, find_tcp_pool);
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("ret:%p linp:%p\n", ret, linp);
	}
#endif
	if ((ret == NULL) && (linp)) {
		/* Found a EP but not this address */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB1) {
			printf("Found endpoint %p but not address state:%x\n",
			       linp, linp->sctp_flags);
			       
		}
#endif
    		chdr = (struct sctp_chunkhdr *)((caddr_t)sh +
						sizeof(struct sctphdr));
		if ((chdr->chunk_type == SCTP_INITIATION) ||
		    (chdr->chunk_type == SCTP_INITIATION_ACK)) {
#ifdef SCTP_TCP_MODEL_SUPPORT
			/*
			 * special hook, we do NOT return linp or an
			 * association that is linked to an existing
			 * association that is under the TCP pool (i.e. no
			 * listener exists). The endpoint finding routine
			 * will always find a listner before examining the
			 * TCP pool.
			 */
			if (linp->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL) {
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_PCB1) {
					printf("Gak, its in the TCP pool... return NULL");
				}

#endif
				if (inp) {
					*inp = NULL;
				}
				return (NULL);
			}
#endif /* SCTP_TCP_MODEL_SUPPORT */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_PCB1) {
				printf("Now doing SPECIAL find");
			}
#endif
			ret = sctp_findassociation_special_addr(inp, netp, pkt,
								iphlen, port,
								to);
		}
	}
	return (ret);
}


/*
 * allocate a sctp_inpcb and setup a temporary binding to a port/all
 * addresses. This way if we don't get a bind we by default pick a ephemeral
 * port with all addresses bound.
 */
int
sctp_inpcb_alloc(struct socket *so)
{
	/*
	 * we get called when a new endpoint starts up. We need to allocate
	 * the sctp_inpcb structure from the zone and init it. Mark it as
	 * unbound and find a port that we can use as an ephemeral with
	 * INADDR_ANY. If the user binds later no problem we can then add
	 * in the specific addresses. And setup the default parameters for
	 * the EP.
	 */
	int i, error;
	struct sctp_inpcb *inp;
	struct sctp_pcb *m;

	error = 0;
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	inp = (struct sctp_inpcb *)uma_zalloc(sctppcbinfo.ipi_zone_ep, M_NOWAIT);
#else
	inp = (struct sctp_inpcb *)zalloci(sctppcbinfo.ipi_zone_ep);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	inp = (struct sctp_inpcb *)pool_get(&sctppcbinfo.ipi_zone_ep,
					    PR_NOWAIT);
#endif
	if (inp == NULL) {
		printf("Out of SCTP-INPCB structures - no resources\n");
		return (ENOBUFS);
	}

	/* zap it */
	bzero((caddr_t)inp, sizeof(*inp));

	/* bump generations */
	inp->ip_inp.inp.inp_socket = so;

	/* setup socket pointers */
	inp->sctp_socket = so;

	/* setup inpcb socket too */
	inp->ip_inp.inp.inp_socket = so;
	inp->sctp_frag_point = SCTP_DEFAULT_MAXSEGMENT;
#ifndef SCTP_VTAG_TIMEWAIT_PER_STACK
	LIST_INIT(inp->vtag_timewait);
#endif

#ifdef IPSEC
#ifndef __OpenBSD__
	{
		struct inpcbpolicy *pcb_sp = NULL;
		error = ipsec_init_pcbpolicy(so, &pcb_sp);
		/* Arrange to share the policy */
		inp->ip_inp.inp.inp_sp = pcb_sp;
		((struct in6pcb *)(&inp->ip_inp.inp))->in6p_sp = pcb_sp;
	}
#else
	/* not sure what to do for openbsd here */
	error = 0;
#endif
	if (error != 0) {
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_ep, inp);
#else
		zfreei(sctppcbinfo.ipi_zone_ep, inp);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_ep, inp);
#endif
		return error;
	}
#endif /*IPSEC*/
	sctppcbinfo.ipi_count_ep++;
#if defined(__FreeBSD__)
	inp->ip_inp.inp.inp_gencnt = ++sctppcbinfo.ipi_gencnt_ep;
	inp->ip_inp.inp.inp_ip_ttl = ip_defttl;
#else
	inp->inp_ip_ttl = ip_defttl;
	inp->inp_ip_tos = 0;
#endif

	so->so_pcb = (caddr_t)inp;
	inp->lowest_tcb = (caddr_t)0xffffffff;

	if ((so->so_type == SOCK_DGRAM) ||
	    (so->so_type == SOCK_SEQPACKET)) {
		/* UDP style socket */
		inp->sctp_flags = (SCTP_PCB_FLAGS_UDPTYPE |
				   SCTP_PCB_FLAGS_UNBOUND);
		inp->sctp_flags |= (SCTP_PCB_FLAGS_RECVDATAIOEVNT);
		/* Be sure it is NON-BLOCKING IO for UDP */
		/*so->so_state |= SS_NBIO;*/
#ifdef SCTP_TCP_MODEL_SUPPORT
	} else if (so->so_type == SOCK_STREAM) {
		/* TCP style socket */
		inp->sctp_flags = (SCTP_PCB_FLAGS_TCPTYPE |
				   SCTP_PCB_FLAGS_UNBOUND);
		inp->sctp_flags |= (SCTP_PCB_FLAGS_RECVDATAIOEVNT);
		/* Be sure we have blocking IO bu default */
		so->so_state &= ~SS_NBIO;
#endif /* SCTP_TCP_MODEL_SUPPORT */
	} else {
		/*
		 * unsupported socket type (RAW, etc)- in case we missed
		 * it in protosw
		 */
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_ep, inp);
#else
		zfreei(sctppcbinfo.ipi_zone_ep, inp);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_ep, inp);
#endif
		return (EOPNOTSUPP);
	}
	inp->sctp_tcbhash = hashinit(sctp_pcbtblsize,
#ifdef __NetBSD__
	    HASH_LIST,
#endif
	    M_PCB,
#ifndef __FreeBSD__
	    M_WAITOK,
#endif
	    &inp->sctp_hashmark);
	if (inp->sctp_tcbhash == NULL) {
		printf("Out of SCTP-INPCB->hashinit - no resources\n");
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_ep, inp);
#else
		zfreei(sctppcbinfo.ipi_zone_ep, inp);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_ep, inp);
#endif
		return (ENOBUFS);
	}

	LIST_INSERT_HEAD(&sctppcbinfo.listhead, inp, sctp_list);
	LIST_INIT(&inp->sctp_addr_list);
	LIST_INIT(&inp->sctp_asoc_list);
	TAILQ_INIT(&inp->sctp_queue_list);
	/* Init the timer structure for signature change */
#if __FreeBSD_version >= 500000
	callout_init(&inp->sctp_ep.signature_change.timer, 0);
#else
	callout_init(&inp->sctp_ep.signature_change.timer);
#endif

	/* now init the actual endpoint default data */
	m = &inp->sctp_ep;

	/* setup the base timeout information */
	m->sctp_timeoutticks[SCTP_TIMER_SEND] = SCTP_SEND_SEC;
	m->sctp_timeoutticks[SCTP_TIMER_INIT] = SCTP_INIT_SEC;
	m->sctp_timeoutticks[SCTP_TIMER_RECV] = SCTP_RECV_SEC;
	m->sctp_timeoutticks[SCTP_TIMER_HEARTBEAT] = SCTP_HB_DEFAULT;
	m->sctp_timeoutticks[SCTP_TIMER_PMTU] = SCTP_DEF_PMTU_RAISE;
	m->sctp_timeoutticks[SCTP_TIMER_MAXSHUTDOWN] = SCTP_DEF_MAX_SHUTDOWN;
	m->sctp_timeoutticks[SCTP_TIMER_SIGNATURE] = SCTP_DEFAULT_SECRET_LIFE;
	/* all max/min max are in ms */
	m->sctp_maxrto = SCTP_RTO_UPPER_BOUND;
	m->sctp_minrto = SCTP_RTO_LOWER_BOUND;
	m->initial_rto = SCTP_RTO_INITIAL;
	m->initial_init_rto_max = SCTP_RTO_UPPER_BOUND;

	m->max_open_streams_intome = MAX_SCTP_STREAMS;

	m->max_init_times = SCTP_DEF_MAX_INIT;
	m->max_send_times = SCTP_DEF_MAX_SEND;
	m->def_net_failure = SCTP_DEF_MAX_SEND/2;
	m->sctp_sws_sender = SCTP_SWS_SENDER_DEF;
	m->sctp_sws_receiver = SCTP_SWS_RECEIVER_DEF;
	m->max_burst = SCTP_DEF_MAX_BURST;
	/* number of streams to pre-open on a association */
	m->pre_open_stream_count = SCTP_OSTREAM_INITIAL;

	/* Add adaption cookie */
	m->adaption_layer_indicator = 0x504C5253;

	/* seed random number generator */
	m->random_counter = 1;
	m->store_at = SCTP_SIGNATURE_SIZE;
#if defined(__FreeBSD__) && __FreeBSD_version < 500000
	read_random_unlimited(m->random_numbers, sizeof(m->random_numbers));
#endif
#if defined(__OpenBSD__)
	get_random_bytes(m->random_numbers, sizeof(m->random_numbers));
#endif
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD_version >= 500000)

#if !defined(__FreeBSD__) && NRND > 0
	rnd_extract_data(m->random_numbers, sizeof(m->random_numbers),
			 RND_EXTRACT_ANY);
#else
	{
		u_int32_t *ranm, *ranp;
		ranp = (u_int32_t *)&m->random_numbers;
		ranm = ranp + SCTP_SIGNATURE_ALOC_SIZE;
		if ((u_long)ranp % 4) {
			/* not a even boundary? */
			ranp = (u_int32_t *)((((u_long)ranp + 3) >> 2) << 2);
		}
		while (ranp < ranm) {
			*ranp = random();
			ranp++;
		}
	}
#endif

#endif
	sctp_fill_random_store(m);

	/* Minimum cookie size */
	m->size_of_a_cookie = (sizeof(struct sctp_init_msg) * 2) +
		sizeof(struct sctp_state_cookie);
	m->size_of_a_cookie += SCTP_SIGNATURE_SIZE;

	/* Setup the initial secret */
	{
		struct timeval time;
		SCTP_GETTIME_TIMEVAL(&time);
		m->time_of_secret_change = time.tv_sec;

		for (i = 0; i < SCTP_NUMBER_OF_SECRETS; i++) {
			m->secret_key[0][i] = sctp_select_initial_TSN(m);
		}
		sctp_timer_start(SCTP_TIMER_TYPE_NEWCOOKIE, inp, NULL, NULL);
	}

	/* How long is a cookie good for ? */
	m->def_cookie_life = SCTP_DEFAULT_COOKIE_LIFE;
	return (error);
}


#ifdef SCTP_TCP_MODEL_SUPPORT
void
sctp_move_pcb_and_assoc(struct sctp_inpcb *old_inp,
			struct sctp_inpcb *new_inp,
			struct sctp_tcb  *tcb_tomove)
{
	/* Copy the port across */
	u_short lport, rport;
	struct sctppcbhead *head;
	struct sctp_laddr *laddr, *oladdr;

	new_inp->sctp_ep.time_of_secret_change = old_inp->sctp_ep.time_of_secret_change;
	memcpy(new_inp->sctp_ep.secret_key, old_inp->sctp_ep.secret_key, sizeof(old_inp->sctp_ep.secret_key));
	new_inp->sctp_ep.size_of_a_cookie = old_inp->sctp_ep.size_of_a_cookie;
	new_inp->sctp_ep.current_secret_number = old_inp->sctp_ep.current_secret_number;
	new_inp->sctp_ep.last_secret_number = old_inp->sctp_ep.last_secret_number;

	lport = new_inp->sctp_lport = old_inp->sctp_lport;
	rport = tcb_tomove->rport;
	/* Pull the tcb from the old association */
	
	LIST_REMOVE(tcb_tomove, sctp_tcbhash);
	LIST_REMOVE(tcb_tomove, sctp_tcblist);
	/* Now insert the new_inp into the TCP connected hash */
	head = &sctppcbinfo.sctp_tcpephash[SCTP_PCBHASH_ALLADDR((lport+rport), sctppcbinfo.hashtcpmark)];
	LIST_INSERT_HEAD(head, new_inp, sctp_hash);

	/* Now move the tcb into the endpoint list */
	LIST_INSERT_HEAD(&new_inp->sctp_asoc_list, tcb_tomove, sctp_tcblist);
	/*
	 * Question, do we even need to worry about the ep-hash since
	 * we only have one connection? Probably not :> so lets
	 * get rid of it and not suck up any kernel memory in that.
	 */
	tcb_tomove->sctp_socket = new_inp->sctp_socket;
	tcb_tomove->sctp_ep = new_inp;
	new_inp->highest_tcb = (caddr_t)tcb_tomove;
	new_inp->lowest_tcb = (caddr_t)tcb_tomove;
	if (new_inp->sctp_tcbhash != NULL) {
		free(new_inp->sctp_tcbhash, M_PCB);
		new_inp->sctp_tcbhash = NULL;
	}
	if ((new_inp->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) {
		/* Subset bound, so copy in the laddr list from the old_inp */
		LIST_FOREACH(oladdr, &old_inp->sctp_addr_list, sctp_nxt_addr) {
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			laddr = (struct sctp_laddr *)uma_zalloc(sctppcbinfo.ipi_zone_laddr, M_NOWAIT);
#else
			laddr = (struct sctp_laddr *)zalloci(sctppcbinfo.ipi_zone_laddr);
#endif
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
			laddr = (struct sctp_laddr *)pool_get(&sctppcbinfo.ipi_zone_laddr,
							      PR_NOWAIT);
#endif
			if (laddr == NULL) {
				/*
				 * Gak, what can we do? This assoc is really
				 * HOSED. We probably should send an abort
				 * here.
				 */
#ifdef SCTP_DEBUG
				if (sctp_debug_on & SCTP_DEBUG_PCB1) {
					printf("Association hosed in TCP model, out of laddr memory\n");
				}
#endif /* SCTP_DEBUG */
				continue;
			}
			sctppcbinfo.ipi_count_laddr++;
			sctppcbinfo.ipi_gencnt_laddr++;
			bzero(laddr, sizeof(*laddr));
			laddr->ifa = oladdr->ifa;
			LIST_INSERT_HEAD(&new_inp->sctp_addr_list, laddr,
					 sctp_nxt_addr);
			new_inp->laddr_count++;
		}
	}
}
#endif


static int
sctp_isport_inuse(struct sctp_inpcb *ep, u_short lport)
{
	struct sctppcbhead *head;
	struct sctp_inpcb *lep;
	head = &sctppcbinfo.sctp_ephash[SCTP_PCBHASH_ALLADDR(lport, sctppcbinfo.hashmark)];
	LIST_FOREACH(lep, head, sctp_hash) {
		if (lep->sctp_lport == lport) {
			/* This one is in use. */
			/* check the v6/v4 binding issue */
			if ((lep->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) &&
#if defined(__FreeBSD__)
			    (((struct inpcb *)lep)->inp_flags & IN6P_IPV6_V6ONLY)
#else
#if defined(__OpenBSD__)
			    (0)	/* For open bsd we do dual bind only */
#else
			    (((struct in6pcb *)lep)->in6p_flags & IN6P_IPV6_V6ONLY)
#endif
#endif
				) {
				if (ep->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
					/* collision in V6 space */
					return (1);
				} else {
					/* ep is BOUND_V4 no conflict */
					continue;
				}
			} else if (lep->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
				/* lep is bound v4 and v6 
				 * conflict no matter what.
				 */
				return (1);
			} else {
				/* lep is bound only V4 */
				if ((ep->sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) &&
#if defined(__FreeBSD__)
				    (((struct inpcb *)ep)->inp_flags & IN6P_IPV6_V6ONLY)
#else
#if defined(__OpenBSD__)
				    (0)	/* For open bsd we do dual bind only */
#else
				    (((struct in6pcb *)ep)->in6p_flags & IN6P_IPV6_V6ONLY)
#endif
#endif
					) {
					/* no conflict */
					continue;
				}
				/* else fall through to conflict */
			}
			return (1);
		}
	}
	return (0);
}

#ifndef __FreeBSD__
/* Don't know why but without this I get an unknown
 * reference when compiling NetBSD... hmm
 */
extern void in6_sin6_2_sin (struct sockaddr_in *, struct sockaddr_in6 *sin6);
#endif


int
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
sctp_inpcb_bind(struct socket *so, struct sockaddr *addr, struct thread *p)
#else
sctp_inpcb_bind(struct socket *so, struct sockaddr *addr, struct proc *p)
#endif
{
	/* bind a ep to a socket address */
	struct sctp_inpcb *ep, *lep;
	struct sctppcbhead *head;
	struct inpcb *ip_inp;
	int wild, bindall;
	u_short lport;
	int error;

	lport = 0;
	error = wild = 0;
	bindall = 1;
	ep = (struct sctp_inpcb *)so->so_pcb;
	ip_inp = (struct inpcb *)so->so_pcb;
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		if (addr) {
			printf("Bind called port:%d\n",
			       ntohs(((struct sockaddr_in *)addr)->sin_port));
			printf("Addr :");
			sctp_print_address(addr);
		}
	}
#endif /* SCTP_DEBUG */
	if ((ep->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) !=
	    SCTP_PCB_FLAGS_UNBOUND) {
		/* already did a bind, subsequent binds NOT allowed ! */
		return (EINVAL);
	}

	/*
	 * do we support address re-use? if so I am not sure how. It will
	 * need to be added ...
	 */
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;

	if (addr != NULL) {
		if (addr->sa_family == AF_INET) {
			struct sockaddr_in *sin;

			/* IPV6_V6ONLY socket? */
			if (
#if defined(__FreeBSD__)
				(ip_inp->inp_flags & IN6P_IPV6_V6ONLY)
#else
#if defined(__OpenBSD__)
				(0)	/* For openbsd we do dual bind only */
#else
				(((struct in6pcb *)ep)->in6p_flags & IN6P_IPV6_V6ONLY)
#endif
#endif
				) {
				return (EINVAL);
			}

			if (addr->sa_len != sizeof(*sin))
				return (EINVAL);

			sin = (struct sockaddr_in *)addr;
			lport = sin->sin_port;

			if (sin->sin_addr.s_addr != INADDR_ANY) {
				bindall = 0;
			}
		} else if (addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)addr;

			/* FIX: need to check if this is a V4 socket? */
			if (addr->sa_len != sizeof(*sin6))
				return (EINVAL);

			lport = sin6->sin6_port;
			if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				bindall = 0;
				/* KAME hack: embed scopeid */
#if defined(__FreeBSD__)
#ifdef SCTP_BASE_FREEBSD
				if (in6_embedscope(&sin6->sin6_addr, sin6,
				    ip_inp, NULL) != 0)
					return (EINVAL);
#else
				error = scope6_check_id(sin6, ip6_use_defzone);
				if (error != 0)
					return (error);
#endif /* SCTP_BASE_FREEBSD */
#else
				if (in6_embedscope(&sin6->sin6_addr, sin6) != 0) {
					return (EINVAL);
				}
#endif /* __FreeBSD__ */
			}
#ifndef SCOPEDROUTING
			/* this must be cleared for ifa_ifwithaddr() */
			sin6->sin6_scope_id = 0;
#endif /* SCOPEDROUTING */
		} else {
			return (EAFNOSUPPORT);
		}
	}
	if (lport) {
		/*
		 * Did the caller specify a port? if so we must see if a
		 * ep already has this one bound.
		 */
		/* got to be root to get at low ports */
		if (ntohs(lport) < IPPORT_RESERVED) {
			if (p && (error =
#ifdef __FreeBSD__
#if __FreeBSD_version >= 500000
				  suser_cred(p->td_ucred, 0)
#else
				  suser(p)
#endif
#elif defined(__NetBSD__)
				  suser(p->p_ucred, &p->p_acflag)
#else
				  suser(p, 0)
#endif
				))
				return (error);
		}
		if (p == NULL)
			return (error);

		lep = sctp_pcb_findep(addr, 0);
		if (lep != NULL) {
			return (EADDRNOTAVAIL);
		}
		if (bindall) {
			/* verify that no lport is not used by a singleton */
			if (sctp_isport_inuse(ep, lport)) {
				/* Sorry someone already has this one bound */
				return (EADDRNOTAVAIL);
			}
		}
	} else {
		/*
		 * get any port but lets make sure no one has any address
		 * with this port bound
		 */

		/*
		 * setup the inp to the top (I could use the union but this
		 * is just as easy
		 */
		u_short first, last, *lastport;

#ifndef __OpenBSD__
		ip_inp->inp_flags |= INP_ANONPORT;
#endif
		if (ip_inp->inp_flags & INP_LOWPORT) {
			if (p && (error =
#ifdef __FreeBSD__
#if __FreeBSD_version >= 500000
				  suser_cred(p->td_ucred, 0)
#else
				  suser(p)
#endif
#elif defined(__NetBSD__)
				  suser(p->p_ucred, &p->p_acflag)
#else
				  suser(p, 0)
#endif
				))
				return (error);
			if (p == NULL)
				return (error);

			lastport = &sctppcbinfo.lastlow;
#if defined(__FreeBSD__) || defined(__OpenBSD__)

#if defined(__OpenBSD__)
			first = IPPORT_RESERVED-1; /* 1023 */
			last = 600;		   /* not IPPORT_RESERVED/2 */
#else
			first = ipport_lowfirstauto;
			last = ipport_lowlastauto;
#endif

		} else if (ip_inp->inp_flags & INP_HIGHPORT) {
			lastport = &sctppcbinfo.lasthi;
#if defined(__OpenBSD__)
			first = ipport_hifirstauto;	/* sysctl */
			last = ipport_hilastauto;
#else
			first = ipport_hifirstauto;
			last = ipport_hilastauto;
#endif
#else
			first = lowportmin;
			last = lowportmax;
#endif
		} else {
			lastport = &sctppcbinfo.lastport;
#if defined(__FreeBSD__) || defined(__OpenBSD__)
			first = ipport_firstauto;
			last = ipport_lastauto;
#else
			first = anonportmin;
			last = anonportmax;
#endif
		}
		if (first > last) {
			/* we are assigning from large towards small */
			int max, cnt;
			max = first - last;
			cnt = 0;
			do {
				cnt++;
				if (cnt > max)
					return (EAGAIN);
				if ((*lastport > first) || (*lastport == 0)) {
					*lastport = first;
				} else {
					(*lastport)--;
				}
				lport = htons(*lastport);
			} while (sctp_isport_inuse(ep, lport));
		} else {
			/* we are assigning from small towards large */
			int max, cnt;
			max = last - first;
			cnt = 0;
			do {
				cnt++;
				if (cnt > max)
					return (EAGAIN);

				if (*lastport > last)
					*lastport = first;

				if (*lastport < first) {
					*lastport = first;
				} else {
					(*lastport)++;
				}
				lport = htons(*lastport);
			} while (sctp_isport_inuse(ep, lport));
		}
	}
	/* ok we look clear to give out this port, so lets setup the binding */
	if (bindall) {
		/* binding to all addresses, so just set in the proper flags */
		ep->sctp_flags |= (SCTP_PCB_FLAGS_BOUNDALL |
				   SCTP_PCB_FLAGS_DO_ASCONF);
		/* set the automatic addr changes from kernel flag */
		if (sctp_auto_asconf == 0) {
			ep->sctp_flags &= ~SCTP_PCB_FLAGS_AUTO_ASCONF;
		} else {
			ep->sctp_flags |= SCTP_PCB_FLAGS_AUTO_ASCONF;
		}
	} else {
		/*
		 * bind specific, make sure flags is off and add a new address
		 * structure to the sctp_addr_list inside the ep structure.
		 *
		 * We will need to allocate one and insert it at the head.
		 * The socketopt call can just insert new addresses in there
		 * as well. It will also have to do the embed scope kame hack
		 * too (before adding).
		 */
		struct ifaddr *ifa;

		/*
		 * first find the interface with the bound address
		 * need to zero out the port to find the address! yuck!
		 * can't do this earlier since need port for sctp_pcb_findep()
		 * also handle IPv4-mapped address binds on a IPv6 socket
		 */
		if (addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
			sin6->sin6_port = 0;
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				/* convert IPv4-mapped addr into IPv4 addr */
				struct sockaddr_in sin;
				in6_sin6_2_sin(&sin, sin6);
				ifa = ifa_ifwithaddr((struct sockaddr *)&sin);
			} else {
				/* IPv6 address lookup */
				ifa = ifa_ifwithaddr(addr);
			}
		} else {
			struct sockaddr_in *sin = (struct sockaddr_in *)addr;
			sin->sin_port = 0;
			ifa = ifa_ifwithaddr(addr);
		}
		if (ifa == NULL) {
			/* Can't find an interface with that address */
			return (EADDRNOTAVAIL);
		}
		if (addr->sa_family == AF_INET6) {
			struct in6_ifaddr *ifa6;
			ifa6 = (struct in6_ifaddr *)ifa;
			/*
			 * allow binding of deprecated addresses as per
			 * RFC 2462 and ipng discussion
			 */
			if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
					       IN6_IFF_ANYCAST |
					       IN6_IFF_NOTREADY))
				/* Can't bind a non-existent addr. */
				return (EINVAL);
		}
		/* we're not bound all */
		ep->sctp_flags &= ~SCTP_PCB_FLAGS_BOUNDALL;
#if 0 /* use sysctl now */
		/* don't allow automatic addr changes from kernel */
		ep->sctp_flags &= ~SCTP_PCB_FLAGS_AUTO_ASCONF;
#endif
		/* set the automatic addr changes from kernel flag */
		if (sctp_auto_asconf == 0) {
			ep->sctp_flags &= ~SCTP_PCB_FLAGS_AUTO_ASCONF;
		} else {
			ep->sctp_flags |= SCTP_PCB_FLAGS_AUTO_ASCONF;
		}
		/* allow bindx() to send ASCONF's for binding changes */
		ep->sctp_flags |= SCTP_PCB_FLAGS_DO_ASCONF;
		/* add this address to the endpoint list */
		error = sctp_insert_laddr(&ep->sctp_addr_list, ifa);
		if (error != 0)
			return (error);
		ep->laddr_count++;
	}
	/* find the bucket */
	head = &sctppcbinfo.sctp_ephash[SCTP_PCBHASH_ALLADDR(lport, sctppcbinfo.hashmark)];
	/* put it in the bucket */
	LIST_INSERT_HEAD(head, ep, sctp_hash);
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Main hash to bind at head:%p, bound port:%d\n", head, ntohs(lport));
	}
#endif
	/* set in the port */
	ep->sctp_lport = lport;
	/* turn off just the unbound flag */
	ep->sctp_flags &= ~SCTP_PCB_FLAGS_UNBOUND;
	return (0);
}


/* release sctp_inpcb unbind the port */
void
sctp_inpcb_free(struct sctp_inpcb *ep, int immediate)
{
	/*
	 * Here we free a endpoint. We must find it (if it is in the Hash
	 * table) and remove it from there. Then we must also find it in
	 * the overall list and remove it from there. After all removals are
	 * complete then any timer has to be stopped. Then start the actual
	 * freeing.
	 * a) Any local lists.
	 * b) Any associations.
	 * c) The hash of all associations.
	 * d) finally the ep itself.
	 */
	struct sctp_pcb *m;
	struct sctp_tcb *asoc, *nasoc;
	struct sctp_laddr *laddr, *nladdr;
	struct inpcb *ip_pcb;
	struct socket *so;
	struct sctp_socket_q_list  *sq;
	struct rtentry *rt;
	int s, cnt;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (ep->sctp_flags & SCTP_PCB_FLAGS_SOCKET_ALLGONE) {
		/* been here before */
		splx(s);
		printf("Endpoint was all gone (dup free)?\n");
		return;
	}
	sctp_timer_stop(SCTP_TIMER_TYPE_NEWCOOKIE, ep, NULL, NULL);
	if (ep->control) {
		m_freem(ep->control);
		ep->control = NULL;
	}
	if (ep->pkt) {
		m_freem(ep->pkt);
		ep->pkt = NULL;
	}
	so  = ep->sctp_socket;
	m = &ep->sctp_ep;
	ip_pcb = &ep->ip_inp.inp; /* we could just cast the main
				   * pointer here but I will
				   * be nice :> ( i.e. ip_pcb = ep;)
				   */

	ep->sctp_flags |= SCTP_PCB_FLAGS_SOCKET_GONE;
	if (immediate == 0) {
		int cnt_in_sd;
		cnt_in_sd = 0;
		for ((asoc = LIST_FIRST(&ep->sctp_asoc_list)); asoc != NULL;
		     asoc = nasoc) {
			nasoc = LIST_NEXT(asoc, sctp_tcblist);
			if (((asoc->asoc.state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_WAIT) ||
			    ((asoc->asoc.state & SCTP_STATE_MASK) == SCTP_STATE_COOKIE_ECHOED)) {
				/* Just abandon things in the front states */
				sctp_free_assoc(ep, asoc);
				continue;
			} else {
				asoc->asoc.state |= SCTP_STATE_CLOSED_SOCKET;
			}
			if ((asoc->asoc.size_on_delivery_queue  > 0) ||
			    (asoc->asoc.size_on_reasm_queue > 0) ||
			    (asoc->asoc.size_on_all_streams > 0) ||
			    (so && (so->so_rcv.sb_cc > 0))
				) {
				/* Left with Data unread */
				struct mbuf *err;
				err = NULL;
				MGET(err, M_DONTWAIT, MT_DATA);
				if (err) {
					/* Fill in the user initiated abort */
					struct sctp_paramhdr *ph;
					err->m_len = sizeof(struct sctp_paramhdr);
					ph = mtod(err, struct sctp_paramhdr *);
					ph->param_type = htons(SCTP_CAUSE_USER_INITIATED_ABT);
					ph->param_length = htons(err->m_len);
				}
				sctp_send_abort_tcb(asoc, err);
				sctp_free_assoc(ep, asoc);
				continue;
			} else if (TAILQ_EMPTY(&asoc->asoc.send_queue) &&
				  TAILQ_EMPTY(&asoc->asoc.sent_queue)) {
				if (((asoc->asoc.state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_SENT) &&
				    ((asoc->asoc.state & SCTP_STATE_MASK) != SCTP_STATE_SHUTDOWN_ACK_SENT)) {
					/* there is nothing queued to send, so I send shutdown */
					sctp_send_shutdown(asoc, asoc->asoc.primary_destination);
					asoc->asoc.state = SCTP_STATE_SHUTDOWN_SENT;
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWN, asoc->sctp_ep, asoc,
							 asoc->asoc.primary_destination);
					sctp_timer_start(SCTP_TIMER_TYPE_SHUTDOWNGUARD, asoc->sctp_ep, asoc,
							 asoc->asoc.primary_destination);
					sctp_chunk_output(ep, asoc, 1);
				}
			} else {
				/* mark into shutdown pending */
				asoc->asoc.state |= SCTP_STATE_SHUTDOWN_PENDING;
			}
			cnt_in_sd++;
		}
		/* now is there some left in our SHUTDOWN state? */ 
		if (cnt_in_sd) {
			splx(s);
			return;
		}
	}
	ep->sctp_flags |= SCTP_PCB_FLAGS_SOCKET_ALLGONE;
	rt = ip_pcb->inp_route.ro_rt;
	if (so) {
	/* First take care of socket level things */
#ifdef IPSEC
#ifdef __OpenBSD__
	/* XXX IPsec cleanup here */
	    {
		int s2 = spltdb();
		if (ip_pcb->inp_tdb_in)
		    TAILQ_REMOVE(&ip_pcb->inp_tdb_in->tdb_inp_in,
				 ip_pcb, inp_tdb_in_next);
		if (ip_pcb->inp_tdb_out)
		    TAILQ_REMOVE(&ip_pcb->inp_tdb_out->tdb_inp_out, ip_pcb,
				 inp_tdb_out_next);
		if (ip_pcb->inp_ipsec_localid)
		    ipsp_reffree(ip_pcb->inp_ipsec_localid);
		if (ip_pcb->inp_ipsec_remoteid)
		    ipsp_reffree(ip_pcb->inp_ipsec_remoteid);
		if (ip_pcb->inp_ipsec_localcred)
		    ipsp_reffree(ip_pcb->inp_ipsec_localcred);
		if (ip_pcb->inp_ipsec_remotecred)
		    ipsp_reffree(ip_pcb->inp_ipsec_remotecred);
		if (ip_pcb->inp_ipsec_localauth)
		    ipsp_reffree(ip_pcb->inp_ipsec_localauth);
		if (ip_pcb->inp_ipsec_remoteauth)
		    ipsp_reffree(ip_pcb->inp_ipsec_remoteauth);
		splx(s2);
	    }
#else
	    ipsec4_delete_pcbpolicy(ip_pcb);
#endif
#endif /*IPSEC*/
	    so->so_pcb = 0;
	    sofree(so);
	}

	if (ip_pcb->inp_options) {
		(void)m_free(ip_pcb->inp_options);
		ip_pcb->inp_options = 0;
	}
	if (rt) {
		RTFREE(rt);
		ip_pcb->inp_route.ro_rt = 0;
	}
	if (ip_pcb->inp_moptions) {
		ip_freemoptions(ip_pcb->inp_moptions);
		ip_pcb->inp_moptions = 0;
	}
#ifndef __FreeBSD__
	ep->inp_vflag = 0;
#else
	ip_pcb->inp_vflag = 0;
#endif

	/* Now the sctp_pcb things */

	/*
	 * free each asoc if it is not already closed/free. we can't use
	 * the macro here since le_next will get freed as part of the
	 * sctp_free_assoc() call.
	 */
	cnt = 0;
	for ((asoc = LIST_FIRST(&ep->sctp_asoc_list)); asoc != NULL;
	     asoc = nasoc) {
		nasoc = LIST_NEXT(asoc, sctp_tcblist);
		if ((asoc->asoc.state & SCTP_STATE_MASK) !=
		    SCTP_STATE_COOKIE_WAIT) {
			struct mbuf *err;
			err = NULL;
			MGET(err, M_DONTWAIT, MT_DATA);
			if (err) {
				/* Fill in the user initiated abort */
				struct sctp_paramhdr *ph;
				err->m_len = sizeof(struct sctp_paramhdr);
				ph = mtod(err, struct sctp_paramhdr *);
				ph->param_type = htons(SCTP_CAUSE_USER_INITIATED_ABT);
				ph->param_length = htons(err->m_len);
			}
			sctp_send_abort_tcb(asoc, err);
		}
		cnt++;
		sctp_free_assoc(ep, asoc);
	}
	while ((sq = TAILQ_FIRST(&ep->sctp_queue_list)) != NULL) {
		TAILQ_REMOVE(&ep->sctp_queue_list, sq, next_sq);
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_sockq, sq);
#else
		zfreei(sctppcbinfo.ipi_zone_sockq, sq);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_sockq, sq);
#endif
		sctppcbinfo.ipi_count_sockq--;
		sctppcbinfo.ipi_gencnt_sockq++;
	}
	ep->sctp_socket = 0;
	/* Now first we remove ourselves from the overall list of all EP's */
	LIST_REMOVE(ep, sctp_list);

	/*
	 * Now the question comes as to if this EP was ever bound at all.
	 * If it was, then we must pull it out of the EP hash list.
	 */
	if ((ep->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) !=
	    SCTP_PCB_FLAGS_UNBOUND) {
		/*
		 * ok, this guy has been bound. It's port is somewhere
		 * in the sctppcbinfo hash table. Remove it!
		 */
		LIST_REMOVE(ep, sctp_hash);
	}
	/*
	 * if we have an address list the following will free the list of
	 * ifaddr's that are set into this ep. Again macro limitations here,
	 * since the LIST_FOREACH could be a bad idea.
	 */
#ifndef SCTP_VTAG_TIMEWAIT_PER_STACK
	/* Free anything in the vtag_waitblock */
	{
		int i;
		struct sctp_tagblock *tb, *ntb;
		for (i = 0; i < SCTP_NUMBER_IN_VTAG_BLOCK; i++) {
			tb = LIST_FIRST(&ep->vtag_timewait[i]);
			while (tb) {
				ntb = LIST_NEXT(tb, sctp_nxt_tagblock);
				LIST_REMOVE(tb, sctp_nxt_tagblock);
				free(tb, M_PCB);
				tb = ntb;
			}
		}
	}
#endif /* !SCTP_VTAG_TIMEWAIT_PER_STACK */
	for ((laddr = LIST_FIRST(&ep->sctp_addr_list)); laddr != NULL;
	     laddr = nladdr) {
		nladdr = LIST_NEXT(laddr, sctp_nxt_addr);
		LIST_REMOVE(laddr, sctp_nxt_addr);
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_laddr, laddr);
#else
		zfreei(sctppcbinfo.ipi_zone_laddr, laddr);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_laddr, laddr);
#endif
		sctppcbinfo.ipi_gencnt_laddr++;
		sctppcbinfo.ipi_count_laddr--;
	}
	/* Now lets see about freeing the EP hash table. */
	if (ep->sctp_tcbhash != NULL) {
		free(ep->sctp_tcbhash, M_PCB);
		ep->sctp_tcbhash = 0;
	}

	/* Now we must put the ep memory back into the zone pool */
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	uma_zfree(sctppcbinfo.ipi_zone_ep, ep);
#else
	zfreei(sctppcbinfo.ipi_zone_ep, ep);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	pool_put(&sctppcbinfo.ipi_zone_ep, ep);
#endif
	sctppcbinfo.ipi_count_ep--;
	splx(s);
}


struct sctp_nets *
sctp_findnet(struct sctp_tcb *tcb, struct sockaddr *addr)
{
	struct sctp_nets *net;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	/* use the peer's/remote port for lookup if unspecified */
	sin = (struct sockaddr_in *)addr;
	sin6 = (struct sockaddr_in6 *)addr;
#if 0 /* why do we need to check the port for a nets list on an assoc? */
	if (tcb->rport != sin->sin_port) {
		/* we cheat and just a sin for this test */
		return (NULL);
	}
#endif
	/* locate the address */
	TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
		if (sctp_cmpaddr(addr, (struct sockaddr *)&net->ra._l_addr))
			return (net);
	}
	return (NULL);
}


/*
 * add's a remote endpoint address, done with the INIT/INIT-ACK
 * as well as when a ASCONF arrives that adds it. It will also
 * initialize all the cwnd stats of stuff.
 */
int
sctp_is_address_on_local_host(struct sockaddr *addr)
{
	struct ifnet *ifn;
	struct ifaddr *ifa;
	TAILQ_FOREACH(ifn,&ifnet, if_list) {
		TAILQ_FOREACH(ifa, &ifn->if_addrlist, ifa_list) {
			if (addr->sa_family == ifa->ifa_addr->sa_family) {
				/* same family */
				if (addr->sa_family == AF_INET) {
					struct sockaddr_in *sin,*sin_c;
					sin = (struct sockaddr_in *)addr;
					sin_c = (struct sockaddr_in *)ifa->ifa_addr;
					if (sin->sin_addr.s_addr == sin_c->sin_addr.s_addr) {
						/* we are on the same machine */
						return (1);
					}
				} else if (addr->sa_family == AF_INET6) {
					struct sockaddr_in6 *sin6,*sin_c6;
					sin6 = (struct sockaddr_in6 *)addr;
					sin_c6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					if (SCTP6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
								&sin_c6->sin6_addr)) {
						/* we are on the same machine */
						return (1);
					}
				}
			}
		}
	}
	return (0);
}

int
sctp_add_remote_addr(struct sctp_tcb *tasoc, struct sockaddr *newaddr,
		     int set_scope, int from)
{
	/*
	 * The following is redundant to the same lines in the
	 * sctp_aloc_assoc() but is needed since other's call the add
	 * address function
	 */
	struct sctp_nets *netp, *netfirst;
	int addr_inscope;

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Adding an address (from:%d) to the peer: ", from);
		sctp_print_address(newaddr);
	}
#endif
	netfirst = sctp_findnet(tasoc, newaddr);
	if (netfirst) {
		/* Lie and return ok, we don't want to 
		 * make the association go away for
		 * this behavior. It will happen in the 
		 * TCP model in a connected socket. It does
		 * not reach the hash table until after the
		 * association is built so it can't be found.
		 * Mark as reachable, since the initial creation
		 * will have been cleared and the NOT_IN_ASSOC flag
		 * will have been added... and we don't wan't to
		 * end up removing it back out.
		 */
		if (netfirst->dest_state & SCTP_ADDR_UNCONFIRMED) {
			netfirst->dest_state = (SCTP_ADDR_REACHABLE|SCTP_ADDR_UNCONFIRMED);
		} else {
			netfirst->dest_state = SCTP_ADDR_REACHABLE;
		}

		return (0);
	}
	addr_inscope = 1;
	if (newaddr->sa_family == AF_INET) {
		struct sockaddr_in *sin;
		sin = (struct sockaddr_in *)newaddr;
		if ((sin->sin_port == 0) || (sin->sin_addr.s_addr == 0)) {
			/* Invalid address */
			return (-1);
		}
		/* zero out the bzero area */
		memset(sin->sin_zero,0,sizeof(sin->sin_zero));

		/* assure len is set */
		sin->sin_len = sizeof(struct sockaddr_in);
		if (set_scope) {
#ifdef SCTP_DONT_DO_PRIVADDR_SCOPE
			asoc->ipv4_local_scope = 1;
#else
			if (IN4_ISPRIVATE_ADDRESS(&sin->sin_addr)) {
				tasoc->asoc.ipv4_local_scope = 1;
			}
#endif /* SCTP_DONT_DO_PRIVADDR_SCOPE */
			
			if (sctp_is_address_on_local_host(newaddr)) {
				tasoc->asoc.loopback_scope = 1;
				tasoc->asoc.ipv4_local_scope = 1;
				tasoc->asoc.local_scope = 1;
				tasoc->asoc.site_scope = 1;
			}
		} else {
			if (from == 8) {
				/* From connectx */
				if (sctp_is_address_on_local_host(newaddr)) {
					tasoc->asoc.loopback_scope = 1;
					tasoc->asoc.ipv4_local_scope = 1;
					tasoc->asoc.local_scope = 1;
					tasoc->asoc.site_scope = 1;
				}
			}
			/* Validate the address is in scope */
			if ((IN4_ISPRIVATE_ADDRESS(&sin->sin_addr)) &&
			    (tasoc->asoc.ipv4_local_scope == 0)) {
				addr_inscope = 0;
			}
		}
	} else if (newaddr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)newaddr;
		if ((sin6->sin6_port == 0) ||
		    (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))) {
			/* Invalid address */
			return (-1);
		}
		/* assure len is set */
		sin6->sin6_len = sizeof(struct sockaddr_in6);
		if (set_scope) {
			if (sctp_is_address_on_local_host(newaddr)) {
				tasoc->asoc.loopback_scope = 1;
				tasoc->asoc.local_scope = 1;
				tasoc->asoc.ipv4_local_scope = 1;
				tasoc->asoc.site_scope = 1;
			} else if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				/*
				 * If the new destination is a LINK_LOCAL
				 * we must have common site scope. Don't set
				 * the local scope since we may not share all
				 * links, only loopback can do this.
				 */
				tasoc->asoc.site_scope = 1;
			} else if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
				/*
				 * If the new destination is SITE_LOCAL
				 * then we must have site scope in common.
				 */
				tasoc->asoc.site_scope = 1;
			}
		} else {
			if (from == 8) {
				/* From connectx */
				if (sctp_is_address_on_local_host(newaddr)) {
					tasoc->asoc.loopback_scope = 1;
					tasoc->asoc.ipv4_local_scope = 1;
					tasoc->asoc.local_scope = 1;
					tasoc->asoc.site_scope = 1;
				}
			}
			/* Validate the address is in scope */
			if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) &&
			    (tasoc->asoc.loopback_scope == 0)) {
				addr_inscope = 0;
			} else if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) &&
				   (tasoc->asoc.local_scope == 0)) {
				addr_inscope = 0;
			} else if (IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) &&
				   (tasoc->asoc.site_scope == 0)) {
				addr_inscope = 0;
			}
		}
	} else {
		/* not supported family type */
		return (-1);
	}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	netp = (struct sctp_nets *)uma_zalloc(sctppcbinfo.ipi_zone_raddr, M_NOWAIT);
#else
	netp = (struct sctp_nets *)zalloci(sctppcbinfo.ipi_zone_raddr);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	netp = (struct sctp_nets *)pool_get(&sctppcbinfo.ipi_zone_raddr,
					    PR_NOWAIT);
#endif

	if (netp == NULL) {
		return (-1);
	}
	sctppcbinfo.ipi_count_raddr++;
	sctppcbinfo.ipi_gencnt_raddr++;
	bzero((caddr_t)netp, sizeof(*netp));
	memcpy(&netp->ra._l_addr, newaddr, newaddr->sa_len);
#if defined(__FreeBSD__)
	if (newaddr->sa_family == AF_INET6)
		netp->addr_is_local =
		    in6_localaddr(&(((struct sockaddr_in6 *)newaddr)->sin6_addr));
	else
		netp->addr_is_local = in_localaddr(((struct sockaddr_in *)newaddr)->sin_addr);
#else
	netp->addr_is_local = 0;
#endif

	netp->failure_threshold = tasoc->asoc.def_net_failure;
	if (addr_inscope == 0) {
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB1) {
			printf("Adding an address which is OUT OF SCOPE\n");
		}
#endif /* SCTP_DEBUG */
		netp->dest_state = (SCTP_ADDR_REACHABLE |
				    SCTP_ADDR_OUT_OF_SCOPE);
	} else {
		if (from == 8)
			/* 8 is passed by connect_x */
			netp->dest_state = SCTP_ADDR_REACHABLE;
		else 
			netp->dest_state = SCTP_ADDR_REACHABLE | SCTP_ADDR_UNCONFIRMED;
	}
	netp->RTO = 0;
	tasoc->asoc.numnets++;
	netp->ref_count = 1;

	/* Init the timer structure */
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&netp->rxt_timer.timer, 0);
#else
	callout_init(&netp->rxt_timer.timer);
#endif
	/* Now generate a route for this guy */
#ifdef __FreeBSD__
	netp->ra.ro_rt = rtalloc1((struct sockaddr *)&netp->ra._l_addr,
				  1, 0UL);
#else
	netp->ra.ro_rt = rtalloc1((struct sockaddr *)&netp->ra._l_addr,
				  1);
#endif
	if ((netp->ra.ro_rt) && 
	    (netp->ra.ro_rt->rt_ifp)) {
		netp->mtu = netp->ra.ro_rt->rt_ifp->if_mtu;
		if (from == 1) {
			tasoc->asoc.smallest_mtu = netp->mtu;
		}
		/* start things off to match mtu of interface please. */
		netp->ra.ro_rt->rt_rmx.rmx_mtu = netp->ra.ro_rt->rt_ifp->if_mtu;
	} else {
		netp->mtu = tasoc->asoc.smallest_mtu;
	}
	if (tasoc->asoc.smallest_mtu > netp->mtu) {
		tasoc->asoc.smallest_mtu = netp->mtu;
	}
	if (netp->addr_is_local) {
		netp->cwnd = max((netp->mtu * 4), SCTP_INITIAL_CWND);
	} else {
		netp->cwnd = min((netp->mtu * 4), max((2*netp->mtu), SCTP_INITIAL_CWND));
	}
	if (netp->cwnd < (2*netp->mtu)) {
		netp->cwnd = 2 * netp->mtu;
	}
	netp->ssthresh = tasoc->asoc.peers_rwnd;

	netp->src_addr_selected = 0;
	netfirst = TAILQ_FIRST(&tasoc->asoc.nets);
	if (netp->ra.ro_rt == NULL) {
		/* Since we have no route put it at the back */
		TAILQ_INSERT_TAIL(&tasoc->asoc.nets, netp, sctp_next);
	} else if (netfirst == NULL) {
		/* We are the first one in the pool. */
		TAILQ_INSERT_HEAD(&tasoc->asoc.nets, netp, sctp_next);
	} else if (netfirst->ra.ro_rt == NULL) {
		/*
		 * First one has NO route. Place this one ahead of the
		 * first one.
		 */
		TAILQ_INSERT_HEAD(&tasoc->asoc.nets, netp, sctp_next);
	} else if (netp->ra.ro_rt->rt_ifp != netfirst->ra.ro_rt->rt_ifp) {
		/*
		 * This one has a different interface than the one at the
		 * top of the list. Place it ahead.
		 */
		TAILQ_INSERT_HEAD(&tasoc->asoc.nets, netp, sctp_next);
	} else {
		/*
		 * Ok we have the same interface as the first one. Move
		 * forward until we find either
		 *   a) one with a NULL route... insert ahead of that
		 *   b) one with a different ifp.. insert after that.
		 *   c) end of the list.. insert at the tail.
		 */
		struct sctp_nets *netlook;
		do {
			netlook = TAILQ_NEXT(netfirst, sctp_next);
			if (netlook == NULL) {
				/* End of the list */
				TAILQ_INSERT_TAIL(&tasoc->asoc.nets, netp,
						  sctp_next);
				break;
			} else if (netlook->ra.ro_rt == NULL) {
				/* next one has NO route */
				TAILQ_INSERT_BEFORE(netfirst, netp, sctp_next);
				break;
			} else if (netlook->ra.ro_rt->rt_ifp !=
				   netp->ra.ro_rt->rt_ifp) {
				TAILQ_INSERT_AFTER(&tasoc->asoc.nets, netlook,
						   netp, sctp_next);
				break;
			}
			/* Shift forward */
			netfirst = netlook;
		} while (netlook != NULL);
	}
	/* got to have a primary set */
	if (tasoc->asoc.primary_destination == 0) {
		tasoc->asoc.primary_destination = netp;
	} else if ((tasoc->asoc.primary_destination->ra.ro_rt == NULL) &&
		   (netp->ra.ro_rt)) {
		/* No route to current primary adopt new primary */
		tasoc->asoc.primary_destination = netp;
	}
	sctp_timer_start(SCTP_TIMER_TYPE_PATHMTURAISE, tasoc->sctp_ep,
			 tasoc, netp);

	return (0);
}


/*
 * allocate an association and add it to the endpoint. The caller must
 * be careful to add all additional addresses once they are know right
 * away or else the assoc will be may experience a blackout scenario.
 */
struct sctp_tcb *
sctp_aloc_assoc(struct sctp_inpcb *ep, struct sockaddr *firstaddr,
		int for_a_init, int *error)
{
	struct sctp_tcb *tasoc;
	struct sctp_association *asoc;
	struct sctpasochead *head;
	u_short rport;
	int imp_ret;
	/*
	 * Assumption made here:
	 *  Caller has done a sctp_findassociation_ep_addr(ep, addr's);
	 *  to make sure the address does not exist already.
	 */
	if (sctppcbinfo.ipi_count_asoc >= SCTP_MAX_NUM_OF_ASOC) {
		/* Hit max assoc, sorry no more */
		*error = ENOBUFS;
		return (NULL);
	}

#ifdef SCTP_TCP_MODEL_SUPPORT
	if (ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL) {
		/* If its in the TCP pool, its NOT allowed
		 * to create an association. The parent listener
		 * needs to call sctp_alloc_assoc.. or the one1-2-many
		 * socket. If a peeled off, or connected one does
		 * this.. its an error.
		 */
		*error = EINVAL;
		return (NULL);
 	}
#endif

#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB3) {
		printf("Allocate an association for peer:");
		if (firstaddr)
			sctp_print_address(firstaddr);
		else
			printf("None\n");
		printf("Port:%d\n",
		       ntohs(((struct sockaddr_in *)firstaddr)->sin_port));
	}
#endif /* SCTP_DEBUG */
	if (firstaddr->sa_family == AF_INET) {
		struct sockaddr_in *sin;
		sin = (struct sockaddr_in *)firstaddr;
		if ((sin->sin_port == 0) || (sin->sin_addr.s_addr == 0)) {
			/* Invalid address */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_PCB3) {
				printf("peer address invalid\n");
			}
#endif
			*error = EINVAL;
			return (NULL);
		}
		rport = sin->sin_port;
	} else if (firstaddr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)firstaddr;
		if ((sin6->sin6_port == 0) ||
		    (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))) {
			/* Invalid address */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_PCB3) {
				printf("peer address invalid\n");
			}
#endif
			*error = EINVAL;
			return (NULL);
		}
		rport = sin6->sin6_port;
	} else {
		/* not supported family type */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB3) {
			printf("BAD family %d\n", firstaddr->sa_family);
		}
#endif
		*error = EINVAL;
		return (NULL);
	}
	if (ep->sctp_flags & SCTP_PCB_FLAGS_UNBOUND) {
		/*
		 * If you have not performed a bind, then we need to do
		 * the ephemerial bind for you.
		 */

#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB3) {
			printf("Doing implicit BIND\n");
		}
#endif
		if ((imp_ret = sctp_inpcb_bind(ep->sctp_socket, (struct sockaddr *)NULL,
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
					       (struct thread *)NULL))) {
#else
					       (struct proc *)NULL))) {
#endif
			/* bind error, probably perm */
#ifdef SCTP_DEBUG
			if (sctp_debug_on & SCTP_DEBUG_PCB3) {
				printf("BIND FAILS ret:%d\n", imp_ret);
			}
#endif
			*error = imp_ret;
			return (NULL);
		}
	}

#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	tasoc = (struct sctp_tcb *)uma_zalloc(sctppcbinfo.ipi_zone_asoc, M_NOWAIT);
#else
	tasoc = (struct sctp_tcb *)zalloci(sctppcbinfo.ipi_zone_asoc);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	tasoc = (struct sctp_tcb *)pool_get(&sctppcbinfo.ipi_zone_asoc,
					    PR_NOWAIT);
#endif

	if (tasoc == NULL) {
		/* out of memory? */
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB3) {
			printf("aloc_assoc: no assoc mem left, tasoc=NULL\n");
		}
#endif
		*error = ENOMEM;
		return (NULL);
	}
	sctppcbinfo.ipi_count_asoc++;
	sctppcbinfo.ipi_gencnt_asoc++;

	bzero((caddr_t)tasoc, sizeof(*tasoc));
	asoc = &tasoc->asoc;
	if ((imp_ret = sctp_init_asoc(ep, asoc, for_a_init))) {
		/* failed */
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_asoc, tasoc);
#else
		zfreei(sctppcbinfo.ipi_zone_asoc, tasoc);
#endif
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_asoc, tasoc);
#endif
		sctppcbinfo.ipi_count_asoc--;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB3) {
			printf("aloc_assoc: couldn't init asoc, out of mem?!\n");
		}
#endif
		*error = imp_ret;
		return (NULL);
	}
	/* setup back pointer's */
	tasoc->sctp_ep = ep;
	tasoc->sctp_socket = ep->sctp_socket;

	/* and the port */
	tasoc->rport = rport;

	/* now that my_vtag is set, add it to the  hash */
	head = &sctppcbinfo.sctp_asochash[SCTP_PCBHASH_ASOC(tasoc->asoc.my_vtag, sctppcbinfo.hashasocmark)];
	/* put it in the bucket in the vtag hash of assoc's for the system */
	LIST_INSERT_HEAD(head, tasoc, sctp_asocs);

	if ((imp_ret = sctp_add_remote_addr(tasoc, firstaddr, 1, 1))) {
		/* failure.. memory error? */
		if (asoc->strmout)
			free(asoc->strmout, M_PCB);
		if (asoc->mapping_array)
			free(asoc->mapping_array, M_PCB);
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_asoc, tasoc);
#else
		zfreei(sctppcbinfo.ipi_zone_asoc, tasoc);
#endif
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_asoc, tasoc);
#endif
		sctppcbinfo.ipi_count_asoc--;
#ifdef SCTP_DEBUG
		if (sctp_debug_on & SCTP_DEBUG_PCB3) {
			printf("aloc_assoc: couldn't add remote addr!\n");
		}
#endif
		*error = ENOBUFS;
		return (NULL);
	}
	if ((caddr_t)tasoc < ep->lowest_tcb) {
		ep->lowest_tcb = (caddr_t)tasoc;
	}
	if ((caddr_t)tasoc > ep->highest_tcb) {
		ep->highest_tcb = (caddr_t)tasoc;
	}
	if ((caddr_t)tasoc < sctp_lowest_tcb) {
		sctp_lowest_tcb = (caddr_t)tasoc;
	}
	if ((caddr_t)tasoc > sctp_highest_tcb) {
		sctp_highest_tcb = (caddr_t)tasoc;
	}

	/* Init all the timers */
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	callout_init(&asoc->hb_timer.timer, 0);
	callout_init(&asoc->dack_timer.timer, 0);
	callout_init(&asoc->asconf_timer.timer, 0);
	callout_init(&asoc->shut_guard_timer.timer, 0);
	callout_init(&asoc->autoclose_timer.timer, 0);
#else
	callout_init(&asoc->hb_timer.timer);
	callout_init(&asoc->dack_timer.timer);
	callout_init(&asoc->asconf_timer.timer);
	callout_init(&asoc->shut_guard_timer.timer);
	callout_init(&asoc->autoclose_timer.timer);
#endif

	LIST_INSERT_HEAD(&ep->sctp_asoc_list, tasoc, sctp_tcblist);

	/* now file the port under the hash as well */
	if (ep->sctp_tcbhash != NULL) {
		head = &ep->sctp_tcbhash[SCTP_PCBHASH_ALLADDR(tasoc->rport, ep->sctp_hashmark)];
		LIST_INSERT_HEAD(head, tasoc, sctp_tcbhash);
	}
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		printf("Association %p now allocated\n", tasoc);
	}
#endif
	return (tasoc);
}

void
sctp_free_remote_addr(struct sctp_nets *net)
{
	if (net == NULL)
		return;
	net->ref_count--;
	if (net->ref_count <= 0) {
		/* stop timer if running */
		callout_stop(&net->rxt_timer.timer);
		callout_stop(&net->pmtu_timer.timer);
		net->dest_state = SCTP_ADDR_NOT_REACHABLE;
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_raddr, net);
#else
		zfreei(sctppcbinfo.ipi_zone_raddr, net);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_raddr, net);
#endif
		sctppcbinfo.ipi_count_raddr--;
	}
}

/*
 * remove a remote endpoint address from an association, it
 * will fail if the address does not exist.
 */
int
sctp_del_remote_addr(struct sctp_tcb *tasoc, struct sockaddr *rem)
{
	/*
	 * Here we need to remove a remote address. This is quite simple, we
	 * first find it in the list of address for the association
	 * (tasoc->asoc.nets) and then if it is there, we do a LIST_REMOVE on
	 * that item.
	 * Note we do not allow it to be removed if there are no other
	 * addresses.
	 */
	struct sctp_association *asoc;
	struct sctp_nets *net, *net_tmp;
	asoc = &tasoc->asoc;
	if (asoc->numnets < 2) {
		/* Must have at LEAST two remote addresses */
		return (-1);
	}
	/* locate the address */
	for (net = TAILQ_FIRST(&asoc->nets); net != NULL; net = net_tmp) {
		net_tmp = TAILQ_NEXT(net, sctp_next);
		if (((struct sockaddr *)(&net->ra._l_addr))->sa_family !=
		    rem->sa_family) {
			continue;
		}
		if (sctp_cmpaddr((struct sockaddr *)&net->ra._l_addr, rem)) {
			/* we found the guy */
			asoc->numnets--;
			TAILQ_REMOVE(&asoc->nets, net, sctp_next);
			sctp_free_remote_addr(net);
			if (net == asoc->primary_destination) {
				/* Reset primary */
				struct sctp_nets *lnet;
				lnet = TAILQ_FIRST(&asoc->nets);
				/* Try to find a confirmed primary */
				asoc->primary_destination = sctp_find_alternate_net(tasoc,lnet);
			}
			if (net == asoc->last_data_chunk_from) {
				/* Reset primary */
				asoc->last_data_chunk_from = TAILQ_FIRST(&asoc->nets);
			}
			if (net == asoc->last_control_chunk_from) {
				/* Reset primary */
				asoc->last_control_chunk_from = TAILQ_FIRST(&asoc->nets);
			}
			if (net == asoc->asconf_last_sent_to) {
				/* Reset primary */
				asoc->asconf_last_sent_to = TAILQ_FIRST(&asoc->nets);
			}
			return (0);
		}
	}
	/* not found. */
	return (-2);
}


static void
sctp_add_vtag_to_timewait(struct sctp_inpcb *m, u_int32_t tag)
{
	struct sctpvtaghead *chain;
	struct sctp_tagblock *twait_block;
	struct timeval now;
	int set, i;
	SCTP_GETTIME_TIMEVAL(&now);
#ifdef SCTP_VTAG_TIMEWAIT_PER_STACK
	chain = &sctppcbinfo.vtag_timewait[(tag % SCTP_STACK_VTAG_HASH_SIZE)];
#else
	chain = &m->vtag_timewait[(tag % SCTP_STACK_VTAG_HASH_SIZE)];
#endif
	set = 0;
	if (!LIST_EMPTY(chain)) {
		/* Block(s) present, lets find space, and expire on the fly */
		LIST_FOREACH(twait_block, chain, sctp_nxt_tagblock) {
			for (i = 0; i < SCTP_NUMBER_IN_VTAG_BLOCK; i++) {
				if ((twait_block->vtag_block[i].v_tag == 0) &&
				    !set) {
					twait_block->vtag_block[0].tv_sec_at_expire =
					    now.tv_sec + SCTP_TIME_WAIT;
					twait_block->vtag_block[0].v_tag = tag;
					set = 1;
				} else if ((twait_block->vtag_block[i].v_tag) &&
					   (twait_block->vtag_block[i].tv_sec_at_expire >
					    now.tv_sec)) {
					/* Audit expires this guy */
					twait_block->vtag_block[i].tv_sec_at_expire = 0;
					twait_block->vtag_block[i].v_tag = 0;
					if (set == 0) {
						/* Reuse it for my new tag */
						twait_block->vtag_block[0].tv_sec_at_expire = now.tv_sec + SCTP_TIME_WAIT;
						twait_block->vtag_block[0].v_tag = tag;
						set = 1;
					}
				}
			}
			if (set) {
				/*
				 * We only do up to the block where we can place our
				 * tag for audits
				 */
				break;
			}
		}
	}
	/* Need to add a new block to chain */
	if (!set) {
		twait_block = malloc(sizeof(struct sctp_tagblock), M_PCB, M_NOWAIT);
		if (twait_block == NULL) {
			return;
		}
		memset(twait_block, 0, sizeof(struct sctp_timewait));
		LIST_INSERT_HEAD(chain, twait_block, sctp_nxt_tagblock);
		twait_block->vtag_block[0].tv_sec_at_expire = now.tv_sec +
		    SCTP_TIME_WAIT;
		twait_block->vtag_block[0].v_tag = tag;
	}
}


/*
 * Free the association after un-hashing the remote port.
 */
void
sctp_free_assoc(struct sctp_inpcb *ep, struct sctp_tcb *tasoc)
{
	struct sctp_association *asoc;
	struct sctp_nets *net, *prev;
	struct sctp_laddr *laddr;
	struct sctp_tmit_chunk *chk;
	struct sctp_asconf_addr *aparam;
	struct sctp_socket_q_list *sq;
	int s;
	
	/* first, lets purge the entry from the hash table. */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	if (tasoc->asoc.state == 0) {
		printf("Freeing already free association:%p - huh??\n",
			tasoc);
		splx(s);
		return;
	}
	/* Null all of my entry's on the socket q */
	TAILQ_FOREACH(sq, &ep->sctp_queue_list, next_sq) {
		if (sq->tcb == tasoc) {
			sq->tcb = NULL;
		}
	}

	if (ep->sctp_tcb_at_block == (void *)tasoc) {
		ep->error_on_block = ECONNRESET;
	}
	if (ep->sctp_tcbhash) {
		LIST_REMOVE(tasoc, sctp_tcbhash);
	}
	/* pull it from the vtag hash */
	LIST_REMOVE(tasoc, sctp_asocs);

	/* Now lets remove it from the list of ALL associations in the EP */
	LIST_REMOVE(tasoc, sctp_tcblist);

	/*
	 * Now before we can free the assoc, we must  remove all of the
	 * networks and any other allocated space.. i.e. add removes here
	 * before the zfreei() of the tasoc entry.
	 */
	asoc = &tasoc->asoc;
	asoc->state = 0;

	sctp_add_vtag_to_timewait(ep, asoc->my_vtag);
	/* now clean up any other timers */
	callout_stop(&asoc->hb_timer.timer);
	callout_stop(&asoc->dack_timer.timer);
	callout_stop(&asoc->asconf_timer.timer);
	callout_stop(&asoc->shut_guard_timer.timer);
	callout_stop(&asoc->autoclose_timer.timer);
#ifdef SCTP_TCP_MODEL_SUPPORT
	callout_stop(&asoc->delayed_event_timer.timer);
#endif /* SCTP_TCP_MODEL_SUPPORT */
	TAILQ_FOREACH(net, &asoc->nets, sctp_next) {
		callout_stop(&net->rxt_timer.timer);
		callout_stop(&net->pmtu_timer.timer);
	}
	prev = NULL;
	while (!TAILQ_EMPTY(&asoc->nets)) {
		net = TAILQ_FIRST(&asoc->nets);
		/* pull from list */
		if ((sctppcbinfo.ipi_count_raddr == 0) || (prev == net)) {
			break;
		}
		prev = net;
		TAILQ_REMOVE(&asoc->nets, net, sctp_next);
		/* free it */
		net->ref_count = 0;
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_raddr, net);
#else
		zfreei(sctppcbinfo.ipi_zone_raddr, net);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_raddr, net);
#endif
		sctppcbinfo.ipi_count_raddr--;
	}
	/*
	 * The chunk lists and such SHOULD be empty but we check them
	 * just in case.
	 */
	/* anything on the wheel needs to be removed */
	while (!TAILQ_EMPTY(&asoc->out_wheel)) {
		struct sctp_stream_out *outs;
		outs = TAILQ_FIRST(&asoc->out_wheel);
		TAILQ_REMOVE(&asoc->out_wheel, outs, next_spoke);
		/* now clean up any chunks here */
		chk = TAILQ_FIRST(&outs->outqueue);
		while (chk) {
			TAILQ_REMOVE(&outs->outqueue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
			chk->whoTo = NULL;
			chk->asoc = NULL;
			/* Free the chunk */
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			sctppcbinfo.ipi_gencnt_chunk++;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			chk = TAILQ_FIRST(&outs->outqueue);
		}
		outs = TAILQ_FIRST(&asoc->out_wheel);
	}
	/* pending send queue SHOULD be empty */
	if (!TAILQ_EMPTY(&asoc->send_queue)) {
		chk = TAILQ_FIRST(&asoc->send_queue);
		while (chk) {
			TAILQ_REMOVE(&asoc->send_queue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = TAILQ_FIRST(&asoc->send_queue);
		}
	}
	/* sent queue SHOULD be empty */
	if (!TAILQ_EMPTY(&asoc->sent_queue)) {
		chk = TAILQ_FIRST(&asoc->sent_queue);
		while (chk) {
			TAILQ_REMOVE(&asoc->sent_queue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = TAILQ_FIRST(&asoc->sent_queue);
		}
	}
	/* control queue MAY not be empty */
	if (!TAILQ_EMPTY(&asoc->control_send_queue)) {
		chk = TAILQ_FIRST(&asoc->control_send_queue);
		while (chk) {
			TAILQ_REMOVE(&asoc->control_send_queue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = TAILQ_FIRST(&asoc->control_send_queue);
		}
	}
	if (!TAILQ_EMPTY(&asoc->reasmqueue)) {
		chk = TAILQ_FIRST(&asoc->reasmqueue);
		while (chk) {
			TAILQ_REMOVE(&asoc->reasmqueue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif

			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = TAILQ_FIRST(&asoc->reasmqueue);
		}
	}
	if (!TAILQ_EMPTY(&asoc->delivery_queue)) {
		chk = TAILQ_FIRST(&asoc->delivery_queue);
		while (chk) {
			TAILQ_REMOVE(&asoc->delivery_queue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
			pool_put(&sctppcbinfo.ipi_zone_chunk, chk);
#endif
			sctppcbinfo.ipi_count_chunk--;
			if ((int)sctppcbinfo.ipi_count_chunk < 0) {
				panic("Chunk count is negative");
			}
			sctppcbinfo.ipi_gencnt_chunk++;
			chk = TAILQ_FIRST(&asoc->delivery_queue);
		}
	}
	if (asoc->mapping_array) {
		free(asoc->mapping_array, M_PCB);
		asoc->mapping_array = NULL;
	}

	/* the stream outs */
	if (asoc->strmout) {
		free(asoc->strmout, M_PCB);
		asoc->strmout = NULL;
	}
	asoc->streamoutcnt = 0;
	if (asoc->strmin) {
		int i;
		for (i = 0; i < asoc->streamincnt; i++) {
			if (!TAILQ_EMPTY(&asoc->strmin[i].inqueue)) {
				/* We have somethings on the streamin queue */
				chk = TAILQ_FIRST(&asoc->strmin[i].inqueue);
				while (chk) {
					TAILQ_REMOVE(&asoc->strmin[i].inqueue,
						     chk, sctp_next);
					if (chk->data) {
						m_freem(chk->data);
						chk->data = NULL;
					}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
					uma_zfree(sctppcbinfo.ipi_zone_chunk,
						  chk);
#else
					zfreei(sctppcbinfo.ipi_zone_chunk,
					       chk);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
					pool_put(&sctppcbinfo.ipi_zone_chunk,
						 chk);
#endif
					sctppcbinfo.ipi_count_chunk--;
					if ((int)sctppcbinfo.ipi_count_chunk < 0) {
						panic("Chunk count is negative");
					}
					sctppcbinfo.ipi_gencnt_chunk++;
					chk = TAILQ_FIRST(&asoc->strmin[i].inqueue);
				}
			}
		}
		free(asoc->strmin, M_PCB);
		asoc->strmin = NULL;
	}
	asoc->streamincnt = 0;
	/* local addresses, if any */
	while (!LIST_EMPTY(&asoc->sctp_local_addr_list)) {
		laddr = LIST_FIRST(&asoc->sctp_local_addr_list);
		LIST_REMOVE(laddr, sctp_nxt_addr);
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
		uma_zfree(sctppcbinfo.ipi_zone_laddr, laddr);
#else
		zfreei(sctppcbinfo.ipi_zone_laddr, laddr);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
		pool_put(&sctppcbinfo.ipi_zone_laddr, laddr);
#endif
		sctppcbinfo.ipi_count_laddr--;
	}
	/* pending asconf (address) parameters */
	while (!TAILQ_EMPTY(&asoc->asconf_queue)) {
		aparam = TAILQ_FIRST(&asoc->asconf_queue);
		TAILQ_REMOVE(&asoc->asconf_queue, aparam, next);
		free(aparam, M_PCB);
	}
	if (asoc->last_asconf_ack_sent != NULL) {
		m_freem(asoc->last_asconf_ack_sent);
		asoc->last_asconf_ack_sent = NULL;
	}
	/* Insert new items here :> */

	/* now clean up the tasoc itself */
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	uma_zfree(sctppcbinfo.ipi_zone_asoc, tasoc);
#else
	zfreei(sctppcbinfo.ipi_zone_asoc, tasoc);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	pool_put(&sctppcbinfo.ipi_zone_asoc, tasoc);
#endif
	sctppcbinfo.ipi_count_asoc--;
#ifdef SCTP_TCP_MODEL_SUPPORT
	if ((ep->sctp_socket->so_snd.sb_cc) ||
	    (ep->sctp_socket->so_snd.sb_mbcnt)) {
		/* This will happen when a abort is done */
		ep->sctp_socket->so_snd.sb_cc = 0;
		ep->sctp_socket->so_snd.sb_mbcnt = 0;
	}
	if (ep->sctp_flags & SCTP_PCB_FLAGS_TCPTYPE) {
		if ((ep->sctp_flags & SCTP_PCB_FLAGS_IN_TCPPOOL) == 0) {
			if (ep->sctp_flags & SCTP_PCB_FLAGS_CONNECTED) {
				/*
				 * For the base fd, that is NOT in TCP pool we
				 * turn off the connected flag. This allows
				 * non-listening endpoints to connect/shutdown/
				 * connect.
				 */
				ep->sctp_flags &= ~SCTP_PCB_FLAGS_CONNECTED;
/*				ep->sctp_socket->so_state &= (~SS_ISCONNECTED);*/
				soisdisconnected(ep->sctp_socket);
			}
			/*
			 * For those that are in the TCP pool we just leave
			 * so it cannot be used. When they close the fd we
			 * will free it all.
			 */
		}
	}
#endif /* SCTP_TCP_MODEL_SUPPORT */
	splx(s);
}


/*
 * determine if a destination is "reachable" based upon the addresses
 * bound to the current endpoint (e.g. only v4 or v6 currently bound)
 */
/*
 * FIX: if we allow assoc-level bindx(), then this needs to be fixed
 * to use assoc level v4/v6 flags, as the assoc *may* not have the
 * same address types bound as its endpoint
 */
int
sctp_destination_is_reachable(struct sctp_tcb *tcb, struct sockaddr *destaddr)
{
	struct sctp_inpcb *ep;

	ep = tcb->sctp_ep;
	if (ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL)
		/* if bound all, destination is not restricted */
		return (1);

	/* NOTE: all "scope" checks are done when local addresses are added */
	if (destaddr->sa_family == AF_INET6) {
#ifndef __FreeBSD__
		return (ep->inp_vflag & INP_IPV6);
#else
		return (ep->ip_inp.inp.inp_vflag & INP_IPV6);
#endif
	} else if (destaddr->sa_family == AF_INET) {
#ifndef __FreeBSD__
		return (ep->inp_vflag & INP_IPV4);
#else
		return (ep->ip_inp.inp.inp_vflag & INP_IPV4);
#endif
	} else {
		/* invalid family, so it's unreachable */
		return (0);
	}
}

/*
 * update the inp_vflags on an endpoint
 */
static void
sctp_update_ep_vflag(struct sctp_inpcb *ep) {
	struct sctp_laddr *laddr;

	/* first clear the flag */
#ifndef __FreeBSD__
	ep->inp_vflag = 0;
#else
	ep->ip_inp.inp.inp_vflag = 0;
#endif
	/* set the flag based on addresses on the ep list */
	LIST_FOREACH(laddr, &ep->sctp_addr_list, sctp_nxt_addr) {
		if (laddr->ifa == NULL) {
#ifdef SCTP_DEBUG

			if (sctp_debug_on & SCTP_DEBUG_PCB1) {
				printf("An ounce of prevention is worth a pound of cure\n");
			}
#endif /* SCTP_DEBUG */
			continue;
		}
		if (laddr->ifa->ifa_addr) {
			continue;
		}
		if (laddr->ifa->ifa_addr->sa_family == AF_INET6) {
#ifndef __FreeBSD__
			ep->inp_vflag |= INP_IPV6;
#else
			ep->ip_inp.inp.inp_vflag |= INP_IPV6;
#endif
		} else if (laddr->ifa->ifa_addr->sa_family == AF_INET) {
#ifndef __FreeBSD__
			ep->inp_vflag |= INP_IPV4;
#else
			ep->ip_inp.inp.inp_vflag |= INP_IPV4;
#endif
		}
	}
}

/*
 * Add the address to the endpoint local address list
 * There is nothing to be done if we are bound to all addresses
 */
int
sctp_add_local_addr_ep(struct sctp_inpcb *ep, struct ifaddr *ifa)
{
	struct sctp_laddr *laddr;
	int fnd, error;
	fnd = 0;

	if (ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* You are already bound to all. You have it already */
		return (0);
	}
	if (ifa->ifa_addr->sa_family == AF_INET6) {
		struct in6_ifaddr *ifa6;
		ifa6 = (struct in6_ifaddr *)ifa;
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
				       IN6_IFF_DEPRECATED |
				       IN6_IFF_ANYCAST |
				       IN6_IFF_NOTREADY))
			/* Can't bind a non-existent addr. */
			return (-1);
	}
	/* first, is it already present? */
	LIST_FOREACH(laddr, &ep->sctp_addr_list, sctp_nxt_addr) {
		if (laddr->ifa == ifa) {
			fnd = 1;
			break;
		}
	}

	if (((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) && (fnd == 0)) {
		/* Not bound to all */
		error = sctp_insert_laddr(&ep->sctp_addr_list, ifa);
		if (error != 0)
			return (error);
		ep->laddr_count++;
		/* update inp_vflag flags */
		if (ifa->ifa_addr->sa_family == AF_INET6) {
#ifndef __FreeBSD__
			ep->inp_vflag |= INP_IPV6;
#else
			ep->ip_inp.inp.inp_vflag |= INP_IPV6;
#endif
		} else if (ifa->ifa_addr->sa_family == AF_INET) {
#ifndef __FreeBSD__
			ep->inp_vflag |= INP_IPV4;
#else
			ep->ip_inp.inp.inp_vflag |= INP_IPV4;
#endif
		}
	}
	return (0);
}


/*
 * select a new (hopefully reachable) destination net
 * (should only be used when we deleted an ep addr that is the
 * only usable source address to reach the destination net)
 */
static void
sctp_select_primary_destination(struct sctp_tcb *tcb)
{
	struct sctp_nets *net;

	TAILQ_FOREACH(net, &tcb->asoc.nets, sctp_next) {
		/* for now, we'll just pick the first reachable one we find */
		if (net->dest_state & SCTP_ADDR_UNCONFIRMED)
			continue;
		if (sctp_destination_is_reachable(tcb, (struct sockaddr *)&net->ra._l_addr)) {
			/* found a reachable destination */
			tcb->asoc.primary_destination = net;
		}
	}
	/* I can't there from here! ...we're gonna die shortly... */
}


/*
 * Delete the address from the endpoint local address list
 * There is nothing to be done if we are bound to all addresses
 */
int
sctp_del_local_addr_ep(struct sctp_inpcb *ep, struct ifaddr *ifa)
{
	struct sctp_laddr *laddr;
	int fnd;
	fnd = 0;
	if (ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* You are already bound to all. You have it already */
		return (EINVAL);
	}

	LIST_FOREACH(laddr, &ep->sctp_addr_list, sctp_nxt_addr) {
		if (laddr->ifa == ifa) {
			fnd = 1;
			break;
		}
	}
	if (fnd && (ep->laddr_count < 2)) {
		/* can't delete unless there are at LEAST 2 addresses */
		return (-1);
	}
	if (((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) && (fnd)) {
		/*
		 * clean up any use of this address
		 * go through our associations and clear any
		 *  last_used_address that match this one
		 * for each assoc, see if a new primary_destination is needed
		 */
		struct sctp_tcb *tcb;

		/* clean up "next_addr_touse" */
		if (ep->next_addr_touse == laddr)
			/* delete this address */
			ep->next_addr_touse = NULL;

		/* clean up "last_used_address" */
		LIST_FOREACH(tcb, &ep->sctp_asoc_list, sctp_tcblist) {
			if (tcb->asoc.last_used_address == laddr)
				/* delete this address */
				tcb->asoc.last_used_address = NULL;
		} /* for each tcb */

		/* remove it from the ep list */
		sctp_remove_laddr(laddr);
		ep->laddr_count--;
		/* update inp_vflag flags */
		sctp_update_ep_vflag(ep);
		/* select a new primary destination if needed */
		LIST_FOREACH(tcb, &ep->sctp_asoc_list, sctp_tcblist) {
			if (sctp_destination_is_reachable(tcb, (struct sockaddr *)&tcb->asoc.primary_destination->ra._l_addr) == 0) {
				sctp_select_primary_destination(tcb);
			}
		} /* for each tcb */
	}
	return (0);
}

/*
 * Add the addr to the TCB local address list
 * For the BOUNDALL or dynamic case, this is a "pending" address list
 * (eg. addresses waiting for an ASCONF-ACK response)
 * For the subset binding, static case, this is a "valid" address list
 */
int
sctp_add_local_addr_assoc(struct sctp_tcb *tcb, struct ifaddr *ifa)
{
	struct sctp_inpcb *ep;
	struct sctp_laddr *laddr;
	int error;

	ep = tcb->sctp_ep;
	if (ifa->ifa_addr->sa_family == AF_INET6) {
		struct in6_ifaddr *ifa6;
		ifa6 = (struct in6_ifaddr *)ifa;
		if (ifa6->ia6_flags & (IN6_IFF_DETACHED |
/*				       IN6_IFF_DEPRECATED | */
				       IN6_IFF_ANYCAST |
				       IN6_IFF_NOTREADY))
			/* Can't bind a non-existent addr. */
			return (-1);
	}
	/* does the address already exist? */
	LIST_FOREACH(laddr, &tcb->asoc.sctp_local_addr_list, sctp_nxt_addr) {
		if (laddr->ifa == ifa) {
			return (-1);
		}
	}

	/* add to the list */
	error = sctp_insert_laddr(&tcb->asoc.sctp_local_addr_list, ifa);
	if (error != 0) 
		return (error);
	return (0);
}

/*
 * insert an laddr entry with the given ifa for the desired list
 */
int
sctp_insert_laddr(struct sctpladdr *list, struct ifaddr *ifa) {
	struct sctp_laddr *laddr;
	int s;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	laddr = (struct sctp_laddr *)uma_zalloc(sctppcbinfo.ipi_zone_laddr, M_NOWAIT);
#else
	laddr = (struct sctp_laddr *)zalloci(sctppcbinfo.ipi_zone_laddr);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	laddr = (struct sctp_laddr *)pool_get(&sctppcbinfo.ipi_zone_laddr,
					      PR_NOWAIT);
#endif

	if (laddr == NULL) {
		/* out of memory? */
		splx(s);
		return (EINVAL);
	}
	sctppcbinfo.ipi_count_laddr++;
	sctppcbinfo.ipi_gencnt_laddr++;
	bzero(laddr, sizeof(*laddr));
	laddr->ifa = ifa;
	/* insert it */
	LIST_INSERT_HEAD(list, laddr, sctp_nxt_addr);

	splx(s);
	return (0);
}

/*
 * Remove an laddr entry from the local address list (on an assoc)
 */
void
sctp_remove_laddr(struct sctp_laddr *laddr)
{
	int s;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* remove from the list */
	LIST_REMOVE(laddr, sctp_nxt_addr);
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	uma_zfree(sctppcbinfo.ipi_zone_laddr, laddr);
#else
	zfreei(sctppcbinfo.ipi_zone_laddr, laddr);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	pool_put(&sctppcbinfo.ipi_zone_laddr, laddr);
#endif
	sctppcbinfo.ipi_count_laddr--;
	sctppcbinfo.ipi_gencnt_laddr++;

	splx(s);
}

/*
 * Remove an address from the TCB local address list
 */
int
sctp_del_local_addr_assoc(struct sctp_tcb *tcb, struct ifaddr *ifa)
{
	struct sctp_inpcb *ep;
	struct sctp_laddr *laddr;

	ep = tcb->sctp_ep;
	/* if subset bound and don't allow ASCONF's, can't delete last */
	if (((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) &&
	    ((ep->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) == 0)) {
		if (tcb->asoc.numnets < 2) {
			/* can't delete last address */
			return (-1);
		}
	}

	LIST_FOREACH(laddr, &tcb->asoc.sctp_local_addr_list, sctp_nxt_addr) {
		/* remove the address if it exists */
		if (laddr->ifa == NULL)
			continue;
		if (laddr->ifa == ifa) {
			sctp_remove_laddr(laddr);
			return (0);
		}
	}

	/* address not found! */
	return (-1);
}

/*
 * Remove an address from the TCB local address list
 * lookup using a sockaddr addr
 */
int
sctp_del_local_addr_assoc_sa(struct sctp_tcb *tcb, struct sockaddr *sa)
{
	struct sctp_inpcb *ep;
	struct sctp_laddr *laddr;
	struct sockaddr *l_sa;

	ep = tcb->sctp_ep;
	/* if subset bound and don't allow ASCONF's, can't delete last */
	if (((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0) &&
	    ((ep->sctp_flags & SCTP_PCB_FLAGS_DO_ASCONF) == 0)) {
		if (tcb->asoc.numnets < 2) {
			/* can't delete last address */
			return (-1);
		}
	}

	LIST_FOREACH(laddr, &tcb->asoc.sctp_local_addr_list, sctp_nxt_addr) {
		/* make sure the address exists */
		if (laddr->ifa == NULL)
			continue;
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		l_sa = laddr->ifa->ifa_addr;
		if (l_sa->sa_family == AF_INET6) {
			/* IPv6 address */
			struct sockaddr_in6 *sin1, *sin2;
			sin1 = (struct sockaddr_in6 *)l_sa;
			sin2 = (struct sockaddr_in6 *)sa;
			if (memcmp(&sin1->sin6_addr, &sin2->sin6_addr,
				   sizeof(struct in6_addr)) == 0) {
				/* matched */
				sctp_remove_laddr(laddr);
				return (0);
			}
		} else if (l_sa->sa_family == AF_INET) {
			/* IPv4 address */
			struct sockaddr_in *sin1, *sin2;
			sin1 = (struct sockaddr_in *)l_sa;
			sin2 = (struct sockaddr_in *)sa;
			if (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr) {
				/* matched */
				sctp_remove_laddr(laddr);
				return (0);
			}
		} else {
			/* invalid family */
			return (-1);
		}
	} /* end foreach */
	/* address not found! */
	return (-1);
}

static char sctp_pcb_initialized = 0;

#if defined(__FreeBSD__)

static int sctp_max_number_of_assoc = SCTP_MAX_NUM_OF_ASOC;
/* disable sysctl for now...
SYSCTL_INT(_net_inet_sctp, SCTPCTL_ASOC_CNT, sctp_max_number_of_assoc,
	   CTLFLAG_RW, &sctp_max_number_of_assoc, 0,
	   "Size of number of associations for zone init");
*/

static int sctp_scale_up_for_address = SCTP_SCALE_FOR_ADDR;
/* disable sysctl for now...
SYSCTL_INT(_net_inet_sctp, SCTPCTL_SCALE_VAL, sctp_scale_up_for_address,
	   CTLFLAG_RW, &sctp_scale_up_for_address, 0,
	   "Scale up value (this * SCTPCTL_ASOC_CNT) yields address zinit");
*/
#endif /* FreeBSD */

int sctp_auto_asconf = SCTP_DEFAULT_AUTO_ASCONF;
/* sysctl to enable/disable SCTP_PCB_FLAGS_AUTO_ASCONF for new EP's */
#if defined(__FreeBSD__)
SYSCTL_INT(_net_inet_sctp, SCTPCTL_AUTOASCONF, sctp_auto_asconf,
	   CTLFLAG_RW, &sctp_auto_asconf, 0,
	   "auto ASCONF flag enable(1)/disable(0)");
#endif /* FreeBSD */

#ifndef SCTP_TCBHASHSIZE
#define SCTP_TCBHASHSIZE 1024
#endif

#ifndef SCTP_CHUNKQUEUE_SCALE
#define SCTP_CHUNKQUEUE_SCALE 10
#endif

void
sctp_pcb_init()
{
	/*
	 * SCTP initialization for the PCB structures
	 * should be called by the sctp_init() funciton.
	 */
	int i;
	int hashtblsize = SCTP_TCBHASHSIZE;

#if defined(__FreeBSD__)
	int sctp_chunkscale = SCTP_CHUNKQUEUE_SCALE;
#endif

	if (sctp_pcb_initialized != 0) {
		/* error I was called twice */
		return;
	}
	sctp_pcb_initialized = 1;

	/* Init all peg counts */
	for (i = 0; i < SCTP_NUMBER_OF_PEGS; i++) {
		sctp_pegs[i] = 0;
	}

	/* init the empty list of (All) Endpoints */
	LIST_INIT(&sctppcbinfo.listhead);

	/* init the hash table of endpoints */
#if defined(__FreeBSD__)
#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version >= 440000
	TUNABLE_INT_FETCH("net.inet.sctp.tcbhashsize", &hashtblsize);
	TUNABLE_INT_FETCH("net.inet.sctp.pcbhashsize", &sctp_pcbtblsize);
	TUNABLE_INT_FETCH("net.inet.sctp.chunkscale", &sctp_chunkscale);
#else
	TUNABLE_INT_FETCH("net.inet.sctp.tcbhashsize", SCTP_TCBHASHSIZE,
			  hashtblsize);
	TUNABLE_INT_FETCH("net.inet.sctp.pcbhashsize", SCTP_PCBHASHSIZE,
			  sctp_pcbtblsize);
	TUNABLE_INT_FETCH("net.inet.sctp.chunkscale", SCTP_CHUNKQUEUE_SCALE,
			  sctp_chunkscale);
#endif
#endif

	sctppcbinfo.sctp_asochash = hashinit((hashtblsize * 31),
#ifdef __NetBSD__
					     HASH_LIST,
#endif
					     M_PCB,
#ifndef __FreeBSD__
					     M_WAITOK,
#endif
					     &sctppcbinfo.hashasocmark);


	sctppcbinfo.sctp_ephash = hashinit(hashtblsize,
#ifdef __NetBSD__
	    HASH_LIST,
#endif
	    M_PCB,
#ifndef __FreeBSD__
	    M_WAITOK,
#endif
	    &sctppcbinfo.hashmark);

#ifdef SCTP_TCP_MODEL_SUPPORT
	sctppcbinfo.sctp_tcpephash = hashinit(hashtblsize,
#ifdef __NetBSD__
	    HASH_LIST,
#endif
	    M_PCB,
#ifndef __FreeBSD__
	    M_WAITOK,
#endif
	    &sctppcbinfo.hashtcpmark);
#endif /* SCTP_TCP_MODEL_SUPPORT */

	sctppcbinfo.hashtblsize = hashtblsize;

	/* init the zones */
#if defined(__OpenBSD__)
	pool_init(&sctppcbinfo.ipi_zone_ep, sizeof(struct sctp_inpcb),
		  0, 0, 0, "sctp_ep", NULL);

	pool_init(&sctppcbinfo.ipi_zone_asoc, sizeof(struct sctp_tcb),
		  0, 0, 0, "sctp_asoc", NULL);

	pool_init(&sctppcbinfo.ipi_zone_laddr, sizeof(struct sctp_laddr),
		  0, 0, 0, "sctp_laddr", NULL);

	pool_init(&sctppcbinfo.ipi_zone_raddr, sizeof(struct sctp_nets),
		  0, 0, 0, "sctp_raddr", NULL);

	pool_init(&sctppcbinfo.ipi_zone_chunk, sizeof(struct sctp_tmit_chunk),
		  0, 0, 0,"sctp_chunk", NULL);

	pool_init(&sctppcbinfo.ipi_zone_sockq, sizeof(struct sctp_socket_q_list),
		  0, 0, 0,"sctp_sockq", NULL);

#endif
#if defined(__NetBSD__)
	pool_init(&sctppcbinfo.ipi_zone_ep, sizeof(struct sctp_inpcb),
		  0, 0, 0, "sctp_ep", NULL);

	pool_init(&sctppcbinfo.ipi_zone_asoc, sizeof(struct sctp_tcb),
		  0, 0, 0, "sctp_asoc", NULL);

	pool_init(&sctppcbinfo.ipi_zone_laddr, sizeof(struct sctp_laddr),
		  0, 0, 0, "sctp_laddr", NULL);

	pool_init(&sctppcbinfo.ipi_zone_raddr, sizeof(struct sctp_nets),
		  0, 0, 0, "sctp_raddr", NULL); 

	pool_init(&sctppcbinfo.ipi_zone_chunk, sizeof(struct sctp_tmit_chunk),
		  0, 0, 0,"sctp_chunk", NULL);

	pool_init(&sctppcbinfo.ipi_zone_sockq, sizeof(struct sctp_socket_q_list),
		  0, 0, 0,"sctp_sockq", NULL);


#endif
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
#define UMA_ZFLAG_FULL         0x0020
	sctppcbinfo.ipi_zone_ep = uma_zcreate("sctp_ep",
					      sizeof(struct sctp_inpcb),
					      NULL, NULL, NULL, NULL,
					      UMA_ALIGN_PTR, UMA_ZFLAG_FULL);
	uma_zone_set_max(sctppcbinfo.ipi_zone_ep, maxsockets);

	sctppcbinfo.ipi_zone_asoc = uma_zcreate("sctp_asoc",
						sizeof(struct sctp_tcb),
						NULL, NULL, NULL, NULL,
						UMA_ALIGN_PTR, UMA_ZFLAG_FULL);

	uma_zone_set_max(sctppcbinfo.ipi_zone_asoc, sctp_max_number_of_assoc);
	sctppcbinfo.ipi_zone_laddr = uma_zcreate("sctp_laddr",
						 sizeof(struct sctp_laddr),
						 NULL, NULL, NULL, NULL,
						 UMA_ALIGN_PTR, UMA_ZFLAG_FULL);
	uma_zone_set_max(sctppcbinfo.ipi_zone_laddr,
			 (sctp_max_number_of_assoc *
			 sctp_scale_up_for_address));

	sctppcbinfo.ipi_zone_raddr = uma_zcreate("sctp_raddr",
						 sizeof(struct sctp_nets),
						 NULL, NULL, NULL, NULL,
						 UMA_ALIGN_PTR, UMA_ZFLAG_FULL);
	uma_zone_set_max(sctppcbinfo.ipi_zone_raddr,
			 (sctp_max_number_of_assoc *
			 sctp_scale_up_for_address));

	sctppcbinfo.ipi_zone_chunk = uma_zcreate("sctp_chunk",
						 sizeof(struct sctp_tmit_chunk),
						 NULL, NULL, NULL, NULL,
						 UMA_ALIGN_PTR, UMA_ZFLAG_FULL);
	uma_zone_set_max(sctppcbinfo.ipi_zone_chunk,
			 (sctp_max_number_of_assoc *
			 sctp_scale_up_for_address *
			 sctp_chunkscale));

	sctppcbinfo.ipi_zone_sockq = uma_zcreate("sctp_sockq",
						 sizeof(struct sctp_socket_q_list),
						 NULL, NULL, NULL, NULL,
						 UMA_ALIGN_PTR, UMA_ZFLAG_FULL);
	uma_zone_set_max(sctppcbinfo.ipi_zone_sockq,
			 (sctp_max_number_of_assoc *
			 sctp_scale_up_for_address *
			 sctp_chunkscale));
#else
	sctppcbinfo.ipi_zone_ep = zinit("sctp_ep", sizeof(struct sctp_inpcb),
	    maxsockets, ZONE_INTERRUPT, 0);

	sctppcbinfo.ipi_zone_asoc = zinit("sctp_asoc", sizeof(struct sctp_tcb),
	    sctp_max_number_of_assoc, ZONE_INTERRUPT, 0);
	sctppcbinfo.ipi_zone_laddr = zinit("sctp_laddr",
	    sizeof(struct sctp_laddr),
	    (sctp_max_number_of_assoc * sctp_scale_up_for_address),
	    ZONE_INTERRUPT, 0);

	sctppcbinfo.ipi_zone_raddr = zinit("sctp_raddr",
	    sizeof(struct sctp_nets),
	    (sctp_max_number_of_assoc * sctp_scale_up_for_address),
	    ZONE_INTERRUPT, 0);

	sctppcbinfo.ipi_zone_chunk = zinit("sctp_chunk",
	    sizeof(struct sctp_tmit_chunk),
	    (sctp_max_number_of_assoc * sctp_scale_up_for_address * sctp_chunkscale),
	    ZONE_INTERRUPT, 0);

	sctppcbinfo.ipi_zone_sockq = zinit("sctp_sockq",
	    sizeof(struct sctp_socket_q_list),
	    (sctp_max_number_of_assoc * sctp_scale_up_for_address * sctp_chunkscale),
	    ZONE_INTERRUPT, 0);
#endif


#endif
	/*
	 * I probably should check for NULL return but if it does fail we
	 * are doomed to panic... add later maybe.
	 */

	/* not sure if we need all the counts */
	sctppcbinfo.ipi_count_ep = 0;
	sctppcbinfo.ipi_gencnt_ep = 0;
	/* assoc/tcb zone info */
	sctppcbinfo.ipi_count_asoc = 0;
	sctppcbinfo.ipi_gencnt_asoc = 0;
	/* local addrlist zone info */
	sctppcbinfo.ipi_count_laddr = 0;
	sctppcbinfo.ipi_gencnt_laddr = 0;
	/* remote addrlist zone info */
	sctppcbinfo.ipi_count_raddr = 0;
	sctppcbinfo.ipi_gencnt_raddr = 0;
	/* chunk info */
	sctppcbinfo.ipi_count_chunk = 0;
	sctppcbinfo.ipi_gencnt_chunk = 0;

	/* socket queue zone info */
	sctppcbinfo.ipi_count_sockq = 0;
	sctppcbinfo.ipi_gencnt_sockq = 0;


	/* mbuf tracker */
	sctppcbinfo.mbuf_track = 0;
	/* port stuff */
#if defined(__FreeBSD__) || defined(__OpenBSD__)
	sctppcbinfo.lastlow = ipport_firstauto;
#else
	sctppcbinfo.lastlow = anonportmin;
#endif
#ifdef SCTP_VTAG_TIMEWAIT_PER_STACK
	/* Init the TIMEWAIT list */
	for (i = 0; i < SCTP_STACK_VTAG_HASH_SIZE; i++) {
		LIST_INIT(&sctppcbinfo.vtag_timewait[i]);
	}
#endif

#ifdef _SCTP_NEEDS_CALLOUT_
	TAILQ_INIT(&sctppcbinfo.callqueue);
#endif

}

int
sctp_load_addresses_from_init(struct sctp_tcb *stcb,
			      struct mbuf *m,
			      int iphlen,
			      int param_offset,
			      struct sockaddr *altsa,
			      int limit)
{
	/*
	 * grub through the INIT pulling addresses and
	 * loading them to the nets structure in the asoc.
	 * The from address in the mbuf should also be loaded
	 * (if it is not already). This routine can be called
	 * with either INIT or INIT-ACK's as long as the
	 * m points to the IP packet and the offset points
	 * to the beginning of the parameters.
	 */
	struct sctp_inpcb *ep;
	struct sctp_nets *net, *net_tmp;
	struct ip *iph;
	struct sctp_ipv6addr_param s6_store, *p6;
	struct sctp_paramhdr *phdr;
	struct sctphdr *sctphdr;
	struct sctp_tcb *t_tcb;
	int at;
	u_int16_t ptype, plen;
	struct sockaddr_storage src_store;
	struct sockaddr *sa = (struct sockaddr *)&src_store;
	struct sockaddr_storage dest_store;
	struct sockaddr *localep_sa = (struct sockaddr *)&dest_store;
	struct sockaddr_in sin, *sin_2;
	struct sockaddr_in6 sin6, *sin6_2;


	/* First get the destination address setup too. */
	memset(&sin6, 0, sizeof(sin6));
	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_port = stcb->rport;

	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_port = stcb->rport;
	iph = mtod(m, struct ip *);
	sctphdr = (struct sctphdr *)((caddr_t)iph + iphlen);
	if (iph->ip_v == IPVERSION) {
		/* its IPv4 */
		sin_2 = (struct sockaddr_in *)(localep_sa);
		memset(sin_2, 0, sizeof(sin));
		sin_2->sin_family = AF_INET;
		sin_2->sin_len = sizeof(sin);
		sin_2->sin_port = sctphdr->dest_port;
		sin_2->sin_addr.s_addr = iph->ip_dst.s_addr ;
		sin.sin_addr = iph->ip_src;
		sa = (struct sockaddr *)&sin;
	} else {
		/* its IPv6 */
		struct ip6_hdr *ip6;

		ip6 = mtod(m, struct ip6_hdr *);
		sin6_2 = (struct sockaddr_in6 *)(localep_sa);
		memset(sin6_2, 0, sizeof(sin6));
		sin6_2->sin6_family = AF_INET6;
		sin6_2->sin6_len = sizeof(struct sockaddr_in6);
		sin6_2->sin6_port = sctphdr->dest_port;
		sin6.sin6_addr = ip6->ip6_src;
		sa = (struct sockaddr *)&sin6;
	}
	if (altsa) {
		/*
		 * For cookies we use the src address NOT from the packet
		 * but from the original INIT
		 */
		sa = altsa;
	}
	at = param_offset;
	/* Turn off ECN until we get through all params */
	stcb->asoc.ecn_allowed = 0;

	TAILQ_FOREACH(net, &stcb->asoc.nets, sctp_next) {
		/* mark all addresses that we have currently on the list */
		net->dest_state |= SCTP_ADDR_NOT_IN_ASSOC;
	}
	/* does the source address already exist? if so skip it */
	ep = stcb->sctp_ep;
	t_tcb = sctp_findassociation_ep_addr(&ep, sa, &net_tmp, localep_sa);
	if ((t_tcb == NULL) && ((ep == stcb->sctp_ep) || (ep == NULL))) {
		/* we must add the source address */
		/* no scope set here since we have a tcb already. */
		if ((sa->sa_family == AF_INET) &&
		    (stcb->asoc.ipv4_addr_legal)) {
			if (sctp_add_remote_addr(stcb, sa, 0, 2)) {
				return (-1);
			}	
		} else if ((sa->sa_family == AF_INET6) &&
			   (stcb->asoc.ipv6_addr_legal)) {
			if (sctp_add_remote_addr(stcb, sa, 0, 3)) {
				return (-1);
			}
		}
	} else {
		if ((net_tmp != NULL) && (t_tcb == stcb)) {
			net_tmp->dest_state &= ~SCTP_ADDR_NOT_IN_ASSOC;
		} else if (t_tcb != stcb) {
			/* It belongs to another association? */
			return (-1);
		}
	}
	/* now we must go through each of the params. */
	phdr = sctp_get_next_param(m, at, (struct sctp_paramhdr *)&s6_store,
				   sizeof(struct sctp_paramhdr));
	while (phdr) {
		ptype = ntohs(phdr->param_type);
		plen = ntohs(phdr->param_length);
		if (plen+at > limit) {
			break;
		}
		if (plen == 0) {
			break;
		}
		if ((ptype == SCTP_IPV4_ADDRESS) &&
		    (stcb->asoc.ipv4_addr_legal)) {
			struct sctp_ipv4addr_param *p4;
			/* ok get the v4 address and check/add */
			phdr = sctp_get_next_param(m, at, (struct sctp_paramhdr *)&s6_store,
						   sizeof(struct sctp_ipv4addr_param));
			p4 = (struct sctp_ipv4addr_param *)phdr;
			if (plen != sizeof(struct sctp_ipv4addr_param) ||
			    (phdr == NULL)) {
				return (-1);
			}
			sin.sin_addr.s_addr = p4->addr;
			sa = (struct sockaddr *)&sin;
			ep = stcb->sctp_ep;
			t_tcb = sctp_findassociation_ep_addr(&ep, sa, &net,
							     localep_sa);

			if ((t_tcb == NULL) && ((ep == stcb->sctp_ep) ||
						(ep == NULL))) {
				/* we must add the source address */
				/* no scope set since we have a tcb already */
				if (sctp_add_remote_addr(stcb, sa, 0, 4)) {
					return (-1);
				}
			} else if (t_tcb == stcb) {
				if (net != NULL) {
					/* clear flag */
					net->dest_state &= ~SCTP_ADDR_NOT_IN_ASSOC;
				}
			} else {
				/* strange, address is in another assoc? */
				return (-1);
			}
		} else if ((ptype == SCTP_IPV6_ADDRESS) &&
			   (stcb->asoc.ipv6_addr_legal)) {
			/* ok get the v6 address and check/add */
			phdr = sctp_get_next_param(m, at, (struct sctp_paramhdr *)&s6_store,
						   sizeof(s6_store));
			if (plen != sizeof(struct sctp_ipv6addr_param) ||
			    (phdr == NULL)) {
				return (-1);
			}
			p6 = (struct sctp_ipv6addr_param *)phdr;
			memcpy((caddr_t)&sin6.sin6_addr, p6->addr,
			       sizeof(p6->addr));
			sa = (struct sockaddr *)&sin6;
			ep = stcb->sctp_ep;
			t_tcb = sctp_findassociation_ep_addr(&ep, sa, &net,
							     localep_sa);
			if ((t_tcb == NULL) && ((ep == stcb->sctp_ep) ||
						(ep == NULL))) {
				/* we must add the address, no scope set */
				if (sctp_add_remote_addr(stcb, sa, 0, 5)) {
					return (-1);
				}
			} else if (t_tcb == stcb) {
				if (net != NULL) {
					/* clear flag */
					net->dest_state &= ~SCTP_ADDR_NOT_IN_ASSOC;
				}
			} else {
				/* strange, address is in another assoc? */
				return (-1);
			}
		} else if (ptype == SCTP_ECN_CAPABLE) {
			stcb->asoc.ecn_allowed = 1;
		} else if (ptype == SCTP_ULP_ADAPTION) {
			struct sctp_adaption_layer_indication ai, *aip;

			aip = (struct sctp_adaption_layer_indication *)
				sctp_get_next_param(m, at,
						    (struct sctp_paramhdr *)&ai,
						    sizeof(ai));
			sctp_ulp_notify(SCTP_NOTIFY_ADAPTION_INDICATION,
					stcb,
					ntohl(aip->indication),
					(void *)NULL);
		} else if (ptype == SCTP_SET_PRIM_ADDR) {
			struct sctp_asconf_addr_param lstore, *fee;
			struct sctp_asconf_addrv4_param *fii;
			stcb->asoc.peer_supports_asconf = 1;
			stcb->asoc.peer_supports_asconf_setprim = 1;
			fee  = (struct sctp_asconf_addr_param *)sctp_get_next_param(m, 
										    at,
										    (struct sctp_paramhdr *)&lstore,
										    plen);
			if (fee) {
				int lptype;
				struct sockaddr_in lsin;
				struct sockaddr_in6 lsin6;
				struct sockaddr *lsa = NULL;

				lptype = ntohs(fee->addrp.ph.param_type);
				if (lptype == SCTP_IPV4_ADDRESS) {
					if (plen != sizeof(struct sctp_asconf_addrv4_param)) {
						printf("Sizeof setprim in init/init ack not %d but %d - ignored\n",
						       (int)sizeof(struct sctp_asconf_addrv4_param),
						       plen);
					} else {
						memset(&lsin,0,sizeof(lsin));
						fii = (struct sctp_asconf_addrv4_param *)fee;
						lsa = (struct sockaddr *)&lsin;
						lsin.sin_addr.s_addr = fii->addrp.addr;
						lsin.sin_len = sizeof(lsin);
						lsin.sin_family = AF_INET;
						lsin.sin_port = stcb->rport;
					}
				} else if (lptype == SCTP_IPV6_ADDRESS) {
					if (plen != sizeof(struct sctp_asconf_addr_param)) {
						printf("Sizeof setprim (v6) in init/init ack not %d but %d - ignored\n",
						       (int)sizeof(struct sctp_asconf_addr_param),
						       plen);
					} else {
						memset(&lsin6,0,sizeof(lsin6));
						lsa = (struct sockaddr *)&lsin6;
						memcpy(lsin6.sin6_addr.s6_addr,fee->addrp.addr,sizeof(fee->addrp.addr));
						lsin.sin_len = sizeof(lsin6);
						lsin.sin_family = AF_INET6;
						lsin.sin_port = stcb->rport;
					}
				}
				if (lsa) {
					sctp_set_primary_addr(stcb, lsa);
				}
			}
		} else if (ptype == SCTP_PRSCTP_SUPPORTED) {
			/* Peer supports pr-sctp */
			stcb->asoc.peer_supports_prsctp = 1;
		}
		at += SCTP_SIZE32(plen);
		if (at >= limit) {
			break;
		}
		phdr = sctp_get_next_param(m, at,
		    (struct sctp_paramhdr *)&s6_store,
		    sizeof(struct sctp_paramhdr));
	}
	/* Now check to see if we need to purge any addresses */
	for (net = TAILQ_FIRST(&stcb->asoc.nets); net != NULL; net = net_tmp) {
		net_tmp = TAILQ_NEXT(net, sctp_next);
		if ((net->dest_state & SCTP_ADDR_NOT_IN_ASSOC) ==
		    SCTP_ADDR_NOT_IN_ASSOC) {
			/* This address has been removed from the asoc */
			/* remove and free it */
			stcb->asoc.numnets--;
			TAILQ_REMOVE(&stcb->asoc.nets, net, sctp_next);
			sctp_free_remote_addr(net);
			if (net == stcb->asoc.primary_destination) {
				stcb->asoc.primary_destination = TAILQ_FIRST(&stcb->asoc.nets);
			}
		}
	}
	return (0);
}

int
sctp_set_primary_addr(struct sctp_tcb *stcb, struct sockaddr *sa)
{
	struct sctp_nets *netp;

	/* make sure the requested primary address exists in the assoc */
	netp = sctp_findnet(stcb, sa);
	if (netp == NULL) {
		/* didn't find the requested primary address! */
		return (-1);
	} else {
		/* set the primary address */
		stcb->asoc.primary_destination = netp;
		return (0);
	}
}


int
sctp_is_vtag_good(struct sctp_inpcb *m, u_int32_t tag, struct timeval *now)
{
	/*
	 * This function serves two purposes. It will see if a TAG can be
	 * re-used and return 1 for yes it is ok and 0 for don't use that
	 * tag.
	 * A secondary function it will do is purge out old tags that can
	 * be removed.
	 */
	struct sctpvtaghead *chain;
	struct sctp_tagblock *twait_block;

	int i;
#ifdef SCTP_VTAG_TIMEWAIT_PER_STACK
	chain = &sctppcbinfo.vtag_timewait[(tag % SCTP_STACK_VTAG_HASH_SIZE)];
#else
	chain = &m->vtag_timewait[(tag % SCTP_STACK_VTAG_HASH_SIZE)];
#endif
	if (!LIST_EMPTY(chain)) {
		/*
		 * Block(s) are present, lets see if we have this tag in
		 * the list
		 */

		/*** FIX ME? if a tag is in use/ it would still be good?
		 * This means that even if we setup the compile options to
		 * have the vtag time-wait across the system it is still possible
		 * that two assoc's will have the same tag. To fix this we would
		 * need to add code to this module to assure that a vtag was
		 * not in use. Presumably by hashing the vtag cache in a new
		 * way to assure it is not in use and then doing the stuff below
		 * to verify its not in timed wait...
		 */

		LIST_FOREACH(twait_block, chain, sctp_nxt_tagblock) {
			for (i = 0; i < SCTP_NUMBER_IN_VTAG_BLOCK; i++) {
				if (twait_block->vtag_block[i].v_tag == 0) {
					/* not used */
					continue;
				} else if (twait_block->vtag_block[i].tv_sec_at_expire >
				    now->tv_sec) {
					/* Audit expires this guy */
					twait_block->vtag_block[i].tv_sec_at_expire = 0;
					twait_block->vtag_block[i].v_tag = 0;
				} else if (twait_block->vtag_block[i].v_tag ==
				    tag) {
					/* Bad tag, sorry :< */
					return (0);
				}
			}
		}
	}
	/* Not found, ok to use the tag */
	return (1);
}


/*
 * Delete the address from the endpoint local address list
 * Lookup using a sockaddr address (ie. not an ifaddr)
 */
int
sctp_del_local_addr_ep_sa(struct sctp_inpcb *ep, struct sockaddr *sa)
{
	struct sctp_laddr *laddr;
	struct sockaddr *l_sa;
	int found = 0;

	if (ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) {
		/* You are already bound to all. You have it already */
		return (EINVAL);
	}

	LIST_FOREACH(laddr, &ep->sctp_addr_list, sctp_nxt_addr) {
		/* make sure the address exists */
		if (laddr->ifa == NULL)
			continue;
		if (laddr->ifa->ifa_addr == NULL)
			continue;

		l_sa = laddr->ifa->ifa_addr;
		if (l_sa->sa_family == AF_INET6) {
			/* IPv6 address */
			struct sockaddr_in6 *sin1, *sin2;
			sin1 = (struct sockaddr_in6 *)l_sa;
			sin2 = (struct sockaddr_in6 *)sa;
			if (memcmp(&sin1->sin6_addr, &sin2->sin6_addr,
				   sizeof(struct in6_addr)) == 0) {
				/* matched */
				found = 1;
				break;
			}
		} else if (l_sa->sa_family == AF_INET) {
			/* IPv4 address */
			struct sockaddr_in *sin1, *sin2;
			sin1 = (struct sockaddr_in *)l_sa;
			sin2 = (struct sockaddr_in *)sa;
			if (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr) {
				/* matched */
				found = 1;
				break;
			}
		} else {
			/* invalid family */
			return (-1);
		}
	}

	if (found && (ep->laddr_count < 2)) {
		/* can't delete unless there are at LEAST 2 addresses */
		return (-1);
	}

	if (found && ((ep->sctp_flags & SCTP_PCB_FLAGS_BOUNDALL) == 0)) {
		/*
		 * remove it from the ep list, this should NOT be
		 * done until its really gone from the interface list and
		 * we won't be receiving more of these. Probably right
		 * away. If we do allow a removal of an address from
		 * an association (sub-set bind) than this should NOT
		 * be called until the all ASCONF come back from this
		 * association.
		 */
		sctp_remove_laddr(laddr);
		return (0);
	} else {
		return (-1);
	}
}

static void
sctp_drain_mbufs(struct sctp_inpcb *inp,
		 struct sctp_tcb *tcb)
{
	/*
	 * We must hunt this association for MBUF's past the cumack
	 * (i.e. out of order data that we can renege on).
	 */
	struct sctp_association *asoc;
	struct sctp_tmit_chunk *chk, *nchk;
	u_int32_t cumulative_tsn_p1, tsn;
	int cnt, strmat, gap;
	/* We look for anything larger than the cum-ack + 1 */

	asoc = &tcb->asoc;
	cumulative_tsn_p1 = asoc->cumulative_tsn + 1;
	cnt = 0;
	/* First look in the re-assembly queue */
	chk = TAILQ_FIRST(&asoc->reasmqueue);
	while (chk) {
		/* Get the next one */
		nchk = TAILQ_NEXT(chk, sctp_next);
		if (compare_with_wrap(chk->rec.data.TSN_seq,
				      cumulative_tsn_p1, MAX_TSN)) {
			/* Yep it is above cum-ack */
			cnt++;
			tsn = chk->rec.data.TSN_seq;
			if (tsn >= asoc->mapping_array_base_tsn) {
				gap  = tsn - asoc->mapping_array_base_tsn;
			} else {
				gap = (MAX_TSN - asoc->mapping_array_base_tsn) + tsn + 1;
			}
			asoc->size_on_reasm_queue -= chk->send_size;
			asoc->cnt_on_reasm_queue--;
			SCTP_UNSET_TSN_PRESENT(asoc->mapping_array, gap);
			TAILQ_REMOVE(&asoc->reasmqueue, chk, sctp_next);
			if (chk->data) {
				m_freem(chk->data);
				chk->data = NULL;
			}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
			uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
			zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
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
		chk = nchk;
	}
	/* Ok that was fun, now we will drain all the inbound streams? */
	for (strmat = 0; strmat < asoc->streamincnt; strmat++) {
		chk = TAILQ_FIRST(&asoc->strmin[strmat].inqueue);
		while (chk) {
			nchk = TAILQ_NEXT(chk, sctp_next);
			if (compare_with_wrap(chk->rec.data.TSN_seq,
					      cumulative_tsn_p1, MAX_TSN)) {
				/* Yep it is above cum-ack */
				cnt++;
				tsn = chk->rec.data.TSN_seq;
				if (tsn >= asoc->mapping_array_base_tsn) {
					gap = tsn -
						asoc->mapping_array_base_tsn;
				} else {
					gap = (MAX_TSN -
					       asoc->mapping_array_base_tsn) +
						tsn + 1;
				}
				asoc->size_on_all_streams -= chk->send_size;
				asoc->cnt_on_all_streams--;

				SCTP_UNSET_TSN_PRESENT(asoc->mapping_array,
						       gap);
				TAILQ_REMOVE(&asoc->strmin[strmat].inqueue,
					     chk, sctp_next);
				if (chk->data) {
					m_freem(chk->data);
					chk->data = NULL;
				}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
				uma_zfree(sctppcbinfo.ipi_zone_chunk, chk);
#else
				zfreei(sctppcbinfo.ipi_zone_chunk, chk);
#endif
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
			chk = nchk;
		}
	}
	printf("Harvest %d chunks from drain ep:%p - %d left\n",
	       cnt, inp, sctppcbinfo.ipi_count_chunk);
	/*
	 * Question, should we go through the delivery queue?
	 * The only reason things are on here is the app not reading OR a
	 * p-d-api up. An attacker COULD send enough in to initiate the
	 * PD-API and then send a bunch of stuff to other streams... these
	 * would wind up on the delivery queue.. and then we would not get
	 * to them. But in order to do this I then have to back-track and
	 * un-deliver sequence numbers in streams.. el-yucko. I think for
	 * now we will NOT look at the delivery queue and leave it to be
	 * something to consider later. An alternative would be to abort
	 * the P-D-API with a notification and then deliver the data....
	 * Or another method might be to keep track of how many times the
	 * situation occurs and if we see a possible attack underway just
	 * abort the association.
	 */
#ifdef SCTP_DEBUG
	if (sctp_debug_on & SCTP_DEBUG_PCB1) {
		if (cnt) {
			printf("Freed %d chunks from reneg harvest\n", cnt);
		}
	}
#endif /* SCTP_DEBUG */

	/*
	 * Another issue, in un-setting the TSN's in the mapping array we
	 * DID NOT adjust the higest_tsn marker.  This will cause one of
	 * two things to occur. It may cause us to do extra work in checking
	 * for our mapping array movement. More importantly it may cause us
	 * to SACK every datagram. This may not be a bad thing though since
	 * we will recover once we get our cum-ack above and all this stuff
	 * we dumped recovered.
	 */
}

void
sctp_drain()
{
	/*
	 * We must walk the PCB lists for ALL associations here. The system
	 * is LOW on MBUF's and needs help. This is where reneging will
	 * occur. We really hope this does NOT happen!
	 */
	struct sctp_inpcb *inp;
	struct sctp_tcb *tcb;

	printf("SCTP DRAIN called %d chunks out there\n",
	       sctppcbinfo.ipi_count_chunk);
	LIST_FOREACH(inp, &sctppcbinfo.listhead, sctp_list) {
		/* For each endpoint */
		LIST_FOREACH(tcb, &inp->sctp_asoc_list, sctp_tcblist) {
			/* For each association */
			sctp_drain_mbufs(inp, tcb);
		}
	}
}

int
sctp_add_to_socket_q(struct sctp_inpcb *inp, struct sctp_tcb *tcb)
{
	struct sctp_socket_q_list *sq;

	if ((inp == NULL) || (tcb == NULL)) {
		/* I am paranoid */
		return (0);
	}
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	sq = (struct sctp_socket_q_list *)uma_zalloc(sctppcbinfo.ipi_zone_sockq,
						     M_NOWAIT);
#else
	sq = (struct sctp_socket_q_list *)zalloci(sctppcbinfo.ipi_zone_sockq);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	sq = (struct sctp_socket_q_list *)pool_get(&sctppcbinfo.ipi_zone_sockq,PR_NOWAIT);
#endif
	if (sq == NULL) {
		/* out of sq structs */
		return (0);
	}
	sctppcbinfo.ipi_count_sockq++;
	sctppcbinfo.ipi_gencnt_sockq++;

	sq->tcb = tcb;
	TAILQ_INSERT_TAIL(&inp->sctp_queue_list, sq, next_sq);
	return (1);
}


struct sctp_tcb *
sctp_remove_from_socket_q(struct sctp_inpcb *inp)
{
	struct sctp_tcb *tcb = NULL;
	struct sctp_socket_q_list *sq;

	sq = TAILQ_FIRST(&inp->sctp_queue_list);
	if (sq == NULL)
		return (tcb);

	tcb = sq->tcb;
	TAILQ_REMOVE(&inp->sctp_queue_list, sq, next_sq);
#if defined(__FreeBSD__)
#if __FreeBSD_version >= 500000
	uma_zfree(sctppcbinfo.ipi_zone_sockq, sq);
#else
	zfreei(sctppcbinfo.ipi_zone_sockq, sq);
#endif
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
	pool_put(&sctppcbinfo.ipi_zone_sockq, sq);
#endif
	sctppcbinfo.ipi_count_sockq--;
	sctppcbinfo.ipi_gencnt_sockq++;
	return (tcb);
}




#ifdef _SCTP_NEEDS_CALLOUT_


extern int ticks;

void
callout_init(struct callout *c)
{
	bzero(c, sizeof(*c));
}

void
callout_reset(struct callout *c, int to_ticks, void (*ftn)(void *), void *arg)
{
	int s;

	s = splhigh();
	if (c->c_flags & CALLOUT_PENDING)
		callout_stop(c);

	/*
	 * We could spl down here and back up at the TAILQ_INSERT_TAIL,
	 * but there's no point since doing this setup doesn't take much
	 * time.
	 */
	if (to_ticks <= 0)
		to_ticks = 1;

	c->c_arg = arg;
	c->c_flags = (CALLOUT_ACTIVE | CALLOUT_PENDING);
	c->c_func = ftn;
	c->c_time = ticks + to_ticks;
	TAILQ_INSERT_TAIL(&sctppcbinfo.callqueue, c, tqe);
	splx(s);
}

int
callout_stop(struct callout *c)
{
	int	s;

	s = splhigh();
	/*
	 * Don't attempt to delete a callout that's not on the queue.
	 */
	if (!(c->c_flags & CALLOUT_PENDING)) {
		c->c_flags &= ~CALLOUT_ACTIVE;
		splx(s);
		return (0);
	}
	c->c_flags &= ~(CALLOUT_ACTIVE | CALLOUT_PENDING| CALLOUT_FIRED);
	TAILQ_REMOVE(&sctppcbinfo.callqueue, c, tqe);
	c->c_func = NULL;
	splx(s);
	return (1);
}

void
sctp_fasttim(void)
{
	struct callout *c, *n;
	struct calloutlist locallist;
	int inited = 0;
	int s;
	s = splhigh();
	/* run through and subtract and mark all callouts */
	c = TAILQ_FIRST(&sctppcbinfo.callqueue);
	while (c) {
		n = TAILQ_NEXT(c, tqe);
		if (c->c_time <= ticks) {
			c->c_flags |= CALLOUT_FIRED;
			c->c_time = 0;
			TAILQ_REMOVE(&sctppcbinfo.callqueue, c, tqe);
			if (inited == 0) {
				TAILQ_INIT(&locallist);
				inited = 1;
			}
			/* move off of main list */
			TAILQ_INSERT_TAIL(&locallist, c, tqe);
		}
		c = n;
	}
	/* Now all the ones on the locallist must be called */
	if (inited) {
		c = TAILQ_FIRST(&locallist);
		while (c) {
			/* remove it */
			TAILQ_REMOVE(&locallist, c, tqe);
			/* now validate that it did not get canceled */
			if (c->c_flags & CALLOUT_FIRED) {
				c->c_flags &= ~CALLOUT_PENDING;
				splx(s);
				(*c->c_func)(c->c_arg);
				s = splhigh();
			}
			c = TAILQ_FIRST(&locallist);
		}
	}
	splx(s);
}



#endif /* _SCTP_NEEDS_CALLOUT_ */

