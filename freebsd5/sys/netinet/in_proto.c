/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in_proto.c	8.2 (Berkeley) 2/9/95
 * $FreeBSD: src/sys/netinet/in_proto.c,v 1.73 2004/08/16 18:32:07 rwatson Exp $
 */

#include "opt_ipdivert.h"
#include "opt_ipx.h"
#include "opt_mrouting.h"
#include "opt_ipsec.h"
#include "opt_inet6.h"
#include "opt_natpt.h"
#ifdef __FreeBSD__
#include "opt_mpath.h"
#endif
#include "opt_sctp.h"
#include "opt_dccp.h"
#include "opt_pf.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>
#if defined(RADIX_MPATH)
#include <net/radix_mpath.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_divert.h>
#include <netinet/igmp_var.h>
#ifdef PIM
#include <netinet/pim_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#ifdef DCCP
#include <netinet/dccp.h>
#include <netinet/dccp_var.h>
#endif /* DCCP */
#include <netinet/ip_encap.h>

/*
 * TCP/IP protocol family: IP, ICMP, UDP, TCP.
 */

#ifdef IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#ifdef IPSEC_ESP
#include <netinet6/esp.h>
#endif
#include <netinet6/ipcomp.h>
#endif /* IPSEC */

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#endif /* FAST_IPSEC */

#ifdef IPXIP
#include <netipx/ipx_ip.h>
#endif

#ifdef SCTP
#include <netinet/in_pcb.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctp.h>
#include <netinet/sctp_var.h>
#endif /* SCTP */

#ifdef NATPT
void	natpt_init(void);
int	natpt_ctloutput(int, struct socket *, int, int, struct mbuf **);
extern struct pr_usrreqs natpt_usrreqs;
#endif

#ifdef DEV_PFSYNC
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#endif

extern	struct domain inetdomain;
static	struct pr_usrreqs nousrreqs;

struct protosw inetsw[] = {
{ 0,		&inetdomain,	0,		0,
  0,		0,		0,		0,
  0,
  ip_init,	0,		ip_slowtimo,	ip_drain,
  &nousrreqs
},
{ SOCK_DGRAM,	&inetdomain,	IPPROTO_UDP,	PR_ATOMIC|PR_ADDR,
  udp_input,	0,		udp_ctlinput,	ip_ctloutput,
  0,
  udp_init,	0,		0,		0,
  &udp_usrreqs
},
{ SOCK_STREAM,	&inetdomain,	IPPROTO_TCP,
	PR_CONNREQUIRED|PR_IMPLOPCL|PR_WANTRCVD,
  tcp_input,	0,		tcp_ctlinput,	tcp_ctloutput,
  0,
  tcp_init,	0,		tcp_slowtimo,	tcp_drain,
  &tcp_usrreqs
},
#ifdef SCTP
/*
 * Order is very important here, we add the good one in
 * in this postion so it maps to the right ip_protox[]
 * postion for SCTP. Don't move the one above below
 * this one or IPv6/4 compatability will break
 */
{ SOCK_DGRAM,	&inetdomain,	IPPROTO_SCTP,	PR_ADDR_OPT|PR_WANTRCVD,
  sctp_input,	0,		sctp_ctlinput,	sctp_ctloutput,
  0,
  sctp_init,	0,		0,		sctp_drain,
  &sctp_usrreqs
},
{ SOCK_SEQPACKET,&inetdomain,	IPPROTO_SCTP,	PR_ADDR_OPT|PR_WANTRCVD,
  sctp_input,	0,		sctp_ctlinput,	sctp_ctloutput,
  0,
  0,		0,		0,		sctp_drain,
  &sctp_usrreqs
},

{ SOCK_STREAM,	&inetdomain,	IPPROTO_SCTP,	PR_ADDR_OPT|PR_WANTRCVD,
  sctp_input,	0,		sctp_ctlinput,	sctp_ctloutput,
  0,
  0,		0,		0,		sctp_drain,
  &sctp_usrreqs
},
#endif /* SCTP */
#ifdef DCCP
{ SOCK_DGRAM,	&inetdomain,	IPPROTO_DCCP,	PR_CONNREQUIRED|PR_IMPLOPCL|PR_ATOMIC,
  dccp_input,	0,		dccp_ctlinput,	dccp_ctloutput,
  0,
  dccp_init,	0,		0,		0,
  &dccp_usrreqs
},
#endif /* DCCP */
{ SOCK_RAW,	&inetdomain,	IPPROTO_RAW,	PR_ATOMIC|PR_ADDR,
  rip_input,	0,		rip_ctlinput,	rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_ICMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  icmp_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_IGMP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  igmp_input,	0,		0,		rip_ctloutput,
  0,
  igmp_init,	igmp_fasttimo,	igmp_slowtimo,	0,
  &rip_usrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_RSVP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  rsvp_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
#ifdef IPSEC
{ SOCK_RAW,	&inetdomain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR,
  ah4_input,	0,		0,		0,
  0,
  0,		0,		0,		0,
  &nousrreqs
},
#ifdef IPSEC_ESP
{ SOCK_RAW,	&inetdomain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR,
  esp4_input,	0,		0,		0,
  0,
  0,		0,		0,		0,
  &nousrreqs
},
#endif
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR,
  ipcomp4_input, 0,		0,		0,
  0,
  0,		0,		0,		0,
  &nousrreqs
},
#endif /* IPSEC */
#ifdef FAST_IPSEC
{ SOCK_RAW,	&inetdomain,	IPPROTO_AH,	PR_ATOMIC|PR_ADDR,
  ah4_input,	0,		ah4_ctlinput,	0,
  0,
  0,		0,		0,		0,
  &nousrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_ESP,	PR_ATOMIC|PR_ADDR,
  esp4_input,	0,		esp4_ctlinput,	0,
  0,
  0,		0,		0,		0,
  &nousrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPCOMP,	PR_ATOMIC|PR_ADDR,
  ipcomp4_input,	0,		0,		0,
  0,
  0,		0,		0,		0,
  &nousrreqs
},
#endif /* FAST_IPSEC */
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV4,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	0,		0,		rip_ctloutput,
  0,
  encap_init,		0,		0,		0,
  &rip_usrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_MOBILE,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	0,		0,		rip_ctloutput,
  0,
  encap_init,	0,		0,		0,
  &rip_usrreqs
},
{ SOCK_RAW,	&inetdomain,	IPPROTO_GRE,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	0,		0,		rip_ctloutput,
  0,
  encap_init,	0,		0,		0,
  &rip_usrreqs
},
# ifdef INET6
{ SOCK_RAW,	&inetdomain,	IPPROTO_IPV6,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  encap4_input,	0,		0,		rip_ctloutput,
  0,
  encap_init,	0,		0,		0,
  &rip_usrreqs
},
#endif
#ifdef IPDIVERT
{ SOCK_RAW,	&inetdomain,	IPPROTO_DIVERT,	PR_ATOMIC|PR_ADDR,
  div_input,	0,		div_ctlinput,	ip_ctloutput,
  0,
  div_init,	0,		0,		0,
  &div_usrreqs,
},
#endif
#ifdef IPXIP
{ SOCK_RAW,	&inetdomain,	IPPROTO_IDP,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  ipxip_input,	0,		ipxip_ctlinput,	0,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
#endif
#ifdef NATPT
{ SOCK_RAW,	&inetdomain,	IPPROTO_AHIP,	PR_ATOMIC|PR_ADDR,
  0,		0,		0,		0,
  0,
  natpt_init,	0,		0,		0,
 &natpt_usrreqs
},
#endif
#ifdef PIM
{ SOCK_RAW,	&inetdomain,	IPPROTO_PIM,	PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  pim_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
#endif	/* PIM */
#ifdef DEV_PFSYNC
{ SOCK_RAW,	&inetdomain,	IPPROTO_PFSYNC,	PR_ATOMIC|PR_ADDR,
  pfsync_input,	0,		0,		rip_ctloutput,
  0,
  0,		0,		0,		0,
  &rip_usrreqs
},
#endif	/* DEV_PFSYNC */
	/* raw wildcard */
{ SOCK_RAW,	&inetdomain,	0,		PR_ATOMIC|PR_ADDR|PR_LASTHDR,
  rip_input,	0,		0,		rip_ctloutput,
  0,
  rip_init,	0,		0,		0,
  &rip_usrreqs
},
};

extern int in_inithead(void **, int);

struct domain inetdomain =
    { AF_INET, "internet", 0, 0, 0,
      inetsw,
      &inetsw[sizeof(inetsw)/sizeof(inetsw[0])], 0,
#if defined(RADIX_MPATH)
      rn4_mpath_inithead,
#else
      in_inithead,
#endif
      32, sizeof(struct sockaddr_in)
    };

DOMAIN_SET(inet);

SYSCTL_NODE(_net,      PF_INET,		inet,	CTLFLAG_RW, 0,
	"Internet Family");

SYSCTL_NODE(_net_inet, IPPROTO_IP,	ip,	CTLFLAG_RW, 0,	"IP");
SYSCTL_NODE(_net_inet, IPPROTO_ICMP,	icmp,	CTLFLAG_RW, 0,	"ICMP");
SYSCTL_NODE(_net_inet, IPPROTO_UDP,	udp,	CTLFLAG_RW, 0,	"UDP");
SYSCTL_NODE(_net_inet, IPPROTO_TCP,	tcp,	CTLFLAG_RW, 0,	"TCP");
#ifdef SCTP
SYSCTL_NODE(_net_inet, IPPROTO_SCTP,	sctp,	CTLFLAG_RW, 0,	"SCTP");
#endif /* SCTP */
#ifdef DCCP
SYSCTL_NODE(_net_inet, IPPROTO_DCCP,	dccp,	CTLFLAG_RW, 0,	"DCCP");
#endif /* DCCP */
SYSCTL_NODE(_net_inet, IPPROTO_IGMP,	igmp,	CTLFLAG_RW, 0,	"IGMP");
#ifdef FAST_IPSEC
/* XXX no protocol # to use, pick something "reserved" */
SYSCTL_NODE(_net_inet, 253,		ipsec,	CTLFLAG_RW, 0,	"IPSEC");
SYSCTL_NODE(_net_inet, IPPROTO_AH,	ah,	CTLFLAG_RW, 0,	"AH");
SYSCTL_NODE(_net_inet, IPPROTO_ESP,	esp,	CTLFLAG_RW, 0,	"ESP");
SYSCTL_NODE(_net_inet, IPPROTO_IPCOMP,	ipcomp,	CTLFLAG_RW, 0,	"IPCOMP");
SYSCTL_NODE(_net_inet, IPPROTO_IPIP,	ipip,	CTLFLAG_RW, 0,	"IPIP");
#else
#ifdef IPSEC
SYSCTL_NODE(_net_inet, IPPROTO_AH,	ipsec,	CTLFLAG_RW, 0,	"IPSEC");
#endif /* IPSEC */
#endif /* !FAST_IPSEC */
SYSCTL_NODE(_net_inet, IPPROTO_RAW,	raw,	CTLFLAG_RW, 0,	"RAW");
#ifdef IPDIVERT
SYSCTL_NODE(_net_inet, IPPROTO_DIVERT,	divert,	CTLFLAG_RW, 0,	"DIVERT");
#endif
#ifdef PIM
SYSCTL_NODE(_net_inet, IPPROTO_PIM,    pim,    CTLFLAG_RW, 0,  "PIM");
#endif
