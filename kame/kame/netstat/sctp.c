/*	$KAME: sctp.c,v 1.1 2004/08/17 04:07:49 itojun Exp $	*/

/*
 * Copyright (c) 1983, 1988, 1993
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 */

#include <sys/cdefs.h>
#ifndef lint
#if 0
static char sccsid[] = "from: @(#)inet.c	8.4 (Berkeley) 4/20/94";
#else
static const char rcsid[] = "$NetBSD: inet.c,v 1.51 2002/02/27 02:33:51 lukem Exp $";
#endif
#endif /* not lint */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>

#include <net/if.h>
#if defined(__FreeBSD__)
#include <net/if_var.h>
#endif
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>

#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "netstat.h"

#ifdef SCTP
#if !defined(__OpenBSD__)
struct pool {
};  /* XXX pool defined only KERNEL */
#endif
#include <netinet/sctp_pcb.h>

#ifndef __OpenBSD__
#define nflag	numeric_port
#endif

static int width;

void	inet46print	__P((struct sockaddr *, u_int16_t, int));

void
#if defined(__FreeBSD__)
sctp_protopr(u_long off, char *name, int af)
#else /* NetBSD and OpenBSD */
sctp_protopr(off, name)
	u_long off;
	char *name;
#endif
{
#if !defined(__FreeBSD__)
	int af;
#endif
	struct sctp_epinfo epinfo;
	struct sctp_inpcb *inp_next, *inp_prev;
	struct sctp_inpcb inp;
	struct sctp_tcb *tcb_next, *tcb_prev;
	struct sctp_tcb tcb;
	struct ifaddrs *ifap0, *ifap;
	struct sctp_laddr *laddr_next;
	struct sctp_laddr laddr;
	struct ifaddr ifa;
	struct sockaddr_storage ss;
	int ss_len;
	struct sctp_nets *nets_next;
	struct sctp_nets nets;
	struct sockaddr *sa;
	struct sockaddr_in *sin, *sin_r, sin_any;
	struct sockaddr_in6 *sin6, *sin6_r;
	int ipv4_addr_legal, ipv6_addr_legal;
	struct socket sockb;
	int first;

	if (off == 0)
		return;
	kread(off, (char *)&epinfo, sizeof(epinfo));
	inp_prev = inp_next = epinfo.listhead.lh_first;

#if defined(__FreeBSD__)
	if (Aflag && !Wflag)
		width = 18;
	else if (Wflag)
#else
	if (vflag)
#endif
		width = 45;
	else if (Aflag)
#if defined(__OpenBSD__)
		width = 18;
#else
		width = 21;
#endif
	else 
		width = 22;

	printf("Active Stream Conrol Transmission Protocol associations");
	if (aflag)
		printf(" (including servers)");
	putchar('\n');
	if (Aflag)
		printf("%-8.8s ",
#if defined(__FreeBSD__)
			"Socket");
#else
			"PCB");
#endif
#if defined(__FreeBSD__)
	printf("%-6.6s %-6.6s %-6.6s%s %-*.*s %-*.*s %s\n",
#else
	printf("%-5.5s %-6.6s %-6.6s%s %-*.*s %-*.*s %s\n",
#endif
	    "Proto", "Recv-Q", "Send-Q",
#if defined(__FreeBSD__)
	    " ",
#else
	    Aflag ? "" : " ",
#endif
	    width, width, "Local Address",
	    width, width, "Foreign Address",
#if defined(__FreeBSD__) || defined(__OpenBSD__)
	    "(state)");
#else
	    "State");
#endif

	if (getifaddrs(&ifap0) < 0)
		return;

	memset(&sin_any, 0, sizeof(sin_any));
	sin_any.sin_len = sizeof(sin_any);
	sin_any.sin_family = AF_INET;

	while (inp_next != NULL) {
		kread((u_long)inp_next, (char *)&inp, sizeof(inp));
		inp_prev = inp_next;
		inp_next = inp.sctp_list.le_next;
		kread((u_long)inp.sctp_socket, (char *)&sockb, sizeof(sockb));

		ipv4_addr_legal = ipv6_addr_legal = 0;
		if (inp.sctp_flags & SCTP_PCB_FLAGS_BOUND_V6) {
			ipv6_addr_legal = 1;
			if (
#if defined(__OpenBSD__)
			(0) /* we always do dual bind */
#elif defined (__NetBSD__)
			(((struct in6pcb *)&inp)->in6p_flags & IN6P_IPV6_V6ONLY)
#else
			(((struct in6pcb *)&inp)->inp_flags & IN6P_IPV6_V6ONLY)
#endif
			== 0) {
				ipv4_addr_legal = 1;
			}
		} else {
			ipv4_addr_legal = 1;
		}

		if (aflag && (inp.sctp_flags & SCTP_PCB_FLAGS_ACCEPTING)) {
			if ((inp.sctp_flags & SCTP_PCB_FLAGS_BOUNDALL)) {
				ifap = ifap0;
				laddr_next = NULL;
			} else {
				ifap = NULL;
				laddr_next = inp.sctp_addr_list.lh_first;
			}
			first = 1;
			while (ifap != NULL || laddr_next != NULL) {
				sin = NULL;
				sin6 = NULL;
				if (ifap != NULL) {
					while (ifap != NULL) {
						if (ifap->ifa_addr->sa_family == AF_INET &&
							ipv4_addr_legal) {
							sin = (struct sockaddr_in *)ifap->ifa_addr;
							break;
						} else if (ifap->ifa_addr->sa_family == AF_INET6 &&
							ipv6_addr_legal) {
							sin6 = (struct sockaddr_in6 *)ifap->ifa_addr;
							break;
						}
						ifap = ifap->ifa_next;
					}
					if (ifap != NULL) 
						ifap = ifap->ifa_next;
				} else if (laddr_next != NULL) {
					do {
						kread((u_long)laddr_next,
						    (char *)&laddr,
						    sizeof(laddr));
						laddr_next = laddr.sctp_nxt_addr.le_next;
						if (laddr.ifa == NULL)
							break;
						kread((u_long)laddr.ifa,
						    (char *)&ifa,
						    sizeof(ifa));
						if (ifa.ifa_addr == NULL)
							break;
						kread((u_long)ifa.ifa_addr,
						    (char *)&ss,
						    sizeof(struct sockaddr));
						ss_len = ss.ss_len;
						kread((u_long)ifa.ifa_addr,
						    (char *)&ss,
						    ss_len);
						if  (ss.ss_family == AF_INET) {
							sin = (struct sockaddr_in *)&ss;
						} else if (ss.ss_family == AF_INET6) {
							sin6 = (struct sockaddr_in6 *)&ss;
						}
					} while (0);
				}
				if (sin == NULL && sin6 == NULL)
					continue;
				if (first) {
					if (Aflag)
						printf("%8lx ", (u_long)inp_prev);
#if defined(__FreeBSD__)
					printf("%-6.6s %6ld %6ld%s ",
#else
					printf("%-5.5s %6ld %6ld%s ",
#endif
					    name,
					    (u_long)sockb.so_rcv.sb_cc,
					    (u_long)sockb.so_snd.sb_cc,
#if defined(__FreeBSD__)
					    " ");
#else
					    Aflag ? "" : " ");
#endif
				} else {
#if defined(__FreeBSD__)
					if (Aflag)
						printf("%31s"," ");
					else 
						printf("%22s"," ");
#else
					if (Aflag)
						printf("%29s"," ");
					else 
						printf("%21s"," ");
#endif
				}

				if (sin != NULL) {
					inet46print((struct sockaddr *)sin,
					    inp.sctp_lport, nflag);
				} else if (sin6 != NULL) {
					inet46print((struct sockaddr *)sin6,
					    inp.sctp_lport, nflag);
				}
				inet46print((struct sockaddr *)&sin_any,
				    0, nflag);
				if (first) {
					printf("%s", "LISTEN");
					first = 0;
				}
				putchar('\n');
			}
		}

		tcb_next = inp.sctp_asoc_list.lh_first;
		while (tcb_next != NULL) {
			kread((u_long)tcb_next, (char *)&tcb, sizeof(tcb));
			tcb_prev = tcb_next;
			tcb_next = tcb.sctp_tcblist.le_next;
			nets_next = tcb.asoc.nets.tqh_first;
			if ((inp.sctp_flags & SCTP_PCB_FLAGS_BOUNDALL)) {
				ifap = ifap0;
				laddr_next = NULL;
			} else {
				ifap = NULL;
				laddr_next = inp.sctp_addr_list.lh_first;
			}

			first = 1;
			while (ifap != NULL ||
				laddr_next != NULL ||
				nets_next != NULL) {
				sin = sin_r = NULL;
				sin6 = sin6_r =  NULL;

				if (ifap != NULL) {
					while (ifap != NULL) {
						if (ifap->ifa_addr->sa_family == AF_INET &&
							ipv4_addr_legal) {
							sin = (struct sockaddr_in *)ifap->ifa_addr;
							break;
						} else if (ifap->ifa_addr->sa_family == AF_INET6 &&
							ipv6_addr_legal) {
							sin6 = (struct sockaddr_in6 *)ifap->ifa_addr;
							break;
						}
						ifap = ifap->ifa_next;
					}
					if (ifap != NULL) 
						ifap = ifap->ifa_next;
				} else if (laddr_next != NULL) {
					do {
						kread((u_long)laddr_next,
						    (char *)&laddr,
						    sizeof(laddr));
						laddr_next = laddr.sctp_nxt_addr.le_next;
						if (laddr.ifa == NULL)
							break;
						kread((u_long)laddr.ifa,
						    (char *)&ifa,
						    sizeof(ifa));
						if (ifa.ifa_addr == NULL)
							break;
						kread((u_long)ifa.ifa_addr,
						    (char *)&ss,
						    sizeof(struct sockaddr));
						ss_len = ss.ss_len;
						kread((u_long)ifa.ifa_addr,
						    (char *)&ss,
						    ss_len);
						if  (ss.ss_family == AF_INET) {
							sin = (struct sockaddr_in *)&ss;
						} else if (ss.ss_family == AF_INET6) {
							sin6 = (struct sockaddr_in6 *)&ss;
						}
					} while (0);
				}

				if (nets_next != NULL) {
					kread((u_long)nets_next, (char *)&nets,
					    sizeof(nets));
					nets_next = nets.sctp_next.tqe_next;
					sa = (struct sockaddr *)&nets.ra._l_addr;
					if (sa->sa_family == AF_INET) {
						sin_r = (struct sockaddr_in *)sa;
					} else if (sa->sa_family == AF_INET6) {
						sin6_r = (struct sockaddr_in6 *)sa;
					} 
				}

				if (sin == NULL && sin6 == NULL &&
				    sin_r == NULL && sin6_r == NULL)
					continue;
				if (first) {
					if (Aflag)
						printf("%8lx ", (u_long)inp_prev);
#if defined(__FreeBSD__)
					printf("%-6.6s %6ld %6ld%s ",
#else
					printf("%-5.5s %6ld %6ld%s ",
#endif
					    name,
					    (u_long)sockb.so_rcv.sb_cc,
					    (u_long)sockb.so_snd.sb_cc,
#if defined(__FreeBSD__)
					    " ");
#else
					    Aflag ? "" : " ");
#endif
						
				} else {
#if defined(__FreeBSD__)
					if (Aflag)
						printf("%31s"," ");
					else 
						printf("%22s"," ");
#else
					if (Aflag)
						printf("%29s"," ");
					else 
						printf("%21s"," ");
#endif
				}
					
				if (sin != NULL) {
					inet46print((struct sockaddr *)sin,
					    inp.sctp_lport, nflag);
				} else if (sin6 != NULL) {
					inet46print((struct sockaddr *)sin6,
					    inp.sctp_lport, nflag);
				} else {
					printf("N/A%*s", width - 3 + 1, " ");
				}
				if (sin_r != NULL) {
					inet46print((struct sockaddr *)sin_r,
					    tcb.rport, nflag);
				} else if (sin6_r != NULL) {
					inet46print((struct sockaddr *)sin6_r,
					    tcb.rport, nflag);
				} else {
					printf("N/A%*s", width - 3 + 1, " ");
				}
				if (first) {
					switch (tcb.asoc.state) {
					case SCTP_STATE_COOKIE_WAIT:
						printf("COOKIE_WAIT");
						break;
					case SCTP_STATE_COOKIE_ECHOED:
						printf("COOKIE_ECHOED");
						break;
					case SCTP_STATE_OPEN:
						printf("ESTABLISHED");
						break;
					case SCTP_STATE_SHUTDOWN_SENT:
						printf("SHUTDOWN-SENT");
						break;
					case SCTP_STATE_SHUTDOWN_RECEIVED:
						printf("SHUTDOWN-RECEIVED");
						break;
					case SCTP_STATE_SHUTDOWN_ACK_SENT:
						printf("SHUTDOWN-ACK-SENT");
						break;
					case SCTP_STATE_SHUTDOWN_PENDING:
						printf("SHUTDOWN-PENDING");
						break;
					case SCTP_STATE_EMPTY:
					case SCTP_STATE_INUSE:
					case SCTP_STATE_CLOSED_SOCKET:
					default:
						printf("CLOSED");
						break;
					}
					first = 0;
				}
				putchar('\n');
			}
		}
	}
	freeifaddrs(ifap0);
}

void
inet46print(sa, port, numeric)
	struct sockaddr *sa;
	u_int16_t port;
	int numeric;
{
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	u_int16_t scope_id;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int flags = 0;
	int n, addrwidth;

	addrwidth = width - 6;

	if (sa->sa_family == AF_INET) {
		sin = *(struct sockaddr_in *)sa;
		sin.sin_port = port;
		sa = (struct sockaddr *)&sin;
	} else if (sa->sa_family == AF_INET6) {
		sin6 = *(struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr)) {
			bcopy(&sin6.sin6_addr.s6_addr[2], &scope_id,
			    sizeof(u_int16_t));
			sin6.sin6_scope_id = ntohs(scope_id);
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
		}
		sin6.sin6_port = port;
		sa = (struct sockaddr *)&sin6;
	} else
		return;
	
	if (numeric)
		flags |= NI_NUMERICHOST | NI_NUMERICSERV;

	if (getnameinfo(sa, sa->sa_len, hbuf, sizeof(hbuf),
		sbuf, sizeof(sbuf), flags)) {
		printf("%*s ", width, "???");
		return;
	}
	n = 0;
	if ((sa->sa_family == AF_INET &&
	     sin.sin_addr.s_addr == INADDR_ANY) ||
	    (sa->sa_family == AF_INET6 &&
	     IN6_IS_ADDR_UNSPECIFIED(&sin6.sin6_addr)))
		n = printf("%.*s.", addrwidth, "*");
	else
		n = printf("%.*s.", addrwidth, hbuf);

	if (port == 0)
		n += printf("%-5s ", "*") - 1;
	else
		n += printf("%-5s ", sbuf) - 1;
		
	if (n < width)
		printf("%*s", width - n, " ");
}

static char *pegs_name[SCTP_NUMBER_OF_PEGS] = {
	"PEG_SACKS_SEEN",
	"PEG_SACKS_SENT",
	"PEG_TSNS_SENT",
	"PEG_TSNS_RCVD",
	"DATAGRAMS_SENT",
	"DATAGRAMS_RCVD",
	"RETRANTSN_SENT",
	"DUPTSN_RECVD",
	"HB_RECV",
	"HB_ACK_RECV",
	"HB_SENT",
	"WINDOW_PROBES",
	"DATA_DG_RECV",
	"TMIT_TIMER",
	"RECV_TIMER",
	"HB_TIMER",
	"FAST_RETRAN",
	"TIMERS_EXP",
	"FR_INAWINDOW",
	"RWND_BLOCKED",
	"CWND_BLOCKED",
	"RWND_DROPS",
	"BAD_STRMNO",
	"BAD_SSN_WRAP",
	"DROP_NOMEMORY",
	"DROP_FRAG",
	"BAD_VTAGS",
	"BAD_CSUM",
	"INPKTS",
	"IN_MCAST",
	"HDR_DROPS",
	"NOPORTS",
	"CWND_NOFILL",
	"CALLS_TO_CO",
	"CO_NODATASNT",
	"CWND_NOUSE_SS",
	"MAX_BURST_APL",
	"EXPRESS_ROUTE",
	"NO_COPY_IN",
	"CACHED_SRC",
	"CWND_NOCUM",
	"CWND_SS",
	"CWND_CA",
	"CWND_SKIP",
	"CWND_NOUSE_CA",
	"MAX_CWND",
	"CWND_DIFF_CA",
	"CWND_DIFF_SA",
	"OQS_AT_SS",
	"SQQ_AT_SS",
	"OQS_AT_CA",
	"SQQ_AT_CA",
	"MOVED_MTU",
	"MOVED_QMAX",
	"SQC_AT_SS",
	"SQC_AT_CA",
	"MOVED_MAX",
	"MOVED_NLEF",
	"NAGLE_NOQ",
	"NAGLE_OFF",
	"OUTPUT_FRM_SND",
	"SOS_NOSNT",
	"NOS_NOSNT",
	"SOSE_NOSNT",
	"NOSE_NOSNT",
	"DATA_OUT_ERR",
	"DUP_SSN_RCVD",
	"DUP_FR",
	"VTAG_EXPR",
	"VTAG_BOGUS",
	"T3_SAFEGRD",
	"PDRP_FMBOX",
	"PDRP_FEHOS",
	"PDRP_MB_DA",
	"PDRP_MB_CT",
	"PDRP_BWRPT",
	"PDRP_CRUPT",
	"PDRP_NEDAT",
	"PDRP_PDBRK",
	NULL,
};
		
void
#if defined(__FreeBSD__)
sctp_stats(u_long off, char *name, int af)
#else /* NetBSD and OpenBSD */
sctp_stats(off, name)
        u_long off;
        char *name;
#endif
{
#if !defined(__FreeBSD__)
        int af;
#endif
	int i;
	u_int32_t pegs[SCTP_NUMBER_OF_PEGS];

	if (off == 0)
		return;

	kread(off, (char *)pegs, sizeof(pegs));
	
	printf("sctp:\n");
	for (i = 0; i < SCTP_NUMBER_OF_PEGS; i++) {
		if (pegs_name[i])
			printf("\t%10u :%s\n", pegs[i], pegs_name[i]);
	}
	return;
}
#endif /* SCTP */
