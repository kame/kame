/*	$OpenBSD: ip_var.h,v 1.22 2002/03/14 01:27:11 millert Exp $	*/
/*	$NetBSD: ip_var.h,v 1.16 1996/02/13 23:43:20 christos Exp $	*/

/*
 * Copyright (c) 2002 INRIA. All rights reserved.
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
 *	This product includes software developed by INRIA and its
 *	contributors.
 * 4. Neither the name of INRIA nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Implementation of Internet Group Management Protocol, Version 3.
 *
 * Developed by Hitoshi Asaeda, INRIA, February 2002.
 */

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
 *
 *	@(#)ip_var.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_IP_VAR_H_
#define _NETINET_IP_VAR_H_

#include <sys/queue.h>

/*
 * Overlay for ip header used by other protocols (tcp, udp).
 */
struct ipovly {
	u_int8_t  ih_x1[9];		/* (unused) */
	u_int8_t  ih_pr;		/* protocol */
	u_int16_t ih_len;		/* protocol length */
	struct	  in_addr ih_src;	/* source internet address */
	struct	  in_addr ih_dst;	/* destination internet address */
};

/*
 * Ip (reassembly or sequence) queue structures.
 *
 * XXX -- The following explains why the ipqe_m field is here, for TCP's use:
 * We want to avoid doing m_pullup on incoming packets but that
 * means avoiding dtom on the tcp reassembly code.  That in turn means
 * keeping an mbuf pointer in the reassembly queue (since we might
 * have a cluster).  As a quick hack, the source & destination
 * port numbers (which are no longer needed once we've located the
 * tcpcb) are overlayed with an mbuf pointer.
 */
LIST_HEAD(ipqehead, ipqent);
struct ipqent {
	LIST_ENTRY(ipqent) ipqe_q;
	union {
		struct ip	*_ip;
		struct tcphdr	*_tcp;
	} _ipqe_u1;
	struct mbuf	*ipqe_m;	/* mbuf contains packet */
	u_int8_t	ipqe_mff;	/* for IP fragmentation */
};
#define	ipqe_ip		_ipqe_u1._ip
#define	ipqe_tcp	_ipqe_u1._tcp

/*
 * Ip reassembly queue structure.  Each fragment
 * being reassembled is attached to one of these structures.
 * They are timed out after ipq_ttl drops to 0, and may also
 * be reclaimed if memory becomes tight.
 */
struct ipq {
	LIST_ENTRY(ipq) ipq_q;		/* to other reass headers */
	u_int8_t  ipq_ttl;		/* time for reass q to live */
	u_int8_t  ipq_p;		/* protocol of this fragment */
	u_int16_t ipq_id;		/* sequence id for reassembly */
	struct	  ipqehead ipq_fragq;	/* to ip fragment queue */
	struct	  in_addr ipq_src, ipq_dst;
};

/*
 * Structure stored in mbuf in inpcb.ip_options
 * and passed to ip_output when ip options are in use.
 * The actual length of the options (including ipopt_dst)
 * is in m_len.
 */
#define	MAX_IPOPTLEN	40

struct ipoption {
	struct	in_addr ipopt_dst;	/* first-hop dst if source routed */
	int8_t	ipopt_list[MAX_IPOPTLEN];	/* options proper */
};

/*
 * Socket argument of multicast source filters.
 */
LIST_HEAD(msf_head, sock_msf_source);

struct sock_msf_source {
	struct	  sockaddr_storage src;	/* source address */
	LIST_ENTRY(sock_msf_source) list; /* list of source addresses */
	u_int	refcount;		/* reference count of the source */
};

struct sock_msf {
/*	u_int32_t msf_mode;		 * source filter mode */
	u_int	  msf_grpjoin;		/* number of (*,G) join requests */
	struct	  msf_head *msf_head;	/* head of joined source list chain */
	struct	  msf_head *msf_blkhead;/* head of muted source list chain */
	u_int16_t msf_numsrc;		/* no. of joined src on this socket */
	u_int16_t msf_blknumsrc;	/* no. of muted src on this socket */
};

/*
 * Structure attached to inpcb.ip_moptions and
 * passed to ip_output when IP multicast options are in use.
 */
struct ip_moptions {
	struct	  ifnet *imo_multicast_ifp; /* ifp for outgoing multicasts */
	struct in_addr imo_multicast_addr; /* ifindex/addr on MULTICAST_IF */
	u_int8_t  imo_multicast_ttl;	/* TTL for outgoing multicasts */
	u_int8_t  imo_multicast_loop;	/* 1 => hear sends if a member */
	u_int16_t imo_num_memberships;	/* no. memberships this socket */
	struct	  in_multi *imo_membership[IP_MAX_MEMBERSHIPS];
	struct	  sock_msf *imo_msf[IP_MAX_MEMBERSHIPS];
};

struct	ipstat {
	u_long	ips_total;		/* total packets received */
	u_long	ips_badsum;		/* checksum bad */
	u_long	ips_tooshort;		/* packet too short */
	u_long	ips_toosmall;		/* not enough data */
	u_long	ips_badhlen;		/* ip header length < data size */
	u_long	ips_badlen;		/* ip length < ip header length */
	u_long	ips_fragments;		/* fragments received */
	u_long	ips_fragdropped;	/* frags dropped (dups, out of space) */
	u_long	ips_fragtimeout;	/* fragments timed out */
	u_long	ips_forward;		/* packets forwarded */
	u_long	ips_cantforward;	/* packets rcvd for unreachable dest */
	u_long	ips_redirectsent;	/* packets forwarded on same net */
	u_long	ips_noproto;		/* unknown or unsupported protocol */
	u_long	ips_delivered;		/* datagrams delivered to upper level*/
	u_long	ips_localout;		/* total ip packets generated here */
	u_long	ips_odropped;		/* lost packets due to nobufs, etc. */
	u_long	ips_reassembled;	/* total packets reassembled ok */
	u_long	ips_fragmented;		/* datagrams sucessfully fragmented */
	u_long	ips_ofragments;		/* output fragments created */
	u_long	ips_cantfrag;		/* don't fragment flag was set, etc. */
	u_long	ips_badoptions;		/* error in option processing */
	u_long	ips_noroute;		/* packets discarded due to no route */
	u_long	ips_badvers;		/* ip version != 4 */
	u_long	ips_rawout;		/* total raw ip packets generated */
	u_long	ips_badfrags;		/* malformed fragments (bad length) */
	u_long	ips_rcvmemdrop;		/* frags dropped for lack of memory */
	u_long	ips_toolong;		/* ip length > max ip packet size */
	u_long	ips_nogif;		/* no match gif found */
	u_long	ips_badaddr;		/* invalid address on header */
	u_long	ips_inhwcsum;		/* hardware checksummed on input */
	u_long	ips_outhwcsum;		/* hardware checksummed on output */
};

#ifdef _KERNEL
/* flags passed to ip_output as last parameter */
#define	IP_FORWARDING		0x1		/* most of ip header exists */
#define	IP_RAWOUTPUT		0x2		/* raw ip header exists */
#define	IP_ROUTETOIF		SO_DONTROUTE	/* bypass routing tables */
#define	IP_ALLOWBROADCAST	SO_BROADCAST	/* can send broadcast packets */
#define	IP_MTUDISC		0x0400		/* pmtu discovery, set DF */

struct	  ipstat ipstat;
LIST_HEAD(ipqhead, ipq)	ipq;		/* ip reass. queue */
int	  ip_defttl;			/* default IP ttl */

int   ip_mtudisc;		/* mtu discovery */
u_int ip_mtudisc_timeout;	/* seconds to timeout mtu discovery */
struct rttimer_queue *ip_mtudisc_timeout_q;
extern int   igmpmaxsrcfilter;		/* maximum num. of msf per interface */
extern int   igmpsomaxsrc;		/* maximum num. of msf per socket */
extern struct pool ipqent_pool;

int	 ip_ctloutput(int, struct socket *, int, int, struct mbuf **);
int	 ip_dooptions(struct mbuf *);
void	 ip_drain(void);
void	 ip_flush(void);
void	 ip_forward(struct mbuf *, int);
void	 ip_freef(struct ipq *);
void	 ip_freemoptions(struct ip_moptions *);
int	 ip_getmoptions(int, struct ip_moptions *, struct mbuf **);
void	 ip_init(void);
int	 ip_mforward(struct mbuf *, struct ifnet *);
int	 ip_optcopy(struct ip *, struct ip *);
int	 ip_output(struct mbuf *, ...);
int	 ip_pcbopts(struct mbuf **, struct mbuf *);
struct mbuf *
	 ip_reass(struct ipqent *, struct ipq *);
struct in_ifaddr *
	 in_iawithaddr(struct in_addr, struct mbuf *);
struct in_ifaddr *
	 ip_rtaddr(struct in_addr);
u_int16_t	
	 ip_randomid(void);
int	 ip_setmoptions(int, struct ip_moptions **, struct mbuf *);
void	 ip_slowtimo(void);
struct mbuf *
	 ip_srcroute(void);
void	 ip_stripoptions(struct mbuf *, struct mbuf *);
int	 ip_sysctl(int *, u_int, void *, size_t *, void *, size_t);
void	 ipintr(void);
void	 ipv4_input(struct mbuf *);
int	 rip_ctloutput(int, struct socket *, int, int, struct mbuf **);
void	 rip_init(void);
void	 rip_input(struct mbuf *, ...);
int	 rip_output(struct mbuf *, ...);
int	 rip_usrreq(struct socket *,
	    int, struct mbuf *, struct mbuf *, struct mbuf *);

struct ifnet *
	 ip_multicast_if(struct in_addr *, int *);
int	 ip_check_router_alert(struct ip *);
int	 ip_getmopt_msflist(struct sock_msf *, u_int16_t *,
			    struct sockaddr_storage **, u_int *);
#endif /* _KERNEL */
#endif /* _NETINET_IP_VAR_H_ */
