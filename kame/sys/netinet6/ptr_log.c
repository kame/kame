/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$Id: ptr_log.c,v 1.1 1999/08/12 12:41:12 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_ptr.h"
#endif

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/systm.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/ptr_log.h>

#if	0
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/syslog.h>

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	PM_LOGMAX	64
#define	LOG_RDPRI	(PZERO + 1)


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static struct sockaddr	_ptr_dst = {2, PF_INET};
static struct sockaddr	_ptr_src = {2, PF_INET};


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if	0
static	int	ptr_logattSocket	    __P((int, aTT *));
static	int	ptr_logrouteSocket   __P((struct mbuf *, struct _fwdRoute *));
static	int	ptr_logipSocket	    __P((int, struct mbuf *));
#endif

int	ptr_log		__P((int, int, void *, size_t));

void	ptr_input	__P((struct mbuf *m0, struct sockproto *proto,
			     struct sockaddr *src, struct sockaddr *dst));

char	*itoh		__P((char *, int));
static	__inline void	 itoh1		__P((caddr_t, int));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if	0
void
ptr_logatt(int stub, aTT *att)
{
    ptr_logattSocket(stub, att);
}
#endif


#if	0
void
ptr_logroute(struct mbuf *m, struct _fwdRoute *fwd)
{
    ptr_logrouteSocket(m, fwd);
}
#endif


#if	0
void
ptr_logip(int pri, struct mbuf *mbuf)
{
    ptr_logipSocket(pri, mbuf);
}
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if	0
static	int
ptr_logattSocket(int stub, aTT *att)
{
    register	struct	mbuf	*m0, *m1;
    register	struct	l_hdr	*p0;
    register	struct	l_att	*p1;

    MGETHDR(m0, M_DONTWAIT, MT_DATA);
    if (m0 == NULL)
	return (ENOBUFS);
    
    MGET(m1, M_DONTWAIT, MT_DATA);
    if (m1 == NULL)
    {
	m_freem(m0);
	return (ENOBUFS);
    }

    m0->m_len = sizeof(struct l_hdr);
    m1->m_len = sizeof(struct l_att);

    m0->m_pkthdr.len = m0->m_len + m1->m_len;
    m0->m_pkthdr.rcvif = NULL;
    
    p0 = mtod(m0, struct l_hdr *);
    p1 = mtod(m1, struct l_att *);

    p0->lh_type = LOG_ATT;
    p0->lh_pri	= LOG_DEBUG;
    p0->lh_size = sizeof(struct l_att);
    microtime((struct timeval *)&p0->lh_sec);

    p1->_stub =	 stub;
    p1->_addr = (caddr_t)att;
    p1->_att  = *att;
    if ((att->ip_p == IPPROTO_TCP)
	&& (att->suit.tcp))
	p1->_state = *att->suit.tcp;
    else
	bzero(&p1->_state, sizeof(p1->_state));

    {
	struct sockproto	proto;

	m0->m_next = m1;

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_PM;
	ptr_input(m0, &proto, &_ptr_src, &_ptr_dst);
    }

    return (0);
}
#endif


#if	0
static	int
ptr_logrouteSocket(struct mbuf *m, struct _fwdRoute *fwd)
{
    register	struct	lbuf	*p;

    struct _fwdRoute		*fwdr;
    struct ip			*ip = mtod(m, struct ip *);
    struct udpiphdr		*ui;

    MGETHDR(m, M_DONTWAIT, MT_DATA);
    if (m == NULL)
	return (ENOBUFS);
    m->m_pkthdr.len
	= m->m_len
	    = sizeof(struct l_hdr) + roundup(sizeof(struct _fwdRoute), 4);
    m->m_pkthdr.rcvif = NULL;

    p = mtod(m, struct lbuf *);
    p->l_hdr.lh_type = LOG_ROUTE;
    p->l_hdr.lh_pri  = LOG_DEBUG;
    p->l_hdr.lh_size = roundup(sizeof(struct _fwdRoute), 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);
    bzero(p->l_dat.__buf, LLEN);
    fwdr = (struct _fwdRoute *)p->l_dat.__buf;
    fwdr->ip_src[0] = ip->ip_src;
    fwdr->ip_dst[0] = ip->ip_dst;
    fwdr->ip_p	 = ip->ip_p;
    if (fwd != NULL)
	fwdr->ip_via = fwd->ip_via;

    if ((ip->ip_p == IPPROTO_TCP)
	|| (ip->ip_p == IPPROTO_UDP))
    {
	ui = mtod(m, struct udpiphdr *);
	fwdr->th_sport[0] = ui->ui_sport;
	fwdr->th_dport[0] = ui->ui_dport;
    }

#if	0
    *(struct _fwdRoute *)p->l_dat.__buf = *fwd;
#endif

    {
	struct sockproto	proto;

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_PM;
	ptr_input(m, &proto, &_ptr_src, &_ptr_dst);
    }

    return (0);
}
#endif


#if	0
static	int
ptr_logipSocket(int pri, struct mbuf *mbuf)
{
    struct	mbuf	*m;
    struct	lbuf	*p;

    MGETHDR(m, M_DONTWAIT, MT_DATA);
    m->m_pkthdr.len
	= m->m_len
	    = sizeof(struct l_hdr) + min(LLEN, mbuf->m_len);
    m->m_pkthdr.rcvif = NULL;

    p = mtod(m, struct lbuf *);
    p->l_hdr.lh_type = LOG_IP;
    p->l_hdr.lh_pri  = pri;
    p->l_hdr.lh_size = roundup(sizeof(struct l_att), 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);

#if	0
    bcopy(ip,		p->l_dat.__buf, min(LLEN, ip->ip_len));
    bcopy(mbuf->m_data, p->l_dat.__buf, m->m_len);
#else
    bcopy(mbuf->m_data, p->l_dat.__buf, min(LLEN, mbuf->m_len));
#endif

    {
	struct sockproto	proto;

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_PM;
	ptr_input(m, &proto, &_ptr_src, &_ptr_dst);
    }

    return (0);
}
#endif


int
ptr_log(int type, int priorities, void *item, size_t size)
{
    register	struct	mbuf	*m;
    register	struct	lbuf	*p;

    MGETHDR(m, M_DONTWAIT, MT_DATA);
    if (m == NULL)
	return (ENOBUFS);
    m->m_pkthdr.len = m->m_len = roundup(size, 4);
    m->m_pkthdr.rcvif = NULL;

    p = (struct lbuf *)m->m_pktdat;
    p->l_hdr.lh_type = type;
    p->l_hdr.lh_pri  = priorities;
    p->l_hdr.lh_size = roundup(size, 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);

    {
	struct sockproto	proto;

	m_copyback(m, sizeof(struct l_hdr), p->l_hdr.lh_size, (caddr_t)item);

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_PTR;
	ptr_input(m, &proto, &_ptr_src, &_ptr_dst);
    }

    return (0);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(__bsdi__)
#define	UC(b)	(((int)b) & 0xff)

char *
inet_ntoa(struct in_addr in)
{
    register char    *p;
    static   char   idx;
    static   char   Wow[4][16];

    p = (char *)&in;
    sprintf(Wow[++idx & 0x3], "%d.%d.%d.%d%c",
	    UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]), '\0');

    return (Wow[idx & 0x3]);
}
#endif


char *
itoh(char *Wow, int one)
{
    char	*s, *d;

    s = (char *)&one;
    d = Wow;
    itoh1(&Wow[0], s[0] >> 1);
    itoh1(&Wow[1], s[0] >> 4);
    itoh1(&Wow[2], s[1] >> 1);
    itoh1(&Wow[3], s[1] >> 4);
    itoh1(&Wow[4], s[2] >> 1);
    itoh1(&Wow[5], s[2] >> 4);
    itoh1(&Wow[6], s[3] >> 1);
    itoh1(&Wow[7], s[3] >> 4);
    Wow[8] = '\0';
    
    return (Wow);
}


static __inline void
itoh1(caddr_t addr, int val)
{
     char	tp;

     tp = (val & 0x0f) + '0';
     if (tp > '9')	tp += 39;
     *addr = tp;
}
