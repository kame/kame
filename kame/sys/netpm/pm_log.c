/*	$KAME: pm_log.c,v 1.4 2000/02/22 14:07:13 itojun Exp $	*/

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
//#	$SuMiRe: pm_log.c,v 1.7 1998/09/14 19:49:49 shin Exp $
//#	$Id: pm_log.c,v 1.4 2000/02/22 14:07:13 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_pm.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/kernel.h>
#include <sys/malloc.h>
#endif
#include <sys/types.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/in_pcb.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include "netpm/pm_insns.h"
#include "netpm/pm_defs.h"
#include "netpm/pm_log.h"
#include "netpm/pm_ioctl.h"			/* for struct _fwdRoute		*/
#include "netpm/pm_extern.h"

#if defined(PM_USE_SOCKET)
#include <sys/errno.h>
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

#if defined(PM_USE_SOCKET)
static struct sockaddr	_pm_dst = {2, PF_INET};
static struct sockaddr	_pm_src = {2, PF_INET};
#endif


#if defined(PM_USE_IOCTL)
struct	pmlsoftc
{
    int		sc_init;
    int		sc_open;
    int		sc_priorities;
    pid_t	sc_pgid;
    int		sc_state;
#define	LOG_RDWAIT	0x08
    struct  selinfo sc_selp;
}   pmlsoftc;


struct	pml
{
    u_int	 used;		/* Number of used lbuf.			*/
/*  size_t	 dsize;		   Amount of data in these lbufs.	*/
    struct lbuf *head;
    struct lbuf *tail;
}   pml;
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(PM_USE_SOCKET)
static	int	pm_logattSocket	    __P((int, aTT *));
static	int	pm_logrouteSocket   __P((struct mbuf *, struct _fwdRoute *));
static	int	pm_logipSocket	    __P((int, struct mbuf *));
static	int	pm_logSocket	    __P((int, int, void *, size_t));

void	pm_input	__P((struct mbuf *m0, struct sockproto *proto,
			     struct sockaddr *src, struct sockaddr *dst));
#endif

#if defined(PM_USE_IOCTL)
static	int	pm_logattIoctl	    __P((int, aTT *));
static	int	pm_logrouteIoctl    __P((struct mbuf *, struct _fwdRoute *));
static	int	pm_logipIoctl	    __P((int, struct mbuf *));
static	int	pm_logIoctl	    __P((int, int, void *, size_t));

static struct lbuf	*_allocateLbuf	__P((void));
static		 void	 _advanceTail	__P((struct pml *));
static	__inline void	 itoh1		__P((caddr_t, int));


int	 _pmSetLogLevel		__P((caddr_t addr));
void	 init_pmlog		__P((void));
int	 open_pmlog		__P((int, int, struct proc *));
int	 close_pmlog		__P((int, int, struct proc *));
int	 read_pmlog		__P((struct uio *, int));
int	 select_pmlog		__P((int, struct proc *));
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
pm_logatt(int stub, aTT *att)
{
#if defined(PM_USE_SOCKET)
    pm_logattSocket(stub, att);
#else
    pm_logattIoctl(stub, att);
#endif
}


void
pm_logroute(struct mbuf *m, struct _fwdRoute *fwd)
{
#if defined(PM_USE_SOCKET)
    pm_logrouteSocket(m, fwd);
#else
    pm_logrouteIoctl(m, fwd);
#endif
}


void
pm_logip(int pri, struct mbuf *mbuf)
{
#if defined(PM_USE_SOCKET)
    pm_logipSocket(pri, mbuf);
#else
    pm_logipIoctl(pri, mbuf);
#endif
}


void
pm_log(int type, int priorities, void *item, size_t size)
{
#if defined(PM_USE_SOCKET)
    pm_logSocket(type, priorities, item, size);
#else
    pm_logIoctl(type, priorities, item, size);
#endif
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(PM_USE_SOCKET)
static	int
pm_logattSocket(int stub, aTT *att)
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
    p0->lh_pri  = LOG_DEBUG;
    p0->lh_size = sizeof(struct l_att);
    microtime((struct timeval *)&p0->lh_sec);

    p1->_stub =  stub;
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
	pm_input(m0, &proto, &_pm_src, &_pm_dst);
    }

    return (0);
}


static	int
pm_logrouteSocket(struct mbuf *m, struct _fwdRoute *fwd)
{
    register	struct  lbuf	*p;

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
    fwdr->ip_p   = ip->ip_p;
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
	pm_input(m, &proto, &_pm_src, &_pm_dst);
    }

    return (0);
}


static	int
pm_logipSocket(int pri, struct mbuf *mbuf)
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

#if 	0
    bcopy(ip,           p->l_dat.__buf, min(LLEN, ip->ip_len));
    bcopy(mbuf->m_data, p->l_dat.__buf, m->m_len);
#else
    bcopy(mbuf->m_data, p->l_dat.__buf, min(LLEN, mbuf->m_len));
#endif

    {
	struct sockproto	proto;

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_PM;
	pm_input(m, &proto, &_pm_src, &_pm_dst);
    }

    return (0);
}


static	int
pm_logSocket(int type, int priorities, void *item, size_t size)
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
	proto.sp_protocol = IPPROTO_PM;
	pm_input(m, &proto, &_pm_src, &_pm_dst);
    }

    return (0);
}
#endif


#if defined(PM_USE_IOCTL)
static	int
pm_logattIoctl(int stub, aTT *att)
{
    register	struct	lbuf *p;

    p = _allocateLbuf();

    p->l_hdr.lh_type = LOG_ATT;
    p->l_hdr.lh_pri  = LOG_DEBUG;
    p->l_hdr.lh_size = roundup(sizeof(struct l_att), 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);
    bzero(p->l_dat.__buf, LLEN);
    p->l_dat.l_att._stub =  stub;
    p->l_dat.l_att._addr = (caddr_t)att;
    p->l_dat.l_att._att  = *att;
    if ((att->ip_p == IPPROTO_TCP)
	&& (att->suit.tcp))
	p->l_dat.l_att._state = *att->suit.tcp;

    selwakeup(&pmlsoftc.sc_selp);
    if (pmlsoftc.sc_state & LOG_RDWAIT)
    {
	wakeup((caddr_t)&pml);
	pmlsoftc.sc_state &= ~LOG_RDWAIT;
    }

    return (0);
}


static	int
pm_logrouteIoctl(struct mbuf *m, struct _fwdRoute *fwd)
{
    register	struct  lbuf	*p;

    struct _fwdRoute		*fwdr;
    struct ip			*ip = mtod(m, struct ip *);
    struct udpiphdr		*ui;

    p = _allocateLbuf();

    p->l_hdr.lh_type = LOG_ROUTE;
    p->l_hdr.lh_pri  = LOG_DEBUG;
    p->l_hdr.lh_size = roundup(sizeof(struct _fwdRoute), 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);
    bzero(p->l_dat.__buf, LLEN);
    fwdr = (struct _fwdRoute *)p->l_dat.__buf;
    fwdr->ip_src[0] = ip->ip_src;
    fwdr->ip_dst[0] = ip->ip_dst;
    fwdr->ip_p   = ip->ip_p;
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

    selwakeup(&pmlsoftc.sc_selp);
    if (pmlsoftc.sc_state & LOG_RDWAIT)
    {
	wakeup((caddr_t)&pml);
	pmlsoftc.sc_state &= ~LOG_RDWAIT;
    }

    return (0);
}


static	int
pm_logipIoctl(int pri, struct mbuf *mbuf)
{
    register	struct	lbuf *p;

    p = _allocateLbuf();

    p->l_hdr.lh_type = LOG_IP;
    p->l_hdr.lh_pri  = pri;
    p->l_hdr.lh_size = roundup(sizeof(struct l_att), 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);

#if 	0
    bcopy(ip,           p->l_dat.__buf, min(LLEN, ip->ip_len));
#else
    bcopy(mbuf->m_data, p->l_dat.__buf, min(LLEN, mbuf->m_len));
#endif

    selwakeup(&pmlsoftc.sc_selp);
    if (pmlsoftc.sc_state & LOG_RDWAIT)
    {
	wakeup((caddr_t)&pml);
	pmlsoftc.sc_state &= ~LOG_RDWAIT;
    }

    return (0);
}


static	int
pm_logIoctl(int type, int priorities, void *item, size_t size)
{
    register	struct	lbuf	*p;

    p = _allocateLbuf();

    p->l_hdr.lh_type = type;
    p->l_hdr.lh_pri  = priorities;
    p->l_hdr.lh_size = roundup(size, 4);
    microtime((struct timeval *)&p->l_hdr.lh_sec);

    bzero(p->l_dat.__buf, LLEN);
    bcopy(item, p->l_dat.__buf, min(size, LLEN-1));
    selwakeup(&pmlsoftc.sc_selp);
    if (pmlsoftc.sc_state & LOG_RDWAIT)
    {
	wakeup((caddr_t)&pml);
	pmlsoftc.sc_state &= ~LOG_RDWAIT;
    }

    return (0);
}


static	struct	lbuf *
_allocateLbuf()
{
    struct	lbuf *p;

    if (pml.used == 0)
    {
	MALLOC(p, struct lbuf *, LSIZE, M_PM, M_WAITOK);
	p->l_hdr.lh_next = NULL;
	pml.head = pml.tail = p;
	pml.used++;
    }
    else if (pml.used < PM_LOGMAX)
    {
	MALLOC(p, struct lbuf *, LSIZE, M_PM, M_WAITOK);
	p->l_hdr.lh_next = NULL;
	pml.head->l_hdr.lh_next = p;
	pml.head = p;
	pml.used++;
    }
    else
    {
	p = pml.tail;
	pml.tail = p->l_hdr.lh_next;
	pml.head->l_hdr.lh_next = p;
	pml.head = p;
    }

    return (p);
}
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

u_long
pm_ipopt(u_char *p, struct mbuf *mbuf, u_long k)
{
    return (0);
}


u_long
pm_packetlog(u_char *p, struct mbuf *mbuf, u_long k)
{
    return (0);
}


u_long
pm_icmp(u_char *p, struct mbuf *mbuf, u_long k)
{
    icmp_error(mbuf, ICMP_UNREACH, k, 0, NULL);
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


#if !defined(PM_USE_SOCKET)
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
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(PM_USE_IOCTL)
int
_pmSetLogLevel(caddr_t addr)
{
    pmlsoftc.sc_priorities = *(int *)addr;
    return (0);
}
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/


#if defined(PM_USE_IOCTL)
void
init_pmlog()
{
    int		iter;

    pmlsoftc.sc_open = 0;

    pml.used  = 0;
    pml.head = pml.tail = NULL;
}


int
open_pmlog(int flags, int mode, struct proc *p)
{
    if (pmlsoftc.sc_open)
	return (EBUSY);

    pmlsoftc.sc_open  = 1;
    pmlsoftc.sc_pgid  = p->p_pid;
    pmlsoftc.sc_state = 0;

    return (0);
}


int
close_pmlog(int flags, int mode, struct proc *p)
{
    pmlsoftc.sc_open  = 0;
    pmlsoftc.sc_state = 0;

    return (0);
}


int
read_pmlog(struct uio *uio, int flag)
{
    register	int	s;
		int	size;
		int	error = 0;

    if (uio->uio_resid == 0)
	return (0);

    s = splhigh();
    if (pml.used == 0)
    {
	if (flag & IO_NDELAY)
	{
	    splx(s);
	    return (EWOULDBLOCK);
	}
	pmlsoftc.sc_state |= LOG_RDWAIT;
	error = tsleep((caddr_t)&pml, LOG_RDPRI | PCATCH, "pmlog", 0);
	if (error != 0)
	{
	    splx(s);
	    return (error);
	}
    }

    pmlsoftc.sc_state &= ~LOG_RDWAIT;

    uio->uio_rw = UIO_READ;
    while (pml.used > 0)
    {
	if (pml.tail->l_hdr.lh_size > uio->uio_resid)
	{
	    splx(s);
	    return (error);
	}	    

	size = pml.tail->l_hdr.lh_size + sizeof(struct l_hdr);
	if ((error = uiomove((caddr_t)pml.tail, size, uio)) != 0)
	    break;
	_advanceTail(&pml);
    }

    splx(s);
    return (error);
}


static	void
_advanceTail(struct pml *pml)
{
    if (pml->used == 1)
    {
	FREE(pml->tail, M_PM);
	pml->used = 0;
	pml->head = pml->tail = NULL;
    }
    else
    {
	struct lbuf *p;

	p = pml->tail;
	pml->tail = pml->tail->l_hdr.lh_next;
	FREE(p, M_PM);
	pml->used--;
    }
    
}


int
select_pmlog(int rw, struct proc *p)
{
    switch (rw)
    {
      case FREAD:
	if (pml.used != 0)
	{
	    return (1);
	}
	selrecord(p, &pmlsoftc.sc_selp);
	break;

      case FWRITE:
      case 0:
	break;
    }

    return (0);
}
#endif	/* PM_USE_IOCTL	*/
