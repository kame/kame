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
//#	$SuMiRe: pm_aTT.c,v 1.9 1998/09/14 19:49:32 shin Exp $
//#	$Id: pm_aTT.c,v 1.1 1999/08/12 12:41:07 shin Exp $
//#
//#------------------------------------------------------------------------
*/

#include <netpm/pm_include.h>

#include <netinet/ip_icmp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>

#include <sys/kernel.h>

#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	PM_MAXHASH	397
#if	maybeNotUsed
#define	PM_HASH(ipa)	(((((u_long)ipa >> 24) & 0xff) +		\
			  (((u_long)ipa >> 16) & 0xff) +		\
			  (((u_long)ipa >>  8) & 0xff) +		\
			  (((u_long)ipa >>  0) & 0xff)) % PM_MAXHASH)
#endif


#define	LOCALHASH	0
#define	REMOTEHASH	1
#define	FOREIGNHASH	2


static	Cell	*_localHash  [PM_MAXHASH];
static	Cell	*_remoteHash [PM_MAXHASH];
static	Cell	*_foreignHash[PM_MAXHASH];


static	Cell	*attEntryList;
static	int	 maxAttEntry;
static	int	 usedAttEntry;

static	Cell	*incomingPermit;

static	time_t	 attTimer;
static	time_t	 maxTTLany;
static	time_t	 maxTTLicmp;
static	time_t	 maxTTLudp;
static	time_t	 maxTTLtcp;

static	time_t	 _pm_TCPT_2MSL;
static	time_t	 _pm_tcp_maxidle;


#if defined(__FreeBSD__)
SYSCTL_INT(_net_inet_pm_nat, OID_AUTO, maxTTLany,  CTLFLAG_RW, &maxTTLany,  0, "");
SYSCTL_INT(_net_inet_pm_nat, OID_AUTO, maxTTLicmp, CTLFLAG_RW, &maxTTLicmp, 0, "");
SYSCTL_INT(_net_inet_pm_nat, OID_AUTO, maxTTLudp,  CTLFLAG_RW, &maxTTLudp , 0, "");
SYSCTL_INT(_net_inet_pm_nat, OID_AUTO, maxTTLtcp,  CTLFLAG_RW, &maxTTLtcp , 0, "");

SYSCTL_INT(_net_inet_pm_nat, OID_AUTO, TCPT_2MS,    CTLFLAG_RW, &_pm_TCPT_2MSL,   0, "");
SYSCTL_INT(_net_inet_pm_nat, OID_AUTO, tcp_maxidle, CTLFLAG_RW, &_pm_tcp_maxidle, 0, "");
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

	aTT	*lookingForICMPEcho	__P((IPAssoc *, struct ip *, struct icmp *));
	void	 _markFootPrint		__P((int, u_long, u_short, u_long, u_short, u_long, u_short));
	aTT	*_scanFootPrint		__P((struct ip *));

static	void	 _expireTableEntry	__P((void *ignored_arg));
static	void	 _expireAttEntry	__P((struct timeval *atv));
static	void	 _removeAttEntry	__P((aTT *));
static	void	 _expireFootPrint	__P((struct timeval *atv));

static	Cell	* _internLocalHash	__P((aTT *));
static	Cell	* _internRemoteHash	__P((aTT *));
static	Cell	* _internForeignHash	__P((aTT *));
static	aTT	*_lookingForLocalHash	__P((IPAssoc *));
static	aTT	*_lookingForRemoteHash	__P((IPAssoc *));
static	aTT	*_lookingForForeignHash	__P((int, u_long, u_short));
#if	maybeNotUsed
	aTT	*_lookingForAttEntry	__P((int, u_long, u_short, u_long, u_short));
#endif
static	Cell	*_internHash		__P((Cell *(*)[], int, caddr_t));
static	int	 _removeHash		__P((Cell *(*)[], int, caddr_t));

static	int	 _hash_att		__P((aTT *, int));
static	int	 _hash_foreign		__P((u_long, u_short));
static	int	 _hash_ipa		__P((IPAssoc *));
static	int	 _hash_pjw		__P((u_char *s, int));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

aTT *
ckAppearance(int proto, u_long addr, u_short port)
{
    return (_lookingForForeignHash(proto, addr, port));
}


aTT *
pm_asAttEntry(IPAssoc *ipa)
{
    aTT		*att = NULL;

    if (ipa->inout == InBound)
	att = _lookingForRemoteHash(ipa);
    else
	att = _lookingForLocalHash (ipa);

    return (att);
}


aTT *
addAttEntry(IPAssoc *ipa, AliasPair *ap)
{
    register    aTT	*att;

    MALLOC(att, aTT *, sizeof(aTT), M_PM, M_NOWAIT);
    if (att == NULL)
    {
	char	Wow[128];

	sprintf(Wow, "Cannot allocate aTT.\n");
	pm_log(LOG_MSG, LOG_NOTICE, Wow, strlen(Wow));
	return (NULL);
    }

    bzero(att, sizeof(aTT));
    
    att->pm_type         = ap->pm_type;
    att->ip_p            = ipa->ip_p;
    att->th_rport        = ipa->th_dport;
    att->ip_raddr.s_addr = ipa->ip_dst.s_addr;

    if (ipa->inout == InBound)
    {
	/*	local   <-  ap.foreign					*/
	/*	foreign <- ipa.dst					*/
	/*	remote  <- ipa.src					*/

	att->th_lport        =  ap->th_fport;
	att->th_fport        = ipa->th_dport;
	att->th_rport        = ipa->th_sport;
	att->ip_laddr.s_addr =  ap->ip_laddr.s_addr;
	att->ip_faddr.s_addr = ipa->ip_dst.s_addr;
	att->ip_raddr.s_addr = ipa->ip_src.s_addr;

#if defined(PM_SYSLOG)
	log(LOG_INFO, "[ld] %s %s.%d > (%s.%d) > %s.%d\n",
	    ((ipa->ip_p == IPPROTO_ICMP) ? "icmp"
	    : (ipa->ip_p == IPPROTO_TCP) ? "tcp "
	    : (ipa->ip_p == IPPROTO_UDP) ? "udp "
	    : "unk "),
	    inet_ntoa(ipa->ip_src),  ntohs(ipa->th_sport),
	    inet_ntoa(ipa->ip_dst),  ntohs(ipa->th_dport),
	    inet_ntoa(ap->ip_laddr), ntohs(ap->th_fport));
#else
	pm_logatt(ATT_ALLOC, att);
#endif
    }
    else
    {
	/*	local   <- ipa.src					*/
	/*	foreign	<-  ap.foreign					*/
	/*	remote  <- ipa.dst					*/

	att->th_lport        = ipa->th_sport;
	att->th_fport        =  ap->th_fport;
	att->th_rport        = ipa->th_dport;
	att->ip_laddr.s_addr = ipa->ip_src.s_addr;
	att->ip_faddr.s_addr =  ap->ip_faddr.s_addr;
	att->ip_raddr.s_addr = ipa->ip_dst.s_addr;

#if defined(PM_SYSLOG)
	log(LOG_INFO, "[ld] %s %s.%d > (%s.%d) > %s.%d\n",
	    ((ipa->ip_p == IPPROTO_ICMP) ? "icmp"
	    : (ipa->ip_p == IPPROTO_TCP) ? "tcp "
	    : (ipa->ip_p == IPPROTO_UDP) ? "udp "
	    : "unk "),
	    inet_ntoa(ipa->ip_src),  ntohs(ipa->th_sport),
	    inet_ntoa(ap->ip_faddr), ntohs(ap->th_fport),
	    inet_ntoa(ipa->ip_dst),  ntohs(ipa->th_dport));
#else
	pm_logatt(ATT_ALLOC, att);
#endif
    }

    att->_u.imm[0] = ap->_u.imm[0];
    att->_u.imm[1] = ap->_u.imm[1];
    
    if (registAttEntry(att) == NULL)
    {
	FREE(att, M_PM);
	return (NULL);
    }

    return (att);
}


aTT *
registAttEntry(aTT *att)
{
    struct	timeval	 atv;

    if (usedAttEntry >= maxAttEntry)
	return (NULL);

    usedAttEntry++;
    microtime(&atv);
    att->tstamp = atv.tv_sec;
    att->inbound = att->outbound = 0;
    att->suit.tcp = NULL;

    {
	Cell	*p;

	p = LST_cons(att, NIL);
	if (attEntryList == NULL)
	    attEntryList = p;
	else
	    CDR(p) = attEntryList, attEntryList = p;
    }
    _internLocalHash  (att);
    _internRemoteHash (att);
    _internForeignHash(att);

    pm_logatt(ATT_REGIST, att);

    return (att);
}


void
pm_removeAttEntry(aTT *att)
{
    _removeAttEntry(att);
}


aTT *
lookingForICMPEcho(IPAssoc *ipa, struct ip *ip, struct icmp *icp)
{
    register	Cell	*p;
    register	aTT	*att;

    int		 hv = _hash_ipa(ipa);

    for (p = _remoteHash[hv]; p; p = CDR(p))
    {
	att = (aTT *)CAR(p);

	if ((att->ip_p == IPPROTO_ICMP)
	    && (att->ip_raddr.s_addr == ip->ip_src.s_addr)
	    && (att->ip_faddr.s_addr == ip->ip_dst.s_addr)
	    && (att->suit.ih_idseq.icd_id  == icp->icmp_id)
	    && (att->suit.ih_idseq.icd_seq == icp->icmp_seq))
	    return (att);
    }

    return (NULL);
}


void
_markFootPrint(int proto,
	       u_long laddr, u_short lport,
	       u_long faddr, u_short fport,
	       u_long raddr, u_short rport)
{
    Cell		*p;
    aTT			*att;
    struct timeval	 atv;

    for (p = incomingPermit; p; p = CDR(p))
    {
	att = (aTT *)CAR(p);
	if ((att->ip_faddr.s_addr == faddr)
	    && (att->th_fport == fport))
	    return;
    }

    MALLOC(att, aTT *, sizeof(aTT), M_PM, M_WAITOK);
    bzero(att, sizeof(aTT));

    microtime(&atv);
    att->tstamp = atv.tv_sec;

    att->pm_type = NAT_DYNAMIC;
    att->ip_p    = proto;
    att->ip_laddr.s_addr = laddr;
    att->ip_faddr.s_addr = faddr;
    att->ip_raddr.s_addr = raddr;
    att->th_lport = lport;
    att->th_fport = fport;
    att->th_rport = rport;

    LST_hookup_list(&incomingPermit, att);
    pm_logatt(ATT_FASTEN, att);
}


aTT *
_scanFootPrint(struct ip *ip)
{
    Cell		*p;
    struct tcpiphdr	*ti = (struct tcpiphdr *)ip;

    aTT			*att;

    for (p = incomingPermit; p; p = CDR(p))
    {
	att = (aTT *)CAR(p);

	if ((ip->ip_p == att->ip_p)
	    && (ip->ip_src.s_addr == att->ip_raddr.s_addr)
	    && (ip->ip_dst.s_addr == att->ip_faddr.s_addr))
	{
	    LST_remove_elem(&incomingPermit, att);

	    return (registAttEntry(att));
	}
    }
    return (NULL);
}


int
init_aTT()
{
    attEntryList = NULL;

    maxAttEntry  = MAXATTENTRY;
    usedAttEntry = 0;

    attTimer = 60 * hz;	/* _expireTableEntry was invoked every minutes	*/
    timeout(_expireTableEntry, (caddr_t)0, attTimer);

    _pm_TCPT_2MSL   = 120;				/* [sec]	*/
    _pm_tcp_maxidle = 600;				/* [sec]	*/

    maxTTLicmp = maxTTLudp = _pm_TCPT_2MSL;
    maxTTLtcp  = maxTTLany = 86400;			/* [sec]	*/

    return (0);
}


void
init_hash()
{
    bzero((caddr_t)_localHash,   sizeof(_localHash));
    bzero((caddr_t)_remoteHash,  sizeof(_remoteHash));
    bzero((caddr_t)_foreignHash, sizeof(_foreignHash));
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	void
_expireTableEntry(void *ignored_arg)
{
    struct	timeval	atv;
    int		s;

    s = splnet();
    
    timeout(_expireTableEntry, (caddr_t)0, attTimer);
    microtime(&atv);

    _expireAttEntry(&atv);
    _expireFootPrint(&atv);

    splx(s);
}


static	void
_expireAttEntry(struct timeval *atv)
{
    register	Cell	*p;
    register	aTT	*att;

    p = attEntryList;
    while(p)
    {
	att = (aTT *)CAR(p);
	p = CDR(p);

	switch (att->ip_p)
	{
	  case IPPROTO_ICMP:
	    if ((atv->tv_sec - att->tstamp) >= maxTTLicmp)
		_removeAttEntry(att);
	    break;

	  case IPPROTO_UDP:
	    if ((atv->tv_sec - att->tstamp) >= maxTTLudp)
		_removeAttEntry(att);
	    break;

	  case IPPROTO_TCP:
	    switch (att->suit.tcp->_state)
	    {
	      case TCPS_CLOSED:
		if ((atv->tv_sec - att->tstamp) >= _pm_TCPT_2MSL)
		    _removeAttEntry(att);
		break;

	      case TCPS_SYN_SENT:
	      case TCPS_SYN_RECEIVED:
		if ((atv->tv_sec - att->tstamp) >= _pm_tcp_maxidle)
		    _removeAttEntry(att);
		break;

	      case TCPS_ESTABLISHED:
		if ((atv->tv_sec - att->tstamp) >= maxTTLtcp)
		    _removeAttEntry(att);
		break;

	      case TCPS_FIN_WAIT_1:
	      case TCPS_FIN_WAIT_2:
		if ((atv->tv_sec - att->tstamp) >= _pm_tcp_maxidle)
		    _removeAttEntry(att);
		break;
		
	      case TCPS_TIME_WAIT:
		if ((atv->tv_sec - att->tstamp) >= _pm_TCPT_2MSL)
		    _removeAttEntry(att);
		break;

	      default:
		if ((atv->tv_sec - att->tstamp) >= maxTTLtcp)
		    _removeAttEntry(att);
		break;
	    }
	    break;

	  default:
	    if ((atv->tv_sec - att->tstamp) >= maxTTLany)
		_removeAttEntry(att);
	    break;
	}
    }
}


static	void
_removeAttEntry(aTT *att)
{
    if (att->ip_p == IPPROTO_TCP)
    {
	if (att->suit.tcp)
	{
	    FREE(att->suit.tcp, M_PM);
	}
    }

    usedAttEntry--;
    _removeHash(&_localHash,   _hash_att(att, LOCALHASH),   (caddr_t)att);
    _removeHash(&_remoteHash,  _hash_att(att, REMOTEHASH),  (caddr_t)att);
    _removeHash(&_foreignHash, _hash_att(att, FOREIGNHASH), (caddr_t)att);

    LST_remove_elem(&attEntryList, att);

    pm_logatt(ATT_REMOVE, att);

    FREE(att, M_PM);
}


static	void
_expireFootPrint(struct timeval *atv)
{
    register	Cell	*p;
    register	aTT	*att;

    p = incomingPermit;
    while (p)
    {
	att = (aTT *)CAR(p);
	p = CDR(p);

	if ((atv->tv_sec - att->tstamp) >= _pm_TCPT_2MSL)
	{
	    pm_logatt(ATT_UNFASTEN, att);
	    LST_remove_elem(&incomingPermit, att);
	    FREE(att, M_PM);
	}
    }
}


static	Cell *
_internLocalHash(aTT *att)
{
    return (_internHash(&_localHash, _hash_att(att, LOCALHASH), (caddr_t)att));
}


static	Cell *
_internRemoteHash(aTT *att)
{
    return (_internHash(&_remoteHash, _hash_att(att, REMOTEHASH), (caddr_t)att));
}


static	Cell *
_internForeignHash(aTT *att)
{
    return (_internHash(&_foreignHash, _hash_att(att, FOREIGNHASH), (caddr_t)att));
}


static	aTT *
_lookingForLocalHash(register IPAssoc *ipa)
{
    register	Cell	*p;
    register	aTT	*att;

    int		 hv = _hash_ipa(ipa);

    for (p = _localHash[hv]; p; p = CDR(p))
    {
	att = (aTT *)CAR(p);

	if (ipa->ip_p == att->ip_p)
	{
	    if (ipa->ip_p == IPPROTO_ICMP)		goto raddr;
	    else					goto lport;
	}
	continue;

      lport:;
	if (ipa->th_sport == att->th_lport)		goto rport;
	continue;

      rport:;
	if (ipa->th_dport == att->th_rport)		goto raddr;
	continue;

      raddr:;
	if (ipa->ip_dst.s_addr == att->ip_raddr.s_addr)	
	{
	    return (att);
	}
    }

    return (NULL);
}


static	aTT *
_lookingForRemoteHash(register IPAssoc *ipa)
{
    register	Cell	*p;
    register	aTT	*att;

    int		 hv = _hash_ipa(ipa);

    for (p = _remoteHash[hv]; p; p = CDR(p))
    {
	att = (aTT *)CAR(p);

	if (ipa->ip_p == att->ip_p)
	{
	    if (ipa->ip_p == IPPROTO_ICMP)		goto raddr;
	    else					goto fport;
	}
	continue;

      fport:;
	if (ipa->th_dport == att->th_fport)		goto rport;
	continue;

      rport:;
	if (ipa->th_sport == att->th_rport)		goto raddr;
	continue;

      raddr:;
	if (ipa->ip_src.s_addr == att->ip_raddr.s_addr)
	{
	    return (att);
	}
    }

    return (NULL);
}


static	aTT *
_lookingForForeignHash(int proto, u_long addr, u_short port)
{
    register	Cell	*p;
    register	aTT	*att;

    int		hv = _hash_foreign(addr, port);
    
    for (p = _foreignHash[hv]; p; p = CDR(p))
    {
	att = (aTT *)CAR(p);

	if ((att->ip_p == proto)
	    && (att->ip_faddr.s_addr == addr)
	    && (att->th_fport == port))
	    return (att);
    }

    return (NULL);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if	maybeNotUsed
static	aTT	*
_lookingForAttEntry(int proto, u_long laddr, u_short lport, u_long faddr, u_short fport)
{
    register    int      hv = _hash_obsolete(faddr);
    register	Cell	*p;
    register	aTT	*att;

    for (p = _remoteHash[hv]; p; p = CDR(p))
    {
	if ((u_long)CAAR(p) == faddr)
	{
	    att = (aTT *)CDAR(p);

	    if ((proto == att->ip_p)
		&& (laddr == att->ip_laddr.s_addr)
		&& (lport == att->th_lport)
		&& (faddr == att->ip_faddr.s_addr)
		&& (fport == att->th_fport))
		return (att);
	}
    }

    return (NULL);
}
#endif


static	Cell *
_internHash(Cell *(*table)[], int hv, caddr_t node)
{
    Cell	*hp, *np;

    np = LST_cons((void *)node, NIL);
    
    if (hp = (*table)[hv])
	CDR(np) = hp;

    (*table)[hv] = np;

    return (np);
}


static	int
_removeHash(Cell *(*table)[], int hv, caddr_t node)
{
    register	Cell	*p, *q;

    if ((p = (*table)[hv]) == NULL)
	return (0);

    if (CDR(p) == NULL)
    {
	if (CAR(p) == (Cell *)node)
	{
	    LST_free(p);
	    (*table)[hv] = NULL;
	}
	return (0);
    }

    for (p = (*table)[hv], q = NULL; p; q = p, p = CDR(p))
    {
	if (CAR(p) != (Cell *)node)
	    continue;

	if (q == NULL)
	    (*table)[hv] = CDR(p);
	else
	    CDR(q) = CDR(p);

	LST_free(p);
	return (0);
    }

    return (0);
}



#if	maybeNotUsed
static	int
_hash_obsolete(u_long n)
{
    return (PM_HASH(n));
}
#endif


static	int
_hash_att(register aTT *att, int local)
{
    int		byte;
    u_char	Wow[12];

    switch (local)
    {
      case LOCALHASH:			/* In case outBount packet	*/
	byte = 11;
	*(u_long *)&Wow[0]   = att->ip_laddr.s_addr;
	*(u_long *)&Wow[4]   = att->ip_raddr.s_addr;
	*(u_short *)&Wow[ 8] = att->th_lport;
	*(u_short *)&Wow[10] = att->th_rport;
	break;

      case REMOTEHASH:			/* In case inBound packet	*/
	byte = 11;
	*(u_long *)&Wow[0]   = att->ip_faddr.s_addr;
	*(u_long *)&Wow[4]   = att->ip_raddr.s_addr;
	*(u_short *)&Wow[ 8] = att->th_fport;
	*(u_short *)&Wow[10] = att->th_rport;
	break;
	
      case FOREIGNHASH:
	byte = 5;
	*(u_long *)&Wow[0]  = att->ip_faddr.s_addr;
	*(u_short *)&Wow[4] = att->th_fport;
	break;
    }
    
    return (_hash_pjw(Wow, byte));
}


static	int
_hash_foreign(u_long inaddr, u_short port)
{
    int		byte;
    u_char	Wow[6];

    byte = 5;
    *(u_long *)&Wow[0]  = inaddr;
    *(u_short *)&Wow[4] = port;

    return (_hash_pjw(Wow, byte));
}


static	int
_hash_ipa(register IPAssoc *ipa)
{
    u_char	Wow[12];

    if (ipa->inout == OutBound)		/* In case outBound packet	*/
    {
	*(u_long *)&Wow[0]   = ipa->ip_src.s_addr;
	*(u_long *)&Wow[4]   = ipa->ip_dst.s_addr;
	*(u_short *)&Wow[ 8] = ipa->th_sport;
	*(u_short *)&Wow[10] = ipa->th_dport;
    }
    else				/* In case inBound packet	*/
    {
	*(u_long *)&Wow[0]   = ipa->ip_dst.s_addr;
	*(u_long *)&Wow[4]   = ipa->ip_src.s_addr;
	*(u_short *)&Wow[ 8] = ipa->th_dport;
	*(u_short *)&Wow[10] = ipa->th_sport;
    }

    return (_hash_pjw(Wow, 12 - 1));
}


/*	CAUTION								*/
/*	This hash routine is byte order sensitive.  Be Careful.		*/

static	int
_hash_pjw(register u_char *s, int len)
{
    register	u_int	c;
    register	u_int	h, g;

    for (c = h = g = 0; c <= len; c++, s++)
    {
	h = (h << 4) + (*s);
	if (g = h & 0xf0000000)
	{
	    h ^= (g >> 24);
	    h ^= g;
	}
    }
    return (h % PM_MAXHASH);
}

