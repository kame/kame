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
//#	$SuMiRe: pm_nat.c,v 1.10 1998/09/14 19:49:52 shin Exp $
//#	$Id: pm_nat.c,v 1.4 2000/02/06 09:34:19 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <netpm/pm_include.h>

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/route.h>

#include <netinet/ip_icmp.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcpip.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if BYTE_ORDER == BIG_ENDIAN
# define	PORT	0x504f5254			/* "PORT"	*/
# define	R227	0x32323720			/* "227 "	*/
#else
# define	PORT	0x54524f50			/* "TROP"	*/
# define	R227	0x20373232			/* " 722"	*/
#endif

#define		PORTMINCMD	"PORT 1,1,1,1,1,1\r\n"
#define		PORTMINLEN	18	/* strlen(PORTMINCMD)		*/

/* ftpd should return PASVMINREPLY when enter passive mode (rfc959).	*/
#define		PASVMINREPLY	"227 Entering Passive Mode (1,2,3,4,1,2)\r\n"
#define		PASVMINLEN	41	/* strlen(PASVMINREPLY)		*/

#define		FTP_DATA	20
#define		FTP_CONTROL	21
#define		FTPPASSIVE	 1


#undef	adjustICMPChecksum
#define	useIncrementalUpdateChecksum	1


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

extern	struct _pmBox	*currentPmBox;


static	int	 _nat_icmp		__P((InOut, struct ip *, struct mbuf *));
static	aTT	*_maybeTraceroute	__P((struct ip *, struct mbuf *));
static	void	 _icmpEchoreply		__P((aTT *, struct ip *, struct icmp *));
static	void	 _icmpEcho		__P((aTT *, struct ip *, struct icmp *));
static	aTT	*_icmpTimxceed		__P((struct ip *, struct icmp *));
static	int	 _nat_udp		__P((InOut, struct ip *, struct mbuf *));
static	int	 _nat_tcp		__P((InOut, struct ip *, struct mbuf *));
static  __inline void	modifyAck	__P((struct ip *, struct tcpiphdr *, int));
static	__inline void	modifySeq	__P((struct ip *, struct tcpiphdr *, int));
#if defined(FTPPASSIVE)
static	int	 _censorPayload		__P((InOut, aTT *, struct ip *, struct mbuf *));
#else
static	int	 _censorPayload		__P((aTT *, struct ip *, struct mbuf *));
#endif
static	int	 _nat_ftp		__P((aTT *, struct ip *, struct mbuf *));
#if defined(FTPPASSIVE)
static	int	 _nat_ftpPassive	__P((aTT *, struct ip *, struct mbuf *));
#endif
static	int	 _nat_tcpfsm		__P((InOut, InOut, short, u_char));
static	int	 _nat_tcpfsmSessOut	__P((InOut, short, u_char));
static	int	 _nat_tcpfsmSessIn	__P((InOut, short, u_char));
static	aTT	*_nat_translate		__P((struct ip *, IPAssoc *));
#if defined(useIncrementalUpdateChecksum)
static	void	 adjustChecksum		__P((u_char *, int, u_char *, u_char *));
#endif
#if defined(useCalcCksum)
static	u_short	 calc_cksum		__P((u_short *, int));
#endif

extern  aTT	*lookingForICMPEcho	__P((IPAssoc *, struct ip *, struct icmp *));
extern	gAddr	*_assignAddress		__P((int, natRuleEnt *));
extern	void	 _markFootPrint		__P((int, u_long, u_short, u_long, u_short, u_long, u_short));
extern	aTT	*_scanFootPrint		__P((struct ip *));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

u_long
pm_nat(InOut inout, u_char *p, struct mbuf *mbuf, u_long k)
{
    int		 rv;

    switch (((struct ip *)p)->ip_p)
    {
      case IPPROTO_ICMP:
	_nat_icmp(inout, (struct ip *)p, mbuf);
	break;

      case IPPROTO_TCP:
	_nat_tcp(inout, (struct ip *)p, mbuf);
	break;
	
      case IPPROTO_UDP:
	_nat_udp(inout, (struct ip *)p, mbuf);
	break;

      default:
	break;
    }

    return (PM_PASS);
}


static	int
_nat_icmp(InOut inout, struct ip *ip, struct mbuf *mbuf)
{
    aTT		*att;
    IPAssoc	 ipa;

    pm_logip(LOG_DEBUG, mbuf);

    bzero(&ipa, sizeof(IPAssoc));

    ipa.inout = inout;
    ipa.ip_p  = IPPROTO_ICMP;
    ipa.ip_src.s_addr = ip->ip_src.s_addr;
    ipa.ip_dst.s_addr = ip->ip_dst.s_addr;
    if ((att = _nat_translate(ip, &ipa)) == NULL)
    {
	if ((inout == InBound)
	    && ((att = _maybeTraceroute(ip, mbuf)) != NULL))
		ip->ip_dst = att->ip_laddr;
    }
    else
    {
	struct icmp	*icp;

	icp = (struct icmp *)((char *)ip + (ip->ip_hl << 2));

	if (inout == InBound)
	{
	    switch (icp->icmp_type)
	    {
	      case ICMP_ECHOREPLY:
		_icmpEchoreply(att, ip, icp);
		break;

	      case ICMP_UNREACH:
		if (icp->icmp_code == ICMP_UNREACH_PORT)
		    _maybeTraceroute(ip, mbuf);
		break;

	      case ICMP_TIMXCEED:
		if (icp->icmp_code == ICMP_TIMXCEED_INTRANS)
		    _maybeTraceroute(ip, mbuf);
		break;
	    }
	}
	else
	{
	    switch (icp->icmp_type)
	    {
	      case ICMP_ECHOREPLY:
		_icmpEchoreply(att, ip, icp);
		break;

	      case ICMP_ECHO:
		_icmpEcho(att, ip, icp);
		break;
	    }
	}
    }

    return (0);
}


static	aTT *
_maybeTraceroute(struct ip *ip, struct mbuf *mbuf)
{
    
    int		 hlen    = ip->ip_hl << 2;
    int		 icmplen = ip->ip_len - hlen;
    struct icmp	*icp;
    struct _aTT	*rv = NULL;

    icp = (struct icmp *)((char *)ip + (ip->ip_hl << 2));
    switch (icp->icmp_type)
    {
      case ICMP_UNREACH:
	if (icp->icmp_code == ICMP_UNREACH_PORT)
	    rv = _icmpTimxceed(ip, icp);
	break;

      case ICMP_TIMXCEED:
	if (icp->icmp_code == ICMP_TIMXCEED_INTRANS)
	    rv = _icmpTimxceed(ip, icp);
	break;
    }

    return (rv);
}


static	void
_icmpEchoreply(aTT *att, struct ip *ip, struct icmp *icp)
{
    IPAssoc	 ipa;
    struct timeval	 atv;

    if ((att->ip_p == IPPROTO_ICMP)
	&& (att->ip_raddr.s_addr == ip->ip_src.s_addr)
	&& (att->ip_faddr.s_addr == ip->ip_dst.s_addr)
	&& (att->suit.ih_idseq.icd_id  == icp->icmp_id)
	&& (att->suit.ih_idseq.icd_seq == icp->icmp_seq))
	goto	found;

    ipa.inout = InBound;
    ipa.ip_p  = IPPROTO_ICMP;
    ipa.th_sport = 0;
    ipa.th_dport = 0;
    ipa.ip_src   = ip->ip_dst;
    ipa.ip_dst   = ip->ip_src;

    if ((att = lookingForICMPEcho(&ipa, ip, icp)) == NULL)
	return ;

  found:;
    ip->ip_dst = att->ip_laddr;
    ip->ip_src = att->ip_laddr;

    att->inbound++;
    switch (att->pm_type)
    {
      case NAT_STATIC:
      case NAT_DYNAMIC:
	if (att->_u.rule)
	    att->_u.rule->inbound++;
	break;

      case NAT_LDIR:
	if (att->_u.imm[0])
	    ((virtualAddr *)att->_u.imm[0])->inbound++,
	    ((realAddr *)att->_u.imm[1])->inbound++;
	break;
    }

    microtime(&atv);
    att->tstamp = atv.tv_sec;
    return ;
}


static	void
_icmpEcho(aTT *att, struct ip *ip, struct icmp *icp)
{
    att->suit.ih_idseq.icd_id  = icp->icmp_id;
    att->suit.ih_idseq.icd_seq = icp->icmp_seq;
}


static	aTT *
_icmpTimxceed(struct ip *ip, struct icmp *icp)
{
    struct ip		*hip;
    struct udphdr	*hup;
    int			 hlen;
    IPAssoc		 ipa;

    hip   = &icp->icmp_ip;
    hlen  = hip->ip_hl << 2;
    hup = (struct udphdr *)((u_char *)hip + hlen);

    if (hip->ip_p != IPPROTO_UDP)
	return (NULL);

    ipa.inout = InBound;
    ipa.ip_p  = IPPROTO_UDP;
    ipa.th_sport = hup->uh_dport;
    ipa.th_dport = hup->uh_sport;
    ipa.ip_src   = hip->ip_dst;
    ipa.ip_dst   = hip->ip_src;

    {
	aTT		*att;
	struct timeval	 atv;
	if ((att = pm_asAttEntry(&ipa)) == NULL)
	    return (NULL);

	{
	    u_char	Dum[16], Dee[16];

	    *(u_short *)&Dum[0] = hup->uh_sport;
	    *(u_short *)&Dee[0] = att->th_lport;
	    hup->uh_sport = att->th_lport;
	    adjustChecksum((u_char *)&hip->ip_sum, 2, Dum, Dee);
	}


#if defined(adjustICMPChecksum)

	hip->ip_src   = att->ip_laddr;

#if defined(useIncrementalUpdateChecksum)
	{
	    u_char	 Dum[16], Dee[16];

	    *(u_long  *)&Dum[0] = att->ip_faddr.s_addr;
	    *(u_long  *)&Dee[0] = att->ip_laddr.s_addr;
	    adjustChecksum((u_char *)&hip->ip_sum, 4, Dum, Dee);

	    *(u_short *)&Dum[4] = att->th_fport;
	    *(u_short *)&Dee[4] = att->th_lport;
	    adjustChecksum((u_char *)&icp->icmp_cksum, 6, Dum, Dee);
	}
#endif
#endif

	att->inbound++;
	switch (att->pm_type)
	{
	  case NAT_STATIC:
	  case NAT_DYNAMIC:
	    if (att->_u.rule)
		att->_u.rule->inbound++;
	    break;

	  case NAT_LDIR:
	    if (att->_u.imm[0])
		((virtualAddr *)att->_u.imm[0])->inbound++,
		((realAddr *)att->_u.imm[1])->inbound++;
	    break;
	}

	microtime(&atv);
	att->tstamp = atv.tv_sec;
	return (att);
    }

    return (NULL);
}


static	int
_nat_udp(InOut inout, struct ip *ip, struct mbuf *mbuf)
{
    register struct udpiphdr    *ui;
    IPAssoc	 ipa;
    aTT		*att;

    pm_logip(LOG_DEBUG, mbuf);

    ui = mtod(mbuf, struct udpiphdr *);

    ipa.inout = inout;
    ipa.type  = 0;
    ipa.ip_p  = ip->ip_p;
    ipa.th_sport = ui->ui_sport;
    ipa.th_dport = ui->ui_dport;
    ipa.ip_src.s_addr = ui->ui_src.s_addr;
    ipa.ip_dst.s_addr = ui->ui_dst.s_addr;

    if ((att = _nat_translate(ip, &ipa)) == NULL)
	return (0);

    if (att->pm_type == NAT_DYNAMIC)
    {
	if (inout == OutBound)
	    ui->ui_sport = att->th_fport;
	else
	    ui->ui_dport = att->th_lport;
    }

    if (ui->ui_sum)
    {
#if defined(useIncrementalUpdateChecksum)
	u_char		Dum[16], Dee[16];

	if (inout == OutBound)
	{
	    *(u_long  *)&Dum[0] = att->ip_laddr.s_addr;
	    *(u_short *)&Dum[4] = att->th_lport;
	    *(u_long  *)&Dee[0] = att->ip_faddr.s_addr;
	    *(u_short *)&Dee[4] = att->th_fport;
	}
	else
	{
	    *(u_long  *)&Dum[0] = att->ip_faddr.s_addr;
	    *(u_short *)&Dum[4] = att->th_fport;
	    *(u_long  *)&Dee[0] = att->ip_laddr.s_addr;
	    *(u_short *)&Dee[4] = att->th_lport;
	}
	adjustChecksum((u_char *)&ui->ui_sum, 6, Dum, Dee);
#else	
	struct ip	 save_ip;

	save_ip = *ip;
	ui->ui_next = ui->ui_prev = 0;
	ui->ui_x1 = 0;
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = ui->ui_ulen;
	ui->ui_src = save_ip.ip_src;
	ui->ui_dst = save_ip.ip_dst;

	ui->ui_sum = 0;
	ui->ui_sum = in_cksum(mbuf, mbuf->m_pkthdr.len);
	*ip = save_ip;
#endif
    }

    return (0);
}


static	int
_nat_tcp(InOut inout, struct ip *ip, struct mbuf *mbuf)
{
    register struct tcpiphdr    *ti;
    IPAssoc	 ipa;
    aTT		*att;
    TCPstate	*ts;
    u_char	Dum[16], Dee[16];
    u_char	*dump, *deep;

    pm_logip(LOG_DEBUG, mbuf);

    dump = Dum;
    deep = Dee;

    ti = mtod(mbuf, struct tcpiphdr *);

    ipa.inout = inout;
    ipa.type  = 0;
    ipa.ip_p  = ip->ip_p;
    ipa.th_sport = ti->ti_sport;
    ipa.th_dport = ti->ti_dport;
    ipa.ip_src   = ti->ti_src;
    ipa.ip_dst   = ti->ti_dst;

    if ((att = _nat_translate(ip, &ipa)) == NULL)
    {
	if ((inout == OutBound)
	    || ((att = _scanFootPrint(ip)) == NULL))
	    return (0);
    }

    if (att->pm_type == NAT_DYNAMIC)
    {
	if (inout == OutBound)
	    ti->ti_sport = att->th_fport;
	else
	    ti->ti_dport = att->th_lport;
    }

    if ((ts = att->suit.tcp) == NULL)
    {
	MALLOC(ts, TCPstate *, sizeof(TCPstate), M_PM, M_NOWAIT);
	if (ts == NULL)
	{
	    char	Wow[128];

	    sprintf(Wow, "Cannot allocate TCPstatus.\n");
	    pm_log(LOG_MSG, LOG_NOTICE, Wow, strlen(Wow));
	    pm_removeAttEntry(att);
	    return (0);
	}

	bzero(ts, sizeof(TCPstate));

	if (((ti->ti_flags & TH_SYN) != 0)
	    && ((ti->ti_flags & TH_ACK) == 0))
	    ts->_session = (InOut)inout;
	ts->_state = TCPS_CLOSED;
	att->suit.tcp = ts;
    }

    ts->_state = _nat_tcpfsm(ts->_session, inout, ts->_state, ti->ti_flags);
    if (ts->_state == TCPS_SYN_SENT)
	(InOut)ts->_session = inout;

#if defined(FTPPASSIVE)
    ts->_delta[2] = _censorPayload(inout, att, ip, mbuf);
#else
    if ((inout == OutBound)
	&& ((InOut)ts->_session == OutBound))
	ts->_delta[2] = _censorPayload(att, ip, mbuf);
    else
	ts->_delta[2] = 0;
#endif

    if (ts->_ip_id[0] != 0)
    {
	char	Wow[128];

	sprintf(Wow, "nat_tcp id: %d, %d  delta: %d, %d, %d%c",
		ts->_ip_id[0], ts->_ip_id[1],
		ts->_delta[0], ts->_delta[1], ts->_delta[2], '\0');
	pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
    }

    if ((ts->_ip_id[0] != 0)
	&& (ts->_ip_id[0] == ts->_ip_id[1]))	/* In case retransmission	*/
    {
	char	*wow;

	ts->_delta[0] = ts->_delta[1];		/* adjust sequence delta	*/
	ts->_ip_id[1] = 0;
	wow = "********        ********        ********";
	pm_log(LOG_MSG, LOG_DEBUG, wow, strlen(wow));
    }
    
    if (ts->_delta[0] != 0)
    {
#if defined(FTPPASSIVE)
	if ((ti->ti_flags & TH_ACK)
	    && (inout == InBound))
	{
	    if ((((InOut)ts->_session == OutBound)	      /* outBound session */
		 && (ntohs(ti->ti_sport) == FTP_CONTROL))     /* inComing packet  */
		|| (((InOut)ts->_session == InBound)	      /*  inBound session */
		   && (ntohs(ti->ti_dport) == FTP_CONTROL)))  /* inComing packet  */
	    {
		*(u_long *)dump = ti->ti_ack;	dump += sizeof(u_long);
		modifyAck(ip, ti, ts->_delta[0]);
		*(u_long *)deep = ti->ti_ack;	deep += sizeof(u_long);
	    }
	}
	else if (inout == OutBound)
	{
	    if ((((InOut)ts->_session == OutBound)	      /* outBound session */
		 && (ntohs(ti->ti_dport) == FTP_CONTROL))     /* outGoing packet  */
		|| (((InOut)ts->_session == InBound)	      /*  inBound session */
		    && (ntohs(ti->ti_sport) == FTP_CONTROL))) /* outGoing packet  */
	    {
		*(u_long *)dump = ti->ti_seq;	dump += sizeof(u_long);
		modifySeq(ip, ti, ts->_delta[0]);
		*(u_long *)deep = ti->ti_seq;	deep += sizeof(u_long);
	    }
	}
#else
	if ((ti->ti_flags & TH_ACK)
	    && (inout == InBound)
	    && ((InOut)ts->_session == OutBound))
	{
	    if (ntohs(ti->ti_sport) == FTP_CONTROL)
	    {
		*(u_long *)dump = ti->ti_ack;	dump += sizeof(u_long);
		modifyAck(ip, ti, ts->_delta[0]);
		*(u_long *)deep = ti->ti_ack;	deep += sizeof(u_long);
	    }
	}
	else if ((inout == OutBound)
		 && ((InOut)ts->_session == OutBound))
	{
	    if (ntohs(ti->ti_dport) == FTP_CONTROL)
	    {
		*(u_long *)dump = ti->ti_seq;	dump += sizeof(u_long);
		modifySeq(ip, ti, ts->_delta[0]);
		*(u_long *)deep = ti->ti_seq;	deep += sizeof(u_long);
	    }
	}
#endif
    }

    if (ti->ti_sum)
    {
#if 0
	if (inout == OutBound)
	{
	    *(u_long  *)dump = att->ip_laddr.s_addr;	dump += sizeof(u_long);
	    *(u_short *)dump = att->th_lport;		dump += sizeof(u_short);
	    *(u_long  *)deep = att->ip_faddr.s_addr;	deep += sizeof(u_long);
	    *(u_short *)deep = att->th_fport;		deep += sizeof(u_short);
	}
	else
	{
	    *(u_long  *)dump = att->ip_faddr.s_addr;	dump += sizeof(u_long);
	    *(u_short *)dump = att->th_fport;		dump += sizeof(u_short);
	    *(u_long  *)deep = att->ip_laddr.s_addr;	deep += sizeof(u_long);
	    *(u_short *)deep = att->th_lport;		deep += sizeof(u_short);
	}
	adjustChecksum((u_char *)&ti->ti_sum, dump-Dum, Dum, Dee);
#else
	{
	    int		 iphlen = ip->ip_hl << 2;
	    struct ip	 save_ip;

	    save_ip = *ip;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
	    bzero(ti->ti_x1, sizeof(ti->ti_x1));
#else
	    ti->ti_next = ti->ti_prev = 0;
	    ti->ti_x1 = 0;
#endif
	    ti->ti_pr = IPPROTO_TCP;
	    ti->ti_len = htons(mbuf->m_pkthdr.len - iphlen);
	    ti->ti_src = save_ip.ip_src;
	    ti->ti_dst = save_ip.ip_dst;

	    ti->ti_sum = 0;
	    ti->ti_sum = in_cksum(mbuf, mbuf->m_pkthdr.len);
	    *ip = save_ip;
	}
#endif
    }

#if defined(FTPPASSIVE)
    if ((inout == OutBound)
	&& (ts->_delta[2] != 0))
#else
    if ((inout == OutBound)
	&& ((InOut)ts->_session == OutBound)
	&& (ts->_delta[2] != 0))
#endif
    {
	ts->_delta[1]  = ts->_delta[0];
	ts->_delta[0] += ts->_delta[2];
    }

    return (0);
}


static __inline	void
modifyAck(struct ip *ip, struct tcpiphdr *ti, int delta)
{
    u_long	ack[2];

    ack[1] = ti->ti_ack;
    ti->ti_ack = htonl(ntohl(ti->ti_ack) - delta);
    ack[0] = ti->ti_ack;

#if defined(PMDEBUG)
    if (pm_debug & pm_DebugNatFtp)
    {
	char	Wow[128];

	sprintf(Wow, "Rewrite Ack: id:%d, %lu -> %lu%c",
		ip->ip_id, ntohl(ack[1]), ntohl(ack[0]), '\0');
	pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
    }
#endif
}


static __inline void
modifySeq(struct ip *ip, struct tcpiphdr *ti, int delta)
{
    u_long	seq[2];

    seq[1] = ti->ti_seq;
    ti->ti_seq = htonl(ntohl(ti->ti_seq) + delta);
    seq[0] = ti->ti_seq;

#if defined(PMDEBUG)
    if (pm_debug & pm_DebugNatFtp)
    {
	char	Wow[128];

	sprintf(Wow, "Rewrite Seq: id:%d, %lu -> %lu%c",
		ip->ip_id, ntohl(seq[1]), ntohl(seq[0]), '\0');
	pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
    }
#endif
}


#if defined(FTPPASSIVE)
static	int
_censorPayload(InOut inout, aTT *att, struct ip *ip, struct mbuf *mbuf)
{
    int			 rv = 0;
    TCPstate		*ts = att->suit.tcp;
    struct tcpiphdr	*ti = (struct tcpiphdr *)ip;

    if (inout == OutBound)
    {
	if (((InOut)ts->_session == OutBound)
	    && (ntohs(ti->ti_dport) == FTP_CONTROL))
	    rv = _nat_ftp(att, ip, mbuf);
	else if (((InOut)ts->_session == InBound)
		 && (ntohs(ti->ti_sport) == FTP_CONTROL))
	    rv = _nat_ftpPassive(att, ip, mbuf);
    }
    
    return (rv);
}
#else
static	int
_censorPayload(aTT *att, struct ip *ip, struct mbuf *mbuf)
{
    int		rv = 0;
    struct tcpiphdr	*ti = (struct tcpiphdr *)ip;

    if (ntohs(ti->ti_dport) == FTP_CONTROL)
    {
	rv = _nat_ftp(att, ip, mbuf);
    }
    
    return (rv);
}
#endif


static	int
_nat_ftp(aTT *att, struct ip *ip, struct mbuf *mbuf)
{
    int		 dlen, hlen;
    char	*th, *td;
    TCPstate	*ts;
    
    th = (char *)ip + (ip->ip_hl << 2);
    hlen = (ip->ip_hl + ((struct tcphdr *)th)->th_off) << 2;
    dlen = ip->ip_len - hlen;

    if (dlen < PORTMINLEN)
	return (0);

    td = (char *)ip + hlen;
    if (*(int *)td != PORT)
	return (0);

    pm_log(LOG_MSG, LOG_DEBUG, td, dlen);

    {
	char      ch;
	int	  byte, bite[6];
	int	  iter;
	u_long	  faddr;
	u_short	  fport;

	byte = 0;
	bite[0] = bite[1] = bite[2] = bite[3] = bite[4] = bite[5] = 0;

	for (iter = 4; iter < dlen; iter++)
	{
	    ch = td[iter];
	    if (ch >= '0' && ch <= '9')
	    { bite[byte] = bite[byte] * 10 + ch - '0'; }
	    else if (ch == ',')
	    { byte++; }
	}
	faddr = ((bite[0] << 24) + (bite[1] << 16) + (bite[2] << 8) + bite[3]);
	fport = ((bite[4] <<  8) +  bite[5]);
	ts = att->suit.tcp;
	ts->_ip_id[1] = ts->_ip_id[0];
	ts->_ip_id[0] = htons(fport);

	{
	    u_char  *p;
	    int      a0, a1, a2, a3, p0, p1;
	    int	     slen;
	    gAddr   *addr;
	    char     Wow[128];

	    if (att->pm_type == NAT_STATIC)
	    {
		static gAddr	gaddr;

		gaddr.addr = att->ip_faddr;
		gaddr.port = htons(fport);
		addr = &gaddr;
	    }
	    else if ((addr = _assignAddress(IPPROTO_TCP, att->_u.rule)) == NULL)
		return (0);

	    p = (u_char *)&addr->addr.s_addr;
	    a0 = *p++; a1 = *p++; a2 = *p++; a3 = *p;
	    p = (u_char *)&addr->port;
	    p0 = *p++; p1 = *p;

	    sprintf(Wow, "PORT %d,%d,%d,%d,%d,%d\r\n%c", a0, a1, a2, a3, p0, p1, '\0');
	    slen = strlen(Wow);
	    strncpy(td, Wow, slen);

	    pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
	    if (att->pm_type == NAT_DYNAMIC)
		_markFootPrint(IPPROTO_TCP,
			       htonl(faddr), htons(fport),
			       addr->addr.s_addr, addr->port,
			       att->ip_raddr.s_addr, htons((u_short)FTP_DATA));

	    {
		int		 delta;
		struct tcpiphdr	*ti;
		char		 Wow[128];

		delta = slen - dlen;
		ti = mtod(mbuf, struct tcpiphdr *);
		if (ti->ti_sum)
		{
		    int		iphlen = ip->ip_hl << 2;
		    struct ip	save_ip;

		    ip->ip_len  += delta;
		    mbuf->m_len += delta;
		    mbuf->m_pkthdr.len += delta;

#if 0
		    save_ip = *ip;
		    ti->ti_next = ti->ti_prev = 0;
		    ti->ti_x1 = 0;
		    ti->ti_pr = IPPROTO_TCP;
		    ti->ti_len = htons(mbuf->m_pkthdr.len - iphlen);
		    ti->ti_src = save_ip.ip_src;
		    ti->ti_dst = save_ip.ip_dst;

		    ti->ti_sum = 0;
		    ti->ti_sum = in_cksum(mbuf, mbuf->m_pkthdr.len);
		    *ip = save_ip;
#endif
		}
	    }

#if 0
	    if (ts->_ip_id[0] == ts->_ip_id[1])
	    {
		sprintf(Wow, "Port id: %d%c", ts->_ip_id[0], '\0');
		pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
		return (0);
	    }
	    else
#endif
	    {
		sprintf(Wow, "nat_ftp id: %d, %d%c", ts->_ip_id[0], ts->_ip_id[1], '\0');
		pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
		return (slen - dlen);
	    }
	}
    }

    return (0);
}


#if defined(FTPPASSIVE)

#define	isdigit(c)	((c) >= '0' && (c) <= '9')

static	int
_nat_ftpPassive(aTT *att, struct ip *ip, struct mbuf *mbuf)
{
    int		 dlen, hlen;
    char	*th, *td;
    TCPstate	*ts;
    
    th = (char *)ip + (ip->ip_hl << 2);
    hlen = (ip->ip_hl + ((struct tcphdr *)th)->th_off) << 2;
    dlen = ip->ip_len - hlen;

    if (dlen < PASVMINLEN)
	return (0);

    td = (char *)ip + hlen;
    if (*(int *)td != R227)
	return (0);

    pm_log(LOG_MSG, LOG_DEBUG, td, dlen);

    {
	char	 ch;
	char	*p;
	int	 byte, bite[6];
	u_long	  faddr;
	u_short	  fport;

	byte = 0;
	bite[0] = bite[1] = bite[2] = bite[3] = bite[4] = bite[5] = 0;

	for (p = td+3; !isdigit(*p) && (*p != '\r') && (*p != '\n'); p++) ;

	if ((*p == '\r') || (*p == '\n'))	return (0);

	while (isdigit(*p) || (*p == ','))
	{
	    if (isdigit(*p))
	    { bite[byte] = bite[byte] * 10 + *p - '0'; }
	    else if (*p == ',')
	    { byte++; }
	    p++;
	}
	faddr = ((bite[0] << 24) + (bite[1] << 16) + (bite[2] << 8) + bite[3]);
	fport = ((bite[4] <<  8) +  bite[5]);
	ts = att->suit.tcp;
	ts->_ip_id[1] = ts->_ip_id[0];
	ts->_ip_id[0] = htons(fport);

	{
	    u_char  *p;
	    int      a0, a1, a2, a3, p0, p1;
	    int	     slen;
	    gAddr   *addr;
	    char     Wow[128];

	    if (att->pm_type == NAT_STATIC)
	    {
		static gAddr	gaddr;

		gaddr.addr = att->ip_faddr;
		gaddr.port = htons(fport);
		addr = &gaddr;
	    }
	    else if ((addr = _assignAddress(IPPROTO_TCP, att->_u.rule)) == NULL)
		return (0);

	    p = (u_char *)&addr->addr.s_addr;
	    a0 = *p++; a1 = *p++; a2 = *p++; a3 = *p;
	    p = (u_char *)&addr->port;
	    p0 = *p++; p1 = *p;

	    sprintf(Wow, "227 Entering Passive Mode. %d,%d,%d,%d,%d,%d\r\n%c",
		    a0, a1, a2, a3, p0, p1, '\0');
	    slen = strlen(Wow);
	    strncpy(td, Wow, slen);

	    pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
	    if (att->pm_type == NAT_DYNAMIC)
		_markFootPrint(IPPROTO_TCP,
			       htonl(faddr), htons(fport),
			       addr->addr.s_addr, addr->port,
			       att->ip_raddr.s_addr, htons((u_short)FTP_DATA));

	    {
		int		 delta;
		struct tcpiphdr	*ti;
		char		 Wow[128];

		delta = slen - dlen;
		ti = mtod(mbuf, struct tcpiphdr *);
		if (ti->ti_sum)
		{
		    int		iphlen = ip->ip_hl << 2;
		    struct ip	save_ip;

		    ip->ip_len  += delta;
		    mbuf->m_len += delta;
		    mbuf->m_pkthdr.len += delta;
		}
	    }

	    {
		sprintf(Wow, "nat_ftp id: %d, %d%c", ts->_ip_id[0], ts->_ip_id[1], '\0');
		pm_log(LOG_MSG, LOG_DEBUG, Wow, strlen(Wow));
		return (slen - dlen);
	    }
	}
    }

    return (0);
}
#endif


static	int
_nat_tcpfsm(InOut session, InOut inout, short state, u_char flags)
{
    int		rv;

    if (flags & TH_RST)
	return (TCPS_CLOSED);

    if (session == OutBound)
	rv = _nat_tcpfsmSessOut(inout, state, flags);
    else
	rv = _nat_tcpfsmSessIn (inout, state, flags);

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#	_nat_tcpfsmSessOut

	delta(start,		eps)			-> CLOSED
	delta(CLOSED,		TH_SYN & !TH_ACK)	-> SYN_SENT
	delta(SYN_SENT,	     in	TH_SYN &  TH_ACK)	-> SYN_RCVD
	delta(SYN_RCVD,		TH_ACK)			-> ESTABLISHED
	delta(ESTABLISHED,	TH_FIN)			-> FIN_WAIT_1
	delta(FIN_WAIT_1,    in	TH_FIN | TH_ACK)	-> TIME_WAIT
	delta(FIN_WAIT_1,    in	TH_ACK)			-> FIN_WAIT_2
	delta(FIN_WAIT_1,    in	TH_FIN)			-> CLOSING
	delta(FIN_WAIT_2,    in	TH_FIN)			-> TIME_WAIT
	delta(CLOSING,		TH_ACK)			-> TIME_WAIT
	delta(TIME_WAIT,	eps)			-> CLOSED

//#------------------------------------------------------------------------
*/

static	int
_nat_tcpfsmSessOut(InOut inout, short state, u_char flags)
{
    int     rv = state;

    switch (state)
    {
      case TCPS_CLOSED:
	if ((inout == OutBound)
	    && (((flags & TH_SYN) != 0)
		&& (flags & TH_ACK) == 0))
	    rv = TCPS_SYN_SENT;
	break;

      case TCPS_SYN_SENT:
	if ((inout == InBound)
	    && (flags & (TH_SYN | TH_ACK)))
	    rv = TCPS_SYN_RECEIVED;
	break;

      case TCPS_SYN_RECEIVED:
	if ((inout == OutBound)
	    && (flags & TH_ACK))
	    rv = TCPS_ESTABLISHED;
	break;

      case TCPS_ESTABLISHED:
	if ((inout == OutBound)
	    && (flags & TH_FIN))
	    rv = TCPS_FIN_WAIT_1;
	break;

      case TCPS_FIN_WAIT_1:
	if (inout == InBound)
	{
	    if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
	    else if (flags & TH_ACK)		rv = TCPS_FIN_WAIT_2;
	    else if (flags & TH_FIN)		rv = TCPS_CLOSING;
	}
	break;

      case TCPS_CLOSING:
	if ((inout == OutBound)
	    && (flags & TH_ACK))
	    rv = TCPS_TIME_WAIT;
	break;

      case TCPS_FIN_WAIT_2:
	if ((inout == InBound)
	    && (flags & TH_FIN))
	    rv = TCPS_TIME_WAIT;
	break;
    }

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#	_nat_tcpfsmSessIn

	delta(start,		eps)			-> CLOSED
	delta(CLOSED,		TH_SYN & !TH_ACK)	-> SYN_RCVD
	delta(SYN_RCVD,		TH_ACK)			-> ESTABLISHED
	delta(ESTABLISHED,   in	TH_FIN)			-> CLOSE_WAIT
	delta(ESTABLISHED,  out	TH_FIN)			-> FIN_WAIT_1
	delta(CLOSE_WAIT,   out	TH_FIN)			-> LAST_ACK
	delta(FIN_WAIT_1,	TH_FIN & TH_ACK)	-> TIME_WAIT
	delta(FIN_WAIT_1,	TH_FIN)			-> CLOSING
	delta(FIN_WAIT_1,	TH_ACK)			-> FIN_WAIT_2
	delta(CLOSING,		TH_ACK)			-> TIME_WAIT
	delta(LAST_ACK),	TH_ACK)			-> CLOSED
	delta(FIN_WAIT_2,	TH_FIN)			-> TIME_WAIT
	delta(TIME_WAIT,	eps)			-> CLOSED

//#------------------------------------------------------------------------
*/

static	int
_nat_tcpfsmSessIn(InOut inout, short state, u_char flags)
{
    int		rv = state;

    switch (state)
    {
      case TCPS_CLOSED:
	if ((inout == InBound)
	    && (((flags & TH_SYN) != 0)
		&& (flags & TH_ACK) == 0))
	    rv = TCPS_SYN_RECEIVED;
	break;

      case TCPS_SYN_RECEIVED:
	if ((inout == InBound)
	    && (flags & TH_ACK))
	    rv = TCPS_ESTABLISHED;
	break;

      case TCPS_ESTABLISHED:
	if ((inout == InBound)
	    && (flags & TH_FIN))
	    rv = TCPS_CLOSE_WAIT;
	if ((inout == OutBound)
	    && (flags & TH_FIN))
	    rv = TCPS_FIN_WAIT_1;
	break;

      case TCPS_CLOSE_WAIT:
	if ((inout == OutBound)
	    && (flags & TH_FIN))
	    rv = TCPS_LAST_ACK;
	break;

      case TCPS_FIN_WAIT_1:
	if (inout == InBound)
	{
	    if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
	    else if (flags & TH_FIN)		rv = TCPS_CLOSING;
	    else if (flags & TH_ACK)		rv = TCPS_FIN_WAIT_2;
	}
	break;

      case TCPS_CLOSING:
	if ((inout == InBound)
	    && (flags & TH_ACK))
	    rv = TCPS_TIME_WAIT;
	break;

      case TCPS_LAST_ACK:
	if ((inout == InBound)
	    && (flags & TH_ACK))
	    rv = TCPS_CLOSED;
	break;

      case TCPS_FIN_WAIT_2:
	if ((inout == InBound)
	    && (flags & TH_FIN))
	    rv = TCPS_TIME_WAIT;
	break;
    }
    
    return (rv);
}


static	aTT *
_nat_translate(struct ip *ip, IPAssoc *ipa)
{
    AliasPair	    *ap;
    register aTT    *att;
    struct timeval   atv;

    if ((att = pm_asAttEntry(ipa)) == NULL)
    {
	if ((ap = pm_getMapEntry(ipa)) == NULL)
	    return (NULL);

	att = addAttEntry(ipa, ap);
	if (att == NULL)
	    return (NULL);
    }

    if (ipa->inout == InBound)
    {
	ip->ip_dst.s_addr = att->ip_laddr.s_addr;
	att->inbound++;
	switch (att->pm_type)
	{
	  case NAT_STATIC:
	  case NAT_DYNAMIC:
	    if (att->_u.rule)
		att->_u.rule->inbound++;
	    break;

	  case NAT_LDIR:
	    if (att->_u.imm[0])
		((virtualAddr *)att->_u.imm[0])->inbound++,
		((realAddr *)att->_u.imm[1])->inbound++;
	    break;
	}
    }
    else
    {
	ip->ip_src.s_addr = att->ip_faddr.s_addr;
	att->outbound++;
	switch (att->pm_type)
	{
	  case NAT_STATIC:
	  case NAT_DYNAMIC:
	    if (att->_u.rule)
		att->_u.rule->outbound++;
	    break;

	  case NAT_LDIR:
	    if (att->_u.imm[0])
		((virtualAddr *)att->_u.imm[0])->outbound++,
		((realAddr *)att->_u.imm[1])->outbound++;
	    break;
	}
    }

    microtime(&atv);
    att->tstamp = atv.tv_sec;
    return (att);
}


#if defined(useIncrementalUpdateChecksum)
/*
//##
//#------------------------------------------------------------------------
//#
     assuming: unsigned char is 8 bits, long is 32 bits.
     - chksum points to the chksum in the packet
     - optr points to the old data in the packet
     - nptr points to the new data in the packet

//#------------------------------------------------------------------------
*/

static	void
adjustChecksum(u_char *chksum, int len, u_char *optr, u_char *nptr)
{
    register	u_long	x, old, new;

    x = ~((chksum[0] << 8) + chksum[1]) & 0x0000ffff;
    while (len)
    {
	old   = ~((optr[0] << 8) + optr[1]) & 0x0000ffff;
	optr += 2;
	x += old;
	if (x & 0x80000000)
	    x = (x & 0xffff) + (x >> 16);

	new   =  ((nptr[0] << 8) + nptr[1]) & 0x0000ffff;
	nptr += 2;
	x += new;
	if (x & 0x80000000)
	    x = (x & 0xffff) + (x >> 16);

	len -= 2;
    }

    while (x >> 16)
	x = (x & 0xffff) + (x >> 16);

    x = ~x;
    chksum[0] = x / 256;
    chksum[1] = x & 0xff;
}
#endif


#if defined(useCalcCksum)
static	u_short
calc_cksum(u_short *addr, int count)
{
    register long sum = 0;

    /*  This is the inner loop */
    while (count > 1)
    {
	sum   += *addr++;
	count -= 2;
    }

    /*  Add left-over byte, if any */
    if(count > 0)
	sum += *(u_char *)addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);

    return (~sum);
}
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

void
pm_debugProbe(char *mesg)
{
    char    WoW[LLEN];

    sprintf(WoW, "[pmd] enter debugprobe, %s\n", mesg);
    pm_log(LOG_MSG, LOG_DEBUG, WoW, strlen(WoW));
}
