/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 *
 *	$Id: misc.c,v 1.1 2000/01/07 15:08:34 fujisawa Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <net/if_dl.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>		/* for n_short			*/

#include <netinet6/in6_var.h>
#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>

#include <netdb.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "defs.h"


/*
 *
 */

struct ifnets	*ifnets;
struct ifaddrs	*ifaddrs;

Cell		*serverInside;		/* list of struct svrInfo	*/
Cell		*serverOutside;		/* list of struct svrInfo	*/

Cell		*openSockets;		/* List of struct sdesc		*/


int		 xmalloc_initialized;
struct
{
    void	*alloced;
    caddr_t	 caller;
    size_t	 size;
}		 xalo[1024];


struct msgHndl	*readQuery		__P((int));
struct sockaddr *extractPTRaddress	__P((char *));
struct sockaddr *extractInaddrArpa	__P((char *));
struct sockaddr *extractIp6Int		__P((char *));
struct msgHndl	*readResponse		__P((struct sdesc *));
struct msgHndl	*readMessage		__P((struct sdesc *));
int		 sendQuerySubsidiary	__P((struct svrInfo *, u_char *, int));
int		 sendQuery4		__P((struct sockaddr_in *, u_char *, int));
int		 sendQuery6		__P((struct sockaddr_in6 *, u_char *, int));

int		 isOutbound		__P((struct ifaddrs *));
struct ifaddrs	*detectRecvInterface	__P((struct sockaddr *));
struct ifaddrs	*toMyAddress		__P((struct sockaddr *));

void		 openSocket		__P((void));
int		 openSocket4		__P((struct ifaddrs *));
int		 openSocket6		__P((struct ifaddrs *));

int		 getifaddrs		__P((struct ifaddrs **));
struct ifnets	*mkifnets		__P((struct ifaddrs *));
void		 dumpIfnets		__P((void));
void		 dumpIfaddrs		__P((void));
void		 dumpIfaddr		__P((struct ifaddrs *));
char		*displaySockaddrIn4	__P((struct sockaddr_in *));
char		*displaySockaddrIn6	__P((struct sockaddr_in6 *));
char		*displaySockaddrDl	__P((struct sockaddr_dl *));

void		 sighandler		__P((int));

void		 xmallocShow		__P((FILE *));


sigset_t	 mask;
int		 signals[] =
{ SIGINT, SIGTERM, };


/*
 *
 */


struct sdesc *
recvMessage()
{
    Cell		*p;
    int			 count = 0;
    struct sdesc	*desc = NULL;
    fd_set		 sockvec;
    fd_set		 recvec;
    
    FD_ZERO(&sockvec);
    for (p = openSockets; p; p = CDR(p))
    {
	desc = (struct sdesc *)CAR(p);
	if ((desc->type != 0)
	    && (desc->sockfd > 0))
	{
	    if (isDebug(DEBUG_SOCKET))
	    {
		log(LOG_DEBUG, "FD_SET(%d) (addr: %s)",
		    desc->sockfd, displaySockaddr(desc->saddr));
	    }
	    FD_SET(desc->sockfd, &sockvec);
	    count++;
	}
    }
    
    if (count <= 0)
    {
	log(LOG_ERR, "FD_SET: no available sockets.\n");
	quitting(0);
    }

    /*	  debugProbe("select");							*/

    FD_COPY(&sockvec, &recvec);
    switch (select(FD_SETSIZE, &recvec, NULL, NULL, NULL))
    {
      case -1:
	if (errno != EINTR)
	    perror("select"), quitting(errno);
	break;

      case 0:
	break;

      default:
	for (p = openSockets; p; p = CDR(p))
	{
	    desc = (struct sdesc *)CAR(p);
	    if ((desc->sockfd > 0)
		&& (FD_ISSET(desc->sockfd, &recvec)))
	    {
		if (isDebug(DEBUG_SOCKET))
		{
		    log(LOG_DEBUG, "FD_ISSET(%d) (addr: %s)",
			desc->sockfd, displaySockaddr(desc->saddr));
		}
		
		if (desc->type == RES_PRF_QUERY)
		    desc->query = readQuery(desc->sockfd);
		else if (desc->type == RES_PRF_REPLY)
		    desc->response = readResponse(desc);
		return (desc);
	    }
	}
	break;
    }

    return (NULL);
}


struct msgHndl *
readQuery(int sockfd)
{
    int				 rv, len;
    struct timeval		 atv;
    struct sockaddr_storage	 from;
    struct msgHndl		*msg;
    struct _question		*qst;
    u_char			 Wow[PACKETSZ];

    rv = ioctl(sockfd, FIONREAD, (int *)&len);
    rv = recvfrom(sockfd, Wow, PACKETSZ, 0, (struct sockaddr *)&from, &len);

    if (isOff(daemon)
	&& (isDebug(DEBUG_RESOLVER)))
    {
	if (from.__ss_family == AF_INET)
	    fprintf(stderr, "*** recvIPv4msg() from "),
	    fprintf(stderr, "%s", displaySockaddr((struct sockaddr *)&from));
	else if (from.__ss_family == AF_INET6)
	    fprintf(stderr, "*** recvIPv6msg() from "),
	    fprintf(stderr, "%s", displaySockaddr((struct sockaddr *)&from));
	fprintf(stderr, " ***\n");

	__fp_nquery(Wow, rv, stderr);			/* DEBUG_RESOLVER	*/
    }

    msg = parseMessage((HEADER *)Wow, rv);

    msg->msgID	= rand();

    gettimeofday(&atv, NULL);
    msg->tstamp = atv.tv_sec;
    msg->ifap = detectRecvInterface((struct sockaddr *)&from);
    if (from.__ss_family == AF_INET)
	msg->f.from4 = *(struct sockaddr_in *)&from;
    else if (from.__ss_family == AF_INET6)
	msg->f.from6 = *(struct sockaddr_in6 *)&from;

    msg->b.inout = isOutbound(msg->ifap);

    qst = (struct _question *)CAR(msg->question);
    msg->b.qtype = qst->qtype;
    if (qst->qtype == T_PTR)
    {
	struct sockaddr	*subj;
	struct ifaddrs	*ifap;

	if (strlen(qst->qname) > strlen(INADDRARPA))
	    msg->b.T_PTR6 = 1;
	if ((subj = extractPTRaddress(qst->qname)) != NULL)
	{
	    if ((ifap = toMyAddress(subj)) != NULL)
		msg->b.ptrself = 1;
	    xfree(subj);
	}
	else
	    msg->b.ptrbroken = 1;
    }

    if (isDebug(DEBUG_NS))
	dumpNs("from", (struct sockaddr *)&from, msg);

    return (msg);
}


struct sockaddr *
extractPTRaddress(char *qname)
{
    int			 border = strlen(INADDRARPA);
    struct sockaddr	*subj;
  
    if (strlen(qname) <= border)
	subj = extractInaddrArpa(qname);	/* it should be ...in-addr.arpa	*/
    else
	subj = extractIp6Int(qname);		/* it should be ...ip6.int	*/

    return (subj);
}


struct sockaddr *
extractInaddrArpa(char *qname)
{
    int			 idx, octet;
    char		*ch, *byte;
    struct sockaddr_in	*in4;

    in4 = (struct sockaddr_in *)xmalloc(sizeof(struct sockaddr_in));
    bzero(in4, sizeof(struct sockaddr_in));
    byte = (char *)&in4->sin_addr;
    byte += 3;

    for (idx = 3, ch = qname; idx >= 0; idx--)
    {
	octet = 0;
	while (isdigit(*ch))
	{
	    octet = octet * 10 + *ch - '0';
	    ch++;
	}
	*byte-- = (char)octet;
	if (*ch != '.')	
	{
	    xfree(in4);
	    return (NULL);
	}
	ch++;
    }

    in4->sin_len = sizeof(struct sockaddr_in);
    in4->sin_family = AF_INET;
    return ((struct sockaddr *)in4);
}


struct sockaddr *
extractIp6Int(char *qname)
{
    int			 idx, nibble[2];
    char		*ch, *byte;
    struct sockaddr_in6	*in6;

    in6 = (struct sockaddr_in6 *)xmalloc(sizeof(struct sockaddr_in6));
    bzero(in6, sizeof(struct sockaddr_in6));
    byte = (char *)&in6->sin6_addr;
    byte += 15;
    
    for (idx = 15, ch = qname; idx >= 0; idx--)
    {
	nibble[0] = isdigit(*ch) ? (*ch - '0')
	    : isupper(*ch) ? (*ch - 'A' + 10)
	    : (*ch - 'a' + 10);
	if (*++ch != '.')
	{
	    xfree(in6);
	    return (NULL);
	}
	ch++;

	nibble[1] = isdigit(*ch) ? (*ch - '0')
	    : isupper(*ch) ? (*ch - 'A' + 10)
	    : (*ch - 'a' + 10);
	if (*++ch != '.')
	{
	    xfree(in6);
	    return (NULL);
	}
	ch++;

	*byte-- = (nibble[1] << 4) + nibble[0];
    }

    in6->sin6_len = sizeof(struct sockaddr_in6);
    in6->sin6_family = AF_INET6;
    return ((struct sockaddr *)in6);
}


struct msgHndl *
readResponse(struct sdesc *desc)
{
    int				 rv;
    int				 len;
    struct timeval		 atv;
    struct sockaddr_storage	 from;
    struct msgHndl		*msg;
    u_char			 Wow[PACKETSZ];

    rv = ioctl(desc->sockfd, FIONREAD, (int *)&len);
    rv = recvfrom(desc->sockfd, Wow, PACKETSZ, 0, (struct sockaddr *)&from, &len);
    close(desc->sockfd);
    desc->sockfd = -1;

    if (isOff(daemon)
	&& (isDebug(DEBUG_RESOLVER)))
    {
	if (from.__ss_family == AF_INET)
	    fprintf(stderr, "*** recvResponse4() from "),
	    fprintf(stderr, "%s", displaySockaddr((struct sockaddr *)&from));
	else if (from.__ss_family == AF_INET6)
	    fprintf(stderr, "*** recvResponse6() from "),
	    fprintf(stderr, "%s", displaySockaddr((struct sockaddr *)&from));
	fprintf(stderr, " ***\n");

	__fp_nquery(Wow, rv, stderr);			/* DEBUG_RESOLVER	*/
    }

    msg = parseMessage((HEADER *)Wow, rv);
    if (msg->answer)
    {
	Cell		*p;
	struct _RR	*ans;

	for (p = msg->answer; p; p = CDR(p))
	{
	    ans = (struct _RR *)CAR(p);
	    switch (ans->RRtype)
	    {
	      case T_A:		msg->b.t_a = 1;		break;
	      case T_AAAA:	msg->b.t_aaaa = 1;	break;
	      case T_CNAME:	msg->b.t_cname = 1;	break;
	      case T_PTR:
		if (strlen(ans->RRname) > strlen(INADDRARPA))
		    msg->b.t_ptr6 = 1;
		else
		    msg->b.t_ptr4 = 1;
		break;
	    }
	}
    }

    msg->b.inout = ~desc->query->b.inout;
    gettimeofday(&atv, NULL);
    msg->tstamp = atv.tv_sec;

    if (isDebug(DEBUG_NS))
	dumpNs("from", (struct sockaddr *)&from, msg);

    return (msg);
}


struct msgHndl *
readMessage(struct sdesc *desc)
{
    return (NULL);
}


void
sendQuery(struct msgHndl *msg, struct sdesc *desc)
{
    int			 rv;
    int			 sd;
    Cell		*p, *sList;
    struct sdesc	*descR, *descQ;
    struct svrInfo	*svr;
    u_char		 Wow[PACKETSZ];

    sList = serverOutside;
    if (msg->b.inout == 0)			/* in case of inBound query	*/
	sList = serverInside;

    for (p = sList; p; p = CDR(p))
    {
	svr = (struct svrInfo *)CAR(p);

	if ((rv = composeMessage(msg, Wow, sizeof(Wow))) < 0)
	{
	    log(LOG_INFO, "sendQuery(): failure on compose query.\n");
	}

	if ((sd = sendQuerySubsidiary(svr, Wow, rv)) < 0)
	{
	    log(LOG_INFO, "sendQuery(): failure on send query.\n");
	}

	descR = desc;
	descQ = desc->sd;
	if (desc->type == RES_PRF_QUERY)
	{
	    descQ = desc;
	    descR = internReplyDesc(desc->sockfd);
	    descR->saddr = svr->svaddr->ai_addr;
	}

	descR->sockfd = sd;
	descR->sd     = descQ;
	descR->server = svr;
	descR->query = msg;
	msg->b.linkc++;

	if (isDebug(DEBUG_NS))
	    dumpNs("to", svr->svaddr->ai_addr, msg);
    }

}


int
sendQuerySubsidiary(struct svrInfo *svr, u_char *buf, int buflen)
{
    int			sockfd;
    struct timeval	atv;

    gettimeofday(&atv, NULL);
    switch (svr->svaddr->ai_family)
    {
      case AF_INET:
	sockfd = sendQuery4((struct sockaddr_in *)svr->svaddr->ai_addr, buf, buflen);
	svr->tstamp4 = atv.tv_sec;
	break;

      case AF_INET6:
	sockfd = sendQuery6((struct sockaddr_in6 *)svr->svaddr->ai_addr, buf, buflen);
	svr->tstamp6 = atv.tv_sec;
	break;

      default:
	return (-1);
    }

    return (sockfd);
}


int
sendQuery4(struct sockaddr_in *server, u_char *buf, int buflen)
{
    int		sockfd;
    int		rv;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
	log(LOG_ERR, "Cannot open socket4: %s\n", strerror(errno));
	return (-1);
    }

    if (server->sin_port == 0)
	server->sin_port = htons(NAMESERVER_PORT);

    rv = sendto(sockfd, buf, buflen, 0, (struct sockaddr *)server, server->sin_len);
    if (rv != buflen)
    {
	log(LOG_ERR, "Cannot send Datagram4: %s\n", strerror(errno));
	close(sockfd);
	return (-1);
    }

    return (sockfd);
}


int
sendQuery6(struct sockaddr_in6 *server, u_char *buf, int buflen)
{
    int		sockfd;
    int		rv;

    if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
	log(LOG_ERR, "Cannot open socket6: %s\n", strerror(errno));
	return (-1);
    }

    if (server->sin6_port == 0)
	server->sin6_port = htons(NAMESERVER_PORT);

    rv = sendto(sockfd, buf, buflen, 0, (struct sockaddr *)server, server->sin6_len);
    if (rv != buflen)
    {
	log(LOG_ERR, "Cannot send Datagram6: %s\n", strerror(errno));
	close(sockfd);
	return (-1);
    }

    return (sockfd);
}


int
sendResponse(int sockfd, struct sockaddr *client, u_char *buf, int buflen)
{
    int			 rv = 0;

    switch (client->sa_family)
    {
      case AF_INET:
	rv = sendto(sockfd, buf, buflen, 0, client, client->sa_len);
	break;

      case AF_INET6:
	rv = sendto(sockfd, buf, buflen, 0, client, client->sa_len);
	break;
    }

    return (rv);
}


struct sdesc *
internReplyDesc(int sockfd)
{
    Cell		*p;
    struct sdesc	*sd;

    for (p = openSockets; p; p = CDR(p))
    {
	sd = (struct sdesc *)CAR(p);
	if ((sd->type == RES_PRF_REPLY)
	    && (sd->sockfd <= 0))
	{
	    sd->sockfd = sockfd;
	    return (sd);
	}
    }

    sd = xmalloc(sizeof(struct sdesc));
    bzero(sd, sizeof(struct sdesc));
    sd->type = RES_PRF_REPLY;
    sd->sockfd = sockfd;
    LST_hookup_list(&openSockets, sd);
    return (sd);
}


struct sdesc *
lookForQueryDesc()
{
    return (NULL);
}


/*
 *
 */

int
isOutbound(struct ifaddrs *ifap)
{
    struct ifnets	*ifnp;

    if (ifap == NULL)
	return (FALSE);

    ifnp = (struct ifnets *)ifap->ifa_data;	/* incoming interface	*/
    if (ifnp)
	switch (ifnp->if_side)
	{
	  case noSide:
	  case inSide:
	    return (TRUE);

	  case outSide:
	    return (FALSE);

	  default:
	    log(LOG_INFO, "isOutbound(): illegal side %d\n", ifnp->if_side);
	}

    return (FALSE);
}


struct ifaddrs *
detectRecvInterface(struct sockaddr *from)
{
    struct ifaddrs	*ifap;

    switch (from->sa_family)
    {
      case AF_INET:
	for (ifap = ifaddrs; ifap; ifap = ifap->ifa_next)
	{
	    if (ifap->ifa_addr && (ifap->ifa_addr->sa_family == PF_INET))
	    {
		struct in_addr		addr4, mask4, pckt4;

		mask4 = ((struct sockaddr_in *)ifap->ifa_netmask)->sin_addr;

		addr4 = ((struct sockaddr_in *)ifap->ifa_addr)->sin_addr;
		addr4.s_addr &= mask4.s_addr;

		pckt4 = ((struct sockaddr_in *)from)->sin_addr;
		pckt4.s_addr &= mask4.s_addr;

		if (addr4.s_addr == pckt4.s_addr)
		    return (ifap);
	    }
	}
	break;

#define	s6_addr32	__u6_addr.__u6_addr32
      case AF_INET6:
	for (ifap = ifaddrs; ifap; ifap = ifap->ifa_next)
	{
	    if (ifap->ifa_addr && (ifap->ifa_addr->sa_family == PF_INET6))
	    {
		struct in6_addr		addr6, mask6, pckt6;

		mask6 = ((struct sockaddr_in6 *)ifap->ifa_netmask)->sin6_addr;

		addr6 = ((struct sockaddr_in6 *)ifap->ifa_addr)->sin6_addr;
		addr6.s6_addr32[0] &= mask6.s6_addr32[0];
		addr6.s6_addr32[1] &= mask6.s6_addr32[1];
		addr6.s6_addr32[2] &= mask6.s6_addr32[2];
		addr6.s6_addr32[3] &= mask6.s6_addr32[3];

		pckt6 = ((struct sockaddr_in6 *)from)->sin6_addr;
		pckt6.s6_addr32[0] &= mask6.s6_addr32[0];
		pckt6.s6_addr32[1] &= mask6.s6_addr32[1];
		pckt6.s6_addr32[2] &= mask6.s6_addr32[2];
		pckt6.s6_addr32[3] &= mask6.s6_addr32[3];

		if (IN6_ARE_ADDR_EQUAL(&addr6, &pckt6))
		    return (ifap);
	    }
	}
	break;
#undef	s6_addr32

      default:
	return (NULL);
    }

    return (NULL);
}


struct addrinfo *
getAddrInfo(int family, char *text)
{
    int			 rv;
    struct addrinfo	 hints;
    struct addrinfo	*res;

    switch (family)
    {
      case PF_INET6:
	{
	    struct in6_addr	 in6;
	    struct addrinfo	*ain6;
	    struct sockaddr_in6	*sin6;
	    
	    if ((rv = inet_pton(AF_INET6, text, &in6)) == 0)
		return (NULL);

	    sin6 = xmalloc(sizeof(struct sockaddr_in6));
	    bzero(sin6, sizeof(struct sockaddr_in6));
	    sin6->sin6_len = sizeof(struct sockaddr_in6);
	    sin6->sin6_family = AF_INET6;
	    sin6->sin6_addr = in6;

	    ain6 = xmalloc(sizeof(struct addrinfo));
	    bzero(ain6, sizeof(struct addrinfo));
	    ain6->ai_family  = PF_INET6;
	    ain6->ai_addrlen = sizeof(struct sockaddr_in6);
	    ain6->ai_addr    = (struct sockaddr *)sin6;
	    return (ain6);
	}
	break;

      case PF_UNSPEC:
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = family;

	if ((rv = getaddrinfo(text, NULL, &hints, &res)) != 0)
	{
	    log(LOG_DEBUG, "getAddrInfo: %s\n", gai_strerror(rv));
	    return (NULL);
	}
	break;
    }
    
    if ((family != PF_UNSPEC)
	&& (res->ai_addr->sa_family != family))
    {
	log(LOG_DEBUG, "getAddrInfo: \n");
	return (NULL);
    }

    return (res);
}


void
setServerInside(char *addr)
{
    struct svrInfo	*svr;
    struct addrinfo	*res;

    if ((res = getAddrInfo(PF_UNSPEC, addr)) != NULL)
    {
	svr = (struct svrInfo *)xmalloc(sizeof(struct svrInfo));
	bzero(svr, sizeof(struct svrInfo));
	svr->svaddr = res;

	LST_hookup_list(&serverInside, svr);

	log(LOG_INFO, " InsideServer: %s", displaySockaddr(res->ai_addr));
    }
}


void
setServerOutside(char *addr)
{
    struct svrInfo	*svr;
    struct addrinfo	*res;

    if ((res = getAddrInfo(PF_UNSPEC, addr)) != NULL)
    {
	svr = (struct svrInfo *)xmalloc(sizeof(struct svrInfo));
	bzero(svr, sizeof(struct svrInfo));
	svr->svaddr = res;

	LST_hookup_list(&serverOutside, svr);

	log(LOG_INFO, "OutsideServer: %s", displaySockaddr(res->ai_addr));
    }
}


struct ifaddrs *
toMyAddress(struct sockaddr *from)
{
    char		*ifname;
    struct ifnets	*ifnp;
    struct ifaddrs	*ifap;

    ifname = "";
    for (ifnp = ifnets; ifnp; ifnp = ifnp->if_next)
    {
	if (ifnp->if_flags & IFF_POINTOPOINT)
	    continue;

	if (!(ifnp->if_flags & IFF_RUNNING))
	    continue;

	for (ifap = ifnp->if_addrlist; ifap; ifap = ifap->ifa_next)
	{
	    if (strcmp(ifnp->if_name, ifap->ifa_name) != 0)
		continue;

	    if (ifap->ifa_addr)
	    {
		switch (ifap->ifa_addr->sa_family)
		{
		  case AF_INET:
		    {
			struct in_addr	*adr4, *ptr4;

			adr4 = &((struct sockaddr_in *)ifap->ifa_addr)->sin_addr;
			ptr4 = &((struct sockaddr_in *)from)->sin_addr;
			if (adr4->s_addr == ptr4->s_addr)
			    return (ifap);
		    }
		    break;

		  case AF_INET6:
		    {
			struct in6_addr	*adr6, *ptr6;

			if (ifap->ifa_flags6 & IN6_IFF_ANYCAST)
			    continue;

			adr6 = &((struct sockaddr_in6 *)ifap->ifa_addr)->sin6_addr;
			ptr6 = &((struct sockaddr_in6 *)from)->sin6_addr;
			if (IN6_ARE_ADDR_EQUAL(adr6, ptr6))
			    return (ifap);
		    }
		    break;
		}
	    }
	}
    }

    return (NULL);
}


/*
 *
 */

void
openSocket()
{
    int			 sd;
    char		*ifname;
    struct ifnets	*ifnp;
    struct ifaddrs	*ifap;

    openSockets = NULL;
    ifname = "";
    for (ifnp = ifnets; ifnp; ifnp = ifnp->if_next)
    {
	if (ifnp->if_flags & IFF_POINTOPOINT)
	    continue;

	if (!(ifnp->if_flags & IFF_RUNNING))
	    continue;

	for (ifap = ifnp->if_addrlist; ifap; ifap = ifap->ifa_next)
	{
	    if (strcmp(ifnp->if_name, ifap->ifa_name) != 0)
		continue;

	    if (ifap->ifa_addr)
	    {
		struct sdesc	*desc;

		desc = xmalloc(sizeof(struct sdesc));
		bzero(desc, sizeof(struct sdesc));
		desc->saddr = ifap->ifa_addr;

		switch (ifap->ifa_addr->sa_family)
		{
		  case AF_INET:
		    if ((sd = openSocket4(ifap)) > 0)
		    {
			desc->type = RES_PRF_QUERY;
			desc->sockfd = sd;
			LST_hookup_list(&openSockets, desc);
		    }
		    break;

		  case AF_INET6:
		    if ((sd = openSocket6(ifap)) > 0)
		    {
			desc->type = RES_PRF_QUERY;
			desc->sockfd = sd;
			LST_hookup_list(&openSockets, desc);
		    }
		    break;
		}
	    }
	}
    }
}


int
openSocket4(struct ifaddrs *ifap)
{
    int			sd4;
    struct sockaddr_in	sin4;

    if ((sd4 = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
	log(LOG_ERR, "socket open failure on `%s\'", ifap->ifa_name);
	return (-1);
    }

    bzero(&sin4, sizeof(struct sockaddr_in));
    sin4.sin_family = AF_INET;
    sin4.sin_port   = htons(NAMESERVER_PORT);
    sin4.sin_addr   = ((struct sockaddr_in *)ifap->ifa_addr)->sin_addr;
    if (bind(sd4, (struct sockaddr *)&sin4, sizeof(struct sockaddr_in)) < 0)
    {
	log(LOG_ERR, "bind failure on `%s\' (%s: %s)",
	    ifap->ifa_name,
	    strerror(errno),
	    displaySockaddrIn4(&sin4));
	return (-2);
    }

    return (sd4);
}


int
openSocket6(struct ifaddrs *ifap)
{
    int			sd6;
    struct sockaddr_in6	sin6;
    struct in6_ifreq	ifr6;

    if ((sd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
	log(LOG_ERR, "socket open failure on `%s\'", ifap->ifa_name);
	return (-1);
    }

    bzero(&sin6, sizeof(struct sockaddr_in6));
    sin6.sin6_len    = sizeof(struct sockaddr_in6);
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr   = ((struct sockaddr_in6 *)ifap->ifa_addr)->sin6_addr;

    bzero(&ifr6, sizeof(struct in6_ifreq));
    strncpy(ifr6.ifr_name, ifap->ifa_name, sizeof(ifr6.ifr_name));
    ifr6.ifr_addr = sin6;
    if (ioctl(sd6, SIOCGIFAFLAG_IN6, &ifr6) < 0)
    {
	log(LOG_INFO, "ioctl failure on SIOCGIFAFLAG_IN6");
	close (sd6);
	return (-1);
    }

    ifap->ifa_flags6 = ifr6.ifr_ifru.ifru_flags6;
    if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST)
    {
	log(LOG_INFO, "cannot bind anycast address (%s) of %s",
	    displaySockaddrIn6(&sin6),
	    ifap->ifa_name);
	close (sd6);
	return (-1);
    }

    sin6.sin6_port   = htons(NAMESERVER_PORT);
    if (bind(sd6, (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6)) < 0)
    {
	log(LOG_ERR, "bind failure on `%s\' (%s: %s)",
	    ifap->ifa_name,
	    strerror(errno),
	    displaySockaddrIn6(&sin6));
	return (-2);
    }

    return (sd6);
}


/*
 *
 */

#if defined(NET_RT_IFLIST) && (defined(__FreeBSD__) || defined(__NetBSD__))

int
getifaddrs(struct ifaddrs **pif)
{
    int			 mib[6];
    size_t		 needed;
    char		*buf, *lim, *next;
    struct rt_msghdr	*rtm;
    struct ifaddrs	*ifa, *ifc, *ift, *cif;

    ifa = ifc = ift = cif = NULL;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
	perror("sysctl"), quitting(errno);

    if ((buf = xmalloc(needed)) == NULL)
	perror("xmalloc"), quitting(errno);

    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
	perror("sysctl"), quitting(errno);

    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen)
    {
	rtm = (struct rt_msghdr *)next;
	if (rtm->rtm_version != RTM_VERSION)
	    continue;

	switch (rtm->rtm_type)
	{
	  case RTM_IFINFO:
	    {
		struct if_msghdr	*ifm;
		struct sockaddr_dl	*dl;

		ifm =  (struct if_msghdr *)rtm;
		if (ifm->ifm_addrs & RTA_IFP)
		{
		    dl = (struct sockaddr_dl *)(ifm+1);

		    ifc = (struct ifaddrs *)calloc(1, sizeof(struct ifaddrs));
		    ifc->ifa_addr = (struct sockaddr *)dl;

		    ifc->ifa_name = (char *)calloc(1, ROUNDUP(dl->sdl_nlen + 1));
		    bcopy(dl->sdl_data, ifc->ifa_name, dl->sdl_nlen);
		    ifc->ifa_flags = (int)ifm->ifm_flags;

		    if (ifa == NULL)	ifa = ifc;
		    if (ift == NULL)	ift = ifc;
		    else		ift->ifa_next = ifc, ift = ifc;
		    cif = ifc;
		}
	    }
	    break;

	  case RTM_NEWADDR:
	    {
		int			 bits;
		struct ifa_msghdr	*ifam;
		struct sockaddr		*sa;

		ifc = (struct ifaddrs *)calloc(1, sizeof(struct ifaddrs));
		ifc->ifa_name  = cif->ifa_name;
		ifc->ifa_flags = cif->ifa_flags;

		if (ifa == NULL)	ifa = ifc;
		if (ift == NULL)	ift = ifc;
		else		ift->ifa_next = ifc, ift = ifc;

		ifam = (struct ifa_msghdr *)rtm;
		sa = (struct sockaddr *)(ifam+1);

		for (bits = 1; bits <= 0x80; bits <<= 1)
		{
		    if ((ifam->ifam_addrs & bits) == 0)
			continue;
		    
		    switch (bits)
		    {
		      case RTA_NETMASK:
			ifc->ifa_netmask = sa;
			break;

		      case RTA_IFA:
			ifc->ifa_addr = sa;
			break;

		      case RTA_BRD:
			ifc->ifa_broadaddr = sa;
			break;
		    }
		    sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len));
		}
	    }
	    break;
	}
    }
    *pif = ifa;
    return (0);
}

#endif	/* defined(NET_RT_IFLIST) && (defined(__FreeBSD__) || defined(__NetBSD__))	*/


struct ifnets *
mkifnets(struct ifaddrs *ifaddrs)
{
    char		*ifname;
    struct ifaddrs	*ifap;
    struct ifnets	*hook, *anchor, *ifnp;

    ifname = "";
    hook = anchor = NULL;
    for (ifap = ifaddrs; ifap; ifap = ifap->ifa_next)
    {
	if (strcmp(ifname, ifap->ifa_name) != 0)
	{
	    ifnp = (struct ifnets *)xmalloc(sizeof(struct ifnets));
	    bzero(ifnp, sizeof(struct ifnets));
	    ifnp->if_addrlist = ifap;
	    ifnp->if_flags = ifap->ifa_flags;
	    strncpy(ifnp->if_name, ifap->ifa_name, MIN(strlen(ifap->ifa_name), IFNAMSIZ));

	    if (hook == NULL)
		hook = anchor = ifnp;
	    else
		anchor->if_next = ifnp, anchor = ifnp;

	    ifname = ifap->ifa_name;
	}

	ifap->ifa_data = (void *)anchor;
    }

    return (hook);
}


void
dumpIfnets()
{
    char		*ifname;
    struct ifnets	*ifnp;
    struct ifaddrs	*ifap;

    ifname = "";
    for (ifnp = ifnets; ifnp; ifnp = ifnp->if_next)
    {
	ifname = ifnp->if_name;

	printf("%s: flags=%x\n", ifnp->if_name, ifnp->if_flags);
	for (ifap = ifnp->if_addrlist; ifap; ifap = ifap->ifa_next)
	{
	    if (strcmp(ifname, ifap->ifa_name) == 0)
		dumpIfaddr(ifap);
	}
    }
}


void
dumpIfaddrs()
{
    char		*ifname;
    struct ifaddrs	*ifap;

    ifname = "";
    for (ifap = ifaddrs; ifap; ifap = ifap->ifa_next)
    {
	if (strcmp(ifname, ifap->ifa_name) != 0)
	{
	    printf("%s: flags=%x\n", ifap->ifa_name, ifap->ifa_flags);
	    ifname = ifap->ifa_name;
	}

	dumpIfaddr(ifap);
    }
}


void
dumpIfaddr(struct ifaddrs *ifap)
{
    if (ifap->ifa_addr)
    {
	if (ifap->ifa_addr->sa_family == PF_INET)
	    printf("\tinet  %s", displaySockaddr(ifap->ifa_addr));
	else if (ifap->ifa_addr->sa_family == PF_INET6)
	    printf("\tinet6 %s", displaySockaddr(ifap->ifa_addr));
	else if (ifap->ifa_addr->sa_family == PF_LINK)
	    printf("\tether %s", displaySockaddr(ifap->ifa_addr));
    }

    if (ifap->ifa_netmask)
    {
	if ((ifap->ifa_netmask->sa_family == PF_INET)
	    || (ifap->ifa_netmask->sa_family == PF_UNSPEC))
	    printf("\tnetmask  %s", displaySockaddr(ifap->ifa_netmask));
	else if (ifap->ifa_netmask->sa_family == PF_INET6)
	    printf("\tnetmask6 %s", displaySockaddr(ifap->ifa_netmask));
    }

    if (ifap->ifa_dstaddr)
    {
	if (ifap->ifa_dstaddr->sa_family == PF_INET)
	    printf("\tdstaddr  %s", displaySockaddr(ifap->ifa_dstaddr));
	else if (ifap->ifa_dstaddr->sa_family == PF_INET6)
	    printf("\tdstaddr6 %s", displaySockaddr(ifap->ifa_dstaddr));
    }

#if	0
    if (ifap->ifa_data)
	printf("\t(%s)", ((struct ifnets *)ifap->ifa_data)->if_name);
#endif
    
    printf("\n");
}


char *
displaySockaddr(struct sockaddr *from)
{
    switch (from->sa_family)
    {
      case AF_INET:
	return (displaySockaddrIn4((struct sockaddr_in *)from));

      case AF_INET6:
	return (displaySockaddrIn6((struct sockaddr_in6 *)from));
	
      case AF_LINK:
	return (displaySockaddrDl((struct sockaddr_dl *)from));
    }

    return ("unknown");
}


char *
displaySockaddrIn4(struct sockaddr_in *from)
{
    static char	in4txt[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, (char *)&from->sin_addr, in4txt, INET_ADDRSTRLEN);
    return (in4txt);
}


char *
displaySockaddrIn6(struct sockaddr_in6 *from)
{
    static char	in6txt[INET6_ADDRSTRLEN];
    
    inet_ntop(AF_INET6, (char *)&from->sin6_addr, in6txt, INET6_ADDRSTRLEN);
    return (in6txt);
}


char *
displaySockaddrDl(struct sockaddr_dl *from)
{
    char	*cp;
    static char	 dltxt[sizeof("ff:ff:ff:ff:ff:ff:00")];

    cp = from->sdl_data;
    cp += from->sdl_nlen;
    sprintf(dltxt, "%02x:%02x:%02x:%02x:%02x:%02x",
	    cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
    return (dltxt);
}


void
sighandler(int sig)
{
    switch (sig)
    {
      case 0:
	{
	    int		iter;

	    sigemptyset(&mask);
	    for (iter = 0; iter < sizeof(signals) / sizeof(signals[0]); iter++)
	    {
		sigaddset(&mask, signals[iter]);
	    }

	    for (iter = 0; iter < sizeof(signals) / sizeof(signals[0]); iter++)
	    {
		struct sigaction	sa;

		bzero(&sa, sizeof(struct sigaction));
		sa.sa_mask = mask;
		sa.sa_handler = sighandler;
		if (sigaction(signals[iter], &sa, NULL) < 0)
		{
		    log(LOG_NOTICE, "initSignal(): sigaction failed(%d): %s",
			signals[iter], strerror(errno));
		}
	    }
	}
	break;

      case SIGTERM:
	{
	    FILE	*fp;

	    if ((fp = writeOpen(__op.dumpFilename, 0)) != NULL)
	    {
		xmallocShow(fp);
		fclose(fp);
	    }
	}
	break;

      default:
	log(LOG_ERR, "caught signal, %d\n", sig);
	quitting (0);
	break;
    }
}


/*
 *
 */

void
debugProbe(char *msg)
{
    char	Wow[BUFSIZ];

    sprintf(Wow, "%s\n", msg);
    fprintf(stderr, Wow);
}


void *
xmalloc(size_t size)
{
    int		 iter;
    void	*p;
    caddr_t	 fp;

    if (xmalloc_initialized == 0)
    {
	xmalloc_initialized++;
	bzero(xalo, sizeof(xalo));
    }

    fp = (caddr_t)&size;
    fp -= sizeof(void *);				/* FreeBSD228 specific	XXX	*/

    p = malloc(size);
    for (iter = 0; iter < 1024; iter++)
    {
	if (xalo[iter].alloced == NULL)
	{
	    xalo[iter].alloced = p;
	    xalo[iter].caller  = *(caddr_t *)fp;
	    xalo[iter].size    = size;
	    break;
	}
    }

    if (isDebug(DEBUG_XMALLOC))
    {
	log(LOG_DEBUG, "alloced: 0x%08x, caller: 0x%08x, size %5d",
	    xalo[iter].alloced, xalo[iter].caller, xalo[iter].size);
    }

    return (p);
}


void
xfree(void *ptr)
{
    int		iter;

    for (iter = 0; iter < 1024; iter++)
    {
	if (xalo[iter].alloced == ptr)
	{
	    xalo[iter].alloced = NULL;
	    xalo[iter].caller  = NULL;
	    xalo[iter].size    = 0;
	    break;
	}
    }

    if (isDebug(DEBUG_XMALLOC))
    {
	log(LOG_DEBUG, "freed: 0x%08x", ptr);
    }

    free(ptr);
}


void
xmallocShow(FILE *fp)
{
    int		iter;
    FILE	*stream = stderr;

    if (fp != NULL)
	stream = fp;

    for (iter = 0; iter < 1024; iter++)
    {
	if (xalo[iter].alloced != NULL)
	{
	    fprintf(stream, "addr: 0x%08x, caller: 0x%08x, size: %6d",
		    (uint)xalo[iter].alloced,
		    (uint)xalo[iter].caller,
		    (uint)xalo[iter].size);

	    if (xalo[iter].size == sizeof(struct msgHndl))
	    {
		struct msgHndl	*msg = (struct msgHndl *)xalo[iter].alloced;
		fprintf(stream, " id: %6d", ntohs(msg->hdr.id));
	    }
		
	    fprintf(stream, "\n");
	}
    }
}


/*
 *
 */

void
initIfnets()
{
#if defined(__FreeBSD__) || defined(__NetBSD__) || (_BSDI_VERSION >= 199701)
    if (getifaddrs(&ifaddrs) < 0)
	perror("getifaddrs");
#else
    struct ifaddrs	*nip;

    if (getifaddrs(&ifaddrs, &nip) < 0)
	perror("getifaddrs");
#endif	/* defined(__FreeBSD__) || defined(__NetBSD__) || (_BSDI_VERSION >= 199701)	*/

    ifnets = mkifnets(ifaddrs);
}


void
initSignal()
{
    sighandler(0);
}


void
init_misc()
{
    if (isDebug(DEBUG_IFADDR))
	dumpIfaddrs(), dumpIfnets();

    openSocket();
}
