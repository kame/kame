/*	$KAME: showsubs.c,v 1.6 2001/09/11 06:43:08 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#define TCPSTATES		1
#include <netinet/tcp_fsm.h>

#include <arpa/inet.h>

#include <netinet6/natpt_defs.h>


/*
 *
 */

struct logmsg
{
	int		 lmsg_size;	/* data byte count			*/
	char		*lmsg_data;	/* malloced data area			*/
	char		*lmsg_last;	/* pointer to just after last byte.	*/
};


extern char	*tcpstates[];


/*
 *
 */

void	 makeCSlotLine		__P((char *, int, struct cSlot *));
void	 appendPAddr		__P((struct logmsg *, struct pAddr *));
void	 appendPAddr4		__P((struct logmsg *, struct pAddr *));
void	 appendPAddr6		__P((struct logmsg *, struct pAddr *));
void	 appendPort		__P((struct logmsg *, struct pAddr *));
void	 makeTSlotLine		__P((char *, int, struct tSlot *,
				     struct tcpstate *, int));
void	 appendPAddrXL		__P((struct logmsg *, struct pAddr *, int));
void	 appendPAddrXL4		__P((struct logmsg *, struct pAddr *));
void	 appendPAddrXL6		__P((struct logmsg *, struct pAddr *, int));
void	 appendpAddrXL6long	__P((struct logmsg *, struct in6_addr *, u_short));
void	 appendpAddrXL6short	__P((struct logmsg *, struct in6_addr *, u_short));
void	 concat			__P((struct logmsg *, char *, ...));

int	 readKvm		__P((void *, int, void *));


/*
 *
 */

void
makeCSlotLine(char *wow, int size, struct cSlot *csl)
{
	struct logmsg	lmsg;

	bzero(&lmsg, sizeof(struct logmsg));

	lmsg.lmsg_size = size;
	lmsg.lmsg_data = wow;
	lmsg.lmsg_last = lmsg.lmsg_data;

	concat(&lmsg, " from");
	appendPAddr(&lmsg, &csl->local);
	concat(&lmsg, " to");
	appendPAddr(&lmsg, &csl->remote);

	if (csl->proto) {
		int	found = 0;

		concat(&lmsg, " proto ");
		if (csl->proto & NATPT_ICMP) {
			concat(&lmsg, "icmp");
			found++;
		}
		if (csl->proto & NATPT_TCP) {
			if (found > 0)
				concat(&lmsg, "/");
			concat(&lmsg, "tcp");
			found++;
		}
		if (csl->proto & NATPT_UDP) {
			if (found > 0)
				concat(&lmsg, "/");
			concat(&lmsg, "udp");
		}
	}

	if (csl->lifetime != CSLOT_INFINITE_LIFETIME) {
		int		 remain;
		struct timeval	 atv;


		gettimeofday(&atv, NULL);
		remain = csl->lifetime - (atv.tv_sec - csl->tstamp);
		concat(&lmsg, " lifetime %d", (remain >= 0) ? remain : 0);
	}

	*lmsg.lmsg_last =  '\0';
}


void
appendPAddr(struct logmsg *lmsg, struct pAddr *pad)
{
	if (pad->sa_family == AF_INET)
		appendPAddr4(lmsg, pad);
	else
		appendPAddr6(lmsg, pad);
}


void
appendPAddr4(struct logmsg *lmsg, struct pAddr *pad)
{
	char	Wow[128];

	if (pad->aType == ADDR_ANY)
		concat(lmsg, " any4");
	else
		concat(lmsg, " %s",
		       inet_ntop(AF_INET, &pad->in4Addr, Wow, sizeof(Wow)));

	if (pad->prefix != 0)
		concat(lmsg, "/%d", pad->prefix);
	else if (pad->in4RangeEnd.s_addr != 0)
		concat(lmsg, " - %s",
		       inet_ntop(AF_INET, &pad->in4RangeEnd, Wow, sizeof(Wow)));

	appendPort(lmsg, pad);
}


void
appendPAddr6(struct logmsg *lmsg, struct pAddr *pad)
{
	struct in6_addr	in6addr = IN6ADDR_ANY_INIT;
	char		Wow[128];

	if (IN6_ARE_ADDR_EQUAL(&pad->in6Addr, &in6addr))
		concat(lmsg, " any6");
	else
		concat(lmsg, " %s",
		       inet_ntop(AF_INET6, &pad->in6Addr, Wow, sizeof(Wow)));

	if (pad->prefix != 0)
		concat(lmsg, "/%d", pad->prefix);

	appendPort(lmsg, pad);
}


void
appendPort(struct logmsg *lmsg, struct pAddr *pad)
{
	if (pad->port[0] == 0) {
		if (pad->port[1] == 0)
			;
		else
			concat(lmsg, " dport %d", ntohs(pad->port[1]));
	} else {
		concat(lmsg, " port %d", ntohs(pad->port[0]));
		if (pad->port[1] != 0) {
			if (pad->pType == PORT_MINUS)
				concat(lmsg, " - %d", ntohs(pad->port[1]));
			else
				concat(lmsg, " : %d",
				       ntohs(pad->port[1]) - ntohs(pad->port[0]));
		}
	}
}


void
makeTSlotLine(char *wow, int size, struct tSlot *tsl,
	      struct tcpstate *ts, int type)
{
	long		 idle;
	struct timeval	 tp;
	struct logmsg	 lmsg;


	bzero(&lmsg, sizeof(struct logmsg));

	lmsg.lmsg_size = size;
	lmsg.lmsg_data = wow;
	lmsg.lmsg_last = lmsg.lmsg_data;

	switch (tsl->ip_p) {
	case IPPROTO_ICMP:	concat(&lmsg, "icmp  ");	break;
	case IPPROTO_ICMPV6:	concat(&lmsg, "icmp6 ");	break;
	case IPPROTO_TCP:	concat(&lmsg, "tcp   ");	break;
	case IPPROTO_UDP:	concat(&lmsg, "udp   ");	break;
	default:		concat(&lmsg, "unk   ");	break;
	}

	appendPAddrXL(&lmsg, &tsl->local, type);
	appendPAddrXL(&lmsg, &tsl->remote, type);

	concat(&lmsg, "%6d%6d ", tsl->tofrom, tsl->fromto);

	gettimeofday(&tp, NULL);
	idle = tp.tv_sec - tsl->tstamp;
	concat(&lmsg, "%02d:%02d:%02d ", idle/3600, (idle%3600)/60, idle%60);

	switch (tsl->ip_p) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		concat(&lmsg, "%5d/%-5d ",
		       tsl->suit.ih_idseq.icd_id, tsl->suit.ih_idseq.icd_seq);
		break;

	case IPPROTO_TCP:
		if (ts == NULL)
			break;

		if (ts->state < TCP_NSTATES)
			concat(&lmsg, "%s ", tcpstates[ts->state]);
		else
			concat(&lmsg, "%d ", ts->state);
		break;
	}

	*lmsg.lmsg_last = '\0';
}



void
appendPAddrXL(struct logmsg *lmsg, struct pAddr *pad, int type)
{
	if (pad->sa_family == AF_INET)
		appendPAddrXL4(lmsg, pad);
	else
		appendPAddrXL6(lmsg, pad, type);
}


void
appendPAddrXL4(struct logmsg *lmsg, struct pAddr *pad)
{
	char	Bow[128];
	char	Wow[128];

	inet_ntop(AF_INET, &pad->in4src, Bow, sizeof(Bow));
	snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[0]));
	concat(lmsg, "%-22s", Wow);

	inet_ntop(AF_INET, &pad->in4dst, Bow, sizeof(Bow));
	snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[1]));
	concat(lmsg, "%-22s", Wow);
}


void
appendPAddrXL6(struct logmsg *lmsg, struct pAddr *pad, int type)
{
	if (type != 0) {
		appendpAddrXL6long(lmsg, &pad->in6src, pad->port[0]);
		appendpAddrXL6long(lmsg, &pad->in6dst, pad->port[1]);

	} else {
		appendpAddrXL6short(lmsg, &pad->in6src, pad->port[0]);
		appendpAddrXL6short(lmsg, &pad->in6dst, pad->port[1]);
	}
}


void
appendpAddrXL6long(struct logmsg *lmsg, struct in6_addr *addr, u_short port)
{
	char	Bow[128];
	char	Wow[128];

	inet_ntop(AF_INET6, addr, Bow, sizeof(Bow));
	snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(port));
	concat(lmsg, "%-45s", Wow);
}


void
appendpAddrXL6short(struct logmsg *lmsg, struct in6_addr *addr, u_short port)
{
	int	 iter;
	char	*s, *d;
	char	 Bow[128];
	char	 Wow[128];
	char	 miaow[128];

	bzero(miaow, sizeof(miaow));
	bzero(Bow,   sizeof(Bow));
	inet_ntop(AF_INET6, addr, miaow, sizeof(miaow));

	if (strlen(miaow) <= 15) {
		strcpy(Bow, miaow);
	} else {
		s = miaow;
		d = Bow;
		for (iter = 0; iter <= 3; iter++)	*d++ = *s++;
		*d++ = '=';
		while (*s++ != '\0')			;
		s -= 10;
		for (iter = 0; iter <= 9; iter++)	*d++ = *s++;
	}

	snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(port));
	concat(lmsg, "%-22s", Wow);
}


void
concat(struct logmsg *lmsg, char *fmt, ...)
{
	const char *fn = __FUNCTION__;

	int	 rv;
	char	*s, *d;
	char	 Wow[BUFSIZ];
	va_list	 ap;

	va_start(ap, fmt);
	rv = vsnprintf(Wow, sizeof(Wow), fmt, ap);

	if (lmsg->lmsg_last + rv > lmsg->lmsg_data + lmsg->lmsg_size)
		errx(1, "%s(): too big message", fn);
	va_end(ap);

	s = Wow;
	d = lmsg->lmsg_last;
	while (*s)	*d++ = *s++;
	lmsg->lmsg_last = d;
}
