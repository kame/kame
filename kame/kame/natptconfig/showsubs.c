/*	$KAME: showsubs.c,v 1.31 2002/07/01 21:06:25 fujisawa Exp $	*/

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

#include "defs.h"


/*
 *
 */

int	cslmode;

struct logmsg
{
	int		 lmsg_size;	/* data byte count			*/
	char		*lmsg_data;	/* malloced data area			*/
	char		*lmsg_last;	/* pointer to just after last byte.	*/
};


extern char	*tcpstates[];

char *tcpstatesshort[] = {
	"CL",		/* "CLOSED" */
	"LI",		/* "LISTEN" */
	"SS",		/* "SYN_SENT" */
	"SR",		/* "SYN_RCVD" */
	"ES",		/* "ESTABLISHED" */
	"CW",		/* "CLOSE_WAIT" */
	"F1",		/* "FIN_WAIT_1" */
	"CG",		/* "CLOSING" */
	"LA",		/* "LAST_ACK" */
	"F2",		/* "FIN_WAIT_2" */
	"TW",		/* "TIME_WAIT" */
};

/*
 *
 */

void	 makeCSlotLine		__P((char *, int, struct cSlot *));
void	 makeCUILine		__P((char *, int, struct cSlot *));
void	 makeCUI64Line		__P((struct logmsg *, struct cSlot *));
void	 makeCUI46Line		__P((struct logmsg *, struct cSlot *));
void	 appendPAddr		__P((struct logmsg *, struct cSlot *, struct mAddr *));
void	 appendPAddr4		__P((struct logmsg *, struct cSlot *, struct mAddr *));
void	 appendPAddr6		__P((struct logmsg *, struct cSlot *, struct mAddr *));
void	 appendPort		__P((struct logmsg *, struct mAddr *));
void	 appendProto		__P((struct logmsg *, struct cSlot *));
void	 makeTSlotLine		__P((char *, int, struct tSlot *,
				     struct tcpstate *, int));
void	 appendPAddrXL		__P((struct logmsg *, struct pAddr *, int, int));
void	 appendPAddrXL4		__P((struct logmsg *, struct pAddr *, int, int));
void	 appendPAddrXL6		__P((struct logmsg *, struct pAddr *, int, int));
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

	cslmode = 1;

	bzero(&lmsg, sizeof(struct logmsg));
	lmsg.lmsg_size = size;
	lmsg.lmsg_data = wow;
	lmsg.lmsg_last = lmsg.lmsg_data;

	concat(&lmsg, " from");
	appendPAddr(&lmsg, csl, &csl->local);
	concat(&lmsg, " to");
	appendPAddr(&lmsg, csl, &csl->remote);

	appendProto(&lmsg, csl);

	if (csl->map & NATPT_BIDIR) {
		concat(&lmsg, " bidir");
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
makeCUILine(char *wow, int size, struct cSlot *csl)
{
	struct logmsg	lmsg;

	cslmode = 0;

	bzero(&lmsg, sizeof(struct logmsg));
	lmsg.lmsg_size = size;
	lmsg.lmsg_data = wow;
	lmsg.lmsg_last = lmsg.lmsg_data;

	/*
	 * Translation rule supports onln v6->v4 and v4->v6 translation
	 * when use Character-based User Interface.
	 */
	if (csl->local.saddr.sa_family == AF_INET6)
		makeCUI64Line(&lmsg, csl);
	else
		makeCUI46Line(&lmsg, csl);

	*lmsg.lmsg_last =  '\0';
}


void
makeCUI64Line(struct logmsg *lmsg, struct cSlot *csl)
{
	/* In case v6->v4, assume NAPT-PT or One-on-one translation	*/
	if ((csl->remote.Port[0])
	    || ((csl->proto & NATPT_ICMPV6)
		&& (((struct mAddr *)&csl->local)->saddr.aType != ADDR_SINGLE))) {

		/* in case NAPT-PT	*/
		concat(lmsg, "masquerade");
		if (((struct mAddr *)&csl->local)->saddr.prefix != 0)
			appendPAddr6(lmsg, csl, (struct mAddr *)&csl->local);
		else
			concat(lmsg, " any");
		appendPAddr4(lmsg, csl, (struct mAddr *)&csl->remote);
		appendProto(lmsg, csl);
	} else {

		/* in case One-on-one translation */
		if (((struct mAddr *)&csl->local)->saddr.aType != ADDR_SINGLE)
			concat(lmsg, "masquerade");
		else
			concat(lmsg, "static");

		if (csl->map & NATPT_BIDIR) {
			concat(lmsg, " bidir");
		} else {
			concat(lmsg, " 6to4");
		}

		appendPAddr6(lmsg, csl, (struct mAddr *)&csl->local);
		appendPAddr4(lmsg, csl, (struct mAddr *)&csl->remote);
		appendProto(lmsg, csl);
	}
}


void
makeCUI46Line(struct logmsg *lmsg, struct cSlot *csl)
{
	/* In case v4->v6, assume port redirect or One-on-one translation */

	if (csl->remote.dport == 0) {
		concat(lmsg, "static");
		concat(lmsg, " 4to6");
		appendPAddr4(lmsg, csl, (struct mAddr *)&csl->local);
		appendPAddr6(lmsg, csl, (struct mAddr *)&csl->remote);
		appendProto(lmsg, csl);
	} else {
		concat(lmsg, "redirect");
		appendPAddr4(lmsg, csl, (struct mAddr *)&csl->local);
		appendPAddr6(lmsg, csl, (struct mAddr *)&csl->remote);
		appendProto(lmsg, csl);
	}
}


void
appendPAddr(struct logmsg *lmsg, struct cSlot *csl, struct mAddr *mpad)
{
	if (mpad->saddr.sa_family == AF_INET)
		appendPAddr4(lmsg, csl, mpad);
	else
		appendPAddr6(lmsg, csl, mpad);
}


void
appendPAddr4(struct logmsg *lmsg, struct cSlot *csl, struct mAddr *mpad)
{
	char	Wow[128];

	if (mpad->saddr.aType != ADDR_ANY)
		concat(lmsg, " %s",
		       inet_ntop(AF_INET, &mpad->saddr.in4Addr, Wow, sizeof(Wow)));
	else if ((csl->map & NATPT_REDIRECT_ADDR) == 0)
		concat(lmsg, " any4");

	if (mpad->saddr.prefix != 0)
		concat(lmsg, "/%d", mpad->saddr.prefix);
	else if (mpad->saddr.in4RangeEnd.s_addr != 0)
		concat(lmsg, " - %s",
		       inet_ntop(AF_INET, &mpad->saddr.in4RangeEnd, Wow, sizeof(Wow)));

	if (csl->map & NATPT_REDIRECT_ADDR) {
		concat(lmsg, (cslmode ? " daddr " : " "));
		concat(lmsg, "%s",
		       inet_ntop(AF_INET, &mpad->daddr, Wow, sizeof(Wow)));
	}

	appendPort(lmsg, mpad);
}


void
appendPAddr6(struct logmsg *lmsg, struct cSlot *csl, struct mAddr *mpad)
{
	struct in6_addr	in6addr = IN6ADDR_ANY_INIT;
	char		Wow[128];

	if (!IN6_ARE_ADDR_EQUAL(&mpad->saddr.in6Addr, &in6addr))
		concat(lmsg, " %s",
		       inet_ntop(AF_INET6, &mpad->saddr.in6Addr, Wow, sizeof(Wow)));
	else if ((csl->map & NATPT_REDIRECT_ADDR) == 0)
		concat(lmsg, " any6");

	if (mpad->saddr.prefix != 0)
		concat(lmsg, "/%d", mpad->saddr.prefix);

	if (csl->map & NATPT_REDIRECT_ADDR) {
		concat(lmsg, (cslmode ? " daddr " : " "));
		concat(lmsg, "%s",
		       inet_ntop(AF_INET6, &mpad->daddr, Wow, sizeof(Wow)));
	}

	appendPort(lmsg, mpad);
}


void
appendPort(struct logmsg *lmsg, struct mAddr *mpad)
{
	char	*fmtp = " port %d";
	char	*fmtd = " - %d";

	if (cslmode == 0) {
		fmtp = " %d";
		fmtd = "-%d";
	}

	if (mpad->Port[0]) {
		concat(lmsg, fmtp, ntohs(mpad->saddr.port[0]));
		if (mpad->Port[1] != 0) {
			if (mpad->saddr.pType == PORT_MINUS)
				concat(lmsg, fmtd, ntohs(mpad->Port[1]));
			else
				concat(lmsg, " : %d",
				       ntohs(mpad->Port[1]) - ntohs(mpad->Port[0]));
		}
	}

	if (mpad->dport) {
		concat(lmsg, (cslmode ? " dport " : " "));
		concat(lmsg, "%d", ntohs(mpad->dport));
	}
}


void
appendProto(struct logmsg *lmsg, struct cSlot *csl)
{
	int	found = 0;

	if (csl->proto) {
		concat(lmsg, (cslmode ? " proto " : " "));
		if (csl->proto & NATPT_ICMP) {
			concat(lmsg, "icmp");
			found++;
		}
		if (csl->proto & NATPT_TCP) {
			if (found > 0)
				concat(lmsg, "/");
			concat(lmsg, "tcp");
			found++;
		}
		if (csl->proto & NATPT_UDP) {
			if (found > 0)
				concat(lmsg, "/");
			concat(lmsg, "udp");
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

	appendPAddrXL(&lmsg, &tsl->local, type, XLATE_LOCAL);
	appendPAddrXL(&lmsg, &tsl->remote, type, XLATE_REMOTE);

	concat(&lmsg, "%6d%6d ", tsl->tofrom, tsl->fromto);

	gettimeofday(&tp, NULL);
	idle = tp.tv_sec - tsl->tstamp;
	concat(&lmsg, "%02d:%02d:%02d ", idle/3600, (idle%3600)/60, idle%60);

	switch (tsl->ip_p) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		concat(&lmsg, "%5d/%-5d ",
		       ntohs(tsl->suit.ih_idseq.icd_id),
		       ntohs(tsl->suit.ih_idseq.icd_seq));
		break;

	case IPPROTO_TCP:
		if (ts == NULL)
			break;

		if (ts->state < TCP_NSTATES) {
			if ((type == XLATE_TRACE)
			    || (type == XLATE_SHORT))
				concat(&lmsg, "%s ", tcpstatesshort[ts->state]);
			else
				concat(&lmsg, "%s ", tcpstates[ts->state]);
		} else
			concat(&lmsg, "%d ", ts->state);
		break;
	}

	*lmsg.lmsg_last = '\0';
}



void
appendPAddrXL(struct logmsg *lmsg, struct pAddr *pad, int type, int inv)
{
	if (pad->sa_family == AF_INET)
		appendPAddrXL4(lmsg, pad, type, inv);
	else
		appendPAddrXL6(lmsg, pad, type, inv);
}


void
appendPAddrXL4(struct logmsg *lmsg, struct pAddr *pad, int type, int inv)
{
	char	Bow[128];
	char	Wow[128];

	if (inv == XLATE_LOCAL) {
		switch (type) {
		case XLATE_TRACE:
		case XLATE_SHORT:
			inet_ntop(AF_INET, &pad->in4src, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[0]));
			concat(lmsg, "%-22s", Wow);
			break;

		default:
			inet_ntop(AF_INET, &pad->in4src, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[0]));
			concat(lmsg, "%-22s", Wow);

			inet_ntop(AF_INET, &pad->in4dst, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[1]));
			concat(lmsg, "%-22s", Wow);
			break;
		}
	} else {
		switch (type) {
		case XLATE_TRACE:
			inet_ntop(AF_INET, &pad->in4src, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[0]));
			concat(lmsg, "%-22s", Wow);
			break;

		case XLATE_SHORT:
			inet_ntop(AF_INET, &pad->in4dst, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[1]));
			concat(lmsg, "%-22s", Wow);
			break;

		default:
			inet_ntop(AF_INET, &pad->in4dst, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[1]));
			concat(lmsg, "%-22s", Wow);

			inet_ntop(AF_INET, &pad->in4src, Bow, sizeof(Bow));
			snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(pad->port[0]));
			concat(lmsg, "%-22s", Wow);
			break;
		}
	}
}


void
appendPAddrXL6(struct logmsg *lmsg, struct pAddr *pad, int type, int inv)
{
	if (inv == XLATE_LOCAL) {
		switch (type) {
		case XLATE_TRACE:
		case XLATE_SHORT:
			appendpAddrXL6short(lmsg, &pad->in6src, pad->port[0]);
			break;

		case XLATE_REGULAR:
			appendpAddrXL6short(lmsg, &pad->in6src, pad->port[0]);
			appendpAddrXL6short(lmsg, &pad->in6dst, pad->port[1]);
			break;

		default:
			appendpAddrXL6long(lmsg, &pad->in6src, pad->port[0]);
			appendpAddrXL6long(lmsg, &pad->in6dst, pad->port[1]);
			break;
		}
	} else {
		switch (type) {
		case XLATE_TRACE:
			appendpAddrXL6short(lmsg, &pad->in6src, pad->port[0]);
			break;

		case XLATE_SHORT:
			appendpAddrXL6short(lmsg, &pad->in6dst, pad->port[1]);
			break;

		case XLATE_REGULAR:
			appendpAddrXL6short(lmsg, &pad->in6dst, pad->port[1]);
			appendpAddrXL6short(lmsg, &pad->in6src, pad->port[0]);
			break;

		default:
			appendpAddrXL6long(lmsg, &pad->in6dst, pad->port[1]);
			appendpAddrXL6long(lmsg, &pad->in6src, pad->port[0]);
			break;
		}
	}
}


void
appendpAddrXL6long(struct logmsg *lmsg, struct in6_addr *addr, u_short port)
{
	char	Bow[128];
	char	Wow[128];

	inet_ntop(AF_INET6, addr, Bow, sizeof(Bow));
	snprintf(Wow, sizeof(Wow), "%s.%d", Bow, ntohs(port));
	concat(lmsg, "%-46s", Wow);
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
		*d++ = XLATE_ELLIPSIS;
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
