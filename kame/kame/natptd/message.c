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
 *	$Id: message.c,v 1.1 2000/01/07 15:08:34 fujisawa Exp $
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _SYS_TYPES_H_
#include <sys/types.h>
#endif
#include <sys/socket.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>

#include "defs.h"
#include "misc.h"


/*
 *
 */

u_short		 _res_id;		/* current message id		*/
struct addrinfo	*natptPrefix;


int		 parseQuestion		__P((struct dnpExpand *, u_char *));
int		 parseAnswer		__P((struct dnpExpand *, u_char *, int));
void		 parseRData		__P((struct dnpExpand *, struct _RR *, u_char *));

struct msgHndl	*sendBackSelfPTR	__P((int, struct msgHndl *));

void		 queryCNAME1		__P((struct sdesc *));
void		 queryCNAME4		__P((struct sdesc *));
void		 convertCNAME1A4	__P((struct sdesc *));
void		 queryCNAMEend		__P((struct sdesc *));
void		 queryANYPTR4		__P((struct sdesc *));
void		 rewriteA1toA4		__P((struct msgHndl *));
void		 rewriteRR		__P((int, int, struct _RR *));
void		 relayResponse		__P((struct sdesc *));
void		 relayResponseSubs	__P((int, struct sockaddr *, struct msgHndl *));

int		 msgHndlDfaQry		__P((struct msgHndl *));
int		 msgHndlDfaRsp		__P((struct msgHndl *, struct msgHndl *));

int		 composeQuestion	__P((struct msgHndl *, struct dnpComp *));
int		 composeRR		__P((Cell *, struct dnpComp *));
int		 makeRR			__P((struct _RR *, struct dnpComp *));

void		 freeMessage		__P((struct msgHndl *));
void		 freeQuestion		__P((Cell *));
void		 freeAnswer		__P((Cell *));

int		 sprintQNs		__P((char *, struct _question *));
int		 sprintRNs		__P((char *, struct _RR *));
char		*typ2str		__P((char *, int));
char		*tok2str		__P((struct tok *, char *, int));


/*
 *
 */

struct msgHndl *
parseMessage(HEADER *hdr, int len)
{
    u_char		*cp;
    struct dnpExpand	 dnp;

    if (sizeof(HEADER) > len)
	return (NULL);

    dnp.startOfMsg = (u_char *)hdr;
    dnp.endOfMsg   = (u_char *)hdr + len;
    cp		   = (u_char *)hdr + sizeof(HEADER);

    dnp.msg = (struct msgHndl *)xmalloc(sizeof(struct msgHndl));
    bzero(dnp.msg, sizeof(struct msgHndl));
    bcopy(hdr, &dnp.msg->hdr, sizeof(HEADER));

#define	ANSWER		0
#define	AUTHORITY	1
#define	ADDITIONAL	2

    if (htons(hdr->qdcount) > 0)	cp += parseQuestion(&dnp, cp);
    if (htons(hdr->ancount) > 0)	cp += parseAnswer(&dnp, cp, ANSWER);
    if (htons(hdr->nscount) > 0)	cp += parseAnswer(&dnp, cp, AUTHORITY);
    if (htons(hdr->arcount) > 0)	cp += parseAnswer(&dnp, cp, ADDITIONAL);

    if (isDebug(DEBUG_MSGHDR))
    {
	fprintf(stderr, "allocateMessage(): %8p, %5d\n",
		dnp.msg, htons(dnp.msg->hdr.id));
    }

    return (dnp.msg);
}


int
parseQuestion(struct dnpExpand *dnp, u_char *cp)
{
    int			 rv, iter;
    u_char		*cpSaved = cp;
    struct _question	*qst;
    char		 qname[MAXDNAME];

    for (iter = 0; iter < htons(dnp->msg->hdr.qdcount); iter++)
    {
	qst = (struct _question *)xmalloc(sizeof(struct _question));
	bzero(qst, sizeof(struct _question));

	rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	if (rv < 0)
	    log(LOG_ERR, "parseResponse: extract error: "), quitting(errno);

	qst->qname = xmalloc(ROUNDUP(strlen(qname)+1));
	strcpy(qst->qname, qname);

	cp += rv;
	if (cp + 2*INT16SZ > dnp->endOfMsg)
	    perror("parseQuery: no query type: "), quitting(errno);

	GETSHORT(qst->qtype,  cp);
	GETSHORT(qst->qclass, cp);

	LST_hookup_list(&dnp->msg->question, qst);
    }

    return (cp - cpSaved);
}


int
parseAnswer(struct dnpExpand *dnp, u_char *cp, int type)
{
    int		rv;
    int		iter, count;
    u_char	*cpSaved = cp;
    Cell	**anchor;
    struct _RR	*rr;
    char	 qname[MAXDNAME];

    switch (type)
    {
      case ANSWER:
	count = ntohs(dnp->msg->hdr.ancount);
	anchor = &dnp->msg->answer;
	break;

      case AUTHORITY:
	count = ntohs(dnp->msg->hdr.nscount);
	anchor = &dnp->msg->authority;
	break;

      case ADDITIONAL:
	count = ntohs(dnp->msg->hdr.arcount);
	anchor = &dnp->msg->additional;
	break;

      default:
	return (0);
	break;
    }
    
    for (iter = 0; iter < count; iter++)
    {
	rr = (struct _RR *)xmalloc(sizeof(struct _RR));
	bzero(rr, sizeof(struct _RR));

	rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	if (rv < 0)
	    log(LOG_ERR, "parseResponse: extract error: "), quitting(errno);

	rr->RRname = xmalloc(ROUNDUP(strlen(qname)+1));
	strcpy(rr->RRname, qname);

	cp += rv;
	if (cp + 2*INT16SZ > dnp->endOfMsg)
	    log(LOG_ERR, "parseResponse: extract error: "), quitting(errno);

	GETSHORT(rr->RRtype,   cp);
	GETSHORT(rr->RRclass,  cp);
	GETLONG (rr->RRttl,    cp);
	GETSHORT(rr->RDlength, cp);
	parseRData (dnp, rr, cp);

	cp += rr->RDlength;
	LST_hookup_list(anchor, rr);
    }

    return (cp - cpSaved);
}


void
parseRData(struct dnpExpand *dnp, struct _RR *rr, u_char *cp)
{
    switch (rr->RRtype)
    {
      case T_A:
	{
	    struct sockaddr_in	*sin = xmalloc(sizeof(struct sockaddr_in));

	    bzero(sin, sizeof(struct sockaddr_in));

	    sin->sin_len = sizeof(struct sockaddr_in);
	    sin->sin_family = AF_INET;
	    bcopy(cp, (void *)&sin->sin_addr.s_addr, rr->RDlength);
	    rr->RData = (char *)sin;
	    rr->RDcocked = sizeof(struct sockaddr_in);
	}
	break;

      case T_CNAME:
	{
	    int			rv;
	    char		qname[MAXDNAME];
	    
	    rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	    if (rv < 0)
		log(LOG_ERR, "mkRData: extract error: "), quitting(errno);
	    cp += rv;
	    rr->RData = xmalloc(ROUNDUP(strlen(qname)+1));
	    strcpy(rr->RData, qname);
	}
	break;

      case T_SOA:
	{
	    int			 rv;
	    char		 qname[MAXDNAME];
	    struct _SOA		*soa = xmalloc(sizeof(struct _SOA));

	    bzero(soa, sizeof(struct _SOA));
	    rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	    if (rv < 0)
		log(LOG_ERR, "mkRData: extract error: "), quitting(errno);
	    cp += rv;
	    soa->mname = xmalloc(ROUNDUP(strlen(qname)+1));
	    strcpy(soa->mname, qname);
	    rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	    if (rv < 0)
		log(LOG_ERR, "mkRData: extract error: "), quitting(errno);
	    cp += rv;
	    soa->rname = xmalloc(ROUNDUP(strlen(qname)+1));
	    strcpy(soa->rname, qname);

	    GETLONG(soa->serial,  cp);
	    GETLONG(soa->refresh, cp);
	    GETLONG(soa->retry,	  cp);
	    GETLONG(soa->expire,  cp);
	    GETLONG(soa->minimum, cp);

	    rr->RData = (char *)soa;
	    rr->RDcocked = sizeof(struct _SOA);
	}
	break;

      case T_NS:
      case T_PTR:
	{
	    int		rv;
	    char	qname[MAXDNAME];

	    rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	    if (rv < 0)
		log(LOG_ERR, "mkRData: extract error: "), quitting(errno);

	    rr->RDcocked = strlen(qname);
	    rr->RData = xmalloc(ROUNDUP(strlen(qname)+1));
	    strcpy(rr->RData, qname);
	}
	break;

      case T_MX:
	{
	    int		 rv;
	    char	 qname[MAXDNAME];
	    struct _MX	*mx = xmalloc(sizeof(struct _MX));

	    bzero(mx, sizeof(struct _MX));
	    GETSHORT(mx->preference, cp);
	    rv = dn_expand(dnp->startOfMsg, dnp->endOfMsg, cp, qname, MAXDNAME);
	    if (rv < 0)
		log(LOG_ERR, "mkRData: extract error: "), quitting(errno);
	    cp += rv;
	    mx->exchange = xmalloc(ROUNDUP(strlen(qname)+1));
	    strcpy(mx->exchange, qname);

	    rr->RData = (char *)mx;
	    rr->RDcocked = sizeof(struct _MX);
	}
	break;

      case T_AAAA:
	{
	    struct sockaddr_in6	*sin6 = xmalloc(sizeof(struct sockaddr_in6));

	    bzero(sin6, sizeof(struct sockaddr_in6));

	    sin6->sin6_len = sizeof(struct sockaddr_in6);
	    sin6->sin6_family = AF_INET6;
	    bcopy(cp, (void *)&sin6->sin6_addr.s6_addr, rr->RDlength);
	    rr->RData = (char *)sin6;
	    rr->RDcocked = sizeof(struct sockaddr_in6);
	}
	break;

      default:
	{
	    rr->RData = xmalloc(rr->RDlength);
	    bcopy(cp, rr->RData, rr->RDlength);
	}
	break;
    }
}


/*
 *
 */

void
processQuery(struct sdesc *desc)
{
    struct msgHndl	*qry = desc->query;

    qry->b.dfasts = msgHndlDfaQry(qry);

    if (qry->b.ptrself)
    {
	sendBackSelfPTR(desc->sockfd, qry);
    }
    else if (isOff(useTAny))
	sendQuery(qry, desc);
    else
    {
	int			 Qqtype = 0;
	struct _question	*qst = NULL;

	qst = (struct _question *)CAR(qry->question);
	Qqtype = qst->qtype;		/* this should be same as msg->b.qtype	*/
	qst->qtype = T_ANY;		/* wildcard query instaed of original	*/

	sendQuery(qry, desc);

	qst->qtype = Qqtype;		/* retrieve original query type		*/
    }

    desc->query = NULL;
}


struct msgHndl *
sendBackSelfPTR(int sockfd, struct msgHndl *msg)
{
    int			 rv;
    struct msgHndl	*rsp;
    struct _question	*qst0, *qst1;
    struct _RR		*rr0;
    u_char		 Wow[PACKETSZ];

    rsp = (struct msgHndl *)xmalloc(sizeof(struct msgHndl));
    bzero(rsp, sizeof(struct msgHndl));
    rsp->hdr = msg->hdr;

    /* Assemble query section							*/
    qst0 = (struct _question *)CAR(msg->question);
    qst1 = (struct _question *)xmalloc(sizeof(struct _question));
    qst1->qname = xmalloc(ROUNDUP(strlen(qst0->qname)+1));
    strcpy(qst1->qname, qst0->qname);
    qst1->qtype	 = qst0->qtype;				/* It should be T_PTR	*/
    qst1->qclass = qst0->qclass;			/* It should be C_IN	*/
    LST_hookup_list(&rsp->question, qst1);
    rsp->hdr.qdcount = htons(1);

    /* Assemble answer section							*/
    rr0 = (struct _RR *)xmalloc(sizeof(struct _RR));
    rr0->RRname = xmalloc(ROUNDUP(strlen(qst0->qname)+1));
    strcpy(rr0->RRname, qst0->qname);
    rr0->RRtype	  = T_PTR;
    rr0->RRclass  = C_IN;
    rr0->RRttl	  = 32767;
    rr0->RDlength = 0;
    rr0->RData	  = xmalloc(ROUNDUP(strlen("sumire.kame.net")+1));	/* XXX	*/
    strcpy(rr0->RData, "sumire.kame.net");				/* XXX	*/
    LST_hookup_list(&rsp->answer, rr0);
    rsp->hdr.ancount = htons(1);

    rv = composeMessage(rsp, Wow, sizeof(Wow));
    sendResponse(sockfd, &msg->f.from, Wow, rv);
    if (isDebug(DEBUG_NS))
	dumpNs("to", (struct sockaddr *)&msg->f.from, msg);

    freeMessage(rsp);

    return (NULL);
}


void
processResponse(struct sdesc *desc)
{
    int			 dfasts;
    struct msgHndl	*query = desc->query;

    dfasts = msgHndlDfaRsp(query, desc->response);
    query->b.dfasts = dfasts;			/* update DFA status		*/
    switch (dfasts)
    {
      case STSconvertA1A4:
	rewriteA1toA4(desc->response);
	relayResponse(desc);
	break;

      case STSqueryAgain1:
      case STSqueryAgain4:
	query->b.linkc--;
	sendQuery(query, desc);			/* in sendQuery, b.linkc++	*/

	freeMessage(desc->response);
	break;

      case STSqueryCNAME1:
	queryCNAME1(desc);
	break;

      case STSqueryCNAME4:
	queryCNAME4(desc);
	break;

      case STSconvertCNAME1A4:
	convertCNAME1A4(desc);
	break;

      case STSqueryCNAMEend:
	queryCNAMEend(desc);
	break;

      case STSqueryANYPTR4:
	queryANYPTR4(desc);
	break;

      case STSend:
	relayResponse(desc);
	break;

      case STSunknown:
	log(LOG_ERR, "unknown DFA status\n");
	break;
    }
}


void
queryCNAME1(struct sdesc *desc)
{
    char		*qnameSaved;
    struct msgHndl	*query = desc->query;
    struct _question	*quest;
    struct _RR		*cname;

    quest = (struct _question *)CAR(query->question);
    cname = (struct _RR *)CAR(desc->response->answer);

    qnameSaved = quest->qname;
    quest->qname = cname->RData;
    query->b.linkc--;
    sendQuery(query, desc);	/* send query with origial qtype	*/
				/*	      with canonical name	*/
    quest->qname = qnameSaved;

    if (desc->responseQ == NULL)
    {
	desc->responseQ = desc->response;
	desc->response	= NULL;
    }
}


void
queryCNAME4(struct sdesc *desc)
{
    int			 qtypeSaved;
    char		*qnameSaved;
    struct msgHndl	*query = desc->query;
    struct _question	*quest;
    struct _RR		*cname;

    quest = (struct _question *)CAR(query->question);
    cname = (struct _RR *)CAR(desc->response->answer);

    qnameSaved = quest->qname;
    qtypeSaved = quest->qtype;
    quest->qname = cname->RData;
    quest->qtype = T_ANY;
    query->b.linkc--;
    sendQuery(query, desc);		/* send query with origial qtype	*/
					/*	      with canonical name	*/
    quest->qtype = qtypeSaved;
    quest->qname = qnameSaved;

    if (desc->responseQ == NULL)
    {
	desc->responseQ = desc->response;
	desc->response	= NULL;
    }
}


void
convertCNAME1A4(struct sdesc *desc)
{
    /* query should have original query (query->queston)
       and canonical name (query->responseQ)
       and address (query->response).
       So we will append address RR to canonical name RR
       and return to initial quarier (desc->sd->sockfd				*/

    int			 ancount;
    Cell		*p;
    struct _question	*quest = (struct _question *)CAR(desc->query->question);
    struct msgHndl	 response;

    bzero(&response, sizeof(struct msgHndl));
    response.hdr = desc->response->hdr;
    response.question = desc->query->question;	/* this should be original question	*/
    response.answer   = desc->responseQ->answer;
    response.authority = desc->response->authority;
    response.additional = desc->response->additional;

    ancount = ntohs(response.hdr.ancount);
    for (p = desc->response->answer; p; p = CDR(p))
    {
	struct _RR	*rr;

	rr = (struct _RR *)CAR(p);
	if ((rr->RRtype == quest->qtype)
	    || (rr->RRtype == T_A))
	{
	    ancount++;
	    LST_hookup_list(&response.answer, rr);
	}
    }

    response.hdr.ancount = htons(ancount);
    rewriteA1toA4(&response);
    relayResponseSubs(desc->sd->sockfd, &desc->query->f.from, &response);
}


void
queryCNAMEend(struct sdesc *desc)
{
    /* query should have original query (query->queston)
       and canonical name (query->responseQ)
       and address (query->response).
       So we will append address RR to canonical name RR
       and return to initial quarier (desc->sd->sockfd				*/

    int			 ancount;
    Cell		*p;
    struct _question	*quest = (struct _question *)CAR(desc->query->question);
    struct msgHndl	 response;

    bzero(&response, sizeof(struct msgHndl));
    response.hdr = desc->response->hdr;
    response.question = desc->query->question;	/* this should be original question	*/
    response.answer   = desc->responseQ->answer;
    response.authority = desc->response->authority;
    response.additional = desc->response->additional;

    ancount = ntohs(response.hdr.ancount);
    for (p = desc->response->answer; p; p = CDR(p))
    {
	struct _RR	*rr;

	rr = (struct _RR *)CAR(p);
	if (rr->RRtype == quest->qtype)
	{
	    ancount++;
	    LST_hookup_list(&response.answer, rr);
	}
    }

    response.hdr.ancount = htons(ancount);
    relayResponseSubs(desc->sd->sockfd, &desc->query->f.from, &response);
}


void
queryANYPTR4(struct sdesc *desc)
{
    struct msgHndl	*qry = desc->query;
    struct msgHndl	*rsp = desc->response;
    struct _question	*qstQ, *qstR;

    qstQ = (struct _question *)CAR(qry->question);
    qstR = (struct _question *)CAR(rsp->question);
    qstR->qtype = qstQ->qtype;
    rsp->hdr.id = qry->hdr.id;

    relayResponseSubs(desc->sd->sockfd, &qry->f.from, rsp);

    qry->b.linkc--;

    if (qry->b.linkc <= 0)
	freeMessage(qry);
    freeMessage(rsp);

    bzero(desc, sizeof(struct sdesc));
    desc->type = RES_PRF_REPLY;
}


void
rewriteA1toA4(struct msgHndl *rsp)
{
    Cell		*p;
    
    for (p = rsp->answer; p; p = CDR(p))
	rewriteRR(T_A, T_AAAA, (struct _RR *)CAR(p));

    for (p = rsp->authority; p; p = CDR(p))
	rewriteRR(T_A, T_AAAA, (struct _RR *)CAR(p));

    for (p = rsp->additional; p; p = CDR(p))
	rewriteRR(T_A, T_AAAA, (struct _RR *)CAR(p));
}


void
rewriteRR(int ftype, int ttype, struct _RR *rr)
{
    if ((ftype != T_A)
	|| (ttype != T_AAAA))
    {
	fprintf(stderr, "rewriteRR(): cannot rewrite %s to %s\n",
		typ2str("Type%d", ftype),
		typ2str("Type%d", ttype));
	return ;
    }

    if (rr->RRtype == T_A)
    {
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;

	rr->RRtype = T_AAAA;
	sin4 = (struct sockaddr_in *)rr->RData;		/* This should be	*/
	sin6 = xmalloc(sizeof(struct sockaddr_in6));
	bzero(sin6, sizeof(struct sockaddr_in6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = ((struct sockaddr_in6 *)natptPrefix->ai_addr)->sin6_addr;
	sin6->sin6_addr.s6_addr[12] = sin4->sin_addr.s_addr;
	rr->RData = (char *)sin6;
	xfree(sin4);
    }
}


void
relayResponse(struct sdesc *desc)
{
    struct msgHndl	*qry = desc->query;
    struct msgHndl	*rsp = desc->response;
    struct _question	*qstQ, *qstR;

    qstQ = (struct _question *)CAR(qry->question);
    qstR = (struct _question *)CAR(rsp->question);
    qstR->qtype = qstQ->qtype;
    rsp->hdr.id = qry->hdr.id;

    relayResponseSubs(desc->sd->sockfd, &qry->f.from, rsp);

    qry->b.linkc--;

    if (qry->b.linkc <= 0)
	freeMessage(qry);
    freeMessage(rsp);

    bzero(desc, sizeof(struct sdesc));
    desc->type = RES_PRF_REPLY;
}


void
relayResponseSubs(int sockfd, struct sockaddr *client, struct msgHndl *rsp)
{
    int			 rv;
    u_char		 Wow[PACKETSZ];

    if ((rv = composeMessage(rsp, Wow, sizeof(Wow))) < 0)
    {
	return ;
    }
    rv = sendResponse(sockfd, client, Wow, rv);

    if (isDebug(DEBUG_NS))
	dumpNs("to", client, rsp);
}


int
msgHndlDfaQry(struct msgHndl *qry)
{
    switch (qry->b.qtype)
    {
      case T_A:
	if (isOn(useTAny))			return (STSqueryANY1);
	else					return (STSqueryA1);
	    
      case T_AAAA:
	if (isOn(useTAny))			return (STSqueryANY4);
	else					return (STSqueryA4);

      case T_PTR:
	if (qry->b.T_PTR6)
	    if (isOn(useTAny))			return (STSqueryANYPTR6);
	    else				return (STSqueryPTR6);
	else
	    if (isOn(useTAny))			return (STSqueryANYPTR4);
	    else				return (STSqueryPTR4);
    }

    return (STSunknown);
}


int
msgHndlDfaRsp(struct msgHndl *qry, struct msgHndl *rsp)
{
    if (rsp->hdr.rcode != 0)
	return (STSend);		/* In case some error occured	*/

    switch (qry->b.dfasts)
    {
      case STSqueryANY1:			/* A1 -> ANY			*/
      case STSqueryAgain1:
	if (rsp->b.t_a)					return (STSend);
	if ((rsp->b.t_aaaa)
	    && (isOn(supportA4A1)))			return (STSconvertA4A1);
	if (rsp->b.t_cname)				return (STSqueryCNAME1);
	if (ntohs(rsp->hdr.ancount) == 0)		return (STSend);
	return (STSqueryAgain1);

      case STSqueryANY4:			/* A4 -> ANY			*/
      case STSqueryAgain4:
	if (rsp->b.t_aaaa)				return (STSend);
	if ((rsp->b.t_a)
	    && (isOn(supportA1A4)))			return (STSconvertA1A4);
	if (rsp->b.t_cname)				return (STSqueryCNAME4);
	if (ntohs(rsp->hdr.ancount) == 0)		return (STSend);
	return (STSqueryAgain4);

      case STSqueryCNAME1:			/* A1 -> ANY (CNAME) -> A1	*/
	if (rsp->b.t_a)					return (STSqueryCNAMEend);
	if (rsp->b.t_cname)				return (STSqueryCNAME1);
	if (ntohs(rsp->hdr.ancount) == 0)		return (STSqueryCNAMEend);
	return (STSqueryCNAME1);

      case STSqueryCNAME4:			/* A4 -> ANY (CNAME) -> ANY	*/
	if (rsp->b.t_aaaa)				return (STSqueryCNAMEend);
	if ((rsp->b.t_a)
	    && (isOn(supportA1A4)))			return (STSconvertCNAME1A4);
	if (rsp->b.t_cname)				return (STSqueryCNAME4);
	if (ntohs(rsp->hdr.ancount) == 0)		return (STSqueryCNAMEend);
	return (STSqueryCNAME4);

      case STSqueryANYPTR4:			/* PTR4 -> ANY (PTR4)		*/
	if (rsp->b.t_ptr4)				return (STSend);
	break;
    }

    return (STSunknown);
}


/*
 *
 */

int
composeMessage(struct msgHndl *msg, u_char *buf, int buflen)
{
    int			 rv;
    u_char		*dnptrs[64], **dpp, **lastdnptr;
    struct dnpComp	 dnp;

    if ((buf == NULL) || (buflen < sizeof(HEADER)))
	return (-1);

    bzero(buf, buflen);
    bcopy(&msg->hdr, buf, sizeof(HEADER));
    
    dpp = dnptrs;
    *dpp++ = buf;
    *dpp++ = NULL;
    lastdnptr = dnptrs + sizeof(dnptrs)/sizeof(dnptrs[0]);

    dnp.cp = buf + sizeof(HEADER);
    dnp.buflen = buflen - sizeof(HEADER);
    dnp.dnptrs = dnptrs;
    dnp.lastdnptr = lastdnptr;

    if ((rv = composeQuestion(msg, &dnp)) > 0)
	dnp.cp += rv, dnp.buflen -= rv;

    composeRR(msg->answer, &dnp);
    composeRR(msg->authority, &dnp);
    composeRR(msg->additional, &dnp);

    if (isOff(daemon)
	&& (isDebug(DEBUG_RESOLVER)))
    {
	fprintf(stderr, "*** composeMessage() ***\n");
	__fp_nquery((u_char *)buf, dnp.cp - buf, stderr);	/* DEBUG_RESOLVER	*/
    }

    return (dnp.cp - buf);
}


int
composeQuestion(struct msgHndl *msg, struct dnpComp *dnp)
{
    int			 rv;
    int			 iter;
    int			 buflen = dnp->buflen;
    Cell		*p;
    struct _question	*qst;
    u_char		*cp = dnp->cp;
    u_char		*cpSaved = cp;

    for (p = msg->question, iter = 0; p; p = CDR(p), iter++)
    {
	if ((buflen -= QFIXEDSZ) < 0)
	    return (-1);

	qst = (struct _question *)CAR(p);
	if ((rv = dn_comp(qst->qname, cp, buflen, dnp->dnptrs, dnp->lastdnptr)) < 0)
	    return (-1);

	cp += rv;
	buflen -= rv;

	PUTSHORT(qst->qtype,  cp);
	PUTSHORT(qst->qclass, cp);
    }

    msg->hdr.qdcount = htons(iter);

    return (cp - cpSaved);
}


int
composeRR(Cell *list, struct dnpComp *dnp)
{
    int		 rv;
    Cell	*p;

    for (p = list; p; p = CDR(p))
    {
	if ((rv = makeRR((struct _RR *)CAR(p), dnp)) > 0)
	    dnp->cp += rv, dnp->buflen -= rv;
    }

    return (0);
}


int
makeRR(struct _RR *rr, struct dnpComp *dnp)
{
    int		 rv;
    int		 buflen = dnp->buflen;
    u_char	*cp = dnp->cp;
    u_char	*sp;

    if ((buflen -= RRFIXEDSZ) < 0)
	return (-1);

    rv = dn_comp(rr->RRname, cp, buflen, dnp->dnptrs, dnp->lastdnptr);
    if (rv < 0)
	return (-1);

    cp += rv;
    buflen -= rv;
    if (buflen < 0)
	return (-1);

    PUTSHORT(rr->RRtype,  cp);
    PUTSHORT(rr->RRclass, cp);
    PUTLONG (rr->RRttl,	  cp);
    sp = cp;
    cp += INT16SZ;
    switch (rr->RRtype)
    {
      case T_A:
	memcpy(cp, &((struct sockaddr_in *)rr->RData)->sin_addr, sizeof(struct in_addr));
	PUTSHORT(sizeof(struct in_addr), sp);
	cp += sizeof(struct in_addr);
	break;

      case T_CNAME:
	rv = dn_comp(rr->RData, cp, buflen, dnp->dnptrs, dnp->lastdnptr);
	if (rv < 0)
	    return (-1);
	PUTSHORT(rv, sp);
	cp += rv;
	break;

      case T_SOA:
	{
	    u_char		*qp = cp;
	    struct _SOA		*soa = (struct _SOA *)rr->RData;

	    rv = dn_comp(soa->mname, cp, buflen, dnp->dnptrs, dnp->lastdnptr);
	    if (rv < 0)
		return (-1);
	    cp += rv;
	    rv = dn_comp(soa->rname, cp, buflen, dnp->dnptrs, dnp->lastdnptr);
	    if (rv < 0)
		return (-1);
	    cp += rv;
	    
	    PUTLONG(soa->serial,  cp);
	    PUTLONG(soa->refresh, cp);
	    PUTLONG(soa->retry,	  cp);
	    PUTLONG(soa->expire,  cp);
	    PUTLONG(soa->minimum, cp);

	    PUTSHORT(cp - qp, sp);		/* RDLENGTH		*/
	}
	break;

      case T_NS:
      case T_PTR:
	rv = dn_comp(rr->RData, cp, buflen, dnp->dnptrs, dnp->lastdnptr);
	if (rv < 0)
	    return (-1);
	PUTSHORT(rv, sp);
	cp += rv;
	break;

      case T_MX:
	{
	    int		 rv;
	    u_char	*qp = cp;
	    struct _MX	*mx = (struct _MX *)rr->RData;

	    PUTSHORT(mx->preference, cp);
	    rv = dn_comp(mx->exchange, cp, buflen, dnp->dnptrs, dnp->lastdnptr);
	    if (rv < 0)
		return (-1);
	    cp += rv;

	    PUTSHORT(cp - qp, sp);		/* RDLENGTH		*/
	}
	break;

      case T_AAAA:
	memcpy(cp, &((struct sockaddr_in6 *)rr->RData)->sin6_addr, sizeof(struct in6_addr));
	PUTSHORT(sizeof(struct in6_addr), sp);
	cp += sizeof(struct in6_addr);
	break;

      default:
	memcpy(cp, rr->RData, rr->RDlength);
	PUTSHORT(rr->RDlength, sp);
	cp += rr->RDlength;
    }

    return (cp - dnp->cp);
}


void
freeMessage(struct msgHndl *msg)
{
    if (isDebug(DEBUG_MSGHDR))
    {
	fprintf(stderr, "freeMessage(): %8p, %5d\n",
		msg, htons(msg->hdr.id));
    }

    msg->msgID = 0xdeadface;	/* this structure was deleted mark	*/
    freeQuestion(msg->question);
    freeAnswer(msg->answer);
    freeAnswer(msg->authority);
    freeAnswer(msg->additional);

    xfree(msg);
}


void
freeQuestion(Cell *question)
{
    Cell		*p0, *q0;
    struct _question	*qst;

    for (p0 = question; p0; q0 = CDR(p0), LST_free(p0), p0 = q0)
    {
	qst = (struct _question *)CAR(p0);
	if (qst->qname)
	    xfree(qst->qname);
	xfree(qst);
    }
}


void
freeAnswer(Cell *answer)
{
    Cell	*p0, *q0;
    struct _RR	*rr;
    
    for (p0 = answer; p0; q0 = CDR(p0), LST_free(p0), p0 = q0)
    {
	rr = (struct _RR *)CAR(p0);

	if (rr->RRname)
	    xfree(rr->RRname);

	switch (rr->RRtype)
	{
	  case T_SOA:
	    xfree(((struct _SOA *)rr->RData)->mname);
	    xfree(((struct _SOA *)rr->RData)->rname);
	    break;

	  case T_MX:
	    xfree(((struct _MX *)rr->RData)->exchange);
	    break;
	}
	
	xfree(rr->RData);
	xfree(rr);
    }
}


/*
 *
 */

void
dumpNs(char *fromto, struct sockaddr *addr, struct msgHndl *msg)
{
    int		 rv = 0;
    int		 qdcount, ancount, nscount, arcount;
    char	*cp;
    char	 Wow[BUFSIZ];
    HEADER	*np = &msg->hdr;

    qdcount = ntohs(np->qdcount);
    ancount = ntohs(np->ancount);
    nscount = ntohs(np->nscount);
    arcount = ntohs(np->arcount);

    cp = Wow;
    rv = sprintf(cp, "%4s %s:", fromto, displaySockaddr(addr));
    cp += rv;

    if (np->qr == 1)
    {					/* This is a response		*/
	rv = sprintf(cp, " %d%s%s%s%s%s",
		     ntohs(np->id),
		     ns_ops[np->opcode],
		     ns_resp[np->rcode],
		     np->aa ? "*" : "",
		     np->ra ? ""  : "-",
		     np->tc ? "|" : "");
	cp += rv;

	if (qdcount != 1)
	    rv = sprintf(cp, " [%dq]", qdcount), cp += rv;

	rv = sprintf(cp, " %d/%d/%d", ancount, nscount, arcount);
	cp += rv;

	if (ancount)
	{
	    Cell	*p;
	    struct _RR	*rr;

	    for (p = msg->answer; p; p = CDR(p))
	    {
		rr = (struct _RR *)CAR(p);
		rv = sprintRNs(cp, rr);
		cp += rv;
	    }
	}
    }
    else
    {					/* This is a request		*/
	struct _question	*qst;

	rv = sprintf(cp, " %d%s%s",
		     ntohs(np->id),
		     ns_ops[np->opcode],
		     np->rd ? "+" : "");
	cp += rv;

	if (*(((u_short *)np)+1) & htons(0x6ff))
	    rv = sprintf(cp, " [b2&3=0x%x]", ntohs(*(((u_short *)np)+1))),
		cp += rv;

	if (np->opcode == IQUERY)
	{
	    if (qdcount)	rv = sprintf(cp, " [%dq]", qdcount), cp += rv;
	    if (ancount)	rv = sprintf(cp, " [%da]", ancount), cp += rv;
	}
	else
	{
	    if (ancount)	rv = sprintf(cp, " [%da]", ancount), cp += rv;
	    if (qdcount != 1)	rv = sprintf(cp, " [%dq]", qdcount), cp += rv;
	}

	if (nscount)		rv = sprintf(cp, " [%dn]", nscount), cp += rv;
	if (arcount)		rv = sprintf(cp, " [%dau]", arcount), cp += rv;

	qst = (struct _question *)CAR(msg->question);
	rv = sprintQNs(cp, qst);
	cp += rv;
    }
    
    *cp = '\0';
    log(LOG_DEBUG, "%s", Wow);
}


int
sprintQNs(char *cp, struct _question *qst)
{
    int			 rv = 0;
    char		*sp = cp;

    rv = sprintf(cp, " %s?", tok2str(Qtype2str, "Type%d", qst->qtype));
    cp += rv;

    rv = sprintf(cp, " %s", qst->qname);
    cp += rv;

    return (cp - sp);
}


int
sprintRNs(char *cp, struct _RR *rr)
{
    int		 rv;
    char	*sp = cp;

    rv = sprintf(cp, " %s", tok2str(Qtype2str, "Type%d", rr->RRtype));
    cp += rv;

    rv = 0;
    switch (rr->RRtype)
    {
      case T_A:
	rv = sprintf(cp, " %s", displaySockaddr((struct sockaddr *)rr->RData));
	break;

      case T_NS:
      case T_PTR:
	rv = sprintf(cp, " %s", rr->RData);
	break;

      case T_AAAA:
	rv = sprintf(cp, " %s", displaySockaddr((struct sockaddr *)rr->RData));
	break;
    }

    cp += rv;
    return (cp - sp);
}


char *
typ2str(char *fmt, int val)
{
    return (tok2str(Qtype2str, fmt, val));
}


char *
tok2str(struct tok *tbl, char *fmt, int val)
{
    static	char	 buf[128];

    while (tbl->str != NULL)
    {
	if (tbl->val == val)
	    return (tbl->str);
	tbl++;
    }

    if (fmt == NULL)
	fmt = "#%d";
    sprintf(buf, fmt, val);
    return (buf);
}


/*
 *
 */

void
init_message()
{
    _res_id = res_randomid();
}
