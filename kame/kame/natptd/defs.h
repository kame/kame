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
 *	$Id: defs.h,v 1.1 2000/01/07 15:08:34 fujisawa Exp $
 */

#ifndef TRUE
#define	TRUE			(1)
#define	FALSE			(0)
#endif

#define	ROUNDUP(x)		roundup(x, sizeof(void *))

#define	OPT_DUMPFILE		(0)
#define	OPT_PIDFILE		(1)
#define	OPT_STATSFILE		(2)

#define	_PATH_DUMPFILE		"/var/tmp/ptrd_dump"
#define	_PATH_PIDFILE		"/var/run/ptrd.pid"
#define	_PATH_STATSFILE		"/var/tmp/ptrd.stats"

#define	INADDRARPA		"255.255.255.255.in-addr.arpa."

#define	isOn(name)		(__op.b.name == 1)
#define	isOff(name)		(__op.b.name == 0)

#define	isDebug(d)		(__debug & (d))

#define	DEBUG_IFADDR		0x00000100
#define	DEBUG_RESOLVER		0x00000200
#define	DEBUG_MSGHDR		0x00000400
#define	DEBUG_XMALLOC		0x00000800

#define	DEBUG_SOCKET		0x00010000
#define	DEBUG_NS		0x00020000

#define	NOSYSLOG		0x40000000
#define	LOGTOSTDERR		0x80000000


/*
 *
 */

struct ifnets
{
    struct ifnets	*if_next;
    struct ifaddrs	*if_addrlist;
    char		 if_name[IFNAMSIZ];
    u_short		 if_flags;
    u_short		 if_side;
    /* #define	noSide			(0)					*/
    /* #define	inSide			(1)					*/
    /* #define	outSide			(2)					*/
};


struct ifaddrs
{
    struct ifaddrs	*ifa_next;
    char		*ifa_name;
    u_int		 ifa_flags;
    u_int		 ifa_flags6;		/* ifr6.ifr_ifru.ifru_flags6	*/
    struct sockaddr	*ifa_addr;
    struct sockaddr	*ifa_netmask;
    struct sockaddr	*ifa_dstaddr;
    /*	  char		*ifa_fqdn;						*/
    void		*ifa_data;		/* Now point to upper ifnets{}	*/
};


struct svrInfo
{
    int			 flags;
    struct addrinfo	*svaddr;
    time_t		 tstamp4;
    time_t		 tstamp6;
};


struct sdesc
{
    int			 type;
    /*	#define	RES_PRF_QUERY	-- waiting for query			*/
    /*	#define	RES_PRF_REPLY	-- waiging for response			*/
    int			 sockfd;	/* socket descriptor or -1	*/
    struct sockaddr	*saddr;		/* address of sockfd		*/

    /* followings are used only type == RES_PRF_REPLY			*/
    struct sdesc	*sd;		/* pointer to original sdesc	*/
    struct msgHndl	*query;		/* pointer to original query	*/
    struct msgHndl	*response;	/* pointer to server response	*/
    struct msgHndl	*responseQ;	/* pointer to old response	*/
    struct svrInfo	*server;	/* nameserver info		*/
};


enum
{
    STSstart,
    STSqueryA1,
    STSqueryA4,
    STSqueryANY1,
    STSqueryANY4,
    STSqueryCNAME1,
    STSqueryCNAME4,
    STSqueryCNAMEend,
    STSqueryPTR4,
    STSqueryPTR6,
    STSqueryANYPTR6,
    STSqueryANYPTR4,
    STSqueryAgain1,
    STSqueryAgain4,
    /*	STSqueryPTR64,			*/
    /*	STSqueryCNAME4,			*/
    /*	STSqueryCNAME6,			*/
    STSconvertA1A4,
    STSconvertA4A1,
    STSconvertCNAME1A4,
    STSend,
    STSunknown,
};


struct msgHndl
{
    u_int		 msgID;		/* used only original query		*/
    struct
    {
	unsigned	 inout:1;	/* TRUE if outgoing packet		*/
	unsigned	 T_PTR6:1;	/* TRUE if Query of v6 T_PTR		*/
	unsigned	 unused0:6;

	unsigned	 linkc:4;	/* linkcount				*/
	unsigned	 dfasts:4;	/* DFA inner status			*/

	unsigned	 unused1:1;
	unsigned	 t_a:1;		/* answer has T_A			*/
	unsigned	 t_aaaa:1;	/* answer has T_AAAA			*/
	unsigned	 t_cname:1;	/* answer has T_CNAME			*/
	unsigned	 t_ptr4:1;	/* answer has T_PTR (IPv4)		*/
	unsigned	 t_ptr6:1;	/* answer has T_PTR (IPv6)		*/
	unsigned	 ptrbroken:1;	/* question has broken ptr query	*/
	unsigned	 ptrself:1;	/* questhio has localhost ptr query	*/

	unsigned	 qtype:8;	/* Type value of query			*/
    }b;

    /*	  int			 socket;					*/
    time_t		 tstamp;
    struct ifaddrs	*ifap;
    /*	struct svrInfo	*server;						*/
    /*	struct msgHndl	*queryOriginal;		*//* back link to queryOriginal	*/
    /*	u_int		 queryOriginalID;	*//* msgID of queryOriginal	*/

    union
    {
	struct sockaddr		from;
	struct sockaddr_in	from4;
	struct sockaddr_in6	from6;
    }f;						/* Who send this messsge	*/

    HEADER		 hdr;
    Cell		*question;		/* List of struct _question	*/
    Cell		*answer;		/* List of struct _RR		*/
    Cell		*authority;		/* List of struct _RR		*/
    Cell		*additional;		/* List of struct _RR		*/
};


struct _question
{
    char	*qname;
    u_short	 qtype;
    u_short	 qclass;
};


struct _RR
{
    char	*RRname;
    u_short	 RRtype;
    u_short	 RRclass;
    u_long	 RRttl;
    u_short	 RDlength;		/* raw rdlength			*/
    u_short	 RDcocked;		/* cocked rdlength		*/
    char	*RData;
};


struct _SOA
{
    char	*mname;
    char	*rname;
    u_int	 serial;
    u_int	 refresh;
    u_int	 retry;
    u_int	 expire;
    u_int	 minimum;
};


struct _MX
{
    u_int	 preference;
    char	*exchange;
};


struct dnpExpand
{
    struct msgHndl	*msg;
    u_char		*startOfMsg;
    u_char		*endOfMsg;
};


struct dnpComp
{
    u_char	*cp;		/* ptr to begining of stored area		*/
    int		 buflen;	/* length of stored area			*/
    u_char	**dnptrs;	/* ptr to previously-compressed name array	*/
    u_char	**lastdnptr;	/* limit of its array				*/
};


struct options
{
    struct
    {
	unsigned	daemon:1;	/* TRUE if daemon mode			*/
	unsigned	useTAny:1;	/* TRUE if use T_ANY			*/
	unsigned	supportA1A4:1;	/* TRUE if support A1 -> A4 mapping	*/
	unsigned	supportA4A1:1;	/* TRUE if support A4 -> A1 mapping	*/
	unsigned	unused:26;
	unsigned	logsyslog:1;	/* TRUE if log to syslog		*/
	unsigned	logstderr:1;	/* TRUE if log to stderr		*/
    }b;
    char	*dumpFilename;
    char	*pidFilename;
    char	*statsFilename;
};


/*
 *
 */

extern	int		 errno;
extern	u_long		 __debug;
extern	struct options	 __op;

/*	main.c									*/
FILE		*writeOpen		__P((char *, int));
void		 quitting		__P((int));
void		 log			__P((int, char *, ...));


/*	message.c								*/
struct msgHndl	*parseMessage		__P((HEADER *, int));
void		 processQuery		__P((struct sdesc *));
void		 processResponse	__P((struct sdesc *));
int		 composeMessage		__P((struct msgHndl *, u_char *, int));
void		 dumpNs			__P((char *, struct sockaddr *, struct msgHndl *));

void		 init_message		__P((void));


/*	misc.c									*/
struct sdesc	*recvMessage		__P((void));
void		 sendQuery		__P((struct msgHndl *, struct sdesc *));
int		 sendResponse		__P((int, struct sockaddr *, u_char *, int));

struct sdesc	*internReplyDesc	__P((int));
struct sdesc	*lookForQueryDesc	__P((void));

struct addrinfo	*getAddrInfo		__P((int, char *));
void		 setServerInside	__P((char *));
void		 setServerOutside	__P((char *));

char		*displaySockaddr	__P((struct sockaddr *));

void		 debugProbe		__P((char *));
void		*xmalloc		__P((size_t));
void		 xfree			__P((void *));

void		 initIfnets		__P((void));
void		 initSignal		__P((void));
void		 init_misc		__P((void));
