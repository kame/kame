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
 *	$Id: natptlog.c,v 1.2 2000/02/06 09:51:48 itojun Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>

#include <sys/param.h>
#include <sys/mbuf.h>

#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netinet6/natpt_log.h>


/*
 *
 */

#ifndef TRUE
#define	TRUE			(1)
#define	FALSE			(0)
#endif

#define	PORT_ANY		(0)

#define	xmalloc			malloc
#define	ROUNDUP(x)		roundup(x, sizeof(void *))

#define	OPT_PIDFILE		(1)
#define	OPT_STATSFILE		(2)

#define	_PATH_PIDFILE		"/var/run/natptlog.pid"
#define	_PATH_STATSFILE		"/var/tmp/natptlog.stats"

#define	isOn(name)		(__op.b.name == 1)
#define	isOff(name)		(__op.b.name == 0)

#define	isDebug(d)		(__debug & (d))


u_long		 __debug;
sigset_t	 mask;
int		 signals[] = { SIGINT, SIGTERM, };

struct options
{
    struct
    {
	unsigned	daemon:1;	/* TRUE if daemon mode			*/
	unsigned	logsyslog:1;	/* TRUE if log to syslog		*/
	unsigned	logstderr:1;	/* TRUE if log to stderr		*/
    }	b;
    char	*pidFilename;
    char	*statsFilename;
}		__op;


void	 parseArgument		__P((int, char *[]));
void	 recvMesg		__P((int));

void	 printLogMsg		__P((struct lbuf *));
void	 printLogMBuf		__P((struct lbuf *));
void	 printLogIP4		__P((struct lbuf *));
void	 printLogIP6		__P((struct lbuf *));
void	 printLogIN6addr	__P((struct lbuf *));

char	*displaySockaddr	__P((struct sockaddr *));
char	*displaySockaddrIn4	__P((struct sockaddr_in *));
char	*displaySockaddrIn6	__P((struct sockaddr_in6 *));
char	*displaySockaddrDl	__P((struct sockaddr_dl *));

int	 hexdump16		__P((int, char *, int));
void	 quitting		__P((int));

void	 openLog		__P((void));
void	 log			__P((int, char *, ...));
void	 closeLog		__P((void));

void	 updatePidFile		__P((char *));
FILE	*writeOpen		__P((char *, int));

void	 setFileName		__P((char *, int));
void	 initSignal		__P((void));
void	 sighandler		__P((int));
void	 preinit		__P((void));
void	 init_main		__P((void));


/*
 *
 */

int
main(int argc, char *argv[])
{
    int			sockfd;

    preinit();

    parseArgument(argc, argv);

    init_main();

    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_AHIP)) < 0)
	log(LOG_ERR, "main(): socket open failure: %s", strerror(errno)),
	exit (errno);

    recvMesg(sockfd);

    exit (0);
}


void
parseArgument(int argc, char *argv[])
{
    int			 ch;

    extern	char	*optarg;
    extern	int	 optind;

    while ((ch = getopt(argc, argv, "b:d:h")) != EOF)
    {
	switch (ch)
	{
	  case 'b':
	    if ((*optarg == 'd') && (*(optarg+1) == '\0'))
		__op.b.daemon = 1;
	    else
		goto	illegalopt;
	    break;

	  case 'd':
	    if (strncmp((optarg-1), "debug=", strlen("debug=")) == 0)	
		__debug = strtoul(optarg+5, (char **)NULL, 0);
	    else
		goto	illegalopt;
	    break;
	}
    }

    argc -= optind;
    argv += optind;

    return ;

illegalopt:;
    log(LOG_ERR, "parseArgument(): Illegal option name `%s\'\n", (optarg-1));
    exit (errno);
}


void
recvMesg(int sockfd)
{
    int				 len;
    struct lbuf			*lbuf;
    struct sockaddr_storage	 from;
    u_char			 Wow[PACKETSZ];
    fd_set			 sockvec;
    fd_set			 recvec;

    FD_ZERO(&sockvec);
    FD_SET(sockfd, &sockvec);

    while (TRUE)
    {
	FD_COPY(&sockvec, &recvec);
	switch (select(FD_SETSIZE, &recvec, NULL, NULL, NULL))
	{
	  case -1:
	    if (errno != EINTR)
		log(LOG_ERR, "recvMesg(): select failure: %s\n", strerror(errno)),
		quitting(errno);
	    break;

	  case 0:
	    break;

	  default:
	    if (FD_ISSET(sockfd, &recvec))
	    {
		int	rv;

		if ((rv = ioctl(sockfd, FIONREAD, &len)) < 0)
		{
		    log(LOG_ERR, "recvMesg(): ioctl failure: %s\n", strerror(errno));
		    continue;
		}

		rv = recvfrom(sockfd, Wow, PACKETSZ, 0, (struct sockaddr *)&from, &len);
		if (rv <= 0)
		{
		    log(LOG_ERR, "recvMesg(): recvfrom faulure: %s\n", strerror(errno));
		    continue;
		}

		lbuf = (struct lbuf *)Wow;
		switch (lbuf->l_hdr.lh_type)
		{
		  case LOG_MSG:		printLogMsg(lbuf);	break;
		  case LOG_MBUF:	printLogMBuf(lbuf);	break;
		  case LOG_IP4:		printLogIP4(lbuf);	break;
		  case LOG_IP6:		printLogIP6(lbuf);	break;
		  case LOG_IN6ADDR:	printLogIN6addr(lbuf);	break;
		}
	    }
	    break;
	}
    }
}


void
printLogMsg(struct lbuf *lbuf)
{
    log(lbuf->l_hdr.lh_pri, "%s", lbuf->l_dat.__buf);
}


void
printLogMBuf(struct lbuf *lbuf)
{
    int		 rv;
    int		 rbytes = lbuf->l_hdr.lh_size;
    char	*dbytes = lbuf->l_dat.__buf;

    while (rbytes > 0)
    {
	rv = hexdump16(lbuf->l_hdr.lh_pri | 0x80000000, dbytes, rbytes);
	if (rv <= 0)
	{
	    log(LOG_ERR, "printLogMBuf(): something wroing in hexdump16." );
	    continue;
	}
	
	rbytes -= rv;
	dbytes += rv;
    }
}


void
printLogIP4(struct lbuf *lbuf)
{
    struct ip	*ip4;
    char	 from[INET_ADDRSTRLEN];
    char	 to  [INET_ADDRSTRLEN];

    ip4 = (struct ip *)lbuf->l_dat.__buf;
    inet_ntop(AF_INET, (char *)&ip4->ip_src, from, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, (char *)&ip4->ip_dst, to,   INET_ADDRSTRLEN);
    log(lbuf->l_hdr.lh_pri, "from %s to %s", from, to);
}


void
printLogIP6(struct lbuf *lbuf)
{
    struct ip6_hdr	*ip6;
    char		 from[INET6_ADDRSTRLEN];
    char		 to  [INET6_ADDRSTRLEN];

    ip6 = (struct ip6_hdr *)lbuf->l_dat.__buf;
    inet_ntop(AF_INET6, (char *)&ip6->ip6_src, from, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, (char *)&ip6->ip6_dst, to,   INET6_ADDRSTRLEN);
    log(lbuf->l_hdr.lh_pri, "from %s to %s", from, to);
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


void
printLogIN6addr(struct lbuf *lbuf)
{
    char	in6addr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, (char *)lbuf->l_addr.in6addr, in6addr, INET6_ADDRSTRLEN);
    log(lbuf->l_hdr.lh_pri, "%s%s", lbuf->l_addr.__msg, in6addr);
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


int
hexdump16(int priority, char *buffer, int len)
{
    int		 i, j;
    int		 offh, offc;
    int		 nbytes;
    u_char	*dbyte;
    u_char	 Wow[128];

    dbyte = buffer;
    memset(Wow, ' ', sizeof(Wow));

    if (len < 16)
    {
	nbytes = len;

	for (i = 0, offh = 0, offc = 38; i <= 3; i++, offh += 9, offc += 5)
	{
	    for (j = 0; j <= 3; j++, dbyte++)
	    {
		sprintf(&Wow[offh+j*2], "%02x", *dbyte);
		sprintf(&Wow[offc+j],	"%c",
			(*dbyte >= 0x20 && *dbyte <= 0x7e) ? *dbyte : '.');
		Wow[offh+j*2+2] = ' ';
		Wow[offc+j+1]	= ' ';

		if (--nbytes <= 0)
		{
		    Wow[57] = '\0';
		    log(priority, "%s", Wow);
		    return (len);
		}
	    }
	}
	return (0);			/* may be something wrong	*/
    }

    for (i = 0, offh = 0, offc = 38; i <= 3; i++, offh += 9, offc += 5)
    {
	for (j = 0; j <= 3; j++, dbyte++)
	{
	    sprintf(&Wow[offh+j*2], "%02x", *dbyte);
	    sprintf(&Wow[offc+j],   "%c",
		    (*dbyte >= 0x20 && *dbyte <= 0x7e) ? *dbyte : '.');
	}
	Wow[offh+j*2] = ' ';
	Wow[offc+j]   = ' ';
    }

    Wow[57] = '\0';
    log(priority, "%s", Wow);
    return (16);
}


void
quitting(int status)
{
    if (__op.pidFilename != NULL)
	unlink(__op.pidFilename);

    exit(status);
}


/*
 *
 */

void
openLog()
{
    int		logopt = 0;

    logopt = LOG_PID | LOG_NOWAIT;
    openlog("natptlog", logopt, LOG_DAEMON);
}


void
log(int priority, char *fmt, ...)
{
    va_list	ap;
    char	Wow[BUFSIZ];

    va_start(ap, fmt);
    vsprintf(Wow, fmt, ap);

    if (isOn(logsyslog))
	syslog(priority, Wow);

    if (isOn(logstderr))
    {
	struct tm	*tm;
	struct timeval	 atv;
	char		*months[] =
	{
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};

	if (priority & 0x80000000)
	    fprintf(stderr, "		     ");
	else
	{
	    gettimeofday(&atv, NULL);
	    tm = localtime(&atv.tv_sec);

	    fprintf(stderr, "%s ", months[tm->tm_mon]);
	    fprintf(stderr, "%02d ", tm->tm_mday);
	    fprintf(stderr, "%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec);
	}
	fprintf(stderr, "%s", Wow),
	fprintf(stderr, "\n");
    }

    va_end(ap);
}



void
closeLog()
{
    if (isOn(daemon))
	closelog();
}


/*
 *
 */

void
updatePidFile(char *filename)
{
    FILE	*fp;

    if ((fp = writeOpen(filename, O_EXCL)) != NULL)
    {
	fprintf(fp, "%ld\n", (long)getpid());
	fclose(fp);
    }
    else
    {
	log(LOG_ERR, "updatePidFile(): couldn't create pid file '%s'", filename);
    }
}


FILE *
writeOpen(char *filename, int flag)
{
    int			 fd;
    int			 regular = 0;
    FILE		*stream;
    struct stat		 sb;

    if (stat(filename, &sb) >= 0)
	regular = sb.st_mode & S_IFREG;
    else
    {
	regular = 1;
	if (errno != ENOENT)
	{
	    log(LOG_ERR, "writeOpen(): stat of %s failed: %s\n",
		filename, strerror(errno));
	    return (NULL);
	}
    }

    if (regular == 0)
    {
	log(LOG_ERR, "writeOpen(): %s isn't a regular file\n", filename);
	return (NULL);
    }

    if ((regular == 0x8000)		/* exist regular file		*/
	&& (flag == O_EXCL))		/* and error if already exists	*/
    {
	log(LOG_ERR, "writeOpen(): file exists\n");
	return (NULL);
    }

    unlink(filename);
    fd = open(filename,
	      O_WRONLY|O_CREAT|O_EXCL,
	      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    if (fd < 0)
	return (NULL);

    stream = fdopen(fd, "w");
    if (stream == NULL)
	close(fd);
    
    return (stream);
}


/*
 *
 */

void
setFileName(char *filename, int type)
{
    switch (type)
    {
      case OPT_PIDFILE:
	__op.pidFilename = xmalloc(ROUNDUP(strlen(filename)+1));
	strcpy(__op.pidFilename, filename);
	log(LOG_INFO, "	     PidFile: %s", filename);
	break;

      case OPT_STATSFILE:
	__op.statsFilename = xmalloc(ROUNDUP(strlen(filename)+1));
	strcpy(__op.statsFilename, filename);
	log(LOG_INFO, "	    StatFile: %s", filename);
	break;
    }
}


void
initSignal()
{
    sighandler(0);
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
		    log(LOG_NOTICE, "sighandler(): sigaction failed(%d): %s",
			signals[iter], strerror(errno));
		}
	    }
	}
	break;

      default:
	log(LOG_ERR, "sighandler(): caught signal, %d\n", sig);
	quitting (0);
	break;
    }
}


void
preinit()
{
    __op.b.logsyslog = 0;
    __op.b.logstderr = 1;

    openLog();
    log(LOG_INFO, "starting natptlog");
}


void
init_main()
{
    if (isOn(daemon)
	&& (daemon(0, 0) < 0))
    {
	__op.b.logsyslog = 1;
	__op.b.logstderr = 0;

	log(LOG_ERR, "init_main(): failure on daemon()"),
	exit(errno);
    }

    if (__op.pidFilename == NULL)
	setFileName(_PATH_PIDFILE, OPT_PIDFILE);

    initSignal();
    updatePidFile(__op.pidFilename);
}
