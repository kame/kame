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
 *	$Id: main.c,v 1.1 2000/01/07 15:08:34 fujisawa Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>

#include <netdb.h>
#include <resolv.h>
#include <arpa/nameser.h>

#include "defs.h"
#include "main.h"


/*
 *
 */

u_long		__debug;
struct options	__op;


char		*parseArgument		__P((int, char *[]));
void		 parseConfig		__P((char *));
char		*parseConfigLine	__P((char *, int, char *, char *));
void		 doConfig		__P((char *, char *));
int		 keyword		__P((char *));

void		 setFileName		__P((char *, int));
void		 setSide		__P((char *, int));
void		 setPrefix		__P((char *));
void		 updatePidFile		__P((void));

void		 openLog		__P((void));

void		 preinit		__P((void));
void		 init_main		__P((void));


/*
 *
 */

int
main(int argc, char *argv[])
{
    char		*fname = NULL;
    struct sdesc	*desc;

    preinit();

    if ((fname = parseArgument(argc, argv)) != NULL)
	parseConfig(fname);

    init_main();

    while (1)
    {
	if ((desc = recvMessage()) != NULL)
	{
	    if (desc->type == RES_PRF_QUERY)
		processQuery(desc);
	    else
		processResponse(desc);
	}
    }

    exit(0);
}


char *
parseArgument(int argc, char *argv[])
{
    int		 ch;
    char	*fname = NULL;

    extern	char	*optarg;
    extern	int	 optind;

    while ((ch = getopt(argc, argv, "b:d:f:")) != EOF)
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
	    {
		__debug = strtoul(optarg+5, (char **)NULL, 0);
		if (isDebug(NOSYSLOG))		__op.b.logsyslog = 0;
		if ((isDebug(LOGTOSTDERR))
		    && (!isOn(daemon)))		__op.b.logstderr = 1;

	    }
	    else
		goto	illegalopt;
	    break;

	  case 'f':
	    fname = optarg;
	    break;
	}
    }

    argc += optind;
    argv += optind;

    return (fname);
    
illegalopt:;
    log(LOG_ERR, "Illegal option name `%s\'\n", (optarg-1));
    exit (errno);
}


void
parseConfig(char *fname)
{
    int		 lineno;
    char	*filename = NULL;
    FILE	*fp = NULL;
    char	 buf[BUFSIZ];

    if (strcmp(fname, "-") == 0)
    {
	fp = stdin;
	filename = "stdin";
    }
    else
    {
	if ((fp = fopen(fname, "r")) == NULL)
	    log(LOG_ERR, "%s: %s\n", fname, strerror(errno)),
	    quitting(errno);

	filename = fname;
    }
    
    lineno = 0;

    while (fgets(buf, sizeof(buf), fp))
    {
	char	*bufp;
	int	 buflen, linelen;
	char	 key[128], val[128];

	lineno++;
	bufp = buf;
	buflen = sizeof(buf);
	linelen = strlen(buf);

	while (TRUE)
	{
	    if ((linelen < 2) || (bufp[linelen-2] != '\\'))
		break;
	    bufp += linelen - 2;
	    buflen -= linelen;
	    if (fgets(bufp, buflen, fp) == NULL)
		break;

	    lineno++;
	    linelen = strlen(bufp);
	}

	if (parseConfigLine(buf, lineno, key, val) != NULL)
	    doConfig(key, val);
    }

    fclose(fp);
}


char *
parseConfigLine(char *buf, int lineno, char *key, char *val)
{
    char	*chp, *chq;

    chp = buf;
    while (*chp && isspace(*chp))	chp++;
    if ((*chp == '\0') || (*chp == '#'))
	return (NULL);

    chq = key;
    while (*chp && isalpha(*chp))	*chq++ = *chp++;
    if (*chp != ':')
	return (NULL);
    *chq = '\0';

    chp++;
    while (*chp && isspace(*chp))	chp++;
    chq = val;
    while (*chp && *chp != '#' && *chp != '\n')	*chq++ = *chp++;
    while (--chq >= val && isspace(*chq)) ;
    *(chq+1) = '\0';

    return (buf);
}


void
doConfig(char *key, char *val)
{
    int	token;

    token = keyword(key);

    switch (token)
    {
      case SDUMPFILE:		setFileName(val, OPT_DUMPFILE);		break;
      case SINSIDE:		setSide(val, inSide);			break;
      case SNATPTPREFIX:	setPrefix(val);				break;
      case SOUTSIDE:		setSide(val, outSide);			break;
      case SPIDFILE:		setFileName(val, OPT_PIDFILE);		break;
      case SSERVERINSIDE:	setServerInside(val);			break;
      case SSERVEROUTSIDE:	setServerOutside(val);			break;
      case SSTATFILE:		setFileName(val, OPT_STATSFILE);	break;

      default:
	log(LOG_NOTICE, "Illegal keyword %s\n", key);
	break;
    }
}


int
keyword(char *yytext)
{
    int		iter;

    for (iter = 0; keyTable[iter].word; iter++)
    {
	if (strncasecmp(keyTable[iter].word, yytext, strlen(yytext)) == 0)
	    return (keyTable[iter].token);
    }

    return (0);
}


void
setFileName(char *filename, int type)
{
    switch (type)
    {
      case OPT_DUMPFILE:
	__op.dumpFilename = xmalloc(ROUNDUP(strlen(filename)+1));
	strcpy(__op.dumpFilename, filename);
	log(LOG_INFO, "	    DumpFile: %s", filename);
	break;

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
setSide(char *ifname, int side)
{
		struct ifnets	*ifnp;
    extern	struct ifnets	*ifnets;

    for (ifnp = ifnets; ifnp; ifnp = ifnp->if_next)
    {
	if (strncmp(ifnp->if_name, ifname, strlen(ifname)) == 0)
	{
	    ifnp->if_side = side;

	    log(LOG_INFO, "	 %sSide: %s",
		((side == inSide) ? " in"
		: (side == outSide) ? "out"
		: "unknown"),
		ifnp->if_name);

	    return ;
	}
    }
}


void
setPrefix(char *addr)
{
		struct addrinfo	*res;
    extern	struct addrinfo	*natptPrefix;

    if ((res = getAddrInfo(PF_INET6, addr)) != NULL)
    {
	natptPrefix = res;
	log(LOG_INFO, "	 natptPrefix: %s",
	    displaySockaddr(res->ai_addr));
    }
}


void
updatePidFile()
{
    FILE	*fp;

    if ((fp = writeOpen(__op.pidFilename, O_EXCL)) != NULL)
    {
	fprintf(fp, "%ld\n", (long)getpid());
	fclose(fp);
    }
    else
    {
	log(LOG_ERR, "couldn't create pid file '%s'\n", __op.pidFilename);
	exit(errno);
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
    openlog("ptrd", logopt, LOG_DAEMON);
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

	gettimeofday(&atv, NULL);
	tm = localtime(&atv.tv_sec);

	fprintf(stderr, "%s ", months[tm->tm_mon]);
	fprintf(stderr, "%02d ", tm->tm_mday);
	fprintf(stderr, "%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec);
	fprintf(stderr, Wow),
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
preinit()
{
    __op.b.useTAny = 1;
    __op.b.supportA1A4 = 1;
    __op.b.logsyslog = 1;
    __op.b.logstderr = 0;

    openLog();
    log(LOG_INFO, "starting daemon");

    initIfnets();
}


void
init_main()
{
    if (isDebug(DEBUG_RESOLVER))
    {
	if (((_res.options & RES_INIT) == 0)
	    && (res_init() == -1))
	    log(LOG_ERR, "init_main: failure on res_init()"),
	    exit(errno);
    }

    if (isOn(daemon)
	&& (daemon(0, 0) < 0))
    {
	log(LOG_ERR, "init_main: failure on daemon()"),
	exit(errno);
    }

    if (__op.dumpFilename == NULL)
	setFileName(_PATH_DUMPFILE, OPT_DUMPFILE);

    if (__op.pidFilename == NULL)
	setFileName(_PATH_PIDFILE, OPT_PIDFILE);

    if (__op.statsFilename == NULL)
	setFileName(_PATH_STATSFILE, OPT_STATSFILE);

    initSignal();
    updatePidFile();

    init_misc();
    init_message();
}
