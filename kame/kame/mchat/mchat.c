/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <stdarg.h>
#include <errno.h>
#include "screen.h"
#include "history.h"

#ifndef IPV6_ADDR_SCOPE_RESERVED
#define IPV6_ADDR_SCOPE_RESERVED	0x00
#endif

/*
 * me ---> target(multicast:port)
 * me(multicast:port) <--- target
 * me ---> target(unicast:port+1)
 * me(unicast:port+1) <--- target
 */
static char *pname = "mcast";
static char myhostname[BUFSIZ];

struct session {
	struct session *s_next;
	char *s_mif;				/* multicast if */

	int s_mfd;				/* multicast sender fd */
	char *s_mport;				/* multicast sender port */
	struct sockaddr_storage s_mcast;	/* multicast destination addr */

	int s_rfd;				/* multicast receiver port */
	char *s_rpolicy;			/* multicast policy */

	int s_ufd;				/* unicast fd */
	char *s_uport;				/* unicast port */
	char *s_upolicy;			/* unicast policy */

	int logging;				/* log fd */

	char myname[BUFSIZ];
};

int debug = 0;
char *ifname = NULL;
int hlim = 0;
int dumbterm = 0;

static struct session *session = NULL;
static char msgbuf[BUFSIZ];

int af = AF_INET6;
int doit = 1;

int main __P((int, char **));
static void usage __P((void));
static void sighandler __P((int));
static void mainloop __P((int));
static int sendstr __P((int, struct sockaddr *, char *, ...));
static int parsecmd __P((char *, int, struct sockaddr *));
static struct sockaddr *getsrc __P((struct sockaddr *));
static int cmd_who __P((char *, struct sockaddr *));
static int cmd_secret __P((char *, struct sockaddr *));
static int cmd_file __P((char *, struct sockaddr *));
static int cmd_log __P((char *, struct sockaddr *));
static int logtofile __P((char *buf, int len));
static int cmd_quit __P((char *, struct sockaddr *));
static int cmd_help __P((char *, struct sockaddr *));
static int cmd_name __P((char *, struct sockaddr *));
static int set_info __P((struct session *));

#define max(a, b)	((a) > (b) ? (a) : (b))

struct cmdtab {
	char *cmdstr;
	int (*cmdlproc) __P((char *, struct sockaddr *));
	int (*cmdrproc) __P((char *, struct sockaddr *));
	char *helpstr;
} cmdtab[] = {
	{ "/w",		NULL,		cmd_who, "query members", },
	{ "/who",	NULL,		cmd_who, "query members", },
	{ "/s",		cmd_secret,	NULL,	"secret message, args: dstaddr msg", },
	{ "/secret",	cmd_secret,	NULL,	"secret message, args: dstaddr msg", },
	{ "/name",	cmd_name,	NULL,	"change name, args: name-string", },
	{ "/file",	cmd_file,	NULL,	"send data of file, args: file", },
	{ "/log",	cmd_log,	NULL,	"log date received, args: file", },
	{ "/q",		cmd_quit,	NULL,	"quit", },
	{ "/quit",	cmd_quit,	NULL,	"quit", },
	{ "/h",		cmd_help,	NULL,	"help", },
	{ "/help",	cmd_help,	NULL,	"help", },
	{ NULL,		NULL },
};

int
main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	char pbuf[10];
	int s;
	char *iface = NULL, *policy = NULL;
	char *addr, *port;
	struct addrinfo hints, *res;
	int error;

	pname = argv[0];
	gethostname(myhostname, sizeof(myhostname));

	while ((c = getopt(argc, argv, "dDi:l:P:")) != EOF) {
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'D':
			dumbterm++;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'l':
			hlim = atoi(optarg);
			break;
		case 'P':
			policy = optarg;
			break;
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage();
		exit(1);
	}

	addr = argv[0];
	port = argv[1];

	session = (struct session *)calloc(1, sizeof(struct session));
	if (!session)
		err(1, "malloc");
	memset(session, 0, sizeof(*session));

	strncpy(session->myname, getlogin(), sizeof(session->myname));

	if (iface)
		session->s_mif = strdup(iface);
	session->s_mport = strdup(port);
	snprintf(pbuf, sizeof(pbuf), "%d", atoi(port) + 1);
	session->s_uport = strdup(pbuf);
	if (policy) {
		session->s_rpolicy = strdup(policy);
		session->s_upolicy = strdup(policy);
	}

	/* configure multicast sender port */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, session->s_mport, &hints, &res);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));
	if (res->ai_next) {
		errx(1, "%s/%s resolved to multiple addresses", addr,
			session->s_mport);
	}
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
		err(1, "socket");
	if (ifname != NULL) {
		int ifindex;

		ifindex = if_nametoindex(ifname);
		if (ifindex == 0)
			err(1, "if_nametoindex");
		error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
				&ifindex, sizeof(ifindex));
		if (error < 0)
			err(1, "setsockopt(IPV6_MULTICAST_IF)");
	}
	if (hlim != 0) {
		error = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				&hlim, sizeof(hlim));
		if (error < 0)
			err(1, "setsockopt(IPV6_MULTICAST_HOPS)");
	}
	memcpy(&session->s_mcast, res->ai_addr, res->ai_addrlen);
	session->s_mfd = s;
	freeaddrinfo(res);

	/* configure multicast receiver port */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(addr, session->s_mport, &hints, &res);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));
	if (res->ai_next) {
		errx(1, "%s/%s resolved to multiple addresses", "wildcard",
			session->s_uport);
	}
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
		err(1, "socket");
	if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
		err(1, "bind");
	switch (res->ai_family) {
	case AF_INET6:
		if (IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr)) {
			struct ipv6_mreq mreq6;

			memset(&mreq6, 0, sizeof(mreq6));
			if (ifname) {
				mreq6.ipv6mr_interface = if_nametoindex(ifname);
				if (mreq6.ipv6mr_interface == 0)
					err(1, "if_nametoindex(%s)", ifname);
			}

			memcpy(&mreq6.ipv6mr_multiaddr,
				&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
				sizeof(mreq6.ipv6mr_multiaddr));

			if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
					&mreq6, sizeof(mreq6))) {
				err(1, "setsockopt(IPV6_JOIN_GROUP)");
			}
		}
		break;
	default:
		errx(1, "unsupported address family %d", res->ai_family);
	}
	session->s_rfd = s;
	freeaddrinfo(res);

	/* configure unicast port */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, session->s_uport, &hints, &res);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));
	if (res->ai_next) {
		errx(1, "%s/%s resolved to multiple addresses", "wildcard",
			session->s_uport);
	}
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
		err(1, "socket");
	if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
		err(1, "bind");
	if (session->s_upolicy) {
#if defined(IPSEC) && defined(IPSEC_POLICY_IPSEC)
		char *buf;
		int level, optname;

		buf = ipsec_set_policy(session->s_upolicy,
			strlen(session->s_upolicy));
		if (buf == NULL)
			errx(1, ipsec_strerror());
		switch (res->ai_family) {
		case AF_INET6:
			level = IPPROTO_IPV6;
			optname = IPV6_IPSEC_POLICY;
			break;
		default:
			level = optname = 0;
			break;
		}
		if (level) {
			if (setsockopt(s, level, optname,
					buf, ipsec_get_policylen(buf)) < 0)
				warnx("Unable to set IPSec policy");
		} else
			errx(1, "unsupported address family %d", res->ai_family);
		free(buf);
		/* XXX what do i do INBOUND policy ? */
#else
		errx(1, "ipsec policy has no efffect in this configuration");
#endif
	}
	session->s_ufd = s;
	freeaddrinfo(res);

	signal(SIGINT, sighandler);
	init_screen(1);
	init_hist();
	mainloop(STDIN_FILENO);
	close_screen();
	exit(0);
}

static void
usage()
{
	printf("Usage: %s [-dD] [-i ifname] [-l hlim] [-P policy] "
		"addr port\n", pname);
}

static void
sighandler(sig)
	int sig;
{
	cmd_quit("", NULL);
	close_screen();
}

static void
mainloop(fd)
	int fd;		/* console */
{
	int len;
	char buf[BUFSIZ];
	fd_set rset0, rset;
	int nfd;
	int n;
	struct sockaddr_storage ss;
	int in, inuni, out;

	/* XXX to be applied to current session ? */
	in = session->s_rfd;
	inuni = session->s_ufd;
	out = session->s_mfd;
	set_info(session);

	FD_ZERO(&rset0);
	FD_SET(fd, &rset0);
	FD_SET(in, &rset0);
	FD_SET(inuni, &rset0);
	nfd = max(fd, in);
	nfd = max(nfd, inuni);

	sendstr(session->s_mfd, (struct sockaddr *)&session->s_mcast,
		">> %s@%s joined", session->myname, myhostname);

	while (doit) {
		rset = rset0;
		n = select(nfd + 1, &rset, NULL, NULL, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "select");
		}

		memset(buf, 0, sizeof(buf));
		if (FD_ISSET(fd, &rset)) {
			if (wmsgcheck(msgbuf, sizeof(msgbuf))) {
				if (msgbuf[0] == '/'
				 && parsecmd(msgbuf, 1, NULL) >= 0)
					;
				else {
					sendstr(session->s_mfd,
						(struct sockaddr *)&session->s_mcast,
						"[%s] %s", session->myname, msgbuf);
				}
			}
		}
		if (FD_ISSET(in, &rset)) {
			int socklen;
			socklen = sizeof(ss);
			len = recvfrom(in, buf, sizeof(buf), 0,
				(struct sockaddr *)&ss, &socklen);
			buf[len] = '\0';
			if (parsecmd(buf, 0, (struct sockaddr *)&ss) < 0) {
				if (session->logging)
					logtofile(buf, strlen(buf));
				wrecv_print("%s\n", buf);
			} else {
				/* command processed, */
			}
		}
		if (FD_ISSET(inuni, &rset)) {
			int socklen;
			socklen = sizeof(ss);
			len = recvfrom(inuni, buf, sizeof(buf), 0,
				(struct sockaddr *)&ss, &socklen);
			buf[len] = '\0';
			if (parsecmd(buf, 0, (struct sockaddr *)&ss) < 0)
				wrecv_print("%s\n", buf);
			else {
				/* command processed, */
			}
		}
	}
}

static int
sendstr(s, sa, msg)
	int s;
	struct sockaddr *sa;
	char *msg;
{
	va_list ap;
	char buf[BUFSIZ];
	int error;

	va_start(ap, msg);
	vsnprintf(buf, sizeof(buf), msg, ap);
	va_end(ap);
	error = sendto(s, buf, strlen(buf), 0, sa, sa->sa_len);
	if (error < 0) {
		strcpy(buf, "(unknown)");
		getnameinfo(sa, sa->sa_len, buf, sizeof(buf), 0, NULL,
			NI_NUMERICHOST);
		wrecv_print(">> sendto %s: %s\n", buf, strerror(errno));
	}
	return error;
}


static int
parsecmd(buf, local, sa)
	char *buf;
	int local;		/* command from local user, or remote */
	struct sockaddr *sa;
{
	char *body;
	char *p;
	struct cmdtab *ct;
	int l;

	if (!local) {
		/* chop off user name */
		body = strchr(buf, ']');
		if (!body)
			return -1;
		body++;
		if (body[0] != ' ')
			return -1;
		body++;
	} else
		body = buf;

	for (ct = &cmdtab[0]; ct->cmdstr; ct++) {
		l = strlen(ct->cmdstr);
		if (strncmp(body, ct->cmdstr, l) != 0)
			continue;
		if (body[l] != '\0' && !isspace(body[l]))
			continue;

		p = body + l;
		while (*p && isspace(*p))
			p++;

		if (local && ct->cmdlproc)
			return (*ct->cmdlproc)(p, sa);
		else if (!local && ct->cmdrproc)
			return (*ct->cmdrproc)(p, sa);
		/* fail */
	}
	return -1;
}

static struct sockaddr *
getsrc(dst)
	struct sockaddr *dst;
{
	int s;
	static struct sockaddr_storage ss;
	int sslen;

	s = socket(dst->sa_family, SOCK_DGRAM, 0);
	if (s < 0)
		return NULL;
	if (connect(s, dst, dst->sa_len) < 0) {
		close(s);
		return NULL;
	}
	sslen = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &sslen) < 0) {
		close(s);
		return NULL;
	}
	close(s);
	return (struct sockaddr *)&ss;
}

static int
cmd_who(buf, sa)
	char *buf;
	struct sockaddr *sa;
{
	char abuf[BUFSIZ];
	struct sockaddr_storage ss;
	struct sockaddr *src;
	int error;

	getnameinfo(sa, sa->sa_len,
		abuf, sizeof(abuf), 0, NULL, NI_NUMERICHOST);
	wrecv_print(">> who request from %s\n", abuf);

	src = getsrc(sa);
	if (src) {
		error = getnameinfo((struct sockaddr *)src, src->sa_len,
			abuf, sizeof(abuf), 0, NULL, NI_NUMERICHOST);
		if (error)
			strcpy(abuf, "unknown");
	} else
		strcpy(abuf, "unknown");

	memcpy(&ss, sa, sa->sa_len);
	switch (ss.ss_family) {
	case AF_INET6:
		((struct sockaddr_in6 *)&ss)->sin6_port = ntohs(atoi(session->s_uport));
		break;
	default:
		wstat_print(">> unsupported af %d\n", ss.ss_family);
		return 0;
	}

	sendstr(session->s_mfd, (struct sockaddr *)&ss, ">> %s@%s (%s)",
		session->myname, myhostname, abuf);

	return 0;
}

static int
cmd_secret(buf, sa)
	char *buf;
	struct sockaddr *sa;
{
	char *p;
	struct addrinfo hints, *res;
	int error;
	char myaddr[BUFSIZ];
	struct sockaddr *src;

	p = buf;
	while (*p && !isspace(*p))
		p++;
	*p++ = '\0';
	while (*p && isspace(*p))
		p++;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(buf, session->s_uport, &hints, &res);
	if (error) {
		wstat_print("secret: %s\n", gai_strerror(error));
		return 0;
	}
	if (res->ai_next) {
		wstat_print("secret: resolved to multiple addrs\n");
		freeaddrinfo(res);
		return 0;
	}

#ifdef __KAME__	/*should use advapi*/
	switch (res->ai_family) {
	case AF_INET6:
	    {
		struct sockaddr_in6 *sin6;
		sin6 = (struct sockaddr_in6 *)res->ai_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
			int ifindex;

			if (!ifname) {
				wstat_print("secret: no interface specified, "
					"cannot send to link-local address\n");
				return 0;
			}

			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				wstat_print("secret: "
					"if_nametoindex(%s) failed\n", ifname);
				return 0;
			}
			*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] =
				htons(ifindex);
		}
		break;
	    }
	}
#endif

	memset(&myaddr, 0, sizeof(myaddr));
	((struct sockaddr *)res->ai_addr)->sa_len = res->ai_addrlen;
	src = getsrc(res->ai_addr);
	if (src) {
		error = getnameinfo((struct sockaddr *)src, src->sa_len,
			myaddr, sizeof(myaddr), 0, NULL, NI_NUMERICHOST);
		if (error)
			strcpy(myaddr, "unknown");
	} else
		strcpy(myaddr, "unknown");

	wstat_print(">> sending secret message to %s\n", buf);
	sendstr(session->s_ufd, res->ai_addr, "<%s/%s> %s", session->myname, myaddr, p);
	freeaddrinfo(res);
	return 0;
}

static int
cmd_file(fname, sa)
	char *fname;
	struct sockaddr *sa;
{
	int fd, len;
	char buf[512];
	int error;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		wstat_print(">> open %s: %s\n", fname, strerror(errno));
		return 0;
	}

	wstat_print(">> sending data of file, %s\n", fname);

	sa = (struct sockaddr *)&session->s_mcast;
	while (1) {
		len = read(fd, buf, sizeof(buf));
		if (len == 0)
			break;
		if (len < 0) {
			warn("read");
			(void)close(fd);
			return 0;
		}
		error = sendto(session->s_mfd, buf, len, 0,
				sa, sa->sa_len);
		if (error < 0) {
			strcpy(buf, "(unknown)");
			getnameinfo(sa, sa->sa_len, buf, sizeof(buf), 0, NULL,
				NI_NUMERICHOST);
			wstat_print(">> sendto %s: %s\n", buf, strerror(errno));
		}
	}

	(void)close(fd);

	return 0;
}

static int
cmd_log(fname, sa)
	char *fname;
	struct sockaddr *sa;
{
	if (!session->logging) {
		session->logging = open(fname, O_WRONLY | O_CREAT);
		if (session->logging < 0) {
			wstat_print(">> open %s: %s\n", fname, strerror(errno));
			session->logging = 0;
			return 0;
		}
		if (session->logging == 0) {
			wstat_print(">> open %s: fd == zero ?\n", fname);
			session->logging = 0;
			return 0;
		}
	} else {
		(void)close(session->logging);
		session->logging = 0;
	}

	wstat_print(">> logging %s\n", session->logging ? "on" : "off");

	return 0;
}

static int
logtofile(buf, len)
	char *buf;
	int len;
{
	int error;

	error = write(session->logging, buf, len);
	if (error < 0) {
		wstat_print(">> write: %s\n", strerror(errno));
		(void)close(session->logging);
		session->logging = 0;
		return 0;
	}

	return 0;
}

static int
cmd_quit(buf, sa)
	char *buf;
	struct sockaddr *sa;	/* not used */
{
	sendstr(session->s_mfd, (struct sockaddr *)&session->s_mcast,
		">> %s@%s left", session->myname, myhostname);
	wrecv_print(">> %s@%s left\n", session->myname, myhostname);

	doit = 0;
	return 0;
}

static int
cmd_help(buf, sa)
	char *buf;
	struct sockaddr *sa;	/* not used */
{
	struct cmdtab *ct;

	wrecv_print(">> the following commands are available:\n");
	for (ct = &cmdtab[0]; ct->cmdstr; ct++)
		wrecv_print(">>  %-8s  %s\n", ct->cmdstr, ct->helpstr);

	return 0;
}

static int
cmd_name(buf, sa)
	char *buf;
	struct sockaddr *sa;	/* not used */
{
	if (buf[0])
		strncpy(session->myname, buf, sizeof(session->myname));
	else
		strncpy(session->myname, getlogin(), sizeof(session->myname));
	wrecv_print(">> name set to \"%s\"\n", session->myname);
	set_info(session);	/* XXX to be applied to current session */

	return 0;
}

static int
set_info(ss)
	struct session *ss;
{
	char buf[256];
	char host[24], serv[10];
	int error;

	error = getnameinfo((struct sockaddr *)&ss->s_mcast,
				ss->s_mcast.__ss_len,
				host, sizeof(host),
				serv, sizeof(serv), NI_NUMERICSERV);
	if (error) {
		wstat_print(">> failed getnameinfo with status %d\n", error);
		return 1;
	}
	snprintf(buf, sizeof(buf), "%s[%s] %s", host, serv, ss->myname);
	wstat_setmsg(buf, sizeof(buf));

	return 0;
}
