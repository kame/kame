/*
 * Copyright (C) 1998 WIDE Project.
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

/*
 * Copyright (c) 1983, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)rcmd.c	8.3 (Berkeley) 3/26/94";
#endif /* LIBC_SCCS and not lint */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifdef YP
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#endif

extern int innetgr __P(( const char *, const char *, const char *, const char * ));

#define max(a, b)	((a > b) ? a : b)

int __ivaliduser_af __P((FILE *, const void *, const char *, const char *, int, int));
static int __icheckhost __P((const void *, const char *, int, int));

char paddr[INET6_ADDRSTRLEN];

int
rcmd(ahost, rport, locuser, remuser, cmd, fd2p)
	char **ahost;
	u_short rport;
	const char *locuser, *remuser, *cmd;
	int *fd2p;
{
	struct addrinfo hints, *res, *ai;
	struct sockaddr_storage from;
	fd_set reads;
	long oldmask;
	pid_t pid;
	int s, lport, timo, error;
	char c;
	int refused;
	char num[8];

	pid = getpid();

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	(void)snprintf(num, sizeof(num), "%d", ntohs(rport));
	error = getaddrinfo(*ahost, num, &hints, &res);
	if (error) {
		fprintf(stderr, "rcmd: getaddrinfo: %s\n",
			gai_strerror(error));
		return (-1);
	}

	if (res->ai_canonname)
		*ahost = res->ai_canonname;
	ai = res;
	refused = 0;
	oldmask = sigblock(sigmask(SIGURG));
	for (timo = 1, lport = IPPORT_RESERVED - 1;;) {
		s = rresvport_af(&lport, ai->ai_family);
		if (s < 0) {
			if (errno == EAGAIN)
				(void)fprintf(stderr,
				    "rcmd: socket: All ports in use\n");
			else
				(void)fprintf(stderr, "rcmd: socket: %s\n",
				    strerror(errno));
			sigsetmask(oldmask);
			freeaddrinfo(res);
			return (-1);
		}
		fcntl(s, F_SETOWN, pid);
		if (connect(s, ai->ai_addr, ai->ai_addrlen) >= 0)
			break;
		(void)close(s);
		if (errno == EADDRINUSE) {
			lport--;
			continue;
		}
		if (errno == ECONNREFUSED)
			refused = 1;
		if (ai->ai_next != NULL) {
			int oerrno = errno;

			getnameinfo(ai->ai_addr, ai->ai_addrlen,
				    paddr, sizeof(paddr),
				    NULL, 0,
				    NI_NUMERICHOST);
			fprintf(stderr, "connect to address %s: ", paddr);
			errno = oerrno;
			perror(0);
			ai = ai->ai_next;
			getnameinfo(ai->ai_addr, ai->ai_addrlen,
				    paddr, sizeof(paddr),
				    NULL, 0,
				    NI_NUMERICHOST);
			fprintf(stderr, "Trying %s...\n", paddr);
			continue;
		}
		if (refused && timo <= 16) {
			(void)sleep(timo);
			timo *= 2;
			ai = res;
			refused = 0;
			continue;
		}
		freeaddrinfo(res);
		(void)fprintf(stderr, "%s: %s\n", *ahost, strerror(errno));
		sigsetmask(oldmask);
		return (-1);
	}
	lport--;
	if (fd2p == 0) {
		write(s, "", 1);
		lport = 0;
	} else {
		int s2 = rresvport_af(&lport, ai->ai_family), s3;
		int len = ai->ai_addrlen;
		int nfds;

		if (s2 < 0)
			goto bad;
		listen(s2, 1);
		(void)snprintf(num, sizeof(num), "%d", lport);
		if (write(s, num, strlen(num)+1) != strlen(num)+1) {
			(void)fprintf(stderr,
			    "rcmd: write (setting up stderr): %s\n",
			    strerror(errno));
			(void)close(s2);
			goto bad;
		}
		nfds = max(s, s2)+1;
		if(nfds > FD_SETSIZE) {
			fprintf(stderr, "rcmd: too many files\n");
			(void)close(s2);
			goto bad;
		}
again:
		FD_ZERO(&reads);
		FD_SET(s, &reads);
		FD_SET(s2, &reads);
		errno = 0;
		if (select(nfds, &reads, 0, 0, 0) < 1 || !FD_ISSET(s2, &reads)){
			if (errno != 0)
				(void)fprintf(stderr,
				    "rcmd: select (setting up stderr): %s\n",
				    strerror(errno));
			else
				(void)fprintf(stderr,
				"select: protocol failure in circuit setup\n");
			(void)close(s2);
			goto bad;
		}
		s3 = accept(s2, (struct sockaddr *)&from, &len);
		switch (from.__ss_family) {
		case AF_INET:
			rport = ntohs(((struct sockaddr_in *)&from)->sin_port);
			break;
		case AF_INET6:
			rport = ntohs(((struct sockaddr_in6 *)&from)->sin6_port);
			break;
		default:
			rport = 0;	/* error */
			break;
		}
		/*
		 * XXX careful for ftp bounce attacks. If discovered, shut them
		 * down and check for the real auxiliary channel to connect.
		 */
		if (rport == 20) {
			close(s3);
			goto again;
		}
		(void)close(s2);
		if (s3 < 0) {
			(void)fprintf(stderr,
			    "rcmd: accept: %s\n", strerror(errno));
			lport = 0;
			goto bad;
		}
		*fd2p = s3;
		if (rport >= IPPORT_RESERVED || rport < IPPORT_RESERVED / 2) {
			(void)fprintf(stderr,
			    "socket: protocol failure in circuit setup.\n");
			goto bad2;
		}
	}
	(void)write(s, locuser, strlen(locuser)+1);
	(void)write(s, remuser, strlen(remuser)+1);
	(void)write(s, cmd, strlen(cmd)+1);
	if (read(s, &c, 1) != 1) {
		(void)fprintf(stderr,
		    "rcmd: %s: %s\n", *ahost, strerror(errno));
		goto bad2;
	}
	if (c != 0) {
		while (read(s, &c, 1) == 1) {
			(void)write(STDERR_FILENO, &c, 1);
			if (c == '\n')
				break;
		}
		goto bad2;
	}
	sigsetmask(oldmask);
	freeaddrinfo(res);
	return (s);
bad2:
	if (lport)
		(void)close(*fd2p);
bad:
	(void)close(s);
	sigsetmask(oldmask);
	freeaddrinfo(res);
	return (-1);
}

int	__check_rhosts_file = 1;
char	*__rcmd_errstr;

int
ruserok_af(rhost, superuser, ruser, luser, af)
	const char *rhost, *ruser, *luser;
	int superuser, af;
{
	struct hostent *hp;
	union {
		struct in_addr addr_in;
		struct in6_addr addr_in6;
	} addr;
	char **ap;
	int ret, h_error;

	if ((hp = getipnodebyname(rhost, af, AI_DEFAULT, &h_error)) == NULL)
		return (-1);
	ret = -1;
	for (ap = hp->h_addr_list; *ap; ++ap) {
		bcopy(*ap, &addr, hp->h_length);
		if (iruserok_af(&addr, superuser, ruser, luser, af) == 0) {
			ret = 0;
			break;
		}
	}
	freehostent(hp);
	return (ret);
}

int
ruserok(rhost, superuser, ruser, luser)
	const char *rhost, *ruser, *luser;
	int superuser;
{
	return ruserok_af(rhost, superuser, ruser, luser, AF_INET);
}

/*
 * New .rhosts strategy: We are passed an ip address. We spin through
 * hosts.equiv and .rhosts looking for a match. When the .rhosts only
 * has ip addresses, we don't have to trust a nameserver.  When it
 * contains hostnames, we spin through the list of addresses the nameserver
 * gives us and look for a match.
 *
 * Returns 0 if ok, -1 if not ok.
 */
int
iruserok_af(raddr, superuser, ruser, luser, af)
	const void *raddr;
	int superuser;
	const char *ruser, *luser;
	int af;
{
	register char *cp;
	struct stat sbuf;
	struct passwd *pwd;
	FILE *hostf;
	uid_t uid;
	int first;
	char pbuf[MAXPATHLEN];
	int len = 0;

	switch (af) {
	case AF_INET:
		len = sizeof(struct in_addr);
		break;
	case AF_INET6:
		len = sizeof(struct in6_addr);
		break;
	}

	first = 1;
	hostf = superuser ? NULL : fopen(_PATH_HEQUIV, "r");
again:
	if (hostf) {
		if (__ivaliduser_af(hostf, raddr, luser, ruser, af, len) == 0) {
			(void)fclose(hostf);
			return (0);
		}
		(void)fclose(hostf);
	}
	if (first == 1 && (__check_rhosts_file || superuser)) {
		first = 0;
		if ((pwd = getpwnam(luser)) == NULL)
			return (-1);
		(void)strcpy(pbuf, pwd->pw_dir);
		(void)strcat(pbuf, "/.rhosts");

		/*
		 * Change effective uid while opening .rhosts.  If root and
		 * reading an NFS mounted file system, can't read files that
		 * are protected read/write owner only.
		 */
		uid = geteuid();
		(void)seteuid(pwd->pw_uid);
		hostf = fopen(pbuf, "r");
		(void)seteuid(uid);

		if (hostf == NULL)
			return (-1);
		/*
		 * If not a regular file, or is owned by someone other than
		 * user or root or if writeable by anyone but the owner, quit.
		 */
		cp = NULL;
		if (lstat(pbuf, &sbuf) < 0)
			cp = ".rhosts lstat failed";
		else if (!S_ISREG(sbuf.st_mode))
			cp = ".rhosts not regular file";
		else if (fstat(fileno(hostf), &sbuf) < 0)
			cp = ".rhosts fstat failed";
		else if (sbuf.st_uid && sbuf.st_uid != pwd->pw_uid)
			cp = "bad .rhosts owner";
		else if (sbuf.st_mode & (S_IWGRP|S_IWOTH))
			cp = ".rhosts writeable by other than owner";
		/* If there were any problems, quit. */
		if (cp) {
			__rcmd_errstr = cp;
			(void)fclose(hostf);
			return (-1);
		}
		goto again;
	}
	return (-1);
}

int
iruserok(raddr, superuser, ruser, luser)
#if defined(__NetBSD__) || defined(__OpenBSD__)
	u_int32_t raddr;
#else
	u_long raddr;
#endif
	int superuser;
	const char *ruser, *luser;
{
	return iruserok_af(&raddr, superuser, ruser, luser, AF_INET);
}

/*
 * Returns 0 if ok, -1 if not ok.
 */
int
__ivaliduser_af(hostf, raddr, luser, ruser, af, len)
	FILE *hostf;
	const void *raddr;
	const char *luser, *ruser;
	int af, len;
{
	register char *user, *p;
	int ch;
	char buf[MAXHOSTNAMELEN + 128];		/* host + login */
	char hname[MAXHOSTNAMELEN];
	struct hostent *hp;
	/* Presumed guilty until proven innocent. */
	int userok = 0, hostok = 0;
	int h_error;
#ifdef YP
	char *ypdomain;

	if (yp_get_default_domain(&ypdomain))
		ypdomain = NULL;
#else
#define	ypdomain NULL
#endif
	/* We need to get the damn hostname back for netgroup matching. */
	hp = getipnodebyaddr((char *)raddr, len, af, &h_error);
	if (hp == NULL)
		return (-1);
	strncpy(hname, hp->h_name, sizeof(hname));
	hname[sizeof(hname) - 1] = '\0';
	freehostent(hp);

	while (fgets(buf, sizeof(buf), hostf)) {
		p = buf;
		/* Skip lines that are too long. */
		if (strchr(p, '\n') == NULL) {
			while ((ch = getc(hostf)) != '\n' && ch != EOF);
			continue;
		}
		if (*p == '\n' || *p == '#') {
			/* comment... */
			continue;
		}
		while (*p != '\n' && *p != ' ' && *p != '\t' && *p != '\0') {
			*p = isupper(*p) ? tolower(*p) : *p;
			p++;
		}
		if (*p == ' ' || *p == '\t') {
			*p++ = '\0';
			while (*p == ' ' || *p == '\t')
				p++;
			user = p;
			while (*p != '\n' && *p != ' ' &&
			    *p != '\t' && *p != '\0')
				p++;
		} else
			user = p;
		*p = '\0';
		/*
		 * Do +/- and +@/-@ checking. This looks really nasty,
		 * but it matches SunOS's behavior so far as I can tell.
		 */
		switch(buf[0]) {
		case '+':
			if (!buf[1]) {     /* '+' matches all hosts */
				hostok = 1;
				break;
			}
			if (buf[1] == '@')  /* match a host by netgroup */
				hostok = innetgr((char *)&buf[2],
					(char *)&hname, NULL, ypdomain);
			else		/* match a host by addr */
				hostok = __icheckhost(raddr,(char *)&buf[1],
						      af, len);
			break;
		case '-':     /* reject '-' hosts and all their users */
			if (buf[1] == '@') {
				if (innetgr((char *)&buf[2],
					      (char *)&hname, NULL, ypdomain))
					return(-1);
			} else {
				if (__icheckhost(raddr,(char *)&buf[1],af,len))
					return(-1);
			}
			break;
		default:  /* if no '+' or '-', do a simple match */
			hostok = __icheckhost(raddr, buf, af, len);
			break;
		}
		switch(*user) {
		case '+':
			if (!*(user+1)) {      /* '+' matches all users */
				userok = 1;
				break;
			}
			if (*(user+1) == '@')  /* match a user by netgroup */
				userok = innetgr(user+2, NULL, ruser, ypdomain);
			else	   /* match a user by direct specification */
				userok = !(strcmp(ruser, user+1));
			break;
		case '-': 		/* if we matched a hostname, */
			if (hostok) {   /* check for user field rejections */
				if (!*(user+1))
					return(-1);
				if (*(user+1) == '@') {
					if (innetgr(user+2, NULL,
							ruser, ypdomain))
						return(-1);
				} else {
					if (!strcmp(ruser, user+1))
						return(-1);
				}
			}
			break;
		default:	/* no rejections: try to match the user */
			if (hostok)
				userok = !(strcmp(ruser,*user ? user : luser));
			break;
		}
		if (hostok && userok)
			return(0);
	}
	return (-1);
}

int
__ivaliduser(hostf, raddr, luser, ruser)
	FILE *hostf;
	u_long raddr;
	const char *luser, *ruser;
{
	return __ivaliduser_af(hostf, &raddr, luser, ruser, AF_INET, sizeof(raddr));
}

/*
 * Returns "true" if match, 0 if no match.
 */
static int
__icheckhost(raddr, lhost, af, len)
	const void *raddr;
        const char *lhost;
	int af, len;
{
	struct hostent *hp;
	char laddr[BUFSIZ]; /* xxx */
	char **pp;
	int h_error;
	int match;

	/* Try for raw ip address first. */
	if (inet_pton(af, lhost, laddr) == 1) {
		if (memcmp(raddr, laddr, len) == 0)
			return (1);
		else
			return (0);
	}

	/* Better be a hostname. */
	if ((hp = getipnodebyname(lhost, af, AI_DEFAULT, &h_error)) == NULL)
		return (0);

	/* Spin through ip addresses. */
	match = 0;
	for (pp = hp->h_addr_list; *pp; ++pp)
		if (!bcmp(raddr, *pp, len)) {
			match = 1;
			break;
		}
	
	freehostent(hp);
	return (match);
}
