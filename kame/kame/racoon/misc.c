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
 */
/* YIPS @(#)$Id: misc.c,v 1.3 1999/08/21 22:16:45 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet6/in6.h>
#include <netinet6/ipsec.h>

#include <netkey/keydb.h>
#include <netkey/key_var.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "var.h"
#include "vmbuf.h"
#include "misc.h"
#include "debug.h"
#include "isakmp.h"
#include "schedule.h"
#include "handler.h"

char _addr1_[BUFADDRSIZE], _addr2_[BUFADDRSIZE]; /* for message */

static char *timetostr __P((time_t));

int
plog0(const char *fmt, ...)
{
	va_list ap;

	YIPSDEBUG(DEBUG_DATE, printf("%s: ", timetostr(time(0))));

	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);

	return(0);
}

int
plog(const char *func, const char *fmt, ...)
{
	va_list ap;

	YIPSDEBUG(DEBUG_DATE, printf("%s: ", timetostr(time(0))));
	YIPSDEBUG(DEBUG_DEBUG, printf("%s: ", func));

	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);

	return(0);
}

int
plog2(struct sockaddr *addr, const char *func, const char *fmt, ...)
{
	va_list ap;

	YIPSDEBUG(DEBUG_DATE, printf("%s: ", timetostr(time(0))));
	YIPSDEBUG(DEBUG_DEBUG, printf("%s: ", func));
	YIPSDEBUG(DEBUG_ADDR,
		if (addr != 0) {
			GETNAMEINFO(addr, _addr1_, _addr2_);
		        printf("[%s] ", _addr1_);
		});

	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);

	return(0);
}

static char *
timetostr(t)
	time_t t;
{
	static char buf[20];
	struct tm *tm;

	tm = localtime(&t);
	snprintf(buf, sizeof(buf), "%02d-%02d-%02d %02d:%02d:%02d",
	    tm->tm_year, tm->tm_mon+1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);

	return(buf);
}

int
pdump(buf0, len, mode)
	void *buf0;
	int len;
	int mode;
{
	caddr_t buf = (caddr_t)buf0;
	int i;

	for (i = 0; i < len; i++) {
		if (mode == YDUMP_BIN) {
			printf("%c", (unsigned char)buf[i]);
		} else { /* HEX */
			if (i != 0 && i % 32 == 0) printf("\n");
			if (i % 4 == 0) printf(" ");
			printf("%02x", (unsigned char)buf[i]);
		}
	}

	printf("\n");
	return 0;
}

/*
 * must free buffer allocated later.
 */
u_char *
mem2str(buf, mlen)
	const u_char *buf;
	int mlen;
{
	u_char *new;
	u_int len = (mlen * 2) + mlen / 8 + 10;
	u_int i, j;

	if ((new = malloc(len)) == 0) return(0);

	for (i = 0, j = 0; i < mlen; i++) {
		snprintf(&new[j], len - j, "%02x", buf[i]);
		j += 2;
		if (i % 8 == 7) {
			new[j++] = ' ';
			new[j] = '\0';
		}
	}
	new[j] = '\0';

	return(new);
}

char *
strtob(str, base, len)
	char *str;
	int base;
	size_t *len;
{
	int f, i;
	char *dst;
	u_char *rp;
	char *p, b[3], *bp;

	for (i = 0, p = str; *p != '\0'; p++) {
		if ( (*p >= '0' && *p <= '9')
		  || (*p >= 'a' && *p <= 'f')
		  || (*p >= 'A' && *p <= 'F')) {
			i++;
		} 
	}
	i = i/2;
	if (i == 0) return(0);

	if ((dst = malloc(i)) == 0) {
		return(0);
	}

	i = 0;
	f = 0;
	for (rp = dst, p = str; *p != '\0'; p++) {
		if ( (*p >= '0' && *p <= '9')
		  || (*p >= 'a' && *p <= 'f')
		  || (*p >= 'A' && *p <= 'F')) {
			if (!f) {
				b[0] = *p;
				f = 1;
			} else {
				b[1] = *p;
				b[2] = '\0';
				*rp++ = (char)strtol(b, &bp, base);
				i++;
				f = 0;
			}
		} 
	}

	*len = i;

	return(dst);
}

/*
 * compare two sockaddr without port number.
 * OUT:	0: equal.
 *	1: not equal.
 */
int
saddrcmp_woport(addr1, addr2)
	struct sockaddr *addr1;
	struct sockaddr *addr2;
{
	if (addr1 == 0 && addr2 == 0)
		return 0;
	if (addr1 == 0 || addr2 == 0)
		return 1;

	if (addr1->sa_len != addr2->sa_len
	 || addr1->sa_family != addr2->sa_family)
		return 1;

	if (memcmp(_INADDRBYSA(addr1), _INADDRBYSA(addr2),
		_INALENBYAF(addr2->sa_family)) != 0)
		return 1;

	return 0;
}

/*
 * compare two sockaddr with port.
 * OUT:	0: equal.
 *	1: not equal.
 */
int
saddrcmp(addr1, addr2)
	struct sockaddr *addr1;
	struct sockaddr *addr2;
{
	if (addr1 == 0 && addr2 == 0)
		return 0;
	if (addr1 == 0 || addr2 == 0)
		return 1;

	if (addr1->sa_len != addr2->sa_len
	 || addr1->sa_family != addr2->sa_family)
		return 1;

	if (_INPORTBYSA(addr1) != _INPORTBYSA(addr2))
		return 1;

	if (memcmp(_INADDRBYSA(addr1), _INADDRBYSA(addr2),
		_INALENBYAF(addr2->sa_family)) != 0)
		return 1;

	return 0;
}

/*
 * exchange hex string to value.
 */
caddr_t
hexstr2val(buf, len)
	caddr_t buf;
	u_int len;
{
	caddr_t res, bp;
	caddr_t p = buf;

	if ((res = malloc(len)) == 0)
		return(0);
	memset(res, 0, len);

	bp = res;
	while (*p) {
		*bp = (ATOX(p[0]) << 4) | ATOX(p[1]);
		p += 2, bp++;
	}

	return(res);
}

/*
 * copy the buffer into new allocated buffer.
 * NOTE: may be used by GET_NEWBUF();
 */
void *
get_newbuf(src, len)
	void *src;
	u_int len;
{
	caddr_t new;

	if ((new = CALLOC(len, caddr_t)) == NULL) {
		printf("get_newbuf: No more memory.\n");
		return NULL;
	}
	memcpy(new, src, len);

	return new;
}

/* get local address against the destination. */
struct sockaddr *
get_localaddr(remote)
	struct sockaddr *remote;
{
	struct sockaddr *local;
	int local_len = sizeof(struct sockaddr_storage);
	int s;	/* for dummy connection */

	/* allocate buffer */
	if ((local = CALLOC(local_len, struct sockaddr *)) == NULL) {
		plog(LOCATION,
			"calloc (%s)\n", strerror(errno)); 
		goto err;
	}
	
	/* get real interface received packet */
	if ((s = socket(remote->sa_family, SOCK_DGRAM, 0)) < 0) {
		plog(LOCATION,
			"socket (%s)\n", strerror(errno));
		goto err;
	}
	
	if (connect(s, remote, remote->sa_len) < 0) {
		plog(LOCATION,
			"connect (%s)\n", strerror(errno));
		close(s);
		goto err;
	}

	if (getsockname(s, local, &local_len) < 0) {
		plog(LOCATION,
			"getsockname (%s)\n", strerror(errno));
		close(s);
		return NULL;
	}

	close(s);
	return local;

    err:
	if (local != NULL)
		free(local);
	return NULL;
}


/*
 * Receive packet, with src/dst information.  It is assumed that necessary
 * setsockopt() have already performed on socket.
 */
int
recvfromto(s, buf, buflen, flags, from, fromlen, to, tolen)
	int s;
	void *buf;
	size_t buflen;
	int flags;
	struct sockaddr *from;
	int *fromlen;
	struct sockaddr *to;
	int *tolen;
{
	int otolen;
	int len;
	struct sockaddr_storage ss;
	struct msghdr m;
	struct cmsghdr *cm;
	struct iovec iov[2];
	u_char cmsgbuf[256];
#if defined(INET6) && defined(ADVAPI)
	struct in6_pktinfo *pi;
#endif /*ADVAPI*/
	struct sockaddr_in *sin;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif

	len = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &len) < 0) {
		plog(LOCATION, "getsockname (%s)\n", strerror(errno));
		return -1;
	}

	m.msg_name = (caddr_t)from;
	m.msg_namelen = *fromlen;
	iov[0].iov_base = (caddr_t)buf;
	iov[0].iov_len = buflen;
	m.msg_iov = iov;
	m.msg_iovlen = 1;
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	cm = (struct cmsghdr *)cmsgbuf;
	m.msg_control = (caddr_t)cm;
	m.msg_controllen = sizeof(cmsgbuf);
	if ((len = recvmsg(s, &m, flags)) < 0) {
		plog(LOCATION, "recvmsg (%s)\n", strerror(errno));
		return -1;
	}
	*fromlen = m.msg_namelen;

	otolen = *tolen;
	*tolen = 0;
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&m);
	     m.msg_controllen != 0 && cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&m, cm)) {
#if 0
		plog(LOCATION, "cmsg %d %d\n", cm->cmsg_level, cm->cmsg_type);)
#endif
#if defined(INET6) && defined(ADVAPI)
		if (ss.ss_family == AF_INET6
		 && cm->cmsg_level == IPPROTO_IPV6
		 && cm->cmsg_type == IPV6_PKTINFO
		 && otolen >= sizeof(*sin6)) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			*tolen = sizeof(*sin6);
			sin6 = (struct sockaddr_in6 *)to;
			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			memcpy(&sin6->sin6_addr, &pi->ipi6_addr,
				sizeof(sin6->sin6_addr));
			/* XXX other cases, such as site-local? */
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				sin6->sin6_scope_id = pi->ipi6_ifindex;
			else
				sin6->sin6_scope_id = 0;
			sin6->sin6_port =
				((struct sockaddr_in6 *)&ss)->sin6_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
#endif
#ifdef INET6
		if (ss.ss_family == AF_INET6
		      && cm->cmsg_level == IPPROTO_IPV6
		      && cm->cmsg_type == IPV6_RECVDSTADDR
		      && otolen >= sizeof(*sin6)) {
			*tolen = sizeof(*sin6);
			sin6 = (struct sockaddr_in6 *)to;
			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			memcpy(&sin6->sin6_addr, CMSG_DATA(cm),
				sizeof(sin6->sin6_addr));
			sin6->sin6_port =
				((struct sockaddr_in6 *)&ss)->sin6_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
#endif
		if (ss.ss_family == AF_INET
		 && cm->cmsg_level == IPPROTO_IP
		 && cm->cmsg_type == IP_RECVDSTADDR
		 && otolen >= sizeof(*sin)) {
			*tolen = sizeof(*sin);
			sin = (struct sockaddr_in *)to;
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			memcpy(&sin->sin_addr, CMSG_DATA(cm),
				sizeof(sin->sin_addr));
			sin->sin_port = ((struct sockaddr_in *)&ss)->sin_port;
			otolen = -1;	/* "to" already set */
			continue;
		}
	}

	YIPSDEBUG(DEBUG_NET,
		GETNAMEINFO((struct sockaddr *)to, _addr1_, _addr2_);
		plog(LOCATION, "to %s %s\n", _addr1_, _addr2_);
		GETNAMEINFO((struct sockaddr *)from, _addr1_, _addr2_);
		plog(LOCATION, "from %s %s\n", _addr1_, _addr2_);)

	return len;
}

/* send packet, with fixing src/dst address pair. */
int
sendfromto(s, buf, buflen, src, dst)
	int s;
	const void *buf;
	size_t buflen;
	struct sockaddr *src;
	struct sockaddr *dst;
{
	struct sockaddr_storage ss;
	int len;

	if (src->sa_family != dst->sa_family) {
		plog(LOCATION, "address family mismatch\n");
		return -1;
	}

	len = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &len) < 0) {
		plog(LOCATION, "getsockname (%s)\n", strerror(errno));
		return -1;
	}

	YIPSDEBUG(DEBUG_NET,
		GETNAMEINFO((struct sockaddr *)&ss, _addr1_, _addr2_);
		plog(LOCATION, "sockname %s %s\n", _addr1_, _addr2_);
		GETNAMEINFO((struct sockaddr *)src, _addr1_, _addr2_);
		plog(LOCATION, "src %s %s\n", _addr1_, _addr2_);
		GETNAMEINFO((struct sockaddr *)dst, _addr1_, _addr2_);
		plog(LOCATION, "dst %s %s\n", _addr1_, _addr2_);)

	if (src->sa_family != ss.ss_family) {
		plog(LOCATION, "address family mismatch\n");
		return -1;
	}

	switch (src->sa_family) {
#if defined(INET6) && defined(ADVAPI)
	case AF_INET6:
	    {
		struct msghdr m;
		struct cmsghdr *cm;
		struct iovec iov[2];
		u_char cmsgbuf[256];
		struct in6_pktinfo *pi;
		int ifindex;
		struct sockaddr_in6 src6, dst6;

		memcpy(&src6, src, sizeof(src6));
		memcpy(&dst6, dst, sizeof(dst6));

		/* XXX take care of other cases, such as site-local */
		ifindex = 0;
		if (IN6_IS_ADDR_LINKLOCAL(&src6.sin6_addr)
		 || IN6_IS_ADDR_MULTICAST(&src6.sin6_addr)) {
			ifindex = src6.sin6_scope_id;	/*???*/
		}

		/* XXX some sanity check on dst6.sin6_scope_id */

		/* flowinfo for IKE?  mmm, maybe useful but for now make it 0 */
		src6.sin6_flowinfo = dst6.sin6_flowinfo = 0;

		m.msg_name = (caddr_t)&dst6;
		m.msg_namelen = sizeof(dst6);
		iov[0].iov_base = (char *)buf;
		iov[0].iov_len = buflen;
		m.msg_iov = iov;
		m.msg_iovlen = 1;

		memset(cmsgbuf, 0, sizeof(cmsgbuf));
		cm = (struct cmsghdr *)cmsgbuf;
		m.msg_control = (caddr_t)cm;
		m.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

		cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_PKTINFO;
		pi = (struct in6_pktinfo *)CMSG_DATA(cm);
		memcpy(&pi->ipi6_addr, &src6.sin6_addr, sizeof(src6.sin6_addr));
		pi->ipi6_ifindex = ifindex;

		YIPSDEBUG(DEBUG_NET,
			GETNAMEINFO((struct sockaddr *)&src6, _addr1_, _addr2_);
			plog(LOCATION, "src6 %s %s %d\n", _addr1_, _addr2_,
				src6.sin6_scope_id);
			GETNAMEINFO((struct sockaddr *)&dst6, _addr1_, _addr2_);
			plog(LOCATION, "dst6 %s %s %d\n", _addr1_, _addr2_,
				dst6.sin6_scope_id);)

		len = sendmsg(s, &m, 0 /*MSG_DONTROUTE*/);
		if (len < 0) {
			plog(LOCATION, "sendmsg (%s)\n", strerror(errno));
			return -1;
		}
		return len;
	    }
#endif
	default:
	    {
		int needclose = 0;
		int sendsock;

		if (ss.ss_family == src->sa_family && memcmp(&ss, src, src->sa_len) == 0) {
			sendsock = s;
			needclose = 0;
		} else {
			int yes = 1;
			/*
			 * Use newly opened socket for sending packets.
			 * NOTE: this is unsafe, because if the peer is quick enough
			 * the packet from the peer may be queued into sendsock.
			 * Better approach is to prepare bind'ed udp sockets for
			 * each of the interface addresses.
			 */
			sendsock = socket(src->sa_family, SOCK_DGRAM, 0);
			if (sendsock < 0) {
				plog(LOCATION, "socket (%s)\n", strerror(errno));
				return -1;
			}
			if (setsockopt(sendsock, SOL_SOCKET, SO_REUSEPORT,
				       (void *)&yes, sizeof(yes)) < 0) {
				plog(LOCATION, "setsockopt (%s)\n", strerror(errno));
				return -1;
			}

			if (setsockopt_bypass(sendsock, src->sa_family) < 0)
				return -1;

			if (bind(sendsock, (struct sockaddr *)src, src->sa_len) < 0) {
				plog(LOCATION, "bind 1 (%s)\n", strerror(errno));
				return -1;
			}
			needclose = 1;
		}

		len = sendto(sendsock, buf, buflen, 0, dst, dst->sa_len);
		if (len < 0) {
			plog(LOCATION, "sendto (%s)\n", strerror(errno));
			return len;
		}

		if (needclose)
			close(sendsock);

		return len;
	    }
	}
}

int
setsockopt_bypass(so, family)
	int so, family;
{
	int level, optname;
	char buf[16];
	int len;

	switch (family) {
	case AF_INET:
		level = IPPROTO_IP;
		optname = IP_IPSEC_POLICY;
		break;
#ifdef INET6
	case AF_INET6:
		level = IPPROTO_IPV6;
		optname = IPV6_IPSEC_POLICY;
		break;
#endif
	default:
		plog(LOCATION,
			"unsupported address family %d\n", family);
		return -1;
	}

	if ((len = ipsec_set_policy(buf, sizeof(buf), "bypass")) < 0) {
		plog(LOCATION, "ipsec_set_policy (%s)\n",
			ipsec_strerror());
		return -1;
	}
	if (setsockopt(so, level, optname, buf, len) < 0) {
		plog(LOCATION, "setsockopt (%s)\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

const char *
debug_location(file, line, func)
	char *file;
	int line;
	char *func;
{
	static char buf[1024];
	char *p;

	/* truncate pathname */
	p = strrchr(file, '/');
	if (p)
		p++;
	else
		p = file;

	if (func)
		snprintf(buf, sizeof(buf), "%s:%d:%s()", p, line, func);
	else
		snprintf(buf, sizeof(buf), "%s:%d", p, line);
	return buf;
}
