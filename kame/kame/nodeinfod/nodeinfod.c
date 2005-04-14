/*	$KAME: nodeinfod.c,v 1.31 2005/04/14 06:22:34 suz Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#ifdef HAVE_MD5_H
#include <md5.h>
#endif
#ifdef HAVE_OPENSSL_MD5_H
#include <openssl/md5.h>
#endif
#include <ctype.h>

int main __P((int, char **));
void usage __P((void));
void sockinit __P((void));
int joingroups __P((const char *));
const char *nigroup __P((const char *));
void mainloop __P((void));
ssize_t response __P((struct sockaddr*, socklen_t, char *, ssize_t));
static int ni6_input_code0 __P((struct sockaddr *, socklen_t, const char *,
	ssize_t));
static int ni6_input __P((struct sockaddr *, socklen_t, const char *, ssize_t));
static ssize_t ni6_nametodns __P((const char *, char *, char *, ssize_t, int));
static int ni6_dnsmatch __P((const char *, int, const char *, int));
static int findsubjif __P((char *, size_t, struct sockaddr *, socklen_t));
static ssize_t ni6_addrs __P((struct icmp6_nodeinfo *, char *, char *,
	ssize_t, struct sockaddr *, socklen_t, const char *, int));
static int ismyaddr __P((struct sockaddr *, socklen_t));
static int getflags6 __P((const char *, const struct sockaddr *, socklen_t));
static time_t getlifetime __P((const char *, const struct sockaddr *, socklen_t));
static void setkernmode __P((int));

int s;
int mode = 7;	/* reply to all message types */
char hostname[MAXHOSTNAMELEN];
int foreground = 0;
int debug = 0;

int (*func[256]) __P((struct sockaddr *, socklen_t, const char *, ssize_t));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	char dnsbuf[BUFSIZ];

	gethostname(hostname, sizeof(hostname));

	while ((ch = getopt(argc, argv, "dfn:")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'f':
			foreground++;
			break;
		case 'n':
			strlcpy(hostname, optarg, sizeof(hostname));
			break;
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		usage();
		exit(1);
	}

	if (ni6_nametodns(hostname, dnsbuf, dnsbuf, sizeof(dnsbuf), 0) < 0)
		errx(1, "invalid hostname");

	memset(func, 0, sizeof(func));

	/* XXX todo: split funcs based on query type */
	func[NI_QTYPE_NOOP] = ni6_input_code0;
	func[NI_QTYPE_SUPTYPES] = ni6_input;
	func[NI_QTYPE_FQDN] = ni6_input;
	func[NI_QTYPE_DNSNAME] = ni6_input;
	func[NI_QTYPE_NODEADDR] = ni6_input;
	func[NI_QTYPE_IPV4ADDR] = ni6_input;

	if (!foreground)
		daemon(0, 0);

	sockinit();
	joingroups(hostname);
	setkernmode(0);
	mainloop();
	exit(0);
}

void
usage()
{

	fprintf(stderr, "usage: nodeinfod [-df] [-n name]\n");
}

void
sockinit()
{
	struct addrinfo hints, *res;
	int error;

	if (debug)
		warnx("sockinit");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo("::", NULL, &hints, &res);
	if (error) {
		errx(1, "%s", gai_strerror(error));
		/* NOTREACHED */
	}
	if (res->ai_next) {
		errx(1, "unexpected result from getaddrinfo");
		/* NOTREACHED */
	}

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0) {
		err(1, "socket");
		/* NOTREACHED */
	}
	if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
		err(1, "bind");
		/* NOTREACHED */
	}

	/* XXX filter setup */

	freeaddrinfo(res);
}

int
joingroups(name)
	const char *name;
{
	struct addrinfo hints, *res;
	int error;
	struct ifaddrs *ifa, *ifap;
	unsigned int ifidx;
	struct ipv6_mreq m6;
	struct sockaddr_in6 *sin6;

	if (debug)
		warnx("joingroups");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMPV6;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(nigroup(name), NULL, &hints, &res);
	if (error) {
		errx(1, "%s", gai_strerror(error));
		/* NOTREACHED */
	}
	if (res->ai_next) {
		errx(1, "unexpected result from getaddrinfo");
		/* NOTREACHED */
	}

	sin6 = (struct sockaddr_in6 *)res->ai_addr;
	memset(&m6, 0, sizeof(m6));
	memcpy(&m6.ipv6mr_multiaddr, &sin6->sin6_addr,
	    sizeof(m6.ipv6mr_multiaddr));

	if (getifaddrs(&ifap) < 0) {
		err(1, "getifaddrs");
		/* NOTREACHED */
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		/*
		 * get a list of IPv6-capable interfaces.  we assume that
		 * every interface has at least a link-local address associated
		 * with it.
		 */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			continue;

		ifidx = if_nametoindex(ifa->ifa_name);
		if (!ifidx)
			continue;

		m6.ipv6mr_interface = ifidx;

		if (debug)
			warnx("joingroups: %s", ifa->ifa_name);

		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &m6,
		    sizeof(m6)) < 0) {
			err(1, "setsockopt(IPV6_JOIN_GROUP)");
			/* NOTREACHED */
		}
	}

	freeifaddrs(ifap);
	freeaddrinfo(res);

	return 0;
}

#ifdef HAVE_OPENSSL_MD5_H
#define MD5Init	MD5_Init
#define MD5Update	MD5_Update
#define MD5Final	MD5_Final
#endif

const char *
nigroup(name)
	const char *name;
{
	const char *p;
	unsigned char *q;
	MD5_CTX ctxt;
	u_int8_t digest[16];
	u_int8_t c;
	size_t l;
	static char hbuf[NI_MAXHOST];
	struct in6_addr in6;

	if (debug)
		warnx("nigroup");

	p = strchr(name, '.');
	if (!p)
		p = name + strlen(name);
	l = p - name;
	if (l > 63 || l > sizeof(hbuf) - 1)
		return NULL;	/*label too long*/
	strncpy(hbuf, name, l);
	hbuf[(int)l] = '\0';

	for (q = hbuf; *q; q++) {
		if (isupper(*q))
			*q = tolower(*q);
	}

	/* generate 4 bytes of pseudo-random value. */
	bzero(&ctxt, sizeof(ctxt));
	MD5Init(&ctxt);
	c = l & 0xff;
	MD5Update(&ctxt, &c, sizeof(c));
	MD5Update(&ctxt, hbuf, l);
	MD5Final(digest, &ctxt);

	if (inet_pton(AF_INET6, "ff02::2:0000:0000", &in6) != 1)
		return NULL;	/*XXX*/
	bcopy(digest, &in6.s6_addr[12], 4);

	if (inet_ntop(AF_INET6, &in6, hbuf, sizeof(hbuf)) == NULL)
		return NULL;

	return hbuf;
}

void
mainloop()
{
	fd_set fds;
	int n;
	char buf[BUFSIZ];
	ssize_t l;
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	socklen_t salen = sizeof(ss);
	struct icmp6_hdr *icmp6;
	struct icmp6_nodeinfo *ni6;
	u_int16_t qtype;

	if (debug)
		warnx("mainloop");

	if (s >= FD_SETSIZE) {
		errx(1, "socket exceeds FD_SETSIZE");
		/* NOTREACHED */
	}

	while (1) {
		FD_ZERO(&fds);
		FD_SET(s, &fds);
		n = select(s + 1, &fds, NULL, NULL, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else {
				err(1, "select");
				/* NOTREACHED */
			}
		} else if (n == 0) {
			errx(1, "should not reach here");
			/* NOTREACHED */
		}

		salen = sizeof(ss);
		l = recvfrom(s, buf, sizeof(buf), 0, sa, &salen);
		if (l < sizeof(*icmp6)) {
			warnx("packet too short");
			continue;
		}
		icmp6 = (struct icmp6_hdr *)buf;

		if (debug)
			warnx("incoming message, %u/%u", icmp6->icmp6_type,
			    icmp6->icmp6_code);

		switch (icmp6->icmp6_type) {
		case ICMP6_WRUREQUEST:	/* ICMP6_FQDN_QUERY */
			break;
		default:
			continue;
		}

		ni6 = (struct icmp6_nodeinfo *)buf;
		if (l < sizeof(*ni6))
			qtype = 0;
		else
			qtype = ntohs(ni6->ni_qtype);

		/* pass 2nd arg just for linux friendliness... */
		if (qtype < sizeof(func) / sizeof(func[0]) && func[qtype])
			(void) (*func[qtype])(sa, salen, buf, l);
	}
}

ssize_t
response(sa, salen, buf, l)
	struct sockaddr *sa;
	socklen_t salen;
	char *buf;
	ssize_t l;
{

	return sendto(s, buf, l, 0, sa, salen);
}

static int
ni6_input_code0(from, fromlen, buf, l)
	struct sockaddr *from;
	socklen_t fromlen;
	const char *buf;
	ssize_t l;
{
	struct icmp6_hdr *icmp6;
	enum { WRU, FQDN } wrumode;
	char reply[BUFSIZ];
	char *p;

	if (debug)
		warnx("ni6_input_code0");

	if (l == sizeof(struct icmp6_hdr) + 4)
		wrumode = WRU;
	else if (l >= sizeof(struct icmp6_nodeinfo))
		wrumode = FQDN;
	else
		return -1;	/* truncated */

	if (wrumode == WRU) {
		if (l > sizeof(reply))
			return -1;
		memcpy(reply, buf, l);
		icmp6 = (struct icmp6_hdr *)reply;
		memset(icmp6, 0, sizeof(*icmp6));
		icmp6->icmp6_type = ICMP6_WRUREPLY;
		memset(icmp6 + 1, 0, sizeof(u_int32_t));	/* TTL */
		p = reply + sizeof(*icmp6) + sizeof(u_int32_t);
		memcpy(p, hostname, strlen(hostname));
		response(from, fromlen, reply, strlen(hostname) + p - reply);
		return 0;
	} else
		return ni6_input(from, fromlen, buf, l);
}

/*
 * Process a Node Information Query packet, based on
 * draft-ietf-ipngwg-icmp-name-lookups-07.
 * 
 * Spec incompatibilities:
 * - IPv6 Subject address handling
 * - IPv4 Subject address handling support missing
 * - Proxy reply (answer even if it's not for me)
 * - joins NI group address at in6_ifattach() time only, does not cope
 *   with hostname changes by sethostname(3)
 */
static int
ni6_input(from, fromlen, buf, l)
	struct sockaddr *from;
	socklen_t fromlen;
	const char *buf;
	ssize_t l;
{
	const struct icmp6_nodeinfo *ni6;
	struct icmp6_nodeinfo *nni6;
	u_int16_t qtype;
	int subjlen;
	char replybuf[BUFSIZ];
	int replylen = sizeof(struct icmp6_nodeinfo);
	struct ni_reply_fqdn *fqdn;
	struct sockaddr_in6 sin6; /* double meaning; ip6_dst and subjectaddr */
	struct sockaddr_in sin;
	int oldfqdn = 0;	/* if 1, return pascal string (03 draft) */
	const char *subj = NULL;
	ssize_t tlen;
	char ifnamebuf[IF_NAMESIZE];
	const char *ifname = NULL;

	if (debug)
		warnx("ni6_input");

	if (sizeof(*ni6) > l)
		return -1;
	ni6 = (const struct icmp6_nodeinfo *)buf;

#if 0
	/*
	 * Validate IPv6 destination address.
	 *
	 * The Responder must discard the Query without further processing
	 * unless it is one of the Responder's unicast or anycast addresses, or
	 * a link-local scope multicast address which the Responder has joined.
	 * [icmp-name-lookups-07, Section 4.]
	 */
	bzero(&sin6, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	bcopy(&ip6->ip6_dst, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
	/* XXX scopeid */
	if ((ia6 = (struct in6_ifaddr *)ifa_ifwithaddr((struct sockaddr *)&sin6)) != NULL) {
		/* unicast/anycast, fine */
		if ((ia6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
		    (icmp6_nodeinfo & 4) == 0) {
			nd6log((LOG_DEBUG, "ni6_input: ignore node info to "
				"a temporary address in %s:%d",
			       __FILE__, __LINE__));
			goto bad;
		}
	} else if (IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr))
		; /* link-local multicast, fine */
	else
		goto bad;
#endif

	/* validate query Subject field. */
	qtype = ntohs(ni6->ni_qtype);

	subjlen = l - sizeof(struct icmp6_nodeinfo);
	switch (qtype) {
	case NI_QTYPE_NOOP:
	case NI_QTYPE_SUPTYPES:
		/* 07 draft */
		if (ni6->ni_code == ICMP6_NI_SUBJ_FQDN && subjlen == 0)
			break;
		/* FALLTHROUGH */
	case NI_QTYPE_FQDN:
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
#if ICMP6_NI_SUBJ_IPV6 != 0
		case 0:
#endif
			/*
			 * backward compatibility - try to accept 03 draft
			 * format, where no Subject is present.
			 */
			if (qtype == NI_QTYPE_FQDN && ni6->ni_code == 0 &&
			    subjlen == 0) {
				oldfqdn++;
				break;
			}
#if ICMP6_NI_SUBJ_IPV6 != 0
			if (ni6->ni_code != ICMP6_NI_SUBJ_IPV6)
				goto bad;
#endif

			if (subjlen != sizeof(sin6.sin6_addr))
				goto bad;

			/*
			 * Validate Subject address.
			 *
			 * Not sure what exactly "address belongs to the node"
			 * means in the spec, is it just unicast, or what?
			 *
			 * At this moment we consider Subject address as
			 * "belong to the node" if the Subject address equals
			 * to the IPv6 destination address; validation for
			 * IPv6 destination address should have done enough
			 * check for us.
			 *
			 * We do not do proxy at this moment.
			 */
			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_family = AF_INET6;
			sin6.sin6_len = sizeof(struct sockaddr_in6);
			memcpy(&sin6.sin6_addr, ni6 + 1,
			    sizeof(sin6.sin6_addr));
			if (ismyaddr((struct sockaddr *)&sin6, sizeof(sin6)))
				;
			else if (IN6_IS_ADDR_MULTICAST(&sin6.sin6_addr)) {
				/*
				 * let us permit multicasts for now.
				 */
			} else {
				/*
				 * proxy case - if we are going to do something
				 * about this case, be really careful about
				 * scope issues.
				 */
				goto bad;
			}

			if (findsubjif(ifnamebuf, sizeof(ifnamebuf),
			    (struct sockaddr *)&sin6, sin6.sin6_len) == 0)
				ifname = ifnamebuf;
			else
				ifname = NULL;
			break;

		case ICMP6_NI_SUBJ_FQDN:
			/*
			 * Validate Subject name with gethostname(3).
			 *
			 * The behavior may need some debate, since:
			 * - we are not sure if the node has FQDN as
			 *   hostname (returned by gethostname(3)).
			 * - the code does wildcard match for truncated names.
			 *   however, we are not sure if we want to perform
			 *   wildcard match, if gethostname(3) side has
			 *   truncated hostname.
			 */
			tlen = ni6_nametodns(hostname, replybuf, replybuf,
			    sizeof(replybuf), 0);
			if (tlen < 0)
				goto bad;
			subj = (const char *)(ni6 + 1);
			if (!ni6_dnsmatch(subj, subjlen, replybuf, tlen))
				goto bad;
			break;

		case ICMP6_NI_SUBJ_IPV4:
			if (subjlen != sizeof(sin.sin_addr))
				goto bad;

			/*
			 * Validate Subject address.
			 */
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof(struct sockaddr_in);
			memcpy(&sin.sin_addr, ni6 + 1, sizeof(sin.sin_addr));
			if (ismyaddr((struct sockaddr *)&sin, sizeof(sin)))
				;
			else {
				/*
				 * proxy case
				 */
				goto bad;
			}

			if (findsubjif(ifnamebuf, sizeof(ifnamebuf),
			    (struct sockaddr *)&sin, sin.sin_len) == 0)
				ifname = ifnamebuf;
			else
				ifname = NULL;
			break;

		default:
			goto bad;
		}
		break;
	}

	/* refuse based on configuration.  XXX ICMP6_NI_REFUSED? */
	switch (qtype) {
	case NI_QTYPE_FQDN:
		if ((mode & 1) == 0)
			goto bad;
		break;
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		if ((mode & 2) == 0)
			goto bad;
		break;
	}

	/* guess reply length */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		break;		/* no reply data */
	case NI_QTYPE_SUPTYPES:
		replylen += sizeof(u_int32_t);
		break;
	case NI_QTYPE_FQDN:
		/* XXX will adjust later */
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		break;
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
		if (l > sizeof(replybuf))
			goto bad;
		memcpy(replybuf, buf, l);
		nni6 = (struct icmp6_nodeinfo *)replybuf;
		replylen = ni6_addrs(nni6, NULL, NULL, 0, from, fromlen, ifname,
		    (qtype == NI_QTYPE_NODEADDR) ? AF_INET6 : AF_INET);
		/* XXX: will truncate pkt later */
		if (replylen > sizeof(replybuf))
			replylen = sizeof(replybuf);
		break;
	default:
		/*
		 * XXX: specwise, we should return a reply with the ICMP6 code
		 * `unknown Qtype' in this case.  However we regard the case
		 * as an FQDN query for backward compatibility.
		 * Older versions set a random value to this field,
		 * so it rarely varies in the defined qtypes.
		 * But the mechanism is not reliable...
		 * maybe we should obsolete older versions.
		 *
		 * "Unknown Qtype" response may not be the best idea...
		 */
		qtype = NI_QTYPE_FQDN;
		replylen += offsetof(struct ni_reply_fqdn, ni_fqdn_namelen);
		oldfqdn++;
		break;
	}

	/* copy IPv6 + Node Information base headers */
	nni6 = (struct icmp6_nodeinfo *)replybuf;
	memcpy(nni6, ni6, sizeof(*nni6));

	/* qtype dependent procedure */
	switch (qtype) {
	case NI_QTYPE_NOOP:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = 0;
		break;
	case NI_QTYPE_SUPTYPES:
	{
		u_int32_t v;
		nni6->ni_code = ICMP6_NI_SUCCESS;
		nni6->ni_flags = htons(0x0000);	/* raw bitmap */
		/* supports NOOP, SUPTYPES, FQDN, NODEADDR and IPV4ADDR */
		v = (u_int32_t)htonl(0x0000001f);
		memcpy(nni6 + 1, &v, sizeof(u_int32_t));
		break;
	}
	case NI_QTYPE_FQDN:
		nni6->ni_code = ICMP6_NI_SUCCESS;
		fqdn = (struct ni_reply_fqdn *)(nni6 + 1);
		nni6->ni_flags = 0; /* XXX: meaningless TTL */
		fqdn->ni_fqdn_ttl = 0;	/* ditto. */
		/*
		 * XXX do we really have FQDN in variable "hostname"?
		 */
		tlen = ni6_nametodns(hostname, &fqdn->ni_fqdn_namelen,
		    replybuf, sizeof(replybuf), oldfqdn);
		if (tlen < 0)
			goto bad;
		replylen += tlen;
		break;
	case NI_QTYPE_NODEADDR:
	case NI_QTYPE_IPV4ADDR:
	{
		int copied;

		nni6->ni_code = ICMP6_NI_SUCCESS;
		replylen = sizeof(struct icmp6_nodeinfo);
		copied = ni6_addrs(nni6, (char *)(nni6 + 1), replybuf,
		    sizeof(replybuf), from, fromlen, ifname,
		    (qtype == NI_QTYPE_NODEADDR) ? AF_INET6 : AF_INET);
		replylen = sizeof(struct icmp6_nodeinfo) + copied;
		break;
	}
	default:
		break;		/* XXX impossible! */
	}

	nni6->ni_type = ICMP6_NI_REPLY;
	response(from, fromlen, replybuf, replylen);
	return 0;

  bad:
	return -1;
}

/*
 * make a DNS-encoded string.  no compression support.
 *
 * XXX names with less than 2 dots (like "foo" or "foo.section") will be
 * treated as truncated name (two \0 at the end).  this is a wild guess.
 */
static ssize_t
ni6_nametodns(name, cp0, buf, buflen, old)
	const char *name;
	char *cp0;
	char *buf;
	ssize_t buflen;
	int old;	/* return pascal string if non-zero */
{
	char *cp, *ep;
	const char *p, *q;
	int i, nterm;
	int namelen = strlen(name);

	if (debug)
		warnx("ni6_nametodns");

	if (old) {
		i = strlen(name);
		cp = cp0;
		cp[0] = i;
		memcpy(cp + 1, name, i);
		return 1 + i;
	} else {
		cp = cp0;
		ep = buf + buflen;

		/* if not certain about my name, return empty buffer */
		if (namelen == 0)
			return 0;

		/*
		 * guess if it looks like shortened hostname, or FQDN.
		 * shortened hostname needs two trailing "\0".
		 */
		i = 0;
		for (p = name; p < name + namelen; p++) {
			if (*p && *p == '.')
				i++;
		}
		if (i < 2)
			nterm = 2;
		else
			nterm = 1;

		p = name;
		while (cp < ep && p < name + namelen) {
			i = 0;
			for (q = p; q < name + namelen && *q && *q != '.'; q++)
				i++;
			/* result does not fit into buf */
			if (cp + i + 1 >= ep)
				goto fail;
			/*
			 * DNS label length restriction, RFC1035 page 8.
			 * "i == 0" case is included here to avoid returning
			 * 0-length label on "foo..bar".
			 */
			if (i <= 0 || i >= 64)
				goto fail;
			*cp++ = i;
			if (!isalpha(p[0]) || !isalnum(p[i - 1]))
				goto fail;
			while (i > 0) {
				if (!isalnum(*p) && *p != '-')
					goto fail;
				if (isupper(*p))
					*cp++ = tolower(*p++);
				else
					*cp++ = *p++;
				i--;
			}
			p = q;
			if (p < name + namelen && *p == '.')
				p++;
		}
		/* termination */
		if (cp + nterm >= ep)
			goto fail;
		while (nterm-- > 0)
			*cp++ = '\0';
		return cp - cp0;
	}

	errx(1, "should not reach here");
	/*NOTREACHED*/

 fail:
	return -1;
}

/*
 * check if two DNS-encoded string matches.  takes care of truncated
 * form (with \0\0 at the end).  no compression support.
 * XXX upper/lowercase match (see RFC2065)
 */
static int
ni6_dnsmatch(a, alen, b, blen)
	const char *a;
	int alen;
	const char *b;
	int blen;
{
	const char *a0, *b0;
	int l;

	if (debug)
		warnx("ni6_dnsmatch");

	/* simplest case - need validation? */
	if (alen == blen && memcmp(a, b, alen) == 0)
		return 1;

	a0 = a;
	b0 = b;

	/* termination is mandatory */
	if (alen < 2 || blen < 2)
		return 0;
	if (a0[alen - 1] != '\0' || b0[blen - 1] != '\0')
		return 0;
	alen--;
	blen--;

	while (a - a0 < alen && b - b0 < blen) {
		if (a - a0 + 1 > alen || b - b0 + 1 > blen)
			return 0;

		if ((signed char)a[0] < 0 || (signed char)b[0] < 0)
			return 0;
		/* we don't support compression yet */
		if (a[0] >= 64 || b[0] >= 64)
			return 0;

		/* truncated case */
		if (a[0] == 0 && a - a0 == alen - 1)
			return 1;
		if (b[0] == 0 && b - b0 == blen - 1)
			return 1;
		if (a[0] == 0 || b[0] == 0)
			return 0;

		if (a[0] != b[0])
			return 0;
		l = a[0];
		if (a - a0 + 1 + l > alen || b - b0 + 1 + l > blen)
			return 0;
		if (memcmp(a + 1, b + 1, l) != 0)
			return 0;

		a += 1 + l;
		b += 1 + l;
	}

	if (a - a0 == alen && b - b0 == blen)
		return 1;
	else
		return 0;
}

static int
findsubjif(buf, buflen, sa, salen)
	char *buf;
	size_t buflen;
	struct sockaddr *sa;
	socklen_t salen;
{
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) < 0)
		return -1;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == sa->sa_family &&
		    ifa->ifa_addr->sa_len == salen &&
		    memcmp(ifa->ifa_addr, sa, salen) == 0) {
			strlcpy(buf, ifa->ifa_name, buflen);
			freeifaddrs(ifap);
			return 0;
		}
	}

	freeifaddrs(ifap);
	return -1;
}

static ssize_t
ni6_addrs(ni6, p, buf, buflen, sa, salen, ifname, af)
	struct icmp6_nodeinfo *ni6;
	char *p;
	char *buf;
	ssize_t buflen;
	struct sockaddr *sa;
	socklen_t salen;
	const char *ifname;
	int af;
{
	int addrs, copied;
	u_int16_t niflags = ni6->ni_flags;
	struct ifaddrs *ifap, *ifa;
	char *cp, *ep;
	int32_t ltime;
	struct in6_addr *in6;
	struct in_addr *in;
	int flags6;
	time_t expire;
	u_int8_t *ap;
	size_t alen;

	if (debug)
		warnx("ni6_addrs");

	cp = p;
	if (buf)
		ep = buf + buflen;
	else
		ep = NULL;

	if (getifaddrs(&ifap) < 0)
		return -1;

	if ((niflags & NI_NODEADDR_FLAG_ALL) != 0)
		ifname = NULL;
	else {
		switch (ni6->ni_code) {
		case ICMP6_NI_SUBJ_IPV6:
		case ICMP6_NI_SUBJ_IPV4:
			/* use the ifname given */
			break;
		case ICMP6_NI_SUBJ_FQDN:
			/* there's no concept of "interface" in hostname */
			ifname = NULL;
			break;
		default:
			goto fail;
		}
	}

	copied = addrs = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != af)
			continue;

		if (ifname && strcmp(ifname, ifa->ifa_name) != 0)
			continue;

		/* XXX reorder preferred/deprecated */

		/*
		 * IPv4-mapped addresses can only be returned by a
		 * Node Information proxy, since they represent
		 * addresses of IPv4-only nodes, which perforce do
		 * not implement this protocol.
		 * [icmp-name-lookups-07, Section 5.4]
		 * So we don't support NI_NODEADDR_FLAG_COMPAT in
		 * this function at this moment.
		 */

		/* What do we have to do about ::1? */
		switch (af) {
		case AF_INET6:
			in6 = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
			if (IN6_IS_ADDR_MULTICAST(in6))
				continue; /* should not be possible */
			else if (IN6_IS_ADDR_LINKLOCAL(in6)) {
				if ((niflags & NI_NODEADDR_FLAG_LINKLOCAL) == 0)
					continue;
			} else if (IN6_IS_ADDR_SITELOCAL(in6)) {
				if ((niflags & NI_NODEADDR_FLAG_SITELOCAL) == 0)
					continue;
			} else {
				if ((niflags & NI_NODEADDR_FLAG_GLOBAL) == 0)
					continue;
			}

			flags6 = getflags6(ifa->ifa_name, ifa->ifa_addr,
			    ifa->ifa_addr->sa_len);
			if (flags6 < 0)
				continue;

			/*
			 * check if anycast is okay.
			 * XXX: just experimental. not in the spec.
			 */
			if ((flags6 & IN6_IFF_ANYCAST) != 0 &&
			    (niflags & NI_NODEADDR_FLAG_ANYCAST) == 0)
				continue; /* we need only unicast addresses */
#ifdef IN6_IFF_TEMPORARY
			if ((flags6 & IN6_IFF_TEMPORARY) != 0 &&
			    (mode & 4) == 0)
				continue;
#endif

			ap = (u_int8_t *)in6;
			alen = sizeof(*in6);

			break;
		case AF_INET:
			in = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			ap = (u_int8_t *)in;
			alen = sizeof(*in);
			break;
		default:
			goto fail;
		}

		/* now we can copy the address */
		if (p && ep) {
			if (p + alen + sizeof(int32_t) > ep) {
				/*
				 * We give up much more copy.
				 * Set the truncate flag and return.
				 */
				ni6->ni_flags |= NI_NODEADDR_FLAG_TRUNCATE;
				freeifaddrs(ifap);
				return(copied);
			}

			/*
			 * Set the TTL of the address.
			 * The TTL value should be one of the following
			 * according to the specification:
			 *
			 * 1. The remaining lifetime of a DHCP lease on the
			 *    address, or
			 * 2. The remaining Valid Lifetime of a prefix from
			 *    which the address was derived through Stateless
			 *    Autoconfiguration.
			 *
			 * Note that we currently do not support stateful
			 * address configuration by DHCPv6, so the former
			 * case can't happen.
			 */
			expire = getlifetime(ifa->ifa_name, ifa->ifa_addr,
			    ifa->ifa_addr->sa_len);
			if (expire < 0)
				ltime = 0;
			else if (expire == 0)
				ltime = ND6_INFINITE_LIFETIME;
			else {
				if (expire > time(NULL))
					ltime = expire - time(NULL);
				else
					ltime = 0;
			}
			ltime = ntohl(ltime & 0x7fffffff);
			memcpy(cp, &ltime, sizeof(ltime));
			cp += sizeof(ltime);

			/* copy the address itself */
			memcpy(cp, ap, alen);
			/* XXX: KAME link-local hack; remove ifindex */
			if (af == AF_INET6 &&
			    IN6_IS_ADDR_LINKLOCAL((struct in6_addr *)cp)) {
				((struct in6_addr *)cp)->s6_addr[2] = 0;
				((struct in6_addr *)cp)->s6_addr[3] = 0;
			}
			cp += alen;
			
			copied += (alen + sizeof(int32_t));
			addrs++;
		}
	}

	freeifaddrs(ifap);
	return copied;

fail:
	freeifaddrs(ifap);
	return(0);
}

static int
ismyaddr(sa, salen)
	struct sockaddr *sa;
	socklen_t salen;
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 sin6;

	if (getifaddrs(&ifap) < 0)
		return 0;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != sa->sa_family)
			continue;
		/* yeah, getifaddrs(3) is biased to 4.4BSD sockaddr... */
		if (ifa->ifa_addr->sa_len != salen)
			continue;

#ifdef __KAME__
		if (ifa->ifa_addr->sa_family == AF_INET6 &&
		    sizeof(sin6) == salen &&
		    IN6_IS_ADDR_LINKLOCAL(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr)) {
			memcpy(&sin6, ifa->ifa_addr, sizeof(sin6));
			sin6.sin6_scope_id = sin6.sin6_addr.s6_addr[3] |
			    (u_int32_t)sin6.sin6_addr.s6_addr[2] << 8;
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
			if (memcmp(&sin6, sa, salen) == 0) {
				freeifaddrs(ifap);
				return 1;
			}
		}
#endif
		if (memcmp(ifa->ifa_addr, sa, salen) == 0) {
			freeifaddrs(ifap);
			return 1;
		}
	}

	freeifaddrs(ifap);
	return 0;
}

static int
getflags6(ifname, sa, salen)
	const char *ifname;
	const struct sockaddr *sa;
	socklen_t salen;
{
	const struct sockaddr_in6 *sin6;
	struct in6_ifreq ifr6;
	int sock;

	if (sa->sa_family != AF_INET6)
		return -1;
	sin6 = (const struct sockaddr_in6 *)sa;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	memset(&ifr6, 0, sizeof(ifr6));
	strncpy(ifr6.ifr_name, ifname, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = *sin6;
	if (ioctl(sock, SIOCGIFAFLAG_IN6, (caddr_t)&ifr6) < 0) {
		close(sock);
		return -1;
	}

	close(sock);
	return ifr6.ifr_ifru.ifru_flags6;
}

static time_t
getlifetime(ifname, sa, salen)
	const char *ifname;
	const struct sockaddr *sa;
	socklen_t salen;
{
	const struct sockaddr_in6 *sin6;
	struct in6_ifreq ifr6;
	int sock;

	if (sa->sa_family != AF_INET6)
		return -1;
	sin6 = (const struct sockaddr_in6 *)sa;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	memset(&ifr6, 0, sizeof(ifr6));
	strncpy(ifr6.ifr_name, ifname, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = *sin6;
	if (ioctl(sock, SIOCGIFALIFETIME_IN6, (caddr_t)&ifr6) < 0) {
		close(sock);
		return -1;
	}

	close(sock);
	return ifr6.ifr_ifru.ifru_lifetime.ia6t_expire;
}

static void
setkernmode(m)
	int m;
{
	int mib[] = { CTL_NET, AF_INET6, IPPROTO_ICMPV6, ICMPV6CTL_NODEINFO };

	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), NULL, NULL, &m,
	    sizeof(m)) < 0) {
		err(1, "sysctl");
		/* NOTREACHED */
	}
}
