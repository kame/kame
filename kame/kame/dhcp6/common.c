/*	$KAME: common.c,v 1.37 2002/05/01 10:53:46 jinmei Exp $	*/
/*
 * Copyright (C) 1998 and 1999 WIDE Project.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <net/if.h>
#include <net/if_types.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif
#include <net/if_dl.h>
#include <net/if_arp.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>

#ifdef HAVE_GETIFADDRS 
# ifdef HAVE_IFADDRS_H
#  define USE_GETIFADDRS
#  include <ifaddrs.h>
# endif
#endif

#include <dhcp6.h>
#include <common.h>

int foreground;
int debug_thresh;

#if 0
static unsigned int if_maxindex __P((void));
#endif
static int in6_matchflags __P((struct sockaddr *, char *, int));
static ssize_t gethwid __P((char *, int, const char *, u_int16_t *));

#if 0
static unsigned int
if_maxindex()
{
	struct if_nameindex *p, *p0;
	unsigned int max = 0;

	p0 = if_nameindex();
	for (p = p0; p && p->if_index && p->if_name; p++) {
		if (max < p->if_index)
			max = p->if_index;
	}
	if_freenameindex(p0);
	return max;
}
#endif

int
getifaddr(addr, ifnam, prefix, plen, strong, ignoreflags)
	struct in6_addr *addr;
	char *ifnam;
	struct in6_addr *prefix;
	int plen;
	int strong;		/* if strong host model is required or not */
	int ignoreflags;
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 sin6;
	int error = -1;

	if (getifaddrs(&ifap) != 0) {
		err(1, "getifaddr: getifaddrs");
		/*NOTREACHED*/
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		int s1, s2;

		if (strong && strcmp(ifnam, ifa->ifa_name) != 0)
			continue;

		/* in any case, ignore interfaces in different scope zones. */
		if ((s1 = in6_addrscopebyif(prefix, ifnam)) < 0 ||
		    (s2 = in6_addrscopebyif(prefix, ifa->ifa_name)) < 0 ||
		     s1 != s2)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (ifa->ifa_addr->sa_len > sizeof(sin6))
			continue;

		if (in6_matchflags(ifa->ifa_addr, ifa->ifa_name, ignoreflags))
			continue;

		memcpy(&sin6, ifa->ifa_addr, ifa->ifa_addr->sa_len);
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
			sin6.sin6_addr.s6_addr[2] = 0;
			sin6.sin6_addr.s6_addr[3] = 0;
		}
#endif
		if (plen % 8 == 0) {
			if (memcmp(&sin6.sin6_addr, prefix, plen / 8) != 0)
				continue;
		} else {
			struct in6_addr a, m;
			int i;

			memcpy(&a, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
			memset(&m, 0, sizeof(m));
			memset(&m, 0xff, plen / 8);
			m.s6_addr[plen / 8] = (0xff00 >> (plen % 8)) & 0xff;
			for (i = 0; i < sizeof(a); i++)
				a.s6_addr[i] &= m.s6_addr[i];

			if (memcmp(&a, prefix, plen / 8) != 0 ||
			    a.s6_addr[plen / 8] !=
			    (prefix->s6_addr[plen / 8] & m.s6_addr[plen / 8]))
				continue;
		}
		memcpy(addr, &sin6.sin6_addr, sizeof(sin6.sin6_addr));
#ifdef __KAME__
		if (IN6_IS_ADDR_LINKLOCAL(addr))
			addr->s6_addr[2] = addr->s6_addr[3] = 0; 
#endif
		error = 0;
		break;
	}

	freeifaddrs(ifap);
	return(error);
}

int
in6_addrscopebyif(addr, ifnam)
	struct in6_addr *addr;
	char *ifnam;
{
	u_int ifindex; 

	if ((ifindex = if_nametoindex(ifnam)) == 0)
		return(-1);

	if (IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MC_LINKLOCAL(addr))
		return(ifindex);

	if (IN6_IS_ADDR_SITELOCAL(addr) || IN6_IS_ADDR_MC_SITELOCAL(addr))
		return(1);	/* XXX */

	if (IN6_IS_ADDR_MC_ORGLOCAL(addr))
		return(1);	/* XXX */

	return(1);		/* treat it as global */
}

/* XXX: this code assumes getifaddrs(3) */
const char *
getdev(addr)
	struct sockaddr_in6 *addr;
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in6 *a6;
	static char ret_ifname[IF_NAMESIZE];

	if (getifaddrs(&ifap) != 0) {
		err(1, "getdev: getifaddrs");
		/* NOTREACHED */
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		a6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (!IN6_ARE_ADDR_EQUAL(&a6->sin6_addr, &addr->sin6_addr) ||
		    a6->sin6_scope_id != addr->sin6_scope_id)
			continue;

		break;
	}

	if (ifa)
		strlcpy(ret_ifname, ifa->ifa_name, sizeof(ret_ifname));
	freeifaddrs(ifap);

	return(ifa ? ret_ifname : NULL);
}

int
transmit_sa(s, sa, hlim, buf, len)
	int s;
	struct sockaddr *sa;
	int hlim;
	char *buf;
	size_t len;
{
	int error;

	if (hlim == 0)
		hlim = 64;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hlim,
			sizeof(hlim)) < 0) {
		dprintf(LOG_ERR, "setsockopt(IPV6_MULTICAST_HOPS): %s",
			strerror(errno));
		exit(1);	/* XXX */
	}

	error = sendto(s, buf, len, 0, sa, sa->sa_len);

	return (error != len) ? -1 : 0;
}

long
random_between(x, y)
	long x;
	long y;
{
	long ratio;

	ratio = 1 << 16;
	while ((y - x) * ratio < (y - x))
		ratio = ratio / 2;
	return x + ((y - x) * (ratio - 1) / random() & (ratio - 1));
}

char *
addr2str(sa)
	struct sockaddr *sa;
{
	static char addrbuf[8][NI_MAXHOST];
	static int round = 0;
	char *cp;

	round = (round + 1) & 7;
	cp = addrbuf[round];

	getnameinfo(sa, sa->sa_len, cp, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

	return(cp);
}

char *
in6addr2str(in6, scopeid)
	struct in6_addr *in6;
	int scopeid;
{
	struct sockaddr_in6 sa6;

	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_addr = *in6;
	sa6.sin6_scope_id = scopeid;

	return(addr2str((struct sockaddr *)&sa6));
}

/* return IPv6 address scope type. caller assumes that smaller is narrower. */
int
in6_scope(addr)
	struct in6_addr *addr;
{
	int scope;

	if (addr->s6_addr[0] == 0xfe) {
		scope = addr->s6_addr[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return 2; /* link-local */
			break;
		case 0xc0:
			return 5; /* site-local */
			break;
		default:
			return 14; /* global: just in case */
			break;
		}
	}

	/* multicast scope. just return the scope field */
	if (addr->s6_addr[0] == 0xff)
		return(addr->s6_addr[1] & 0x0f);

	if (bcmp(&in6addr_loopback, addr, sizeof(addr) - 1) == 0) {
		if (addr->s6_addr[15] == 1) /* loopback */
			return 1;
		if (addr->s6_addr[15] == 0) /* unspecified */
			return 0; /* XXX: good value? */
	}

	return 14;		/* global */
}

static int
in6_matchflags(addr, ifnam, flags)
	struct sockaddr *addr;
	char *ifnam;
	int flags;
{
	int s;
	struct in6_ifreq ifr6;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		warn("in6_matchflags: socket(DGRAM6)");
		return(-1);
	}
	memset(&ifr6, 0, sizeof(ifr6));
	strncpy(ifr6.ifr_name, ifnam, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = *(struct sockaddr_in6 *)addr;

	if (ioctl(s, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		warn("in6_matchflags: ioctl(SIOCGIFAFLAG_IN6, %s)",
		     addr2str(addr));
		close(s);
		return(-1);
	}

	close(s);

	return(ifr6.ifr_ifru.ifru_flags6 & flags);
}

int
get_duid(idfile, duid)
	char *idfile;
	struct duid *duid;
{
	FILE *fp = NULL;
	u_int16_t len = 0, hwtype;
	struct dhcp6_duid_type1 *dp; /* we only support the type1 DUID */
	char tmpbuf[256];	/* DUID should be no more than 256 bytes */

	if ((fp = fopen(idfile, "r")) == NULL && errno != ENOENT)
		dprintf(LOG_NOTICE, "get_duid: failed to open DUID file:");

	if (fp) {
		/* decode length */
		if (fread(&len, sizeof(len), 1, fp) != 1) {
			dprintf(LOG_ERR, "get_duid: DUID file corrupted");
			goto fail;
		}
	} else {
		int l;

		if ((l = gethwid(tmpbuf, sizeof(tmpbuf), NULL, &hwtype)) < 0) {
			dprintf(LOG_INFO,
				"get_duid: failed to get a hardware address");
			goto fail;
		}
		len = l + sizeof(struct dhcp6_duid_type1);
	}

	memset(duid, 0, sizeof(*duid));
	duid->duid_len = len;
	if ((duid->duid_id = (char *)malloc(len)) == NULL)
		err(1, "get_duid: failed to allocate memory");

	/* copy (and fill) the ID */
	if (fp) {
		if (fread(duid->duid_id, len, 1, fp) != 1) {
			dprintf(LOG_ERR, "get_duid: DUID file corrupted");
			goto fail;
		}

		dprintf(LOG_DEBUG,
			"get_duid: extracted an existing DUID from %s",
			idfile);
	} else {
		u_int64_t t64;

		dp = (struct dhcp6_duid_type1 *)duid->duid_id;
		dp->dh6duid1_type = htons(1); /* type 1 */
		dp->dh6duid1_hwtype = htons(hwtype);
		/* time is Jan 1, 2000 (UTC), modulo 2^32 */
		t64 = (u_int64_t)(time(NULL) - 946684800);
		dp->dh6duid1_time = htonl((u_long)(t64 & 0xffffffff));
		memcpy((void *)(dp + 1), tmpbuf, (len - sizeof(*dp)));

		dprintf(LOG_DEBUG, "get_duid: generated a new DUID");
	}

	/* save the (new) ID to the file for next time */
	if (!fp) {
		if ((fp = fopen(idfile, "w+")) == NULL) {
			dprintf(LOG_ERR,
				"get_duid: failed to open DUID file for save");
			goto fail;
		}
		if ((fwrite(&len, sizeof(len), 1, fp)) != 1) {
			dprintf(LOG_ERR, "get_duid: failed to save DUID");
			goto fail;
		}
		if ((fwrite(duid->duid_id, len, 1, fp)) != 1) {
			dprintf(LOG_ERR, "get_duid: failed to save DUID");
			goto fail;
		}

		dprintf(LOG_DEBUG, "get_duid: saved generated DUID to %s",
			idfile);
	}

	if (fp)
		fclose(fp);
	return(0);

  fail:
	if (fp)
		fclose(fp);
	if (duid->duid_id) {
		free(duid->duid_id);
		duid->duid_id = NULL; /* for safety */
	}
	return(-1);
}

static ssize_t
gethwid(buf, len, ifname, hwtypep)
	char *buf;
	int len;
	const char *ifname;
	u_int16_t *hwtypep;
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_dl *sdl;
	ssize_t l;

	if (getifaddrs(&ifap) < 0)
		return -1;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifname && strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (len < 2 + sdl->sdl_alen)
			goto fail;
		/*
		 * translate interface type to hardware type based on
		 * http://www.iana.org/assignments/arp-parameters
		 */
		switch(sdl->sdl_type) {
		case IFT_ETHER:
#ifdef IFT_IEEE80211
		case IFT_IEEE80211:
#endif
			*hwtypep = ARPHRD_ETHER;
			break;
		default:
			continue; /* XXX */
		}
		dprintf(LOG_DEBUG, "gethwid: found an interface %s for DUID",
			ifa->ifa_name);
		memcpy(buf, LLADDR(sdl), sdl->sdl_alen);
		l = sdl->sdl_alen; /* sdl will soon be freed */
		freeifaddrs(ifap);
		return l;
	}

  fail:
	freeifaddrs(ifap);
	return -1;
}

void
dhcp6_init_options(optinfo)
	struct dhcp6_optinfo *optinfo;
{
	memset(optinfo, 0, sizeof(*optinfo));
}

int
dhcp6_get_options(p, ep, optinfo)
	struct dhcp6opt *p, *ep;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6opt *np;
	int opt, optlen;
	char *cp;

	for (; p + 1 <= ep; p = np) {
		cp = (char *)(p + 1);
		optlen = ntohs(p->dh6opt_len);
		opt = ntohs(p->dh6opt_type);
		np = (struct dhcp6opt *)(cp + optlen);

		dprintf(LOG_DEBUG, "DHCP option %s, len %d",
			dhcpoptstr(opt), optlen);

		/* option length field overrun */
		if (np > ep) {
			dprintf(LOG_INFO, "malformed DHCP options");
			return -1;
		}

		switch (opt) {
		case DH6OPT_CLIENTID:
			if (optlen == 0)
				goto malformed;
			optinfo->clientID.duid_len = optlen;
			optinfo->clientID.duid_id = cp;
			break;
		case DH6OPT_SERVERID:
			if (optlen == 0)
				goto malformed;
			optinfo->serverID.duid_len = optlen;
			optinfo->serverID.duid_id = cp;
			break;
		case DH6OPT_RAPID_COMMIT:
			if (optlen != 0)
				goto malformed;
			optinfo->rapidcommit = 1;
			break;
		case DH6OPT_DNS:
			if (optlen % sizeof(struct in6_addr) || optlen == 0)
				goto malformed;
			optinfo->dns.n = optlen / sizeof(struct in6_addr);
			optinfo->dns.list = cp;
			break;
		default:
			/* no option specific behavior */
			dprintf(LOG_INFO,
				"unknown DHCP6 option type %d, len %d",
				opt, optlen);
			break;
		}
	}

	return(0);

  malformed:
	dprintf(LOG_INFO, "malformed DHCP option: type %d, len %d",
		opt, optlen);
	return(-1);
}

#define COPY_OPTION(t, l, v, p) do { \
	if ((void *)(ep) - (void *)(p) < (l) + sizeof(struct dhcp6opt)) { \
		dprintf(LOG_INFO, "option buffer short for %s", dhcpoptstr((t))); \
		return(-1); \
	} \
	(p)->dh6opt_type = htons((t)); \
	(p)->dh6opt_len = htons((l)); \
	if ((l)) \
		memcpy((p) + 1, (v), (l)); \
	(p) = (struct dhcp6opt *)((char *)((p) + 1) + (l)); \
 	(len) += sizeof(struct dhcp6opt) + (l); \
	dprintf(LOG_DEBUG, "set DHCP option %s", dhcpoptstr((t))); \
} while (0)

int
dhcp6_set_options(bp, ep, optinfo)
	struct dhcp6opt *bp, *ep;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6opt *p = bp;
	int len = 0;

	if (optinfo->clientID.duid_len) {
		COPY_OPTION(DH6OPT_CLIENTID, optinfo->clientID.duid_len,
			    optinfo->clientID.duid_id, p);
	}

	if (optinfo->serverID.duid_len) {
		COPY_OPTION(DH6OPT_SERVERID, optinfo->serverID.duid_len,
			    optinfo->serverID.duid_id, p);
	}

	if (optinfo->rapidcommit)
		COPY_OPTION(DH6OPT_RAPID_COMMIT, 0, NULL, p);

	if (optinfo->dns.n) {
		COPY_OPTION(DH6OPT_DNS,
			    optinfo->dns.n * sizeof(struct in6_addr),
			    optinfo->dns.list, p);
	}

	return(len);
}
#undef COPY_OPTION

char *
dhcpoptstr(type)
	int type;
{
	static char genstr[sizeof("opt65535") + 1]; /* XXX thread unsafe */

	if (type > 65535)
		return "INVALID option";

	switch(type) {
	case DH6OPT_CLIENTID:
		return "client ID";
	case DH6OPT_SERVERID:
		return "server ID";
	case DH6OPT_DNS:
		return "DNS";
	case DH6OPT_RAPID_COMMIT:
		return "rapid commit";
	default:
		sprintf(genstr, "opt%d", type);
		return(genstr);
	}
}

char *
dhcpmsgstr(type)
	int type;
{
	static char genstr[sizeof("msg255") + 1]; /* XXX thread unsafe */

	if (type > 255)
		return "INVALID msg";

	switch(type) {
	case DH6_SOLICIT:
		return "solicit";
	case DH6_REPLY:
		return "reply";
	case DH6_INFORM_REQ:
		return "information request";
	default:
		sprintf(genstr, "msg%d", type);
		return(genstr);
	}
}

void
setloglevel(debuglevel)
	int debuglevel;
{
	if (foreground) {
		switch(debuglevel) {
		case 0:
			debug_thresh = LOG_ERR;
			break;
		case 1:
			debug_thresh = LOG_INFO;
			break;
		default:
			debug_thresh = LOG_DEBUG;
			break;
		}
	} else {
		switch(debuglevel) {
		case 0:
			setlogmask(LOG_UPTO(LOG_ERR));
			break;
		case 1:
			setlogmask(LOG_UPTO(LOG_INFO));
			break;
		}
	}
}

void
dprintf(int level, const char *fmt, ...)
{
	va_list ap;
	char logbuf[LINE_MAX];

	va_start(ap, fmt);
	vsnprintf(logbuf, sizeof(logbuf), fmt, ap);

	if (foreground && debug_thresh >= level)
		fprintf(stderr, "%s\n", logbuf);
	else
		syslog(level, "%s", logbuf);
}
