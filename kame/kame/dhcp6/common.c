/*	$KAME: common.c,v 1.49 2002/05/10 05:02:54 jinmei Exp $	*/
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
#include <config.h>

int foreground;
int debug_thresh;

#if 0
static unsigned int if_maxindex __P((void));
#endif
static int in6_matchflags __P((struct sockaddr *, char *, int));
static ssize_t gethwid __P((char *, int, const char *, u_int16_t *));
static int get_delegated_prefixes __P((char *, char *,
				       struct dhcp6_optinfo *));

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
transmit_sa(s, sa, buf, len)
	int s;
	struct sockaddr *sa;
	char *buf;
	size_t len;
{
	int error;

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

int
prefix6_mask(in6, plen)
	struct in6_addr *in6;
	int plen;
{
	struct sockaddr_in6 mask6;
	int i;

	if (sa6_plen2mask(&mask6, plen))
		return(-1);

	for (i = 0; i < 16; i++)
		in6->s6_addr[i] &= mask6.sin6_addr.s6_addr[i];

	return(0);
}

int
sa6_plen2mask(sa6, plen)
	struct sockaddr_in6 *sa6;
	int plen;
{
	u_char *cp;

	if (plen < 0 || plen > 128)
		return(-1);

	memset(sa6, 0, sizeof(*sa6));
	sa6->sin6_family = AF_INET6;
	sa6->sin6_len = sizeof(*sa6);
	
	for (cp = (u_char *)&sa6->sin6_addr; plen > 7; plen -= 8)
		*cp++ = 0xff;
	*cp = 0xff << (8 - plen);

	return(0);
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
			"get_duid: extracted an existing DUID from %s: %s",
			idfile, duidstr(duid));
	} else {
		u_int64_t t64;

		dp = (struct dhcp6_duid_type1 *)duid->duid_id;
		dp->dh6duid1_type = htons(1); /* type 1 */
		dp->dh6duid1_hwtype = htons(hwtype);
		/* time is Jan 1, 2000 (UTC), modulo 2^32 */
		t64 = (u_int64_t)(time(NULL) - 946684800);
		dp->dh6duid1_time = htonl((u_long)(t64 & 0xffffffff));
		memcpy((void *)(dp + 1), tmpbuf, (len - sizeof(*dp)));

		dprintf(LOG_DEBUG, "get_duid: generated a new DUID: %s",
			duidstr(duid));
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
	TAILQ_INIT(&optinfo->dnslist);
	TAILQ_INIT(&optinfo->prefix);
}

void
dhcp6_clear_options(optinfo)
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_optconf *ropt, *ropt_next;
	struct dnslist *d, *dn;
	struct delegated_prefix *p, *pn;

	for (ropt = optinfo->requests; ropt; ropt = ropt_next) {
		ropt_next = ropt->next;

		if (ropt->val)
			free(ropt->val);
		free(ropt);
	}

	for (d = TAILQ_FIRST(&optinfo->dnslist); d; d = dn) {
		dn = TAILQ_NEXT(d, link);
		TAILQ_REMOVE(&optinfo->dnslist, d, link);
		free(d);
	}

	for (p = TAILQ_FIRST(&optinfo->prefix); p; p = pn) {
		pn = TAILQ_NEXT(p, link);
		TAILQ_REMOVE(&optinfo->prefix, p, link);
		free(p);
	}

	dhcp6_init_options(optinfo);
}

int
dhcp6_get_options(p, ep, optinfo)
	struct dhcp6opt *p, *ep;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6opt *np, opth;
	int i, opt, optlen, reqopts;
	char *cp, *val;
	struct dhcp6_optconf *optconf;

	for (; p + 1 <= ep; p = np) {
		/*
		 * get the option header.  XXX: since there is no guarantee
		 * about the header alignment, we need to make a local copy.
		 */
		memcpy(&opth, p, sizeof(opth));
		optlen = ntohs(opth.dh6opt_len);
		opt = ntohs(opth.dh6opt_type);

		cp = (char *)(p + 1);
		np = (struct dhcp6opt *)(cp + optlen);

		dprintf(LOG_DEBUG, "get DHCP option %s, len %d",
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
			dprintf(LOG_DEBUG, "  DUID: %s",
				duidstr(&optinfo->clientID));
			break;
		case DH6OPT_SERVERID:
			if (optlen == 0)
				goto malformed;
			optinfo->serverID.duid_len = optlen;
			optinfo->serverID.duid_id = cp;
			dprintf(LOG_DEBUG, "  DUID: %s",
				duidstr(&optinfo->serverID));
			break;
		case DH6OPT_ORO:
			if ((optlen % 2) != 0 || optlen == 0)
				goto malformed;
			reqopts = optlen / 2;
			for (i = 0, val = cp; i < reqopts;
			     i++, val += sizeof(u_int16_t)) {
				struct dhcp6_optconf *opt;
				u_int16_t opttype;

				memcpy(&opttype, val, sizeof(u_int16_t));
				opttype = ntohs(opttype);

				/* duplication check */
				for (opt = optinfo->requests; opt;
				     opt = opt->next) {
					if (opt->type == opttype) {
						dprintf(LOG_INFO,
							"dhcp6_get_options: "
							"duplicated option "
							"type (%s)",
							dhcpoptstr(opttype));
						goto nextoption;
					}
				}

				optconf = (struct dhcp6_optconf *)
					malloc(sizeof(*optconf));
				if (optconf == NULL) {
					dprintf(LOG_NOTICE,
						"memory allocation failed "
						"during parse options");
					goto fail;
				}
				memset(optconf, 0, sizeof(*optconf));
				optconf->type = opttype;
				dprintf(LOG_DEBUG, "  requested option: %s",
					dhcpoptstr(optconf->type));
				optconf->next = optinfo->requests;
				optinfo->requests = optconf;

			  nextoption:
			}
			break;
		case DH6OPT_RAPID_COMMIT:
			if (optlen != 0)
				goto malformed;
			optinfo->rapidcommit = 1;
			break;
		case DH6OPT_DNS:
			if (optlen % sizeof(struct in6_addr) || optlen == 0)
				goto malformed;
			for (val = cp; val < cp + optlen;
			     val += sizeof(struct in6_addr)) {
				struct dnslist *dle;

				if ((dle = malloc(sizeof *dle)) == NULL) {
					dprintf(LOG_ERR, "memory allocation"
						"failed during parse options");
					goto fail;
				}
				memcpy(&dle->addr, val,
				       sizeof(struct in6_addr));
				TAILQ_INSERT_TAIL(&optinfo->dnslist,
						  dle, link);
			}
			break;
		case DH6OPT_PREFIX_DELEGATION:
			if (get_delegated_prefixes(cp, cp + optlen, optinfo))
				goto fail;
			break;
		default:
			/* no option specific behavior */
			dprintf(LOG_INFO, "unknown or unexpected DHCP6 option "
				"%s, len %d", dhcpoptstr(opt), optlen);
			break;
		}
	}

	return(0);

  malformed:
	dprintf(LOG_INFO, "malformed DHCP option: type %d, len %d",
		opt, optlen);
  fail:
	dhcp6_clear_options(optinfo);
	return(-1);
}

static int
get_delegated_prefixes(p, ep, optinfo)
	char *p, *ep;
	struct dhcp6_optinfo *optinfo;
{
	char *np, *cp;
	struct dhcp6opt opth;
	struct dhcp6_prefix_info pi;
	struct delegated_prefix *dp;
	int optlen, opt;

	for (; p + sizeof(struct dhcp6opt) <= ep; p = np) {
		/* XXX: alignment issue */
		memcpy(&opth, p, sizeof(opth));
		optlen =  ntohs(opth.dh6opt_len);
		opt = ntohs(opth.dh6opt_type);

		cp = p + sizeof(opth);
		np = cp + optlen;
		dprintf(LOG_DEBUG, "  prefix delegation option: %s, "
			"len %d", dhcpoptstr(opt), optlen);

		if (np > ep) {
			dprintf(LOG_INFO, "malformed DHCP options");
			return -1;
		}

		switch(opt) {
		case DH6OPT_PREFIX_INFORMATION:
			if (optlen != sizeof(pi) - 4)
				goto malformed;
			memcpy(&pi, p, sizeof(pi));
			if (pi.dh6_pi_plen > 128) {
				dprintf(LOG_INFO, "  invalid prefix length "
					"(%d)", pi.dh6_pi_plen);
				goto malformed;
			}
			pi.dh6_pi_duration = ntohl(pi.dh6_pi_duration);
			if (pi.dh6_pi_duration != DHCP6_DURATITION_INFINITE) {
				dprintf(LOG_DEBUG, "  prefix information: "
					"%s/%d duration %ld",
					in6addr2str(&pi.dh6_pi_paddr, 0),
					pi.dh6_pi_plen, pi.dh6_pi_duration);
			} else {
				dprintf(LOG_DEBUG, "  prefix information: "
					"%s/%d duration infinity",
					in6addr2str(&pi.dh6_pi_paddr, 0),
					pi.dh6_pi_plen);
			}

			if ((dp = malloc(sizeof(*dp))) == NULL) {
				dprintf(LOG_ERR, "memory allocation failed"
					"during parse prefix options");
				goto fail;
			}
			memset(dp, 0, sizeof(*dp));
			dp->prefix.addr = pi.dh6_pi_paddr;
			dp->prefix.plen = pi.dh6_pi_plen;
			dp->prefix.duration = pi.dh6_pi_duration;

			TAILQ_INSERT_TAIL(&optinfo->prefix, dp, link);
		}
	}

	return(0);

  malformed:
	dprintf(LOG_INFO,
		"  malformed prefix delegation option: type %d, len %d",
		opt, optlen);
  fail:
	return(-1);
}

#define COPY_OPTION(t, l, v, p) do { \
	if ((void *)(ep) - (void *)(p) < (l) + sizeof(struct dhcp6opt)) { \
		dprintf(LOG_INFO, "option buffer short for %s", dhcpoptstr((t))); \
		goto fail; \
	} \
	opth.dh6opt_type = htons((t)); \
	opth.dh6opt_len = htons((l)); \
	memcpy((p), &opth, sizeof(opth)); \
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
	struct dhcp6opt *p = bp, opth;
	int len = 0, optlen;
	char *tmpbuf = NULL;

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

	if (!TAILQ_EMPTY(&optinfo->dnslist)) {
		struct in6_addr *in6;
		struct dnslist *d;
		int ns;

		tmpbuf = NULL;
		for (ns = 0, d = TAILQ_FIRST(&optinfo->dnslist); d;
		     d = TAILQ_NEXT(d, link), ns++)
			;
		optlen = ns * sizeof(struct in6_addr);
		if ((tmpbuf = malloc(optlen)) == NULL) {
			dprintf(LOG_ERR,
				"memory allocation failed for DNS options");
			goto fail;
		}
		in6 = (struct in6_addr *)tmpbuf;
		for (d = TAILQ_FIRST(&optinfo->dnslist); d;
		     d = TAILQ_NEXT(d, link), in6++) {
			memcpy(in6, &d->addr, sizeof(*in6));
		}
		COPY_OPTION(DH6OPT_DNS, optlen, tmpbuf, p);
		free(tmpbuf);
	}

	if (optinfo->requests) {
		int nopts;
		struct dhcp6_optconf *opt;
		u_int16_t *valp;

		tmpbuf = NULL;
		for (nopts = 0, opt = optinfo->requests; opt;
		     opt = opt->next, nopts++)
			;
		optlen = nopts * sizeof(u_int16_t);
		if ((tmpbuf = malloc(optlen)) == NULL) {
			dprintf(LOG_ERR,
				"memory allocation failed for options");
			goto fail;
		}
		for (opt = optinfo->requests, valp = (u_int16_t *)tmpbuf; opt;
		     opt = opt->next, valp++) {
			*valp = htons(opt->type);
		}
		COPY_OPTION(DH6OPT_ORO, optlen, tmpbuf, p);
		free(tmpbuf);
	}

	if (!TAILQ_EMPTY(&optinfo->prefix)) {
		int pfxs;
		char *tp;
		struct delegated_prefix *dp;
		struct dhcp6_prefix_info pi;

		tmpbuf = NULL;
		for (pfxs = 0, dp = TAILQ_FIRST(&optinfo->prefix); dp;
		     dp = TAILQ_NEXT(dp, link), pfxs++)
			;
		optlen = pfxs * sizeof(struct dhcp6_prefix_info);
		if ((tmpbuf = malloc(optlen)) == NULL) {
			dprintf(LOG_ERR,
				"memory allocation failed for options");
			goto fail;
		}
		for (dp = TAILQ_FIRST(&optinfo->prefix), tp = tmpbuf; dp;
		     dp = TAILQ_NEXT(dp, link), tp += sizeof(pi)) {
			/*
			 * XXX: We need a temporary structure due to alignment
			 * issue.
			 */
			memset(&pi, 0, sizeof(pi));
			pi.dh6_pi_type = htons(DH6OPT_PREFIX_INFORMATION);
			pi.dh6_pi_len = htons(sizeof(pi) - 4);
			pi.dh6_pi_duration = htonl(dp->prefix.duration);
			pi.dh6_pi_plen = dp->prefix.plen;
			memcpy(&pi.dh6_pi_paddr, &dp->prefix.addr,
			       sizeof(struct in6_addr));
			memcpy(tp, &pi, sizeof(pi));
		}
		COPY_OPTION(DH6OPT_PREFIX_DELEGATION, optlen, tmpbuf, p);
		free(tmpbuf);
		     
	}
	return(len);

  fail:
	if (tmpbuf)
		free(tmpbuf);
	return(-1);
}
#undef COPY_OPTION

char *
dhcpoptstr(type)
	int type;
{
	static char genstr[sizeof("opt_65535") + 1]; /* XXX thread unsafe */

	if (type > 65535)
		return "INVALID option";

	switch(type) {
	case DH6OPT_CLIENTID:
		return "client ID";
	case DH6OPT_SERVERID:
		return "server ID";
	case DH6OPT_ORO:
		return "option request";
	case DH6OPT_RAPID_COMMIT:
		return "rapid commit";
	case DH6OPT_DNS:
		return "DNS";
	case DH6OPT_PREFIX_DELEGATION:
		return "prefix delegation";
	case DH6OPT_PREFIX_INFORMATION:
		return "prefix information";
	default:
		sprintf(genstr, "opt_%d", type);
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

char *
duidstr(duid)
	struct duid *duid;
{
	int i;
	char *cp;
	static char duidstr[sizeof("xx:") * 256 + sizeof("...")];

	cp = duidstr;
	for (i = 0; i < duid->duid_len && i <= 256; i++) {
		cp += sprintf(cp, "%s%02x", i == 0 ? "" : ":",
			      duid->duid_id[i] & 0xff);
	}
	if (i < duid->duid_len)
		sprintf(cp, "%s", "...");

	return(duidstr);
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
