/*	$KAME: common.c,v 1.57 2002/05/23 02:37:33 jinmei Exp $	*/
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
#include <config.h>
#include <common.h>
#include <timer.h>

int foreground;
int debug_thresh;

#if 0
static unsigned int if_maxindex __P((void));
#endif
static int in6_matchflags __P((struct sockaddr *, char *, int));
static ssize_t gethwid __P((char *, int, const char *, u_int16_t *));
static int get_delegated_prefixes __P((char *, char *,
				       struct dhcp6_optinfo *));

int
dhcp6_copy_list(dst, src)
	struct dhcp6_list *dst, *src;
{
	struct dhcp6_listval *ent, *dent;

	for (ent = TAILQ_FIRST(src); ent; ent = TAILQ_NEXT(ent, link)) {
		if ((dent = malloc(sizeof(*dent))) == NULL)
			goto fail;

		memset(dent, 0, sizeof(*dent));
		memcpy(&dent->uv, &ent->uv, sizeof(ent->uv));

		TAILQ_INSERT_TAIL(dst, dent, link);
	}

	return 0;

  fail:
	dhcp6_clear_list(dst);
	return -1;
}

void
dhcp6_clear_list(head)
	struct dhcp6_list *head;
{
	struct dhcp6_listval *v;

	while (v = TAILQ_FIRST(head)) {
		TAILQ_REMOVE(head, v, link);
		free(v);
	}

	return;
}

int
dhcp6_count_list(head)
	struct dhcp6_list *head;
{
	struct dhcp6_listval *v;
	int i;

	for (i = 0, v = TAILQ_FIRST(head); v; v = TAILQ_NEXT(v, link))
		i++;

	return i;
}

struct dhcp6_listval *
dhcp6_find_listval(head, val, type)
	struct dhcp6_list *head;
	void *val;
	dhcp6_listval_type_t type;
{
	struct dhcp6_listval *lv;

	for (lv = TAILQ_FIRST(head); lv; lv = TAILQ_NEXT(lv, link)) {
		switch(type) {
		case DHCP6_LISTVAL_NUM:
			if (lv->val_num == *(int *)val)
				return(lv);
			break;
		case DHCP6_LISTVAL_ADDR6:
			if (IN6_ARE_ADDR_EQUAL(&lv->val_addr6,
				(struct in6_addr *)val)) {
				return(lv);
			}
			break;
		case DHCP6_LISTVAL_PREFIX6:
			if (IN6_ARE_ADDR_EQUAL(&lv->val_prefix6.addr,
				&((struct dhcp6_prefix *)val)->addr) &&
			    lv->val_prefix6.plen ==
			    ((struct dhcp6_prefix *)val)->plen) {
				return(lv);
			}
			break;
		}
	}

	return(NULL);
}

struct dhcp6_listval *
dhcp6_add_listval(head, val, type)
	struct dhcp6_list *head;
	void *val;
	dhcp6_listval_type_t type;
{
	struct dhcp6_listval *lv;

	if ((lv = malloc(sizeof(*lv))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory for list "
		    "entry", FNAME);
		return(NULL);
	}
	memset(lv, 0, sizeof(*lv));

	switch(type) {
	case DHCP6_LISTVAL_NUM:
		lv->val_num = *(int *)val;
		break;
	case DHCP6_LISTVAL_ADDR6:
		lv->val_addr6 = *(struct in6_addr *)val;
		break;
	case DHCP6_LISTVAL_PREFIX6:
		lv->val_prefix6 = *(struct dhcp6_prefix *)val;
		break;
	default:
		dprintf(LOG_ERR, "%s" "unexpected list value type (%d)",
		    FNAME, type);
		exit(1);
	}

	TAILQ_INSERT_TAIL(head, lv, link);

	return(lv);
}

struct dhcp6_event *
dhcp6_create_event(ifp, state)
	struct dhcp6_if *ifp;
	int state;
{
	struct dhcp6_event *ev;

	if ((ev = malloc(sizeof(*ev))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory for an event",
			FNAME);
		return(NULL);
	}
	ev->ifp = ifp;
	ev->state = state;
	TAILQ_INIT(&ev->data_list);

	return(ev);
}

void
dhcp6_remove_event(ev)
	struct dhcp6_event *ev;
{
	dprintf(LOG_DEBUG, "%s" "removing an event on %s, state=%d", FNAME,
		ev->ifp->ifname, ev->state);

	if (!TAILQ_EMPTY(&ev->data_list)) {
		dprintf(LOG_ERR, "%s" "assumption failure: "
			"event data list is not empty", FNAME);
		exit(1);
	}

	duidfree(&ev->serverid);

	if (ev->timer)
		dhcp6_remove_timer(&ev->timer);
	TAILQ_REMOVE(&ev->ifp->event_list, ev, link);

	free(ev);
}

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
		dprintf(LOG_NOTICE, "%s" "failed to open DUID file: %s",
		    FNAME, idfile);

	if (fp) {
		/* decode length */
		if (fread(&len, sizeof(len), 1, fp) != 1) {
			dprintf(LOG_ERR, "%s" "DUID file corrupted", FNAME);
			goto fail;
		}
	} else {
		int l;

		if ((l = gethwid(tmpbuf, sizeof(tmpbuf), NULL, &hwtype)) < 0) {
			dprintf(LOG_INFO, "%s"
			    "failed to get a hardware address", FNAME);
			goto fail;
		}
		len = l + sizeof(struct dhcp6_duid_type1);
	}

	memset(duid, 0, sizeof(*duid));
	duid->duid_len = len;
	if ((duid->duid_id = (char *)malloc(len)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory", FNAME);
		goto fail;
	}

	/* copy (and fill) the ID */
	if (fp) {
		if (fread(duid->duid_id, len, 1, fp) != 1) {
			dprintf(LOG_ERR, "%s" "DUID file corrupted", FNAME);
			goto fail;
		}

		dprintf(LOG_DEBUG, "%s"
		    "extracted an existing DUID from %s: %s", FNAME,
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

		dprintf(LOG_DEBUG, "%s" "generated a new DUID: %s", FNAME,
			duidstr(duid));
	}

	/* save the (new) ID to the file for next time */
	if (!fp) {
		if ((fp = fopen(idfile, "w+")) == NULL) {
			dprintf(LOG_ERR, "%s"
			    "failed to open DUID file for save", FNAME);
			goto fail;
		}
		if ((fwrite(&len, sizeof(len), 1, fp)) != 1) {
			dprintf(LOG_ERR, "%s" "failed to save DUID", FNAME);
			goto fail;
		}
		if ((fwrite(duid->duid_id, len, 1, fp)) != 1) {
			dprintf(LOG_ERR, "%s" "failed to save DUID", FNAME);
			goto fail;
		}

		dprintf(LOG_DEBUG, "%s" "saved generated DUID to %s", FNAME,
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
		dprintf(LOG_DEBUG, "%s" "found an interface %s for DUID",
			FNAME, ifa->ifa_name);
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

	optinfo->pref = DH6OPT_PREF_UNDEF;

	TAILQ_INIT(&optinfo->reqopt_list);
	TAILQ_INIT(&optinfo->stcode_list);
	TAILQ_INIT(&optinfo->dns_list);
	TAILQ_INIT(&optinfo->prefix_list);
}

void
dhcp6_clear_options(optinfo)
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6_optconf *ropt, *ropt_next;
	struct dnslist *d, *dn;
	struct delegated_prefix *p, *pn;

	duidfree(&optinfo->clientID);
	duidfree(&optinfo->serverID);

	dhcp6_clear_list(&optinfo->reqopt_list);
	dhcp6_clear_list(&optinfo->stcode_list);
	dhcp6_clear_list(&optinfo->dns_list);
	dhcp6_clear_list(&optinfo->prefix_list);

	dhcp6_init_options(optinfo);
}

int
dhcp6_copy_options(src, dst)
	struct dhcp6_optinfo *src, *dst;
{
	if (duidcpy(&dst->clientID, &src->clientID))
		goto fail;
	if (duidcpy(&dst->serverID, &src->serverID))
		goto fail;
	dst->rapidcommit = src->rapidcommit;

	if (dhcp6_copy_list(&dst->reqopt_list, &src->reqopt_list))
		goto fail;
	if (dhcp6_copy_list(&dst->stcode_list, &src->stcode_list))
		goto fail;
	if (dhcp6_copy_list(&dst->dns_list, &src->dns_list))
		goto fail;
	if (dhcp6_copy_list(&dst->prefix_list, &src->prefix_list))
		goto fail;
	dst->pref = src->pref;

	return 0;

  fail:
	/* cleanup temporary resources */
	dhcp6_clear_options(dst);
	return -1;
}

int
dhcp6_get_options(p, ep, optinfo)
	struct dhcp6opt *p, *ep;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6opt *np, opth;
	struct dhcp6_listval *lv;
	int i, opt, optlen, reqopts, num;
	char *cp, *val;
	u_int16_t val16;

	for (; p + 1 <= ep; p = np) {
		struct duid duid0;

		/*
		 * get the option header.  XXX: since there is no guarantee
		 * about the header alignment, we need to make a local copy.
		 */
		memcpy(&opth, p, sizeof(opth));
		optlen = ntohs(opth.dh6opt_len);
		opt = ntohs(opth.dh6opt_type);

		cp = (char *)(p + 1);
		np = (struct dhcp6opt *)(cp + optlen);

		dprintf(LOG_DEBUG, "%s" "get DHCP option %s, len %d",
		    FNAME, dhcpoptstr(opt), optlen);

		/* option length field overrun */
		if (np > ep) {
			dprintf(LOG_INFO,
			    "%s" "malformed DHCP options", FNAME);
			return -1;
		}

		switch (opt) {
		case DH6OPT_CLIENTID:
			if (optlen == 0)
				goto malformed;
			duid0.duid_len = optlen;
			duid0.duid_id = cp;
			dprintf(LOG_DEBUG, "  DUID: %s", duidstr(&duid0));
			if (duidcpy(&optinfo->clientID, &duid0)) {
				dprintf(LOG_ERR, "%s" "failed to copy DUID",
					FNAME);
				goto fail;
			}
			break;
		case DH6OPT_SERVERID:
			if (optlen == 0)
				goto malformed;
			duid0.duid_len = optlen;
			duid0.duid_id = cp;
			dprintf(LOG_DEBUG, "  DUID: %s", duidstr(&duid0));
			if (duidcpy(&optinfo->serverID, &duid0)) {
				dprintf(LOG_ERR, "%s" "failed to copy DUID",
					FNAME);
				goto fail;
			}
			break;
		case DH6OPT_STATUS_CODE:
			if (optlen < sizeof(u_int16_t))
				goto malformed;
			memcpy(&val16, cp, sizeof(val16));
			num = ntohs(val16);
			dprintf(LOG_DEBUG, "  status code: %d", num);

			/* need to check duplication? */

			if (dhcp6_add_listval(&optinfo->stcode_list,
				&num, DHCP6_LISTVAL_NUM) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to copy "
				    "status code", FNAME);
				goto fail;
			}

			break;
		case DH6OPT_ORO:
			if ((optlen % 2) != 0 || optlen == 0)
				goto malformed;
			reqopts = optlen / 2;
			for (i = 0, val = cp; i < reqopts;
			     i++, val += sizeof(u_int16_t)) {
				struct dhcp6_listval *opt;
				u_int16_t opttype;

				memcpy(&opttype, val, sizeof(u_int16_t));
				num = ntohs(opttype);

				dprintf(LOG_DEBUG, "  requested option: %s",
					dhcpoptstr(num));

				if (dhcp6_find_listval(&optinfo->reqopt_list,
					&num, DHCP6_LISTVAL_NUM)) {
					dprintf(LOG_INFO, "%s" "duplicated "
					    "option type (%s)", FNAME,
					    dhcpoptstr(opttype));
					goto nextoption;
				}

				if (dhcp6_add_listval(&optinfo->reqopt_list,
					&num, DHCP6_LISTVAL_NUM) == NULL) {
					dprintf(LOG_ERR, "%s" "failed to copy "
					    "requested option", FNAME);
					goto fail;
				}
			  nextoption:
			}
			break;
		case DH6OPT_PREFERENCE:
			if (optlen != 1)
				goto malformed;
			optinfo->pref = (int)*(u_char *)cp;
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
				if (dhcp6_find_listval(&optinfo->dns_list,
					&num, DHCP6_LISTVAL_ADDR6)) {
					dprintf(LOG_INFO, "%s" "duplicated "
					    "DNS address (%s)", FNAME,
					    in6addr2str((struct in6_addr *)val,
						0));
					goto nextdns;
				}

				if (dhcp6_add_listval(&optinfo->dns_list,
					val, DHCP6_LISTVAL_ADDR6) == NULL) {
					dprintf(LOG_ERR, "%s" "failed to copy "
					    "DNS address", FNAME);
					goto fail;
				}
			  nextdns:
			}
			break;
		case DH6OPT_PREFIX_DELEGATION:
			if (get_delegated_prefixes(cp, cp + optlen, optinfo))
				goto fail;
			break;
		default:
			/* no option specific behavior */
			dprintf(LOG_INFO, "%s"
			    "unknown or unexpected DHCP6 option %s, len %d",
			    FNAME, dhcpoptstr(opt), optlen);
			break;
		}
	}

	return(0);

  malformed:
	dprintf(LOG_INFO, "%s" "malformed DHCP option: type %d, len %d",
	    FNAME, opt, optlen);
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
	struct dhcp6_prefix prefix;
	struct dhcp6_listval *dp;
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
			dprintf(LOG_INFO, "%s" "malformed DHCP options",
			    FNAME);
			return -1;
		}

		switch(opt) {
		case DH6OPT_PREFIX_INFORMATION:
			if (optlen != sizeof(pi) - 4)
				goto malformed;

			memcpy(&pi, p, sizeof(pi));

			if (pi.dh6_pi_plen > 128) {
				dprintf(LOG_INFO, "%s" "invalid prefix length "
				    "(%d)", FNAME, pi.dh6_pi_plen);
				goto malformed;
			}

			/* clear padding bits in the prefix address */
			prefix6_mask(&pi.dh6_pi_paddr, pi.dh6_pi_plen);

			/* copy the information into internal format */
			memset(&prefix, 0, sizeof(prefix));
			prefix.addr = pi.dh6_pi_paddr;
			prefix.plen = pi.dh6_pi_plen;
			prefix.duration = ntohl(pi.dh6_pi_duration);

			if (prefix.duration != DHCP6_DURATITION_INFINITE) {
				dprintf(LOG_DEBUG, "  prefix information: "
				    "%s/%d duration %ld",
				    in6addr2str(&prefix.addr, 0),
				    prefix.plen, prefix.duration);
			} else {
				dprintf(LOG_DEBUG, "  prefix information: "
				    "%s/%d duration infinity",
				    in6addr2str(&prefix.addr, 0),
				    prefix.plen);
			}

			if (dhcp6_find_listval(&optinfo->prefix_list,
				&prefix, DHCP6_LISTVAL_PREFIX6)) {
				dprintf(LOG_INFO, "%s" "duplicated "
				    "prefix (%s/%d)", FNAME,
				    in6addr2str(&prefix.addr, 0),
				    prefix.plen);
				goto nextoption;
			}

			if (dhcp6_add_listval(&optinfo->prefix_list, &prefix,
				DHCP6_LISTVAL_PREFIX6) == NULL) {
				dprintf(LOG_ERR, "%s" "failed to copy a "
				    "prefix", FNAME);
				goto fail;
			}
		}

	  nextoption:
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
		dprintf(LOG_INFO, "%s" "option buffer short for %s", FNAME, dhcpoptstr((t))); \
		goto fail; \
	} \
	opth.dh6opt_type = htons((t)); \
	opth.dh6opt_len = htons((l)); \
	memcpy((p), &opth, sizeof(opth)); \
	if ((l)) \
		memcpy((p) + 1, (v), (l)); \
	(p) = (struct dhcp6opt *)((char *)((p) + 1) + (l)); \
 	(len) += sizeof(struct dhcp6opt) + (l); \
	dprintf(LOG_DEBUG, "%s" "set %s", FNAME, dhcpoptstr((t))); \
} while (0)

int
dhcp6_set_options(bp, ep, optinfo)
	struct dhcp6opt *bp, *ep;
	struct dhcp6_optinfo *optinfo;
{
	struct dhcp6opt *p = bp, opth;
	struct dhcp6_listval *stcode;
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

	if (optinfo->pref != DH6OPT_PREF_UNDEF) {
		u_int8_t p8 = (u_int8_t)optinfo->pref;

		COPY_OPTION(DH6OPT_PREFERENCE, sizeof(p8), &p8, p);
	}

	for (stcode = TAILQ_FIRST(&optinfo->stcode_list); stcode;
	     stcode = TAILQ_NEXT(stcode, link)) {
		u_int16_t code;

		code = htons(stcode->val_num);
		COPY_OPTION(DH6OPT_STATUS_CODE, sizeof(code), &code, p);
	}

	if (!TAILQ_EMPTY(&optinfo->reqopt_list)) {
		struct dhcp6_listval *opt;
		u_int16_t *valp;

		tmpbuf = NULL;
		optlen = dhcp6_count_list(&optinfo->reqopt_list) *
			sizeof(u_int16_t);
		if ((tmpbuf = malloc(optlen)) == NULL) {
			dprintf(LOG_ERR, "%s"
			    "memory allocation failed for options", FNAME);
			goto fail;
		}
		valp = (u_int16_t *)tmpbuf;
		for (opt = TAILQ_FIRST(&optinfo->reqopt_list); opt;
		     opt = TAILQ_NEXT(opt, link), valp++) {
			*valp = htons((u_int16_t)opt->val_num);
		}
		COPY_OPTION(DH6OPT_ORO, optlen, tmpbuf, p);
		free(tmpbuf);
	}

	if (!TAILQ_EMPTY(&optinfo->dns_list)) {
		struct in6_addr *in6;
		struct dhcp6_listval *d;

		tmpbuf = NULL;
		optlen = dhcp6_count_list(&optinfo->dns_list) *
			sizeof(struct in6_addr);
		if ((tmpbuf = malloc(optlen)) == NULL) {
			dprintf(LOG_ERR, "%s"
			    "memory allocation failed for DNS options", FNAME);
			goto fail;
		}
		in6 = (struct in6_addr *)tmpbuf;
		for (d = TAILQ_FIRST(&optinfo->dns_list); d;
		     d = TAILQ_NEXT(d, link), in6++) {
			memcpy(in6, &d->val_addr6, sizeof(*in6));
		}
		COPY_OPTION(DH6OPT_DNS, optlen, tmpbuf, p);
		free(tmpbuf);
	}

	if (!TAILQ_EMPTY(&optinfo->prefix_list)) {
		int pfxs;
		char *tp;
		struct dhcp6_listval *dp;
		struct dhcp6_prefix_info pi;

		tmpbuf = NULL;
		optlen = dhcp6_count_list(&optinfo->prefix_list) *
			sizeof(struct dhcp6_prefix_info);
		if ((tmpbuf = malloc(optlen)) == NULL) {
			dprintf(LOG_ERR, "%s"
				"memory allocation failed for options", FNAME);
			goto fail;
		}
		for (dp = TAILQ_FIRST(&optinfo->prefix_list), tp = tmpbuf; dp;
		     dp = TAILQ_NEXT(dp, link), tp += sizeof(pi)) {
			/*
			 * XXX: We need a temporary structure due to alignment
			 * issue.
			 */
			memset(&pi, 0, sizeof(pi));
			pi.dh6_pi_type = htons(DH6OPT_PREFIX_INFORMATION);
			pi.dh6_pi_len = htons(sizeof(pi) - 4);
			pi.dh6_pi_duration = htonl(dp->val_prefix6.duration);
			pi.dh6_pi_plen = dp->val_prefix6.plen;
			memcpy(&pi.dh6_pi_paddr, &dp->val_prefix6.addr,
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

void
dhcp6_set_timeoparam(ev)
	struct dhcp6_event *ev;
{
	ev->retrans = 0;
	ev->init_retrans = 0;
	ev->max_retrans_cnt = 0;
	ev->max_retrans_dur = 0;
	ev->max_retrans_time = 0;

	switch(ev->state) {
	case DHCP6S_SOLICIT:
		ev->init_retrans = SOL_TIMEOUT;
		ev->max_retrans_time = SOL_MAX_RT;
		break;
	case DHCP6S_INFOREQ:
		ev->init_retrans = INF_TIMEOUT;
		ev->max_retrans_time = INF_MAX_RT;
		break;
	case DHCP6S_REQUEST:
		ev->init_retrans = REQ_TIMEOUT;
		ev->max_retrans_time = REQ_MAX_RT;
		ev->max_retrans_cnt = REQ_MAX_RC;
		break;
	case DHCP6S_RENEW:
		ev->init_retrans = REN_TIMEOUT;
		ev->max_retrans_time = REN_MAX_RT;
		break;
	case DHCP6S_REBIND:
		ev->init_retrans = REB_TIMEOUT;
		ev->max_retrans_time = REB_MAX_RT;
		break;
	default:
		dprintf(LOG_INFO, "%s" "unexpected event state %d on %s",
		    FNAME, ev->state, ev->ifp->ifname);
		exit(1);
	}
}

void
dhcp6_reset_timer(ev)
	struct dhcp6_event *ev;
{
	double n, r;
	char *statestr;
	struct timeval interval;

	switch(ev->state) {
	case DHCP6S_INIT:
		/*
		 * The first Solicit message from the client on the interface
		 * MUST be delayed by a random amount of time between
		 * MIN_SOL_DELAY and MAX_SOL_DELAY.
		 * [dhcpv6-24 17.1.2]
		 */
		ev->retrans = (random() % (MAX_SOL_DELAY - MIN_SOL_DELAY)) +
			MIN_SOL_DELAY;
		break;
	default:
		if (ev->state == DHCP6S_SOLICIT && ev->timeouts == 0) {
			/*
			 * The first RT MUST be selected to be strictly
			 * greater than IRT by choosing RAND to be strictly
			 * greater than 0.
			 * [dhcpv6-24 17.1.2]
			 * Note: since RAND is between -0.1 and +0.1, RT is
			 * always greater than IRT, regardless of the value
			 * of RAND.  However, the authors of the draft chose
			 * to leave the spec as is.
			 */
			r = (double)(random() % 1000) / 10000;
			n = 2 * ev->init_retrans + r * ev->init_retrans;
		} else {
			r = (double)((random() % 2000) - 1000) / 10000;

			if (ev->timeouts == 0) {
				n = 2 * ev->init_retrans +
					r * ev->init_retrans;
			} else
				n = 2 * ev->retrans + r * ev->retrans;
		}
		if (ev->max_retrans_time && n > ev->max_retrans_time)
			n = ev->max_retrans_time + r * ev->max_retrans_time;
		ev->retrans = (long)n;
		break;
	}

	switch(ev->state) {
	case DHCP6S_INIT:
		statestr = "INIT";
		break;
	case DHCP6S_SOLICIT:
		statestr = "SOLICIT";
		break;
	case DHCP6S_INFOREQ:
		statestr = "INFOREQ";
		break;
	case DHCP6S_REQUEST:
		statestr = "REQUEST";
		break;
	case DHCP6S_RENEW:
		statestr = "RENEW";
		break;
	case DHCP6S_REBIND:
		statestr = "REBIND";
		break;
	case DHCP6S_IDLE:
		statestr = "IDLE";
		break;
	default:
		statestr = "???"; /* XXX */
		break;
	}

	interval.tv_sec = (ev->retrans * 1000) / 1000000;
	interval.tv_usec = (ev->retrans * 1000) % 1000000;
	dhcp6_set_timer(&interval, ev->timer);

	dprintf(LOG_DEBUG, "%s" "reset a timer on %s, "
		"state=%s, timeo=%d, retrans=%d", FNAME,
		ev->ifp->ifname, statestr, ev->timeouts, ev->retrans);
}

int
duidcpy(dd, ds)
	struct duid *dd, *ds;
{
	dd->duid_len = ds->duid_len;
	if ((dd->duid_id = malloc(dd->duid_len)) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed", FNAME);
		return(-1);
	}
	memcpy(dd->duid_id, ds->duid_id, dd->duid_len);

	return(0);
}

int
duidcmp(d1, d2)
	struct duid *d1, *d2;
{
	if (d1->duid_len == d2->duid_len) {
		return(memcmp(d1->duid_id, d2->duid_id, d1->duid_len));
	} else
		return(-1);
}

void
duidfree(duid)
	struct duid *duid;
{
	if (duid->duid_id)
		free(duid->duid_id);
	duid->duid_len = 0;
}

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
	case DH6OPT_PREFERENCE:
		return "preference";
	case DH6OPT_STATUS_CODE:
		return "status code";
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
	case DH6_ADVERTISE:
		return "advertise";
	case DH6_RENEW:
		return "renew";
	case DH6_REBIND:
		return "rebind";
	case DH6_REQUEST:
		return "request";
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

	if (foreground && debug_thresh >= level) {
		time_t now;
		struct tm *tm_now;

		if ((now = time(NULL)) < 0)
			exit(1); /* XXX */
		tm_now = localtime(&now);
		fprintf(stderr, "%04d/%02d/%02d %02d:%02d:%02d %s\n",
			tm_now->tm_year + 1900, tm_now->tm_mon,
			tm_now->tm_mday,
			tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
			logbuf);
	} else
		syslog(level, "%s", logbuf);
}
