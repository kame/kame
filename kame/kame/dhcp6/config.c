/*	$KAME: config.c,v 1.20 2002/06/14 15:32:55 jinmei Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
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
#include <sys/queue.h>

#include <net/if_dl.h>

#include <netinet/in.h>

#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>

#include <dhcp6.h>
#include <config.h>
#include <common.h>

extern int errno;

struct dhcp6_if *dhcp6_if;
struct prefix_ifconf *prefix_ifconflist;
struct dhcp6_list dnslist;

static struct dhcp6_ifconf *dhcp6_ifconflist;
static struct prefix_ifconf *prefix_ifconflist0;
static struct host_conf *host_conflist0, *host_conflist;
static struct dhcp6_list dnslist0; 

enum { DHCPOPTCODE_SEND, DHCPOPTCODE_REQUEST, DHCPOPTCODE_ALLOW };

extern struct cf_list *cf_dns_list;
extern char *configfilename;

static int add_options __P((int, struct dhcp6_ifconf *, struct cf_list *));
static int add_prefix __P((struct host_conf *, struct dhcp6_prefix *));
static void clear_ifconf __P((struct dhcp6_ifconf *));
static void clear_prefixifconf __P((struct prefix_ifconf *));
static void clear_hostconf __P((struct host_conf *));
static void clear_options __P((struct dhcp6_optconf *));
static int configure_duid __P((char *, struct duid *));
static int get_default_ifid __P((struct prefix_ifconf *));

void
ifinit(ifname)
	char *ifname;
{
	struct dhcp6_if *ifp;

	if ((ifp = find_ifconfbyname(ifname)) != NULL) {
		dprintf(LOG_NOTICE, "%s" "duplicated interface: %s",
			FNAME, ifname);
		return;
	}

	if ((ifp = malloc(sizeof(*ifp))) == NULL) {
		dprintf(LOG_ERR, "%s" "malloc failed", FNAME);
		goto die;
	}
	memset(ifp, 0, sizeof(*ifp));

	TAILQ_INIT(&ifp->event_list);

	if ((ifp->ifname = strdup(ifname)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to copy ifname", FNAME);
		goto die;
	}

	if ((ifp->ifid = if_nametoindex(ifname)) == 0) {
		dprintf(LOG_ERR, "%s" "invalid interface(%s): %s", FNAME,
			ifname, strerror(errno));
		goto die;
	}
#ifdef HAVE_SCOPELIB
	if (inet_zoneid(AF_INET6, 2, ifname, &ifp->linkid)) {
		dprintf(LOG_ERR, "%s" "failed to get link ID for %s",
			FNAME, ifname);
		goto die;
	}
#else
	ifp->linkid = ifp->ifid; /* XXX */
#endif

	ifp->next = dhcp6_if;
	dhcp6_if = ifp;
	return;

  die:
	exit(1);
}

int
configure_interface(iflist)
	struct cf_namelist *iflist;
{
	struct cf_namelist *ifp;
	struct dhcp6_ifconf *ifc;

	for (ifp = iflist; ifp; ifp = ifp->next) {
		struct cf_list *cfl;

		if ((ifc = malloc(sizeof(*ifc))) == NULL) {
			dprintf(LOG_ERR, "%s"
				"memory allocation for %s failed", FNAME,
				ifp->name);
			goto bad;
		}
		memset(ifc, 0, sizeof(*ifc));
		ifc->next = dhcp6_ifconflist;
		dhcp6_ifconflist = ifc;

		if ((ifc->ifname = strdup(ifp->name)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to copy ifname", FNAME);
			goto bad;
		}

		ifc->server_pref = DH6OPT_PREF_UNDEF;
		TAILQ_INIT(&ifc->reqopt_list);

		for (cfl = ifp->params; cfl; cfl = cfl->next) {
			switch(cfl->type) {
			case DECL_REQUEST:
				if (dhcp6_mode != DHCP6_MODE_CLIENT) {
					dprintf(LOG_INFO, "%s" "%s:%d "
						"client-only configuration",
						FNAME, configfilename,
						cfl->line);
					goto bad;
				}
				if (add_options(DHCPOPTCODE_REQUEST,
						ifc, cfl->list)) {
					goto bad;
				}
				break;
			case DECL_SEND:
				if (add_options(DHCPOPTCODE_SEND,
						ifc, cfl->list)) {
					goto bad;
				}
				break;
			case DECL_ALLOW:
				if (add_options(DHCPOPTCODE_ALLOW,
						ifc, cfl->list)) {
					goto bad;
				}
				break;
			case DECL_INFO_ONLY:
				if (dhcp6_mode != DHCP6_MODE_CLIENT) {
					dprintf(LOG_INFO, "%s" "%s:%d "
						"client-only configuration",
						FNAME, configfilename,
						cfl->line);
					goto bad;
				}
				ifc->send_flags |= DHCIFF_INFO_ONLY;
				break;
			case DECL_PREFERENCE:
				if (dhcp6_mode != DHCP6_MODE_SERVER) {
					dprintf(LOG_INFO, "%s" "%s:%d "
						"server-only configuration",
						FNAME, configfilename,
						cfl->line);
					goto bad;
				}
				ifc->server_pref = (int)cfl->num;
				if (ifc->server_pref < 0 ||
				    ifc->server_pref > 255) {
					dprintf(LOG_INFO, "%s" "%s:%d "
						"bad value: %d", FNAME,
						configfilename, cfl->line,
						ifc->server_pref);
					goto bad;
				}
				break;
			default:
				dprintf(LOG_ERR, "%s" "%s:%d "
					"invalid interface configuration",
					FNAME, configfilename, cfl->line);
				goto bad;
			}
		}
	}
	
	return(0);

  bad:
	clear_ifconf(dhcp6_ifconflist);
	dhcp6_ifconflist = NULL;
	return(-1);
}

int
configure_prefix_interface(iflist)
	struct cf_namelist *iflist;
{
	struct cf_namelist *ifp;
	struct prefix_ifconf *pif;

	for (ifp = iflist; ifp; ifp = ifp->next) {
		struct cf_list *cfl;

		if ((pif = malloc(sizeof(*pif))) == NULL) {
			dprintf(LOG_ERR, "%s"
				"memory allocation for %s failed", FNAME,
				ifp->name);
			goto bad;
		}
		memset(pif, 0, sizeof(*pif));
		pif->next = prefix_ifconflist0;
		prefix_ifconflist0 = pif;

		/* validate and copy ifname */
		if (if_nametoindex(ifp->name) == 0) {
			dprintf(LOG_ERR, "%s" "invalid interface (%s): %s",
				FNAME, ifp->name, strerror(errno));
			goto bad;
		}
		if ((pif->ifname = strdup(ifp->name)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to copy ifname", FNAME);
			goto bad;
		}

		pif->ifid_len = IFID_LEN_DEFAULT;
		pif->sla_len = SLA_LEN_DEFAULT;
		if (get_default_ifid(pif)) {
			dprintf(LOG_NOTICE, "%s"
				"failed to get default IF ID for %s",
				FNAME, pif->ifname);
			goto bad;
		}

		for (cfl = ifp->params; cfl; cfl = cfl->next) {
			switch(cfl->type) {
			case IFPARAM_SLA_ID:
				pif->sla_id = (u_int32_t)cfl->num;
				break;
			case IFPARAM_SLA_LEN:
				pif->sla_len = (int)cfl->num;
				if (pif->sla_len < 0 || pif->sla_len > 128) {
					dprintf(LOG_ERR, "%s"
					    "invalid SLA length: %d", FNAME,
					    pif->sla_len);
					goto bad;
				}
				break;
			default:
				dprintf(LOG_ERR, "%s" "%s:%d "
					"invalid configuration", FNAME,
					configfilename, cfl->line);
				goto bad;
			}
		}
	}
	
	return(0);

  bad:
	/* there is currently nothing special to recover the error */
	return(-1);
}

int
configure_host(hostlist)
	struct cf_namelist *hostlist;
{
	struct cf_namelist *host;
	struct host_conf *hconf;

	for (host = hostlist; host; host = host->next) {
		struct cf_list *cfl;

		if ((hconf = malloc(sizeof(*hconf))) == NULL) {
			dprintf(LOG_ERR, "%s" "memory allocation failed "
				"for host %s", FNAME, host->name);
			goto bad;
		}
		memset(hconf, 0, sizeof(*hconf));
		TAILQ_INIT(&hconf->prefix_list);
		TAILQ_INIT(&hconf->prefix_binding_list);
		hconf->next = host_conflist0;
		host_conflist0 = hconf;

		if ((hconf->name = strdup(host->name)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to copy host name: %s",
				FNAME, host->name);
			goto bad;
		}

		for (cfl = host->params; cfl; cfl = cfl->next) {
			switch(cfl->type) {
			case DECL_DUID:
				if (hconf->duid.duid_id) {
					dprintf(LOG_ERR, "%s" "%s:%d "
						"duplicated DUID for %s",
						FNAME, configfilename,
						cfl->line, host->name);
					goto bad;
				}
				if ((configure_duid((char *)cfl->ptr,
						    &hconf->duid)) != 0) {
					dprintf(LOG_ERR, "%s" "%s:%d "
						"failed to configure "
						"DUID for %s", FNAME,
						configfilename, cfl->line,
						host->name);
					goto bad;
				}
				dprintf(LOG_DEBUG, "%s"
					"configure DUID for %s: %s", FNAME,
					host->name, duidstr(&hconf->duid));
				break;
			case DECL_PREFIX:
				if (add_prefix(hconf, cfl->ptr)) {
					dprintf(LOG_ERR, "%s" "failed "
						"to configure prefix for %s",
						FNAME, host->name);
					goto bad;
				}
				break;
			default:
				dprintf(LOG_ERR, "%s" "%s:%d "
					"invalid host configuration for %s"
					FNAME, configfilename, cfl->line,
					host->name);
				goto bad;
			}
		}
	}

	return(0);

  bad:
	/* there is currently nothing special to recover the error */
	return(-1);
}

int
configure_global_option()
{
	struct cf_list *cl;

	/* DNS servers */
	if (cf_dns_list && dhcp6_mode != DHCP6_MODE_SERVER) {
		dprintf(LOG_INFO, "%s" "%s:%d server-only configuration",
		    FNAME, configfilename, cf_dns_list->line);
		goto bad;
	}
	TAILQ_INIT(&dnslist0);
	for (cl = cf_dns_list; cl; cl = cl->next) {
		/* duplication check */
		if (dhcp6_find_listval(&dnslist0, cl->ptr,
		    DHCP6_LISTVAL_ADDR6)) {
			dprintf(LOG_INFO, "%s"
			    "%s:%d duplicated DNS server: %s", FNAME,
			    configfilename, cl->line,
			    in6addr2str((struct in6_addr *)cl->ptr, 0));
			goto bad;
		}
		if (dhcp6_add_listval(&dnslist0, cl->ptr,
		    DHCP6_LISTVAL_ADDR6) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a DNS server");
			goto bad;
		}
	}

	return 0;

  bad:
	return -1;
}

static int
configure_duid(str, duid)
	char *str;		/* this is a valid DUID string */
	struct duid *duid;
{
	char *cp, *bp;
	char *idbuf = NULL;
	int duidlen, slen;

	/* calculate DUID len */
	slen = strlen(str);
	if (slen < 2)
		goto bad;
	duidlen = 1;
	slen -= 2;
	if ((slen % 3) != 0)
		goto bad;
	duidlen += (slen / 3);
	if (duidlen > 256) {
		dprintf(LOG_ERR, "%s" "too long DUID (%d)", FNAME, duidlen);
		return(-1);
	}

	if ((idbuf = malloc(sizeof(duidlen))) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed", FNAME);
		return(-1);
	}

	for (cp = str, bp = idbuf; *cp;) {
		if (*cp == ':') {
			cp++;
			continue;
		}

		if (sscanf(cp, "%02x", bp) != 1)
			goto bad;
		cp += 2;
		bp++;
	}

	duid->duid_len = duidlen;
	duid->duid_id = idbuf;

	return(0);

  bad:
	if (idbuf)
		free(idbuf);
	dprintf(LOG_ERR, "%s" "assumption failure (bad string)", FNAME);
	return(-1);
}

/* we currently only construct EUI-64 based interface ID */
static int
get_default_ifid(pif)
	struct prefix_ifconf *pif;
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr_dl *sdl;

	if (pif->ifid_len < 64) {
		dprintf(LOG_NOTICE, "%s" "ID length too short", FNAME);
		return -1;
	}

	if (getifaddrs(&ifap) < 0) {
		dprintf(LOG_ERR, "%s" "getifaddrs failed: %s",
			FNAME, strerror(errno));
		return -1;
	}
	
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		char *cp;

		if (strcmp(ifa->ifa_name, pif->ifname) != 0)
			continue;

		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen < 6) {
			dprintf(LOG_NOTICE, "%s"
				"link layer address is too short (%s)",
				FNAME, pif->ifname);
			goto fail;
		}

		memset(pif->ifid, 0, sizeof(pif->ifid));
		cp = (char *)(sdl->sdl_data + sdl->sdl_nlen);
		pif->ifid[8] = cp[0];
		pif->ifid[8] ^= 0x02; /* reverse the u/l bit*/
		pif->ifid[9] = cp[1];
		pif->ifid[10] = cp[2];
		pif->ifid[11] = 0xff;
		pif->ifid[12] = 0xfe;
		pif->ifid[13] = cp[3];
		pif->ifid[14] = cp[4];
		pif->ifid[15] = cp[5];

		break;
	}

	if (ifa == NULL) {
		dprintf(LOG_INFO, "%s"
			"cannot find interface information for %s",
			FNAME, pif->ifname);
		goto fail;
	}

	freeifaddrs(ifap);
	return(0);

  fail:
	freeifaddrs(ifap);
	return(-1);
}

void
configure_cleanup()
{
	clear_ifconf(dhcp6_ifconflist);
	dhcp6_ifconflist = NULL;
	clear_prefixifconf(prefix_ifconflist0);
	prefix_ifconflist0 = NULL;
	clear_hostconf(host_conflist0);
	host_conflist0 = NULL;
	dhcp6_clear_list(&dnslist0);
	TAILQ_INIT(&dnslist0);
}

void
configure_commit()
{
	struct dhcp6_ifconf *ifc;
	struct dhcp6_if *ifp;

	/* commit interface configuration */
	for (ifc = dhcp6_ifconflist; ifc; ifc = ifc->next) {
		if ((ifp = find_ifconfbyname(ifc->ifname)) != NULL) {
			ifp->send_flags = ifc->send_flags;

			ifp->allow_flags = ifc->allow_flags;

			clear_options(ifp->send_options);

			ifp->send_options = ifc->send_options;
			ifc->send_options = NULL;

			dhcp6_clear_list(&ifp->reqopt_list);
			ifp->reqopt_list = ifc->reqopt_list;
			TAILQ_INIT(&ifc->reqopt_list);

			ifp->server_pref = ifc->server_pref;
		}
	}
	clear_ifconf(dhcp6_ifconflist);

	/* commit prefix configuration */
	if (prefix_ifconflist) {
		/* clear previous configuration. (need more work?) */
		clear_prefixifconf(prefix_ifconflist);
	}
	prefix_ifconflist = prefix_ifconflist0;
	prefix_ifconflist0 = NULL;

	/* commit prefix configuration */
	if (host_conflist) {
		/* clear previous configuration. (need more work?) */
		clear_hostconf(host_conflist);
	}
	host_conflist = host_conflist0;
	host_conflist0 = NULL;

	/* commit DNS addresses */
	if (!TAILQ_EMPTY(&dnslist)) {
		dhcp6_clear_list(&dnslist);
	}
	dnslist = dnslist0;
	TAILQ_INIT(&dnslist0);
}

static void
clear_ifconf(iflist)
	struct dhcp6_ifconf *iflist;
{
	struct dhcp6_ifconf *ifc, *ifc_next;

	for (ifc = iflist; ifc; ifc = ifc_next) {
		ifc_next = ifc->next;

		free(ifc->ifname);
		clear_options(ifc->send_options);
		dhcp6_clear_list(&ifc->reqopt_list);

		free(ifc);
	}
}

static void
clear_prefixifconf(iflist)
	struct prefix_ifconf *iflist;
{
	struct prefix_ifconf *pif, *pif_next;

	for (pif = iflist; pif; pif = pif_next) {
		pif_next = pif->next;

		free(pif->ifname);
		free(pif);
	}
}

static void
clear_hostconf(hlist)
	struct host_conf *hlist;
{
	struct host_conf *host, *host_next;
	struct dhcp6_listval *p;

	for (host = hlist; host; host = host_next) {
		host_next = host->next;

		free(host->name);
		while (p = TAILQ_FIRST(&host->prefix_list)) {
			TAILQ_REMOVE(&host->prefix_list, p, link);
			free(p);
		}
		if (host->duid.duid_id)
			free(host->duid.duid_id);
		free(host);
	}
}

static void
clear_options(opt0)
	struct dhcp6_optconf *opt0;
{
	struct dhcp6_optconf *opt, *opt_next;

	for (opt = opt0; opt; opt = opt_next) {
		opt_next = opt->next;

		free(opt->val);
		free(opt);
	}
}

static int
add_options(opcode, ifc, cfl0)
	int opcode;
	struct dhcp6_ifconf *ifc;
	struct cf_list *cfl0;
{
	struct dhcp6_listval *opt;
	struct cf_list *cfl;
	int opttype;

	for (cfl = cfl0; cfl; cfl = cfl->next) {
		if (opcode ==  DHCPOPTCODE_REQUEST) {
			for (TAILQ_FIRST(&ifc->reqopt_list); opt;
			     opt = TAILQ_NEXT(opt, link)) {
				if (opt->val_num == cfl->type) {
					dprintf(LOG_INFO, "%s"
						"duplicated requested"
						" option: %s", FNAME,
						dhcp6optstr(cfl->type));
					goto next; /* ignore it */
				}
			}
		}

		switch(cfl->type) {
		case DHCPOPT_RAPID_COMMIT:
			switch(opcode) {
			case DHCPOPTCODE_SEND:
				ifc->send_flags |= DHCIFF_RAPID_COMMIT;
				break;
			case DHCPOPTCODE_ALLOW:
				ifc->allow_flags |= DHCIFF_RAPID_COMMIT;
				break;
			default:
				dprintf(LOG_ERR, "%s" "invalid operation (%d) "
					"for option type (%d)",
					FNAME, opcode, cfl->type);
				return(-1);
			}
			break;
		case DHCPOPT_PREFIX_DELEGATION:
			switch(opcode) {
			case DHCPOPTCODE_REQUEST:
				opttype = DH6OPT_PREFIX_DELEGATION;
				if (dhcp6_add_listval(&ifc->reqopt_list,
				    &opttype, DHCP6_LISTVAL_NUM) == NULL) {
					dprintf(LOG_ERR, "%s" "failed to "
					    "configure an option", FNAME);
					return(-1);
				}
				break;
			default:
				dprintf(LOG_ERR, "%s" "invalid operation (%d) "
					"for option type (%d)",
					FNAME, opcode, cfl->type);
				break;
			}
			break;
		case DHCPOPT_DNS:
			switch(opcode) {
			case DHCPOPTCODE_REQUEST:
				opttype = DH6OPT_DNS;
				if (dhcp6_add_listval(&ifc->reqopt_list,
				    &opttype, DHCP6_LISTVAL_NUM) == NULL) {
					dprintf(LOG_ERR, "%s" "failed to "
					    "configure an option", FNAME);
					return(-1);
				}
				break;
			default:
				dprintf(LOG_ERR, "%s" "invalid operation (%d) "
					"for option type (%d)",
					FNAME, opcode, cfl->type);
				break;
			}
			break;
		default:
			dprintf(LOG_ERR, "%s"
				"unknown option type: %d", FNAME, cfl->type);
				return(-1);
		}

	  next:
	}

	return(0);
}

static int
add_prefix(hconf, prefix0)
	struct host_conf *hconf;
	struct dhcp6_prefix *prefix0;
{
	struct dhcp6_prefix oprefix;
	struct dhcp6_listval *p, *pent;

	oprefix = *prefix0;

	/* additional validation of parameters */
	if (oprefix.plen < 0 || oprefix.plen > 128) {
		dprintf(LOG_ERR, "%s" "invalid prefix: %d",
			FNAME, oprefix.plen);
		return(-1);
	}
	/* clear trailing bits */
	prefix6_mask(&oprefix.addr, oprefix.plen);
	if (!IN6_ARE_ADDR_EQUAL(&prefix0->addr, &oprefix.addr)) {
		dprintf(LOG_WARNING, "%s" "prefix %s/%d for %s "
			"has a trailing garbage.  It should be %s/%d",
			FNAME, in6addr2str(&prefix0->addr, 0), prefix0->plen,
			hconf->name,
			in6addr2str(&oprefix.addr, 0), oprefix.plen);
		/* ignore the error */
	}

	/* avoid invalid prefix addresses */
	if (IN6_IS_ADDR_MULTICAST(&oprefix.addr) ||
	    IN6_IS_ADDR_LINKLOCAL(&oprefix.addr) ||
	    IN6_IS_ADDR_SITELOCAL(&oprefix.addr)) {
		dprintf(LOG_ERR, "%s" "invalid prefix address: %s",
			FNAME, in6addr2str(&oprefix.addr, 0));
		return(-1);
	}

	/* prefix duplication check */
	for (p = TAILQ_FIRST(&hconf->prefix_list); p;
	     p = TAILQ_NEXT(p, link)) {
		if (IN6_ARE_ADDR_EQUAL(&p->val_prefix6.addr, &oprefix.addr) &&
		    p->val_prefix6.plen == oprefix.plen) {
			dprintf(LOG_ERR, "%s"
				"duplicated prefix: %s/%d for %s", FNAME,
				in6addr2str(&oprefix.addr, 0), oprefix.plen,
				hconf->name);
			return(-1);
		}
	}

	/* allocate memory for the new prefix and insert it to the chain */
	if ((pent = malloc(sizeof(*pent))) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed for %s",
			FNAME, hconf->name);
		return(-1);
	}
	memset(pent, 0, sizeof(*pent));
	pent->val_prefix6 = oprefix;
	TAILQ_INSERT_TAIL(&hconf->prefix_list, pent, link);

	return(0);
}

struct dhcp6_if *
find_ifconfbyname(ifname)
	char *ifname;
{
	struct dhcp6_if *ifp;

	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		if (strcmp(ifp->ifname, ifname) == 0)
			return(ifp);
	}

	return(NULL);
}

struct dhcp6_if *
find_ifconfbyid(id)
	unsigned int id;
{
	struct dhcp6_if *ifp;

	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		if (ifp->ifid == id)
			return(ifp);
	}

	return(NULL);
}

struct prefix_ifconf *
find_prefixifconf(ifname)
	char *ifname;
{
	struct prefix_ifconf *ifp;

	for (ifp = prefix_ifconflist; ifp; ifp = ifp->next) {
		if (strcmp(ifp->ifname, ifname) == NULL)
			return(ifp);
	}

	return(NULL);
}

struct host_conf *
find_hostconf(duid)
	struct duid *duid;
{
	struct host_conf *host;

	for (host = host_conflist; host; host = host->next) {
		if (host->duid.duid_len == duid->duid_len &&
		    memcmp(host->duid.duid_id, duid->duid_id,
			   host->duid.duid_len) == 0) {
			return(host);
		}
	}

	return(NULL);
}

struct dhcp6_prefix *
find_prefix6(list, prefix)
	struct dhcp6_list *list;
	struct dhcp6_prefix *prefix;
{
	struct dhcp6_listval *v;

	for (v = TAILQ_FIRST(list); v; v = TAILQ_NEXT(v, link)) {
		if (v->val_prefix6.plen == prefix->plen &&
		    IN6_ARE_ADDR_EQUAL(&v->val_prefix6.addr, &prefix->addr)) {
			return(&v->val_prefix6);
		}
	}
}
