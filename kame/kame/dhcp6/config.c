/*	$KAME: config.c,v 1.27 2003/02/07 12:22:03 jinmei Exp $	*/

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

#include <net/if.h>
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
struct ia_conflist ia_conflist0;
static struct host_conf *host_conflist0, *host_conflist;
static struct dhcp6_list dnslist0; 

enum { DHCPOPTCODE_SEND, DHCPOPTCODE_REQUEST, DHCPOPTCODE_ALLOW };

/* temporary configuration structure for DHCP interface */
struct dhcp6_ifconf {
	struct dhcp6_ifconf *next;

	char *ifname;

	/* configuration flags */
	u_long send_flags;
	u_long allow_flags;

	int server_pref;	/* server preference (server only) */

	struct dhcp6_list reqopt_list;
	struct ia_conflist iaconf_list;
};

extern struct cf_list *cf_dns_list;
extern char *configfilename;

static int add_pd_pif __P((struct iapd_conf *, struct cf_list *));
static int add_options __P((int, struct dhcp6_ifconf *, struct cf_list *));
static int add_prefix __P((struct dhcp6_list *, char *,
    struct dhcp6_prefix *));
static void clear_pd_pif __P((struct iapd_conf *));
static void clear_ifconf __P((struct dhcp6_ifconf *));
static void clear_iaconf __P((struct ia_conflist *));
static void clear_hostconf __P((struct host_conf *));
static int configure_duid __P((char *, struct duid *));
static int get_default_ifid __P((struct prefix_ifconf *));
static struct ia_conf *find_iaconf_fromhead __P((struct ia_conflist *,
    int, u_int32_t));

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

	TAILQ_INIT(&ifp->reqopt_list);
	TAILQ_INIT(&ifp->iaconf_list);

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
		TAILQ_INIT(&ifc->iaconf_list);

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
	
	return (0);

  bad:
	clear_ifconf(dhcp6_ifconflist);
	dhcp6_ifconflist = NULL;
	return (-1);
}

int
configure_ia(ialist, iatype)
	struct cf_namelist *ialist;
	iatype_t iatype;
{
	struct cf_namelist *iap;
	struct ia_conf *iac = NULL;
	size_t confsize;

	TAILQ_INIT(&ia_conflist0);

	switch(iatype) {
	case IATYPE_PD:
		confsize = sizeof(struct iapd_conf);
		break;
	default:
		dprintf(LOG_ERR, "%s" "internal error", FNAME);
		goto bad;
	}

	for (iap = ialist; iap; iap = iap->next) {
		struct cf_list *cfl;

		if ((iac = malloc(confsize)) == NULL) {
			dprintf(LOG_ERR, "%s"
				"memory allocation for IA %s failed", FNAME,
				iap->name);
			goto bad;
		}
		memset(iac, 0, confsize);

		/* common initialization */
		iac->type = iatype;
		iac->iaid = (u_int32_t)atoi(iap->name);
		TAILQ_INIT(&iac->iadata);
		TAILQ_INSERT_TAIL(&ia_conflist0, iac, link);

		/* IA-type specific initialization */
		switch(iatype) {
		case IATYPE_PD:
			TAILQ_INIT(&((struct iapd_conf *)iac)->iapd_prefix_list);
			TAILQ_INIT(&((struct iapd_conf *)iac)->iapd_pif_list);
			break;
		}

		/* set up parameters for the IA */
		for (cfl = iap->params; cfl; cfl = cfl->next) {
			/* sanity check */
			if ((cfl->type == IACONF_PIF ||
			    cfl->type == IACONF_PREFIX) &&
			    iatype != IATYPE_PD) {
				if (iatype != IATYPE_PD) {
					dprintf(LOG_ERR, "%s" "%s:%d "
					    "internal error "
					    "(IA type mismatch)",
					    FNAME, configfilename, cfl->line);
				}
			}

			switch(cfl->type) {
			case IACONF_PIF:
				if (add_pd_pif((struct iapd_conf *)iac, cfl))
					goto bad;
				break;
			case IACONF_PREFIX:
				if (add_prefix(&((struct iapd_conf *)iac)->iapd_prefix_list,
				    "IAPD", cfl->ptr)) {
					dprintf(LOG_NOTICE, "%s" "failed "
						"to configure prefix", FNAME);
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

	return (0);

  bad:
	return (-1);
}

static int
add_pd_pif(iapdc, cfl0)
	struct iapd_conf *iapdc;
	struct cf_list *cfl0;
{
	struct cf_list *cfl;
	struct prefix_ifconf *pif;

	/* duplication check */
	for (pif = TAILQ_FIRST(&iapdc->iapd_pif_list); pif;
	    pif = TAILQ_NEXT(pif, link)) {
		if (strcmp(pif->ifname, cfl0->ptr) == 0) {
			dprintf(LOG_NOTICE, "%s" "%s:%d "
			    "duplicated prefix interface: %s",
			    FNAME, configfilename, cfl0->line, cfl0->ptr);
			return (0); /* ignore it */
		}
	}

	if ((pif = malloc(sizeof(*pif))) == NULL) {
		dprintf(LOG_ERR, "%s"
		    "memory allocation for %s failed", FNAME, cfl0->ptr);
		goto bad;
	}
	memset(pif, 0, sizeof(*pif));

	/* validate and copy ifname */
	if (if_nametoindex(cfl0->ptr) == 0) {
		dprintf(LOG_ERR, "%s" "%s:%d invalid interface (%s): %s",
		    FNAME, configfilename, cfl0->line,
		    cfl0->ptr, strerror(errno));
		goto bad;
	}
	if ((pif->ifname = strdup(cfl0->ptr)) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to copy ifname", FNAME);
		goto bad;
	}

	pif->ifid_len = IFID_LEN_DEFAULT;
	pif->sla_len = SLA_LEN_DEFAULT;
	if (get_default_ifid(pif)) {
		dprintf(LOG_NOTICE, "%s" "failed to get default IF ID for %s",
		    FNAME, pif->ifname);
		goto bad;
	}

	for (cfl = cfl0->list; cfl; cfl = cfl->next) {
		switch(cfl->type) {
		case IFPARAM_SLA_ID:
			pif->sla_id = (u_int32_t)cfl->num;
			break;
		case IFPARAM_SLA_LEN:
			pif->sla_len = (int)cfl->num;
			if (pif->sla_len < 0 || pif->sla_len > 128) {
				dprintf(LOG_ERR, "%s" "%s:%d "
				    "invalid SLA length: %d", FNAME,
				    configfilename, cfl->line, pif->sla_len); 
				goto bad;
			}
			break;
		default:
			dprintf(LOG_ERR, "%s" "%s:%d internal error: "
			    "invalid configuration", FNAME,
			    configfilename, cfl->line);
			goto bad;
		}
	}

	TAILQ_INSERT_TAIL(&iapdc->iapd_pif_list, pif, link);
	return (0);

  bad:
	if (pif->ifname)
		free(pif->ifname);
	free(pif);
	return (-1);
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
				if (add_prefix(&hconf->prefix_list,
				    hconf->name, cfl->ptr)) {
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

	return (0);

  bad:
	/* there is currently nothing special to recover the error */
	return (-1);
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
		if (dhcp6_find_listval(&dnslist0, DHCP6_LISTVAL_ADDR6,
		    cl->ptr, 0)) {
			dprintf(LOG_INFO, "%s"
			    "%s:%d duplicated DNS server: %s", FNAME,
			    configfilename, cl->line,
			    in6addr2str((struct in6_addr *)cl->ptr, 0));
			goto bad;
		}
		if (dhcp6_add_listval(&dnslist0, DHCP6_LISTVAL_ADDR6,
		    cl->ptr, NULL) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a DNS server");
			goto bad;
		}
	}

	return (0);

  bad:
	return (-1);
}

static int
configure_duid(str, duid)
	char *str;		/* this is a valid DUID string */
	struct duid *duid;
{
	char *cp, *bp;
	char *idbuf = NULL;
	int duidlen, slen;
	unsigned int x;

	/* calculate DUID len */
	slen = strlen(str);
	if (slen < 2)
		goto bad;
	duidlen = 1;
	slen -= 2;
	if ((slen % 3) != 0)
		goto bad;
	duidlen += (slen / 3);
	if (duidlen > 128) {
		dprintf(LOG_ERR, "%s" "too long DUID (%d)", FNAME, duidlen);
		return (-1);
	}

	if ((idbuf = malloc(sizeof(duidlen))) == NULL) {
		dprintf(LOG_ERR, "%s" "memory allocation failed", FNAME);
		return (-1);
	}

	for (cp = str, bp = idbuf; *cp;) {
		if (*cp == ':') {
			cp++;
			continue;
		}

		if (sscanf(cp, "%02x", &x) != 1)
			goto bad;
		*bp = x;
		cp += 2;
		bp++;
	}

	duid->duid_len = duidlen;
	duid->duid_id = idbuf;

	return (0);

  bad:
	if (idbuf)
		free(idbuf);
	dprintf(LOG_ERR, "%s" "assumption failure (bad string)", FNAME);
	return (-1);
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
		return (-1);
	}

	if (getifaddrs(&ifap) < 0) {
		dprintf(LOG_ERR, "%s" "getifaddrs failed: %s",
			FNAME, strerror(errno));
		return (-1);
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
	return (0);

  fail:
	freeifaddrs(ifap);
	return (-1);
}

void
configure_cleanup()
{
	clear_iaconf(&ia_conflist0);
	clear_ifconf(dhcp6_ifconflist);
	dhcp6_ifconflist = NULL;
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
	struct ia_conf *iac;

	/* commit interface configuration */
	for (ifc = dhcp6_ifconflist; ifc; ifc = ifc->next) {
		if ((ifp = find_ifconfbyname(ifc->ifname)) != NULL) {
			ifp->send_flags = ifc->send_flags;

			ifp->allow_flags = ifc->allow_flags;

			dhcp6_clear_list(&ifp->reqopt_list);
			dhcp6_move_list(&ifp->reqopt_list, &ifc->reqopt_list);

			clear_iaconf(&ifp->iaconf_list);
			while ((iac = TAILQ_FIRST(&ifc->iaconf_list))
			    != NULL) {
				TAILQ_REMOVE(&ia_conflist0, iac, link);
				TAILQ_INSERT_TAIL(&ifp->iaconf_list,
				    iac, link);
			}

			ifp->server_pref = ifc->server_pref;
		}
	}
	clear_ifconf(dhcp6_ifconflist);
	dhcp6_ifconflist = NULL;

	/* clear unused IA configuration */
	if (!TAILQ_EMPTY(&ia_conflist0)) {
		dprintf(LOG_INFO, "%s" "some IA configuration defined "
		    "but not used", FNAME);
	}
	clear_iaconf(&ia_conflist0);

	/* commit per-host configuration */
	clear_hostconf(host_conflist);
	host_conflist = host_conflist0;
	host_conflist0 = NULL;

	/* commit DNS addresses */
	dhcp6_clear_list(&dnslist);
	dhcp6_move_list(&dnslist, &dnslist0);
}

static void
clear_ifconf(iflist)
	struct dhcp6_ifconf *iflist;
{
	struct dhcp6_ifconf *ifc, *ifc_next;

	for (ifc = iflist; ifc; ifc = ifc_next) {
		ifc_next = ifc->next;

		free(ifc->ifname);
		dhcp6_clear_list(&ifc->reqopt_list);

		clear_iaconf(&ifc->iaconf_list);

		free(ifc);
	}
}

static void
clear_pd_pif(iapdc)
	struct iapd_conf *iapdc;
{
	struct prefix_ifconf *pif, *pif_next;

	for (pif = TAILQ_FIRST(&iapdc->iapd_pif_list); pif; pif = pif_next) {
		pif_next = TAILQ_NEXT(pif, link);

		free(pif->ifname);
		free(pif);
	}

	dhcp6_clear_list(&iapdc->iapd_prefix_list);
}

static void
clear_iaconf(ialist)
	struct ia_conflist *ialist;
{
	struct ia_conf *iac;

	while ((iac = TAILQ_FIRST(ialist)) != NULL) {
		TAILQ_REMOVE(ialist, iac, link);

		if (!TAILQ_EMPTY(&iac->iadata)) {
			dprintf(LOG_ERR, "%s" "assumption failure", FNAME);
			exit(1);
		}

		switch(iac->type) {
		case IATYPE_PD:
			clear_pd_pif((struct iapd_conf *)iac);
			break;
		}
		free(iac);
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
		dhcp6_clear_list(&host->prefix_list);
		if (host->duid.duid_id)
			free(host->duid.duid_id);
		free(host);
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
	struct ia_conf *iac;

	for (cfl = cfl0; cfl; cfl = cfl->next) {
		if (opcode ==  DHCPOPTCODE_REQUEST) {
			for (opt = TAILQ_FIRST(&ifc->reqopt_list); opt;
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
				return (-1);
			}
			break;
		case DHCPOPT_IA_PD:
			switch(opcode) {
			case DHCPOPTCODE_SEND:
				iac = find_iaconf(&ia_conflist0, IATYPE_PD,
				    (u_int32_t)cfl->num);
				if (iac == NULL) {
					dprintf(LOG_ERR, "%s" "%s:%d "
					    "IA_PD (%lu) is not defined",
					    FNAME, configfilename, cfl->line,
					    (u_long)cfl->num);
					return (-1);
				}

				TAILQ_REMOVE(&ia_conflist0, iac, link);
				TAILQ_INSERT_TAIL(&ifc->iaconf_list,
				    iac, link);

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
				    DHCP6_LISTVAL_NUM, &opttype, NULL)
				    == NULL) {
					dprintf(LOG_ERR, "%s" "failed to "
					    "configure an option", FNAME);
					return (-1);
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
			dprintf(LOG_ERR, "%s" "%s:%d "
			    "unsupported option type: %d",
			    FNAME, configfilename, cfl->line, cfl->type);
			return (-1);
		}

	  next:
	}

	return (0);
}

static int
add_prefix(head, name, prefix0)
	struct dhcp6_list *head;
	char *name;
	struct dhcp6_prefix *prefix0;
{
	struct dhcp6_prefix oprefix;

	oprefix = *prefix0;

	/* additional validation of parameters */
	if (oprefix.plen < 0 || oprefix.plen > 128) {
		dprintf(LOG_ERR, "%s" "invalid prefix: %d",
			FNAME, oprefix.plen);
		return (-1);
	}
	/* clear trailing bits */
	prefix6_mask(&oprefix.addr, oprefix.plen);
	if (!IN6_ARE_ADDR_EQUAL(&prefix0->addr, &oprefix.addr)) {
		dprintf(LOG_WARNING, "%s" "prefix %s/%d for %s "
		    "has a trailing garbage.  It should be %s/%d",
		    FNAME, in6addr2str(&prefix0->addr, 0), prefix0->plen,
		    name, in6addr2str(&oprefix.addr, 0), oprefix.plen);
		/* ignore the error */
	}

	/* avoid invalid prefix addresses */
	if (IN6_IS_ADDR_MULTICAST(&oprefix.addr) ||
	    IN6_IS_ADDR_LINKLOCAL(&oprefix.addr) ||
	    IN6_IS_ADDR_SITELOCAL(&oprefix.addr)) {
		dprintf(LOG_ERR, "%s" "invalid prefix address: %s",
			FNAME, in6addr2str(&oprefix.addr, 0));
		return (-1);
	}

	/* prefix duplication check */
	if (dhcp6_find_listval(head, DHCP6_LISTVAL_PREFIX6,
	    &oprefix, 0)) {
		dprintf(LOG_NOTICE, "%s"
		    "duplicated prefix: %s/%d for %s", FNAME,
		    in6addr2str(&oprefix.addr, 0), oprefix.plen, name);
		return (-1);
	}

	/* validation about relationship of pltime and vltime */
	if (oprefix.vltime != DHCP6_DURATITION_INFINITE &&
	    (oprefix.pltime == DHCP6_DURATITION_INFINITE ||
	    oprefix.pltime > oprefix.vltime)) {
		dprintf(LOG_NOTICE, "%s" "%s/%d has larger preferred lifetime "
		    "than valid lifetime", FNAME,
		    in6addr2str(&oprefix.addr, 0), oprefix.plen);
		return (-1);
	}

	/* insert the new prefix to the chain */
	if (dhcp6_add_listval(head, DHCP6_LISTVAL_PREFIX6,
	    &oprefix, NULL) == NULL) {
		return (-1);
	}

	return (0);
}

struct dhcp6_if *
find_ifconfbyname(ifname)
	char *ifname;
{
	struct dhcp6_if *ifp;

	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		if (strcmp(ifp->ifname, ifname) == 0)
			return (ifp);
	}

	return (NULL);
}

struct dhcp6_if *
find_ifconfbyid(id)
	unsigned int id;
{
	struct dhcp6_if *ifp;

	for (ifp = dhcp6_if; ifp; ifp = ifp->next) {
		if (ifp->ifid == id)
			return (ifp);
	}

	return (NULL);
}

struct ia_conf *
find_iaconf(head, type, iaid)
	struct ia_conflist *head;
	int type;
	u_int32_t iaid;
{
	struct ia_conf *iac;

	for (iac = TAILQ_FIRST(head); iac; iac = TAILQ_NEXT(iac, link)) {
		if (iac->type == type && iac->iaid == iaid)
			return (iac);
	}

	return (NULL);
}

#if 0
struct ia_conf *
find_iaconf(type, iaid)
	int type;
	u_int32_t iaid;
{
	return (find_iaconf_fromhead(ia_conflist, type, iaid));
}
#endif

struct host_conf *
find_hostconf(duid)
	struct duid *duid;
{
	struct host_conf *host;

	for (host = host_conflist; host; host = host->next) {
		if (host->duid.duid_len == duid->duid_len &&
		    memcmp(host->duid.duid_id, duid->duid_id,
			   host->duid.duid_len) == 0) {
			return (host);
		}
	}

	return (NULL);
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
			return (&v->val_prefix6);
		}
	}
	return (NULL);
}
