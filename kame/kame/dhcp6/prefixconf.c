/*	$KAME: prefixconf.c,v 1.3 2002/05/22 12:42:41 jinmei Exp $	*/

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
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ioctl.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif

#include <netinet/in.h>

#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "prefixconf.h"

/* should be moved to a header file later */
struct dhcp6_ifprefix {
	TAILQ_ENTRY(dhcp6_ifprefix) plink;

	/* interface configuration */
	struct prefix_ifconf *ifconf;

	/* interface prefix parameters */
	struct sockaddr_in6 paddr;
	int plen;

	/* address assigned on the interface based on the prefix */
	struct sockaddr_in6 ifaddr;
};
static TAILQ_HEAD(, dhcp6_siteprefix) siteprefix_listhead;

typedef enum { IFADDRCONF_ADD, IFADDRCONF_REMOVE } ifaddrconf_cmd_t;

static int ifaddrconf __P((ifaddrconf_cmd_t, struct dhcp6_ifprefix *));
static struct dhcp6_siteprefix *find_siteprefix6 __P((struct dhcp6_prefix *));
static struct dhcp6_timer *prefix6_timo __P((void *));
static int add_ifprefix __P((struct dhcp6_prefix *, struct prefix_ifconf *));
static void prefix6_remove __P((struct dhcp6_siteprefix *));
static int update __P((struct dhcp6_siteprefix *, struct dhcp6_prefix *));

extern struct dhcp6_timer *client6_timo __P((void *));
extern void client6_send_renew __P((struct dhcp6_event *));

void
prefix6_init()
{
	TAILQ_INIT(&siteprefix_listhead);
}

int
prefix6_add(ifp, prefix)
	struct dhcp6_if *ifp;
	struct dhcp6_prefix *prefix;
{
	struct prefix_ifconf *pif;
	struct dhcp6_siteprefix *sp;

	dprintf(LOG_DEBUG, "%s" "try to add prefix %s/%d", FNAME,
		in6addr2str(&prefix->addr, 0), prefix->plen);

	/* ignore meaningless prefix */
	if (prefix->duration == 0) {
		dprintf(LOG_INFO, "%s" "zero duration for %s/%d",
			in6addr2str(&prefix->addr, 0), prefix->plen);
		return 0;
	}

	if ((sp = find_siteprefix6(prefix)) != NULL) {
		dprintf(LOG_INFO, "%s" "duplicated delegated prefix: %s/%d",
		    FNAME, in6addr2str(&prefix->addr, 0), prefix->plen);
		return -1;
	}

	if ((sp = malloc(sizeof(*sp))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory"
			" for a prefix", FNAME);
		return -1;
	}
	memset(sp, 0, sizeof(*sp));
	TAILQ_INIT(&sp->ifprefix_list);
	sp->prefix = *prefix;
	sp->ifp = ifp;
	sp->state = PREFIX6S_ACTIVE;

	/* if an finite lease duration is specified, set up a timer. */
	if (sp->prefix.duration != DHCP6_DURATITION_INFINITE) {
		struct timeval timo;

		if ((sp->timer = dhcp6_add_timer(prefix6_timo, sp)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to add a timer for "
				"prefix %s/%d",
				in6addr2str(&prefix->addr, 0), prefix->plen);
			goto fail;
		}
		
		timo.tv_sec = sp->prefix.duration >> 1;
		timo.tv_usec = 0;

		dhcp6_set_timer(&timo, sp->timer);
	}

	for (pif = prefix_ifconflist; pif; pif = pif->next) {
		if (strcmp(pif->ifname, ifp->ifname)) {
			add_ifprefix(prefix, pif);
		}
	}

	TAILQ_INSERT_TAIL(&siteprefix_listhead, sp, link);

	return 0;

  fail:
	free(sp);
	return -1;
}

static void
prefix6_remove(sp)
	struct dhcp6_siteprefix *sp;
{
	struct dhcp6_ifprefix *ipf;

	dprintf(LOG_DEBUG, "%s" "removing prefix %s/%d", FNAME,
	    in6addr2str(&sp->prefix.addr, 0), sp->prefix.plen);

	while ((ipf = TAILQ_FIRST(&sp->ifprefix_list)) != NULL) {
		TAILQ_REMOVE(&sp->ifprefix_list, ipf, plink);
		ifaddrconf(IFADDRCONF_REMOVE, ipf);
		free(ipf);
	}

	if (sp->timer)
		dhcp6_remove_timer(&sp->timer);

	if (sp->evdata) {
		TAILQ_REMOVE(&sp->evdata->event->data_list, sp->evdata, link);
		free(sp->evdata);
		sp->evdata = NULL;
	}

	TAILQ_REMOVE(&siteprefix_listhead, sp, link);

	free(sp);
}

int
prefix6_update(ev, prefix_list)
	struct dhcp6_event *ev;
	struct dhcp6_list *prefix_list;
{
	struct dhcp6_listval *lv;
	struct dhcp6_eventdata *evd, *evd_next;
	struct dhcp6_siteprefix *sp;

	/* add new prefixes */
	for (lv = TAILQ_FIRST(prefix_list); lv; lv = TAILQ_NEXT(lv, link)) {

		if (find_siteprefix6(&lv->val_prefix6) != NULL)
			continue;

		if (prefix6_add(ev->ifp, &lv->val_prefix6)) {
			dprintf(LOG_INFO, "%s" "failed to add a new prefix");
			/* continue updating */
		}
	}

	/* update existing prefixes */
	for (evd = TAILQ_FIRST(&ev->data_list); evd; evd = evd_next) {
		evd_next = TAILQ_NEXT(evd, link);

		if (evd->type != DHCP6_DATA_PREFIX)
			continue;

		lv = dhcp6_find_listval(prefix_list,
		    &((struct dhcp6_siteprefix *)evd->data)->prefix,
		    DHCP6_LISTVAL_PREFIX6);
		if (lv == NULL)
			continue;

		TAILQ_REMOVE(&ev->data_list, evd, link);
		((struct dhcp6_siteprefix *)evd->data)->evdata = NULL;

		update((struct dhcp6_siteprefix *)evd->data, &lv->val_prefix6);

		free(evd);		    
	}

	/* remove prefixes that were not updated */
	for (evd = TAILQ_FIRST(&ev->data_list); evd; evd = evd_next) {
		evd_next = TAILQ_NEXT(evd, link);

		if (evd->type != DHCP6_DATA_PREFIX)
			continue;

		TAILQ_REMOVE(&ev->data_list, evd, link);
		((struct dhcp6_siteprefix *)evd->data)->evdata = NULL;

		prefix6_remove((struct dhcp6_siteprefix *)evd->data);

		free(evd);
	}

	return 0;
}

static int
update(sp, prefix)
	struct dhcp6_siteprefix *sp;
	struct dhcp6_prefix *prefix;
{
	struct timeval timo;

	if (prefix->duration == DHCP6_DURATITION_INFINITE) {
		dprintf(LOG_DEBUG, "%s" "update a prefix %s/%d "
		    "with infinite duration", FNAME,
		    in6addr2str(&prefix->addr, 0), prefix->plen,
		    prefix->duration);
	} else {
		dprintf(LOG_DEBUG, "%s" "update a prefix %s/%d "
		    "with duration %d", FNAME,
		    in6addr2str(&prefix->addr, 0), prefix->plen,
		    prefix->duration);
	}
 
	sp->prefix.duration = prefix->duration;

	switch(sp->prefix.duration) {
	case 0:
		prefix6_remove(sp);
		return 0;
	case DHCP6_DURATITION_INFINITE:
		if (sp->timer)
			dhcp6_remove_timer(&sp->timer);
		break;
	default:
		if (sp->timer == NULL) {
			sp->timer = dhcp6_add_timer(prefix6_timo, sp);
			if (sp->timer == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add prefix "
				    "timer", FNAME);
				prefix6_remove(sp); /* XXX */
				return -1;
			}
		}
		/* update the timer */
		timo.tv_sec = sp->prefix.duration >> 1;
		timo.tv_usec = 0;

		dhcp6_set_timer(&timo, sp->timer);
		break;
	}

	sp->state = PREFIX6S_ACTIVE;

	return 0;
}

static struct dhcp6_siteprefix *
find_siteprefix6(prefix)
	struct dhcp6_prefix *prefix;
{
	struct dhcp6_siteprefix *sp;

	for (sp = TAILQ_FIRST(&siteprefix_listhead); sp;
	     sp = TAILQ_NEXT(sp, link)) {
		if (sp->prefix.plen == prefix->plen &&
		    IN6_ARE_ADDR_EQUAL(&sp->prefix.addr, &prefix->addr)) {
			return(sp);
		}
	}

	return(NULL);
}

static struct dhcp6_timer *
prefix6_timo(arg)
	void *arg;
{
	struct dhcp6_siteprefix *sp = (struct dhcp6_siteprefix *)arg;
	struct dhcp6_event *ev;
	struct dhcp6_eventdata *evd;
	struct timeval timeo;
	struct dhcp6_timer *new_timer = NULL;
	double d;

	dprintf(LOG_DEBUG, "%s" "prefix timeout for %s/%d, state=%d", FNAME,
		in6addr2str(&sp->prefix.addr, 0), sp->prefix.plen, sp->state);

	switch(sp->state) {
	case PREFIX6S_ACTIVE:
		sp->state = PREFIX6S_RENEW;
		d = sp->prefix.duration * 0.3; /* (0.8 - 0.5) * duration */
		timeo.tv_sec = (long)d;
		timeo.tv_usec = 0;
		new_timer = sp->timer;

		if ((ev = dhcp6_create_event(sp->ifp, DHCP6S_RENEW)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to create a new event"
				FNAME);
			exit(1); /* XXX: should try to recover */
		}
		if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to create a new event "
				"timer", FNAME);
			free(ev);
			exit(1); /* XXX */
		}
		if ((evd = malloc(sizeof(*evd))) == NULL) {
			dprintf(LOG_ERR, "%s" "failed to create a new event "
				"data", FNAME);
			free(ev->timer);
			free(ev);
			exit(1); /* XXX */
		}
		memset(evd, 0, sizeof(*evd));
		evd->type = DHCP6_DATA_PREFIX;
		evd->data = sp;
		evd->event = ev;
		TAILQ_INSERT_TAIL(&ev->data_list, evd, link);

		TAILQ_INSERT_TAIL(&sp->ifp->event_list, ev, link);

		ev->timeouts = 0;
		ev->state = DHCP6S_RENEW;
		client6_send_renew(ev);
		dhcp6_set_timeoparam(ev);
		dhcp6_reset_timer(ev);

		sp->evdata = evd;
		break;
	}

	return(new_timer);
}

static int
add_ifprefix(prefix, pconf)
	struct dhcp6_prefix *prefix;
	struct prefix_ifconf *pconf;
{
	struct dhcp6_ifprefix *ifpfx = NULL;
	struct in6_addr *a;
	u_long sla_id;
	char *sp;
	int b, i;

	if ((ifpfx = malloc(sizeof(*ifpfx))) == NULL) {
		dprintf(LOG_ERR, "%s" "failed to allocate memory for ifprefix",
			FNAME);
		return -1;
	}
	memset(ifpfx, 0, sizeof(*ifpfx));

	ifpfx->ifconf = pconf;

	ifpfx->paddr.sin6_family = AF_INET6;
	ifpfx->paddr.sin6_len = sizeof(struct sockaddr_in6);
	ifpfx->paddr.sin6_addr = prefix->addr;
	ifpfx->plen = prefix->plen + pconf->sla_len;
	/*
	 * XXX: our current implementation assumes ifid len is a multiple of 8
	 */
	if ((pconf->ifid_len % 8) != 0) {
		dprintf(LOG_NOTICE, "add_ifprefix: "
			"assumption failure on the length of interface ID");
		goto bad;
	}
	if (ifpfx->plen + pconf->ifid_len < 0 ||
	    ifpfx->plen + pconf->ifid_len > 128) {
		dprintf(LOG_INFO, "add_ifprefix: "
			"invalid prefix length %d + %d + %d",
			prefix->plen, ifpfx->plen, pconf->ifid_len);
		goto bad;
	}

	/* copy prefix and SLA ID */
	a = &ifpfx->paddr.sin6_addr;
	b = prefix->plen;
	for (i = 0, b = prefix->plen; b > 0; b -= 8, i++)
		a->s6_addr[i] = prefix->addr.s6_addr[i];
	sla_id = htonl(pconf->sla_id);
	sp = ((char *)&sla_id + 3);
	i = (128 - pconf->ifid_len) / 8;
	for (b = pconf->sla_len; b > 7; b -= 8, sp--)
		a->s6_addr[--i] = *sp;
	if (b)
		a->s6_addr[--i] |= *sp;

	/* configure the corresponding address */
	ifpfx->ifaddr = ifpfx->paddr;
	for (i = 15; i >= pconf->ifid_len / 8; i--)
		ifpfx->ifaddr.sin6_addr.s6_addr[i] = pconf->ifid[i];
	if (ifaddrconf(IFADDRCONF_ADD, ifpfx))
		goto bad;

	/* TODO: send a control message for other processes */

	return 0;

  bad:
	if (ifpfx)
		free(ifpfx);
	return -1;
}

static int
ifaddrconf(cmd, ifpfx)
	ifaddrconf_cmd_t cmd;
	struct dhcp6_ifprefix *ifpfx;
{
	struct prefix_ifconf *pconf = ifpfx->ifconf;
	struct in6_aliasreq req;
	unsigned long ioctl_cmd;
	char *cmdstr;
	int s;			/* XXX overhead */

	switch(cmd) {
	case IFADDRCONF_ADD:
		cmdstr = "add";
		ioctl_cmd = SIOCAIFADDR_IN6;
		break;
	case IFADDRCONF_REMOVE:
		cmdstr = "remove";
		ioctl_cmd = SIOCDIFADDR_IN6;
		break;
	}

	if ((s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		dprintf(LOG_ERR, "%s" "can't open a temporary socket: %s",
			FNAME, strerror(errno));
		return(-1);
	}

	memset(&req, 0, sizeof(req));
	memcpy(req.ifra_name, pconf->ifname, sizeof(req.ifra_name));
	req.ifra_addr = ifpfx->ifaddr;
	(void)sa6_plen2mask(&req.ifra_prefixmask, ifpfx->plen);
	/* XXX: should lifetimes be calculated based on the lease duration? */
	req.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	req.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	if (ioctl(s, ioctl_cmd, &req)) {
		dprintf(LOG_NOTICE, "%s" "failed to %s an address on %s: %s",
		    FNAME, cmdstr, pconf->ifname, strerror(errno));
		close(s);
		return(-1);
	}

	dprintf(LOG_DEBUG, "%s" "%s an address %s on %s", FNAME, cmdstr,
	    addr2str((struct sockaddr *)&ifpfx->ifaddr), pconf->ifname);

	close(s);
	return(0);
}
