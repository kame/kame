/*	$KAME: dhcp6c_ia.c,v 1.7 2003/01/22 08:53:24 jinmei Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.
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
#include <sys/queue.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#include "timer.h"
#include "dhcp6c_ia.h"
#include "prefixconf.h"

typedef enum {IAS_ACTIVE, IAS_RENEW, IAS_REBIND} iastate_t;

struct ia {
	TAILQ_ENTRY(ia) link;

	/* identifier of this IA */
	iatype_t iatype;
	u_int32_t iaid;

	/* common parameters of IA */
	u_int32_t t1;		/* duration for renewal */
	u_int32_t t2;		/* duration for rebind  */

	/* internal parameters for renewal/rebinding */
	iastate_t state;
	struct dhcp6_timer *timer;
	struct dhcp6_eventdata *evdata;

	/* DHCP related parameters */
	struct dhcp6_if *ifp;	/* DHCP interface */
	struct duid serverid;	/* the server ID that provided this IA */

	/* control information shared with each particular config routines */
	struct iactl *ctl;
};
static TAILQ_HEAD(, ia) ia_listhead;

static void callback __P((struct ia *));
static int release_ia __P((struct ia *));
static void remove_ia __P((struct ia *));
static struct ia *get_ia __P((iatype_t, struct dhcp6_if *,
    struct dhcp6_listval *, struct duid *));
static struct ia *find_ia __P((iatype_t, u_int32_t));
static struct dhcp6_timer *ia_timo __P((void *));

static char *iastr __P((iatype_t));
static char *statestr __P((iastate_t));

extern struct dhcp6_timer *client6_timo __P((void *));
extern int client6_ifinit __P((struct dhcp6_if *));
extern void client6_send_renew __P((struct dhcp6_event *));
extern void client6_send_rebind __P((struct dhcp6_event *));
extern void client6_send_release __P((struct dhcp6_event *));

void
init_ia()
{
	TAILQ_INIT(&ia_listhead);
}

void
update_ia(iatype, ialist, ifp, serverid)
	iatype_t iatype;
	struct dhcp6_list *ialist;
	struct dhcp6_if *ifp;
	struct duid *serverid;
{
	struct ia *ia;
	struct ia_conf *iac;
	struct iapd_conf *iapdc;
	struct dhcp6_listval *iav, *siav, *convf;
	struct timeval timo;
	struct duid newserver;

	for (iav = TAILQ_FIRST(ialist); iav; iav = TAILQ_NEXT(iav, link)) {
		/* if we're not interested in this IA, ignore it. */
		if ((iac = find_iaconf(iatype, iav->val_ia.iaid)) == NULL)
			continue;

		/* validate parameters */
		if (iav->val_ia.t2 != 0 && iav->val_ia.t1 > iav->val_ia.t2) {
			dprintf(LOG_INFO, "%s" "invalid IA: T1(%lu) > T2(%lu)",
			    FNAME, iav->val_ia.t1, iav->val_ia.t2);
			continue; /* XXX: or should we try to recover? */
		}

		/* locate or make the local IA */
		ia = get_ia(iatype, ifp, iav, serverid);

		/* update IA configuration information */
		for (siav = TAILQ_FIRST(&iav->sublist); siav;
		    siav = TAILQ_NEXT(siav, link)) {
			switch (siav->type) {
			case DHCP6_LISTVAL_PREFIX6:
				/* add or update the prefix */
				iapdc = (struct iapd_conf *)iac;
				if (update_prefix(ia, &siav->val_prefix6,
				    &iapdc->iapd_pif_list, ifp, &ia->ctl,
				    callback)) {
					dprintf(LOG_NOTICE, "%s"
					    "failed to update a prefix %s/%d",
					    FNAME,
					    in6addr2str(&siav->val_prefix6.addr, 0),
					    siav->val_prefix6.plen);
				}
				break;
			case DHCP6_LISTVAL_STCODE:
				dprintf(LOG_INFO, "%s"
				    "status code for %s-%lu: %s", FNAME,
				    iastr(iatype), iav->val_ia.iaid,
				    dhcp6_stcodestr(siav->val_num16));
				if ((ia->state == IAS_RENEW ||
				    ia->state == IAS_REBIND) &&
				    siav->val_num16 == DH6OPT_STCODE_NOBINDING) {
					/*
					 * When the client receives a NoBinding
					 * status in an IA from the server
					 * in response to a Renew message or
					 * a Rebind message, the client sends
					 * a Request to reestablish an IA with
					 * the server.
					 * [dhcpv6-28 Section 18.1.8]
					 * XXX: what about the PD case?
					 */
					dprintf(LOG_INFO, "%s"
					    "receive NoBinding against "
					    "renew/rebind for %s-%lu", FNAME,
					    iastr(ia->iatype), ia->iaid);
					remove_ia(ia);
					goto nextia;
				}
				break;
			}
		}

		/* see if this IA is still valid.  if not, remove it. */
		if (ia->ctl == NULL || !(*ia->ctl->isvalid)(ia->ctl)) {
			dprintf(LOG_DEBUG, "%s" "IA %s-%lu is invalidated",
			    FNAME, iastr(ia->iatype), ia->iaid);
			remove_ia(ia);
			continue;
		}

		/* if T1 or T2 is 0, determine appropriate values locally. */
		if (ia->t1 == 0 || ia->t2 == 0) {
			u_int32_t duration;

			if (ia->ctl && ia->ctl->duration) {
				duration = (*ia->ctl->duration)(ia->ctl);
			} else
				duration = 1800; /* 30min. XXX: no rationale */

			if (ia->t1 == 0) {
				if (duration == DHCP6_DURATITION_INFINITE)
					ia->t1 = DHCP6_DURATITION_INFINITE;
				else
					ia->t1 = duration / 2;
			}
			if (ia->t2 == 0) {
				if (duration == DHCP6_DURATITION_INFINITE)
					ia->t2 = DHCP6_DURATITION_INFINITE;
				else
					ia->t2 = duration * 4 / 5;
			}

			/* make sure T1 <= T2 */
			if (ia->t1 > ia->t2)
				ia->t1 = ia->t2 * 5 / 8;

			dprintf(LOG_INFO, "%s" "T1(%lu) and/or T2(%lu) "
			    "is locally determined", FNAME, ia->t1, ia->t2);
		}

		/* set up a timer for this IA. */
		if (ia->t1 == DHCP6_DURATITION_INFINITE) {
			if (ia->timer)
				dhcp6_remove_timer(&ia->timer);
		} else {
			if (ia->timer == NULL)
				ia->timer = dhcp6_add_timer(ia_timo, ia);
			if (ia->timer == NULL) {
				dprintf(LOG_ERR, "%s" "failed to add IA "
				    "timer", FNAME);
				remove_ia(ia); /* XXX */
				continue;
			}
			timo.tv_sec = ia->t1;
			timo.tv_usec = 0;
			dhcp6_set_timer(&timo, ia->timer);
		}

		ia->state = IAS_ACTIVE;

	  nextia:
	}
}

static void
callback(ia)
	struct ia *ia;
{
	struct dhcp6_if *ifp;

	/* see if this IA is still valid.  if not, remove it. */
	if (ia->ctl == NULL || !(*ia->ctl->isvalid)(ia->ctl)) {
		dprintf(LOG_DEBUG, "%s" "IA %s-%lu is invalidated",
		    FNAME, iastr(ia->iatype), ia->iaid);
		ifp = ia->ifp;
		remove_ia(ia);

		(void)client6_ifinit(ifp);
	}
}

void
release_all_ia()
{
	struct ia *ia, *ia_next;

	for (ia = TAILQ_FIRST(&ia_listhead); ia; ia = ia_next) {
		ia_next = TAILQ_NEXT(ia, link);

		(void)release_ia(ia);

		/*
		 * The client MUST stop using all of the addresses being
		 * released as soon as the client begins the Release message
		 * exchange process.
		 */
		remove_ia(ia);
	}
}

static int
release_ia(ia)
	struct ia *ia;
{
	struct dhcp6_ia iaparam;
	struct dhcp6_event *ev;
	struct dhcp6_eventdata *evd;

	dprintf(LOG_DEBUG, "%s" "release an IA: %s-%lu", FNAME,
	    iastr(ia->iatype), ia->iaid);

	if ((ev = dhcp6_create_event(ia->ifp, DHCP6S_RELEASE))
	    == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to create a new event",
		    FNAME);
		goto fail;
	}
	TAILQ_INSERT_TAIL(&ia->ifp->event_list, ev, link);


	if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
		dprintf(LOG_NOTICE, "%s"
		    "failed to create a new event timer", FNAME);
		goto fail;
	}

	if (duidcpy(&ev->serverid, &ia->serverid)) {
		dprintf(LOG_NOTICE, "%s" "failed to copy server ID",
		    FNAME);
		goto fail;
	}

	if ((evd = malloc(sizeof(*evd))) == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to create a new event "
		    "data", FNAME);
		goto fail;
	}
	memset(evd, 0, sizeof(*evd));
	iaparam.iaid = ia->iaid;
	/* XXX: should we set T1/T2 to 0?  spec is silent on this. */
	iaparam.t1 = ia->t1;
	iaparam.t2 = ia->t2;

	if (ia->ctl && ia->ctl->release_data)
		if ((*ia->ctl->release_data)(ia->ctl, &iaparam, NULL, evd)) {
			dprintf(LOG_NOTICE, "%s" "failed to make "
			    "release data", FNAME);
			goto fail;
		}
	TAILQ_INSERT_TAIL(&ev->data_list, evd, link);

	ev->timeouts = 0;
	dhcp6_set_timeoparam(ev);
	dhcp6_reset_timer(ev);

	client6_send_release(ev);

	return (0);

  fail:
	if (ev)
		dhcp6_remove_event(ev);

	return (-1);
}

static void
remove_ia(ia)
	struct ia *ia;
{
	dprintf(LOG_DEBUG, "%s" "remove an IA: %s-%lu", FNAME,
	    iastr(ia->iatype), ia->iaid);

	TAILQ_REMOVE(&ia_listhead, ia, link);

	duidfree(&ia->serverid);

	if (ia->timer)
		dhcp6_remove_timer(&ia->timer);

	if (ia->evdata) {
		TAILQ_REMOVE(&ia->evdata->event->data_list, ia->evdata, link);
		if (ia->evdata->destructor)
			ia->evdata->destructor(ia->evdata);
		else
			free(ia->evdata);
		ia->evdata = NULL;
	}

	if (ia->ctl && ia->ctl->cleanup)
		(*ia->ctl->cleanup)(ia->ctl);

	free(ia);
}

static struct dhcp6_timer *
ia_timo(arg)
	void *arg;
{
	struct ia *ia = (struct ia *)arg;
	struct dhcp6_ia iaparam;
	struct dhcp6_event *ev;
	struct dhcp6_eventdata *evd;
	struct timeval timo;
	int dhcpstate;

	dprintf(LOG_DEBUG, "%s" "IA timeout for %s-%lu, state=%s", FNAME,
	    iastr(ia->iatype), ia->iaid, statestr(ia->state));

	/* cancel the current event for the prefix. */
	if (ia->evdata) {
		TAILQ_REMOVE(&ia->evdata->event->data_list, ia->evdata, link);
		if (ia->evdata->destructor)
			ia->evdata->destructor(ia->evdata);
		else
			free(ia->evdata);
		ia->evdata = NULL;
	}

	switch (ia->state) {
	case IAS_ACTIVE:
		ia->state = IAS_RENEW;
		dhcpstate = DHCP6S_RENEW;
		timo.tv_sec = ia->t1 < ia->t2 ? ia->t2 - ia->t1 : 0;
		timo.tv_usec = 0;
		dhcp6_set_timer(&timo, ia->timer);
		break;
	case IAS_RENEW:
		ia->state = IAS_REBIND;
		dhcpstate = DHCP6S_REBIND;
		duidfree(&ia->serverid);

		/*
		 * We don't need a timer for the IA.  We'll just wait for a
		 * reply for the REBIND until all associated configuration
		 * parameters for this IA expire.
		 */
		dhcp6_remove_timer(&ia->timer);
		break;
	default:
		dprintf(LOG_ERR, "%s" "invalid IA state (%d)",
		    FNAME, (int)ia->state);
		return (NULL);	/* XXX */
	}

	if ((ev = dhcp6_create_event(ia->ifp, dhcpstate)) == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to create a new event",
		    FNAME);
		goto fail;
	}
	TAILQ_INSERT_TAIL(&ia->ifp->event_list, ev, link);

	if ((ev->timer = dhcp6_add_timer(client6_timo, ev)) == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to create a new event "
		    "timer", FNAME);
		goto fail;
	}

	if ((evd = malloc(sizeof(*evd))) == NULL) {
		dprintf(LOG_NOTICE, "%s" "failed to create a new event "
		    "data", FNAME);
		goto fail;
	}
	memset(evd, 0, sizeof(*evd));
	evd->event = ev;
	TAILQ_INSERT_TAIL(&ev->data_list, evd, link);

	if (ia->state == IAS_RENEW) {
		if (duidcpy(&ev->serverid, &ia->serverid)) {
			dprintf(LOG_NOTICE, "%s" "failed to copy server ID",
			    FNAME);
			goto fail;
		}
	}

	iaparam.iaid = ia->iaid;
	iaparam.t1 = ia->t1;
	iaparam.t2 = ia->t2;
	switch(ia->state) {
	case IAS_RENEW:
		if (ia->ctl && ia->ctl->renew_data)
			if ((*ia->ctl->renew_data)(ia->ctl, &iaparam,
			    &ia->evdata, evd)) {
				dprintf(LOG_NOTICE, "%s" "failed to make "
				    "renew data", FNAME);
				goto fail;
			}
		break;
	case IAS_REBIND:
		if (ia->ctl && ia->ctl->rebind_data)
			if ((*ia->ctl->rebind_data)(ia->ctl, &iaparam,
			    &ia->evdata, evd)) {
				dprintf(LOG_NOTICE, "%s" "failed to make "
				    "rebind data", FNAME);
				goto fail;
			}
		break;
	}

	ev->timeouts = 0;
	dhcp6_set_timeoparam(ev);
	dhcp6_reset_timer(ev);

	ia->evdata = evd;

	switch(ia->state) {
	case IAS_RENEW:
		client6_send_renew(ev);
		break;
	case IAS_REBIND:
		client6_send_rebind(ev);
		break;
	case IAS_ACTIVE:
		/* what to do? */
		break;
	}

	return (ia->timer);

  fail:
	if (ev)
		dhcp6_remove_event(ev);

	return (NULL);
}

static struct ia *
get_ia(type, ifp, iaparam, serverid)
	iatype_t type;
	struct dhcp6_if *ifp;
	struct dhcp6_listval *iaparam;
	struct duid *serverid;
{
	struct ia *ia;
	struct duid newserver;
	int create = 0;

	if (duidcpy(&newserver, serverid)) {
		dprintf(LOG_NOTICE, "%s" "failed to copy server ID",
		    FNAME);
		return (NULL);
	}

	if ((ia = find_ia(type, iaparam->val_ia.iaid)) == NULL) {
		if ((ia = malloc(sizeof(*ia))) == NULL) {
			dprintf(LOG_NOTICE, "%s" "memory allocation failed"
			    FNAME);
			duidfree(&newserver); /* XXX */
			return (NULL);
		}
		memset(ia, 0, sizeof(*ia));
		ia->iatype = type;
		ia->iaid = iaparam->val_ia.iaid;
		ia->state = IAS_ACTIVE;

		TAILQ_INSERT_TAIL(&ia_listhead, ia, link);

		create = 1;
	} else
		duidfree(&ia->serverid);

	ia->t1 = iaparam->val_ia.t1;
	ia->t2 = iaparam->val_ia.t2;
	ia->ifp = ifp;
	ia->serverid = newserver;

	dprintf(LOG_DEBUG, "%s" "%s an IA: %s-%lu", FNAME,
	    create ? "make" : "update", iastr(type), ia->iaid);

	return (ia);
}

static struct ia *
find_ia(type, iaid)
	iatype_t type;
	u_int32_t iaid;
{
	struct ia *ia;

	for (ia = TAILQ_FIRST(&ia_listhead); ia;
	    ia = TAILQ_NEXT(ia, link)) {
		if (ia->iatype == type && ia->iaid == iaid)
			return (ia);
	}

	return (NULL);
}

static char *
iastr(type)
	iatype_t type;
{
	switch (type) {
	case IATYPE_PD:
		return ("PD");
	default:
		return ("???");	/* should be a bug */
	}
}

static char *
statestr(state)
	iastate_t state;
{
	switch (state) {
	case IAS_ACTIVE:
		return "ACTIVE";
	case IAS_RENEW:
		return "RENEW";
	case IAS_REBIND:
		return "REBIND";
	default:
		return "???";	/* should be a bug */
	}
}
