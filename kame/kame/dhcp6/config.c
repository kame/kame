/*	$KAME: config.c,v 1.1 2002/04/30 14:49:08 jinmei Exp $	*/

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

#include <syslog.h>
#include <stdio.h>
#include <string.h>

#include <dhcp6.h>
#include <config.h>

extern int errno;

struct dhcp_if *dhcp_if;

/* temporary configuration parameters during parsing */
static struct dhcp_ifconf *dhcp_ifconflist;

static int add_options __P((struct dhcp_ifconf *, struct dhcp_optconf **,
			    struct cf_dhcpoption *));

static void clear_ifconf __P((struct dhcp_ifconf *));
static void clear_options __P((struct dhcp_optconf *));

void
ifinit(ifname)
	char *ifname;
{
	struct dhcp_if *ifp;

	if ((ifp = find_ifconf(ifname)) != NULL) {
		dprintf(LOG_NOTICE, "duplicated interface: %s", ifname);
		return;
	}

	if ((ifp = (struct dhcp_if *)malloc(sizeof(*ifp))) == NULL) {
		dprintf(LOG_ERR, "malloc failed");
		goto die;
	}
	memset(ifp, 0, sizeof(*ifp));

	ifp->state = DHCP6S_INIT;
	
	if ((ifp->ifname = strdup(ifname)) == NULL) {
		dprintf(LOG_ERR, "failed to copy ifname");
		goto die;
	}

	if ((ifp->ifid = if_nametoindex(ifname)) == 0) {
		dprintf(LOG_ERR, "invalid interface(%s): %s",
			ifname, strerror(errno));
		goto die;
	}
#ifdef HAVE_SCOPELIB
	if (inet_zoneid(AF_INET6, 2, ifname, &ifp->linkid)) {
		dprintf(LOG_ERR, "failed to get link ID for %s", ifname);
		goto die;
	}
#else
	ifp->linkid = ifp->ifid; /* XXX */
#endif

	ifp->next = dhcp_if;
	dhcp_if = ifp;
	return;

  die:
	exit(1);
}

int
configure_interface(iflist)
	struct cf_iflist *iflist;
{
	struct cf_iflist *ifp;
	struct dhcp_ifconf *ifc;

	for (ifp = iflist; ifp; ifp = ifp->if_next) {
		struct cf_declaration *dcl;

		if ((ifc = (struct dhcp_ifconf *)malloc(sizeof(*ifc)))
		    == NULL) {
			dprintf(LOG_ERR, "malloc failed");
			goto bad;
		}
		memset(ifc, 0, sizeof(*ifc));
		ifc->next = dhcp_ifconflist;
		dhcp_ifconflist = ifc;

		if ((ifc->ifname = strdup(ifp->if_conf->ifname)) == NULL) {
			dprintf(LOG_ERR, "failed to copy ifname");
			goto bad;
		}

		for (dcl = ifp->if_conf->decl; dcl; dcl = dcl->decl_next) {
			switch(dcl->decl_type) {
			case DECL_SEND:
				if (add_options(ifc, &ifc->send_options,
						(struct cf_dhcpoption *)dcl->decl_val))
					goto bad;
				break;
			case DECL_INFO_ONLY:
				ifc->flags |= DHCIFF_INFO_ONLY;
				break;
			}
		}
	}
	
	return(0);

  bad:
	clear_ifconf(dhcp_ifconflist);
	dhcp_ifconflist = NULL;
	return(-1);
}

void
configure_cleanup()
{
	clear_ifconf(dhcp_ifconflist);
	dhcp_ifconflist = NULL;
}

void
configure_commit()
{
	struct dhcp_ifconf *ifc;
	struct dhcp_if *ifp;

	for (ifc = dhcp_ifconflist; ifc; ifc = ifc->next) {
		if ((ifp = find_ifconf(ifc->ifname)) != NULL) {
			ifp->flags = ifc->flags;
			clear_options(ifp->send_options);
			ifp->send_options = ifc->send_options;
			ifc->send_options = NULL;
		}
	}
	clear_ifconf(dhcp_ifconflist);
}

static void
clear_ifconf(iflist)
	struct dhcp_ifconf *iflist;
{
	struct dhcp_ifconf *ifc, *ifc_next;

	for (ifc = iflist; ifc; ifc = ifc_next) {
		ifc_next = ifc->next;

		free(ifc->ifname);
		clear_options(ifc->send_options);

		free(ifc);
	}
}

static void
clear_options(opt0)
	struct dhcp_optconf *opt0;
{
	struct dhcp_optconf *opt, *opt_next;

	for (opt = opt0; opt; opt = opt_next) {
		opt_next = opt->next;

		free(opt->val);
		free(opt);
	}
}

static int
add_options(ifc, optp0, cfopt)
	struct dhcp_ifconf *ifc;
	struct dhcp_optconf **optp0;
	struct cf_dhcpoption *cfopt;
{
	struct dhcp_optconf *opt, **optp;
	struct cf_dhcpoption *cfo;

	optp = optp0;
	for (cfo = cfopt; cfo; cfo = cfo->dhcpopt_next) {
		if ((opt = (struct dhcp_optconf *)malloc(sizeof(*opt)))
		    == NULL) {
			dprintf(LOG_ERR, "malloc failed");
			return(-1);
		}
		memset(opt, 0, sizeof(*opt));
		*optp = opt;
		optp = &opt->next;

		switch(cfo->dhcpopt_type) {
		case DHCPOPT_RAPID_COMMIT:
			ifc->flags |= DHCIFF_RAPID_COMMIT;
			opt->type = DH6OPT_RAPID_COMMIT;
			opt->len = 0;
			break;
		}
	}

	return(0);
}


struct dhcp_if *
find_ifconf(ifname)
	char *ifname;
{
	struct dhcp_if *ifp;

	for (ifp = dhcp_if; ifp; ifp = ifp->next) {
		if (strcmp(ifp->ifname, ifname) == NULL)
			return(ifp);
	}

	return(NULL);
}
