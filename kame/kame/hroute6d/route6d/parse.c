/* 
 * $Id: parse.c,v 1.2 1999/10/26 09:05:44 itojun Exp $
 */

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

/* Copyright (c) 1997, 1998. Hitachi,Ltd.  All rights reserved. */
/* Hitachi Id: parse.c,v 1.3 1998/01/12 12:39:05 sumikawa Exp $ */

#include "defs.h"
#include "pathnames.h"

struct keytab {
	char	*kt_cp;
	int	kt_i;
	int	kt_l;
} keywords[] = {
#include "keywords.h"
	{0, 0, 0}
};

#define STRING_LEN	50
#define VAR_LEN		16
#define LINE_LEN	256

static void global_part(void);
static void interface_part(void);

static int keyword(void);
static int prefix(struct prefix *);
static int address(struct in6_addr *, int);
static int rtag(u_short *);
static int metric(short *);
static struct preflist *get_if_addr(struct interface **);

static struct int_config *is_if_configured();
static int pcmp(struct prefix *, struct prefix *);
static void check_ctl_list(struct control **, struct in6_addr *, u_char);
static void clear_ctl_list(struct control **);

static void print_config(void);
static void print_ctl_list(struct control *, u_char);

static struct in6_addr any = IN6ADDR_ANY_INIT;
static char *now;
static int k, lnum = 0;

extern int Cflag;
extern int dflag;

#define SKIPTOKEN \
	while (!isspace(*now)) \
		now++;

#define SKIP \
	while (isspace(*now)) \
		now++;

#define ERR(mes) \
	{ \
		syslog(LOG_ERR, "line %d: %s", lnum, mes); \
		fprintf(stderr, "line %d: %s\n", lnum, mes); \
		goto err; \
	}

void
parse_config(void)
{
	int global = 1;
	FILE *config;

	char line[LINE_LEN];
	char *line_end;

	if ((config = fopen(RT6_CONFIGFILE, "r")) == NULL)
		ERR("cannot find configuration file\n");

	bzero(line, LINE_LEN);
	while (fgets(line, LINE_LEN, config) != NULL) {
		now = line;
		lnum++;
		line_end = index(now, '#');
		if (line_end != NULL)
			*line_end = '\0';
		line_end = index(now, '\n');
		if (line_end != NULL)
			*line_end = '\0';
		SKIP;
		if (*now == '\0')
			continue;
		if ((k = keyword()) == 0)
			ERR("unknown keyword");
		if (k == K_INTERFACE && global)
			global = 0;
		if (global)
			global_part();
		else
			interface_part();
		bzero(line, LINE_LEN);
 	}
	fclose(config);

	if (Cflag) {
		print_config();
		exit(0);
	}
	if (dflag)
		print_config();
	return;

 err:
	if (Cflag)
		exit(1);
	else
		WAIT_FOR_SIGHUP();
}

void
global_part(void)
{
	int plen = 0;
	struct static_rt *st, *sp;
	struct ign_prefix *ip, *ign;
	
	switch(k) {
	case K_QUIET:
		rt6_opmode = MODE_QUIET;
		difconf.int_outpass = CTL_NOSEND;
		difconf.int_ctlout = NULL;
		break;
		
	case K_POISON:
		rt6_scheme = RT6_POISON;
		difconf.int_scheme = RT6_POISON;
		break;
			
	case K_HORIZON:
		rt6_scheme = RT6_HORZN;
		difconf.int_scheme = RT6_HORZN;
		break;

	case K_NOHORIZON:
		rt6_scheme = RT6_NOHORZN;
		difconf.int_scheme = RT6_NOHORZN;
		break;

	case K_TRACE:
		if ((k = keyword()) == K_ON)
			rt6_trace = TRACE_ON;
		else if (k == K_OFF)
			rt6_trace = TRACE_OFF;
		else
			ERR("unknown keyword");
		break;

	case K_DEFAULTMETRIC:
		if (metric(&rt6_metric) < 1)
			ERR("Invalid metric");
		difconf.int_metric_in = rt6_metric;
		break;

	case K_HEADERLEN:
		rt6_hdrlen = atoi(now);
		if ((rt6_hdrlen <= 1) || (rt6_hdrlen < DEFAULT_HDRLEN))
			ERR("too short header length");
		break;

	case K_NEXTHOP:
		if ((k = keyword()) == K_OUT)
			rt6_nhopout = TRUE;
		else if (k == K_NOIN)
			rt6_nhopnoin = TRUE;
		else
			ERR("unknown keyword");
		break;

	case K_ROUTETAG:
		if (rtag(&rt6_tag) < 1)
			ERR("invalid tag");
		break;

	case K_AUTH:	/* xxx for IPsec, just ignore now */
		break;
			
	case K_COMPATIBLE:
		rt6_accept_compat = TRUE;
		break;

	case K_STATIC:
		if ((st = (struct static_rt *)malloc(sizeof(*st))) == NULL)
			ERR("cannot malloc");

		/* prefix */
		if (prefix(&st->sta_prefix) < 1)
			ERR("illegal prefix");
		if (st->sta_prefix.prf_len == 0) {
			/* In fact, this is a default route */
			st->sta_prefix.prf_len = MAX_PREFLEN;
		}

		/* address */
		if (address(&st->sta_gw, 0) < 1)
			ERR("illegal address");
		if (!IN6_IS_ADDR_LINKLOCAL(&st->sta_gw))
			ERR("address is not linklocal");

		/* interface */
		get_if_addr(&st->sta_ifp);
		if (st->sta_ifp == NULL)
			ERR("unknwon interface");

		k = keyword();

		/* metric */
		st->sta_rtstat.rts_metric = rt6_metric;
		if (k == K_METRIC) {
			if (metric(&st->sta_rtstat.rts_metric) < 1)
				ERR("Invalid metric");
			k = keyword();
		}

		/* routetag */
		st->sta_rtstat.rts_tagval = rt6_tag;
		if (k == K_ROUTETAG)
			if (rtag(&st->sta_rtstat.rts_tagval) < 1)
				ERR("invalid tag");
		
		for (sp = statrt; sp; sp = sp->sta_next) {
			if (pcmp(&sp->sta_prefix, &st->sta_prefix)) {
				/* overwrite it */
				st->sta_next = sp->sta_next;
				*sp = *st;
				free(st);
				st = NULL;
				break;
			}
		}
		if (st != NULL) {
			st->sta_next = statrt;
			statrt = st;
		}
		break;

	case K_IGNORE:
		if ((ign = (struct ign_prefix *)
		     malloc(sizeof(struct ign_prefix))) == NULL) {
			syslog(LOG_ERR, "parse: %m");
			exit_route6d();
		}
		if (prefix(&ign->igp_prefix) < 1)
			ERR("Invalid prefix");
			
		if (ign->igp_prefix.prf_len == 0)
			rt6_igndefault = TRUE;
			
		get_mask(plen, (char *)&ign->igp_mask);
		for (ip = ignprf; ip; ip = ip->igp_next) {
			if (pcmp(&ip ->igp_prefix, &ign->igp_prefix)) {
				free(ign);
				ign = NULL;
				break;
			}
		}
		ign->igp_next = ignprf;
		ignprf = ign;
		break;
	default:
		ERR("unknown keyword");
	}
	return;
 err:
	exit_route6d();
}

void
interface_part(void)
{
	int ret;
	char *c;
	struct in6_addr addr;
	struct control *ctl;
	struct aggregate *ag, *ap;
	struct nexthop_rte *nh, *np;

	static struct interface *iface = NULL;
	static struct preflist *if_ll_addr;
	static struct int_config *ifc = NULL;
	
	switch (k) {
	case K_INTERFACE:
		iface = NULL;	/* forget previous interface */
		if ((ifc = is_if_configured()) != NULL) {
			if_ll_addr = iface->if_lladdr;
			break;
		}

		c = now;
		if_ll_addr = get_if_addr(&iface);
		ifc = (struct int_config *)malloc(sizeof(*ifc));
		if (ifc == NULL) {
			syslog(LOG_ERR, "parse: %m");
			exit_route6d();
		}
		ifc->int_next = NULL;
		ifc->int_scheme = rt6_scheme;
		ifc->int_inpass = CTL_LISTEN;
		ifc->int_ctlin = NULL;
		ifc->int_outpass =
			(rt6_opmode == MODE_QUIET) ? CTL_NOSEND : CTL_SEND;
		ifc->int_ctlout = NULL;
		
		/* All router multicast address is default for out */
		if (rt6_opmode != MODE_QUIET) {
			ctl = (struct control *)malloc(sizeof(*ctl));
			if (ctl == NULL)
				ERR("cannot malloc");
			bzero(ctl, sizeof(*ctl));
#define ca ctl->ctl_addr
			ca.sin6_port = htons(RIP6_PORT);
			ca.sin6_len = sizeof(struct sockaddr_in6);
			ca.sin6_family = AF_INET6;
			ca.sin6_flowinfo = 0;
			(void)inet_pton(AF_INET6, ALL_RIP6_ROUTER,
					&ca.sin6_addr);
#undef ca	
			ctl->ctl_pass = CTL_SEND;
			ctl->ctl_next = ifc->int_ctlout;
		} else
			ctl = NULL;

		ifc->int_ctlout = ctl;
		ifc->int_aggr = NULL;
		ifc->int_site = FALSE;
		ifc->int_dstat = NULL;
		ifc->int_dfilter = NULL;
		ifc->int_filter = NULL;
		ifc->int_metric_in = rt6_metric;
		ifc->int_metric_out = DEFAULT_METRIC_OUT;
		ifc->int_nhop = NULL;
		ifc->int_propagate = FALSE;
		strcpy(ifc->int_name, c);
		ifc->int_next = ifconf;
		ifconf = ifc;
		break;

	case K_POISON:
		ifc->int_scheme = RT6_POISON;
		break;
			
	case K_HORIZON:
		ifc->int_scheme = RT6_HORZN;
		break;

	case K_NOHORIZON:
		ifc->int_scheme = RT6_NOHORZN;
		break;
			
	case K_IN:
		if ((ret = address(&addr, 1)) < 1)
			ERR("invalid address");
		/* no address? */
		if (ret == 2) {
			ifc->int_inpass = CTL_LISTEN;
			clear_ctl_list(&(ifc->int_ctlin));
			break;
		}
		if (!IN6_IS_ADDR_LINKLOCAL(&addr))
			ERR("address is not linklocal");
		check_ctl_list(&ifc->int_ctlin, &addr, CTL_LISTEN);
		break;

	case K_NOIN:
		if ((ret = address(&addr, 1)) < 1)
			ERR("invalid address");
		/* no address? */
		if (ret == 2) {
			ifc->int_inpass = CTL_NOLISTEN;
			clear_ctl_list(&(ifc->int_ctlin));
			break;
		}
		if (!IN6_IS_ADDR_LINKLOCAL(&addr))
			ERR("address is not linklocal");
		check_ctl_list(&ifc->int_ctlin, &addr, CTL_NOLISTEN);
		break;

	case K_OUT:
		if ((ret = address(&addr, 1)) < 1)
			ERR("invalid address");
		if (ret != 2) {
			if (!IN6_IS_ADDR_LINKLOCAL(&addr))
				ERR("address is not linklocal");
			check_ctl_list(&ifc->int_ctlout, &addr, CTL_SEND);
			break;
		}

		/* 
		 * If OUT with no parameter, delete all previous
		 * unicast entries in ctlout list, and make
		 * int_outpass to CTL_SEND (to FF02::9)
		 */
		ifc->int_outpass = CTL_SEND;
		clear_ctl_list(&(ifc->int_ctlout));
		/* rebuild FF02::9 entry */
		if ((ctl = (struct control *)malloc(sizeof(*ctl))) == NULL)
			ERR("cannot malloc");
		bzero(ctl, sizeof(*ctl));
		ctl->ctl_addr.sin6_port = htons(RIP6_PORT);
		ctl->ctl_addr.sin6_len = sizeof(struct sockaddr_in6);
		ctl->ctl_addr.sin6_family = AF_INET6;
		ctl->ctl_addr.sin6_flowinfo = 0;
		(void)inet_pton(AF_INET6, ALL_RIP6_ROUTER,
			&ctl->ctl_addr.sin6_addr);
		ctl->ctl_pass = CTL_SEND;
		ctl->ctl_next = ifc->int_ctlout;
		ifc->int_ctlout = ctl;
		break;

	case K_NOOUT:
		ifc->int_outpass = CTL_NOSEND;
		clear_ctl_list(&ifc->int_ctlout);
		break;

	case K_AGGREGATE:
		if ((ag = (struct aggregate *)malloc(sizeof(*ag))) == NULL)
			ERR("cannot malloc");

		/* prefix */
		if (prefix(&ag->agr_pref) < 1)
			ERR("invalid prefix");
		get_mask(ag->agr_pref.prf_len, (char *)&ag->agr_mask);

		k = keyword();

		/* metric */
		ag->agr_stat.rts_metric = rt6_metric;
		if (k == K_METRIC) {
			if (metric(&ag->agr_stat.rts_metric) < 1)
				ERR("Invalid metric");
			k = keyword();
		}
		
		/* routetag */
		ag->agr_stat.rts_tagval = rt6_tag;
		if (k == K_ROUTETAG)
			if (rtag(&ag->agr_stat.rts_tagval) < 1)
				ERR("invalid tag");
		
		for (ap = ifc->int_aggr; ap; ap = ap->agr_next) {
			if (pcmp(&ap->agr_pref, &ag->agr_pref)) {
				ag->agr_next = ap->agr_next;
				*ap = *ag;
				free(ag);
				ag = NULL;
				break;
			}
		}
		if (ag != NULL) {
			ag->agr_next = ifc->int_aggr;
			ifc->int_aggr = ag;
		}
		break;

	case K_NOSITE:
		ifc->int_site = FALSE;
		break;

	case K_SITE:
		ifc->int_site = TRUE;
		break;

	case K_GENDEFAULT:
		/* xxx */
		break;

	case K_FILTER:
		if ((ag = (struct aggregate *)malloc(sizeof(*ag))) == NULL)
			ERR("cannot allocate memory");

		/* prefix */
		if (prefix(&ag->agr_pref) < 1)
			goto err;

		if (ag->agr_pref.prf_len == 0) {
			/* filter all */
			if (ifc->int_dfilter == NULL) {
				ifc->int_dfilter = (struct rte_stat *)
					malloc(sizeof(struct rte_stat));
				if (ifc->int_dfilter == NULL)
					ERR("cannot allocate memory");
			}
			bzero(ifc->int_dfilter, sizeof(struct rte_stat));
			if (keyword() == K_ROUTETAG) {
				if (rtag(&ifc->int_dfilter->rts_tagval) < 1)
					ERR("invalid tag");
				ifc->int_dfilter->rts_metric = TRUE;
			}
			break;
			/* filter all also added to list */
			/* especially that with TAG specified */
		}

		if (keyword() == K_ROUTETAG) {
			if (rtag(&ag->agr_stat.rts_tagval) < 1)
				ERR("invalid tag");
			 ag->agr_stat.rts_metric = TRUE;
		}
		get_mask(ag->agr_pref.prf_len, (char *)&ag->agr_mask);
		for (ap = ifc->int_filter; ap; ap = ap->agr_next) {
			if (pcmp(&ap->agr_pref, &ag->agr_pref) &&
			    (ap->agr_stat.rts_metric == FALSE ||
			     ap->agr_stat.rts_tagval == ag->agr_stat.rts_tagval)) {
				free(ag);
				ag = NULL;
				break;
			}	
		}
		if (ag != NULL) {
			ag->agr_next = ifc->int_filter;
			ifc->int_filter = ag;
		}
		break;

	case K_METRICIN:
		if (metric(&ifc->int_metric_in) < 1)
			ERR("invalid metric");
		break;

	case K_METRICOUT:
		if (metric(&ifc->int_metric_out) < 1)
			ERR("invalid metric");
		break;
		
	case K_NEXTHOP:
		if ((nh = (struct nexthop_rte *)malloc(sizeof(*nh))) == NULL)
			ERR("cannot allocate memory");
		if (prefix(&nh->nh_prf) < 1)
			goto err;
		if (address(&nh->nh_addr, 0) < 1)
			goto err;
		get_mask(nh->nh_prf.prf_len, (char *)&nh->nh_mask);
		for (np = ifc->int_nhop; np; np = np->nh_next) {
			if (pcmp(&np->nh_prf, &nh->nh_prf)) {
				nh->nh_next = np->nh_next;
				*np = *nh;
				free(nh);
				nh = NULL;
				break;
			}
		}
		if (nh != NULL) {
			nh->nh_next = ifc->int_nhop;
			ifc->int_nhop = nh;
		}
		break;

	case K_PROPAGATE:
		ifc->int_propagate = TRUE;
		break;
	default:
		ERR("unknown keyword");
	}

	return;
 err:
	fprintf(stderr, "some error\n");
	exit_route6d();
}

/* 
 * to check the address passed, is present in control list
 */
void
check_ctl_list(struct control **list_start, struct in6_addr *address,
	       u_char pass)
{
	struct control *p;

	for (p = *list_start; p; p = p->ctl_next) {
		if (!memcmp(p->ctl_addr.sin6_addr.s6_addr,
			    address->s6_addr, 16)) {
			p->ctl_pass = pass;
			return;
		}
	}

	/* Add new entry in linklist. */
	p = (struct control *)(malloc(sizeof(struct control)));
	if (p == NULL) {
		syslog(LOG_ERR, "parse: %m");
		exit_route6d();
	}
	bzero(p, sizeof(struct control));
	p->ctl_addr.sin6_port = htons(RIP6_PORT);
	p->ctl_addr.sin6_len = sizeof(struct sockaddr_in6);
	p->ctl_addr.sin6_family = AF_INET6;
	p->ctl_addr.sin6_flowinfo = 0;
	p->ctl_addr.sin6_addr = *address;
	p->ctl_pass = pass;
	p->ctl_next = *list_start;
	*list_start = p;
	return;
}

/* 
 * to clear the control list.
 */
void
clear_ctl_list(struct control **list_start)
{
	struct control *ctl_ptr, *next_ptr;

	for (ctl_ptr = *list_start; ctl_ptr;) {
		next_ptr = ctl_ptr->ctl_next;
		free(ctl_ptr);
		ctl_ptr = next_ptr;
	}
	*list_start = NULL;
	return;
}

static struct int_config *
is_if_configured(void)
{
	struct int_config *p;

	for (p = ifconf; p; p = p->int_next) {
		if (strcmp(p->int_name, now) == 0)
			return(p);
	}
	return(NULL);
}

/* 
 * print all the configuration parameters.
 */
void
print_config(void)
{
	char a1[STRING_LEN], a2[STRING_LEN];

	struct static_rt *st;
	struct ign_prefix *ig;
	struct int_config *ifc;
	struct aggregate *ag;
	struct nexthop_rte *nh;

#define S(a) a == 0 ? "NOHORIZON" : a == 1 ? "HORIZON" : "POISON"
	
	printf("GLOBAL parameters\n");
	printf("-------------------\n");
	if (rt6_opmode == MODE_QUIET)
		printf("quiet\n");
	printf("scheme = %s\n", S(rt6_scheme));
	printf("trace = %s\n", rt6_trace ? "ON" : "OFF");
	printf("metric = %d\n", rt6_metric);
	printf("hdrlen = %d\n", rt6_hdrlen);
	printf("tag = %x\n", rt6_tag);
	if (rt6_nhopout)
		printf("nhopout\n");
	if (rt6_nhopnoin)
		printf("nhopnoin\n");
	if (rt6_accept_compat)
		printf("accept_compat\n");

	if (statrt) {
		printf("\nstatic routes\n");
		printf("  prefix                    address");
		printf("                     metric tag\n");
	}
	for (st = statrt; st; st = st->sta_next) {
		printf("  %-21s %3d %-32s %d %x\n",
		       inet_ntop(AF_INET6,
				 &st->sta_prefix.prf_addr, a1, sizeof(a1)),
		       st->sta_prefix.prf_len,
		       inet_ntop(AF_INET6, &st->sta_gw, a2, sizeof(a2)),
		       st->sta_rtstat.rts_metric, st->sta_rtstat.rts_tagval);
	}

	if (ignprf)
		printf("\nignore prefixes\n");
	for (ig = ignprf; ig; ig = ig->igp_next) {
		printf("  %s/%d\n",
		       inet_ntop(AF_INET6,
				 &ig->igp_prefix.prf_addr, a1, sizeof(a1)),
		       ig->igp_prefix.prf_len);
	}

	printf("\nINTERFACE parameters\n");
	printf("--------------------\n");

	for (ifc = ifconf; ifc; ifc = ifc->int_next) {
		printf("\ninterface %s\n", ifc->int_name);
		printf("  scheme = %s\n", S(ifc->int_scheme));

		printf("  inpass = %s\n",
		       ifc->int_inpass == CTL_LISTEN ? "LISTEN" : "NOLISTEN");
		printf("    metric_in = %d\n", ifc->int_metric_in);
		if (ifc->int_ctlin)
			printf("    in list\n");
		print_ctl_list(ifc->int_ctlin, CTL_LISTEN);
		if (ifc->int_ctlin)
			printf("    noin list\n");
		print_ctl_list(ifc->int_ctlin, CTL_NOLISTEN);

		printf("  outpass = %s\n",
		       ifc->int_outpass == CTL_LISTEN ? "LISTEN" : "NOLISTEN");
		printf("    metric_out = %d\n", ifc->int_metric_out);
		if (ifc->int_ctlout)
			printf("    out list\n");
		print_ctl_list(ifc->int_ctlout, CTL_SEND);
		if (ifc->int_aggr) {
			printf("    aggregate list\n");
			printf("      prefix                    ");
			printf("metric  tag\n");
		}
		for (ag = ifc->int_aggr; ag; ag = ag->agr_next) {
			printf("      %-21s %3d %6d %4x\n",
			       inet_ntop(AF_INET6, &ag->agr_pref.prf_addr,
					 a1, sizeof(a1)),
			       ag->agr_pref.prf_len,
			       ag->agr_stat.rts_metric,
			       ag->agr_stat.rts_tagval);
		}

		if (ifc->int_dstat) {
			printf("  gendefault : ");
			printf("metric = %d", ifc->int_dstat->rts_metric);
			printf(",routetag = %x\n", ifc->int_dstat->rts_tagval);
		}
		if (ifc->int_dfilter || ifc->int_filter)
			printf("  filter list\n");
		if (ifc->int_dfilter != NULL) {
			printf("    filter default RTE");
			if (ifc->int_dfilter->rts_metric == TRUE)
				printf(" with routetag %x",
				       ifc->int_dfilter->rts_tagval);
			printf("\n");
		}
		if (ifc->int_filter)
			printf("    prefix                     tag\n");
		for (ag = ifc->int_filter; ag; ag = ag->agr_next) {
			printf("    %-21s %3d %4x\n",
			       inet_ntop(AF_INET6, &ag->agr_pref.prf_addr,
					 a1, sizeof(a1)),
			       ag->agr_pref.prf_len, ag->agr_stat.rts_tagval);
		}

		if (ifc->int_nhop) {
			printf("  nexthop list\n");
			printf("    prefix              address\n");
		}
		for (nh = ifc->int_nhop; nh; nh = nh->nh_next) {
			printf("  %s  %d  %s \n",
			       inet_ntop(AF_INET6,
					 &nh->nh_prf.prf_addr, a1, sizeof(a1)),
			       nh->nh_prf.prf_len,
			       inet_ntop(AF_INET6,
					 &nh->nh_addr, a2, sizeof(a2)));
		}

		if (ifc->int_site)
			printf("  site\n");
		if (ifc->int_propagate)
			printf("  propagate\n");
	}
	return;
}

/* 
 * print address in control list passed
 */
void
print_ctl_list(struct control *list_start, u_char pass)
{
	char buf[STRING_LEN];
	struct control *ctl;

	for (ctl = list_start; ctl; ctl = ctl->ctl_next) {
		if (ctl->ctl_pass != pass)
			continue;
		printf("      %s\n",
		       inet_ntop(AF_INET6, &ctl->ctl_addr.sin6_addr,
				 buf, sizeof(buf)));
	}
	return;
}

static int
keyword(void)
{
	register struct keytab *kt = keywords;

	while (kt->kt_cp && strncasecmp(kt->kt_cp, now, kt->kt_l))
		kt++;
	now += kt->kt_l;
	if (*now == '\0')
		return(kt->kt_i);
	SKIP;
	return(kt->kt_i);
}

static int
prefix(pref)
	struct prefix *pref;
{
	char *np = now;
	int ret, jp = 0;
	
	while(!isspace(*np) && *np != '\0')
		np++;
	if (isspace(*np)) {
		*np = '\0';
		jp = 1;
	}
	if (strcasecmp(now, "default")) {
		if ((ret = inet_pton(AF_INET6, now, &pref->prf_addr)) != 1)
			goto end;
	} else {
		pref->prf_addr = any;
		pref->prf_len = 0;
		ret = 1;
		if (jp)
			np++; 
		while (isspace(*np))
			np++;
		goto end;
	}
	if (jp)
		np++; 
	while (isspace(*np))
		np++;
	pref->prf_len = atoi(np);
	if ((pref->prf_len < 1) || (pref->prf_len > 128)) {
		ret = -1;
		goto err;
	}
	while (!isspace(*np) && *np != '\0')
		np++;
	while (isspace(*np))
		np++;
 end:
	if (ret == 1)
		now = np;
 err:
	return(ret);
}

static int
address(addr, opt)
	struct in6_addr *addr;
	int opt;
{
	char *np = now;
	int ret, jp = 0;
	
	if (opt && *np == '\0') {
		ret = 2;
		goto end;
	}
	while(!isspace(*np) && *np != '\0')
		np++;
	if (isspace(*np)) {
		*np = '\0';
		jp = 1;
	}
	if ((ret = inet_pton(AF_INET6, now, addr)) != 1)
		goto err;
	if (jp)
		np++; 
	while (isspace(*np))
		np++;
 end:
	now = np;
 err:
	return(ret);
}

struct preflist *
get_if_addr(struct interface **ifp)
{
	struct interface *tmp;
	char *np = now;
	int jp = 0;
	struct preflist *ret = NULL;
	
	while(!isspace(*np) && *np != '\0')
		np++;
	if (isspace(*np)) {
		*np = '\0';
		jp = 1;
	}
	for (tmp = ifnet; tmp; tmp = tmp->if_next) {
		if (strcmp(tmp->if_name, now) == 0) {
			*ifp = tmp;
			ret = tmp->if_lladdr;
		}
	}
	if (jp)
		np++;
	now = np;
	SKIP;
	return(ret);
}

static int
rtag(tag)
	u_short *tag;
{
	int ret = -1;
	int tmp = 0;
	
	while (!isspace(*now) && *now != '\0') {
		switch(*now) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			tmp = (tmp * 16) + (*now - '0');
			break;
		case 'a': case 'b': case 'c':
		case 'd': case 'e': case 'f':
			tmp = (tmp * 16) + (*now - 'a' + 10);
			break;
		case 'A': case 'B': case 'C':
		case 'D': case 'E': case 'F':
			tmp = (tmp * 16) + (*now - 'A' + 10);
			break;
		default:
			goto err;
			break;
		}
		now++;
	}
	if (tmp > 0xffff)
		goto err;
	*tag = (u_short)tmp;
	SKIP;
	ret = 1;
 err:
	return(ret);
}

static int
metric(met)
	short *met;
{
	*met = atoi(now);
	if (*met <= 0 || *met > HOPCOUNT_INFINITY)
		return(-1);
	SKIPTOKEN;
	SKIP;
	return(1);
}

/*
 * to compare two prefixes
 */
int
pcmp(p, q)
	struct prefix *p;
	struct prefix *q;
{
	char t_byte = 0xFF;

	if (p->prf_len != q->prf_len)
		return(0);
	if (bcmp(&p->prf_addr, &q->prf_addr, p->prf_len / 8) != 0)
		return(0);

	if (p->prf_len % 8 != 0) {
		t_byte <<= (8 - p->prf_len % 8);
		return ((p->prf_addr.s6_addr[p->prf_len / 8] & t_byte) ==
			(q->prf_addr.s6_addr[p->prf_len / 8] & t_byte));
	}
	return(1);
}
