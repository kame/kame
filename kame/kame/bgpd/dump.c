/*
 * Copyright (C) 1998 WIDE Project.
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

#include <time.h>

#include "include.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "rt_table.h"
#include "aspath.h"
#include "bgp_var.h"
#include "in6.h"

#include "ripng.h"

extern struct ifinfo *ifentry;
extern struct ripif *ripifs;	/* defined in ripng.c */
extern task *taskhead;

char *dumpfile;

static time_t tloc_now;

static char *aspath2str(struct aspath *);
static char *cll2str(struct clstrlist *);

/* structures to show all BGP route */
struct bgproute_entry {
	struct bgproute_entry *next;
	struct bgproute_list *head; /* back pointer to the list */
	struct rpcb *bnp;
	struct rt_entry *rte;
};
struct bgproute_list {
	struct bgproute_list *next;
	struct bgproute_list *prev;
	struct bgproute_entry *entry;
};
#define bgp_route_head(l) ((l)->next)
#define bgp_route_isend(e,b) ((e) == (b))
#define bgp_route_next(l) ((l)->next)
#define bgp_route_prev(l) ((l)->prev)
#define bgp_route_insert(new,post) insque((new), (post)->prev)

static char *
sec2str(total)
	time_t total;
{
	static char result[256];
	int days, hours, mins, secs;
	int first = 1;
	char *p = result;

	days = total / 3600 / 24;
	hours = (total / 3600) % 24;
	mins = (total / 60) % 60;
	secs = total % 60;

	if (days) {
		first = 0;
		p += sprintf(p, "%dd", days);
	}
	if (!first || hours) {
		first = 0;
		p += sprintf(p, "%dh", hours);
	}
	if (!first || mins) {
		first = 0;
		p += sprintf(p, "%dm", mins);
	}
	sprintf(p, "%ds", secs);

	return(result);
}

static void
dump_if_rtable(FILE *fp, struct rt_entry *base)
{
	struct rt_entry *rte = base;

	while(rte) {
		fprintf(fp, "    "); /* indentation */
		fprintf(fp, "%s/%d(%d)",
			ip6str(&rte->rt_ripinfo.rip6_dest, 0),
			rte->rt_ripinfo.rip6_plen,
			rte->rt_ripinfo.rip6_metric);

		if (rte->rt_flags & (RTF_BGPDIFSTATIC | RTF_BGPDGWSTATIC))
			fprintf(fp, " static");

		if (rte->rt_flags & RTF_BGPDGWSTATIC) {
			fprintf(fp, " gateway=%s",
				ip6str(&rte->rt_gw,
				       rte->rt_proto.rtp_if->ifi_ifn->if_index));
		}

		fputc('\n', fp);

		if ((rte = rte->rt_next) == base)
			break;
	}
}

static void
dump_rip_rtable(FILE *fp, struct rt_entry *base)
{
	struct rt_entry *rte = base;

	rte = base;
	while(rte) {
		fprintf(fp, "    "); /* indentation */
		fprintf(fp,
			"%s/%d(%d) [%d] gw = %s",
			ip6str(&rte->rt_ripinfo.rip6_dest, 0),
			rte->rt_ripinfo.rip6_plen,
			rte->rt_ripinfo.rip6_metric,
			rte->rt_ripinfo.rip6_tag,
			ip6str(&rte->rt_gw, 0));

		if (rte->rt_riptime) {
			fprintf(fp, " timeout=%d:%02d",
				(int)(rte->rt_riptime->tsk_timeval.tv_sec / 60),
				(int)(rte->rt_riptime->tsk_timeval.tv_sec % 60));
		}
		fputc('\n', fp);
		if ((rte = rte->rt_next) == base)
			break;
	}
}

#define FILTERTYPE_FILTER 0
#define FILTERTYPE_RESTRICTION 1

static void
print_filterinfo(FILE *fp, struct filtinfo *top, int type)
{
	struct filtinfo *filter = top; /* must not be NULL */

	while(filter) {
		fprintf(fp, "      "); /* indentation */

		if (type == FILTERTYPE_FILTER)
			fprintf(fp, "%s/%d: filtered %d routes\n",
				ip6str(&filter->filtinfo_addr, 0),
				filter->filtinfo_plen, filter->filtinfo_stat);
		if (type == FILTERTYPE_RESTRICTION)
			fprintf(fp, "%s/%d: passed %d routes\n",
				ip6str(&filter->filtinfo_addr, 0),
				filter->filtinfo_plen, filter->filtinfo_stat);

		if ((filter = filter->filtinfo_next) == top)
			break;
	}
}

static void
dump_filterinfo(FILE *fp, char *indent, struct filterset *filterset)
{
	struct filtinfo *filter;
	
	if ((filter = filterset->filterin) != NULL) {
		fprintf(fp, "%s  Input filter:\n", indent);
		print_filterinfo(fp, filter, FILTERTYPE_FILTER);
	}
	if ((filter = filterset->filterout) != NULL) {
		fprintf(fp, "%s  Output filter:\n", indent);
		print_filterinfo(fp, filter, FILTERTYPE_FILTER);
	}
	if ((filter = filterset->restrictin) != NULL) {
		fprintf(fp, "%s  Input restriction:\n", indent);
		print_filterinfo(fp, filter, FILTERTYPE_RESTRICTION);
	}
	if ((filter = filterset->restrictout) != NULL) {
		fprintf(fp, "%s  Output restriction:\n", indent);
		print_filterinfo(fp, filter, FILTERTYPE_RESTRICTION);
	}

	if (filterset->deffilterflags & DEFAULT_FILTERIN)
		fprintf(fp,
			"%s  %d incoming default routes were filtered\n",
			indent,	filterset->filtered_indef);
	if (filterset->deffilterflags & DEFAULT_FILTEROUT)
		fprintf(fp, "%s  %d outgoing default routes were filtered\n",
			indent, filterset->filtered_outdef);
	if ((filterset->deffilterflags & DEFAULT_RESTRICTIN) ||
	    filterset->restrictin)
		fprintf(fp,
			"%s  %d incoming routes were filtered by "
			"restriction\n", indent, filterset->input_restrected);
	if ((filterset->deffilterflags & DEFAULT_RESTRICTOUT) ||
	    filterset->restrictout)
		fprintf(fp,
			"%s  %d outgoing routes were filtered by "
			"restriction\n", indent, filterset->output_restrected);
}

static void
dump_bgp_rtentry(FILE *fp, struct rt_entry *rte, char *indent)
{
	struct aspath *ap;
	extern char *origin_str[];
	struct optatr *optatr;
	char inetaddrstr[INET_ADDRSTRLEN];

	ap = rte->rt_aspath;

	fprintf(fp, "%s", indent); /* indentation */
	fprintf(fp, "%s%s/%d\n", (rte->rt_flags & RTF_INSTALLED) ? "*" : " ",
		ip6str(&rte->rt_ripinfo.rip6_dest, 0),
		rte->rt_ripinfo.rip6_plen);
	fprintf(fp, "%s  Nexthop: %s\n", indent, ip6str(&rte->rt_bgw, 0));
	if (rte->rt_aspath &&
	    !IN6_IS_ADDR_UNSPECIFIED(&rte->rt_aspath->asp_nexthop_local))
		fprintf(fp, "%s  Nexhop(local): %s\n", indent,
			ip6str(&rte->rt_aspath->asp_nexthop_local, 0));

	fprintf(fp, "%s  ", indent); /* more indent */
	fprintf(fp, "Gateway: %s ",
		ip6str(&rte->rt_gw,
		       rte->rt_gwif ? rte->rt_gwif->ifi_ifn->if_index : 0));
	fprintf(fp, "Flags:");
	if (rte->rt_flags & RTF_UP) fprintf(fp, " UP");
	if (rte->rt_flags & RTF_GATEWAY) fprintf(fp, " GW");
	if (rte->rt_flags & RTF_HOST) fprintf(fp, " HOST");
	if (rte->rt_flags & RTF_IGP_EGP_SYNC) fprintf(fp, " IESYNC");
	if (rte->rt_flags & RTF_NH_NOT_LLADDR)
		fprintf(fp, " NONLOCAL");
	if (rte->rt_flags & RTF_INSTALLED) fprintf(fp, " INSTALLED");
	fputc('\n', fp);
	if (!IN6_IS_ADDR_UNSPECIFIED(&rte->rt_gw)) {
		fprintf(fp, "%s    ", indent); /* more^2 indent */
		switch(rte->rt_gwsrc_type) {
		case RTPROTO_IF:
			fprintf(fp, "gwsrc: ifroute(%s/%d on %s)",
				ip6str(&rte->rt_gwsrc_entry->rt_ripinfo.rip6_dest, 0),
				rte->rt_gwsrc_entry->rt_ripinfo.rip6_plen,
				rte->rt_gwif->ifi_ifn->if_name);
			break;
		case RTPROTO_RIP:
			fprintf(fp, "gwsrc: ripng(%s/%d on %s,\n",
				ip6str(&rte->rt_gwsrc_entry->rt_ripinfo.rip6_dest, 0),
				rte->rt_gwsrc_entry->rt_ripinfo.rip6_plen,
				rte->rt_gwif->ifi_ifn->if_name);
			fprintf(fp, "%s    ", indent); /* more^2 indent */
			fprintf(fp, "             %s)",
				ip6str(&rte->rt_gwsrc_entry->rt_gw,
				       rte->rt_gwif->ifi_ifn->if_index));
			break;
		case RTPROTO_BGP:
			fprintf(fp, "gwsrc: bgp (link %s)\n",
				rte->rt_proto.rtp_bgp->rp_ife ?
				rte->rt_proto.rtp_bgp->rp_ife->ifi_ifn->if_name :
				"??");
			break;
		default:
			fprintf(fp, "gwsrc: unknown(%d)",
				rte->rt_gwsrc_type);
			break;
		}
		fputc('\n', fp);
	}

	fprintf(fp, "%s  ", indent); /* more indent */
	fprintf(fp, "MED: %d localpref: %d origin: ID=%s,code=%s\n",
		(int)ntohl(ap->asp_med), (int)ntohl(ap->asp_localpref),
		inet_ntop(AF_INET, &ap->asp_origid,
			  inetaddrstr, INET_ADDRSTRLEN),
		origin_str[ap->asp_origin]);

	fprintf(fp, "%s  ", indent); /* more indent */
	fprintf(fp, "ASPATH: %s\n", aspath2str(ap));
	if (ap->asp_clstr) {
		fprintf(fp, "%s  ", indent); /* more indent */
		fprintf(fp, "Cluster list: %s\n",
			cll2str(ap->asp_clstr));
	}

	/* unrecognized attributes */
	if ((optatr = ap->asp_optatr) != NULL)
		fprintf(fp, "%s  Unrecognized Attributes:\n", indent);
	for (optatr = ap->asp_optatr; optatr; optatr = optatr->next) {
		int c = 0;

		fprintf(fp, "%s    ", indent);
		for (c = 0; c < optatr->len && c < 20; c++)
			fprintf(fp, "%02x ",
				(unsigned char)optatr->data[c]);
		if (optatr->len > 20)
			fprintf(fp, "...");
		fputc('\n', fp);
	}

}

static void
dump_bgp_exportlist(FILE *fp, struct rt_entry *rte, char *indent)
{
	char inetaddrstr[INET_ADDRSTRLEN];
	extern struct rpcb *bgb;
	struct rpcb *srcbnp = rte->rt_proto.rtp_bgp, *obnp;
	int first = 1;

	obnp = bgb;
	while(obnp) {
		struct rtproto *rtp = obnp->rp_adj_ribs_out;
		struct rpcb *ebnp;

		if (obnp != srcbnp &&
		    obnp->rp_state == BGPSTATE_ESTABLISHED) {
			while(rtp) {
				if (rtp->rtp_type == RTPROTO_BGP &&
				    (ebnp = find_epeer_by_rpcb(rtp->rtp_bgp)) != NULL &&
				    ebnp == srcbnp) {
					if (first == 1) {
						fprintf(fp, "%s  Exported to:\n",
							indent);
						first = 0; 
					}
					fprintf(fp,
						"%s    %s(%s), ID=%s\n",
						indent,
						bgp_peerstr(obnp),
						(obnp->rp_mode & BGPO_IGP) ?
						"IBGP" : "EBGP",
						inet_ntop(AF_INET, &obnp->rp_id,
							  inetaddrstr,
							  INET_ADDRSTRLEN));
				}
				if ((rtp = rtp->rtp_next) ==
				    obnp->rp_adj_ribs_out)
				break;
			}
		}

		if ((obnp = obnp->rp_next) == bgb)
			break;
	}
	if (first == 1)
		fprintf(fp, "%s  Not exported\n", indent);
}

#if 0
static void
dump_bgp_rtable(FILE *fp, struct rt_entry *base)
{
	struct rt_entry *rte = base;

	while(rte) {
		dump_bgp_rtentry(fp, rte, "    ");

		if ((rte = rte->rt_next) == base)
			break;
	}
}
#endif

#if notused
static void
dump_exports(FILE *fp, struct rtproto *base)
{
	struct rtproto *rtp = base;
	struct rpcb *ebnp;
	char inetaddrstr[INET_ADDRSTRLEN];

	while(rtp) {
		switch(rtp->rtp_type) {
		 case RTPROTO_IF:
			 fprintf(fp, "   Interface routes:\n");
			 dump_rip_rtable(fp, rtp->rtp_if->ifi_rte);
			 break;
		 case RTPROTO_BGP:
			 fprintf(fp, "   BGP routes: ");
			 ebnp = find_epeer_by_rpcb(rtp->rtp_bgp);

			 if (rtp->rtp_bgp->rp_mode & BGPO_IGP) { /* IBGP */
				 u_int32_t peerid =
					 ebnp ? ebnp->rp_id : rtp->rtp_bgp->rp_id;
				 fprintf(fp, "from an IBGP peer, ID = %s\n",
					 inet_ntop(AF_INET,
						   &peerid,
						   inetaddrstr,
						   INET_ADDRSTRLEN));
			 }
			 else	/* EBGP */
				 fprintf(fp, "from an EBGP peer, AS = %d\n",
					 rtp->rtp_bgp->rp_as);
			 if (ebnp)
				 dump_bgp_rtable(fp, ebnp->rp_adj_ribs_in);
			 else
				 fprintf(fp, "    No established peer\n");
			 break;
		 case RTPROTO_RIP:
			 fprintf(fp, "   RIPng routes\n");
			 dump_rip_rtable(fp, rtp->rtp_rip->rip_adj_ribs_in);

			 break;
		}

		if ((rtp = rtp->rtp_next) == base)
			break;
	}
}
#endif

static void
print_if_dump(FILE *fp)
{
	struct ifinfo *ife = ifentry;

	fprintf(fp, "=== Direct Interfaces Information ===\n");

	while(ife) {
		fprintf(fp, " Interface: %s\n", ife->ifi_ifn->if_name);
		fprintf(fp, "  Link-local Address: %s\n",
			ip6str(&ife->ifi_laddr, ife->ifi_ifn->if_index));
		fprintf(fp, "  Global Address: %s\n",
			IN6_IS_ADDR_UNSPECIFIED(&ife->ifi_gaddr) ? "NONE" :
			ip6str(&ife->ifi_gaddr, 0));
		fprintf(fp, "  Routes to the interface\n" );
		dump_if_rtable(fp, ife->ifi_rte);

		if ((ife = ife->ifi_next) == ifentry)
			break;
	}
}

static void
print_rip_dump(FILE *fp)
{
	struct ripif *ripif = ripifs;
	task *t = taskhead;
	extern time_t last_rip_dump;

	fprintf(fp, "\n=== RIPng generic information ===\n");
	while (t) {
		if (t->tsk_timename == RIP_DUMP_TIMER) {
			fprintf(fp, "  Dump timer=%d:%02d\n",
				(int)(t->tsk_timeval.tv_sec / 60),
				(int)(t->tsk_timeval.tv_usec % 60));
			break;
		}
		if ((t = t->tsk_next) == taskhead)
			break;
	}
	fprintf(fp, "  Last dump: %s", ctime(&last_rip_dump));
	fprintf(fp, "    (%s before)\n", sec2str(tloc_now - last_rip_dump));

	fprintf(fp, "\n=== RIPng per interface information ===\n");
	while(ripif) {
		fprintf(fp, " Interface: %s",
			ripif->rip_ife->ifi_ifn->if_name);
		if (ripif->rip_desc)
			fprintf(fp, " Description: %s", ripif->rip_desc);
		fputc('\n', fp);
		/* RIPng related flags */
		fprintf(fp, "  Flags:");
		if (ripif->rip_mode & IFS_NORIPIN)
			fprintf(fp, " NORIPIN");
		if (ripif->rip_mode & IFS_NORIPOUT)
			fprintf(fp, " NORIPOUT");
		if (ripif->rip_filterset.deffilterflags & DEFAULT_FILTERIN)
			fprintf(fp, " FILTERIN_DEFAULT");
		if (ripif->rip_filterset.deffilterflags & DEFAULT_FILTEROUT)
			fprintf(fp, " FILTEROUT_DEFAULT");
		if (ripif->rip_filterset.deffilterflags & DEFAULT_RESTRICTIN)
			fprintf(fp, " RESTRICTIN_DEFAULT");
		if (ripif->rip_filterset.deffilterflags & DEFAULT_RESTRICTOUT)
			fprintf(fp, " RESTRICTOUT_DEFAULT");
		if (ripif->rip_mode & IFS_DEFAULTORIGINATE)
			fprintf(fp, " DEFRT_ORIGINATE");
		fputc('\n', fp);

		/* RIPng routing table */
		fprintf(fp, "  RIPng routing table\n");		
		dump_rip_rtable(fp, ripif->rip_adj_ribs_in);
		/* RIPng filter statistics */
		fprintf(fp, "  RIPng filter information\n");
		dump_filterinfo(fp, "  ", &ripif->rip_filterset);

		if ((ripif = ripif->rip_next) == ripifs)
			break;
	}
}

static struct bgproute_list *
init_bgp_route_list()
{
	static struct bgproute_list head;

	memset(&head, 0, sizeof(head));
	head.next = head.prev = &head;
	return(&head);
}

/*
 * Compare two IPv6 prefixes. A supplement function.
 * Return value:
 *   -1 if rte1 < rte2
 *    0 if rte1 == rte2
 *   +1 if rte1 > rte2
 */
static int
prefix_comp(rte1, rte2)
	struct rt_entry *rte1, *rte2;
{
	u_int32_t i32_1, i32_2;
	int i;

	for (i = 0; i < 4; i++) {
		i32_1 = ntohl(*(u_int32_t *)&(rte1->rt_ripinfo.rip6_dest.s6_addr[i * 4]));
		i32_2 = ntohl(*(u_int32_t *)&(rte2->rt_ripinfo.rip6_dest.s6_addr[i * 4]));
		if (i32_1 < i32_2)
			return(-1);
		if (i32_1 > i32_2)
			return(1);
		/* continue to next 32 bits */
	}

	/* Two addresses are equal. Compare prefix length. */
	if (rte1->rt_ripinfo.rip6_plen < rte2->rt_ripinfo.rip6_plen)
		return(-1);
	if (rte1->rt_ripinfo.rip6_plen > rte2->rt_ripinfo.rip6_plen)
		return(1);
	return(0);		/* completely equal */
}

static void
insert_bgp_route_entry(list, rte, bnp)
	struct bgproute_list *list;
	struct rt_entry *rte;
	struct rpcb *bnp;
{
	struct bgproute_list *brl, *newbrl;
	struct rt_entry *orte;
	struct bgproute_entry **brep, *newbre;
	int cmp;

	for (brl = bgp_route_head(list); !bgp_route_isend(brl, list);
	     brl = bgp_route_next(brl)) {
		if (brl->entry == NULL || (orte = brl->entry->rte) == NULL) {
			syslog(LOG_ERR, "<%s>: bogus bgproute list(%p)",
				__FUNCTION__, brl);
			continue; /* XXX */
		}
		if ((cmp = prefix_comp(rte, orte)) == 0) /* rte == orte */
			goto insert_entry;
		else if (cmp > 0) /* rte > orte */
			continue;
		else {
			break;	/* insert new list and entry */
		}
	}
	if ((newbrl = (struct bgproute_list *)malloc(sizeof(*newbrl))) == NULL)
		fatalx("<insert_bgp_route_entry>: malloc failed"); /* XXX */
	memset(newbrl, 0, sizeof(*newbrl));
	bgp_route_insert(newbrl, brl);
	brl = newbrl;
	
  insert_entry:
	for (brep = &brl->entry; *brep; brep = &(*brep)->next) {
		orte = (*brep)->rte;
		/*
		 * if the new entry is preferred to the old one, insert here.
		 * A route that is installed to the kernel is the most preferable
		 * one. There is no preference between routes that is not up. 
		 */
		if ((rte->rt_flags & RTF_INSTALLED) ||
		    !(orte->rt_flags & RTF_UP))
			break;
	}
	/* allocate a new entry and insert it */
	if ((newbre = (struct bgproute_entry *)malloc(sizeof(*newbre))) == NULL)
		fatalx("<insert_bgp_route_entry>: malloc failed"); /* XXX */
	newbre->head = brl;
	newbre->bnp = bnp;
	newbre->rte = rte;
	newbre->next = *brep;
	*brep = newbre;
}

static struct bgproute_list *
make_bgp_route_list()
{
	extern struct rpcb *bgb;
	struct bgproute_list *brl;
	struct rpcb *bnp = bgb;
	struct rt_entry *rte;

	brl = init_bgp_route_list();
	
	while(bnp) {
		if (bnp->rp_state == BGPSTATE_ESTABLISHED) {
			rte = bnp->rp_adj_ribs_in;
			while(rte) {
				insert_bgp_route_entry(brl, rte, bnp);
				if ((rte = rte->rt_next) == bnp->rp_adj_ribs_in)
					break;
			}
		}

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}

	return(brl);
}

static void
free_bgp_route_list(head)
	struct bgproute_list *head;
{
	struct bgproute_list *brl, *brl_next;
	struct bgproute_entry *bre, *bre_next;

	for (brl = bgp_route_head(head); !bgp_route_isend(brl, head);
	     brl = brl_next) {
		brl_next = bgp_route_next(brl);	/* brl will soon be freed */

		for (bre = brl->entry; bre; bre = bre_next) {
			bre_next = bre->next; /* bre will soon be freed */
			free(bre);
		}

		remque(brl);
		free(brl);
	}
}

static void
show_bgp_route_entry(fp, bre)
	FILE *fp;
	struct bgproute_entry *bre;
{
	struct rpcb *bnp = bre->bnp;
	char inetaddrstr[INET_ADDRSTRLEN]; /* XXX */
	char *indent = " ";

	dump_bgp_rtentry(fp, bre->rte, indent);
	fprintf(fp, "%s  PeerInfo: Addr: %s,\n", indent, bgp_peerstr(bnp));
	
	fprintf(fp, "%s            ID: %s, Type: %s\n", indent,
		inet_ntop(AF_INET, &bnp->rp_id, inetaddrstr, INET_ADDRSTRLEN),
		(bnp->rp_mode & BGPO_IGP) ? "IBGP" : "EBGP");
	fprintf(fp, "%s  Last Update: %s", indent,
		ctime(&bre->rte->rt_time));
	if (bre->rte->rt_flags & RTF_INSTALLED)
		dump_bgp_exportlist(fp, bre->rte, indent);
}

static struct bgproute_entry *
bgp_route_headentry(head)
	struct bgproute_list *head;
{
	struct bgproute_list *brl;

	brl = bgp_route_head(head);
	return(brl->entry);
}

static struct bgproute_entry *
bgp_route_nextentry(listhead, prev)
	struct bgproute_list *listhead;
	struct bgproute_entry *prev;
{
	struct bgproute_list *brl;

	if (prev->next)
		return(prev->next);

	for (brl = prev->head->next; brl != listhead; brl = brl->next) {
		if (brl->entry)
			return(brl->entry);
	}

	return(NULL);
}

/* show a sorted list of BGP routes per prefix */
static void
print_bgp_routes(fp)
	FILE *fp;
{
	struct bgproute_list *brl;
	struct bgproute_entry *bre;

	brl = make_bgp_route_list(); /* make a sorted list */
	for (bre = bgp_route_headentry(brl); bre;
	     bre = bgp_route_nextentry(brl, bre)) {
		fputc('\n', fp);
		show_bgp_route_entry(fp, bre);
	}
	free_bgp_route_list(brl);
}


static void
show_bgp_peer(FILE *fp, struct rpcb *bnp, char *indent)
{
	char inetaddrstr[INET_ADDRSTRLEN];
	static char *bgpstate[] = {"", /* dummy */
				   "IDLE", "CONNECT", "ACTIVE",
				   "OPENSENT", "OPENCONFERM",
				   "ESTABLISHED"};
	struct rpcb *abnp = find_aopen_peer(bnp);

	fprintf(fp, "%sAS: %d, ", indent, bnp->rp_as);
	fprintf(fp, "Router Id: %s, ",
		inet_ntop(AF_INET, &bnp->rp_id,
			  inetaddrstr, INET_ADDRSTRLEN));
	fprintf(fp, "state: %s, ", bgpstate[bnp->rp_state]);
	fprintf(fp, "localpref: %d\n", (int)ntohl(bnp->rp_prefer));

	fprintf(fp, "%sMode:", indent);
	if (bnp->rp_mode & BGPO_PASSIVE) fprintf(fp, " PASSIVE");
	if (bnp->rp_mode & BGPO_IFSTATIC) fprintf(fp, " IFSTATIC");
	if (bnp->rp_mode & BGPO_IGP)
		fprintf(fp, " IBGP");
	else
		fprintf(fp, " EBGP");
	if (bnp->rp_mode & BGPO_RRCLIENT) fprintf(fp, " RRCLIENT");
	if (bnp->rp_mode & BGPO_ONLINK) fprintf(fp, " ONLINK");
	if (bnp->rp_mode & BGPO_IDSTATIC) fprintf(fp, " IDSTATIC");
	if (bnp->rp_mode & BGPO_NOSYNC) fprintf(fp, " NOSYNC");
	if (bnp->rp_mode & BGPO_NEXTHOPSELF) fprintf(fp, " NEXTHOPSELF");
	if (abnp) {
		if (abnp->rp_filterset.deffilterflags & DEFAULT_FILTERIN)
			fprintf(fp, " FILTERIN_DEFAULT");
		if (abnp->rp_filterset.deffilterflags & DEFAULT_FILTEROUT)
			fprintf(fp, " FILTEROUT_DEFAULT");
		if (abnp->rp_filterset.deffilterflags & DEFAULT_RESTRICTIN)
			fprintf(fp, " RESTRICTIN_DEFAULT");
		if (abnp->rp_filterset.deffilterflags & DEFAULT_RESTRICTOUT)
			fprintf(fp, " RESTRICTOUT_DEFAULT");
	}
	fputc('\n', fp);

	fprintf(fp, "%sHis global addr: %s\n", indent, bgp_peerstr(bnp));
	fprintf(fp, "%sHis local addr: %s\n", indent, bgp_peerstr(bnp));
	fprintf(fp, "%sOur addr: %s\n", indent,
		ip6str(&bnp->rp_myaddr.sin6_addr, 0));
	fprintf(fp, "%sTimers:", indent);
	if (bnp->rp_connect_timer)
		fprintf(fp, " connect=%d:%02d",
			(int)(bnp->rp_connect_timer->tsk_timeval.tv_sec/60),
			(int)(bnp->rp_connect_timer->tsk_timeval.tv_sec%60));
	if (bnp->rp_hold_timer)
		fprintf(fp, " hold=%d:%02d",
			(int)(bnp->rp_hold_timer->tsk_timeval.tv_sec/60),
			(int)(bnp->rp_hold_timer->tsk_timeval.tv_sec%60));
	if (bnp->rp_keepalive_timer)
		fprintf(fp, " keepalive=%d:%02d",
			(int)(bnp->rp_keepalive_timer->tsk_timeval.tv_sec/60),
			(int)(bnp->rp_keepalive_timer->tsk_timeval.tv_sec%60));
	fputc('\n', fp);

	/*
	 * Dump filter information and statistics if
	 * - there is an actively opened peer (it must be, though), and
	 *   + bnp is active, or
	 *   + it is an actively opend peer and there is no other active peer.
	 */
	if (abnp &&
	    (bnp->rp_state != BGPSTATE_IDLE ||
	     ((bnp->rp_mode & BGPO_PASSIVE) == 0 &&
	      find_active_peer(bnp) == NULL))) {
		fprintf(fp, "%sStatistics:\n", indent);
		fprintf(fp, "%s Connection retries: %qu\n",
			indent, abnp->rp_stat.rps_connretry);
		fprintf(fp, "%s Peering establishments: %qu\n",
			indent, abnp->rp_stat.established);
		fprintf(fp, "%s OPENs: in/out: %qu/%qu\n",
			indent, abnp->rp_stat.openrcvd,
			abnp->rp_stat.opensent);
		fprintf(fp, "%s UPDATEs: in/out: %qu/%qu\n",
			indent, abnp->rp_stat.updatercvd,
			abnp->rp_stat.updatesent);
		fprintf(fp, "%s NOTIFYs: in/out: %qu/%qu\n",
			indent, abnp->rp_stat.notifyrcvd,
			abnp->rp_stat.notifysent);
		fprintf(fp, "%s KEEPALIVEs: in/out: %qu/%qu\n",
			indent, abnp->rp_stat.keepalivercvd,
			abnp->rp_stat.keepalivesent);
		fprintf(fp, "%s WITHDRAWs: in/out: %qu/%qu\n",
			indent, abnp->rp_stat.withdrawrcvd,
			abnp->rp_stat.withdrawsent);
		if (abnp->rp_stat.last_established) {
			/* ctime appends \n */
			fprintf(fp, "%s Last esbalished: %s", indent,
				ctime(&abnp->rp_stat.last_established));
			if (bnp->rp_state == BGPSTATE_ESTABLISHED)
				fprintf(fp,
					"%s   has been established for %s\n",
					indent,
					sec2str(tloc_now -
						abnp->rp_stat.last_established));
			fprintf(fp, "%s Max esbalished period: %s\n", indent,
				sec2str(abnp->rp_stat.max_establihed_period));
			fprintf(fp, "%s Min esbalished period: %s\n", indent,
				sec2str(abnp->rp_stat.min_establihed_period));
		}
		if (abnp->rp_stat.last_closed) {
			/* ctime appends \n */
			fprintf(fp, "%s Last closed: %s", indent,
				ctime(&abnp->rp_stat.last_established));
			if (bnp->rp_state != BGPSTATE_ESTABLISHED)
				fprintf(fp,
					"%s   hasn't been established for %s\n",
					indent,
					sec2str(tloc_now -
						abnp->rp_stat.last_closed));
		}
		fprintf(fp, "%sFilters:\n", indent);
		dump_filterinfo(fp, indent, &abnp->rp_filterset);
	}
	if (bnp->rp_ebgp_as_prepends)
		fprintf(fp, "%sour own AS number will be prepended "
			"to each advertised AS path %d time%s\n", indent,
			bnp->rp_ebgp_as_prepends,
			(bnp->rp_ebgp_as_prepends == 1) ? "" : "s");
#if 0
	fprintf(fp, "  Imported routes from the peer:\n");
	dump_bgp_rtable(fp, bnp->rp_adj_ribs_in);

	fprintf(fp, "  Exported routes to the peer:\n");
	dump_exports(fp, bnp->rp_adj_ribs_out);
#endif
}

static void
print_bgp_dump(FILE *fp)
{
	struct rpcb *bnp;
	char inetaddrstr[INET_ADDRSTRLEN];
	extern struct rpcb *bgb;
	extern u_int16_t    my_as_number;
	extern u_int32_t    bgpIdentifier;
	extern u_int32_t    clusterId;
	extern u_int16_t    bgpHoldtime;
	extern byte         IamRR;

	bnp = bgb;
	if (bnp) {
		fprintf(fp, "\n=== BGP local information ===\n");
		fprintf(fp, "  AS: %d, ", my_as_number);
		fprintf(fp, "RouterId: %s, ",
			inet_ntop(AF_INET, &bgpIdentifier,
				  inetaddrstr, INET_ADDRSTRLEN));
		fprintf(fp, "ClusterId: %s\n",
			inet_ntop(AF_INET, &clusterId,
				  inetaddrstr, INET_ADDRSTRLEN));
		fprintf(fp, "  HoldTime: %d", bgpHoldtime);
		if (IamRR)
			fprintf(fp, ", Reflector");
		fputc('\n', fp);

		fprintf(fp, "\n=== BGP per peer information ===\n");
	}
	/* show established peer first */
	while(bnp) {
		if (bnp->rp_state == BGPSTATE_ESTABLISHED) {
			show_bgp_peer(fp, bnp, "  ");
			fputc('\n', fp);
		}

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}
	/*
	 * Then show non-established peers, skipping established passive-opend
	 * peers.
	 */
	bnp = bgb;
	while(bnp) {
		if (bnp->rp_state != BGPSTATE_ESTABLISHED &&
		    find_epeer_by_rpcb(bnp) == NULL) {
			show_bgp_peer(fp, bnp, "  ");
			fputc('\n', fp);
		}

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}

	if (bnp) {
		fprintf(fp, "\n=== BGP routing information ===\n");
		print_bgp_routes(fp);
	}

}

void
bgpd_dump_file()
{
	FILE *fp;

	if ((fp = fopen(dumpfile, "w")) == NULL) {
		syslog(LOG_ERR, "<%s>: can't open dump file(%s): %s",
			__FUNCTION__, dumpfile, strerror(errno));
		return;
	}

	(void)time(&tloc_now);
	fprintf(fp, "\n************ bgpd dump on %s", ctime(&tloc_now));
	print_if_dump(fp);
	print_rip_dump(fp);
	print_bgp_dump(fp);

	fclose(fp);
}

static char *
aspath2str(struct aspath *aspath)
{
	struct asnum *asn;
	struct asseg *asg;
	int l = 0, bufwlen, palen, slen;
	static char buf[LINE_MAX];

	if ((asg = aspath->asp_segment) == NULL)
		return("Nil");

	for (palen = 0 ; palen < aspath->asp_len ; palen++) {
		if (asg->asg_type == PA_PATH_SET) {
			strcpy(&buf[l], "set(");
			l += 4;
		}

		asn = asg->asg_asn;
		for (slen = 0; slen < asg->asg_len; slen++) {
			bufwlen = sprintf(&buf[l], "%u ", asn->asn_num);
			l += bufwlen;
			asn = asn->asn_next;
		}

		if (asg->asg_type == PA_PATH_SET) {
			strcpy(&buf[l-1], ") ");
			l++;
		}

		asg = asg->asg_next;
	}

	return(buf);
}

static char *
cll2str(cll)
	struct clstrlist *cll;
{
	static char buf[LINE_MAX];
	char inetaddrstr[INET_ADDRSTRLEN];
	struct clstrlist *cll_top = cll;
	int l = 0;

	if (cll == NULL)
		return("Nil");

	while(cll) {
		l += sprintf(&buf[l], "%s ", inet_ntop(AF_INET, &cll->cll_id,
						       inetaddrstr,
						       INET_ADDRSTRLEN));
		if ((cll = cll->cll_next) == cll_top)
			break;
	}

	return(buf);
}
