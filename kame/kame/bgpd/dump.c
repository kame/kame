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

extern struct ripif *ripifs;	/* defined in ripng.c */

char *dumpfile;
#define DUMPFILE "/var/tmp/bgpd.dump"

static char *aspath2str(struct aspath *);
static char *cll2str(struct clstrlist *);

static void
dump_if_rtable(FILE *fp, struct rt_entry *base)
{
	struct rt_entry *rte = base;

	while(rte) {
		fprintf(fp, "    "); /* indentation */
		fprintf(fp, "%s/%d(%d)\n",
			ip6str(&rte->rt_ripinfo.rip6_dest, 0),
			rte->rt_ripinfo.rip6_plen,
			rte->rt_ripinfo.rip6_metric);

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
			fprintf(fp, " timeout=%d:%d",
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
dump_rip_filterinfo(FILE *fp, struct ripif *ripif)
{
	struct filtinfo *filter;

	fprintf(fp, "  RIPng filter information\n");

	if ((filter = ripif->rip_filterin) != NULL) {
		fprintf(fp, "    Input filter:\n");
		print_filterinfo(fp, filter, FILTERTYPE_FILTER);
	}
	if ((filter = ripif->rip_filterout) != NULL) {
		fprintf(fp, "    Output filter:\n");
		print_filterinfo(fp, filter, FILTERTYPE_FILTER);
	}
	if ((filter = ripif->rip_restrictin) != NULL) {
		fprintf(fp, "    Input restriction:\n");
		print_filterinfo(fp, filter, FILTERTYPE_RESTRICTION);
	}
	if ((filter = ripif->rip_restrictout) != NULL) {
		fprintf(fp, "    Output restriction:\n");
		print_filterinfo(fp, filter, FILTERTYPE_RESTRICTION);
	}

	if (ripif->rip_mode & IFS_DEFAULT_FILTERIN)
		fprintf(fp, "    %d incoming default routes were filtered\n",
			ripif->rip_filtered_indef);
	if (ripif->rip_mode & IFS_DEFAULT_FILTEROUT)
		fprintf(fp, "    %d outgoing default routes were filtered\n",
			ripif->rip_filtered_outdef);
	if ((ripif->rip_mode & IFS_DEFAULT_RESTRICTIN) ||
	    ripif->rip_restrictin)
		fprintf(fp,
			"    %d incoming routes were filtered by restriction\n",
			ripif->rip_input_restrected);
	if ((ripif->rip_mode & IFS_DEFAULT_RESTRICTOUT) ||
	    ripif->rip_restrictout)
		fprintf(fp,
			"    %d outgoing routes were filtered by restriction\n",
			ripif->rip_output_restrected);
}

static void
dump_bgp_rtable(FILE *fp, struct rt_entry *base)
{
	struct rt_entry *rte = base;
	struct aspath *ap;
	char inetaddrstr[INET_ADDRSTRLEN];
	extern char *origin_str[];
	struct optatr *optatr;

	while(rte) {
		ap = rte->rt_aspath;

		fprintf(fp, "    "); /* indentation */
		fprintf(fp, "%s/%d nexthop: %s\n",
			ip6str(&rte->rt_ripinfo.rip6_dest, 0),
			rte->rt_ripinfo.rip6_plen, ip6str(&rte->rt_bgw, 0));

		fprintf(fp, "      "); /* more indent */
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
			fprintf(fp, "        "); /* more^2 indent */
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
				fprintf(fp, "        ");
				fprintf(fp, "             %s)",
					ip6str(&rte->rt_gwsrc_entry->rt_gw,
					       rte->rt_gwif->ifi_ifn->if_index));
				break;
			default:
				fprintf(fp, "gwsrc: unknown(%d)",
					rte->rt_gwsrc_type);
				break;
			}
			fputc('\n', fp);
		}

		fprintf(fp, "      "); /* more indent */
		fprintf(fp, "MED: %d localpref: %d origin: ID=%s,code=%s\n",
			(int)ntohl(ap->asp_med), (int)ntohl(ap->asp_localpref),
			inet_ntop(AF_INET, &ap->asp_origid,
				  inetaddrstr, INET_ADDRSTRLEN),
			origin_str[ap->asp_origin]);

		fprintf(fp, "      "); /* more indent */
		fprintf(fp, "ASPATH: %s\n", aspath2str(ap));
		if (ap->asp_clstr) {
			fprintf(fp, "      "); /* more indent */
			fprintf(fp, "Cluster list: %s\n",
				cll2str(ap->asp_clstr));
		}

		/* unrecognized attributes */
		if ((optatr = ap->asp_optatr) != NULL)
			fprintf(fp, "      Unrecognized Attributes:\n");
		for (optatr = ap->asp_optatr; optatr; optatr = optatr->next) {
			int c = 0;

			fprintf(fp, "        ");
			for (c = 0; c < optatr->len && c < 20; c++)
				fprintf(fp, "%02x ",
					(unsigned char)optatr->data[c]);
			if (optatr->len > 20)
				fprintf(fp, "...");
			fputc('\n', fp);
		}

		if ((rte = rte->rt_next) == base)
			break;
	}
}

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

static void
print_ifrt_dump(FILE *fp)
{
	struct ripif *ripif = ripifs;

	fprintf(fp, "=== Interface routes ===\n");
	while(ripif) {
		fprintf(fp, " Interface: %s\n",
			ripif->rip_ife->ifi_ifn->if_name);
		dump_if_rtable(fp, ripif->rip_ife->ifi_rte);

		if ((ripif = ripif->rip_next) == ripifs)
			break;
	}
}

static void
print_rip_dump(FILE *fp)
{
	struct ripif *ripif = ripifs;

	fprintf(fp, "\n=== RIPng per interface information ===\n");
	while(ripif) {
		fprintf(fp, " Interface: %s\n",
			ripif->rip_ife->ifi_ifn->if_name);
		/* RIPng related flags */
		fprintf(fp, "  Flags:");
		if (ripif->rip_mode & IFS_NORIPIN)
			fprintf(fp, " NORIPIN");
		if (ripif->rip_mode & IFS_NORIPOUT)
			fprintf(fp, " NORIPOUT");
		if (ripif->rip_mode & IFS_DEFAULT_FILTERIN)
			fprintf(fp, " FILTERIN_DEFAULT");
		if (ripif->rip_mode & IFS_DEFAULT_FILTEROUT)
			fprintf(fp, " FILTEROUT_DEFAULT");
		if (ripif->rip_mode & IFS_DEFAULT_RESTRICTIN)
			fprintf(fp, " RESTRICTIN_DEFAULT");
		if (ripif->rip_mode & IFS_DEFAULT_RESTRICTOUT)
			fprintf(fp, " RESTRICTOUT_DEFAULT");
		if (ripif->rip_mode & IFS_DEFAULTORIGINATE)
			fprintf(fp, " DEFRT_ORIGINATE");
		fputc('\n', fp);

		/* RIPng routing table */
		fprintf(fp, "  RIPng routing table\n");		
		dump_rip_rtable(fp, ripif->rip_adj_ribs_in);
		/* RIPng filter statistics */
		dump_rip_filterinfo(fp, ripif);

		if ((ripif = ripif->rip_next) == ripifs)
			break;
	}
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

	static char *bgpstate[] = {"", /* dummy */
				   "IDLE", "CONNECT", "ACTIVE",
				   "OPENSENT", "OPENCONFERM",
				   "ESTABLISHED"};

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
	while(bnp) {
		fprintf(fp, "  AS: %d, ", bnp->rp_as);
		fprintf(fp, "Router Id: %s, ",
			inet_ntop(AF_INET, &bnp->rp_id,
				  inetaddrstr, INET_ADDRSTRLEN));
		fprintf(fp, "state: %s, ", bgpstate[bnp->rp_state]);
		fprintf(fp, "localpref: %d\n", (int)ntohl(bnp->rp_prefer));

		fprintf(fp, "  Mode:");
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
		fputc('\n', fp);

		fprintf(fp, "  His global addr: %s\n", bgp_peerstr(bnp));
		fprintf(fp, "  His local addr: %s\n", bgp_peerstr(bnp));
		fprintf(fp, "  Our addr: %s\n",
			ip6str(&bnp->rp_myaddr.sin6_addr, 0));
		if (bnp->rp_ebgp_as_prepends)
			fprintf(fp, "  our own AS number will be prepended "
				"to each advertised AS path %d time%s\n",
				bnp->rp_ebgp_as_prepends,
				(bnp->rp_ebgp_as_prepends == 1) ? "" : "s");

		fprintf(fp, "  Imported routes from the peer:\n");
		dump_bgp_rtable(fp, bnp->rp_adj_ribs_in);

		fprintf(fp, "  Exported routes to the peer:\n");
		dump_exports(fp, bnp->rp_adj_ribs_out);

		if ((bnp = bnp->rp_next) == bgb)
			break;
	}
}

void
bgpd_dump_file()
{
	time_t tloc;
	FILE *fp;

	if (dumpfile == NULL)
		dumpfile = DUMPFILE;
	if ((fp = fopen(dumpfile, "w")) == NULL) {
		syslog(LOG_ERR, "<%s>: can't open dump file(%s): %s",
			__FUNCTION__, dumpfile, strerror(errno));
		return;
	}

	(void)time(&tloc);
	fprintf(fp, "\n************ bgpd dump on %s", ctime(&tloc));
	print_ifrt_dump(fp);
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
