/*
 * Copyright (C) 2000 WIDE Project.
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
%{
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <err.h>

#include "include.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "rt_table.h"
#include "aspath.h"
#include "bgp_var.h"
#include "in6.h"
#include "ripng.h"
#include "ripng_var.h"
#include "debug.h"
#include "cfparse.h"
#include "vmbuf.h"

#define set_param(var,val,p) \
	do {\
		if ((var) != -1) {\
			yywarn("%s doubly defined(ignore %d)", (p), (val));\
		}\
		else {\
			(var) = val;\
		}\
	} while(0)
#define set_string(var,val,p) \
	do {\
		if ((var) != NULL) {\
			yywarn("%s doubly defined(ignore %s)", (p), (val));\
			free(p);\
		}\
		else {\
			(var) = val;\
		}\
	} while(0)

#define cprint if (confcheck) printf

struct in6_prefix {
	struct sockaddr_in6 paddr;
	int plen;
};

struct attr_list {
	struct attr_list *next;
	int code;
	int type;
	int line;
	union {
		char *str;
		void *data;
		unsigned int flags;
		int number;
		struct sockaddr_in6 in6addr;
		struct in6_prefix prefix;
		struct attr_list *list;
	}attru;
};

struct yy_route_entry {
	struct yy_route_entry *next;
	struct in6_prefix prefix;
	int gwtype;
	int line;
	union {
		struct sockaddr_in6 gateway;
		char ifname[IFNAMSIZ];
	} reu;
};

struct yy_ripifinfo {
	struct yy_ripifinfo *next;
	char ifname[IFNAMSIZ];
	struct attr_list *attribute;
	int line;
};

struct yy_bgppeerinfo {
	struct yy_bgppeerinfo *next;
	int asnum;
	u_int32_t routerid;
	int peertype;		/* an ordinal peer or an IBGP cluster client */
	struct sockaddr_in6 peeraddr;
	struct attr_list *attribute;
	int line;
};

struct yy_exportinfo {		/* XXX: BGP depend */
	struct yy_exportinfo *next;
	int asnum;
	int line;
	struct sockaddr_in6 peeraddr;
	struct attr_list *protolist;
};

struct yy_aggrinfo {
	struct yy_aggrinfo *next;
	struct in6_prefix prefix;
	struct attr_list *aggrinfo;
	int line;
};

struct yy_rtproto {
	int type;
	union {
		struct {
			int peeras;
			struct sockaddr_in6 peeraddr;
		}rtpu_bgp;
		char ifname[IFNAMSIZ];
	}rtpu;
};

enum {GW_IFACE, GW_ADDR};
enum {RIPIFA_DEFAULT, RIPIFA_NORIPIN, RIPIFA_NORIPOUT, RIPIFA_METRICIN,
      RIPIFA_FILINDEF, RIPIFA_FILOUTDEF, RIPIFA_RESINDEF, RIPIFA_RESOUTDEF,
      RIPIFA_FILINPFX, RIPIFA_FILOUTPFX, RIPIFA_RESINPFX, RIPIFA_RESOUTPFX,
      RIPIFA_DESCR, BGPPA_IFNAME, BGPPA_NOSYNC, BGPPA_NEXTHOPSELF,
      BGPPA_LCLADDR, BGPPA_PREFERENCE, BGPPA_PREPEND, BGPPA_DESCR,
      BGPPA_FILINDEF, BGPPA_FILOUTDEF, BGPPA_RESINDEF, BGPPA_RESOUTDEF,
      BGPPA_FILINPFX, BGPPA_FILOUTPFX, BGPPA_RESINPFX, BGPPA_RESOUTPFX,
      EXPA_PROTO, AGGA_PROTO, AGGA_EXPFX, STATICA_RTE};
enum {ATTR_FLAG, ATTR_PREFIX, ATTR_STRING, ATTR_ADDR, ATTR_NUMBER,
      ATTR_DATA, ATTR_LIST};
enum {BGPPEER_NORMAL, BGPPEER_CLIENT}; 
enum {RTP_IFACE, RTP_BGP, RTP_RIP, RTP_IBGP}; 

static struct in6_prefix in6pfx_temp; /* XXX */
static struct yy_route_entry static_temp; /* XXX */
static struct yy_bgppeerinfo bgppeer_temp; /* XXX file global */
static struct yy_bgppeerinfo *yy_bgppeer_head;
static struct yy_route_entry *yy_static_head;
static int yy_debug, yy_asnum, yy_bgpsbsize, yy_holdtime, yy_rrflag,
	yy_rip, yy_rip_sitelocal;
static long yy_routerid, yy_clusterid; /* XXX sizoef(long)? */
static int yy_bgp;
static char *yy_dumpfile;
static struct yy_ripifinfo *yy_ripifinfo_head;
static struct yy_exportinfo *yy_exportinfo_head;
static struct yy_aggrinfo *yy_aggr_head;

extern int lineno;
extern int confcheck;
extern char *configfilename;

extern char *dumpfile;
extern u_int32_t bgpIdentifier, clusterId;
extern u_int16_t my_as_number, bgpHoldtime;
extern byte ripyes, bgpyes, IamRR;
extern struct rpcb *bgb;

#define DUMPFILENAME "/var/run/bgpd.dump"

extern void insque __P((void *, void *)); /* XXX */
extern int yylex __P((void));
%}

%union {
	unsigned long num;
	vchar_t val;
	struct attr_list *attr;
	struct in6_prefix *prefix;
	struct yy_bgppeerinfo *bpeer;
	struct yy_rtproto *rtp;
}

%token EOS BCL ECL
%token YES NO ALL DESCR DESCSTRING IGNORE_END
%token NUMBER STRING SLASH
%token LOG LOGLEV NOLOGLEV
%token LOGASPATH NOLOGASPATH LOGBGPSTATE NOLOGBGPSTATE LOGBGPCONNECT
%token NOLOGBGPCONNECT LOGBGPINPUT NOLOGBGPINPUT LOGBGPOUTPUT NOLOGBGPOUTPUT
%token LOGBGPROUTE NOLOGBGPROUTE LOGINTERFACE NOLOGINTERFACE LOGINET6
%token NOLOGINET6 LOGRIP NOLOGRIP LOGROUTE NOLOGROUTE LOGFILTER NOLOGFILTER
%token LOGTIMER NOLOGTIMER
%token DUMPFILE
%token AUTONOMOUSSYSTEM ROUTERID CLUSTERID HOLDTIME ROUTEREFLECTOR BGPSBSIZE
%token INTERFACE IFNAME
%token STATIC GATEWAY
%token RIP DEFAULT ORIGINATE NORIPIN NORIPOUT SITELOCAL METRICIN
%token FILTERIN FILTEROUT RESTRICTIN RESTRICTOUT
%token BGP GROUP TYPE INTERNAL EXTERNAL PEER CLIENT PEERAS AS
%token SYNCHRONIZATION PREFERENCE PREPEND LCLADDR NEXTHOPSELF NOSYNC
%token EXPORT
%token AGGREGATE EXPLICIT
%token PROTO DIRECT IBGP

%type <num> LOGLEV NOLOGLEV NUMBER
%type <val> STRING IFNAME DESCSTRING
%type <attr> rip_ifattributes peerattributes export_list
%type <attr> aggregate_substatements prefix_list
%type <prefix> prefix
%type <bpeer> peerstatements
%type <rtp> protocol

%%
statements:
		/* empty */
	|	statements statement
	;

statement:
		logging_statement
	|	param_statement
	|	static_statement
	|	rip_statement
	|	bgp_statement
	|	export_statement
	|	aggregate_statement
	;

/* logging */
logging_statement:
	LOG log_specs EOS
	;

log_specs:
		/* empty */
	|	log_specs LOGLEV {yy_debug |= $2;}
	|	log_specs NOLOGLEV {yy_debug &= ~($2);}
	;

param_statement:
		DUMPFILE STRING EOS
		{
			set_string(yy_dumpfile, $2.v, "dumpfile");
		}
	|
		AUTONOMOUSSYSTEM NUMBER EOS
		{
			set_param(yy_asnum, $2, "AS number");
		}
	|	BGPSBSIZE NUMBER EOS
		{
			set_param(yy_bgpsbsize, $2, "BGP sbsize");
		}
	|	ROUTERID STRING EOS
		{
			struct in_addr routerid;

			/* we don't regared -1 as a valid IPv4 address */
			if ((inet_aton($2.v, &routerid)) == 0 &&
			    routerid.s_addr == (u_int32_t)-1) {
				yywarn("invalid router ID: %s", $2.v);
				free($2.v);
				return(-1);
			}
			set_param(yy_routerid, routerid.s_addr, "RouterID");
			free($2.v);
		}
	|	CLUSTERID STRING EOS
		{
			struct in_addr clusterid;

			/* we don't regared -1 as a valid IPv4 address */
			if ((inet_aton($2.v, &clusterid)) == 0 &&
			    clusterid.s_addr == (u_int32_t)-1) {
				yywarn("invalid cluster ID: %s", $2.v);
				free($2.v);
				return(-1);
			}
			set_param(yy_clusterid, clusterid.s_addr, "ClusterID");
			free($2.v);
		}
	|	HOLDTIME NUMBER EOS
		{
			if ($2 > 0 && $2 < 3) {
				yywarn("invalid hold timer value: %d", $2);
				return(-1);
			}
			set_param(yy_holdtime, $2, "holdtime");
		}
	|	ROUTEREFLECTOR EOS
		{
			set_param(yy_rrflag, 1, "route reflector");
		}
	;

/* Static Route */
static_statement: STATIC BCL static_routes ECL EOS

static_routes:
		/* empty */
	|	static_routes static_route
	;

static_route:
		prefix GATEWAY STRING EOS
		{
			static_temp.prefix = *($1);
			if (get_in6_addr($3.v, &static_temp.reu.gateway)) {
				yywarn("bad IPv6 gateway address: %s",
				       $3.v);
				free($3.v);
				return(-1);
			}
			free($3.v);
			static_temp.gwtype = GW_ADDR;
			if (add_static(&static_temp))
				return(-1);
		}
	|	prefix INTERFACE IFNAME EOS
		{
			static_temp.prefix = *($1);
			strncpy(static_temp.reu.ifname, $3.v,
				sizeof(static_temp.reu.ifname));
			free($3.v);
			static_temp.gwtype = GW_IFACE;
			if (add_static(&static_temp))
				return(-1);
		}
	;

/* RIP */
rip_statement:
		RIP YES BCL rip_substatements ECL EOS
		{
			if (yy_rip != -1) {
				yywarn("RIP(yes) doubly defined (ignored)");
				return(-1);
			}
			yy_rip = 1;
		}
	|	RIP BCL rip_substatements ECL EOS
		{
			if (yy_rip != -1) {
				yywarn("RIP(yes) doubly defined (ignored)");
				return(-1);
			}
			yy_rip = 1;
		}
	|	RIP NO IGNORE_END EOS
		{
			if (yy_rip != -1) {
				yywarn("RIP(no) doubly defined (ignored)");
				return(-1);
			}
			yy_rip = 0;
		}
	;

rip_substatements:
		/* empty */
	|	rip_substatements rip_substatement
	;

rip_substatement:
		INTERFACE IFNAME rip_ifattributes EOS
		{
			struct yy_ripifinfo *ifinfo;
			
			ifinfo = add_ripifinfo($2.v);
			if (ifinfo == NULL) {
				yywarn("can't add RIP interface: %s", $2.v);
				free($2.v);
				return(-1);
			}
			else {
				struct attr_list *p;

				for (p = (struct attr_list *)ifinfo->attribute;
				     p && p->next; p = p->next)
					;
				if (p)
					p->next = (void *)$3;
				else
					ifinfo->attribute = (void *)$3;
			}
			free($2.v);
		}
	|	SITELOCAL YES EOS
		{
			set_param(yy_rip_sitelocal, 1, "RIP site-local");
		}
	|	SITELOCAL NO EOS
		{
			set_param(yy_rip_sitelocal, 0, "RIP site-local");
		}
	;

rip_ifattributes:
		{ $$ = NULL; }
	|	rip_ifattributes DEFAULT ORIGINATE
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_DEFAULT, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes NORIPIN
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_NORIPIN, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes NORIPOUT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_NORIPOUT, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes METRICIN NUMBER
		{
			int metric = $3;
			
			if (metric < 0 || metric >= 16) {
				yywarn("invalid RIP metric(%d)", metric);
				return(-1);
			}
			if (($$ = add_attribute($1, ATTR_NUMBER,
						RIPIFA_METRICIN, &metric)) ==
			    NULL)
				return(-1);
		}
	|	rip_ifattributes FILTERIN DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_FILINDEF, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes FILTEROUT DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_FILOUTDEF, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes RESTRICTIN DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_RESINDEF, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes RESTRICTOUT DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						RIPIFA_RESOUTDEF, 0)) == NULL)
				return(-1);
		}
	|	rip_ifattributes FILTERIN prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						RIPIFA_FILINPFX, $3)) == NULL)
				return(-1);
		}
	|	rip_ifattributes FILTEROUT prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						RIPIFA_FILOUTPFX, $3)) == NULL)
				return(-1);
		}
	|	rip_ifattributes RESTRICTIN prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						RIPIFA_RESINPFX, $3)) == NULL)
				return(-1);
		}
	|	rip_ifattributes RESTRICTOUT prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						RIPIFA_RESOUTPFX, $3)) == NULL)
				return(-1);
		}
	|	rip_ifattributes DESCR DESCSTRING
		{
			if (($$ = add_attribute($1, ATTR_STRING,
						RIPIFA_DESCR, $3.v)) == NULL)
				return(-1);
		}
	;

/* BGP */
bgp_statement:
		BGP YES BCL bgp_substatements ECL EOS
		{
			if (yy_bgp != -1) {
				yywarn("BGP(yes) doubly defined (ignored)");
				return(-1);
			}
			yy_bgp = 1;
		}
	|
		BGP BCL bgp_substatements ECL EOS
		{
			if (yy_bgp != -1) {
				yywarn("BGP(yes) doubly defined (ignored)");
				return(-1);
			}
			yy_bgp = 1;
		}
	|
		BGP NO IGNORE_END
		{
			if (yy_bgp != -1) {
				yywarn("BGP(no) doubly defined (ignored)");
				return(-1);
			}
			yy_bgp = 0;
		}
	;

bgp_substatements:
		/* empty */
	|	bgp_substatements GROUP TYPE EXTERNAL PEERAS NUMBER BCL peerstatements ECL EOS
		{
			if ($6 < 0 || $6 > 65535) {
				yywarn("bad AS number: %d", $6);
				return(-1);
			}
			if (add_bgppeer($6, 0, $8))
				return(-1); /* XXX free? */
		}
	|	bgp_substatements GROUP TYPE INTERNAL BCL peerstatements ECL EOS
		{
			if (add_bgppeer(-1, 0, $6))
				return(-1);
		}
	|	bgp_substatements GROUP TYPE INTERNAL ROUTERID STRING BCL peerstatements ECL EOS
		{
			struct in_addr routerid;

			if ((inet_aton($6.v, &routerid)) == 0) {
				yywarn("invalid router ID: %s", $6.v);
				free($6.v);
				return(-1);
			}
			free($6.v);

			if (add_bgppeer(-1, routerid.s_addr, $8))
				return(-1);
		}
	;

peerstatements:
		PEER STRING peerattributes EOS
		{
			memset(&bgppeer_temp, 0, sizeof(bgppeer_temp));
			if (get_in6_addr($2.v, &bgppeer_temp.peeraddr)) {
				yywarn("bad BGP peer address: %s", $2.v);
				free($2.v);
				return(-1);
			}
			bgppeer_temp.peertype = BGPPEER_NORMAL;
			bgppeer_temp.attribute = $3;
			$$ = &bgppeer_temp;
		}
	|	CLIENT STRING peerattributes EOS
		{
			memset(&bgppeer_temp, 0, sizeof(bgppeer_temp));
			if (get_in6_addr($2.v, &bgppeer_temp.peeraddr)) {
				yywarn("bad BGP peer address: %s", $2.v);
				free($2.v);
				return(-1);
			}
			bgppeer_temp.peertype = BGPPEER_CLIENT;
			bgppeer_temp.attribute = $3;
			$$ = &bgppeer_temp;
		}
	;

peerattributes:
		{ $$ = NULL; }	/* empty */
	|	peerattributes INTERFACE IFNAME
		{
			if (($$ = add_attribute($1, ATTR_STRING,
						BGPPA_IFNAME, $3.v)) == NULL) {
				free($3.v);
				return(-1);
			}
		}
	|	peerattributes NOSYNC
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						BGPPA_NOSYNC, 0)) == NULL)
				return(-1);
		}
	|	peerattributes NEXTHOPSELF
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						BGPPA_NEXTHOPSELF, 0)) == NULL)
				return(-1);
		}
	|	peerattributes LCLADDR STRING
		{
			struct sockaddr_in6 lcladdr;

			if (get_in6_addr($3.v, &lcladdr)) {
				yywarn("bad IPv6 address: %s", $3.v);
				free($3.v);
				return(-1);
			}
			if (($$ = add_attribute($1, ATTR_ADDR, BGPPA_LCLADDR,
						&lcladdr)) == NULL)
				return(-1);
		}
	|	peerattributes PREFERENCE NUMBER
		{
			int pref = $3;

			if (($$ = add_attribute($1, ATTR_NUMBER,
						BGPPA_PREFERENCE,
						(void *)&pref)) == NULL)
				return(-1);
		}
	|	peerattributes PREPEND
		{
			int pref = BGP_DEF_ASPREPEND;

			if (($$ = add_attribute($1, ATTR_NUMBER,
						BGPPA_PREPEND,
						(void *)&pref)) == NULL)
				return(-1);
		}
	|	peerattributes PREPEND NUMBER
		{
			int pref = $3;

			if (($$ = add_attribute($1, ATTR_NUMBER,
						BGPPA_PREPEND,
						(void *)&pref)) == NULL)
				return(-1);
		}
	|	peerattributes DESCR DESCSTRING
		{
			if (($$ = add_attribute($1, ATTR_STRING,
						BGPPA_DESCR, $3.v)) == NULL)
				return(-1);
		}
	|	peerattributes FILTERIN DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						BGPPA_FILINDEF, 0)) == NULL)
				return(-1);
		}
	|	peerattributes FILTEROUT DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						BGPPA_FILOUTDEF, 0)) == NULL)
				return(-1);
		}
	|	peerattributes RESTRICTIN DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						BGPPA_RESINDEF, 0)) == NULL)
				return(-1);
		}
	|	peerattributes RESTRICTOUT DEFAULT
		{
			if (($$ = add_attribute($1, ATTR_FLAG,
						BGPPA_RESOUTDEF, 0)) == NULL)
				return(-1);
		}
	|	peerattributes FILTERIN prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						BGPPA_FILINPFX, $3)) == NULL)
				return(-1);
		}
	|	peerattributes FILTEROUT prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						BGPPA_FILOUTPFX, $3)) == NULL)
				return(-1);
		}
	|	peerattributes RESTRICTIN prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						BGPPA_RESINPFX, $3)) == NULL)
				return(-1);
		}
	|	peerattributes RESTRICTOUT prefix
		{
			if (($$ = add_attribute($1, ATTR_PREFIX,
						BGPPA_RESOUTPFX, $3)) == NULL)
				return(-1);
		}
	;

/* export */
export_statement:
		EXPORT PROTO BGP AS NUMBER BCL export_list ECL EOS
		{
			if (add_export($5, NULL, $7))
				return(-1); /* XXX free? */
		}
	|	EXPORT PROTO BGP PEER STRING BCL export_list ECL EOS 
		{
			struct sockaddr_in6 peeraddr;

			if (get_in6_addr($5.v, &peeraddr)) {
				yywarn("bad peer address: %s", $5.v);
				free($5.v);
				return(-1);
			}
			if (add_export(-1, &peeraddr, $7))
				return(-1);
		}
	;

export_list:
		{ $$ = NULL; };	/* empty */
	|	export_list protocol
		{
			if (($$ = add_attribute($1, ATTR_DATA, EXPA_PROTO,
						$2)) == NULL)
				return(-1);
		}
	;

protocol:			/* XXX: currently too restrictive */
		PROTO DIRECT INTERFACE IFNAME all_block EOS
		{
			struct yy_rtproto *p;

			if ((p = malloc(sizeof(*p))) == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(p, 0, sizeof(*p));
			if (strlen($4.v) >= sizeof(p->rtpu.ifname)) {
				yywarn("interface name(%s) is too long",
				       $4.v);
				free($4.v);
				return(-1);
			}
			p->type = RTP_IFACE;
			strcpy(p->rtpu.ifname, $4.v);

			$$ = p;
		}
	|	PROTO BGP AS NUMBER all_block EOS
		{
			struct yy_rtproto *p;

			if ((p = malloc(sizeof(*p))) == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(p, 0, sizeof(*p));
			p->type = RTP_BGP;
			p->rtpu.rtpu_bgp.peeras = $4;

			$$ = p;
		}
	|	PROTO BGP PEER STRING all_block EOS
		{
			struct yy_rtproto *p;

			if ((p = malloc(sizeof(*p))) == NULL) {
				yywarn("can't allocate memory");
				free($4.v);
				return(-1);
			}
			memset(p, 0, sizeof(*p));
			p->type = RTP_BGP;
			if (get_in6_addr($4.v, &p->rtpu.rtpu_bgp.peeraddr)) {
				yywarn("bad peer address: %s", $4.v);
				free($4.v);
				return(-1);
			}
			free($4.v);
			$$ = p;
		}
	|	PROTO RIP all_block EOS
		{
			struct yy_rtproto *p;

			if ((p = malloc(sizeof(*p))) == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(p, 0, sizeof(*p));
			p->type = RTP_RIP;

			$$ = p;
		}
	|	PROTO IBGP all_block EOS
		{
			struct yy_rtproto *p;

			if ((p = malloc(sizeof(*p))) == NULL) {
				yywarn("can't allocate memory");
				return(-1);
			}
			memset(p, 0, sizeof(*p));
			p->type = RTP_IBGP;

			$$ = p;
		}
	;

/* just for shortcut */
all_block:			/* do nothing */
		/* empty */
	|	BCL ALL EOS ECL
	;

/* aggregate */
aggregate_statement:
	AGGREGATE prefix BCL aggregate_substatements ECL EOS
	{
		if (add_aggregation($2, $4))
			return(-1);
	};

aggregate_substatements:
		{ $$ = NULL; }	/* empty */
	|	aggregate_substatements protocol
		{
			if (($$ = add_attribute($1, ATTR_DATA, AGGA_PROTO,
						$2)) == NULL)
				return(-1);
		}
	|	aggregate_substatements EXPLICIT BCL prefix_list ECL EOS
		{
			if (($$ = add_attribute($1, ATTR_LIST, AGGA_EXPFX,
						$4)) == NULL)
				return(-1);
		}
	;

/* prefix */
prefix_list:
		{ $$ = NULL; }	/* empty */
	|	prefix_list prefix EOS
		{
			if (($$ = add_attribute($1, ATTR_PREFIX, ATTR_PREFIX,
						$2)) == NULL)
				return(-1);
		}
	;

prefix:
		STRING
		{
			if (get_in6_addr($1.v, &in6pfx_temp.paddr)) {
				yywarn("bad IPv6 prefix: %s", $1.v);
				free($1.v);
				return(-1);
			}
			free($1.v);
			in6pfx_temp.plen = 128;
			$$ = &in6pfx_temp;
		}
	|	STRING SLASH NUMBER
		{
			if (get_in6_addr($1.v, &in6pfx_temp.paddr)) {
				yywarn("bad IPv6 prefix: %s", $1.v);
				free($1.v);
				return(-1);
			}
			if ($3 < 0 || $3 > 128) {
				yywarn("bad IPv6 prefixlen: %s", $1.v);
				free($1.v);
				return(-1);
			}
			free($1.v);
			in6pfx_temp.plen = $3;
			$$ = &in6pfx_temp;
		}
	;

%%
static int
add_static(new_rte)
	struct yy_route_entry *new_rte;
{
	struct yy_route_entry *rte;

	/* canonize the address part */
	mask_nclear(&new_rte->prefix.paddr.sin6_addr, new_rte->prefix.plen);

	/* check if duplicated */
	for (rte = yy_static_head; rte; rte = rte->next) {
		if (sa6_equal(&rte->prefix.paddr, &new_rte->prefix.paddr) &&
		    rte->prefix.plen == new_rte->prefix.plen) {
			yywarn("static route doubly defined: %s/%d",
			       ip6str2(&rte->prefix.paddr), rte->prefix.plen);
			return(-1);
		}
	}

	/* add a new route */
	if ((rte = malloc(sizeof(*rte))) == NULL) {
		warnx("can't allocate space for a static route");
		return(-1);
	}
	*rte = *new_rte;
	rte->next = yy_static_head;
	rte->line = lineno;
	yy_static_head = rte;

	return(0);
}

static int
add_aggregation(prefix, aggrinfo)
	struct in6_prefix *prefix;
	struct attr_list *aggrinfo;
{
	struct yy_aggrinfo *info;

	/* check if duplicated */
	for (info = yy_aggr_head; info; info = info->next) {
		if (sa6_equal(&info->prefix.paddr, &prefix->paddr) &&
		    info->prefix.plen == prefix->plen) {
			yywarn("aggregate prefix(%s/%d) doulby defined",
			       ip6str2(&prefix->paddr), prefix->plen);
			return(-1);
		}
	}

	/* allocate a new one */
	if ((info = malloc(sizeof(*info))) == NULL) {
		yywarn("can't allocate memory for aggregation");
		return(-1);
	}
	memset(info, 0, sizeof(*info));
	info->prefix = *prefix;
	info->aggrinfo = aggrinfo;
	info->line = lineno;

	info->next = yy_aggr_head;
	yy_aggr_head = info;

	return(0);
}

static int
add_export(asnum, peer, list)	/* XXX BGP depend */
	int asnum;
	struct sockaddr_in6 *peer;
	struct attr_list *list;
{
	struct yy_exportinfo *info;

	/* check if duplicated */
	for (info = yy_exportinfo_head; info; info = info->next) {
		if (asnum >= 0 && info->asnum == asnum) {
			yywarn("export peer (AS: %d) doubly defined", asnum);
			return(-1);
		}
		if (peer && sa6_equal(peer, &info->peeraddr)) {
			yywarn("export peer (addr: %s) doubly defined",
			       ip6str2(&info->peeraddr));
			return(-1);
		}
	}

	/* allocate a new one */
	if ((info = malloc(sizeof(*info))) == NULL) {
		yywarn("can't allocate memory for export peer");
		return(-1);
	}
	memset(info, 0, sizeof(*info));
	info->asnum = asnum;
	info->line = lineno;
	if (peer)
		info->peeraddr = *peer;
	info->protolist = list;

	info->next = yy_exportinfo_head;
	yy_exportinfo_head = info;

	return(0);
}

static int
add_bgppeer(asnum, routerid, peerinfo)
	int asnum;
	u_int32_t routerid;
	struct yy_bgppeerinfo *peerinfo;
{
	struct yy_bgppeerinfo *info;

	/* check if duplicated */
	for (info = yy_bgppeer_head; info; info = info->next) {
		if (asnum >= 0 && info->asnum == asnum) {
			yywarn("BGP peer (AS: %d) doubly defined", asnum);
			return(-1);
		}
		if (routerid && info->routerid == routerid) {
			yywarn("BGP peer (routerID: %x) doubly defined",
			       htonl(routerid));
			return(-1);
		}
		if (sa6_equal(&info->peeraddr, &peerinfo->peeraddr)) {
			yywarn("BGP peer (addr: %s) doubly defined",
			       ip6str2(&info->peeraddr));
			return(-1);
		}
	}

	/* allocate a new one */
	if ((info = malloc(sizeof(*info))) == NULL) {
		yywarn("can't allocate memory for BGP peerinfo");
		return(-1);
	}
	memset(info, 0, sizeof(*info));
	info->asnum = asnum;
	info->routerid = routerid;
	info->peertype = peerinfo->peertype;
	info->peeraddr = peerinfo->peeraddr;
	info->attribute = peerinfo->attribute;
	info->line = lineno;

	info->next = yy_bgppeer_head;
	yy_bgppeer_head = info;

	return(0);
}

static struct yy_ripifinfo *
add_ripifinfo(ifname)
	char *ifname;
{
	struct yy_ripifinfo *info;

	if ((info = malloc(sizeof(*info))) == NULL) {
		yywarn("can't allocate memory for ripifinfo");
		return(NULL);
	}
	if (strlen(ifname) >= sizeof(info->ifname)) {
		yywarn("interface name(%s) is too long", ifname);
		free(info);
		return(NULL);
	}
	memset(info, 0, sizeof(*info));
	strcpy(info->ifname, ifname);
	info->line = lineno;
	info->next = yy_ripifinfo_head;
	yy_ripifinfo_head = info;

	return(info);
}

static struct attr_list *
add_attribute(list, type, code, val)
	struct attr_list *list;
	int type, code;
	void *val;
{
	struct attr_list *p;
	
	if ((p = malloc(sizeof(*p))) == NULL) {
		yyerror("malloc failed");
		return(NULL);
	}
	memset((void *)p, 0, sizeof(*p));
	p->code = code;
	p->type = type;
	p->line = lineno;
	switch(type) {
	case ATTR_FLAG:
		p->attru.flags++;
		break;
	case ATTR_PREFIX:
		p->attru.prefix = *(struct in6_prefix *)val;
		break;
	case ATTR_STRING:
		p->attru.str = (char *)val;
		break;
	case ATTR_ADDR:
		p->attru.in6addr = *(struct sockaddr_in6 *)val;
		break;
	case ATTR_NUMBER:
		p->attru.number = *(int *)val;
		break;
	case ATTR_DATA:
		p->attru.data = val;
		break;
	case ATTR_LIST:
		p->attru.list = (struct attr_list *)val;
		break;
	default:
		/* XXX what do I do? */
		yywarn("unknown attribute type(%d)", type);
		break;
	}
	p->next = list;

	return(p);
}

static int
set_filter(headp, prefix, line)
	struct filtinfo **headp;
	struct in6_prefix *prefix;
	int line;
{
	struct filtinfo *filter;

	if ((filter = malloc(sizeof(*filter))) == NULL) {
		warnx("can't allocate space for filter");
		return(-1);
	}
	memset(filter, 0, sizeof(*filter));
	memset(filter, 0, sizeof(struct filtinfo));
	filter->filtinfo_addr = prefix->paddr.sin6_addr; /* XXX */
	filter->filtinfo_plen = prefix->plen;

	if (*headp) {
		if (find_filter(*headp, filter)) {
			fprintf(stderr, "%s:%d route filter(%s/%d) doubly "
				"defined\n",
				configfilename, line,ip6str2(&prefix->paddr),
				prefix->plen);
			return(-1);
		}
		insque(filter, *headp);
	} else {
		filter->filtinfo_next = filter->filtinfo_prev = filter;
		*headp = filter;
	}

	return(0);
}

static void
param_config()
{
	struct in_addr ipv4id;

	if (yy_debug) {		/* debug flag */
		logflags = yy_debug;
		cprint("set %x to the debug flag\n", (u_int)logflags);
	}
	if (yy_asnum >= 0) {	/* our AS number */
		my_as_number = yy_asnum;
		cprint("set %d to AS number\n", my_as_number);
	}
	if (yy_bgpsbsize >= 0) { /* BGP socket buffer size */
		bgpsbsize = yy_bgpsbsize;
		cprint("set %d to the BGP socket buffer size\n", bgpsbsize);
	}
	if (yy_holdtime >= 0) {	/* BGP holdtimer value */
		bgpHoldtime = yy_holdtime;
		cprint("set %d to BGP hold timer\n", bgpHoldtime);
	}
	if ((yy_rrflag >= 0)) {
		IamRR = yy_rrflag;
		cprint("act as a route reflector\n");
	}
	if (yy_rip >= 0) {
		ripyes = yy_rip;
		cprint("Enable RIPng\n");
	}
	if (yy_bgp >= 0) {
		bgpyes = yy_bgp;
		cprint("Enable BGP4+\n");
	}
	if (dumpfile)
		free(dumpfile);
	if (yy_dumpfile) {
		dumpfile = strdup(yy_dumpfile);
		cprint("set %s to the dump file\n", dumpfile);
	}
	else
		dumpfile = strdup(DUMPFILENAME);
	if (yy_routerid != -1) {
		ipv4id.s_addr = bgpIdentifier = yy_routerid;
		cprint("set %s to the BGP Identifier\n", inet_ntoa(ipv4id));
	}
	if (yy_clusterid != -1) {
		ipv4id.s_addr = clusterId = yy_clusterid;
		cprint("set %s to the BGP cluster ID\n", inet_ntoa(ipv4id));
	}
}

static int
static_config()
{
	struct yy_route_entry *yrte;
	struct rt_entry *rte = NULL;
	struct ifinfo *ifp;
	extern struct rt_entry static_rte_head;

	cprint("Static Route config\n");

	for (yrte = yy_static_head; yrte; yrte = yrte->next) {
		cprint("  Destination: %s/%d",
		       ip6str2(&yrte->prefix.paddr), yrte->prefix.plen);

		if ((rte = malloc(sizeof(*rte))) == NULL) {
			warnx("can't allocate space for a static route");
			return(-1);
		}
		memset(rte, 0, sizeof(*rte));

		/* XXX: scoped addr support */
		rte->rt_ripinfo.rip6_dest = yrte->prefix.paddr.sin6_addr;
		rte->rt_ripinfo.rip6_plen = yrte->prefix.plen;
		if (rte->rt_ripinfo.rip6_plen == 128)
			rte->rt_flags |= RTF_HOST;

		switch(yrte->gwtype) {
		case GW_IFACE:
			cprint(" to Interface %s", yrte->reu.ifname);

			if ((ifp = find_if_by_name(yrte->reu.ifname))
			    == NULL) {
				warnx("%s line %d: invalid interface name: %s",
				      configfilename, yrte->line,
				      yrte->reu.ifname);
				goto bad;
			}
			rte->rt_proto.rtp_type = RTPROTO_IF;
			rte->rt_proto.rtp_if = ifp;
			/* use our own address as gateway */
			if (!IN6_IS_ADDR_UNSPECIFIED(&ifp->ifi_laddr))
				rte->rt_gw = ifp->ifi_laddr;
			else
				rte->rt_gw = ifp->ifi_gaddr;
			rte->rt_flags |= RTF_BGPDIFSTATIC;
			break;
		case GW_ADDR:
			cprint(" gateway: %s", ip6str2(&yrte->reu.gateway));

			if (IN6_IS_ADDR_LINKLOCAL(&yrte->reu.gateway.sin6_addr)) {
				/* XXX: link vs I/F issue... */
				u_int linkid = yrte->reu.gateway.sin6_scope_id;

				if (linkid == 0) {
					warnx("%s line %d: "
					      "link-local gateway without"
					      "scope id: %s",
					      configfilename, yrte->line,
					      ip6str2(&yrte->reu.gateway));
					goto bad;
				}
				if ((ifp = find_if_by_index(linkid)) == NULL) {
					yywarn("%s line %d: "
					       "invalid scope id",
					       configfilename, yrte->line,
					       ip6str2(&yrte->reu.gateway));
					goto bad;
				}
			}
			else if (in6_is_addr_onlink(&yrte->reu.gateway.sin6_addr,
						    &ifp) == 0) {
					warnx("bad gateway (off-link): %s",
					      ip6str2(&yrte->reu.gateway));
					return(-1);
			}

			rte->rt_proto.rtp_type = RTPROTO_IF;
			rte->rt_proto.rtp_if = ifp;
			rte->rt_gw = yrte->reu.gateway.sin6_addr;
			rte->rt_flags |= RTF_GATEWAY;
			rte->rt_flags |= RTF_BGPDGWSTATIC;
			break;
		default:
			cprint(" unknown gateway type(%d)", yrte->gwtype);
			goto bad;
		}

		cprint("\n");
		insque(rte, &static_rte_head);
	}

	return(0);

  bad:
	if (rte)
		free(rte);
	return(-1);
}

static int
rip_config()
{
	struct yy_ripifinfo *info;
	struct attr_list *attr;
	struct ifinfo *ifp;
	struct ripif *ripif;

	if (ripyes == 0)
		return(0);
	rip_init();

	cprint("RIP config\n");

	for (info = yy_ripifinfo_head; info; info = info->next) {
		cprint("  %s: ", info->ifname);
		if ((ifp = find_if_by_name(info->ifname)) == NULL ||
		    (ripif = find_rip_by_index(ifp->ifi_ifn->if_index)) ==
		    NULL) {
			warnx("%s line %d: invalid interface: %s\n", 
			      configfilename, info->line,
			      info->ifname);
			return(-1);
		}

		for (attr = info->attribute; attr; attr = attr->next) {
			switch(attr->code) {
			case RIPIFA_DEFAULT:
				ripif->rip_mode |= IFS_DEFAULTORIGINATE;
				ripif->rip_filterset.deffilterflags
					|= DEFAULT_FILTERIN;
				cprint("default_originate ");
				break;
			case RIPIFA_NORIPIN:
				ripif->rip_mode |= IFS_NORIPIN;
				cprint("noripin ");
				break;
			case RIPIFA_NORIPOUT:
				ripif->rip_mode |= IFS_NORIPOUT;
				cprint("noripout ");
				break;
			case RIPIFA_METRICIN:
				ripif->rip_metricin = attr->attru.number;
				cprint("metricin %d ", attr->attru.number);
				break;
			case RIPIFA_FILINDEF:
				ripif->rip_filterset.deffilterflags
					|= DEFAULT_FILTERIN;
				cprint("input_filter_default ");
				break;
			case RIPIFA_FILOUTDEF:
				ripif->rip_filterset.deffilterflags
					|= DEFAULT_FILTEROUT;
				cprint("output_filter_default ");
				break;
			case RIPIFA_RESINDEF:
				ripif->rip_filterset.deffilterflags
					|= DEFAULT_RESTRICTIN;
				cprint("input_restriction_default ");
				break;
			case RIPIFA_RESOUTDEF:
				ripif->rip_filterset.deffilterflags
					|= DEFAULT_RESTRICTOUT;
				cprint("output_restriction_default ");
				break;
			case RIPIFA_FILINPFX:
				if (set_filter(&ripif->rip_filterin,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("input_filter(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case RIPIFA_FILOUTPFX:
				if (set_filter(&ripif->rip_filterout,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("output_filter(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case RIPIFA_RESINPFX:
				if (set_filter(&ripif->rip_restrictin,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("input_restriction(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case RIPIFA_RESOUTPFX:
				if (set_filter(&ripif->rip_restrictout,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("output_restriction(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case RIPIFA_DESCR:
				if (ripif->rip_desc) {
					free(ripif->rip_desc);
					ripif->rip_desc = NULL;
				}
				ripif->rip_desc = strdup(attr->attru.str);
				if (ripif->rip_desc == NULL) {
					warnx("can't allocate memory "
					      "for RIPng I/F description");
					return(-1);
				}
				cprint("descr=%s ", attr->attru.str);
				break;
			default:
				cprint("unknown_attribute(%d) ", attr->code);
			}
		}
		cprint("\n");
	}

	return(0);
}

static int
bgp_config()
{
	struct yy_bgppeerinfo *info;
	struct attr_list *attr;
	struct rpcb *bnp;

	if (bgpyes == 0)
		return(0);

	if (my_as_number == 0) {
		warnx("%s: BGP specified without internal AS number",
		      configfilename);
		return(-1);
	}

	cprint("BGP config\n");

	for (info = yy_bgppeer_head; info; info = info->next) {
		/* make a new peer structure */
		bnp = bgp_new_peer();
		if (bgb == NULL) {
			bgb = bnp;
			bgb->rp_next = bgb->rp_prev = bgb;
		}
		else
			insque(bnp, bgb);

		cprint("  peer: %s ", ip6str2(&info->peeraddr));
		if (info->asnum < 0) { /* IBGP */
			cprint("IBGP ");

			bnp->rp_mode |= BGPO_IGP;
			bnp->rp_as = my_as_number;
			if (info->peertype == BGPPEER_CLIENT) {
				if (!IamRR) {
					warnx("%s line %d: a BGP client "
					      "specified while we're not "
					      "a reflector",
					      configfilename, info->line);
					return(-1);
				}
				bnp->rp_mode |= BGPO_RRCLIENT;
				cprint("CLIENT ");
			}
			if (info->routerid) {
				bnp->rp_mode |= BGPO_IDSTATIC;
				bnp->rp_id = htonl(info->routerid);
				cprint("routerID: %x ",
				       (u_int)(htonl(info->routerid)));
			}
		}
		else {		/* EBGP */
			cprint("EBGP ");
			bnp->rp_as = info->asnum;
		}

		/* peer address setting */
		bnp->rp_addr = info->peeraddr;
		bnp->rp_addr.sin6_port = htons(BGP_PORT);
		if (IN6_IS_ADDR_LINKLOCAL(&bnp->rp_addr.sin6_addr))
			bnp->rp_laddr = bnp->rp_addr.sin6_addr; /* copy  */
		else
			bnp->rp_gaddr = bnp->rp_addr.sin6_addr; /* ummh  */
		{
			struct ifinfo *ife_dummy = NULL; /* XXX */
			if (in6_is_addr_onlink(&bnp->rp_addr.sin6_addr,
					       &ife_dummy))
				bnp->rp_mode |= BGPO_ONLINK;
		}

		for (attr = info->attribute; attr; attr = attr->next) {
			switch(attr->code) {
			case BGPPA_IFNAME:
				cprint("interface: %s ", attr->attru.str);
				if ((bnp->rp_ife = find_if_by_name(attr->attru.str)))
					bnp->rp_mode |= BGPO_IFSTATIC;
				else {
					warnx("Bad interface for a BGP peer "
					      ": %s", attr->attru.str);
					return(-1);
				}
				/* scope check: XXX for link-local only */
				if (bnp->rp_addr.sin6_scope_id &&
				    bnp->rp_addr.sin6_scope_id !=
				    bnp->rp_ife->ifi_ifn->if_index) {
					warnx("BGP peer address(%s) "
					      "condradicts interface(%s)",
					      ip6str2(&bnp->rp_addr),
					      attr->attru.str);
					return(-1);
				}
				    
				break;
			case BGPPA_NOSYNC:
				cprint("nosync ");
				bnp->rp_mode |= BGPO_NOSYNC;
				break;
			case BGPPA_NEXTHOPSELF:
				cprint("nexthop_self ");
				bnp->rp_mode |= BGPO_NEXTHOPSELF;
				break;
			case BGPPA_LCLADDR:
				cprint("lcladdr %s ",
				       ip6str2(&attr->attru.in6addr));
				bnp->rp_lcladdr = attr->attru.in6addr;
				break;
			case BGPPA_PREFERENCE:
				cprint("preference %d ", attr->attru.number);
				bnp->rp_prefer = htonl(attr->attru.number);
				break;
			case BGPPA_PREPEND:
				cprint("prepend %d ", attr->attru.number);
				bnp->rp_ebgp_as_prepends = attr->attru.number;
				break;
			case BGPPA_DESCR:
				cprint("descr=%s ", attr->attru.str);
				bnp->rp_descr = strdup(attr->attru.str);
				break;
			case BGPPA_FILINDEF:
				bnp->rp_filterset.deffilterflags |=
				  DEFAULT_FILTERIN;
				cprint("input_filter_default ");
				break;
			case BGPPA_FILOUTDEF:
				bnp->rp_filterset.deffilterflags |=
				  DEFAULT_FILTEROUT;
				cprint("output_filter_default ");
				break;
			case BGPPA_RESINDEF:
				bnp->rp_filterset.deffilterflags |=
				  DEFAULT_RESTRICTIN;
				cprint("input_restriction_default ");
				break;
			case BGPPA_RESOUTDEF:
				bnp->rp_filterset.deffilterflags |=
				  DEFAULT_RESTRICTOUT;
				cprint("output_restriction_default ");
				break;
			case BGPPA_FILINPFX:
				if (set_filter(&bnp->rp_filterset.filterin,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("input_filter(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case BGPPA_FILOUTPFX:
				if (set_filter(&bnp->rp_filterset.filterout,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("output_filter(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case BGPPA_RESINPFX:
				if (set_filter(&bnp->rp_filterset.restrictin,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("input_restriction(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			case BGPPA_RESOUTPFX:
				if (set_filter(&bnp->rp_filterset.restrictout,
					       &attr->attru.prefix,
					       attr->line))
					return(-1);
				cprint("output_restriction(%s/%d) ",
				       ip6str2(&attr->attru.prefix.paddr),
				       attr->attru.prefix.plen);
				break;
			default:
				cprint("unknown_attribute(%d) ", attr->code);
			}
		}
		cprint("\n");

		/*
		 * We need to disambigute the scope for a peer with a scoped
		 * address.
		 * XXX: site-local address?
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&bnp->rp_addr.sin6_addr)) {
			if (bnp->rp_addr.sin6_scope_id == 0 &&
			    bnp->rp_ife == NULL) {
				warnx("%s line %d: link-local peer(%s) "
				      "without I/F or scope ID",
				      configfilename, info->line,
				      ip6str2(&bnp->rp_addr));
				return(-1);
			}
		}
	}

	return(0);
}

static int
add_protoexport(bnp, attr, ptype, pdata)
	struct rpcb *bnp;
	struct attr_list *attr;
	int ptype;
	void *pdata;
{
	struct rtproto *rtp = NULL;

	if ((rtp = malloc(sizeof(*rtp))) == NULL) {
		warnx("can't allocate space for export protocol");
		return(-1);
	}
	rtp->rtp_type = ptype;
	switch(ptype) {
	case RTPROTO_IF:
		rtp->rtp_if = (struct ifinfo *)pdata;
		break;
	case RTPROTO_BGP:
		rtp->rtp_bgp = (struct rpcb *)pdata;
		break;
	case RTPROTO_RIP:
		rtp->rtp_rip = (struct ripif *)pdata;
		break;
	/* default? */
	}

	if (bnp->rp_adj_ribs_out != NULL) {
		if (find_rtp(rtp, bnp->rp_adj_ribs_out)) {
			warnx("%s line %d: export protocol doubly defined",
			      configfilename, attr->line);
			free(rtp); /* necessary? */
			return(-1);
		}
		insque(rtp, bnp->rp_adj_ribs_out);
	} else {
		rtp->rtp_next = rtp;
		rtp->rtp_prev = rtp;
		bnp->rp_adj_ribs_out = rtp;
	}

	return(0);

}
static int
add_protoexportlist(exportinfo, bnp)
	struct yy_exportinfo *exportinfo;
	struct rpcb *bnp;	/* BGP depend */
{
	struct attr_list *attr;
	struct ifinfo *ifp;
	struct rpcb *ibnp;
	struct ripif *ripif;
	extern struct ripif *ripifs; 

	for (attr = exportinfo->protolist; attr; attr = attr->next) {
		struct yy_rtproto *proto;
			
		proto = (struct yy_rtproto *)attr->attru.data;
		switch(proto->type) {
		case RTP_IFACE:
			cprint("interface_route(%s) ", proto->rtpu.ifname);

			if ((ifp = find_if_by_name(proto->rtpu.ifname)) == NULL) {
				warnx("%s line %d: invalid I/F name: %s",
				      configfilename, attr->line,
				      proto->rtpu.ifname);
				return(-1);
			}
			if (add_protoexport(bnp, attr, RTPROTO_IF, (void *)ifp))
				return(-1);
			break;
		case RTP_BGP:
			cprint("BGP(AS: %d) ", proto->rtpu.rtpu_bgp.peeras);

			if (proto->rtpu.rtpu_bgp.peeras == my_as_number)
				goto ibgp;

			if ((ibnp = find_peer_by_as(proto->rtpu.rtpu_bgp.peeras))
			    == NULL) {
				warnx("%s line %d: invalid AS number: %d",
				      configfilename, attr->line,
				      proto->rtpu.rtpu_bgp.peeras);
				return(-1);
			}

			if (add_protoexport(bnp, attr, RTPROTO_BGP, (void *)ibnp))
				return(-1);
			break;
		case RTP_RIP:
			cprint("RIP ");

			if (!ripyes || !ripifs) {
				warnx("%s line %d: RIPng specified but disabled",
				      configfilename, attr->line);
				return(-1);
			}

			ripif = ripifs;
			while(ripifs) {	/* XXX: odd loop */
				if (add_protoexport(bnp, attr, RTPROTO_RIP,
						    (void *)ripif))
					return(-1);

				if ((ripif = ripif->rip_next) == ripifs)
					break;
			}
			break;
		case RTP_IBGP:
		  ibgp:
			cprint("IBGP ");

			ibnp = bgb;
			while(ibnp) { /* XXX: odd loop */
				if (ibnp->rp_mode & BGPO_IGP)
					if (add_protoexport(bnp, attr,
							    RTPROTO_BGP,
							    (void *)ibnp))
						return(-1);
				if ((ibnp = ibnp->rp_next) == bgb)
					break;
			}
			break;
		default:
			cprint("unknown or unsupported proto(%d) ", proto->type);
			break;
		}
	}

	return(0);
}

static int
export_config()
{
	struct yy_exportinfo *info;
	struct sockaddr_in6 *peeraddr;
	struct rpcb *asp, *bnp;
	int peeras;

	cprint("Export config\n");
	for (info = yy_exportinfo_head; info; info = info->next) {
		peeras = info->asnum;
		peeraddr = &info->peeraddr;
		if (!IN6_IS_ADDR_UNSPECIFIED(&peeraddr->sin6_addr)) {
			cprint(" peer addr: %s ", ip6str2(peeraddr));

			/* XXX scoped address support */
			asp = find_apeer_by_addr(&peeraddr->sin6_addr);
			if (asp == NULL) {
				warnx("%s line %d: invalid BGP peer address: "
				      "%s", configfilename, info->line,
				      ip6str2(peeraddr));
				return(-1);
			}
			/* this check is in fact redundant */
			if (peeras > 0 && peeras != asp->rp_as) {
				warnx("%s line %d: bad peer AS(%d) for %s",
				      configfilename, info->line,
				      peeras,
				      ip6str2(peeraddr));
				return(-1);
			}

			if (add_protoexportlist(info, asp))
				return(-1);

			cprint("\n");
			continue;
		}

		for (bnp = bgb; bnp; ) { /* XXX: odd loop... */
			if (bnp->rp_as == peeras) {
				cprint(" peer as: %d (addr: %s) ",
				       peeras, bgp_peerstr(bnp));
				if (add_protoexportlist(info, bnp))
					return(-1);
				cprint("\n");
			}

			if ((bnp = bnp->rp_next) == bgb)
				break;
		}
	}

	return(0);
}

static int
add_protoaggr(attr, aggregated, ptype, pdata)
	struct attr_list *attr;
	struct rt_entry *aggregated;
	int ptype;
	void *pdata;
{
	struct rtproto *rtp = NULL;
	if ((rtp = malloc(sizeof(*rtp))) == NULL) {
		warnx("can't allocate space for aggregation");
		return(-1);
	}
	memset(rtp, 0, sizeof(*rtp));

	rtp->rtp_type = ptype;
	switch(ptype) {
	case RTPROTO_IF:
		rtp->rtp_if = (struct ifinfo *)pdata;
		break;
	case RTPROTO_BGP:
		rtp->rtp_bgp = (struct rpcb *)pdata;
		break;
	}

	if (aggregated->rt_aggr.ag_rtp != NULL) {
		if (find_rtp(rtp, aggregated->rt_aggr.ag_rtp)) {
			warnx("%s line %d: aggregation doubly defined: %s/%d",
			      configfilename, attr->line,
			      ip6str(&aggregated->rt_ripinfo.rip6_dest, 0),
			      aggregated->rt_ripinfo.rip6_plen);
			goto bad;
		}
		insque(rtp, aggregated->rt_aggr.ag_rtp);
	}
	else {
		rtp->rtp_next = rtp->rtp_prev = rtp;
		aggregated->rt_aggr.ag_rtp = rtp;
	}

	return(0);

  bad:
	free(rtp);
	return(-1);
}

static int
aggr_proto_config(attr, aggregated)
	struct attr_list *attr;
	struct rt_entry *aggregated;
{
	struct yy_rtproto *proto;
	struct ifinfo *ifp;
	struct sockaddr_in6 *peeraddr;
	int peeras;
	struct rpcb *asp = NULL, *bnp;

	proto = (struct yy_rtproto *)attr->attru.data;

	switch(proto->type) {
	case RTP_IFACE:
		cprint("   interface_route(%s) ", proto->rtpu.ifname);

		if ((ifp = find_if_by_name(proto->rtpu.ifname)) == NULL) {
			warnx("%s line %d: invalid interface name: %s",
			      configfilename, attr->line,
			      proto->rtpu.ifname);
			return(-1);
		}

		if (add_protoaggr(attr, aggregated, RTPROTO_IF, (void *)ifp))
			return(-1);
		break;
	case RTP_BGP:
		cprint("   BGP");

		peeraddr = &proto->rtpu.rtpu_bgp.peeraddr;
		peeras = proto->rtpu.rtpu_bgp.peeras;

		if (peeras > 0)
			cprint(" AS(%d)", peeras);

		if (!IN6_IS_ADDR_UNSPECIFIED(&peeraddr->sin6_addr)) {
			cprint(" peer(%s)", ip6str2(peeraddr));

			/* XXX scoped address support */
			asp = find_apeer_by_addr(&peeraddr->sin6_addr);
			if (asp == NULL) {
				warnx("%s line %d: invalid BGP peer address: "
				      "%s", configfilename, attr->line,
				      ip6str2(peeraddr));
				return(-1);
			}
			/* this check is in fact redundant */
			if (peeras > 0 && peeras != asp->rp_as) {
				warnx("%s line %d: bad peer AS(%d) for %s",
				      configfilename, attr->line,
				      peeras,
				      ip6str2(peeraddr));
				return(-1);
			}
			if (add_protoaggr(attr, aggregated,
					  RTPROTO_BGP, (void *)asp))
				return(-1);

			break;
		}

		for (bnp = bgb; bnp; ) { /* XXX: odd loop... */
			if (bnp->rp_as == peeras) {
				cprint("\n    peer=%s", bgp_peerstr(bnp));
				if (add_protoaggr(attr, aggregated,
						  RTPROTO_BGP, (void *)bnp))
					return(-1);
			}

			if ((bnp = bnp->rp_next) == bgb)
				break;
		}
		break;
	case RTP_RIP:
		cprint("   RIP ");
		warnx("%s line %d: proto RIP can't specified for aggregation "
		      "(sorry)", configfilename, attr->line);
		return(-1);
		break;
	case RTP_IBGP:
		cprint("   IBGP ");
		warnx("%s line %d: proto IBGP can't specified for aggregation",
		      configfilename, attr->line);
		return(-1);
		break;
	default:
		cprint("   unknown proto(%d) ", proto->type);
		warnx("%s line %d: unkonw proto for aggregation: %d",
		      configfilename, attr->line, proto->type);
		return(-1);
		break;
	}

	return(0);
}

static int
aggr_explict_config(aggr, aggregated, expl)
	struct attr_list *aggr;
	struct rt_entry *aggregated, *expl;
{
	struct rt_entry *e;
	struct attr_list *epfx;

	cprint("   Explicit: ");

	for (epfx = aggr->attru.list; epfx; epfx = epfx->next) {
		struct in6_prefix *pfx = &epfx->attru.prefix;

		cprint("%s/%d ", ip6str2(&pfx->paddr), pfx->plen);

		if ((e = malloc(sizeof(*e))) == NULL) {
			warnx("can't allocate space for explict route");
			return(-1);
		}
		memset(e, 0, sizeof(*e));
		e->rt_ripinfo.rip6_dest = pfx->paddr.sin6_addr; /* XXX */
		e->rt_ripinfo.rip6_plen = pfx->plen;
			
		/* check if this is really aggregatable. */
		if (aggregated != aggregatable(e)) {
			warnx("%s line %d: not aggregatable(%s/%d)",
			      configfilename, aggr->line,
			      ip6str2(&pfx->paddr), pfx->plen);
			return(-1);
		}

		if (aggregated->rt_aggr.ag_explt) {
			if (find_rte(e, aggregated->rt_aggr.ag_explt)) {
				warnx("%s line %d: explict prefix (%s/%d) "
				      "doubly defined",
				      configfilename, aggr->line,
				      ip6str2(&pfx->paddr), pfx->plen);
				return(-1);
			}
			insque(e, aggregated->rt_aggr.ag_explt);
		} else {
			e->rt_next = e->rt_prev = e;
			aggregated->rt_aggr.ag_explt = e;
		}
	}

	return(0);
}

static int
aggregate_config()
{
	struct yy_aggrinfo *info;
	struct attr_list *attr;
	struct rt_entry *aggregated;
	extern struct rt_entry *aggregations;

	cprint("Aggregation config\n");
	for (info = yy_aggr_head; info; info = info->next) {
		cprint("  prefix: %s/%d\n",
		       ip6str2(&info->prefix.paddr),
		       info->prefix.plen);

		if ((aggregated = malloc(sizeof(*aggregated))) == NULL) {
			warnx("can't allocate space for aggregation");
			return(-1);
		}
		memset(aggregated, 0, sizeof(*aggregated));
		aggregated->rt_proto.rtp_type = RTPROTO_AGGR;
		/* XXX: this would drop scope information */
		aggregated->rt_ripinfo.rip6_dest =
			info->prefix.paddr.sin6_addr;
		aggregated->rt_ripinfo.rip6_plen = info->prefix.plen;
		/* canonize the address part */
		mask_nclear(&aggregated->rt_ripinfo.rip6_dest, 
			    aggregated->rt_ripinfo.rip6_plen);

		for (attr = info->aggrinfo; attr; attr = attr->next) {
			switch(attr->code) {
			case AGGA_PROTO:
				if (aggr_proto_config(attr, aggregated))
					return(-1);
				break;
			case AGGA_EXPFX:
				if (aggr_explict_config(info, aggregated,
							attr))
					return(-1);
				break;
			default:
				cprint("   unkown info(%d)\n", attr->code);
				break;
			}
			cprint("\n");
		}

		if (aggregations) {
			if (find_rte(aggregated, aggregations)) {
				warnx("%s line %d: aggregate route doubly "
				      "doubly defined: %s/%d",
				      configfilename, info->line,
				      ip6str(&info->prefix.paddr.sin6_addr, 0),
				      info->prefix.plen);
				return(-1);
			}
			insque(aggregated, aggregations);
		} else {
			aggregated->rt_next = aggregated;
			aggregated->rt_prev = aggregated;
			aggregations = aggregated;
		}
	}

	return(0);
}

/*
 * The followings statics are cleanup fucntions.
 */
static void
attr_cleanup(head)
	struct attr_list *head;
{
	struct attr_list *attr, *nattr;

	for (attr = head; attr; attr = nattr) {
		nattr = attr->next;

		switch(attr->type) {
		case ATTR_STRING:
			free(attr->attru.str);
			break;
		case ATTR_DATA:
			free(attr->attru.data);
			break;
		case ATTR_LIST:
			attr_cleanup(attr->attru.list);
			break;
		default:	/* nothing to do */
			break;
		}

		free(attr);
	}
}

static void
staticconfig_cleanup(head)
	struct yy_route_entry *head;
{
	struct yy_route_entry *rte, *nrte;

	for (rte = head; rte; rte = nrte) {
		nrte = rte->next;

		free(rte);
	}
}

static void
ripconfig_cleanup(head)
	struct yy_ripifinfo *head;
{
	struct yy_ripifinfo *info, *ninfo;

	for (info = head; info; info = ninfo) {
		ninfo = info->next;

		attr_cleanup(info->attribute);
		free(info);
	}
}

static void
bgpconfig_cleanup(head)
	struct yy_bgppeerinfo *head;
{
	struct yy_bgppeerinfo *info, *ninfo;

	for (info = head; info; info = ninfo) {
		ninfo = info->next;

		attr_cleanup(info->attribute);
		free(info);
	}
}

static void
exportconfig_cleanup(head)
	struct yy_exportinfo *head;
{
	struct yy_exportinfo *info, *ninfo;

	for (info = head; info; info = ninfo) {
		ninfo = info->next;

		attr_cleanup(info->protolist);
		free(info);
	}
}

static void
aggrconfig_cleanup(head)
	struct yy_aggrinfo *head;
{
	struct yy_aggrinfo *info, *ninfo;

	for (info = head; info; info = ninfo) {
		ninfo = info->next;

		attr_cleanup(info->aggrinfo);
		free(info);
	}
}

static void
config_cleanup()
{
	if (yy_dumpfile)
		free(yy_dumpfile);
	staticconfig_cleanup(yy_static_head);
	ripconfig_cleanup(yy_ripifinfo_head);
	bgpconfig_cleanup(yy_bgppeer_head);
	exportconfig_cleanup(yy_exportinfo_head);
	aggrconfig_cleanup(yy_aggr_head);

	cf_init();		/* maybe unnecessary, but call it for safety */
}

/*
 * Global functions called from outside of the parser. 
 */
int
cf_post_config()
{
	param_config();	 /* always success */
	if (static_config())
		return(-1);
	if (rip_config())
		return(-1);
	if (bgp_config())
		return(-1);
	if (aggregate_config())
		return(-1);
	if (export_config())
		return(-1);
	config_cleanup();
 
	return(0);
}

/* initialize all temporary variables */
void
cf_init()
{
	yy_debug = 0;
	yy_asnum = yy_bgpsbsize = yy_holdtime = yy_rrflag = -1;
	yy_rip = yy_rip_sitelocal = yy_bgp = -1;
	yy_routerid = yy_clusterid = -1;
	yy_dumpfile = NULL;
	yy_static_head = NULL;
	yy_ripifinfo_head = NULL;
	yy_bgppeer_head = NULL;
	yy_exportinfo_head = NULL;
	yy_aggr_head = NULL;
	
	return;
}
