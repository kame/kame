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

struct in6_prefix {
	struct sockaddr_in6 paddr;
	int plen;
};

struct attr_list {
	struct attr_list *next;
	int code;
	union {
		char *str;
		void *data;
		unsigned int flags;
		int number;
		struct sockaddr_in6 in6addr;
		struct in6_prefix prefix;
	}attru;
};

struct yy_ripifinfo {
	struct yy_ripifinfo *next;
	char ifname[IFNAMSIZ];
	struct attr_list *attribute;
};

struct yy_bgppeerinfo {
	struct yy_bgppeerinfo *next;
	int asnum;
	u_int32_t routerid;
	int peertype;		/* an ordinal peer or an IBGP cluster client */
	struct sockaddr_in6 peeraddr;
	struct attr_list *attribute;
};

struct yy_exportinfo {		/* XXX: BGP depend */
	struct yy_exportinfo *next;
	int asnum;
	struct sockaddr_in6 peeraddr;
	struct attr_list *protolist;
};

struct yy_rtproto {
	int type;
	union {
		struct {
			int peeras;
			struct sockaddr_in6 peeraddr;
		}rtp_bgp;
		char ifname[IFNAMSIZ];
	}rtpu;
};

enum {RIPIFA_DEFAULT, RIPIFA_NORIPIN, RIPIFA_NORIPOUT, RIPIFA_FILINDEF,
      RIPIFA_FILOUTDEF, RIPIFA_RESINDEF, RIPIFA_RESOUTDEF, RIPIFA_FILINPFX,
      RIPIFA_FILOUTPFX, RIPIFA_RESINPFX, RIPIFA_RESOUTPFX, RIPIFA_DESCR,
      BGPPA_IFNAME, BGPPA_NOSYNC, BGPPA_NEXTHOPSELF, BGPPA_LCLADDR,
      BGPPA_PREFERENCE, BGPPA_PREPEND, BGPPA_DESCR,
      EXPA_PROTO};
enum {ATTR_FLAG, ATTR_PREFIX, ATTR_STRING, ATTR_ADDR, ATTR_NUMBER,
      ATTR_DATA};
enum {BGPPEER_NORMAL, BGPPEER_CLIENT}; 
enum {RTP_IFACE, RTP_BGP, RTP_RIP, RTP_IBGP}; 

static struct in6_prefix in6pfx_temp; /* XXX */
static struct yy_bgppeerinfo bgppeer_temp; /* XXX file global */
static struct yy_bgppeerinfo *bgppeer_head;
static int yy_debug, yy_asnum, yy_bgpsbsize, yy_holdtime, yy_rrflag,
	yy_rip, yy_rip_sitelocal;
static int yy_bgp;
static char *yy_dumpfile, *yy_routerid;
static struct yy_ripifinfo *yy_ripifinfo_head;
static struct yy_exportinfo *yy_exportinfo_head;

extern char *dumpfile;

extern int yylex __P((void));
extern int get_in6_addr __P((char *, struct sockaddr_in6 *));
extern char *ip6str __P((struct in6_addr *, unsigned int));
extern int sa6_equal __P((struct sockaddr_in6 *, struct sockaddr_in6 *));
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
%token DUMPFILE
%token AUTONOMOUSSYSTEM ROUTERID HOLDTIME ROUTEREFLECTOR BGPSBSIZE
%token INTERFACE IFNAME
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
			set_string(yy_routerid, $2.v, "RouterID");
		}
	|	HOLDTIME NUMBER EOS
		{
			set_param(yy_holdtime, $2, "holdtime");
		}
	|	ROUTEREFLECTOR EOS
		{
			set_param(yy_rrflag, 1, "route reflector");
		}
	;


/* RIP */
rip_statement:
		RIP YES BCL rip_substatements ECL
		{
			if (yy_rip != -1) {
				yywarn("RIP(yes) doubly defined (ignored)");
				return(-1);
			}
			yy_rip = 1;
		}
	|	RIP BCL rip_substatements ECL
		{
			if (yy_rip != -1) {
				yywarn("RIP(yes) doubly defined (ignored)");
				return(-1);
			}
			yy_rip = 1;
		}
	|	RIP NO IGNORE_END
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
			
			ifinfo = find_ripifinfo($2.v);
			if (ifinfo == NULL) {
				yywarn("can't find RIP interface: %s", $2.v);
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
		BGP YES BCL bgp_substatements ECL
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
			int pref = 1;

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
			p->rtpu.rtp_bgp.peeras = $4;

			$$ = p;
		}
	|	PROTO BGP PEER STRING all_block EOS
		{
			struct yy_rtproto *p;
			struct sockaddr_in6 peeraddr;

			if ((p = malloc(sizeof(*p))) == NULL) {
				yywarn("can't allocate memory");
				free($4.v);
				return(-1);
			}
			memset(p, 0, sizeof(*p));
			p->type = RTP_BGP;
			if (get_in6_addr($4.v, &p->rtpu.rtp_bgp.peeraddr)) {
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
		
	};

aggregate_substatements:
		/* empty */
	|	protocol
		{
		}
	|	EXPLICIT BCL prefix_list ECL EOS
		{
		}
	;

/* prefix */
prefix_list:
		/* empty */
	|	prefix_list prefix EOS
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
			       ip6str(&info->peeraddr.sin6_addr,
				      info->peeraddr.sin6_scope_id));
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
	for (info = bgppeer_head; info; info = info->next) {
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
			       ip6str(&info->peeraddr.sin6_addr,
				      info->peeraddr.sin6_scope_id));
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

	info->next = bgppeer_head;
	bgppeer_head = info;

	return(0);
}

static struct yy_ripifinfo *
find_ripifinfo(ifname)
	char *ifname;
{
	struct yy_ripifinfo *info;

	for (info = yy_ripifinfo_head; info; info = info->next) {
		if (strcmp(info->ifname, ifname) == 0)
			return(info);
	}

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
	default:
		/* XXX what do I do? */
		yywarn("unknown attribute type(%d)", type);
		break;
	}
	p->next = list;

	return(p);
}

static void
rip_config()
{
	struct yy_ripifinfo *info;
	struct attr_list *attr;

	printf("RIP config\n");

	for (info = yy_ripifinfo_head; info; info = info->next) {
		printf("  %s: ", info->ifname);

		for (attr = info->attribute; attr; attr = attr->next) {
			switch(attr->code) {
			case RIPIFA_DEFAULT:
				printf("default_originate ");
				break;
			case RIPIFA_NORIPIN:
				printf("noripin ");
				break;
			case RIPIFA_NORIPOUT:
				printf("noripout ");
				break;
			case RIPIFA_FILINDEF:
				printf("input_filter_default ");
				break;
			case RIPIFA_FILOUTDEF:
				printf("output_filter_default ");
				break;
			case RIPIFA_RESINDEF:
				printf("input_restriction_default ");
				break;
			case RIPIFA_RESOUTDEF:
				printf("output_restriction_default ");
				break;
			case RIPIFA_FILINPFX:
				printf("input_filter(%s/%d) ",
				   ip6str(&attr->attru.prefix.paddr.sin6_addr,
					  attr->attru.prefix.paddr.sin6_scope_id),
				   attr->attru.prefix.plen);
				break;
			case RIPIFA_FILOUTPFX:
				printf("output_filter(%s/%d) ",
				   ip6str(&attr->attru.prefix.paddr.sin6_addr,
					  attr->attru.prefix.paddr.sin6_scope_id),
				   attr->attru.prefix.plen);
				break;
			case RIPIFA_RESINPFX:
				printf("input_restriction(%s/%d) ",
				   ip6str(&attr->attru.prefix.paddr.sin6_addr,
					  attr->attru.prefix.paddr.sin6_scope_id),
				   attr->attru.prefix.plen);
				break;
			case RIPIFA_RESOUTPFX:
				printf("output_restriction(%s/%d) ",
				       ip6str(&attr->attru.prefix.paddr.sin6_addr,
					      attr->attru.prefix.paddr.sin6_scope_id),
				       attr->attru.prefix.plen);
				break;
			case RIPIFA_DESCR:
				printf("descr=%s ", attr->attru.str);
				break;
			default:
				printf("unknown_attribute(%d) ", attr->code);
			}
		}
		printf("\n");
	}
}

static void
bgp_config()
{
	struct yy_bgppeerinfo *info;
	struct attr_list *attr;

	printf("BGP config\n");

	for (info = bgppeer_head; info; info = info->next) {
		printf("  peer: %s ",
		       ip6str(&info->peeraddr.sin6_addr,
			      info->peeraddr.sin6_scope_id));
		if (info->asnum < 0) {
			printf("IBGP ");
			if (info->peertype == BGPPEER_CLIENT)
				printf("CLIENT ");
			if (info->routerid)
				printf("routerID: %x ", htonl(info->routerid));
		}
		else
			printf("EBGP ");

		for (attr = info->attribute; attr; attr = attr->next) {
			switch(attr->code) {
			case BGPPA_IFNAME:
				printf("interface: %s ", attr->attru.str);
				break;
			case BGPPA_NOSYNC:
				printf("nosync ");
				break;
			case BGPPA_NEXTHOPSELF:
				printf("nexthop_self ");
				break;
			case BGPPA_LCLADDR:
				printf("lcladdr %s ",
				       ip6str(&attr->attru.in6addr.sin6_addr,
					      attr->attru.in6addr.sin6_scope_id));
				break;
			case BGPPA_PREFERENCE:
				printf("preference %d ", attr->attru.number);
				break;
			case BGPPA_PREPEND:
				printf("prepend %d ", attr->attru.number);
				break;
			case BGPPA_DESCR:
				printf("descr=%s ", attr->attru.str);
				break;
			default:
				printf("unknown_attribute(%d) ", attr->code);
			}
		}

		putchar('\n');
	}
}

static void
export_config()
{
	struct yy_exportinfo *info;
	struct attr_list *attr;

	printf("Export config\n");
	for (info = yy_exportinfo_head; info; info = info->next) {
		printf("  peer: ");
		if (info->asnum >= 0)
			printf(" AS: %d ", info->asnum);
		if (!IN6_IS_ADDR_UNSPECIFIED(&info->peeraddr.sin6_addr))
			printf(" addr: %s ",
			       ip6str(&info->peeraddr.sin6_addr,
				      info->peeraddr.sin6_scope_id));

		for (attr = info->protolist; attr; attr = attr->next) {
			struct yy_rtproto *proto;
			
			proto = (struct yy_rtproto *)attr->attru.data;

			switch(proto->type) {
			case RTP_IFACE:
				printf("interface_route(%s) ",
				       proto->rtpu.ifname);
				break;
			case RTP_BGP:
				printf("BGP(AS: %d) ",
				       proto->rtpu.rtp_bgp.peeras);
				break;
			case RTP_RIP:
				printf("RIP ");
				break;
			case RTP_IBGP:
				printf("IBGP ");
				break;
			default:
				printf("unknown proto(%d) ", proto->type);
				break;
			}
		}
		putchar('\n');
	}
}

int
cf_post_config()
{
	rip_config();
	bgp_config();
	export_config();
 
	return(0);
}

/* initialize all the temporary variables */
void
cf_init()
{
	yy_debug = yy_asnum = yy_bgpsbsize = yy_holdtime = yy_rrflag = -1;
	yy_rip = yy_rip_sitelocal = yy_bgp = -1;
	yy_dumpfile = yy_routerid = NULL;
	yy_ripifinfo_head = NULL;
	yy_exportinfo_head = NULL;
	
	return;
}
