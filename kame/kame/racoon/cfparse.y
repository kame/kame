%{
#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet6/ipsec.h>
#include <netkey/key_var.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#include "addrinfo.h"
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "str2val.h"
#include "debug.h"

#include "cfparse.h"
#include "cftoken.h"
#include "algorithm.h"
#include "localconf.h"
#include "policy.h"
#include "oakley.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "isakmp_var.h"
#include "handler.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "strnames.h"

struct proposalspec {
	time_t lifetime;		/* for isakmp/ipsec */
	int lifebyte;			/* for isakmp/ipsec */
	struct secprotospec *spspec;	/* the head is always current spec. */
	struct proposalspec *next;	/* the tail is the most prefered. */
	struct proposalspec *prev;
};

struct secprotospec {
	int prop_no;
	int trns_no;
	int strength;		/* for isakmp/ipsec */
	int encklen;		/* for isakmp/ipsec */
	time_t lifetime;	/* for isakmp */
	int lifebyte;		/* for isakmp */
	int proto_id;		/* for ipsec (isakmp?) */
	int ipsec_level;	/* for ipsec */
	int encmode;		/* for ipsec */
	struct sockaddr *remote;
	int algclass[MAXALGCLASS];

	struct secprotospec *next;	/* the tail is the most prefiered. */
	struct secprotospec *prev;
	struct proposalspec *back;
};

static int cur_algclass;
static struct policyindex *cur_spidx;
static struct remoteconf *cur_rmconf;
static int tmpalgtype[MAXALGCLASS];

static struct proposalspec *prhead;	/* the head is always current. */

static struct addrinfo *parse_addr __P((char *host, char *port, int flag));
static struct policyindex * parse_spidx __P((caddr_t src, int prefs, int ports,
		caddr_t dst, int prefd, int portd, int ul_proto, int dir));
static struct proposalspec *newprspec __P((void));
static void cleanprhead __P((void));
static void insprspec
	__P((struct proposalspec *spspec, struct proposalspec **head));
static struct secprotospec *newspspec __P((void));
static void insspspec
	__P((struct secprotospec *spspec, struct proposalspec **head));

static int set_ipsec_proposal
	__P((struct policyindex *spidx, struct proposalspec *prspec));
static int set_isakmp_proposal
	__P((struct remoteconf *rmconf, struct proposalspec *prspec));
static u_int32_t set_algtypes __P((struct secprotospec *s, int class));
static void clean_tmpalgtype __P((void));
static int expand_ipsecspec __P((int prop_no, int trns_no, int *types,
	int class, int last, struct proposalspec *p, struct secprotospec *s,
	struct ipsecpolicy *ipsp));
static int expand_isakmpspec __P((int prop_no, int trns_no, int *types,
	int class, int last, time_t lifetime, int lifebyte, int encklen,
	struct remoteconf *rmconf));
%}

%union {
	unsigned long num;
	vchar_t val;
	struct addrinfo *res;
	struct policyindex *spidx;
	struct remoteconf *rmconf;
	struct sockaddr *saddr;
}

	/* path */
%token PATH PATHTYPE
	/* include */
%token INCLUDE
	/* self information */
%token IDENTIFIER IDENTIFIERTYPE VENDORID
	/* logging */
%token LOGGING LOGLEV
	/* padding */
%token PADDING PAD_MAXLEN PAD_RANDOMIZE PAD_RESTRICT PAD_EXCLTAIL
	/* listen */
%token LISTEN X_ISAKMP X_ADMIN
	/* timer */
%token RETRY RETRY_COUNTER RETRY_INTERVAL RETRY_PERSEND
%token RETRY_PHASE1 RETRY_PHASE2
	/* algorithm */
%token ALGORITHM_LEVEL ALGORITHM_CLASS ALGORITHMTYPE STRENGTHTYPE
	/* policy */
%token POLICY DIRTYPE ACTION
%token PLADDRTYPE PROPOSAL WHICHSIDE
%token PROTOCOL SECLEVEL SECLEVELTYPE SECMODE SECMODETYPE
	/* remote */
%token REMOTE ANONYMOUS
%token EXCHANGE_MODE EXCHANGETYPE DOI DOITYPE SITUATION SITUATIONTYPE
%token NONCE_SIZE DH_GROUP KEEPALIVE
%token POST_COMMAND
%token EXEC_PATH EXEC_COMMAND EXEC_SUCCESS EXEC_FAILURE

%token PREFIX PORT PORTANY UL_PROTO ANY
%token PFS_GROUP LIFETIME LIFETYPE UNITTYPE STRENGTH

	/* static sa */
%token STATICSA STATICSA_STATEMENT

%token NUMBER SWITCH
%token HEXSTRING QUOTEDSTRING ADDRSTRING
%token EOS BOC EOC

%type <num> NUMBER SWITCH keylength
%type <num> PATHTYPE IDENTIFIERTYPE LOGLEV 
%type <num> ALGORITHM_CLASS algorithm_types algorithm_type
%type <num> ALGORITHMTYPE STRENGTHTYPE
%type <num> PREFIX prefix PORT port ike_port DIRTYPE ACTION PLADDRTYPE WHICHSIDE
%type <num> ul_proto UL_PROTO secproto
%type <num> LIFETYPE UNITTYPE
%type <num> SECLEVELTYPE SECMODETYPE 
%type <num> EXCHANGETYPE DOITYPE SITUATIONTYPE
%type <val> QUOTEDSTRING HEXSTRING ADDRSTRING
%type <res> ike_addrinfo_port
%type <spidx> policy_index
%type <saddr> remote_index

%%

statements
	:	/* nothing */
	|	statements statement
	;
statement
	:	path_statement
	|	include_statement
	|	identifier_statement
	|	logging_statement
	|	padding_statement
	|	listen_statement
	|	timer_statement
	|	algorithm_statement
	|	policy_statement
	|	remote_statement
	|	staticsa_statement
	;

	/* path */
path_statement
	:	PATH PATHTYPE QUOTEDSTRING EOS
		{
			if ($2 > LC_PATHTYPE_MAX) {
				yyerror("invalid path type %d", $2);
				return -1;
			}

			/* free old pathinfo */
			if (lcconf->pathinfo[$2])
				free(lcconf->pathinfo[$2]);

			/* set new pathinfo */
			lcconf->pathinfo[$2] = $3.v;
		}
	;

	/* include */
include_statement
	:	INCLUDE QUOTEDSTRING EOS
		{
			char path[MAXPATHLEN];

			snprintf(path, sizeof(path), "%s/%s", 
				lcconf->pathinfo[LC_PATHTYPE_INCLUDE], $2.v);
			free($2.v);
			if (yycf_switch_buffer(path) != 0)
				return -1;
		}
	;

	/* self infomation */
identifier_statement
	:	IDENTIFIER identifier_stmt
	;
identifier_stmt
	:	VENDORID QUOTEDSTRING EOS
		{
			lcconf->vendorid = vdup(&$2);
			if (lcconf->vendorid == NULL) {
				yyerror("failed to set vendorid: %s",
					strerror(errno));
				return -1;
			}
		}
	|	IDENTIFIERTYPE QUOTEDSTRING EOS
		{
			lcconf->ident[$1] = vdup(&$2);
			free($2.v);
			if (lcconf->ident[$1] == NULL) {
				yyerror("failed to set my ident: %s",
					strerror(errno));
				return -1;
			}
		}
	;

	/* logging */
logging_statement
	:	LOGGING log_level EOS
	;
log_level
	:	HEXSTRING
		{
			/* command line option has a priority than it. */
			if (!f_debugcmd) {
				size_t size;
				debug |= *(u_int32_t *)str2val($1.v, 16, &size);
				free($1.v);
			}
		}
	|	LOGLEV
		{
			/* command line option has a priority than it. */
			if (!f_debugcmd)
				debug = $1;
		}
	;

	/* padding */
padding_statement
	:	PADDING BOC padding_stmts EOC
	;
padding_stmts
	:	/* nothing */
	|	padding_stmts padding_stmt
	;
padding_stmt
	:	PAD_RANDOMIZE SWITCH EOS { lcconf->pad_random = $2; }
	|	PAD_MAXLEN NUMBER EOS { lcconf->pad_maxsize = $2; }
	|	PAD_RESTRICT SWITCH EOS { lcconf->pad_restrict = $2; }
	|	PAD_EXCLTAIL SWITCH EOS { lcconf->pad_excltail = $2; }
	;

	/* listen */
listen_statement
	:	LISTEN BOC listen_stmts EOC
	;
listen_stmts
	:	/* nothing */
	|	listen_stmts listen_stmt
	;
listen_stmt
	:	X_ISAKMP ike_addrinfo_port EOS
		{
			struct myaddrs *p;

			p = newmyaddr();
			if (p == NULL) {
				yyerror("failed to allocate myaddrs");
				return -1;
			}
			p->addr = dupsaddr($2->ai_addr);
			if (p->addr == NULL) {
				yyerror("failed to copy sockaddr ");
				delmyaddr(p);
				return NULL;
			}
			freeaddrinfo($2);

			insmyaddr(p, &lcconf->myaddrs);

			lcconf->autograbaddr = 0;
		}
	|	X_ADMIN PORT EOS
		{
			lcconf->port_admin = $2;
		}
	;
ike_addrinfo_port
	:	ADDRSTRING ike_port
		{
			char portbuf[10];

			snprintf(portbuf, sizeof(portbuf), "%ld", $2);
			$$ = parse_addr($1.v, portbuf, AI_NUMERICHOST);
			free($1.v);
			if (!$$)
				return -1;
		}
	;
ike_port
	:	/* nothing */	{ $$ = PORT_ISAKMP; }
	|	PORT		{ $$ = $1; }
	;

	/* timer */
timer_statement
	:	RETRY BOC timer_stmts EOC
	;
timer_stmts
	:	/* nothing */
	|	timer_stmts timer_stmt
	;
timer_stmt
	:	RETRY_COUNTER NUMBER EOS { lcconf->retry_counter = $2; }
	|	RETRY_INTERVAL NUMBER UNITTYPE EOS { lcconf->retry_interval = $2 * $3; }
	|	RETRY_PERSEND NUMBER EOS { lcconf->count_persend = $2; }
	|	RETRY_PHASE1 NUMBER UNITTYPE EOS { lcconf->retry_checkph1 = $2; }
	|	RETRY_PHASE2 NUMBER UNITTYPE EOS { lcconf->wait_ph2complete = $2; }
	;

	/* algorithm */
algorithm_statement
	:	ALGORITHM_LEVEL BOC algorithm_stmts EOC
	;
algorithm_stmts
	:	/* nothing */
	|	algorithm_stmts algorithm_stmt
	;
algorithm_stmt
	:	algorithm_class BOC algorithm_strengthes EOC
	;
algorithm_class
	:	ALGORITHM_CLASS { cur_algclass = $1; }
	;
algorithm_strengthes
	:	/* nothing */
	|	algorithm_strengthes algorithm_strength
	;
algorithm_strength
	:	STRENGTHTYPE algorithm_types EOS
		{
			lcconf->algstrength[cur_algclass]->algtype[$1] = $2;
			YIPSDEBUG(DEBUG_CONF,
				printf("current algclass = %s\n",
					s_algclass(cur_algclass));
				printf("%s\n", BIT2STR($2)));
			$2 = 0;
		}
	;
algorithm_types
	:	algorithm_type {
			$$ = (1 << $1) >> 1;
		}
	|	algorithm_type algorithm_types {
			$$ = (1 << $1) >> 1;
			$$ |= $2;
		}
	;
algorithm_type
	:	ALGORITHMTYPE
		{
			$$ = algtype2doi(cur_algclass, $1);
			if ($$ == -1) {
				yyerror("parse error");
				return -1;
			}
		}
	;

	/* policy */
policy_statement
	:	POLICY policy_index {
			cur_spidx = $2;
		}
		policy_specswrap
	;
policy_specswrap
	:	EOS
		{
			if (cur_spidx->action == IPSEC_POLICY_IPSEC) {
				yyerror("must define policy for IPsec");
				return -1;
			}
		}
	|	BOC
		{
			if (cur_spidx->action != IPSEC_POLICY_IPSEC) {
				yyerror("must not define policy for no IPsec");
				return -1;
			}

			cur_spidx->policy = newipsp();
			if (cur_spidx->policy == NULL) {
				yyerror("failed to allocate ipsec policy");
				return -1;
			}
			cur_spidx->policy->spidx = cur_spidx;
		}
		policy_specs EOC
		{
			if (set_ipsec_proposal(cur_spidx, prhead) != 0)
				return -1;

			/* DH group settting if PFS is required. */
			if (cur_spidx->policy->pfs_group != 0
			 && oakley_setdhgroup(cur_spidx->policy->pfs_group,
					&cur_spidx->policy->pfsgrp) < 0) {
				yyerror("failed to set DH value.\n");
				return -1;
			}

			ipsecdoi_printsa(cur_spidx->policy->proposal);
			insspidx(cur_spidx);

			cleanprhead();
		}
	;
policy_index
	:	ADDRSTRING prefix port
		ADDRSTRING prefix port ul_proto DIRTYPE ACTION
		{
			$$ = parse_spidx($1.v, $2, $3, $4.v, $5, $6, $7, $8);
			$$->action = $9;
			free($1.v);
			free($4.v);
		}
	;
prefix
	:	/* nothing */ { $$ = ~0; }
	|	PREFIX { $$ = $1; }
	;
port
	:	/* nothing */ { $$ = IPSEC_PORT_ANY; }
	|	PORT { $$ = $1; }
	|	PORTANY { $$ = IPSEC_PORT_ANY; }
	;
ul_proto
	:	NUMBER { $$ = $1; }
	|	UL_PROTO { $$ = $1; }
	|	ANY { $$ = IPSEC_ULPROTO_ANY; }
	;
policy_specs
	:	/* nothing */
	|	policy_specs policy_spec
	;
policy_spec
	:	PFS_GROUP ALGORITHMTYPE EOS
		{
			int doi;

			doi = algtype2doi(algclass_isakmp_dh, $2);
			if (doi == -1) {
				yyerror("must be DH group");
				return -1;
			}
			cur_spidx->policy->pfs_group = doi;
		}
	|	PROPOSAL
		{
			struct proposalspec *prspec;

			prspec = newprspec();
			if (prspec == NULL)
				return -1;
			prspec->lifetime = ipsecdoi_get_defaultlifetime();
			insprspec(prspec, &prhead);
		}
		BOC ipsecproposal_specs EOC
	;
ipsecproposal_specs
	:	/* nothing */
	|	ipsecproposal_specs ipsecproposal_spec
	;
ipsecproposal_spec
	:	LIFETIME LIFETYPE NUMBER UNITTYPE EOS
		{
			if ($2 == CF_LIFETYPE_TIME)
				prhead->lifetime = $3 * $4;
			else
				prhead->lifebyte = $3 * $4;
		}
	|	PROTOCOL secproto
		{
			struct secprotospec *spspec;
	
			spspec = newspspec();
			if (spspec == NULL)
				return -1;
			insspspec(spspec, &prhead);

			prhead->spspec->proto_id = ipproto2doi($2);
		}
		BOC secproto_specs EOC
	;
secproto
	:	UL_PROTO {
			switch ($1) {
			case IPPROTO_ESP:
			case IPPROTO_AH:
			case IPPROTO_IPCOMP:
				break;
			default:
				yyerror("It's not security protocol");
				return -1;
			}
			$$ = $1;
		}
	;
secproto_specs
	:	/* nothing */
	|	secproto_specs secproto_spec
	;
secproto_spec
	:	SECLEVEL SECLEVELTYPE EOS { prhead->spspec->ipsec_level = $2; }
	|	SECMODE secmode EOS
	|	STRENGTH STRENGTHTYPE EOS { prhead->spspec->strength = $2; }
	|	ALGORITHM_CLASS ALGORITHMTYPE keylength EOS
		{
			int doi;
			int defklen;

			doi = algtype2doi($1, $2);
			if (doi == -1) {
				yyerror("algorithm mismatched");
				return -1;
			}
			switch ($1) {
			case algclass_ipsec_enc:
				if (prhead->spspec->proto_id != IPSECDOI_PROTO_IPSEC_ESP) {
					yyerror("algorithm mismatched");
					return -1;
				}
				prhead->spspec->algclass[algclass_ipsec_enc] = doi;
				defklen = default_keylen($1, $2);
				if (defklen == 0) {
					if ($3) {
						yyerror("keylen not allowed");
						return -1;
					}
				} else {
					if ($3 && check_keylen($1, $2, $3) < 0) {
						yyerror("invalid keylen %d", $3);
						return -1;
					}
				}
				if ($3)
					prhead->spspec->encklen = $3;
				else
					prhead->spspec->encklen = defklen;
				break;
			case algclass_ipsec_auth:
				if (prhead->spspec->proto_id == IPSECDOI_PROTO_IPCOMP) {
					yyerror("algorithm mismatched");
					return -1;
				}
				prhead->spspec->algclass[algclass_ipsec_auth] = doi;
				break;
			case algclass_ipsec_comp:
				if (prhead->spspec->proto_id != IPSECDOI_PROTO_IPCOMP) {
					yyerror("algorithm mismatched");
					return -1;
				}
				prhead->spspec->algclass[algclass_ipsec_auth] = doi;
				break;
			default:
				yyerror("algorithm mismatched");
				return -1;
			}
		}
	;
secmode
	:	SECMODETYPE {
			if ($1 == IPSECDOI_ATTR_ENC_MODE_TUNNEL) {
				yyerror("must specify peer's address");
				return -1;
			}
			prhead->spspec->encmode = $1;
			prhead->spspec->remote = NULL;
		}
	|	SECMODETYPE ADDRSTRING {
			struct addrinfo *res;

			if ($1 != IPSECDOI_ATTR_ENC_MODE_TUNNEL) {
				yyerror("should not specify peer's address");
				return -1;
			}
			prhead->spspec->encmode = $1;

			res = parse_addr($2.v, NULL, AI_NUMERICHOST);
			if (res == NULL)
				return -1;
			free($2.v);
			prhead->spspec->remote = dupsaddr(res->ai_addr);
			if (prhead->spspec->remote == NULL) {
				yyerror("failed to copy sockaddr ");
				return -1;
			}
			freeaddrinfo(res);
		}
	;
keylength
	:	/* nothing */ { $$ = 0; }
	|	NUMBER { $$ = $1; }
	;

	/* remote */
remote_statement
	:	REMOTE remote_index
		{
			struct remoteconf *new;
			struct proposalspec *prspec;

			new = newrmconf();
			if (new == NULL)
				return -1;

			new->remote = $2;
			cur_rmconf = new;

			prspec = newprspec();
			if (prspec == NULL)
				return -1;
			prspec->lifetime = oakley_get_defaultlifetime();
			insprspec(prspec, &prhead);
		}
		BOC remote_specs EOC
		{
			if (set_isakmp_proposal(cur_rmconf, prhead) != 0)
				return -1;

			/* DH group settting if aggressive mode is there. */
			if (check_etypeok(cur_rmconf, ISAKMP_ETYPE_AGG) != NULL) {
				if (cur_rmconf->dh_group == 0) {
					yyerror("DH group must be required "
						"in aggressive mode.\n");
					return -1;
				}

				/* DH group settting if PFS is required. */
				if (oakley_setdhgroup(cur_rmconf->dh_group,
						&cur_rmconf->dhgrp) < 0) {
					yyerror("failed to set DH value.\n");
					return -1;
				}
			}

			insrmconf(cur_rmconf);

			cleanprhead();
		}
	;
remote_index
	:	ANONYMOUS ike_port
		{
			$$ = newsaddr(sizeof(struct sockaddr *));
			$$->sa_family = AF_UNSPEC;
			((struct sockaddr_in *)$$)->sin_port = htons($2);
		}
	|	ike_addrinfo_port
		{
			$$ = newsaddr($1->ai_addrlen);
			if ($$ == NULL) {
				yyerror("filed to allocate sockaddr");
				return -1;
			}
			memcpy($$, $1->ai_addr, $1->ai_addrlen);
		}
	;
remote_specs
	:	/* nothing */
	|	remote_specs remote_spec
	;
remote_spec
	:	EXCHANGE_MODE exchange_types EOS
	|	DOI DOITYPE EOS { cur_rmconf->doitype = $2; }
	|	SITUATION SITUATIONTYPE EOS { cur_rmconf->sittype = $2; }
	|	IDENTIFIER IDENTIFIERTYPE EOS
		{
			cur_rmconf->identtype = idtype2doi($2);
		}
	|	NONCE_SIZE NUMBER EOS { cur_rmconf->nonce_size = $2; }
	|	DH_GROUP ALGORITHMTYPE EOS
		{
			int doi;

			doi = algtype2doi(algclass_isakmp_dh, $2);
			if (doi == -1) {
				yyerror("must be DH group");
				return -1;
			}
			cur_rmconf->dh_group = doi;
		}
	|	KEEPALIVE EOS { cur_rmconf->keepalive = TRUE; }
	|	LIFETIME LIFETYPE NUMBER UNITTYPE EOS
		{
			if ($2 == CF_LIFETYPE_TIME)
				prhead->lifetime = $3 * $4;
			else
				prhead->lifebyte = $3 * $4;
		}
	|	PROPOSAL
		{
			struct secprotospec *spspec;

			spspec = newspspec();
			if (spspec == NULL)
				return -1;
			insspspec(spspec, &prhead);
		}
		BOC isakmpproposal_specs EOC
	;
exchange_types
	:	/* nothing */
	|	exchange_types EXCHANGETYPE
		{
			struct etypes *new;
			new = malloc(sizeof(struct etypes));
			if (new == NULL) {
				yyerror("filed to allocate etypes");
				return -1;
			}
			new->type = $2;
			new->next = NULL;
			if (cur_rmconf->etypes == NULL)
				cur_rmconf->etypes = new;
			else {
				struct etypes *p;
				for (p = cur_rmconf->etypes;
				     p->next != NULL;
				     p = p->next)
					;
				p->next = new;
			}
		}
	;
isakmpproposal_specs
	:	/* nothing */
	|	isakmpproposal_specs isakmpproposal_spec
	;
isakmpproposal_spec
	:	STRENGTH STRENGTHTYPE EOS { prhead->spspec->strength = $2; }
	|	LIFETIME LIFETYPE NUMBER UNITTYPE EOS
		{
			if ($2 == CF_LIFETYPE_TIME)
				prhead->spspec->lifetime = $3 * $4;
			else
				prhead->spspec->lifebyte = $3 * $4;
		}
	|	ALGORITHM_CLASS ALGORITHMTYPE keylength EOS
		{
			int doi;

			doi = algtype2doi($1, $2);
			if (doi == -1) {
				yyerror("algorithm mismatched");
				return -1;
			}
			switch ($1) {
			case algclass_isakmp_enc:
				prhead->spspec->algclass[algclass_isakmp_enc] = doi;
				if (check_keylen($1, $2, $3) == -1)
					return -1;
				prhead->spspec->encklen = $3;
				break;
			case algclass_isakmp_hash:
				prhead->spspec->algclass[algclass_isakmp_hash] = doi;
				break;
			case algclass_isakmp_dh:
				prhead->spspec->algclass[algclass_isakmp_dh] = doi;
				break;
			case algclass_isakmp_ameth:
				prhead->spspec->algclass[algclass_isakmp_ameth] = doi;
				break;
			default:
				yyerror("algorithm mismatched");
				return -1;
			}
		}
	;

	/* static sa */
staticsa_statement
	:	STATICSA STATICSA_STATEMENT EOS
		{
			/* execute static sa */
			/* system("setkey $2.v"); */
		}
	;

%%

static struct addrinfo *
parse_addr(host, port, flag)
	char *host;
	char *port;
	int flag;
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = flag;
	error = getaddrinfo(host, port, &hints, &res);
	if (error != 0) {
		yyerror("getaddrinfo(%s%s%s): %s",
			host, port ? "," : "", port ? port : "",
			gai_strerror(error));
		return NULL;
	}
	if (res->ai_next != NULL) {
		yyerror("getaddrinfo(%s%s%s): "
			"resolved to multiple address, "
			"taking the first one",
			host, port ? "," : "", port ? port : "");
	}
	return res;
}

static struct policyindex *
parse_spidx(src, prefs, ports, dst, prefd, portd, ul_proto, dir)
	caddr_t src, dst;
	int prefs, ports, prefd, portd, ul_proto, dir;
{
	struct policyindex *spidx;
	char portbuf[10];
	struct addrinfo *res;

	if ((ul_proto == IPPROTO_ICMP || ul_proto == IPPROTO_ICMPV6)
	 && (ports != IPSEC_PORT_ANY || portd != IPSEC_PORT_ANY)) {
		yyerror("port number must be \"any\".");
		return NULL;
	}

	spidx = newspidx();
	if (spidx == NULL) {
		yyerror("failed to allocate policy index");
		return NULL;
	}

	spidx->dir = dir;
	spidx->ul_proto = ul_proto;

	snprintf(portbuf, sizeof(portbuf), "%d", ports);
	res = parse_addr(src, portbuf, AI_NUMERICHOST);
	if (res == NULL) {
		delspidx(spidx);
		return NULL;
	}
	memcpy(&spidx->src, res->ai_addr, res->ai_addrlen);
	spidx->prefs = prefs == ~0
		? (_INALENBYAF(res->ai_family) << 3)
		: prefs;
	freeaddrinfo(res);

	snprintf(portbuf, sizeof(portbuf), "%d", portd);
	res = parse_addr(dst, portbuf, AI_NUMERICHOST);
	if (res == NULL) {
		delspidx(spidx);
		return NULL;
	}
	memcpy(&spidx->dst, res->ai_addr, res->ai_addrlen);
	spidx->prefd = prefd == ~0
		? (_INALENBYAF(res->ai_family) << 3)
		: prefd;
	freeaddrinfo(res);

	return spidx;
}

static struct proposalspec *
newprspec()
{
	struct proposalspec *new;

	new = CALLOC(sizeof(*new), struct proposalspec *);
	if (new == NULL)
		yyerror("failed to allocate proposal: %s", strerror(errno));

	return new;
}

static void
cleanprhead()
{
	struct proposalspec *p, *next;

	if (prhead == NULL)
		return;

	for (p = prhead; p != NULL; p = next) {
		next = p->next;
		free(p);
	}

	prhead = NULL;
}

/*
 * insert into head of list.
 */
static void
insprspec(prspec, head)
	struct proposalspec *prspec;
	struct proposalspec **head;
{
	if (*head != NULL)
		(*head)->prev = prspec;
	prspec->next = *head;
	*head = prspec;
}

static struct secprotospec *
newspspec()
{
	struct secprotospec *new;

	new = CALLOC(sizeof(*new), struct secprotospec *);
	if (new == NULL) {
		yyerror("failed to allocate spproto: %s", strerror(errno));
		return NULL;
	}

	new->encklen = 0;	/*XXX*/

	return new;
}

/*
 * insert into head of list.
 */
static void
insspspec(spspec, head)
	struct secprotospec *spspec;
	struct proposalspec **head;
{
	spspec->back = *head;

	if ((*head)->spspec != NULL)
		(*head)->spspec->prev = spspec;
	spspec->next = (*head)->spspec;
	(*head)->spspec = spspec;
}

/* set final acceptable proposal */
static int
set_ipsec_proposal(spidx, prspec)
	struct policyindex *spidx;
	struct proposalspec *prspec;
{
	struct proposalspec *p;
	struct secprotospec *s;
	struct proposalspec *new;
	int prop_no; 
	int trns_no;
	u_int32_t types[MAXALGCLASS];

	if (spidx->policy == NULL)
		return -1;

	/*
	 * first, try to assign proposal/transform numbers to the table.
	 */
	for (p = prspec; p->next; p = p->next)
		;
	prop_no = 1;
	while (p) {
		for (s = p->spspec; s && s->next; s = s->next)
			;
		trns_no = 1;
		while (s) {
			s->prop_no = prop_no;
			s->trns_no = trns_no;
			trns_no++;
			s = s->prev;
		}

		prop_no++;
		p = p->prev;
	}

	/* split up proposals if necessary */
	for (p = prspec; p && p->next; p = p->next)
		;
	while (p) {
		int proto_id = 0;

		for (s = p->spspec; s && s->next; s = s->next)
			;
		if (s)
			proto_id = s->proto_id;
		new = NULL;
		while (s) {
			if (proto_id != s->proto_id) {
				if (!new)
					new = newprspec();
				if (!new)
					return -1;
				new->lifetime = p->lifetime;
				new->lifebyte = p->lifebyte;

				/* detach it from old list */
				if (s->prev)
					s->prev->next = s->next;
				else
					p->spspec = s->next;
				if (s->next)
					s->next->prev = s->prev;
				s->next = s->prev = NULL;

				/* insert to new list */
				insspspec(s, &new);
			}
			s = s->prev;
		}

		if (new) {
			new->prev = p->prev;
			p->prev->next = new;
			new->next = p;
			p->prev = new;
			new = NULL;
		}

		p = p->prev;
	}

#if 0
	for (p = prspec; p; p = p->next) {
		fprintf(stderr, "prspec: %p next=%p prev=%p\n", p, p->next, p->prev);
		for (s = p->spspec; s; s = s->next) {
			fprintf(stderr, "    spspec: %p next=%p prev=%p prop:%d trns:%d\n", s, s->next, s->prev, s->prop_no, s->trns_no);
		}
	}
#endif

	for (p = prspec; p->next != NULL; p = p->next)
		;
	while (p != NULL) {
		for (s = p->spspec; s->next != NULL; s = s->next)
			;
		while (s != NULL) {
			YIPSDEBUG(DEBUG_CONF,
				printf("lifetime = %ld\n", p->lifetime);
				printf("lifebyte = %d\n", p->lifebyte);
				printf("level=%s\n", s_ipsec_level(s->ipsec_level));
				printf("mode=%s\n", s_ipsecdoi_encmode(s->encmode));
				printf("remote=%s\n", saddrwop2str(s->remote));
				printf("proto=%s\n", s_ipsecdoi_proto(s->proto_id));
				printf("strength=%s\n", s_algstrength(s->strength));
				printf("encklen=%d\n", s->encklen);
			);

			switch (s->proto_id) {
			case IPSECDOI_PROTO_IPSEC_ESP:
				types[algclass_ipsec_enc] =
					set_algtypes(s, algclass_ipsec_enc);
				types[algclass_ipsec_auth] =
					set_algtypes(s, algclass_ipsec_auth);
				types[algclass_ipsec_comp] = 0;

				/* expanding spspec */
				clean_tmpalgtype();
				trns_no = expand_ipsecspec(s->prop_no,
						s->trns_no, types,
						algclass_ipsec_enc,
						algclass_ipsec_auth + 1,
						p, s, spidx->policy);
				if (trns_no == -1) {
					plog(logp, LOCATION, NULL,
						"failed to expand "
						"ipsec proposal.\n");
					return -1;
				}
				break;
			case IPSECDOI_PROTO_IPSEC_AH:
				types[algclass_ipsec_enc] = 0;
				types[algclass_ipsec_auth] =
					set_algtypes(s, algclass_ipsec_auth);
				types[algclass_ipsec_comp] = 0;

				/* expanding spspec */
				clean_tmpalgtype();
				trns_no = expand_ipsecspec(s->prop_no,
						s->trns_no, types,
						algclass_ipsec_auth,
						algclass_ipsec_auth + 1,
						p, s, spidx->policy);
				if (trns_no == -1) {
					plog(logp, LOCATION, NULL,
						"failed to expand "
						"ipsec proposal.\n");
					return -1;
				}
				break;
			case IPSECDOI_PROTO_IPCOMP:
				types[algclass_ipsec_comp] =
					set_algtypes(s, algclass_ipsec_comp);
				types[algclass_ipsec_enc] = 0;
				types[algclass_ipsec_auth] = 0;

				/* expanding spspec */
				clean_tmpalgtype();
				trns_no = expand_ipsecspec(s->prop_no,
						s->trns_no, types,
						algclass_ipsec_comp,
						algclass_ipsec_comp + 1,
						p, s, spidx->policy);
				if (trns_no == -1) {
					plog(logp, LOCATION, NULL,
						"failed to expand "
						"ipsec proposal.\n");
					return -1;
				}
				break;
			default:
				yyerror("Invaled ipsec protocol %d\n",
					s->proto_id);
				return -1;
			}

			s = s->prev;
		}
		prop_no++; 
		trns_no = 1;	/* reset */
		p = p->prev;
	}

	return 0;
}

/* set final acceptable proposal */
static int
set_isakmp_proposal(rmconf, prspec)
	struct remoteconf *rmconf;
	struct proposalspec *prspec;
{
	struct proposalspec *p;
	struct secprotospec *s;
	int prop_no = 1; 
	int trns_no = 1;
	u_int32_t types[MAXALGCLASS];

	/*
	 * XXX When aggressive mode, all DH type in each proposal MUST be
	 * checked whether equal
	 */
	p = prspec;
	if (p->next != 0) {
		plog(logp, LOCATION, NULL,
			"multiple proposal definition.\n");
		return -1;
	}

	for (s = p->spspec; s->next != NULL; s = s->next)
		;
	while (s != NULL) {
		YIPSDEBUG(DEBUG_CONF,
			printf("lifetime = %ld\n",
				s->lifetime ? s->lifetime : p->lifetime);
			printf("lifebyte = %d\n",
				s->lifebyte ? s->lifebyte : p->lifebyte);
			printf("strength=%s\n", s_algstrength(s->strength));
			printf("encklen=%d\n", s->encklen);
		);

		types[algclass_isakmp_enc] =
			set_algtypes(s, algclass_isakmp_enc);
		types[algclass_isakmp_hash] =
			set_algtypes(s, algclass_isakmp_hash);
		types[algclass_isakmp_dh] =
			set_algtypes(s, algclass_isakmp_dh);
		types[algclass_isakmp_ameth] =
			set_algtypes(s, algclass_isakmp_ameth);

		/* expanding spspec */
		clean_tmpalgtype();
		trns_no = expand_isakmpspec(prop_no, trns_no, types,
				algclass_isakmp_enc, algclass_isakmp_ameth + 1,
				s->lifetime ? s->lifetime : p->lifetime,
				s->lifebyte ? s->lifebyte : p->lifebyte,
				s->encklen,
				rmconf);
		if (trns_no == -1) {
			plog(logp, LOCATION, NULL,
				"failed to expand isakmp proposal.\n");
			return -1;
		}

		s = s->prev;
	}

	if (rmconf->proposal == NULL) {
		plog(logp, LOCATION, NULL,
			"no proposal found.\n");
		return -1;
	}

	return 0;
}

static u_int32_t
set_algtypes(s, class)
	struct secprotospec *s;
	int class;
{
	u_int32_t algtype = 0;

	if (s->algclass[class])
		algtype = (1 << s->algclass[class]) >> 1;
	else
		algtype = lcconf->algstrength[class]->algtype[s->strength];

	YIPSDEBUG(DEBUG_CONF,
		printf("%s=\t%s\n", s_algclass(class), BIT2STR(algtype)));

	return algtype;
}

static void
clean_tmpalgtype()
{
	int i;
	for (i = 0; i < MAXALGCLASS; i++)
		tmpalgtype[i] = 0;	/* means algorithm undefined. */
}

static int
expand_ipsecspec(prop_no, trns_no, types,
		class, last, p, s, ipsp)
	int prop_no, trns_no;
	int *types, class, last;
	struct proposalspec *p;
	struct secprotospec *s;
	struct ipsecpolicy *ipsp;
{
	int b = types[class];
	int bl = sizeof(lcconf->algstrength[0]->algtype[0]) << 3;
	int i;

	if (class == last) {
		struct ipsecsa *new = NULL;

		YIPSDEBUG(DEBUG_CONF,
			int j;
			char tb[4];
			printf("p:%d t:%d ", prop_no, trns_no);
			for (j = 0; j < MAXALGCLASS; j++) {
				snprintf(tb, sizeof(tb), "%d", tmpalgtype[j]);
				printf("%s%s%s%s ",
					s_algtype(j, tmpalgtype[j]),
					tmpalgtype[j] ? "(" : "",
					tb[0] == '0' ? "" : tb,
					tmpalgtype[j] ? ")" : "");
			}
			printf("\n");
		);

		/* check mandatory values */
		if (ipsecdoi_checkalgtypes(s->proto_id, 
			tmpalgtype[algclass_ipsec_enc],
			tmpalgtype[algclass_ipsec_auth],
			tmpalgtype[algclass_ipsec_comp]) == -1) {
			return -1;
		}

		/* set new sa */
		new = newipsa();
		if (new == NULL) {
			yyerror("failed to allocate ipsec sa");
			return -1;
		}
		new->prop_no = prop_no;
		new->trns_no = trns_no;
		new->lifetime = p->lifetime;
		new->lifebyte = p->lifebyte;
		new->proto_id = s->proto_id;
		new->ipsec_level = s->ipsec_level;
		new->encmode = s->encmode;
		new->dst = s->remote;
		new->enctype = tmpalgtype[algclass_ipsec_enc];
		new->encklen = s->encklen;
		new->authtype = tmpalgtype[algclass_ipsec_auth];
		new->comptype = tmpalgtype[algclass_ipsec_comp];

		insipsa(new, ipsp);

		return trns_no + 1;
	}

	for (i = 0; i < bl; i++) {
		if (b & 1) {
			tmpalgtype[class] = i + 1;
			trns_no = expand_ipsecspec(prop_no, trns_no, types,
					class + 1, last, p, s, ipsp);
			if (trns_no == -1)
				return -1;
		}
		b >>= 1;
	}

	return trns_no;
}

static int
expand_isakmpspec(prop_no, trns_no, types,
		class, last, lifetime, lifebyte, encklen, rmconf)
	int prop_no, trns_no;
	int *types, class, last;
	time_t lifetime;
	int lifebyte;
	int encklen;
	struct remoteconf *rmconf;
{
	int b = types[class];
	int bl = sizeof(lcconf->algstrength[0]->algtype[0]) << 3;
	int i;

	if (class == last) {
		struct isakmpsa *new;

		YIPSDEBUG(DEBUG_CONF,
			int j;
			char tb[4];
			printf("p:%d t:%d ", prop_no, trns_no);
			for (j = 0; j < MAXALGCLASS; j++) {
				snprintf(tb, sizeof(tb), "%d", tmpalgtype[j]);
				printf("%s%s%s%s ",
					s_algtype(j, tmpalgtype[j]),
					tmpalgtype[j] ? "(" : "",
					tb[0] == '0' ? "" : tb,
					tmpalgtype[j] ? ")" : "");
			}
			printf("\n");
		);

#define TMPALGTYPE2STR(n) \
	s_algtype(algclass_isakmp_##n, tmpalgtype[algclass_isakmp_##n])
		/* check mandatory values */
		if (tmpalgtype[algclass_isakmp_enc] == 0
		 || tmpalgtype[algclass_isakmp_ameth] == 0
		 || tmpalgtype[algclass_isakmp_hash] == 0
		 || tmpalgtype[algclass_isakmp_dh] == 0) {
			yyerror("few definition of algorithm "
				"enc=%s ameth=%s hash=%s dhgroup=%s.\n",
				TMPALGTYPE2STR(enc),
				TMPALGTYPE2STR(ameth),
				TMPALGTYPE2STR(hash),
				TMPALGTYPE2STR(dh));
			return -1;
		}
#undef TMPALGTYPE2STR(n)

		/* set new sa */
		new = newisakmpsa();
		if (new == NULL) {
			yyerror("failed to allocate isakmp sa");
			return -1;
		}
		new->prop_no = prop_no;
		new->trns_no = trns_no;
		new->lifetime = lifetime;
		new->lifebyte = lifebyte;
		new->enctype = tmpalgtype[algclass_isakmp_enc];
		new->encklen = encklen;
		new->authmethod = tmpalgtype[algclass_isakmp_ameth];
		new->hashtype = tmpalgtype[algclass_isakmp_hash];
		new->dh_group = tmpalgtype[algclass_isakmp_dh];

		insisakmpsa(new, rmconf);

		return trns_no + 1;
	}

	for (i = 0; i < bl; i++) {
		if (b & 1) {
			tmpalgtype[class] = i + 1;
			trns_no = expand_isakmpspec(prop_no, trns_no, types,
					class + 1, last, lifetime, lifebyte,
					encklen, rmconf);
			if (trns_no == -1)
				return -1;
		}
		b >>= 1;
	}

	return trns_no;
}

int
cfparse()
{
	int error;

	yycf_init_buffer();

	if (yycf_set_buffer(lcconf->racoon_conf) != 0)
		return -1;

	prhead = NULL;

	error = yyparse();
	if (error != 0) {
		if (yyerrorcount) {
			plog(logp, LOCATION, NULL,
				"fatal parse failure (%d errors)\n",
				yyerrorcount);
		} else {
			plog(logp, LOCATION, NULL,
				"fatal parse failure.\n");
		}
		return -1;
	}

	if (error == 0 && yyerrorcount) {
		plog(logp, LOCATION, NULL,
			"parse error is nothing, but yyerrorcount is %d.\n",
				yyerrorcount);
		exit(1);
	}

	yycf_clean_buffer();

	YIPSDEBUG(DEBUG_CONF, printf("parse successed.\n"));

	return 0;
}

int
cfreparse()
{
	flushph2();
	flushph1();
	flushrmconf();
	flushspidx();
	cleanprhead();
	clean_tmpalgtype();
	yycf_init_buffer();

	if (yycf_set_buffer(lcconf->racoon_conf) != 0)
		return -1;

	return(cfparse());
}

