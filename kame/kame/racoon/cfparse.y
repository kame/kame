%{
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>

#include <net/route.h>

#include <netinet/in.h>
#ifndef IPV6_INRIA_VERSION
#include <netinet6/in6.h>
#endif

#include <netkey/keydb.h>
#include <netkey/key_var.h>
#include <netdb.h>
#if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#include "gai.h"
#endif

#include <errno.h>

#include "var.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "cfparse.h"
#include "pfkey.h"
#include "admin.h"
#include "handler.h"
#include "misc.h"
#include "debug.h"

#define	IDVHLEN (sizeof(struct ipsecdoi_id) - sizeof(struct isakmp_gen))

int reparse = 0;

char *racoon_conf = YIPSD_CONF_FILE;
struct isakmp_conf cftab;
struct sockaddr_storage anonremote;
static struct isakmp_conf *cfp = NULL;		/* current cfp */
static int cf_ph;
static struct isakmp_cf_sa *cur_sap;
static struct isakmp_cf_p  *cur_pp;
static struct isakmp_cf_t  *cur_tp;

static struct addrinfo *parse_addr __P((char *, char *, int));
static int cf_setdata_v __P((int, caddr_t, int));
static int cf_setdata_l __P((int, u_int32_t));
int cf_post_config __P((void));

extern int yylex __P((void));
%}

%union {
	unsigned long num;
	vchar_t val;
	struct addrinfo *res;
}

%token EOS BOC EOC

%token LOGGING LOGLEV
%token PADDING MAX_LENGTH RANDOM_LENGTH CHECK_LENGTH EXCL_LASTONE
%token LISTEN X_ISAKMP X_ADMIN

	/* remote */
%token REMOTE ANONYMOUS
%token TRY_TO_SEND SEND_TIMER
%token NEED PFS VENDOR_ID
%token PHASE EXCHANGE_MODE EXCHANGE_T
%token DOI DOI_T
%token SITUATION SITUATION_T
%token ID_TYPE ID_IPV4_ADDR ID_IPV6_ADDR PORT FQDN USER_FQDN
%token PROPOSAL PROTOCOL PROTOCOL_T SPI
%token TRANSFORM TRANSFORM_T
%token ENCRYPTION_ALGORITHM CIPHER_T
%token HASH_ALGORITHM HASH_T
%token AUTHENTICATION_METHOD PRE_SHARED_KEY RSA DSS
%token DH_GROUP PFS_GROUP DH_GROUP_T
%token NONCE_SIZE
%token LIFETIME SECOND KB
%token ENCRYPTION_MODE ENC_MODE_T
%token AUTHENTICATION_ALGORITHM AUTH_T

	/* post-command */
%token POST_COMMAND
%token EXEC_PATH EXEC_COMMAND EXEC_SUCCESS EXEC_FAILURE

	/* filter */
%token FILTER DEFAULT
%token ALLOW DENY

%token SWITCH DECSTRING HEXSTRING QUOTEDSTRING HOSTNAME STRING

%type <num> LOGLEV DECSTRING SWITCH
%type <num> EXCHANGE_T DOI_T HASH_T DH_GROUP_T ENC_MODE_T AUTH_T PROTOCOL_T
%type <num> SITUATION_T TRANSFORM_T CIPHER_T
%type <num> ike_port port passive_port
%type <num> ID_IPV4_ADDR ID_IPV6_ADDR idtype_string FQDN USER_FQDN
%type <val> QUOTEDSTRING HEXSTRING STRING address
%type <res> ike_addrinfo_port addrinfo_port addrinfo

%%

statements:
		/* empty */
	|	statements statement
	;

statement:
		logging_statement
	|	padding_statement
	|	listen_statement
	|	remote_statement
	|	filter_statement
	;

	/* logging */
logging_statement:
		LOGGING log_specs EOS
	;

log_specs:
		/* empty */
	|	log_specs HEXSTRING
		{
			if (!f_debug)
				debug |= (u_long)hexstr2val($2.v, $2.l);
		}
	|	log_specs LOGLEV
		{
			if (!f_debug)
				debug |= $2;
		}
	;

	/* padding */
padding_statement:
	 	PADDING BOC padding_stmts EOC
	|	PADDING padding_stmt
	;

padding_stmts:
		/* empty */
	|	padding_stmts padding_stmt
	;

padding_stmt:
		MAX_LENGTH DECSTRING EOS { isakmp_random_padding = $2; }
	|	RANDOM_LENGTH SWITCH EOS { isakmp_random_padsize = $2; }
	|	CHECK_LENGTH SWITCH EOS { isakmp_check_padding = $2; }
	|	EXCL_LASTONE SWITCH EOS { isakmp_pad_exclone = $2; }
	;

	/* listen */
listen_statement:
		LISTEN BOC listen_stmts EOC
	;

listen_stmts:
		/* empty */
	|	listen_stmts listen_stmt
	;

listen_stmt:
		X_ISAKMP ike_addrinfo_port EOS
		{
			struct myaddrs *p;

			p = CALLOC(sizeof(*p), struct myaddrs *);
			if (!p) {
				yyerror("calloc: %s", strerror(errno));
				return -1;
			}
			p->addr = CALLOC($2->ai_addrlen, struct sockaddr *);
			if (!p->addr) {
				yyerror("calloc: %s", strerror(errno));
				return -1;
			}
			memcpy(p->addr, $2->ai_addr, $2->ai_addrlen);
			p->next = myaddrs;
			myaddrs = p;

			autoaddr = 0;
		}
	|	X_ADMIN DECSTRING EOS
		{
			port_admin = $2;
		}
	;

addrinfo
	:	address
		{
			$$ = parse_addr($1.v, NULL, AI_NUMERICHOST);
			if (!$$)
				return -1;
		}

addrinfo_port
	:	address passive_port
		{
			char portbuf[10];

			snprintf(portbuf, sizeof(portbuf), "%ld", $2);
			$$ = parse_addr($1.v, portbuf, AI_NUMERICHOST);
			if (!$$)
				return -1;
		}
	;

ike_addrinfo_port
	:	address ike_port
		{
			char portbuf[10];

			snprintf(portbuf, sizeof(portbuf), "%ld", $2);
			$$ = parse_addr($1.v, portbuf, AI_NUMERICHOST);
			if (!$$)
				return -1;
		}
	;

address :	STRING		{ $$ = $1; }
	;

	/* remote */
remote_statement:
		REMOTE remote_spec BOC remote_stmts EOC
	;

remote_spec:
		ANONYMOUS ike_port
		{
			YIPSDP(PLOG("*** remote anonymous ***\n"));
			cftab.remote = CALLOC(sizeof(struct sockaddr_storage),
				struct sockaddr *);
			memset(cftab.remote, 0, sizeof(struct sockaddr_storage));

			cftab.remote->sa_len = sizeof(struct sockaddr_in);
			cftab.remote->sa_family = af;
			_INPORTBYSA(cftab.remote)= htons($2);

			cfp = &cftab;
		}
	|	ike_addrinfo_port
		{
			struct isakmp_conf *new;

			YIPSDP(PLOG("*** remote %s ***\n", yylval.val.v));
			if ((new = CALLOC(sizeof(struct isakmp_conf),
			                  struct isakmp_conf *)) == 0) {
				yyerror("calloc: %s", strerror(errno));
				return(-1);
			}

			new->remote = CALLOC($1->ai_addrlen, struct sockaddr *);
			if (!new->remote) {
				yyerror("calloc: %s", strerror(errno));
				return -1;
			}
			memcpy(new->remote, $1->ai_addr, $1->ai_addrlen);

			new->next = cftab.next;
			cftab.next = new;

			cfp = new;
		}
	;

ike_port
	:	/* nothing */	{ $$ = PORT_ISAKMP; }
	|	port		{ $$ = $1; }
	;

passive_port
	:	/* nothing */	{ $$ = 0; }
	|	port		{ $$ = $1; }
	;

port	:	PORT DECSTRING	{ $$ = $2; }

remote_stmts:
		/* empty */
	|	remote_stmts remote_stmt
	;

remote_stmt:
		PHASE DECSTRING
		{
			switch ($2) {
			case 1:
			case 2:
				cf_ph = $2 - 1;
				break;
			default:
				yyerror("invalid phase number %d", $2);
				return(-1);
			}

			if ((cfp->ph[cf_ph] = CALLOC(sizeof(struct isakmp_cf_phase),
			                 struct isakmp_cf_phase *)) == 0) {
				yyerror("calloc: %s", strerror(errno));
				return(-1);
			}

			cur_sap = &cfp->ph[cf_ph]->sa;
			cur_pp = cur_sap->p;

			YIPSDP(PLOG("*** phase %ld allocated ***\n", $2));
		}
		BOC phase_stmts EOC
	|	TRY_TO_SEND DECSTRING EOS
		{
			isakmp_try = $2;
			pfkey_set_acquire_time(isakmp_try * isakmp_timer);
		}
	|	SEND_TIMER DECSTRING EOS
		{
			isakmp_timer = $2;
			pfkey_set_acquire_time(isakmp_try * isakmp_timer);
		}
	|	NEED PFS EOS
		{
			yywarn("warning: \"need PFS\" is obsolete (ignored)");
		}
	|	VENDOR_ID QUOTEDSTRING EOS
		{
			if (!(cfp->vendorid = vdup(&$2))) {
				yyerror("vdup: %s", strerror(errno));
				return(-1);
			}
		}
	|	POST_COMMAND BOC post_commands EOC
	;

phase_stmts:
		/* empty */
	|	phase_stmts phase_stmt
	;

phase_stmt:
		EXCHANGE_MODE EXCHANGE_T EOS
		{
			cfp->ph[cf_ph]->etype = $2;
		}
	|	DOI DOI_T EOS
		{
			cur_sap->doi = htonl($2);
		}
	|	SITUATION SITUATION_T EOS
		{
			cur_sap->sit = htonl($2);
		}
	|	id_statement
	|	PROPOSAL DECSTRING PROTOCOL_T
		{
			struct isakmp_cf_p **p;

			if (cur_sap->p == 0)
				p = &cur_sap->p;
			else
				p = &cur_pp->next;

			if ((*p = CALLOC(sizeof(struct isakmp_cf_p),
			                 struct isakmp_cf_p *)) == 0) {
				yyerror("calloc: %s", strerror(errno));
				return(-1);
			}

			(*p)->p_no = $2;
			cur_pp = (*p);

			YIPSDP(PLOG("*** proposal %ld allocated ***\n", $2));

			cur_pp->proto_id = $3;
		}
		BOC transform_stmts EOC
	|	PFS_GROUP DH_GROUP_T EOS
		{
			if ($2 < sizeof(dhgroup) / sizeof(dhgroup[0])
			 && dhgroup[$2].type) {
				cfp->ph[cf_ph]->pfsgroup = $2;
				cfp->ph[cf_ph]->pfsdh = &dhgroup[$2];
			} else
				yyerror("invalid pfs group %d", $2);
		}
	;

id_statement:
		ID_TYPE ID_IPV4_ADDR addrinfo_port EOS
		{
			struct sockaddr_in *sin;
			int tlen;
			caddr_t bp;

			if ($3->ai_family != AF_INET) {
				yyerror("non IPv4 address specified with \"ipv4_address\"\n");
				goto id_v4a_skip;
			}
			sin = (struct sockaddr_in *)$3->ai_addr;

			tlen = IDVHLEN + sizeof(sin->sin_addr);
			if ((cfp->ph[cf_ph]->id_b = vmalloc(tlen)) == 0) {
				yyerror("vmalloc: %s", strerror(errno));
				return(-1);
			}
			bp = cfp->ph[cf_ph]->id_b->v;

			bp[0] = IPSECDOI_ID_IPV4_ADDR;
			if (sin->sin_port) {
				bp[1] = IPPROTO_UDP;
				*(u_int16_t *)&bp[2] = htons(sin->sin_port);
			} else {
				bp[1] = 0;
				*(u_int16_t *)&bp[2] = 0;
			}

			memcpy(bp + IDVHLEN, &sin->sin_addr,
				sizeof(sin->sin_addr));
		id_v4a_skip:;
		}
	|	ID_TYPE ID_IPV6_ADDR addrinfo_port EOS
		{
#ifdef INET6
			struct sockaddr_in6 *sin6;
			int tlen;
			caddr_t bp;

			if ($3->ai_family != AF_INET6) {
				yyerror("non IPv6 address specified with \"ipv6_address\"\n");
				goto id_v6a_skip;
			}
			sin6 = (struct sockaddr_in6 *)$3->ai_addr;

			tlen = IDVHLEN + sizeof(sin6->sin6_addr);
			if ((cfp->ph[cf_ph]->id_b = vmalloc(tlen)) == 0) {
				yyerror("vmalloc: %s", strerror(errno));
				return(-1);
			}
			bp = cfp->ph[cf_ph]->id_b->v;

			bp[0] = IPSECDOI_ID_IPV6_ADDR;
			if (sin6->sin6_port) {
				bp[1] = IPPROTO_UDP;
				*(u_int16_t *)&bp[2] = htons(sin6->sin6_port);
			} else {
				bp[1] = 0;
				*(u_int16_t *)&bp[2] = 0;
			}

			memcpy(bp + IDVHLEN, &sin6->sin6_addr,
				sizeof(sin6->sin6_addr));
		id_v6a_skip:;
#else
			yyerror("\"ipv6_address\" not supported in this configuration");
#endif /*INET6*/
		}
	|	ID_TYPE idtype_string QUOTEDSTRING EOS
		{
			int tlen;
			int idlen = $3.l;
			caddr_t bp;

			tlen = IDVHLEN + idlen;
			if ((cfp->ph[cf_ph]->id_b = vmalloc(tlen)) == 0) {
				yyerror("vmalloc: %s", strerror(errno));
				return(-1);
			}
			bp = cfp->ph[cf_ph]->id_b->v;

			bp[0] = $2;
			bp[1] = 0; /* XXX */
			*(u_int16_t *)&bp[2] = 0; /* XXX */

			memcpy(bp + IDVHLEN, $3.v, idlen);
		}
	;

idtype_string
	:	FQDN		{ $$ = $1; }
	|	USER_FQDN	{ $$ = $1; }
	;

transform_stmts:
		/* empty */
	|	transform_stmts transform_stmt
	;

transform_stmt:
		TRANSFORM DECSTRING TRANSFORM_T
		{
			struct isakmp_cf_t **t;

			if (cur_pp->t == 0)
				t = &cur_pp->t;
			else
				t = &cur_tp->next;

			if ((*t = CALLOC(sizeof(struct isakmp_cf_t),
			                 struct isakmp_cf_t *)) == 0) {
				yyerror("calloc: %s", strerror(errno));
				return(-1);
			}

			(*t)->t_no = $2;
			cur_tp = (*t);
			cur_pp->num_t++;

			YIPSDP(PLOG("*** transform %ld allocated ***\n", $2));

			cur_tp->t_id = $3;
		}
		BOC transform_attributes EOC
		{
			struct isakmp_data *p, *ep;
			int attrseen[16];	/*magic number*/
			int attr;

			memset(attrseen, 0, sizeof(attrseen));
			/* add DH group desc if phase 2 PFS is necessary */
			switch (cf_ph) {
			case 0:
				if (cfp->ph[cf_ph]->etype == ISAKMP_ETYPE_AGG
				 && cfp->ph[cf_ph]->pfsgroup) {
					cf_setdata_l(OAKLEY_ATTR_GRP_DESC,
						cfp->ph[cf_ph]->pfsgroup);
				}
				break;
			case 1:
				if (cfp->ph[cf_ph]->pfsgroup) {
					cf_setdata_l(IPSECDOI_ATTR_GRP_DESC,
						cfp->ph[cf_ph]->pfsgroup);
				}
				break;
			}

			/* sanity checks on cur_tp */
			p = (struct isakmp_data *)cur_tp->data->v;
			ep = (struct isakmp_data *)
				(cur_tp->data->v + cur_tp->data->l);
			while (p < ep) {
				attr = ntohs(p->type) & ~ISAKMP_GEN_MASK;
				if (attr < sizeof(attrseen)/sizeof(attrseen[0]))
					attrseen[attr]++;

				if (ntohs(p->type) & ISAKMP_GEN_MASK)
					p++;
				else {
					p = (struct isakmp_data *)
						((caddr_t)(p + 1) + ntohs(p->lorv));
				}
			}

			switch (cf_ph) {
			case 0:
				if (!attrseen[OAKLEY_ATTR_ENC_ALG]) {
					yyerror("\"encryption_algorithm\" must always be present in phase 1 transform");
				}
				if (!attrseen[OAKLEY_ATTR_HASH_ALG]) {
					yyerror("\"hash_algorithm\" must always be present in phase 1 transform");
				}
				if (!attrseen[OAKLEY_ATTR_AUTH_METHOD]) {
					yyerror("\"authentication_method\" must always be present in phase 1 transform");
				}
				if (!attrseen[OAKLEY_ATTR_GRP_DESC]) {
					yyerror("\"dh_group\" must always be present in phase 1 transform");
				}
				break;
			case 1:
				if (cur_pp->proto_id == IPSECDOI_PROTO_IPSEC_AH
				 && !attrseen[IPSECDOI_ATTR_AUTH]) {
					yyerror("\"authentication_algorithm\" must always be present in AH transform");
				}
				break;
			}
		}
	;

transform_attributes:
		/* empty */
	|	transform_attributes transform_attribute
	;

transform_attribute:
		LIFETIME HEXSTRING life_t EOS
		{
			caddr_t value = hexstr2val($2.v, $2.l);

			cf_setdata_v((cf_ph == 1 ? IPSECDOI_ATTR_SA_LD
						 : OAKLEY_ATTR_SA_LD),
					value, $2.l);
		}
	|	LIFETIME DECSTRING life_t EOS
		{
			u_int32_t i = htonl($2);
			cf_setdata_v((cf_ph == 1 ? IPSECDOI_ATTR_SA_LD
						 : OAKLEY_ATTR_SA_LD),
					(caddr_t)&i, sizeof(u_int32_t));
		}
	|	ENCRYPTION_ALGORITHM CIPHER_T EOS
		{
			if (cf_ph == 0) {
				if ($2)
					cf_setdata_l(OAKLEY_ATTR_ENC_ALG, $2);
			} else
				yyerror("\"encryption_algorithm\" is not valid in phase %d", cf_ph + 1);
		}
	|	ENCRYPTION_ALGORITHM CIPHER_T DECSTRING EOS
		{
			if (cf_ph == 0) {
				if ($2)
					cf_setdata_l(OAKLEY_ATTR_ENC_ALG, $2);
				switch ($2) {
				case OAKLEY_ATTR_ENC_ALG_BLOWFISH:
				case OAKLEY_ATTR_ENC_ALG_RC5:
				case OAKLEY_ATTR_ENC_ALG_CAST:
					if ($3 % 8 != 0)
						yyerror("key length %d is not multiple of 8", $3);
					else if ($3)
						cf_setdata_l(OAKLEY_ATTR_KEY_LEN, $2);
					break;
				default:
					if ($3)
						yyerror("key length is invalid for algorithm %d", $2);
					break;
				}
			} else
				yyerror("\"encryption_algorithm\" is not valid in phase %d", cf_ph + 1);
		}
	|	HASH_ALGORITHM HASH_T EOS
		{
			if (cf_ph == 0) {
				if ($2)
					cf_setdata_l(OAKLEY_ATTR_HASH_ALG, $2);
			} else 
				yyerror("\"hash_algorithm\" is not valid in phase %d", cf_ph + 1);
		}
	|	AUTHENTICATION_METHOD auth_method EOS
		{
			if (cf_ph != 0)
				yyerror("\"authentication_method\" is not valid in phase %d", cf_ph + 1);
		}
	|	DH_GROUP DH_GROUP_T EOS
		{
			if (cf_ph == 0) {
				if (cfp->ph[cf_ph]->etype == ISAKMP_ETYPE_AGG) {
					if (cfp->ph[cf_ph]->pfsgroup == 0) {
						yyerror(
"no \"pfs_group\" specified for phase %d aggressive mode",
						cf_ph + 1);
					} else if ($2 != cfp->ph[cf_ph]->pfsgroup) {
						yyerror(
"\"dh_group\" mismatch with \"pfs_group\" in phase %d aggressive mode",
						cf_ph + 1);
					}
					/* do not add one here */
				} else {
					if ($2)
						cf_setdata_l(OAKLEY_ATTR_GRP_DESC, $2);
				}
			} else
				yyerror("\"dh_group\" is not valid in phase %d", cf_ph + 1);
		}
	|	NONCE_SIZE DECSTRING EOS
	|	ENCRYPTION_MODE ENC_MODE_T EOS
		{
			yywarn("warning: \"encryption_mode\" is obsolete (ignored)");
		}
	|	AUTHENTICATION_ALGORITHM AUTH_T EOS
		{
			if (cf_ph != 1) {
				yyerror("\"authentication_algorithm\" is not valid in phase %d", cf_ph + 1);
				goto auth_skip;
			}
			if (cur_pp->proto_id == IPSECDOI_PROTO_IPSEC_AH) {
				if ((cur_tp->t_id == IPSECDOI_AH_MD5
				  && $2 == IPSECDOI_ATTR_AUTH_HMAC_MD5)
				 || (cur_tp->t_id == IPSECDOI_AH_SHA
				  && $2 == IPSECDOI_ATTR_AUTH_HMAC_SHA1))
					;
				else
					yyerror("transform type mismatches with hash algorithm");
			}

			if ($2)
				cf_setdata_l(IPSECDOI_ATTR_AUTH, $2);
		auth_skip:;
		}
	;

life_t:
		SECOND
		{
			if (cf_ph == 0) {
				cf_setdata_l(OAKLEY_ATTR_SA_LD_TYPE,
					   OAKLEY_ATTR_SA_LD_TYPE_SEC);
			} else {
				cf_setdata_l(IPSECDOI_ATTR_SA_LD_TYPE,
					IPSECDOI_ATTR_SA_LD_TYPE_SEC);
			}
		}
	|	KB
		{
			if (cf_ph == 0) {
				yywarn("warning: \"KB\" lifetime in phase 2 "
					"is not suppoted (ignored)");
				cf_setdata_l(OAKLEY_ATTR_SA_LD_TYPE,
					   OAKLEY_ATTR_SA_LD_TYPE_KB);
			} else {
				cf_setdata_l(IPSECDOI_ATTR_SA_LD_TYPE,
					IPSECDOI_ATTR_SA_LD_TYPE_KB);
			}
		}
	;

auth_method:
		PRE_SHARED_KEY QUOTEDSTRING
		{
			cf_setdata_l(OAKLEY_ATTR_AUTH_METHOD,
			              OAKLEY_ATTR_AUTH_METHOD_PSKEY);

			if (!(cfp->ph[cf_ph]->pskey = vdup(&$2))) {
				yyerror("vdup: %s", strerror(errno));
				return(-1);
			}
		}
	|	RSA	{ yyerror("RSA authentication isn't supported"); }
	|	DSS	{ yyerror("DSS authentication isn't supported"); }
	;

	/* post-command */
post_commands:
		/* empty */
	|	post_commands post_cmd
	;

post_cmd:
		EXEC_PATH QUOTEDSTRING EOS
		{
			cfp->exec_path = strdup($2.v);
		}
	|	EXEC_COMMAND QUOTEDSTRING EOS
		{
			cfp->exec_command = strdup($2.v);
		}
	|	EXEC_SUCCESS QUOTEDSTRING EOS
		{
			cfp->exec_success = strdup($2.v);
		}
	|	EXEC_FAILURE QUOTEDSTRING EOS
		{
			cfp->exec_failure = strdup($2.v);
		}
	;

	/* filter */
filter_statement:
		FILTER BOC filter_stmts EOC
	;

filter_stmts:
		/* empty */
	|	filter_stmts filter_stmt
	;

filter_stmt:
		DEFAULT filter_rule EOS
	|	filter_rule BOC address_patterns EOC
	;

filter_rule:
		ALLOW
	|	DENY
	;

address_patterns:
		/* empty */
	|	address_patterns address_pattern
	;

address_pattern:
		addrinfo EOS
	|	addrinfo DECSTRING EOS
	|	addrinfo "/" DECSTRING DECSTRING EOS
	|	addrinfo "/" DECSTRING EOS
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
	if (error) {
		yyerror("getaddrinfo(%s%s%s): %s",
			host, port ? "," : "", port ? port : "",
			gai_strerror(error));
		return NULL;
	}
	if (res->ai_next) {
		yyerror("getaddrinfo(%s%s%s): "
			"resolved to multiple address, "
			"taking the first one",
			host, port ? "," : "", port ? port : "");
	}
	return res;
}

static int
cf_setdata_v(type, value, len)
	int type, len;
	caddr_t value;
{
	int oldlen, tlen;

	if (cur_tp->data == 0)
		oldlen = 0;
	else
		oldlen = cur_tp->data->l;

	tlen = oldlen + sizeof(struct isakmp_data) + len;

	if (VREALLOC(cur_tp->data, tlen) == 0) {
		yyerror("vrealloc: %s", strerror(errno));
		return(-1);
	}

	isakmp_set_attr_v(cur_tp->data->v + oldlen, type, value, len);

	return 0;
}

static int cf_setdata_l(int type, u_int32_t lorv)
{
	int oldlen;

	if (cur_tp->data == 0)
		oldlen = 0;
	else
		oldlen = cur_tp->data->l;

	if (VREALLOC(cur_tp->data, oldlen + sizeof(struct isakmp_data)) == NULL) {
		yyerror("vrealloc: %s", strerror(errno));
		return(-1);
	}

	isakmp_set_attr_l(cur_tp->data->v + oldlen, type, lorv);

	return 0;
}

int cf_post_config(void)
{
	struct isakmp_conf *p;
	struct isakmp_cf_sa *cf_sa;
	struct isakmp_cf_p *cf_p;
	struct isakmp_cf_t *cf_t;
	u_int32_t cf_sa_len, cf_p_len;
	int i;

#if 0 /* We try to allow the case ther is no anonymous directive. */
	/* anonymous configuration is required */
	if (!cftab.ph[0] || !cftab.ph[1]) {
		yyerror("\"remote anonymous\" required");
		return -1;
	}
#endif

	if (!cftab.ph[0] || !cftab.ph[1])
		p = cftab.next;
	else
		p = &cftab;

	for (/*nothing*/; p ; p = p->next) {
		for (i = 0; i < 2; i++) {
			cf_sa = &p->ph[i]->sa;
			cf_sa_len = 0;

			/* modifing proposal payload */
			for (cf_p = cf_sa->p; cf_p; cf_p = cf_p->next) {
				cf_p_len = 0;

				/* modifing transform payload */
				for (cf_t = cf_p->t; cf_t; cf_t = cf_t->next) {
					cf_t->len = sizeof(struct isakmp_pl_t)
					    + (cf_t->data ? cf_t->data->l : 0);
					cf_p_len += cf_t->len;
				}
				cf_p->len = sizeof(struct isakmp_pl_p)
					+ ((cf_p->proto_id == IPSECDOI_PROTO_ISAKMP) ? 0 : 4)
					+ cf_p_len;
				cf_sa_len += cf_p->len;
			}
			cf_sa->len = sizeof(struct isakmp_pl_sa) + cf_sa_len;
		}

		/* special check for aggressive mode - need pfs_group */
		if (p->ph[0]->etype == ISAKMP_ETYPE_AGG) {
			if (!p->ph[0]->pfsgroup) {
				yyerror("\"pfs_group\" required for phase 1 aggressive mode");
				return -1;
			}
		}
	}

	return 0;
}

void
cf_init()
{
	memset((caddr_t)&cftab, 0, sizeof(cftab));
	return;
}

int
re_cfparse()
{
	struct isakmp_conf *p, *q;
	int i;

	/* clean it up */
	for (p = &cftab; p; p = q) {
		q = p->next;
		p->next = NULL;

		if (p->remote)
			free(p->remote);
		for (i = 0; i < sizeof(p->ph)/sizeof(p->ph[0]); i++) {
			if (p->ph[i]->id_b)
				vfree(p->ph[i]->id_b);
			if (p->ph[i]->pskey)
				vfree(p->ph[i]->pskey);
			if (p->ph[i]->pfsdh)
				p->ph[i]->pfsdh = NULL;
		}
		if (p->vendorid)
			vfree(p->vendorid);
		if (p->exec_path)
			free(p->exec_path);
		if (p->exec_command)
			free(p->exec_command);
		if (p->exec_success)
			free(p->exec_success);
		if (p->exec_failure)
			free(p->exec_failure);
		if (p != &cftab)
			free(p);
	}
	memset((caddr_t)&cftab, 0, sizeof(cftab));
	cfp = NULL;

	reparse = 1;
	return(cfparse());
}

