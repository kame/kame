%{
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet6/ipsec.h>
#ifndef IPV6_INRIA_VERSION
#include <netinet6/in6.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"

#include "algorithm.h"
#include "cfparse.h"
#include "cftoken.h"
#include "localconf.h"
#include "oakley.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "y.tab.h"

int yyerrorcount = 0;

#if defined(YIPS_DEBUG)
#  define YYDB                                                                 \
	YIPSDEBUG(DEBUG_CONF,                                                  \
		printf("begin <%d>%s\n",                                       \
		yy_start, yytext));
#  define YYD {                                                                \
	YIPSDEBUG(DEBUG_CONF, printf("<%d>", yy_start);                        \
		ECHO ;                                                         \
		printf("\n"));                                                 \
	}
#else
#  define YYDB
#  define YYD
#endif /* defined(YIPS_DEBUG) */

#define MAX_INCLUDE_DEPTH 10

static struct include_stack {
	char *path;
	FILE *fp;
	YY_BUFFER_STATE state;
	int lineno;
} incstack[MAX_INCLUDE_DEPTH];
static int incstackp = 0;

static int yy_first_time = 1;

static int yycf_count_nl __P((char *p));
%}

/* common seciton */
nl		\n
ws		[ \t]+
digit		[0-9]
letter		[A-Za-z]
hexdigit	[0-9A-Fa-f]
/*octet		(([01]?{digit}?{digit})|((2([0-4]{digit}))|(25[0-5]))) */
special		[()+\|\?\*]
comma		,
dot		\.
slash		\/
bcl		\{
ecl		\}
blcl		\[
elcl		\]
percent		\%
semi		\;
comment		\#.*
ccomment	"/*"
bracketstring	\<[^>]*\>
quotedstring	\"[^"]*\"
addrstring	[a-fA-F0-9:][a-fA-F0-9:\.]*
protectedstring	[a-fA-F0-9:\._][a-fA-F0-9:\._]*
decstring	{digit}+
hexstring	0[xX]({hexdigit}{hexdigit})+
octetstring	{octet}({dot}{octet})+

%s S_INI S_PTH S_INF S_LOG S_PAD S_LST S_RTRY
%s S_ALGST S_ALGCL S_PLCY S_PLCYS S_PLCYP S_PLCYT
%s S_RMT S_RMTS S_RMTP
%s S_SA

%%
%{
	if (yy_first_time) {
		BEGIN S_INI;
		yy_first_time = 0;
	}
%}

	/* path */
<S_INI>path		{ BEGIN S_PTH; YYDB; return(PATH); }
<S_PTH>include		{ YYD; yylval.num = CF_PATHTYPE_INCLUDE;
				return(PATHTYPE); }
<S_PTH>pre_shared_key	{ YYD; yylval.num = CF_PATHTYPE_PSK;
				return(PATHTYPE); }
<S_PTH>certificate	{ YYD; yylval.num = CF_PATHTYPE_CERT;
				return(PATHTYPE); }
<S_PTH>{semi}		{ BEGIN S_INI; YYDB; return(EOS); }

	/* include */
<S_INI>include		{ YYDB; return(INCLUDE); }

	/* self information */
<S_INI>identifier	{ BEGIN S_INF; YYDB; return(IDENTIFIER); }
<S_INF>{semi}		{ BEGIN S_INI; return(EOS); }

	/* logging */
<S_INI>log		{ BEGIN S_LOG; YYDB; return(LOGGING); }
<S_LOG>info		{ YYD; yylval.num = 0x00000032; return(LOGLEV); }
<S_LOG>notify		{ YYD; yylval.num = 0x00000076; return(LOGLEV); }
<S_LOG>debug		{ YYD; yylval.num = 0x0fffffff; return(LOGLEV); }
<S_LOG>debug2		{ YYD; yylval.num = 0x1fffffff; return(LOGLEV); }
<S_LOG>debug3		{ YYD; yylval.num = 0x3fffffff; return(LOGLEV); }
<S_LOG>debug4		{ YYD; yylval.num = 0xffffffff; return(LOGLEV); }
<S_LOG>{semi}		{ BEGIN S_INI; return(EOS); }

	/* padding */
<S_INI>padding		{ BEGIN S_PAD; YYDB; return(PADDING); }
<S_PAD>{bcl}		{ return(BOC); }
<S_PAD>maximum_length	{ YYD; return(PAD_MAXLEN); }
<S_PAD>randomize	{ YYD; return(PAD_RANDOMIZE); }
<S_PAD>restrict_check	{ YYD; return(PAD_RESTRICT); }
<S_PAD>exclusive_tail	{ YYD; return(PAD_EXCLTAIL); }
<S_PAD>{ecl}		{ BEGIN S_INI; return(EOC); }

	/* listen */
<S_INI>listen		{ BEGIN S_LST; YYDB; return(LISTEN); }
<S_LST>{bcl}		{ return(BOC); }
<S_LST>isakmp		{ YYD; return(X_ISAKMP); }
<S_LST>admin		{ YYD; return(X_ADMIN); }
<S_LST>{ecl}		{ BEGIN S_INI; return(EOC); }

	/* timer */
<S_INI>timer		{ BEGIN S_RTRY; YYDB; return(RETRY); }
<S_RTRY>{bcl}		{ return(BOC); }
<S_RTRY>counter		{ YYD; return(RETRY_COUNTER); }
<S_RTRY>interval	{ YYD; return(RETRY_INTERVAL); }
<S_RTRY>persend		{ YYD; return(RETRY_PERSEND); }
<S_RTRY>phase1		{ YYD; return(RETRY_PHASE1); }
<S_RTRY>phase2		{ YYD; return(RETRY_PHASE2); }
<S_RTRY>{ecl}		{ BEGIN S_INI; return(EOC); }

	/* algorithm_level */
<S_INI>algorithm_strength	{ BEGIN S_ALGST; YYDB; return(ALGORITHM_LEVEL); }
<S_ALGST>{bcl}			{ return(BOC); }
<S_ALGST>isakmp_encryption	{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_isakmp_enc; return(ALGORITHM_CLASS); }
<S_ALGST>isakmp_hash		{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_isakmp_hash; return(ALGORITHM_CLASS); }
<S_ALGST>isakmp_dh_group	{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_isakmp_dh; return(ALGORITHM_CLASS); }
<S_ALGST>isakmp_auth_method	{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_isakmp_ameth; return(ALGORITHM_CLASS); }
<S_ALGST>ipsec_encryption	{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_ipsec_enc; return(ALGORITHM_CLASS); }
<S_ALGST>ipsec_authentication	{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_ipsec_auth; return(ALGORITHM_CLASS); }
<S_ALGST>ipsec_ipcomp		{ BEGIN S_ALGCL; YYDB; yylval.num = algclass_ipsec_comp; return(ALGORITHM_CLASS); }
<S_ALGST>{ecl}		{ BEGIN S_INI; return(EOC); }
<S_ALGCL>{bcl}		{ return(BOC); }
<S_ALGCL>extra_high	{ YYD; yylval.num = algstrength_ehigh; return(STRENGTHTYPE); }
<S_ALGCL>high		{ YYD; yylval.num = algstrength_high; return(STRENGTHTYPE); }
<S_ALGCL>normal		{ YYD; yylval.num = algstrength_normal; return(STRENGTHTYPE); }
<S_ALGCL>nothing	{ YYD; yylval.num = algtype_nothing; return(ALGORITHMTYPE); }
<S_ALGCL>{comma}	{ /* XXX ignored, but to be handled. */ ; }
<S_ALGCL>{ecl}		{ BEGIN S_ALGST; return(EOC); }

	/* policy */
<S_INI>policy		{ BEGIN S_PLCY; YYDB; return(POLICY); }
<S_PLCY>any		{ YYD; return(ANY); }
<S_PLCY>{bcl}any{ecl}	{ YYD; return(PORTANY); }
<S_PLCY>in		{ YYD; yylval.num = IPSEC_DIR_INBOUND; return(DIRTYPE); }
<S_PLCY>out		{ YYD; yylval.num = IPSEC_DIR_OUTBOUND; return(DIRTYPE); }
<S_PLCY>inout		{ YYD; /* XXX */ yylval.num = IPSEC_DIR_ANY; return(DIRTYPE); }
<S_PLCY>discard		{ YYD; yylval.num = IPSEC_POLICY_DISCARD; return(ACTION); }
<S_PLCY>none		{ YYD; yylval.num = IPSEC_POLICY_NONE; return(ACTION); }
<S_PLCY>ipsec		{ YYD; yylval.num = IPSEC_POLICY_IPSEC; return(ACTION); }
	/* policy spec */
<S_PLCY>{bcl}		{ BEGIN S_PLCYS; return(BOC); }
<S_PLCY>{semi}		{ BEGIN S_INI; return(EOS); }
<S_PLCYS>{ecl}		{ BEGIN S_INI; return(EOC); }
<S_PLCYS>pfs_group	{ YYD; return(PFS_GROUP); }
	/* policy proposal */
<S_PLCYS>proposal	{ BEGIN S_PLCYP; YYDB; return(PROPOSAL); }
<S_PLCYP>{bcl}		{ return(BOC); }
<S_PLCYP>{ecl}		{ BEGIN S_PLCYS; return(EOC); }
<S_PLCYP>lifetime	{ YYD; return(LIFETIME); }
<S_PLCYP>time		{ YYD; yylval.num = CF_LIFETYPE_TIME; return(LIFETYPE); }
<S_PLCYP>byte		{ YYD; yylval.num = CF_LIFETYPE_BYTE; return(LIFETYPE); }
	/* policy protocol */
<S_PLCYP>protocol	{ BEGIN S_PLCYT; YYDB; return(PROTOCOL); }
<S_PLCYT>{bcl}		{ return(BOC); }
<S_PLCYT>{ecl}		{ BEGIN S_PLCYP; return(EOC); }
<S_PLCYT>level		{ YYD; return(SECLEVEL); }
<S_PLCYT>require	{ YYD; yylval.num = IPSEC_LEVEL_REQUIRE; return(SECLEVELTYPE); }
<S_PLCYT>use		{ YYD; yylval.num = IPSEC_LEVEL_USE; return(SECLEVELTYPE); }
<S_PLCYT>default	{ YYD; yylval.num = IPSEC_LEVEL_DEFAULT; return(SECLEVELTYPE); }
<S_PLCYT>unique		{ YYD; yylval.num = IPSEC_LEVEL_UNIQUE; return(SECLEVELTYPE); }
<S_PLCYT>mode		{ YYD; return(SECMODE); }
<S_PLCYT>tunnel		{ YYD; yylval.num = IPSECDOI_ATTR_ENC_MODE_TUNNEL; return(SECMODETYPE); }
<S_PLCYT>transport	{ YYD; yylval.num = IPSECDOI_ATTR_ENC_MODE_TRNS; return(SECMODETYPE); }
<S_PLCYT>strength	{ YYD; return(STRENGTH); }
<S_PLCYT>extra_high	{ YYD; yylval.num = algstrength_ehigh; return(STRENGTHTYPE); }
<S_PLCYT>high		{ YYD; yylval.num = algstrength_high; return(STRENGTHTYPE); }
<S_PLCYT>normal		{ YYD; yylval.num = algstrength_normal; return(STRENGTHTYPE); }
<S_PLCYT>encryption_algorithm { YYD; yylval.num = algclass_ipsec_enc; return(ALGORITHM_CLASS); }
<S_PLCYT>authentication_algorithm { YYD; yylval.num = algclass_ipsec_auth; return(ALGORITHM_CLASS); }
<S_PLCYT>compression_algorithm	{ YYD; yylval.num = algclass_ipsec_comp; return(ALGORITHM_CLASS); }

	/* remote */
<S_INI>remote		{ BEGIN S_RMT; YYDB; return(REMOTE); }
<S_RMT>anonymous	{ YYD; return(ANONYMOUS); }
	/* remote spec */
<S_RMT>{bcl}		{ BEGIN S_RMTS; return(BOC); }
<S_RMTS>{ecl}		{ BEGIN S_INI; return(EOC); }
<S_RMTS>exchange_mode	{ YYD; return(EXCHANGE_MODE); }
<S_RMTS>{comma}		{ /* XXX ignored, but to be handled. */ ; }
<S_RMTS>base		{ YYD; yylval.num = ISAKMP_ETYPE_BASE; return(EXCHANGETYPE); }
<S_RMTS>main		{ YYD; yylval.num = ISAKMP_ETYPE_IDENT; return(EXCHANGETYPE); }
<S_RMTS>aggressive	{ YYD; yylval.num = ISAKMP_ETYPE_AGG; return(EXCHANGETYPE); }
<S_RMTS>doi		{ YYD; return(DOI); }
<S_RMTS>ipsec_doi	{ YYD; yylval.num = IPSEC_DOI; return(DOITYPE); }
<S_RMTS>situation	{ YYD; return(SITUATION); }
<S_RMTS>identity_only	{ YYD; yylval.num = IPSECDOI_SIT_IDENTITY_ONLY; return(SITUATIONTYPE); }
<S_RMTS>secrecy		{ YYD; yylval.num = IPSECDOI_SIT_SECRECY; return(SITUATIONTYPE); }
<S_RMTS>integrity	{ YYD; yylval.num = IPSECDOI_SIT_INTEGRITY; return(SITUATIONTYPE); }
<S_RMTS>identifier	{ YYD; return(IDENTIFIER); }
<S_RMTS>dh_group	{ YYD; return(DH_GROUP); }
<S_RMTS>nonce_size	{ YYD; return(NONCE_SIZE); }
<S_RMTS>keepalive	{ YYD; return(KEEPALIVE); }
<S_RMTS>lifetime	{ YYD; return(LIFETIME); }
<S_RMTS>time		{ YYD; yylval.num = CF_LIFETYPE_TIME; return(LIFETYPE); }
<S_RMTS>byte		{ YYD; yylval.num = CF_LIFETYPE_BYTE; return(LIFETYPE); }
	/* remote proposal */
<S_RMTS>proposal	{ BEGIN S_RMTP; YYDB; return(PROPOSAL); }
<S_RMTP>{bcl}		{ return(BOC); }
<S_RMTP>{ecl}		{ BEGIN S_RMTS; return(EOC); }
<S_RMTP>lifetime	{ YYD; return(LIFETIME); }
<S_RMTP>time		{ YYD; yylval.num = CF_LIFETYPE_TIME; return(LIFETYPE); }
<S_RMTP>byte		{ YYD; yylval.num = CF_LIFETYPE_BYTE; return(LIFETYPE); }
<S_RMTP>strength	{ YYD; return(STRENGTH); }
<S_RMTP>extra_high	{ YYD; yylval.num = algstrength_ehigh; return(STRENGTHTYPE); }
<S_RMTP>high		{ YYD; yylval.num = algstrength_high; return(STRENGTHTYPE); }
<S_RMTP>normal		{ YYD; yylval.num = algstrength_normal; return(STRENGTHTYPE); }
<S_RMTP>encryption_algorithm { YYD; yylval.num = algclass_isakmp_enc; return(ALGORITHM_CLASS); }
<S_RMTP>authentication_method { YYD; yylval.num = algclass_isakmp_ameth; return(ALGORITHM_CLASS); }
<S_RMTP>hash_algorithm	{ YYD; yylval.num = algclass_isakmp_hash; return(ALGORITHM_CLASS); }
<S_RMTP>dh_group	{ YYD; yylval.num = algclass_isakmp_dh; return(ALGORITHM_CLASS); }

	/* static sa */
<S_INI>static_sa	{ BEGIN S_SA; YYDB; return(STATICSA); }
<S_SA>{semi}		{ YYD; BEGIN S_INI; return(EOS); }
<S_SA>[a-zA-Z0-9:\.\-_/ \n\t\"][a-zA-Z0-9:\.\-_/ \n\t\"]* {
		yymore();

		incstack[incstackp].lineno += yycf_count_nl(yytext);

		yylval.val.l = strlen(yytext);
		yylval.val.v = strdup(yytext);

		return(STATICSA_STATEMENT);
}

	/* parameter */
on		{ YYD; yylval.num = TRUE; return(SWITCH); }
off		{ YYD; yylval.num = FALSE; return(SWITCH); }

	/* prefix */
{slash}{digit}{1,3} {
			YYD;
			yytext++;
			yylval.num = atoi(yytext);
			return(PREFIX);
		}

	/* port number */
{blcl}{decstring}{elcl}	{
			char *p = yytext;
			YYD;
			while (*++p != ']') ;
			*p = NULL;
			yytext++;
			yylval.num = atoi(yytext);
			return(PORT);
		}

	/* upper protocol */
esp		{ YYD; yylval.num = IPPROTO_ESP; return(UL_PROTO); }
ah		{ YYD; yylval.num = IPPROTO_AH; return(UL_PROTO); }
ipcomp		{ YYD; yylval.num = IPPROTO_IPCOMP; return(UL_PROTO); }
icmp		{ YYD; yylval.num = IPPROTO_ICMP; return(UL_PROTO); }
icmp6		{ YYD; yylval.num = IPPROTO_ICMPV6; return(UL_PROTO); }
tcp		{ YYD; yylval.num = IPPROTO_TCP; return(UL_PROTO); }
udp		{ YYD; yylval.num = IPPROTO_UDP; return(UL_PROTO); }

	/* algorithm type */
des_iv64	{ YYD; yylval.num = algtype_des_iv64;	return(ALGORITHMTYPE); }
des		{ YYD; yylval.num = algtype_des;	return(ALGORITHMTYPE); }
3des		{ YYD; yylval.num = algtype_3des;	return(ALGORITHMTYPE); }
rc5		{ YYD; yylval.num = algtype_rc5;	return(ALGORITHMTYPE); }
idea 		{ YYD; yylval.num = algtype_idea;	return(ALGORITHMTYPE); }
cast128		{ YYD; yylval.num = algtype_cast128;	return(ALGORITHMTYPE); }
blowfish	{ YYD; yylval.num = algtype_blowfish;	return(ALGORITHMTYPE); }
3idea		{ YYD; yylval.num = algtype_3idea;	return(ALGORITHMTYPE); }
des_iv32	{ YYD; yylval.num = algtype_des_iv32;	return(ALGORITHMTYPE); }
rc4 		{ YYD; yylval.num = algtype_rc4;	return(ALGORITHMTYPE); }
null_enc	{ YYD; yylval.num = algtype_null_enc;	return(ALGORITHMTYPE); }
non_auth	{ YYD; yylval.num = algtype_non_auth;	return(ALGORITHMTYPE); }
hmac_md5	{ YYD; yylval.num = algtype_hmac_md5;	return(ALGORITHMTYPE); }
hmac_sha1	{ YYD; yylval.num = algtype_hmac_sha1;	return(ALGORITHMTYPE); }
des_mac		{ YYD; yylval.num = algtype_des_mac;	return(ALGORITHMTYPE); }
kpdk		{ YYD; yylval.num = algtype_kpdk;	return(ALGORITHMTYPE); }
md5		{ YYD; yylval.num = algtype_md5;	return(ALGORITHMTYPE); }
sha1		{ YYD; yylval.num = algtype_sha1;	return(ALGORITHMTYPE); }
tiger		{ YYD; yylval.num = algtype_tiger;	return(ALGORITHMTYPE); }
oui		{ YYD; yylval.num = algtype_oui;	return(ALGORITHMTYPE); }
deflate		{ YYD; yylval.num = algtype_deflate;	return(ALGORITHMTYPE); }
lzs		{ YYD; yylval.num = algtype_lzs;	return(ALGORITHMTYPE); }
modp768		{ YYD; yylval.num = algtype_modp768;	return(ALGORITHMTYPE); }
modp1024	{ YYD; yylval.num = algtype_modp1024;	return(ALGORITHMTYPE); }
modp1536	{ YYD; yylval.num = algtype_modp1536;	return(ALGORITHMTYPE); }
ec2n155		{ YYD; yylval.num = algtype_ec2n155;	return(ALGORITHMTYPE); }
ec2n185		{ YYD; yylval.num = algtype_ec2n185;	return(ALGORITHMTYPE); }
pre_shared_key	{ YYD; yylval.num = algtype_psk;	return(ALGORITHMTYPE); }
rsasig		{ YYD; yylval.num = algtype_rsasig;	return(ALGORITHMTYPE); }
dsssig		{ YYD; yylval.num = algtype_dsssig;	return(ALGORITHMTYPE); }
rsaenc		{ YYD; yylval.num = algtype_rsaenc;	return(ALGORITHMTYPE); }
rsarev		{ YYD; yylval.num = algtype_rsarev;	return(ALGORITHMTYPE); }

	/* identifier type */
vendor_id	{ YYD; return(VENDORID); }
user_fqdn	{ YYD; yylval.num = LC_IDENTTYPE_USERFQDN; return(IDENTIFIERTYPE); }
fqdn		{ YYD; yylval.num = LC_IDENTTYPE_FQDN; return(IDENTIFIERTYPE); }
cert		{ YYD; yylval.num = LC_IDENTTYPE_CERT; return(IDENTIFIERTYPE); }
secret		{ YYD; yylval.num = LC_IDENTTYPE_SECRET; return(IDENTIFIERTYPE); }
keyid		{ YYD; yylval.num = LC_IDENTTYPE_KEYID; return(IDENTIFIERTYPE); }
address		{ YYD; yylval.num = LC_IDENTTYPE_ADDRESS; return(IDENTIFIERTYPE); }
	/* units */
B|byte|bytes		{ YYD; yylval.num = CF_UNITTYPE_B; return(UNITTYPE); }
KB			{ YYD; yylval.num = CF_UNITTYPE_KB; return(UNITTYPE); }
MB			{ YYD; yylval.num = CF_UNITTYPE_MB; return(UNITTYPE); }
TB			{ YYD; yylval.num = CF_UNITTYPE_TB; return(UNITTYPE); }
sec|secs|second|seconds	{ YYD; yylval.num = CF_UNITTYPE_S; return(UNITTYPE); }
min|mins|minute|minutes	{ YYD; yylval.num = CF_UNITTYPE_M; return(UNITTYPE); }
hour|hours		{ YYD; yylval.num = CF_UNITTYPE_H; return(UNITTYPE); }

{decstring}	{
			char *bp;

			YYD;
			yylval.num = strtol(yytext, &bp, 10);
			return(NUMBER);
		}

{hexstring}	{
			int len = yyleng - 2; /* (str - "0x") */

			YYD; 

			yylval.val.l = (len & 1) + (len / 2);

			/* fixed string if length is odd. */
			if (len & 1) {
				yytext[1] = '0';
				yylval.val.v = strdup(yytext + 1);
			} else
				yylval.val.v = strdup(yytext + 2);

			return(HEXSTRING);
		}

{quotedstring}	{
			u_char *p = yytext;
			YYD;
			while (*++p != '"') ;
			*p = NULL;
			yytext++;
			yylval.val.l = yyleng-2;
			yylval.val.v = strdup(yytext);
			return(QUOTEDSTRING);
		}

{addrstring}	{
			YYD;
			yylval.val.l = strlen(yytext);
			yylval.val.v = strdup(yytext);
			return(ADDRSTRING);
		}

<<EOF>>		{
			if ( --incstackp < 0 ) {
				yyterminate();
			} else {
				yy_delete_buffer(YY_CURRENT_BUFFER);
				yy_switch_to_buffer(incstack[incstackp].state);
			}
		}

	/* ... */
{ws}		{ ; }
{nl}		{ incstack[incstackp].lineno++; }
{comment}	{ YYD; }
{semi}		{ return(EOS); }
.		{ yymore(); }

%%

static int
yycf_count_nl(p)
	char *p;
{
	int n = 0;

	while (*p != NULL) {
		if (*p == '\n')
			n++;
		p++;
	}

	return n;
}

void
yyerror(char *s, ...)
{
	char fmt[512];

	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	snprintf(fmt, sizeof(fmt), "%d: \"%s\" %s\n",
		incstack[incstackp].lineno, yytext, s);
	plogv(logp, LOCATION, NULL,
		fmt, ap);
	va_end(ap);
	plog(logp, LOCATION, NULL,
		"in %s\n", incstack[incstackp].path);

	yyerrorcount++;
}

void
yywarn(char *s, ...)
{
	char fmt[512];

	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	snprintf(fmt, sizeof(fmt), "%d: \"%s\" %s\n",
		incstack[incstackp].lineno, yytext, s);
	plogv(logp, LOCATION, NULL,
		fmt, ap);
	va_end(ap);
	plog(logp, LOCATION, NULL,
		"in %s\n", incstack[incstackp].path);
}

int
yycf_switch_buffer(path)
	char *path;
{
	/* got the include file name */
	if (incstackp >= MAX_INCLUDE_DEPTH) {
		plog(logp, LOCATION, NULL,
			"Includes nested too deeply");
		return -1;
	}

	incstack[incstackp++].state = YY_CURRENT_BUFFER;

	if (yycf_set_buffer(path) != 0)
		return -1;

	yy_switch_to_buffer(yy_create_buffer(yyin, YY_BUF_SIZE));

	BEGIN(S_INI);

	return 0;
}

int
yycf_set_buffer(path)
	char *path;
{
	yyin = fopen(path, "r");
	if (yyin == NULL) {
		fprintf(stderr, "fialed to open file %s (%s)\n",
			path, strerror(errno));
		plog(logp, LOCATION, NULL,
			"fialed to open file %s (%s)\n",
			path, strerror(errno));
		return -1;
	}

	/* initialize */
	incstack[incstackp].fp = yyin;
	incstack[incstackp].path = strdup(path);
	incstack[incstackp].lineno = 1;

	return 0;
}

void
yycf_init_buffer()
{
	int i;

	for (i = 0; i < MAX_INCLUDE_DEPTH; i++)
		memset(&incstack[i], 0, sizeof(incstack[i]));
	incstackp = 0;
}

void
yycf_clean_buffer()
{
	int i;

	for (i = 0; i < MAX_INCLUDE_DEPTH; i++) {
		if (incstack[i].path != NULL) {
			fclose(incstack[i].fp);
			free(incstack[i].path);
			incstack[i].path = NULL;
		}
	}
}

