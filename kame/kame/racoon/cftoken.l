%{
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef IPV6_INRIA_VERSION
#include <netinet6/in6.h>
#endif

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include "var.h"
#include "vmbuf.h"
#include "y.tab.h"
#include "cfparse.h"
#include "debug.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "misc.h"

int lineno = 1;
int yy_first_time = 1;
static int yyerrorcount = 0;

static void cfdebug_print __P((char *, char *, int));
%}

/* common seciton */
nl		\n
ws		[ \t]+
digit		[0-9]
letter		[A-Za-z]
hexdigit	[0-9A-Fa-f]
/*octet		(([01]?{digit}?{digit})|((2([0-4]{digit}))|(25[0-5]))) */
special		[()+\|\?\*,]
dot		\.
hyphen		\-
colon		\:
slash		\/
bcl		\{
ecl		\}
blcl		\[
elcl		\]
percent		\%
semi		\;
usec		{dot}{digit}{1,6}
comment		\#.*
ccomment	"/*"
bracketstring	\<[^>]*\>
quotedstring	\"[^"]*\"
decstring	{digit}+
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
octetstring	{octet}({dot}{octet})+
keyword		{letter}{letter}+
name		{letter}(({letter}|{digit}|{hyphen})*({letter}|{digit}))*
hostname	{name}(({dot}{name})+{dot}?)?

%s S_CNF S_LOG S_LST S_PAD
%s S_RMT S_RMT_PH S_RMT_P S_RMT_T S_RMT_COM
%s S_FLT S_FLT_DEF S_FLT_A S_FLT_D
%%
%{
	if (yy_first_time) {
		BEGIN S_CNF;
		yy_first_time = 0;
	}
%}

	/* logging */
<S_CNF>log		{ DP("begin logging"); BEGIN S_LOG; return(LOGGING); }
<S_LOG>info		{ YYD_ECHO; yylval.num = 0x00000032; return(LOGLEV); }
<S_LOG>notify		{ YYD_ECHO; yylval.num = 0x00000076; return(LOGLEV); }
<S_LOG>sched		{ YYD_ECHO; yylval.num = 0x20000000; return(LOGLEV); }
<S_LOG>sched2		{ YYD_ECHO; yylval.num = 0x10000000; return(LOGLEV); }
<S_LOG>cipher		{ YYD_ECHO; yylval.num = 0x0f000000; return(LOGLEV); }
<S_LOG>sa		{ YYD_ECHO; yylval.num = 0x00100000; return(LOGLEV); }
<S_LOG>net		{ YYD_ECHO; yylval.num = 0x00020000; return(LOGLEV); }
<S_LOG>misc		{ YYD_ECHO; yylval.num = 0x00000100; return(LOGLEV); }
<S_LOG>all		{ YYD_ECHO; yylval.num = 0xffffffff; return(LOGLEV); }
<S_LOG>{semi}		{ DP("end logging"); BEGIN S_CNF; return(EOS); }

	/* padding */
<S_CNF>padding		{ DP("begin padding"); BEGIN S_PAD; return(PADDING); }
<S_PAD>{bcl}		{ YYD_ECHO; return(BOC); }
<S_PAD>max_length	{ YYD_ECHO; return(MAX_LENGTH); }
<S_PAD>random_length	{ YYD_ECHO; return(RANDOM_LENGTH); }
<S_PAD>check_length	{ YYD_ECHO; return(CHECK_LENGTH); }
<S_PAD>excl_lastone	{ YYD_ECHO; return(EXCL_LASTONE); }
<S_PAD>{ecl}		{ DP("end padding"); BEGIN S_CNF; return(EOC); }

	/* listen */
<S_CNF>listen		{ DP("begin listen"); BEGIN S_LST; return(LISTEN); }
<S_LST>{bcl}		{ YYD_ECHO; return(BOC); }
<S_LST>isakmp		{ YYD_ECHO; return(X_ISAKMP); }
<S_LST>port		{ YYD_ECHO; return(PORT); }
<S_LST>admin		{ YYD_ECHO; return(X_ADMIN); }
<S_LST>{ecl}		{ DP("end listen"); BEGIN S_CNF; return(EOC); }

	/* remote */
<S_CNF>remote		{ DP("begin remote"); BEGIN S_RMT; return(REMOTE); }
<S_RMT>{bcl}		{ YYD_ECHO; return(BOC); }
<S_RMT>anonymous	{ YYD_ECHO; return(ANONYMOUS); }
<S_RMT>port		{ YYD_ECHO; return(PORT); }
<S_RMT>try_to_send	{ YYD_ECHO; return(TRY_TO_SEND); }
<S_RMT>send_timer	{ YYD_ECHO; return(SEND_TIMER); }
<S_RMT>need		{ YYD_ECHO; return(NEED); }
<S_RMT>PFS		{ YYD_ECHO; return(PFS); }
<S_RMT>vendor_id	{ YYD_ECHO; return(VENDOR_ID); }
<S_RMT>{ecl}		{ DP("end remote"); BEGIN S_CNF; return(EOC); }
	/* phase */
<S_RMT>phase		{ DP("begin phase"); BEGIN S_RMT_PH; return(PHASE); }
<S_RMT_PH>{bcl}		{ YYD_ECHO; return(BOC); }

<S_RMT_PH>exchange_mode	{ YYD_ECHO; return(EXCHANGE_MODE); }
<S_RMT_PH>main		{ YYD_ECHO;
			  yylval.num = ISAKMP_ETYPE_IDENT;
			  return(EXCHANGE_T); }
<S_RMT_PH>aggressive	{ YYD_ECHO;
			  yylval.num = ISAKMP_ETYPE_AGG;
			  return(EXCHANGE_T); }
<S_RMT_PH>quick		{ YYD_ECHO;
			  yylval.num = ISAKMP_ETYPE_QUICK;
			  return(EXCHANGE_T); }

<S_RMT_PH>doi		{ YYD_ECHO; return(DOI); }
<S_RMT_PH>ipsec_doi	{ YYD_ECHO; yylval.num = IPSEC_DOI; return(DOI_T); }

<S_RMT_PH>situation	{ YYD_ECHO; return(SITUATION); }
<S_RMT_PH>identity_only	{ YYD_ECHO; 
			  yylval.num = IPSECDOI_SIT_IDENTITY_ONLY;
			  return(SITUATION_T); }

<S_RMT_PH>id_type		{ YYD_ECHO; return(ID_TYPE); }
<S_RMT_PH>ipv4_address	{ YYD_ECHO;
			  yylval.num = IPSECDOI_ID_IPV4_ADDR;
			  return(ID_IPV4_ADDR); }
<S_RMT_PH>ipv6_address	{ YYD_ECHO;
			  yylval.num = IPSECDOI_ID_IPV6_ADDR;
			  return(ID_IPV6_ADDR); }
<S_RMT_PH>port		{ YYD_ECHO; return(PORT); }
<S_RMT_PH>FQDN		{ YYD_ECHO;
			  yylval.num = IPSECDOI_ID_FQDN;
			  return(FQDN); }
<S_RMT_PH>user-FQDN	{ YYD_ECHO;
			  yylval.num = IPSECDOI_ID_USER_FQDN;
			  return(USER_FQDN); }

<S_RMT_PH>pfs_group	{ YYD_ECHO; return(PFS_GROUP); }
<S_RMT_PH>modp768	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_GRP_DESC_MODP768;
			  return(DH_GROUP_T); }
<S_RMT_PH>modp1024	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_GRP_DESC_MODP1024;
			  return(DH_GROUP_T); }
<S_RMT_PH>modp1536	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_GRP_DESC_MODP1536;
			  return(DH_GROUP_T); }
<S_RMT_PH>{ecl}		{ DP("end phase"); BEGIN S_RMT; return(EOC); }

	/* proposal */
<S_RMT_PH>proposal	{ DP("begin proposal"); BEGIN S_RMT_P; return(PROPOSAL); }
<S_RMT_P>{bcl}		{ YYD_ECHO; return(BOC); }

<S_RMT_P>protocol	{ YYD_ECHO; return(PROTOCOL); }
<S_RMT_P>isakmp		{ YYD_ECHO;
			  yylval.num = IPSECDOI_PROTO_ISAKMP;
			  return(PROTOCOL_T); }
<S_RMT_P>esp		{ YYD_ECHO;
			  yylval.num = IPSECDOI_PROTO_IPSEC_ESP;
			  return(PROTOCOL_T); }
<S_RMT_P>ah		{ YYD_ECHO;
			  yylval.num = IPSECDOI_PROTO_IPSEC_AH;
			  return(PROTOCOL_T); }
<S_RMT_P>ipcomp		{ YYD_ECHO;
			  yylval.num = IPSECDOI_PROTO_IPCOMP;
			  return(PROTOCOL_T); }

<S_RMT_P>spi		{ YYD_ECHO; return(SPI); }
<S_RMT_P>transform	{ YYD_ECHO; return(TRANSFORM); }
<S_RMT_P>{ecl}		{ DP("end proposal"); BEGIN S_RMT_PH; return(EOC); }

	/* transform */
<S_RMT_P>oakley		{ DP("begin oakley transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_KEY_IKE;
			  return(TRANSFORM_T); }
<S_RMT_P>des_iv64	{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_DES_IV64;
			  return(TRANSFORM_T); }
<S_RMT_P>des		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_DES;
			  return(TRANSFORM_T); }
<S_RMT_P>3des		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_3DES;
			  return(TRANSFORM_T); }
<S_RMT_P>null		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_NULL;
			  return(TRANSFORM_T); }
<S_RMT_P>rc5		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_RC5;
			  return(TRANSFORM_T); }
<S_RMT_P>cast128	{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_CAST;
			  return(TRANSFORM_T); }
<S_RMT_P>blowfish	{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_BLOWFISH;
			  return(TRANSFORM_T); }
<S_RMT_P>des_iv32	{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_ESP_DES_IV32;
			  return(TRANSFORM_T); }
<S_RMT_P>md5		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_AH_MD5;
			  return(TRANSFORM_T); }
<S_RMT_P>sha1		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_AH_SHA;
			  return(TRANSFORM_T); }
<S_RMT_P>oui		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_IPCOMP_OUI;
			  return(TRANSFORM_T); }
<S_RMT_P>deflate	{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_IPCOMP_DEFLATE;
			  return(TRANSFORM_T); }
<S_RMT_P>lzs		{ DP("begin ipsec transform"); BEGIN S_RMT_T;
			  yylval.num = IPSECDOI_IPCOMP_LZS;
			  return(TRANSFORM_T); }

<S_RMT_T>{bcl}		{ YYD_ECHO; return(BOC); }
	/* common */
<S_RMT_T>lifetime	{ YYD_ECHO; return(LIFETIME); }
<S_RMT_T>second		{ YYD_ECHO; return(SECOND); }
<S_RMT_T>KB		{ YYD_ECHO; return(KB); }
	/* oakley */

<S_RMT_T>encryption_algorithm	{ YYD_ECHO; return(ENCRYPTION_ALGORITHM); }
<S_RMT_T>des 		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_ENC_ALG_DES;
			  return(CIPHER_T); }
<S_RMT_T>idea 		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_ENC_ALG_IDEA;
			  return(CIPHER_T); }
<S_RMT_T>blowfish	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_ENC_ALG_BLOWFISH;
			  return(CIPHER_T); }
<S_RMT_T>rc5 		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_ENC_ALG_RC5;
			  return(CIPHER_T); }
<S_RMT_T>3des 		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_ENC_ALG_3DES;
			  return(CIPHER_T); }
<S_RMT_T>cast 		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_ENC_ALG_CAST;
			  return(CIPHER_T); }

<S_RMT_T>hash_algorithm	{ YYD_ECHO; return(HASH_ALGORITHM); }
<S_RMT_T>md5		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_HASH_ALG_MD5;
			  return(HASH_T); }
<S_RMT_T>sha1		{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_HASH_ALG_SHA;
			  return(HASH_T); }

<S_RMT_T>authentication_method	{ YYD_ECHO; return(AUTHENTICATION_METHOD); }
<S_RMT_T>pre_shared_key	{ YYD_ECHO; return(PRE_SHARED_KEY); }
<S_RMT_T>rsa		{ YYD_ECHO; return(RSA); }
<S_RMT_T>dss		{ YYD_ECHO; return(DSS); }

<S_RMT_T>dh_group	{ YYD_ECHO; return(DH_GROUP); }
<S_RMT_T>modp768	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_GRP_DESC_MODP768;
			  return(DH_GROUP_T); }
<S_RMT_T>modp1024	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_GRP_DESC_MODP1024;
			  return(DH_GROUP_T); }
<S_RMT_T>modp1536	{ YYD_ECHO;
			  yylval.num = OAKLEY_ATTR_GRP_DESC_MODP1536;
			  return(DH_GROUP_T); }

<S_RMT_T>nonce_size	{ YYD_ECHO; return(NONCE_SIZE); }

	/* ipsec */
<S_RMT_T>encryption_mode	{ YYD_ECHO; return(ENCRYPTION_MODE); }
<S_RMT_T>tunnel		{ YYD_ECHO;
			  yylval.num = IPSECDOI_ATTR_ENC_MODE_TUNNEL;
			  return(ENC_MODE_T); }
<S_RMT_T>transport	{ YYD_ECHO;
			  yylval.num = IPSECDOI_ATTR_ENC_MODE_TRNS;
			  return(ENC_MODE_T); }

<S_RMT_T>authentication_algorithm	{ YYD_ECHO; return(AUTHENTICATION_ALGORITHM); }
<S_RMT_T>none		{ YYD_ECHO; yylval.num = 0; return(AUTH_T); }
<S_RMT_T>hmac_md5	{ YYD_ECHO;
			  yylval.num = IPSECDOI_ATTR_AUTH_HMAC_MD5;
			  return(AUTH_T); }
<S_RMT_T>hmac_sha1	{ YYD_ECHO;
			  yylval.num = IPSECDOI_ATTR_AUTH_HMAC_SHA1;
			  return(AUTH_T); }

<S_RMT_T>{ecl}		{ DP("end transform"); BEGIN S_RMT_P; return(EOC); }

	/* post-command */
<S_RMT>post-command	{ DP("begin post-command");
			  BEGIN S_RMT_COM; return(POST_COMMAND); }
<S_RMT_COM>{bcl}	{ YYD_ECHO; return(BOC); }
<S_RMT_COM>path		{ YYD_ECHO; return(EXEC_PATH); }
<S_RMT_COM>exec		{ YYD_ECHO; return(EXEC_COMMAND); }
<S_RMT_COM>success	{ YYD_ECHO; return(EXEC_SUCCESS); }
<S_RMT_COM>failure	{ YYD_ECHO; return(EXEC_FAILURE); }
<S_RMT_COM>{ecl}	{ DP("end post-command"); BEGIN S_RMT; return(EOC); }

	/* filter */
<S_CNF>filter		{ DP("begin filter"); BEGIN S_FLT; return(FILTER); }
<S_FLT>{bcl}		{ YYD_ECHO; return(BOC); }
<S_FLT>default		{ DP("begin default"); BEGIN S_FLT_DEF; return(DEFAULT); }
<S_FLT_DEF>allow	{ YYD_ECHO; return(ALLOW); }
<S_FLT_DEF>deny		{ YYD_ECHO; return(DENY); }
<S_FLT_DEF>{semi}	{ DP("end default"); BEGIN S_FLT; return(EOS); }
<S_FLT>allow		{ DP("begin allow"); BEGIN S_FLT_A; return(ALLOW); }
<S_FLT_A>{bcl}		{ YYD_ECHO; return(BOC); }
<S_FLT_A>{ecl}		{ DP("end allow"); BEGIN S_FLT; return(EOC); }
<S_FLT>deny		{ DP("begin deny"); BEGIN S_FLT_D; return(DENY); }
<S_FLT_D>{bcl}		{ YYD_ECHO; return(BOC); }
<S_FLT_D>{ecl}		{ DP("end deny"); BEGIN S_FLT; return(EOC); }
<S_FLT>{ecl}		{ DP("end filter"); BEGIN S_CNF; return(EOC); }

	/* ... */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ DP("comment"); }
{semi}		{ return(EOS); }

	/* parameter */
on		{ YYD_ECHO; yylval.num = 1; return(SWITCH); }
off		{ YYD_ECHO; yylval.num = 0; return(SWITCH); }

{decstring}	{
			char *bp;

			YYD_ECHO;
			yylval.num = strtol(yytext, &bp, 10);
			return(DECSTRING);
		}

{hexstring}	{
			int len = yyleng - 2; /* (str - "0x") */

			YYD_ECHO; 

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
			YYD_ECHO;
			while (*++p != '"') ;
			*p = NULL;
			yytext++;
			yylval.val.l = yyleng-2;
			yylval.val.v = strdup(yytext);
			return(QUOTEDSTRING);
		}

{hostname}	{
			YYD_ECHO;
			yylval.val.l = yyleng;
			yylval.val.v = strdup(yytext);
			return(HOSTNAME);
		}

[a-zA-Z0-9:\._][a-zA-Z0-9:\._]* {
			YYD_ECHO;
			yylval.val.l = strlen(yytext);
			yylval.val.v = strdup(yytext);
			return(STRING);
		}

%%

static void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
	printf("<%d>%s [%s] (%d)\n", yy_start, w, t, l);
}

static void
yyerror0(char *s, va_list ap)
{
	fprintf(stderr, "%s %d: ", racoon_conf, lineno);
	vfprintf(stderr, s, ap);
	fprintf(stderr, "\n");
}

void
yyerror(char *s, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	yyerror0(s, ap);
	va_end(ap);
	yyerrorcount++;
}

void
yywarn(char *s, ...)
{
	va_list ap;
#ifdef HAVE_STDARG_H
	va_start(ap, s);
#else
	va_start(ap);
#endif
	yyerror0(s, ap);
	va_end(ap);
}

int
cfparse()
{
	extern int cf_post_config __P((void));

	if ((yyin = fopen(racoon_conf, "r")) == NULL) {
		plog("cfparse", "%s, fopen (%s)\n", racoon_conf, strerror(errno));
		return(-1);
	}

	cf_init();

	if (yyparse() || yyerrorcount) {
		if (yyerrorcount) {
			yyerror("fatal parse failure: exiting (%d errors)",
				yyerrorcount);
		} else
			yyerror("fatal parse failure: exiting");
		return(-1);
	}

	YIPSDP(PLOG("parse successed.\n"));
	return cf_post_config();
}
