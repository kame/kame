/*	$KAME: cftoken.l,v 1.35 2005/01/12 06:06:11 suz Exp $	*/

%{
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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <errno.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "dhcp6.h"
#include "config.h"
#include "common.h"
#if defined(__NetBSD__) && __NetBSD_Version__ >= 106000000	/* XXX */
#include "cfparse.h"
#else
#include "y.tab.h"
#endif

#define YY_NO_UNPUT 1

char *configfilename;
int lineno = 1;

static int yy_first_time = 1;
static int yyerrorcount = 0;
 
#ifndef NOCONFIG_DEBUG
#define YYDEBUG 1

int cfdebug = 1;
#else
int cfdebug = 0;
#endif

extern int yyparse __P((void));
extern int cf_post_config __P((void));

static void cfdebug_print __P((char *, char *, int));

#define DP(str) if (cfdebug) cfdebug_print(str, yytext, yyleng)
#define DECHO if (cfdebug) cfdebug_print(NULL, yytext, yyleng);
#define DNOECHO if (cfdebug) cfdebug_print(NULL, "****", yyleng);
%}

/* abbreviations */
nl		\n
ws		[ \t]+
comma		,
comment		\#.*
semi		\;
quotedstring	\"[^\"]*\"
string		[a-zA-Z0-9:\._][a-zA-Z0-9:\._]*
digit		[0-9]
integer 	{digit}+
number		{integer}|({digit}*\.{integer})
hexdigit	[0-9A-Fa-f]
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexpair}+
duid 		{hexpair}(:{hexpair})*
ifname		[a-zA-Z]+[0-9]+
slash		\/
bcl		\{
ecl		\}

%s S_CNF
%s S_IFACE
%s S_PREF
%s S_HOST
%s S_DUID
%s S_IA
%s S_AUTH
%s S_KEY
%s S_SECRET

%%
%{
	if (yy_first_time) {
		BEGIN S_CNF;
		yy_first_time = 0;
	}
%}
	/* interface configuration */
<S_CNF>interface { DECHO; BEGIN S_IFACE; return (INTERFACE); }
<S_IFACE>{ifname} {
	DECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return (IFNAME);
}

	/* host configuration */
<S_CNF>host { DECHO; BEGIN S_HOST; return (HOST); }
<S_HOST>{string} {
	DECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return (HOSTNAME);
}

<S_CNF>duid { DECHO; BEGIN S_DUID; return (DUID); }
<S_DUID>{duid} {
	DECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return (DUID_ID);
}

<S_CNF>address { DECHO; return (ADDRESS); }

<S_CNF>prefix { DECHO; return (PREFIX); }

<S_CNF>preference { DECHO; return (PREFERENCE); }

<S_CNF>script { DECHO; return (SCRIPT); }

<S_CNF>delayedkey { DECHO; return (DELAYEDKEY); }

	/* request */
<S_CNF>request { DECHO; return (REQUEST); }

	/* send */
<S_CNF>send { DECHO; return (SEND); }

	/* DHCP options */
<S_CNF>option { DECHO; return (OPTION); }

<S_CNF>rapid-commit { DECHO; return (RAPID_COMMIT); }
<S_CNF>ia-pd { DECHO; return (IA_PD); }
<S_CNF>ia-na { DECHO; return (IA_NA); }
<S_CNF>domain-name-servers { DECHO; return (DNS_SERVERS); }
<S_CNF>domain-name { DECHO; return (DNS_NAME); }
<S_CNF>sip-server-address { DECHO; return (SIP_SERVERS); }
<S_CNF>sip-server-domain-name { DECHO; return (SIP_NAME); }
<S_CNF>ntp-servers { DECHO; return (NTP_SERVERS); }
<S_CNF>refreshtime { DECHO; return (REFRESHTIME); }

	/* generic options */
<S_CNF>information-only { DECHO; return (INFO_ONLY); }

<S_CNF>allow { DECHO; return (ALLOW); }

	/* identity association */
<S_CNF>id-assoc { DECHO; BEGIN S_IA; return(ID_ASSOC); }
<S_IA>pd { DECHO; return(IA_PD); }
<S_IA>na { DECHO; return(IA_NA); }
<S_IA>{number} { DECHO; yylval.str = strdup(yytext); return(IAID); }
<S_IA>{bcl} { DP("begin of closure"); BEGIN S_CNF; return (BCL); }

	/*
	 * interface parameters for delegated prefix configuration.
	 * when lex reads an interface name, the state will be back to
	 * S_CNF.
	 */
<S_CNF>prefix-interface { DECHO; BEGIN S_IFACE; return (PREFIX_INTERFACE); }
<S_CNF>sla-id { DECHO; return (SLA_ID); }
<S_CNF>sla-len { DECHO; return (SLA_LEN); }

	/* duration */
<S_CNF>infinity { DECHO; return (INFINITY); }

	/* authentication option */
<S_CNF>authentication { DECHO; BEGIN S_AUTH; return (AUTHENTICATION); }
<S_AUTH>{string} {
	DECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return (AUTHNAME);
}

	/* authentication parameters */
<S_CNF>protocol { DECHO; return (PROTOCOL); };
<S_CNF>algorithm { DECHO; return (ALGORITHM); };
<S_CNF>rdm { DECHO; return (RDM); };
<S_CNF>key { DECHO; return (KEY); };

	/* authentication protocols */
<S_CNF>delayed { DECHO; return (DELAYED); };
<S_CNF>reconfig { DECHO; return (RECONFIG); };

	/* authentication algorithms */
<S_CNF>hmac-md5 { DECHO; return (HMACMD5); };
<S_CNF>HMAC-MD5 { DECHO; return (HMACMD5); };
<S_CNF>hmacmd5 { DECHO; return (HMACMD5); };
<S_CNF>HMACMD5 { DECHO; return (HMACMD5); };

	/* authentication RDM */
<S_CNF>monocounter { DECHO; return (MONOCOUNTER); };

	/* secret keys */
<S_CNF>keyinfo { DECHO; BEGIN S_KEY; return (KEYINFO); }
<S_KEY>{string} {
	DECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return (KEYNAME);
}

	/* key parameters */
<S_CNF>realm { DECHO; return (REALM); }
<S_CNF>keyid { DECHO; return (KEYID); }
<S_CNF>secret { DECHO; BEGIN S_SECRET; return (SECRET); }
<S_SECRET>{quotedstring} {
	DNOECHO;
	yylval.str = strdup(yytext);
	BEGIN S_CNF;
	return (QSTRING);
}
<S_CNF>expire { DECHO; return (EXPIRE); }

	/* quoted string */
{quotedstring} {
		DECHO;
		yylval.str = strdup(yytext);
		return (QSTRING);
	}

	/* misc */
{ws}		{ ; }
{nl}		{ lineno++; }
{comment}	{ DP("comment"); }
{number} 	{
	DECHO;
	yylval.num = strtoll(yytext, NULL, 10);
	return (NUMBER);
}
{slash} { DECHO; return (SLASH); }
{comma} { DECHO; return (COMMA); }
{semi} { DP("end of sentence"); return (EOS); }
{bcl} { DP("begin of closure"); return (BCL); }
{ecl} { DP("end of closure"); return (ECL); }

	/* generic string */
{string} {
		DECHO;
		yylval.str = strdup(yytext);
		return (STRING);
	}

%%
static void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
	if (w) {
		dprintf(LOG_DEBUG, FNAME,
		    "<%d>%s [%s] (%d)", yy_start, w, t, l);
	} else {
		dprintf(LOG_DEBUG, FNAME,
		    "<%d>[%s] (%d)", yy_start, t, l);
	}
}

static void
yyerror0(int level, char *s, va_list ap)
{
	char ebuf[BUFSIZ], *bp, *ep;

	bp = ebuf;
	ep = ebuf + sizeof(ebuf);
	bp += snprintf(bp, ep - bp, "%s %d: ", configfilename, lineno);
	if (bp < ep)
		bp += vsnprintf(bp, ep - bp, s, ap);

	dprintf(level, FNAME, ebuf);
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
	yyerror0(LOG_ERR, s, ap);
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
	yyerror0(LOG_WARNING, s, ap);
	va_end(ap);
}

int
cfparse(conf)
	char *conf;
{
	configfilename = conf;
	if ((yyin = fopen(configfilename, "r")) == NULL) {
		dprintf(LOG_ERR, FNAME, "cfparse: fopen(%s): %s",
			configfilename, strerror(errno));
		if (errno == ENOENT)
			return (0);
		return (-1);
	}

	if (yyparse() || yyerrorcount) {
		if (yyerrorcount) {
			yyerror("fatal parse failure: exiting (%d errors)",
				yyerrorcount);
		} else
			yyerror("fatal parse failure: exiting");
		return (-1);
	}

	return (cf_post_config());
}
