%{
#include <string.h>

#include "cfparse.h"

void cfdebug_print(char *, char *, int);

static int yy_first_time = 1;

#define YY_NO_UNPUT 1

#define DP(str) cfdebug_print(str, yytext, yyleng)
#define D cfdebug_print(NULL, yytext, yyleng)
%}

/* abbreviations */
ws		[ \t]+
bcl		\{
ecl		\}
semi		\;
slash		\/
comment		\#.*
digit		[0-9]
integer		{digit}+
addrstring	[a-zA-Z0-9:\._][a-zA-Z0-9:\._]*
ifname		[a-zA-Z]+[0-9]+
mipifname	mip[0-9]+

%s S_CONFIG
%s S_INTERFACE
%s S_PREFIXTABLE

%%
%{
	if (yy_first_time) {
		BEGIN S_CONFIG;
		yy_first_time = 0;
	}
%}
	/* config parameters */
<S_CONFIG>debug { D; return (DEBUG); }
<S_CONFIG>namelookup { D; return (NAMELOOKUP); }
<S_CONFIG>interface { D; BEGIN S_INTERFACE; return (INTERFACE); }
<S_INTERFACE>{mipifname} {
	D;
	BEGIN S_CONFIG;
	yylval.string = strdup(yytext);
	return (MIPIFNAME);
}
<S_INTERFACE>{ifname} {
	D;
	BEGIN S_CONFIG;
	yylval.string = strdup(yytext);
	return (IFNAME);
}
<S_CONFIG>home-registration-lifetime { D; return (HOMEREGISTRATIONLIFETIME ); }
<S_CONFIG>preference { D; return (PREFERENCE); }
<S_CONFIG>prefixtable { D; BEGIN S_PREFIXTABLE; return (PREFIXTABLE); }
<S_PREFIXTABLE>{bcl} { D; return (BCL); }
<S_PREFIXTABLE>explicit {
	D;
	yylval.string = strdup(yytext);
	return (EXPLICIT);
}
<S_PREFIXTABLE>implicit {
	D;
	yylval.string = strdup(yytext);
	return (IMPLICIT);
}
<S_PREFIXTABLE>{integer} {
	D;
	yylval.number = (int)strtol(yytext, NULL, 10);
	return (INTEGER);
}
<S_PREFIXTABLE>{addrstring} {
	D;
	yylval.string = strdup(yytext);
	return (ADDRSTRING);
}
<S_PREFIXTABLE>{slash} { D; return (SLASH); }
<S_PREFIXTABLE>{ecl} { D; BEGIN S_CONFIG; return (ECL); }

	/* misc */
{ws} { ; }
{comment} { ; }
{integer} {
	D;
	yylval.number = (int)strtol(yytext, NULL, 10);
	return (INTEGER);
}
{bcl} { D; return (BCL); }
{ecl} { D; return (ECL); }
{semi} { D; return (EOS); }

%%

void
cfdebug_print(w, t, l)
	char *w, *t;
	int l;
{
#if 0
	if (w) {
		fprintf(stderr, "<%d>%s [%s] (%d)", yy_start, w, t, l);
	} else {
		fprintf(stderr, "<%d>[%s] (%d)", yy_start, t, l);
	}
#endif
}
