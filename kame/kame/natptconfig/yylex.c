/*	$KAME: yylex.c,v 1.9 2001/09/21 08:27:52 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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

#include <stdio.h>
#include <string.h>

#include "cfparse.h"
#include "defs.h"


int		_yylex			__P((void));
int		yylex			__P((void));
int		yylexExitHook		__P((int));


struct
{
	char	*word;
	int	 token;
	char	*tokenstring;
}	keyTable[] =
{
	{ "any6",	SANY6,		"SANY6",	},
	{ "break",	SBREAK,		"SBREAK",	},
	{ "disable",	SDISABLE,	"SDISABLE",	},
	{ "dport",	SDPORT,		"SDPORT",	},
	{ "enable",	SENABLE,	"SENABLE",	},
	{ "flush",	SFLUSH,		"SFLUSH",	},
	{ "from",	SFROM,		"SFROM",	},
	{ "icmp",	SICMP,		"SICMP",	},
	{ "log",	SLOG,		"SLOG",		},
	{ "long",	SLONG,		"SLONG",	},
	{ "map",	SMAP,		"SMAP",		},
	{ "mapping",	SMAPPING,	"SMAPPING",	},
	{ "port",	SPORT,		"SPORT",	},
	{ "prefix",	SPREFIX,	"SPREFIX",	},
	{ "rules",	SRULES,		"SRULES",	},
	{ "set",	SSET,		"SSET",		},
	{ "show",	SSHOW,		"SSHOW",	},
	{ "tcp",	STCP,		"STCP",		},
	{ "test",	STEST,		"STEST",	},
	{ "to",		STO,		"STO",		},
	{ "udp",	SUDP,		"SUDP",		},
	{ "variables",	SVARIABLES,	"SVARIABLES",	},
	{ "xlate",	SXLATE,		"SXLATE",	},
	{  NULL,	NULL,		 NULL,		},
};


/*
 *
 */

int
yylex(void)
{
	int	token;

	while ((token = yylexExitHook(_yylex())) == SEOS)
		;
	return (token);
}


int
yylexExitHook(int token)
{
	int	rv = token;

	if (isDebug(D_LEXTOKEN)) {
		if ((token > SEOS) && (token < SOTHER))	{
			int	iter;

			for (iter = 0; keyTable[iter].token; iter++) {
				if (keyTable[iter].token == token) {
					fprintf(stderr, " %s", keyTable[iter].tokenstring);
					return (rv);
				}
			}
			fprintf(stderr, " unknown IDENTIFIER(%d)", token);
			return (rv);
		}

		switch (token) {
		case SEOS:
			fprintf(stderr, " [SEOS]\n");
			break;

		case SOTHER:
			fprintf(stderr, " Unknown:%s", yytext);
			break;

		case SSLASH:
			fprintf(stderr, " /");
			break;

		case SNAME:
			fprintf(stderr, " [%s]", yytext);
			break;

		case SDECIMAL:
			fprintf(stderr, " [%s]", yytext);
			break;

		case SSTRING:
			fprintf(stderr, " \"%s\"", yytext);
			break;

		case SIPV4ADDR:
			fprintf(stderr, " [v4:%s]", yytext);
			break;

		case SIPV6ADDR:
			fprintf(stderr, " [v6:%s]", yytext);
			break;
		}
	}

	return (rv);
}


int
SNAMEorKeyword(char *yytext)
{
	int	iter;

	for (iter = 0; keyTable[iter].word; iter++)
		if (strcasecmp(keyTable[iter].word, yytext) == 0)
			return (keyTable[iter].token);

	return (SNAME);
}
