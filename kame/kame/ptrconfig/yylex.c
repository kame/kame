/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$Id: yylex.c,v 1.1.1.1 1999/08/08 23:31:16 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>

#include "defs.h"
#include "extern.h"
#include "ptrconfig.y.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int	_yylex		__P((void));

struct
{
    char    *word;
    int	     token;
    char    *tokenstring;
}   keyTable[] =
{
    { "break",		SBREAK,		"SBREAK",	},
    { "disable",	SDISABLE,	"SDISABLE",	},
    { "dynamic",	SDYNAMIC,	"SDYNAMIC",	},
    { "enable",		SENABLE,	"SENABLE",	},
    { "external",	SEXTERNAL,	"SEXTERNAL",	},
    { "faith",		SFAITH,		"SFAITH",	},
    { "flush",		SFLUSH,		"SFLUSH",	},
    { "from",		SFROM,		"SFROM",	},
    { "interface",	SINTERFACE,	"SINTERFACE",	},
    { "internal",	SINTERNAL,	"SINTERNAL",	},
    { "map",		SMAP,		"SMAP",		},
    { "prefix",		SPREFIX,	"SPREFIX",	},
    { "show",		SSHOW,		"SSHOW",	},
    { "static",		SSTATIC,	"SSTATIC",	},
    { "to",		STO,		"STO",		},
    { "xlate",		SXLATE,		"SXLATE",	},
    {  NULL,		NULL,		 NULL,		},
};


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
yylex(void)
{
    int     token;

    extern  int	    yylexExitHook	__P((int));
    extern  int     __yylex		__P((void));

    while ((token = yylexExitHook(_yylex())) == SEOS) ;
    return (token);
}


int
yylexExitHook(int token)
{
    int     rv = token;

    extern  char    *yytext;

    if (isDebug(D_LEXTOKEN))
    {
	if ((token > SEOS) && (token < SOTHER))
	{
	    int     iter;

	    for (iter = 0; keyTable[iter].token; iter++)
	    {
		if (keyTable[iter].token == token)
		{
		    DebugOut(" %s", keyTable[iter].tokenstring);
		    goto    EXIT;
		}
	    }
	    DebugOut(" unknown IDENTIFIER(%d)", token);
	    goto    EXIT;
	}

	switch (token)
	{
	  case SOTHER:	DebugOut(" Unknown:%s", yytext);break;

	  case SNAME:	DebugOut(" [%s]", yytext);	break;
	  case SDECIMAL:DebugOut(" [%s]", yytext);	break;
	  case SSTRING:	DebugOut(" \"%s\"", yytext);	break;

	  case SPERIOD:	DebugOut(" SPERIOD");		break;
	  case SSLASH:	DebugOut(" SSLASH");		break;
	    
	}
    }

    EXIT:;
    return (rv);
}


int
SNAMEorKeyword(char *yytext)
{
    int     iter;

    for (iter = 0; keyTable[iter].word; iter++)
    {
	if (strncmp(keyTable[iter].word, yytext, strlen(yytext)) == SAME)
	    return (keyTable[iter].token);
    }
    return (SNAME);
}
