/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 *
 *	$Id: main.c,v 1.2 2000/01/07 14:33:32 fujisawa Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <err.h>

#include <sys/syslog.h>
#include <sys/time.h>

#include "defs.h"
#include "extern.h"


/*
 *
 */

u_int		_debug;


char	*parseArgument		__P((int, char *[]));
void	 initMain		__P((void));

/*	natptconfig.y						*/
int	 yyparse		__P((void));

/*	natptconfing.l						*/
void	 switchToBuffer		__P((char *));
void	 reassembleCommandLine	__P((int, char *[], char *));


/*
 *
 */

int
main(int argc, char *argv[])
{
    char	*fname = NULL;

    extern	int	 yylineno;
    extern	char	*yyfilename;

    initMain();

    fname = parseArgument(argc, argv);
    if (fname == NULL)
    {
	yyfilename = "commandline";
	yylineno = 0;
	yyparse();
    }
    else
    {
	FILE	*fp = NULL;
	char	 buf[BUFSIZ];

	if (strcmp(fname, "-") == 0)
	{
	    fp = stdin;
	    yyfilename = "stdin";
	}
	else
	{
	    if ((fp = fopen(fname, "r")) == NULL)
		err(1, "fopen failure");

	    yyfilename = fname;
	}
	yylineno = 0;
	while (fgets(buf, sizeof(buf), fp))
	{
	    yylineno++;
	    switchToBuffer(buf);
	    yyparse();
	}
	fclose (fp);
    }

    close_fd();
    return (0);
}


char *
parseArgument(int argc, char *argv[])
{
    int		 ch;
    char	*fname = NULL;

    extern	 char	*optarg;
    extern	 int	 optind;

    while ((ch = getopt(argc, argv, "d:f:n:")) != EOF)
    {
	switch (ch)
	{
	  case 'd':
	    _debug = strtoul(optarg+5, NULL, 0);
#ifdef YYDEBUG
	    {
		extern	int	yydebug;

		if (isDebug(D_YYDEBUG))
		    yydebug = 1;
	    }
#endif
	    break;

	  case 'f':
	    fname = optarg;
	    break;

	  case 'n':
	    if (strcmp(optarg, "osocket") == SAME)
		_debug |= D_NOSOCKET;
	    break;
	}
    }

    argc -= optind;
    argv += optind;

    if (argc)
    {
	char	Wow[BUFSIZ];

	bzero(Wow, sizeof(Wow));

	reassembleCommandLine(argc, argv, Wow);
	return (NULL);
    }

    return (fname);
}


void
printHelp(char *complaint)
{
    if ((complaint != NULL)
	&& (isprint(*complaint) != 0))
    {
	printf("%s\n", complaint);
    }

    printf("Available directives are\n");
    printf("	    interface	 Mark interface as outside or inside.\n");
    printf("	    map		 Set translation rule.\n");
    printf("	    set		 Set  value to in-kernel variable.\n");
    printf("	    show	 Show setting.\n");
    printf("\n");

    exit (0);
}


void
printInterfaceHelp()
{
    printf("	    <interfaceName> {internal|external}\n");
    printf("\n");

    exit (0);
}


void
printPrefixHelp()
{
    printf("	    faith <ipv6addr>\n");
    printf("	    faith <ipv6addr> / <decimal>\n");
    printf("	    natpt <ipv6addr>\n");
    printf("	    natpt <ipv6addr> / <decimal>\n");

    exit (0);
}


void
printRuleHelp()
{
    printf("	    map from <ipaddr> to <ipaddr>\n");
    printf("	    map from <ipaddr> to faith\n");
    printf("	    map flush\n");
    printf("	    map enable\n");
    printf("	    map disable\n");

    exit(0);
}


void
printSetHelp()
{
    printf("	    set debug=<value>\n");

    exit(0);
}


void
printShowHelp()
{
    printf("	    show interface\n");
    printf("	    show prefix\n");
    printf("	    show static\n");
    printf("	    show dynamic\n");
    printf("	    show xlate [<interval>]\n");
    printf("	    show mapping\n");

    exit(0);
}


void
initMain()
{
    init_misc();
}
