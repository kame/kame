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
//#	$SuMiRe: main.c,v 1.6 1998/09/17 01:14:54 shin Exp $
//#	$Id: main.c,v 1.1.1.1 1999/08/08 23:31:08 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"
#include "extern.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

FILE	*StandardInput;
FILE	*StandardOutput;
FILE	*ErrorOutput;
FILE	*DebugOutput;

int	_debug;
char	Wow[BUFSIZ];


char	*parseArgument		__P((int, char *[]));
void	reassembleCommandLine	__P((int, char *[], char *, int));
void	doPrintHelp		__P((void));
void	initMain		__P((int, char *[]));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

int
main(int argc, char *argv[])
{
    char *fname;
    extern int yylineno;
    extern char *yyfilename;

    initMain(argc, argv);
    fname = parseArgument(argc, argv);
    if (!fname) {
	yyfilename = "commandline";
	yylineno = 0;
	yyparse();
    } else {
	FILE *fp = NULL;
	char buf[BUFSIZ];

	if (strcmp(fname, "-") == 0) {
	    fp = stdin;
	    yyfilename = "stdin";
	} else {
	    fp = fopen(fname, "r");
	    if (!fp) {
		perror("open");
		exit(1);
	    }
	    yyfilename = fname;
	}
	yylineno = 0;
	while (fgets(buf, sizeof(buf), fp)) {
	    yylineno++;
	    switchToBuffer(buf);
	    yyparse();
	}
	fclose(fp);
    }

    close_fd();
    return (0);
}


char *
parseArgument(int argc, char *argv[])
{
    extern char *optarg;
    extern int optind;
    int ch;
    char *fname;

    extern void reassembleCommandLine __P((int, char *[], char *, int));

    fname = "-";
    while ((ch = getopt(argc, argv, "d:e:f:")) != EOF) {
	switch (ch) {
	case 'd':
	    _debug = strtol(optarg, NULL, 0);
#if defined(YYDEBUG)
	  {
	    extern  int     yydebug;

	    if (isDebug(D_YYDEBUG))
		yydebug = 1;
	  }
#endif
	    break;
	case 'e':
	    switchToBuffer(optarg);
	    return NULL;
	case 'f':
	    fname = optarg;
	    break;
	default:
	    exit(1);
	}
    }
    argc -= optind;
    argv += optind;

    if (argc) {
	reassembleCommandLine(argc, argv, Wow, BUFSIZ);
	return NULL;
    } else {
#if 0
	doPrintHelp();
	exit(1);
#else
	return fname;
#endif
    }
}


void
doPrintHelp()
{
    StandardOut("usage: pma [-d debuglevel] -e configuration\n");

    exit (0);
}


void
initMain(int argc, char *argv[])
{
    StandardInput  = stdin;
    StandardOutput = stdout;
    ErrorOutput    = stderr;
    DebugOutput    = stderr;

    init_misc();
}
