/*	$KAME: main.c,v 1.8 2001/09/02 19:32:28 fujisawa Exp $	*/

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

#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include "cfparse.h"
#include "defs.h"
#include "miscvar.h"
#include "showvar.h"

int		 u_debug;


char		*parseArgument		__P((int, char *[]));
int		 prepParse		__P((char *));
void		 printDirectiveHelp	__P((void));
void		 printPrefixHelp	__P((void));
void		 printMapHelp		__P((void));
void		 printSetHelp		__P((void));
void		 printShowHelp		__P((void));
void		 printTestHelp		__P((void));
void		 init_main		__P((void));


/*
 *
 */

int
main(int argc, char *argv[])
{
	char	*fname = NULL;
	extern int	 yylineno;
	extern char	*yyfilename;

	init_main();

	if ((fname = parseArgument(argc, argv)) == NULL) {
		yyfilename = "commandline";
		yylineno = 0;
		yyparse();
	} else {
		FILE	*fp = NULL;
		char	 buf[BUFSIZ];

		fp = stdin;
		yyfilename = "stdin";
		if (strcmp(fname, "-") != 0) {
			if ((fp = fopen(fname, "r")) == NULL)
				err(1, "fopen failure");

			yyfilename = fname;
		}

		yylineno = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			yylineno++;
			if (prepParse(buf) == TRUE) {
				switchToBuffer(buf);
				yyparse();
			}
		}
		fclose(fp);
	}

	clean_misc();
	clean_show();
	return (0);
}


char *
parseArgument(int argc, char *argv[])
{
	int	 ch;
	char	*fname = NULL;

	extern int	 optind;
	extern char	*optarg;

	while ((ch = getopt(argc, argv, "d:f:")) != -1) {
		switch (ch) {
		case 'd':
			u_debug = strtoul(optarg, NULL, 0);
#ifdef YYDEBUG
			{
				extern int	yydebug;

				if (isDebug(D_YYDEBUG)) {
					yydebug = 1;
				}
			}
#endif
			break;

		case 'f':
			fname = optarg;
			break;

		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		reassembleCommandLine(argc, argv);
		return (NULL);
	}

	return (fname);
}


int
prepParse(char *line)
{
	char	*d;

	d = line;
	while (*d == ' ' || *d == '\t')
		d++;

	if (*d == '#' || *d == '\n' || *d == '\0')
		return (FALSE);

	return (TRUE);
}


void
printHelp(int type, char *complaint)
{
	if ((complaint != NULL)
	    && (isprint(*complaint) != 0)) {
		printf("%s\n", complaint);
	}

	switch (type) {
	case SQUESTION:
		printDirectiveHelp();
		break;

	case SPREFIX:
		printPrefixHelp();
		break;

	case SMAP:
		printMapHelp();
		break;

	case SSET:
		printSetHelp();
		break;

	case SSHOW:
		printShowHelp();
		break;

	case STEST:
		printTestHelp();
		break;
	}
}


void
printDirectiveHelp()
{
	printf("Available directives are\n");
	printf("	prefix	Set NAT-PT prefix.\n");
	printf("	map	Set translation rule.\n");
	printf("	show	Show settings.\n");
	printf("	test	Test log system.\n");
	printf("\n");
}


void
printPrefixHelp()
{
	printf("	prefix <ipv6addr>\n");
}


void
printMapHelp()
{
	printf("	map flush\n");

	printf("	map {enable|disable}\n");
}


void
printSetHelp()
{
	printf("	set natpt_debug=<value>\n");
	printf("	set natpt_dump=<value>\n");
}


void
printShowHelp()
{
	printf("	show prefix\n");
	printf("	show rule\n");
	printf("	show xlate [\"long\"] [<interval>]\n");
	printf("	show variables\n");
	printf("	show mapping\n");
}


void
printTestHelp()
{
	printf("	test log\n");
	printf("	test log <name>\n");
	printf("	test log \"string\"\n");
}


void
init_main()
{
	init_misc();
}
