%{
/*
 * Copyright (C) 1999 WIDE Project.
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
/*
 * KAME $Id: scanner.l,v 1.3 2000/02/04 04:51:41 itojun Exp $
 */

/*
 * The following regular expression tries to identify IPv6 address (possibly
 * with scope identifier extension) as correct as possible.
 *
 * There are possible loose ends, though.  This is inherently difficult
 * for a parser to tackle.
 * While we can exactly identify IPv4 address with regular expression,
 * it is impossible to identify IPv6 address with scope identifiers.
 * This is because:
 * - interface identifier portion is determined by kernel configuration.
 *   If you say fe80::1@1000 and you only have 10 interfaces, it is invalid.
 *   If you say fe80::1@ether0 and your kernel has no "ether0" interface, it is
 *   invalid.
 * - interface identifier portion is context-dependent to IPv6 numeric address
 *   portion.  For example, the regular expression cannot reject "3ffe::1@10"
 *   (scope id after global address).
 * If we would like to identify such situations, we would add a rule like 
 * following, at the very end of ruleset:
 *	.*	{ if (getaddrinfo success) return T_IPv6; else return T_STR; }
 * however, this leaves too high possibility for conflicts, like mistakingly
 * identify "10%fe80::1" as numeric "10", token "%" and then IPv6 address.
 * 
 * If you can shorten regular expression for IPv6 numeric address, please let
 * me know.  Obvious one is to use {m,n} (repeat m to n times), but I fear
 * that it is not supported in certain platform so I tried to avoid it.
 *
 * itojun, KAME project
 */ 

#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <err.h>

#ifndef YY_MAIN
#ifdef FLEX_SCANNER
#define YY_NO_UNPUT
#undef YY_INPUT
#define YY_INPUT(buf, result, max)\
 {\
	char *src = in_buffer;\
	int i;\
\
	if (*src == 0)\
		result = YY_NULL;\
	else {\
		for (i = 0; *src && i < max; ++i)\
			buf[i] = *src++;\
		in_buffer += i;\
		result = i;\
	}\
 }
#else
#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif
static char *in_buffer;
#endif /*YY_MAIN*/

enum foo { T_V6, T_V6KAMEID, T_V6ID, T_V4, T_V4OLD };

%}

N		([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])
NN		([0-9]|[1-9][0-9]*)
W		([0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?)

V680		{W}:{W}:{W}:{W}:{W}:{W}:{W}:{W}

V670		::{W}:{W}:{W}:{W}:{W}:{W}:{W}
V671		{W}::{W}:{W}:{W}:{W}:{W}:{W}
V672		{W}:{W}::{W}:{W}:{W}:{W}:{W}
V673		{W}:{W}:{W}::{W}:{W}:{W}:{W}
V674		{W}:{W}:{W}:{W}::{W}:{W}:{W}
V675		{W}:{W}:{W}:{W}:{W}::{W}:{W}
V676		{W}:{W}:{W}:{W}:{W}:{W}::{W}
V677		{W}:{W}:{W}:{W}:{W}:{W}:{W}::

V660		::{W}:{W}:{W}:{W}:{W}:{W}
V661		{W}::{W}:{W}:{W}:{W}:{W}
V662		{W}:{W}::{W}:{W}:{W}:{W}
V663		{W}:{W}:{W}::{W}:{W}:{W}
V664		{W}:{W}:{W}:{W}::{W}:{W}
V665		{W}:{W}:{W}:{W}:{W}::{W}
V666		{W}:{W}:{W}:{W}:{W}:{W}::

V650		::{W}:{W}:{W}:{W}:{W}
V651		{W}::{W}:{W}:{W}:{W}
V652		{W}:{W}::{W}:{W}:{W}
V653		{W}:{W}:{W}::{W}:{W}
V654		{W}:{W}:{W}:{W}::{W}
V655		{W}:{W}:{W}:{W}:{W}::

V640		::{W}:{W}:{W}:{W}
V641		{W}::{W}:{W}:{W}
V642		{W}:{W}::{W}:{W}
V643		{W}:{W}:{W}::{W}
V644		{W}:{W}:{W}:{W}::

V630		::{W}:{W}:{W}
V631		{W}::{W}:{W}
V632		{W}:{W}::{W}
V633		{W}:{W}:{W}::

V620		::{W}:{W}
V621		{W}::{W}
V622		{W}:{W}::

V610		::{W}
V611		{W}::

V600		::

V6604		{W}:{W}:{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}

V6504		::{W}:{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6514		{W}::{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6524		{W}:{W}::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6534		{W}:{W}:{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6544		{W}:{W}:{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}
V6554		{W}:{W}:{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}

V6404		::{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6414		{W}::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6424		{W}:{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6434		{W}:{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}
V6444		{W}:{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}

V6304		::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6314		{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6324		{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}
V6334		{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}

V6204		::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6214		{W}::{W}:{N}\.{N}\.{N}\.{N}
V6224		{W}:{W}::{N}\.{N}\.{N}\.{N}

V6104		::{W}:{N}\.{N}\.{N}\.{N}
V6114		{W}::{N}\.{N}\.{N}\.{N}

V6004		::{N}\.{N}\.{N}\.{N}

V6		({V680}|{V670}|{V671}|{V672}|{V673}|{V674}|{V675}|{V676}|{V677}|{V660}|{V661}|{V662}|{V663}|{V664}|{V665}|{V666}|{V650}|{V651}|{V652}|{V653}|{V654}|{V655}|{V640}|{V641}|{V642}|{V643}|{V644}|{V630}|{V631}|{V632}|{V633}|{V620}|{V621}|{V622}|{V610}|{V611}|{V600}|{V6604}|{V6504}|{V6514}|{V6524}|{V6534}|{V6544}|{V6554}|{V6404}|{V6414}|{V6424}|{V6434}|{V6444}|{V6304}|{V6314}|{V6324}|{V6334}|{V6204}|{V6214}|{V6224}|{V6104}|{V6114}|{V6004})

ID		[A-Za-z0-9][-_A-Za-z0-9]*

V6ID		({NN}\%{V6}|{ID}\%{V6})
V6KAMEID	({V6}\@{NN}|{V6}\@{ID})

V4		{N}\.{N}\.{N}\.{N}
V4OLD		{N}(\.{N})?(\.{N})?(\.{N})?

%a 3000

%%

{V6ID}\n	{ return T_V6ID; }
{V6KAMEID}\n	{ return T_V6KAMEID; }
{V6}\n		{ return T_V6; }
{V4}\n		{ return T_V4; }
{V4OLD}\n	{ return T_V4OLD; }

.		{ return -1; }
%%
int
yywrap()
{
	return 1;
}

#ifndef YY_MAIN
void
lex_init(buf)
        char *buf;
{
	in_buffer = malloc(strlen(buf) + 10);
	if (!in_buffer)
		errx(1, "not enough core");
	sprintf(in_buffer, "%s\n", buf);
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	int i;
	const char *result;
	struct in_addr in;
	struct in6_addr in6;
	struct addrinfo hints, *res;

	if (argc != 2) {
		fprintf(stderr, "usage: v6regex addr\n");
		exit(1);
	}

	printf("input: %s\t", argv[1]);

	printf("inet_pton:");
	i = 0;
	if (inet_pton(AF_INET6, argv[1], &in6) == 1) {
		printf(" IPv6");
		i++;
	}
	if (inet_pton(AF_INET, argv[1], &in) == 1) {
		printf(" IPv4");
		i++;
	}
	if (i == 0)
		printf(" invalid");

	printf("  getaddrinfo:");
	i = 0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(argv[1], "0", &hints, &res) == 0) {
		printf(" IPv4");
		freeaddrinfo(res);
		i++;
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(argv[1], "0", &hints, &res) == 0) {
		printf(" IPv6");
		freeaddrinfo(res);
		i++;
	}
	if (i == 0)
		printf(" invalid");

	printf("  regex:");
	lex_init(argv[1]);
	i = yylex();
	switch (i) {
	case T_V6:
		printf(" IPv6");
		break;
	case T_V6KAMEID:
		printf(" IPv6 with kame scopeid");
		break;
	case T_V6ID:
		printf(" IPv6 with scopeid");
		break;
	case T_V4:
		printf(" IPv4");
		break;
	case T_V4OLD:
		printf(" IPv4 old");
		break;
	default:
		printf(" invalid");
		break;
	}

	printf("\n");
	exit(0);
}
#endif
