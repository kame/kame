/*	$KAME: cfparse.y,v 1.1 2001/07/11 08:36:58 suz Exp $	*/

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
%{
#include "mfc.h"
extern int yylex __P((void));
%}

%union {
	struct sockaddr_in6 in6;
	mifi_t	ifindex;
	struct if_set ifset;
	char *string;
}

%token EOS FROM	TO
%token <string> STRING V6ADDR
%type <in6> srcaddr, dstaddr, ipv6addr
%type <ifset> interface_list
%type <ifindex> interface

%%
statements:
	  /* empty */
	| statements statement
	;

statement:
	route_statement
	;

route_statement:
	dstaddr	FROM srcaddr '@' interface TO interface_list EOS
	{
		add_mfc((struct sockaddr *)&$3, (struct sockaddr *)&$1,
			$5, &$7);
	}
	;

srcaddr: 
	ipv6addr 
	{
		if (IN6_IS_ADDR_MULTICAST(&$1.sin6_addr))
			errx(1, "src address should not be multicast\n");
		if (IN6_IS_ADDR_LINKLOCAL(&$1.sin6_addr))
			errx(1, "src address should not be linklocal\n");

		$$ = $1;
	}
	;

dstaddr:
	 ipv6addr
	{
		if (!IN6_IS_ADDR_MULTICAST(&$1.sin6_addr))
			errx(1, "dst address should be multicast\n");
		$$ = $1;
	}
	;

ipv6addr:	V6ADDR
	{
		struct addrinfo hints, *res;
		int error;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;
		if ((error = getaddrinfo($1, NULL, &hints, &res)) != 0)
			errx(1, "getaddrinfo: %s\n", gai_strerror(error));
		bzero(&$$, sizeof($$));
		bcopy(res->ai_addr, &$$, res->ai_addrlen);
	}
	;

interface_list:
	   interface
	 {
		IF_ZERO(&$$);	
		IF_SET($1, &$$);	
	 }
	 | interface_list interface
	 {
		$$ = $1;
		IF_SET($2, &$$);
	 }
	 ;

interface: 	
	   STRING
	 {
		int ifindex = if_nametoindex($1);
		if (ifindex == 0)
			errx(1, "invalid interface %s", $1);

		$$ = add_mif($1);
	 }
	 ;
	 
%%
