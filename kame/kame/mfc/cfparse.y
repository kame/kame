/*	$KAME: cfparse.y,v 1.3 2004/01/21 06:49:57 suz Exp $	*/

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

#ifdef __FreeBSD__
#define SIN_ADDR(x) (ntohl(((struct sockaddr_in *) &(x))->sin_addr.s_addr))
#else
#define SIN_ADDR(x) (((struct sockaddr_in *) &(x))->sin_addr.s_addr)
#endif
#define SIN6_ADDR(x) (&(((struct sockaddr_in6 *) &(x))->sin6_addr))

extern int yylex __P((void));
%}

%union {
	struct sockaddr_storage addr;
	mifi_t	ifindex;
	struct if_set ifset;
	char *string;
}

%token EOS FROM	TO
%token <string> INTERFACE INTERFACE4 INTERFACE6 V6ADDR V4ADDR
%type <addr> srcaddr6, dstaddr6, ipv6addr, srcaddr4, dstaddr4, ipv4addr
%type <ifset> interface_list
%type <ifindex> interface, interface4, interface6

%%
statements:
	  /* empty */
	| statements statement
	;

statement:
	route_statement
	;

route_statement:
	  dstaddr6 FROM srcaddr6 '@' interface6 TO interface_list EOS
	{
		add_mfc6((struct sockaddr *)&$3, (struct sockaddr *)&$1,
			 $5, &$7);
	}
	| dstaddr4 FROM srcaddr4 '@' interface4 TO interface_list EOS
	{
		add_mfc4((struct sockaddr *)&$3, (struct sockaddr *)&$1,
			 $5, &$7);
	}
	;

srcaddr6:
	ipv6addr 
	{
		if (IN6_IS_ADDR_MULTICAST(SIN6_ADDR($1)))
			errx(1, "src address should not be IPv6 multicast\n");
		if (IN6_IS_ADDR_LINKLOCAL(SIN6_ADDR($1)))
			errx(1, "src address should not be IPv6 linklocal\n");

		$$ = $1;
	}
	;

srcaddr4:
	ipv4addr 
	{
		if (IN_MULTICAST(SIN_ADDR($1)))
			errx(1, "src address should not be IPv4 multicast\n");

		$$ = $1;
	}
	;

dstaddr6:
	 ipv6addr
	{
		if (!IN6_IS_ADDR_MULTICAST(SIN6_ADDR($1)))
			errx(1, "dst address should be IPv6 multicast\n");
		$$ = $1;
	}
	;

dstaddr4:
	 ipv4addr
	{
		if (!IN_MULTICAST(SIN_ADDR($1)))
			errx(1, "dst address should be IPv4 multicast\n");
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

ipv4addr:	V4ADDR
	{
		struct addrinfo hints, *res;
		int error;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
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
	   interface6
	 | interface4
	 ;

interface6:
	   INTERFACE6
	 {
		int ifindex;

		if (strlen($1) == strlen("reg0") &&
		    strcmp($1, "reg0") == 0) {
			$$ = add_reg_mif6();
			if ($$ == NULL)
				errx(1, "something wrong with register I/F");
			break;
		}
		ifindex = if_nametoindex($1);
		if (ifindex == 0)
			errx(1, "invalid interface %s", $1);

		$$ = add_mif6($1);
	 }
	 ;

interface4:
	   INTERFACE4
	 {
		int ifindex;

		ifindex = if_nametoindex($1);
		if (ifindex == 0)
			errx(1, "invalid interface %s", $1);

		$$ = add_mif4($1);
	 }
	 ;
%%
