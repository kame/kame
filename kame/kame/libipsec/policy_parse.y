/*	$NetBSD: policy_parse.y,v 1.14 2003/11/23 08:33:13 itojun Exp $	*/
/*	$KAME: policy_parse.y,v 1.22 2004/06/18 17:42:07 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
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
 * IN/OUT bound policy configuration take place such below:
 *	in <policy>
 *	out <policy>
 *
 * <policy> is one of following:
 *	"discard", "none", "ipsec <requests>", "entrust", "bypass",
 *
 * The following requests are accepted as <requests>:
 *
 * old syntax:
 *	protocol/mode/src-dst/level
 *	protocol/mode/src-dst		parsed as protocol/mode/src-dst/default
 *	protocol/mode/src-dst/		parsed as protocol/mode/src-dst/default
 *	protocol/transport		parsed as protocol/mode/any-any/default
 *	protocol/transport//level	parsed as protocol/mode/any-any/level
 *
 * new syntax:
 *	protocol/level			(everything is transport mode)
 *	encap/src-dst			(encapsulation)
 *
 * You can concatenate these requests with either ' '(single space) or '\n'.
 */

%{
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet6/ipsec.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include "ipsec_strerror.h"

static u_int8_t *pbuf = NULL;		/* sadb_x_policy buffer */
static int tlen = 0;			/* total length of pbuf */
static int offset = 0;			/* offset of pbuf */

struct _val;
extern void yyerror __P((char *));
static struct sockaddr *parse_sockaddr __P((struct _val *));
static int rule_check __P((void));
static int set_x_request __P((int, int, struct sockaddr *, struct sockaddr *,
	int, int));
static int init_x_policy __P((int, int));
static int set_sockaddr __P((struct sockaddr *));
static caddr_t policy_parse __P((char *, int));

extern void __policy__strbuffer__init__ __P((char *));
extern void __policy__strbuffer__free__ __P((void));
extern int yyparse __P((void));
extern int yylex __P((void));

extern char *__libyytext;	/*XXX*/

%}

%union {
	int num;
	struct {
		int level;
		int reqid;
	} level;
	struct _val{
		int len;
		char *buf;
	} val;
	struct sockaddr_storage addr;
	struct {
		struct sockaddr_storage src;
		struct sockaddr_storage dst;
	} addrrange;
}

%token DIR ACTION
%token IPADDRESS
%token ME ANY
%token SLASH HYPHEN
%type <level> level level_specify
%type <num> DIR ACTION protocol mode PROTOCOL MODE LEVEL
%type <val> LEVEL_SPECIFY IPADDRESS
%type <addr> address
%type <addrrange> addresses

%%
policy_spec
	:	DIR ACTION
		{
			if ($2 != IPSEC_POLICY_IPSEC) {
				__ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
				return (-1);
			}
			if (init_x_policy($1, $2))
				return (-1);
		}
		rules
	|	DIR ACTION
		{
			if ($2 == IPSEC_POLICY_IPSEC) {
				__ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
				return (-1);
			}
		}
	|	DIR
		{
			if (init_x_policy($1, 0))
				return (-1);
		}
	;

rules
	:	rules rule
	|	rule
	;

rule
	:	protocol SLASH mode SLASH addresses SLASH level {
			if (set_x_request($1, $3, (struct sockaddr *)&$5.src,
			    (struct sockaddr *)&$5.dst, $7.level, $7.reqid) < 0)
				return (-1);
		}
	|	protocol SLASH mode SLASH addresses SLASH {
			if (set_x_request($1, $3, (struct sockaddr *)&$5.src,
			    (struct sockaddr *)&$5.dst,
			    IPSEC_LEVEL_DEFAULT, 0) < 0)
				return (-1);
		}
	|	protocol SLASH mode SLASH addresses {
			if (set_x_request($1, $3, (struct sockaddr *)&$5.src,
			    (struct sockaddr *)&$5.dst,
			    IPSEC_LEVEL_DEFAULT, 0) < 0)
				return (-1);
		}
	|	protocol SLASH mode SLASH {
			if ($3 == IPSEC_MODE_TUNNEL) {
				__ipsec_errcode = EIPSEC_INVAL_MODE;
				return (-1);
			}
			if (set_x_request($1, $3, NULL, NULL,
			    IPSEC_LEVEL_DEFAULT, 0) < 0)
				return (-1);
		}
	|	protocol SLASH mode SLASH SLASH level {
			if ($3 == IPSEC_MODE_TUNNEL) {
				__ipsec_errcode = EIPSEC_INVAL_MODE;
				return (-1);
			}
			if (set_x_request($1, $3, NULL, NULL, $6.level,
			    $6.reqid) < 0)
				return (-1);
		}
	|	protocol SLASH mode {
			if ($3 == IPSEC_MODE_TUNNEL) {
				__ipsec_errcode = EIPSEC_INVAL_MODE;
				return (-1);
			}
			if (set_x_request($1, $3, NULL, NULL,
			    IPSEC_LEVEL_DEFAULT, 0) < 0)
				return (-1);
		}
		/* new syntax */
	|	protocol SLASH level {
			if (set_x_request($1, IPSEC_MODE_TRANSPORT, NULL, NULL,
			    $3.level, $3.reqid) < 0)
				return (-1);
		}
	|	ENCAP SLASH addresses {
			int proto;

			switch ($3.src.ss_family) {
			case AF_INET:
				proto = IPPROTO_IPV4;
				break;
			case AF_INET6:
				proto = IPPROTO_IPV6;
				break;
			default:
				__ipsec_errcode = EIPSEC_INVAL_FAMILY;
				return (-1);
			}
			if (set_x_request(proto, IPSEC_MODE_TUNNEL,
			    (struct sockaddr *)&$3.src,
			    (struct sockaddr *)&$3.dst,
			    IPSEC_LEVEL_REQUIRE, 0) < 0)
				return (-1);
		}
	|	protocol SLASH {
			__ipsec_errcode = EIPSEC_FEW_ARGUMENTS;
			return (-1);
		}
	|	protocol {
			__ipsec_errcode = EIPSEC_FEW_ARGUMENTS;
			return (-1);
		}
	;

protocol
	:	PROTOCOL { $$ = $1; }
	;

mode
	:	MODE { $$ = $1; }
	;

level
	:	LEVEL {
			$$.level = $1;
			$$.reqid = 0;
		}
	|	LEVEL_SPECIFY {
			$$.level = IPSEC_LEVEL_UNIQUE;
			$$.reqid = atol($1.buf);	/* atol() is good. */
		}
	;

address
	:	IPADDRESS {
			struct sockaddr *sa;

			sa = parse_sockaddr(&$1);
			if (!sa || sa->sa_len > sizeof($$))
				return (-1);
			memcpy(&$$, sa, sa->sa_len);
		}

addresses
	:	address HYPHEN address {
			if ($1.ss_family != $3.ss_family) {
				__ipsec_errcode = EIPSEC_FAMILY_MISMATCH;
				return (-1);
			}
			$$.src = $1;
			$$.dst = $3;
		}
	;

%%

void
yyerror(msg)
	char *msg;
{
	fprintf(stderr, "libipsec: %s while parsing \"%s\"\n",
		msg, __libyytext);

	return;
}

static struct sockaddr *
parse_sockaddr(buf)
	struct _val *buf;
{
	struct addrinfo hints, *res;
	char *serv = NULL;
	int error;
	struct sockaddr *newaddr = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(buf->buf, serv, &hints, &res);
	if (error != 0) {
		yyerror("invalid IP address");
		__ipsec_set_strerror(gai_strerror(error));
		return NULL;
	}

	if (res->ai_addr == NULL) {
		yyerror("invalid IP address");
		__ipsec_set_strerror(gai_strerror(error));
		return NULL;
	}

	newaddr = malloc(res->ai_addr->sa_len);
	if (newaddr == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		freeaddrinfo(res);
		return NULL;
	}
	memcpy(newaddr, res->ai_addr, res->ai_addr->sa_len);

	freeaddrinfo(res);

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return newaddr;
}

static int
init_x_policy(dir, action)
	int dir;
	int action;
{
	struct sadb_x_policy *p;

	if (pbuf) {
		free(pbuf);
		tlen = 0;
	}
	pbuf = malloc(sizeof(struct sadb_x_policy));
	if (pbuf == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		return (-1);
	}
	tlen = sizeof(struct sadb_x_policy);

	memset(pbuf, 0, tlen);
	p = (struct sadb_x_policy *)pbuf;
	p->sadb_x_policy_len = 0;	/* must update later */
	p->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	p->sadb_x_policy_type = action;
	p->sadb_x_policy_dir = dir;
	p->sadb_x_policy_id = 0;

	offset = tlen;

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
set_x_request(protocol, mode, src, dst, level, reqid)
	int protocol;
	int mode;
	struct sockaddr *src, *dst;
{
	struct sadb_x_ipsecrequest *p;
	int reqlen;
	caddr_t n;

	reqlen = sizeof(*p) + (src ? src->sa_len : 0) + (dst ? dst->sa_len : 0);

	n = realloc(pbuf, tlen + reqlen);
	if (n == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		return (-1);
	}
	tlen += reqlen;
	pbuf = n;
	p = (struct sadb_x_ipsecrequest *)&pbuf[offset];
	p->sadb_x_ipsecrequest_len = reqlen;
	p->sadb_x_ipsecrequest_proto = protocol;
	p->sadb_x_ipsecrequest_mode = mode;
	p->sadb_x_ipsecrequest_level = level;
	p->sadb_x_ipsecrequest_reqid = reqid;
	offset += sizeof(*p);

	if (set_sockaddr(src) || set_sockaddr(dst))
		return (-1);

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
set_sockaddr(addr)
	struct sockaddr *addr;
{
	if (addr == NULL) {
		__ipsec_errcode = EIPSEC_NO_ERROR;
		return 0;
	}

	/* tlen has already incremented */

	memcpy(&pbuf[offset], addr, addr->sa_len);

	offset += addr->sa_len;

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static caddr_t
policy_parse(msg, msglen)
	char *msg;
	int msglen;
{
	int error;

	pbuf = NULL;
	tlen = 0;

	/* initialize */
	__policy__strbuffer__init__(msg);

	error = yyparse();	/* it must be set errcode. */
	__policy__strbuffer__free__();

	if (error) {
		if (pbuf != NULL)
			free(pbuf);
		return NULL;
	}

	/* update total length */
	((struct sadb_x_policy *)pbuf)->sadb_x_policy_len = PFKEY_UNIT64(tlen);

	__ipsec_errcode = EIPSEC_NO_ERROR;

	return pbuf;
}

caddr_t
ipsec_set_policy(msg, msglen)
	char *msg;
	int msglen;
{
	caddr_t policy;

	policy = policy_parse(msg, msglen);
	if (policy == NULL) {
		if (__ipsec_errcode == EIPSEC_NO_ERROR)
			__ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
		return NULL;
	}

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return policy;
}
