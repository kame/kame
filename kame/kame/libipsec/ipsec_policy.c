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

#ifndef lint
static char *rcsid = "@(#) ipsec_policy.c $Revision: 1.2 $";
#endif

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
 *	protocol/mode/src-dst/level
 *	protocol/mode/src-dst		parsed as protocol/mode/src-dst/default
 *	protocol/mode/src-dst/		parsed as protocol/mode/src-dst/default
 *
 * You can concatenate these requests with either ' '(single space) or '\n'.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <assert.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/ipsec.h>

#include <netkey/keyv2.h>
#include <netkey/key_var.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>

#include "ipsec_strerror.h"

/* order must be the same */
static char *tokens[] = {
	"in", "out",
	"discard", "none", "ipsec", "entrust", "bypass",
	"esp", "ah", "ipcomp", "default", "use", "require",
	"transport", "tunnel", "/", NULL
};
enum token {
	t_invalid = -1,
	t_in, t_out,
	t_discard, t_none, t_ipsec, t_entrust, t_bypass,
	t_esp, t_ah, t_ipcomp, t_default, t_use, t_require,
	t_transport, t_tunnel, t_slash,
};
static int values[] = {
	IPSEC_DIR_INBOUND, IPSEC_DIR_OUTBOUND,
	IPSEC_POLICY_DISCARD, IPSEC_POLICY_NONE, IPSEC_POLICY_IPSEC,
	IPSEC_POLICY_ENTRUST, IPSEC_POLICY_BYPASS,
	IPPROTO_ESP, IPPROTO_AH, IPPROTO_IPCOMP,
	IPSEC_LEVEL_DEFAULT, IPSEC_LEVEL_USE, IPSEC_LEVEL_REQUIRE,
	IPSEC_MODE_TRANSPORT, IPSEC_MODE_TUNNEL, 0
};
struct pbuf {
	char *buf;
	int buflen;	/* size of the buffer */
	int off;	/* current offset */
};

static char *ipsp_dir_strs[] = {
	"any", "inbound", "outbound",
};

static char *ipsp_policy_strs[] = {
	"discard", "none", "ipsec", "entrust", "bypass",
};

static enum token gettoken __P((char *p));
static char *skiptoken __P((char *p, enum token t));
static char *skipspaces __P((char *p));
static char *parse_request __P((struct pbuf *pbuf, char *p));
static char *parse_addresses __P((struct sockaddr *src, struct sockaddr *dst,
	char *p));
static char *parse_policy __P((struct pbuf *pbuf, char *p));
static char *get_sockaddr __P((char *host, struct sockaddr *addr));
static int parse_setreq __P((struct pbuf *pbuf, int proto, int mode, int level,
	struct sockaddr *src, struct sockaddr *dst));
static int parse_main __P((struct pbuf *pbuf, char *policy));

static enum token
gettoken(p)
	char *p;
{
	int i;
	int l;

	assert(p);
	for (i = 0; i < sizeof(tokens)/sizeof(tokens[0]); i++) {
		if (tokens[i] == NULL)
			continue;
		l = strlen(tokens[i]);
		if (strncmp(p, tokens[i], l) != 0)
			continue;
		/* slash alone is okay as token */
		if (i == t_slash)
			return i;
		/* other ones are words, so needs proper termination */
		if (isspace(p[l]) || p[l] == '/' || p[l] == '\0')
			return i;
	}
	return t_invalid;
}

static char *
skiptoken(p, t)
	char *p;
	enum token t;
{
	assert(p);
	assert(tokens[t] != NULL);

	if (gettoken(p) != t)
		return NULL;
	return p + strlen(tokens[t]);
}

static char *
skipspaces(p)
	char *p;
{
	assert(p);
	while (p && isspace(*p))
		p++;
	return p;
}

static char *
parse_request(pbuf, p)
	struct pbuf *pbuf;
	char *p;
{
	enum token t;
	int i;
	enum token ts[7];	/* set of tokens */
	struct sockaddr_storage src, dst;

	assert(p);
	assert(pbuf);

	i = 0;

	/*
	 * here, we accept sequence like:
	 *	[token slash]* token
	 * and decode that into ts[].
	 */
	for (i = 0; i < sizeof(ts)/sizeof(ts[0]); i++)
		ts[i] = t_invalid;
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	i = 0;
	while (i < sizeof(ts)/sizeof(ts[0])) {
		/* get a token */
		p = skipspaces(p);
		t = gettoken(p);
		switch (t) {
		case t_invalid:
			if (i == 4) {
				/* this may be peer's addresses. */
				p = parse_addresses((struct sockaddr *)&src,
				                    (struct sockaddr *)&dst, p);
				if (p == NULL) {
					/* parse_address sets ipsec_errorcode.*/
					return NULL;
				}
			} else if (*p == '\0') {
				/* this may be omited level specifier. */
				goto breakbreak;
			} else {
				goto parseerror;
			}

			i++;
			break;
		case t_esp:
		case t_ah:
		case t_ipcomp:
		case t_transport:
		case t_tunnel:
		case t_default:
		case t_use:
		case t_require:
			/* even is always either protocol, mode or level. */
			if (i & 1)
				goto parseerror;
			/*
			 * protocol, mode or level - just keep it into ts[],
			 * we'll care about protocol/level ordering afterwards
			 */
			ts[i++] = t;
			p = skiptoken(p, t);
			break;
		default:
			/* bzz, you are wrong */
			goto parseerror;
		}

		/* skip space */
		p = skipspaces(p);
		t = gettoken(p);
		switch (t) {
		case t_invalid:
			if (*p == '\0')
				break;
			else
				goto parseerror;
			break;
		case t_esp:
		case t_ah:
		case t_ipcomp:
			/* we may reach at next request. */
			goto breakbreak;
		case t_slash:
			/* odds is always 'slash'. */
			if (!(i & 1))
				goto parseerror;
			i++;
			p = skiptoken(p, t);
			break;
		default:
			/* bzz, you are wrong */
			goto parseerror;
		}
	}

breakbreak:

	/* alright, we've got the tokens. */
	switch (i) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
		ipsec_errcode = EIPSEC_NO_PROTO;
		return NULL;	/* less token?  naa, go away */
	case 5:
	case 6:
	case 7:
		if (!(ts[0] == t_esp || ts[0] == t_ah || ts[0] == t_ipcomp)) {
			ipsec_errcode = EIPSEC_INVAL_PROTO;
			return NULL;
		}
		if (!(ts[2] == t_transport || ts[2] == t_tunnel)) {
			ipsec_errcode = EIPSEC_INVAL_MODE;
			return NULL;
		}
		if (i != 7)
			ts[6] = t_default;
		if (!(ts[6] == t_default || ts[6] == t_use
		 || ts[6] == t_require)) {
			ipsec_errcode = EIPSEC_INVAL_LEVEL;
			return NULL;
		}
		break;
	default:
		ipsec_errcode = EIPSEC_INVAL_LEVEL;	/*XXX*/
		return NULL;
	}

	if (parse_setreq(pbuf, values[ts[0]], values[ts[2]], values[ts[6]],
			(struct sockaddr *)&src, (struct sockaddr *)&dst) < 0) {
		/* parse_setreq updates ipsec_errcode */
		return NULL;
	}

	return p;

parseerror:
	ipsec_errcode = EIPSEC_NO_ERROR;	/*sentinel*/
	switch (i) {
	case 0:
		ipsec_errcode = EIPSEC_NO_PROTO;
		break;
	case 1:
	case 2:
		if (!(ts[0] == t_esp || ts[0] == t_ah || ts[0] == t_ipcomp))
			ipsec_errcode = EIPSEC_INVAL_PROTO;
		if (i == 1)
			break;
		if (!(ts[1] == t_default || ts[1] == t_use
		 || ts[1] == t_require)) {
			ipsec_errcode = EIPSEC_INVAL_LEVEL;
		}
		break;
	}
	if (ipsec_errcode == EIPSEC_NO_ERROR)
		ipsec_errcode = EIPSEC_INVAL_LEVEL;	/*XXX*/
	return NULL;
}

static char *
parse_addresses(src, dst, p)
	struct sockaddr *src, *dst;
	char *p;
{
	char *p2;

	if ((p2 = strchr(p, '-')) == NULL) {
		ipsec_errcode = EIPSEC_INVAL_ADDRESS;
		return NULL;
	}
	*p2 = '\0';
	
	p = get_sockaddr(p, src);
	if (p == NULL) {
		/* get_sockaddr updates ipsec_errcode */
		return NULL;
	}
	*p2 = '-';
	if (p != p2) {
		ipsec_errcode = EIPSEC_INVAL_ADDRESS;
		return NULL;
	}

	p = get_sockaddr(p2 + 1, dst);
	if (p == NULL) {
		/* get_sockaddr updates ipsec_errcode */
		return NULL;
	}

	return p;
}

static char *
parse_policy(pbuf, p)
	struct pbuf *pbuf;
	char *p;
{
	enum token t, dir;
	int len;
	struct sadb_x_policy *policy;

	assert(p);
	assert(pbuf);
	ipsec_errcode = EIPSEC_NO_ERROR;

	/* get direction */
	p = skipspaces(p);
	dir = gettoken(p);
	switch (dir) {
	case t_in:
	case t_out:
		p = skiptoken(p, dir);
		break;
	default:
		/* bzz, you're wrong */
		ipsec_errcode = EIPSEC_INVAL_POLICY;
		return NULL;
	}

	/* get policy type */
	p = skipspaces(p);
	t = gettoken(p);
	switch (t) {
	case t_discard:
	case t_none:
	case t_ipsec:
	case t_entrust:
	case t_bypass:
		p = skiptoken(p, t);
		break;
	default:
		/* bzz, you're wrong */
		ipsec_errcode = EIPSEC_INVAL_POLICY;
		return NULL;
	}

	/* construct policy structure */
	len = PFKEY_ALIGN8(sizeof(*policy));
	policy = NULL;
	if (pbuf->buf) {
		if (pbuf->off + len > pbuf->buflen) {
			/* buffer overflow */
			ipsec_errcode = EIPSEC_NO_BUFS;
			return NULL;
		}

		policy = (struct sadb_x_policy *)&pbuf->buf[pbuf->off];
		memset(policy, 0, sizeof(*policy));
		policy->sadb_x_policy_len = PFKEY_UNIT64(len);
			/* update later */
		policy->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
		policy->sadb_x_policy_type = values[t];
		policy->sadb_x_policy_dir = values[dir];
	}
	pbuf->off += len;

	/* alright, go to the next step */
	while (p && *p)
		p = parse_request(pbuf, p);

	/* ipsec policy needs request */
	if (t == t_ipsec && pbuf->off == len) {
		ipsec_errcode = EIPSEC_INVAL_POLICY;
		return NULL;
	}

	/* update length */
	if (policy)
		policy->sadb_x_policy_len = PFKEY_UNIT64(pbuf->off);
	
	return p;
}

static char *
get_sockaddr(host, addr)
	char *host;
	struct sockaddr *addr;
{
	struct sockaddr *saddr = NULL;
	struct addrinfo hints, *res;
	char *serv = NULL;
	int error;
	char *p, c;

	/* find the next delimiter */
	p = host;
	while (p && *p && !isspace(*p) && *p != '/')
		p++;
	if (p == host)
		return NULL;
	c = *p;
	*p = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	if ((error = getaddrinfo(host, serv, &hints, &res)) != 0) {
		ipsec_set_strerror(gai_strerror(error));
		*p = c;
		return NULL;
	}

	if (res->ai_addr == NULL) {
		ipsec_set_strerror(gai_strerror(error));
		*p = c;
		return NULL;
	}

#if 0
	if (res->ai_next) {
		printf("getaddrinfo(%s): "
			"resolved to multiple address, taking the first one",
			host);
	}
#endif

	if ((saddr = malloc(res->ai_addr->sa_len)) == NULL) {
		ipsec_errcode = EIPSEC_NO_BUFS;
		freeaddrinfo(res);
		*p = c;
		return NULL;
	}
	memcpy(addr, res->ai_addr, res->ai_addr->sa_len);

	freeaddrinfo(res);

	ipsec_errcode = EIPSEC_NO_ERROR;
	*p = c;
	return p;
}

static int
parse_setreq(pbuf, proto, mode, level, src, dst)
	struct pbuf *pbuf;
	int proto, mode, level;
	struct sockaddr *src, *dst;
{
	struct sadb_x_ipsecrequest *req;
	int start;
	int len;

	assert(pbuf);
	assert(src && dst);

	ipsec_errcode = EIPSEC_NO_ERROR;
	start = pbuf->off;

	len = PFKEY_ALIGN8(sizeof(*req) + src->sa_len + dst->sa_len);
	req = NULL;
	if (pbuf->buf) {
		if (pbuf->off + len > pbuf->buflen) {
			/* buffer overflow */
			ipsec_errcode = EIPSEC_NO_BUFS;
			return -1;
		}
		req = (struct sadb_x_ipsecrequest *)&pbuf->buf[pbuf->off];
		memset(req, 0, len);
		req->sadb_x_ipsecrequest_len = len;
		req->sadb_x_ipsecrequest_proto = proto;
		req->sadb_x_ipsecrequest_mode = mode;
		req->sadb_x_ipsecrequest_level = level;

		memcpy(req + 1, src, src->sa_len);
		memcpy((caddr_t)(req + 1) + src->sa_len, dst, dst->sa_len);
	}
	pbuf->off += len;

	return 0;
}

static int
parse_main(pbuf, policy)
	struct pbuf *pbuf;
	char *policy;
{
	char *p;

	ipsec_errcode = EIPSEC_NO_ERROR;

	if (policy == NULL) {
		ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
		return -1;
	}

	p = parse_policy(pbuf, policy);
	if (!p) {
		/* ipsec_errcode updated somewhere inside */
		return -1;
	}
	p = skipspaces(p);
	if (*p != '\0') {
		ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
		return -1;
	}

	ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

/* %%% */
int
ipsec_get_policylen(policy)
	char *policy;
{
	struct pbuf pbuf;

	memset(&pbuf, 0, sizeof(pbuf));
	if (parse_main(&pbuf, policy) < 0)
		return -1;

	ipsec_errcode = EIPSEC_NO_ERROR;
	return pbuf.off;
}

int
ipsec_set_policy(buf, len, policy)
	char *buf;
	int len;
	char *policy;
{
	struct pbuf pbuf;

	memset(&pbuf, 0, sizeof(pbuf));
	pbuf.buf = buf;
	pbuf.buflen = len;
	if (parse_main(&pbuf, policy) < 0)
		return -1;

	ipsec_errcode = EIPSEC_NO_ERROR;
	return pbuf.off;
}

/*
 * policy is sadb_x_policy buffer.
 * Must call free() later.
 * When delimiter == NULL, alternatively ' '(space) is applied.
 */
char *
ipsec_dump_policy(policy, delimiter)
	char *policy;
	char *delimiter;
{
	struct sadb_x_policy *xpl = (struct sadb_x_policy *)policy;
	struct sadb_x_ipsecrequest *xisr;
	int xtlen, buflen;
	char *buf;

	/* sanity check */
	if (policy == NULL)
		return NULL;
	if (xpl->sadb_x_policy_exttype != SADB_X_EXT_POLICY) {
		ipsec_errcode = EIPSEC_INVAL_EXTTYPE;
		return NULL;
	}

	/* set delimiter */
	if (delimiter == NULL)
		delimiter = " ";

	switch (xpl->sadb_x_policy_dir) {
	case IPSEC_DIR_ANY:
	case IPSEC_DIR_INBOUND:
	case IPSEC_DIR_OUTBOUND:
		break;
	default:
		ipsec_errcode = EIPSEC_INVAL_DIR;
		return NULL;
	}

	switch (xpl->sadb_x_policy_type) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_NONE:
	case IPSEC_POLICY_IPSEC:
	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_ENTRUST:
		break;
	default:
		ipsec_errcode = EIPSEC_INVAL_POLICY;
		return NULL;
	}

	buflen = strlen(ipsp_dir_strs[xpl->sadb_x_policy_dir])
		+ 1	/* space */
		+ strlen(ipsp_policy_strs[xpl->sadb_x_policy_type])
		+ 1;	/* NUL */

	if ((buf = malloc(buflen)) == NULL) {
		ipsec_errcode = EIPSEC_NO_BUFS;
		return NULL;
	}
	strcpy(buf, ipsp_dir_strs[xpl->sadb_x_policy_dir]);
	strcat(buf, " ");
	strcat(buf, ipsp_policy_strs[xpl->sadb_x_policy_type]);

	if (xpl->sadb_x_policy_type != IPSEC_POLICY_IPSEC) {
		ipsec_errcode = EIPSEC_NO_ERROR;
		return buf;
	}

	xtlen = PFKEY_UNUNIT64(xpl->sadb_x_policy_len) - sizeof(*xpl);
	xisr = (struct sadb_x_ipsecrequest *)(policy + sizeof(*xpl));

	/* count length of buffer for use */
	/* XXX non-seriously */
	while (xtlen > 0) {
		buflen += 20;
		if (xisr->sadb_x_ipsecrequest_mode ==IPSEC_MODE_TUNNEL)
			buflen += 50;
		xtlen -= xisr->sadb_x_ipsecrequest_len;
		xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
				+ xisr->sadb_x_ipsecrequest_len);
	}

	/* validity check */
	if (xtlen < 0) {
		ipsec_errcode = EIPSEC_INVAL_SADBMSG;
		free(buf);
		return NULL;
	}

	if ((buf = realloc(buf, buflen)) == NULL) {
		ipsec_errcode = EIPSEC_NO_BUFS;
		return NULL;
	}

	xtlen = PFKEY_UNUNIT64(xpl->sadb_x_policy_len) - sizeof(*xpl);
	xisr = (struct sadb_x_ipsecrequest *)(policy + sizeof(*xpl));

	while (xtlen > 0) {
		switch (xisr->sadb_x_ipsecrequest_proto) {
		case IPPROTO_ESP:
			strcat(buf, delimiter);
			strcat(buf, "esp");
			break;
		case IPPROTO_AH:
			strcat(buf, delimiter);
			strcat(buf, "ah");
			break;
		case IPPROTO_IPCOMP:
			strcat(buf, delimiter);
			strcat(buf, "ipcomp");
			break;
		default:
			ipsec_errcode = EIPSEC_INVAL_PROTO;
			free(buf);
			return NULL;
		}

		switch (xisr->sadb_x_ipsecrequest_mode) {
		case IPSEC_MODE_ANY:
			strcat(buf, "/any");
			break;
		case IPSEC_MODE_TRANSPORT:
			strcat(buf, "/transport");
			break;
		case IPSEC_MODE_TUNNEL:
			strcat(buf, "/tunnel");
			break;
		default:
			ipsec_errcode = EIPSEC_INVAL_MODE;
			free(buf);
			return NULL;
		}

	    {
		char tmp[100]; /* XXX */
		struct sockaddr *saddr = (struct sockaddr *)(xisr + 1);
#if 1
		inet_ntop(saddr->sa_family, _INADDRBYSA(saddr),
			tmp, sizeof(tmp));
#else
		getnameinfo(saddr, saddr->sa_len, tmp, sizeof(tmp),
			NULL, 0, NI_NUMERICHOST);
#endif
		strcat(buf, "/");
		strcat(buf, tmp);
		strcat(buf, "-");

		saddr = (struct sockaddr *)((caddr_t)saddr + saddr->sa_len);
#if 1
		inet_ntop(saddr->sa_family, _INADDRBYSA(saddr),
			tmp, sizeof(tmp));
#else
		getnameinfo(saddr, saddr->sa_len, tmp, sizeof(tmp),
			NULL, 0, NI_NUMERICHOST);
#endif
		strcat(buf, tmp);
	    }
		
		switch (xisr->sadb_x_ipsecrequest_level) {
		case IPSEC_LEVEL_DEFAULT:
			strcat(buf, "/default");
			break;
		case IPSEC_LEVEL_USE:
			strcat(buf, "/use");
			break;
		case IPSEC_LEVEL_REQUIRE:
			strcat(buf, "/require");
			break;
		default:
			ipsec_errcode = EIPSEC_INVAL_LEVEL;
			free(buf);
			return NULL;
		}

		xtlen -= xisr->sadb_x_ipsecrequest_len;
		xisr = (struct sadb_x_ipsecrequest *)((caddr_t)xisr
				+ xisr->sadb_x_ipsecrequest_len);
	}

	ipsec_errcode = EIPSEC_NO_ERROR;
	return buf;
}
