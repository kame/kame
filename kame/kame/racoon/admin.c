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
 */
/* YIPS @(#)$Id: admin.c,v 1.3 2000/01/09 01:31:20 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/signal.h>

#include <netkey/keyv2.h>
#include <netkey/key_var.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "isakmp_var.h"
#include "handler.h"
#include "pfkey.h"
#include "admin.h"
#include "admin_var.h"
#include "session.h"

static int admin_process __P((int so2, char *combuf));
static int admin_reply __P((int so, struct admin_com *combuf, vchar_t *buf));
static u_int admin2pfkey_proto __P((u_int proto));

int
admin_handler()
{
	int so2;
	struct sockaddr_storage from;
	int fromlen = sizeof(from);
	struct admin_com com;
	char *combuf = NULL;
	int len;

	so2 = accept(lcconf->sock_admin, (struct sockaddr *)&from, &fromlen);
	if (so2 < 0) {
		plog(logp, LOCATION, NULL,
			"failed to accept admin command (%s)\n",
			strerror(errno));
		return -1;
	}

	/* get buffer length */
	while ((len = recv(so2, (char *)&com, sizeof(com), MSG_PEEK)) < 0) {
		if (errno == EINTR)
			continue;
		plog(logp, LOCATION, NULL,
			"failed to recv admin command (%s)\n",
			strerror(errno));
		return -1;
	}

	/* sanity check */
	if (len < sizeof(com)) {
		plog(logp, LOCATION, NULL,
			"Invalid header length of admin command.\n");
		return -1;
	}

	/* get buffer to receive */
	if ((combuf = malloc(com.ac_len)) == 0) {
		plog(logp, LOCATION, NULL,
			"failed to alloc buffer for admin command (%s)\n",
			strerror(errno));
		return -1;
	}

	/* get real data */
	while ((len = recv(so2, combuf, com.ac_len, 0)) < 0) {
		if (errno == EINTR)
			continue;
		plog(logp, LOCATION, NULL,
			"failed to recv admin command (%s)\n",
			strerror(errno));
		return -1;
	}

	/* don't fork() because of reloading config. */
	if (com.ac_cmd == ADMIN_RELOAD_CONF) {
		signal_handler(SIGHUP);
		goto end;
	}

	/* fork for processing */
	if (!(debug & DEBUG_ADMIN)) {
		pid_t pid;

		if ((pid = fork()) < 0) {
			plog(logp, LOCATION, NULL,
				"failed to fork for admin processing (%s)\n",
				strerror(errno));
			return -1;
		}

		/* parant's process. */
		if (pid != 0)
			goto end;

		/* child's process */
		admin_close();
	}

	admin_process(so2, combuf);

    end:
	(void)close(so2);
	if (combuf)
		free(combuf);

	return 0;
}

static int
admin_process(so2, combuf)
	int so2;
	char *combuf;
{
	struct admin_com *com = (struct admin_com *)combuf;
	vchar_t *buf = NULL;
	int error = 0;

	com->ac_errno = 0;

	switch (com->ac_cmd) {
	case ADMIN_RELOAD_CONF:
		/* don't entered because of proccessing it in other place. */
		plog(logp, LOCATION, NULL,
			"Why the way are you in.\n");
		goto bad;

	case ADMIN_SHOW_SCHED:
	{
		caddr_t p;
		int len;
		if (sched_dump(&p, &len) == -1)
			com->ac_errno = -1;
		buf = vmalloc(len);
		memcpy(buf->v, p, len);
	}
		break;
	case ADMIN_SHOW_SA:
	case ADMIN_FLUSH_SA:
	    {
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				buf = dumpph1(com->ac_proto);
				if (buf == NULL)
					com->ac_errno = -1;
				break;
			case ADMIN_FLUSH_SA:
				flushph1(com->ac_proto);
				break;
			}
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
			    {
				u_int p;
				p = admin2pfkey_proto(com->ac_proto);
				if (p == ~0)
					goto bad;
				buf = pfkey_dump_sadb(p);
				if (buf == NULL)
					com->ac_errno = -1;
			    }
				break;
			case ADMIN_FLUSH_SA:
				pfkey_flush_sadb(com->ac_proto);
				break;
			}
			break;

		case ADMIN_PROTO_INTERNAL:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				buf = NULL; /*XXX dumpph2(&error);*/
				if (buf == NULL)
					com->ac_errno = error;
				break;
			case ADMIN_FLUSH_SA:
				/*XXX flushph2();*/
				com->ac_errno = 0;
				break;
			}
			break;

		default:
			/* ignore */
			com->ac_errno = -1;
		}
	    }
		break;

	case ADMIN_DELETE_SA:
		break;

	case ADMIN_ESTABLISH_SA:
	    {
		struct sockaddr *dst;
		struct sockaddr *src;
		src = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->src;
		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
		    {
			struct remoteconf *rmconf;
			struct sockaddr *remote;
			struct sockaddr *local;

			/* search appropreate configuration */
			rmconf = getrmconf(dst);
			if (rmconf == NULL) {
				plog(logp, LOCATION, dst,
					"no configuration found "
					"for peer address.\n");
				com->ac_errno = -1;
				break;
			}

			/* get remote IP address and port number. */
			remote = dupsaddr(dst);
			if (remote == NULL) {
				com->ac_errno = -1;
				break;
			}
			_INPORTBYSA(remote) = _INPORTBYSA(rmconf->remote);

			/* get local address */
			local = dupsaddr(src);
			if (local == NULL) {
				com->ac_errno = -1;
				break;
			}
			_INPORTBYSA(local) = getmyaddrsport(local);

			YIPSDEBUG(DEBUG_INFO,
				plog(logp, LOCATION, local,
					"local address\n");
				plog(logp, LOCATION, remote,
					"remote address\n"));

			/* begin ident mode */
			if (isakmp_ph1begin_i(rmconf, remote) == NULL) {
				com->ac_errno = -1;
				break;
			}
		    }
			break;
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			break;
		default:
			/* ignore */
			com->ac_errno = -1;
		}
	    }
		break;

	default:
		plog(logp, LOCATION, NULL,
			"illegal command\n");
		com->ac_errno = -1;
	}

	if (admin_reply(so2, com, buf) < 0)
		goto bad;

	if (buf != NULL)
		vfree(buf);
	return 0;

    bad:
	if (buf != NULL)
		vfree(buf);
	return -1;
}

static int
admin_reply(so, combuf, buf)
	int so;
	struct admin_com *combuf;
	vchar_t *buf;
{
	int tlen;
	char *retbuf = NULL;

	if (buf != NULL)
		tlen = sizeof(*combuf) + buf->l;
	else
		tlen = sizeof(*combuf);

	retbuf = CALLOC(tlen, char *);
	if (retbuf == NULL) {
		plog(logp, LOCATION, NULL,
			"failed to allocate admin buffer (%s)\n",
			strerror(errno));
		return -1;
	}

	memcpy(retbuf, combuf, sizeof(*combuf));
	((struct admin_com *)retbuf)->ac_len = tlen;

	if (buf != NULL)
		memcpy(retbuf + sizeof(*combuf), buf->v, buf->l);

	tlen = send(so, retbuf, tlen, 0);
	free(retbuf);
	if (tlen < 0) {
		plog(logp, LOCATION, NULL,
			"failed to send admin command (%s)\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static u_int
admin2pfkey_proto(proto)
	u_int proto;
{
	switch (proto) {
	case ADMIN_PROTO_IPSEC:
		return SADB_SATYPE_UNSPEC;
	case ADMIN_PROTO_AH:
		return SADB_SATYPE_AH;
	case ADMIN_PROTO_ESP:
		return SADB_SATYPE_ESP;
	default:
		plog(logp, LOCATION, NULL,
			"Invalid proto for admin: %u\n", proto);
		return ~0;
	}
	/*NOTREACHED*/
}

int
admin_init()
{
	struct addrinfo hints, *res;
	char *paddr = "127.0.0.1";	/* XXX */
	char pbuf[10];
	int error;
	int tmp;

	snprintf(pbuf, sizeof(pbuf), "%d", lcconf->port_admin);
	memset(&hints, 0, sizeof(hints));
	switch (lcconf->default_af) {
	case 4:
		hints.ai_family = PF_INET;
		break;
	case 6:
		hints.ai_family = PF_INET6;
		break;
	default:
		hints.ai_family = PF_UNSPEC;
		break;
	}
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(paddr, pbuf, &hints, &res);
	if (error) {
		plog(logp, LOCATION, NULL,
			"getaddrinfo (%s)\n", gai_strerror(error));
		return -1;
	}
	if (res->ai_next) {
		/* warning */
		plog(logp, LOCATION, NULL,
			"resolved to multiple addresses, "
			"using the first one\n");
	}

	lcconf->sock_admin = socket(res->ai_family, res->ai_socktype, 0);
	if (lcconf->sock_admin < 0) {
		plog(logp, LOCATION, NULL,
			"socket (%s)\n", strerror(errno));
		freeaddrinfo(res);
		return -1;
	}

	tmp = 1;
	if (setsockopt(lcconf->sock_admin, SOL_SOCKET, SO_REUSEPORT,
		       (void *)&tmp, sizeof(tmp)) < 0) {
		plog(logp, LOCATION, NULL,
			"setsockopt (%s)\n", strerror(errno));
		(void)close(lcconf->sock_admin);
		freeaddrinfo(res);
		return -1;
	}

	if (bind(lcconf->sock_admin, res->ai_addr, res->ai_addrlen) < 0) {
		plog(logp, LOCATION, NULL,
			"bind (%s) port=%u\n",
			strerror(errno), lcconf->port_admin);
		(void)close(lcconf->sock_admin);
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);

	if (listen(lcconf->sock_admin, 5) < 0) {
		plog(logp, LOCATION, NULL,
			"listen (%s) port=%u\n",
			strerror(errno), lcconf->port_admin);
		(void)close(lcconf->sock_admin);
		return -1;
	}
	YIPSDEBUG(DEBUG_INFO,
		plog(logp, LOCATION, NULL,
			"open %s[%s] as racoon management.\n",
			paddr, pbuf));

	return 0;
}

int
admin_close()
{
	return(close(lcconf->sock_admin));
}

