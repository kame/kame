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
/* YIPS @(#)$Id: admin.c,v 1.2 2000/01/01 06:21:40 sakane Exp $ */

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
#include "vmbuf.h"
#include "schedule.h"
#include "isakmp.h"
#include "handler.h"
#include "cfparse.h"
#include "pfkey.h"
#include "admin.h"
#include "misc.h"
#include "debug.h"
#include "session.h"
#include "isakmp_var.h"

int sock_admin;
u_int port_admin = DEFAULT_ADMIN_PORT;

static int admin_process __P((int so2, char *combuf));
static u_int admin2pfkey_proto __P((u_int proto));

static char _addr1_[BUFADDRSIZE], _addr2_[BUFADDRSIZE]; /* for message */

int
admin_handler()
{
	int so2;
	struct admin_com com;
	char *combuf;
	int len;

    {
	struct sockaddr_storage from;
	int fromlen = sizeof(from);

	if ((so2 = accept(sock_admin, (struct sockaddr *)&from, &fromlen)) < 0){
		plog(LOCATION, "accept (%s)\n", strerror(errno));
		return -1;
	}
    }

	while ((len = recv(so2, (char *)&com, sizeof(com), MSG_PEEK)) < 0) {
		if (errno == EINTR) continue;
		plog(LOCATION, "recv (%s)\n", strerror(errno));
		return -1;
	}

	/* sanity check */
	if (len < sizeof(com)) {
		plog(LOCATION, "Invalid header length.\n");
		return -1;
	}

	/* get buffer to receive */
	if ((combuf = malloc(com.ac_len)) == 0) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		return -1;
	}

	/* get real data */
	while ((len = recv(so2, combuf, com.ac_len, 0)) < 0) {
		if (errno == EINTR) continue;
		plog(LOCATION, "recv (%s)\n", strerror(errno));
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
			plog(LOCATION, "fork (%s)\n", strerror(errno));
			return -1;
		}

		/* exit if parant's process. */
		if (pid != 0)
			goto end;

		/* child's process */
		(void)close(sock_admin);
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
		plog(LOCATION, "Why the way are you in.\n");
		goto bad;

	case ADMIN_SHOW_SCHED:
		if ((buf = sched_dump()) == NULL)
			com->ac_errno = -1;
		break;

	case ADMIN_SHOW_SA:
	case ADMIN_FLUSH_SA:
	    {
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				if ((buf = isakmp_dump_ph1sa(com->ac_proto)) == NULL)
					com->ac_errno = -1;
				break;
			case ADMIN_FLUSH_SA:
				isakmp_flush_ph1sa(com->ac_proto);
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
				if ((buf = pfkey_dump_sadb(p)) == NULL)
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
				if ((buf = pfkey_dump_pst(&error)) == NULL)
					com->ac_errno = error;
				break;
			case ADMIN_FLUSH_SA:
				pfkey_flush_pst();
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
			struct isakmp_conf *cfp;
			struct sockaddr *remote;
			struct sockaddr *local;

			/* search appropreate configuration */
			cfp = isakmp_cfbypeer(dst);
			if (cfp == NULL) {
				plog(LOCATION,
					"no configuration is found for peer address.\n");
				com->ac_errno = -1;
				break;
			}

			/* get remote IP address and port number. */
			GET_NEWBUF(remote, struct sockaddr *, dst, dst->sa_len);
			if (remote == NULL) {
				com->ac_errno = -1;
				break;
			}
			_INPORTBYSA(remote) = _INPORTBYSA(cfp->remote);

			/* get local address */
			GET_NEWBUF(local, struct sockaddr *, src, src->sa_len);
			if (local == NULL) {
				com->ac_errno = -1;
				break;
			}
			_INPORTBYSA(local) = isakmp_get_localport(local);

			YIPSDEBUG(DEBUG_INFO,
				GETNAMEINFO(local, _addr1_, _addr2_);
				plog(LOCATION, "local %s %s\n",
					_addr1_, _addr2_));
			YIPSDEBUG(DEBUG_INFO,
				GETNAMEINFO(remote, _addr1_, _addr2_);
				plog(LOCATION, "remote %s %s\n",
					_addr1_, _addr2_));

			/* begin ident mode */
			if (isakmp_begin_phase1(cfp, local, remote) == NULL) {
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
		plog(LOCATION, "illegal command\n");
		com->ac_errno = -1;
	}

    {
	int tlen;
	char *retbuf = NULL;

	if (buf != NULL)
		tlen = sizeof(struct admin_com) + buf->l;
	else
		tlen = sizeof(struct admin_com);

	if ((retbuf = malloc(tlen)) == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto bad;
	}

	memcpy(retbuf, com, sizeof(struct admin_com));
	((struct admin_com *)retbuf)->ac_len = tlen;

	if (buf != NULL)
		memcpy(retbuf + sizeof(struct admin_com), buf->v, buf->l);

	tlen = send(so2, retbuf, tlen, 0);
	free(retbuf);
	if (tlen < 0) {
		plog(LOCATION, "sendto (%s)\n", strerror(errno));
		goto bad;
	}
    }

	if (buf != NULL)
		vfree(buf);
	return 0;

    bad:
	if (buf != NULL)
		vfree(buf);
	return -1;
}

int
admin_init()
{
	struct addrinfo hints, *res;
	char pbuf[10];
	int error;
	int tmp;

	/*
	 * the admin port may be connected from outer world with
	 * any authentication.
	 * Anyhow unix domain socket is not good.
	 */
	snprintf(pbuf, sizeof(pbuf), "%d", port_admin);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(NULL, pbuf, &hints, &res);
	if (error) {
		plog(LOCATION, "getaddrinfo (%s)\n", gai_strerror(error));
		return -1;
	}
	if (res->ai_next) {
		plog(LOCATION, "resolved to multiple addresses, "
			"using the first one\n");
	}

	if ((sock_admin = socket(res->ai_family, res->ai_socktype, 0)) < 0) {
		plog(LOCATION, "socket (%s)\n", strerror(errno));
		freeaddrinfo(res);
		return -1;
	}

	tmp = 1;
	if (setsockopt(sock_admin, SOL_SOCKET, SO_REUSEPORT,
		       (void *)&tmp, sizeof(tmp)) < 0) {
		plog(LOCATION, "setsockopt (%s)\n", strerror(errno));
		close(sock_admin);
		return -1;
	}

	if (bind(sock_admin, res->ai_addr, res->ai_addrlen) < 0) {
		plog(LOCATION, "bind (%s) port=%u\n",
			strerror(errno), port_admin);
		(void)close(sock_admin);
		freeaddrinfo(res);
		return -1;
	}
	freeaddrinfo(res);

	if (listen(sock_admin, 5) < 0) {
		plog(LOCATION, "listen (%s) port=%u\n",
			strerror(errno), port_admin);
		(void)close(sock_admin);
		return -1;
	}
	YIPSDEBUG(DEBUG_INFO, plog(LOCATION,
	    "using port of %d as to manage daemon.\n", port_admin));

	return 0;
}

int
admin_close()
{
	return(close(sock_admin));
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
		plog(LOCATION,
			"Invalid proto for admin: %u\n", proto);
		return ~0;
	}
	/*NOTREACHED*/
}

