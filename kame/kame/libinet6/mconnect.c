/*	$KAME: mconnect.c,v 1.6 2001/11/13 12:38:46 jinmei Exp $ */

/*
 * Copyright (C) 2000 WIDE Project.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define MC_DEFAULT_INTERVAL 1000000 /* usec */
#define MILLION 1000000

static int mc_interval = MC_DEFAULT_INTERVAL;

struct conninfo {
	struct conninfo *conn_next;
	int conn_fd;		/* socket descriptor */
	int conn_status;	/* done, trying, or established */
	struct addrinfo *conn_ai;
};

enum {CONN_BEFORE, CONN_TRYING, CONN_ESTABLISHED, CONN_FAILED};

#ifdef MCONNECT_DEBUG
static void mc_dprint __P((struct addrinfo *, char *, int));
#endif

int
mconnect(ai0, errorp)
	struct addrinfo *ai0;
	int *errorp;
{
	struct addrinfo *ai;
	int n, s, error = 0, rest = 0;
	int flags, maxsock = -1, fdmasks = -1, connsock = -1;
	fd_set *rfdmaskp = NULL, *wfdmaskp = NULL;
	struct timeval timo;
	struct conninfo *conn0, *conn, *cnext, **cprev = &conn0;

	/* make intermediate structure to manage connection list */
	for (ai = ai0; ai != NULL; ai = ai->ai_next, rest++) {
		if ((conn = (struct conninfo *)malloc(sizeof(*conn)))
		    == NULL) {
			error = errno;
#ifdef MCONNECT_DEBUG
			mc_dprint(ai, "malloc", errno);
#endif
			continue;
		}

		if ((s = socket(ai->ai_family, ai->ai_socktype,
				ai->ai_protocol)) < 0) {
			error = errno;
#ifdef MCONNECT_DEBUG
			mc_dprint(ai, "socket", errno);
#endif
			free(conn);
			continue;
		}

		if ((flags = fcntl(s, F_GETFL, 0)) == -1) {
			error = errno;
#ifdef MCONNECT_DEBUG
			mc_dprint(ai, "fcntl(GET)", errno);
#endif
			free(conn);
			close(s);
			continue;
		}
		if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
			error = errno;
#ifdef MCONNECT_DEBUG
			mc_dprint(ai, "fcntl(SET)", errno);
#endif
			free(conn);
			close(s);
			continue;
		}

		if (maxsock == -1 || maxsock < s)
			maxsock = s;

		memset(conn, 0, sizeof(*conn));
		*cprev = conn;
		cprev = &conn->conn_next;
		conn->conn_ai = ai;
		conn->conn_fd = s;
		conn->conn_status = CONN_BEFORE;

#ifdef MCONNECT_DEBUG
		mc_dprint(ai, "registered", 0);
#endif
	}

	/* prepare fd_set for select(2) */
	fdmasks = howmany(maxsock + 1, NFDBITS) * sizeof(fd_mask);
	if ((rfdmaskp = (fd_set *)malloc(fdmasks)) == NULL ||
	    (wfdmaskp = (fd_set *)malloc(fdmasks)) == NULL) {
		error = errno;
#ifdef MCONNECT_DEBUG
		mc_dprint(NULL, "malloc(fdmask)", errno);
#endif
		goto done;	/* give up */
	}

	while(rest > 0) {
		int tried = 0;

		maxsock = -1;
		memset(rfdmaskp, 0, fdmasks);
		memset(wfdmaskp, 0, fdmasks);

		for (conn = conn0; conn; conn = conn->conn_next) {
			switch(conn->conn_status) {
			case CONN_FAILED:
				continue;
			case CONN_BEFORE:
				if (tried) /* only one attempt per loop */
					break;
				tried++;

				if (connect(conn->conn_fd,
					    conn->conn_ai->ai_addr,
					    conn->conn_ai->ai_addrlen) >= 0) {
					/*
					 * this happens if the server and the
					 * client are on the same node.
					 */
					conn->conn_status = CONN_ESTABLISHED;
					goto done;
				}

				if (errno != EINPROGRESS) { /* fatal error */
					error = errno;
#ifdef MCONNECT_DEBUG
					mc_dprint(conn->conn_ai, "connect",
						  errno);
#endif
					close(conn->conn_fd);
					conn->conn_status = CONN_FAILED;
					rest--;
					break;
				}
#ifdef MCONNECT_DEBUG
				mc_dprint(conn->conn_ai, "now trying", 0);
#endif
				conn->conn_status = CONN_TRYING;
				/* fall through */
			case CONN_TRYING:
				FD_SET(conn->conn_fd, rfdmaskp);
				FD_SET(conn->conn_fd, wfdmaskp);
				if (maxsock == -1 || maxsock < conn->conn_fd)
					maxsock = conn->conn_fd;
				break;
			default: /* impossible! */
#ifdef MCONNECT_DEBUG
				mc_dprint(NULL, "something odd", 0);
#endif
				goto done;
			}
		}

		if (maxsock == -1)
			break;	/* no need to call select() */

		timo.tv_usec = mc_interval % MILLION;
		timo.tv_sec = mc_interval / MILLION;
		n = select(maxsock + 1, rfdmaskp, wfdmaskp, NULL, &timo);

		if (n == 0)	/* timeout */
			continue; /* just try next one */

		for (conn = conn0; conn; conn = conn->conn_next) {
			if (conn->conn_status != CONN_TRYING)
				continue;

			if (FD_ISSET(conn->conn_fd, rfdmaskp) ||
			    FD_ISSET(conn->conn_fd, wfdmaskp)) {
				int n, error0 = 0;

				n = sizeof(error0);
				if (getsockopt(conn->conn_fd, SOL_SOCKET,
					       SO_ERROR, &error0, &n) < 0 ||
				    error0 != 0) {
					/* connect failed for this socket */
					error = error0 ? error0 : errno;
#ifdef MCONNECT_DEBUG
					mc_dprint(conn->conn_ai, "SO_ERROR",
						  error);
#endif
					close(conn->conn_fd);
					conn->conn_status = CONN_FAILED;
					rest--;
					break;
				}

				/* connection established */
#ifdef MCONNECT_DEBUG
				mc_dprint(conn->conn_ai,
					  "connection established", 0);
#endif
				conn->conn_status = CONN_ESTABLISHED;
				goto done;
			}
		}
	}

  done:
	if (rfdmaskp)
		free(rfdmaskp);
	if (wfdmaskp)
		free(wfdmaskp);

	for (conn = conn0; conn; conn = cnext) {
		cnext = conn->conn_next;

		switch(conn->conn_status) {
		case CONN_BEFORE:
		case CONN_TRYING:
			close(conn->conn_fd);
			break;
		case CONN_ESTABLISHED:
			connsock = conn->conn_fd;
			break;
		case CONN_FAILED:
			break;	/* already closed, nothing to do. */
		}

		free(conn);
	}

	if (connsock == -1 && errorp != NULL)
		*errorp = error;
	return(connsock);
}

#ifdef MCONNECT_DEBUG
static void
mc_dprint(ai, str, error)
	struct addrinfo *ai;
	char *str;
	int error;
{
	int ni_flags = 0;
	char hostbuf[NI_MAXHOST];

	ni_flags |= NI_NUMERICHOST;
	if (ai != NULL &&
	    getnameinfo(ai->ai_addr, ai->ai_addrlen, hostbuf, sizeof(hostbuf),
			NULL, 0, ni_flags)) {
		fprintf(stderr, "mc_dprint: getnameinfo failed\n");
		return;
	}

	fprintf(stderr, "mconnect: %s (host = %s, error = %s)\n",
		str,
		ai != NULL ? hostbuf : "none",
		error != 0 ? strerror(error) : "none");

	return;
}
#endif
