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
/* YIPS @(#)$Id: session.c,v 1.2 1999/10/20 15:06:09 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(s)	((unsigned)(s) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(s)	(((s) & 255) == 0)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <errno.h>

#include <netkey/keyv2.h>

#include "var.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "pfkey.h"
#include "admin.h"
#include "handler.h"
#include "debug.h"
#include "cfparse.h"
#include "misc.h"
#include "session.h"
#include "schedule.h"

static int close_sockets __P((void));

static int sigreq = 0;

int session(void)
{
	static fd_set mask0;
	int nfds;
	fd_set rfds;
	struct timeval timeout, *tm;
	int num = 0;	/* number of entry in schedule */
	struct myaddrs *p;

	FD_ZERO(&mask0);

	FD_SET(sock_admin, &mask0);
	nfds = (nfds > sock_admin ? nfds : sock_admin);
	FD_SET(sock_pfkey, &mask0);
	nfds = (nfds > sock_pfkey ? nfds : sock_pfkey);
	FD_SET(rtsock, &mask0);
	nfds = (nfds > rtsock ? nfds : rtsock);

	for (p = myaddrs; p; p = p->next) {
		if (!p->addr)
			continue;
		FD_SET(p->sock, &mask0);
		nfds = (nfds > p->sock ? nfds : p->sock);
	}
	nfds++;

	/* initialize */
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;
	tm = &timeout;

	sigreq = 0;
	while (1) {
		rfds = mask0;

		/*
		 * asynchronous requests via signal.
		 * make sure to reset sigreq to 0.
		 */
		switch (sigreq) {
		case SIGHUP:
			if (re_cfparse()) {
				plog(LOCATION, "configuration read failed");
				exit(1);
			}
			sigreq = 0;
			break;
		}

		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0, tm) < 0) {
			YIPSDEBUG(DEBUG_NET, plog(LOCATION,
				"return select() with result-code=%d\n", errno));
			switch (errno) {
			case EINTR: continue;
			default:
				plog(LOCATION, "select (%s)\n", strerror(errno));
				return(-1);
			}
			/*NOTREACHED*/
		}

		if (FD_ISSET(sock_admin, &rfds)) {
			admin_handler();
		}

		for (p = myaddrs; p; p = p->next) {
			if (!p->addr)
				continue;
			if (FD_ISSET(p->sock, &rfds)) {
				isakmp_handler(p->sock);
			}
		}

		if (FD_ISSET(sock_pfkey, &rfds)) {
			pfkey_handler();
		}

		num = schedular(num);
		if (num > 0) {
			timeout.tv_sec = 1; /* XXX sufficient ? */
			timeout.tv_usec = 0;
			tm = &timeout;
		} else
		if (num == 0) {
			tm = 0;	/* do block mode to select. */
		} else {
			plog(LOCATION, "error in scheduling\n");
			return(-1);
		}

		if (FD_ISSET(rtsock, &rfds)) {
			if (autoaddr) {
				if (update_myaddrs()) {
					isakmp_close();
					grab_myaddrs();
					isakmp_autoconf();
					isakmp_open();
				}
			} else
				(void)update_myaddrs();	/*dummy*/

			/* initialize socket list again */
			FD_ZERO(&mask0);
			nfds = 0;

			FD_SET(sock_admin, &mask0);
			nfds = (nfds > sock_admin ? nfds : sock_admin);
			FD_SET(sock_pfkey, &mask0);
			nfds = (nfds > sock_pfkey ? nfds : sock_pfkey);
			FD_SET(rtsock, &mask0);
			nfds = (nfds > rtsock ? nfds : rtsock);

			for (p = myaddrs; p; p = p->next) {
				if (!p->addr)
					continue;
				FD_SET(p->sock, &mask0);
				nfds = (nfds > p->sock ? nfds : p->sock);
			}
			nfds++;
		}
	}
}

static int signals[] = {
SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGCHLD, 0
};

RETSIGTYPE signal_handler(int sig)
{
	int i;

	switch (sig) {
	case 0:
		for (i = 0; signals[i] != 0; i++)
			if (set_signal(signals[i], signal_handler) < 0)
				exit(-1);
		break;

	case SIGHUP:
		/*
		 * asynchronous requests will actually dispatched in the
		 * main loop in session().
		 */
		sigreq = sig;
		break;

	case SIGCHLD:
	    {
		pid_t pid;
		int s;

		pid = wait(&s);
	    }
		break;

	default:
		plog(LOCATION, "caught signal, %d\n", sig);
		close_sockets();
		exit(0);
		break;
	}
}

int
set_signal(sig, func)
	int sig;
	RETSIGTYPE (*func)();
{
	struct sigaction sa;

	memset((caddr_t)&sa, 0, sizeof(sa));
	sa.sa_handler = func;
	sa.sa_flags = SA_RESTART;

	if (sigemptyset(&sa.sa_mask) < 0) {
		perror("sigemptyset");
		return(-1);
	}

	sigaction(sig, &sa, (struct sigaction *)0);

	return(0);
}

static int
close_sockets()
{
	isakmp_close();
	pfkey_close(sock_pfkey);
	(void)admin_close();
	return 0;
}

