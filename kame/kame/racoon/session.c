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
/* YIPS @(#)$Id: session.c,v 1.4 2000/01/09 01:31:32 itojun Exp $ */

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

#ifdef IPV6_INRIA_VERSION
#include <netinet/ipsec.h>
#else
#include <netinet6/ipsec.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"

#include "schedule.h"
#include "session.h"
#include "grabmyaddr.h"
#include "cfparse.h"
#include "isakmp_var.h"
#include "admin_var.h"
#include "pfkey.h"
#include "handler.h"
#include "localconf.h"
#include "remoteconf.h"

static int set_signal __P((int sig, RETSIGTYPE (*func)()));
static int close_sockets __P((void));

static int sigreq = 0;

int
session(void)
{
	static fd_set mask0;
	int nfds = 0;
	fd_set rfds;
	struct timeval *timeout;
	int error;
	struct myaddrs *p;

	signal_handler(0);

	if (admin_init() < 0)
		exit(1);

	if (pfkey_init() < 0)
		exit(1);

	initmyaddr();
	setmyaddrtormconf();

	if (isakmp_init() < 0)
		exit(1);

	FD_ZERO(&mask0);

	FD_SET(lcconf->sock_admin, &mask0);
	nfds = (nfds > lcconf->sock_admin ? nfds : lcconf->sock_admin);
	FD_SET(lcconf->sock_pfkey, &mask0);
	nfds = (nfds > lcconf->sock_pfkey ? nfds : lcconf->sock_pfkey);
	FD_SET(lcconf->rtsock, &mask0);
	nfds = (nfds > lcconf->rtsock ? nfds : lcconf->rtsock);

	for (p = lcconf->myaddrs; p; p = p->next) {
		if (!p->addr)
			continue;
		FD_SET(p->sock, &mask0);
		nfds = (nfds > p->sock ? nfds : p->sock);
	}
	nfds++;

	/* initialize schedular */
	sched_init();

	sigreq = 0;
	while (1) {
		rfds = mask0;

		/*
		 * asynchronous requests via signal.
		 * make sure to reset sigreq to 0.
		 */
		switch (sigreq) {
		case SIGHUP:
			if (cfreparse()) {
				plog(logp, LOCATION, NULL,
					"configuration read failed");
				/* XXX exit ? */
				exit(1);
			}
			sigreq = 0;
			break;
		}

		/* scheduling */
		timeout = schedular();

		error = select(nfds, &rfds, (fd_set *)0, (fd_set *)0, timeout);
		if (error < 0) {
			switch (errno) {
			case EINTR:
				continue;
			default:
				plog(logp, LOCATION, NULL,
					"failed to select (%s)\n",
					strerror(errno));
				return -1;
			}
			/*NOTREACHED*/
		}

		if (FD_ISSET(lcconf->sock_admin, &rfds))
			admin_handler();

		for (p = lcconf->myaddrs; p; p = p->next) {
			if (!p->addr)
				continue;
			if (FD_ISSET(p->sock, &rfds))
				isakmp_handler(p->sock);
		}

		if (FD_ISSET(lcconf->sock_pfkey, &rfds))
			pfkey_handler();

		if (FD_ISSET(lcconf->rtsock, &rfds)) {
			if (lcconf->autograbaddr) {
				if (update_myaddrs()) {
					isakmp_close();
					grab_myaddrs();
					autoconf_myaddrsport();
					setmyaddrtormconf();
					isakmp_open();
				}
			} else
				(void)update_myaddrs();	/*dummy*/

			/* initialize socket list again */
			FD_ZERO(&mask0);
			nfds = 0;

			FD_SET(lcconf->sock_admin, &mask0);
			nfds = (nfds > lcconf->sock_admin
				? nfds : lcconf->sock_admin);
			FD_SET(lcconf->sock_pfkey, &mask0);
			nfds = (nfds > lcconf->sock_pfkey
				? nfds : lcconf->sock_pfkey);
			FD_SET(lcconf->rtsock, &mask0);
			nfds = (nfds > lcconf->rtsock
				? nfds : lcconf->rtsock);

			for (p = lcconf->myaddrs; p; p = p->next) {
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
	SIGHUP,
	SIGINT,
	SIGTERM,
	SIGUSR1,
	SIGUSR2,
	SIGCHLD,
	0
};

RETSIGTYPE
signal_handler(sig)
	int sig;
{
	int i;

	switch (sig) {
	case 0:
		for (i = 0; signals[i] != 0; i++)
			if (set_signal(signals[i], signal_handler) < 0) {
				plog(logp, LOCATION, NULL,
					"failed to set_signal (%s)\n",
					strerror(errno));
				exit(1);
			}
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
		plog(logp, LOCATION, NULL,
			"caught signal %d\n", sig);
		close_sockets();
		exit(1);
		break;
	}
}

static int
set_signal(sig, func)
	int sig;
	RETSIGTYPE (*func)();
{
	struct sigaction sa;

	memset((caddr_t)&sa, 0, sizeof(sa));
	sa.sa_handler = func;
	sa.sa_flags = SA_RESTART;

	if (sigemptyset(&sa.sa_mask) < 0)
		return -1;

	sigaction(sig, &sa, (struct sigaction *)0);

	return 0;
}

static int
close_sockets()
{
	isakmp_close();
	pfkey_close(lcconf->sock_pfkey);
	(void)admin_close();
	return 0;
}

