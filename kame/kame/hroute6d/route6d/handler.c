/* 
 * $Id: handler.c,v 1.1 1999/08/08 23:29:46 itojun Exp $
 */

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

/* Copyright (c) 1997, 1998. Hitachi,Ltd.  All rights reserved. */
/* Hitachi Id: handler.c,v 1.3 1998/01/12 12:39:01 sumikawa Exp $ */

#include "defs.h"

extern int Nflag;

/* 
 * to release resources and restart route6d.
 */
void
sighup_handler(void)
{
	alarm(0);
	release_resources();	/* and also kernel_routes */
	execl(progname, progname, NULL);
	quit_route6d("restart failed");
}

/* 
 * to reset global counters.
 */
void
sigint_handler(void)
{
	struct interface *if_ptr;
	sigset_t sss;
	sigset_t oss;

	if (Nflag) {
		release_resources();
		exit(0);
	}

	sigemptyset(&sss);
	sigaddset(&sss, SIGALRM);
	sigprocmask(SIG_BLOCK, &sss, &oss);

	grc_counter = (u_long) 0;
	gq_counter = (u_long) 0;
	for (if_ptr = ifnet; if_ptr; if_ptr = if_ptr->if_next) {
		if_ptr->if_badpkt = 0;
		if_ptr->if_badrte = 0;
		if_ptr->if_updates = 0;
	}

	sigprocmask(SIG_SETMASK, &oss, NULL);	/* unblock */
	return;
}

/* 
 * to toggle the tracing of events.
 */
void
sigusr1_handler(void)
{
	rt6_trace = !(rt6_trace);
}

/* 
 * to release resources, flush kernel's routing table and exit route6d.
 */
void
sigterm_handler(void)
{
	alarm(0);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	release_resources();
	exit(1);
}
