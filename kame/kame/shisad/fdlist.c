/*	$KAME: fdlist.c,v 1.1 2004/12/09 02:18:33 t-momose Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <syslog.h>
#include <sys/queue.h>
#include "fdlist.h"

int fdlists;	/* # of elements */
SLIST_HEAD(fd_list_head, fd_list) fd_list_head;

struct pollfd fdl_fds[MAX_FDS];
int fdl_nfds;

void
fdlist_init()
{
	SLIST_INIT(&fd_list_head);
}

struct fd_list *
new_fd_list(fd, events, func)
	int fd;
	short events;
	int (*func)(int);
{
	struct fd_list *fdl;

	fdl = (struct fd_list *)malloc(sizeof(*fdl));
	if (fdl == NULL)
		return (NULL);

	memset(fdl, 0, sizeof(*fdl));
	fdl->pollfd.fd = fd;
	fdl->pollfd.events = events;
	fdl->func = func;

	SLIST_INSERT_HEAD(&fd_list_head, fdl, fdl_entry);
	fdlists++;
	
	pollfd_array();
	
	return (fdl);
}

void
delete_fd_list_entry(fd)
	int fd;
{
	struct fd_list *fdl;

	SLIST_FOREACH(fdl, &fd_list_head, fdl_entry) {
		if (fdl->pollfd.fd != fd)
			continue;

		SLIST_REMOVE(&fd_list_head, fdl, fd_list, fdl_entry);
		free(fdl);
		pollfd_array();
		return;
	}
}

int
pollfd_array()
{
	int i = 0;
	struct fd_list *fdl;

	SLIST_FOREACH(fdl, &fd_list_head, fdl_entry)
		fdl_fds[i++] = fdl->pollfd;

	fdl_nfds = i;
	return (i);
}

void
clear_revents()
{
	int i;

	for (i = 0; i < fdl_nfds; i++) {
		fdl_fds[i].revents = 0;
	}
}

void
dispatch_fdfunctions(fds, nfds)
	struct pollfd *fds;
	int nfds;
{
	int i;
	struct fd_list *fdl, *fdl_next;

	fdl = SLIST_FIRST(&fd_list_head);
	for (i = 0; i < nfds; i++) {
		fdl_next = SLIST_NEXT(fdl, fdl_entry);
		if ((fds[i].revents & fds[i].events) != 0) {
			if (fdl->func)
				(*fdl->func)(fdl->pollfd.fd);
		}
		fdl = fdl_next;
	}
}
