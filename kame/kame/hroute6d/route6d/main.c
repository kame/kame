/* 
 * $Id: main.c,v 1.1 1999/08/08 23:29:47 itojun Exp $
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

/*
 * Copyright(C)1997 by Hitachi, Ltd.
 */

#include "defs.h"
#include "globals.h"
#include "pathnames.h"

int  allocate_memory(void);
void set_fdvec(fd_set *fdvec);
void garbage_collect(void);

extern int Nflag;

/* 
 * starting function for route6d. It initializes the daemon, receives
 * input from sockets and calls appropriate functions.
 */
int
main(int argc, char **argv)
{
	int result, nfd, len, n;
	char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	fd_set fdvec;
	struct timeval timeout, *tptr;
	struct msghdr *mh;
	struct sockaddr_in6 rsrc, sa;
	struct in6_addr anyaddr = IN6ADDR_ANY_INIT;
	char ch;

	progname = argv[0];
        if ((prog = rindex(argv[0], '/')) == NULL)
                prog = argv[0];
        else
                prog++;

	initialize_dctlout();

	while ((ch = getopt(argc, argv, "CNdA:O:R:aDhnqsS")) != EOF) {
		switch (ch) {
#define	FLAG(c, flag, n)	case c: flag = n; break
			FLAG('C', Cflag, 1);
			FLAG('N', Nflag, 1);
			FLAG('d', dflag, 1);
#undef	FLAG
		default:
			fprintf(stderr, "unknown option\n");
			syslog(LOG_ERR, "%s: unknown option", RT6_CONFIGFILE);
			break;
		}
	}

	if (dflag)
		Nflag = 1;
	
	openlog(prog, LOG_NDELAY | LOG_PID, LOG_DAEMON);

	if ((trace_file_ptr = fopen(RT6_TRACEFILE, "w")) == NULL)
		syslog(LOG_ERR, "%s: %m", RT6_TRACEFILE);

	if (!Cflag) {
		initialize_pidfile();
		initialize_signals();
		initialize_cache();
	}
	if (initialize_interface())
		goto HALT;
	parse_config();
	if (Cflag)
		exit(0);

	if (!Nflag)
		daemon(0, 0);
	
	if ((rip6_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		quit_route6d("rip6_sock socket retry");

	bzero((char *)&sa, sizeof(sa));
	sa.sin6_len = sizeof(sa);
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(RIP6_PORT);
	sa.sin6_flowinfo = 0;
	sa.sin6_addr = anyaddr;	/* ANY */
	if (bind(rip6_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		quit_route6d("ripng bind another port");

	initialize_sockets();
	install_interface();
	install_routes();
	if (allocate_memory())
		goto HALT;

	/* What the hell is going on ?? */
	nfd = (admin_sock > rt6_sock) ? admin_sock : rt6_sock;
	nfd = ((nfd > rip6_sock) ? nfd : rip6_sock) + 1;

	send_request();

	scanning = 0;		/* enable timer */
	(void)gettimeofday(&nr_time, (struct timezone *)NULL);
	nt_time = nr_time;
	srandom((u_int) nr_time.tv_usec);

	/* my interface route should be advertised as soon as waking up */
	send_regular_update();	/* sendupdate=FALSE */

	alarminterval = TIMER_RATE + get_random_num(URANGE);
	nr_time.tv_sec += alarminterval;
	alarm(alarminterval);

	while (!halted) {
		if (garbage) {
			garbage = 0;
			garbage_collect();
		}
		if (sigusr2) {
			sigusr2 = 0;
			scanning = 1;
			if (scan_interface()) {
				halted = 1;
				break;
			}
			if (scanning == 0)
				timer();
			else
				scanning = 0;
		}
		(void)gettimeofday(&now_time, (struct timezone *)NULL);
		if (regular) {
			send_regular_update();
		}
		if (sendupdate && timercmp(&nt_time, &nr_time, <)) {
			/* need triggered update */
			timeout = nt_time;
			timevalsub(&timeout, &now_time);
			if (timeout.tv_sec < 0)	/* Do polling and return immediately */
				bzero((char *)&timeout, sizeof(struct timeval));
			tptr = &timeout;
		} else {
			/* regular update will occur while wait on select() */
			tptr = (struct timeval *)NULL;
			/* Wait forever on select() */
		}

		set_fdvec(&fdvec);
		result = select(nfd, &fdvec, NULL, NULL, tptr);

		if ((result < 0) && (errno == EINTR))
			continue;	/* go to the top of for(;;) */

		if ((result == 0) && sendupdate) {
			trigger_update();
			/* result is zero. so no fd is set */
			continue;
		}
		bzero((void *)rcv_data, max_datasize);

		if (FD_ISSET(rip6_sock, &fdvec) && (rcv_data != NULL)) {
			mh = &rmsgh;
			mh->msg_name = (char *)&rsrc;
			mh->msg_namelen = sizeof(rsrc);
			mh->msg_iov = &riov;
			mh->msg_iovlen = 1;
			mh->msg_control = cbuf;
			mh->msg_controllen = sizeof(cbuf);

			bzero(cbuf, sizeof(cbuf));
			((struct cmsghdr *)cbuf)->cmsg_len
				= CMSG_LEN(sizeof(struct in6_pktinfo));
			((struct cmsghdr *)cbuf)->cmsg_level = IPPROTO_IPV6;
			((struct cmsghdr *)cbuf)->cmsg_type = IPV6_PKTINFO;
			riov.iov_base = rcv_data;
			riov.iov_len = max_datasize;

			bzero(mh->msg_name, mh->msg_namelen);

			n = recvmsg(rip6_sock, mh, 0);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "recvmsg: UDP socket error: %m");
			} else
				process_rip6_msg(mh, n);
		}		/* process RIP */
		if (FD_ISSET(rt6_sock, &fdvec) && (rcv_data != NULL)) {
			n = recvfrom(rt6_sock, rcv_data, max_datasize, 0,
				     (struct sockaddr *)NULL, (int *)NULL);
			if (n < 0)
				syslog(LOG_ERR, "recvfrom: Route socket error: %m");
			else
				process_kernel_msg(rcv_data, n);
		}		/* process KERNEL */
		if (FD_ISSET(admin_sock, &fdvec) && (rcv_data != NULL)) {
			len = sizeof(admin_dest);
			n = recvfrom(admin_sock, rcv_data, max_datasize, 0,
				     (struct sockaddr *)&admin_dest, &len);
			if (n < 0)
				syslog(LOG_ERR, "recvfrom: UNIX socket error: %m");
			else
				process_admin_msg(rcv_data, n);
		}		/* process ADMIN */
	}			/* while(!halted) */

 HALT:
	WAIT_FOR_SIGHUP();
}

/* 
 * Reinitializes the interface structure and the routes to interface.
 */
int
scan_interface(void)
{
	static int scan_now = 0;	/* block interrupt */

	if (scan_now)
		return 0;
	scan_now = 1;

	if (initialize_interface()) {
		syslog(LOG_ERR, "init_interface failed");
		scan_now = 0;
		return -1;
	}
	install_interface();
	if (allocate_memory()) {
		syslog(LOG_ERR, "scan_interface: allocate failed");
		scan_now = 0;
		return -1;
	}
	scan_now = 0;
	return 0;
}

/* 
 * Clear and set the file descriptor set for select call.
 */
void
set_fdvec(fd_set * fdvec)
{
	FD_ZERO(fdvec);
	FD_SET(rip6_sock, fdvec);
	FD_SET(admin_sock, fdvec);
	FD_SET(rt6_sock, fdvec);
	return;
}

/* 
 * Initialises enough memory for data transmission.
 */
int
allocate_memory(void)
{
	struct interface *ifp;
	max_datasize = 0;
	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if ((ifp->if_flag & IFF_UP) && (ifp->if_lmtu > max_datasize))
			max_datasize = ifp->if_lmtu;
	}

	if (snd_data != NULL)
		free(snd_data);	/* re-initialize */

	if ((snd_data = malloc(max_datasize)) == NULL) {
		syslog(LOG_ERR, "sndbuf malloc failed %m");
		return -1;
	}
	if (rcv_data != NULL)
		free(rcv_data);	/* re-initialize */

	if ((rcv_data = malloc(max_datasize)) == NULL) {
		syslog(LOG_ERR, "rcvbuf malloc failed %m");
		return -1;
	}
	return 0;
}

/* 
 * Log & Quit
 */
void
quit_route6d(char *s)
{
	syslog(LOG_ERR, "%s: %m", s);
	syslog(LOG_ERR, "unrecoverable, QUIT");
	release_resources();
	exit(1);
}

/* 
 * delete timed-out routes from local cache (and kernel)
 */
void
garbage_collect(void)
{
	struct rt_plen *rtp, *temp;
	struct gateway *gwp;

	garbage = 0;
	for (gwp = gway; gwp; gwp = gwp->gw_next) {
		for (rtp = gwp->gw_dest; rtp;) {
			temp = rtp;
			rtp = rtp->rp_ndst;
			if ((temp->rp_state & (RTS6_KERNEL |
					       RTS6_STATIC |
					       RTS6_INTERFACE)) != 0)
				continue;
			if (temp->rp_timer > GARBAGE_TIME)
				delete_local_route(temp);
		}
	}
	return;
}
