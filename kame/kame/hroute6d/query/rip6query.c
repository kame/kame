/* 
 * $Id: rip6query.c,v 1.2 1999/10/26 09:05:43 itojun Exp $
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
 * Copyright(C)1997 by Hitach, Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "route6d.h"

/* local defines */
#define WTIME		6	/* Time to wait for each response */
#define ERROR		-1
#define MAXPACKETSIZE	9600	/* ad hoc */

/* forward references */
int validate_arguments(int, char **);
void send_query(void);
void process_response(struct sockaddr_in6 *, int);
void start_timer(void);
void timeout(void);
void exit_query(void);

/* private variables declarations */
int s;
int timedout;
char *target_router;
struct in6_addr tgt_r;
char *target_prefix;
struct in6_addr tgt_p;
int prefix_len;
int response_flag = 0;
char packet[MAXPACKETSIZE];

int
main(int argc, char *argv[])
{
	int cc;
	struct sockaddr_in6 from6;
	int from6len = sizeof(from6), size = 10240;	/* ad hoc */

	if (validate_arguments(argc, argv) == ERROR) {
		fprintf(stderr,
			"Usage : %s target-router [target-prefix]\n", argv[0]);
		exit(1);
	}
	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		exit(1);
	}
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
		perror("setsockopt SO_RCVBUF");

	send_query();
	start_timer();

	while (!timedout) {
		cc = recvfrom(s, packet, MAXPACKETSIZE, 0,
			      (struct sockaddr *)&from6, &from6len);
		if (cc <= 0) {
			if (errno != EINTR) {
				perror("recvfrom");
				exit_query();
			}
		} else {
			alarm(WTIME);
			process_response((struct sockaddr_in6 *)&from6, cc);
		}
	}
	if (!response_flag)
		printf("No Response\n");
	close(s);
	exit(0);
}

/* 
 * Func: start_timer
 * Desc: Start signal handlers for SIGTERM and SIGALRM
 */
void
start_timer(void)
{
	struct sigaction sigact, sigter;

	(void)bzero((void *)&sigter, sizeof(struct sigaction));
	sigter.sa_handler = exit_query;
	sigter.sa_flags = 0;	/* For no RESTART */
	if (sigaction(SIGTERM, &sigter, (struct sigaction *)NULL) == -1)
		perror("sigterm");

	bzero((void *)&sigact, sizeof(struct sigaction));
	sigact.sa_handler = timeout;
	sigact.sa_flags = 0;	/* For no RESTART */
	if (sigaction(SIGALRM, &sigact, (struct sigaction *)NULL) == -1)
		perror("sigaction");

	alarm(WTIME);
	return;
}

/* 
 * Func: send_query
 * Desc: Constructs and sends query to the target router
 */
void
send_query(void)
{
	struct sockaddr_in6 router;
	register struct rip6 *msg = (struct rip6 *)packet;

	bzero((char *)&router, sizeof(router));
	router.sin6_addr = tgt_r;	/* struct copy */
	router.sin6_family = AF_INET6;
	router.sin6_port = htons(RIP6_PORT);

	msg->rip6_cmd = RIP6_REQUEST;
	msg->rip6_ver = RIP6_VERSION;

	if (prefix_len == 0) {
		bzero((void *)&(msg->rip6_rte[0].rip6_addr),
		      sizeof(struct in6_addr));
		msg->rip6_rte[0].rip6_metric = HOPCOUNT_INFINITY;
		msg->rip6_rte[0].rip6_prflen = 0;
	} else {
		msg->rip6_rte[0].rip6_addr = tgt_p;	/* struct copy */
		msg->rip6_rte[0].rip6_prflen = prefix_len;
	}

	if (sendto(s, packet, sizeof(struct rip6), 0,
		    (struct sockaddr *)&router, sizeof(router)) < 0) {
		perror("sendto");
		exit_query();
	}
	return;
}

/* 
 * Func: process_response
 * Desc: Process the received packet
 */
void
process_response(struct sockaddr_in6 *from6, int size)
{
	struct rip6 *msg;
	struct route_entry *re;
	char str1[INET6_ADDRSTRLEN];

#ifdef DEBUG_QUERY
	printf("Inside process_response()..\n");
#endif

	msg = (struct rip6 *)packet;

	if (msg->rip6_cmd != RIP6_RESPONSE) {
		printf("Not a response packet...\n");
		return;
	}
	/* No need to check source address */
	/* Destination == (myaddr,myport) is enough */

	response_flag = 1;

	re = msg->rip6_rte;
	size = size - (sizeof(struct rip6) - sizeof(struct route_entry));

	while (size >= sizeof(struct route_entry)) {
		if (re->rip6_metric == (u_char) 0xff &&
		    re->rip6_rtag == 0 &&
		    re->rip6_prflen == 0) {
			/* This is a Next Hop entry */
			/* ... REALLY?? */
			inet_ntop(AF_INET6, (void *)(re->rip6_addr.s6_addr),
				  str1, INET6_ADDRSTRLEN);
			printf("NextHop %-46s\n", str1);
		} else {
			inet_ntop(AF_INET6, (void *)(re->rip6_addr.s6_addr),
				  str1, INET6_ADDRSTRLEN);
			printf("%-46s", str1);
			printf("/%-3d", re->rip6_prflen);
			printf(" metric %2d", re->rip6_metric);
			printf(" routetag %04X\n", re->rip6_rtag);
		}
		size -= sizeof(struct route_entry);
		re++;
	}
	return;
}

/* 
 * Func: timeout
 * Desc: timer function for SIGALRM signal
 */
void
timeout(void)
{
	timedout = 1;
}

/* 
 * Func: exit_query
 * Desc: Function to exit from the rip6query module
 */
__dead void
exit_query(void)
{
	if (!response_flag)
		printf("No response from the target router\n");
	close(s);
	exit(1);
}

/* 
 * Func: validate_arguments
 * Desc: Function to validate the command line arguments
 * INs : int argc, char *argv[]
 * ret : ERROR/1
 * Call: None
 */
int
validate_arguments(int argc, char *argv[])
{
	int auth_flag = 0;

	if (argc != 2 && argc != 4 && argc != 6) {
#ifdef DEBUG_QUERY
		printf("Number of arguments are wrong..\n");
#endif
		return ERROR;
	}
	if (strcmp(argv[1], "-auth") == 0) {
		auth_flag = 1;
		if (argc == 2) {
#ifdef DEBUG_QUERY
			printf("Authentication Key value missing..\n");
#endif
			return ERROR;
		}
	}
	switch (argc) {
	case 2:
		target_router = argv[1];
		prefix_len = 0;
		break;
	case 4:
		if (auth_flag) {
			target_router = argv[3];
			prefix_len = 0;
		} else {
			target_router = argv[1];
			target_prefix = argv[2];
			prefix_len = atoi(argv[3]);
			if (inet_pton(AF_INET6, target_prefix,
				      (void *)(tgt_p.s6_addr)) != 1) {
#ifdef DEBUG_QUERY
				printf("target prefix validation fails..\n");
#endif
				fprintf(stderr,
					"Error!! Invalid target prefix\n");
				return ERROR;
			}
		}
		break;
	case 6:
		if (!auth_flag)
			return ERROR;
		target_router = argv[3];
		target_prefix = argv[4];
		prefix_len = atoi(argv[5]);
		if (inet_pton(AF_INET6, target_prefix,
			      (void *)(tgt_p.s6_addr)) != 1) {
#ifdef DEBUG_QUERY
			printf("[auth] target prefix validation fails..\n");
#endif
			fprintf(stderr, "Error!! Invalid target prefix\n");
			return ERROR;
		}
		break;
	default:
		return ERROR;
	}
#ifdef DEBUG_QUERY
	printf("target %s\n", target_router);
#endif

	if (inet_pton(AF_INET6, target_router, (void *)(tgt_r.s6_addr)) != 1) {
		struct hostent *hp;
		int i;
#ifdef DEBUG_QUERY
		printf(" hostname lookup ...");
#endif
		if ((hp = gethostbyname2(target_router, AF_INET6)) == NULL) {
			fprintf(stderr,
				"Error!! Invalid target router address\n");
			return ERROR;
		}
#ifdef DEBUG_QUERY
		printf(" found %s\n", hp->h_name);
#endif
		if (hp->h_addrtype != AF_INET6) {
			fprintf(stderr, "Error No INET6 address\n");
			return ERROR;
		}
		for (i = 0; i < hp->h_length; i++)
			tgt_r.s6_addr[i] = hp->h_addr[i];
#ifdef DEBUG_QUERY
		printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		       tgt_r.s6_addr[0] , tgt_r.s6_addr[1] , tgt_r.s6_addr[2],
		       tgt_r.s6_addr[3] , tgt_r.s6_addr[4] , tgt_r.s6_addr[5],
		       tgt_r.s6_addr[6] , tgt_r.s6_addr[7] , tgt_r.s6_addr[8],
		       tgt_r.s6_addr[9] , tgt_r.s6_addr[10], tgt_r.s6_addr[11],
		       tgt_r.s6_addr[12], tgt_r.s6_addr[13], tgt_r.s6_addr[14],
		       tgt_r.s6_addr[15]);
#endif
	}
	return 1;
}
