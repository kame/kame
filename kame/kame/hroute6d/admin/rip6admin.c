/* 
 * $Id: rip6admin.c,v 1.2 1999/10/26 09:05:42 itojun Exp $
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

#include "rip6adm.h"
#include "pathnames.h"

/* 
 * Takes the command line parameters and communicates appropriately
 * with the route6 daemon.
 */
int
main(int argc, char *argv[])
{
	int command;
	int pid;
	struct sigaction sig;

	bzero((void *)&sig, sizeof(sig));
	sig.sa_handler = (void *)cleanup;
	sig.sa_flags = 0;
	if (sigaction(SIGALRM, &sig, (struct sigaction *)NULL) < 0) {
		perror("sigaction");
		exit(1);
	}
	sig.sa_flags = 0;
	sig.sa_handler = (void *)cleanup;
	if (sigaction(SIGTERM, &sig, (struct sigaction *)NULL) < 0) {
		perror("sigaction");
		exit(1);
	}
	if ((command = parse(argc, argv)) < 0) {
		usage();
		exit(1);
	}
	switch (command) {
	case ADM_STAT:
	case ADM_TABLE:
		process_req();
		break;

	case ADM_SIGNAL:
		/* superuser permissions reqd. to send signals to route6d */
		if (getuid() != 0) {
			fprintf(stderr, "Permission denied\n");
			exit(1);
		}
		if ((pid = getroute6dpid()) == 0) {
			fprintf(stderr, "%s is not runnig.", PROGNAME);
			exit(1);
		}

		/* Send requested signal to route6d */
		if (kill(pid, sigval) < 0)
			perror("kill");
		break;

	case ADM_EXEC:
		if (getuid() != 0) {
			fprintf(stderr, "Permission denied\n");
			exit(1);
		}
		if ((pid = getroute6dpid()) != 0) {
			fprintf(stderr, "maybe %s is still alive\n", PROGNAME);
			exit(1);
		}
		execl(RT6_PATH, RT6_PATH, NULL);
		perror("start failed");
		break;
	}

	cleanup();
	exit(0);
}

/* 
 * Parse the command line to check for illegal usage or invalid
 * parameters. If the command is one of [restart | reset |
 * trace | stop] then identify the respective signal to be sent. For
 * stat or table the request is constructed.
 */
int
parse(int argc, char *argv[])
{
	int len = 0;
	int i;

	bzero((void *)&infodetail, sizeof(struct info_detail));
	if (argc < 2)
		return(-1);

	if (argc > 2) {
		if (((strcasecmp("table", argv[1])) != 0) || (argc > 4))
			return(-1);

		if (argc == 3 && (strcasecmp("default", argv[2]) != 0))
			return(-1);

		infodetail.id_type = ADM_TABLE;

		if (argc == 3) {
			len = infodetail.id_prflen = 128;
			bzero((void *)infodetail.id_addr.s6_addr,
			      sizeof(struct in6_addr));
			return (infodetail.id_type);
		} else {
			len = atoi(argv[3]);
			if (!(VALID_PREF_ADDR_LEN(len)))
				return (-1);
			infodetail.id_prflen = (u_char) len;
		}

		/* if request for entire routing table len is 0 */
		if (len == 0)
			bzero(&infodetail.id_addr, sizeof(struct in6_addr));
		else
			if ((inet_pton(AF_INET6, argv[2],
				       (void *)&(infodetail.id_addr))) != 1)
				return(-1);

		i = (len - 1) / 8 + 1;
		infodetail.id_addr.s6_addr[i - 1] &=
			((signed char)0x80 >> ((len - 1) % 8));
		for (; i < 16; i++)
			infodetail.id_addr.s6_addr[i] = 0;

		return(infodetail.id_type);
	}
	if ((strcasecmp("stat", argv[1])) == 0) {
		infodetail.id_type = ADM_STAT;
		return(infodetail.id_type);
	}
	if ((strcasecmp("restart", argv[1])) == 0) {
		sigval = SIGHUP;
		return(ADM_SIGNAL);
	}
	if ((strcasecmp("reset", argv[1])) == 0) {
		sigval = SIGINT;
		return(ADM_SIGNAL);
	}
	if ((strcasecmp("trace", argv[1])) == 0) {
		sigval = SIGUSR1;
		return(ADM_SIGNAL);
	}
	if ((strcasecmp("stop", argv[1])) == 0) {
		sigval = SIGTERM;
		return(ADM_SIGNAL);
	}
	if ((strcasecmp("start", argv[1])) == 0) {
		return(ADM_EXEC);
	}
	return (-1);
}

/* 
 * Display the correct usage
 */
void
usage(void)
{
	fprintf(stderr, "Usage : rip6admin [restart | reset | trace | stop]\n");
	fprintf(stderr, "\t\t  [stat] [table prefix prefixlen]\n\n");
	return;
}

/* 
 * Gets the process id of route6d from pid file
 */
int
getroute6dpid(void)
{
	FILE *fp;
	int pid = 0;

	if ((fp = fopen(RT6_PID, "r")) == NULL)
		return(0);
	fscanf(fp, "%d", &pid);
	fclose(fp);
	return(pid);
}

/* 
 * Send the request for statistics or routing table to route6d over
 * UNIX domain sockets.
 */
void
process_req(void)
{
	int sockfd, firstpkt = 1, numofentries, datalen, len, optval;
	u_char databuf[ADM_PKTSIZE];
	char prefstr[INET6_ADDRSTRLEN];
	char *offset, line[100], line2[100];
	struct sockaddr_un localsock, route6dsock;
	struct sockaddr_un src;
	struct statistic *stat;
	struct per_if_info *ifinfo;
	struct rt_table *rte;

	if ((sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return;
	}
	optval = ADM_BUFSIZE;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
		       (void *)&optval, sizeof(int))) {
		perror("setsockopt");
		return;
	}
	localsock.sun_family = AF_UNIX;

	/* 
	 * To allow multiple rip6admin commands to run, bind to a dynamically 
	 * constructed path.
	 */
	bzero((void *)udspath, PATH_MAX);
	sprintf(udspath, "%s%d", ADM_RIP6_ADM, getpid());
	strcpy(localsock.sun_path, udspath);
	if (bind(sockfd, (struct sockaddr *)&localsock,
		 sizeof(struct sockaddr_un))) {
		perror("bind");
		return;
	}
	route6dsock.sun_family = AF_UNIX;
	strcpy(route6dsock.sun_path, ADM_RIP6_UDS);

	if ((len = sendto(sockfd, &infodetail, sizeof(infodetail), 0,
	   (struct sockaddr *)&route6dsock, sizeof(struct sockaddr_un))) < 0
	    || len != (sizeof(infodetail))) {
		perror("sendto");
		return;
	}
	while (1) {
		len = sizeof(struct sockaddr_un);
		alarm(TIMEOUT);
		if ((datalen = recvfrom(sockfd, databuf, ADM_PKTSIZE, 0,
				      (struct sockaddr *)&src, &len)) < 0) {
			perror("recvfrom");
			return;
		}
		/* deactivate the alarm */
		alarm(0);
		/*
		 * End of data = packet of len 1 with ADM_EOF as the
                 * only char in it
		 */
		if (datalen == 1 && databuf[0] == ADM_EOF)
			break;

		numofentries = 0;
		switch (infodetail.id_type) {
		case ADM_STAT:
			/* 
			 * reply pkt. contain the global counts first
			 followed by per interface stats.
			 */
			if (firstpkt) {
				numofentries = (datalen - sizeof(struct statistic)) /
					sizeof(struct per_if_info);
				firstpkt = 0;
				if (datalen < sizeof(struct statistic))
					 return;
				stat = (struct statistic *)databuf;
				printf("Routes changed:\t%lu\n", stat->st_grccount);
				printf("Valid queries:\t%lu\n", stat->st_gqcount);
				offset = 0;
				offset = (char *)databuf + sizeof(struct statistic);
				ifinfo = (struct per_if_info *)offset;
				printf("Interface\t\tBad Pkts\t\tBad RTEs\t\tSndPkts\n");
			} else {
				numofentries = datalen / sizeof(struct per_if_info);
				ifinfo = (struct per_if_info *)databuf;
			}
			while (numofentries--) {
				printf("  %s\t\t\t", ifinfo->pi_ifname);
				printf("%lu\t\t\t", ifinfo->pi_badpkt);
				printf("%lu\t\t\t", ifinfo->pi_badrte);
				printf("%lu\n", ifinfo->pi_updates);
				ifinfo++;
			}
			break;

		case ADM_TABLE:
			numofentries = datalen / sizeof(struct rt_table);
			rte = (struct rt_table *)databuf;
			while (numofentries--) {
				if (inet_ntop(AF_INET6, (void *)&(rte->rt_dest),
					      prefstr, sizeof(prefstr)) == 0) {
					strcpy(line, "<<Incorrect data>>");
				} else
					sprintf(line, "%s/%d", prefstr,
						rte->rt_prflen);

				
				if (inet_ntop(AF_INET6, (void *)&(rte->rt_gway),
					      prefstr, sizeof(prefstr)) == 0) {
					strcpy(line2, "<<Incorrect data>>");
				} else
					strcpy(line2, prefstr);

				printf("%-43s %s\n", line, line2);
				printf("\t%-5s metric %d ",
				       rte->rt_ifname, rte->rt_metric);
				displayflg(rte->rt_flag);
				
				rte++;
			}
			break;
		}
	}
	close(sockfd);
	unlink(udspath);
	return;
}

/* 
 * Displays the flags corresponding to bits set.
 */
void
displayflg(int flag)
{
	int f = 0;
	int tryflag = 1;

	printf("< ");
	while (flag) {
		f = flag & tryflag;
		flag &= ~tryflag;
		tryflag <<= 1;
		switch (f) {
		case RTS6_CHANGED:
			printf("CHANGED ");
			break;
		case RTS6_STATIC:
			printf("STATIC ");
			break;
		case RTS6_DEFAULT:
			printf("DEFAULT ");
			break;
		case RTS6_KERNEL:
			printf("KERNEL ");
			break;
		case RTS6_LOOPBACK:
			printf("LOOPBACK ");
			break;
		case RTS6_INTERFACE:
			printf("INTERFACE ");
			break;
		case RTS6_PTOP:
			printf("PTOP ");
			break;
		}
	}
	printf(">\n");
	return;
}

void
cleanup(void)
{
	unlink(udspath);
	exit(1);
}
