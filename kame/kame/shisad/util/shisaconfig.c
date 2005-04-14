/*      $KAME: shisaconfig.c,v 1.2 2005/04/14 06:22:36 suz Exp $  */
/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <net/if.h>
#include <net/if_dl.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip6.h>
#include <netinet/ip6mh.h>
#include <netinet/in_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <netinet6/mip6_var.h>
#include <net/mipsock.h>
#include <net/if_mip.h>

#include "callout.h"
#include "shisad.h"
#include "fsm.h"

static int bulk_get(char *);

void
usage() {
	printf("Usage: shisa [-g mipifname] (max # of entries is 10) \n");
	printf("       shisa [-d hoa peer]\n");
	printf("       shisa -f\n");
	exit(0);
}

int
main(int argc, char **argv) {
	int mipsock, err = 0;
	char buf[128];
	struct mip_msghdr *mipsockhdr;
	int ch;
	int command = 0;
	struct mipu_info *mipu;
	struct sockaddr_in6 hoa_s6, peer_s6;
	char *hoa = NULL, *peer = NULL, *ifname = NULL;

	if (argc <= 1) 
		usage();

	/* get options */
	while ((ch = getopt(argc, argv, "g:dfh.")) != -1) {
		switch (ch) {
		case 'g':
			ifname = optarg;
			return bulk_get(ifname);
		case 'd':
			command = MIPM_BULREMOVE;
			if (optind + 2 > argc) 
				usage();
			hoa = argv[optind++];
			peer = argv[optind];

			goto done;
		case 'f':
			command = MIPM_BULFLASH;
			goto done;
		case 'h':
			usage();
			exit(0);
		default:
			fprintf(stderr, "unknown option\n");
			usage();
			break;
		}
	}
 done:
	mipsock = socket(PF_MOBILITY, SOCK_RAW, 0);
        if (mipsock < 0) {
                perror("socket for MOBILITY");
                exit(-1);
        }

	memset(&buf, 0, sizeof(buf)); 

	switch (command) {
	case MIPM_BULREMOVE:
                mipu = (struct mipu_info *)buf;
		mipu->mipu_msglen = sizeof(buf);
		mipu->mipu_version = MIP_VERSION; 
		mipu->mipu_type = MIPM_BULREMOVE;
		mipu->mipu_seq = 3;

		hoa_s6.sin6_len = peer_s6.sin6_len = sizeof(struct sockaddr_in6);
		hoa_s6.sin6_family = peer_s6.sin6_family = AF_INET6;

		if (inet_pton(AF_INET6, hoa, &hoa_s6.sin6_addr) != 1) {
			fprintf(stderr, "%s is not correct address\n", hoa);
			exit(-1);
		}
		if (inet_pton(AF_INET6, peer, &peer_s6.sin6_addr) != 1) {
			fprintf(stderr, "%s is not correct address\n", peer);
			exit(-1);
		}

		/* buinfo->mipu_coa_ifname xxx */
		memcpy(MIPU_HOA(mipu), &hoa_s6, hoa_s6.sin6_len);
		memcpy(MIPU_PEERADDR(mipu), &peer_s6, peer_s6.sin6_len);

		err = write(mipsock, mipu, mipu->mipu_msglen);
		if (err == -1) {
			perror("write");
			return -1;
		}
		
		break;
	case MIPM_BULFLASH:
		mipsockhdr = (struct mip_msghdr *)buf;
		mipsockhdr->miph_msglen = sizeof(buf);
		mipsockhdr->miph_version = MIP_VERSION; 
		mipsockhdr->miph_type = MIPM_BULFLASH;
		mipsockhdr->miph_seq = 3;
		
		err = write(mipsock, mipsockhdr, mipsockhdr->miph_msglen);
		if (err == -1) {
			perror("write");
			return -1;
		}
		break;
	default:
		break;
	}
	return (0);

}

int
bulk_get(char *ifname) {
	struct if_bulreq bulreq;
	struct bul6info *bul6;
	int sock, i;
	char addrbuf[128];

	memset(&bulreq, 0, sizeof(bulreq));
	bulreq.ifbu_count = 0;
	bulreq.ifbu_len = sizeof(struct if_bulreq) + sizeof(struct bul6info) * 10;
	bulreq.ifbu_info = (struct bul6info *)malloc(sizeof(struct bul6info) * 10);
	
	strncpy(bulreq.ifbu_ifname, ifname, strlen(ifname));
	
	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return errno;
	}
	
	if (ioctl(sock, SIOGBULIST, &bulreq) < 0) { 
		perror("ioctl");
		return errno;
	} 
	
	printf("count %d\n", bulreq.ifbu_count);
	
	/* dump bul */
	for (i = 0; i < bulreq.ifbu_count; i ++) {
		bul6 = bulreq.ifbu_info + i * sizeof(struct bul6info);
		
		inet_ntop(AF_INET6, &bul6->bul_peeraddr, addrbuf, sizeof(addrbuf)); 
		printf("peer addr %s\n", addrbuf);
		
		inet_ntop(AF_INET6, &bul6->bul_hoa, addrbuf, sizeof(addrbuf)); 
		printf("hoa %s\n", addrbuf);
		
		inet_ntop(AF_INET6, &bul6->bul_coa, addrbuf, sizeof(addrbuf)); 
		printf("coa %s\n", addrbuf);
		
		printf("flags %d, ifindex %d\n", bul6->bul_flags, bul6->bul_ifindex);
	}

	
	return (0);
}



