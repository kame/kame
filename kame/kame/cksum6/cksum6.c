/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#define MAXPACKET	8192

u_char packet[MAXPACKET];
int tcp, udp, icmp;
int all;
int debug;

main(argc, argv)
	char *argv[];
{
	int i;
	u_int a;
	int len = 0;
	int off;
	u_long cksum, oldsum;
	unsigned char buf[BUFSIZ], *p, *np;
	int ch;

	while ((ch = getopt(argc, argv, "ad")) != EOF) {
		switch (ch) {
		case 'a':
			all++;
			break;
		case 'd':
			debug++;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc) {
		fprintf(stderr, "too many arguments\n");
		exit(1);
	}

	i = 0;
#if 0
	while (scanf("%2x", &a) > 0)
		packet[i++] = a;
#else
	while (fgets((char *)buf, sizeof(buf), stdin)) {
		p = buf;
		for (;;) {
			while (*p && !isxdigit(*p))
				p++;
			if (*p == '\0')
				break;
			if (sscanf((char *)p, "%2x", &a) != 1) {
				printf("error in sscanf: \"%s\"\n", p);
				exit(1);
			}
			p += 2;
			packet[i++] = a;
		}
	}
#endif

	if (all) {
		off = 0;
		len = i;
	} else {
		off = 40;
		len = (packet[4] << 8) | packet[5];
	}
	switch (packet[6]) {
	case 6:
		tcp++;
		break;
	case 17:
		udp++;
		break;
	case 58:
		icmp++;
		break;
	default:
		printf("unknown proto %x\n", packet[6]);
		break;
	}
printf("off=%d, len=%d, input=%d, proto=%d\n", off, len, i, packet[6]);
	if (all) {
		cksum = in_cksum(packet, len);
	} else {
		u_char ipovly[40];
		bcopy(&packet[8], &ipovly[0], 32);
		ipovly[32] = 0;
		ipovly[33] = 0;
		ipovly[34] = packet[4];
		ipovly[35] = packet[5];
		ipovly[36] = 0;
		ipovly[37] = 0;
		ipovly[38] = 0;
		ipovly[39] = packet[6];
		bcopy(ipovly, (packet + off) - sizeof(ipovly), sizeof(ipovly));
		if (tcp) {
			oldsum = (packet[off + 16] << 8) + packet[off + 17];
			packet[off + 16] = packet[off + 17] = 0; /* clear check sum */
		} else if (udp) {
			oldsum = (packet[off + 6] << 8) + packet[off + 7];
			packet[off + 6] = packet[off + 7] = 0; /* clear check sum */
		} else if (icmp) {
			oldsum = (packet[off + 2] << 8) + packet[off + 3];
			packet[off + 2] = packet[off + 3] = 0; /* clear check sum */
		} else {
			printf("XXX\n");
			abort();
		}
		if (i < len)
			printf("SHORT PACKET!!\n");
		cksum = htons(in_cksum((packet + off) - sizeof(ipovly),
				       len + sizeof(ipovly)));
	}
	if (all)
		printf("checksum = %04x (~%04x)\n", cksum, (u_short)~cksum);
	else if (oldsum == cksum)
		printf("checksum = %04x\n", cksum);
	else
		printf("BAD checksum: %04x != %04x\n", oldsum, cksum);
	exit(0);
}


/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
in_cksum(addr, len)
	u_short *addr;
	int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

  if (debug) {
    u_char *p = (u_char *)addr;
    int i;
    printf("checksum packets: \n\t");
    for (i = 0; i < len; i++) {
	printf("%02x", p[i]);
	if (i % 16 == 15)
	    printf("\n\t");
	else if (i % 2 == 1)
	    printf(" ");
    }
    printf("\n");
  }
	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}
