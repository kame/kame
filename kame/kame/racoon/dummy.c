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
/* YIPS @(#)$Id: dummy.c,v 1.1 1999/08/08 23:31:20 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/pfkeyv2.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "var.h"
#include "pfkey.h"
#include "debug.h"

static u_int32_t getseq _P((void));
static struct samsghdr *create_msg __P((u_long, u_long));

Usage(pname)
	char *pname;
{
	printf("Usage: %s (pfkey port) (my address) (peer address) (peer port)\n", pname);
}

main(ac, av)
	int ac;
	char **av;
{
	u_int lport, pport;
	u_long maddr, paddr;

	if (ac != 5) {
		Usage(av[0]);
		exit(1);
	}

	lport = atoi(av[1]);
	maddr = ntohl(inet_addr(av[2]));
	paddr = ntohl(inet_addr(av[2]));
	pport = atoi(av[3]);

	printf("send to %d, src=%08x, dst=%08x:%d\n",
	    lport, maddr, paddr, pport);

	sendit(lport, maddr, paddr, pport);
}

sendit(lport, maddr, paddr, pport)
	u_int lport, pport;
	u_long maddr, paddr;
{
	struct samsghdr *buf;
	int tlen;
	int so, len;
	struct sockaddr_in from, to;

	buf = create_msg(maddr, paddr);

	if ((so = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return(-1);
	}

	memset((char *)&from, 0, sizeof(from));
	from.sin_family = AF_INET;
	from.sin_port = htons((u_short)0);
	from.sin_addr.s_addr = htonl(0x7f000001);
	from.sin_len = sizeof(from);

	memset((char *)&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons((u_short)lport);
	to.sin_addr.s_addr = htonl(0x7f000001);
	to.sin_len = sizeof(to);

	if ((len = sendto(so, (char *)buf, buf->len,
	                  0, (struct sockaddr *)&to, sizeof(to))) < 0) {
		perror("sendto");
		return(-1);
	}
}

static struct samsghdr *
create_msg(maddr, paddr)
	u_long maddr, paddr;
{
	struct sockaddr src, dst;
	int buflen;
	int addrlen = SA_HSIZE_OPT + sizeof(struct sockaddr);
	struct samsghdr *mh;
	char *bp;
	struct samsgopt mo;
	u_int8_t *curopt;

	memset((caddr_t)&src, 0, sizeof(src));
	((struct sockaddr_in *)&src)->sin_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&src)->sin_family = PF_INET;
	((struct sockaddr_in *)&src)->sin_port = 0;
	((struct sockaddr_in *)&src)->sin_addr.s_addr = htonl(maddr);

	memcpy((caddr_t)&dst, (caddr_t)&src, sizeof(dst));
	((struct sockaddr_in *)&dst)->sin_addr.s_addr = htonl(paddr);

	buflen = sizeof(struct samsghdr);
	buflen += (addrlen * 2);
#if 0
	if (is_myaddr(src))
		buflen += (addrlen * 2);
#endif

	if ((mh = CALLOC(buflen, struct samsghdr *)) == 0) {
		perror("calloc");
		return(0);
	}

	/* make header of SA_ACUIRE */
	mh->len        = buflen;
	mh->cmd        = SA_ACQUIRE;
	mh->errno      = 0;
	mh->state      = SA_SPAWN;
	mh->type       = SA_TYPE_ESP;
	mh->mode       = 0;           /* XXX: any */
	mh->dir        = SA_OUTBOUND;
	mh->nextpr     = SA_OPT_SRCADDR;

	bp = (char*)mh + sizeof(struct samsghdr);
	curopt = &mh->optid_next;

#define COPYOPTDATA(ptr,type,len) \
  if ((ptr)) { \
    bzero((char*)&mo, sizeof(struct samsgopt)); \
    *curopt = type; \
    curopt = &((struct samsgopt_h *)bp)->optid_next; \
    mo.h.optlen = len; \
    bcopy((char*)&mo, bp, SA_HSIZE_OPT); \
    bp += SA_HSIZE_OPT; \
    bcopy((ptr), bp, mo.h.optlen); \
    bp += mo.h.optlen; \
  }

	COPYOPTDATA(&dst, SA_OPT_DSTADDR, dst.sa_len);
	COPYOPTDATA(&src, SA_OPT_SRCADDR, src.sa_len);
#if 0
	COPYOPTDATA(&pxd, SA_OPT_DSTPROXY, pxd.sa_len);
	COPYOPTDATA(&pxs, SA_OPT_SRCPROXY, pxs.sa_len);
#endif

#undef COPYOPTDATA(ptr,type,len)

	return(mh);
}

static u_int32_t
getseq()
{
	struct timeval tp;

	gettimeofday(&tp, 0);

	return(tp.tv_usec);
}
