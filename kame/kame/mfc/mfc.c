/*	$KAME: mfc.c,v 1.1 2001/07/11 08:36:59 suz Exp $	*/

/*
 * Copyright (C) 1999 WIDE Project.
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

#include "mfc.h"

int s;
static int mif2phyif[MAXMIFS];

static void usage __P((void));
static int get_mifi(mifi_t *,  int);
static void mfc_init(void);

mifi_t add_mif(const char *ifname);
void add_mfc(struct sockaddr *src, struct sockaddr *dst, mifi_t in, 
	     struct if_set *out);

int
main(int argc, char *argv[])
{
	if (argc != 2)
		usage();

	mfc_init();

	parse_conf(argv[1]);

	while (1)
		;
	/* NOTREACHED */
}

static void
mfc_init()
{
	int on;

	/* enable multicast routing */
	if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		errx(1, "socket");
	}
	on = 1;
	if (setsockopt(s, IPPROTO_IPV6, MRT6_INIT, &on, sizeof(on)) < 0) {
		errx(1, "MRT6_INIT %s", strerror(errno));
	}

	/* start mif management */
	bzero(mif2phyif, sizeof(mif2phyif));
	mif2phyif[0] = -1;
}

mifi_t
add_mif(const char *ifname)
{
	struct mif6ctl mif6c;
	int ifindex = 0;
	int err;

	bzero(&mif6c, sizeof(mif6c));
	ifindex = if_nametoindex(ifname);
	if (get_mifi(&mif6c.mif6c_mifi, ifindex) == 0)
		goto end; /* it's already registered */
	mif6c.mif6c_pifi = ifindex;
	mif6c.mif6c_flags = NULL;
	err =setsockopt(s, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6c, sizeof(mif6c)); 
	if (err != 0) {
		errx(1, "MRT6_ADD_MIF for %s failed: %s",
		     ifname, strerror(errno));
	}

end:
	return mif6c.mif6c_mifi;
}

void
add_mfc(struct sockaddr *src, struct sockaddr *dst, mifi_t in, 
	struct if_set *out)
{
	struct mf6cctl mf6c;

	bcopy(src, &mf6c.mf6cc_origin, sizeof(mf6c.mf6cc_origin));
	bcopy(dst, &mf6c.mf6cc_mcastgrp, sizeof(mf6c.mf6cc_mcastgrp));
	mf6c.mf6cc_parent = in;
	mf6c.mf6cc_ifset = *out;

	if (setsockopt(s, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6c, sizeof(mf6c)) < 0) {
		errx(1, "MRT6_ADD_MFC %s", strerror(errno));
	}
}


static int
get_mifi(mifi_t *mifi, int ifindex)
{
	int i;
	for (i = 0; i < MAXMIFS; i++) {
		/* found already allocated one */
		if (mif2phyif[i] == ifindex) {
			*mifi = i;
			return 0;
		}

		/* you have seeked all the registerd mifs */
		if (mif2phyif[i] == 0) {
			*mifi = i;
			mif2phyif[i] = ifindex;
			return i;
		}
	}
	errx(1, "too much mifs");
	return 0;
}


static void
usage()
{
	printf("usage: mfc (config-file)\n");
	exit(1);
}
