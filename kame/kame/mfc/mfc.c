/*	$KAME: mfc.c,v 1.6 2004/07/09 14:18:16 suz Exp $	*/

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

int s4 = -1, s6 = -1;
static int mif2phyif[MAXMIFS];
static int vif2phyif[MAXVIFS];

static void usage(void);
static int get_mifi(mifi_t *,  int);
static int get_vifi(mifi_t *,  int);
static void mfc_init(void);
static void ifname2addr(const char *, struct in_addr *);

mifi_t add_mif4(const char *ifname);
mifi_t add_mif6(const char *ifname);
mifi_t add_reg_mif6(void);
void add_mfc4(struct sockaddr *src, struct sockaddr *dst, mifi_t in, 
	      struct if_set *out);
void add_mfc6(struct sockaddr *src, struct sockaddr *dst, mifi_t in, 
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

	/* enable IPv4 multicast routing */
	if ((s4 = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0) {
		errx(1, "socket");
	}
	on = 1;
	if (setsockopt(s4, IPPROTO_IP, MRT_INIT, &on, sizeof(on)) < 0) {
		warn("IPv4 multicast is disabled");
	}

	/* enable IPv6 multicast routing */
	if ((s6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		errx(1, "socket");
	}
	on = 1;
	if (setsockopt(s6, IPPROTO_IPV6, MRT6_INIT, &on, sizeof(on)) < 0) {
		warn("IPv6 multicast is disabled");
	}

	/* start vif/mif management */
	bzero(mif2phyif, sizeof(mif2phyif));
	mif2phyif[0] = -1;
	bzero(vif2phyif, sizeof(vif2phyif));
	vif2phyif[0] = -1;
}

mifi_t
add_mif6(const char *ifname)
{
	struct mif6ctl mif6c;
	int ifindex = 0;
	int err;

	if (s6 < 0)
		errx(1, "IPv6 multicasting is disabled");
	bzero(&mif6c, sizeof(mif6c));
	ifindex = if_nametoindex(ifname);
	if (get_mifi(&mif6c.mif6c_mifi, ifindex) == 0)
		goto end; /* it's already registered */
	mif6c.mif6c_pifi = ifindex;
	mif6c.mif6c_flags = NULL;
	err = setsockopt(s6, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6c, sizeof(mif6c));
	if (err != 0) {
		errx(1, "MRT6_ADD_MIF for %s failed: %s",
		     ifname, strerror(errno));
	}

end:
	return mif6c.mif6c_mifi;
}

mifi_t
add_mif4(const char *ifname)
{
	struct vifctl vifc;
	int ifindex = 0;
	int err;

	if (s4 < 0)
		errx(1, "IPv4 multicasting is disabled");
	bzero(&vifc, sizeof(vifc));
	ifindex = if_nametoindex(ifname);
	if (get_vifi(&vifc.vifc_vifi, ifindex) == 0)
		goto end; /* it's already registered */
	ifname2addr(ifname, &vifc.vifc_lcl_addr);
	vifc.vifc_flags = NULL;
	vifc.vifc_threshold = 1;
	err = setsockopt(s4, IPPROTO_IP, MRT_ADD_VIF, &vifc, sizeof(vifc)); 
	if (err != 0) {
		errx(1, "MRT_ADD_VIF for %s failed: %s",
		     ifname, strerror(errno));
	}

end:
	return vifc.vifc_vifi;
}

mifi_t
add_reg_mif6(void)
{
	struct mif6ctl mif6c;
	int ifindex = 0;
	int err;

	if (s6 < 0)
		errx(1, "IPv6 multicasting is disabled");
	bzero(&mif6c, sizeof(mif6c));
	ifindex = if_nametoindex("lo0");
	if (get_mifi(&mif6c.mif6c_mifi, ifindex) == 0)
		goto end; /* it's already registered */
	mif6c.mif6c_pifi = ifindex;
	mif6c.mif6c_flags = MIFF_REGISTER;
	err =setsockopt(s4, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6c, sizeof(mif6c)); 
	if (err != 0) {
		errx(1, "MRT6_ADD_MIF for %s failed: %s",
		     "reg0", strerror(errno));
	}

end:
	return mif6c.mif6c_mifi;
}

void
add_mfc6(struct sockaddr *src, struct sockaddr *dst, mifi_t in, 
	 struct if_set *out)
{
	struct mf6cctl mf6c;

	if (s6 < 0)
		errx(1, "IPv6 multicasting is disabled");
	bcopy(src, &mf6c.mf6cc_origin, sizeof(mf6c.mf6cc_origin));
	bcopy(dst, &mf6c.mf6cc_mcastgrp, sizeof(mf6c.mf6cc_mcastgrp));
	mf6c.mf6cc_parent = in;
	mf6c.mf6cc_ifset = *out;

	if (setsockopt(s6, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6c, sizeof(mf6c)) < 0) {
		errx(1, "MRT6_ADD_MFC %s", strerror(errno));
	}
}

void
add_mfc4(struct sockaddr *src, struct sockaddr *dst, mifi_t in, 
	 struct if_set *out)
{
	struct mfcctl mfc;
	int i;

	if (s4 < 0)
		errx(1, "IPv4 multicasting is disabled");
	bcopy(&((struct sockaddr_in *)src)->sin_addr, &mfc.mfcc_origin,
	      sizeof(mfc.mfcc_origin));
	bcopy(&((struct sockaddr_in *)dst)->sin_addr, &mfc.mfcc_mcastgrp,
	      sizeof(mfc.mfcc_mcastgrp));
	mfc.mfcc_parent = in;
	for (i = 0; i < MAXVIFS; i++) {
		if (IF_ISSET(i, out))
			mfc.mfcc_ttls[i] = 32;
		else
			mfc.mfcc_ttls[i] = 0;
	}
	if (setsockopt(s4, IPPROTO_IP, MRT_ADD_MFC, &mfc, sizeof(mfc)) < 0) {
		errx(1, "MRT_ADD_MFC %s", strerror(errno));
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


static int
get_vifi(vifi_t *vifi, int ifindex)
{
	int i;
	for (i = 0; i < MAXVIFS; i++) {
		/* found already allocated one */
		if (vif2phyif[i] == ifindex) {
			*vifi = i;
			return 0;
		}

		/* you have seeked all the registerd mifs */
		if (vif2phyif[i] == 0) {
			*vifi = i;
			vif2phyif[i] = ifindex;
			return i;
		}
	}
	errx(1, "too much vifs");
	return 0;
}

static void
usage()
{
	printf("usage: mfc (config-file)\n");
	exit(1);
}

static void
ifname2addr(const char *ifname, struct in_addr *addr)
{
	struct ifaddrs *ifa, *ifap;

	bzero(addr, sizeof(*addr));
	getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		bcopy(&((struct sockaddr_in *) (ifa->ifa_addr))->sin_addr,
		      addr, sizeof(*addr));
		goto final;
	}

final:
	freeifaddrs(ifap);
	return;
}
