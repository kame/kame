/*
 * Copyright (C) 1999
 *	Sony Computer Science Laboratories, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: pvcbridge.c,v 1.1 2000/01/19 12:47:08 kjc Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <err.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <net/if_atm.h>

enum bridge_op { DELETE, ADD, GET };
static void usage(void);
static int pcr2str(int pcr, char *buf);

static void 
usage(void)
{
	fprintf(stderr, "usage: pvcbridge [add|delete] pvc_if1 pvc_if2\n");
	fprintf(stderr, "       pvcbridge [get] pvc_if\n");
	exit(1);
}

int verbose = 1;
int operation = GET;

int 
main(int argc, char **argv)
{
	struct pvcfwdreq pvcreq;
	struct pvctxreq pvctxreq, pvctxreq2;
	char *if_name, *if_name2;
	char speed[64], speed2[64];
	int s;

	if (argc < 2)
		usage();

	argc--; argv++;
	if (strcmp(*argv, "add") == 0) {
		operation = ADD;
		argc--; argv++;
	}
	else if (strcmp(*argv, "delete") == 0) {
		operation = DELETE;
		argc--; argv++;
	}
	if (strcmp(*argv, "get") == 0) {
		operation = GET;
		argc--; argv++;
	}

	if (argc > 0) {
		if_name = *argv;
		argc--; argv++;

		if (strncmp(if_name, "pvc", 3) != 0)
			usage();
			
		if (operation != GET && argc > 0) {
			if_name2 = *argv;
			argc--; argv++;

			if (strncmp(if_name2, "pvc", 3) != 0)
				usage();
		}
	}
	else
		usage();

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "can't open socket");

	pvcreq.pvc_ifname[IFNAMSIZ-1] = '\0';
	strncpy(pvcreq.pvc_ifname, if_name, IFNAMSIZ-1);

	if (operation != GET) {
		pvcreq.pvc_ifname2[IFNAMSIZ-1] = '\0';
		strncpy(pvcreq.pvc_ifname2, if_name2, IFNAMSIZ-1);
		pvcreq.pvc_op = operation;

		if (ioctl(s, SIOCSPVCFWD, &pvcreq) < 0)
			err(1, "SIOCSPVCFWD");

		if (operation == DELETE) {
			printf("pvc bridging %s <--> %s deleted\n",
			       pvcreq.pvc_ifname, pvcreq.pvc_ifname2);
			return (0);
		}
	}

	if (ioctl(s, SIOCGPVCFWD, &pvcreq) < 0)
		err(1, "SIOCSPVCFWD");

	/*
	 * print info
	 */
	if (pvcreq.pvc_ifname2[0] == '\0') {
		printf("pvc bridging is not set on %s\n",
		       pvcreq.pvc_ifname);
		return (0);
	}

	/*
	 * get tx info
	 */
	bzero(&pvctxreq, sizeof(pvctxreq));
	strncpy(pvctxreq.pvc_ifname, pvcreq.pvc_ifname, IFNAMSIZ-1);
	if (ioctl(s, SIOCGPVCTX, &pvctxreq) < 0)
		err(1, "SIOCSPVCTX");
	bzero(&pvctxreq2, sizeof(pvctxreq2));
	strncpy(pvctxreq2.pvc_ifname, pvcreq.pvc_ifname2, IFNAMSIZ-1);
	if (ioctl(s, SIOCGPVCTX, &pvctxreq2) < 0)
		err(1, "SIOCSPVCTX");

	pcr2str(pvctxreq.pvc_pcr, speed);
	pcr2str(pvctxreq2.pvc_pcr, speed2);
	printf("pvc bridging %s:[%d:%d](%s) <--> %s:[%d:%d](%s)\n",
	       pvcreq.pvc_ifname,
	       ATM_PH_VPI(&pvctxreq.pvc_aph),
	       ATM_PH_VCI(&pvctxreq.pvc_aph),
	       speed,
	       pvcreq.pvc_ifname2, 
	       ATM_PH_VPI(&pvctxreq2.pvc_aph),
	       ATM_PH_VCI(&pvctxreq2.pvc_aph),
	       speed2);
	close(s);

	return (0);
}

static int 
pcr2str(int pcr, char *buf)
{
	if (pcr < 0)
		sprintf(buf, "invalid\n");
	else if (pcr == 0)
		sprintf(buf, "full speed");
	else if (pcr < 1000)
		sprintf(buf, "%dbps", pcr * 48 * 8);
	else if (pcr < 1000000)
		sprintf(buf, "%.2fKbps", (double)pcr * 48 * 8 / 1000);
	else
		sprintf(buf, "%.2fMbps", (double)pcr * 48 * 8 / 1000000);
	return (strlen(buf));
}
