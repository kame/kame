/*      $KAME: md.c,v 1.1 2004/12/09 02:18:50 t-momose Exp $  */
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

/* Sample of Movement Detector */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/mip6.h>
#include <net/mipsock.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int
usage(cmd)
	char *cmd;
{
	fprintf(stderr, "%s [-d] hoa coa\n", cmd);
}


int
main(argc, argv)
	int argc;
	char *argv[];
{
	int s;
	int len, command, i;
	char *hoa, *coa;
	size_t size;
	struct sockaddr_in6 sin_hoa, sin_coa;
	struct mipm_md_info *mdinfo;

	command = MIPM_MD_REREG;
	hoa = NULL;
	coa = NULL;

	for (i=1; i<argc; i++) {
		if (!strcmp("-d", argv[i])) {
			command = MIPM_MD_DEREGFOREIGN;
		} else
		if (hoa == NULL) {
			hoa = argv[i];
		} else
		if (coa == NULL) {
			coa = argv[i];
		} else {
			usage(argv[0]);
			exit(0);
		}
	}

	if (hoa == NULL || coa == NULL) {
		usage(argv[0]);
		exit(-1);
	}

	bzero(&sin_hoa, sizeof(sin_hoa));
	sin_hoa.sin6_family = AF_INET6;
	sin_hoa.sin6_len = sizeof(sin_hoa);
	inet_pton(AF_INET6, hoa , &sin_hoa.sin6_addr);
	
	bzero(&sin_coa, sizeof(sin_coa));
	sin_coa.sin6_family = AF_INET6;
	sin_coa.sin6_len = sizeof(sin_coa);
	inet_pton(AF_INET6, coa, &sin_coa.sin6_addr);
	
	size = sizeof(*mdinfo) + (sizeof(struct sockaddr_in6) * 2)/* hoa+coa */;
	if ((mdinfo = malloc(size)) == NULL) {
		perror("malloc");
		exit(-1);
	}
	bzero(mdinfo, size);
	mdinfo->mipm_md_hdr.miph_msglen = size;
	mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
	mdinfo->mipm_md_hdr.miph_type = MIPM_MD_INFO;
	mdinfo->mipm_md_hdr.miph_seq = random();
	mdinfo->mipm_md_hint = MIPM_MD_ADDR;
	mdinfo->mipm_md_command = MIPM_MD_REREG;
	
	s = socket(PF_MOBILITY, SOCK_RAW, 0);
	if (s < 0) {
		perror("socket");
		exit(-1);
	}

	memcpy(MIPD_HOA(mdinfo), &sin_hoa, sizeof(sin_hoa));
	memcpy(MIPD_COA(mdinfo), &sin_coa, sizeof(sin_coa));
	len = write(s, mdinfo, size);

	close(s);

	return (0);
}
