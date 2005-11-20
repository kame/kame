/*      $KAME: msockwatch.c,v 1.2 2005/11/20 13:12:21 ryuji Exp $  */
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>
#include <net/mipsock.h>


void
main(int argc,char **argv) {
  	char msg[2056], addr_buf[256];
	int fd, n;
	struct mip_msghdr *miphdr;

	if ((fd = socket (PF_MOBILITY, SOCK_RAW, NULL)) < 0){ 
		perror("MIP sock: socket()"); 
		close(fd); 
		return; 
	}

  	while(1){
		memset(&msg, 0, sizeof(msg));
      		n = read(fd, &msg, sizeof(msg));
		if (n <= 0)
			continue;

		miphdr = (struct mip_msghdr *)msg;
		if (miphdr->miph_version != MIP_VERSION) {
			printf("unknown version number %d\n", miphdr->miph_version);
			continue;
		}

		switch(miphdr->miph_type) {
		case MIPM_BC_ADD:
		case MIPM_BC_UPDATE:
		case MIPM_BC_REMOVE: {

			struct mipm_bc_info *mipc;
			mipc = (struct mipm_bc_info *)msg;

			if (mipc->mipc_msglen < 
			    sizeof(struct mipm_bc_info) + sizeof(struct sockaddr_in6) * 3) {
				printf("received buffer size is small\n");
				break;
			}
			
			if (miphdr->miph_type == MIPM_BC_ADD)
				printf("** Binding Cache Add request **\n");
			else if (miphdr->miph_type == MIPM_BC_UPDATE)
				printf("** Binding Cache Update request **\n");
			else if (miphdr->miph_type == MIPM_BC_REMOVE)
				printf("** Binding Cache Remove request **\n");


			printf("Seq %d, Lifetime %d, Flags 0x%x\n", 
			       mipc->mipc_seqno, mipc->mipc_lifetime, mipc->mipc_flags);
			
			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPC_HOA(mipc))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("HoA %s\n", addr_buf);

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPC_COA(mipc))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("CoA %s\n", addr_buf);

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPC_CNADDR(mipc))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("DST %s\n", addr_buf);
			
			break;
		}
		case MIPM_BUL_ADD:
		case MIPM_BUL_UPDATE:
		case MIPM_BUL_REMOVE: {
			struct mipm_bul_info *mipu;

			mipu = (struct mipm_bul_info *)msg;
			if (mipu->mipu_msglen < 
			    sizeof(struct mipm_bul_info) + 
			    	sizeof(struct sockaddr_in6) * 3) {
				printf("received buffer size is small\n");
				break;
			}
			
			if (miphdr->miph_type == MIPM_BUL_ADD)
				printf("** Binding Update List Add request **\n");
			else if (miphdr->miph_type == MIPM_BUL_UPDATE)
				printf("** Binding Update List Update request **\n");
			else if (miphdr->miph_type == MIPM_BUL_REMOVE)
				printf("** Binding Update List Remove request **\n");

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPU_HOA(mipu))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("HoA %s\n", addr_buf);

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPU_COA(mipu))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("CoA %s\n", addr_buf);

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPU_PEERADDR(mipu))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("DST %s\n", addr_buf);
			
			break;
		}

		case MIPM_NODETYPE_INFO: {
			struct mipm_nodetype_info *nodei;
			char *nodetypes[] = {"MIP6_NODETYPE_NONE", 
					     "MIP6_NODETYPE_CORRESPONDENT_NODE", 
					     "MIP6_NODETYPE_HOME_AGENT", 
					     "MIP6_NODETYPE_MOBILE_NODE"};

			
			nodei = (struct mipm_nodetype_info *)msg;

		/*	printf("** Nodetype set request %s **\n", nodetypes[nodei->mipm_nodetype]);*/

			break;
		}
		case MIPM_HOME_HINT: {
			struct mipm_home_hint *hint;
			hint = (struct mipm_home_hint *)msg;

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)&hint->mipmhh_prefix[0])->sin6_addr, 
				  addr_buf, sizeof(addr_buf));
			
			printf("** Home Hint: ifindex %d, %s/%d **\n", 
			       hint->mipmhh_ifindex, addr_buf, hint->mipmhh_prefixlen);

			break;
		}

		case MIPM_BUL_FLUSH:
			printf("** BUL Flush request **\n");
			break;
		case MIPM_MD_INFO: {
			struct mipm_md_info *mdi;

			mdi = (struct mipm_md_info *)msg;
			
			switch(mdi->mipm_md_command) {
			case MIPM_MD_REREG:
				printf("** movememnt detection Re-Registration **\n");
				break;
			case MIPM_MD_DEREGHOME:
				printf("** movememnt detection De-Registration at Home **\n");
				break;
			case MIPM_MD_DEREGFOREIGN:
				printf("** movememnt detection De-Registration from Foreign **\n");
				break;
			case MIPM_MD_SCAN:
				printf("** movememnt detection Reset Router lifetime **\n");
				break;
			default:
				break;
			}

			switch(mdi->mipm_md_hint) {
			case MIPM_MD_INDEX:
				printf("%d\n", mdi->mipm_md_ifindex);
				break;
			case MIPM_MD_ADDR:

				memset(&addr_buf, 0, sizeof(addr_buf));
				inet_ntop(AF_INET6, 
					  &((struct sockaddr_in6 *)MIPD_HOA(mdi))->sin6_addr,
					  addr_buf, sizeof(addr_buf));
				printf("HoA: %s\n", addr_buf);
				       
				memset(&addr_buf, 0, sizeof(addr_buf));
				inet_ntop(AF_INET6, 
					  &((struct sockaddr_in6 *)MIPD_COA(mdi))->sin6_addr,
					  addr_buf, sizeof(addr_buf));
				printf("CoA: %s\n", addr_buf);
				
				break;
			default:
				break;
			}
			break;
		}

		case MIPM_RR_HINT: {
			struct mipm_rr_hint *rrhint;
			rrhint = (struct mipm_rr_hint *)msg;

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPMRH_HOA(rrhint))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("** Return Routability Hint of HoA %s for peer **", addr_buf);

			memset(&addr_buf, 0, sizeof(addr_buf));
			inet_ntop(AF_INET6, 
				  &((struct sockaddr_in6 *)MIPMRH_PEERADDR(rrhint))->sin6_addr,
				  addr_buf, sizeof(addr_buf));
			printf("%s\n", addr_buf);
 
			break;
		}
		default:
			break;
		}
	}

	return;
}
