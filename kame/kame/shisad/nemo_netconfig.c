/*      $KAME: nemo_netconfig.c,v 1.10 2005/03/10 23:43:26 t-momose Exp $  */
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/mipsock.h>
#include <net/if_dl.h>
#include <netinet/ip6mh.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#define MODE_HA 0x01
#define MODE_MR 0x02

#define NEMO_TUNOPTNUM 3
#define NEMO_TUNNAME "nemo"

#define NEMO_OPTNUM_MCOA 5
#define NEMO_OPTNUM 4

#include "callout.h"
#include "shisad.h"

/* Variables */
struct nemo_if {
	LIST_ENTRY(nemo_if) nemo_ifentry;
	char ifname[IFNAMSIZ];
	struct in6_addr hoa;
	struct in6_addr coa;
	u_int16_t bid;
};
LIST_HEAD(nemo_if_head, nemo_if) nemo_ifhead;

struct nemo_mnpt {
	LIST_ENTRY(nemo_mnpt) nemo_mnptentry;
	struct in6_addr hoa;
	struct in6_addr nemo_prefix;
	int nemo_prefixlen;
	u_int16_t bid;
	struct nemo_if *nemo_if;
};
LIST_HEAD(nemo_mnpt_head, nemo_mnpt) nemo_mnpthead;

int mode;
int debug = 0;
int foreground = 0;
int numerichost = 1;
int staticmode = 0;
int multiplecoa = 0;

/* Functions */
static int set_nemo_ifinfo();
static void mainloop();
static void nemo_terminate(int);
static int ha_parse_ptconf(char *);
static int mr_parse_ptconf(char *);
static struct nemo_if *find_nemo_if_from_name(char *);
static void set_static_tun(char *);
static struct nemo_if *nemo_setup_forwarding (struct sockaddr *, struct sockaddr *, 
					      struct in6_addr *, u_int16_t);
static struct nemo_if *nemo_destroy_forwarding(struct in6_addr *, u_int16_t);
static void nemo_dump();

void
nemo_usage() {
	fprintf(stderr, "nemonetd -d -D -M [-h or -m] -f prefix_table.conf -t static_tun.conf\n");
	fprintf(stderr, "\t-d: Verbose Debug messages \n");
	fprintf(stderr, "\t-D: Verbose Debug messages + foreground\n");
	fprintf(stderr, "\t-h: when Home Agent\n");
	fprintf(stderr, "\t-m: when Mobile Router\n");
	fprintf(stderr, "\t-M: Multiple CoA Registration Support\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Note: If prefixtable is not specified, ");
	fprintf(stderr, "nemonetd will read /etc/prefix_table.conf\n");

	exit(0);
}

int
main (argc, argv)
	int argc;
	char **argv;
{
	char *pt_filename = NULL, *tun_filename = NULL;
	int ch = 0;
	int if_number = 0, pt_number = 0;
	struct nemo_if *nif;
	struct nemo_mnpt *npt;
	
	LIST_INIT(&nemo_mnpthead);
	LIST_INIT(&nemo_ifhead);

	mode = 0;
	while ((ch = getopt(argc, argv, "dDMnhmf:t:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'D':
			debug = 1;
			foreground = 1;
			break;
		case 'n':
			numerichost = 1;
			break;
		case 'M':
			multiplecoa = 1;
			break;
		case 'h':
			mode = MODE_HA;
			break;
		case 'm':
			mode = MODE_MR;
			break;
		case 'f':
			pt_filename = optarg;
			break;
		case 't':
			tun_filename = optarg;
			staticmode = 1;
			break;
		default:
			fprintf(stderr, "unknown execution option\n");
			nemo_usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (mode == 0)
		nemo_usage();

	/* open syslog */
	openlog("shisad(nemod)", 0, LOG_DAEMON);
	syslog(LOG_INFO, "Start NEMO daemon\n");

	/* parse prefix table */
	switch (mode) {
	case MODE_HA:
		if (ha_parse_ptconf((pt_filename)?pt_filename:NEMO_PTFILE) > 0)
			exit(0);
		break;
	case MODE_MR:
		if (mr_parse_ptconf((pt_filename)?pt_filename:NEMO_PTFILE) > 0)
			exit(0);
		break;
	default:
		nemo_usage();
		exit(0);
	}

	/* get nemotun from the kernel and flush all states */
	if (set_nemo_ifinfo()) {
		syslog(LOG_ERR, "set_nemo_ifinfo %s\n", strerror(errno));
		return (-1);
	}

	LIST_FOREACH(nif, &nemo_ifhead, nemo_ifentry) {
		if_number ++;
	}
	LIST_FOREACH(npt, &nemo_mnpthead, nemo_mnptentry) {
		pt_number ++;
	}

	if (if_number < pt_number) {
		syslog(LOG_ERR, "Create %d of nemo interfaces\n", pt_number);	
		exit(0);
	} 
	
	/* statically tunnel mode setting */
	if (staticmode && tun_filename) 
		set_static_tun(tun_filename);

	signal(SIGTERM, nemo_terminate);
	signal(SIGHUP, nemo_terminate);
	signal(SIGKILL, nemo_terminate);
	signal(SIGINT, nemo_terminate);

	if (debug)
		nemo_dump();

	if (!foreground) {
		if (daemon(0, 0) < 0) {
			syslog(LOG_ERR, "daemon execution %s\n", strerror(errno));
			nemo_terminate(0);
			exit(-1);
		}
	}

	mainloop();

	return (0);
};

static int
ha_parse_ptconf(filename)
	char *filename;
{
        FILE *file;
        int i=0;
        char buf[256], *spacer, *head;
	struct nemo_mnpt *pt;
        char *option[NEMO_OPTNUM];
        /*
         * option[0]: HoA 
         * option[1]: Mobile Network Prefix
         * option[2]: Mobile Network Prefix Length
         * option[3]: Registration mode
         * option[4]: Binding Unique Identifier (optional)
         */

	if (filename == NULL)
		return (EINVAL);
	file = fopen(filename, "r");
        if(file == NULL) {
		syslog(LOG_ERR, "opening %s is failed %s\n", 
			filename, strerror(errno));
                return (errno);
        }

        memset(buf, 0, sizeof(buf));
        while((fgets(buf, sizeof(buf), file)) != NULL){
                /* ignore comments */
                if (strchr(buf, '#') != NULL) 
                        continue;
                if (strchr(buf, ' ') == NULL) 
                        continue;
                
                /* parsing all options */
                for (i = 0; i < NEMO_OPTNUM; i++)
                        option[i] = '\0';
                head = buf;
                for (i = 0, head = buf; 
                     (head != NULL) && (i < (multiplecoa)?NEMO_OPTNUM:NEMO_OPTNUM_MCOA); 
                     head = ++spacer, i ++) {

                        spacer = strchr(head, ' ');
                        if (spacer) {
                                *spacer = '\0';
                                option[i] = head;
                        } else {
                                option[i] = head;
                                break;
                        }
                }

		pt = malloc(sizeof(*pt));
		if (pt == NULL)
			return (ENOMEM);
		memset(pt, 0, sizeof(pt));
                if (inet_pton(AF_INET6, option[0], &pt->hoa) < 0) {
                        fprintf(stderr, "%s is not correct address\n", option[0]);
			free(pt);
                        continue;
                }
                if (inet_pton(AF_INET6, option[1], &pt->nemo_prefix) < 0) {
                        fprintf(stderr, "%s is not correct address\n", option[1]);
			free(pt);
                        continue;
                }
		pt->nemo_prefixlen = atoi(option[2]);  

		if (multiplecoa) {
			if (option[4])
				pt->bid = atoi(option[4]);
			else 
				pt->bid = 0;
		}


		LIST_INSERT_HEAD(&nemo_mnpthead, pt, nemo_mnptentry);

                memset(buf, 0, sizeof(buf));
        } 
	fclose(file);
	return (0);

};

static int
mr_parse_ptconf(filename)
	char *filename;
{
        FILE *file;
        int i=0;
        char buf[256], *spacer, *head;
	struct nemo_mnpt *pt;

        char *option[NEMO_OPTNUM];
        /*
         * option[0]: HoA 
         * option[1]: Mobile Network Prefix
         * option[2]: Mobile Network Prefix Length
         * option[3]: Registration mode
         * option[4]: Binding Unique Id (optional)
         */

	if (filename == NULL)
		return (EINVAL);

        file = fopen(filename, "r");
        if(file == NULL) {
		syslog(LOG_ERR, "opening %s is failed %s\n", filename, strerror(errno));
                return (errno);
        }

        memset(buf, 0, sizeof(buf));
        while((fgets(buf, sizeof(buf), file)) != NULL){
                /* ignore comments */
                if (strchr(buf, '#') != NULL) 
                        continue;
                if (strchr(buf, ' ') == NULL) 
                        continue;
                
                /* parsing all options */
                for (i = 0; i < NEMO_OPTNUM; i++)
                        option[i] = '\0';
                head = buf;
                for (i = 0, head = buf; 
                     (head != NULL) && (i < (multiplecoa)?NEMO_OPTNUM:NEMO_OPTNUM_MCOA); 
                     head = ++spacer, i ++) {

                        spacer = strchr(head, ' ');
                        if (spacer) {
                                *spacer = '\0';
                                option[i] = head;
                        } else {
                                option[i] = head;
                                break;
                        }
                }

		pt = malloc(sizeof(*pt));
		if (pt == NULL)
			return (ENOMEM);
		memset(pt, 0, sizeof(*pt));

		if (inet_pton(AF_INET6, option[0], &pt->hoa) < 0) {
			fprintf(stderr, "%s is not correct address\n", option[0]);
			free(pt);
			continue;
		}

		if (inet_pton(AF_INET6, option[1], &pt->nemo_prefix) < 0) {
			fprintf(stderr, "%s is not correct address\n", option[1]);
			free(pt);
			continue;
		}
		pt->nemo_prefixlen = atoi(option[2]);

		if (multiplecoa) {
			if (option[4])
				pt->bid = atoi(option[4]);
			else 
				pt->bid = 0;
		}

		LIST_INSERT_HEAD(&nemo_mnpthead, pt, nemo_mnptentry);
		memset(buf, 0, sizeof(buf));
	} 
	
	fclose(file);
	return (0);
};


static int
set_nemo_ifinfo() {
	size_t needed;
	char *buf, *next, name[IFNAMSIZ];
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;
	int mib[6];
	struct nemo_if *nif;
	
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET6;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;
	
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		syslog(LOG_ERR, "sysctl: %s\n", strerror(errno));
		return (errno);
	}
	if ((buf = malloc(needed)) == NULL) {
		syslog(LOG_ERR, "malloc: %s\n", strerror(errno));
		return (errno);
	}
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		syslog(LOG_ERR, "sysctl: %s\n", strerror(errno));
		return (errno);
	}

        for (next = buf; next < buf + needed ; next += ifm->ifm_msglen) {
                ifm = (struct if_msghdr *)next;

                if (ifm->ifm_type == RTM_IFINFO) {
                        sdl = (struct sockaddr_dl *)(ifm + 1);

                        bzero(name, sizeof(name));
                        strncpy(name, &sdl->sdl_data[0], sdl->sdl_nlen);

                        if (strncmp(name, NEMO_TUNNAME, strlen(NEMO_TUNNAME)) == 0) {

				nif = malloc(sizeof(struct nemo_if));
				if (nif == NULL)
					return (ENOMEM);

				memset(nif, 0, sizeof(*nif));
				strncpy(nif->ifname, name, strlen(name));

				/* clear tunnel configuration */ 
				nemo_tun_del(nif->ifname); 

				if (LIST_FIRST(&nemo_ifhead) == NULL)
					LIST_INSERT_HEAD(&nemo_ifhead, nif, nemo_ifentry);
				else {
					struct nemo_if *nif1, *nif2;
					for (nif1 = LIST_FIRST(&nemo_ifhead); nif1;
					     nif1 = nif2) {
						nif2 = LIST_NEXT(nif1, nemo_ifentry);
						if (nif2 == NULL) {
							LIST_INSERT_AFTER(nif1, nif, nemo_ifentry);
							break;
						}
					}
				}
                                continue;
                        }
                }               
        }
        free(buf); 

	return (0);
};


static void
set_static_tun(filename)
	char *filename;
{
	struct nemo_if *nif;
	FILE *file;
	int i=0;
	char buf[256], *spacer, *head;
	char *option[NEMO_TUNOPTNUM];
	/*
	 * option[0]: tun name
	 * option[1]: HoA
	 * option[2]: Binding Unique Id (optional)
	 */ 
	if (filename == NULL)
		return; 
		
	file = fopen(filename, "r");
	if(file == NULL) {
		syslog(LOG_ERR, "opening %s is failed: %s\n", 
			filename, strerror(errno));
		nemo_usage();
		exit(-1);
	} 
	
	
	memset(buf, 0, sizeof(buf));
	while((fgets(buf, sizeof(buf), file)) != NULL){
		/* ignore comments */
		if (strchr(buf, '#') != NULL) 
			continue; 
		if (strchr(buf, ' ') == NULL) 
			continue;
                /* parsing all options */
		
		for (i = 0; i < NEMO_TUNOPTNUM; i++)
			option[i] = '\0';
		head = buf;
		
		for (i = 0, head = buf; 
			(head != NULL) && (i < NEMO_TUNOPTNUM); 
				head = ++spacer, i ++) { 
				
			spacer = strchr(head, ' ');
			if (spacer) {
				*spacer = '\0';
				option[i] = head;
			} else {
				option[i] = head;
				break;
			}
		} 
		
		nif = find_nemo_if_from_name(option[0]);
		if (nif == NULL) {
			syslog(LOG_ERR, "%s is not available\n", option[0]);
			exit(-1);
		}
                if (inet_pton(AF_INET6, option[1], &nif->hoa) < 0) {
			syslog(LOG_ERR, "%s is not correct address\n", option[1]);
			exit(-1);
		} 
		
		if (multiplecoa) {
			if (option[2])
				nif->bid = atoi(option[2]);
			else 
				nif->bid = 0;
		}
	} 
	
	return; 
}




static struct nemo_if *
find_nemo_if(hoa, bid)
	struct in6_addr *hoa;
	u_int16_t bid; 
{
	struct nemo_if *nif;
	short flags;
	
	LIST_FOREACH(nif, &nemo_ifhead, nemo_ifentry) {
		if (multiplecoa) {
			if (hoa && IN6_ARE_ADDR_EQUAL(hoa, &nif->hoa)) {
				if ((bid > 0) && (bid == nif->bid)) 
					return (nif);
			}
		} else {
			if (hoa && IN6_ARE_ADDR_EQUAL(hoa, &nif->hoa)) {  
				return (nif);
			} 
		}
	}

	if (staticmode)
		return (NULL);

	LIST_FOREACH(nif, &nemo_ifhead, nemo_ifentry) {
		flags = nemo_ifflag_get(nif->ifname);
		if (!(flags & IFF_UP))
			return (nif);
	}

	return (NULL);
}

static struct nemo_if *
find_nemo_if_from_name(ifname)
	char *ifname;
{
	struct nemo_if *nif; 
	
	if (ifname == NULL)
		return (NULL); 
		
	LIST_FOREACH(nif, &nemo_ifhead, nemo_ifentry) {
		if (strncmp(ifname, nif->ifname, strlen(nif->ifname)) == 0)
			return (nif);
	} 
	
	return (NULL);
}

static void	
mainloop() {
	int msock, n, nfds = 0;
        fd_set fds;
        struct mip_msghdr *mhdr = NULL;
	char buf[256];
	struct in6_addr local_in6, def, *hoa;
	struct sockaddr_in6 src, dst;
	struct nemo_mnpt *npt = NULL, *nptn = NULL;
	struct nemo_if *nif;
	struct mipm_bul_info *mbu;
	struct mipm_bc_info *mbc;
	u_int16_t bid = 0;

	memset(&def, 0, sizeof(def));
	memset(&local_in6, 0, sizeof(local_in6));
	inet_pton(AF_INET6, "::1", &local_in6);

        msock = socket(PF_MOBILITY, SOCK_RAW, 0);

        if (msock < 0) {
		syslog(LOG_ERR, "socket(PF_MOBILITY) %s\n", strerror(errno));
                exit(-1);
        }

	while (1) {
		FD_ZERO(&fds);
		nfds = -1;
		FD_SET(msock, &fds);
		nfds = msock + 1;

                if (select(nfds, &fds, NULL, NULL, NULL) < 0) {
			syslog(LOG_ERR, "select %s\n", strerror(errno));
                        exit(-1);
                }

                if (FD_ISSET(msock, &fds)) {
			n = read(msock, buf, sizeof(buf));
			if (n < 0) {
				syslog(LOG_ERR, "read %s\n", strerror(errno));
				continue;
			}

			mhdr = (struct mip_msghdr *)buf;
                        switch (mhdr->miph_type) {
                        case MIPM_BUL_ADD:
                        case MIPM_BUL_UPDATE:
                                /* tunnel setup and route add for MNPs */

				if (mode != MODE_MR)
					break;

                                mbu = (struct mipm_bul_info *)buf;
				/* if R flag is not set, ignore the BU */
                                if (!(mbu->mipu_flags & (IP6_MH_BU_HOME | IP6_MH_BU_ROUTER))) 
					break;
				memset(&src, 0, sizeof(src));
				memset(&dst, 0, sizeof(dst));
				src.sin6_family = dst.sin6_family = AF_INET6;
				src.sin6_len = dst.sin6_len =
					sizeof(struct sockaddr_in6);
				src.sin6_addr =
					((struct sockaddr_in6 *)MIPU_COA(mbu))->sin6_addr;
				dst.sin6_addr =
					((struct sockaddr_in6 *)MIPU_PEERADDR(mbu))->sin6_addr;
				hoa = &((struct sockaddr_in6 *)MIPU_HOA(mbu))->sin6_addr;
				if (hoa == NULL)
					break;

				if (debug) {
					syslog(LOG_INFO, 
						"cmd=BUL_ADD, hoa=%s, dst=%s, src=%s\n", 
						ip6_sprintf(hoa), 
						ip6_sprintf(&dst.sin6_addr), 
						ip6_sprintf(&src.sin6_addr));
				}

				if (multiplecoa)
					memcpy(&bid, &((struct sockaddr_in6 *)MIPU_COA(mbu))->sin6_port, sizeof(bid));
				nif = nemo_setup_forwarding((struct sockaddr *)&src, 
							    (struct sockaddr *)&dst, hoa, bid);


				if (nif == NULL) 
					break;

				/*
				 * setup routes toward nif for all
				 * associated mobile network prefixes 
				 */
				for (npt = LIST_FIRST(&nemo_mnpthead); npt; npt = nptn) {
					nptn = LIST_NEXT(npt, nemo_mnptentry);

					if (!IN6_ARE_ADDR_EQUAL(hoa, &npt->hoa)) 
						continue;

					if ((multiplecoa && bid <= 0) || multiplecoa == 0) {
						/* remove default route */
						route_del(0);
						/* add default route */
						route_add(&def, &local_in6, NULL, 0,
							  if_nametoindex(nif->ifname));
						
						syslog(LOG_INFO, 
						"adding a default route to %s\n", nif->ifname);
					}
					
					npt->nemo_if = nif;
					break;
				}

                                break;
                        case MIPM_BUL_REMOVE:
				if (mode != MODE_MR)
					break;

                                mbu = (struct mipm_bul_info *)buf;

				/* if R flag is not set, ignore the BU */
                                if (!(mbu->mipu_flags & (IP6_MH_BU_HOME | IP6_MH_BU_ROUTER))) 
					break;
				hoa = &((struct sockaddr_in6 *)MIPU_HOA(mbu))->sin6_addr;
				if (hoa == NULL)
					break;

				if (multiplecoa) 
					memcpy(&bid, &((struct sockaddr_in6 *)MIPU_COA(mbu))->sin6_port, sizeof(bid));
				nif = nemo_destroy_forwarding(hoa, bid);

				for (npt = LIST_FIRST(&nemo_mnpthead); npt; npt = nptn) {
					nptn = LIST_NEXT(npt, nemo_mnptentry);

					if (!IN6_ARE_ADDR_EQUAL(hoa, &npt->hoa)) 
						continue;
					
					if (npt->nemo_if) {
						npt->nemo_if = NULL; 
						/* remove default route */
						if ((multiplecoa && (bid <= 0)) || multiplecoa == 0) 
							route_del(0);
						
					}
                                }
                                break;
			case MIPM_BC_ADD:
			case MIPM_BC_UPDATE:
				if (mode != MODE_HA)
					break;

                                mbc = (struct mipm_bc_info *)buf;
				/* if R flag is not set, ignore the BU */
                                if (!(mbc->mipc_flags & (IP6_MH_BU_HOME | IP6_MH_BU_ROUTER))) 
					break;
				hoa = &((struct sockaddr_in6 *)MIPC_HOA(mbc))->sin6_addr;
				if (hoa == NULL)
					break;

				memset(&src, 0, sizeof(src));
				memset(&dst, 0, sizeof(dst));
				src.sin6_family = dst.sin6_family = AF_INET6;
				src.sin6_len = dst.sin6_len = sizeof(struct sockaddr_in6);
				src.sin6_addr = 
					((struct sockaddr_in6 *)MIPC_CNADDR(mbc))->sin6_addr;
				dst.sin6_addr = 
       					((struct sockaddr_in6 *)MIPC_COA(mbc))->sin6_addr;

				if (multiplecoa) 
					memcpy(&bid, &((struct sockaddr_in6 *)MIPC_COA(mbc))->sin6_port, sizeof(bid));

				nif = nemo_setup_forwarding((struct sockaddr *)&src, 
							    (struct sockaddr *)&dst, hoa, bid);
				if (nif == NULL) 
					break;

				route_del(if_nametoindex(nif->ifname));

				for (npt = LIST_FIRST(&nemo_mnpthead); npt; npt = nptn) {
					nptn = LIST_NEXT(npt, nemo_mnptentry);

					if (!IN6_ARE_ADDR_EQUAL(hoa, &npt->hoa)) 
						continue;

					npt->nemo_if = nif;
					route_add(&npt->nemo_prefix, &local_in6, NULL, 
						  npt->nemo_prefixlen, if_nametoindex(nif->ifname));
				}
                                break;

			case MIPM_BC_REMOVE:
				if (mode != MODE_HA)
					break;

                                mbc = (struct mipm_bc_info *)buf;
				/* if R flag is not set, ignore the BU */
                                if (!(mbc->mipc_flags & (IP6_MH_BU_HOME | IP6_MH_BU_ROUTER))) 
					break;
				hoa = &((struct sockaddr_in6 *)MIPC_HOA(mbc))->sin6_addr;
				if (hoa == NULL)
					break;

				if (multiplecoa) 
					memcpy(&bid, &((struct sockaddr_in6 *)MIPC_COA(mbc))->sin6_port, sizeof(bid));
				nif = nemo_destroy_forwarding(hoa, bid);

				route_del(if_nametoindex(nif->ifname));

				for (npt = LIST_FIRST(&nemo_mnpthead); npt; npt = nptn) {
					nptn = LIST_NEXT(npt, nemo_mnptentry);

					if (!IN6_ARE_ADDR_EQUAL(hoa, &npt->hoa)) 
						continue;

					npt->nemo_if = NULL; 
					/* remove default route */
                                }
                                break;
                        default:
                                break;
                        }

                }
	}
}

/*
 * Setup bi-directional tunnel between HA and CoA
 */ 
static struct nemo_if *
nemo_setup_forwarding (src, dst, hoa, bid) 
	struct sockaddr *src, *dst;
	struct in6_addr *hoa;
	u_int16_t bid;
{
	struct nemo_if *nif = NULL;

	nif = find_nemo_if(hoa, bid);
	if (nif == NULL) {
		syslog(LOG_ERR, 
		       "No more available nemo interfaces\n");
		return (NULL);
	}
	
	nif->hoa = *hoa;
	if (multiplecoa && bid)
		nif->bid = bid;

       /* If CoA is not changed, don't touch tunnel  */
	if (multiplecoa) {
		if (IN6_ARE_ADDR_EQUAL(&nif->coa, 
				       (mode == MODE_HA) ?  
				       &((struct sockaddr_in6 *)dst)->sin6_addr :
				       &((struct sockaddr_in6 *)src)->sin6_addr)) { 
			/*nemo_gif_ar_set(nif->ifname, &((struct sockaddr_in6 *)src)->sin6_addr);*/ 
			
			return (nif);
		}
	}

	/* tunnel disable (just for safety) */
	nemo_tun_del(nif->ifname);

	if (mode == MODE_HA) {
		/* tunnel activate */
		nemo_tun_set((struct sockaddr *)src,
			     (struct sockaddr *)dst,
			     if_nametoindex(nif->ifname), 0 /* FALSE */);
		/* Update CoA */
		nif->coa = ((struct sockaddr_in6 *)dst)->sin6_addr;
	} else if (mode == MODE_MR) {
		/* tunnel activate */
		nemo_tun_set((struct sockaddr *)src,
			     (struct sockaddr *)dst,
			     if_nametoindex(nif->ifname), 1 /* TRUE */);
		nemo_gif_ar_set(nif->ifname, &((struct sockaddr_in6 *)src)->sin6_addr);
                /* Update CoA */
		nif->coa = ((struct sockaddr_in6 *)src)->sin6_addr;
	} 
	
        if (debug) {
		syslog(LOG_INFO, "tunnel setup, src=%s, dst=%s\n",
			ip6_sprintf(&((struct sockaddr_in6 *)src)->sin6_addr), 
			ip6_sprintf(&((struct sockaddr_in6 *)dst)->sin6_addr));
	}

	return (nif);
}

static struct nemo_if *
nemo_destroy_forwarding (hoa, bid) 
	struct in6_addr *hoa;
	u_int16_t bid;
{
	struct nemo_if *nif = NULL;
	short flags;

	nif = find_nemo_if(hoa, bid);
	if (nif == NULL) {
		syslog(LOG_ERR, 
		       "No associated nemo interfaces for %s\n", ip6_sprintf(hoa));
		return (NULL);
	}

	nemo_tun_del(nif->ifname);

	flags = nemo_ifflag_get(nif->ifname);

	if (flags & IFF_UP)
		nemo_ifflag_set(nif->ifname, 
				(flags &= ~IFF_UP));

	if (staticmode == 0) {
		memset(&nif->hoa, 0, sizeof(*hoa));
		if (multiplecoa)
			nif->bid = 0;
	}
        memset(&nif->coa, 0, sizeof(nif->coa));

	return (nif);
}


static void
nemo_terminate(dummy)
	int dummy;
{
	static struct nemo_if *nif;
	short flags;

	LIST_FOREACH(nif, &nemo_ifhead, nemo_ifentry) {

		nemo_tun_del(nif->ifname);

		flags = nemo_ifflag_get(nif->ifname);
		if (flags & IFF_UP)
			nemo_ifflag_set(nif->ifname, 
					(flags &= ~IFF_UP));

		if (multiplecoa == 0) {
			if (mode == MODE_HA)
				route_del(if_nametoindex(nif->ifname));
		}
	}

	if (multiplecoa == 0) {
		if (mode == MODE_MR)
			route_del(0);
	}

	exit(-1);
}


static void
nemo_dump() {
	struct nemo_if *nif;
	struct nemo_mnpt *npt;
	int i = 1;

	syslog(LOG_INFO, "Dump nemod info. for %s\n",
		 (mode==MODE_HA)? "Home Agent" : "Mobile Router");
	      
	syslog(LOG_INFO, "debug=%s, DNS=%s, MCoA=%s, Static=%s", 
		(debug)? "on" : "off", 
		(numerichost)? "off" : "on", 
		(multiplecoa)? "on" : "off", 
		(staticmode)? "on" : "off");

	LIST_FOREACH(nif, &nemo_ifhead, nemo_ifentry) {
		syslog(LOG_INFO, "nemo tunnel no.%d %s\n", 
			i++, nif->ifname);
		if (multiplecoa)
			syslog(LOG_INFO, "\tbid: %d\n", nif->bid);
		if (staticmode) 
			syslog(LOG_INFO, "\thoa: %s\n", ip6_sprintf(&nif->hoa));
	}

	i = 0;
	LIST_FOREACH(npt, &nemo_mnpthead, nemo_mnptentry) {
		syslog(LOG_INFO, "Prefix Table no.%d\n", i);
		syslog(LOG_INFO, "\tprefix: %s/%d\n", 
		       ip6_sprintf(&npt->nemo_prefix), npt->nemo_prefixlen);
		syslog(LOG_INFO, "\thoa: %s\n", ip6_sprintf(&npt->hoa));
		if (multiplecoa)
			syslog(LOG_INFO, "\tbid: %d\n", npt->bid);
	}
}
