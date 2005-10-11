/*      $KAME: mdd.c,v 1.5 2005/10/11 15:24:23 mitsuya Exp $  */
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
#include <stdarg.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/mipsock.h>
#include <netinet/ip6mh.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef MIP_MCOA
#include <sys/sysctl.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <netinet6/in6_var.h>
#endif /* MIP_MCOA */

#include "mdd.h"

static void reload(int);
static void terminate(int);

static char *cmd;
int ver_major = 0;
int ver_minor = 1;
int debug = 0;
int namelookup = 1;
int cflag = 0;
int mflag = 0;
int hflag = 0;
int pflag = 0;
struct bl	bl_head;
struct cifl	cifl_head;
struct coacl	coacl_head;
int sock_rt, sock_m, sock_dg6, sock_dg, poll_time = -1;
#ifdef MIP_MCOA
char ingressif[IFNAMSIZ];
#endif /* MIP_MCOA */

#ifdef MIP_MCOA
static void dereg_detach_coa(struct ifa_msghdr *);
int mipsock_deregforeign(struct sockaddr_in6 *, struct sockaddr_in6 *, 
				struct sockaddr_in6 *, int, u_int16_t);
extern void get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
extern int get_ifmsg(void);
#endif /* MIP_MCOA */

void
usage()
{
	fprintf(stderr, "%s\n", cmd);
	fprintf(stderr, "movement detection daemon for mobile router\n");
	fprintf(stderr, "\t[-h HoA]        HoA\n");
	fprintf(stderr, "\t[-i IF_for_CoA] Interface for watching\n");
	fprintf(stderr, "\t[-d]            Debug mode\n");
	fprintf(stderr, "\t[-n]            Don't resolve names\n");
	fprintf(stderr, "\t[-m]            Don\'t use mipsock\n");
	fprintf(stderr, "\t[-p interval]   polling link status per interval(sec)\n");
#ifdef MIP_MCOA
	fprintf(stderr, "\t[-b bid]   set Binding Unique Identifier");
	fprintf(stderr, "\t           -b must be used with -i and - h option.\n");
	fprintf(stderr, "\t           multiple mdds must be executed.\n");
	fprintf(stderr, "\t[-x ifname]   set ingress interface name");
#endif /* MIP6_MCOA */
}

int
main(argc, argv, env)
	int argc;
	char **argv;
	char **env;
{
	int ch;
	struct binding *bp = NULL;
	int if_pref = 0;
#ifdef MIP_MCOA
	u_int16_t bid = 0; 
	
	memset(ingressif, 0, sizeof(ingressif));
#endif /* MIP_MCOA */

	/*  Clear all parameters */
	LIST_INIT(&bl_head);
	LIST_INIT(&cifl_head);
	LIST_INIT(&coacl_head);

	cmd = argv[0];

	/*  Option processing */
#ifndef MIP_MCOA
	while ((ch=getopt(argc, argv, "i:dnh:mp:")) != -1)
#else
        while ((ch=getopt(argc, argv, "x:b:i:dnh:mp:")) != -1) 
#endif /* MIP_MCOA */
	{
		switch (ch) {
#ifdef MIP_MCOA
                case 'x':
			strncpy(ingressif, optarg, strlen(optarg));
			break;
		case 'b':
			bid = atoi(optarg);
			if (bid <= 0) {
				fprintf(stderr, "Please specify non zero value\n");
				usage();
				exit(0);
			}
			break;
#endif /* MIP_MCOA */
		case 'i':
			if_pref++;
			set_coaif(optarg, if_pref);
			cflag += 1;
			break;
		case 'h':
#ifdef MIP_MCOA
			if (bp) {
				fprintf(stderr, "You can specify multiple HoA here\n");
				usage();
				exit(0);
			}
#endif /* MIP_MCOA */
			bp = set_hoa_str(optarg);
			hflag += 1;
			break;

		case 'd':
			debug += 1;
			break;

		case 'n':
			namelookup = 0;
			break;

		case 'm':
			mflag += 1;
			break;
		case 'p':
			pflag += 1; 
			poll_time = atoi(optarg);
			break;
		default:
			usage();
			exit(0);
		}
	}
	argc -= optind;
	argv += optind;

#ifdef MIP_MCOA
	if (bid) {
		if (bp == NULL) {
			fprintf(stderr, "You must specify a HoA with -b option\n");
			usage();
			exit(0);
		}
		bp->bid = bid;
	} 
#endif /* MIP_MCOA */

	/*
	 *  Prepare sockets
	 */
	sock_rt = socket(PF_ROUTE, SOCK_RAW, 0);
	if (sock_rt < 0) {
		perror("socket(PF_ROUTE)");
		exit (-1);
	}

	if (!mflag) {
		sock_m = socket(PF_MOBILITY, SOCK_RAW, 0);
		if (sock_m < 0) {
			perror("socket(PF_MOBILITY)");
			exit (-1);
		}
	}

	sock_dg6 = socket(PF_INET6, SOCK_DGRAM, 0);
	if (sock_dg6 < 0) {
		perror("socket(PF_INET6)");
		exit (-1);
	}

	sock_dg = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock_dg < 0) {
		perror("socket(PF_INET)");
		exit (-1);
	}

	/* Get static parameters */
	if (!cflag) {
		get_coaiflist();
		if (debug > 1) {
			print_coaiflist(stderr);
		}
	}
	if (!hflag) {
		get_hoalist();
		if (debug > 1) {
			print_bl(stderr);
		}
	}

	/* Get dynamic parameters, at this moment */
	get_coacandidate();
	set_coa();

	/*
	 *  Show starting parameters, if started as debug mode
	 */
	if (debug) {
		syslog(LOG_INFO, "# Command:	%s\n", cmd);
		syslog(LOG_INFO, "# Version: 	%d.%d\n", ver_major, ver_minor);
		syslog(LOG_INFO, "# Debug level:	%d\n", debug);

		print_coaiflist(stderr);

		print_bl(stderr);
	}
	sync_binding();

	/*
	 *  Main loop
	 */
	signal(SIGHUP, reload);
	signal(SIGTERM, terminate);
	signal(SIGINT, terminate);

	if (debug == 0) {
		if (daemon(0, 0) < 0) {
			perror("daemon");
			terminate(0);
			exit(-1);
		}
	}

	openlog("shisad(mdd)", 0, LOG_DAEMON);
	mainloop();

	/* not reached */
	return (0);
}

static void
reload(dummy)
	int dummy;
{
	struct binding *bp;
	struct cif *cifp;
	struct coac *cp;

	if (debug) {
		syslog(LOG_INFO, "Reload parameters\n");
	}

	while (!LIST_EMPTY(&bl_head)) {
		bp = LIST_FIRST(&bl_head);
		LIST_REMOVE(bp, binding_entries);
		free(bp);
	}
	while (!LIST_EMPTY(&cifl_head)) {
		cifp = LIST_FIRST(&cifl_head);
		LIST_REMOVE(cifp, cif_entries);
		free(cifp);
	}
	while (!LIST_EMPTY(&coacl_head)) {
		cp = LIST_FIRST(&coacl_head);
		LIST_REMOVE(cp, coac_entries);
		free(cp);
	}

	if (!cflag) get_coaiflist();
	if (!hflag) get_hoalist();
	get_coacandidate();
	set_coa();
	sync_binding();
}


static void
terminate(dummy)
	int dummy;    
{

	if (debug) {
		syslog(LOG_INFO, "Terminate\n");
	}

	close(sock_rt);
	close(sock_dg6);
	close(sock_dg);
	if (!mflag)
		close(sock_m);

	exit(-1);
}

struct binding *
set_hoa(ia6, prefixlen)
	struct in6_addr *ia6;
	int prefixlen;
{
	struct binding *bp;

	bp = (struct binding *) malloc(sizeof(struct binding));
	if (bp == NULL) {
		perror("malloc:");
		return (NULL);
	}
	memset(bp, 0, sizeof(*bp));
	bp->hoa.sin6_len	= sizeof(bp->hoa);
	bp->hoa.sin6_family	= AF_INET6;
	bp->hoa.sin6_port	= htons(0);;
	memcpy(&bp->hoa.sin6_addr, ia6, sizeof(*ia6));
	bp->hoa.sin6_flowinfo	= htonl(0);;
	bp->hoa_prefixlen 	= prefixlen;
	bp->flags 		= BF_INUSE;
	LIST_INSERT_HEAD(&bl_head, bp, binding_entries);

	return (bp);
}

struct binding *
set_hoa_str(addr)
	char *addr;
{
	struct in6_addr	ia6;
	char *cp;
	int prefixlen = DEFAULT_PREFIXLEN;

	cp = strchr(addr, '/');
	if (cp != NULL) {
		*cp = '\0';
		cp++;
		prefixlen = strtol(cp, NULL, 10);
		if (errno == ERANGE) prefixlen = DEFAULT_PREFIXLEN;
	}

	if (inet_pton(AF_INET6, addr, &ia6) < 0) {
		return (NULL);
	}
	return (set_hoa(&ia6, prefixlen));
}

void
get_hoalist()
{

	_get_hoalist();
}

void
set_coaif(ifname, preference)
	char *ifname;
	int preference;
{
	struct cif *cifp;

	cifp = (struct cif *) malloc(sizeof(struct cif));
	cifp->cif_name = ifname;
	cifp->cif_linkstatus = -1;
	cifp->preference = preference;
	LIST_INSERT_HEAD(&cifl_head, cifp, cif_entries);
}

void
get_coaiflist()
{
	struct cif *cifp;
	struct ifreq ifr;

	get_ifl(&cifl_head);
	del_if_from_ifl(&cifl_head, IFT_MIP);

    retry:
	LIST_FOREACH(cifp, &cifl_head, cif_entries) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, cifp->cif_name, IFNAMSIZ);
		if (ioctl(sock_dg, SIOCGIFFLAGS, &ifr) < 0) {
			perror("ioctl(SIOCGIFFLAGS)");
			continue;
		}

		if (ifr.ifr_flags & IFF_LOOPBACK) {
			LIST_REMOVE(cifp, cif_entries);
			free(cifp->cif_name);
			free(cifp);
			goto retry;
		}
	}
}

void
get_coacandidate()
{
	struct coac *cp;
	char buf[PA_BUFSIZE];

	/* List Deletion. */
	while (!LIST_EMPTY(&coacl_head)) {
		cp = LIST_FIRST(&coacl_head);
		LIST_REMOVE(cp, coac_entries);
		free(cp);
	}

	get_addr_with_ifl(&coacl_head, &cifl_head);

    retry:
	LIST_FOREACH(cp, &coacl_head, coac_entries) {
		if (in6_addrscope(&cp->coa.sin6_addr)
					!= __IPV6_ADDR_SCOPE_GLOBAL) {
			LIST_REMOVE(cp, coac_entries);
			free(cp);
			goto retry;
		}
	}

	if (debug > 1) {
		syslog(LOG_INFO, "CoA candidate\n");
		LIST_FOREACH(cp, &coacl_head, coac_entries) {
			syslog(LOG_INFO, "\tCoA: %s\n",
				(char *) inet_ntop(AF_INET6, &cp->coa.sin6_addr,
							buf, sizeof(buf)));
		}
	}
}

int
in6_matchlen(a1, a2)
	struct in6_addr *a1;
	struct in6_addr *a2;
{
	int bytes;
	int i, j;
	u_int8_t mask;

	bytes = sizeof(struct in6_addr)/sizeof(u_int8_t);
	for (i=0; i<bytes; i++) {
		mask = 0;
		for (j=0; j<8; j++) {
			mask |= 0x80 >> j;
			if ((mask & a1->s6_addr[i]) != (mask & a2->s6_addr[i]))
				return (8 * i + j);
		}
	}

	/* same address */
	return (8 * i);
}

void
set_coa()
{
	struct coac *cp;
	struct binding *bp;
	int maxmatchlen, matchlen, if_pref;
	struct sockaddr_in6 sin6;
	char buf[PA_BUFSIZE];


	LIST_FOREACH(bp, &bl_head, binding_entries) {
		maxmatchlen = -1;
		if_pref = -1;

		LIST_FOREACH(cp, &coacl_head, coac_entries) {
			matchlen = in6_matchlen(&bp->hoa.sin6_addr,
							&cp->coa.sin6_addr);

			/* 
			 * 1. check preference 
			 *      take bigger one as primary coa
			 * 2. if preference were same, check matchlen 
			 *      take bigger one as primary coa
			 */
			if (if_pref < cp->preference) {
				if_pref = cp->preference;
				maxmatchlen = matchlen;
				memcpy(&sin6, &cp->coa, sizeof(sin6));
			} else if (if_pref == cp->preference) {
				if (maxmatchlen < matchlen) {
					maxmatchlen = matchlen;
					memcpy(&sin6, &cp->coa, sizeof(sin6));
				}
			}
		}
		if (maxmatchlen < 0) {
			bp->flags &= ~BF_BOUND;
			bp->flags &= ~BF_HOME;
			memcpy(&bp->pcoa, &bp->coa, sizeof(bp->pcoa));
			memset(&bp->coa, 0, sizeof(bp->coa));
		} else
		if (maxmatchlen >= bp->hoa_prefixlen) {
			bp->flags &= ~BF_BOUND;
			bp->flags |= BF_HOME;
#if 0
			/*
			 * returning home is processed separately when
			 * receiving a MIPM_HOME_HINT message.
			 */
			bp->flags &= ~BF_BOUND;
			bp->flags |= BF_HOME;
			memcpy(&bp->pcoa, &bp->coa, sizeof(bp->pcoa));
			bp->pcoaifindex = bp->coaifindex;
			memcpy(&bp->coa, &sin6, sizeof(bp->coa));
			bp->coaifindex = in6_addr2ifindex(&bp->coa.sin6_addr);
#endif
		} else {
			bp->flags |= BF_BOUND;
			bp->flags &= ~BF_HOME;
			memcpy(&bp->pcoa, &bp->coa, sizeof(bp->pcoa));
			memcpy(&bp->coa, &sin6, sizeof(bp->coa));

			printf("set_coa(): coa %s\n",
				(char *) inet_ntop(AF_INET6,
				&bp->coa.sin6_addr,
				buf, sizeof(buf)));
		}
	}
}

void
sync_binding()
{
	struct binding *bp;
	u_int16_t bid = 0;

#ifdef MIP_MCOA
	bid = bp->bid;
#endif

	LIST_FOREACH(bp, &bl_head, binding_entries) {
		if (memcmp(&bp->coa, &bp->pcoa, sizeof(bp->coa)) == 0)
				continue;

		if (bp->flags & BF_HOME) {
			/* HOME */
			returntohome(&bp->hoa, &bp->coa, bp->coaifindex);
		} else if (bp->flags & BF_BOUND) {
			chbinding(&bp->hoa, &bp->coa, bid);
		}
	}
}

void
print_bl(fp)
	FILE *fp;
{
	char buf[PA_BUFSIZE];
	struct binding *bp;

	LIST_FOREACH(bp, &bl_head, binding_entries) {
		syslog(LOG_INFO, "HoA: %s",
			(char *) inet_ntop(AF_INET6, &bp->hoa.sin6_addr,
							buf, sizeof(buf)));
		if (bp->flags & BF_BOUND) {
			syslog(LOG_INFO, "\t-> %s",
				(char *) inet_ntop(AF_INET6, &bp->coa.sin6_addr,
							buf, sizeof(buf)));
		}
		syslog(LOG_INFO, "\n");
	}
}

void
print_coaiflist(fp)
	FILE *fp;
{
	struct cif *cifp;

	LIST_FOREACH(cifp, &cifl_head, cif_entries) {
		syslog(LOG_INFO, "CoA IF: %s\n", cifp->cif_name);
	}
}

void
mainloop()
{
	char buf[BUFSIZE];
	struct if_msghdr *ifm;
	struct mip_msghdr *mhdr;
	struct mipm_home_hint *m;
	struct timeval tv;
	fd_set fds, tfds;
	int nfds;
	int cc;

	ifm = (struct if_msghdr *)buf;
	mhdr= (struct mip_msghdr *)buf;
	m = (struct mipm_home_hint *)buf;

	if (pflag) {
		memset(&tv, 0, sizeof(struct timeval));
		tv.tv_sec = poll_time;
		tv.tv_usec = 0;
	}
	FD_ZERO(&fds);
	nfds = -1;

	FD_SET(sock_rt, &fds);
	if (sock_rt >= nfds)	nfds = sock_rt + 1;
	FD_SET(sock_m, &fds);
	if (sock_m >= nfds)	nfds = sock_m + 1;

	for (;;) {
		tfds = fds;
		if (select(nfds, &tfds, NULL, NULL, (pflag) ? &tv : NULL) < 0) {
			exit(-1);
		}

		if (FD_ISSET(sock_m, &tfds)) {
			if ((cc=read(sock_m, buf, sizeof(buf))) < 0) {
				exit(-1);
			}
			if (debug > 1) {
				syslog(LOG_INFO, "SOCK_MOB: type=%d\n",
						mhdr->miph_type);
			}

			switch (mhdr->miph_type) {
			case MIPM_HOME_HINT:
				recv_home_hint((int)m->mipmhh_ifindex,
				    (struct sockaddr_in6 *)m->mipmhh_prefix,
				    (int) m->mipmhh_prefixlen);
				sync_binding();
				break;
			default:
				break;
			}

		}

		if (FD_ISSET(sock_rt, &tfds)) {
			if ((cc=read(sock_rt, buf, sizeof(buf))) < 0) {
				exit(-1);
			}
			if (debug > 1) {
				syslog(LOG_INFO, "SOCK_ROUTE: type=%d\n",
							ifm->ifm_type);
			}

			if (ifm->ifm_type != RTM_NEWADDR &&
			    ifm->ifm_type != RTM_DELADDR &&
			    ifm->ifm_type != RTM_ADDRINFO) continue;

#ifdef MIP_MCOA
			if (ifm->ifm_type == RTM_ADDRINFO) 
				(void) dereg_detach_coa((struct ifa_msghdr *) ifm);
#endif /* MIP_MCOA */

			get_coacandidate();
			set_coa();
			sync_binding();

			if (debug > 2) {
				print_bl(stderr);
			}
		}

		if (pflag)
			probe_ifstatus(sock_dg6);
	}
}

#ifdef MIP_MCOA
static void
dereg_detach_coa(difam) 
	struct ifa_msghdr *difam;
{
        struct in6_ifreq ifr6;
        struct sockaddr_in6 dsin6, *sin6;
        struct sockaddr *rti_info[RTAX_MAX];
        char ifname[IFNAMSIZ];
	char *next, *limit;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;

        if (if_indextoname(difam->ifam_index, ifname) == NULL)
                return;

	/* Skip mip interface */
        if (strncmp(ifname, "mip", strlen("mip")) == 0) 
                return;

        get_rtaddrs(difam->ifam_addrs, (struct sockaddr *) (difam + 1), rti_info);
	if (rti_info[RTAX_IFA] == NULL)
		return;

	memset(&dsin6, 0, sizeof(dsin6));
	memcpy(&dsin6, (struct sockaddr_in6 *) rti_info[RTAX_IFA], sizeof(dsin6)); 
	
	/* Detached address must be global */
	if (in6_addrscope(&dsin6.sin6_addr) !=  __IPV6_ADDR_SCOPE_GLOBAL) 
		return;


	memset(&ifr6, 0, sizeof(ifr6));
	ifr6.ifr_addr = dsin6;
	strncpy(ifr6.ifr_name, ifname, strlen(ifname));
	if (ioctl(sock_dg6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		perror("ioctl(SIOCGIFAFLAG_IN6)");
		return;
	}

	/* address is now detached from the link, send
         *  deregfromforeign to mnd 
	 */
	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DETACHED) {
		int mib[6];
		char *ifmsg = NULL;
		int len;

		mib[0] = CTL_NET;
		mib[1] = PF_ROUTE;
		mib[2] = 0;
		mib[3] = AF_INET6;
		mib[4] = NET_RT_IFLIST;
		mib[5] = 0;

		if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
			perror("sysctl");
			return;
		}
		if ((ifmsg = malloc(len)) == NULL) {
			perror("malloc");
			return;
		}
		if (sysctl(mib, 6, ifmsg, &len, NULL, 0) < 0) {
			perror("sysctl");
			free(ifmsg);
			return;
		}
        
		limit = ifmsg +  len;
		for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
			char buf[1024];
			struct binding *bp;

			ifm = (struct if_msghdr *) next;

			if (ifm->ifm_type == RTM_NEWADDR) {
				ifam = (struct ifa_msghdr *) next;

				get_rtaddrs(ifam->ifam_addrs,
					    (struct sockaddr *) (ifam + 1), rti_info);
				sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];
				memset(&ifr6, 0, sizeof(ifr6));
				ifr6.ifr_addr = *sin6;

				/* unknown interface !? */
				if (if_indextoname(ifm->ifm_index, ifr6.ifr_name) == NULL) 
					continue;
				
				/* Do not use an address attached to ingress interface */
 				if(strlen(ingressif) > 0 && 
					(strncmp(ifr6.ifr_name, ingressif, 
					strlen(ingressif)) == 0)) 
                                         continue;

				/* MUST be global */
				if (in6_addrscope(&sin6->sin6_addr) !=  __IPV6_ADDR_SCOPE_GLOBAL) 
					continue;
					
				if (ioctl(sock_dg6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
					perror("ioctl(SIOCGIFAFLAG_IN6)");
					continue;
				}
				if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_READONLY) 
					continue;
				
				syslog(LOG_INFO, "Detached address is %s\n", 
					inet_ntop(AF_INET6, &dsin6.sin6_addr, buf, sizeof(buf)));
				syslog(LOG_INFO, "send dereg from address is %s\n", 
					inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)));
				
				LIST_FOREACH(bp, &bl_head, binding_entries) {
					if (memcmp(&bp->coa, &dsin6, sizeof(bp->coa)) == 0)
						break;
				}
				if (bp == NULL)
					break;
				mipsock_deregforeign(&bp->hoa, &dsin6, sin6, 
						     ifm->ifm_index, bp->bid);

				/* send bu to msock */
				free(ifmsg);
				return;
			}
		}
		if (ifmsg)
			free(ifmsg);
        }

	return;
}

int
mipsock_deregforeign(hoa, deregcoa, newcoa, ifindex, bid)
	struct sockaddr_in6 *hoa, *deregcoa, *newcoa;
	int ifindex;
	u_int16_t bid;
{
	int len;
	struct mipm_md_info *mdinfo;
	char buf[PA_BUFSIZE];

	len = sizeof(*mdinfo) + sizeof(*hoa) + sizeof(*deregcoa) + sizeof(*newcoa);
	mdinfo = (struct mipm_md_info *) alloca(len);
	if (mdinfo == NULL) 
		return (-1);

	memset(mdinfo, 0, len);
	mdinfo->mipm_md_hdr.miph_msglen	= len;
	mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
	mdinfo->mipm_md_hdr.miph_type	= MIPM_MD_INFO;
	mdinfo->mipm_md_hdr.miph_seq	= random();
	mdinfo->mipm_md_hint		= MIPM_MD_ADDR;
	mdinfo->mipm_md_command		= MIPM_MD_DEREGFOREIGN;
	mdinfo->mipm_md_ifindex		= ifindex;
	mdinfo->mipm_md_bid = bid; 

	memcpy(MIPD_HOA(mdinfo), hoa, sizeof(*hoa));
	memcpy(MIPD_COA(mdinfo), deregcoa, sizeof(*deregcoa));
	memcpy(MIPD_COA2(mdinfo), newcoa, sizeof(*newcoa));

	if (!mflag) {
		if (write(sock_m, mdinfo, len) < 0) {
			perror("wirte");
			return (-1);
		}
	}

	if (mdinfo)
		free(mdinfo);

	if (debug) {
		syslog(LOG_INFO, "Dereg from foreign: %s\n",
			(char *) inet_ntop(AF_INET6, &deregcoa->sin6_addr,
							buf, sizeof(buf)));
 	}

	return (0);
}
#endif /* MIP_MCOA */

int
chbinding(hoa, coa, bid)
	struct sockaddr_in6 *hoa, *coa;
	u_int16_t bid;
{
	int len;
	struct mipm_md_info *mdinfo;
	char buf[PA_BUFSIZE];

	len = sizeof(*mdinfo) + sizeof(*hoa) + sizeof(*coa);
	mdinfo = (struct mipm_md_info *) alloca(len);
	if (mdinfo == NULL)
		return (-1);

	memset(mdinfo, 0, len);
	mdinfo->mipm_md_hdr.miph_msglen	= len;
	mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
	mdinfo->mipm_md_hdr.miph_type	= MIPM_MD_INFO;
	mdinfo->mipm_md_hdr.miph_seq	= random();
	mdinfo->mipm_md_hint		= MIPM_MD_ADDR;
	mdinfo->mipm_md_command		= MIPM_MD_REREG;
#ifdef MIP_MCOA
	mdinfo->mipm_md_bid = bid; 
#endif /* MIP_MCOA */
	memcpy(MIPD_HOA(mdinfo), hoa, sizeof(*hoa));
	memcpy(MIPD_COA(mdinfo), coa, sizeof(*coa));

	if (!mflag) {
		if (write(sock_m, mdinfo, len) < 0) {
			perror("write");
			return (-1);
		}
	}

	if (debug) {
		syslog(LOG_INFO, "Binding: %s",
			(char *) inet_ntop(AF_INET6, &hoa->sin6_addr,
							buf, sizeof(buf)));
		syslog(LOG_INFO, "\t-> %s\n",
			(char *) inet_ntop(AF_INET6, &coa->sin6_addr,
							buf, sizeof(buf)));
	}

	return (0);
}


int
returntohome(hoa, coa, ifindex)
	struct sockaddr_in6 *hoa;
	struct sockaddr_in6 *coa;
	int ifindex;
{
	int len;
	struct mipm_md_info *mdinfo;
	char buf[PA_BUFSIZE];

	len = sizeof(*mdinfo) + sizeof(*hoa) + sizeof(*coa);
	mdinfo = (struct mipm_md_info *) alloca(len);
	if (mdinfo == NULL)
		return (-1);

	memset(mdinfo, 0, len);
	mdinfo->mipm_md_hdr.miph_msglen	= len;
	mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
	mdinfo->mipm_md_hdr.miph_type	= MIPM_MD_INFO;
	mdinfo->mipm_md_hdr.miph_seq	= random();
	mdinfo->mipm_md_hint		= MIPM_MD_ADDR;
	mdinfo->mipm_md_command		= MIPM_MD_DEREGHOME;
	mdinfo->mipm_md_ifindex		= ifindex;
	memcpy(MIPD_HOA(mdinfo), hoa, sizeof(*hoa));
	memcpy(MIPD_COA(mdinfo), hoa, sizeof(*hoa));

	if (!mflag) {
		if (write(sock_m, mdinfo, len) < 0) {
			perror("write");
			return (-1);
		}
	}

	if (debug) {
		syslog(LOG_INFO, "Return to home: %s\n",
			(char *) inet_ntop(AF_INET6, &hoa->sin6_addr,
							buf, sizeof(buf)));
 	}

	return (0);
}

void
recv_home_hint(ifindex, sin6, prefixlen)
	int ifindex;
	struct sockaddr_in6 *sin6;
	int prefixlen;
{
	struct binding *bp;
	int matchlen;

	LIST_FOREACH(bp, &bl_head, binding_entries) {
		matchlen = in6_matchlen(&bp->hoa.sin6_addr, &sin6->sin6_addr);
		if (matchlen >= prefixlen) {
			bp->flags &= ~BF_BOUND;
			bp->flags |= BF_HOME;
			memcpy(&bp->pcoa, &bp->coa, sizeof(bp->pcoa));
			bp->pcoaifindex =bp->coaifindex;
			memcpy(&bp->coa, &bp->hoa, sizeof(bp->hoa));
			bp->coaifindex = ifindex;
		}
	}
}
