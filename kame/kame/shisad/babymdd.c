/*      $Id: babymdd.c,v 1.4 2005/03/01 17:34:01 ryuji Exp $  */
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

#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/mipsock.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6mh.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

#include "babymdd.h"
#include "callout.h"
#include "shisad.h"

#define storage2sin6(x) ((struct sockaddr_in6 *)(x))

/* base functions */
static void baby_initif();
static void init_hoa(u_int16_t);
static struct if_info *init_if(char *);
static void print_debug();
static void baby_terminate();
static void baby_reset();

void baby_getifinfo(struct if_info *);
void baby_selection();
int baby_checklink();
int baby_rtmsg(struct rt_msghdr *, int);
int baby_mipmsg(struct mip_msghdr *, int);

/* MIPsocket commands */
static int baby_md_scan(struct if_info *);
static int baby_md_reg(struct sockaddr_in6 *, u_int16_t);
static void baby_md_home(struct sockaddr_in6 *, struct sockaddr_in6 *, int);
static void get_rtaddrs(int, struct sockaddr *, struct sockaddr **);

/* utilities */
static int baby_coa_equal(struct if_info *);
static int is_hoa_ornot(struct in6_addr *);
static int in6_addrscope(struct in6_addr *);
static struct if_info *baby_ifindex2ifinfo(u_int16_t);
static int send_rs(struct if_info  *);

struct mdd_info babyinfo;

void
baby_usage()
{
	fprintf(stderr, "babymdd is a simple movement detecter for a mobile node and a mobile router\n");
        fprintf(stderr, "babymdd [options] -h mipif interfaces..\n");
	fprintf(stderr, "\t-h mipif      specify your mipxx interface\n");
	fprintf(stderr, "\tinterfaces    specify interfaces which you want to attach to the Internet. If you don't specify any interfaces, babymdd will use all the available interfaces.\n");
	fprintf(stderr, "Options\n");
        fprintf(stderr, "\t-d            turn on debug mode\n");
        fprintf(stderr, "\t-D            turn on verbose debug mode\n");
        fprintf(stderr, "\t-p interval   polling link status per interval(sec)\n");
}


#if 0
static char *msgtypes[] = {
        "",
        "RTM_ADD: Add Route",
        "RTM_DELETE: Delete Route",
        "RTM_CHANGE: Change Metrics or flags",
        "RTM_GET: Report Metrics",
        "RTM_LOSING: Kernel Suspects Partitioning",
        "RTM_REDIRECT: Told to use different route",
        "RTM_MISS: Lookup failed on this address",
        "RTM_LOCK: fix specified metrics",
        "RTM_OLDADD: caused by SIOCADDRT",
        "RTM_OLDDEL: caused by SIOCDELRT",
        "RTM_RESOLVE: Route created by cloning",
        "RTM_NEWADDR: address being added to iface",
        "RTM_DELADDR: address being removed from iface",
        "RTM_OIFINFO: iface status change (pre-1.5)",
	"RTM_OIFINFO: Old (pre-1.5) RTM_IFINFO message",
	"RTM_IFINFO: iface/link going up/down etc.",
	"RTM_IFANNOUNCE: iface arrival/departure", 
	"RTM_ADDRINFO: change address flags",
        0,
};
#endif

int debug = 0;
int numerichost = 1;

int
main (argc, argv)
        int argc;
        char **argv;
{
	int ch, n;
	int nfds;
	fd_set fds;
	char buf[256];
	time_t now, lastlinkcheck;
	struct if_info *ifinfo;
	int priority = 0;

	memset(&babyinfo, 0, sizeof(babyinfo));

        while ((ch = getopt(argc, argv, "h:dDfnp")) != -1) {
		switch (ch) {
		case 'h':
			babyinfo.hoa_index = if_nametoindex(optarg);

			break;
		case 'd':
			babyinfo.debug = DEBUG_NORMAL;
			debug = 1;
			break;
		case 'D':
			babyinfo.debug = DEBUG_HIGH;
			debug = 1;
			break;
		case 'f':
			babyinfo.nondaemon = 1;
			break;
		case 'n':
			babyinfo.dns = 1;
			break;
		case 'p':
			babyinfo.linkpoll = 1;
			break;
		default:
			break;
		}
	}
	if (babyinfo.hoa_index <= 0) {
		baby_usage();
		exit(0);
	}

        argc -= optind;
        argv += optind;

        /* open syslog */
        openlog("shisad(baby)", 0, LOG_DAEMON);
        syslog(LOG_INFO, "Baby start !!\n");

	/* mdd initialization */
	LIST_INIT(&babyinfo.ifinfo_head);
	LIST_INIT(&babyinfo.hoainfo_head);
	
	/* open a routing socket */
	babyinfo.rtsock = socket(PF_ROUTE, SOCK_RAW, 0);
	if (babyinfo.rtsock < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s rtocket: %s\n",  
			       __FUNCTION__, strerror(errno));
		exit (0);
	}

	/* open a socket for linkinfo */
        babyinfo.linksock = socket(PF_INET6, SOCK_DGRAM, 0);
        if (babyinfo.linksock < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s linksocket: %s\n",  
			       __FUNCTION__, strerror(errno));
                exit (-1);
        }

	/* open a mipsock */
        babyinfo.mipsock = socket(PF_MOBILITY, SOCK_RAW, 0);
        if (babyinfo.mipsock < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s mipsocket: %s\n",  
			       __FUNCTION__, strerror(errno));
                exit (-1);
        }

	/* initilization of home addresses */
	init_hoa(babyinfo.hoa_index);

	/* initilization of interfaces */
	if (argc == 0) {
		/* 
		 * no interfaces are specified by users, babymdd uses all the
		 * available interfaces 
		 */
		struct ifaddrs *ifa, *ifap;

		if (getifaddrs(&ifap) != 0) {
			syslog(LOG_ERR, "getifaddrs failed: %s\n", 
				strerror(errno));
			exit(-1);
		}

		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			ifinfo = init_if(ifa->ifa_name);
			if (ifinfo)
				ifinfo->priority = priority++;
		}
		freeifaddrs(ifap);

	} else {
		while (argc--) {
			ifinfo = init_if(*argv++);
			
			/* increment priority, a bigger value indicats less priority */
			if (ifinfo)
				ifinfo->priority = priority++;
		} 
	}
	/* each interface is initialized here */
	baby_initif();

	/* dump Configuration */
 	if (DEBUGHIGH) {
		print_debug();
	}

        signal(SIGHUP, baby_terminate);
        signal(SIGINT, baby_terminate);
        signal(SIGKILL, baby_terminate);
        signal(SIGTERM, baby_terminate);

        if (!babyinfo.nondaemon) {
                if (daemon(0, 0) < 0) {
                        perror("daemon");
			baby_terminate();
                        exit(-1);
                }
        }

	baby_selection();

	if (DEBUGHIGH) {
		syslog(LOG_INFO, "<Interface Status>\n");
		print_debug();
	}
	lastlinkcheck = time(0);

	while (1) {
		                
                FD_ZERO(&fds);
		nfds = -1;
                FD_SET(babyinfo.rtsock, &fds);
		if (babyinfo.rtsock >= nfds)    
			nfds = babyinfo.rtsock + 1;
                FD_SET(babyinfo.mipsock, &fds);
		if (babyinfo.mipsock >= nfds)    
			nfds = babyinfo.mipsock + 1;

                if (select(nfds, &fds, NULL, NULL, &babyinfo.poll) < 0) {
			if (DEBUGNORM)
				syslog(LOG_ERR, "select %s\n", strerror(errno));
                        exit(-1);
                }
                if (FD_ISSET(babyinfo.rtsock, &fds)) {
                        n = read(babyinfo.rtsock, buf, sizeof(buf));
                        if (n < 0) 
                                continue;

			if (baby_rtmsg((struct rt_msghdr *)buf, n))
				baby_selection();
		}

                if (FD_ISSET(babyinfo.mipsock, &fds)) {
                        n = read(babyinfo.mipsock, buf, sizeof(buf));
                        if (n < 0) 
                                continue;

			if (baby_mipmsg((struct mip_msghdr *)buf, n))
				baby_selection();
		}

		/* link status check */
		now = time(0);
		if ((now - lastlinkcheck) > babyinfo.linkpoll) {
			if (baby_checklink())
				baby_selection();
			lastlinkcheck = time(0);

		}
	}

	return (0);
};

/* check link status */
int
baby_checklink() {
        struct ifmediareq ifmr;
	struct if_info *ifinfo, *ifinfo_next;

	for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		memset(&ifmr, 0, sizeof(ifmr));
		strncpy(ifmr.ifm_name, ifinfo->ifname, strlen(ifinfo->ifname));

		if (ioctl(babyinfo.linksock, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
			continue;

		if (ifinfo->linkstatus == ifmr.ifm_status)
			continue;

		if ((ifmr.ifm_status & IFM_AVALID) == 0) 
			continue;

		switch (IFM_TYPE(ifmr.ifm_active)) {
		case IFM_ETHER:
			if (ifmr.ifm_status & IFM_ACTIVE) {
				send_rs(ifinfo);

				if (DEBUGHIGH)
					syslog(LOG_INFO, "%s link up\n", ifinfo->ifname); 

			} else {
				if (DEBUGHIGH)
					syslog(LOG_INFO, 
					       "%s link failed\n", ifinfo->ifname); 
				baby_md_scan(ifinfo);
				send_rs(ifinfo);

			}
			break;
			
		case IFM_FDDI:
		case IFM_TOKEN:
			break;
		case IFM_IEEE80211:
			if (ifmr.ifm_status & IFM_ACTIVE) {
				send_rs(ifinfo);
				if (DEBUGHIGH)
					syslog(LOG_INFO, "%s link up\n", ifinfo->ifname); 
			}
			else {
				if (DEBUGHIGH)
					syslog(LOG_INFO, 
					       "%s link failed\n", ifinfo->ifname); 
				baby_md_scan(ifinfo);
				send_rs(ifinfo);

			}
			break;
		}
		ifinfo->linkstatus = ifmr.ifm_status;		
	}

	return (0);
}

/* reset router lifetime of NDP, 0 = success, -1 = error */
static int
baby_md_scan(struct if_info *ifinfo) {
	struct mipm_md_info mdinfo;
	
	if (!ifinfo)
		return (-1);

	memset(&mdinfo, 0, sizeof(mdinfo));
	mdinfo.mipm_md_hdr.miph_msglen	= sizeof(mdinfo);
	mdinfo.mipm_md_hdr.miph_version = MIP_VERSION;
	mdinfo.mipm_md_hdr.miph_type	= MIPM_MD_INFO;
	mdinfo.mipm_md_hdr.miph_seq	= random();
	mdinfo.mipm_md_command		= MIPM_MD_SCAN;
	mdinfo.mipm_md_ifindex          = ifinfo->ifindex;

	if (write(babyinfo.mipsock, &mdinfo, sizeof(babyinfo)) < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s: write %s\n", 
			       __FUNCTION__, strerror(errno));
		return (-1);
	}

	return (0);
}

static int
baby_md_reg(coa, bid) 
	struct sockaddr_in6 *coa;
	u_int16_t bid;
{
	int len;
	struct mipm_md_info *mdinfo;
	struct sockaddr_in6 hoa;
	struct hoa_info *hoainfo, *hoainfo_next;
	
	for (hoainfo = LIST_FIRST(&babyinfo.hoainfo_head);
	     hoainfo; hoainfo = hoainfo_next) {
		hoainfo_next = LIST_NEXT(hoainfo, hoainfo_entry); 

		memset(&hoa, 0, sizeof(hoa)); 
		hoa.sin6_family = AF_INET6;
		hoa.sin6_addr = ((struct sockaddr_in6 *)&hoainfo->hoa)->sin6_addr;
		hoa.sin6_len = sizeof(struct sockaddr_in6);

		/* do not send md_info msg for an address generated at a home link */
		if (mip6_are_prefix_equal(&hoa.sin6_addr, &coa->sin6_addr, 64)) 
			return (0);
		
		len = sizeof(*mdinfo) + sizeof(hoa) + sizeof(*coa);
		mdinfo = (struct mipm_md_info *) malloc(len);
		if (mdinfo == NULL)
			return (-1);
		
		memset(mdinfo, 0, len);
		mdinfo->mipm_md_hdr.miph_msglen	= len;
		mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
		mdinfo->mipm_md_hdr.miph_type	= MIPM_MD_INFO;
		mdinfo->mipm_md_hdr.miph_seq	= random();
		mdinfo->mipm_md_hint		= MIPM_MD_ADDR;
		mdinfo->mipm_md_command		= MIPM_MD_REREG;
		
		memcpy(MIPD_HOA(mdinfo), &hoa, sizeof(hoa));
		memcpy(MIPD_COA(mdinfo), coa, sizeof(*coa));
		
		if (write(babyinfo.mipsock, mdinfo, len) < 0) {
			if (DEBUGNORM)
				syslog(LOG_ERR, "%s: write %s\n", 
				       __FUNCTION__, strerror(errno));
			return (-1);
		}
		free(mdinfo);
		if (DEBUGNORM) {
			syslog(LOG_INFO, "[binding %s -> %s]\n", 
			       ip6_sprintf(&hoa.sin6_addr),ip6_sprintf(&coa->sin6_addr));
		}
	}

	return (0);
}

/* 0 return means no changes, 1 return means changes occured */
int
baby_mipmsg(mipm, msglen)
	struct mip_msghdr *mipm;
	int msglen;
{
	struct mipm_home_hint *miphome = NULL;
	struct mipm_md_info *mipmd = NULL;
	struct if_info *ifinfo;
	struct hoa_info *hoainfo, *hoainfo_next;

	switch (mipm->miph_type) {
	case MIPM_HOME_HINT:
		miphome = (struct mipm_home_hint *)mipm;

		ifinfo = baby_ifindex2ifinfo(miphome->mipmhh_ifindex);
		if (ifinfo == NULL)                        
			break;
		
		/* 
		 * compare all the home addresses to the prefix
		 * received from mipsock. If one of the home address
		 * is matched, babymdd assumes "return home"
		 */
		for (hoainfo = LIST_FIRST(&babyinfo.hoainfo_head);
		     hoainfo; hoainfo = hoainfo_next) {
			hoainfo_next = LIST_NEXT(hoainfo, hoainfo_entry);

			if (miphome->mipmhh_prefix && 
			    mip6_are_prefix_equal(
				    &((struct sockaddr_in6 *)miphome->mipmhh_prefix)->sin6_addr,
				    &storage2sin6(&hoainfo->hoa)->sin6_addr, 
					miphome->mipmhh_prefixlen)) {

				babyinfo.whereami = IAMHOME;

				storage2sin6(&ifinfo->coa)->sin6_addr =
					storage2sin6(&hoainfo->hoa)->sin6_addr;
				storage2sin6(&ifinfo->coa)->sin6_family = AF_INET6;
				storage2sin6(&ifinfo->coa)->sin6_len = sizeof(struct sockaddr_in6);
				
				babyinfo.coaif = NULL;
				
				return (1);
			}
		}
		break;
	case MIPM_MD_INFO:
                mipmd = (struct mipm_md_info *)mipm;
                if (mipmd->mipm_md_command == MIPM_MD_SCAN) {

			ifinfo = baby_ifindex2ifinfo(mipmd->mipm_md_ifindex);
			if (ifinfo != NULL)                        
				send_rs(ifinfo);
                } 
		break;
	default:
		break;
	}

	return (0);
}


/* 0 return means no changes, 1 return means changes occured */
int
baby_rtmsg(rtm, msglen)
	struct rt_msghdr *rtm;
	int msglen;
{
        struct ifa_msghdr *ifam;
        struct in6_ifreq ifr6;
	struct if_info *ifinfo;
        struct sockaddr *rti_info[RTAX_MAX];
	struct sockaddr_in6 *sin6;
	struct hoa_info *hoainfo, *hoainfo_next;

#if 0
	if (DEBUGHIGH) {
		if (msgtypes[rtm->rtm_type])
			syslog(LOG_INFO, "\t%s:\n", msgtypes[rtm->rtm_type]);
	}
#endif
	
	switch(rtm->rtm_type) {
	case RTM_NEWADDR:
		if (msglen < sizeof(struct ifa_msghdr))
			return (0);
		ifam = (struct ifa_msghdr *)rtm;

		/* find appropriate ifinfo */
		ifinfo = baby_ifindex2ifinfo(ifam->ifam_index);
		if (ifinfo == NULL)
			break;

		baby_getifinfo(ifinfo); 	
		
		return (1);

	case RTM_DELADDR:
		if (msglen < sizeof(struct ifa_msghdr))
			return (0);
		ifam = (struct ifa_msghdr *)rtm;

		/* find appropriate ifinfo */
		ifinfo = baby_ifindex2ifinfo(ifam->ifam_index);
		if (ifinfo == NULL)
			return (0);
		
		get_rtaddrs(ifam->ifam_addrs,
			    (struct sockaddr *) (ifam + 1), rti_info);

		if (rti_info[RTAX_IFA]->sa_family == AF_INET6) {

			sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];

			if (DEBUGHIGH)
				syslog(LOG_INFO, "%s becomes invalid\n", 
				       ip6_sprintf(&sin6->sin6_addr));

			/* 
			 * when a home address is deleted, it assumes
			 * moving out from home. If a home address is
			 * detached, we use the same code. see
			 * ADDRINFO case.
			 */
			if (babyinfo.whereami == IAMHOME) {

				for (hoainfo = LIST_FIRST(&babyinfo.hoainfo_head); hoainfo; 
				     hoainfo = hoainfo_next) {
					hoainfo_next = LIST_NEXT(hoainfo, hoainfo_entry);
					
					if ((ifinfo == babyinfo.coaif) && 
					    (mip6_are_prefix_equal(&storage2sin6(&hoainfo->hoa)->sin6_addr,
								   &sin6->sin6_addr, 64))) {
						
						memset(&ifinfo->coa, 0, 
						       sizeof(ifinfo->coa));
						memset(&ifinfo->pcoa, 0, 
						       sizeof(ifinfo->coa));
						babyinfo.whereami = 0; /* reset */
						break;
					}
				}
			}
			
			if (babyinfo.coaif == ifinfo) {
				/* remove the primary CoA */
				babyinfo.coaif = NULL;
				
				/* 
				 * if a different CoA becomes
				 * invalid, getting a new
				 * coa 
				 */
				if (babyinfo.whereami != IAMHOME && 
				    IN6_ARE_ADDR_EQUAL(&storage2sin6(&ifinfo->coa)->sin6_addr,
						       &sin6->sin6_addr)) {
					
					baby_getifinfo(ifinfo); 	
				} 
			} else {
				memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));
				baby_getifinfo(ifinfo); 	
			}
		}

		return (1);

	case RTM_ADDRINFO:
		ifam = (struct ifa_msghdr *)rtm;

		/* find appropriate ifinfo */
		ifinfo = baby_ifindex2ifinfo(ifam->ifam_index);
		if (ifinfo == NULL)
			break;

		get_rtaddrs(ifam->ifam_addrs, (struct sockaddr *) (ifam + 1), rti_info);
		if (rti_info[RTAX_IFA] == NULL)
			break;
		if (rti_info[RTAX_IFA]->sa_family != AF_INET6) 
			break;

		sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];
		
		/* The detached address must be global */
		if (in6_addrscope(&sin6->sin6_addr) !=  
		    __IPV6_ADDR_SCOPE_GLOBAL) 
			break;

		/* retrieving flags */
		memset(&ifr6, 0, sizeof(ifr6));
		ifr6.ifr_addr = *sin6;
		strncpy(ifr6.ifr_name, ifinfo->ifname, strlen(ifinfo->ifname));
		if (ioctl(babyinfo.linksock, SIOCGIFAFLAG_IN6, &ifr6) < 0) 
			break;

		/* 
		 * When the address is detached, send dereg from
		 * foreign. 
		 */
		if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DETACHED) {
			if (DEBUGHIGH)
				syslog(LOG_INFO, "%s is detached\n", 
				       ip6_sprintf(&sin6->sin6_addr)); 

			/* 
			 * The HoA is removed by mnd. Otherwise, it
			 * removes the detached address from the
			 * interface.
			 */
			if (!is_hoa_ornot(&sin6->sin6_addr))
				delete_ip6addr(ifinfo->ifname, &sin6->sin6_addr, 128);
			else {
				/* 
				 * when the HoA is detached, it
				 * assumes moving out from the home 
				 */
				memset(&ifinfo->coa, 0, 
				       sizeof(ifinfo->coa));
				memset(&ifinfo->pcoa, 0, 
				       sizeof(ifinfo->coa));
				babyinfo.whereami = 0; /* reset */
				
				baby_getifinfo(ifinfo);

				return (1);
			}
		}
		break;
	default:
		break;
	}
	return (0);	
}

#define MAYHAVE(var, cap, def)  \
	do {                    \
		if ((var = agetnum(cap)) < 0)  \
			var = def;  \
	} while (0)


/* 
 * 0 not
 * 1 hoa
 */
static int
is_hoa_ornot(struct in6_addr *addr) {
	struct hoa_info  *hoainfo, *hoainfo_next;

	for (hoainfo = LIST_FIRST(&babyinfo.hoainfo_head); hoainfo; 
	     hoainfo = hoainfo_next) {
		hoainfo_next = LIST_NEXT(hoainfo, hoainfo_entry);
					
		if (IN6_ARE_ADDR_EQUAL(addr, &storage2sin6(&hoainfo->hoa)->sin6_addr))
			return (1);
	}

	return (0);
}

/* 
 * if multiple mobile prefixes are advertised at a home link, babymdd
 * must be aware of all the global addressed generated by the mobile
 * prefixes 
 */
static void
init_hoa(u_int16_t hoaindex) {
	int mib[6], len;
	char *ifmsg = NULL, *next, *limit;
        struct if_msghdr *ifm;
        struct ifa_msghdr *ifam;
        struct sockaddr *rti_info[RTAX_MAX];
        struct in6_ifreq ifr6;
        struct sockaddr_in6 *sin6;
	struct hoa_info *hinfo;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET6;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, (size_t *)&len, NULL, 0) < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "sysctl %s\n", strerror(errno));
		return;
	}
	if ((ifmsg = malloc(len)) == NULL) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "malloc %s\n", strerror(errno));
		return;
	}
	if (sysctl(mib, 6, ifmsg, (size_t *)&len, NULL, 0) < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "sysctl %s\n", strerror(errno));
		free(ifmsg);
		return;
	}
 
	limit = ifmsg +  len;
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		
		ifm = (struct if_msghdr *) next;

		/* unknown interface !? */
		if (ifm->ifm_index != hoaindex)
			continue;
		
		if (ifm->ifm_type == RTM_NEWADDR) {
			ifam = (struct ifa_msghdr *) next;
			
			get_rtaddrs(ifam->ifam_addrs,
				    (struct sockaddr *) (ifam + 1), rti_info);
			sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];
			memset(&ifr6, 0, sizeof(ifr6));
			ifr6.ifr_addr = *sin6;
			
			/* MUST be global */
			if (in6_addrscope(&sin6->sin6_addr) !=  
			    __IPV6_ADDR_SCOPE_GLOBAL) 
				continue;
			
#if 0
			if (ioctl(babyinfo.linksock, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
				perror("ioctl(SIOCGIFAFLAG_IN6)");
				continue;
			}
			if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_READONLY)
				continue;
#endif

			/* allocation of memory for hoa_info */
			hinfo = malloc(sizeof(struct hoa_info));
			if (hinfo == NULL)
				continue;
			memset(hinfo, 0, sizeof(struct hoa_info));
			
			memcpy(&hinfo->hoa, sin6, sizeof(struct sockaddr_in6));
			LIST_INSERT_HEAD(&babyinfo.hoainfo_head, hinfo, hoainfo_entry);
			
			free(ifmsg);
			ifmsg = NULL;

		}
	}
	if (ifmsg)
		free(ifmsg);

	return;

}

static struct if_info *
init_if(char *targetif) {
	struct if_info *ifinfo;
	u_int16_t index = 0;

	index = if_nametoindex(targetif);
	if (index == 0) {
		syslog(LOG_ERR, "%s is not correct, ignore\n", targetif);
		return NULL;
	}

	ifinfo = malloc(sizeof(struct if_info));
	memset(ifinfo, 0, sizeof(struct if_info));
	strncpy(ifinfo->ifname, targetif, strlen(targetif));
	ifinfo->ifindex = index;

	/* add to babyinfo iflist */
	LIST_INSERT_HEAD(&babyinfo.ifinfo_head, ifinfo, ifinfo_entry);

	return (ifinfo);
};


/* Print all the information stored in babymdd */
static void
print_debug () {
	struct if_info *ifinfo;
	struct hoa_info *hoainfo;

	syslog(LOG_INFO, "babymdd info.\n");
	syslog(LOG_INFO, "\tdebug level %d\n", babyinfo.debug); 
	syslog(LOG_INFO, "\tDNS is %s\n", 
	       (babyinfo.dns) ? "active" : "inactive");
	syslog(LOG_INFO, "\tmdd is %s\n", 
	       (babyinfo.nondaemon) ? "forwarground":"background");

	syslog(LOG_INFO, "\tHoA:\n");
	LIST_FOREACH(hoainfo, &babyinfo.hoainfo_head, hoainfo_entry) {
		syslog(LOG_INFO, "%s\n", 
		       ip6_sprintf(&storage2sin6(&hoainfo->hoa)->sin6_addr));
	}

	syslog(LOG_INFO, "\tCoA:\n");
	LIST_FOREACH(ifinfo, &babyinfo.ifinfo_head, ifinfo_entry) {
		syslog(LOG_INFO, "\t\tifname %s\n", ifinfo->ifname);
		syslog(LOG_INFO, "\t\tpriority %d\n", ifinfo->priority);
		if (ifinfo->coa.ss_family == AF_INET6)
			syslog(LOG_INFO, "\t\t%s\n", 
			       ip6_sprintf(&storage2sin6(&ifinfo->coa)->sin6_addr));
	}
}


void
baby_reset() {
	struct if_info *ifinfo, *ifinfo_next;
	struct hoa_info *hoainfo, *hoainfo_next;

	/* Clear all the memory for hoa_info entries */
	for (hoainfo = LIST_FIRST(&babyinfo.hoainfo_head); hoainfo; 
	     hoainfo = hoainfo_next) {
		hoainfo_next = LIST_NEXT(hoainfo, hoainfo_entry);

		LIST_REMOVE(hoainfo, hoainfo_entry);
		free(hoainfo);
		hoainfo = NULL;
	};
	
	/* Clear all the memory for coa_info entries */
	for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);

		LIST_REMOVE(ifinfo, ifinfo_entry);
		free(ifinfo);
		ifinfo = NULL;
	};

	syslog(LOG_INFO, "goodbye\n");
	return;
};


static void 
baby_terminate() {

	baby_reset();
	exit(0);
}

static void
baby_initif() {
	struct if_info *ifinfo, *ifinfo_next;

	/* Sorting by priority  */
again:
	for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		if (ifinfo_next == NULL) 
			break;
		
		if (ifinfo->priority > ifinfo_next->priority) {
			LIST_REMOVE(ifinfo_next, ifinfo_entry);
			LIST_INSERT_BEFORE(ifinfo, ifinfo_next, ifinfo_entry);
			ifinfo_next = ifinfo;
			goto again;
		}
	}

	/* Retrieving care-of addresses per interface */
	for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);

		baby_getifinfo(ifinfo); 
	}

	return;
}

static int
in6_addrscope(addr)
	struct in6_addr *addr;
{
	int scope;

	if (addr->s6_addr[0] == 0xfe) {
		scope = addr->s6_addr[1] & 0xc0;

		switch (scope) {
		case 0x80:
			return (__IPV6_ADDR_SCOPE_LINKLOCAL);
			break;
		case 0xc0:
			return (__IPV6_ADDR_SCOPE_SITELOCAL);
			break;
		default:
			return (__IPV6_ADDR_SCOPE_GLOBAL); /* just in case */
			break;
		}
	}


	if (addr->s6_addr[0] == 0xff) {
		scope = addr->s6_addr[1] & 0x0f;

		/*
		 * due to other scope such as reserved,
		 * return scope doesn't work.
		 */
		switch (scope) {
		case __IPV6_ADDR_SCOPE_INTFACELOCAL:
			return (__IPV6_ADDR_SCOPE_INTFACELOCAL);
			break;
		case __IPV6_ADDR_SCOPE_LINKLOCAL:
			return (__IPV6_ADDR_SCOPE_LINKLOCAL);
			break;
                case __IPV6_ADDR_SCOPE_SITELOCAL:
			return (__IPV6_ADDR_SCOPE_SITELOCAL);
			break;
		default:
			return (__IPV6_ADDR_SCOPE_GLOBAL);
			break;
		}
	}

	/*
	 * Regard loopback and unspecified addresses as global, since
	 * they have no ambiguity.
	 */
	if (bcmp(&in6addr_loopback, addr, sizeof(*addr) - 1) == 0) {
		if (addr->s6_addr[15] == 1) /* loopback */
			return (__IPV6_ADDR_SCOPE_LINKLOCAL);
		if (addr->s6_addr[15] == 0) /* unspecified */
			return (__IPV6_ADDR_SCOPE_GLOBAL); /* XXX: correct? */
	}

	return (__IPV6_ADDR_SCOPE_GLOBAL);
}


#define ROUNDUP(a, size)                                        \
	(((a) & ((size)-1)) ? (1+((a) | ((size)-1))) : (a))

static int
next_sa(sa)
        struct sockaddr *sa;
{
        if (sa->sa_len) {
                return (ROUNDUP(sa->sa_len, sizeof (u_long)));
        } else {
                return (sizeof(u_long));
        }
}


static void
get_rtaddrs(addrs, sa, rti_info)
        int addrs;
        struct sockaddr *sa;
        struct sockaddr *rti_info[];
{
        int i;

        for (i=0; i < RTAX_MAX; i++) {
                if (addrs & (1 << i)) {
                        rti_info[i] = sa;
                        sa = (struct sockaddr *) ((caddr_t) sa + next_sa(sa));
                } else {
                        rti_info[i] = NULL;
                }
        }
}

void
baby_getifinfo(ifinfo) 
	struct if_info *ifinfo;
{
	int mib[6];
	char *ifmsg = NULL;
	int len;
        char *next, *limit;
        struct if_msghdr *ifm;
        struct ifa_msghdr *ifam;
        struct sockaddr *rti_info[RTAX_MAX];
        struct in6_ifreq ifr6;
        struct sockaddr_in6 *sin6;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET6;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, (size_t *)&len, NULL, 0) < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "sysctl %s\n", strerror(errno));
		return;
	}
	if ((ifmsg = malloc(len)) == NULL) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "malloc %s\n", strerror(errno));
		return;
	}
	if (sysctl(mib, 6, ifmsg, (size_t *)&len, NULL, 0) < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "sysctl %s\n", strerror(errno));
		free(ifmsg);
		return;
	}
 
	memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));
        
	limit = ifmsg +  len;
	for (next = ifmsg; next < limit; next += ifm->ifm_msglen) {
		
		ifm = (struct if_msghdr *) next;
		
		if (ifm->ifm_type == RTM_NEWADDR) {
			ifam = (struct ifa_msghdr *) next;
			
			get_rtaddrs(ifam->ifam_addrs,
				    (struct sockaddr *) (ifam + 1), rti_info);
			sin6 = (struct sockaddr_in6 *) rti_info[RTAX_IFA];
			memset(&ifr6, 0, sizeof(ifr6));
			ifr6.ifr_addr = *sin6;
			
			/* unknown interface !? */
			if (if_indextoname(ifm->ifm_index, 
					   ifr6.ifr_name) == NULL) 
				continue;

			if (ifm->ifm_index != ifinfo->ifindex)
				continue;
			
			/* MUST be global */
			if (in6_addrscope(&sin6->sin6_addr) !=  
			    __IPV6_ADDR_SCOPE_GLOBAL) 
				continue;

			if (ioctl(babyinfo.linksock, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
				perror("ioctl(SIOCGIFAFLAG_IN6)");
				continue;
			}
			if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_READONLY)
				continue;

			memcpy(&ifinfo->coa, sin6, sizeof(struct sockaddr_in6));
			
			free(ifmsg);
			return;
		}
	}
	memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));
	if (ifmsg)
		free(ifmsg);

	return;
}

/* detrmin which CoAs are passed to mobile network daemon */
void
baby_selection() {
	struct if_info *ifinfo, *ifinfo_next;

	if (babyinfo.whereami == IAMHOME) {
		/* 
		 * when it moves to home but the primary CoA is not
		 * set, it sends MD_INFO message indicating home. If
		 * the primary CoA is already set, do nothing. MR
		 * being home, the coa can be changed to other than
		 * home address (ex. an address auto-configured at the
		 * home link), but it does not matter whether coa is
		 * the home address or not. Only when the home address
		 * is detached/deleted, baby_selection() starts to
		 * select other address as a primary CoA and marks
		 * foreign. 
		 */
		
		for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); 
		     ifinfo; ifinfo = ifinfo_next) {
			ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);

			if (is_hoa_ornot(&(storage2sin6(&ifinfo->coa)->sin6_addr)))
				break;
		}
		if (ifinfo && babyinfo.coaif != ifinfo) {
			struct hoa_info *hoainfo, *hoainfo_next;

			for (hoainfo = LIST_FIRST(&babyinfo.hoainfo_head);
			     hoainfo; hoainfo = hoainfo_next) {
				hoainfo_next = LIST_NEXT(hoainfo, hoainfo_entry); 
				
				baby_md_home(storage2sin6(&hoainfo->hoa), 
				    storage2sin6(&ifinfo->coa), 
				    ifinfo->ifindex);
			}
		}

		return;
	}

	/* pick a primary CoA from the first matched interface */
	for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); 
	     ifinfo; ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		if (ifinfo->coa.ss_family != AF_INET6) 
			continue;
		
		/* 
		 * when the primray coa is not set or
		 * the priority of the primary coa is
		 * lower than the one of the active
		 * interface (ifinfo), trigger
		 * movement detection to other daemons
		 */
		if (((babyinfo.coaif == NULL) || 
		     (babyinfo.coaif && 
		      babyinfo.coaif->priority <= ifinfo->priority)) 
		    && !baby_coa_equal(ifinfo)) {
			
			fprintf(stderr,"sending reg info\n");
			baby_md_reg((struct sockaddr_in6 *)&ifinfo->coa, 0); 
			memcpy(&ifinfo->pcoa, &ifinfo->coa, 
			       sizeof(ifinfo->coa));
			
			babyinfo.coaif = ifinfo;
			babyinfo.whereami = IAMFOREIGN;
			
			return;	
		}
	}

	return;
}


static int
baby_coa_equal(struct if_info *ifinfo) {

	if ((ifinfo->coa.ss_family != 0) && 
	    (ifinfo->coa.ss_family != ifinfo->pcoa.ss_family)) 
		return (0);

	if (ifinfo->coa.ss_family == AF_INET6) {
		if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)&ifinfo->coa)->sin6_addr, 
				       &((struct sockaddr_in6 *)&ifinfo->pcoa)->sin6_addr))
			return (1);
	}

	return (0);
};

static int
send_rs(struct if_info  *ifinfo) {
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pi = NULL;
        struct sockaddr_in6 to;
        char adata[512], buf[1024];
        struct nd_router_solicit *rs;
        size_t rslen = 0;
	int icmpsock = -1, on = 1;

	icmpsock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmpsock < 0) {
		if (DEBUGHIGH)
			syslog(LOG_ERR, "%s socket: %s\n",  
			       __FUNCTION__, strerror(errno));
		return (0);
	}
	if (setsockopt(icmpsock, IPPROTO_IPV6, 
		       IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
		if (DEBUGHIGH)
			syslog(LOG_ERR, "%s setsockopt: %s\n",  
			       __FUNCTION__, strerror(errno));
		return (0);
	}

        memset(&to, 0, sizeof(to));
        if (inet_pton(AF_INET6, "ff02::1",&to.sin6_addr) != 1) {
		close (icmpsock);
                return (-1);
	}
	to.sin6_family = AF_INET6;
	to.sin6_port = 0;
	to.sin6_scope_id = 0;
	to.sin6_len = sizeof (struct sockaddr_in6);

        msg.msg_name = (void *)&to;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (void *) adata;
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) 
		+ CMSG_SPACE(sizeof(int));

	/* Packet Information i.e. Source Address */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	memset(pi, 0, sizeof(*pi));
	pi->ipi6_ifindex = ifinfo->ifindex;
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_HOPLIMIT;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)(CMSG_DATA(cmsgptr)) = 255;
        cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
		
	bzero(buf, sizeof(buf));
	rs = (struct nd_router_solicit *)buf;
        rs->nd_rs_type = ND_ROUTER_SOLICIT;
        rs->nd_rs_code = 0;
        rs->nd_rs_cksum = 0;
        rs->nd_rs_reserved = 0;
	rslen = sizeof(struct nd_router_solicit);

	iov.iov_base = buf;
	iov.iov_len = rslen;
	
	if (sendmsg(icmpsock, &msg, 0) < 0) {
		if (DEBUGHIGH)
			syslog(LOG_ERR, "%s sendmsg: %s\n",  
			       __FUNCTION__, strerror(errno));
	}

	close (icmpsock);
	return errno;
}


static void
baby_md_home(hoa, coa, ifindex)
        struct sockaddr_in6 *hoa;
        struct sockaddr_in6 *coa;
        int ifindex;
{
        int len;
        struct mipm_md_info *mdinfo;

        len = sizeof(*mdinfo) + sizeof(*hoa) + sizeof(*coa);
        mdinfo = (struct mipm_md_info *) malloc(len);
        if (mdinfo == NULL)
                return;

        memset(mdinfo, 0, len);
        mdinfo->mipm_md_hdr.miph_msglen = len;
        mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
        mdinfo->mipm_md_hdr.miph_type   = MIPM_MD_INFO;
        mdinfo->mipm_md_hdr.miph_seq    = random();
        mdinfo->mipm_md_hint            = MIPM_MD_ADDR;
        mdinfo->mipm_md_command         = MIPM_MD_DEREGHOME;
        mdinfo->mipm_md_ifindex         = ifindex;
        memcpy(MIPD_HOA(mdinfo), hoa, sizeof(*hoa));
        memcpy(MIPD_COA(mdinfo), hoa, sizeof(*hoa));

	if (write(babyinfo.mipsock, mdinfo, len) < 0) {
		if (DEBUGNORM) {
			syslog(LOG_ERR, "%s write: %s\n", 
			       __FUNCTION__, strerror(errno));
		}
		return;
	}

	if (mdinfo)
		free(mdinfo);

	if (DEBUGNORM) {
                syslog(LOG_INFO, "Returning HOME: %s\n",
		       ip6_sprintf(&hoa->sin6_addr));
        }

        return;
}

static struct if_info *
baby_ifindex2ifinfo(u_int16_t ifindex) {
	struct if_info *ifinfo = NULL, *ifinfo_next = NULL;

	for (ifinfo = LIST_FIRST(&babyinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		if (ifinfo->ifindex == ifindex)
			break;
	}

	return ifinfo;
}
