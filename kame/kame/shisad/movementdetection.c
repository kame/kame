/*      $Id: movementdetection.c,v 1.5 2005/05/17 10:31:24 keiichi Exp $  */
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

#include "advcap.h"
#include "movementdetection.h"
#include "callout.h"
#include "shisad.h"

static void parse_mainconfig();
static void parse_ifconfig(char *);
static void print_mainconfig();
static void print_ifconfig();
static void mdd_terminate();
void mdd_reset();
void mdd_getifinfo(struct if_info *);
void mdd_selection();
int mdd_checklink();

int mdd_rtmsg(struct rt_msghdr *, int);
int mdd_mipmsg(struct mip_msghdr *, int);

static void mdd_initif();
static int mdd_md_scan(struct if_info *);
static int mdd_md_reg(struct sockaddr_in6 *, u_int16_t);
static void mdd_md_dereg(struct if_info *);
static void mdd_md_home(struct sockaddr_in6 *, struct sockaddr_in6 *, int);


static void get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
static int mdd_coa_equal(struct if_info *);
static int send_rs(struct if_info  *);

static int in6_addrscope(struct in6_addr *);
static struct if_info *mdd_ifindex2ifinfo(u_int16_t);


char *conffile = DEFAULT_CONFFILE;
struct mdd_info mddinfo;

#define storage2sin6(x) ((struct sockaddr_in6 *)(x))

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
int namelookup = 1;

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

	memset(&mddinfo, 0, sizeof(mddinfo));

        while ((ch = getopt(argc, argv, "c:dDf")) != -1) {
		switch (ch) {
		case 'c':
			conffile = optarg;
			break;
		case 'd':
			mddinfo.debug = DEBUG_NORMAL;
			debug = 1;
			break;
		case 'D':
			mddinfo.debug = DEBUG_HIGH;
			debug = 1;
			break;
		case 'f':
			mddinfo.nondaemon = 1;
			break;
		default:
			break;
		}
	}
        argc -= optind;
        argv += optind;
	if (argc == 0) {
		fprintf(stderr,
                        "usage: mdd [-dDf] [-c conffile] "
                        "interfaces...\n");
                exit(1);
	}

        /* open syslog */
        openlog("shisad(move)", 0, LOG_DAEMON);
        syslog(LOG_INFO, "Let's start moving\n");

	/* mdd initialization */
	LIST_INIT(&mddinfo.ifinfo_head);
	mddinfo.rtsock = socket(PF_ROUTE, SOCK_RAW, 0);
	if (mddinfo.rtsock < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s rtocket: %s\n",  
			       __FUNCTION__, strerror(errno));
		exit (0);
	}
        mddinfo.linksock = socket(PF_INET6, SOCK_DGRAM, 0);
        if (mddinfo.linksock < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s linksocket: %s\n",  
			       __FUNCTION__, strerror(errno));
                exit (-1);
        }
        mddinfo.mipsock = socket(PF_MOBILITY, SOCK_RAW, 0);
        if (mddinfo.mipsock < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s mipsocket: %s\n",  
			       __FUNCTION__, strerror(errno));
                exit (-1);
        }

	/* parse configuration file */
	parse_mainconfig();
        while (argc--)
		parse_ifconfig(*argv++);

	/* each interface is initialized here */
	mdd_initif();

	/* dump Configuration */
 	if (DEBUGHIGH) {
		print_mainconfig();
		print_ifconfig();
	}

        signal(SIGHUP, mdd_terminate);
        signal(SIGINT, mdd_terminate);
        signal(SIGKILL, mdd_terminate);
        signal(SIGTERM, mdd_terminate);

        if (!mddinfo.nondaemon) {
                if (daemon(0, 0) < 0) {
                        perror("daemon");
			mdd_terminate();
                        exit(-1);
                }
        }

	mdd_selection();

	if (DEBUGHIGH) {
		syslog(LOG_INFO, "<Interface Status>\n");
		print_ifconfig();
	}
	lastlinkcheck = time(0);

	while (1) {
		                
                FD_ZERO(&fds);
		nfds = -1;
                FD_SET(mddinfo.rtsock, &fds);
		if (mddinfo.rtsock >= nfds)    
			nfds = mddinfo.rtsock + 1;
                FD_SET(mddinfo.mipsock, &fds);
		if (mddinfo.mipsock >= nfds)    
			nfds = mddinfo.mipsock + 1;

                if (select(nfds, &fds, NULL, NULL, &mddinfo.poll) < 0) {
			if (DEBUGNORM)
				syslog(LOG_ERR, "select %s\n", strerror(errno));
                        exit(-1);
                }
                if (FD_ISSET(mddinfo.rtsock, &fds)) {
                        n = read(mddinfo.rtsock, buf, sizeof(buf));
                        if (n < 0) 
                                continue;

			if (mdd_rtmsg((struct rt_msghdr *)buf, n))
				mdd_selection();
		}

                if (FD_ISSET(mddinfo.mipsock, &fds)) {
                        n = read(mddinfo.mipsock, buf, sizeof(buf));
                        if (n < 0) 
                                continue;

			if (mdd_mipmsg((struct mip_msghdr *)buf, n))
				mdd_selection();
		}

		/* link status check */
		now = time(0);
		if ((now - lastlinkcheck) > mddinfo.linkpoll) {
			if (mdd_checklink())
				mdd_selection();
			lastlinkcheck = time(0);

		}
	}

	return (0);
};

/* check link status */
int
mdd_checklink() {
        struct ifmediareq ifmr;
	struct if_info *ifinfo, *ifinfo_next;

	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		memset(&ifmr, 0, sizeof(ifmr));
		strncpy(ifmr.ifm_name, ifinfo->ifname, strlen(ifinfo->ifname));

		if (ioctl(mddinfo.linksock, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
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
				mdd_md_scan(ifinfo);
				send_rs(ifinfo);

				/* XXX shoud be called only when mdd receives RTM_IF_DEL? */ 
				if (mddinfo.multiplecoa) 
					mdd_md_dereg(ifinfo);
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
				mdd_md_scan(ifinfo);
				send_rs(ifinfo);

				/* XXX shoud be called only when mdd receives RTM_IF_DEL? */ 
				if (mddinfo.multiplecoa)
					mdd_md_dereg(ifinfo);
			}
			break;
		}
		ifinfo->linkstatus = ifmr.ifm_status;		
	}

	return (0);
}

/* reset router lifetime of NDP, 0 = success, -1 = error */
static int
mdd_md_scan(struct if_info *ifinfo) {
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

	if (write(mddinfo.mipsock, &mdinfo, sizeof(mddinfo)) < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s: write %s\n", 
			       __FUNCTION__, strerror(errno));
		return (-1);
	}

	return (0);
}

static int
mdd_md_reg(coa, bid) 
	struct sockaddr_in6 *coa;
	u_int16_t bid;
{
	int len;
	struct mipm_md_info *mdinfo;
	struct sockaddr_in6 hoa;

	memset(&hoa, 0, sizeof(hoa)); 
	hoa.sin6_family = AF_INET6;
	hoa.sin6_addr = mddinfo.hoa;
	hoa.sin6_len = sizeof(struct sockaddr_in6);

	/* do not send md_info msg including the home link */
	if (mip6_are_prefix_equal(&mddinfo.hoa, &coa->sin6_addr, 64)) 
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
	if (mddinfo.multiplecoa) 
		memcpy(&((struct sockaddr_in6 *)MIPD_COA(mdinfo))->sin6_port,
		    &bid, sizeof(u_int16_t));
	
	if (write(mddinfo.mipsock, mdinfo, len) < 0) {
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

	return (0);
}

/* 0 return means no changes, 1 return means changes occured */
int
mdd_mipmsg(mipm, msglen)
	struct mip_msghdr *mipm;
	int msglen;
{
	struct mipm_home_hint *miphome = NULL;
	struct mipm_md_info *mipmd = NULL;
	struct if_info *ifinfo;

	switch (mipm->miph_type) {
	case MIPM_HOME_HINT:
		miphome = (struct mipm_home_hint *)mipm;

		ifinfo = mdd_ifindex2ifinfo(miphome->mipmhh_ifindex);
		if (ifinfo == NULL)                        
			break;
		
		if (miphome->mipmhh_prefix && 
		    mip6_are_prefix_equal(&((struct sockaddr_in6 *)miphome->mipmhh_prefix)->sin6_addr,
					  &mddinfo.hoa, miphome->mipmhh_prefixlen)) {

			mddinfo.whereami = IAMHOME;

			storage2sin6(&ifinfo->coa)->sin6_addr = mddinfo.hoa;
			storage2sin6(&ifinfo->coa)->sin6_family = AF_INET6;
			storage2sin6(&ifinfo->coa)->sin6_len = sizeof(struct sockaddr_in6);

			mddinfo.coaif = NULL;

			return (1);
		}
		break;
	case MIPM_MD_INFO:
                mipmd = (struct mipm_md_info *)mipm;
                if (mipmd->mipm_md_command == MIPM_MD_SCAN) {

			ifinfo = mdd_ifindex2ifinfo(mipmd->mipm_md_ifindex);
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
mdd_rtmsg(rtm, msglen)
	struct rt_msghdr *rtm;
	int msglen;
{
        struct ifa_msghdr *ifam;
        struct in6_ifreq ifr6;
	struct if_info *ifinfo;
        struct sockaddr *rti_info[RTAX_MAX];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char buf[265];

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
		ifinfo = mdd_ifindex2ifinfo(ifam->ifam_index);
		if (ifinfo == NULL)
			break;

		mdd_getifinfo(ifinfo); 	
		
		return (1);

	case RTM_DELADDR:
		if (msglen < sizeof(struct ifa_msghdr))
			return (0);
		ifam = (struct ifa_msghdr *)rtm;

		/* find appropriate ifinfo */
		ifinfo = mdd_ifindex2ifinfo(ifam->ifam_index);
		if (ifinfo == NULL)
			return (0);
		
		get_rtaddrs(ifam->ifam_addrs,
			    (struct sockaddr *) (ifam + 1), rti_info);

		switch(rti_info[RTAX_IFA]->sa_family) {
		case AF_INET:
			if (mddinfo.multiplecoa) { 
				sin = (struct sockaddr_in *) rti_info[RTAX_IFA];
				memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));
				memset(&ifinfo->pcoa, 0, sizeof(ifinfo->coa));
				if (DEBUGHIGH)
					syslog(LOG_INFO, "%s becomes invalid\n", 
					       inet_ntop(AF_INET, 
							 &sin->sin_addr, 
							 buf, sizeof(buf)));
			}
			break;
		case AF_INET6:
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
			if (mddinfo.whereami == IAMHOME) {
				if ((ifinfo == mddinfo.coaif) && 
				    (mip6_are_prefix_equal(&mddinfo.hoa, 
						 &sin6->sin6_addr, 64))) {

					memset(&ifinfo->coa, 0, 
					       sizeof(ifinfo->coa));
					memset(&ifinfo->pcoa, 0, 
					       sizeof(ifinfo->coa));
					mddinfo.whereami = 0; /* reset */
				}
			}
			
			if (mddinfo.multiplecoa) { 
				/* 
				 * multiplecoa is supported, invalid
				 * CoA should be explicitly
				 * deregistered.
				 */
				if (IN6_ARE_ADDR_EQUAL(
					    &storage2sin6(&ifinfo->coa)->sin6_addr, 
					    &sin6->sin6_addr)) {

					mdd_md_dereg(ifinfo);
				} 
				memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));
			} else {
				if (mddinfo.coaif == ifinfo) {
					/* remove the primary CoA */
					mddinfo.coaif = NULL;

					/* 
					 * if a different CoA becomes
					 * invalid, getting a new
					 * coa 
					 */
                                	if (mddinfo.whereami != IAMHOME && 
					    IN6_ARE_ADDR_EQUAL(&storage2sin6(&ifinfo->coa)->sin6_addr,
						    &sin6->sin6_addr)) {

						mdd_getifinfo(ifinfo); 	
					} 
				} else {
					memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));
					mdd_getifinfo(ifinfo); 	
				}
			}
			break;
		default:
			return (0);
		}

		return (1);

	case RTM_ADDRINFO:
		ifam = (struct ifa_msghdr *)rtm;

		/* find appropriate ifinfo */
		ifinfo = mdd_ifindex2ifinfo(ifam->ifam_index);
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
		if (ioctl(mddinfo.linksock, SIOCGIFAFLAG_IN6, &ifr6) < 0) 
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
			if (!IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &mddinfo.hoa)) 
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
				mddinfo.whereami = 0; /* reset */
				
				mdd_getifinfo(ifinfo);

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

static void
parse_mainconfig() {
        char tbuf[BUFSIZ];
	char buf[BUFSIZ];
	int stat, val;
        char *bp = buf;
	char *addr;

        if ((stat = agetent(tbuf, "main")) <= 0) {
                memset(tbuf, 0, sizeof(tbuf));
		printf("<%s> main isn't defined in the configuration file"
                       " or the configuration file doesn't exist."
                       " Please check your configuration\n",
		       __func__);
		exit(0);
        }

	/* DNS Lookup */
	if (agetflag("nondns")) {
		mddinfo.dns = 0;
		namelookup = 0;
	} else 
		mddinfo.dns = 1;

	/* MultipleCoA Support */
	if (agetflag("multiplecoa")) 
		mddinfo.multiplecoa = 1;

	/* Set polling time */
        MAYHAVE(val, "poll", DEFAULT_POLL);
	mddinfo.poll.tv_usec = val;

	/* Set link polling time */
        MAYHAVE(val, "linkpoll", DEFAULT_LINKCHECK);
	mddinfo.linkpoll = val;

	/* Set debug level */
        MAYHAVE(val, "debug", DEFAULT_DEBUG);
	if (mddinfo.debug == 0)
		mddinfo.debug = val;

	/* Set Home Address */
	addr = (char *)agetstr("hoa", &bp);
	if (addr) {
		if (inet_pton(AF_INET6, addr, &mddinfo.hoa) != 1) {
			if (DEBUGNORM)
				syslog(LOG_ERR,
				       "the specified home agent addrss (%s) is invalid.\n",
				       addr);
			exit(-1);
		}
	} else {
		fprintf(stderr, "No Home Address\n");
		exit(1);
	}

	return;
};

static void
print_mainconfig () {

	syslog(LOG_INFO, "main option\n");
	syslog(LOG_INFO, "\tHoA %s\n", ip6_sprintf(&mddinfo.hoa));
	syslog(LOG_INFO, "\tdebug level %d\n", mddinfo.debug); 
	syslog(LOG_INFO, "\tpolling time %ld usec\n", mddinfo.poll.tv_usec); 
	syslog(LOG_INFO, "\tDNS is %s\n", 
	       (mddinfo.dns) ? "active" : "inactive");
	syslog(LOG_INFO, "\tmultiplecoa is %s\n", 
	       (mddinfo.multiplecoa) ? "active" : "inactive");
	syslog(LOG_INFO, "\tmdd is %s\n", 
	       (mddinfo.nondaemon) ? "forwarground":"background");
}

static void
parse_ifconfig(char *targetif) {
        char tbuf[BUFSIZ];
	int stat, val, s = 0;
	struct if_info *ifinfo;
        struct ifmediareq ifmr;

        if ((stat = agetent(tbuf, targetif)) <= 0) {
                memset(tbuf, 0, sizeof(tbuf));
		printf("<%s> %s isn't defined in the configuration file"
                       " or the configuration file doesn't exist."
                       " Treat it as default\n",
		       __func__, targetif);
        }

	ifinfo = malloc(sizeof(struct if_info));
	memset(ifinfo, 0, sizeof(struct if_info));

	strncpy(ifinfo->ifname, targetif, strlen(targetif));
	ifinfo->ifindex = if_nametoindex(ifinfo->ifname);

	/* set IPv4 capability */
	if (agetflag("ipv4")) 
		ifinfo->ipv4 = 1;

	/* set priority */
        MAYHAVE(val, "priority", DEFAULT_PRIORITY);
	ifinfo->priority = val;

	/* set media specific info (for wifi) */
        s = socket(PF_INET6, SOCK_DGRAM, 0);
        if (s < 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s socket: %s\n",  __FUNCTION__, strerror(errno));
                exit (-1);
        }
	memset(&ifmr, 0, sizeof(ifmr));
	strncpy(ifmr.ifm_name, ifinfo->ifname, strlen(ifinfo->ifname));
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) != -1) {
		if (IFM_TYPE(ifmr.ifm_active) == IFM_IEEE80211) {
			MAYHAVE(val, "linkhigh", DEFAULT_LINKWIFIHIGH);
			ifinfo->priority = val;
			MAYHAVE(val, "linklow", DEFAULT_LINKWIFILOW);
			ifinfo->priority = val;
		}
	}

	/* set BID */
        if ((val = agetnum("bid")) < 0) {
		if (mddinfo.multiplecoa) {
			fprintf(stderr, "no BID\n");
			exit(1);
		}
	} else 
		ifinfo->bid = val;

	/* add to mddinfo iflist */
	LIST_INSERT_HEAD(&mddinfo.ifinfo_head, ifinfo, ifinfo_entry);
};


static void
print_ifconfig () {
	struct if_info *ifinfo;
	char buf[256];
	LIST_FOREACH(ifinfo, &mddinfo.ifinfo_head, ifinfo_entry) {
		syslog(LOG_INFO, "ifname %s\n", ifinfo->ifname);
		syslog(LOG_INFO, "\tIPv4 Support is %s\n", 
		       (ifinfo->ipv4) ? "active" : "inactive");
		syslog(LOG_INFO, "\tpriority %d\n", ifinfo->priority);
		syslog(LOG_INFO, "\tbid is %d\n", ifinfo->bid);
		switch (ifinfo->coa.ss_family) {
		case AF_INET:
			syslog(LOG_INFO, "\tcoa %s\n", 
			       inet_ntop(AF_INET, 
					 &((struct sockaddr_in *)&ifinfo->coa)->sin_addr, 
					 buf, sizeof(buf)));
			break;
		case AF_INET6:
			syslog(LOG_INFO, "\tcoa %s\n", 
			       ip6_sprintf(&storage2sin6(&ifinfo->coa)->sin6_addr));
			break;
		default:
			syslog(LOG_INFO, "\tcoa is not available yet\n");
		}
	}
}


void
mdd_reset() {
	struct if_info *ifinfo, *ifinfo_next;
	
	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); ifinfo; 
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
mdd_terminate() {

	syslog(LOG_INFO, "goodbye\n");
	mdd_reset();

	exit(0);
}

static void
mdd_initif() {

	struct if_info *ifinfo, *ifinfo_next;
	
	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);

		mdd_getifinfo(ifinfo); 
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
mdd_getifinfo(ifinfo) 
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
        struct ifaddrs *ifa, *ifap;


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

			if (ioctl(mddinfo.linksock, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
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

	if (!ifinfo->ipv4) {
		if (DEBUGNORM)
			syslog(LOG_INFO, "%s is ipv4 inactive\n", ifinfo->ifname);
		return;
	}

	/* Search v4 address */
	if (getifaddrs(&ifap) != 0) {
		if (DEBUGNORM)
			syslog(LOG_ERR, "%s\n", strerror(errno));
                return;
        }

        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct sockaddr *sa;

		if (if_nametoindex(ifa->ifa_name) != ifinfo->ifindex)
			continue;

                sa = ifa->ifa_addr;
                
                if (sa->sa_family != AF_INET)
                        continue;

		memcpy(&ifinfo->coa, sa, sizeof(struct sockaddr));

		return;
	}

	memset(&ifinfo->coa, 0, sizeof(ifinfo->coa));

	return;
}

/* detrmin which CoAs are passed to mobile network daemon */
void
mdd_selection() {
	int inet_n = 0;
	int inet6_n = 0;
	struct if_info *ifinfo, *ifinfo_next;

	/* Priority Based Arrangement */
	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		if (ifinfo_next == NULL) 
			break;
		
		if (ifinfo->priority < ifinfo_next->priority) {
			LIST_REMOVE(ifinfo_next, ifinfo_entry);
			LIST_INSERT_BEFORE(ifinfo, ifinfo_next, ifinfo_entry);
			ifinfo_next = ifinfo;
		}
	}

	/* Count # of addresses */
	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		switch (ifinfo->coa.ss_family) {
		case AF_INET:
			inet_n ++;
			break;
		case AF_INET6:
			inet6_n ++;
			break;
		}
	}

/*
	if (DEBUGHIGH)
		fprintf(stderr, "%s: v4 %d v6 %d\n", __FUNCTION__, inet_n, inet6_n);
*/
	if (mddinfo.whereami == IAMHOME) {
		/* 
		 * when it moves to home but the primary CoA is not
		 * set, it sends MD_INFO message indicating home. If
		 * the primary CoA is already set, do nothing. MR
		 * being home, the coa can be changed to other than
		 * home address (ex. an address auto-configured at the
		 * home link), but it does not matter whether coa is
		 * the home address or not. Only when the home address
		 * is detached/deleted, mdd_selection() starts to
		 * select other address as a primary CoA and marks
		 * foreign. 
		 */
		
		for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); 
		     ifinfo; ifinfo = ifinfo_next) {
			ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
			
			if (IN6_ARE_ADDR_EQUAL(&(storage2sin6(&ifinfo->coa)->sin6_addr), 
					       &mddinfo.hoa)) 
				break;
		}
		if (ifinfo && mddinfo.coaif != ifinfo) {
			mdd_md_home(storage2sin6(&ifinfo->coa), 
				    storage2sin6(&ifinfo->coa), 
				    ifinfo->ifindex);
		}

		return;
	}
	
	if (mddinfo.multiplecoa) {
		if (inet6_n > 0) {
			/* send all CoAs to mnd */
			for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); 
			     ifinfo; ifinfo = ifinfo_next) {
				ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
				
				if (ifinfo->coa.ss_family != AF_INET6) 
					continue;

				if (!mdd_coa_equal(ifinfo)) {
					mdd_md_reg((struct sockaddr_in6 *)&ifinfo->coa,
						   ifinfo->bid); 
					memcpy(&ifinfo->pcoa, &ifinfo->coa, 
					       sizeof(ifinfo->coa));
				}
			}
		} else if (inet_n > 0 && inet6_n == 0) {
			/* send v4 CoA to mns */
			char buf[256];
			memset(buf, 0, sizeof(buf));
			for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); 
			     ifinfo; ifinfo = ifinfo_next) {
				ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
				
				if (ifinfo->coa.ss_family != AF_INET) 
					continue;
				if (!mdd_coa_equal(ifinfo)) {
					fprintf(stderr, 
						"send %s CoAs to mnd\n",
						inet_ntop(AF_INET, &((struct sockaddr_in *)&ifinfo->coa)->sin_addr,  buf, sizeof(buf)));
					/* XXX */
				}
				memcpy(&ifinfo->pcoa, &ifinfo->coa, 
				       sizeof(ifinfo->coa));
				
				return;
			}
		}
	} else { /* regular Mobile IPv6 */
		if (inet6_n > 0) {
			if (mddinfo.whereami == IAMV4) {
				/* XXX deregistration for v4 address */
			}

			/* pick a primary CoA from the first matched interface */
			for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); 
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
				if (((mddinfo.coaif == NULL) || 
				     (mddinfo.coaif && 
				      mddinfo.coaif->priority <= ifinfo->priority)) 
				    && !mdd_coa_equal(ifinfo)) {

/*
				if ((((mddinfo.coaif == NULL) && !mdd_coa_equal(ifinfo)) 
				     || 
				     (mddinfo.coaif && 
				      mddinfo.coaif->priority <= ifinfo->priority && 
				      !mdd_coa_equal(ifinfo)))) {
*/

					mdd_md_reg((struct sockaddr_in6 *)&ifinfo->coa, 0); 
					memcpy(&ifinfo->pcoa, &ifinfo->coa, 
					       sizeof(ifinfo->coa));

					mddinfo.coaif = ifinfo;
					mddinfo.whereami = IAMFOREIGN;
					
					return;	
				}
			}
			return;
		} else if (inet_n > 0 && inet6_n == 0) {
			/* send the first IPv4 CoA */
			char buf[256];
			memset(buf, 0, sizeof(buf));
			for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); 
			     ifinfo; ifinfo = ifinfo_next) {
				ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
				
				if (ifinfo->coa.ss_family != AF_INET) 
					continue;

				if (!mdd_coa_equal(ifinfo) || 
				    mddinfo.coaif != ifinfo) {
					fprintf(stderr, 
						"send %s CoAs to mnd\n",
						inet_ntop(AF_INET, &((struct sockaddr_in *)&ifinfo->coa)->sin_addr, 
							  buf, sizeof(buf)));
					mddinfo.coaif = ifinfo;
					mddinfo.whereami = IAMV4;
					/* XXX */
				}
				memcpy(&ifinfo->pcoa, &ifinfo->coa, sizeof(ifinfo->coa));
				return;

			}
		} 
	}

	return;
}


static int
mdd_coa_equal(struct if_info *ifinfo) {

	if ((ifinfo->coa.ss_family != 0) && 
	    (ifinfo->coa.ss_family != ifinfo->pcoa.ss_family)) 
		return (0);


	switch (ifinfo->coa.ss_family) {
	case AF_INET:
		if ((memcmp(&((struct sockaddr_in *)&ifinfo->coa)->sin_addr, 
			    &((struct sockaddr_in *)&ifinfo->pcoa)->sin_addr, 
			    sizeof(struct in_addr)) == 0))
			return (1);
		break;
	case AF_INET6:
		if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)&ifinfo->coa)->sin6_addr, 
				       &((struct sockaddr_in6 *)&ifinfo->pcoa)->sin6_addr))
			return (1);
		break;
	default:
		break;
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
mdd_md_home(hoa, coa, ifindex)
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

	if (write(mddinfo.mipsock, mdinfo, len) < 0) {
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


static void
mdd_md_dereg(struct if_info *dereg_ifinfo) {
	struct if_info *ifinfo, *ifinfo_next; 
	int len;
	struct mipm_md_info *mdinfo;
	struct sockaddr_in6 hoa;

        if (dereg_ifinfo == NULL)
		return;

        /* Detached address must be global */
         if (in6_addrscope(&storage2sin6(&dereg_ifinfo->coa)->sin6_addr) != 
		__IPV6_ADDR_SCOPE_GLOBAL) 
                return;
        
	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); 
	     ifinfo; ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);

		if (ifinfo == dereg_ifinfo)
			continue;

         	if (in6_addrscope(&storage2sin6(&ifinfo->coa)->sin6_addr) != 
		    __IPV6_ADDR_SCOPE_GLOBAL) 
			continue;

		syslog(LOG_INFO, "send dereg from address is %s\n", 
			ip6_sprintf(&storage2sin6(&ifinfo->coa)->sin6_addr));

                /* mdinfo + hoa + newcoa + deregcoa */
		len = sizeof(*mdinfo) + sizeof(struct sockaddr_in6) * 3; 
		mdinfo = (struct mipm_md_info *) malloc(len);
		if (mdinfo == NULL) 
			return;
		
		memset(mdinfo, 0, len);
		mdinfo->mipm_md_hdr.miph_msglen	= len;
		mdinfo->mipm_md_hdr.miph_version = MIP_VERSION;
		mdinfo->mipm_md_hdr.miph_type	= MIPM_MD_INFO;
		mdinfo->mipm_md_hdr.miph_seq	= random();
		mdinfo->mipm_md_hint		= MIPM_MD_ADDR;
		mdinfo->mipm_md_command		= MIPM_MD_DEREGFOREIGN;
		mdinfo->mipm_md_ifindex		= ifinfo->ifindex;

		memset(&hoa, 0, sizeof(hoa)); 
		hoa.sin6_family = AF_INET6;
		hoa.sin6_addr = mddinfo.hoa;
		hoa.sin6_len = sizeof(struct sockaddr_in6);
		
		memcpy(MIPD_HOA(mdinfo), &hoa, 
		       sizeof(struct sockaddr_in6));
		memcpy(MIPD_COA(mdinfo), (struct sockaddr_in6 *)&dereg_ifinfo->coa, 
		       sizeof(struct sockaddr_in6));
		memcpy(&((struct sockaddr_in6 *)MIPD_COA(mdinfo))->sin6_port,
		    &dereg_ifinfo->bid, sizeof(u_int16_t));
		memcpy(MIPD_COA2(mdinfo), (struct sockaddr_in6 *)&ifinfo->coa, 
		       sizeof(struct sockaddr_in6));
		memcpy(&((struct sockaddr_in6 *)MIPD_COA2(mdinfo))->sin6_port,
		    &dereg_ifinfo->bid, sizeof(u_int16_t));

		if (write(mddinfo.mipsock, mdinfo, len) < 0) {
			if (DEBUGNORM) {
				syslog(LOG_ERR, "%s write: %s\n", 
				       __FUNCTION__, strerror(errno));
			}
			return;
		}
	
		if (mdinfo)
			free(mdinfo);

		memset(&dereg_ifinfo->coa, 0, sizeof(dereg_ifinfo->coa));
		memset(&dereg_ifinfo->pcoa, 0, sizeof(dereg_ifinfo->pcoa));
		
		break;		
	}

        return;
}


static struct if_info *
mdd_ifindex2ifinfo(u_int16_t ifindex) {
	struct if_info *ifinfo = NULL, *ifinfo_next = NULL;

	for (ifinfo = LIST_FIRST(&mddinfo.ifinfo_head); ifinfo; 
	     ifinfo = ifinfo_next) {
		ifinfo_next = LIST_NEXT(ifinfo, ifinfo_entry);
		
		if (ifinfo->ifindex == ifindex)
			break;
	}

	return ifinfo;
}
