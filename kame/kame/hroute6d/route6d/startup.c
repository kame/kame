/* 
 * $Id: startup.c,v 1.3 1999/10/04 14:55:42 itojun Exp $
 */

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

/* Copyright (c) 1997, 1998. Hitachi,Ltd.  All rights reserved. */
/* Hitachi Id: startup.c,v 1.3 1998/01/12 12:39:06 sumikawa Exp $ */

#include "defs.h"
#include "pathnames.h"

/* forward references */
int get_address(const int, char *, char *, struct preflist *);
void if_install(struct interface *);
void install_address(struct preflist **, struct interface *);
struct interface *if_ifwithaddr(struct preflist *, struct interface *);
struct interface *if_ifwithdstaddr(struct preflist *, struct interface *);
void add_address(struct preflist *, struct interface *);
void add_route(struct preflist *, struct interface *);
void del_route(struct preflist *, struct interface *);
void if_freeaddresses(struct interface *);
struct interface *get_if_by_name(struct sockaddr_dl *);
void if_duplicate(struct preflist *, struct interface *);

static void prt_iflist(void);

extern int dflag;
extern int Nflag;

void
initialize_signals(void)
{
	struct sigaction sact;
	sigset_t sss;

	sigemptyset(&sact.sa_mask);
	sact.sa_flags = SA_RESTART;

	sact.sa_handler = (void *)timer;
	sigaction(SIGALRM, &sact, (struct sigaction *)NULL);

	sact.sa_handler = (void *)sighup_handler;
	sigaction(SIGHUP, &sact, (struct sigaction *)NULL);

	sact.sa_handler = (void *)sigint_handler;
	sigaction(SIGINT, &sact, (struct sigaction *)NULL);

	sact.sa_handler = (void *)sigterm_handler;
	sigaction(SIGTERM, &sact, (struct sigaction *)NULL);

	sact.sa_handler = (void *)sigusr1_handler;
	sigaction(SIGUSR1, &sact, (struct sigaction *)NULL);

	sigfillset(&sss);
	sigprocmask(SIG_UNBLOCK, &sss, NULL);	/* for restart case */

	return;
}

void
initialize_dctlout(void)
{
	dctlout.ctl_next = NULL;

	bzero(&dctlout.ctl_addr, sizeof(struct sockaddr_in6));
	dctlout.ctl_addr.sin6_len = sizeof(struct sockaddr_in6);
	dctlout.ctl_addr.sin6_family  = AF_INET6;
	dctlout.ctl_addr.sin6_port = htons(RIP6_PORT);
	if (inet_pton(AF_INET6, ALL_RIP6_ROUTER,
		      &dctlout.ctl_addr.sin6_addr) < 1) {
		fprintf(stderr, "can't initialize dctlout\n");
		exit(1);
	}
	dctlout.ctl_pass = CTL_SEND;
}

void
initialize_pidfile(void)
{
	FILE *fp;

	if ((fp = fopen(RT6_PID, "r")) != NULL) {
		fclose(fp);
		syslog(LOG_ERR, "QUIT: maybe another %s is running", prog);
		if (Nflag)
			fprintf(stderr, "maybe another %s is running\n", prog);
		exit(1);
	}

	if ((fp = fopen(RT6_PID, "w")) == NULL)
		quit_route6d("could not write to pid file");
	rt6_pid = getpid();
	fprintf(fp, "%d", rt6_pid);
	fclose(fp);

	return;
}

void
initialize_sockets(void)
{
	struct sockaddr_un su;
	u_int hops;		/* name does not mean anything */

	hops = 0;		/* does not want to hear myself */
	if (setsockopt(rip6_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		       (void *)&hops, sizeof(unsigned int)) < 0)
		syslog(LOG_ERR, "multicast loop: %m");

	hops = RIP6_HOPS;	/* hop limit */
	if (setsockopt(rip6_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		       (void *)&hops, sizeof(int)) < 0)
		syslog(LOG_ERR, "multicast hops: %m");

	hops = 1;		/* want to RX_INFO */
	if (setsockopt(rip6_sock, IPPROTO_IPV6, IPV6_PKTINFO, (void *)&hops,
		       sizeof(int)) < 0) {
		syslog(LOG_ERR, "sockopt PKTINFO: %m");
		exit_route6d();
	}
	if ((admin_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "admin socket: %m");
		exit_route6d();
	}
	unlink(ADM_RIP6_UDS);	/* fail safe */
	bzero((char *)&su, sizeof(su));
	su.sun_len = sizeof(su);
	su.sun_family = AF_UNIX;
	strcpy(su.sun_path, ADM_RIP6_UDS);
	if (bind(admin_sock, (struct sockaddr *)&su, sizeof(su)) < 0) {
		syslog(LOG_ERR, "admin bind: %m");
		exit_route6d();
	}
	hops = ADM_BUFSIZE;
	if (setsockopt(admin_sock, SOL_SOCKET, SO_SNDBUF, (void *)&hops,
		       sizeof(hops)) < 0)
		syslog(LOG_ERR, "admin_sock setsockopt: %m");

	hops = 0;
	if (setsockopt(admin_sock, SOL_SOCKET, SO_USELOOPBACK, (void *)&hops,
		       sizeof(hops)) < 0)
		syslog(LOG_ERR, "rt6_sock setsockopt: %m");

	if ((rt6_sock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		syslog(LOG_ERR, "routing sock: %m");
		exit_route6d();
	}
	hops = 0;		/* Do not want to hear my own rt_msg */
	if (setsockopt(rt6_sock, SOL_SOCKET, SO_USELOOPBACK, (void *)&hops,
		       sizeof(hops)) < 0)
		syslog(LOG_ERR, "rt6_sock setsockopt: %m");

	return;
}

/* 
 * Extract addresses from the given buffer
 */
void
xaddress(const int rti_addrs, char *cp, char *cplim, struct rt_addrinfo *rtinfo)
{
	register struct sockaddr *sa;
	register int i;

	bzero((char *)rtinfo, sizeof(struct rt_addrinfo));
	for (i = 0; (i < RTAX_MAX) && (cp < cplim); i++) {
		if ((rti_addrs & (1 << i)) == 0)
			continue;
		rtinfo->rti_info[i] = sa = (struct sockaddr *)cp;
		ADVANCE(cp, sa);
	}
}

/* 
 * Copies the addresses into given structure.
 */
#undef ifaaddr
int
get_address(const int rti_addrs, char *cp, char *cplim, struct preflist *plp)
{
	struct rt_addrinfo *rtinfo;
	struct sockaddr_in6 *ifaaddr;
	int i;
	/* ASSERT: RTM_IFINFO+RTM_NEWADDR */
	rtinfo = (struct rt_addrinfo *)malloc(sizeof(struct rt_addrinfo));
	if (rtinfo == NULL) {
		syslog(LOG_ERR, "rtinfo malloc: %m");
		return -1;
	}
	xaddress(rti_addrs, cp, cplim, rtinfo);
	if (rtinfo->rti_info[RTAX_NETMASK] == 0
	    || rtinfo->rti_info[RTAX_IFA] == 0) {
		free(rtinfo);
		return -1;
	}
	ifaaddr = (struct sockaddr_in6 *)(rtinfo->rti_info[RTAX_IFA]);
	if (ifaaddr->sin6_family != AF_INET6) {
		free(rtinfo);
		return -1;
	}
	/* VALID INTERFACE ADDRESS ? */
	if (IN6_IS_ADDR_MULTICAST(&ifaaddr->sin6_addr) ||
	    IN6_IS_ADDR_BLOCK1(&ifaaddr->sin6_addr) ||
	    (IN6_IS_ADDR_BLOCK0(&ifaaddr->sin6_addr) &&
	     !IN6_IS_ADDR_LOOPBACK(&ifaaddr->sin6_addr))) {
		free(rtinfo);
		return -1;	/* UNSPECIFIED: s6_addr[0] == 0 */
		/* V4MAPPED   : s6_addr[0] == 0 */
		/* V4COMPAT   : s6_addr[0] == 0 */
	}

	/* ifaaddr copy */
	plp->pl_pref.prf_addr = ifaaddr->sin6_addr;

	/* netmask copy , EXIST */
	/* but, maybe SHORTER than sockaddr_in6 */
	i = 16 + rtinfo->rti_info[RTAX_NETMASK]->sa_len -
		sizeof(struct sockaddr_in6);
	if (i > 0)
		bcopy((void *)
		      &((struct sockaddr_in6 *)rtinfo->rti_info[RTAX_NETMASK])->sin6_addr,
		      (void *)&(plp->pl_mask), i);

	if (rtinfo->rti_info[RTAX_BRD])	{ /* VALID only when IFF_POINTTOPOINT */
		if (((struct sockaddr_in6 *)rtinfo->rti_info[RTAX_BRD])->sin6_family == AF_INET6)
			plp->pl_dest = ((struct sockaddr_in6 *)rtinfo->rti_info[RTAX_BRD])->sin6_addr;
	}

	plp->pl_pref.prf_len = get_prefixlen((struct sockaddr_in6 *)rtinfo->rti_info[RTAX_NETMASK]);

	if (plp->pl_pref.prf_len <= 0)	/* sanity check */
		if (!IN6_IS_ADDR_LINKLOCAL(&plp->pl_pref.prf_addr)) {
			/* default address is assigned at an interface */
			free(rtinfo);
			return -1;
		}
	plp->pl_flag = PL_NEWADDR;

	free(rtinfo);
	return 0;
}

/* 
 * Calculates prefix length from given mask.
 */
int
get_prefixlen(struct sockaddr_in6 *mask)
{
	register int i, len = 0;

	/* ASSERT: Host route should be handled by caller. I don't care */
	/* ASSERT: continuous mask */
	/* ASSERT: *mask is SHORTER than sockaddr_in6 (but not 0 length) */
	/* ASSERT: *mask is NOT LONGER than sockaddr_in6 */

	i = 15 + mask->sin6_len - sizeof(struct sockaddr_in6);

	if ((i < 0) || (mask->sin6_addr.s6_addr[0] == 0))
		len = 0;
	else {
		while (mask->sin6_addr.s6_addr[i] == 0)
			i--;
		len = i * 8 + 9 - ffs(mask->sin6_addr.s6_addr[i]);
	}

	return len;
}

/* 
 * Reads kernel interface list and makes a copy for the local use.
 */
int
initialize_interface(void)
{
	size_t needed;
	int newif = FALSE, mib[6], flags = 0;
	char *buf, *cplim, *cp;
	struct interface *ifs, *ifp;
	struct preflist *plp = NULL;
	struct sockaddr_dl *sdl;
	register struct if_msghdr *ifm;
	register struct ifa_msghdr *ifam;
	int externalinterfaces = 0;

	/* I'm afraid of stack overflow. */
	/* So work areas are malloc-ed.  */
	ifs = (struct interface *)malloc(sizeof(struct interface));
	if (ifs == NULL) {
		syslog(LOG_ERR, "work area malloc: %m");
		return -1;
	}
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET6;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		free(ifs);
		syslog(LOG_ERR, "sysctl IFLIST 1 : %m");
		return -1;
	}
	if ((buf = malloc(needed)) == NULL) {
		free(ifs);
		syslog(LOG_ERR, "sysctl IFLIST malloc : %m");
		return -1;
	}
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		free(buf);
		free(ifs);
		syslog(LOG_ERR, "sysctl IFLIST 2 : %m");
		return -1;
	}
	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		for (plp = ifp->if_ip6addr; plp; plp = plp->pl_next)
			plp->pl_flag = PL_DELADDR;
		for (plp = ifp->if_sladdr; plp; plp = plp->pl_next)
			plp->pl_flag = PL_DELADDR;
		for (plp = ifp->if_lladdr; plp; plp = plp->pl_next)
			plp->pl_flag = PL_DELADDR;
	}
	/* so, ifp is NULL now */

	cplim = buf + needed;
	for (cp = buf; cp < cplim; cp += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)cp;
		if (ifm->ifm_type == RTM_IFINFO) {
			newif = FALSE;
			ifp = (struct interface *)NULL;
			if (ifm->ifm_addrs != RTA_IFP)
				continue;	/* sanity check */
			sdl = (struct sockaddr_dl *)(ifm + 1);
			if ((ifp = get_if_by_name(sdl)) == NULL) {
			/* Hack! */
			/* IFF_RUNNING means 'has at least one linklocal'
			 * <CAN_SEND> */
			/* IFF_JOINED  means 'joined multicast group'
			 * <CAN_RECEIVE> */
				flags = ifm->ifm_flags & ~(IFF_RUNNING | IFF_JOINED);
				if ((flags & IFF_UP) == 0) {
					ifp = NULL;
					continue;
				}
				bzero(ifs, sizeof(struct interface));
				ifp = ifs;	/* pointer copy */
				newif = TRUE;
				/* already bzeroed, so trailing 0 is not needed */
				strncpy(ifp->if_name, sdl->sdl_data, sdl->sdl_nlen);
				ifp->if_sdl = *sdl;	/* struct copy */
				ifp->if_flag = flags;
			} else {
				flags = ifm->ifm_flags;
				if ((flags & IFF_UP) == 0) {
					if (ifp->if_flag & IFF_JOINED)
						drop_multicast_group(ifp);
					ifp->if_flag = flags & ~(IFF_RUNNING | IFF_JOINED);
					/* if_freeaddresses( ifp ); */
					/* free will be done in install_address */
					ifp = NULL;
					continue;
				}
				if ((ifp->if_flag & IFF_UP) == 0) {
					/* wake up */
					/* counter reset */
					ifp->if_badpkt = ifp->if_badrte = ifp->if_updates = 0;
				}
				ifp->if_flag = (flags & ~(IFF_RUNNING | IFF_JOINED))
					| (ifp->if_flag & (IFF_RUNNING | IFF_JOINED));
				ifp->if_sdl = *sdl;	/* maybe MAC address
							 * was changed (?) */
			}

			ifp->if_metrc = ifm->ifm_data.ifi_metric;
			/* maybe index was changed */
			if_index(ifp) = ifm->ifm_index;
			ifp->if_lmtu = ifm->ifm_data.ifi_mtu;
			/* sanity check */
			if (ifp->if_lmtu <
			    (sizeof(struct rip6) + rt6_hdrlen +
			     sizeof(struct route_entry))) {
				/* rt6_hdrlen may be HUGER than DEFAULT(576) */
				ifp->if_flag &= ~IFF_UP;
				syslog(LOG_ERR, "Too small MTU");
				ifp = NULL;
				newif = FALSE;
			}
			continue;
		}		/* if(RTM_IFINFO) */
		if (ifm->ifm_type != RTM_NEWADDR) {
			free(buf);
			free(ifs);
			syslog(LOG_ERR, "sysctl illegal data");
			return -1;
		}
		if (ifp == NULL)
			continue;
		/* ifp without IFF_UP shall reach here */
		/* First message is RTM_NEWADDR (not RTM_IFINFO) shall
                   reach here */

		ifam = (struct ifa_msghdr *)ifm;
		rtinfo.rti_addrs = ifam->ifam_addrs;
		plp = (struct preflist *)malloc(sizeof(struct preflist));
		if (plp == NULL) {
			free(buf);
			free(ifs);
			syslog(LOG_ERR, "initialize_interface: malloc failed");
			return -1;
		}
		bzero((void *)plp, sizeof(struct preflist));

		if (get_address(ifam->ifam_addrs, (char *)(ifam + 1),
				(cp + ifam->ifam_msglen), plp) < 0) {
			free(plp);	/* plp = NULL; */
			continue;
		}
		if (flags & IFF_POINTOPOINT) {
			if (if_ifwithdstaddr(plp, ifp)) {
			/* address already on the interface list ( marked
			 * OLDADDR ) */
				free(plp);	/* plp = NULL; */
				continue;
			}
		} else {
			int i;

#define vdst  plp->pl_dest.s6_addr
#define vsrc1 plp->pl_pref.prf_addr.s6_addr
#define vsrc2 plp->pl_mask.s6_addr
			for (i = 0; i < sizeof(struct in6_addr); i++)
				vdst[i] = vsrc1[i] & vsrc2[i];
#undef vsrc2
#undef vsrc1
#undef vdst
			if (if_ifwithaddr(plp, ifp)) {
			/* address already on the interface list ( marked
			 * OLDADDR ) */
				free(plp);	/* plp = NULL; */
				continue;
			}
		}

		if (newif != FALSE) {
			if ((ifp = (struct interface *)malloc(sizeof(struct interface))) == NULL) {
				free(plp);
				free(buf);
				free(ifs);
				syslog(LOG_ERR, "initialize_interface: new if malloc :%m");
				return -1;
			}
			*ifp = *ifs;	/* struct copy */
			ifp->if_next = ifnet;
			ifnet = ifp;
			newif = FALSE;	/* CAUTION: this interface loop has
					 * not been finished */
			if ((ifp->if_flag & IFF_LOOPBACK) == 0)
				externalinterfaces++;
		}
		add_address(plp, ifp);	/* plp = NULL; */

		if (ifp->if_flag & IFF_LOOPBACK)
			foundloopback = 1;
	}			/* for */

	/* Unnumbered P2P check */
	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if (ifp->if_flag & IFF_POINTOPOINT
		    && ifp->if_flag & IFF_UP) {
			for (plp = ifp->if_ip6addr; plp; plp = plp->pl_next)
				if (plp->pl_flag != PL_DELADDR)
					if_duplicate(plp, ifp);
			/* Duplicate address will be zeroed */
			for (plp = ifp->if_sladdr; plp; plp = plp->pl_next)
				if (plp->pl_flag != PL_DELADDR)
					if_duplicate(plp, ifp);
			/* Duplicate address will be zeroed */
		}
	}

	/* Even if we have only one (external) interface, RIPng works */
	/* MODE_UNSPEC really needed ? */
	if (externalinterfaces == 0)
		rt6_opmode = MODE_QUIET;

	free(buf);
	free(ifs);
	return 0;
}

/* 
 * Map interface entries to its configuration entries.
 */
void
install_interface(void)
{
	struct interface *ifp;
	struct int_config *ifc;

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		ifp->if_config = &difconf;	/* interfaces not appearing
						 * in conf-file */
		for (ifc = ifconf; ifc; ifc = ifc->int_next) {
			if (strcmp(ifp->if_name, ifc->int_name) == 0) {
				ifp->if_config = ifc;
				break;
			}
		}
		if ((ifp->if_flag & IFF_LOOPBACK) == 0) {
			if_install(ifp);	/* for DELETE or ADD
						 * interface routes */
		}
	}

	if (dflag)
		prt_iflist();

	return;
}

/* 
 * Sets additional interface details and adds routes to interface
 * addresses. Joins/drops multicast group for interfaces.
 */
void
if_install(struct interface *ifp)
{
	struct in6_addr *addr;

	/* ASSERT: ifp != lo0 */
	install_address(&ifp->if_lladdr, ifp);/* DELETE or ADD local routes */
	install_address(&ifp->if_sladdr, ifp);
	install_address(&ifp->if_ip6addr, ifp);

	if (ifp->if_lladdr && ifp->if_flag & IFF_UP) {
		/* at least one lladdr to send updates */
		ci_cmsg(ifp->if_cinfo).cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		ci_cmsg(ifp->if_cinfo).cmsg_level = IPPROTO_IPV6;
		ci_cmsg(ifp->if_cinfo).cmsg_type = IPV6_PKTINFO;
		addr = &ci_info(ifp->if_cinfo).ipi6_addr;
		*addr = ifp->if_lladdr->pl_pref.prf_addr;
		ifp->if_flag |= IFF_RUNNING;	/* has linklocal */
	} else
		ifp->if_flag &= ~IFF_RUNNING;	/* doesn't have linklocal */

	/* 
	 * Join multicast group for the interface if not joined.
	 * ... Even if it has no linklocal, it can receive multicast
	 *     ( but at least one IPv6 address needed ?)
	 */
	if (!(ifp->if_flag & IFF_JOINED) && (ifp->if_flag & IFF_UP))
		join_multicast_group(ifp);
	return;
}

/* 
 * Delete/retain addresses to list and handle the route entries.
 */
void
install_address(struct preflist **plist, struct interface *ifp)
{
	struct preflist *pl, **ppl, *temp;

	/* DELETE FIRST */
	for (pl = *plist, ppl = plist; pl;) {
		temp = pl;
		pl = pl->pl_next;
		if (temp->pl_flag != PL_DELADDR) {
			ppl = &(temp->pl_next);
			continue;
		} else {
			*ppl = pl;
			del_route(temp, ifp);
			free(temp);
		}
	}

	/* AND THEN ADD */
	for (pl = *plist, ppl = plist; pl;) {
		temp = pl;
		pl = pl->pl_next;
		if (temp->pl_flag == PL_NEWADDR) {
			if (ifp->if_flag & IFF_UP && ifp->if_lladdr != NULL)
				add_route(temp, ifp);
		}
		ppl = &(temp->pl_next);
	}

	return;
}

/* 
 * ADD_STATIC_TO_LOCAL
 * int state
 * network byte order index
 * int plen
 * in6_addr *r_dst *r_gate
 * u_short tagval
 * u_char met
 */
#define ADD_STATIC_TO_LOCAL( state, index, plen, r_dst, r_gate, tagval, met ) \
do\
{\
  struct rt_plen   *lrt;\
  struct tree_node *node;\
  struct interface *ifp;\
  struct route_entry re,rg;\
\
  /* index is network byte order */\
  for( ifp = ifnet; ifp; ifp = ifp->if_next )\
    if( (ifp->if_flag & IFF_UP) && ((index) == if_index(ifp))) break;\
\
  if((ifp!=NULL)&&!(ifp->if_flag & IFF_LOOPBACK))\
  {\
\
    bzero( (void *)&re, sizeof(re) );\
    re.rip6_prflen = (plen);\
    re.rip6_addr   = *(r_dst); /* struct copy */\
    re.rip6_rtag   = (tagval);\
    if( (met) == 0 ) /* special case */\
      re.rip6_metric = rt6_metric + ifp->if_config->int_metric_in;\
    else\
      re.rip6_metric = (met);\
\
    if( re.rip6_metric >= HOPCOUNT_INFINITY ) \
    { \
      if( (state)& RTS6_KERNEL )\
        re.rip6_metric = HOPCOUNT_INFINITY - 1; /* anyway it exists */\
      else break; /* no need to add */\
    } \
    lrt = locate_local_route( &re, &node );\
\
    bzero( (void *)&rg, sizeof(rg) );\
    rg.rip6_addr   = *(r_gate);\
\
    if(lrt == NULL)\
      add_local_route( &re, &rg, ifp, state, node );\
    else\
    {\
      lrt->rp_state |= state;    /* directly change target entry */\
      modify_local_route( lrt, &re, &rg, ifp );/* modify cannot modify state */\
    }\
  }\
} while(0)

/* 
 * Install all static routes in the kernel.
 */
void
install_routes(void)
{
	struct static_rt *sp;

	int mib[6];
	size_t bufsize;
	char *buf, *p, *lim;
	struct rt_msghdr *rtm;
	int sflag;

	kernel_routes = 0;	/* init */

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET6;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;
	if (sysctl(mib, 6, NULL, &bufsize, NULL, 0) < 0) {
		syslog(LOG_ERR, "sysctl1 RT_DUMP:%m");
		exit_route6d();
	}
	if ((buf = malloc(bufsize)) == NULL) {
		syslog(LOG_ERR, "RT_DUMP: %m");
		exit_route6d();
	}
	if (sysctl(mib, 6, buf, &bufsize, NULL, 0) < 0) {
		syslog(LOG_ERR, "sysctl2 RT_DUMP:%m");
		exit_route6d();
		/* But, maybe some entries are added between 2 sysctls */
	}
	lim = buf + bufsize;
	for (p = buf; p < lim; p += rtm->rtm_msglen) {
		struct sockaddr_in6 *r_dst, *r_gate, *r_mask;
		char *tmp;
		int plen;

		r_mask = NULL;

		rtm = (struct rt_msghdr *)p;
#if !defined( __NetBSD__) && !defined(__OpenBSD__)
		if ((rtm->rtm_flags & RTF_UP) == 0 ||
		    (rtm->rtm_flags &
		     (RTF_CLONED | RTF_XRESOLVE |
		      RTF_LLINFO | RTF_BLACKHOLE)))
#else
		if ((rtm->rtm_flags & RTF_UP) == 0 ||
		    (rtm->rtm_flags &
		     (RTF_XRESOLVE | RTF_LLINFO | RTF_BLACKHOLE)))
#endif
			continue; /* maybe RTF_STATIC check is enough */

		if (!(rtm->rtm_addrs & RTA_DST) ||
		    !(rtm->rtm_addrs & RTA_GATEWAY))
			continue;	/* always non-NULL */

		kernel_routes++;
		if (rtm->rtm_flags & RTF_STATIC)
			sflag = RTS6_STATIC;
		else
			sflag = 0;
		if ((rtm->rtm_flags & RTF_GATEWAY) == 0)
			sflag |= RTS6_INTERFACE;

		tmp = (char *)(rtm + 1);
		r_dst = (struct sockaddr_in6 *)tmp;
		if (IN6_IS_ADDR_LINKLOCAL(&r_dst->sin6_addr) ||
		    IN6_IS_ADDR_LOOPBACK(&r_dst->sin6_addr) ||
		    IN6_IS_ADDR_MULTICAST(&r_dst->sin6_addr))
			continue;

		ADVANCE(tmp, (struct sockaddr *)r_dst);
		r_gate = (struct sockaddr_in6 *)tmp;
		if (r_gate->sin6_family != AF_INET6 ||
		    !IN6_IS_ADDR_LINKLOCAL(&r_gate->sin6_addr)
		    )
			continue;	/* ignore */

		if (rtm->rtm_addrs & RTA_NETMASK) {
			ADVANCE(tmp, (struct sockaddr *)r_gate);
			r_mask = (struct sockaddr_in6 *)tmp;
			/* WARNING: r_mask is SHORTER than sockaddr_in6 */
		}
		/* maybe there is GENMASK */

		if (rtm->rtm_flags & RTF_HOST)
			plen = MAX_PREFLEN;	/* r_mask->sin6_len == 0 */
		else if (!r_mask)
			plen = MAX_PREFLEN;	/* fail safe ? */
		else if (r_mask->sin6_len == 0)
			plen = 0;	/* default route */
		else
			plen = get_prefixlen(r_mask);

		if (!plen) {
			bzero((void *)&r_dst->sin6_addr,
			      sizeof(struct in6_addr));
			plen = MAX_PREFLEN;
			ADD_STATIC_TO_LOCAL(sflag | RTS6_KERNEL | RTS6_DEFAULT,
					    rtm->rtm_index,
					    plen,
					    &r_dst->sin6_addr,
					    &r_gate->sin6_addr,
					    (sflag & RTS6_INTERFACE) ? rt6_tag : 0,
					    (sflag & RTS6_INTERFACE) ? rt6_metric : 0);
		} else
			ADD_STATIC_TO_LOCAL(sflag | RTS6_KERNEL,
				rtm->rtm_index,
				plen,
				&r_dst->sin6_addr, &r_gate->sin6_addr,
				((sflag & RTS6_INTERFACE) ? rt6_tag : 0),
				((sflag & RTS6_INTERFACE) ? rt6_metric : 0));
		}		/* for each rtm */

	free(buf);

#ifdef NINSTALL
	return;
#endif

	for (sp = statrt; sp; sp = sp->sta_next) {
		/* Writing to kernel is done in add_local_route */

		/* sanity check */
		if (IN6_IS_ADDR_LINKLOCAL(&sp->sta_prefix.prf_addr) ||
		    IN6_IS_ADDR_LOOPBACK(&sp->sta_prefix.prf_addr) ||
		    IN6_IS_ADDR_MULTICAST(&sp->sta_prefix.prf_addr))
			continue;

		if (IN6_IS_ADDR_UNSPECIFIED(&sp->sta_prefix.prf_addr) &&
		    sp->sta_prefix.prf_len == MAX_PREFLEN)
			ADD_STATIC_TO_LOCAL(RTS6_STATIC | RTS6_DEFAULT, if_index(sp->sta_ifp),
			   sp->sta_prefix.prf_len, &sp->sta_prefix.prf_addr,
				     &sp->sta_gw, sp->sta_rtstat.rts_tagval,
					    sp->sta_rtstat.rts_metric);
		else
			ADD_STATIC_TO_LOCAL(RTS6_STATIC, if_index(sp->sta_ifp),
			   sp->sta_prefix.prf_len, &sp->sta_prefix.prf_addr,
				     &sp->sta_gw, sp->sta_rtstat.rts_tagval,
					    sp->sta_rtstat.rts_metric);
	}

    {
	/* install blackhole (RTF_REJECT) route for aggregated prefixes. */
	struct interface *ifp;
	struct aggregate *ap;
	struct rt_plen *lrt;
	struct tree_node *node;
	struct route_entry re, rg;

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		for (ap = ifp->if_config->int_aggr; ap; ap = ap->agr_next) {
			memset(&re, 0, sizeof(re));
			re.rip6_prflen = ap->agr_pref.prf_len;
			re.rip6_addr = ap->agr_pref.prf_addr;
			re.rip6_rtag = ap->agr_stat.rts_tagval;
			re.rip6_metric = ap->agr_stat.rts_metric;
			lrt = locate_local_route(&re, &node);
			memset(&rg, 0, sizeof(rg));
			memcpy(&rg.rip6_addr, &in6addr_loopback,
				sizeof(struct in6_addr));	/*XXX*/
			if (lrt == NULL) {
				add_local_route(&re, &rg, ifp,
					RTS6_BLACKHOLE | RTS6_INTERFACE, node);
			} else {
				lrt->rp_state |=
					(RTS6_BLACKHOLE | RTS6_INTERFACE);
				modify_local_route(lrt, &re, &rg, ifp);
			}
		}
	}
    }

	return;
}

/* 
 * Find the interface with address addr.
 */
struct interface *
if_ifwithaddr(struct preflist *addr, struct interface *ifp)
{
	register struct interface *inf;
	register struct preflist *pl = NULL;

#define equal( a1, a2 ) \
	((bcmp((char *)&a1->pl_pref.prf_addr, (char *)&a2->pl_pref.prf_addr, \
	       sizeof(struct in6_addr)) == 0) && \
	 (a1->pl_pref.prf_len == a2->pl_pref.prf_len))

	for (inf = ifnet; inf; inf = inf->if_next) {
		if (inf->if_flag & IFF_POINTOPOINT)
			continue;	/* ignore */

		if (IN6_IS_ADDR_LINKLOCAL(&addr->pl_pref.prf_addr))
			pl = inf->if_lladdr;
		else if (IN6_IS_ADDR_GLOBAL(&addr->pl_pref.prf_addr))
			pl = inf->if_ip6addr;
		else if (IN6_IS_ADDR_SITELOCAL(&addr->pl_pref.prf_addr))
			pl = inf->if_sladdr;
		/* else ? */

		for (; pl; pl = pl->pl_next) {
			if (equal(pl, addr)) {
				if (inf == ifp) {
					pl->pl_flag = PL_OLDADDR;
					return (inf);
				} else if (pl->pl_flag == PL_DELADDR)
					continue;
				/* duplicated address, ignore */
				if (!IN6_IS_ADDR_LINKLOCAL(&addr->pl_pref.prf_addr))
					return (inf);
			}
		}
	}
	return ((struct interface *)NULL);
}

/* 
 * Find the point-to-point interface with destination address addr.
 */
struct interface *
if_ifwithdstaddr(struct preflist *addr, struct interface *ifp)
{
	register struct interface *inf;
	register struct preflist *pl = NULL;

	/* Unknown Address of the other side */
	if (IN6_IS_ADDR_UNSPECIFIED(&addr->pl_dest))
		return (struct interface *)NULL;

	for (inf = ifnet; inf; inf = inf->if_next) {
		if ((inf->if_flag & IFF_POINTOPOINT) == 0)
			continue;

		if (IN6_IS_ADDR_LINKLOCAL(&addr->pl_pref.prf_addr))
			pl = inf->if_lladdr;
		else if (IN6_IS_ADDR_GLOBAL(&addr->pl_pref.prf_addr))
			pl = inf->if_ip6addr;
		else if (IN6_IS_ADDR_SITELOCAL(&addr->pl_pref.prf_addr))
			pl = inf->if_sladdr;
		/* else ? */

		for (; pl; pl = pl->pl_next) {
			if (IN6_ARE_ADDR_EQUAL(&pl->pl_dest, &addr->pl_dest)) {
				if ((inf == ifp) && (equal(pl, addr))) {
					pl->pl_flag = PL_OLDADDR;
					return (inf);
				} else if (pl->pl_flag == PL_DELADDR)
					continue;
				/* duplicated address, ignore */
				if (!IN6_IS_ADDR_LINKLOCAL(&addr->pl_pref.prf_addr))
					return (inf);
			}
		}
	}
	return ((struct interface *)NULL);
}

/* 
 * Clear the duplicate address on an unnumbered link
 */
void
if_duplicate(struct preflist *pl, struct interface *ifp)
{
	struct interface *inf;
	struct preflist *prf;

	/* maybe already zapped */
	if (IN6_IS_ADDR_UNSPECIFIED(&pl->pl_pref.prf_addr))
		return;

	for (inf = ifnet; inf; inf = inf->if_next) {
		if (inf == ifp)
			continue;	/* skip myself */
		/* assert: pl is never be the linklocal address */
		if (IN6_IS_ADDR_GLOBAL(&pl->pl_pref.prf_addr))
			prf = inf->if_ip6addr;
		else
			prf = inf->if_sladdr;

		for (; prf; prf = prf->pl_next) {
			if (IN6_ARE_ADDR_EQUAL(&pl->pl_pref.prf_addr,
					       &prf->pl_pref.prf_addr)) {
				if (prf->pl_flag == PL_DELADDR)
					continue;
				/* ZAP ME */
				bzero((void *)&(pl->pl_pref.prf_addr), sizeof(struct in6_addr));
				return;
			}
		}
	}
	return;
}

/* 
 * Adds address to the list of addresses maintained for interface.
 */
void
add_address(struct preflist *pl, struct interface *ifp)
{
	/* 
	 * Note: The first address of link local list is always used
	 * as the * source address of a packet if no address is
	 * specified through * Interface configuration.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&(pl->pl_pref.prf_addr))) {
		if (ifp->if_lladdr) {
			pl->pl_next = ifp->if_lladdr->pl_next;
			ifp->if_lladdr->pl_next = pl;
		} else {
			pl->pl_next = ifp->if_lladdr;
			ifp->if_lladdr = pl;
		}
	} else if (IN6_IS_ADDR_SITELOCAL(&(pl->pl_pref.prf_addr))) {
		pl->pl_next = ifp->if_sladdr;
		ifp->if_sladdr = pl;
	} else {		/* never a multicast address. already checked 
				 * in get_address() */
		if (ifp->if_ip6addr) {
			pl->pl_next = ifp->if_ip6addr->pl_next;
			ifp->if_ip6addr->pl_next = pl;
		} else {
			pl->pl_next = ifp->if_ip6addr;
			ifp->if_ip6addr = pl;
		}
	}
	return;
}

/* 
 * Add interface route for given address.
 */
void
add_route(struct preflist *pl, struct interface *ifp)
{
	int state;
	struct rt_plen *rtp;
	struct tree_node *tnp;
	struct route_entry re, rg;

	if (ifp->if_flag & IFF_POINTOPOINT) {
		/* both myaddr-route and remoteaddr-host-route are added */
		/* my addr */
		if (!IN6_IS_ADDR_LINKLOCAL(&pl->pl_pref.prf_addr) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&pl->pl_pref.prf_addr)) {
			/* unnumbered */
			bzero((char *)&re, sizeof(re));
			bzero((char *)&rg, sizeof(rg));
			re.rip6_addr = pl->pl_pref.prf_addr;
			re.rip6_prflen = pl->pl_pref.prf_len;
			re.rip6_rtag = rt6_tag;
			re.rip6_metric = rt6_metric;	/* direct reachable */
			rg.rip6_addr = ifp->if_lladdr->pl_pref.prf_addr;
			state = RTS6_INTERFACE | RTS6_PTOP;
			/* write to kernel */
			if ((rtp = locate_local_route(&re, &tnp)) == NULL)
				add_local_route(&re, &rg, ifp, state, tnp);
			else {
				rtp->rp_state = state;
				modify_local_route(rtp, &re, &rg, ifp);
			}
		}
		/* remote addr */
		if (IN6_IS_ADDR_LINKLOCAL(&pl->pl_dest) ||
		    IN6_IS_ADDR_UNSPECIFIED(&pl->pl_dest))
			return;

		bzero((char *)&re, sizeof(re));
		bzero((char *)&rg, sizeof(rg));
		re.rip6_addr = pl->pl_dest;
		re.rip6_prflen = 128;	/* HOST ROUTE */
		re.rip6_rtag = rt6_tag;
		re.rip6_metric = rt6_metric;	/* direct reachable */
		rg.rip6_addr = ifp->if_lladdr->pl_pref.prf_addr;
		state = RTS6_INTERFACE | RTS6_KERNEL | RTS6_PTOP;
		if ((rtp = locate_local_route(&re, &tnp)) == NULL)
			add_local_route(&re, &rg, ifp, state, tnp);
		else {
			rtp->rp_state = state;
			modify_local_route(rtp, &re, &rg, ifp);
		}

		return;
	}			/* end of PTOP */
	if (IN6_IS_ADDR_LINKLOCAL(&pl->pl_dest))
		return;

	bzero((char *)&re, sizeof(re));
	bzero((char *)&rg, sizeof(rg));
	re.rip6_addr = pl->pl_dest;
	re.rip6_prflen = pl->pl_pref.prf_len;
	re.rip6_rtag = rt6_tag;
	re.rip6_metric = rt6_metric;	/* direct reachable */
	rg.rip6_addr = ifp->if_lladdr->pl_pref.prf_addr;

	/* 
	 * We dont add routes to interface in the kernel. If we need
	 * to add * such routes RTS6_KERNEL should not be set in the
	 * state.
	 */
	state = RTS6_INTERFACE | RTS6_KERNEL;

	if ((rtp = locate_local_route(&re, &tnp)) == NULL)
		add_local_route(&re, &rg, ifp, state, tnp);
	else {
		rtp->rp_state = state;
		modify_local_route(rtp, &re, &rg, ifp);
	}
	return;
}

/* 
 * Delete interface route for the address.
 */
void
del_route(struct preflist *pl, struct interface *ifp)
{
	struct rt_plen *rtp;
	struct tree_node *tnp;
	struct route_entry *re;

	re = (struct route_entry *)malloc(sizeof(struct route_entry));
	if (re == NULL) {
		syslog(LOG_ERR, "del_route malloc : %m");
		return;
	}
	if (ifp->if_flag & IFF_POINTOPOINT) {
		/* both myaddr-route and remote-host-route are deleted */
		/* remote */
		if (!IN6_IS_ADDR_LINKLOCAL(&pl->pl_dest) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&pl->pl_dest)) {
			re->rip6_addr = pl->pl_dest;
			re->rip6_prflen = 128;	/* HOST ROUTE */
			if ((rtp = locate_local_route(re, &tnp)) != NULL)
				delete_local_route(rtp);
		}
		/* myaddr */
		if (!IN6_IS_ADDR_LINKLOCAL(&pl->pl_pref.prf_addr) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&pl->pl_pref.prf_addr)) {
			re->rip6_addr = pl->pl_pref.prf_addr;
			re->rip6_prflen = pl->pl_pref.prf_len;
			if ((rtp = locate_local_route(re, &tnp)) != NULL)
				delete_local_route(rtp);
		}
	} else {		/* !P2P */
		if (!IN6_IS_ADDR_LINKLOCAL(&pl->pl_dest)) {
			re->rip6_addr = pl->pl_dest;
			re->rip6_prflen = pl->pl_pref.prf_len;
			if ((rtp = locate_local_route(re, &tnp)) != NULL)
				delete_local_route(rtp);
		}
	}

	free(re);

	return;
}

void
if_freeaddresses(struct interface *ifp)
{
	struct preflist *pl;

	for (pl = ifp->if_ip6addr; pl; pl = ifp->if_ip6addr) {
		ifp->if_ip6addr = pl->pl_next;
		free(pl);
	}
	for (pl = ifp->if_sladdr; pl; pl = ifp->if_sladdr) {
		ifp->if_sladdr = pl->pl_next;
		free(pl);
	}
	for (pl = ifp->if_lladdr; pl; pl = ifp->if_lladdr) {
		ifp->if_lladdr = pl->pl_next;
		free(pl);
	}
	return;
}

/* 
 * Get pointer to local interface with the name.
 */
struct interface *
get_if_by_name(struct sockaddr_dl *sdl)
{
	struct interface *ifp;

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if (strncmp(ifp->if_name, sdl->sdl_data, sdl->sdl_nlen) == 0)
			return ifp;
	}
	return ((struct interface *)NULL);
}

/* 
 * Join all router multicast group for the interface.
 */
int
join_multicast_group(struct interface *ifp)
{
	struct ipv6_mreq mr;
	struct sockaddr_in6 sin;

	(void)inet_pton(AF_INET6, ALL_RIP6_ROUTER, &(mr.ipv6mr_multiaddr));
	bzero((char *)&sin, sizeof(sin));
	mr.ipv6mr_interface = if_index(ifp);

	if (setsockopt(rip6_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		       (void *)&(mr.ipv6mr_interface),
		       sizeof(unsigned int)) < 0)
		syslog(LOG_ERR, "multicast if: %m");

	if (setsockopt(rip6_sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		       (void *)&mr, sizeof(mr)) < 0)
		syslog(LOG_ERR, "join multicast: %m");

	ifp->if_flag |= IFF_JOINED;
	return 0;
}

/* 
 * Drop all router multicast group for the interface.
 */
int
drop_multicast_group(struct interface *ifp)
{
	struct ipv6_mreq mr;

	if (inet_pton(AF_INET6, ALL_RIP6_ROUTER, &(mr.ipv6mr_multiaddr)) <= 0)
		return -1;	/* WHO CARES? */
	mr.ipv6mr_interface = if_index(ifp);
	if (setsockopt(rip6_sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
		       (void *)&mr, sizeof(mr)) < 0)
		syslog(LOG_ERR, "drop multicast: %m");
	return 0;
}

/* 
 * dump if list
 */
static void
prt_iflist(void)
{
	struct interface *ifp;
	struct preflist *pl;
	char str[INET6_ADDRSTRLEN];

	printf("\nInterface List\n");
	printf("--------------\n");
	
	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		printf("Interface name: %s\n", ifp->if_name);
		printf("  index: %d  metric: %d  flag: %d  mtu : %d\n",
		       if_index(ifp), ifp->if_metrc, ifp->if_flag,
		       ifp->if_lmtu);
		printf("  Global addresses:\n");
		for (pl = ifp->if_ip6addr; pl; pl = pl->pl_next) {
			inet_ntop(AF_INET6, &pl->pl_pref.prf_addr,
				  str, sizeof(str));
			printf("    addr: %s\n", str);
			printf("    len:: %d\n", pl->pl_pref.prf_len);
			inet_ntop(AF_INET6, &pl->pl_mask, str, sizeof(str));
			printf("    mask: %s\n", str);
			inet_ntop(AF_INET6, &pl->pl_dest, str, sizeof(str));
			printf("    dest: %s\n", str);
		}
		printf("  Linklocal addresses:\n");
		for (pl = ifp->if_lladdr; pl; pl = pl->pl_next) {
			inet_ntop(AF_INET6, &pl->pl_pref.prf_addr,
				  str, sizeof(str));
			printf("    addr: %s\n", str);
			printf("    len:: %d\n", pl->pl_pref.prf_len);
			inet_ntop(AF_INET6, &pl->pl_mask, str, sizeof(str));
			printf("    mask: %s\n", str);
			inet_ntop(AF_INET6, &pl->pl_dest, str, sizeof(str));
			printf("    dest: %s\n", str);
		}
		printf("  Siltelocal addresses:\n");
		for (pl = ifp->if_sladdr; pl; pl = pl->pl_next) {
			inet_ntop(AF_INET6, &pl->pl_pref.prf_addr,
				  str, sizeof(str));
			printf("    addr: %s\n", str);
			printf("    len:: %d\n", pl->pl_pref.prf_len);
			inet_ntop(AF_INET6, &pl->pl_mask, str, sizeof(str));
			printf("    mask: %s\n", str);
			inet_ntop(AF_INET6, &pl->pl_dest, str, sizeof(str));
			printf("    dest: %s\n", str);
		}
		printf("  Config list name : %s\n", ifp->if_config->int_name);
		if (ifp->if_config->int_ctlout != NULL) {
			inet_ntop(AF_INET6, &ifp->if_config->int_ctlout->ctl_addr.sin6_addr,
				  str, sizeof(str));
			printf("  ctl out addr : %s\n", str);
		}
	}
	return;
}
