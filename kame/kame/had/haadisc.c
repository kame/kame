/*	$KAME: haadisc.c,v 1.7 2003/02/18 09:57:06 t-momose Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.
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

/*
 * $Id: haadisc.c,v 1.7 2003/02/18 09:57:06 t-momose Exp $
 */

/*
 * Copyright (C) 2000 NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of NEC Corporation or any of its affiliates shall not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NEC CORPORATION ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL NEC CORPORATION BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif /* __FreeBSD__ >= 3 */
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include <kvm.h>
#include <nlist.h>
#include <netinet6/mip6_var.h>
#include <fcntl.h>
#include <limits.h>

#include "halist.h"
#include "haadisc.h"
#include "timestamp.h"

/* structures for ND option processing */
struct nd_optlist {
	struct nd_optlist *next;
	struct nd_opt_hdr *opt;
};
union nd_opts {
	struct nd_opt_hdr *nd_opt_array[9];	/*max = home agent info*/
	struct {
		struct nd_opt_hdr *zero;
		struct nd_opt_hdr *src_lladdr;
		struct nd_opt_hdr *tgt_lladdr;
		struct nd_opt_prefix_info *pi_beg;/* multiple opts, start */
		struct nd_opt_rd_hdr *rh;
		struct nd_opt_mtu *mtu;
		struct nd_opt_hdr *six;
		struct nd_opt_advinterval *adv;
		struct nd_opt_homeagent_info *hai;
		struct nd_opt_hdr *search;	/* multiple opts */
		struct nd_opt_hdr *last;	/* multiple opts */
		int done;
		struct nd_opt_prefix_info *pi_end;/* multiple opts, end */
	} nd_opt_each;
};
#define nd_opts_src_lladdr	nd_opt_each.src_lladdr
#define nd_opts_tgt_lladdr	nd_opt_each.tgt_lladdr
#define nd_opts_pi		nd_opt_each.pi_beg
#define nd_opts_pi_end		nd_opt_each.pi_end
#define nd_opts_rh		nd_opt_each.rh
#define nd_opts_mtu		nd_opt_each.mtu
#define nd_opts_adv		nd_opt_each.adv
#define nd_opts_hai		nd_opt_each.hai
#define nd_opts_search		nd_opt_each.search
#define nd_opts_last		nd_opt_each.last
#define nd_opts_done		nd_opt_each.done

void read_config __P((char *));
static void sock_open __P((void));
static void icmp6_recv __P((void));
static void ra_input __P((int, struct nd_router_advert *, struct in6_pktinfo *,
			  struct sockaddr_in6 *));
void nd6_option_init __P((void *, int, union nd_opts *));
int nd6_options __P((union nd_opts *));
static void haad_request_input __P((int, struct dhaad_req *,
				    struct in6_pktinfo *, struct sockaddr_in6 *,
				    int));
static void haad_reply_output __P((u_int16_t, struct sockaddr_in6 *,
				   struct in6_addr *, struct hagent_ifinfo *,
				   int, int));
static void haadisc_set_dump_file __P((void));
static void haadisc_clean_hal __P((void));


struct sockin6_addr {
  LIST_ENTRY (sockin6_addr)   sockin6_entry;
  struct sockaddr_in6 addr;
};
LIST_HEAD(sockin6_addr_list, sockin6_addr);

static void mpi_solicit_input __P((struct in6_pktinfo *, struct sockaddr_in6 *, struct mobile_prefix_solicit *));
static void mpi_advert_output_All __P((struct sockin6_addr_list *, struct in6_addr *, struct hagent_ifinfo *));
static void mpi_advert_output __P((struct sockaddr_in6 *, struct in6_addr *, struct hagent_ifinfo *, u_int16_t));
static int reg_hoa_pick __P((struct in6_addr *, struct in6_addr *hoaddr));
static int reg_coa_pick __P((struct sockin6_addr_list *));
static int pi_pick __P((struct in6_addr *, struct nd_opt_prefix_info *, struct hagent_ifinfo *, int));
static int ha_pick __P((struct in6_addr *, struct in6_addr *, struct hagent_ifinfo *));
static int prefix_dup_check __P((struct nd_opt_prefix_info *, struct hagent_gaddr *, int));
static int kread __P((u_long addr, void *buf, int size));
static int get_bc_list __P((struct mip6_bc_list *));

struct nlist nl[] = {
#define N_MIP6_BC_LIST      0
        { "_mip6_bc_list" },
        { NULL }
};

/* home agent list for each interfaces */
struct hagent_ifinfo *haifinfo_tab;

static char *dumpfilename = "/var/run/had.dump";
					/* XXX: should be configurable */
static char *pidfilename = "/var/run/had.pid";	/* XXX */
int ifnum;
int sock;
int dump, do_dump = 0, do_clean = 0;;

#define RABUFSIZE 2048

static u_char *rcvcmsgbuf, *sndcmsgbuf;
static size_t rcvcmsgbuflen, sndcmsgbuflen;
struct msghdr rcvmhdr, sndmhdr;
struct iovec rcviov[2], sndiov[2];
struct sockaddr_in6 from;
static u_char rabuf[RABUFSIZE];

/* preventing too many loops in ND option parsing */
int nd6_maxndopt = 10;	/* max # of ND options allowed */

char *__progname;

kvm_t *kvmd = NULL;

#define KREAD(addr, buf, type) \
        kread((u_long)addr, (void *)buf, sizeof(type))

void
usage()
{
	(void) fprintf(stderr, "usage: %s [-Df] interface ...\n", __progname);
	exit(1);
}

/*
 * 
 * listen RA (not send RA by myself)
 * update home agent list with RA
 * home agent list aging
 * receive HAAD ICMP and send reply
 */

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int ch, i;
    int daemonmode = 1;

    fd_set fdset;
    int maxfd = 0;
    struct timeval timeout;

    char kvm_err[_POSIX2_LINE_MAX];

    __progname = strrchr(argv[0], '/');
    if (__progname == NULL)
	__progname = argv[0];
    else
	__progname++;

    /*
     * sequence:
     * configure home link interface
     * get interface infromation
     * prepare home agent list
     */

    openlog(__progname, LOG_NDELAY|LOG_PID, LOG_DAEMON);

    while ((ch = getopt(argc, argv, "Df")) != -1) {
	switch (ch) {
	case 'D':
	    dump = 1;
	    break;
	case 'f':
	    daemonmode = 0;
	    break;
	default:
	    usage();
	    /* NOTREACHED */
	}
    }

    argc -= optind;
    argv += optind;

    ifnum = argc;
    if (ifnum == 0) {
	usage();
	/* NOTREACHED */
    }


    if ((haifinfo_tab = malloc(ifnum * sizeof (struct hagent_ifinfo))) == NULL) {
	syslog(LOG_ERR, __FUNCTION__ "memory allocation failed.\n");
	exit(3);
    }
    bzero(haifinfo_tab, ifnum * sizeof (struct hagent_ifinfo));

    /* interfae table initializtion */
    for (i = 0; i < ifnum; ++i) {
	haifinfo_tab[i].ifindex = if_nametoindex(argv[i]);
	if_indextoname(haifinfo_tab[i].ifindex, haifinfo_tab[i].ifname);
    }

    /* get linklocal addresses of interfaces */
    if (haif_getifaddrs() != 0) {
	syslog(LOG_ERR, __FUNCTION__
	       "get linklocal address of interfaces failed");
	exit(1);
    }

    /* raw socket initiailzation */
    sock_open();

    /* set signal handler */
    signal(SIGUSR1, (void *)haadisc_set_dump_file);
    signal(SIGHUP, (void *)haadisc_clean_hal);

    /* set timezone */
    thiszone = gmt2local(0);

    if (daemonmode) {
	pid_t pid;
	FILE *fp;

	daemon(1, 0);
	pid = getpid();
	if ((fp = fopen(pidfilename, "w")) == NULL)
		syslog(LOG_ERR, __FUNCTION__
		       "failed to open a log file(%s): %s",
		       pidfilename, strerror(errno));
	else {
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	}
    }

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    maxfd = sock;
    timeout.tv_usec = 0;
    timeout.tv_sec = 1;

    if ((kvmd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, kvm_err)) == NULL) {
        fprintf(stderr, "(%s)\n", kvm_err);
    }
    
    for (;;) {
	struct fd_set select_fd = fdset; /* reinitialize */

	if (do_dump) { /* SIGUSR1 */
	    haadisc_dump_file(dumpfilename);
	    do_dump = 0;
	}

	if (do_clean) { /* SIGHUP */
	    /* clean home agent list and update interface address */
	    haadisc_hup();
	    do_clean = 0;
	}

	/* IMPLID:MIP6HA#15 */
	hal_check_expire();

	/* wait message arrival or timeout */
	if ((i = select(maxfd + 1, &select_fd,
			NULL, NULL, &timeout)) < 0) {
	    continue;
	}

	DPRINT("<x:main:select returned>\n");
	if (FD_ISSET(sock, &select_fd)) {
	    icmp6_recv();
	}
    }
    kvm_close(kvmd);
    exit(0);		/* NOTREACHED */
}

/*
 * open raw socket(for receive and send ICMPv6)
 */
static void
sock_open()
{
    struct icmp6_filter filt;
    int on;

    /* create socket descriptor */
    if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
	syslog(LOG_ERR, "<%s> socket: %s", __FUNCTION__,
	       strerror(errno));
	exit(1);
    }

    /* specify to tell receiving interface */
    on = 1;
#ifdef IPV6_RECVPKTINFO
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		   sizeof(on)) < 0) {
	syslog(LOG_ERR, "<%s> IPV6_RECVPKTINFO: %s",
	       __FUNCTION__, strerror(errno));
	exit(1);
    }
#else  /* old adv. API */
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &on,
		   sizeof(on)) < 0) {
	syslog(LOG_ERR, "<%s> IPV6_PKTINFO: %s",
	       __FUNCTION__, strerror(errno));
	exit(1);
    }
#endif 

    /* configure filter to receive only RA and ICMPv6 related MIPv6 */
#ifdef ICMP6_FILTER
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
    ICMP6_FILTER_SETPASS(ICMP6_DHAAD_REQUEST, &filt);
    ICMP6_FILTER_SETPASS(ICMP6_MOBILEPREFIX_SOLICIT, &filt);
#ifdef ICMP6_DHAAD_REQUEST_KAME
    ICMP6_FILTER_SETPASS(ICMP6_DHAAD_REQUEST_KAME, &filt);
#endif
    if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		   sizeof(filt)) < 0) {
	syslog(LOG_ERR, "<%s> IICMP6_FILTER: %s",
	       __FUNCTION__, strerror(errno));
	exit(1);
    }
#endif

    on = 1;
    /* specify to tell value of hoplimit field of received IP6 hdr */
#ifdef IPV6_RECVHOPLIMIT
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on,
		   sizeof(on)) < 0) {
	syslog(LOG_ERR, "<%s> IPV6_RECVHOPLIMIT: %s",
	       __FUNCTION__, strerror(errno));
	exit(1);
    }
#else  /* old adv. API */
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &on,
		   sizeof(on)) < 0) {
	syslog(LOG_ERR, "<%s> IPV6_HOPLIMIT: %s",
	       __FUNCTION__, strerror(errno));
	exit(1);
    }
#endif

    /* initialize message buffers */
    rcvcmsgbuflen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	CMSG_SPACE(sizeof(int));
    rcvcmsgbuf = (u_char *)malloc(rcvcmsgbuflen);
    if (rcvcmsgbuf == NULL) {
	syslog(LOG_ERR, "<%s> not enough core", __FUNCTION__);
	exit(1);
    }

    sndcmsgbuflen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    sndcmsgbuf = (u_char *)malloc(sndcmsgbuflen);
    if (sndcmsgbuf == NULL) {
	syslog(LOG_ERR, "<%s> not enough core", __FUNCTION__);
	exit(1);
    }

    rcviov[0].iov_base = (caddr_t)rabuf;
    rcviov[0].iov_len = sizeof(rabuf);
    rcvmhdr.msg_name = (caddr_t)&from;
    rcvmhdr.msg_namelen = sizeof(from);
    rcvmhdr.msg_iov = rcviov;
    rcvmhdr.msg_iovlen = 1;
    rcvmhdr.msg_control = (caddr_t) rcvcmsgbuf;
    rcvmhdr.msg_controllen = rcvcmsgbuflen;

    sndmhdr.msg_namelen = sizeof(struct sockaddr_in6);
    sndmhdr.msg_iov = sndiov;
    sndmhdr.msg_iovlen = 1;
    sndmhdr.msg_control = (caddr_t)sndcmsgbuf;
    sndmhdr.msg_controllen = sndcmsgbuflen;
}

static void
haadisc_set_dump_file()
{
    do_dump = 1;
}

static void
haadisc_clean_hal()
{
    do_clean = 1;
}

/*
 * receive ICMPv6 message from raw socket
 */
static void
icmp6_recv()
{
#ifdef OLDRAWSOCKET
    struct ip6_hdr *ip;
#endif 
    struct icmp6_hdr *icp;
    struct cmsghdr *cm;
    struct in6_pktinfo *pi = NULL;
    int len;
    int *hlimp = NULL;
    u_char ntopbuf[INET6_ADDRSTRLEN], ifnamebuf[IFNAMSIZ];

    DPRINT("<s:icmp6_recv>");
    /*
     * Get message. We reset msg_controllen since the field could
     * be modified if we had received a message before setting
     * receive options.
     */
    rcvmhdr.msg_controllen = rcvcmsgbuflen;
    if ((len = recvmsg(sock, &rcvmhdr, 0)) < 0) {
	DPRINT("<e:icmp6_recv:recvmsg() failed>");
	return;
    }
  
    /* extract optional information via Advanced API */
    for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&rcvmhdr);
	 cm;
	 cm = (struct cmsghdr *)CMSG_NXTHDR(&rcvmhdr, cm)) {
	if (cm->cmsg_level == IPPROTO_IPV6 &&
	    cm->cmsg_type == IPV6_PKTINFO &&
	    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
	    pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
	}
	if (cm->cmsg_level == IPPROTO_IPV6 &&
	    cm->cmsg_type == IPV6_HOPLIMIT &&
	    cm->cmsg_len == CMSG_LEN(sizeof(int))) {
		hlimp = (int *)CMSG_DATA(cm);
	}
    }

    if (hlimp == NULL) {
	syslog(LOG_ERR,
	       "<%s> failed to get receiving hop limit",
	       __FUNCTION__);
	return;
    }

    /* check message length */
#ifdef OLDRAWSOCKET
    if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
	syslog(LOG_ERR,
	       "<%s> packet size(%d) is too short",
	       __FUNCTION__, len);
	DPRINT("<e:icmp6_recv:read data too short>");
	return;
    }

    ip = (struct ip6_hdr *)recvmhdr.msg_iov[0].iov_base;
    icp = (struct icmp6_hdr *)(ip + 1); /* XXX: ext. hdr? */
#else
    if (len < sizeof(struct icmp6_hdr)) {
	syslog(LOG_ERR,
	       "<%s> packet size(%d) is too short",
	       __FUNCTION__, len);
	DPRINT("<e:icmp6_recv:read data too short>");
	return;
    }

    icp = (struct icmp6_hdr *)rcvmhdr.msg_iov[0].iov_base;
#endif 

    /* dispatch per message routine */
    switch (icp->icmp6_type) {
    case ND_ROUTER_ADVERT:
	/* check hop-limit */
	if (*hlimp != 255) {
	    syslog(LOG_ERR,
		   "<%s> RA with invalid hop limit(%d) "
		   "received from %s on %s",
		   __FUNCTION__, *hlimp,
		   inet_ntop(AF_INET6, &from.sin6_addr, ntopbuf,
			     INET6_ADDRSTRLEN),
		   if_indextoname(pi->ipi6_ifindex, ifnamebuf));
	    return;
	}
	if (icp->icmp6_code) {
		syslog(LOG_NOTICE,
		       "<%s> RS with invalid ICMP6 code(%d) "
		       "received from %s on %s",
		       __FUNCTION__, icp->icmp6_code,
		       inet_ntop(AF_INET6, &from.sin6_addr, ntopbuf,
				 INET6_ADDRSTRLEN),
		if_indextoname(pi->ipi6_ifindex, ifnamebuf));
		return;
	}
	if (len < sizeof(struct nd_router_advert)) {
		syslog(LOG_NOTICE,
		       "<%s> RA from %s on %s does not have enough "
		       "length (len = %d)",
		       __FUNCTION__,
		       inet_ntop(AF_INET6, &from.sin6_addr, ntopbuf,
				 INET6_ADDRSTRLEN),
		       if_indextoname(pi->ipi6_ifindex, ifnamebuf), len);
		return;
	}
	/* IMPLID:MIP6HA#8 */
	/* from contains sender's linklocal address */
	if (!IN6_IS_ADDR_LINKLOCAL(&(from.sin6_addr))) {
	    syslog(LOG_ERR, "<%s> src %s is not link-local",
		   __FUNCTION__,
		   inet_ntop(AF_INET6, &(from.sin6_addr), ntopbuf,
			     INET6_ADDRSTRLEN));
	    return;
	}
	ra_input(len, (struct nd_router_advert *)icp, pi, &from);
	break;
    case ICMP6_DHAAD_REQUEST:
#ifdef ICMP6_DHAAD_REQUEST_KAME
    case ICMP6_DHAAD_REQUEST_KAME:
#endif
	if (icp->icmp6_code) {
		syslog(LOG_NOTICE,
		       "<%s> HAAD Request with invalid ICMP6 code(%d) "
		       "received from %s on %s",
		       __FUNCTION__, icp->icmp6_code,
		       inet_ntop(AF_INET6, &from.sin6_addr, ntopbuf,
				 INET6_ADDRSTRLEN),
		if_indextoname(pi->ipi6_ifindex, ifnamebuf));
		return;
	}
	if (len < sizeof(struct dhaad_req)) {
		syslog(LOG_NOTICE,
		       "<%s> HAAD Request from %s on %s does not have enough "
		       "length (len = %d)",
		       __FUNCTION__,
		       inet_ntop(AF_INET6, &from.sin6_addr, ntopbuf,
				 INET6_ADDRSTRLEN),
		       if_indextoname(pi->ipi6_ifindex, ifnamebuf), len);
		return;
	}
	haad_request_input(len, (struct dhaad_req *)icp, pi, &from, icp->icmp6_type);
	break;
    case ICMP6_MOBILEPREFIX_SOLICIT:
        if(kvmd != NULL)
            mpi_solicit_input(pi, &from, (struct mobile_prefix_solicit *)icp);
        break;
    default:
	/* should not occur */
	break;
    }
    DPRINT("<e:icmp6_recv>\n");
}

/*
 * Receive Router Advertisement Message
 */
static void
ra_input(len, ra, pinfo, from)
    int len;
    struct nd_router_advert *ra;
    struct in6_pktinfo *pinfo;
    struct sockaddr_in6 *from;
{
    union nd_opts ndopts;
    /* IMPLID:MIP6HA#10 */
    u_int16_t ha_lifetime;
    int16_t ha_pref = 0;
    struct hagent_entry *halp;
    struct hagent_ifinfo *haif;
    u_char ntopbuf[INET6_ADDRSTRLEN];
    struct sockin6_addr_list addr_list;

    /* lookup home agent interface info from receiving ifindex */
    haif = haif_find(pinfo->ipi6_ifindex);
    if (haif == NULL) {
#ifdef DEBUG
	fprintf(stderr, "<x:ra_input: RA received on ifindex %d"
		" which is not home link, ignored>\n",
		pinfo->ipi6_ifindex);
#endif
	goto done;
    }

    /* process ND option(s) */
    bzero(&ndopts, sizeof(union nd_opts));
    nd6_option_init(ra + 1, len - sizeof(struct nd_router_advert), &ndopts);
    if (nd6_options(&ndopts) < 0) {
	syslog(LOG_INFO, "ra_input: invalid ND option, ignored\n");
	goto done;
    }

    /* Is this RA from some home agent or not? */
    if (0 == (ra->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT)) {
	/* IMPLID:MIP6HA#7 */
	/*
	 * delete home agent list entry if it exists,
	 * because this router is not a home agent.
	 */
	hal_delete(haif, &(from->sin6_addr));
	goto done;
    }

    /* determine HA lifetime and preference */
    /* IMPLID:MIP6HA#9 */
    ha_lifetime = ntohs(ra->nd_ra_router_lifetime);
    if (ndopts.nd_opts_hai) {
	ha_lifetime = ntohs(ndopts.nd_opts_hai->nd_opt_hai_lifetime);
	/* IMPLID:MIP6HA#10 */
	ha_pref = ntohs(ndopts.nd_opts_hai->nd_opt_hai_preference);
    }

    /* update and get home agent list entry */
    halp = hal_update(pinfo->ipi6_ifindex, &from->sin6_addr, ha_lifetime, ha_pref);

    if (!halp) {
	/*
	 * no home agent list entry (deleted or cannot create)
	 */
	goto done;
    }

    /* proceee prefix information option in RA
     * in order to accumlate home agent global address
     * information in home agent list
     */
    if (ndopts.nd_opts_pi) {
	/*
	 * parse prefix information option and
	 * get global address(es) in it.
	 */
	struct nd_opt_hdr *pt;
	struct nd_opt_prefix_info *pi;
	struct hagent_gaddr *lastp;
	/* tempolary global address list */
	struct hagent_gaddr newgaddrs;

	newgaddrs.hagent_next_gaddr = NULL;
	lastp = &newgaddrs;

	/* search prefix information vector */
	for (pt = (struct nd_opt_hdr *)ndopts.nd_opts_pi;
	     pt <= (struct nd_opt_hdr *)ndopts.nd_opts_pi_end;
	     pt = (struct nd_opt_hdr *)((caddr_t)pt +
					(pt->nd_opt_len << 3))) {

	    if (pt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
		continue;
	    pi = (struct nd_opt_prefix_info *)pt;

	    if (pi->nd_opt_pi_len != 4) {
		syslog(LOG_INFO,
		       "ra_input: invalid option "
		       "len %d for prefix information option, "
		       "ignored\n", pi->nd_opt_pi_len);
		continue;
	    }

	    if (128 < pi->nd_opt_pi_prefix_len) {
		syslog(LOG_INFO,
		       "ra_input: invalid prefix "
		       "len %d for prefix information option, "
		       "ignored\n", pi->nd_opt_pi_prefix_len);
		continue;
	    }

	    if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix)
		|| IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix)) {
		syslog(LOG_INFO,
		       "ra_input: invalid prefix "
		       "%s, ignored\n",
		       inet_ntop(AF_INET6, &pi->nd_opt_pi_prefix,
				 ntopbuf, INET6_ADDRSTRLEN));
		continue;
	    }

	    /* aggregatable unicast address, rfc2374 */
	    if ((pi->nd_opt_pi_prefix.s6_addr[0] & 0xe0) == 0x20
		&& pi->nd_opt_pi_prefix_len != 64) {
		syslog(LOG_INFO,
		       "ra_input: invalid prefixlen "
		       "%d for rfc2374 prefix %s, ignored\n",
		       pi->nd_opt_pi_prefix_len,
		       inet_ntop(AF_INET6, &pi->nd_opt_pi_prefix,
				 ntopbuf, INET6_ADDRSTRLEN));
		continue;
	    }

	    /* onlink and R bit is set XXX */
	    if ((pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK)
		&& (pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ROUTER)) {
		    /* IMPLID:MIP6HA#14 */
		    lastp = hal_gaddr_add(halp, lastp, pi);
	    }
	}
	/* replace home agent global address list to new one */
	if (newgaddrs.hagent_next_gaddr == NULL) goto done;
	hal_gaddr_last(halp, newgaddrs.hagent_next_gaddr);
	
        if (kvmd != NULL){
	    /* pick CoAs */
	    LIST_INIT(&addr_list);
	    if (reg_coa_pick(&addr_list) == 0) {
	    /* send Mobile Prefix Advertisement */
	        mpi_advert_output_All(&addr_list, &(pinfo->ipi6_addr), haif);
	    }
        }
    }
done:
}

/*
 * ND option processing initialization
 * (from kame/sys/netinet6/nd6.c)
 */
void
nd6_option_init(opt, icmp6len, ndopts)
    void *opt;
    int icmp6len;
    union nd_opts *ndopts;
{
    bzero(ndopts, sizeof(*ndopts));
    ndopts->nd_opts_search = (struct nd_opt_hdr *)opt;
    ndopts->nd_opts_last
	= (struct nd_opt_hdr *)(((u_char *)opt) + icmp6len);

    if (icmp6len == 0) {
	ndopts->nd_opts_done = 1;
	ndopts->nd_opts_search = NULL;
    }
}

/*
 * Take one ND option.
 * (from kame/sys/netinet6/nd6.c)
 */
struct nd_opt_hdr *
nd6_option(ndopts)
    union nd_opts *ndopts;
{
    struct nd_opt_hdr *nd_opt;
    int olen;

    if (!ndopts)
	exit(1);
    if (!ndopts->nd_opts_last)
	exit(1);
    if (!ndopts->nd_opts_search)
	return NULL;
    if (ndopts->nd_opts_done)
	return NULL;

    nd_opt = ndopts->nd_opts_search;

    olen = nd_opt->nd_opt_len << 3;
    if (olen == 0) {
	/*
	 * Message validation requires that all included
	 * options have a length that is greater than zero.
	 */
	bzero(ndopts, sizeof(*ndopts));
	return NULL;
    }

    ndopts->nd_opts_search = (struct nd_opt_hdr *)((caddr_t)nd_opt + olen);
    if (!(ndopts->nd_opts_search < ndopts->nd_opts_last)) {
	ndopts->nd_opts_done = 1;
	ndopts->nd_opts_search = NULL;
    }
    return nd_opt;
}

/*
 * Parse multiple ND options.
 * This function is much easier to use, for ND routines that do not need
 * multiple options of the same type.
 * (from kame/sys/netinet6/nd6.c)
 */
int
nd6_options(ndopts)
    union nd_opts *ndopts;
{
    struct nd_opt_hdr *nd_opt;
    int i = 0;

    if (!ndopts)
	exit(1);
    if (!ndopts->nd_opts_last)
	exit(1);
    if (!ndopts->nd_opts_search)
	return 0;

    while (1) {
	nd_opt = nd6_option(ndopts);
	if (!nd_opt && !ndopts->nd_opts_last) {
	    /*
	     * Message validation requires that all included
	     * options have a length that is greater than zero.
	     */
	    bzero(ndopts, sizeof(*ndopts));
	    return -1;
	}

	if (!nd_opt)
	    goto skip1;

	switch (nd_opt->nd_opt_type) {
	case ND_OPT_SOURCE_LINKADDR:
	case ND_OPT_TARGET_LINKADDR:
	case ND_OPT_MTU:
	case ND_OPT_REDIRECTED_HEADER:
	case ND_OPT_ADVINTERVAL:
	case ND_OPT_HOMEAGENT_INFO:
	    if (ndopts->nd_opt_array[nd_opt->nd_opt_type]) {
		printf("duplicated ND6 option found "
		       "(type=%d)\n", nd_opt->nd_opt_type);
				/* XXX bark? */
	    } else {
		ndopts->nd_opt_array[nd_opt->nd_opt_type]
		    = nd_opt;
	    }
	    break;
	case ND_OPT_PREFIX_INFORMATION:
	    if (ndopts->nd_opt_array[nd_opt->nd_opt_type] == 0) {
		ndopts->nd_opt_array[nd_opt->nd_opt_type]
		    = nd_opt;
	    }
	    ndopts->nd_opts_pi_end =
		(struct nd_opt_prefix_info *)nd_opt;
	    break;
	default:
	    /*
	     * Unknown options must be silently ignored,
	     * to accomodate future extension to the protocol.
	     */
	    syslog(LOG_DEBUG,
		   "nd6_options: unsupported option %d - "
		   "option ignored\n", nd_opt->nd_opt_type);
	}

    skip1:
	i++;
	if (i > nd6_maxndopt) {
	    printf("too many loop in nd opt\n");
	    break;
	}

	if (ndopts->nd_opts_done)
	    break;
    }

    return 0;
}

/*
 * Receive Home Agent Address Discovery Request Message
 */
static void
haad_request_input(len, haad_req, pi, src, type)
    int len;
    struct dhaad_req *haad_req;
    struct in6_pktinfo *pi;
    struct sockaddr_in6 *src;
    int type;
{
    u_int16_t msgid;
    struct hagent_ifinfo *haif;
    int ifga_index = -1;

    msgid = haad_req->dhaad_req_id;

    /* determine home link by global address */
    haif = haif_findwithanycast(&pi->ipi6_addr, &ifga_index);

    if (! haif) {
	syslog(LOG_ERR, __FUNCTION__ "cannt get home agent ifinfo.\n");
	goto err;
    }

    /* send home agent address discovery response message */
    haad_reply_output(msgid, src,
#ifdef MIP6_DRAFT13
		      &(haad_req->ha_dreq_home),
#else
		      &(pi->ipi6_addr),		/* anycast addr. */
#endif
		      haif, type, ifga_index);
err:
}

/*
 * Send Home Agent Address Discovery Reply Message
 */
static void
haad_reply_output(msgid, coaddr, reqaddr, haif, type, ifga_index)
    u_int16_t msgid;
    struct sockaddr_in6 *coaddr;
    struct in6_addr *reqaddr;
    struct hagent_ifinfo *haif;
    int type, ifga_index;
{
    struct cmsghdr *cm;
    struct in6_pktinfo *pi;
    struct dhaad_rep *hap;
    struct in6_addr *hagent_addr;
    struct in6_addr src = in6addr_any;
    int len, nhaa, count;
    u_int8_t buf[IPV6_MMTU];

    /*
     * sequence:
     * - build ICMP reply message
     * - source address is home agent global address 
     * - destination address is source address of request packet
     */

    if (haif->haif_gavec[ifga_index].global != NULL)
	    src = ((struct sockaddr_in6 *)(haif->haif_gavec[ifga_index].global->ifa_addr))->sin6_addr;

    /* create ICMPv6 message */
    hap = (struct dhaad_rep *)buf;
    bzero(hap, sizeof (struct dhaad_rep));
#ifdef ICMP6_DHAAD_REQUEST_KAME
    hap->dhaad_rep_type = (type == ICMP6_DHAAD_REQUEST_KAME ?
				ICMP6_DHAAD_REPLY_KAME :
				ICMP6_DHAAD_REPLY);
#else
    hap->dhaad_rep_type = ICMP6_DHAAD_REPLY;
#endif
    hap->dhaad_rep_code = 0;
    hap->dhaad_rep_cksum = 0;
    hap->dhaad_rep_id = msgid;
    len = sizeof (struct dhaad_rep);
    hagent_addr = (struct in6_addr *)(hap + 1);
    count = (IPV6_MMTU - sizeof (struct ip6_hdr) -
	     sizeof (struct dhaad_rep)) / sizeof (struct in6_addr);
    /* pick home agent global addresses for this home address */
     if ((nhaa = hal_pick(reqaddr, hagent_addr, &src, haif, count)) < 0) {
	syslog(LOG_ERR, __FUNCTION__ "cannot fild any home agents in home agent list.\n");
	goto err;
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&src))
	goto err;
    len += nhaa * sizeof (struct in6_addr);

    sndmhdr.msg_name = (caddr_t)coaddr;
    sndmhdr.msg_namelen = coaddr->sin6_len;
    sndmhdr.msg_iov[0].iov_base = (caddr_t)buf;
    sndmhdr.msg_iov[0].iov_len = len;

    cm = CMSG_FIRSTHDR(&sndmhdr);
    /* specify source address */
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    pi = (struct in6_pktinfo *)CMSG_DATA(cm);
    pi->ipi6_addr = src;
    pi->ipi6_ifindex = 0; /* determined with routeing table */

    if ((len = sendmsg(sock, &sndmhdr, 0)) < 0) {
	syslog(LOG_ERR, __FUNCTION__ "%s.\n", strerror(errno));
	goto err;
    }
err:
}

/* 
 * Receive Mobile Prefix Solicitation message
 */
void
mpi_solicit_input(pi, coaddr, mps)
    struct in6_pktinfo *pi;
    struct sockaddr_in6 *coaddr;
    struct mobile_prefix_solicit *mps; 
{   
    int ifga_index = -1;
    struct hagent_ifinfo *haif;
    struct in6_addr ha_addr;
    struct in6_addr hoaddr;
    struct in6_addr src;
    int error;
    
    ha_addr = pi->ipi6_addr;
    /* determine home link by global address */
    haif = haif_findwithunicast(&pi->ipi6_addr, &ifga_index);

    if (!haif) {
        syslog(LOG_ERR, __FUNCTION__ "cannot get home agent ifinfo.\n");
        goto err;
    }
	
    /* Pick Home Agent Address */
    /* 1. pick Home Address by using registerd Care-of Address */
    error = reg_hoa_pick(&coaddr->sin6_addr, &hoaddr);
    if (error) {
        bcopy(&ha_addr, &src, sizeof(struct in6_addr));
    } else {
        /* Home Address is found */
        /* 2. pick Home Agent address which registers Home Address */
        /* -- search the HA address whose prefix is same as HoA */
        if (ha_pick(&hoaddr, &src, haif)) {
            /* if HA is not found, copy the default address */
            bcopy(&ha_addr, &src, sizeof (struct in6_addr));
        }
    }
    mpi_advert_output(coaddr, &src, haif, mps->mp_sol_id);
err:
}

/* 
 * Send Mobile Prefix Advertisement message
 */
void
mpi_advert_output(coaddr, src, haif, id)
    struct sockaddr_in6 *coaddr;
    struct in6_addr *src;
    struct hagent_ifinfo *haif;
    u_int16_t id;
{   
    struct cmsghdr *cm;
    struct nd_opt_prefix_info *prefix_info;
    u_int8_t buf[IPV6_MMTU];
    struct mobile_prefix_advert *map;
    int len;
    int count;
    int npi;
    struct in6_pktinfo *pi;
    
    /* create ICMPv6 message */
    map = (struct mobile_prefix_advert *)buf;
    bzero(map, sizeof (struct mobile_prefix_advert));
    map->mp_adv_type = ICMP6_MOBILEPREFIX_ADVERT;
    map->mp_adv_code = 0;

    len = 4;
    prefix_info = (struct nd_opt_prefix_info *)&map[1];
    /* count number of prefix informations -- to make assurance (not in spec.) */
    count = (IPV6_MMTU - sizeof (struct ip6_hdr) -
			 sizeof (struct mobile_prefix_advert)) / sizeof (struct nd_opt_prefix_info);

    /* Pick home agent prefixes */
    /* -- search by dest. address instead of Home Address */
    if ((npi = pi_pick(src, prefix_info, haif, count)) < 0) {
        syslog(LOG_ERR, __FUNCTION__ "cannot fild any home agent prefixes in home agent list.\n");
        goto err;
    }
    
    if(!npi)
         return;
    
    len += npi * sizeof (struct nd_opt_prefix_info);

    map->mp_adv_cksum = 0;
    map->mp_adv_id = id;
    sndmhdr.msg_name = (caddr_t)coaddr;
    sndmhdr.msg_namelen = coaddr->sin6_len;
    sndmhdr.msg_iov[0].iov_base = (caddr_t)buf;
    sndmhdr.msg_iov[0].iov_len = len;

    cm = CMSG_FIRSTHDR(&sndmhdr);
    /* specify source address */
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    pi = (struct in6_pktinfo *)CMSG_DATA(cm);
    pi->ipi6_addr = *src;
    pi->ipi6_ifindex = 0; /* determined with routeing table */

    if ((len = sendmsg(sock, &sndmhdr, 0)) < 0) {
        syslog(LOG_ERR, __FUNCTION__ "%s.\n", strerror(errno));
        goto err;
    }
err:
}

/* 
 * Send Mobile Prefix Advertisement message to every addresses in the list 
 */
void
mpi_advert_output_All(addr_list, src, haif)
    struct sockin6_addr_list *addr_list;
    struct in6_addr *src;
    struct hagent_ifinfo *haif;
{
    struct sockin6_addr *addrp;
  
    for (addrp = LIST_FIRST(addr_list);
         addrp;
	 addrp = LIST_FIRST(addr_list)) {
	mpi_advert_output(&(addrp->addr), src, haif, 0/*XXX*/);
	LIST_REMOVE(addrp, sockin6_entry);
	free(addrp);
    }
}

/*
 * pick up prefixes for home agents on specified link and prefix
 */
int
pi_pick(home_addr, prefix_info, haif, count)
    struct in6_addr *home_addr;
    struct nd_opt_prefix_info *prefix_info;
    struct hagent_ifinfo *haif;
    int count;
{
    int naddr;
    struct hagent_entry *hap;
    struct hagent_gaddr *ha_gaddr;
    struct hagent_gaddr hagent_addr;
    struct nd_opt_prefix_info *h_prefix_info;
    struct timeval now;
    u_int32_t vltime, pltime;
	
    h_prefix_info = prefix_info;
    /* search home agent list and pick appropriate prefixes */
    for (naddr = 0, hap = &(haif->halist_pref);
         hap && naddr < count; hap = hap->hagent_next_pref) {
        ha_gaddr = hap->hagent_galist.hagent_next_gaddr;
        if (get_gaddr(ha_gaddr, home_addr, &hagent_addr))
            continue;
        /* duplication check whether MPA includes duplecated prefixes */
        if (prefix_dup_check(h_prefix_info, ha_gaddr, naddr))
            /* duplicated prefix is included */
            continue;

        /* make prefix information */
        prefix_info->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
        prefix_info->nd_opt_pi_len = 4;
        prefix_info->nd_opt_pi_prefix_len = hagent_addr.hagent_prefixlen;
        prefix_info->nd_opt_pi_flags_reserved = 0;

        if (hagent_addr.hagent_flags.onlink)
                prefix_info->nd_opt_pi_flags_reserved |=
                        ND_OPT_PI_FLAG_ONLINK;
        if (hagent_addr.hagent_flags.autonomous)
                prefix_info->nd_opt_pi_flags_reserved |=
                        ND_OPT_PI_FLAG_AUTO;
        if (hagent_addr.hagent_flags.router)
                prefix_info->nd_opt_pi_flags_reserved |=
                        ND_OPT_PI_FLAG_ROUTER;


        if (hagent_addr.hagent_vltime || hagent_addr.hagent_pltime)
                gettimeofday(&now, NULL);
        if (hagent_addr.hagent_vltime == 0)
                vltime = hagent_addr.hagent_expire;
        else
                vltime = (hagent_addr.hagent_expire > now.tv_sec) ?
                          hagent_addr.hagent_expire - now.tv_sec : 0;
        if (hagent_addr.hagent_pltime == 0)
                pltime = hagent_addr.hagent_preferred;
        else
                pltime = (hagent_addr.hagent_pltime > now.tv_sec) ? 
                        hagent_addr.hagent_pltime - now.tv_sec : 0;
        if (vltime < pltime) {
                /*
                 * this can happen if vltime is decrement but pltime
                 * is not.
                 */
                pltime = vltime;
        }
        prefix_info->nd_opt_pi_valid_time = htonl(vltime);
        prefix_info->nd_opt_pi_preferred_time = htonl(pltime);
        prefix_info->nd_opt_pi_reserved2 = 0;
        prefix_info->nd_opt_pi_prefix = hagent_addr.hagent_gaddr;

        prefix_info ++;
        naddr ++;
    }
    return naddr;
}

/*
 * pick up address for home agents whose prefix is same as HoA
 */
int
ha_pick(home_addr, src_addr, haif)
    struct in6_addr *home_addr;
    struct in6_addr *src_addr;
    struct hagent_ifinfo *haif;
{
    struct hagent_entry *hap;
    struct hagent_gaddr *ha_gaddr;
    struct hagent_gaddr hagent_addr;

    /* search home agent list and pick appropriate global addresses */
    for (hap = &(haif->halist_pref); hap; hap = hap->hagent_next_pref) {
        ha_gaddr = hap->hagent_galist.hagent_next_gaddr;
        if (!get_gaddr(ha_gaddr, home_addr, &hagent_addr)){
            /* found */
            *src_addr = hagent_addr.hagent_gaddr;
            return 0;
        }
    }
    /* not found */
    return -1;
}

/*
 * prefix duplication check
 */
int
prefix_dup_check(prefix_info, ha_gaddr, naddr)
    struct nd_opt_prefix_info *prefix_info;
    struct hagent_gaddr *ha_gaddr;
    int naddr;
{
    int i;
    for (i = 0; i < naddr; i++, prefix_info++){
      if(prefix_info->nd_opt_pi_prefix_len == ha_gaddr->hagent_prefixlen){
        struct in6_addr mask;
        create_mask(&mask, ha_gaddr->hagent_prefixlen);
        if (IN6_ARE_ADDR_MASKEQUAL(prefix_info->nd_opt_pi_prefix, mask, 
                                   ha_gaddr->hagent_gaddr))
            return -1;
      }
    }
    return 0;
}

/*
 * get registerd Home Address binding with given CoA
 */
int
reg_hoa_pick(coaddr, hoaddr)
    struct in6_addr *coaddr;
    struct in6_addr *hoaddr;
{
    struct mip6_bc *mbc, mip6_bc;
    struct mip6_bc_list mip6_bc_list;

    if (get_bc_list(&mip6_bc_list))
        return -1;
	
    for (mbc = LIST_FIRST(&mip6_bc_list);
         mbc;
         mbc = LIST_NEXT(mbc, mbc_entry)) {
        if (KREAD(mbc, &mip6_bc, mip6_bc)) {
            return (-1);
	}
        mbc = &mip6_bc;
        if (IN6_ARE_ADDR_EQUAL(&(mbc->mbc_pcoa.sin6_addr), coaddr))
            break;
    }
    
    if (!mbc)
        return -1;

    bcopy(&(mbc->mbc_phaddr.sin6_addr), hoaddr, sizeof (struct in6_addr));
    
    return 0;
}

/*
 * get registerd Care-of Address binding with given HA's prefix
 */
int
reg_coa_pick(addr_list)
    struct sockin6_addr_list *addr_list;
{
    struct mip6_bc *mbc, mip6_bc;
    struct mip6_bc_list mip6_bc_list;
    
    if (get_bc_list(&mip6_bc_list))
	 return -1;
    
    for (mbc = LIST_FIRST(&mip6_bc_list);
         mbc;
         mbc = LIST_NEXT(mbc, mbc_entry)) {
        if (KREAD(mbc, &mip6_bc, mip6_bc))
            return (-1);
        mbc = &mip6_bc;
        if (mbc->mbc_flags & IP6MU_HOME) {
            int dup = 0;
            struct sockin6_addr *addrp;

            for (addrp = LIST_FIRST(addr_list);
                 addrp;
                 addrp = LIST_NEXT(addrp, sockin6_entry)) {
			if (IN6_ARE_ADDR_EQUAL(&(mbc->mbc_pcoa.sin6_addr), &(addrp->addr.sin6_addr))) {
				dup = -1;
				break;
			}
	    }
            
            if(!dup) {
                struct sockin6_addr *nmbc;

		nmbc = (struct sockin6_addr *)malloc(sizeof(struct sockin6_addr *));
		if (nmbc == NULL) {
			perror("reg_coa_pick():malloc");
		}
                bcopy(&(mbc->mbc_pcoa), &(nmbc->addr), sizeof(struct sockaddr_in6));
		LIST_INSERT_HEAD(addr_list, nmbc, sockin6_entry);
            }			  
        }
    }
    
    return 0;
}

/*
 * get binding cache entries
 */
int
get_bc_list(mip6_bc_list)
    struct mip6_bc_list *mip6_bc_list;
{
    if (kvm_nlist(kvmd, nl) < 0) {
        fprintf(stderr, "no namelist\n");
        goto err;
    }

    if (nl[N_MIP6_BC_LIST].n_value == 0) {
        fprintf(stderr, "bc not found\n");
        goto err;
    }

    return (KREAD(nl[N_MIP6_BC_LIST].n_value, mip6_bc_list, &mip6_bc_list));

err:
    return -1;
}


int
kread(addr, buf, size)
    u_long addr;
    void *buf;
    int size;
{
    if (kvm_read(kvmd, addr, buf, size) != size) {
        fprintf(stderr, "%s\n", kvm_geterr(kvmd));
        return -1;
    }

    return 0;
}
