/*	$KAME: mnd.c,v 1.48 2007/02/06 05:56:42 t-momose Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <poll.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <ifaddrs.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <net/route.h>
#include <net/mipsock.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip6mh.h>
#include <netinet/icmp6.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/mip6.h>
#include <arpa/inet.h>

#include "callout.h"
#include "stat.h"
#include "shisad.h"
#include "fsm.h"
#include "fdlist.h"
#include "command.h"
#include "config.h"

/* Global Variables */
int mipsock, icmp6sock, mhsock, csock;
#ifdef DSMIP
int udp4sock;
#endif /* DSMIP */
struct mip6_mipif_list mipifhead;
struct mip6_hinfo_list hoa_head;
struct no_ro_head noro_head;
struct mip6stat mip6stat;

/* configuration parameters */
int debug = 0;
int foreground = 0;
int namelookup = 1;
int command_port = MND_COMMAND_PORT;
int mobileroutersupport = 0;
int default_lifetime = MIP6_DEFAULT_BINDING_LIFE;
int keymanagement = 0;
#ifdef MIP_IPV4MNPSUPPORT
int ipv4mnpsupport = 0;
#endif /* MIP_IPV4MNPSUPPORT */
struct config_entry *if_params;

int main(int, char **);

/*static void command_show_status(int, char *);*/
static void command_flush(int, char *);
static void command_show_hal(int, char *);
static void show_current_config(int, char *);

static void mn_usage(void);
static void mn_lists_init(void);
static int mipsock_recv_rr_hint(struct mip_msghdr *);
static void mnd_init_homeprefix(struct mip6_mipif *);
int  mip6_icmp6_create_haanyaddr(struct in6_addr *, struct in6_addr *, int);
static struct mip6_mipif *mnd_add_mipif(char *);
static void terminate(int);
static int mipsock_md_dereg_bul_fl(struct in6_addr *, struct in6_addr *, 
    struct in6_addr *, u_int16_t, u_int16_t);

static struct in6_addr *get_hoa_from_ifindex(u_int16_t);
static int add_hal_by_commandline_xxx(char *);

static void noro_init(void);
static void noro_show(int, char *);
static void noro_sync(void);
static void command_add_noro(int, char *);

static void config_lifetime(int, char *);

struct command_table show_command_table[] = {
	{"bul", command_show_bul, "Binding Update List in Shisa"},
	{"kbul", command_show_kbul, "Binding Update List in kernel"},
	{"hal", command_show_hal, "Home Agent List"},
	{"stat", command_show_stat, "statistics"},
	{"noro", noro_show, "Nodes that have no capability of routing optimization"},
	{"config", show_current_config, "Current configuration"},
	{"callout", show_callout_table, "the list in the callout queue"},
	{"pt", command_show_pt, "Prefix Table, MR only"},
	{NULL}	/* The last {NULL} is needed for the sub command table */
};

struct command_table add_command_table[] = {
	{"noro", command_add_noro, ""},
	{NULL}	/* The last {NULL} is needed for the sub command table */
};

struct command_table config_command_table[] = {
	{"lifetime", config_lifetime, "Change the value of default Binding lifetime"},
	{NULL}	/* The last {NULL} is needed for the sub command table */
};

struct command_table command_table[] = {
	{"show", NULL, "Show stat, bul, hal, kbul, noro, config"
	 ", pt"
	 , show_command_table
	},
	{"add", NULL, "add ", add_command_table},
	{"config", NULL, "Configuration parameters", config_command_table},
	{"flush", command_flush, "Flush stat, bul, hal, noro"},
};

static void
mn_usage()
{
	char *banner = "mnd [-fn] [-c configfile] mipinterface\n";

	fprintf(stderr, banner);
	fprintf(stderr, "Basic NEMO Support version\n");
#ifdef MIP_MCOA
	fprintf(stderr, "Multiple CoA Reg Support version\n");
#endif /* MIP_MCOA */
        return;
}


int
main(argc, argv)
	int argc;
	char **argv;
{
	int pfds, ch = 0;
	FILE *pidfp;
	struct mip6_hoainfo *hoainfo = NULL;
	struct binding_update_list *bul;
	u_int16_t bul_flags;
	char *homeagent = NULL;
#ifdef DSMIP
	char *v4homeagent = NULL;
#endif /* DSMIP */
	char *argopts = "fnc:a:";
	char *conffile = MND_CONFFILE;
	struct config_entry *dummy;

#if 1 /* MIP_NEMO */
	argopts = "fnc:a:t:";
#endif /* MIP_NEMO */
#ifdef DSMIP
	argopts = "fnc:a:t:A:";
#endif /* DSMIP */

        while ((ch = getopt(argc, argv, argopts)) != -1) {
                switch (ch) {
                case 'f':
                        foreground = 1;
                        break;
                case 'n':
                        namelookup = 0;
                        break;
		case 'c':
			conffile = optarg;
			break;
		case 'a':
			homeagent = optarg;
			break;
#ifdef DSMIP
		case 'A':
			v4homeagent = optarg;
			break;
#endif /* DSMIP */
                default:
                        fprintf(stderr, "unknown option\n");
                        mn_usage();
                        break;
                }
        }
	argc -= optind;
	argv += optind;

	if (argv == NULL || *argv == NULL) {
		mn_usage();
		exit(-1);
	}
	
	/* open syslog infomation. */
#if 0 /* MIP_NEMO */
	openlog("shisad(mrd)", 0, LOG_DAEMON);
	syslog(LOG_INFO, "Start Mobile Router");
#else
	openlog("shisad(mnd)", 0, LOG_DAEMON);
	syslog(LOG_INFO, "Start Mobile Node");
#endif

	/* parse configuration file and set default values. */
	if (parse_config(
#if 1 /* MIP_NEMO */
	    CFM_MRD, 
#else
	    CFM_MND,
#endif
	    conffile) == 0) {
		config_get_interface(*argv, &if_params,
		    config_params);
	}
	if (if_params != NULL) {
		/* get interface specific parameters. */
		config_get_number(CFT_DEBUG, &debug, if_params);
		config_get_number(CFT_COMMANDPORT, &command_port,
		    if_params);
		if (config_get_prefixtable(&dummy, if_params) == 0)
			mobileroutersupport = 1;
		config_get_number(CFT_HOMEREGISTRATIONLIFETIME,
		    &default_lifetime, if_params);
		config_get_number(CFT_KEYMANAGEMENT,
		    &keymanagement, if_params);
#ifdef MIP_IPV4MNPSUPPORT
		config_get_number(CFT_IPV4MNPSUPPORT,
		    &ipv4mnpsupport, if_params);
#endif /* MIP_IPV4MNPSUPPORT */
	}
	if (config_params != NULL) {
		/* get global parameters. */
		config_get_number(CFT_DEBUG, &debug, config_params);
		config_get_number(CFT_COMMANDPORT, &command_port,
		    config_params);
		if (config_get_prefixtable(&dummy, if_params) == 0)
			mobileroutersupport = 1;
		config_get_number(CFT_HOMEREGISTRATIONLIFETIME,
		    &default_lifetime, config_params);
		config_get_number(CFT_KEYMANAGEMENT,
		    &keymanagement, config_params);
#ifdef MIP_IPV4MNPSUPPORT
		config_get_number(CFT_IPV4MNPSUPPORT,
		    &ipv4mnpsupport, config_params);
#endif /* MIP_IPV4MNPSUPPORT */
	}

	kernel_debug(debug);

	mhsock_open();
	icmp6sock_open();
	mipsock_open();
#ifdef DSMIP
	udp4sock_open();
#endif /* DSMIP */

	mn_lists_init();

	noro_init();

	shisad_callout_init();
	fdlist_init();
	csock = command_init("mn> ", command_table, 
	    sizeof(command_table) / sizeof(struct command_table),
	    command_port, if_params);
	if (csock < 0) {
		fprintf(stderr, "Unable to open user interface\n");
	}

	/* Initialization of mip virtual interfaces, home address and
	 * binding update list */
	if (mnd_add_mipif(*argv) == NULL) {
		syslog(LOG_ERR, "interface %s is invalid.", *argv);
		exit(-1);
	}

#if 1 /* MIP_NEMO */
	if (mobileroutersupport)
		nemo_parse_conf();
#endif /* MIP_NEMO */

#if 1
	/* ETSI 2004.10.12 XXX */
	/* install a home agent address, if specified. */
#ifdef DSMIP
	if (v4homeagent != NULL)
		add_hal_by_commandline_xxx(v4homeagent);
#endif /* DSMIP */
	if (homeagent != NULL)
		add_hal_by_commandline_xxx(homeagent);
#endif

	/* let's insert NULL binding update list to each binding update list */
	for (hoainfo = LIST_FIRST(&hoa_head); hoainfo;
	     hoainfo = LIST_NEXT(hoainfo, hinfo_entry)) {
		bul_flags = IP6_MH_BU_HOME|IP6_MH_BU_ACK
#if 1 /* MIP_NEMO */
		    | (mobileroutersupport ? IP6_MH_BU_ROUTER : 0)
#endif
#ifdef MIP_MCOA 
		    | IP6_MH_BU_MCOA
#endif
		    ;
		if (keymanagement)
			bul_flags |= IP6_MH_BU_KEYM;

		/*
		 * RFC3375 Sec. 11.7.1. 
		 * if the mobile node's link-local address has the same
		 * interface identifier as the home address for which it is 
		 * supplying a new care-of address, then the mobile node
		 * SHOULD set the L bit. 
		 */
		if (bul_check_ifid(hoainfo))
			bul_flags |= IP6_MH_BU_LLOCAL;

		bul = bul_insert(hoainfo, NULL, NULL, bul_flags, 0);
		if (bul == NULL) {
			syslog(LOG_ERR,
			    "cannot insert bul, something wrong");
			 continue;
		}
		/* The HoA is registered as a no RO host */
		noro_add(&hoainfo->hinfo_hoa);

		syslog(LOG_INFO, "Kick fsm to MOVEMENT");
		/* kick the fsm to start its state transition. */
		bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_MOVEMENT, NULL);
	}

	new_fd_list(mipsock, POLLIN, mipsock_input_common);
	new_fd_list(mhsock, POLLIN, mh_input_common);
	new_fd_list(icmp6sock, POLLIN, icmp6_input_common);
#ifdef DSMIP
	new_fd_list(udp4sock, POLLIN, udp4_input_common);
#endif /* DSMIP */

	/* notify a kernel to behave as a mobile node. */
	mipsock_nodetype_request(mobileroutersupport ?
				 MIP6_NODETYPE_MOBILE_ROUTER : MIP6_NODETYPE_MOBILE_NODE, 1);

	/* register signal handlers. */
	signal(SIGTERM, terminate);
	signal(SIGINT, terminate);

	if (foreground == 0)
		daemon(0, 0);

	/* dump current PID */
	if ((pidfp = fopen(
#ifdef MIP6_NEMO
		         MRD_PIDFILE,
#else
		         MND_PIDFILE,
#endif
			 "w")) != NULL) {
		fprintf(pidfp, "%d\n", getpid());
		fclose(pidfp);
	}

	/* main loop. */
	while (1) {
		clear_revents();
	    
		if ((pfds = poll(fdl_fds, fdl_nfds, get_next_timeout())) < 0) {
			perror("poll");
			continue;
		}
		if (pfds != 0) {
			dispatch_fdfunctions(fdl_fds, fdl_nfds);
		}
		/* Timeout */
		callout_expire_check();
	}

	/* not reach */
	return (0);
}


static void
mn_lists_init()
{
	LIST_INIT(&hoa_head);
	LIST_INIT(&mipifhead);
	LIST_INIT(&noro_head);
}


/* mipsock BUL add and delete functions */
int
mipsock_bul_request(bul, command)
	struct binding_update_list *bul;
	u_char command;
{
	char buf[1024];
	int err = 0;
	struct mipm_bul_info *buinfo;
	struct sockaddr_in6 hoa_s6, coa_s6, peer_s6;

	if (command != MIPM_BUL_ADD &&
	    command != MIPM_BUL_REMOVE) {
		syslog(LOG_ERR, "mipsock_bul_request: "
		    "invalid command %d", command);
		return (EOPNOTSUPP);
	}

	if (bul->bul_hoainfo == NULL) {
		syslog(LOG_ERR, "mipsock_bul_request: "
		    "no related home address info");
		return (EINVAL);
	}

	memset(&hoa_s6, 0, sizeof(hoa_s6));
	memset(&coa_s6, 0, sizeof(coa_s6));
	memset(&peer_s6, 0, sizeof(peer_s6));

	hoa_s6.sin6_len = coa_s6.sin6_len = 
		peer_s6.sin6_len = sizeof(struct sockaddr_in6);
	hoa_s6.sin6_family = coa_s6.sin6_family =
		peer_s6.sin6_family = AF_INET6;
	
	hoa_s6.sin6_addr = bul->bul_hoainfo->hinfo_hoa;
	coa_s6.sin6_addr = bul->bul_coa;
	peer_s6.sin6_addr = bul->bul_peeraddr;

	memset(buf, 0, sizeof(buf));
	buinfo = (struct mipm_bul_info *)buf;

	buinfo->mipmui_msglen = 
		sizeof(struct mipm_bul_info) + sizeof(struct sockaddr_in6) * 3;
	buinfo->mipmui_version = MIP_VERSION;
	buinfo->mipmui_type = command;
	buinfo->mipmui_seq = random();
	buinfo->mipmui_flags = bul->bul_flags;
	buinfo->mipmui_hoa_ifindex = bul->bul_hoainfo->hinfo_ifindex;
#ifdef MIP_MCOA
	coa_s6.sin6_port = bul->bul_bid;
#endif /* MIP_MCOA */
	buinfo->mipmui_state = bul->bul_state;
	memcpy(MIPU_HOA(buinfo), &hoa_s6, hoa_s6.sin6_len);
	memcpy(MIPU_COA(buinfo), &coa_s6, coa_s6.sin6_len);
	memcpy(MIPU_PEERADDR(buinfo), &peer_s6, peer_s6.sin6_len);

 	err = write(mipsock, buinfo, buinfo->mipmui_msglen);
	
	return (0);
}

int
mipsock_recv_mdinfo(miphdr)
	struct mip_msghdr *miphdr;
{
	struct mipm_md_info *mdinfo;
	struct in6_addr hoa, coa, acoa;
	int err = 0;
	u_int16_t bid = 0;
	struct mipm_dad mipmdad;
	
	syslog(LOG_INFO, "mipsock_recv_mdinfo");

	mdinfo = (struct mipm_md_info *)miphdr;

	/* Get HoA (if ifindex is specified, HoA could be :: */
	if (MIPD_HOA(mdinfo)->sa_family != AF_INET6)
		return (0);
	memcpy(&hoa, &((struct sockaddr_in6 *)MIPD_HOA(mdinfo))->sin6_addr,
	       sizeof(struct in6_addr));

	/* Get CoA */
#ifdef DSMIP
	switch (MIPD_COA(mdinfo)->sa_family) {
	case AF_INET:
		/* put IPv4 address into IPv6 address (mapped address) */
		memset(&coa, 0, sizeof(struct in6_addr));
		coa.s6_addr[10] = 0xff;
		coa.s6_addr[11] = 0xff;
		memcpy(&coa.s6_addr[12],
			&((struct sockaddr_in *)MIPD_COA(mdinfo))->sin_addr,
			sizeof(struct in_addr));

		/* XXX maybe we need more check */

		if (debug) 
			syslog(LOG_INFO, "new coa is %s", ip6_sprintf(&coa));
		break;
	case AF_INET6:
		memcpy(&coa, &((struct sockaddr_in6 *)MIPD_COA(mdinfo))->sin6_addr, sizeof(struct in6_addr));

		if (MIPD_COA(mdinfo)->sa_family != AF_INET6)
			return (0);
		memcpy(&coa, &((struct sockaddr_in6 *)MIPD_COA(mdinfo))->sin6_addr,
			sizeof(struct in6_addr));

		/* If new CoA is not global, ignore */
		if (IN6_IS_ADDR_LINKLOCAL(&coa)
			|| IN6_IS_ADDR_MULTICAST(&coa)
			|| IN6_IS_ADDR_LOOPBACK(&coa)
			|| IN6_IS_ADDR_V4MAPPED(&coa)
			|| IN6_IS_ADDR_UNSPECIFIED(&coa))
			return (EINVAL);

		if (debug) 
			syslog(LOG_INFO, "new coa is %s", ip6_sprintf(&coa));
		break;
	default:
		return(0);
	}
#else
	if (MIPD_COA(mdinfo)->sa_family != AF_INET6)
		return (0);
	memcpy(&coa, &((struct sockaddr_in6 *)MIPD_COA(mdinfo))->sin6_addr,
	       sizeof(struct in6_addr));

	/* If new CoA is not global, ignore */
	if (IN6_IS_ADDR_LINKLOCAL(&coa)
	    || IN6_IS_ADDR_MULTICAST(&coa)
	    || IN6_IS_ADDR_LOOPBACK(&coa)
	    || IN6_IS_ADDR_V4MAPPED(&coa)
	    || IN6_IS_ADDR_UNSPECIFIED(&coa))
		return (EINVAL);

	if (debug) 
		syslog(LOG_INFO, "new coa is %s", ip6_sprintf(&coa));
#endif /* DSMIP */

#ifdef MIP_MCOA
	memcpy(&bid, &((struct sockaddr_in6 *)MIPD_COA(mdinfo))->sin6_port, sizeof(bid));
#endif /* MIP_MCOA */
	/* Update bul according to md_hint */
	switch (mdinfo->mipmmi_command) {
	case MIPM_MD_REREG:
		/* XXX do we need MIPM_MD_INDEX?! */
		if (mdinfo->mipmmi_hint == MIPM_MD_INDEX)
			err = mipsock_md_update_bul_byifindex(mdinfo->mipmmi_ifindex, &coa);
		else if (mdinfo->mipmmi_hint == MIPM_MD_ADDR) {
			err = bul_update_by_mipsock_w_hoa(&hoa, &coa, bid);
		
			/*
			 * do DAD for link local address
			 */
			if (mdinfo->mipmmi_ifindex <= 0)
				syslog(LOG_ERR,
					"ifindex is not set by (baby)mdd");
			else {
				/* write DAD requrest for link local addr */
				mipmdad.mipmdad_msglen = sizeof(mipmdad);
				mipmdad.mipmdad_version = MIP_VERSION;
				mipmdad.mipmdad_type = MIPM_DAD;
				mipmdad.mipmdad_seq = random();
				mipmdad.mipmdad_message = MIPM_DAD_LINKLOCAL;
				mipmdad.mipmdad_ifindex = 
							mdinfo->mipmmi_ifindex;
				mipmdad.mipmdad_addr6 = coa;
				if (write(mipsock, &mipmdad, sizeof(mipmdad))
					== -1)
					syslog(LOG_ERR, "failed to request DAD"
						    " for link local addr");
			}
		}
		break;
	case MIPM_MD_DEREGHOME:
		err = mipsock_md_dereg_bul(&hoa, &coa, mdinfo->mipmmi_ifindex);
		break;
	case MIPM_MD_DEREGFOREIGN:
		/* Get CoA to send de-reg BU */
		if (MIPD_COA2(mdinfo)->sa_family != AF_INET6)
			return (0);
		memcpy(&acoa, &((struct sockaddr_in6 *)MIPD_COA2(mdinfo))->sin6_addr, sizeof(struct in6_addr));

		err = mipsock_md_dereg_bul_fl(&hoa, &coa, &acoa, 
					      mdinfo->mipmmi_ifindex, bid);
		break;
	default:
		syslog(LOG_ERR, "unsupported md_info command %d",
		    mdinfo->mipmmi_command);
		err = EOPNOTSUPP;
		break;
	}

	return (err);
}

int
mipsock_md_update_bul_byifindex(ifindex, coa)
	u_int16_t ifindex;
	struct in6_addr *coa;
{
	syslog(LOG_ERR,
	       "mipsock_md_update_bul_byifindex is not supported yet");
	return (0);
}

/* DE-REGISTRATION (i.e. FL to HL movement only) */
int
mipsock_md_dereg_bul(hoa, coa, ifindex)
	struct in6_addr *hoa, *coa;
	u_int16_t ifindex;
{

	struct mip6_hoainfo *hoainfo;
	struct binding_update_list *bul, *bul_next;
	char ifname[IFNAMSIZ], mipifname[IFNAMSIZ];
	int err = 0;

	hoainfo = hoainfo_find_withhoa(hoa);
	if (hoainfo == NULL)
		return (ENETDOWN);

	if (!IN6_ARE_ADDR_EQUAL(hoa, coa)) 
		return (EINVAL);

	/* Remove HoA from viturla interface */
	if (if_indextoname(hoainfo->hinfo_ifindex, mipifname) == NULL) 
		return (EINVAL);
	err = delete_ip6addr(mipifname, &hoainfo->hinfo_hoa, 64);
	if (err) {
		syslog(LOG_ERR,
		    "removing a home address (%s) from %s failed.",
		    ip6_sprintf(&hoainfo->hinfo_hoa), mipifname);
		return (err);
	}

	/*
	 * add a home address to the physical interface specified by
	 * the movement detector.
	 */
	if (if_indextoname(ifindex, ifname) == NULL) 
		return (EINVAL);
#if 1
	/* ETSI 2004.10.13 */
{
	int flags = 0;

	bul = bul_get_homeflag(&hoainfo->hinfo_hoa);
	if (bul == NULL) {
		syslog(LOG_ERR, "mipsock_md_dereg_bul: "
		    "received home hint, but there is no bul for %s",
		    ip6_sprintf(&hoainfo->hinfo_hoa));
		return (-1);
	}
	if (bul->bul_flags & IP6_MH_BU_HOME) {
		if ((bul->bul_reg_fsm_state == MIP6_BUL_REG_FSM_STATE_WAITAR) ||
			(bul->bul_reg_fsm_state == MIP6_BUL_REG_FSM_STATE_BOUND)) {
			flags = IN6_IFF_NODAD|IN6_IFF_HOME|IN6_IFF_DEREGISTERING;
		} else  
			/* 
			 * if the home agent doesn't have a bc for the HoA, it
			 *  should operate DAD for the HoA 
			 */
			flags = IN6_IFF_HOME;
	}
	
	err = set_ip6addr(ifname, &hoainfo->hinfo_hoa, 64, flags);
}
#else
	err = set_ip6addr(ifname, &hoainfo->hinfo_hoa, 64,
	    IN6_IFF_NODAD|IN6_IFF_HOME|IN6_IFF_DEREGISTERING);
#endif
	if (err) {
		syslog(LOG_ERR,
		    "assigning a home address (%s) to %s failed.",
		    ip6_sprintf(&hoainfo->hinfo_hoa), ifname);
		return (err);
	}

	/* set HOME as mn's location */
	hoainfo->hinfo_location = MNINFO_MN_HOME;

	if (LIST_EMPTY(&hoainfo->hinfo_bul_head))
		return (ENOENT);

	for (bul = LIST_FIRST(&hoainfo->hinfo_bul_head); bul;
		bul = bul_next) {
		bul_next = LIST_NEXT(bul, bul_entry);

		bul->bul_coa = *coa;
		bul->bul_lifetime = 0;
		bul->bul_home_ifindex = ifindex;
		/* send de-registration */
		syslog(LOG_INFO, 
		       "change fsm MIP6_BUL_FSM_EVENT_RETURNING_HOME to %s",
		       ifname);

		if (bul_kick_fsm(bul,  MIP6_BUL_FSM_EVENT_RETURNING_HOME, NULL) == -1) {
			syslog(LOG_ERR, 
			       "fsm processing of movement detection failed.");
		}
	}

	return (0);
}

/* DE-REGISTRATION from FL  */
static int
mipsock_md_dereg_bul_fl(hoa, oldcoa, newcoa, ifindex, bid)
	struct in6_addr *hoa, *oldcoa, *newcoa;
	u_int16_t ifindex, bid;
{
	struct mip6_hoainfo *hoainfo;
	struct binding_update_list *bul, *bul_next;
#ifdef MIP_MCOA
	struct binding_update_list *mbul = NULL;
#endif /* MIP_MCOA */
	char ifname[IFNAMSIZ];

	hoainfo = hoainfo_find_withhoa(hoa);
	if (hoainfo == NULL)
		return (ENETDOWN);

	if (if_indextoname(ifindex, ifname) == NULL) 
		return (EINVAL);

	for (bul = LIST_FIRST(&hoainfo->hinfo_bul_head); bul; bul = bul_next) {
		bul_next = LIST_NEXT(bul, bul_entry);
#ifdef MIP_MCOA
		/* update bul that matched with the bid */
		if (bid && !LIST_EMPTY(&bul->bul_mcoa_head)) {
			for (mbul = LIST_FIRST(&bul->bul_mcoa_head); mbul;
			     mbul = LIST_NEXT(mbul, bul_entry)) {
				
				if (IN6_ARE_ADDR_EQUAL(&mbul->bul_coa, oldcoa) &&
				    mbul->bul_bid == bid) 
					break;
			}
		}

		/* send de-registration */
		if (bid) {
			if (mbul) {
				mbul->bul_coa = *newcoa;
				mbul->bul_lifetime = 0;
				mbul->bul_home_ifindex = ifindex;
				syslog(LOG_INFO, 
				       "change fsm MIP6_BUL_FSM_EVENT_RETURNING_HOME to %s bid = %d",
				       ifname, bid);

				if (bul_kick_fsm(mbul, 
						 MIP6_BUL_FSM_EVENT_RETURNING_HOME, NULL) == -1) {
					syslog(LOG_ERR, 
					       "fsm processing of movement detection failed.");
				}
			}
			continue;
		} else {  
#endif /* MIP_MCOA */
		if (!IN6_ARE_ADDR_EQUAL(&bul->bul_coa, oldcoa))
			continue;
#ifdef MIP_MCOA
		}
#endif /* MIP_MCOA */

		bul->bul_coa = *newcoa;
		bul->bul_lifetime = 0;
		bul->bul_home_ifindex = ifindex;

		/* send de-registration */
		syslog(LOG_INFO, 
		       "change fsm MIP6_BUL_FSM_EVENT_RETURNING_HOME to %s",
		       ifname);

		if (bul_kick_fsm(bul,  MIP6_BUL_FSM_EVENT_RETURNING_HOME, NULL) == -1) {
			syslog(LOG_ERR, 
			       "fsm processing of movement detection failed.");
		}
	}

	return (0);
}



/* re-registration. */
int 
bul_update_by_mipsock_w_hoa(hoa, coa, bid)
	struct in6_addr *hoa, *coa;
	u_int16_t bid;
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr *sa;
	char mipname[IFNAMSIZ];
	struct mip6_hoainfo *hoainfo;
	struct binding_update_list *bul;
#ifdef MIP_MCOA
	struct binding_update_list *mbul;
#endif /* MIP_MCOA */

	hoainfo = hoainfo_find_withhoa(hoa);
	if (hoainfo == NULL)
		return (ENETDOWN);

	if (LIST_EMPTY(&hoainfo->hinfo_bul_head))
		return (ENOENT);

	if (getifaddrs(&ifap) != 0) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return (-1);
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		sa = ifa->ifa_addr;
		
		if (sa->sa_family != AF_INET6)
			continue;

		if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
				       hoa)) {

			if (if_nametoindex(ifa->ifa_name) != hoainfo->hinfo_ifindex) {

				/* move a home address to a virtual i/f. */
				if (delete_ip6addr(ifa->ifa_name, hoa, 64 /* XXX */)) {
					syslog(LOG_ERR,
					    "removing a home address "
					    "from a physical i/f failed.");
					freeifaddrs(ifap);
					return (-1);
				}

				if (set_ip6addr(if_indextoname(hoainfo->hinfo_ifindex, 
					mipname), hoa, 64 /* XXX */,
					IN6_IFF_NODAD|IN6_IFF_HOME)) {

					syslog(LOG_ERR,
					    "adding a home address "
					    "to a mip virtual i/f failed.");
					/* XXX recover the old phy addr. */
					freeifaddrs(ifap);
					return (-1);
				}

				/* set FOREIGN as a mobile node's location. */
				hoainfo->hinfo_location = MNINFO_MN_FOREIGN;
			}
		}
	}
	freeifaddrs(ifap);

#ifdef MIP_MCOA
        /* for bootstrap */
	if (bid) {
		bul = bul_get_homeflag(&hoainfo->hinfo_hoa);
		if (bul) {
			mbul = bul_mcoa_get(&hoainfo->hinfo_hoa, &bul->bul_peeraddr, bid);
			if (mbul == NULL) {
				mbul = bul_insert(hoainfo, &bul->bul_peeraddr, 
					   coa, bul->bul_flags, bid);

				mbul->bul_lifetime
					= set_default_bu_lifetime(bul->bul_hoainfo);
				mbul->bul_reg_fsm_state = bul->bul_reg_fsm_state;
			} 
		} else 
			syslog(LOG_INFO," bul unknown with %d", bid);
	};
#endif /* MIP_MCOA */

	/* update bul */
	for (bul = LIST_FIRST(&hoainfo->hinfo_bul_head); bul;
		bul = LIST_NEXT(bul, bul_entry)) {
		/* update CoA */
		memcpy(&bul->bul_coa, coa, sizeof(*coa));

		if (bid <= 0) {
			syslog(LOG_INFO,
			    "change fsm (%p) MIP6_BUL_FSM_EVENT_MOVEMENT",
			    bul);
			if (bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_MOVEMENT,
			    NULL) == -1) {
				syslog(LOG_ERR, 
				    "fsm processing of movement detection "
				    "failed.");
			}
		}
#ifdef MIP_MCOA
		else {
			/* update bul that matched with the bid */
			for (mbul = LIST_FIRST(&bul->bul_mcoa_head); mbul;
			     mbul = LIST_NEXT(mbul, bul_entry)) {
	
				if (mbul->bul_bid == bid) {
					/* update CoA */
					memcpy(&mbul->bul_coa, coa,
					    sizeof(*coa));

					syslog(LOG_INFO, "change fsm (%p, bid = %d) MIP6_BUL_FSM_EVENT_MOVEMENT", mbul, bid);
					if (bul_kick_fsm(mbul,
					    MIP6_BUL_FSM_EVENT_MOVEMENT,
					    NULL) == -1) {
						syslog(LOG_ERR, 
						       "fsm processing of movement detection "
						       "failed.");
					}
				}
			}
		}
#endif /* MIP_MCOA */
	}

	return (0);
}

static int
mipsock_recv_rr_hint(miphdr)
	struct mip_msghdr *miphdr;
{
	struct mipm_rr_hint *rr_hint;
	struct sockaddr_in6 *sin6;
	struct fsm_message fsmmsg;
	struct binding_update_list *bulhome = NULL, *bul;
	struct mip6_hoainfo *hoainfo = NULL;
	int error = -1;

	rr_hint = (struct mipm_rr_hint *)miphdr;

	bzero(&fsmmsg, sizeof(struct fsm_message));

	if (MIPMRH_HOA(rr_hint)->sa_family != AF_INET6)
		return (-1);
	sin6 = (struct sockaddr_in6 *)MIPMRH_HOA(rr_hint);
	fsmmsg.fsmm_dst = &sin6->sin6_addr;

	if (MIPMRH_PEERADDR(rr_hint)->sa_family != AF_INET6)
		return (-1);
	sin6 = (struct sockaddr_in6 *)MIPMRH_PEERADDR(rr_hint);
	fsmmsg.fsmm_src = &sin6->sin6_addr;

	/* if the destination address is listed in NoRO list, just ignore */
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
	    noro_get(&sin6->sin6_addr)) {
		syslog(LOG_INFO, 
		       "MN cannot start RO for %s",
		       ip6_sprintf(&sin6->sin6_addr));
		return (0);		
	}

	bul = bul_get(fsmmsg.fsmm_dst, fsmmsg.fsmm_src);
	if (bul == NULL) {
		hoainfo = hoainfo_find_withhoa(fsmmsg.fsmm_dst);
		if (hoainfo == NULL)
			return (-1);
		bulhome = bul_get_homeflag(&hoainfo->hinfo_hoa);
		if (bulhome == NULL)
			return (-1);

		bul = bul_insert(hoainfo, fsmmsg.fsmm_src, 
				 &bulhome->bul_coa, 0, 0);
		if (bul == NULL)
			return (-1);
		bul->bul_lifetime = bulhome->bul_lifetime; /* XXX */
	}

#ifndef MIP_MCOA
	error = bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_REVERSE_PACKET, &fsmmsg);
	if (error == -1) {
		syslog(LOG_ERR, "fsm processing failed.");
	}
#else
	{
		struct binding_update_list *mbul, *mbuln, *newbul;

		bulhome = bul_get_homeflag(&hoainfo->hinfo_hoa);
		if (bulhome == NULL)
			return (-1);
		
		if (LIST_EMPTY(&bulhome->bul_mcoa_head)) {
			error = bul_kick_fsm(bul, 
			     MIP6_BUL_FSM_EVENT_REVERSE_PACKET, &fsmmsg);
			if (error == -1) {
				syslog(LOG_ERR, "fsm processing failed.");
			}
		}

		for (mbul = LIST_FIRST(&bulhome->bul_mcoa_head); mbul;
		     mbul = mbuln) {
			mbuln = LIST_NEXT(mbul, bul_entry);
			
			newbul = bul_insert(hoainfo, fsmmsg.fsmm_src, 
				    &mbul->bul_coa, 0, mbul->bul_bid);
			if (newbul == NULL)
				continue;

			error = bul_kick_fsm(newbul, 
				     MIP6_BUL_FSM_EVENT_REVERSE_PACKET, &fsmmsg);
			if (error == -1) {
				syslog(LOG_ERR, "fsm processing failed.");
			}
		}
	}
#endif /* MIP_MCOA */

	return (error);
}

int
mipsock_input(miphdr)
	struct mip_msghdr *miphdr;
{
	int err = 0;

	switch (miphdr->miph_type) {
	case MIPM_BC_ADD:
	/*case MIPM_BC_UPDATE:*/
	case MIPM_BC_REMOVE:
	case MIPM_BUL_ADD:
	/*case MIPM_BUL_UPDATE:*/
	case MIPM_BUL_REMOVE:
	case MIPM_NODETYPE_INFO:
	case MIPM_BUL_FLUSH:
	case MIPM_HOME_HINT: /* ignore, it's for MD deamon*/
		break;
	case MIPM_MD_INFO:
		/* event trigger: update bul entries */
		err = mipsock_recv_mdinfo(miphdr);
		break;
	case MIPM_RR_HINT:
		err = mipsock_recv_rr_hint(miphdr);
		break;
	default:
		break;
	}
	return (err);
}


int
send_haadreq(hoainfo, hoa_plen, src)
	struct mip6_hoainfo *hoainfo;
	int hoa_plen;
	struct in6_addr *src;
{
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pi = NULL;
        struct sockaddr_in6 to;
        char adata[512], buf[1024];
	struct mip6_dhaad_req dhreq;
#if defined(MIP_MN)
	struct sockaddr_in6 *ar_sin6 = NULL, ar_sin6_orig;
#endif

        memset(&to, 0, sizeof(to));
        if (mip6_icmp6_create_haanyaddr(&to.sin6_addr, 
				&hoainfo->hinfo_hoa, hoa_plen)) 
                return (EINVAL);

	to.sin6_family = AF_INET6;
	to.sin6_port = 0;
	to.sin6_scope_id = 0;
	to.sin6_len = sizeof (struct sockaddr_in6);

        msg.msg_name = (void *)&to;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (void *) adata;
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
#if defined(MIP_MN)
	ar_sin6 = nemo_ar_get(src, &ar_sin6_orig);
	if (ar_sin6)
		msg.msg_controllen += 
			CMSG_SPACE(sizeof(struct sockaddr_in6));
#endif /* MIP_NEMO */

	/* Packet Information i.e. Source Address */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	memset(pi, 0, sizeof(*pi));
        pi->ipi6_addr = *src;
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
	if (debug)
		syslog(LOG_INFO, "send DHAAD req from %s to %s",
		       ip6_sprintf(src), ip6_sprintf(&to.sin6_addr));
		
#if defined(MIP_MN)
	if (ar_sin6) { 
		if (debug)
			syslog(LOG_INFO, "send ICMP msg via %s/%d\n", 
				ip6_sprintf(&ar_sin6->sin6_addr), ar_sin6->sin6_scope_id);
		cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct sockaddr_in6));
		cmsgptr->cmsg_level = IPPROTO_IPV6;
		cmsgptr->cmsg_type = IPV6_NEXTHOP;
		memcpy(CMSG_DATA(cmsgptr), ar_sin6, sizeof(struct sockaddr_in6));
		cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
	}
#endif

	bzero(buf, sizeof(buf));
	iov.iov_base = (char *)&dhreq;
	iov.iov_len = sizeof(dhreq);
	
	dhreq.mip6_dhreq_type = MIP6_HA_DISCOVERY_REQUEST;
	dhreq.mip6_dhreq_code = 0;
	dhreq.mip6_dhreq_cksum = 0;
	dhreq.mip6_dhreq_id = htons(++hoainfo->hinfo_dhaad_id);
#if 1 /* MIP_NEMO */
	dhreq.mip6_dhreq_reserved = mobileroutersupport ? MIP6_DHREQ_FLAG_MR : 0;
#else
	dhreq.mip6_dhreq_reserved = 0;
#endif /* MIP_NEMO */
	
	if (sendmsg(icmp6sock, &msg, 0) < 0) {
		syslog(LOG_ERR, "sending DHAAD REQUEST from %s to %s was failed: %s",
		       ip6_sprintf(src), ip6_sprintf(&to.sin6_addr), strerror(errno));
	} else {
		mip6stat.mip6s_odhreq++;
		syslog(LOG_INFO, "sent DHAAD REQUEST from %s to %s",
		       ip6_sprintf(src), ip6_sprintf(&to.sin6_addr));
	}

	return (errno);
}

int
mip6_icmp6_create_haanyaddr(haanyaddr, mpfx, mpfx_len)
        struct in6_addr *haanyaddr;
        struct in6_addr *mpfx;
	int mpfx_len;
{
	static const struct in6_addr haanyaddr_ifid64 = {
		{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		   0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}
	};
	static const struct in6_addr haanyaddr_ifidnn = {
		{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe }}
	};

        if (mpfx == NULL)
                return (EINVAL);

        if (mpfx_len == 64)
                mip6_create_addr(haanyaddr, &haanyaddr_ifid64, mpfx, mpfx_len);
        else
                mip6_create_addr(haanyaddr, &haanyaddr_ifidnn, mpfx, mpfx_len);

        return (0);
}

int
send_unsolicited_na(ifindex, target)
	int ifindex;
	struct in6_addr *target;
{
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_in6 to;
	char adata[512]; /* for ip6_pktopts and hlim */
	char nabuf[1024]; /* for neighbor advertisement message */
	struct cmsghdr *cmsgptr;
	struct in6_pktinfo *pi;
	struct nd_neighbor_advert *na;
	size_t nalen;
	struct nd_opt_hdr *ndopt;
	struct ifaddrs *ifahead, *ifa;

	if (!ifindex)
		return (-1);
	if (target == NULL)
		return (-1);

	bzero(&to, sizeof(to));
	to.sin6_len = sizeof(to);
	to.sin6_family = AF_INET6;
	to.sin6_addr = in6addr_linklocal_allnodes;
	to.sin6_scope_id = ifindex;

	msg.msg_name = (void *)&to;
	msg.msg_namelen = sizeof(to);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo))
				+ CMSG_SPACE(sizeof(int));

	/*
	 * set the source address of an unsolicited neighbor
	 * advertisement message
	 */
	cmsgptr = CMSG_FIRSTHDR(&msg);
	pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
	bzero(pi, sizeof(*pi));
        pi->ipi6_ifindex = ifindex;
        pi->ipi6_addr = *target;
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(*pi));
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	/* HopLimit Information (always 255) */
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_HOPLIMIT;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)(CMSG_DATA(cmsgptr)) = 255;
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	bzero(nabuf, sizeof(nabuf));
	na = (struct nd_neighbor_advert *)nabuf;
	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	na->nd_na_cksum = 0;
	na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
	na->nd_na_target = *target;
	nalen = sizeof(struct nd_neighbor_advert);

	/* target link-layer option. */
	if (getifaddrs(&ifahead) != 0) {
		syslog(LOG_ERR,
		    "retrieving my link-layer address failed.");
		return (-1);
	}
#define ROUNDUP8(a) (1 + (((a) - 1) | 7))
	for (ifa = ifahead; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_dl *sdl;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)(ifa->ifa_addr);
		if (sdl->sdl_index != ifindex)
			continue;
		ndopt = (struct nd_opt_hdr *) (nabuf + nalen);
		ndopt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		ndopt->nd_opt_len = (ROUNDUP8(sdl->sdl_alen + 2)) >> 3;
		memcpy((void *)(ndopt + 1), LLADDR(sdl), sdl->sdl_alen);
		nalen += ROUNDUP8(sdl->sdl_alen + 2);
		break;
	}
#undef ROUNDUP8
	freeifaddrs(ifahead);

	iov.iov_base = nabuf;
	iov.iov_len = nalen;
        
	if (sendmsg(icmp6sock, &msg, 0) == -1) {
		syslog(LOG_ERR,
		   "sending an unsolicited neighbor advertisement message "
		   "failed.");
		return (-1);
	}

	return 0;
}

struct home_agent_list *
mnd_add_hal(hpfx_entry, gladdr, flag)
	struct  mip6_hpfxl *hpfx_entry;
	struct in6_addr *gladdr;
	int flag;
{
	struct home_agent_list *hal = NULL, *haln = NULL, *halnew;

	hal = mip6_get_hal(hpfx_entry, gladdr);
	if (hal && (hal->hal_flag != flag)) { 
		hal->hal_flag = flag;
		return (hal);
	} 

	halnew = NULL;
	halnew = malloc(sizeof(*halnew));
	memset(halnew, 0, sizeof(*halnew));

	halnew->hal_ip6addr = *gladdr;
	halnew->hal_flag = flag;

	if (LIST_EMPTY(&hpfx_entry->hpfx_hal_head)) 
		LIST_INSERT_HEAD(&hpfx_entry->hpfx_hal_head, halnew, hal_entry);
	else {
		for (hal = LIST_FIRST(&hpfx_entry->hpfx_hal_head); hal; hal = haln) {
			haln =  LIST_NEXT(hal, hal_entry);
			if (haln == NULL) {
				LIST_INSERT_AFTER(hal, halnew, hal_entry);
				break;
			}
		}
	}

	if (debug)
		syslog(LOG_INFO, "Home Agent (%s) added into home agent list", 
		       ip6_sprintf(gladdr));
		
	return (hal);
}

static int
add_hal_by_commandline_xxx(homeagent)
	char *homeagent;
{
	struct in6_addr homeagent_in6;
	struct mip6_mipif *mif;
	struct mip6_hpfxl *hpfx;

	if (inet_pton(AF_INET6, homeagent, &homeagent_in6) != 1) {
		syslog(LOG_ERR,
		    "the specified home agent addrss (%s) is invalid.",
		    homeagent);
		return (-1);
	}

	LIST_FOREACH(mif, &mipifhead, mipif_entry) {
		LIST_FOREACH(hpfx, &mif->mipif_hprefx_head, hpfx_entry) {
#ifdef DSMIP
			if(IN6_IS_ADDR_V4MAPPED(&homeagent_in6)) {
				mnd_add_hal(hpfx, &homeagent_in6, 0);
			}
#endif /* DSMIP */
			if (inet_are_prefix_equal(&hpfx->hpfx_prefix,
				&homeagent_in6, hpfx->hpfx_prefixlen)) {
				/* XXXX can we add the same addr to
				   multiple prefixes? */
				mnd_add_hal(hpfx, &homeagent_in6, 0);
			}
		}
	}

	return (0);
}

#ifdef MIP_MN
void
hpfxlist_set_expire_timer(hpfx, tick)
        struct mip6_hpfxl *hpfx;
        int tick;
{
        remove_callout_entry(hpfx->hpfx_retrans);
        hpfx->hpfx_retrans = new_callout_entry(tick, hpfxlist_expire_timer,
				       (void *)hpfx, "hpfxlist_expire_timer");
}


void
hxplist_stop_expire_timer(hpfx)
        struct mip6_hpfxl *hpfx;
{
        remove_callout_entry(hpfx->hpfx_retrans);
}

void
hpfxlist_expire_timer(arg)
	void *arg;
{
        struct mip6_hpfxl *hpfx = (struct mip6_hpfxl *)arg;
	time_t now = time(0);

	hxplist_stop_expire_timer(hpfx);

	if (hpfx->hpfx_vlexpire <= now) {
		syslog(LOG_INFO, 
		       "Lifetime for the Home Prefix %s is expired", 
		       ip6_sprintf(&hpfx->hpfx_prefix));

		/* delete HoA XXXX */

		send_mps(hpfx);

		hpfxlist_set_expire_timer(hpfx, 5);

		return;
	}

	syslog(LOG_INFO, 
	       "Lifetime for the Home Prefix %s is soon expired",
	       	ip6_sprintf(&hpfx->hpfx_prefix));

	/* Soliciting Mobile Prefixes managed by the Home Agent */
	send_mps(hpfx);

	/* rate limiting XXX */
	hpfxlist_set_expire_timer(hpfx, 
		((hpfx->hpfx_vlexpire - now) > 5) ? (hpfx->hpfx_vlexpire - now):5);
}
#endif /* MIP_MN */

struct mip6_hpfxl *
mnd_add_hpfxlist(home_prefix, home_prefixlen, hpfx_mnoption, mipif)
	struct in6_addr *home_prefix;
	u_int16_t home_prefixlen;
	struct mip6_hpfx_mn_exclusive *hpfx_mnoption;
	struct mip6_mipif *mipif;
{
	struct mip6_hpfxl *hpfx = NULL;
	time_t now;

	if (mipif == NULL)
		return NULL;

	now = time(0);
	hpfx = mip6_get_hpfxlist(home_prefix, 
				 home_prefixlen, &mipif->mipif_hprefx_head);
	if (hpfx) {
		if (hpfx_mnoption) {
			hpfx->hpfx_vltime = hpfx_mnoption->hpfxlist_vltime;
			hpfx->hpfx_vlexpire = now + hpfx->hpfx_vltime;
			hpfx->hpfx_pltime = hpfx_mnoption->hpfxlist_pltime;
			hpfx->hpfx_plexpire = now + hpfx->hpfx_pltime;

			hpfxlist_set_expire_timer(hpfx, (hpfx->hpfx_pltime - 5));
		}
		
		return (hpfx);
	}

	hpfx = malloc(sizeof(*hpfx));
	memset(hpfx, 0, sizeof(*hpfx));

	hpfx->hpfx_prefix = *home_prefix;
	hpfx->hpfx_prefixlen = home_prefixlen;
	hpfx->hpfx_mipif = mipif;
	if (hpfx_mnoption) {
		hpfx->hpfx_vltime = hpfx_mnoption->hpfxlist_vltime;
		hpfx->hpfx_vlexpire = now + hpfx->hpfx_vltime;
		hpfx->hpfx_pltime = hpfx_mnoption->hpfxlist_pltime;
		hpfx->hpfx_plexpire = now + hpfx->hpfx_pltime;

		hpfxlist_set_expire_timer(hpfx, (hpfx->hpfx_pltime - 5));
	}

	LIST_INIT(&hpfx->hpfx_hal_head);

	if (debug)
		syslog(LOG_INFO, "Home Prefix (%s/%d) added into home prefix list",
		       ip6_sprintf(home_prefix), home_prefixlen);
	
	LIST_INSERT_HEAD(&mipif->mipif_hprefx_head, hpfx, hpfx_entry);

	return (hpfx);
}

static struct mip6_mipif *
mnd_add_mipif(ifname)
	char *ifname;
{
	struct mip6_mipif *mif = NULL;
	u_int16_t ifindex;

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		syslog(LOG_ERR, "%s %s", ifname, strerror(errno));
		return (NULL);
	}
	
	mif = mnd_get_mipif(ifindex);
	if (mif)
		return (mif);
	
	mif = malloc(sizeof(struct mip6_mipif));
	memset(mif, 0, sizeof(struct mip6_mipif));
	mif->mipif_ifindex = ifindex;

	/* initialize home prefix head */
	LIST_INIT(&mif->mipif_hprefx_head);

	/* add all global prefixes assigned to this ifindex */
	mnd_init_homeprefix(mif);

	LIST_INSERT_HEAD(&mipifhead, mif, mipif_entry);

	if (debug)
		syslog(LOG_ERR, "%s is added successfully", ifname);

	return (mif);
}

struct mip6_mipif *
mnd_get_mipif(ifindex)
	u_int16_t ifindex;
{
	struct mip6_mipif *mif;

	LIST_FOREACH(mif, &mipifhead, mipif_entry) {
		if (mif->mipif_ifindex == ifindex) 
			return (mif);
	}

	return (NULL);
}

static void
mnd_init_homeprefix(mipif)
	struct mip6_mipif *mipif;
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr *sa;
	struct sockaddr_in6 *addr_sin6, *mask_sin6;
	int prefixlen = 0;
	struct mip6_hpfxl *hpfxent = NULL;
	struct mip6_hoainfo *hoa = NULL;
	struct mip6_hpfx_mn_exclusive mnoption;
#if 1 /* MIP_NEMO */
	struct nemo_mptable *mpt = NULL;
#endif /* MIP_NEMO */

	if (getifaddrs(&ifap) != 0) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}
	
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		sa = ifa->ifa_addr;
		
		if (sa->sa_family != AF_INET6)
			continue;
		if (if_nametoindex(ifa->ifa_name) != mipif->mipif_ifindex) 
			continue;

		if (!(ifa->ifa_flags & IFF_UP)) 
			continue;

		/* home prefix must be global scope */
		addr_sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&addr_sin6->sin6_addr))
			continue;

		/* set Home Address to mip6_hoainfo */
		hoa = hoainfo_insert(&addr_sin6->sin6_addr, 
				     mipif->mipif_ifindex);
		if (hoa == NULL)
			continue;

		mask_sin6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
		prefixlen = in6_mask2len(&mask_sin6->sin6_addr, NULL);

		hpfxent = mip6_get_hpfxlist(&addr_sin6->sin6_addr, 
					    prefixlen, 
					    &mipif->mipif_hprefx_head);
		if (hpfxent)
			continue;

		memset(&mnoption, 0, sizeof(mnoption)); 
		mnoption.hpfxlist_vltime = 604800;
		mnoption.hpfxlist_pltime = 10;

		hpfxent = mnd_add_hpfxlist(&addr_sin6->sin6_addr, 
			prefixlen, &mnoption, mipif);
		if (hpfxent == NULL) {
			syslog(LOG_ERR, "fail to add home prefix entry %s",
			       ip6_sprintf(&addr_sin6->sin6_addr));
			continue;
		}
		
#if 1 /* MIP_NEMO */
		LIST_FOREACH(mpt, &hoa->hinfo_mpt_head, mpt_entry) {
			if (mpt->mpt_ha.s6_addr == 0)
				continue;
			if (mnd_add_hal(hpfxent, &mpt->mpt_ha, 0) == NULL) {
				syslog(LOG_ERR, "fail to add home agent entry %s",
				       ip6_sprintf(&mpt->mpt_ha));
			}
		}
#endif /* MIP_NEMO */
	}
	
	freeifaddrs(ifap);
	
	if (LIST_EMPTY(&mipif->mipif_hprefx_head)) {
		syslog(LOG_ERR,
		    "please configure at least one global home prefix");
		exit(-1);
	}
	return;
}

#ifdef DSMIP
struct in_addr *
mnd_get_v4hoa_by_ifindex (ifindex) 
	u_int16_t ifindex;
{
	struct ifaddrs *ifa, *ifap;
	struct sockaddr *sa;
	struct sockaddr_in *addr_sin;

	if (getifaddrs(&ifap) != 0) { 
		syslog(LOG_ERR, "%s", strerror(errno)); 
		return NULL;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		sa = ifa->ifa_addr;
 
		if (sa->sa_family != AF_INET)
			continue;
		if (if_nametoindex(ifa->ifa_name) != ifindex)
			continue;
 
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		addr_sin = (struct sockaddr_in *)ifa->ifa_addr;
		return (&addr_sin->sin_addr);
	}

	return NULL;
}
#endif /* DSMIP */

int
set_default_bu_lifetime(hoainfo) 
	struct mip6_hoainfo *hoainfo;
{
	return (default_lifetime);
}

static void
config_lifetime(s, arg)
	int s;
	char *arg;
{
	int val;

	if (*arg == '\0') {
		command_printf(s, "Usage: config lifetime <lifetime in second>\nThe value will be truncated in units of 4sec");
		return;
	}
	
	val = strtol(arg, NULL, 10) >> 2;
	if (val == 0) {
		command_printf(s, "The specified value is invalid\n");
	} else if (val > USHRT_MAX) {
		command_printf(s, "The specified value is too big\n");
	} else {
		if (val != strtol(arg, NULL, 10)) {
			command_printf(s, "The sepecified value is truncated to %d(s)\n", val << 2);
		}
		default_lifetime = val;
	}
}

int
receive_hadisc_reply(dhrep, dhrep_len)
	struct mip6_dhaad_rep *dhrep;
	size_t dhrep_len;
{
	int optlen, total;
	char *options;
	struct binding_update_list *bul;
	struct mip6_mipif *mif;
	struct mip6_hpfxl *hpfx;
	struct in6_addr *dhrep_addr;
	struct mip6_hoainfo *hoainfo;

	/* Is this HAADREPLY mine? */
	hoainfo = hoainfo_get_withdhaadid(ntohs(dhrep->mip6_dhrep_id));
	if (hoainfo == NULL)
		return (ENOENT);

#if 1 /* MIP_NEMO */
	if (mobileroutersupport &&
	    (dhrep->mip6_dhrep_reserved & MIP6_DHREP_FLAG_MR) == 0) {
		/* XXX */
		syslog(LOG_INFO, "HA does not support the basic NEMO protocol");
		return (ENOENT);
	} 
#endif /* MIP_NEMO */

	/*
	 * When MN receives DHAAD reply, it flushes all home
	 * agent entries in the list except for static
	 * configured entries. After flush, new entries will
	 * be added according to the reply packet 
	 */
	mif = mnd_get_mipif(hoainfo->hinfo_ifindex);
	if (mif == NULL)
		return (0);

	LIST_FOREACH(hpfx, &mif->mipif_hprefx_head, hpfx_entry) {
		if (inet_are_prefix_equal(&hoainfo->hinfo_hoa, 
					  &hpfx->hpfx_prefix, hpfx->hpfx_prefixlen)) {
			break;
		}
	}
	if (hpfx == NULL)
		return (ENOENT);

	mip6_flush_hal(hpfx, MIP6_HAL_STATIC);

	options = (char *)dhrep + sizeof(struct mip6_dhaad_rep);
	total = dhrep_len - sizeof(struct mip6_dhaad_rep);
	for (optlen = 0; total > 0; total -= optlen) {
		options += optlen;
		dhrep_addr = (struct in6_addr *)options; 
		optlen = sizeof(struct in6_addr);
		if (mnd_add_hal(hpfx, dhrep_addr, 0) == NULL)
			continue;

		if (debug) 
			syslog(LOG_INFO, "%s is added into hal list",
			       ip6_sprintf(dhrep_addr));
	}

	if ((bul = bul_get_homeflag(&hoainfo->hinfo_hoa)) == NULL)
		return (0);
		
#if 0
	bul->bul_reg_fsm_state = MIP6_BUL_REG_FSM_STATE_DHAAD;
#endif
	bul_kick_fsm(bul, MIP6_BUL_FSM_EVENT_DHAAD_REPLY, NULL);
	syslog(LOG_INFO, "DHAAD gets %s",
	       ip6_sprintf(&bul->bul_peeraddr));

#ifdef MIP_MCOA
	if (!LIST_EMPTY(&bul->bul_mcoa_head)) {
		struct binding_update_list *mbul;

		for (mbul = LIST_FIRST(&bul->bul_mcoa_head); mbul;
		     mbul = LIST_NEXT(mbul, bul_entry)) {
#if 0
			mbul->bul_reg_fsm_state = MIP6_BUL_REG_FSM_STATE_DHAAD;
#endif
			bul_kick_fsm(mbul, MIP6_BUL_FSM_EVENT_DHAAD_REPLY, NULL);
		}
	}
#endif /* MIP_MCOA */

	return (0);
}

int
send_mps(hpfx)
	struct mip6_hpfxl *hpfx;
{
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr  *cmsgptr = NULL;
        struct in6_pktinfo *pi = NULL;
        struct sockaddr_in6 to;
        char adata[512], buf[1024];
        struct mip6_prefix_solicit *mpfx;
        size_t mpfxlen = 0;
        struct binding_update_list *bul;
        struct ip6_dest *dest;
        struct ip6_opt_home_address *hoadst;
	struct in6_addr *hoa;
#if defined(MIP_MN)
	struct sockaddr_in6 *ar_sin6, ar_sin6_orig;
#endif /* MIP_NEMO */ 

	if (hpfx == NULL)
		return 0;
	if (hpfx->hpfx_mipif == NULL)
		return 0;

	/* Get source address of MPS (i.e. HoA) */
	hoa = get_hoa_from_ifindex(hpfx->hpfx_mipif->mipif_ifindex);
	if (hoa == NULL)
		return 0;

	/* Get destination address of MPS (i.e. HA) */
	bul = bul_get_homeflag(hoa);
	if (bul == NULL)
		return (0);

        memset(&to, 0, sizeof(to));
        to.sin6_addr = bul->bul_peeraddr;
        to.sin6_family = AF_INET6;
        to.sin6_port = 0;
        to.sin6_scope_id = 0;
        to.sin6_len = sizeof (struct sockaddr_in6);

        msg.msg_name = (void *)&to;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = (void *) adata;
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + 
		CMSG_SPACE(sizeof(struct ip6_opt_home_address) + 2 + 4);

#if defined(MIP_MN)
        ar_sin6 = nemo_ar_get(&bul->bul_coa, &ar_sin6_orig);
        if (ar_sin6) 
                msg.msg_controllen += 
                        CMSG_SPACE(sizeof(struct sockaddr_in6));
#endif /*MIP_NEMO */

        /* Packet Information i.e. Source Address */
        cmsgptr = CMSG_FIRSTHDR(&msg);
        pi = (struct in6_pktinfo *)(CMSG_DATA(cmsgptr));
        memset(pi, 0, sizeof(*pi));
        pi->ipi6_addr = *hoa;
        cmsgptr->cmsg_level = IPPROTO_IPV6;
        cmsgptr->cmsg_type = IPV6_PKTINFO;
        cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

#if defined(MIP_MN)
        if (ar_sin6) { 
                if (debug) 
                        syslog(LOG_INFO, "sendmsg via %s/%d",
			       ip6_sprintf(&ar_sin6->sin6_addr), 
			       ar_sin6->sin6_scope_id);
                cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct sockaddr_in6));
                cmsgptr->cmsg_level = IPPROTO_IPV6;
                cmsgptr->cmsg_type = IPV6_NEXTHOP;
                memcpy(CMSG_DATA(cmsgptr), ar_sin6, 
		       sizeof(struct sockaddr_in6));
                cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);
        }
#endif

        /* Destination Option */
	dest = (struct ip6_dest *)(CMSG_DATA(cmsgptr));
	
	/* padding */
	MIP6_FILL_PADDING((char *)(dest + 1), MIP6_HOAOPT_PADLEN);
	
	dest->ip6d_nxt = 0;
	dest->ip6d_len = ((sizeof(struct ip6_opt_home_address) +
			   sizeof(struct ip6_dest) + 
			   MIP6_HOAOPT_PADLEN) >> 3) - 1;
	
	hoadst = (struct ip6_opt_home_address *)
		((char *)(dest + 1) + MIP6_HOAOPT_PADLEN);
	memset(hoadst, 0, sizeof(*hoadst));
	hoadst->ip6oh_type = 0xc9;
	hoadst->ip6oh_len = sizeof(struct ip6_opt_home_address) - 
		sizeof(struct ip6_dest);
	memcpy(hoadst->ip6oh_addr, &bul->bul_coa, sizeof(struct in6_addr));
	
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_DSTOPTS;
	cmsgptr->cmsg_len = 
		CMSG_LEN(sizeof(struct ip6_opt_home_address) + 
			 sizeof(struct ip6_dest) + MIP6_HOAOPT_PADLEN);
	cmsgptr = CMSG_NXTHDR(&msg, cmsgptr);

	hpfx->hpfx_mipif->mipif_mps_id = random(); 

        bzero(buf, sizeof(buf));
        mpfx = (struct mip6_prefix_solicit *)buf;
        mpfx->mip6_ps_type = MIP6_PREFIX_SOLICIT;
        mpfx->mip6_ps_code = 0;
        mpfx->mip6_ps_cksum = 0;
        mpfx->mip6_ps_id = htons(hpfx->hpfx_mipif->mipif_mps_id);
        mpfx->mip6_ps_reserved = 0;
        mpfxlen = sizeof(struct mip6_prefix_solicit);

        iov.iov_base = buf;
        iov.iov_len = mpfxlen;

	if (debug)
		syslog(LOG_INFO, "sending Mobile Prefix Solicitation");

        if (sendmsg(icmp6sock, &msg, 0) < 0)
                perror ("sendmsg");

	hpfx->hpfx_mipif->mipif_mps_lastsent = time(0);

        return errno;
}

static struct in6_addr *
get_hoa_from_ifindex(ifindex)
	u_int16_t ifindex;
{
        struct ifaddrs *ifa, *ifap;
        struct sockaddr *sa;
	struct in6_addr *address;
	struct binding_update_list *bul = NULL;
	
        if (getifaddrs(&ifap) != 0) {
                syslog(LOG_ERR, "%s", strerror(errno));
                return NULL;
        }
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                sa = ifa->ifa_addr;
                
                if (sa->sa_family != AF_INET6)
                        continue;
                if (ifa->ifa_addr == NULL)
                        continue;
		address = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                
		if (IN6_IS_ADDR_LINKLOCAL(address)
		    || IN6_IS_ADDR_MULTICAST(address)
		    || IN6_IS_ADDR_LOOPBACK(address)
		    || IN6_IS_ADDR_V4MAPPED(address)
		    || IN6_IS_ADDR_UNSPECIFIED(address)) 
			continue;
		
		bul = bul_get_homeflag(address);
		if (bul == NULL)
			continue;

		break;
	}

	if (bul) {
		freeifaddrs(ifap);
		return &bul->bul_hoainfo->hinfo_hoa;
	}

	freeifaddrs(ifap);
	return NULL;
}

int
receive_mpa(mpa, mpalen, bul)
	struct mip6_prefix_advert *mpa;
	size_t mpalen;
	struct binding_update_list *bul;
{
	int error = 0;
	int done = 0;
	struct mip6_mipif *mif = NULL;
	struct nd_opt_hdr *pt;
	struct mip6_hpfx_mn_exclusive mnoption;

	/* 
	 * determine solicited MPA or unsolicited one. If it is
	 * unsolicited MPA, the MN must issue a MPS and discard the
	 * MPA. (sec 11.4.3)
	 */
	LIST_FOREACH(mif, &mipifhead, mipif_entry) {
		if (mif->mipif_mps_id == ntohs(mpa->mip6_pa_id))
			break;
	}

	if (mif == NULL) { /* Unsolicited MPA */
		struct mip6_hoainfo *hoainfo = NULL;
		struct mip6_hpfxl *hpfx = NULL;

		hoainfo = hoainfo_find_withhoa(&bul->bul_hoainfo->hinfo_hoa);
		if (hoainfo == NULL)
			return (ENOENT);

		mif = mnd_get_mipif(hoainfo->hinfo_ifindex);
		if (mif == NULL)
			return (ENOENT);

		LIST_FOREACH(hpfx, &mif->mipif_hprefx_head, hpfx_entry) {
			if (inet_are_prefix_equal(&hoainfo->hinfo_hoa, 
						  &hpfx->hpfx_prefix, hpfx->hpfx_prefixlen)) {
				break;
			}
		}
		if (hpfx == NULL)
			return (ENOENT);

		send_mps(hpfx);

		return (0);
	}

	/* Solicited MPA */
	memset(&ndopts, 0, sizeof(ndopts));
	error = mip6_get_nd6options(&ndopts,
				    (char *)mpa + sizeof(struct mip6_prefix_advert),
				    mpalen - sizeof(struct mip6_prefix_advert));
		
	for (pt = (struct nd_opt_hdr *)ndopts.ndpi_start;
	     pt <= (struct nd_opt_hdr *)ndopts.ndpi_end;
	     pt = (struct nd_opt_hdr *)((caddr_t)pt +
					(pt->nd_opt_len << 3))) {
		struct nd_opt_prefix_info *pi;
		
		if (pt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
			continue;

		pi = (struct nd_opt_prefix_info *)pt;
			
		if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix) ||
		    IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix))
			continue;

		/* aggregatable unicast address, rfc2374 XXX */
		if (pi->nd_opt_pi_prefix_len != 64)
			continue;

		memset(&mnoption, 0, sizeof(mnoption)); 
		mnoption.hpfxlist_vltime = 
			ntohl(pi->nd_opt_pi_valid_time);
		mnoption.hpfxlist_pltime = 
			ntohl(pi->nd_opt_pi_preferred_time);
		
		/* XXX check the lifetime and send BU if possible */
		
		mnd_add_hpfxlist(&pi->nd_opt_pi_prefix,
				 pi->nd_opt_pi_prefix_len,
				 &mnoption, mif);
		done = 1;
	}

	if (!done) {
		error = EINVAL;
		syslog(LOG_ERR, "Could not find valid PI in MPA");
	}

	return (error);
}

static void
terminate(dummy)
	int dummy;
{
	struct mip_msghdr mipmsg;

	/* stop acting as a mobile node. */
	mipsock_nodetype_request(mobileroutersupport ?
				 MIP6_NODETYPE_MOBILE_ROUTER : MIP6_NODETYPE_MOBILE_NODE, 0);

	/* flush all bul registered in a kernel. */
	memset(&mipmsg, 0, sizeof(struct mip_msghdr));
	mipmsg.miph_msglen = sizeof(struct mip_msghdr);
	mipmsg.miph_type = MIPM_BUL_FLUSH;
	if (write(mipsock, &mipmsg, sizeof(struct mip_msghdr)) == -1) {
		syslog(LOG_ERR,
		    "removing all bul entries failed.");
	}

	close(csock);	
	close(icmp6sock);
	close(mipsock);
	close(mhsock);

	noro_sync();

#ifdef MIP6_NEMO
	unlink(MRD_PIDFILE);
#else
	unlink(MND_PIDFILE);
#endif

	exit(-1);
}

/* 
 * Entry for hosts not supporting Route Optimization.  This entry is
 * also used to tell shisad not to run RO for specified host in file.  
 */
static void
noro_init()
{ 
        FILE *file;
	char buf[256], *bl;
	struct in6_addr noro_addr;
	struct noro_host_list *noro;
	
	file = fopen(MND_NORO_FILE, "r");
        if(file == NULL) 
                return;

        memset(buf, 0, sizeof(buf));
        while((fgets(buf, sizeof(buf), file)) != NULL){
		/* ignore comments */
		if (strchr(buf, '#') != NULL) 
			continue;

		bl = strchr(buf, '\n');
		if (bl) 
			*bl = '\0';

                if (inet_pton(AF_INET6, buf, &noro_addr) < 0) {
                        fprintf(stderr, "%s is not correct address\n", buf);
                        continue;
		}

		if (noro_get(&noro_addr)) {
			syslog(LOG_ERR, "%s is duplicated in %s", buf, MND_NORO_FILE);
			continue;
		}

		noro = malloc(sizeof(struct noro_host_list));
		if (noro == NULL) {
			perror("malloc");
			return;
		}
		memset(noro, 0, sizeof(struct noro_host_list));
		noro->noro_host = noro_addr;
		LIST_INSERT_HEAD(&noro_head, noro, noro_entry); 
	}
	fclose(file);

	return;
}

/*
   Return value:
   1: success
   0: something wrong happens (the address was already registered)
   -1: some system error occures. errno is set
 */
int
noro_add(tgt)
	struct in6_addr *tgt;
{ 
	struct noro_host_list *noro = NULL;

	noro = noro_get(tgt);
	if (noro)
		return (0);

	noro = malloc(sizeof(struct noro_host_list));
	if (noro == NULL)
		return (-1);

	memset(noro, 0, sizeof(struct noro_host_list));
	noro->noro_host = *tgt;
	LIST_INSERT_HEAD(&noro_head, noro, noro_entry); 
	
	return (1);
}


struct noro_host_list *
noro_get(tgt)
	struct in6_addr *tgt;
{ 
	struct noro_host_list *noro = NULL;

        for (noro = LIST_FIRST(&noro_head); noro; 
	     noro = LIST_NEXT(noro, noro_entry)) {
		if (IN6_ARE_ADDR_EQUAL(tgt, &noro->noro_host)) 
			return (noro);
	}

	return (NULL);
}


static void
noro_show(s, dummy)
	int s;
	char *dummy;
{ 
	struct noro_host_list *noro = NULL;

        for (noro = LIST_FIRST(&noro_head); noro; 
	     noro = LIST_NEXT(noro, noro_entry)) {
		command_printf(s, "%s\n", ip6_sprintf(&noro->noro_host));
	}
}

static void
command_add_noro(s, arg)
	int s;
	char *arg;
{
	struct in6_addr addr;
	
	if (*arg == '\0') {
		command_printf(s, "Usage: add noro <address>\n");
		return;
	}

	if (inet_pton(AF_INET6, arg, &addr) != 1) {
		command_printf(s, "The specified address [%s] is not persable\n", arg);
		return;
	}

	switch (noro_add(&addr)) {
	case 0:
		command_printf(s, "The address is already registered\n");
		break;
	case -1:
		command_printf(s, "Error has occured - %s\n", strerror(errno));
		break;
	default:
		/* Nothing to do */
		break;
	}
}

static void
noro_sync()
{ 
        FILE *file;
	struct noro_host_list *noro = NULL;
	
	file = fopen(MND_NORO_FILE, "w");
        if(file == NULL) 
                return;

        for (noro = LIST_FIRST(&noro_head); noro; 
	     noro = LIST_NEXT(noro, noro_entry)) {
		fputs(ip6_sprintf(&noro->noro_host), file);
	}

	fclose(file);
}


static void
command_show_hal(s, dummy)
	int s;
	char *dummy;
{
	struct mip6_mipif *mipif = NULL;

        LIST_FOREACH(mipif, &mipifhead, mipif_entry) {
		show_hal(s, &mipif->mipif_hprefx_head);
	}
}

/* Flush BC should be done by cnd */
static void
command_flush(s, arg)
	int s;
	char *arg;
{
	command_printf(s, "Not implemented at all\n");
	if (strcmp(arg, "bul") == 0) {
		/*flush_bc();*/
		command_printf(s, "-- Clear Binding Update List --\n");
	} else if (strcmp(arg, "stat") == 0) {
		command_printf(s, "-- Clear Shisa Statistics --\n");
	} else if (strcmp(arg, "hal") == 0) {
		command_printf(s, "-- Clear Home Agent List --\n");
	} else if (strcmp(arg, "noro") == 0) {
		command_printf(s, "-- Clear No Route Optimization Host --\n");
	} else {
		command_printf(s, "Available options are:\n");
		command_printf(s, "\tbul (Binding Update List)\n\thal (Home Agent List)\n\tstat (Statistics)\n\tnoro (No Route Optimization Hosts)\n\n");
	}
}

static void
show_current_config(s, dummy)
	int s;
	char *dummy;
{
	command_printf(s, "Current configuration\n");
	command_printf(s, "debug: %s\n", debug ? "on" : "off");
	command_printf(s, "name lookup: %s\n", namelookup ? "true" : "false");
	command_printf(s, "command port: %d\n", command_port);
	command_printf(s, "Binding Update Lifetime for Home registration: %d(s)\n",
		default_lifetime * 4);
}
