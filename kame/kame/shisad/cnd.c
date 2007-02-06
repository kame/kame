/*	$KAME: cnd.c,v 1.19 2007/02/06 05:58:52 t-momose Exp $	*/

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
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <poll.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>
#include <netinet/ip6.h>
#include <net/mipsock.h>
#include <netinet6/mip6.h>

#include "callout.h"
#include "stat.h"
#include "shisad.h"
#include "fdlist.h"
#include "command.h"
#include "config.h"

int main(int, char **);

static void cn_usage(char *);
static void cn_lists_init(void);

/*static void command_show_status(int, char *);*/
static void command_flush(int, char *);
static void terminate(int);

struct command_table show_command_table[] = {
	{"bc", command_show_bc, "binding cache"},
	{"kbc", command_show_kbc, "binding cache in kernel"},
	{"stat", command_show_stat, "statistics"},
	{"callout", show_callout_table, "show callout table "},
	{NULL}
};

struct command_table command_table[] = {
	{"show", NULL, "Show status", show_command_table},
	{"flush", command_flush, "Flush binding caches"},
};

/* Global Variables */
int mhsock, mipsock, icmp6sock;
struct mip6stat mip6stat;
int homeagent_mode = 0;

/* configuration parameters */
int debug = 0;
int foreground = 0;
int namelookup = 1;
int command_port = CND_COMMAND_PORT;
char *conffile = CND_CONFFILE;

static void
cn_usage(path)
	char *path;
{
	char *cmd;

	cmd = strrchr(path, '/');
	if (!cmd)
		cmd = path;
	else
		cmd++;
	fprintf(stderr, "%s [-fn] [-c configfile]\n", cmd);
} 


int
main(argc, argv)
	int argc;
	char **argv;
{
	int pfds;
	int ch = 0;
	FILE *pidfp;

	/* get options */
	while ((ch = getopt(argc, argv, "fnc:")) != -1) {
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
		default:
			fprintf(stderr, "unknown option\n");
			cn_usage(argv[0]);
			exit(0);
			/* Not reach */
			break;
		}
	}

	/* parse configuration file and set default values. */
	if (parse_config(CFM_CND, conffile) == 0) {
		config_get_number(CFT_DEBUG, &debug, config_params);
		config_get_number(CFT_COMMANDPORT, &command_port,
		    config_params);
	}

	kernel_debug(debug);

	/* open syslog infomation. */
	openlog("shisad(cnd)", 0, LOG_DAEMON);
	syslog(LOG_INFO, "-- Start CN daemon at -- \n");

	/* open sockets */
	mhsock_open();
	mipsock_open();
	icmp6sock_open();

	/* start timer */
	shisad_callout_init();

	/* initialization */
	fdlist_init();
	if (command_init("cn> ", command_table, sizeof(command_table) / sizeof(struct command_table), command_port, NULL) < 0) {
		fprintf(stderr, "Unable to open user interface\n");
	}
	cn_lists_init();
	init_nonces();

	/* register signal handlers. */
	signal(SIGTERM, terminate);
	signal(SIGINT, terminate);

	if (foreground == 0)
		daemon(0, 0);

	/* dump current PID */
	if ((pidfp = fopen(CND_PIDFILE, "w")) != NULL) {
		fprintf(pidfp, "%d\n", getpid());
		fclose(pidfp);
	}

	new_fd_list(mhsock, POLLIN, mh_input_common);
        new_fd_list(mipsock, POLLIN, mipsock_input_common);
        new_fd_list(icmp6sock, POLLIN, icmp6_input_common);

	/* notify a kernel to behave as a correspondent node. */
	mipsock_nodetype_request(MIP6_NODETYPE_CORRESPONDENT_NODE, 1);

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

	return (0);
}

static void
cn_lists_init(void)
{
	mip6_bc_init();
}

int
cn_receive_dst_unreach(icp)
	struct icmp6_hdr *icp;
{
	struct ip6_hdr *iip6;
	struct binding_cache *bc;
	struct ip6_rthdr2 *rth2;

	iip6 = (struct ip6_hdr *)(icp + 1);
	if ((rth2 = find_rthdr2(iip6)) == NULL)
		return (0);
	bc = mip6_bc_lookup((struct in6_addr *)(rth2 + 1), &iip6->ip6_src, 0);
	if (bc)  {
		mip6_bc_delete(bc);
		syslog(LOG_INFO, 
		       "binding for %s is deleted due to ICMP destunreach.\n",
		       ip6_sprintf(&iip6->ip6_dst));
	}

	return (0);
}

int
mipsock_input(miphdr)
	struct mip_msghdr *miphdr;
{
	int err = 0;
	struct mipm_nodetype_info *nodeinfo;

	switch (miphdr->miph_type) {
	case MIPM_NODETYPE_INFO:
		nodeinfo = (struct mipm_nodetype_info *)miphdr;
		homeagent_mode = nodeinfo->mipmni_enable & MIP6_NODETYPE_HOME_AGENT;
	case MIPM_BE_HINT:
		mipsock_behint_input(miphdr);
		break;
	default:
		break;
	}

	return (err);
}

static void
command_flush(s, arg)
	int s;
	char *arg;
{
	flush_bc();
}

static void
terminate(dummy)
	int dummy;
{
	mip6_flush_kernel_bc();
	mipsock_nodetype_request(MIP6_NODETYPE_CORRESPONDENT_NODE, 0);
	unlink(CND_PIDFILE);
	exit(1);
}
