/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 and 2000 WIDE Project.
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
 * Copyright (c) 1999 and 2000 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Hesham Soliman <Hesham.Soliman@ericsson.com.au>
 *          Magnus Braathen <Magnus.Braathen@era.ericsson.se>
 *
 * $Id: mip6config.c,v 1.1 2000/02/07 17:27:07 itojun Exp $
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <err.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet6/mip6_common.h>
#include "mip6config.h"

static int startmip6;
static int s;

static char *configfilename;

static int
upd_kernel(int cmd, struct input_data *args)
{
    struct input_data dummy;

    if (args == NULL) {
        bzero(&dummy, sizeof(dummy));
        args = &dummy;    /* ioctl() third argument must be non-NULL */
    }

    /* Note: max transfer size is PAGE_SIZE (4096 bytes?) */
    if (ioctl(s, cmd, (caddr_t)args) < 0) {
		perror("ioctl");
        printf("Make sure kernel supports MIP6.\n");
        exit(1);
    }
    return 0;  /* XXXYYY Better error handling needed? */
}

/*
mip6config -F (Set Default foreign IP Address)
mip6config -H (Write home address)
mip6config -E (Remove default foreign address from list)

mip6config -f (Read from file)
mip6config -b (Default BU lifetime)
mip6config -w (Set time when CN should send Binding request)
mip6config -y (HA preference)
mip6config -l (Default lifetime for home registration, not BU)

mip6config -g (Enable HA functionality)
mip6config -u (Enable forwarding of Site local Unicast dest addresses)
mip6config -m (Enable forwarding of Site local Multicast dest addresses)
mip6config -p (Enable lnk layer promiscuous mode)
mip6config -r (Enable sending BU to CN, ie.Route optimisation on/off )
mip6config -t (Enable tunneling of packets from MN to CN via HA)
mip6config -q (Enable sending BR to the MN)
mip6config -d (Enable debug)
mip6config -a (Allow autoconfiguration of Home address)
mip6config -e (Enable eager Movement Detection)
mip6config -x (De-activate MN/HA functionality)
*/

static void
usage()
{
	fprintf(stderr, "\n%s\n%s\n%s%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
"usage: mip6config -a [-F foreign_address/plen@if] [-b bu_lifetime]",
"                     [-w br_time] [-l hr_lifetime] [-depqrt 0/1]",
"       mip6config -H home_address/plen@if%ha_addr ",
                     "[-F foreign_address/plen@if]",
"                     [-b bu_lifetime] [-w br_time] [-l hr_lifetime]",
"                     [-depqrt 0/1]",
"       mip6config -g [-w br_time] [-y ha_pref] [-l hr_lifetime] [-mqu 0/1]",
"       mip6config -x",
"       mip6config -E address",
"       mip6config -f file",
"       mip6config [-F foreign_address/plen@if] [-b bu_lifetime] [-w br_time]",
"                  [-y ha_pref] [-l hr_lifetime] [-dempqrtu 0/1]");
	exit(1);
}

/* parses a line like ipv6addr/prefixlen@interface */
static int
parse_addr(char *addrline, char **addr, int *plen, char **iface)
{
    char *plen_ptr;

    *addr = addrline;

    if ((plen_ptr = strchr(*addr, '/')) == NULL) {
        return -1;
    }

    *plen_ptr = '\0';
    plen_ptr++;

    *plen = atoi(plen_ptr);

    if ((*iface = strchr(plen_ptr, '@')) == NULL) {
        return -1;
    }

    **iface = '\0';
    (*iface)++;

    return 0;
}

/* Returns the address in network order */
static int
getaddress(char *address, struct in6_addr *in6addr)
{
    if (inet_pton(AF_INET6, address, in6addr) == NULL) {
        struct hostent *hp;
 	if ((hp = gethostbyname2(address, AF_INET6)) == NULL)
            return -1;
        else
            memcpy(in6addr, hp->h_addr_list[0], sizeof(struct in6_addr));
    }
    return 0;
}

/* Parsing functions */
static int
set_homeaddr(char *homeaddr, int command)
{
    struct input_data input;
    char *address, *interface, *homeagent = NULL;
    int   plen;
    int retval;

    if (parse_addr(homeaddr, &address, &plen, &interface) < 0) {
        printf(PROGNAME "error parsing home address %s\n", homeaddr);
        return -1;
    }

    if ((homeagent = strchr(interface, '%')) != NULL) {
        *homeagent = '\0';
        homeagent++;
    }

#ifdef DEBUG
    printf("set_homeaddr: address: %s, plen: %d, interface: %s, homeagent: %s\n",
           address, plen, interface, homeagent);
#endif /* DEBUG */

    if (getaddress(address, &input.ip6_addr) < 0) {
        printf(PROGNAME "unknown home address %s\n", address);
        return -1;
    }

    if (homeagent == NULL || *homeagent == '\0' || *homeagent == ' ')
        input.ha_addr = in6addr_any;
    else {
 	if (getaddress(homeagent, &input.ha_addr) < 0) {
            printf(PROGNAME "unknown homeagent address %s\n", homeagent);
            return -1;
        }
    }

    input.prefix_len = plen;
    strcpy(input.if_name, interface);

    startmip6 = 1;

    if ((retval = upd_kernel(command, (void *)&input)) > 0) {
        /* error */
        print_err(retval);
    }

    return retval;
}

static int
del_coaddr(char *coaddr, int command)
{
    struct input_data input;
    char *address, *interface;
    int   plen;
    int retval;

    if (parse_addr(coaddr, &address, &plen, &interface) < 0) {
        printf(PROGNAME "error parsing c/o address %s\n", coaddr);
        return -1;
    }

#ifdef DEBUG
    printf("del_coaddr: address: %s, plen: %d, interface: %s\n",
           address, plen, interface);
#endif /* DEBUG */

    if (getaddress(address, &input.ip6_addr) < 0) {
        printf(PROGNAME "unknown c/o address %s\n", address);
        return -1;
    }

    input.prefix_len = plen;
    strcpy(input.if_name, interface);

    if ((retval = upd_kernel(command, (void *)&input)) > 0) {
        /* error */
        print_err(retval);
    }

    return retval;
}

static int
set_coaddr(char *coaddr, int command)
{
    struct input_data input;
    char *address, *interface;
    int   plen;
    int retval;

    if (parse_addr(coaddr, &address, &plen, &interface) < 0) {
        printf(PROGNAME "error parsing c/o address %s\n", coaddr);
        return -1;
    }

#ifdef DEBUG
    printf("set_coaddr: address: %s, plen: %d, interface: %s\n",
           address, plen, interface);
#endif /* DEBUG */

    if (getaddress(address, &input.ip6_addr) < 0) {
        printf(PROGNAME "unknown c/o address %s\n", address);
        return -1;
    }

    input.prefix_len = plen;
    strcpy(input.if_name, interface);

    if ((retval = upd_kernel(command, (void *)&input)) > 0) {
        /* error */
        print_err(retval);
    }

    return retval;
}

static int
set_enable(char *enable, int command)
{
    struct input_data input;
    int retval;

#ifdef DEBUG
    printf("set_enable: %s, command: %d\n", enable, command);
#endif /* DEBUG */

    if ((enable == NULL) || (enable != NULL && atoi(enable) >= 1))
        input.value = 1;
    else
        input.value = 0;

    if (command == SIOCSAUTOCONFIG_MIP6)
        startmip6 = 1;

    if ((retval = upd_kernel(command, (void *)&input)) > 0) {
        /* error */
        print_err(retval);
    }

    return retval;
}

static int
set_value(char *value, int command)
{
    struct input_data input;
    int retval;

#ifdef DEBUG
    printf("set_value: %s, command: %d\n", value, command);
#endif /* DEBUG */

    if (value == NULL)
        return -1;

    input.value = atoi(value);

    if ((retval = upd_kernel(command, (void *)&input)) > 0) {
        /* error */
        print_err(retval);
    }

    return retval;
}

static int
set_enable_ha(char *value, int command)
{
#ifdef DEBUG
    printf("set_enable_ha: %s, command: %d\n", value, command);
#endif /* DEBUG */

    startmip6 = 1;

    return 0;
}

/* Parsing template */
struct config_tmpl config_mip6[] = {
    { "homeaddr", set_homeaddr, SIOCAHOMEADDR_MIP6},
    { "coaddr", set_coaddr, SIOCACOADDR_MIP6},
    { "enable_ha", set_enable_ha, 0},
    { "bu_lifetime", set_value, SIOCSBULIFETIME_MIP6},
    { "br_update", set_value, SIOCSBRUPDATE_MIP6},
    { "autoconfig", set_enable, SIOCSAUTOCONFIG_MIP6},
    { "ha_pref", set_value, SIOCSHAPREF_MIP6},
    { "hr_lifetime", set_value, SIOCSHRLIFETIME_MIP6},
    { "fwd_sl_unicast", set_enable, SIOCSFWDSLUNICAST_MIP6},
    { "fwd_sl_multicast", set_enable, SIOCSFWDSLMULTICAST_MIP6},
    { "prom_mode", set_enable, SIOCSPROMMODE_MIP6},
    { "bu_to_cn", set_enable, SIOCSBU2CN_MIP6},
    { "rev_tunnel", set_enable, SIOCSREVTUNNEL_MIP6},
    { "enable_br", set_enable, SIOCSENABLEBR_MIP6},
    { "debug", set_enable, SIOCSDEBUG_MIP6},
    { "eager_md", set_enable, SIOCSEAGERMD_MIP6},
    { NULL, NULL, -1 }
};

static void
mip6_init(void)
{
    int retval;
    if ((retval = upd_kernel(SIOCSATTACH_MIP6, NULL)) > 0) {
        print_err(retval);
	printf(PROGNAME "cannot initialize \"mip6\" module.\n");
	exit(1);
    }
}

static int
read_config()
{
    FILE *configfile;
    char buf[160];
    int retval = 0;

    if ((configfile = fopen(configfilename, "r")) == NULL) {
	perror(configfilename);
	return -1;
    }

    while(fgets(buf, sizeof(buf), configfile) != NULL) {
	char *argptr;
	int   i;

	/* Remove last CR */
 	if (buf[strlen(buf) - 1] == '\n')
	    buf[strlen(buf) - 1] = '\0';

	/* Argptr is the second parameter in the config file or NULL */
 	if ((argptr = strchr(buf, ' ')) != NULL) {
	    *argptr = '\0';
	    argptr++;
	}

	/* Ignore empty lines and comments */
 	if (*buf == '\0' || *buf == '#')
	    continue;

	/* Depending on the first paramenter, call the parsing function */
	for(i = 0; config_mip6[i].comstring != NULL; i++)
     	if (strcmp(config_mip6[i].comstring, buf) == NULL) {
		retval = config_mip6[i].parse(argptr, config_mip6[i].command);
		break;
	    }

 	if (config_mip6[i].comstring == NULL)
	    printf(PROGNAME "ignored unknown option %s\n", buf);

 	if (retval < 0) {
	    printf(PROGNAME "error in %s while parsing %s\n",
		   configfilename, config_mip6[i].comstring);
	    break;
	}
    }

    if (ferror(configfile)) {
	perror("read error");
	retval = -1;
    }

    fclose(configfile);
    return retval;
}

static char *delcoaddr, *coaddr, *homeaddr, *hr_lifetime, *fwd_sl_unicast;
static char *autoconfig, *bu_lifetime, *enable_bu_to_cn, *enable_debug;
static char *enable_ha, *ha_pref, *fwd_sl_multicast, *prom_mode, *enable_br;
static char *enable_rev_tunnel, *br_update, *eager_md, *release;

int
main(int argc, char *argv[])
{
    int ch;

    /*signal(SIGTERM, mip6_exit);*/

    if (getuid() != 0){
        printf(PROGNAME "permission denied\n");
        exit(1);
    }

    if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
        err(1, "socket");

    while ((ch = getopt(argc, argv, "F:H:E:f:b:w:y:l:hgxu:m:p:r:t:q:d:a:e:")) != -1)
	switch(ch) {
	case 'F':
	    coaddr = optarg;
	    break;
	case 'H':
	    homeaddr = optarg;
	    break;
	case 'l':
	    hr_lifetime = optarg;
	    break;
	case 'u':
	    fwd_sl_unicast = optarg;
	    break;
	case 'm':
	    fwd_sl_multicast = optarg;
	    break;
	case 'a':
	    autoconfig = (char *)1;
	    break;
	case 'r':
	    enable_bu_to_cn = optarg;
	    break;
	case 'd':
	    enable_debug = optarg;
	    break;
	case 'E':
	    delcoaddr = optarg;
	    break;
	case 'f':
	    configfilename = optarg;
	    break;
	case 'g':
	    enable_ha = (void *)1;
	    startmip6 = 1;
	    break;
	case 'x':
	    release = (void *)1;
	    break;
	case 'h':
	    usage();
	    break;
	case 'p':
	    prom_mode = optarg;
	    break;
	case 'y':
	    ha_pref = optarg;
	    break;
	case 'q':
	    enable_br = optarg;
	    break;
	case 'w':
	    br_update = optarg;
	    break;
	case 't':
	    enable_rev_tunnel = optarg;
	    break;
	case 'b':
	    bu_lifetime = optarg;
	    break;
	case 'e':
	    eager_md = optarg;
	    break;
	default:
	    usage();
	}
    argv += optind;
    argc -= optind;

    if (optind < 2)
        usage();

    /* -f is the only switch allowed */
    if (configfilename &&
       (delcoaddr || coaddr || homeaddr || hr_lifetime ||
        fwd_sl_unicast || autoconfig || bu_lifetime || enable_bu_to_cn ||
        enable_debug || fwd_sl_multicast || prom_mode || enable_br ||
        enable_rev_tunnel || br_update || ha_pref || eager_md || release))
        usage();

    /* -E is the only switch allowed */
    if (delcoaddr &&
       (coaddr || homeaddr || hr_lifetime ||
        fwd_sl_unicast || autoconfig || bu_lifetime || enable_bu_to_cn ||
        enable_debug || fwd_sl_multicast || prom_mode || enable_br ||
        enable_rev_tunnel || br_update || ha_pref || eager_md || release))
        usage();

    /* -x is the only switch allowed */
    if (release &&
       (delcoaddr || coaddr || homeaddr || hr_lifetime ||
        fwd_sl_unicast || autoconfig || bu_lifetime || enable_bu_to_cn ||
        enable_debug || fwd_sl_multicast || prom_mode || enable_br ||
        enable_rev_tunnel || br_update || ha_pref || eager_md))
        usage();

    /* Only one of -a, -H and -g allowed */
    if (autoconfig &&
       (homeaddr || enable_ha))
        usage();
    if (homeaddr &&
       (autoconfig || enable_ha))
        usage();
    if (enable_ha &&
       (homeaddr || autoconfig))
        usage();

    /* -F or -e not allowed if homeagent */
    if (enable_ha &&
       (coaddr || eager_md))
	usage();

    /* -m, -u, -y and -t only allowed if homeagent */
    if (fwd_sl_unicast &&
       (autoconfig || homeaddr))
	usage();
    if (fwd_sl_multicast &&
       (autoconfig || homeaddr))
	usage();
    if (ha_pref &&
       (autoconfig || homeaddr))
	usage();
    if (enable_rev_tunnel &&
       (autoconfig || homeaddr))
	usage();

    if (configfilename) {
	if (read_config() < 0) {
	    printf(PROGNAME "error reading configuration file\n");
	    exit(1);
	}
    }

    if (delcoaddr)
 	if (del_coaddr(delcoaddr, SIOCDCOADDR_MIP6) > 0)
 	    exit(1);

    if (autoconfig)
 	if (set_enable(NULL, SIOCSAUTOCONFIG_MIP6) > 0)
 	    exit(1);

    if (homeaddr)
 	if (set_homeaddr(homeaddr, SIOCAHOMEADDR_MIP6) > 0)
 	    exit(1);

#if 0
    /*XXXYYY*/
    if (enable_ha)
	if (set_enable(NULL, SIOCSENABLEHA_MIP6) > 0)
	    exit(1);
#endif

    if (release)
	if (set_enable(NULL, SIOCSRELEASE_MIP6) > 0)
	exit(1);

    if (coaddr)
	if (set_coaddr(coaddr, SIOCACOADDR_MIP6) > 0)
	    exit(1);

    if (hr_lifetime)
	if (set_value(hr_lifetime, SIOCSHRLIFETIME_MIP6) > 0)
	    exit(1);

    if (fwd_sl_unicast)
	if (set_enable(fwd_sl_unicast, SIOCSFWDSLUNICAST_MIP6) > 0)
	    exit(1);

    if (fwd_sl_multicast)
	if (set_enable(fwd_sl_multicast, SIOCSFWDSLMULTICAST_MIP6) > 0)
	    exit(1);

    if (enable_bu_to_cn)
	if (set_enable(enable_bu_to_cn, SIOCSBU2CN_MIP6) > 0)
	    exit(1);

    if (enable_debug)
	if (set_enable(enable_debug, SIOCSDEBUG_MIP6) > 0)
	    exit(1);

    if (prom_mode)
	if (set_enable(prom_mode, SIOCSPROMMODE_MIP6) > 0)
	    exit(1);

    if (ha_pref)
	if (set_value(ha_pref, SIOCSHAPREF_MIP6) > 0)
	    exit(1);

    if (enable_br)
	if (set_enable(enable_br, SIOCSENABLEBR_MIP6) > 0)
	    exit(1);

    if (br_update)
	if (set_value(br_update, SIOCSBRUPDATE_MIP6) > 0)
	    exit(1);

    if (enable_rev_tunnel)
	if (set_enable(enable_rev_tunnel, SIOCSREVTUNNEL_MIP6) > 0)
	    exit(1);

    if (bu_lifetime)
	if (set_value(bu_lifetime, SIOCSBULIFETIME_MIP6) > 0)
	    exit(1);

    if (eager_md)
	if (set_enable(eager_md, SIOCSEAGERMD_MIP6) > 0)
	    exit(1);

    if (startmip6) /* Should be last */
	mip6_init();

    return 0;
}
