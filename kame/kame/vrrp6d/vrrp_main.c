/*	$KAME: vrrp_main.c,v 1.5 2003/02/19 10:10:01 ono Exp $	*/

/*
 * Copyright (C) 2002 WIDE Project.
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
 * Copyright (c) 2001,2002 Sebastien Petit <spe@bsdfr.org>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "vrrp_main.h"

void
vrrp_main_pre_init(struct vrrp_vr * vr)
{
	bzero(vr, sizeof(*vr));
	vr->priority = 100;
	vr->adv_int = VRRP_DEFAULT_ADV_INT;
	vr->preempt_mode = 1;

	return;
}

char
vrrp_main_post_init(struct vrrp_vr * vr)
{
	int             size = MAX_IP_ALIAS;
	struct ether_addr *ethaddr;
	char macaddr[18];
	
	snprintf(macaddr, 18, "00:00:5e:00:01:%02d", vr->vr_id);
	macaddr[17] = '\0';
	
	if ((ethaddr = ether_aton(macaddr)) == NULL) {
		syslog(LOG_WARNING, "mac address incorrect");
		return -1;
	}

	bcopy(ethaddr, &vr->ethaddr, ETHER_ADDR_LEN);

	vr->skew_time = (256 - vr->priority) / 256;
	vr->master_down_int = (3 * vr->adv_int) + vr->skew_time;
	vrrp_misc_get_if_infos(vr->vr_if->if_name, &vr->vr_if->ethaddr, vr->vr_if->ip_addrs, &size);
	vr->vr_if->nb_ip = size;

	return 0;
}

void
vrrp_main_print_struct(struct vrrp_vr * vr)
{
	int             cpt;
	char addr[NI_MAXHOST];

	fprintf(stderr, "VServer ID\t\t: %u\n", vr->vr_id);
	fprintf(stderr, "VServer PRIO\t\t: %u\n", vr->priority);
	fprintf(stderr, "VServer ETHADDR\t\t: %s\n", ether_ntoa(&vr->ethaddr));
	fprintf(stderr, "VServer IPs\t\t: %s\n", inet_ntop(AF_INET6, &vr->vr_ip[0].addr, &addr[0], sizeof(addr)) ? addr : "<NULL>");
	fprintf(stderr, "VServer ADV_INT\t\t: %u\n", vr->adv_int);
	fprintf(stderr, "VServer MASTER_DW_TM\t: %u\n", vr->master_down_int);
	fprintf(stderr, "VServer SKEW_TIME\t: %u\n", vr->skew_time);
	fprintf(stderr, "VServer State\t\t: %u\n", vr->state);
	fprintf(stderr, "VServer VRRPIF_NAME\t: %s\n", vr->vrrpif_name);
	fprintf(stderr, "Server IF_NAME\t\t: %s\n", vr->vr_if->if_name);
	fprintf(stderr, "Server NB_IP\t\t: %u\n", vr->vr_if->nb_ip);
	fprintf(stderr, "Server IPs\t\t:\n");
	for (cpt = 0; cpt < vr->vr_if->nb_ip; cpt++)
	  fprintf(stderr, "\t%s\n", inet_ntop(AF_INET6, &vr->vr_if->ip_addrs[cpt], &addr[0], sizeof(addr)) ? addr : "<NULL>");
	fprintf(stderr, "Server ETHADDR\t\t: %s\n", ether_ntoa(&vr->vr_if->ethaddr));

	return;
}

int optflag_f;
int optflag_d;
char *vrrp_conf_file_name = NULL;

void
usage()
{
	printf("Usage: vrrp6d [options] \n");
	printf("Options:\n");
	printf("   -c file config file.\n");
	printf("   -f      run as foreground mode.\n");
	printf("   -d      show more verbose messages.\n");
	exit(1);
}

void
vrrp_main_parse_options(int argc, char **argv)
{
	int ch;

	optflag_f = optflag_d = 0;
	while ((ch = getopt(argc, argv, "c:fdh")) != -1)
		switch (ch) 
		{
		case 'f':
			optflag_f = 1;
			break;
		case 'c':
			vrrp_conf_file_name = optarg;
			break;
		case 'd':
			optflag_d = 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
}


int
main(int argc, char **argv)
{
	FILE           *stream;
	int             coderet = 0;
	struct vrrp_vr *vr;
	int		sd_bpf = 0;


	vrrp_main_parse_options(argc, argv);

	if (!optflag_f)
		daemon(0, 0);

	if (vrrp_conf_file_name == NULL) {
		vrrp_conf_file_name = VRRP_CONF_FILE_NAME;
	}
	if ((stream = vrrp_conf_open_file(vrrp_conf_file_name)) == NULL)
		return -1;
	/* Initialisation of struct vrrp_vr * adresses table */
	bzero(&vr_ptr, sizeof(vr_ptr));
	syslog(LOG_NOTICE, "initializing timers");
	vrrp_timer_init();
	syslog(LOG_NOTICE, "reading configuration file %s", VRRP_CONF_FILE_NAME);

	vrrp_signal_initialize();

	while (!coderet) {
		vr = (struct vrrp_vr *) malloc(sizeof(struct vrrp_vr));
		bzero(vr, sizeof(*vr));
		vrrp_main_pre_init(vr);
		coderet = vrrp_conf_lecture_fichier(vr, stream);
		if (coderet < 0)
			return coderet;
		if (vrrp_main_post_init(vr) < 0) {
			return -1;
		}
		/*
		 * Don't need ethaddr list anyway see vrrp_proto.h if
		 * (vr->vr_if->p == NULL || vr->vr_if->d == NULL) if
		 * (vrrp_list_initialize(vr, &vr->vr_if->ethaddr) < 0) return
		 * -1;
		 */

		vrrp_interface_owner_verify(vr);
		sd_bpf = vrrp_misc_search_sdbpf_entry(vr->vr_if->if_name);
		if (sd_bpf < 0) {
			sd_bpf = vrrp_network_open_bpf(vr);
			if (sd_bpf < 0)
				return sd_bpf;
		}
		vr->sd_bpf = sd_bpf;
		if (vrrp_multicast_open_socket(vr) == -1)
			return -1;
		vrrp_main_print_struct(vr);

		if (vr_ptr_pos == 255) {
			syslog(LOG_ERR, "cannot configure more than 255 VRID... exiting\n");
			exit(-1);
		}
		vr_ptr[vr_ptr_pos++] = vr;
	}

	if (vrrp_state_initialize_all() == -1)
		return -1;

	if (!optflag_f)
		syslog(LOG_NOTICE, "launching in background into daemon mode");

	vrrp_state_start();

	return 0;
}
