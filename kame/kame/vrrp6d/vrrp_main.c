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
 *
 * $Id: vrrp_main.c,v 1.1 2002/07/09 07:19:20 ono Exp $
 */

#include "vrrp_main.h"

void
vrrp_main_pre_init(struct vrrp_vr * vr)
{
	vrrp_signal_initialize();
	bzero(vr, sizeof(*vr));
	vr->priority = 100;
	vr->adv_int = VRRP_DEFAULT_ADV_INT;
	vr->preempt_mode = 1;

	return;
}

void
vrrp_main_post_init(struct vrrp_vr * vr)
{
	int             size = MAX_IP_ALIAS;

	vr->ethaddr.octet[0] = 0x00;
	vr->ethaddr.octet[1] = 0x00;
	vr->ethaddr.octet[2] = 0x5E;
	vr->ethaddr.octet[3] = 0x00;
	vr->ethaddr.octet[4] = 0x01;
	vr->ethaddr.octet[5] = vr->vr_id;
	vr->skew_time = (256 - vr->priority) / 256;
	vr->master_down_int = (3 * vr->adv_int) + vr->skew_time;
	vrrp_misc_get_if_infos(vr->vr_if->if_name, &vr->vr_if->ethaddr, vr->vr_if->ip_addrs, &size);
	vr->vr_if->nb_ip = size;

	return;
}

void
vrrp_main_print_struct(struct vrrp_vr * vr)
{
	int             cpt;

	fprintf(stderr, "VServer ID\t\t: %u\n", vr->vr_id);
	fprintf(stderr, "VServer PRIO\t\t: %u\n", vr->priority);
	fprintf(stderr, "VServer ETHADDR\t\t: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", vr->ethaddr.octet[0], vr->ethaddr.octet[1], vr->ethaddr.octet[2], vr->ethaddr.octet[3], vr->ethaddr.octet[4], vr->ethaddr.octet[5]);
	fprintf(stderr, "VServer CNT_IP\t\t: %u\n", vr->cnt_ip);
	fprintf(stderr, "VServer IPs\t\t:\n");
	for (cpt = 0; cpt < vr->cnt_ip; cpt++)
		fprintf(stderr, "\t%s\n", inet_ntoa(vr->vr_ip[cpt].addr));
	fprintf(stderr, "VServer ADV_INT\t\t: %u\n", vr->adv_int);
	fprintf(stderr, "VServer MASTER_DW_TM\t: %u\n", vr->master_down_int);
	fprintf(stderr, "VServer SKEW_TIME\t: %u\n", vr->skew_time);
	fprintf(stderr, "VServer State\t\t: %u\n", vr->state);
	fprintf(stderr, "Server IF_NAME\t\t: %s\n", vr->vr_if->if_name);
	fprintf(stderr, "Server NB_IP\t\t: %u\n", vr->vr_if->nb_ip);
	fprintf(stderr, "Server IPs\t\t:\n");
	for (cpt = 0; cpt < vr->vr_if->nb_ip; cpt++)
		fprintf(stderr, "\t%s\n", inet_ntoa(vr->vr_if->ip_addrs[cpt]));
	fprintf(stderr, "Server ETHADDR\t\t: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", vr->vr_if->ethaddr.octet[0], vr->vr_if->ethaddr.octet[1], vr->vr_if->ethaddr.octet[2], vr->vr_if->ethaddr.octet[3], vr->vr_if->ethaddr.octet[4], vr->vr_if->ethaddr.octet[5]);

	return;
}

int
main(int argc, char **argv)
{
	FILE           *stream;
	int             coderet = 0;
	struct vrrp_vr *vr;
	int		sd_bpf = 0;

	daemon(0, 0);
	if ((stream = vrrp_conf_open_file(VRRP_CONF_FILE_NAME)) == NULL)
		return -1;
	/* Initialisation of struct vrrp_vr * adresses table */
	bzero(&vr_ptr, sizeof(vr_ptr));
	syslog(LOG_NOTICE, "initializing threads and all VRID");
	vrrp_thread_initialize();
	syslog(LOG_NOTICE, "reading configuration file %s", VRRP_CONF_FILE_NAME);
	while (!coderet) {
		vr = (struct vrrp_vr *) malloc(sizeof(struct vrrp_vr));
		bzero(vr, sizeof(*vr));
		vrrp_main_pre_init(vr);
		coderet = vrrp_conf_lecture_fichier(vr, stream);
		if (coderet < 0)
			return coderet;
		vrrp_main_post_init(vr);
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
		if (vrrp_thread_create_vrid(vr) == -1)
			return -1;
	}
	syslog(LOG_NOTICE, "launching in background into daemon mode");
	pthread_exit(NULL);

	return 0;
}
