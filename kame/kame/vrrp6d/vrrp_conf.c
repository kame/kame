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
 * $Id: vrrp_conf.c,v 1.2 2002/07/09 07:28:59 ono Exp $
 */

#include "vrrp_conf.h"

int 
vrrp_conf_ident_option_arg(char *chaine, char *option, char *arg)
{
	int             i = 0;
	char           *ptr;

	while (isalpha(chaine[i]) && chaine[i] != 0) {
		i++;
		if (i > 1022) {
			syslog(LOG_ERR, "a bad line was found in your configuration file (line > 1024 char), exiting...");
			exit(-1);
		}
	}
	if (!i) {
		syslog(LOG_ERR, "a bad line was found in your configuration file: %s\n", chaine);
		exit(-1);
	}
	strncpy(option, chaine, i);
	option[i] = '\0';
	while (chaine[i] != '=' && chaine[i] != 0) {
		i++;
		if (i > 1021) {
			syslog(LOG_ERR, "a bad line was found in your configuration file (line > 1024 char), exiting...");
			exit(-1);
		}
	}
	i++;
	while (chaine[i] == ' ' && chaine[i] != 0) {
		i++;
		if (i > 1021) {
			syslog(LOG_ERR, "a bad line was found in your configuration file (line > 1024 char), exiting...");
			exit(-1);
		}
	}
	ptr = &chaine[i];
	strncpy(arg, ptr, strlen(chaine) - i);
	if (arg[strlen(chaine) - i - 1] == '\n')
		i++;
	arg[strlen(chaine) - i] = '\0';

	return 0;
}

char          **
vrrp_conf_split_args(char *args, char delimiter)
{
	char          **tabargs;
	int             i, j, nbargs = 0;
	char           *ptr;

	tabargs = (char **)malloc(sizeof(char *) * VRRP_CONF_MAX_ARGS);
	bzero(tabargs, sizeof(char **) * VRRP_CONF_MAX_ARGS);
	if (!tabargs) {
		syslog(LOG_ERR, "cannot malloc memory : %m");
		exit(EXIT_FAILURE);
	}
	i = 0;
	while (i < strlen(args)) {
		ptr = &args[i];
		j = 0;
		while (ptr[j] != delimiter && ptr[j] != 0 && (isalnum(ptr[j]) || ptr[j] == ':' || ptr[j] == '/')) {
			i++;
			j++;
		}
		tabargs[nbargs] = (char *)calloc(j + 1, 1);
		strncpy(tabargs[nbargs], ptr, j);
		i++;
		while (!isalnum(args[i]) && args[i] != ':' && args[i] != '/' && args[i])
			i++;
		nbargs++;
		if (nbargs >= VRRP_CONF_MAX_ARGS) {
			syslog(LOG_ERR, "too many arguments in the configuration file");
			exit(EXIT_FAILURE);
		}
	}

	return tabargs;
}

void 
vrrp_conf_freeargs(char **temp)
{
	int             i = 0;

	while (temp[i]) {
		free(temp[i]);
		temp[i] = NULL;
		i++;
	}
	free(temp);

	return;
}

FILE           *
vrrp_conf_open_file(char *name)
{
	FILE           *stream;
	struct stat     st;

	stream = fopen(name, "r");
	if (!stream) {
		syslog(LOG_ERR, "cannot open configuration file %s: %m", name);
		return NULL;
	}
	if (lstat(name, &st) == -1) {
		syslog(LOG_ERR, "cannot call lstat(): %m");
		return NULL;
	}
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		syslog(LOG_ERR, "%s is not a regular file", name);
		return NULL;
	}
	return stream;
}

char 
vrrp_conf_close_file(FILE * stream)
{
	if (fclose(stream) == EOF) {
		syslog(LOG_ERR, "can't close the file stream FILE *stream: %m\n");
		return -1;
	}
	return 0;
}

char 
vrrp_conf_lecture_fichier(struct vrrp_vr * vr, FILE * stream)
{
	char            ligne[1024] = "#";
	char          **temp;
	char          **temp2;
	char            option[1024], arg[1024];
	int             i, j;
	fpos_t          pos;

	fgetpos(stream, &pos);
	if (!pos) {
		while (ligne[0] == '#' || ligne[0] == 0 || ligne[0] == '\n')
			fgets(ligne, 1024, stream);
		if (strncmp(ligne, "[VRID]\n", sizeof(ligne))) {
			syslog(LOG_ERR, "configuration file error ! cannot see [VRID] section");
			return -1;
		}
		fgets(ligne, 1024, stream);
	}
	while (!feof(stream) && strncmp(ligne, "[VRID]\n", sizeof(ligne))) {
		if (ligne[0] != 0 && ligne[0] != '\n' && ligne[0] != '#') {
			if (feof(stream))
				break;
			vrrp_conf_ident_option_arg(ligne, option, arg);
			if (!strcmp(option, "addr")) {
				temp = vrrp_conf_split_args(arg, ',');
				i = 0;
				while (temp[i])
					i++;
				vr->vr_ip = (struct vrrp_vip *) calloc(i, sizeof(struct vrrp_vip) + 1);
				vr->vr_netmask = (u_int *) calloc(i, sizeof(u_int) + 1);
				bzero(vr->vr_ip, sizeof(struct vrrp_vip));
				i = 0;
				while (temp[i] && (i < VRRP_CONF_MAX_ARGS)) {
					temp2 = vrrp_conf_split_args(temp[i], '/');
					j = 0;
					while (temp2[j])
						j++;
					if (j != 2) {
						syslog(LOG_ERR, "bad value in the configuration file for addr option: %s", arg);
						exit(-1);
					}
					if (inet_pton(AF_INET6, temp2[0], &vr->vr_ip[i].addr) == 0) {
						syslog(LOG_ERR, "inet_pton error");
						return -1;
					}
					vr->vr_netmask[i] = atoi(temp2[1]);
					i++;
				}
				vr->cnt_ip = i;
				vrrp_conf_freeargs(temp);
			}
			if (!strcmp(option, "interface")) {
				temp = vrrp_conf_split_args(arg, ',');
				if (!(vr->vr_if = vrrp_misc_search_if_entry(temp[0]))) {
					vr->vr_if = (struct vrrp_if *) malloc(sizeof(struct vrrp_if));
					strncpy(vr->vr_if->if_name, temp[0], sizeof(vr->vr_if->if_name));
					vr->vr_if->if_index = if_nametoindex(temp[0]);
				}
				vrrp_conf_freeargs(temp);
			}
			if (!strcmp(option, "vrrpinterface")) {
				temp = vrrp_conf_split_args(arg, ',');
				strncpy(vr->vrrpif_name, temp[0], sizeof(vr->vrrpif_name));
				vr->vrrpif_index = if_nametoindex(temp[0]);
				vrrp_conf_freeargs(temp);
			}
			if (!strcmp(option, "serverid")) {
				temp = vrrp_conf_split_args(arg, ',');
				vr->vr_id = atoi(temp[0]);
				vrrp_conf_freeargs(temp);
			}
			if (!strcmp(option, "priority")) {
				temp = vrrp_conf_split_args(arg, ',');
				vr->priority = atoi(temp[0]);
				vrrp_conf_freeargs(temp);
			}
			if (!strcmp(option, "password")) {
				temp = vrrp_conf_split_args(arg, ',');
				vr->password = (char *)calloc(8, 1);
				strncpy(vr->password, temp[0], 8);
				vrrp_conf_freeargs(temp);
				vr->auth_type = 1;
			}
		}
		fgets(ligne, 1024, stream);
	}
	if (feof(stream))
		return 1;

	return 0;
}
