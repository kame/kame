/*	$KAME: config.c,v 1.4 2005/10/04 07:36:57 keiichi Exp $	*/

/*
 * Copyright (C) 2005 WIDE Project.  All rights reserved.
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
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "config.h"

struct config_entry *config_params;

int
parse_config(type, filename)
	int type;
	const char *filename;
{
	return(parse(type, filename, &config_params));
}

int
config_get_number(type, ret, cfe_head)
	int type;
	int *ret;
	struct config_entry *cfe_head;
{
	while (cfe_head != NULL) {
		if (cfe_head->cfe_type == type) {
			*ret = cfe_head->cfe_number;
			return (0);
		}
		cfe_head = cfe_head->cfe_next;
	}
	return (-1);
}

int
config_get_string(type, ret, cfe_head)
	int type;
	char **ret;
	struct config_entry *cfe_head;
{
	while (cfe_head != NULL) {
		if (cfe_head->cfe_type == type) {
			*ret = cfe_head->cfe_ptr;
			return (0);
		}
		cfe_head = cfe_head->cfe_next;
	}
	return (-1);
}

int
config_get_list(type, ret, cfe_head)
	int type;
	struct config_entry **ret;
	struct config_entry *cfe_head;
{
	while (cfe_head != NULL) {
		if (cfe_head->cfe_type == type) {
			*ret = cfe_head->cfe_list;
			return (0);
		}
		cfe_head = cfe_head->cfe_next;
	}
	return (-1);
}

int
config_get_interface(ifname, ret, cfe_head)
	const char *ifname;
	struct config_entry **ret;
	struct config_entry *cfe_head;
{
	struct config_entry *cfe;

	for (cfe = cfe_head; cfe != NULL; cfe = cfe->cfe_next) {
		if (cfe->cfe_type != CFT_INTERFACE)
			continue;
		if (strcmp(cfe->cfe_ptr, ifname) == 0) {
			*ret = cfe->cfe_list;
			return (0);
		}
	}

	*ret = NULL;
	return (-1);
}

int
config_get_prefixtable(ret, cfe_head)
	struct config_entry **ret;
	struct config_entry *cfe_head;
{
	return (config_get_list(CFT_PREFIXTABLELIST, ret, cfe_head));
}

int
config_get_static_tunnel(ret, cfe_head)
	struct config_entry **ret;
	struct config_entry *cfe_head;
{
	return (config_get_list(CFT_STATICTUNNELLIST, ret, cfe_head));
}

int
config_get_ipv4_dummy_tunnel(ret, cfe_head)
	struct config_entry **ret;
	struct config_entry *cfe_head;
{
	return (config_get_list(CFT_IPV4DUMMYTUNNELLIST, ret, cfe_head));
}
