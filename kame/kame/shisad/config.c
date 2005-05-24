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
