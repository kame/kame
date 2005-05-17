#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include "config.h"

extern int parse(int, FILE *);

int
parse_config(type, filename)
	int type;
	const char *filename;
{
	FILE *conf;
	int error;

	conf = fopen(filename, "r");
	if (conf == NULL) {
		return (-1);
	}
	error = parse(type, conf);
	fclose(conf);
	return (error);
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
config_get_prefixtable(ret, cfe_head)
	struct config_entry **ret;
	struct config_entry *cfe_head;
{
	return (config_get_list(CFT_PREFIXTABLELIST, ret, cfe_head));
}
