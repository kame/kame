/*
 * draft-ietf-dhc-v6exts-10
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dhcp6opt.h>

static struct dhcp6_opt dh6opttab[] = {
	/* IP Address Extension */
	{ 1, OL6_N,	"IP Address",			OT6_NONE, },

	/* General Extension */
	{ 2, 4,		"Time Offset",			OT6_NUM, },
	{ 3, OL6_N,	"IEEE 1003.1 POSIX Timezone",	OT6_STR, },
	{ 6, OL6_16N,	"Domain Name Server",		OT6_V6, },
	{ 10, OL6_N,	"Domain Name",			OT6_STR, },

	/* Application and Service Parameters */
	{ 16, OL6_N,	"Directory Agent",		OT6_NONE, },
	{ 17, OL6_N,	"Service Scope"	,		OT6_NONE, },
	{ 18, OL6_16N,	"Network Time Protocol Servers", OT6_V6, },
	{ 19, OL6_N,	"NIS Domain",			OT6_STR, },
	{ 20, OL6_16N,	"NIS Servers",			OT6_V6, },
	{ 21, OL6_N,	"NIS+ Domain",			OT6_STR, },
	{ 22, OL6_16N,	"NIS+ Servers",			OT6_V6, },

	/* TCP Parameters */
	{ 32, 4,	"TCP Keepalive Interval",	OT6_NUM, },

	/* DHCPv6 Extensions */
	{ 40, 4,	"Maximum DHCPv6 Message Size",	OT6_NUM, },
	{ 41, OL6_N,	"DHCP Retransmission and Configuration Parameter",
							OT6_NONE, },
	{ 48, OL6_N,	"Platform Specific Information", OT6_NONE, },
	{ 49, OL6_N,	"Platform Class Identifier",	OT6_STR, },
	{ 64, OL6_N,	"Class Identifier",		OT6_STR, },
	{ 66, 16,	"Reconfigure Multicast Address", OT6_V6, },
	{ 67, 16,	"Renumber DHCPv6 Server Address",
							OT6_V6, },
	{ 68, OL6_N,	"DHCP Relay ICMP Error Message", OT6_NONE, },
	{ 84, OL6_N,	"Client-Server Authentication",	OT6_NONE, },
	{ 85, 4,	"Client Key Selection",		OT6_NUM, },

	/* End Extension */
	{ 65536, OL6_Z,	"End",				OT6_NONE, },

	{ 0 },
};

struct dhcp6_opt *dh6o_pad;
struct dhcp6_opt *dh6o_end;
int dhcp6_param[] = {
	-1,	2000,	4,	100,	1000,
	10,	2000,	2000,	12000,	10,
	12000,	2000,	10000,	1000,	5000,
	600000
};

void
dhcp6opttab_init()
{
	dh6o_pad = dhcp6opttab_bycode(0);
	dh6o_end = dhcp6opttab_bycode(65536);
}

struct dhcp6_opt *
dhcp6opttab_byname(name)
	char *name;
{
	struct dhcp6_opt *p;

	for (p = dh6opttab; p->code; p++)
		if (strcmp(name, p->name) == 0)
			return p;
	return NULL;
}

struct dhcp6_opt *
dhcp6opttab_bycode(code)
	u_int code;
{
	struct dhcp6_opt *p;

	for (p = dh6opttab; p->code; p++)
		if (p->code == code)
			return p;
	return NULL;
}
