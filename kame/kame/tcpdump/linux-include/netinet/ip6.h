/*
 *      IPv6 TLV options.
 */
#define IP6OPT_PAD1	0
#define IP6OPT_PADN	1
#define IP6OPT_RTALERT	20
#define IP6OPT_JUMBO    194

#define IP6OPT_JUMBO_LEN        6
#define IP6OPT_RTALERT_LEN      4
#define IP6OPT_MINLEN           2

#include_next <netinet/ip6.h>
