#include_next <netinet/icmp6.h>

/*
 *      Router Renumbering (not implemented on Linux)
 */

#define ICMP6_ROUTER_RENUMBERING        138     /* router renumbering */
#define ICMP6_ROUTER_RENUMBERING_COMMAND  0     /* rr command */
#define ICMP6_ROUTER_RENUMBERING_RESULT   1     /* rr result */
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255     /* rr seq num reset */


/*
 *	Multicast Listener Discovery
 */
struct mld6_hdr {
        struct icmp6_hdr        mld6_hdr;
        struct in6_addr         mld6_addr; /* multicast address */
};

#define mld6_type       mld6_hdr.icmp6_type
#define mld6_code       mld6_hdr.icmp6_code
#define mld6_cksum      mld6_hdr.icmp6_cksum
#define mld6_maxdelay   mld6_hdr.icmp6_data16[0]
#define mld6_reserved   mld6_hdr.icmp6_data16[1]

