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
struct mld_hdr {
        struct icmp6_hdr        mld_icmp6_hdr;
        struct in6_addr         mld_addr; /* multicast address */
};

#define mld_type       mld_icmp6_hdr.icmp6_type
#define mld_code       mld_icmp6_hdr.icmp6_code
#define mld_cksum      mld_icmp6_hdr.icmp6_cksum
#define mld_maxdelay   mld_icmp6_hdr.icmp6_data16[0]
#define mld_reserved   mld_icmp6_hdr.icmp6_data16[1]

