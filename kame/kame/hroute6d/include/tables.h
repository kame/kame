/*
 * Copyright(C)1997 by Hitachi, Ltd.
 */

/*
 * This structure holds prefix length for a prefix. In case of a prefix with
 * multiple prefix length, it will be a linked list of structures.
 */
struct rt_plen {
	struct rt_plen   *rp_next;   /* next prefix length entry */
	struct rt_plen   *rp_prev;   /* previous prefix length entry */
	struct rt_plen   *rp_ndst;   /* Next dest using same gateway */
	struct rt_plen   *rp_pdst;   /* Previous dest using the same gateway */
	struct tree_node *rp_leaf;   /* back pointer to leaf for prefix */
	struct gateway   *rp_gway;   /* pointer to the gateway */
	u_short           rp_tag;    /* Tag value for the route */
	u_char            rp_len;    /* Prefix length */
	u_char            rp_metric; /* Metric for the route */
	u_int             rp_timer;  /* timer for validity */
	u_int             rp_flags;  /* Flags used for the kernel update */
	u_int             rp_state;  /* State for internal operation */
};

/*
 * This is the structure for gateway entry in routing table.
 */
struct gateway {
	struct gateway *gw_next; /* Next entry */
	struct in6_addr gw_addr; /* Gateway Link local address */
	struct interface *gw_ifp;/* Pointer to interface gateway belongs to */
	struct rt_plen *gw_dest; /* List of destinations using this gateway */
};

/*
 * This is the structure for every node in tree.
 * Union with diffrent structures for leaf and internal node.
 */
#define LEAF_BIT_POSN    255
struct tree_node {
	struct tree_node  *tn_backp; /* Pointer to parent node in tree */
	u_char             tn_bposn; /* Bit position to be checked */  
	char               tn_bmask; /* Bit mask to be used for comparing */
	union {
		struct {
			struct in6_addr tnu_key; /* Destination address */  
			struct rt_plen *tnu_rtp; /* Linked list of dests */
		} leaf;
		struct {
			int tnu_off; /* Offset in bytes in in6_addr to
					be skipped comparing */
			struct tree_node *tnu_lptr; /* Pointer to left node */
			struct tree_node *tnu_rptr; /* Pointer to right node */
		} node;
	} tn_node;
#define key	tn_node.leaf.tnu_key
#define dst	tn_node.leaf.tnu_rtp
#define lptr	tn_node.node.tnu_lptr
#define rptr	tn_node.node.tnu_rptr
#define boff	tn_node.node.tnu_off
};

/*
 * This is the structure for the head of the local cache tree.
 */
#define HEAD_BIT_POSN	0
#define HEAD_BIT_OFFSET	0
struct tree_head {
	struct  tree_node  th_node[3];
};
#define TREE_LEFT	0
#define TREE_HEAD	1
#define TREE_RIGHT	2

/* 
 * The route state values 
 */
#define RTS6_CHANGED	0x001	/* Changed route entry */
#define RTS6_STATIC	0x002	/* Static route entry not timed */
#define RTS6_DEFAULT	0x004	/* Default Route entry */
#define RTS6_KERNEL	0x008	/* Learned from kernel and not timed */
#define RTS6_LOOPBACK	0x010	/* Noone set this flag... USELESS !! */
#define RTS6_INTERFACE	0x020	/* route to interface */ 
#define RTS6_PTOP	0x040
#define RTS6_BLACKHOLE	0x080	/* blackhole route (for aggregated prefix) */
