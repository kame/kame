/*
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
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

struct rpstat {
  int rps_connretry;
};

struct rpcb {
  struct  rpcb        *rp_next;
  struct  rpcb        *rp_prev;
  struct  sockaddr_in6 rp_addr;     /* socket address/port                 */
  struct  in6_addr     rp_gaddr;    /* rtr's global address     (if known) */
  struct  in6_addr     rp_laddr;    /* rtr's link-local address (if known) */
  u_int32_t            rp_id;       /* Router ID, that the router told me  */
  u_int16_t            rp_as;       /* Autonomous System number            */
  u_int32_t	       rp_ebgp_as_prepends;/* # of iteration of prepended AS */
  int                  rp_socket;
  struct sockaddr_in6  rp_myaddr;   /* address of connection               */
  struct sockaddr_in6  rp_lcladdr;  /* if specified, use it as the source */
  struct ifinfo       *rp_ife;      /* interface                           */
  u_int32_t            rp_prefer;   /* preference (net-order)              */
  int                  rp_sfd[2];   /* parent/child pipe                   */

  byte		       rp_inpkt[BGPMAXPACKETSIZE]; /* input buffer */
  int		       rp_incc;	    /* watermark for the input buffer */
  int		       rp_inputmode; /* header or data */
  int		       rp_inlen; /* data length to be read */
#define BGP_READ_HEADER 0
#define BGP_READ_DATA   1

  struct _task        *rp_connect_timer;    /* ConnectRetryTimer           */
  struct _task        *rp_hold_timer;       /* HoldTimer                   */
  struct _task        *rp_keepalive_timer;  /* KeepAliveTimer              */
  byte                 rp_state;        /* Protocol State                  */

  struct rt_entry     *rp_adj_ribs_in;  /* Imported RTEs via BGP message   */
  struct rtproto      *rp_adj_ribs_out; /* Exporting RTEs of protocols     */

  u_long               rp_mode;         /* info bit                        */
  struct rpstat        rp_stat;         /* statistics                      */
#define                    BGPO_PASSIVE      0x01
#define                    BGPO_IFSTATIC     0x02
#define                    BGPO_IGP          0x04
#define                    BGPO_RRCLIENT     0x08
#define                    BGPO_ONLINK       0x10
#define                    BGPO_IDSTATIC     0x20
#define                    BGPO_NOSYNC       0x40
#define			   BGPO_NEXTHOPSELF  0x80

#define			   BGPO_EBGPSTATIC   0x0 /* XXX: currently, this is empty */
#define			   BGPO_IBGPSTATIC  (BGPO_RRCLIENT|BGPO_NOSYNC|\
					     BGPO_NEXTHOPSELF)
};


/*
 *   Interface information learned from the kernel or config file.
 *             (smaller)
 */
struct ifinfo {
  struct ifinfo       *ifi_next;
  struct ifinfo       *ifi_prev;
  struct if_nameindex *ifi_ifn;
  struct in6_addr      ifi_laddr;  /* link-local      */
  struct in6_addr      ifi_gaddr;  /* global          */
  struct rt_entry     *ifi_rte;    /* I/F direct RTEs */
  int                  ifi_flags;  /* I/F flags */

#define               RTPROTO_NONE  0
#define               RTPROTO_IF    1
#define               RTPROTO_RIP   2
#define               RTPROTO_OSPF  3
#define               RTPROTO_BGP   4
#define               RTPROTO_AGGR  5
#define               RTPROTO_MAX   5
  caddr_t              ifi_rtpinfo[RTPROTO_MAX+1];
};

struct ifinfo *find_if_by_index  __P((u_int));
struct ifinfo *find_if_by_name   __P((char *));
struct ifinfo *find_if_by_addr   __P((struct in6_addr *));


#define MALLOC(p, type) { if (((p) = ((type *)malloc(sizeof(type)))) == NULL)\
			    fatalx("malloc");\
			  memset((p), 0, sizeof(type));}

struct rtproto {
  struct rtproto *rtp_next;
  struct rtproto *rtp_prev;
  char            rtp_type;
  union {
    struct ifinfo   *rtpu_if;
    struct rpcb     *rtpu_bgp;
    struct ripif    *rtpu_rip;
    struct rpcb     *rtpu_ospf;
  } rtp_rtpu;
#define rtp_if   rtp_rtpu.rtpu_if
#define rtp_bgp  rtp_rtpu.rtpu_bgp
#define rtp_rip  rtp_rtpu.rtpu_rip
#define rtp_ospf rtp_rtpu.rtpu_ospf
};


void             ifconfig     __P((void));
void             loconfig     __P((char *));
u_int32_t        get_32id     __P((void));

/*
 *    search
 */
struct rpcb     *rpcblookup   __P((struct rpcb *, u_int32_t));
struct rt_entry *find_rte     __P((struct rt_entry *, struct rt_entry *));
struct rtproto  *find_rtp     __P((struct rtproto  *, struct rtproto *));
int              find_nexthop __P((struct in6_addr *, struct in6_addr *,
				   struct ifinfo *));

/*
 * nexthop resolution
 */
int set_nexthop __P((struct in6_addr *, struct rt_entry *));
