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

#define OSPF_AUTH_SIMPLE_SIZE   8
#define OSPF_AUTH_MD5_SIZE      16
#define OSPF_AUTH_SIZE          (MAX(OSPF_AUTH_SIMPLE_SIZE, OSPF_AUTH_MD5_SIZE) / sizeof (u_int32_t))


struct ospf_mon_hdr       {};
struct ospf_hello_hdr {
  u_int32_t oh_if_id;           /* Interface ID */
  u_int8_t  oh_rtr_priority;    /* this router's priority */
  u_int8_t  oh_opts[3];         /* options capabilities supported by router  */
  u_int16_t oh_helloint;        /* seconds between this rtr's Hello packets  */
  u_int16_t oh_deadint;         /* seconds before declaring this router down */
  u_int32_t oh_dr;              /* ID of DR for this net */
  u_int32_t oh_bdr;             /* ID of the backup DR for this net */
};

struct ospf_db_hdr {
  u_int8_t  od_zero1;           /* 0                                        */
  u_int8_t  od_opts[3];         /* options capabilities supported by router */
  u_int16_t od_ifmtu;           /* Interface MTU                            */
  u_int8_t  od_zero2;           /* 0                                        */
  u_int8_t  od_i_m_ms;          /* I, M, MS                                 */
#define         bit_I   0x04      /*  Init bit                              */
#define         bit_M   0x02      /*  More bit                              */
#define         bit_MS  0x01      /*  Master/Slave bit                      */
  u_int32_t od_ddseq;           /* DD sequence number                       */
};

struct ospf_ls_req_hdr    {};
struct ospf_ls_update_hdr {};
struct ospf_ls_ack_hdr    {};

union ospf_types {            /* The rest of the packet */
    struct ospf_mon_hdr       ot_mon;
    struct ospf_hello_hdr     ot_hello;
    struct ospf_db_hdr        ot_database;
    struct ospf_ls_req_hdr    ot_ls_req;
    struct ospf_ls_update_hdr ot_ls_update;
    struct ospf_ls_ack_hdr    ot_ls_ack;
};

struct ospfhdr {
    u_int8_t         ospfh_vers;
#define OSPF_VERSION_3          3
    u_int8_t         ospfh_type;
#define         OSPF_PKT_MON    0       /* monitor request */
#define         OSPF_PKT_HELLO  1       /* hello */
#define         OSPF_PKT_DD     2       /* database description */
#define         OSPF_PKT_LSR    3       /* link state request */
#define         OSPF_PKT_LSU    4       /* link state update */
#define         OSPF_PKT_ACK    5       /* link state ack */
#define         OSPF_PKT_MAX    6
    u_int16_t        ospfh_length;      /* length of entire packet in bytes */
    u_int32_t        ospfh_rtr_id;      /* Router ID */
    u_int32_t        ospfh_area_id;     /* Area ID */
    u_int16_t        ospfh_cksum;
    u_int8_t         ospfh_instance;    /* Instance ID */
    u_int8_t         ospfh_zero;
    union ospf_types ospfh_un;
#define ospfh_mon       ospfh_un.ot_mon
#define ospfh_hello     ospfh_un.ot_hello
#define ospfh_database  ospfh_un.ot_database
#define ospfh_ls_req    ospfh_un.ot_ls_req
#define ospfh_ls_update ospfh_un.ot_ls_update
#define ospfh_ls_ack    ospfh_un.ot_ls_ack
};


struct ospf_prfx {
    u_int8_t      opx_plen;        /* PrefixLength                       */
    u_int8_t      opx_opts;        /* PrefixOptions                      */
#define         bit_NU   0x01          /* "no unicast" capability bit    */
#define         bit_LA   0x02          /* "local address" capability bit */
#define         bit_MC   0x04          /* "multicast bit" capability bit */
#define         bit_P    0x08          /* "propagate" bit                */
    u_int16_t     opx_metric;      /* Metric                             */
};



struct lsahdr {
    u_int16_t     lsa_age;         /* LS age                             */
    u_int16_t     lsa_lstype;      /* LS type                            */
    u_int32_t     lsa_lsid;        /* Link State ID                      */
    u_int32_t     lsa_adv_rtr;     /* Advertising Router (originated)    */
      int32_t     lsa_seq;         /* LS sequence number                 */
    u_int16_t     lsa_lscksum;     /* LS checksum                        */
    u_int16_t     lsa_length;      /* length includes LSA header         */
};

/**      LS type        **/
#define         bit_U   0x8000
#define         bit_S2  0x4000
#define         bit_S1  0x2000

#define LS_STUB         0
#define LS_RTR          1
#define LS_NET          2
#define LS_SUM_NET      3
#define LS_SUM_ASB      4
#define LS_ASE          5
#define LS_GM           6
#define LS_NSSA         7
#define LS_LINK         8
#define LS_PREFIX       9
#define LS_MAX          9



/*  Router-LSAs:             LS type = 1  */
struct rtr_lsa {
    u_int8_t     rtr_bits;  
#define bit_W  0x08      /* wild-card multicast receiver */
#define bit_V  0x04      /* virtual link endpoint        */
#define bit_E  0x02      /* AS border router             */
#define bit_B  0x01      /* area border router           */
    u_int8_t     rtr_opts[3];      /* Options            */
};

/* describe each router interface */
struct rtr_lsa_ifs {
    u_int8_t     rli_type;     /* Type                  */
    u_int8_t     rli_zero;     /*  0                    */
    u_int16_t    rli_metric;   /* Metric                */
    u_int32_t    rli_if_id;    /* Interface ID          */
    u_int32_t    rli_nif_id;   /* Neighbor Interface ID */
    u_int32_t    rli_nr_id;    /* Neighbor Router ID    */
};



/*  Intra-Area-Prefix-LSAs:  LS type = 9  */
struct iap_lsa {
    u_int16_t     iap_num;         /* # prefixes                    */
    u_int16_t     iap_ref_lstype;  /* Referenced LS type            */
    u_int32_t     iap_ref_lsid;    /* Referenced Link State ID      */
    u_int32_t     iap_ref_adv_rtr; /* Referenced Advertising Router */
};



/*  draft-ietf-ospf-ospfv6-04.txt  */

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF           89
#endif
#define ALLSPFROUTERS          "ff02::5"
#define ALLDROUTERS            "ff02::6"
#define OSPF_HOPLIMIT          IP_DEFAULT_MULTICAST_TTL

#define OSPF_BUFSIZ            65535
#define OSPF_MAXPKT            65535

#define OSPF_T_HELLOINTERVAL   10
#define InitialSequenceNumber  0x80000001
#define MaxSequenceNumber      0x7fffffff


struct area {
  struct area    *ar_next;
  struct area    *ar_prev;
  u_int32_t       ar_id;     /*  Area ID (net-order)  */
};


/* Per interface info. */
struct ospflink {
  struct area    *ol_area;   /*  this I/F belongs to     */
  struct rpcb    *ol_nbrs;   /*  current neighbor list   */
};


void ospf_init               __P(());
void ospf_hello              __P(());
void ospf_sendmsg            __P((struct sockaddr_in6 *,
				  struct in6_pktinfo *,
				  int));
void ospf_input              __P(());
void ospf_process_hello      __P((struct ospfhdr *, struct ifinfo *));
void ospf_process_dd         __P((struct ospfhdr *, struct rpcb *));
int  ospf_make_dump          __P((u_char *));

u_int16_t lsa_cksum          __P((u_char *, int));
u_int32_t GET_IN6_IF_ID_OSPF __P((struct in6_addr *));
