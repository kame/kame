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

/*
 * Origin codes
 */
#define PATH_ORG_IGP            0     /* interior to the originating AS     */
#define PATH_ORG_EGP            1     /* route learned via EGP              */
#define PATH_ORG_XX             2     /* learned by some other means        */

#define PATH_FLAG_LOCAL_AGG    0x01   /* path created by local aggregation  */
#define PATH_FLAG_ATOMIC_AGG   0x02   /* atomic aggregate was/should be set */

/*
 * Bit definitions for the attribute flags byte
 */
#define PA_FLAG_OPT     0x80    /* attribute is optional */
#define PA_FLAG_TRANS   0x40    /* attribute is transitive */
#define PA_FLAG_PARTIAL 0x20    /* incomplete optional, transitive attribute */
#define PA_FLAG_EXTLEN  0x10    /* extended length flag */

#define PA_FLAG_ALL  (PA_FLAG_OPT|PA_FLAG_TRANS|PA_FLAG_PARTIAL|PA_FLAG_EXTLEN)
#define PA_FLAG_OPTTRANS        (PA_FLAG_OPT|PA_FLAG_TRANS)

/*
 * Lengths for a few of the attributes (the fixed length ones)
 */
#define PA_LEN_ORIGIN           1
#define PA_LEN_NEXTHOP          4
#define PA_LEN_UNREACH          0
#define PA_LEN_METRIC           2
#define PA_LEN_AS               2
#define PA_LEN_CLUSTER          4

/*
 * BGP version 4 attribute type codes (the dorks moved metric!).
 */
#define PA4_TYPE_INVALID        0
#define PA4_TYPE_ORIGIN         1
#define PA4_TYPE_ASPATH         2
#define PA4_TYPE_NEXTHOP        3
#define PA4_TYPE_METRIC         4
#define PA4_TYPE_LOCALPREF      5
#define PA4_TYPE_ATOMICAGG      6
#define PA4_TYPE_AGGREGATOR     7

/* [rfc1977] BGP Communities Attribute */
#define PA4_TYPE_COMMUNITY      8

/* [rfc1966] Route Reflection   */
#define PA4_TYPE_ORIGINATOR     9
#define PA4_TYPE_CLUSTERLIST   10


/*
 *  multiprotocol extention (bgp4+)
 */
#define PA4_TYPE_MPREACHNLRI    14
#define PA4_TYPE_MPUNREACHNLRI  15

#define PA4_MAXTYPE             0xff

#define PA4_TYPE_VALID(a)  (((a) >= PA4_TYPE_ORIGIN &&\
			     (a) <= PA4_TYPE_CLUSTERLIST) ||\
			    (a) == PA4_TYPE_MPREACHNLRI  ||\
			    (a) == PA4_TYPE_MPUNREACHNLRI)


/*
 * BGP4 subcodes for the AS_PATH attribute
 */
#define PA_PATH_NOTSETORSEQ     0       /* not a valid path type */
#define PA_PATH_SET             1
#define PA_PATH_SEQ             2
#define PA_PATH_MAXSEGLEN       255     /* maximum segment length */

/*
 * Lengths for a few of the version 4 attributes (the fixed length ones)
 */
#define PA4_LEN_ORIGIN          1
#define PA4_LEN_UNREACH         0
#define PA4_LEN_METRIC          4
#define PA4_LEN_LOCALPREF       4
#define PA4_LEN_ATOMICAGG       0
#define PA4_LEN_AGGREGATOR      6
#define PA4_LEN_ORIGINATOR      4  /* [rfc1966] */

#define PA4_LEN_SEGMENT         2

/*
 *  multiprotocol extention (I-D)
 */
#define PA4_MP_UCAST            1
#define PA4_MP_MCAST            2

struct asnum {
  struct asnum *asn_next;
  struct asnum *asn_prev;
  u_int16_t     asn_num;   /* AS number */
};

struct asseg {
  struct asseg *asg_next;
  struct asseg *asg_prev;
  byte          asg_type; /* PA_PATH_SET or PA_PATH_SET            */
  byte          asg_len;  /* the number of ASs in the path segment */
  struct asnum *asg_asn;
};

struct aspath {
  struct aspath    *asp_next;
  struct aspath    *asp_prev;
  byte              asp_origin;
  struct in6_addr   asp_nexthop;  /* global address         */
  u_int32_t         asp_med;
  u_int32_t         asp_localpref;
  byte              asp_atomagg;
  u_int32_t         asp_origid;
  struct clstrlist *asp_clstr;
  struct optatr	   *asp_optatr;
  u_short           asp_len;      /* "length" of this path  */
  struct asseg     *asp_segment;
};

struct clstrlist {
  struct clstrlist *cll_next;
  struct clstrlist *cll_prev;
  u_int32_t         cll_id;   /* CLUSTER_ID (NOT always equals to ROUTER_ID), network byte order */
};


struct optatr {		/* structure for unrecognized optional attribute */
  struct optatr *next;
  int len;			/* attribute length */
  char *data;			/* attribute data */
};
