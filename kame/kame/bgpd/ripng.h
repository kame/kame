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

/* requires config.h, bgp.h, rt_table.h */

struct ripif {
  struct ripif     *rip_next;
  struct ripif     *rip_prev;
  struct ifinfo    *rip_ife;
  struct rt_entry  *rip_adj_ribs_in;  /* Imported RTEs via BGP message   */
  struct rtproto   *rip_adj_ribs_out; /* Exporting RTEs of protocols     */
  char *rip_desc;		/* interface description */
  byte              rip_mode;         /* info bit                        */
#define IFS_NORIPIN          0x80
#define IFS_NORIPOUT         0x40
#define IFS_DEFAULTORIGINATE 0x10
#if 0
#define IFS_DEFAULT_FILTERIN 0x20
#define IFS_DEFAULT_FILTEROUT    0x08
#define IFS_DEFAULT_RESTRICTIN   0x04
#define IFS_DEFAULT_RESTRICTOUT  0x02
#endif
  int		    rip_metricin; /* added to incoming routes */
  u_long rip_defaultfilter;
  struct filterset  rip_filterset;
#define rip_filterin rip_filterset.filterin
#define rip_filterout rip_filterset.filterout
#define rip_restrictin rip_filterset.restrictin
#define rip_restrictout rip_filterset.restrictout

#define rip_filtered_indef rip_filterset.filtered_indef
#define rip_filtered_outdef rip_filterset.filtered_outdef
#define rip_input_restrected rip_filterset.input_restrected
#define rip_output_restrected rip_filterset.output_restrected
#if 0
  struct filtinfo   *rip_filterin;  /* incoming filter list */
  struct filtinfo   *rip_filterout; /* outgoing filter list */
  struct filtinfo   *rip_restrictin; /* incoming restriction list */
  struct filtinfo   *rip_restrictout; /* outgoing restriction list */

  u_int32_t	rip_filtered_indef; /* # of filtered incoming defaults */
  u_int32_t	rip_filtered_outdef; /* # of filtered outgoing defaults */

  /* # of filtered incoming routes by restriction: */
  u_int32_t	rip_input_restrected;
  /* # of filtered outgoing routes by restriction: */
  u_int32_t	rip_output_restrected;
#endif
};

#define RIPNG_VERSION            1
#define RIPNG_PORT             521    /* Port number to use with RIP     */
#define RIPNG_DEST          "ff02::9" /* all-rip-routers multicast group */


#define RIPNG_METRIC_UNREACHABLE 16
#define RIPNG_METRIC_NEXTHOP     0xff

struct riphdr {
    byte        riph_cmd;                /* request/response   */
    byte        riph_vers;               /* protocol version # */
    u_int16_t   riph_zero2;              /* unused             */
};


#define RIPNG_BUFSIZ     0xffff
#define RIPNG_MAXPKT    (MINMTU - IPV6_HDRLEN - sizeof(struct udphdr))
#define RIPNG_MAXRTES   ((RIPNG_MAXPKT - sizeof(struct riphdr))/\
                               sizeof(struct ripinfo6))
#define RIPNG_HOPLIMIT   255
/*
 * Packet types.
 */
#define RIPNGCMD_REQUEST          1     /* want info */
#define RIPNGCMD_RESPONSE         2     /* responding to request */
#define RIPNGCMD_TRACEON          3     /* turn tracing on */
#define RIPNGCMD_TRACEOFF         4     /* turn it off */
#define RIPNGCMD_POLL             5     /* like request, but anyone answers */
#define RIPNGCMD_POLLENTRY        6     /* like poll, but for entire entry */
#define RIPNGCMD_MAX              7

#define RIP_T_DUMP               30
#define RIP_T_LIFE              180
#define RIP_T_GARBAGE           120
#define RIP_T_DUMPRAND           15     /* (+)(-) sec */

