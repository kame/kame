/* $Id: mipsock.h,v 1.1 2004/12/09 02:18:59 t-momose Exp $ */

/*
 * Copyright (C) 2004 WIDE Project.
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

#ifndef _NET_MIPSOCK_H_
#define _NET_MIPSOCK_H_

#include <netinet/in.h>

struct mip_msghdr {
 	u_short	miph_msglen;	/* to skip over non-understood messages */
 	u_char	miph_version;	/* future binary compatibility */
 	u_char	miph_type;	/* message type */
	int	miph_seq;	/* for sender to identify action */
};

struct mipm_bc_info {
 	u_short	mipc_msglen;	/* to skip over non-understood messages */
 	u_char	mipc_version;	/* future binary compatibility */
 	u_char	mipc_type;	/* message type */
	int	mipc_seq;	/* for sender to identify action */

	int mipc_seqno;
	int mipc_lifetime;
	u_int16_t mipc_flags;
	u_int16_t mipc_bid;      /* Binding Unique Identifier */
	struct sockaddr mipc_addr[0];
#define MIPC_HOA(mipc)	(&(mipc)->mipc_addr[0])
#define MIPC_COA(mipc)	((struct sockaddr *)((caddr_t)(MIPC_HOA(mipc)) \
				+ (MIPC_HOA(mipc))->sa_len))
#define MIPC_CNADDR(mipc)	((struct sockaddr *)((caddr_t)(MIPC_COA(mipc)) \
				+ (MIPC_COA(mipc))->sa_len))
};

struct mipm_bul_info {
 	u_short	mipu_msglen;	/* to skip over non-understood messages */
 	u_char	mipu_version;	/* future binary compatibility */
 	u_char	mipu_type;	/* message type */
	int	mipu_seq;	/* for sender to identify action */

	u_int16_t	mipu_flags;
	u_short		mipu_hoa_ifindex;
	char	mipu_coa_ifname[IFNAMSIZ];
	u_int16_t mipu_bid;     /* Binding Unique Identifier */
	u_int8_t        mipu_state;
	struct sockaddr mipu_addr[0];
#define MIPU_HOA(mipu)	(&(mipu)->mipu_addr[0])
#define MIPU_COA(mipu)	((struct sockaddr *)((caddr_t)(MIPU_HOA(mipu)) \
				+ (MIPU_HOA(mipu))->sa_len))
#define MIPU_PEERADDR(mipu)	((struct sockaddr *)((caddr_t)(MIPU_COA(mipu)) \
				+ (MIPU_COA(mipu))->sa_len))
};

struct mipm_nodetype_info {
	struct mip_msghdr mipmni_hdr;
	u_int8_t mipmni_nodetype;
	u_int8_t mipmni_enable; /* set 1 to enable, 0 to disable */
};
#define mipmni_msglen mipmni_hdr.miph_msglen
#define mipmni_version mipmni_hdr.miph_version
#define mipmni_type mipmni_hdr.miph_type
#define mipmni_seq mipmni_hdr.miph_seq

struct mipm_home_hint {
	struct mip_msghdr mipmhh_hdr;
	u_int16_t mipmhh_ifindex;		/* ifindex of interface
						   which received RA */
	u_int16_t mipmhh_prefixlen;		/* Prefix Length */
	struct sockaddr mipmhh_prefix[0];	/* received prefix */
};
#define mipmhh_msglen mipmhh_hdr.miph_msglen
#define mipmhh_version mipmhh_hdr.miph_version
#define mipmhh_type mipmhh_hdr.miph_type
#define mipmhh_seq mipmhh_hdr.miph_seq

/*
 * Usage: 
 * 
 * switch (command) {
 * case MIPM_MD_REREG:
 *    + mandate field: 
 *         'mipm_md_newcoa' (MUST set to a care-of address(s) to send BU)
 *    + options field: 
 *         'mipm_md_ifindex or mipm_md_hoa' (if an option(s) is
 *         defined, the new coa is applied only to the specified
 *         target (i.e. either mip virtual interface or HoA, or both))
 *
 * case MIPM_MD_DEREGHOME:
 *    +	mandate fields: 
 *          'mipm_md_newcoa' (MUST set to the home address)
 *          'mipm_md_ifindex or mipm_md_hoa' (MUST set either a mip
 *          virtual interface or a HoA (can be both) which is now
 *          returned to home)
 *
 * case MIPM_MD_DEREGFOREIGN:
 *    +	mandate fields: 
 *           'mipm_md_newcoa' (MUST set to a CoA to send dereg BU) 
 *           'mipm_md_ifindex or mipm_md_hoa' (MUST set either a mip
 *           virtual interface or a HoA (can be both) which is now
 *           returned to home) 
 * } 
 */
struct mipm_md_info {
	struct mip_msghdr mipm_md_hdr;
	u_char mipm_md_command;
#define MIPM_MD_REREG 		0x01
#define MIPM_MD_DEREGHOME 	0x02
#define MIPM_MD_DEREGFOREIGN 	0x03
	
	u_char mipm_md_hint;
#define MIPM_MD_INDEX 		0x01
#define MIPM_MD_ADDR 		0x02
#define MIPM_MD_HOME 		0x03
	u_int16_t mipm_md_ifindex;        
	u_int16_t mipm_md_bid;      /* Binding Unique Identifier */

	struct sockaddr mipm_md_addr[0];
#define MIPD_HOA(mipd)	(&(mipd)->mipm_md_addr[0])
#define MIPD_COA(mipd)	((struct sockaddr *)((caddr_t)(MIPD_HOA(mipd)) \
				+ (MIPD_HOA(mipd))->sa_len))
#define MIPD_COA2(mipd)	((struct sockaddr *)((caddr_t)(MIPD_COA(mipd)) \
				+ (MIPD_COA(mipd))->sa_len))
};

struct mipm_rr_hint {
	struct mip_msghdr mipmrh_hdr;
	struct sockaddr mipmrh_addr[0];
};
#define mipmrh_msglen mipmrh_hdr.miph_msglen
#define mipmrh_version mipmrh_hdr.miph_version
#define mipmrh_type mipmrh_hdr.miph_type
#define mipmrh_seq mipmrh_hdr.miph_seq
#define MIPMRH_HOA(mipmrh) ((mipmrh)->mipmrh_addr)
#define MIPMRH_PEERADDR(mipmrh)				\
    ((struct sockaddr *)((caddr_t)(MIPMRH_HOA(mipmrh))	\
    + (MIPMRH_HOA(mipmrh))->sa_len))

struct mipm_be_hint {
	struct mip_msghdr mipmbeh_hdr;
	u_int8_t mipmbeh_status;
	struct sockaddr mipmbeh_addr[0];
};
#define mipmbeh_msglen mipmbeh_hdr.miph_msglen
#define mipmbeh_version mipmbeh_hdr.miph_version
#define mipmbeh_type mipmbeh_hdr.miph_type
#define mipmbeh_seq mipmbeh_hdr.miph_seq
#define MIPMBEH_PEERADDR(mipmbeh) ((mipmbeh)->mipmbeh_addr)
#define MIPMBEH_COA(mipmbeh)					\
    ((struct sockaddr *)((caddr_t)(MIPMBEH_PEERADDR(mipmbeh))	\
    + (MIPMBEH_PEERADDR(mipmbeh))->sa_len))
#define MIPMBEH_HOA(mipmbeh)					\
    ((struct sockaddr *)((caddr_t)(MIPMBEH_COA(mipmbeh))	\
    + (MIPMBEH_COA(mipmbeh))->sa_len))

#define MIP_VERSION	1

#define MIPM_NODETYPE_INFO	1
#define MIPM_BC_ADD		2
#define MIPM_BC_UPDATE		3
#define MIPM_BC_REMOVE		4
#define MIPM_BC_FLUSH		5
#define MIPM_BUL_ADD		6
#define MIPM_BUL_UPDATE		7
#define MIPM_BUL_REMOVE		8
#define MIPM_BUL_FLUSH		9
#define MIPM_MD_INFO		10
#define MIPM_HOME_HINT		11
#define MIPM_RR_HINT		12
#define MIPM_BE_HINT		13

void mips_notify_home_hint(u_int16_t, struct in6_addr *, u_int16_t);
void mips_notify_rr_hint(struct in6_addr *, struct in6_addr *);
void mips_notify_be_hint(struct in6_addr *, struct in6_addr *,
    struct in6_addr *, u_int8_t);

#endif /* !_NET_MIPSOCK_H_ */
