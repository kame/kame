/*
 * Copyright (C) 1999 LSIIT Laboratory.
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
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pimd.
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */


#ifndef MLD6V2_H
#define MLD6V2_H
/**************** LIP6 DEV *******************/

struct mld6v2_hdr
{				/* MLDv2 Header */
    struct icmp6_hdr mld6v2_hdr;	/* Standard ICMP header */
    struct in6_addr mld6v2_addr;	/* Multicast Address */
    u_int8          mld6v2_misc;	/* Resv+S+QRV */
    u_int8          mld6v2_qqi;	/* QQIC */
    u_int16         mld6v2_numsrc;	/* Number of Sources */
    struct in6_addr mld6v2_sources[1];	/* Sources Addresses List */
};

#define mld6v2_type	mld6v2_hdr.icmp6_type
#define mld6v2_code	mld6v2_hdr.icmp6_code
#define mld6v2_cksum	mld6v2_hdr.icmp6_cksum
#define mld6v2_maxrc	mld6v2_hdr.icmp6_data16[0]
#define mld6v2_reserved	mld6v2_hdr.icmp6_data16[1]

struct mld6v2_maddr_rec
{				/* Multicast Address Record  */
    u_int8          mmr_type;	/* Multicast Address Record Type */
    u_int8          mmr_datalen;	/* Aux Data Length */
    u_int16         mmr_numsrc;	/* Number of Sources */
    struct in6_addr mmar_maddr;	/* Multicast Address */
    struct in6_addr mmar_sources[1];	/* Sources Addresses List */
};

#define nmcastrcd mld6v2_hdr.icmp6_data16[1]

struct mld6v2_report
{				/* Multicast Report */
    struct icmp6_hdr mld6v2_hdr;	/* Standard ICMP header */
    struct mld6v2_maddr_rec mr_maddr[1];	/* Multicast Records */
};


#define MLD6_QRV(x) ((x)->mld6v2_misc & (0x07))
#define MLD6_SFLAG(x) ((x)->mld6v2_misc &(0x08))


#define MLD6_MINLEN 24;		/* Minimal Message Length */
#define MLD6_HDRLEN 24;		/* Minimal Header Length */
#define MLD6_MADDR_REC_HDRLEN 20;	/* Minimal Multicast Addresses Length */
#define MLD6_PREPEND 0;		/* Allocation for low level use  */

#define MLD6_MAXSOURCES(len)  (((len)-28)>>2)

/*************** MYDEV ***********************/

#define SFLAGYES		0x08
#define SFLAGNO			0x0

/*
 * Multicast Address Record Types 
 */
/*
 * In PIM-SSM only value 1,5,6 are used 
 */

#define MODE_IS_INCLUDE 	1
#define MODE_IS_EXCLUDE		2
#define CHANGE_TO_INCLUDE_MODE	3
#define CHANGE_TO_EXCLUDE_MODE	4
#define	ALLOW_NEW_SOURCES	5
#define BLOCK_OLD_SOURCES	6

unsigned int    codafloat(unsigned int nbr, unsigned int *realnbr,
			  unsigned int sizeexp, unsigned int sizemant);
unsigned int	decodeafloat(unsigned int nbr,unsigned int sizeexp,
			     unsigned int sizemant);
void            make_mld6v2_msg(int type, int code, struct sockaddr_in6 *src,
				struct sockaddr_in6 *dst,
				struct in6_addr *group, int ifindex,
				unsigned int delay, int datalen, int alert,
				int sflag, int qrv, int qqic,
				struct listaddr *sources);
void            send_mld6v2(int type, int code, struct sockaddr_in6 *src,
			    struct sockaddr_in6 *dst, struct in6_addr *group,
			    int ifindex, unsigned int delay, int datalen,
			    int alert, int sflag, int qrv, int qqic,
			    struct listaddr *sources);



#endif
