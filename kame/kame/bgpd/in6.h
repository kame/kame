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

/*  rfc1700  */
#define AFN_IP6   2

#define IN6_IS_ADDR_ROUTABLE(a) (!IN6_IS_ADDR_MULTICAST((a)) &&\
			       !IN6_IS_ADDR_LOOPBACK((a)) &&\
			       !IN6_IS_ADDR_LINKLOCAL((a)))

byte IN6_ARE_PRFX_EQUAL __P((struct in6_addr *, struct in6_addr *, int));
byte in6_is_addr_onlink __P((struct in6_addr *, struct ifinfo **));

#define POCTETS(plen) ( (plen)%8  ?  (plen)/8 + 1 :  (plen)/8 )


#ifndef ADVANCEDAPI
struct in6_pktinfo {
  struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
  u_int           ipi6_ifindex; /* send/recv interface index */
};
#endif

struct ip6_pseudohdr {
  struct in6_addr ph6_src;     /* Source      Address       */
  struct in6_addr ph6_dst;     /* Destination Address       */
  u_int32_t       ph6_uplen;   /* Upper-Layer Packet Length */
  u_int8_t        ph6_zero[3]; /* zero                      */
  u_int8_t        ph6_nxt;     /* Next Header               */
};


#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) (!memcmp((void *)(a),(void *)(b),16))
#endif

#ifndef CMSG_SPACE
/* macros for IPv6 advanced socket API */
#define CMSG_SPACE(length) ( ALIGN(sizeof(struct cmsghdr)) + \
                             ALIGN(length) )
#define CMSG_LEN(length) ( ALIGN(sizeof(struct cmsghdr)) + (length) )
#endif

#ifndef CLEAR_IN6_LINKLOCAL_IFINDEX
/* Macros to treat link local addresses */
#define SET_IN6_LINKLOCAL_IFINDEX(a,i) (*(u_int16_t *)(&(a)->s6_addr[2]) = htons(i))
#define CLEAR_IN6_LINKLOCAL_IFINDEX(a) (*(u_int16_t *)(&(a)->s6_addr[2]) = 0)
#define GET_IN6_LINKLOCAL_IFINDEX(a) (ntohs(*(u_int16_t *)(&(a)->s6_addr[2])))
#endif



int              mask2len    __P((struct sockaddr_in6 *));
void             mask_nset   __P((struct in6_addr  *, int));
void             mask_nclear __P((struct in6_addr  *, int));
int              inet_ptox   __P((int, const char *, void *, u_char *));
u_int16_t        ip6_cksum   __P((struct ip6_pseudohdr *, u_char *));
char            *ip6str      __P((struct in6_addr *, unsigned int));

#ifndef IPV6_JOIN_MEMBERSHIP
/* XXX */
#define IPV6_JOIN_MEMBERSHIP IPV6_ADD_MEMBERSHIP
#endif
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP
#endif
