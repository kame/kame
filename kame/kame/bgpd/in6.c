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

#include "include.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "rt_table.h"
#include "in6.h"
#include <netdb.h>

int
mask2len(addr)
        struct  sockaddr_in6      *addr;
{
        int     i = 0;
        u_char  *p, *lim;

	p = (u_char *)&addr->sin6_addr;
	lim = (u_char *)addr + addr->sin6_len;
        for (; p < lim; p++) {
                if (*p != 0xff)
                        break;
                i += 8;
        }
        if (p < lim) {
                switch (*p) {
#define MASKLEN(m, l)   case m: i += l; break
                MASKLEN(0xfe, 7);
                MASKLEN(0xfc, 6);
                MASKLEN(0xf8, 5);
                MASKLEN(0xf0, 4);
                MASKLEN(0xe0, 3);
                MASKLEN(0xc0, 2);
                MASKLEN(0x80, 1);
#undef  MASKLEN
                }
        }
        return i;
}


/*
 *   len = 8l + a;
 */
byte
IN6_ARE_PRFX_EQUAL(a1, a2, len)
     struct in6_addr *a1;
     struct in6_addr *a2;
     int    len;
{
  u_char  l, a;
  u_char c1, c2;
  
  if (len > 128)
    return 0;

  l = len / 8;
  a = len % 8;

  if (memcmp((caddr_t)(a1), (caddr_t)(a2), (l)))
    return 0;

  if (a == 0)
    return 1;

  c1 = ((u_char *)a1)[l];
  c2 = ((u_char *)a2)[l];

  c1 = c1 >> (8 - a);
  c2 = c2 >> (8 - a);

  if (c1 == c2)
    return 1;
  else
    return 0;
}


byte
in6_is_addr_onlink(dst, retifp)
     struct in6_addr *dst;
     struct ifinfo **retifp;
{
  struct ifinfo        *ife;
  struct rt_entry      *rte;
  extern struct ifinfo *ifentry;

  if (IN6_IS_ADDR_LINKLOCAL(dst)) {
	  *retifp = NULL;
	  return 1;
  }

  ife = ifentry; /* global */
  while(ife) {
    rte = ife->ifi_rte;
    while(rte) {
      if (IN6_ARE_PRFX_EQUAL(dst,
			     &rte->rt_ripinfo.rip6_dest,
			     rte->rt_ripinfo.rip6_plen)  &&
	  (rte->rt_flags & RTF_UP)) {
	      *retifp = ife;
	      return 1;
      }
      if ((rte = rte->rt_next) == ife->ifi_rte)
	break;
    }
    if ((ife = ife->ifi_next) == ifentry)
      break;
  }
  return 0;  /* not found */
}



/*
 *   len = 8l + a;
 */
void
mask_nset(mask, len)
     struct in6_addr *mask;
     int           len;
{
  u_char  l, a;
  
  len = MIN(len, 128);

  l = len / 8;
  a = len % 8;

  memset(mask,        0, sizeof(struct in6_addr));
  memset((u_char *)mask, 0xff, l);

  if (l < sizeof(struct in6_addr))
    ((u_char *)mask)[l] = (u_char)(0xff << (8 - a));

  return;
}

void
mask_nclear(mask, len)
     struct in6_addr *mask;
     int           len;
{
  u_char  l, a;
  
  len = MIN(len, 128);

  l = len / 8;
  a = len % 8;

  if (l < sizeof(struct in6_addr)) {

    ((u_char *)mask)[l] &= (u_char)(0xff << (8 - a));

    if (l < sizeof(struct in6_addr) - 1)
      memset( &(((u_char *)mask)[l+1]), 0, sizeof(struct in6_addr) - 1 - l);
  }

  return;
}

int
inet_ptox(int af, const char *src, void *prfx, u_char *plen) {
  int i, j, txtlen, retval;
  char in6txt[INET6_ADDRSTRLEN];

  if (af != AF_INET6) {
    errno = EAFNOSUPPORT;
    return -1;
  }  

  memset(in6txt,  0, INET6_ADDRSTRLEN);
  i = j = 0;
  txtlen = strlen(src);

  while(i <= txtlen) {
    if (src[i] == '/') break;
    in6txt[i] = src[i];
    i++;
  }

  if (i > txtlen)
    return 0;

  if ((retval = inet_pton(AF_INET6, in6txt, prfx)) != 1)
    return retval;

  i++;
  *plen = (u_char)(atoi(&src[i]));

  return 1;
}


u_int16_t
ip6_cksum(phdr, payload)
     struct ip6_pseudohdr *phdr;
     u_char               *payload;
{
  u_int32_t sum = 0;
  int       i   = IPV6_HDRLEN;
  int       len = (int)phdr->ph6_uplen;

  while(i > 1) {
    sum += *((u_int16_t *) phdr)++;
    if (sum & 0x80000000)
      sum = (sum & 0xffff) + (sum >> 16);
    i -= 2;
  }

  while(len > 1) {
    sum += *((u_int16_t *) payload)++;
    if (sum & 0x80000000)
      sum = (sum & 0xffff) + (sum >> 16);
    len -= 2;
  }

  if (len)
    sum += (u_int16_t)*(u_char *)payload;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

char *
ip6str(addr, ifindex)
	struct in6_addr *addr;
	unsigned int ifindex;
{
	struct sockaddr_in6 sa6;

	memset(&sa6, 0, sizeof(sa6));
	sa6.sin6_len = sizeof(sa6);
	sa6.sin6_family = AF_INET6;
	sa6.sin6_addr = *addr;
	sa6.sin6_scope_id = ifindex; /* XXX: link(not i/f) index should be used */
	return(ip6str2(&sa6));
}

/* same as ip6str(), but takes sockaddr_in6 instead of in6_addr */
char *
ip6str2(sa6)
	struct sockaddr_in6 *sa6;
{
	static char ip6buf[8][MAXHOSTNAMELEN];
	static int ip6round = 0;
	char *cp;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	getnameinfo((struct sockaddr *)sa6, sa6->sin6_len, cp, MAXHOSTNAMELEN,
		    NULL, 0, NI_NUMERICHOST|NI_WITHSCOPEID);

	return(cp);
}

int
get_in6_addr(addr, sap)
	char *addr;
	struct sockaddr_in6 *sap;
{
	int ret_ga, error = 0;
	struct addrinfo *res0, *res, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;

	ret_ga = getaddrinfo(addr, NULL, &hints, &res);
	if (ret_ga) {
		syslog(LOG_DEBUG, "getaddrinfo failed for %s: %s",
		       addr, gai_strerror(ret_ga));
		return(-1);
	}

	res0 = res;
	for(; res; res = res->ai_next) {
		if (res->ai_addr->sa_family == AF_INET6) {
			memcpy(sap, res->ai_addr, sizeof(*sap));
			break;
		}
	}
	if (res == NULL) {	/* no inet6 addr */
		syslog(LOG_DEBUG, "getaddrinfo returns no INET6 addr for %s",
		       addr);
		error = -1;
		goto end;
	}
	
  end:
	freeaddrinfo(res0);
	return(error);
}

int
sa6_equal(sa1, sa2)
	struct sockaddr_in6 *sa1, *sa2;
{
	if (IN6_ARE_ADDR_EQUAL(&sa1->sin6_addr, &sa2->sin6_addr) &&
	    sa1->sin6_scope_id == sa2->sin6_scope_id)
		return(1);

	return(0);
}
