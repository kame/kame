/*	$KAME: halist.c,v 1.1 2001/12/28 06:38:19 k-sugyou Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.
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
 * $Id: halist.c,v 1.1 2001/12/28 06:38:19 k-sugyou Exp $
 */

/*
 * Copyright (C) 2000 NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of NEC Corporation or any of its affiliates shall not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NEC CORPORATION ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL NEC CORPORATION BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <net/if.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <net/if_var.h>
#endif /* __FreeBSD__ >= 3 */
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include "halist.h"
#include "haadisc.h"
#include "timestamp.h"

/*
 * home agent list implementations
 */

struct hagent_gaddr *hal_gaddr_add __P((struct hagent_entry *,
					struct hagent_gaddr *,
					struct nd_opt_prefix_info *));
static struct hagent_gaddr *hal_gaddr_find __P((struct hagent_entry *,
						struct in6_addr *, u_int8_t));
static void hal_expire __P((struct hagent_entry *, long));
void hal_gaddr_clean __P((struct hagent_entry *));
static int get_gaddr __P((struct hagent_gaddr *, struct in6_addr *,
			  struct in6_addr *));
static void create_mask __P((struct in6_addr *, u_int8_t));
static void hal_dump __P((FILE *));
static void halent_dump __P((FILE *, struct hagent_entry *));
static void gaddr_dump __P((FILE *, struct hagent_gaddr *));

/* 
 * home agent list (sorted by home agent preference)
 */
struct hagent_entry	halist_expire_head;

/* 
 * update home agent list with RA information
 */
struct hagent_entry *
hal_update(ifindex, ha_addr, ha_lifetime, ha_pref)
    int ifindex;
    struct in6_addr *ha_addr;
    u_int16_t ha_lifetime;
    int16_t ha_pref;
{
    struct hagent_entry *halp, *curp, *prevp;
    struct hagent_ifinfo *haif;
    struct timeval tv;
    long now;

    DPRINT("<s:hal_update>");

    gettimeofday(&tv, NULL);
    now = tv.tv_sec;

    /* lookup home agent i/f info from ifindex */
    haif = haif_find(ifindex);

    if (!haif) {
	syslog(LOG_ERR, __FUNCTION__ "cannt get home agent ifinfo for ifindex %d.\n", ifindex);
	goto err;
    }

    /* lookup home agent entry from home agent list of specified i/f */
    halp = hal_find(haif, ha_addr);

    /* if HA entry exists, remove it from list first */
    if (halp) {

	DPRINT("<x:hal_update[entry already exists]>");

	/* remove from preference list */
	if (halp->hagent_next_pref) {
	    halp->hagent_next_pref->hagent_prev_pref
		= halp->hagent_prev_pref;
	}
	if (halp->hagent_prev_pref) {
	    halp->hagent_prev_pref->hagent_next_pref
		= halp->hagent_next_pref;
	}
	halp->hagent_next_pref = halp->hagent_prev_pref = NULL;

	/* remove from expire list */
	if (halp->hagent_next_expire) {
	    halp->hagent_next_expire->hagent_prev_expire
		= halp->hagent_prev_expire;
	}
	if (halp->hagent_prev_expire) {
	    halp->hagent_prev_expire->hagent_next_expire
		= halp->hagent_next_expire;
	}
	halp->hagent_next_expire = halp->hagent_prev_expire = NULL;
    }

    if (ha_lifetime > 0) {
	/* create list entry if not already exist */
	if (! halp) {

	    /* IMPLID:MIP6HA#13 */
	    halp = malloc(sizeof (struct hagent_entry));
	    if (halp) {
		bzero(halp, sizeof (struct hagent_entry));
		bcopy(ha_addr, &halp->hagent_addr, sizeof (struct in6_addr));
		DPRINT("<x:hal_update[created new entry]>");
	    }
	    else {
		syslog(LOG_ERR, __FUNCTION__ "cannt allocate memory.\n");
		goto err;
	    }
	}

	/* IMPLID:MIP6HA#12 */
	/* update parameters */
	halp->hagent_pref = ha_pref;
	halp->hagent_lifetime = ha_lifetime;
	halp->hagent_expire = now + ha_lifetime;

	/* insert entry to preference list */
	for (prevp = curp = haif->halist_pref.hagent_next_pref;
	     curp; curp = curp->hagent_next_pref) {
	    if (halp->hagent_pref > curp->hagent_pref) {
		halp->hagent_prev_pref = curp->hagent_prev_pref;
		halp->hagent_next_pref = curp;
		if (curp->hagent_prev_pref) {
		    curp->hagent_prev_pref->hagent_next_pref = halp;
		}
		curp->hagent_prev_pref = halp;

		break;
	    }
	    prevp = curp;
	}
	if (! curp) {
	    if (prevp) {
		/* append tail */
		prevp->hagent_next_pref = halp;
		halp->hagent_prev_pref = prevp;
	    }
	    else {
		/* insert head */
		haif->halist_pref.hagent_next_pref = halp;
		halp->hagent_prev_pref = &haif->halist_pref;
	    }
	}

	/* insert entry to expire list */
	for (prevp = curp = halist_expire_head.hagent_next_expire;
	     curp; curp = curp->hagent_next_expire) {
	    if (curp->hagent_expire > halp->hagent_expire) {
		halp->hagent_prev_expire = curp->hagent_prev_expire;
		halp->hagent_next_expire = curp;
		if (curp->hagent_prev_expire) {
		    curp->hagent_prev_expire->hagent_next_expire = halp;
		}
		curp->hagent_prev_expire = halp;

		break;
	    }
	    prevp = curp;
	}
	if (! curp) {
	    if (prevp) {
		/* append tail */
		prevp->hagent_next_expire = halp;
		halp->hagent_prev_expire = prevp;
	    }
	    else {
		/* insert head */
		halist_expire_head.hagent_next_expire = halp;
		halp->hagent_prev_expire = &halist_expire_head;
	    }
	}

    }
    else if (halp) { /* must be deleted */
	/* IMPLID:MIP6HA#11 */
	/* clear global address list */
	hal_gaddr_clean(halp);
	free(halp);
	halp = NULL;

	DPRINT("<x:hal_update[removed entry]>");
    }

done:
    DPRINT("<e:hal_update>");

    /* dump home agent list */
    if (dump)
      hal_dump(stderr);

    return halp;
err:
    DPRINT("<e:hal_update[error]>");

    halp = NULL;
    goto done;
}

/*
 * lookup an home agent entry from home agent list
 */
struct hagent_entry *
hal_find(haif, ha_addr)
    struct hagent_ifinfo *haif;
    struct in6_addr *ha_addr;
{
    struct hagent_entry *halp;

    for (halp = haif->halist_pref.hagent_next_pref; halp;
	 halp = halp->hagent_next_pref) {
	if (IN6_ARE_ADDR_EQUAL(&(halp->hagent_addr), ha_addr))
	    break;
    }
    return halp;
}

/*
 * add an global address for some home agent (referenced by halp)
 */
struct hagent_gaddr *
hal_gaddr_add(halp, lastp, pi)
    struct hagent_entry *halp;
    struct hagent_gaddr *lastp;
    struct nd_opt_prefix_info *pi;
{
    struct hagent_gaddr *galp;

    galp = hal_gaddr_find(halp, &pi->nd_opt_pi_prefix, 
			  pi->nd_opt_pi_prefix_len);

    if (! galp) {
	/* create global address list entry and enqueue */
	galp = malloc(sizeof(struct hagent_gaddr));
	if (galp) {
	    bzero(galp, sizeof(struct hagent_gaddr));
	    bcopy(&(pi->nd_opt_pi_prefix), &(galp->hagent_gaddr), 
		  sizeof(struct in6_addr));
	    galp->hagent_prefixlen = pi->nd_opt_pi_prefix_len;
	}
	else {
	    syslog(LOG_ERR, __FUNCTION__ "cannt allocate memory.\n");
	    goto err;
	}
    }
    else {
	/* remove from old list */
	if (galp->hagent_next_gaddr) {
	    galp->hagent_next_gaddr->hagent_prev_gaddr
		= galp->hagent_prev_gaddr;
	}
	if (galp->hagent_prev_gaddr) {
	    galp->hagent_prev_gaddr->hagent_next_gaddr
		= galp->hagent_next_gaddr;
	}
	galp->hagent_next_gaddr = galp->hagent_prev_gaddr = NULL;
    }
    /* insert to new list */
    lastp->hagent_next_gaddr = galp;
    galp->hagent_prev_gaddr = lastp;

    lastp = galp;
err:
    return lastp;
}

/*
 * lookup a global address for certain home agent
 */
static struct hagent_gaddr *
hal_gaddr_find(halp, ha_addr, ha_prefixlen)
    struct hagent_entry *halp;
    struct in6_addr *ha_addr;
    u_int8_t ha_prefixlen;
{
    struct hagent_gaddr *galp;

    for (galp = halp->hagent_galist.hagent_next_gaddr;
	 galp; galp = galp->hagent_next_gaddr) {
	if ((galp->hagent_prefixlen == ha_prefixlen) &&
	    IN6_ARE_ADDR_EQUAL(&(galp->hagent_gaddr), ha_addr))
	    break;
    }
    return galp;
}

/*
 * last action of accumulation of global address to a home agent entry
 */
#ifdef OLD_HAL_GADDR_LAST
void
hal_gaddr_last(halp, newgal)
    struct hagent_entry *halp;
    struct hagent_gaddr *newgal;
{
    /* clean old global address list */
    hal_gaddr_clean(halp);

    /* update global address list */
    halp->hagent_galist.hagent_next_gaddr = newgal;
    newgal->hagent_prev_gaddr = &halp->hagent_galist;
}
#else
void
hal_gaddr_last(halp, newgal)
    struct hagent_entry *halp;
    struct hagent_gaddr *newgal;
{
    struct hagent_gaddr *galp;

    for (galp = &halp->hagent_galist;
	 galp->hagent_next_gaddr != NULL;
	 galp = galp->hagent_next_gaddr) /* nothing to do */ ;

    /* append global address list */
    galp->hagent_next_gaddr = newgal;
    newgal->hagent_prev_gaddr = galp;
}
#endif /* OLD_HAL_GADDR_LAST */

/*
 * purge global addresses for certain home agent
 */
void
hal_gaddr_clean(halp)
    struct hagent_entry *halp;
{
    struct hagent_gaddr *tmp;

    /* remove old global addresses */
    while (halp->hagent_galist.hagent_next_gaddr) {
	tmp = halp->hagent_galist.hagent_next_gaddr;
	halp->hagent_galist.hagent_next_gaddr = tmp->hagent_next_gaddr;
	free(tmp);
    }
}

/*
 * expiration check of home agent list entry
 * ToDo: expiration check of global address
 */
void
hal_check_expire()
{
    long now;
    struct timeval tv;

    DPRINT("<s:hal_check_expire>");

    gettimeofday(&tv, NULL);
    now = tv.tv_sec;

    /* at first check first entry only because it will expires first */
    /* IMPLID:MIP6HA#15 */
    if (halist_expire_head.hagent_next_expire
	&& (halist_expire_head.hagent_next_expire->hagent_expire < now)) {
	hal_expire(halist_expire_head.hagent_next_expire, now);
    }

    DPRINT("<e:hal_check_expire>\n");

    if (dump)
	hal_dump(stderr);
}

/*
 * delete expired home agent list entry
 */
static void
hal_expire(halp, now)
    struct hagent_entry *halp;
    long now;
{
    struct hagent_entry *tmp;

    DPRINT("<s:hal_expire>");

    /* lookup expired entry and remove it from list and delete it */
    for ( ; halp && (halp->hagent_expire < now); halp = tmp) {
	tmp = halp->hagent_next_expire;

	DPRINT("<x:hal_expire[expired]>");

	if (halp->hagent_prev_pref) {
	    halp->hagent_prev_pref->hagent_next_pref
		= halp->hagent_next_pref;
	}
	if (halp->hagent_next_pref) {
	    halp->hagent_next_pref->hagent_prev_pref
		= halp->hagent_prev_pref;
	}
	if (halp->hagent_next_expire) {
	    halp->hagent_next_expire->hagent_prev_expire
		= halp->hagent_prev_expire;
	}
	if (halp->hagent_prev_expire) {
	    halp->hagent_prev_expire->hagent_next_expire
		= halp->hagent_next_expire;
	}
    
	/* clear global address list */
	hal_gaddr_clean(halp);

	free(halp);
    }

    DPRINT("<e:hal_expire>");
}

/*
 * delete all home agent list entry
 */
void
hal_clean()
{
    long now = LONG_MAX;

    if (halist_expire_head.hagent_next_expire) {
	hal_expire(halist_expire_head.hagent_next_expire, now);
    }
    syslog(LOG_WARNING, "clean up home agent list");
}

/*
 * delete a home agent list entry with given ifindex and address
 */
int
hal_delete(haif, ha_addr)
    struct hagent_ifinfo *haif;
    struct in6_addr *ha_addr;
{
    struct hagent_entry *halp;
    int ret = 0;

    DPRINT("<s:hal_delete>");

    halp = hal_find(haif, ha_addr);

    if (!halp) {
	ret = -1;
	goto done;
    }

    /* remove it from list */
    if (halp->hagent_prev_pref) {
	halp->hagent_prev_pref->hagent_next_pref
	    = halp->hagent_next_pref;
    }
    if (halp->hagent_next_pref) {
	halp->hagent_next_pref->hagent_prev_pref
	    = halp->hagent_prev_pref;
    }
    if (halp->hagent_prev_expire) {
	halp->hagent_prev_expire->hagent_next_expire
	    = halp->hagent_next_expire;
    }
    if (halp->hagent_next_expire) {
	halp->hagent_next_expire->hagent_prev_expire
	    = halp->hagent_prev_expire;
    }

    /* clear global address list */
    hal_gaddr_clean(halp);

    free(halp);

done:
    DPRINT("<x:hal_delete>");
    return ret;
}

/*
 * swap preference order.
 */
void
hal_swap_preference_order(a, b)
     struct hagent_entry *a, *b;
{
    struct hagent_entry *ap, *an, *bp, *bn, *t;

    if (a == NULL || b == NULL) return;

    ap = a->hagent_prev_pref;
    an = a->hagent_next_pref;
    bp = b->hagent_prev_pref;
    bn = b->hagent_next_pref;

    ap->hagent_next_pref = b;
    bp->hagent_next_pref = a;
    t = a->hagent_next_pref;
    a->hagent_next_pref = b->hagent_next_pref;
    b->hagent_next_pref = t;

    if (an != NULL) an->hagent_prev_pref = b;
    if (bn != NULL) bn->hagent_prev_pref = a;
    t = a->hagent_prev_pref;
    a->hagent_prev_pref = b->hagent_prev_pref;
    b->hagent_prev_pref = t;

    return;
}

/*
 * shuffle home agent entries with same preference.
 */
int
hal_shuffle(haif)
     struct hagent_ifinfo *haif;
{
    int index, table_size, i;
    struct hagent_entry **tablep, **tableptmp, *hap, *haptmp;
    
#define DEFAULT_TABLE_SIZE 10
    tablep = (struct hagent_entry **)malloc(sizeof (struct hagent_entry *) *
					    DEFAULT_TABLE_SIZE);
    if (tablep == NULL) {
	syslog(LOG_ERR, __FUNCTION__ "memory allocation failed.\n");
	return 0;
    }
    table_size = DEFAULT_TABLE_SIZE;
    
    for (hap = haif->halist_pref.hagent_next_pref;
	 hap;
	 hap = haptmp) {
	for (haptmp = hap, index = 0;
	     haptmp;
	     haptmp = haptmp->hagent_next_pref) {
	    if (hap->hagent_pref != haptmp->hagent_pref) break;
	    if (index >= table_size) {
		/* grow table */
		tableptmp = (struct hagent_entry **)malloc(sizeof (struct hagent_entry *) *
							   table_size * 2);
		if (tableptmp == NULL) {
		    syslog(LOG_ERR, __FUNCTION__ "memory reallocation failed.\n");
		    free(tablep);
		    return 0;
		}
		bcopy(tablep, tableptmp, sizeof (struct hagent_entry *) * table_size);
		free(tablep);
		tablep = tableptmp;
		table_size *= 2;
	    }
	    tablep[index++] = haptmp;
	}
	
	for (i = 0; i < index; i++)
	    hal_swap_preference_order(tablep[i], tablep[random() % index]);
    }
    free(tablep);
    return 1;
}

/*
 * pick up global addresses for home agents on specified link and prefix
 */
int
hal_pick(req_addr, hagent_addrs, src_addr, haif, count)
    struct in6_addr *req_addr;
    struct in6_addr *hagent_addrs;
    struct in6_addr *src_addr;
    struct hagent_ifinfo *haif;
    int count;
{
    int first, naddr;
    struct hagent_entry *hap, *selfhalp = NULL;

#define IN6_ARE_ADDR_MASKEQUAL(x,y,z) (\
	(((x).__u6_addr.__u6_addr32[0] & (y).__u6_addr.__u6_addr32[0]) == ((z).__u6_addr.__u6_addr32[0] & (y).__u6_addr.__u6_addr32[0])) && \
	(((x).__u6_addr.__u6_addr32[1] & (y).__u6_addr.__u6_addr32[1]) == ((z).__u6_addr.__u6_addr32[1] & (y).__u6_addr.__u6_addr32[1])) && \
	(((x).__u6_addr.__u6_addr32[2] & (y).__u6_addr.__u6_addr32[2]) == ((z).__u6_addr.__u6_addr32[2] & (y).__u6_addr.__u6_addr32[2])) && \
	(((x).__u6_addr.__u6_addr32[3] & (y).__u6_addr.__u6_addr32[3]) == ((z).__u6_addr.__u6_addr32[3] & (y).__u6_addr.__u6_addr32[3])))

    /* shuffle home agent entries with same preference */
    hal_shuffle(haif);

    /* lookup self entry from home agent list */
    if (haif->linklocal)
	selfhalp = hal_find(haif, &((struct sockaddr_in6 *)(haif->linklocal->ifa_addr))->sin6_addr);

    /* search home agent list and pick appropriate global addresses */
    for (first = 1, naddr = 0, hap = haif->halist_pref.hagent_next_pref;
	 hap && naddr < count; hap = hap->hagent_next_pref) {
	if (get_gaddr(hap->hagent_galist.hagent_next_gaddr, 
		       req_addr, hagent_addrs))
	    continue;
	if (hap == selfhalp) {
	    *src_addr = *hagent_addrs;
	    if (first)
		continue;
	}
	first = 0;
	hagent_addrs ++;
	naddr ++;
    }
    return naddr;
}

/*
 * pick up a global address that machies given prefix
 */
int
get_gaddr(hagent_gaddr, req_addr, dest)
    struct hagent_gaddr *hagent_gaddr;
    struct in6_addr *req_addr;
    struct in6_addr *dest;
{
    struct in6_addr mask;
    u_int8_t old_plen = 128;

    while (hagent_gaddr) {
	if (old_plen != hagent_gaddr->hagent_prefixlen)
	    create_mask(&mask, hagent_gaddr->hagent_prefixlen);
	old_plen = hagent_gaddr->hagent_prefixlen;
	if (IN6_ARE_ADDR_MASKEQUAL(*req_addr, mask, 
				   hagent_gaddr->hagent_gaddr)) {
	    *dest = hagent_gaddr->hagent_gaddr;
	    return 0;
	}
	hagent_gaddr = hagent_gaddr->hagent_next_gaddr;
    }
    return -1;
}


/*
 * create netmask by mask length
 */
void
create_mask(mask, plen)
    struct in6_addr *mask;
    u_int8_t plen;
{
    int i;

    bzero(mask, sizeof(*mask));
    for (i = 0; i < plen / 8; i++)
	mask->s6_addr[i] = 0xff;
    if (plen % 8)
	mask->s6_addr[i] = (0xff00 >> (plen % 8)) & 0xff;
}

/*
 * lookup home agent interface information entry for certain interface
 */
struct hagent_ifinfo *
haif_find(ifindex)
    int ifindex;
{
    int i;
    for (i = 0; i < ifnum; ++i) {
	if (haifinfo_tab[i].ifindex == ifindex)
	    return &haifinfo_tab[i];
    }
    return NULL;
}

struct hagent_ifinfo *
haif_findwithaddr(ha_addr)
    struct in6_addr *ha_addr;
{
    int i;
    struct ifaddrs *ifap;

    for (i = 0; i < ifnum; ++i) {
	ifap = haifinfo_tab[i].anycast;
	/* find the information on interface anycast address */
	if (ifap != NULL &&
	    IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)(ifap->ifa_addr))->sin6_addr,
			       ha_addr))
	{
	    return &haifinfo_tab[i];
	}
    }
    return NULL;
}

#define REVERSE_MASK(d,s) (\
	((d).__u6_addr.__u6_addr32[0] = ~(s).__u6_addr.__u6_addr32[0]), \
	((d).__u6_addr.__u6_addr32[1] = ~(s).__u6_addr.__u6_addr32[1]), \
	((d).__u6_addr.__u6_addr32[2] = ~(s).__u6_addr.__u6_addr32[2]), \
	((d).__u6_addr.__u6_addr32[3] = ~(s).__u6_addr.__u6_addr32[3]))

int
haif_getifaddrs()
{
    struct ifaddrs *ifalist, *ifap;
    struct sockaddr_in6 *sa6;
    struct hagent_ifinfo *haif = NULL;
    int ifindex, oifindex = 0, anycast_found = 0;
    struct in6_addr mask;
    struct in6_addr haanycast = {{{0xff, 0xff, 0xff, 0xff, 
				   0xff, 0xff, 0xff, 0xff, 
				   0xff, 0xff, 0xff, 0xff, 
				   0xff, 0xff, 0xff, 0xfe}}};
    int s;
    struct in6_ifreq ifr6;

    /* get interface adresses */
    if (getifaddrs(&ifalist) < 0) {
	return -1;
    }
    if ((s = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
	return -1;

    /* search address list and pick up linklocal/anycast addresses */
    for (ifap = ifalist; ifap; ifap = ifap->ifa_next) {
	if (ifap->ifa_addr->sa_family != AF_INET6) 
	    continue;

	ifindex = if_nametoindex(ifap->ifa_name);
	if (ifindex != oifindex)
	    haif = haif_find(ifindex);
	oifindex = ifindex;
	if (!haif)
	    continue;

	sa6 = (struct sockaddr_in6 *)ifap->ifa_addr;
	(void) memset(&ifr6, 0, sizeof(ifr6));
	(void) strncpy(ifr6.ifr_name, ifap->ifa_name, sizeof(ifr6.ifr_name));
	ifr6.ifr_addr = *sa6;
	if (ioctl(s, SIOCGIFAFLAG_IN6, (caddr_t)&ifr6) < 0) {
	    ifr6.ifr_ifru.ifru_flags6 = 0;
	}
	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST) {
	    REVERSE_MASK(mask, ((struct sockaddr_in6 *)(ifap->ifa_netmask))->sin6_addr);
	    mask.s6_addr[8] &= 0xfd; /* ignore universal bit XXX */
	    if (IN6_ARE_ADDR_MASKEQUAL(sa6->sin6_addr, mask, haanycast)) {
		haif->anycast = ifap;
		anycast_found = 1;
	    }
	    continue;
	}
	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DUPLICATED)
	    continue;
	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DETACHED)
	    continue;
  	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_DEPRECATED)
	    continue;
	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_TEMPORARY)
	    continue;
	if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_HOME)
	    continue;

	sa6 = (struct sockaddr_in6 *)ifap->ifa_addr;
	if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
	    /* clear scopeid */
	    sa6->sin6_addr.__u6_addr.__u6_addr16[1] = 0;
	    /* store ifaddr structure */
	    haif->linklocal = ifap;
	}
	else if (IN6_IS_ADDR_SITELOCAL(&sa6->sin6_addr)) {
	    continue;
	}
	else {
	    haif->global = ifap;
	}
    }
    close(s);

    if (anycast_found == 0)
	syslog(LOG_WARNING, __FUNCTION__ "anycast address not found");

    return 0;
}

void gaddr_dump(fp, galp)
 	FILE *fp;
	struct hagent_gaddr *galp;
{
	char buf[40];
	inet_ntop(AF_INET6, &galp->hagent_gaddr, buf, sizeof(buf) - 1);
	fprintf(fp, "      %s/%d\n", buf, galp->hagent_prefixlen);
}

void halent_dump(fp, halp)
	FILE *fp;
	struct hagent_entry *halp;
{
	char buf[40];
	struct hagent_gaddr *galp;
	fprintf(fp, "  <<<home agent entry %x>>>\n", (u_int32_t)halp);
	fprintf(fp, "    [next expire=%x] [previous expire=%x]\n",
	       (u_int32_t)(halp->hagent_next_expire),
	       (u_int32_t)(halp->hagent_prev_expire));
	fprintf(fp, "    [next preference=%x] [previous preference=%x]\n",
	       (u_int32_t)(halp->hagent_next_pref),
	       (u_int32_t)(halp->hagent_prev_pref));
	inet_ntop(AF_INET6, &halp->hagent_addr, buf, sizeof(buf) - 1);
	fprintf(fp, "    home agent address=%s\n", buf);
	fprintf(fp, "    lifetime=%d expire=%ld\n",
		halp->hagent_lifetime, halp->hagent_expire);
	fprintf(fp, "    preference=%d\n", halp->hagent_pref);
	fprintf(fp, "    global addresses:\n");
	for (galp = halp->hagent_galist.hagent_next_gaddr;  galp;
	     galp = galp->hagent_next_gaddr) {
		gaddr_dump(fp, galp);
	}
}

void hal_dump(FILE *fp)
{
	int i;
	char buf[40];
	struct hagent_entry *halp;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	fprintf(fp, "<<<DUMP home agent list ");
	ts_print(fp, &tv);
	fprintf(fp, ">>>\n<<<dumping expiration list...>>>\n");
	fprintf(fp, "  sentinel entry=%x\n", (u_int32_t)&halist_expire_head);
	for (halp = halist_expire_head.hagent_next_expire; halp;
	     halp = halp->hagent_next_expire) {
		halent_dump(fp, halp);
	}
	for (i = 0; i < ifnum; ++i) {
		fprintf(fp, "<<<dumping preference list for ifindex %d>>>\n",
			haifinfo_tab[i].ifindex);
		fprintf(fp, "  sentinel entry=%x\n",
			(u_int32_t)&haifinfo_tab[i].halist_pref);
		for (halp = haifinfo_tab[i].halist_pref.hagent_next_pref; halp;
		     halp = halp->hagent_next_pref) {
			halent_dump(fp, halp);
		}
		if (haifinfo_tab[i].global != NULL) {
			inet_ntop(AF_INET6,
				  &((struct sockaddr_in6 *)(haifinfo_tab[i].global->ifa_addr))->sin6_addr,
				  buf, sizeof(buf) - 1);
		    fprintf(fp, "  global addresses=%s\n", buf);
		}
		if (haifinfo_tab[i].anycast != NULL) {
			inet_ntop(AF_INET6,
				  &((struct sockaddr_in6 *)(haifinfo_tab[i].anycast->ifa_addr))->sin6_addr,
				  buf, sizeof(buf) - 1);
		    fprintf(fp, "  anycast addresses=%s\n", buf);
		}
	}
	fprintf(fp, "<<<DUMP done>>>\n");
	fflush(fp);
}

void
haadisc_dump_file(dumpfile)
	char *dumpfile;
{
	static FILE *fp;

	if ((fp = fopen(dumpfile, "w")) == NULL) {
		syslog(LOG_WARNING, "<%s> open a dump file(%s)",
		       __FUNCTION__, dumpfile);
		return;
	}

	hal_dump(fp);

	fclose(fp);
}
