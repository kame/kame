/*	$KAME: mpa.c,v 1.13 2004/08/19 11:28:24 sumikawa Exp $	*/

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
 * $Id: mpa.c,v 1.13 2004/08/19 11:28:24 sumikawa Exp $
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>

#if defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/callout.h>
#elif defined(__OpenBSD__)
#include <sys/timeout.h>
#endif

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
#include <netinet/ip6mh.h>

#include <arpa/inet.h>

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include <kvm.h>
#include <nlist.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>
#include <fcntl.h>
#include <limits.h>

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include "halist.h"

struct sockin6_addr {
  LIST_ENTRY (sockin6_addr)   sockin6_entry;
  struct sockaddr_in6 addr;
};
LIST_HEAD(sockin6_addr_list, sockin6_addr);

static void mpi_advert_output __P((struct sockaddr_in6 *, struct in6_addr *, struct hagent_ifinfo *, u_int16_t));
static int reg_hoa_pick __P((struct in6_addr *, struct in6_addr *hoaddr));
static int reg_coa_pick __P((struct sockin6_addr_list *));
static int pi_pick __P((struct in6_addr *, struct nd_opt_prefix_info *, struct hagent_ifinfo *, int));
static int ha_pick __P((struct in6_addr *, struct in6_addr *, struct hagent_ifinfo *));
static int prefix_dup_check __P((struct nd_opt_prefix_info *, struct hagent_gaddr *, int));
static int get_bc_list __P((struct mip6_bc_list *));
static int kread __P((u_long addr, void *buf, int size));
static int kwrite __P((u_long addr, void *buf, int size));

struct nlist nl[] = {
#define N_MIP6_BC_LIST      0
        { "_mip6_bc_list" },
        { NULL }
};

kvm_t *kvmd = NULL;

extern struct msghdr rcvmhdr, sndmhdr;
extern int sock;

#define KREAD(addr, buf, type) \
        kread((u_long)addr, (void *)buf, sizeof(type))
#define KWRITE(addr, buf, type) \
        kwrite((u_long)addr, (void *)buf, sizeof(type))
#define min(a, b)	(((a) > (b)) ? (b) : (a))
#define abs(a)		(((a) > 0) ? (a) : (-a))

/* 
 * Receive Mobile Prefix Solicitation message
 */
void
mpi_solicit_input(pi, sin6_hoa, mps)
    struct in6_pktinfo *pi;
    struct sockaddr_in6 *sin6_hoa;
    struct mip6_prefix_solicit *mps; 
{   
    int ifga_index = -1;
    struct in6_addr ha_addr;
    struct hagent_ifinfo *haif;
    struct in6_addr src;
    int error;
   
    if(kvmd == NULL)
	return;

    ha_addr = pi->ipi6_addr;
    /* determine a home link by the global address */
    haif = haif_findwithunicast(&pi->ipi6_addr, &ifga_index);

    if (!haif) {
        syslog(LOG_ERR, __FUNCTION__, "cannot get home agent ifinfo.\n");
        goto err;
    }

#ifdef TODO
    if (ha_addr is not a home agent addr which is set in the binding cache entry for the mobile node which sent this mobile prefix solicitation) {
	    select one global address
    } else
#endif
    src = ha_addr;
    mpi_advert_output(sin6_hoa, &src, haif, mps->mip6_ps_id);
err:
    ;
}

/* 
 * Send Mobile Prefix Advertisement message
 */
void
mpi_advert_output(dst_sa, src, haif, id)
    struct sockaddr_in6 *dst_sa;	/* home addr of destination MN */
    struct in6_addr *src;
    struct hagent_ifinfo *haif;
    u_int16_t id;
{   
    struct cmsghdr *cm;
    struct nd_opt_prefix_info *prefix_info;
    u_int8_t buf[IPV6_MMTU];
    struct mip6_prefix_advert *map;
    int len;
    int count;
    int npi;
    struct in6_pktinfo *pi;
    
    /* create ICMPv6 message */
    map = (struct mip6_prefix_advert *)buf;
    bzero(map, sizeof (struct mip6_prefix_advert));
    map->mip6_pa_type = MIP6_PREFIX_ADVERT;
    map->mip6_pa_code = 0;

    len = sizeof(struct mip6_prefix_advert);
    prefix_info = (struct nd_opt_prefix_info *)&map[1];
    /* count number of prefix informations -- to make assurance (not in spec.) */
    count = (IPV6_MMTU - sizeof (struct ip6_hdr) - /* XXX: should include the size of routing header*/
			 sizeof (struct mip6_prefix_advert)) / sizeof (struct nd_opt_prefix_info);

    /* Pick home agent prefixes */
    /* -- search by dest. address instead of Home Address */
    if ((npi = pi_pick(src, prefix_info, haif, count)) < 0) {
        syslog(LOG_ERR, __FUNCTION__, "cannot fild any home agent prefixes in home agent list.\n");
        goto err;
    }
    
    if(!npi)
         return;
    
    len += npi * sizeof (struct nd_opt_prefix_info);

    map->mip6_pa_cksum = 0;
    map->mip6_pa_id = id;
    sndmhdr.msg_name = (caddr_t)dst_sa;
    sndmhdr.msg_namelen = dst_sa->sin6_len;
    sndmhdr.msg_iov[0].iov_base = (caddr_t)buf;
    sndmhdr.msg_iov[0].iov_len = len;

    cm = CMSG_FIRSTHDR(&sndmhdr);
    /* specify source address */
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    pi = (struct in6_pktinfo *)CMSG_DATA(cm);
    pi->ipi6_addr = *src;
    pi->ipi6_ifindex = 0; /* determined with a routing table */

    if ((len = sendmsg(sock, &sndmhdr, 0)) < 0) {
        syslog(LOG_ERR, __FUNCTION__, "%s.\n", strerror(errno));
        goto err;
    }
err:
    ;
}

/*
 * pick up prefixes for home agents on specified link and prefix
 */
int
pi_pick(home_addr, prefix_info, haif, count)
    struct in6_addr *home_addr;
    struct nd_opt_prefix_info *prefix_info;
    struct hagent_ifinfo *haif;
    int count;
{
    int naddr;
    struct hagent_entry *hap;
    struct hagent_gaddr *ha_gaddr;
    struct nd_opt_prefix_info *h_prefix_info;
    struct timeval now;
    u_int32_t vltime, pltime;
	
    h_prefix_info = prefix_info;
    /* search home agent list and pick all prefixes */
    for (naddr = 0, hap = haif->halist_pref.hagent_next_pref;
         hap && naddr < count; hap = hap->hagent_next_pref) {
	for (ha_gaddr = hap->hagent_galist.hagent_next_gaddr;
	    (ha_gaddr != NULL) && (naddr < count);
	    ha_gaddr = ha_gaddr->hagent_next_gaddr) {
	    /* duplication check whether MPA includes duplecated prefixes */
	    if (prefix_dup_check(h_prefix_info, ha_gaddr, naddr))
		/* duplicated prefix is included */
		continue;

	    /* make prefix information */
	    prefix_info->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	    prefix_info->nd_opt_pi_len = 4;
	    prefix_info->nd_opt_pi_prefix_len = ha_gaddr->hagent_prefixlen;
	    prefix_info->nd_opt_pi_flags_reserved = 0;

	    if (ha_gaddr->hagent_flags.onlink)
		prefix_info->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
	    if (ha_gaddr->hagent_flags.autonomous)
                prefix_info->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	    if (ha_gaddr->hagent_flags.router)
		prefix_info->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ROUTER;

	    if (ha_gaddr->hagent_vltime || ha_gaddr->hagent_pltime)
		gettimeofday(&now, NULL);
	    if (ha_gaddr->hagent_vltime == 0)
		vltime = ha_gaddr->hagent_expire;
	    else
		vltime = (ha_gaddr->hagent_expire > now.tv_sec) ?
		    ha_gaddr->hagent_expire - now.tv_sec : 0;
	    if (ha_gaddr->hagent_pltime == 0)
		pltime = ha_gaddr->hagent_preferred;
	    else
		pltime = (ha_gaddr->hagent_preferred > now.tv_sec) ? 
		    ha_gaddr->hagent_preferred - now.tv_sec : 0;
	    if (vltime < pltime) {
		/*
                 * this can happen if vltime is decrement but pltime
                 * is not.
                 */
		pltime = vltime;
	    }
	    prefix_info->nd_opt_pi_valid_time = htonl(vltime);
	    prefix_info->nd_opt_pi_preferred_time = htonl(pltime);
	    prefix_info->nd_opt_pi_reserved2 = 0;
	    prefix_info->nd_opt_pi_prefix = ha_gaddr->hagent_gaddr;

	    prefix_info ++;
	    naddr ++;
	}
    }
    return naddr;
}

/*
 * pick up address for home agents whose prefix is same as HoA
 */
int
ha_pick(home_addr, src_addr, haif)
    struct in6_addr *home_addr;
    struct in6_addr *src_addr;
    struct hagent_ifinfo *haif;
{
    struct hagent_entry *hap;
    struct hagent_gaddr *ha_gaddr;
    struct hagent_gaddr hagent_addr;

    /* search home agent list and pick appropriate global addresses */
    for (hap = &(haif->halist_pref); hap; hap = hap->hagent_next_pref) {
        ha_gaddr = hap->hagent_galist.hagent_next_gaddr;
        if (!get_gaddr(ha_gaddr, home_addr, &hagent_addr)){
            /* found */
            *src_addr = hagent_addr.hagent_gaddr;
            return 0;
        }
    }

    /* not found */
    return -1;
}

/*
 * prefix duplication check
 */
int
prefix_dup_check(prefix_info, ha_gaddr, naddr)
    struct nd_opt_prefix_info *prefix_info;
    struct hagent_gaddr *ha_gaddr;
    int naddr;
{
    int i;
    for (i = 0; i < naddr; i++, prefix_info++){
      if(prefix_info->nd_opt_pi_prefix_len == ha_gaddr->hagent_prefixlen){
        struct in6_addr mask;
        create_mask(&mask, ha_gaddr->hagent_prefixlen);
        if (IN6_ARE_ADDR_MASKEQUAL(prefix_info->nd_opt_pi_prefix, mask, 
                                   ha_gaddr->hagent_gaddr))
            return -1;
      }
    }
    return 0;
}

/*
 * get registerd Home Address binding with given CoA
 */
int
reg_hoa_pick(coaddr, hoaddr)
    struct in6_addr *coaddr;
    struct in6_addr *hoaddr;
{
    struct mip6_bc *mbc, mip6_bc;
    struct mip6_bc_list mip6_bc_list;

    if (get_bc_list(&mip6_bc_list))
        return -1;
	
    for (mbc = LIST_FIRST(&mip6_bc_list);
         mbc;
         mbc = LIST_NEXT(mbc, mbc_entry)) {
        if (KREAD(mbc, &mip6_bc, mip6_bc)) {
            return (-1);
	}
        mbc = &mip6_bc;
        if (IN6_ARE_ADDR_EQUAL(&(mbc->mbc_pcoa), coaddr))
            break;
    }
    
    if (!mbc)
        return -1;

    bcopy(&(mbc->mbc_phaddr), hoaddr, sizeof (struct in6_addr));
    
    return 0;
}

/*
 * get registerd Care-of Address binding with given HA's prefix
 */
int
reg_coa_pick(addr_list)
    struct sockin6_addr_list *addr_list;
{
    struct mip6_bc *mbc, mip6_bc;
    struct mip6_bc_list mip6_bc_list;
    
    if (get_bc_list(&mip6_bc_list))
	 return -1;
    
    for (mbc = LIST_FIRST(&mip6_bc_list);
         mbc;
         mbc = LIST_NEXT(mbc, mbc_entry)) {
        if (KREAD(mbc, &mip6_bc, mip6_bc))
            return (-1);
        mbc = &mip6_bc;
        if (mbc->mbc_flags & IP6MU_HOME) {
            int dup = 0;
            struct sockin6_addr *addrp;

            for (addrp = LIST_FIRST(addr_list);
                 addrp;
                 addrp = LIST_NEXT(addrp, sockin6_entry)) {
			if (IN6_ARE_ADDR_EQUAL(&(mbc->mbc_pcoa), &(addrp->addr.sin6_addr))) {
				dup = -1;
				break;
			}
	    }
            
            if(!dup) {
                struct sockin6_addr *nmbc;

		nmbc = (struct sockin6_addr *)malloc(sizeof(struct sockin6_addr *));
		if (nmbc == NULL) {
			perror("reg_coa_pick():malloc");
		}
                bcopy(&(mbc->mbc_pcoa), &(nmbc->addr), sizeof(struct sockaddr_in6));
		LIST_INSERT_HEAD(addr_list, nmbc, sockin6_entry);
            }			  
        }
    }
    
    return 0;
}

/*
 * get binding cache entries
 */
int
get_bc_list(mip6_bc_list)
    struct mip6_bc_list *mip6_bc_list;
{
    if (kvm_nlist(kvmd, nl) < 0) {
        fprintf(stderr, "no namelist\n");
        goto err;
    }

    if (nl[N_MIP6_BC_LIST].n_value == 0) {
        fprintf(stderr, "bc not found\n");
        goto err;
    }

    return (KREAD(nl[N_MIP6_BC_LIST].n_value, mip6_bc_list, &mip6_bc_list));

err:
    return -1;
}

/*	This function should be reconsidered */
void
examine_mpaexp_bc()
{
    int index;
    time_t time_second;
    int32_t max_sched_delay;
    u_int32_t rand_adv_delay;
    struct in6_addr *hagent_addr;
    struct hagent_ifinfo *haif;
    struct hagent_entry *hal;
    struct hagent_gaddr *galp;
    struct mip6_bc *mbc, mip6_bc;
    struct mip6_bc_list mip6_bc_list;
    struct sockaddr_in6 phaddr_sa;
    
    if (get_bc_list(&mip6_bc_list))
	return;
    if (time(&time_second) == -1)
	return;
    
    for (mbc = LIST_FIRST(&mip6_bc_list);
         mbc;
         mbc = LIST_NEXT(&mip6_bc, mbc_entry)) {
        if (KREAD(mbc, &mip6_bc, mip6_bc))
            return;
        if ((mip6_bc.mbc_flags & IP6MU_HOME) == 0)
	    continue;

	if (mip6_bc.mbc_mpa_exp > time_second)
	    continue;

    	if ((haif = haif_findwithhomeaddr(&mip6_bc.mbc_phaddr, &index)) == NULL)
	    continue;

	hagent_addr = &((struct sockaddr_in6 *)(haif->haif_gavec[index].global->ifa_addr))->sin6_addr;

	for (hal = &haif->halist_pref; hal; hal = hal->hagent_next_pref) {
	    for (galp = hal->hagent_galist.hagent_next_gaddr;
		 galp; galp = galp->hagent_next_gaddr) {
		if (IN6_ARE_ADDR_EQUAL(&(galp->hagent_gaddr), hagent_addr))
		    break;
	    }
	    if (galp)
		break;
	}
	if (!galp)
	    return;

	/* Sending MPA */
	bzero(&phaddr_sa, sizeof(phaddr_sa));
	phaddr_sa.sin6_len = sizeof(phaddr_sa);
	phaddr_sa.sin6_family = AF_INET6;
	phaddr_sa.sin6_addr = mip6_bc.mbc_phaddr;
#ifdef __KAME__
	if (IN6_IS_ADDR_LINKLOCAL(&phaddr_sa.sin6_addr)) {
	    phaddr_sa.sin6_scope_id = ntohs(*(u_int16_t *)&phaddr_sa.sin6_addr.s6_addr[2]);
	    *(u_int16_t *)&phaddr_sa.sin6_addr.s6_addr[2] = 0;
	}
#endif
        mpi_advert_output(&phaddr_sa, hagent_addr, haif, 0);

	/* Update mpa expiration time */
	/* XXX ; These constants should be customized  */
	max_sched_delay = min(MIP6_MAX_MOB_PFX_ADV_INTERVAL, galp->hagent_pltime);
	rand_adv_delay = MIP6_MIN_MOB_PFX_ADV_INTERVAL
			 + (random() % abs(max_sched_delay - MIP6_MIN_MOB_PFX_ADV_INTERVAL));
	mip6_bc.mbc_mpa_exp = time_second + rand_adv_delay;

	/* DANGER! DANGER! DANGER! */
	KWRITE(&mbc->mbc_mpa_exp, mip6_bc.mbc_mpa_exp, mip6_bc.mbc_mpa_exp);
    }
}

int
kread(addr, buf, size)
    u_long addr;
    void *buf;
    int size;
{
    if (kvm_read(kvmd, addr, buf, size) != size) {
        fprintf(stderr, "%s\n", kvm_geterr(kvmd));
        return -1;
    }

    return 0;
}

int
kwrite(addr, buf, size)
    u_long addr;
    void *buf;
    int size;
{
    if (kvm_write(kvmd, addr, buf, size) != size) {
        fprintf(stderr, "%s\n", kvm_geterr(kvmd));
        return -1;
    }

    return 0;
}

void
kinit()
{
    char kvm_err[_POSIX2_LINE_MAX];

    if ((kvmd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, kvm_err)) == NULL) {
        fprintf(stderr, "(%s)\n", kvm_err);
    }
    
}

void
kfinish()
{
    kvm_close(kvmd);
}

