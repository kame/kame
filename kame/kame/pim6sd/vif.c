/*	$KAME: vif.c,v 1.41 2004/06/09 16:24:13 suz Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
 * This program has been derived from pim6dd.        
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.        
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_mroute.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "defs.h"
#include "vif.h"
#include "mld6.h"
#include "mld6v2.h"
#include "mrt.h"
#include "pim6.h"
#include "pimd.h"
#include "route.h"
#include "config.h"
#include "inet6.h"
#include "kern.h"
#include "mld6_proto.h"
#include "mld6v2_proto.h"
#include "pim6_proto.h"
#include "mrt.h"
#include "debug.h"
#include "timer.h"
#include "callout.h"

struct uvif	uvifs[MAXMIFS];	/*the list of virtualsinterfaces */
mifi_t numvifs;				/*total number of interface */
int vifs_down;
mifi_t reg_vif_num;		   /*register interface*/
int default_vif_status;
int phys_vif; /* An enabled vif that has a global address */
int udp_socket;
int total_interfaces;
if_set			if_nullset;
if_set			if_result;

int init_reg_vif __P((void));
void start_all_vifs __P((void));
void start_vif __P((mifi_t vifi));
void stop_vif __P((mifi_t vivi));
int update_reg_vif __P((mifi_t register_vifi));

extern void add_phaddr __P((struct uvif *, struct sockaddr_in6 *,
		           struct in6_addr *, struct sockaddr_in6 *));
extern int cfparse __P((int, int));

void init_vifs()
{
	mifi_t vifi;
	struct uvif *v;
	int enabled_vifs;

	numvifs = 0;
	reg_vif_num = NO_VIF;

	/*
	 * Configure the vifs based on the interface configuration of
	 * the kernel and the contents of the configuration file.
	 * (Open a UDP socket for ioctl use in the config procedures if
	 * the kernel can't handle IOCTL's on the MLD socket.)
	 */
#ifdef IOCTL_OK_ON_RAW_SOCKET
	udp_socket = mld6_socket;
#else
	if ((udp_socket = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		log_msg(LOG_ERR, errno, "UDP6 socket");
#endif

	/* clean all the interfaces ... */

	for (vifi = 0, v = uvifs; vifi < MAXMIFS; ++vifi, ++v) {
		memset(v, 0, sizeof(*v));
		v->uv_metric = DEFAULT_METRIC;
		v->uv_rate_limit = DEFAULT_PHY_RATE_LIMIT;
		strncpy(v->uv_name, "", IFNAMSIZ);
		v->uv_local_pref = default_source_preference;
		v->uv_local_metric = default_source_metric;
		v->uv_mld_version = MLD6_DEFAULT_VERSION;
		v->uv_mld_robustness = MLD6_DEFAULT_ROBUSTNESS_VARIABLE;
		v->uv_mld_query_interval = MLD6_DEFAULT_QUERY_INTERVAL;
		v->uv_mld_query_rsp_interval = MLD6_DEFAULT_QUERY_RESPONSE_INTERVAL;
		v->uv_mld_llqi = MLD6_DEFAULT_LAST_LISTENER_QUERY_INTERVAL;
	}
	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "Interfaces world initialized...");
	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "Getting vifs from %s", configfilename);

	/* read config from file */
	if (cfparse(1, 0) != 0)
		log_msg(LOG_ERR, 0, "fatal error in parsing the config file");

	enabled_vifs = 0;
	phys_vif = -1;

	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "Getting vifs from kernel");
	config_vifs_from_kernel();

	/* IPv6 PIM needs one global unicast address (at least for now) */
	if (max_global_address() == NULL)
		log_msg(LOG_ERR, 0, "There's no global address available");

	for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
		struct phaddr *p;
		if (v->uv_flags & (VIFF_DISABLED | MIFF_REGISTER))
			continue;

		enabled_vifs++;
		if (v->uv_flags & VIFF_DOWN)
			continue;
		if (v->uv_linklocal == NULL)
			log_msg(LOG_ERR, 0,
			    "there is no link-local address on vif %s",
			    v->uv_name);

		/* If this vif has a global address, set its id to phys_vif */
		if (phys_vif != -1)
			continue;
		for (p = v->uv_addrs; p; p = p->pa_next) {
			if (!IN6_IS_ADDR_LINKLOCAL(&p->pa_addr.sin6_addr) &&
			    !IN6_IS_ADDR_SITELOCAL(&p->pa_addr.sin6_addr)) {
				phys_vif = vifi;
				break;
			}
		}
	}
	if (enabled_vifs < 2)
		log_msg(LOG_ERR, 0, "can't forward: %s",
		    enabled_vifs == 0 ? "no enabled vifs" :
		     "only one enabled vif");

	memset(&if_nullset, 0, sizeof(if_nullset));
	k_init_pim(mld6_socket);	
	IF_DEBUG(DEBUG_PIM_DETAIL)
		log_msg(LOG_DEBUG, 0, "Pim kernel initialization done");


	/* Add a dummy virtual interface to support Registers in the kernel. */
 	init_reg_vif();

	start_all_vifs();

}

int init_reg_vif()
{
	struct uvif *v;
	mifi_t i;

	v = &uvifs[numvifs];
	if ((numvifs + 1) == MAXMIFS) {
	     /* Exit the program! The PIM router must have a Register vif */
	    log_msg(LOG_ERR, 0,
		"cannot install the Register vif: too many interfaces");
	    /* To make lint happy */
	    return (FALSE);
	}

	/*
	 * So far in PIM we need only one register vif and we save its number in
	 * the global reg_vif_num.
	 */


	reg_vif_num = numvifs;


	/* 
	 * copy the address of the first available physical interface to
	 * create the register vif.
	 */
	for (i =0 ; i < numvifs ; i++) {
		if (uvifs[i].uv_flags & (VIFF_DOWN | VIFF_DISABLED | MIFF_REGISTER))
			continue;
		break;
	}
	if (i >= numvifs) {
		log_msg(LOG_ERR, 0, "No physical interface enabled");
		return -1;
	}
	
	add_phaddr(v, &uvifs[i].uv_linklocal->pa_addr,
		   &uvifs[i].uv_linklocal->pa_subnetmask,
		   &uvifs[i].uv_linklocal->pa_prefix); 
	v->uv_ifindex = uvifs[i].uv_ifindex;
	strncpy(v->uv_name, "register_mif0", IFNAMSIZ);
	v->uv_flags = MIFF_REGISTER;
	v->uv_mld_version = MLDv1;

#ifdef PIM_EXPERIMENTAL
	v->uv_flags |= MIFF_REGISTER_KERNEL_ENCAP;
#endif

	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0,
		    "Interface %s (subnet %s), installed on vif #%u - rate = %d",
		    v->uv_name,
		    net6name(&v->uv_prefix.sin6_addr,&v->uv_subnetmask),
		    reg_vif_num,
		    v->uv_rate_limit);

	numvifs++;
	total_interfaces++;
	return 0;	
}

void start_all_vifs()
{
	mifi_t vifi;
	struct uvif *v;
	u_int action;


	/* Start first the NON-REGISTER vifs */
	for (action = 0; ; action = MIFF_REGISTER) {
		for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
			/*
			 * If starting non-registers but the vif is a register
			 * or if starting registers, but the interface is not
			 * a register, then just continue.
			 */
			if ((v->uv_flags & MIFF_REGISTER) ^ action)
				continue;

			if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN)) {
				IF_DEBUG(DEBUG_IF)
					log_msg(LOG_DEBUG, 0,
					    "%s is %s; vif #%u out of service",
					    v->uv_name,
					    v->uv_flags & VIFF_DISABLED ? "DISABLED" : "DOWN",
					    vifi); 
				continue;
			}
			start_vif(vifi);
		}
		if (action == MIFF_REGISTER)
			break;
	}
}

/*
 * Initialize the vif and add to the kernel. The vif can be either
 * physical, register or tunnel (tunnels will be used in the future
 * when this code becomes PIM multicast boarder router.
 */
void start_vif (mifi_t vifi)
{
	struct uvif *v;

	v = &uvifs[vifi];

	/* Initialy no router on any vif */

	if( v-> uv_flags & MIFF_REGISTER)
		v->uv_flags = v->uv_flags & ~VIFF_DOWN;
	else
	{
		v->uv_flags = (v->uv_flags | VIFF_DR | VIFF_NONBRS) & ~ VIFF_DOWN;
		v->uv_pim_hello_timer = 1 + RANDOM() % pim_hello_period;
		v->uv_jp_timer = 1 + RANDOM() % pim_join_prune_period;
	}

	/* Tell kernel to add, i.e. start this vif */

	k_add_vif(mld6_socket,vifi,&uvifs[vifi]);
	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG,0,"%s comes up ,vif #%u now in service",v->uv_name,vifi);

	if (!(v->uv_flags & MIFF_REGISTER)) {
	    /*
	     * Join the PIM multicast group on the interface.
	     */
	    k_join(mld6_socket, &allpim6routers_group.sin6_addr,
		   v->uv_ifindex);

	    /*
	     * Join the ALL-ROUTERS multicast group on the interface.
	     * This allows mtrace requests to loop back if they are run
	     * on the multicast router.this allow receiving mld6 messages too.
	     */
	    k_join(mld6_socket, &allrouters_group.sin6_addr, v->uv_ifindex);

	    /*
	     * Until neighbors are discovered, assume responsibility for sending
	     * periodic group membership queries to the subnet.  Send the first
	     * query.
	     */
	    v->uv_flags |= VIFF_QUERIER;
	    if (!v->uv_querier) {
		v->uv_querier = (struct listaddr *)malloc(sizeof(struct listaddr));
		memset(v->uv_querier, 0, sizeof(struct listaddr));
	    }
	    v->uv_querier->al_addr = v->uv_linklocal->pa_addr;
	    v->uv_querier->al_timer = MLD6_OTHER_QUERIER_PRESENT_INTERVAL;
	    time(&v->uv_querier->al_ctime); /* reset timestamp */
	    v->uv_stquery_cnt = MLD6_STARTUP_QUERY_COUNT;

#ifdef MLD6V2_LISTENER_REPORT
	    if (v->uv_mld_version & MLDv2)
		query_groupsV2(v);
	    else
#endif
	        if (v->uv_mld_version & MLDv1)
			query_groups(v);
  
	    /*
	     * Send a probe via the new vif to look for neighbors.
	     */
	    send_pim6_hello(v, pim_hello_holdtime);
	}
}

/*
 * Stop a vif (either physical interface, tunnel or
 * register.) If we are running only PIM we don't have tunnels.
 */ 


void
stop_vif(mifi_t vifi)
{
	struct uvif *v;
	struct listaddr *a;
	register pim_nbr_entry_t *n;
	register pim_nbr_entry_t *next
	struct vif_acl *acl;
 
	/*
	 * TODO: make sure that the kernel viftable is
	 * consistent with the daemon table
	 */
	v = &uvifs[vifi];
	if (!(v->uv_flags & MIFF_REGISTER)) {
		k_leave(mld6_socket, &allpim6routers_group.sin6_addr,
			v->uv_ifindex);
		k_leave(mld6_socket, &allrouters_group.sin6_addr,
			v->uv_ifindex);

		/*
		 * Discard all group addresses.  (No need to tell kernel;
		 * the k_del_vif() call will clean up kernel state.)
		 */
		while (v->uv_groups != NULL) {
			a = v->uv_groups;
			v->uv_groups = a->al_next;

			/* reset all the timers */
			if (a->al_query) {
			    timer_clearTimer(a->al_query);
			}
			if (a->al_timerid) {
			    timer_clearTimer(a->al_timerid);
			}

			/* frees all the related sources */
			while (a->sources != NULL) {
			    struct listaddr *curr = a->sources;
			    a->sources = a->sources->al_next;
			    free((char *)curr);
			}
			a->sources = NULL;

			/* discard the group */
			free((char *)a);
		}
		v->uv_groups = NULL;
	}

	/*
	 * TODO: inform (eventually) the neighbors I am going down by sending
	 * PIM_HELLO with holdtime=0 so someone else should become a DR.
	 */
	/* TODO: dummy! Implement it!! Any problems if don't use it? */
	delete_vif_from_mrt(vifi);

	/*
	 * Delete the interface from the kernel's vif structure.
	 */
	k_del_vif(mld6_socket, vifi);
	v->uv_flags = (v->uv_flags & ~VIFF_DR & ~VIFF_QUERIER & ~VIFF_NONBRS) | VIFF_DOWN;
	if (!(v->uv_flags & MIFF_REGISTER)) {
		RESET_TIMER(v->uv_pim_hello_timer);
		RESET_TIMER(v->uv_jp_timer);
		RESET_TIMER(v->uv_gq_timer);

		for (n = v->uv_pim_neighbors; n != NULL; n = next) {
			/* Free the space for each neighbour */
			next = n->next;
			delete_pim6_nbr(n);
		}
		v->uv_pim_neighbors = NULL;
	}
	if (v->uv_querier != NULL) {
	    free(v->uv_querier);
	    v->uv_querier = NULL;
	}

	/* I/F address list */
	{
	    struct phaddr *pa, *pa_next;
	    for (pa = v->uv_addrs; pa; pa = pa_next) {
		pa_next = pa->pa_next;
		free(pa);
	    }
	}
	v->uv_addrs = NULL;
	v->uv_linklocal = NULL; /* uv_linklocal must be in uv_addrs */

	/* TODO: currently not used */
	/* The Access Control List (list with the scoped addresses) */
	while (v->uv_acl != NULL) {
		acl = v->uv_acl;
		v->uv_acl = acl->acl_next;
		free((char *)acl);
	}

	vifs_down = TRUE;

	IF_DEBUG(DEBUG_IF)
		log_msg(LOG_DEBUG, 0, "%s goes down, vif #%u out of service",
			v->uv_name, vifi);
}

/*
 * Update the register vif in the multicast routing daemon and the
 * kernel because the interface used initially to get its local address
 * is DOWN. register_vifi is the index to the Register vif which needs
 * to be updated. As a result the Register vif has a new uv_lcl_addr and
 * is UP (virtually :))
 */
int
update_reg_vif( mifi_t register_vifi )
{
    register struct uvif *v;
    register mifi_t vifi;

    /* Find the first useable vif with solid physical background */
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | MIFF_REGISTER))
	    continue;
        /* Found. Stop the bogus Register vif first */
	stop_vif(register_vifi);
	add_phaddr(v, &uvifs[vifi].uv_linklocal->pa_addr,
		   &uvifs[vifi].uv_linklocal->pa_subnetmask,
		   &uvifs[vifi].uv_linklocal->pa_prefix); 
	start_vif(register_vifi);
	IF_DEBUG(DEBUG_PIM_REGISTER | DEBUG_IF)
	    log_msg(LOG_NOTICE, 0, "%s has come up; vif #%u now in service",
		uvifs[register_vifi].uv_name, register_vifi);
	return 0;
    }
    vifs_down = TRUE;
    log_msg(LOG_WARNING, 0, "Cannot start Register vif: %s",
	uvifs[vifi].uv_name);
    return(-1);
}

/*
 * return the max global Ipv6 address of an UP and ENABLED interface
 * other than the MIFF_REGISTER interface.
*/
struct sockaddr_in6 *
max_global_address()
{
	mifi_t vifi;
	struct uvif *v;
	struct phaddr *p;
	struct phaddr *pmax = NULL;

	for(vifi=0,v=uvifs;vifi< numvifs;++vifi,++v)
	{
		if(v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | MIFF_REGISTER))
			continue;
		/*
		 * take first the max global address of the interface
		 * (without link local) => aliasing
		 */
		for(p=v->uv_addrs;p!=NULL;p=p->pa_next)
		{
			/*
			 * If this is the first global address, take it anyway.
			 */
			if (pmax == NULL) {
				if (!IN6_IS_ADDR_LINKLOCAL(&p->pa_addr.sin6_addr) &&
				    !IN6_IS_ADDR_SITELOCAL(&p->pa_addr.sin6_addr))
					pmax = p;
			}
			else {
				if (inet6_lessthan(&pmax->pa_addr,
						   &p->pa_addr) &&
				    !IN6_IS_ADDR_LINKLOCAL(&p->pa_addr.sin6_addr) &&
				    !IN6_IS_ADDR_SITELOCAL(&p->pa_addr.sin6_addr))
					pmax=p;	
			}
		}
	}

	return(pmax ? &pmax->pa_addr : NULL);
}

struct sockaddr_in6 *
uv_global(vifi)
	mifi_t vifi;
{
	struct uvif *v = &uvifs[vifi];
	struct phaddr *p;

	for (p = v->uv_addrs; p; p = p->pa_next) {
		if (!IN6_IS_ADDR_LINKLOCAL(&p->pa_addr.sin6_addr) &&
		    !IN6_IS_ADDR_SITELOCAL(&p->pa_addr.sin6_addr))
			return(&p->pa_addr);
	}

	return(NULL);
}

/*
 * Check if the interface exists in the mif table. If true 
 * return the highest address of the interface else return NULL.
 */
struct sockaddr_in6 *
local_iface(char *ifname)
{
	register struct uvif *v;
	mifi_t vifi;
	struct phaddr *p;
	struct phaddr *pmax = NULL;

	for(vifi=0,v=uvifs;vifi<numvifs;++vifi,++v)
	{
		if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | MIFF_REGISTER))
			continue;
		if(EQUAL(v->uv_name, ifname))
		{
			for(p=v->uv_addrs; p!=NULL; p=p->pa_next)
			{
				if (!IN6_IS_ADDR_LINKLOCAL(&p->pa_addr.sin6_addr)&&
				    !IN6_IS_ADDR_SITELOCAL(&p->pa_addr.sin6_addr)) {
					/*
					 * If this is the first global address
					 * or larger than the current MAX global
					 * address, remember it.
					 */
					if (pmax == NULL ||
					    inet6_lessthan(&pmax->pa_addr,
							   &p->pa_addr))
						pmax = p;
				}
			}
			if (pmax)
				return(&pmax->pa_addr);
		}
	}

	return NULL;
}

/*  
 * See if any interfaces have changed from up state to down, or vice versa,
 * including any non-multicast-capable interfaces that are in use as local
 * tunnel end-points.  Ignore interfaces that have been administratively
 * disabled.
 */     
void
check_vif_state()
{
    register mifi_t vifi;
    register struct uvif *v;
    struct ifreq ifr;
    static int checking_vifs=0;

    /*
     * XXX: TODO: True only for DVMRP?? Check.
     * If we get an error while checking, (e.g. two interfaces go down
     * at once, and we decide to send a prune out one of the failed ones)
     * then don't go into an infinite loop!
     */
    if( checking_vifs )
	return;

    vifs_down=FALSE;
    checking_vifs=TRUE;

    /* TODO: Check all potential interfaces!!! */
    /* Check the physical and tunnels only */
    for( vifi=0 , v=uvifs ; vifi<numvifs ; ++vifi , ++v )
    {
	if( v->uv_flags & ( VIFF_DISABLED|MIFF_REGISTER	) )
	    continue;

	strncpy( ifr.ifr_name , v->uv_name , IFNAMSIZ );
  
	/* get the interface flags */
	if( ioctl( udp_socket , SIOCGIFFLAGS , (char *)&ifr )<0 )
	    log_msg(LOG_ERR, errno,
        	"check_vif_state: ioctl SIOCGIFFLAGS for %s", ifr.ifr_name);

	if( v->uv_flags & VIFF_DOWN )
	{
	    if ( ifr.ifr_flags & IFF_UP )
	    {
		start_vif( vifi );
	    }
	    else
		vifs_down=TRUE;
	}
	else
	{
	    if( !( ifr.ifr_flags & IFF_UP ))
	    {
		log_msg( LOG_NOTICE ,0,
		     "%s has gone down ; vif #%u taken out of  service",
		     v->uv_name , vifi );
		stop_vif ( vifi );
		vifs_down = TRUE;
	    }
	}
    }

    /* Check the register(s) vif(s) */
    for( vifi=0 , v=uvifs ; vifi<numvifs ; ++vifi , ++v )
    {
	register mifi_t vifi2;
	register struct uvif *v2;
	int found;

	if( !(v->uv_flags & MIFF_REGISTER ) )
	    continue;
	else
	{
	    found=0;

	    /* Find a physical vif with the same IP address as the
	     * Register vif.
	     */
	    for( vifi2=0 , v2=uvifs ; vifi2<numvifs ; ++vifi2 , ++v2 )
	    {
		if( v2->uv_flags & ( VIFF_DISABLED|VIFF_DOWN|MIFF_REGISTER ))
		    continue;
		if( IN6_ARE_ADDR_EQUAL( &v->uv_linklocal->pa_addr.sin6_addr,
					&v2->uv_linklocal->pa_addr.sin6_addr ))
		{
		    found=1;
		    break;
		}
	    }
	    if(!found)
		/* The physical interface with the IP address as the Register
		 * vif is probably DOWN. Get a replacement.
		 */
		update_reg_vif( vifi );
	}
    }
    checking_vifs=0;
}

/*
 * If the source is directly connected to us, find the vif number for
 * the corresponding physical interface (tunnels excluded).
 * Local addresses are excluded.
 * Return the vif number or NO_VIF if not found.
 */

mifi_t
find_vif_direct(src)
    struct sockaddr_in6 *src;
{
    mifi_t vifi;
    register struct uvif *v;
    register struct phaddr *p;
   
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) 
    {
    	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | MIFF_REGISTER))
        	continue;
	for (p = v->uv_addrs; p; p = p->pa_next) 
	{
            if (inet6_equal(src, &p->pa_addr))
                return(NO_VIF);

	    if (v->uv_flags & VIFF_POINT_TO_POINT)
	    	if (inet6_equal(src, &p->pa_rmt_addr))
		    return(vifi);
            if (inet6_match_prefix(src, &p->pa_prefix, &p->pa_subnetmask))
            	return(vifi);
    	}
    }

    return (NO_VIF);
}

/*
 * Checks if src is local address. If "yes" return the vif index,
 * otherwise return value is NO_VIF.
 */

mifi_t
local_address(src)
    struct sockaddr_in6 *src;
{
    mifi_t vifi;
    register struct uvif *v;
    register struct phaddr *p;

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | MIFF_REGISTER))
	    continue;
	for (p = v->uv_addrs; p; p = p->pa_next) {
	    if (inet6_equal(src, &p->pa_addr))
		return(vifi);
	}
    }
    /* Returning NO_VIF means not a local address */
    return (NO_VIF);
}


/*  
 * If the source is directly connected, or is local address,
 * find the vif number for the corresponding physical interface
 * (tunnels excluded).
 * Return the vif number or NO_VIF if not found.
 */ 

mifi_t
find_vif_direct_local(src)
    struct sockaddr_in6 *src;
{ 
    mifi_t vifi;
    register struct uvif *v; 
    register struct phaddr *p;
   

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
    	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | MIFF_REGISTER))
        	continue;
    	for (p = v->uv_addrs; p; p = p->pa_next) {
        	if (inet6_equal(src, &p->pa_addr) ||
            	    inet6_match_prefix(src, &p->pa_prefix, &p->pa_subnetmask))
        		return(vifi);

		if (v->uv_flags & VIFF_POINT_TO_POINT)
		    if (inet6_equal(src, &p->pa_rmt_addr))
			return(vifi);
    	}
    }
    return (NO_VIF);
}

int
vif_forwarder(if_set *p1 , if_set *p2)
{
	int idx;

	for(idx=0 ; idx < sizeof(*p1)/sizeof(fd_mask) ; idx++)
	{
		if (p1->ifs_bits[idx] & p2->ifs_bits[idx])
			return(TRUE);
		
	}

	/* (p1 & p2) is empty. We're not the forwarder */
	return(FALSE);
}

if_set *
vif_and(if_set *p1 , if_set *p2, if_set *result)
{
	int idx;

	IF_ZERO(result);

	for(idx=0 ; idx < sizeof(*p1)/sizeof(fd_mask) ; idx++)
	{
		result->ifs_bits[idx] = p1->ifs_bits[idx] & p2->ifs_bits[idx];
	}

	return(result);
}

if_set *
vif_xor(if_set *p1 , if_set *p2, if_set *result)
{
	int idx;

	IF_ZERO(result);

	for(idx=0 ; idx < sizeof(*p1)/sizeof(fd_mask) ; idx++)
	{
		result->ifs_bits[idx] =
			p1->ifs_bits[idx] ^ p2->ifs_bits[idx];
	}

	return(result);
}
/*  
 * stop all vifs
 */ 
void
stop_all_vifs()
{
    mifi_t vifi;
    struct uvif *v;
 
    for (vifi = 0, v=uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DOWN | VIFF_DISABLED))
		continue;
	stop_vif(vifi);
    }
}

/* 
 * locate vif from interface name, and allocate a new vif if necessary.
 * 2nd and 3rd arg controls the "necessity" when there is no matching vif.
 *   2nd arg: create vif if 3rd arg permits
 *   3rd arg: default policy to create vif, usually same as 
 *            default_phyint_status.  Only in configuration phase (i.e.
 *            prior to the configuration of this variable), it has to be
 *            specified properly.
 */
struct uvif *
find_vif(ifname, create, default_policy)
	char *ifname;
	int create;
	int default_policy;	
{
	u_int ifindex;
	struct uvif *v;
	mifi_t vifi;

	/* rejects non-existing interface */
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
		return NULL; 	

	/* not allocate same interface multiply */
	for (vifi = 0, v = uvifs; vifi < numvifs ; ++vifi , ++v) {
		if (ifindex == v->uv_ifindex)
			return v;
	}

	if (create == DONT_CREATE || default_policy != VIFF_ENABLED)
		return NULL;

	v = &uvifs[numvifs++];
	strncpy(v->uv_name, ifname, IFNAMSIZ);
	v->uv_ifindex = ifindex;
	v->uv_flags = VIFF_DOWN;
	return v;
}

char *
mif_name(mifi)
	mifi_t mifi;
{
	if (mifi < numvifs)
		return(uvifs[mifi].uv_name);
	else
		return("???");
}
