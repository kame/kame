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
#include "aspath.h"
#include "bgp_var.h"
#include "in6.h"
#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif 

static void get_ifinfo __P((struct ifinfo *));

/*
 *   Initialize "ifentry".
 *        (get information of each interface)
 */
void
ifconfig()
#ifdef HAVE_GETIFADDRS
{
  extern struct ifinfo *ifentry;
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in6 *sin6;
  struct ifinfo    *ife;
  int s;

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    fatal("<ifconfig>: socket");

  if (getifaddrs(&ifap))
    fatal("<ifconfig>: getifaddrs");

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr->sa_family == AF_INET6) {

      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

      if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
	if ((ife = find_if_by_name(ifa->ifa_name)) == NULL) { /* ifreq */
	  /* new interface */
	  MALLOC(ife,          struct ifinfo);
	  MALLOC(ife->ifi_ifn, struct if_nameindex);

	  ife->ifi_ifn->if_index = if_nametoindex(ifa->ifa_name);
	  ife->ifi_ifn->if_name  = (char *)malloc(strlen(ifa->ifa_name) +1);
	  strcpy(ife->ifi_ifn->if_name, ifa->ifa_name);

	  get_ifinfo(ife);

	  if (ifentry != NULL) {    /* (global) */
	    insque(ife, ifentry);
	  } else {
	    ife->ifi_next = ife; 
	    ife->ifi_prev = ife;
	    ifentry       = ife;
	  }
	} else {
	  if (!IN6_IS_ADDR_UNSPECIFIED(&ife->ifi_laddr))
	    fatalx("<ifconfig>: link-local address cannot be doubly defined");
	}
	memcpy(&ife->ifi_laddr, &sin6->sin6_addr, sizeof(struct in6_addr));
#ifdef ADVANCEDAPI
	CLEAR_IN6_LINKLOCAL_IFINDEX(&ife->ifi_laddr);/* Toshiba's IPv6 macro */
#endif
      }

      if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) &&
	  !IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) && /* should keep this? */
	  IN6_IS_ADDR_ROUTABLE(&sin6->sin6_addr)) {
	if ((ife = find_if_by_name(ifa->ifa_name)) == NULL) { /* ifreq */
	  /* new interface */
	  MALLOC(ife,          struct ifinfo);
	  MALLOC(ife->ifi_ifn, struct if_nameindex);

	  ife->ifi_ifn->if_index = if_nametoindex(ifa->ifa_name);
	  ife->ifi_ifn->if_name  = (char *)malloc(strlen(ifa->ifa_name) +1);

	  strcpy(ife->ifi_ifn->if_name, ifa->ifa_name);

	  get_ifinfo(ife);

	  if (ifentry != NULL) {    /* (global) */
	    insque(ife, ifentry);
	  } else {
	    ife->ifi_next = ife; 
	    ife->ifi_prev = ife;
	    ifentry       = ife;
	  }
	  memcpy(&ife->ifi_gaddr, &sin6->sin6_addr, sizeof(struct in6_addr));
	} else { /* ifentry found  */
	  struct in6_ifreq ifr;

	  strcpy(ifr.ifr_name, ife->ifi_ifn->if_name);
	  ifr.ifr_addr = *sin6;
	  if (ioctl(s, SIOCGIFAFLAG_IN6, (caddr_t)&ifr) != 0) {
	    fatal("<ifconfig>: SIOCGIFAFLAG_IN6");
	  } else {
	    if (
		!(ifr.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST) &&  /* new one */
		IN6_IS_ADDR_UNSPECIFIED(&ife->ifi_gaddr)) {    /* already */
	      memcpy(&ife->ifi_gaddr, &sin6->sin6_addr,
		     sizeof(struct in6_addr));
	    }
	  }
	}
      } /* not routable, but INET6 */
    }
  }

  close(s);
  free(ifa);
}
#else  /* !HAVE_GETIFADDRS */
{
  int                 s;
  int                 i;
  char                buf[BUFSIZ * MAXADDRS];
  struct ifconf       ifconf;  /* BSD  */
  struct ifreq       *ifrp;    /* BSD  */

  struct ifinfo    *ife;     /* ours */
  struct sockaddr_in6 *sin;

  extern struct ifinfo *ifentry;

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    fatal("<ifconfig>: socket");
  ifconf.ifc_buf = buf;
  ifconf.ifc_len = BUFSIZ * MAXADDRS;

  if (ioctl(s, SIOCGIFCONF, (char *)&ifconf) < 0)
    fatal("<ifconfig>: ioctl: SIOCGIFCONF");

  for (i = 0; i < ifconf.ifc_len; ) {
    ifrp = (struct ifreq *)(buf + i);
    if (ifrp->ifr_addr.sa_family == AF_INET6) {  /* IPv6 address */

      sin = (struct sockaddr_in6 *)&ifrp->ifr_addr;

      if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr)) {
	if ((ife = find_if_by_name(ifrp->ifr_name)) == NULL) { /* ifreq */
	  /* new interface */
	  MALLOC(ife,          struct ifinfo);
	  MALLOC(ife->ifi_ifn, struct if_nameindex);

	  ife->ifi_ifn->if_index = if_nametoindex(ifrp->ifr_name);
	  ife->ifi_ifn->if_name  = (char *)malloc(strlen(ifrp->ifr_name) +1);
	  strcpy(ife->ifi_ifn->if_name, ifrp->ifr_name);

	  get_ifinfo(ife);

	  if (ifentry != NULL) {    /* (global) */
	    insque(ife, ifentry);
	  } else {
	    ife->ifi_next = ife; 
	    ife->ifi_prev = ife;
	    ifentry       = ife;
	  }
	} else {
	  if (!IN6_IS_ADDR_UNSPECIFIED(&ife->ifi_laddr))
	    fatalx("<ifconfig>: link-local address cannot be doubly defined");
	}
	memcpy(&ife->ifi_laddr, &sin->sin6_addr, sizeof(struct in6_addr));
#ifdef ADVANCEDAPI
	CLEAR_IN6_LINKLOCAL_IFINDEX(&ife->ifi_laddr);/* Toshiba's IPv6 macro */
#endif
      }

      if (!IN6_IS_ADDR_UNSPECIFIED(&sin->sin6_addr) &&
	  !IN6_IS_ADDR_SITELOCAL(&sin->sin6_addr) && /* should keep this? */
	  IN6_IS_ADDR_ROUTABLE(&sin->sin6_addr)) {
	if ((ife = find_if_by_name(ifrp->ifr_name)) == NULL) { /* ifreq */
	  /* new interface */
	  MALLOC(ife,          struct ifinfo);
	  MALLOC(ife->ifi_ifn, struct if_nameindex);

	  ife->ifi_ifn->if_index = if_nametoindex(ifrp->ifr_name);
	  ife->ifi_ifn->if_name  = (char *)malloc(strlen(ifrp->ifr_name) +1);

	  strcpy(ife->ifi_ifn->if_name, ifrp->ifr_name);

	  get_ifinfo(ife);

	  if (ifentry != NULL) {    /* (global) */
	    insque(ife, ifentry);
	  } else {
	    ife->ifi_next = ife; 
	    ife->ifi_prev = ife;
	    ifentry       = ife;
	  }
	  memcpy(&ife->ifi_gaddr, &sin->sin6_addr, sizeof(struct in6_addr));

	} else { /* ifentry found  */
	  struct in6_ifreq ifr;
	  strcpy(ifr.ifr_name, ife->ifi_ifn->if_name); /* ife, sin,       */
	  ifr.ifr_addr = *sin;                       /* got by SIOCGIFCONF */
	  if (ioctl(s, SIOCGIFAFLAG_IN6, (caddr_t)&ifr) != 0) {
	    fatal("<ifconfig>: SIOCGIFAFLAG_IN6");
	  } else {
	    if (
		!(ifr.ifr_ifru.ifru_flags6 & IN6_IFF_ANYCAST) &&  /* new one */
		IN6_IS_ADDR_UNSPECIFIED(&ife->ifi_gaddr)) {    /* already */
	      memcpy(&ife->ifi_gaddr, &sin->sin6_addr, sizeof(struct in6_addr));
	    }
	  }
	}
      } /* not routable, but INET6 */

    }  /* End of AF_INET6 */

    i += IFNAMSIZ; /* 16 */

    if (ifrp->ifr_addr.sa_len > sizeof(struct sockaddr))
      i += ifrp->ifr_addr.sa_len;
    else
      i += sizeof(struct sockaddr);
  }
  close(s);
}
#endif /* HAVE_GETIFADDRS */

/*
 * Get interface flags.
 */
static void
get_ifinfo(struct ifinfo *ife)
{
	int s;
	struct ifreq ifr;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		fatal("<get_ifinfo>: socket");

	strcpy(ifr.ifr_name, ife->ifi_ifn->if_name);
	
	if (ioctl(s, SIOCGIFFLAGS, (char *)&ifr) < 0)
		fatal("<get_ifinfo>: ioctl SIOCGIFFLAGS");

	ife->ifi_flags = ifr.ifr_flags;

	close(s);
}

void
loconfig(loname)
     char *loname;
{
#if 0				/* XXX */
  int s;
  struct in6_aliasreq in6_aliasreq;

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    fatal("<loconfig>: socket");

  bzero(&in6_aliasreq, sizeof(in6_aliasreq));

  strcpy(in6_aliasreq.ifra_name, loname);

  in6_aliasreq.ifra6_addr.sin6_family = AF_INET6;
  in6_aliasreq.ifra6_addr.sin6_len    = sizeof(struct sockaddr_in6);
  in6_aliasreq.ifra6_addr.sin6_addr   = in6addr_loopback;

  in6_aliasreq.ifra6_mask.sin6_family = AF_UNSPEC;
  in6_aliasreq.ifra6_mask.sin6_len    = sizeof(struct sockaddr_in6);
  mask_nset(&in6_aliasreq.ifra6_mask.sin6_addr, 128);


  if (ioctl(s, SIOCAIFADDR_IN6, &in6_aliasreq) < 0) {
    fatal("<loconfig>: SIOCAIFADDR_IN6");
  }

  close(s);
#endif
}

/*
 *    find_if_by_index()
 */
struct ifinfo *
find_if_by_index(index)
     u_int index;
{
  struct ifinfo *ife;

  extern struct ifinfo *ifentry;
  
  if ((ife = ifentry) == NULL)
    return NULL;

  while(ife) {
    if (ife->ifi_ifn == NULL)
      fatalx("<find_if_by_index>: internal error");
    if (ife->ifi_ifn->if_index == index)
      return ife;
    if ((ife = ife->ifi_next) == ifentry)
      return NULL;
  }

  return NULL; /* NOT REACHED */
}



/*
 *    find_if_by_addr()
 */
struct ifinfo *
find_if_by_addr(addr)
     struct in6_addr *addr;
{
  struct ifinfo *ife;
  extern struct ifinfo *ifentry;

  ife = ifentry;
  
  while(ife) {
    if (IN6_ARE_ADDR_EQUAL(&ife->ifi_laddr, addr) ||
	IN6_ARE_ADDR_EQUAL(&ife->ifi_gaddr, addr))
      return ife;
 
    if ((ife = ife->ifi_next) == ifentry)
      return NULL;  /* not fonnd */
  }

  return NULL; /* NOT REACHED */
}



/*
 *    find_if_by_name()
 */
struct ifinfo *
find_if_by_name(ifname)
     char *ifname;
{
  struct ifinfo *ife;

  extern struct ifinfo *ifentry;

  if ((ife = ifentry) == NULL)
    return NULL;

  while(ife) {
    if (ife->ifi_ifn == NULL)
      return NULL;
    if (strcmp(ife->ifi_ifn->if_name, ifname) == 0)
      return ife;

    if ((ife = ife->ifi_next) == ifentry)
      return NULL;
  }

  return NULL; /* NOT REACHED */
}


/*
 *  get_32id()
 *    BGP Identifier must be determined in 4-octets.
 *    It shold be defined in a config file, but if not present, 
 *    our implementation choose the first non-zero IPv4 address to be a
 *    bgp-identifier by default.
 */
u_int32_t
get_32id()
{
  struct if_nameindex *head, *ifni;
  struct ifreq         ifr;
  u_int32_t            id = INADDR_ANY;
  int                  s;

  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) 
    return 0;

  memset(&ifr, 0, sizeof(ifr));
  head = if_nameindex();  /*  API of [rfc2553.txt]  */

  ifni = head;

  while(ifni->if_index) {
    strcpy(ifr.ifr_name, ifni->if_name);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {   /* IPv4 */
      IFLOG(LOG_INTERFACE)
	syslog(LOG_DEBUG, "<get_32id>: SIOCGIFADDR (%s): %s",
	       ifr.ifr_name, strerror(errno));
      ifni++;  /* next I/F */
    } else {
	    id = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

	    /* sanity check for 0.0.0.0 and 127.0.0.1  */
	    if (id == INADDR_ANY || ntohl(id) == 0x7f000001) {
		    id = INADDR_ANY;
		    ifni++;
	    }
	    else
		    break;	/* OK */
    }
  }

  if_freenameindex(head);
  close(s);

  if (id == INADDR_ANY)		/* not found */
	  return 0;

  return id;
}



/*
 *    assume IEEE 802 MAC address
 */
u_int32_t GET_IN6_IF_ID_OSPF(a)
     struct in6_addr *a;
{
  u_int32_t  id = 0;
  u_char    *buf;

  buf = (u_char *)&id;

  buf[0] = a->s6_addr[10];
  buf[1] = a->s6_addr[13];
  buf[2] = a->s6_addr[14];
  buf[3] = a->s6_addr[15];

  return id;
}
