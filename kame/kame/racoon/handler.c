/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
/* YIPS @(#)$Id: handler.c,v 1.1.1.1 1999/08/08 23:31:21 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>

#include <net/pfkeyv2.h>
#include <net/route.h>
#include <net/if.h>
#include <netkey/keydb.h>
#include <netkey/key_var.h>

#include <netinet/in.h>
#include <netinet6/ipsec.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#include "missing/getaddrinfo.h"
#endif

#include "var.h"
#include "vmbuf.h"
#include "schedule.h"
#include "cfparse.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "crypto.h"
#include "handler.h"
#include "pfkey.h"
#include "admin.h"
#include "misc.h"
#include "debug.h"

struct dh dhgroup[MAXDHGROUP];

vchar_t oakley_prime768;
vchar_t oakley_prime1024;
vchar_t oakley_prime1536;

u_int port_isakmp = PORT_ISAKMP;
int autoaddr = 1;
int rtsock;
struct myaddrs *myaddrs = NULL;

static struct isakmp_ph1tab ph1tab;

static int isakmp_check_ph1status __P((struct sched *));
static int isakmp_do_expire __P((struct isakmp_ph1 *));
static unsigned int if_maxindex __P((void));

static char _addr1_[BUFADDRSIZE], _addr2_[BUFADDRSIZE]; /* for message */
static char _addr3_[BUFADDRSIZE], _addr4_[BUFADDRSIZE]; /* for message */

/*
 * isakmp packet handler
 */
int
isakmp_handler(sock_isakmp)
	int sock_isakmp;
{
	struct isakmp isakmp;
	struct sockaddr_storage remote;
	struct sockaddr_storage local;
	int remote_len = sizeof(remote);
	int local_len = sizeof(local);
	int len;
	vchar_t *buf = NULL;
	int error = -1;

	/* read message by MSG_PEEK */
	while ((len = recvfromto(sock_isakmp, (char *)&isakmp, sizeof(isakmp),
		    MSG_PEEK, (struct sockaddr *)&remote, &remote_len,
		    (struct sockaddr *)&local, &local_len)) < 0) {
		if (errno == EINTR) continue;
		plog(LOCATION, "recvfromto (%s)\n", strerror(errno));
		goto end;
	}

	/* check isakmp header length */
	if (len < sizeof(isakmp)) {
		plog2((struct sockaddr *)&remote,
			LOCATION, "received invalid header length.\n");
		if ((len = recvfrom(sock_isakmp, (char *)&isakmp, sizeof(isakmp),
			    0, (struct sockaddr *)&remote, &remote_len)) < 0) {
			plog(LOCATION, "recvfrom (%s)\n", strerror(errno));
		}
		goto end;
	}

	/* read real message */
	if ((buf = vmalloc(ntohl(isakmp.len))) == NULL) {
		plog(LOCATION, "vmalloc (%s)\n", strerror(errno)); 
		goto end;
	}

	while ((len = recvfromto(sock_isakmp, buf->v, buf->l,
	                    0, (struct sockaddr *)&remote, &remote_len,
	                    (struct sockaddr *)&local, &local_len)) < 0) {
		if (errno == EINTR) continue;
		plog(LOCATION, "recvfromto (%s)\n", strerror(errno));
		goto end;
	}

	if (len != buf->l) {
		plog2((struct sockaddr *)&remote,
			LOCATION, "received invalid length, why ?\n");
		goto end;
	}

	YIPSDEBUG(DEBUG_NET,
		GETNAMEINFO((struct sockaddr *)&remote, _addr1_, _addr2_);
		GETNAMEINFO((struct sockaddr *)&local, _addr3_, _addr4_);
		plog(LOCATION,
			"%d bytes message has been received "
			"from %s[%s] by %s[%s].\n", len,
			_addr1_, _addr2_, _addr3_, _addr4_));
	YIPSDEBUG(DEBUG_DNET, pvdump(buf));

	/* XXX: check sender whether to be allowed or not */

	/* XXX: I don't know how to check isakmp half connection. */

	/* isakmp main routine */
	if (isakmp_main(buf, (struct sockaddr *)&remote,
			(struct sockaddr *)&local) != 0) goto end;

	error = 0;

end:
	if (buf != NULL)
		vfree(buf);

	return(error);
}

/* %%%
 *
 */
void
dh_init()
{
	/* set DH MODP */
	oakley_prime768.v = strtob(OAKLEY_PRIME_MODP768, 16, &oakley_prime768.l);
	oakley_prime1024.v = strtob(OAKLEY_PRIME_MODP1024, 16, &oakley_prime1024.l);
	oakley_prime1536.v = strtob(OAKLEY_PRIME_MODP1536, 16, &oakley_prime1536.l);

	memset(&dhgroup, 0, sizeof(dhgroup));
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP768].type = OAKLEY_ATTR_GRP_TYPE_MODP;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP768].prime = vdup(&oakley_prime768);
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP768].gen1 = 2;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP768].gen2 = 0;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1024].type = OAKLEY_ATTR_GRP_TYPE_MODP;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1024].prime = vdup(&oakley_prime1024);
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1024].gen1 = 2;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1024].gen2 = 0;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1536].type = OAKLEY_ATTR_GRP_TYPE_MODP;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1536].prime = vdup(&oakley_prime1536);
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1536].gen1 = 2;
	dhgroup[OAKLEY_ATTR_GRP_DESC_MODP1536].gen2 = 0;
}

int
isakmp_init()
{
	/* initialize a isakmp status table */
	memset((char *)&ph1tab, 0, sizeof(ph1tab));

	srandom(time(0));

	/* initialize routing socket */
	rtsock = socket(PF_ROUTE, SOCK_RAW, PF_UNSPEC);
	if (rtsock < 0) {
		plog(LOCATION, "socket(PF_ROUTE): %s", strerror(errno));
		goto err;
	}

	if (!myaddrs && autoaddr == 1) {
		grab_myaddrs();

		if (isakmp_autoconf() < 0)
			goto err;
	}

	if (isakmp_open() < 0)
		goto err;

	return(0);

err:
	isakmp_close();
	return(-1);
}

/*
 * make strings containing i_cookie + r_cookie + msgid
 */
u_char *
isakmp_pindex(index, msgid)
	isakmp_index *index;
	msgid_t *msgid;
{
	static char buf[64];
	u_char *p;
	int i, j;

	memset(buf, 0, sizeof(buf));

	/* copy index */
	p = (u_char *)index;
	for (j = 0, i = 0; i < sizeof(isakmp_index); i++) {
		snprintf((char *)&buf[j], sizeof(buf) - j, "%02x", p[i]);
		j += 2;
		switch (i) {
		case 7: case 15:
			buf[j++] = ':';
		}
	}

	if (msgid == 0)
		return(buf);

	/* copy msgid */
	p = (u_char *)msgid;
	for (i = 0; i < sizeof(msgid_t); i++) {
		snprintf((char *)&buf[j], sizeof(buf) - j, "%02x", p[i]);
		j += 2;
	}

	return(buf);
}

/* %%%
 */
/* open ISAKMP sockets. */
int
isakmp_open()
{
	int tmp = 1;
	struct myaddrs *p;

	for (p = myaddrs; p; p = p->next) {
		if (!p->addr)
			continue;

		/* warn if wildcard address - should we forbid this? */
		switch (p->addr->sa_family) {
		case AF_INET:
			if (((struct sockaddr_in *)p->addr)->sin_addr.s_addr == 0)
				plog(LOCATION,
"WARNING: listening to wildcard address, broadcast IKE packet may kill you\n");
			break;
#ifdef INET6
		case AF_INET6:
			if (IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)p->addr)->sin6_addr))
				plog(LOCATION,
"WARNING: listening to wildcard address, broadcast IKE packet may kill you\n");
			break;
#endif
		default:
			plog(LOCATION,
				"unsupported address family %d\n", af);
			return -1;
		}

		if ((p->sock = socket(p->addr->sa_family, SOCK_DGRAM, 0)) < 0) {
			GETNAMEINFO(p->addr, _addr1_, _addr2_);
			plog(LOCATION,
				"socket (%s) %s[%s].\n",
				strerror(errno), _addr1_, _addr2_);
			free(p->addr);
			p->addr = NULL;
			continue;
		}

		if (setsockopt(p->sock, SOL_SOCKET, SO_REUSEPORT,
		               (void *)&tmp, sizeof(tmp)) < 0) {
			plog(LOCATION,
				"setsockopt (%s)\n", strerror(errno));
			return -1;
		}

		/* receive my interface address on inbound packets. */
		switch (p->addr->sa_family) {
		case AF_INET:
			if (setsockopt(p->sock, IPPROTO_IP, IP_RECVDSTADDR,
					(void *)&tmp, sizeof(tmp)) < 0) {
				plog(LOCATION,
					"setsockopt (%s)\n", strerror(errno));
				return -1;
			}
			break;
#ifdef INET6
		case AF_INET6:
#ifdef ADVAPI
			if (setsockopt(p->sock, IPPROTO_IPV6, IPV6_PKTINFO,
					(void *)&tmp, sizeof(tmp)) < 0)
#else
			if (setsockopt(p->sock, IPPROTO_IPV6, IPV6_RECVDSTADDR,
					(void *)&tmp, sizeof(tmp)) < 0)
#endif
			{
				plog(LOCATION,
					"setsockopt (%s)\n", strerror(errno));
				return -1;
			}
			break;
#endif
		}

		if (setsockopt_bypass(p->sock, p->addr->sa_family) < 0)
			return -1;

		YIPSDEBUG(DEBUG_INFO,
			GETNAMEINFO(p->addr, _addr1_, _addr2_);
			plog(LOCATION,
				"opening %s[%s]\n",
				_addr1_, _addr2_));
		if (bind(p->sock, p->addr, p->addr->sa_len) < 0) {
			plog(LOCATION, "bind (%s)\n", strerror(errno));
			close(p->sock);
			free(p->addr);
			p->addr = NULL;
			continue;
		}

	    {
		YIPSDEBUG(DEBUG_INFO,
			GETNAMEINFO(p->addr, _addr1_, _addr2_);
			plog(LOCATION,
				"using %s[%s] as isakmp port (fd=%d).\n",
				_addr1_, _addr2_, p->sock));
	    }
	}

	return 0;
}

void
isakmp_close()
{
	struct myaddrs *p, *next;

	for (p = myaddrs; p; p = next) {
		next = p->next;

		if (!p->addr)
			continue;
		close(p->sock);
		free(p->addr);
		free(p);
	}

	myaddrs = NULL;
}

int
isakmp_send(iph1, buf)
	struct isakmp_ph1 *iph1;
	vchar_t *buf;
{
	struct sockaddr *sa;
	int len;
	struct myaddrs *p, *lastresort = NULL;

	sa = iph1->remote;

	/* send HDR;SA to responder */
	/* XXX */
	for (p = myaddrs; p; p = p->next) {
		if (p->addr == NULL)
			continue;
		if (sa->sa_family == p->addr->sa_family)
			lastresort = p;
		if (sa->sa_len == p->addr->sa_len
		 && memcmp(sa, p->addr, sa->sa_len) == 0) {
			break;
		}
	}
	if (!p)
		p = lastresort;
	if (!p) {
		plog(LOCATION, "no socket matches address family %d\n",
			sa->sa_family);
		return -1;
	}

	len = sendfromto(p->sock, buf->v, buf->l, iph1->local, iph1->remote);
	if (len < 0) {
		plog(LOCATION, "sendfromto failed\n");
		return(-1);
	}

	YIPSDEBUG(DEBUG_NET,
		GETNAMEINFO(iph1->local, _addr1_, _addr2_);
		GETNAMEINFO(iph1->remote, _addr3_, _addr4_);
		plog(LOCATION,
			"%d bytes message has been sent from %s[%s] to %s[%s].\n",
			len, _addr1_, _addr2_, _addr3_, _addr4_));
	YIPSDEBUG(DEBUG_DNET, pvdump(buf));

	return(0);
}

int
isakmp_resend_ph1(sc)
	struct sched *sc;
{
	struct isakmp_ph1 *iph1 = (struct isakmp_ph1 *)sc->ptr1;
	vchar_t *buf = (vchar_t *)sc->ptr2;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "resend packet.\n"));
	YIPSDEBUG(DEBUG_SCHED2, plog(LOCATION, "tick over #%s\n",
		sched_pindex(&sc->index)));

	if (isakmp_send(iph1, buf) < 0)
		return -1;

	sc->tick = isakmp_timer;

	return 0;
}

/* called as schedule of negotiating isakmp-sa is time over. */
int
isakmp_timeout_ph1(sc)
	struct sched *sc;
{
	struct isakmp_ph1 *iph1 = (struct isakmp_ph1 *)sc->ptr1;
	vchar_t *buf = (vchar_t *)sc->ptr2;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "timeout to send.\n"));
	YIPSDEBUG(DEBUG_SCHED2, plog(LOCATION, "try over #%s\n",
		sched_pindex(&sc->index)));

	if (isakmp_free_ph1(iph1) < 0)
		return -1;

	vfree(buf);

	sched_kill(&sc);

	return 0;
}

int
isakmp_resend_ph2(sc)
	struct sched *sc;
{
	struct isakmp_ph2 *iph2 = (struct isakmp_ph2 *)sc->ptr1;
	vchar_t *buf = (vchar_t *)sc->ptr2;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "resend packet.\n"));
	YIPSDEBUG(DEBUG_SCHED2, plog(LOCATION, "tick over #%s\n",
	    sched_pindex(&sc->index)));

	if (isakmp_send(iph2->ph1, buf) < 0)
		return(-1);

	sc->tick = isakmp_timer;

	return(0);
}

/* called as schedule of negotiating ipsec-sa is time over. */
int
isakmp_timeout_ph2(sc)
	struct sched *sc;
{
	struct isakmp_ph2 *iph2 = (struct isakmp_ph2 *)sc->ptr1;
	vchar_t *buf = (vchar_t *)sc->ptr2;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "timeout to send.\n"));
	YIPSDEBUG(DEBUG_SCHED2, plog(LOCATION, "try over #%s\n",
		sched_pindex(&sc->index)));

	sched_kill(&sc);

	if (iph2->pst && iph2->pst->sc != NULL)
		sched_kill(&iph2->pst->sc);

	if (isakmp_free_ph2(iph2) < 0)
		return -1;

	vfree(buf);

	return 0;
}

/* called as schedule of isakmp-sa is expired. */
int
isakmp_expire(sc)
	struct sched *sc;
{
	struct isakmp_ph1 *iph1 = (struct isakmp_ph1 *)sc->ptr1;

	YIPSDEBUG(DEBUG_SCHED2,
		plog(LOCATION, "try over #%s\n",
			sched_pindex(&sc->index)));

	sched_kill(&sc);

	plog(LOCATION,
		"ISAKMP-SA is expired. %s\n", isakmp_pindex(&iph1->index, 0));

	if (iph1->ph2tab.len == 0) {
		if (isakmp_do_expire(iph1) < 0)
			return -1;
	} else {
		/* set flag */
		iph1->status |= ISAKMP_STATE_EXPIRED;
	}

	return 0;
}

static int
isakmp_do_expire(iph1)
	struct isakmp_ph1 *iph1;
{
	/* if it's initiator, begin re-negosiation */
	if (iph1->dir == INITIATOR) {
		YIPSDEBUG(DEBUG_STAMP,
		    plog(LOCATION, "begin ISAKMP-SA re-negosiation.\n"));

		if (isakmp_begin_phase1(iph1->cfp,
				iph1->local, iph1->remote) == NULL)
			return(-1);
	}

	/* delete old status record */
	if (isakmp_free_ph1(iph1) < 0)
		return(-1);

	return(0);
}

/* %%%
 * functions about management of the isakmp status table
 */
/*
 * create new isakmp Phase 1 status record to handle isakmp
 */
struct isakmp_ph1 *
isakmp_new_ph1(index)
	isakmp_index *index;
{
	struct isakmp_ph1 *iph1;

	if (isakmp_ph1byindex(index) != 0) {
		plog(LOCATION,
		    "already exists. %s\n", isakmp_pindex(index, 0));
		return(0);
	}

	/* create new iph1 */
	if ((iph1 = CALLOC(sizeof(*iph1), struct isakmp_ph1 *)) == 0) {
		plog(LOCATION, "calloc (%s)\n", strerror(errno)); 
		return(0);
	}

	memcpy((caddr_t)&iph1->index, (caddr_t)index, sizeof(*index));
	iph1->status = ISAKMP_STATE_SPAWN;

	/* add to phase 1 table */
	iph1->next = (struct isakmp_ph1 *)0;
	iph1->prev = ph1tab.tail;

	if (ph1tab.tail == 0)
		ph1tab.head = iph1;
	else
		ph1tab.tail->next = iph1;
	ph1tab.tail = iph1;
	ph1tab.len++;

	return(iph1);
}

/*
 * free from isakmp Phase 1 status table
 */
int
isakmp_free_ph1(iph1)
	struct isakmp_ph1 *iph1;
{
	struct isakmp_ph1 *c;
	int error = -1;

	/* diagnostics */
	if ((c = isakmp_ph1byindex(&iph1->index)) == 0) {
		plog(LOCATION,
			"Why is there no status, %s\n", isakmp_pindex(&iph1->index, 0));
		goto end;
	}

	if (c != iph1) {
		plog(LOCATION,
		    "why not equalize, %s\n", isakmp_pindex(&iph1->index, 0));
		goto end;
	}

	if (c->ph2tab.len != 0) {
		plog(LOCATION,
		    "why ipsec status is alive, %s\n", isakmp_pindex(&iph1->index, 0));
		goto end;
	}

	/* XXX: free more !? */
	/* if (c->dhp) vfree(c->dhp); because this is static */
	if (c->dhpriv) vfree(c->dhpriv);
	if (c->dhpub) vfree(c->dhpub);
	if (c->dhpub_p) vfree(c->dhpub_p);
	if (c->dhgxy) vfree(c->dhgxy);
	if (c->nonce) vfree(c->nonce);
	if (c->nonce_p) vfree(c->nonce_p);
	if (c->skeyid) vfree(c->skeyid);
	if (c->skeyid_d) vfree(c->skeyid_d);
	if (c->skeyid_a) vfree(c->skeyid_a);
	if (c->skeyid_e) vfree(c->skeyid_e);
	if (c->key) vfree(c->key);
	if (c->hash) vfree(c->hash);
	isakmp_free_ivm(c->ivm);
	if (c->sa) vfree(c->sa);
	if (c->id) vfree(c->id);
	if (c->id_p) vfree(c->id_p);

	if (c->remote) free(c->remote);

	if (c->isa) {
		if (c->isa->spi) vfree(c->isa->spi);
		if (c->isa->dh) {
			if (c->isa->dh->prime) vfree(c->isa->dh->prime);
			free(c->isa->dh);
		}
		(void)free(c->isa);
	}

	/* reap from phase 1 table */
	/* middle */
	if (c->prev && c->next) {
		c->prev->next = c->next;
		c->next->prev = c->prev;
	} else
	/* tail */
	if (c->prev && c->next == 0) {
		c->prev->next = (struct isakmp_ph1 *)0;
		ph1tab.tail = c->prev;
	} else
	/* head */
	if (c->prev == 0 && c->next) {
		c->next->prev = (struct isakmp_ph1 *)0;
		ph1tab.head = c->next;
	} else {
	/* iph2->next == 0 && iph2->prev == 0 */
	/* last one */
		ph1tab.head = (struct isakmp_ph1 *)0;
		ph1tab.tail = (struct isakmp_ph1 *)0;
	}

	ph1tab.len--;

	YIPSDEBUG(DEBUG_STAMP,
	    plog(LOCATION, "ISAKMP-SA negotiation is free, %s\n",
	        isakmp_pindex(&iph1->index, 0)));

	(void)free(c);

	error = 0;
end:
	return error;
}

/*
 * search on table of isakmp Phase 1 status by index.
 */
struct isakmp_ph1 *
isakmp_ph1byindex(index)
	isakmp_index *index;
{
	struct isakmp_ph1 *c;

	for (c = ph1tab.head; c; c = c->next) {
		if (memcmp(&c->index, index, sizeof(*index)) == 0)
			return c;
	}

	return NULL;
}

/*
 * search on table of isakmp Phase 1 status by i_ck in index.
 */
struct isakmp_ph1 *
isakmp_ph1byindex0(index)
	isakmp_index *index;
{
	struct isakmp_ph1 *c;

	for (c = ph1tab.head; c; c = c->next) {
		if (memcmp(&c->index, index, sizeof(cookie_t)) == 0)
			return c;
	}

	return NULL;
}

/*
 * search isakmp-sa record established on table of isakmp Phase 1
 * by destination address
 */
struct isakmp_ph1 *
isakmp_ph1byaddr(addr)
	struct sockaddr *addr;
{
	struct isakmp_ph1 *c;

#if 0
	YIPSDEBUG(DEBUG_DMISC,
		GETNAMEINFO(addr, _addr1_, _addr2_);
		plog(LOCATION,
			"addr:%s[%s].\n", _addr1_, _addr2_));
#endif

	for (c = ph1tab.head; c != NULL; c = c->next) {

#if 0
		YIPSDEBUG(DEBUG_DMISC,
			GETNAMEINFO(c->remote, _addr1_, _addr2_);
			plog(LOCATION,
				"subject:%s[%s].\n", _addr1_, _addr2_));
#endif

		if (saddrcmp_woport(c->remote, addr))
			continue;
	 	if (! ISSET(c->status, ISAKMP_STATE_EXPIRED))
			return c;
	}

	return NULL;
}

/*
 * create new isakmp Phase 2 status record to handle isakmp in Phase2
 */
struct isakmp_ph2 *
isakmp_new_ph2(iph1, msgid)
	struct isakmp_ph1 *iph1;
	msgid_t *msgid;
{
	struct isakmp_ph2 *iph2 = 0, *c;
	int error = -1;

	/* validation */
	if ((c = isakmp_ph2bymsgid(iph1, msgid)) != 0) {
		plog(LOCATION,
		    "already exists, %d.\n", isakmp_pindex(&iph1->index, msgid));
		goto end;
	}

	/* create new iph2 */
	if ((iph2 = CALLOC(sizeof(*iph2), struct isakmp_ph2 *)) == 0) {
		plog(LOCATION, "calloc (%s)\n", strerror(errno)); 
		goto end;
	}

	iph2->status = ISAKMP_STATE_SPAWN;
	memcpy((caddr_t)&iph2->msgid, (caddr_t)msgid, sizeof(msgid_t));
	iph2->ph1 = iph1;

	iph2->next = (struct isakmp_ph2 *)0;
	iph2->prev = iph1->ph2tab.tail;

	/* add to phase 2 table */
	if (iph1->ph2tab.tail == 0)
		iph1->ph2tab.head = iph2;
	else
		iph1->ph2tab.tail->next = iph2;
	iph1->ph2tab.tail = iph2;
	iph1->ph2tab.len++;

	error = 0;

end:
	if (error) {
		if (iph2) (void)isakmp_free_ph2(iph2);
		iph2 = 0;
	}

	return iph2;
}

/*
 * free from isakmp Phase 2 status table
 */
int
isakmp_free_ph2(iph2)
	struct isakmp_ph2 *iph2;
{
	struct isakmp_ph1 *iph1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* save isakmp status to check expiration. */
	iph1 = iph2->ph1;

	/* XXX: free more !? */
	/* if (iph2->dhp) vfree(iph2->dhp); because this is static */
	if (iph2->dhpriv) vfree(iph2->dhpriv);
	if (iph2->dhpub) vfree(iph2->dhpub);
	if (iph2->dhpub_p) vfree(iph2->dhpub_p);
	if (iph2->dhgxy) vfree(iph2->dhgxy);
	if (iph2->id) vfree(iph2->id);
	if (iph2->id_p) vfree(iph2->id_p);
	if (iph2->nonce) vfree(iph2->nonce);
	if (iph2->nonce_p) vfree(iph2->nonce_p);
	if (iph2->hash) vfree(iph2->hash);
	isakmp_free_ivm(iph2->ivm);

	if (iph2->pst)
		iph2->pst->ph2 = NULL;	/* don't free here. */
	if (iph2->sa) vfree(iph2->sa);
	if (iph2->isa) free(iph2->isa);

	/* reap from phase 2 table */
	/* middle */
	if (iph2->prev && iph2->next) {
		iph2->prev->next = iph2->next;
		iph2->next->prev = iph2->prev;
	} else
	/* tail */
	if (iph2->prev && iph2->next == 0) {
		iph2->prev->next = (struct isakmp_ph2 *)0;
		iph1->ph2tab.tail = iph2->prev;
	} else
	/* head */
	if (iph2->prev == 0 && iph2->next) {
		iph2->next->prev = (struct isakmp_ph2 *)0;
		iph1->ph2tab.head = iph2->next;
	} else {
	/* iph2->next == 0 && iph2->prev == 0 */
		iph1->ph2tab.head = (struct isakmp_ph2 *)0;
		iph1->ph2tab.tail = (struct isakmp_ph2 *)0;
	}

	iph1->ph2tab.len--;

	YIPSDEBUG(DEBUG_STAMP,
	    plog(LOCATION, "Delete Phase 2 handler, %s\n",
	        isakmp_pindex(&iph1->index, &iph2->msgid)));

	(void)free(iph2);

	/* if isakmp-sa has been expired,
	 * free isakmp-sa and begin to re-negotiation.
	 */
	if (iph1->ph2tab.len == 0
	 && ISSET(iph1->status, ISAKMP_STATE_EXPIRED)) {
		if (isakmp_do_expire(iph1) < 0)
			return -1;
	}

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "end.\n"));

	return 0;
}

struct isakmp_ph2 *
isakmp_ph2bymsgid(iph1, msgid)
	struct isakmp_ph1 *iph1;
	msgid_t *msgid;
{
	struct isakmp_ph2 *c;

	for (c = iph1->ph2tab.head; c; c = c->next) {
		if (memcmp((char *)&c->msgid, (char *)msgid, sizeof(msgid_t)) == 0)
			return c;
	}

	return NULL;
}

struct isakmp_ph2 *
isakmp_ph2byaddr(iph1, src, dst)
	struct isakmp_ph1 *iph1;
	struct sockaddr *src, *dst;
{
	struct isakmp_ph2 *c;

	for (c = iph1->ph2tab.head; c; c = c->next) {
		if (c->pst != NULL
		 && saddrcmp(c->pst->src, src) == 0
		 && saddrcmp(c->pst->dst, dst) == 0)
			return c;
	}

	return NULL;
}

/* %%%
 * Interface between PF_KEYv2 and ISAKMP
 */
/*
 * receive GETSPI from kernel.
 */
int
isakmp_post_getspi(pst)
	struct pfkey_st *pst;
{
	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	/* search isakmp status table by address */
	if (pst->ph2 == NULL) {
		GETNAMEINFO(pst->dst, _addr1_, _addr2_);
		plog(LOCATION,
			"ph1 has not been associated. %s[%s].\n", _addr1_, _addr2_);
		return -1;
	}

	if (pst->ph2->ph1->status != ISAKMP_STATE_ESTABLISHED) {
		GETNAMEINFO(pst->dst, _addr1_, _addr2_);
		plog(LOCATION,
			"ph1 has not completed %s[%s].\n", _addr1_, _addr2_);
		return -1;
	}

#if 0
	if ((iph2 = isakmp_ph2byaddr(pst->ph1, pst->src, pst->dst)) == 0) {
		GETNAMEINFO(pst->dst, _addr1_, _addr2_);
		plog(LOCATION,
			"no ph2 negotiation found, %s[%s].\n", _addr1_, _addr2_);
		return -1;
	}
#endif

	/* check status */
	if (pst->ph2->status != ISAKMP_STATE_2) {
		GETNAMEINFO(pst->dst, _addr1_, _addr2_);
		plog(LOCATION,
			"GETSPI was finished already. %s[%s].\n", _addr1_, _addr2_);
		return -1;
	}

#ifdef PFKEY_RESEND
	/* kill schedule */
	sched_kill(&pst->ph2->sc);
#endif

	switch (pst->ph2->dir) {
	case INITIATOR:
		isakmp_quick_i2(0, pst->dst, pst->ph2);
		break;
	case RESPONDER:
		isakmp_quick_r2(0, pst->dst, pst->ph2);
		break;
	default:
		plog(LOCATION, "illegal direction. ?\n");
		return -1;
		break;
	}

	return 0;
}

/*
 * receive ACQUIRE from kernel, and begin either IDENT or QUICK mode.
 * if IDENT mode finished, begin QUICK mode.
 */
int
isakmp_post_acquire(pst)
	struct pfkey_st *pst;
{
	struct sockaddr *remote = NULL;	/* remote address for ISAKMP-SA */
	struct sockaddr *local = NULL;	/* local address for ISAKMP-SA */
	struct isakmp_conf *cfp;
	struct isakmp_ph1 *iph1 = NULL;
	int error = -1;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

    {
	struct sockaddr *tmp;

	/* get remote address */
	if (pst->proxy != NULL)
		tmp = pst->proxy;
	else
		tmp = pst->dst;

	/* search appropreate configuration with masking port. */
	cfp = isakmp_cfbypeer(tmp);
	if (cfp == NULL) {
		plog(LOCATION,
			"no configuration is found for peer address.\n");
		goto end;
	}

	/* get remote complete address */
	GET_NEWBUF(remote, struct sockaddr *, tmp, tmp->sa_len);
	if (remote == NULL) {
		plog(LOCATION,
			"no buffer available.\n");
		goto end;
	}
	_INPORTBYSA(remote) = _INPORTBYSA(cfp->remote);
    }

	/* search isakmp status table by address with masking port */
	iph1 = isakmp_ph1byaddr(remote);

#if 0
	/*
	 * XXX There must be one bi-directinal ISAKMP-SA between two node.
	 * If not, do enable below code.
	 */
	/* ISAKMP-SA found but is it mine ? */
	if (iph1->dir == RESPONDER)
		iph1 = NULL;
#endif

	/* no ISAKMP-SA found. */
	if (iph1 == NULL) {
		isakmp_new_queue(pst, remote);
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION,
			"request for establishing IPsec-SA was queued, "
			"as no phase 1 exists.\n"));

		/* get local address for phase 1 exchange */
		local = get_localaddr(remote);
		if (local == NULL) {
			plog(LOCATION,
				"no buffer available.\n");
			goto end;
		}

		_INPORTBYSA(local) = isakmp_get_localport(local);

		/* begin ident mode */
		if ((iph1 = isakmp_begin_phase1(cfp, local, remote)) == NULL)
			goto end;

		error = 0;
		goto end;
	}

	/* found ISAKMP-SA, but on negotiation. */
	/* XXX may not need */
	if (iph1->status != ISAKMP_STATE_ESTABLISHED) {
		isakmp_new_queue(pst, remote);
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION,
			"ignore, ISAKMP-SA is not establised.\n"));
		error = 0;
		goto end;
	}

	/* found established ISAKMP-SA */
	/* i.e. iph1->status == ISAKMP_STATE_ESTABLISHED */

#if 0
	/* found ISAKMP-SA, but it's on time in phase 2 negotiation. */
	if (isakmp_ph2byaddr(iph1, pst->src, pst->dst) != 0) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION,
			"now negotiating its SA.\n"));
		goto end;
	}
#endif

	/* found ISAKMP-SA. */
	YIPSDEBUG(DEBUG_STAMP,
		plog(LOCATION, "begin QUICK mode.\n"));

	/* begin quick mode */
	if (isakmp_begin_quick(iph1, pst) < 0)
		goto end;

	error = 0;

end:
	if (remote != NULL)
		free(remote);
	if (local != NULL)
		free(local);
	return(error);
}

int
isakmp_new_queue(pst, remote0)
	struct pfkey_st *pst;
	struct sockaddr *remote0;
{
	struct sockaddr *remote;

	YIPSDEBUG(DEBUG_SCHED,
	    plog(LOCATION, "new IPsec-SA request was scheduled.\n"));

	GET_NEWBUF(remote, struct sockaddr *, remote0, remote0->sa_len);
	if (remote == NULL) {
		plog(LOCATION,
			"no buffer available.\n");
		return -1;
	}

	/* add to the schedule to resend, and seve back pointer. */
	pst->sc = sched_add(1, isakmp_check_ph1status,
				pfkey_acquire_try, isakmp_pfkey_over,
				(caddr_t)pst, (caddr_t)remote,
				SCHED_ID_PST_ACQUIRE);

	return 0;
}

static int
isakmp_check_ph1status(sc)
	struct sched *sc;
{
	struct pfkey_st *pst = (struct pfkey_st *)sc->ptr1;
	struct sockaddr *remote = (struct sockaddr *)sc->ptr2;
	struct isakmp_ph1 *iph1;

	YIPSDEBUG(DEBUG_SCHED2,
	    plog(LOCATION,
	        "tick over #%s\n", sched_pindex(&sc->index)));

	iph1 = isakmp_ph1byaddr(remote);
	if (iph1 != NULL
	 && iph1->dir == INITIATOR		/* <--- XXX need ? */
	 && iph1->status == ISAKMP_STATE_ESTABLISHED
#if 0
	 && iph1->ph2tab.len == 0
#endif
	) {
		/* found isakmp-sa */
		sched_kill(&sc);
		if (isakmp_post_acquire(pst) < 0)
			return -1;
	} else
		sc->tick = 1;

	return 0;
}

/* called as schedule is time over. */
int
isakmp_pfkey_over(sc)
	struct sched *sc;
{
	struct pfkey_st *pst = (struct pfkey_st *)sc->ptr1;

	YIPSDEBUG(DEBUG_STAMP,
	    plog(LOCATION, "timeout to negosiate SA.\n"));
	YIPSDEBUG(DEBUG_SCHED2,
	    plog(LOCATION, "try over #%s\n",
	        sched_pindex(&sc->index)));

	GETNAMEINFO((struct sockaddr *)&pst->dst, _addr1_, _addr2_);
	plog2(pst->dst, LOCATION,
		"Gived up to get IPsec-SA, I could't find the SA for %s[%s]\n",
			_addr1_, _addr2_);

	/* XXX do send error to kernel by SADB_ACQUIRE. */
	pfkey_free_pst(pst);

	sched_kill(&sc);

	return 0;
}

/*  */
int
isakmp_timeout_getspi(sc)
	struct sched *sc;
{
	struct isakmp_ph2 *iph2 = (struct isakmp_ph2 *)sc->ptr2;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "timeout to send.\n"));
	YIPSDEBUG(DEBUG_SCHED2, plog(LOCATION, "try over #%s\n",
		sched_pindex(&sc->index)));

	sched_kill(&iph2->sc);

	if (isakmp_free_ph2(iph2) < 0)
		return -1;

	return 0;
}

/*
 * decision configuration by peer address.
 */
struct isakmp_conf *
isakmp_cfbypeer(remote)
	struct sockaddr *remote;
{
	struct isakmp_conf *cfp;

	YIPSDEBUG(DEBUG_MISC,
		GETNAMEINFO(remote, _addr1_, _addr2_);
		plog(LOCATION,
			"search with remote addr=%s.\n", _addr1_));

	for (cfp = cftab.next; cfp != NULL; cfp = cfp->next) {
		if (saddrcmp_woport(remote, cfp->remote) == 0) {
			YIPSDEBUG(DEBUG_MISC,
				GETNAMEINFO(cfp->remote, _addr1_, _addr2_);
				plog(LOCATION,
					"apply configuration addr=%s[%s]\n",
					_addr1_, _addr2_));
			return cfp;
		}
	}

	/* There is no configuration. */
	if (!cftab.ph[0] || !cftab.ph[1])
		return NULL;

	YIPSDEBUG(DEBUG_MISC,
	    plog(LOCATION, "apply anonymous configuration.\n"));

	return &cftab; /* anonymous */
}

/*
 * dump isakmp-sa
 */
vchar_t *
isakmp_dump_ph1sa(proto)
	u_int proto;
{
	struct isakmp_ph1 *iph1;
	struct isakmp_ph2 *iph2;
	int tlen;
	vchar_t *buf;
	caddr_t bufp;

	/* get length of buffer */
	tlen = (sizeof(struct isakmp_ph1) * ph1tab.len);
	for (iph1 = ph1tab.head;
	     iph1 != NULL;
	     iph1 = iph1->next) {

		tlen += iph1->local->sa_len;
		tlen += iph1->remote->sa_len;

		tlen += (sizeof(struct isakmp_ph2) * iph1->ph2tab.len);
		for (iph2 = iph1->ph2tab.head;
		     iph2 != NULL;
		     iph2 = iph2->next) {

			if (iph2->pst == NULL)
				continue;

			tlen += iph2->pst->src->sa_len;
			tlen += iph2->pst->dst->sa_len;
		}
	}

	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc(%s)\n", strerror(errno));
		return NULL;
	}
	bufp = buf->v;

	for (iph1 = ph1tab.head;
	     iph1 != NULL;
	     iph1 = iph1->next) {

		/* copy ph1 entry */
		memcpy(bufp, iph1, sizeof(*iph1));
		bufp += sizeof(*iph1);
		memcpy(bufp, iph1->local, iph1->local->sa_len);
		bufp += iph1->local->sa_len;
		memcpy(bufp, iph1->remote, iph1->remote->sa_len);
		bufp += iph1->remote->sa_len;

		/* copy ph2 entries */
		for (iph2 = iph1->ph2tab.head;
		     iph2 != NULL;
		     iph2 = iph2->next) {

			/* copy ph2 entry */
			memcpy(bufp, iph2, sizeof(*iph2));
			bufp += sizeof(*iph2);

			if (iph2->pst == NULL)
				continue;

			memcpy(bufp, iph2->pst->src, iph2->pst->src->sa_len);
			bufp += iph2->pst->src->sa_len;
			memcpy(bufp, iph2->pst->dst, iph2->pst->dst->sa_len);
			bufp += iph2->pst->dst->sa_len;
		}
	}

	return buf;
}

/*
 * flush isakmp-sa
 */
void
isakmp_flush_ph1sa(proto)
	u_int proto;
{
	struct isakmp_ph1 *iph1, *next;

	/* get length of buffer */
	for (iph1 = ph1tab.head;
	     iph1 != NULL;
	     iph1 = next) {
		next = iph1->next;
		(void)isakmp_free_ph1(iph1);
	}

	return;
}

/* copy variable data into ALLOCATED buffer. */
void
isakmp_set_attr_v(buf, type, val, len)
	char *buf;
	int type;
	caddr_t val;
	int len;
{
	struct isakmp_data *data;

	data = (struct isakmp_data *)buf;
	data->type = htons((u_int16_t)type | ISAKMP_GEN_TLV);
	data->lorv = htons((u_int16_t)len);
	memcpy((caddr_t)data + sizeof(*data), val, len);

	return;
}

/* copy fixed length data into ALLOCATED buffer. */
void
isakmp_set_attr_l(buf, type, val)
	char *buf;
	int type;
	u_int32_t val;
{
	struct isakmp_data *data;

	data = (struct isakmp_data *)buf;
	data->type = htons((u_int16_t)type | ISAKMP_GEN_TV);
	data->lorv = htons((u_int16_t)val);

	return;
}

/*
 * get a port number to which racoon binded.
 * NOTE: network byte order returned.
 */
u_short
isakmp_get_localport(local)
	struct sockaddr *local;
{
	struct myaddrs *p;

	/* get a relative port */
	for (p = myaddrs; p; p = p->next) {
		if (!p->addr)
			continue;
		if (!saddrcmp_woport(local, p->addr))
			return _INPORTBYSA(p->addr);
			continue;
	}

	return htons(PORT_ISAKMP);
}

static unsigned int
if_maxindex()
{
	struct if_nameindex *p, *p0;
	unsigned int max = 0;

	p0 = if_nameindex();
	for (p = p0; p && p->if_index && p->if_name; p++) {
		if (max < p->if_index)
			max = p->if_index;
	}
	if_freenameindex(p0);
	return max;
}

int
isakmp_autoconf()
{
	/*
	 * initialize default port for ISAKMP to send, if no "listen"
	 * directive is specified in config file.
	 *
	 * DO NOT listen to wildcard addresses.  if you receive packets to
	 * wildcard address, you'll be in trouble (DoS attack possible by
	 * broadcast storm).
	 */
	struct myaddrs *p;
	struct sockaddr_in *sin;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif
	int n;

	YIPSDEBUG(DEBUG_INFO,
		plog(LOCATION,
			"configuring default isakmp port.\n"));
	n = 0;
	for (p = myaddrs; p; p = p->next) {
		switch (p->addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)p->addr;
			sin->sin_port = htons(port_isakmp);
			break;
#ifdef INET6
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)p->addr;
			sin6->sin6_port = htons(port_isakmp);
			break;
#endif
		default:
			plog(LOCATION,
				"unsupported AF %d\n",
				p->addr->sa_family);
			goto err;
		}
		n++;
	}
	YIPSDEBUG(DEBUG_MISC,
		plog(LOCATION, "isakmp_autoconf success, %d addrs\n", n));

	return 0;
err:
	YIPSDEBUG(DEBUG_MISC,
		plog(LOCATION, "isakmp_autoconf fail\n"));
	return -1;
}

void
grab_myaddrs()
{
	int s;
	unsigned int maxif;
	int len;
	struct ifreq *iflist;
	struct ifconf ifconf;
	struct ifreq *ifr, *ifr_end;
	struct myaddrs *p;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif

	maxif = if_maxindex() + 1;
	len = maxif * sizeof(*iflist) * 5;	/* guess guess */
	iflist = (struct ifreq *)malloc(len);
	if (!iflist) {
		plog(LOCATION, "not enough core\n");
		exit(1);
		/*NOTREACHED*/
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		plog(LOCATION, "socket(SOCK_DGRAM)\n");
		exit(1);
		/*NOTREACHED*/
	}
	memset(&ifconf, 0, sizeof(ifconf));
	ifconf.ifc_req = iflist;
	ifconf.ifc_len = len;
	if (ioctl(s, SIOCGIFCONF, &ifconf) < 0) {
		plog(LOCATION, "ioctl(SIOCGIFCONF)\n");
		exit(1);
		/*NOTREACHED*/
	}
	close(s);

	/* Look for this interface in the list */
	ifr_end = (struct ifreq *) (ifconf.ifc_buf + ifconf.ifc_len);
	for (ifr = ifconf.ifc_req;
	     ifr < ifr_end;
	     ifr = (struct ifreq *) ((char *) &ifr->ifr_addr
				    + ifr->ifr_addr.sa_len)) {
		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
#ifdef INET6
		case AF_INET6:
#endif
			p = (struct myaddrs *)malloc(sizeof(struct myaddrs)
				+ ifr->ifr_addr.sa_len);
			if (!p) {
				plog(LOCATION, "not enough core\n");
				exit(1);
				/*NOTREACHED*/
			}
			memcpy(p + 1, &ifr->ifr_addr, ifr->ifr_addr.sa_len);
			p->next = myaddrs;
			p->addr = (struct sockaddr *)(p + 1);
#ifdef INET6
#ifdef __KAME__
			sin6 = (struct sockaddr_in6 *)p->addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)
			 || IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr)) {
				sin6->sin6_scope_id =
					ntohs(sin6->sin6_addr.s6_addr16[1]);
				sin6->sin6_addr.s6_addr16[1] = 0;
			}
#endif
#endif
			myaddrs = p;
			YIPSDEBUG(DEBUG_MISC,
				getnameinfo(p->addr, p->addr->sa_len,
					_addr1_, sizeof(_addr1_), NULL, 0,
					NI_NUMERICHOST);
				plog(LOCATION, "my interface: %s (%s)\n",
				_addr1_, ifr->ifr_name));
			break;
		default:
			break;
		}
	}
}

int
update_myaddrs()
{
	char msg[BUFSIZ];
	int len;
	struct rt_msghdr *rtm;

	len = read(rtsock, msg, sizeof(msg));
	if (len < 0) {
		plog(LOCATION, "read(PF_ROUTE) failed\n");
		return 0;
	}
	if (len < sizeof(*rtm)) {
		plog(LOCATION, "read(PF_ROUTE) short read\n");
		return 0;
	}
	rtm = (struct rt_msghdr *)msg;
	if (rtm->rtm_version != RTM_VERSION) {
		plog(LOCATION, "routing socket version mismatch\n");
		close(rtsock);
		rtsock = 0;
		return 0;
	}
	switch (rtm->rtm_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_DELETE:
	case RTM_IFINFO:
		break;
	default:
		plog(LOCATION, "msg %d not interesting\n", rtm->rtm_type);
		return 0;
	}
	/* XXX more filters here? */

	YIPSDEBUG(DEBUG_MISC, plog(LOCATION,
		"need update interface address list\n"));
	return 1;
}
