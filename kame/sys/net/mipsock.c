/* $Id: mipsock.c,v 1.1 2004/12/09 02:18:59 t-momose Exp $ */

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

#if __FreeBSD__ >= 3
#include "opt_mip6.h"
#endif
#include "mip.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#ifdef __FreeBSD__
#include <sys/malloc.h>
#endif /* __FreeBSD__ */
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/mipsock.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif /* __FreeBSD__ */
#include <net/if_mip.h>
#include <net/raw_cb.h>
#include <net/route.h>


#include <netinet/in.h>
#include <netinet/ip6mh.h>
#include <netinet6/in6_var.h>
#include <netinet6/mip6.h>
#include <netinet6/mip6_var.h>

/*MALLOC_DEFINE(M_RTABLE, "routetbl", "routing tables");*/

static struct	sockaddr mips_dst = { 2, PF_MOBILITY, };
static struct	sockaddr mips_src = { 2, PF_MOBILITY, };
static struct	sockproto mips_proto = { PF_MOBILITY, };

static struct mbuf *mips_msg1(int type, int len);
#ifdef __FreeBSD__
static int	 mips_output __P((struct mbuf *, struct socket *));
#else
static int	 mips_output __P((struct mbuf *, ...));
#endif

#ifdef __NetBSD__
int mips_usrreq(struct socket *, int, struct mbuf *, struct mbuf *, struct mbuf *, struct proc *);
#endif

#ifdef __FreeBSD__
/*
 * It really doesn't make any sense at all for this code to share much
 * with raw_usrreq.c, since its functionality is so restricted.  XXX
 */
static int
mips_abort(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_abort(so);
	splx(s);
	return error;
}

/* pru_accept is EOPNOTSUPP */

static int
mips_attach(struct socket *so, int proto,
#if __FreeBSD_version >= 503000
	    struct thread *td
#else
	    struct proc *p
#endif
	    )
{
	struct rawcb *rp;
	int s, error;

	if (sotorawcb(so) != 0)
		return EISCONN;	/* XXX panic? */
	MALLOC(rp, struct rawcb *, sizeof *rp, M_PCB, M_WAITOK|M_ZERO);
	if (rp == 0)
		return ENOBUFS;
	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications (like RTM_REDIRECT or RTM_LOSING) while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)rp;
	error = raw_attach(so, proto);
	rp = sotorawcb(so);
	if (error) {
		splx(s);
		free(rp, M_PCB);
		return error;
	}
	switch(rp->rcb_proto.sp_protocol) {
	case AF_INET:
		break;
	case AF_INET6:
		break;
	}
	rp->rcb_faddr = &mips_src;
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;
	splx(s);
	return 0;
}

static int
mips_bind(struct socket *so, struct sockaddr *nam,
#if __FreeBSD_version >= 503000
	  struct thread *p
#else
	  struct proc *p
#endif
	  )
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_bind(so, nam, p); /* xxx just EINVAL */
	splx(s);
	return error;
}

static int
mips_connect(struct socket *so, struct sockaddr *nam,
#if __FreeBSD_version >= 503000
	  struct thread *p
#else
	  struct proc *p
#endif
	  )
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_connect(so, nam, p); /* XXX just EINVAL */
	splx(s);
	return error;
}

/* pru_connect2 is EOPNOTSUPP */
/* pru_control is EOPNOTSUPP */

static int
mips_detach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);
	int s, error;

	s = splnet();
	if (rp != 0) {
		switch(rp->rcb_proto.sp_protocol) {
		case AF_INET:
			break;
		case AF_INET6:
			break;
		}
	}
	error = raw_usrreqs.pru_detach(so);
	splx(s);
	return error;
}

static int
mips_disconnect(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_disconnect(so);
	splx(s);
	return error;
}

/* pru_listen is EOPNOTSUPP */

static int
mips_peeraddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_peeraddr(so, nam);
	splx(s);
	return error;
}

/* pru_rcvd is EOPNOTSUPP */
/* pru_rcvoob is EOPNOTSUPP */

static int
mips_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control,
#if __FreeBSD_version >= 503000
	  struct thread *p
#else
	  struct proc *p
#endif
	  )
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_send(so, flags, m, nam, control, p);
	splx(s);
	return error;
}

/* pru_sense is null */

static int
mips_shutdown(struct socket *so)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_shutdown(so);
	splx(s);
	return error;
}

static int
mips_sockaddr(struct socket *so, struct sockaddr **nam)
{
	int s, error;
	s = splnet();
	error = raw_usrreqs.pru_sockaddr(so, nam);
	splx(s);
	return error;
}

static struct pr_usrreqs mip_usrreqs = {
	mips_abort, pru_accept_notsupp, mips_attach, mips_bind, mips_connect,
	pru_connect2_notsupp, pru_control_notsupp, mips_detach, mips_disconnect,
	pru_listen_notsupp, mips_peeraddr, pru_rcvd_notsupp, pru_rcvoob_notsupp,
	mips_send, pru_sense_null, mips_shutdown, mips_sockaddr,
	sosend, soreceive, sopoll
};
#endif

#ifdef __NetBSD__
/*ARGSUSED*/
int
mips_usrreq(so, req, m, nam, control, p)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
	struct proc *p;
{
	int error = 0;
	struct rawcb *rp = sotorawcb(so);
	int s;

	if (req == PRU_ATTACH) {
		MALLOC(rp, struct rawcb *, sizeof(*rp), M_PCB, M_WAITOK);
		if ((so->so_pcb = rp) != NULL)
			memset(so->so_pcb, 0, sizeof(*rp));

	}
#if 0
	if (req == PRU_DETACH && rp)
		rt_adjustcount(rp->rcb_proto.sp_protocol, -1);
#endif
	s = splsoftnet();

	/*
	 * Don't call raw_usrreq() in the attach case, because
	 * we want to allow non-privileged processes to listen on
	 * and send "safe" commands to the routing socket.
	 */
	if (req == PRU_ATTACH) {
		if (p == 0)
			error = EACCES;
		else
			error = raw_attach(so, (int)(long)nam);
	} else
		error = raw_usrreq(so, req, m, nam, control, p);

	rp = sotorawcb(so);
	if (req == PRU_ATTACH && rp) {
		if (error) {
			free((caddr_t)rp, M_PCB);
			splx(s);
			return (error);
		}
		/*		rt_adjustcount(rp->rcb_proto.sp_protocol, 1);*/
		rp->rcb_laddr = &mips_src;
		rp->rcb_faddr = &mips_dst;
		soisconnected(so);
		so->so_options |= SO_USELOOPBACK;
	}
	splx(s);
	return (error);
}
#endif

/*ARGSUSED*/
static int
#ifdef __FreeBSD__
mips_output(m, so)
	register struct mbuf *m;
	struct socket *so;
#else
#if __STDC__
mips_output(struct mbuf *m, ...)
#else
mipus_output(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
#endif
{
	int error = 0;
	struct mip_msghdr *miph = NULL;
	struct mipm_bc_info *mipc = NULL;
	struct mipm_nodetype_info *mipmni = NULL;
#if NMIP > 0
	struct mipm_bul_info *mipu = NULL;
	struct mip6_bul_internal *mbul = NULL;
#endif
	miph = mtod(m, struct mip_msghdr *);

	switch (miph->miph_type) {
	case MIPM_BC_ADD:
	case MIPM_BC_UPDATE:
		mipc = (struct mipm_bc_info *)miph;
#ifndef MIP6_MCOA
		error = mip6_bce_update((struct sockaddr_in6 *)MIPC_CNADDR(mipc),
		    (struct sockaddr_in6 *)MIPC_HOA(mipc),
		    (struct sockaddr_in6 *)MIPC_COA(mipc), mipc->mipc_flags);
#else
		error = mip6_bce_update((struct sockaddr_in6 *)MIPC_CNADDR(mipc),
		    (struct sockaddr_in6 *)MIPC_HOA(mipc),
		    (struct sockaddr_in6 *)MIPC_COA(mipc), mipc->mipc_flags,
		    mipc->mipc_bid);
#endif /* MIP6_MCOA */
		break;

	case MIPM_BC_REMOVE:
		mipc = (struct mipm_bc_info *)miph;
#ifndef MIP6_MCOA
		error = mip6_bce_remove((struct sockaddr_in6 *)MIPC_CNADDR(mipc),
		    (struct sockaddr_in6 *)MIPC_HOA(mipc),
		    (struct sockaddr_in6 *)MIPC_COA(mipc), mipc->mipc_flags);
#else
		error = mip6_bce_remove((struct sockaddr_in6 *)MIPC_CNADDR(mipc),
		    (struct sockaddr_in6 *)MIPC_HOA(mipc),
		    (struct sockaddr_in6 *)MIPC_COA(mipc), mipc->mipc_flags,
		    mipc->mipc_bid);
#endif /* MIP6_MCOA */
		break;

	case MIPM_BC_FLUSH:
		mip6_bce_remove_all();
		break;

	case MIPM_NODETYPE_INFO:
		mipmni = (struct mipm_nodetype_info *)miph;
		if (mipmni->mipmni_enable) {
			if (MIP6_IS_MN
			    && (mipmni->mipmni_nodetype
				& MIP6_NODETYPE_HOME_AGENT))
				error = EINVAL;
			if (MIP6_IS_HA
			    && ((mipmni->mipmni_nodetype
				    & MIP6_NODETYPE_MOBILE_NODE)
				|| (mipmni->mipmni_nodetype
				    & MIP6_NODETYPE_MOBILE_ROUTER)))
				error = EINVAL;
			mip6_nodetype |= mipmni->mipmni_nodetype;
		} else {
			if (mipmni->mipmni_nodetype
			    == MIP6_NODETYPE_NONE)
				error = EINVAL;
			mip6_nodetype &= ~mipmni->mipmni_nodetype;
		}
		break;

#if NMIP > 0
	case MIPM_BUL_ADD:
	case MIPM_BUL_UPDATE:
		mipu = (struct mipm_bul_info *)miph;

		/* Non IPv6 address is not support (only for MIP6) */
		if ((MIPU_PEERADDR(mipu))->sa_family == AF_INET6 &&
		    (MIPU_HOA(mipu))->sa_family == AF_INET6 &&
		    (MIPU_COA(mipu))->sa_family == AF_INET6)
		    
#ifndef MIP6_MCOA
			error = mip6_bul_add(&((struct sockaddr_in6 *)MIPU_PEERADDR(mipu))->sin6_addr,
			    &((struct sockaddr_in6 *)MIPU_HOA(mipu))->sin6_addr,
			    &((struct sockaddr_in6 *)MIPU_COA(mipu))->sin6_addr,
			    mipu->mipu_hoa_ifindex, mipu->mipu_flags,
			    mipu->mipu_state);
#else
			error = mip6_bul_update(&((struct sockaddr_in6 *)MIPU_PEERADDR(mipu))->sin6_addr,
			    &((struct sockaddr_in6 *)MIPU_HOA(mipu))->sin6_addr,
			    &((struct sockaddr_in6 *)MIPU_COA(mipu))->sin6_addr,
			    mipu->mipu_hoa_ifindex, mipu->mipu_flags,
			    mipu_state, mipu->mipu_bid);
#endif /* MIP6_COA */
		else
			error = EPFNOSUPPORT; /* XXX ? */
		break;

	case MIPM_BUL_REMOVE:
		mipu = (struct mipm_bul_info *)miph;
#ifndef MIP6_MCOA
		mbul = mip6_bul_get(&((struct sockaddr_in6 *)MIPU_HOA(mipu))->sin6_addr,
		    &((struct sockaddr_in6 *)MIPU_PEERADDR(mipu))->sin6_addr);
#else
		mbul = mip6_bul_get(&((struct sockaddr_in6 *)MIPU_HOA(mipu))->sin6_addr,
		    &((struct sockaddr_in6 *)MIPU_PEERADDR(mipu))->sin6_addr,
		    mipu->mipu_bid);
#endif /* MIP6_COA */
		if (mbul == NULL) 
			return (ENOENT);

		mip6_bul_remove(mbul);
		break;

	case MIPM_BUL_FLUSH:
		mip6_bul_remove_all();
		break;

	case MIPM_HOME_HINT:
	case MIPM_MD_INFO:
		/* do nothing in kernel, just forward it to all receivers */
		break;
#endif /* NMIP > 0 */

	default:
		return (0);
	}
	
	raw_input(m, &mips_proto, &mips_src, &mips_dst);
	return (error);
}

static struct mbuf *
mips_msg1(type, len)
	int type;
	int len;
{
	register struct mip_msghdr *miph;
	register struct mbuf *m;

	if (len > MCLBYTES)
		panic("mips_msg1");
	m = m_gethdr(M_DONTWAIT, MT_DATA);
	if (m && len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return (m);
	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = 0;
	miph = mtod(m, struct mip_msghdr *);
	bzero((caddr_t)miph, len);
	if (m->m_pkthdr.len != len) {
		m_freem(m);
		return (NULL);
	}
	miph->miph_msglen = len;
	miph->miph_version = MIP_VERSION;
	miph->miph_type = type;
	return (m);
}

/*
void
mips_notify_bc(type, mbc)
	u_char type;
	struct mip6_bc *mbc;
{
	register struct mipm_bc_info *mipc;
	register struct mbuf *m;
	struct sockaddr_in6 *hoa_sin6, *coa_sin6;

	m = mips_msg1(type, sizeof(struct mipm_bc_info) + sizeof(struct sockaddr_in6) * 2);
	if (m == NULL)
		return;
	mipc = mtod(m, struct mipm_bc_info *);
	hoa = (struct sockaddr_in6 *)(mipc + 1)
	coa = hoa + 1;
	bzero(hoa_sin6, sizeof(struct sockaddr_in6));
	bzero(coa_sin6, sizeof(struct sockaddr_in6));
	hoa_sin6->sin6_family = coa_sin6->sin6_family = AF_INET6;
	hoa_sin6->sin6_len = coa_sin6->sin6_len = sizeof(struct sockaddr_in6);
	hoa_sin6->sin6_addr = mbc->mbc_phaddr;
	coa_sin6->sin6_addr = mbc->mbc_pcoa;
	raw_input(m, &mips_proto, &mips_src, &mips_dst);
}
*/

#if 0
void
mips_notify_bul(type, mbul)
	u_char type;
	struct mip6_bul_internal *mbul;
{
	struct mipm_bul_info *mipu;
	struct mbuf *m;
	struct ifaddr *coaifa;
	struct sockaddr_in6 *hoa_sin6, *coa_sin6, *peeraddr_sin6;

	m = mips_msg1(type, sizeof(struct mipm_bul_info) + sizeof(struct sockaddr_in6) * 3);
	if (m == NULL)
		return;
	mipu = mtod(m, struct mipm_bul_info *);
	hoa_sin6 = (struct sockaddr_in6 *)(mipu + 1);
	coa_sin6 = hoa_sin6 + 1;
	peeraddr_sin6 = coa_sin6 + 1;
	bzero(hoa_sin6, sizeof(struct sockaddr_in6));
	bzero(coa_sin6, sizeof(struct sockaddr_in6));
	bzero(peeraddr_sin6, sizeof(struct sockaddr_in6));
	hoa_sin6->sin6_family
	    = coa_sin6->sin6_family
	    = peeraddr_sin6->sin6_family
	    = AF_INET6;
	hoa_sin6->sin6_len
	    = coa_sin6->sin6_len
	    = peeraddr_sin6->sin6_len
	    = sizeof(struct sockaddr_in6);
	hoa_sin6->sin6_addr = mbul->mbul_hoa;
	coa_sin6->sin6_addr = mbul->mbul_coa;
	peeraddr_sin6->sin6_addr = mbul->mbul_peeraddr;
	coaifa = ifa_ifwithaddr((struct sockaddr *)&mbul->mbul_coa);
	sprintf(mipu->mipu_coa_ifname, "%s%d", coaifa->ifa_ifp->if_name,
	    coaifa->ifa_ifp->if_unit);
	mipu->mipu_flags = mbul->mbul_flags;
	raw_input(m, &mips_proto, &mips_src, &mips_dst);
}
#endif


void
mips_notify_home_hint(ifindex, prefix, prefixlen) 
	u_int16_t ifindex;
	struct in6_addr *prefix;
	u_int16_t prefixlen;
{
	struct mipm_home_hint *hint;
	struct sockaddr_in6 sin6;
	struct mbuf *m;
	int len = sizeof(struct mipm_home_hint) + sizeof(struct sockaddr_in6);

	m = mips_msg1(MIPM_HOME_HINT, len);
	if (m == NULL)
		return;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *prefix;

        hint = mtod(m, struct mipm_home_hint *);

	hint->mipmhh_seq = 0;
	hint->mipmhh_ifindex = ifindex;
	hint->mipmhh_prefixlen = prefixlen;
	bcopy(&sin6, (char *) hint->mipmhh_prefix, sizeof(sin6));

	raw_input(m, &mips_proto, &mips_src, &mips_dst);
}

/*
 * notify bi-directional tunneling event so that a moblie node can
 * initiate RR procedure.
 */
void
mips_notify_rr_hint(hoa, peeraddr)
	struct in6_addr *hoa;
	struct in6_addr *peeraddr;
{
	struct mipm_rr_hint *rr_hint;
	struct sockaddr_in6 sin6;
	struct mbuf *m;
	u_short len = sizeof(struct mipm_rr_hint)
	    + (2 * sizeof(struct sockaddr_in6));

	m = mips_msg1(MIPM_RR_HINT, len);
	if (m == NULL)
		return;
	rr_hint = mtod(m, struct mipm_rr_hint *);
	rr_hint->mipmrh_seq = 0;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *hoa;
	bcopy(&sin6, (void *)MIPMRH_HOA(rr_hint), sizeof(sin6));

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *peeraddr;
	bcopy(&sin6, (void *)MIPMRH_PEERADDR(rr_hint), sizeof(sin6));

	raw_input(m, &mips_proto, &mips_src, &mips_dst);
}

/*
 * notify a hint to send a binding error message.  this message is
 * usually sent when an invalid home address is received.
 */
void
mips_notify_be_hint(src, coa, hoa, status)
	struct in6_addr *src;
	struct in6_addr *coa;
	struct in6_addr *hoa;
	u_int8_t status;
{
	struct mipm_be_hint *be_hint;
	struct sockaddr_in6 sin6;
	struct mbuf *m;
	u_short len = sizeof(struct mipm_be_hint)
	    + (3 * sizeof(struct sockaddr_in6));

	m = mips_msg1(MIPM_BE_HINT, len);
	if (m == NULL)
		return;
	be_hint = mtod(m, struct mipm_be_hint *);
	be_hint->mipmbeh_seq = 0;

	be_hint->mipmbeh_status = status;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *src;
	bcopy(&sin6, (void *)MIPMBEH_PEERADDR(be_hint), sizeof(sin6));

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *coa;
	bcopy(&sin6, (void *)MIPMBEH_COA(be_hint), sizeof(sin6));

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *hoa;
	bcopy(&sin6, (void *)MIPMBEH_HOA(be_hint), sizeof(sin6));

	raw_input(m, &mips_proto, &mips_src, &mips_dst);
}

/*
 * Definitions of protocols supported in the MOBILITY domain.
 */

extern struct domain mipdomain;		/* or at least forward */

static struct protosw mipsw[] = {
{ SOCK_RAW,	&mipdomain,	0,		PR_ATOMIC|PR_ADDR,
  0,		mips_output,	raw_ctlinput,	0,
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
  0,
#else
  mips_usrreq,
#endif
  raw_init,	0,		0,		0,
#ifndef __FreeBSD__
  0/*sysctl_rtable*/
#else
# if __FreeBSD__ >= 3
  &mip_usrreqs
# endif
#endif
}
};

struct domain mipdomain =
    { PF_MOBILITY, "mip", 0, 0, 0,
      mipsw, &mipsw[sizeof(mipsw)/sizeof(mipsw[0])] };

#ifdef __FreeBSD__
DOMAIN_SET(mip);
#endif
