/*	$KAME: natpt_log.c,v 1.12 2001/09/02 19:06:25 fujisawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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

#ifdef __FreeBSD__
#include "opt_natpt.h"
#endif

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <machine/stdarg.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

static struct sockaddr	natpt_dst = {2, PF_INET};
static struct sockaddr	natpt_src = {2, PF_INET};


/*
 *
 */

void
natpt_logMsg(int priorities, char *format, ...)
{
	int		 rv;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, format);
	rv = vsnprintf(wow, sizeof(wow), format, ap);
	natpt_log(LOG_MSG, priorities, (void *)wow, strlen(wow)+1);
	va_end(ap);
}


void
natpt_logMBuf(int priorities, struct mbuf *m, ...)
{
	int		 rv;
	char		*format;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, m);
	if ((format = va_arg(ap, char *)) != NULL) {
		rv = vsnprintf(wow, sizeof(wow), format, ap);
		natpt_log(LOG_MSG,  priorities, (void *)wow, strlen(wow)+1);
	}
	va_end(ap);

	natpt_log(LOG_DUMP, priorities, (void *)m->m_data, min(m->m_len, LBFSZ));
}


void
natpt_logIp6(int priorities, struct ip6_hdr *ip6, ...)
{
	int		 rv;
	char		*format;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, ip6);
	if ((format = va_arg(ap, char *)) != NULL) {
		rv = vsnprintf(wow, sizeof(wow), format, ap);
		natpt_log(LOG_MSG,  priorities, (void *)wow, strlen(wow)+1);
	}
	va_end(ap);

	natpt_log(LOG_IP6, priorities, (void *)ip6, sizeof(struct ip6_hdr)+8);
}


void
natpt_logIp4(int priorities, struct ip *ip4, ...)
{
	int		 rv;
	char		*format;
	u_char		 wow[256];
	va_list		 ap;

	va_start(ap, ip4);
	if ((format = va_arg(ap, char *)) != NULL) {
		rv = vsnprintf(wow, sizeof(wow), format, ap);
		natpt_log(LOG_MSG,  priorities, (void *)wow, strlen(wow)+1);
	}
	va_end(ap);

	natpt_log(LOG_IP4, priorities, (void *)ip4, ((ip4->ip_hl << 2) + 20));
}


int
natpt_log(int type, int priorities, void *item, size_t size)
{
	struct sockproto	 proto;
	struct	mbuf	*m;
	struct	lbuf	*p;

	if ((m = natpt_lbuf(type, priorities, size)) == NULL)
		return (ENOBUFS);

	p = (struct lbuf *)m->m_data;
	m_copyback(m, sizeof(struct l_hdr), p->l_hdr.lh_size, (caddr_t)item);

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_AHIP;
	natpt_input(m, &proto, &natpt_src, &natpt_dst);

	return (0);
}


int
natpt_logIN6addr(int priorities, char *msg, struct in6_addr *sin6addr)
{
	int		 size, msgsz;
	struct	mbuf	*m;
	struct	lbuf	*p;

	msgsz = strlen(msg)+1;
	size = sizeof(struct l_hdr) + IN6ADDRSZ + msgsz;

	if ((m = natpt_lbuf(LOG_IN6ADDR, priorities, size)) == NULL)
		return (ENOBUFS);

	{
		struct sockproto	proto;

		p = (struct lbuf *)m->m_pktdat;
		bcopy(sin6addr, p->l_addr.in6addr, sizeof(struct in6_addr));
		strncpy(p->l_msg, msg, min(msgsz, MSGSZ-1));
		p->l_msg[MSGSZ-1] = '\0';

		proto.sp_family = AF_INET;
		proto.sp_protocol = IPPROTO_AHIP;
		natpt_input(m, &proto, &natpt_src, &natpt_dst);
	}

	return (0);
}


struct mbuf *
natpt_lbuf(int type, int priorities, size_t size)
{
	struct	mbuf	*m;
	struct	lbuf	*p;
	int		 maxlen;

	if (size + sizeof(struct l_hdr) > MCLBYTES)
		return (NULL);

	MGETHDR(m, M_NOWAIT, MT_DATA);
	maxlen = MHLEN;
	if (size + sizeof(struct l_hdr) > MHLEN) {
		MCLGET(m, M_NOWAIT);
		maxlen = MCLBYTES;
		if ((m->m_flags & M_EXT) == 0) {
			m_freem(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return (NULL);

	m->m_pkthdr.len = m->m_len = maxlen;
	m->m_pkthdr.rcvif = NULL;

	p = (struct lbuf *)m->m_data;
	p->l_hdr.lh_type = type;
	p->l_hdr.lh_pri	 = priorities;
	p->l_hdr.lh_size = size;
	microtime((struct timeval *)&p->l_hdr.lh_sec);

	return (m);
}
