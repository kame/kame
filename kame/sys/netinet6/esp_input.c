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

/*
 * RFC1827/2406 Encapsulated Security Payload.
 */

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <machine/cpu.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/ip_ecn.h>

#ifdef INET6
#include <netinet6/ip6.h>
#if !defined(__FreeBSD__) || __FreeBSD__ < 3
#include <netinet6/in6_pcb.h>
#endif
#include <netinet6/ip6_var.h>
#include <netinet6/icmp6.h>
#endif

#include <netinet6/ipsec.h>
#include <netinet6/ah.h>
#include <netinet6/esp.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <netkey/key_debug.h>

#include <machine/stdarg.h>

#define IPLEN_FLIPPED

#ifdef __NetBSD__
#define ovbcopy	bcopy
#endif

#ifdef INET
extern struct protosw inetsw[];
#if defined(__bsdi__) || defined(__NetBSD__)
extern u_char ip_protox[];
#endif

void
#if __STDC__
esp4_input(struct mbuf *m, ...)
#else
esp4_input(m, va_alist)
	struct mbuf *m;
	va_dcl
#endif
{
	struct ip *ip;
	struct esp *esp;
	struct esptail *esptail;
	u_int32_t spi;
	struct secas *sa = NULL;
	size_t taillen;
	u_int16_t nxt;
	struct esp_algorithm *algo;
	int ivlen;
	size_t hlen;
	size_t esplen;
	int s;
	va_list ap;
	int off, proto;

	va_start(ap, m);
	off = va_arg(ap, int);
	proto = va_arg(ap, int);
	va_end(ap);

	/* sanity check for alignment. */
	if (off % 4 != 0 || m->m_pkthdr.len % 4 != 0) {
		printf("IPv4 ESP input: packet alignment problem "
			"(off=%d, pktlen=%d)\n", off, m->m_pkthdr.len);
		ipsecstat.in_inval++;
		goto bad;
	}

	if (m->m_len < off + sizeof(struct esp)) {
		m = m_pullup(m, off + sizeof(struct esp));
		if (!m) {
			printf("IPv4 ESP input: can't pullup in esp4_input\n");
			ipsecstat.in_inval++;
			goto bad;
		}
	}

	ip = mtod(m, struct ip *);
	esp = (struct esp *)(((u_int8_t *)ip) + off);
#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	/* find the sassoc. */
	spi = esp->esp_spi;

	if ((sa = key_allocsa(AF_INET,
	                      (caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst,
	                      IPPROTO_ESP, spi)) == 0) {
		printf("IPv4 ESP input: no key association found for spi %u;"
			"dropping the packet for simplicity\n",
			(u_int32_t)ntohl(spi));
		ipsecstat.in_nosa++;
		goto bad;
	}
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP esp4_input called to allocate SA:%p\n", sa));
	if (sa->state != SADB_SASTATE_MATURE
	 && sa->state != SADB_SASTATE_DYING) {
		printf("IPv4 ESP input: non-mature/dying SA found for spi %u; "
			"dropping the packet for simplicity\n",
			(u_int32_t)ntohl(spi));
		ipsecstat.in_badspi++;
		goto bad;
	}
	if (sa->alg_enc == SADB_EALG_NONE) {
		printf("IPv4 ESP input: unspecified encryption algorithm "
			"for spi %u;"
			"dropping the packet for simplicity\n",
			(u_int32_t)ntohl(spi));
		ipsecstat.in_badspi++;
		goto bad;
	}

	algo = &esp_algorithms[sa->alg_enc];	/*XXX*/

	/* check if we have proper ivlen information */
	ivlen = sa->ivlen;
	if (ivlen < 0) {
		log(LOG_NOTICE, "inproper ivlen in IPv4 ESP input: %s %s\n",
			ipsec4_logpacketstr(ip, spi),
			ipsec_logsastr(sa));
		ipsecstat.in_inval++;
		goto bad;
	}

	if (!((sa->flags & SADB_X_EXT_OLD) == 0 && sa->replay
	 && (sa->alg_auth && sa->key_auth)))
		goto noreplaycheck;

	if (sa->alg_auth == SADB_AALG_NULL)
		goto noreplaycheck;

	/*
	 * check for sequence number.
	 */
	if (ipsec_chkreplay(ntohl(((struct newesp *)esp)->esp_seq), sa))
		; /*okey*/
	else {
		ipsecstat.in_espreplay++;
		log(LOG_AUTH, "replay packet in IPv4 ESP input: %s %s\n",
			ipsec4_logpacketstr(ip, spi),
			ipsec_logsastr(sa));
		goto bad;
	}

	/* check ICV */
    {
	struct mbuf *n;
	int len;
	u_char sum0[AH_MAXSUMSIZE];
	u_char sum[AH_MAXSUMSIZE];
	struct ah_algorithm *sumalgo;
	size_t siz;

	sumalgo = &ah_algorithms[sa->alg_auth];
	siz = (((*sumalgo->sumsiz)(sa) + 3) & ~(4 - 1));
	if (AH_MAXSUMSIZE < siz) {
		printf("internal error: AH_MAXSUMSIZE must be larger than %lu\n",
		    (u_long)siz);
		ipsecstat.in_inval++;
		goto bad;
	}

	n = m;
	len = m->m_pkthdr.len;
	len -= siz;
	while (n && 0 < len) {
		if (len < n->m_len)
			break;
		len -= n->m_len;
		n = n->m_next;
	}
	if (!n) {
		printf("mbuf chain problem?\n");
		ipsecstat.in_inval++;
		goto bad;
	}
	m_copydata(n, len, siz, &sum0[0]);

	if (esp_auth(m, off, m->m_pkthdr.len - off - siz, sa, sum)) {
		log(LOG_AUTH, "auth fail in IPv4 ESP input: %s %s\n",
			ipsec4_logpacketstr(ip, spi),
			ipsec_logsastr(sa));
		ipsecstat.in_espauthfail++;
		goto bad;
	}

	if (bcmp(sum0, sum, siz) != 0) {
		log(LOG_AUTH, "auth fail in IPv4 ESP input: %s %s\n",
			ipsec4_logpacketstr(ip, spi),
			ipsec_logsastr(sa));
		ipsecstat.in_espauthfail++;
		goto bad;
	}

	/* strip off */
	m->m_pkthdr.len -= siz;
	n->m_len -= siz;
	ip = mtod(m, struct ip *);
#ifdef IPLEN_FLIPPED
	ip->ip_len = ip->ip_len - siz;
#else
	ip->ip_len = htons(ntohs(ip->ip_len) - siz);
#endif
	m->m_flags |= M_AUTHIPDGM;
	ipsecstat.in_espauthsucc++;
    }

	/*
	 * update sequence number.
	 */
	if ((sa->flags & SADB_X_EXT_OLD) == 0 && sa->replay) {
		(void)ipsec_updatereplay(ntohl(((struct newesp *)esp)->esp_seq), sa);
	}

noreplaycheck:

	/* process main esp header. */
	if (sa->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		esplen = sizeof(struct esp);
	} else {
		/* RFC 2406 */
		if (sa->flags & SADB_X_EXT_DERIV)
			esplen = sizeof(struct esp);
		else
			esplen = sizeof(struct newesp);
	}

	if (m->m_len < off + esplen + ivlen) {
		m = m_pullup(m, off + esplen + ivlen);
		if (!m) {
			printf("IPv4 ESP input: can't pullup in esp4_input\n");
			ipsecstat.in_inval++;
			goto bad;
		}
	}

    {
	/*
	 * decrypt the packet.
	 */
	if (!algo->decrypt)
		panic("internal error: no decrypt function");
	if ((*algo->decrypt)(m, off, sa, algo, ivlen)) {
		log(LOG_AUTH, "decrypt fail in IPv4 ESP input: %s %s\n",
			ipsec4_logpacketstr(ip, spi),
			ipsec_logsastr(sa));
		ipsecstat.in_inval++;
		goto bad;
	}
	ipsecstat.in_esphist[sa->alg_enc]++;

	m->m_flags |= M_DECRYPTED;
    }

#ifdef garbled_data_found_on_mbuf_after_packet
    {
	/*
	 * For simplicity, we'll trim the packet so that there's no extra
	 * part appended after IP packet.
	 * This is rare case for some odd drivers, so there should be no
	 * performance hit.
	 */

	/*
	 * Note that, in ip_input, ip_len was already flipped and header
	 * length was subtracted from ip_len.
	 */
#ifdef IPLEN_FLIPPED
	if (m->m_pkthdr.len != hlen + ip->ip_len)
#else
	if (m->m_pkthdr.len != hlen + ntohs(ip->ip_len))
#endif
	{
		size_t siz;
		struct mbuf *n;

#ifdef IPLEN_FLIPPED
		siz = hlen + ip->ip_len;
#else
		siz = hlen + ntohs(ip->ip_len);
#endif

		/* find the final mbuf */
		for (n = m; n; n = n->m_next) {
			if (n->m_len < siz)
				siz -= n->m_len;
			else
				break;
		}
		if (!n) {
			printf("invalid packet\n");
			ipsecstat.in_inval++;
			goto bad;
		}

		/* trim the final mbuf */
		if (n->m_len < siz) {
			printf("invalid size: %d %d\n", n->m_len, siz);
			ipsecstat.in_inval++;
			goto bad;
		}
		n->m_len = siz;

		/* dispose the rest of the packet */
		m_freem(n->m_next);
		n->m_next = NULL;

#ifdef IPLEN_FLIPPED
		m->m_pkthdr.len = hlen + ip->ip_len;
#else
		m->m_pkthdr.len = hlen + ntohs(ip->ip_len);
#endif
	}
    }
#endif

    {
	/*
	 * find the trailer of the ESP.
	 */
	struct mbuf *n;		/*the last mbuf on the mbuf chain, m_len > 0 */
	struct mbuf *o;		/*the last mbuf on the mbuf chain */
	
	o = m;
	n = NULL;
	while (o) {
		if (0 < o->m_len)
			n = o;
		o = o->m_next;
	}
	if (!n || n->m_len < sizeof(struct esptail)) {
		printf("IPv4 ESP input: assertion on pad part failed; "
			"dropping the packet\n");
		ipsecstat.in_inval++;
		goto bad;
	}

	esptail = (struct esptail *)
		(mtod(n, u_int8_t *) + n->m_len - sizeof(struct esptail));
	nxt = esptail->esp_nxt;
	taillen = esptail->esp_padlen + 2;

	if (m->m_pkthdr.len < taillen
	 || m->m_pkthdr.len - taillen < hlen) {	/*?*/
		log(LOG_NOTICE, "bad pad length in IPv4 ESP input: %s %s\n",
			ipsec4_logpacketstr(ip, spi),
			ipsec_logsastr(sa));
		ipsecstat.in_inval++;
		goto bad;
	}

	/*
	 * strip off the trailing pad area.
	 */
	if (taillen < n->m_len) {
		/* trailing pad data is included in the last mbuf item. */
		n->m_len -= taillen;
		m->m_pkthdr.len -= taillen;
	} else {
		/* trailing pad data spans on multiple mbuf item. */
		size_t siz;

		siz = m->m_pkthdr.len;
		if (siz < taillen) {
			log(LOG_NOTICE, "bad packet length in IPv4 ESP input: %s %s\n",
				ipsec4_logpacketstr(ip, spi),
				ipsec_logsastr(sa));
			ipsecstat.in_inval++;
			goto bad;
		}
		siz -= taillen;

		/* find the final mbuf */
		for (n = m; n; n = n->m_next) {
			if (n->m_len < siz)
				siz -= n->m_len;
			else
				break;
		}
		if (!n) {
			printf("invalid packet\n");
			ipsecstat.in_inval++;
			goto bad;
		}

		/* trim the final mbuf */
		if (n->m_len < siz) {
			printf("invalid size: %d %lu\n", n->m_len, (u_long)siz);
			ipsecstat.in_inval++;
			goto bad;
		}
		n->m_len = siz;

		/* dispose the rest of the packet */
		m_freem(n->m_next);
		n->m_next = NULL;

		m->m_pkthdr.len -= taillen;
	}

#ifdef IPLEN_FLIPPED
	ip->ip_len = ip->ip_len - taillen;
#else
	ip->ip_len = htons(ntohs(ip->ip_len) - taillen);
#endif
    }

	/* was it transmitted over the IPsec tunnel SA? */
	if (ipsec4_tunnel_validate(ip, nxt, sa) && nxt == IPPROTO_IPV4) {
		/*
		 * strip off all the headers that precedes ESP header.
		 *	IP4 xx ESP IP4' payload -> IP4' payload
		 *
		 * XXX more sanity checks
		 * XXX relationship with gif?
		 */
#if 1	/*debug*/
		struct ip oip;
#endif
		u_int8_t tos;

		tos = ip->ip_tos;
#if 1	/*debug*/
		bcopy(mtod(m, struct ip *), &oip, sizeof(oip));
#endif
		m_adj(m, off + esplen + ivlen);
		if (m->m_len < sizeof(*ip)) {
			m = m_pullup(m, sizeof(*ip));
			if (!m) {
				ipsecstat.in_inval++;
				goto bad;
			}
		}
		ip = mtod(m, struct ip *);
		/* ECN consideration. */
		ip_ecn_egress(ip4_ipsec_ecn, &tos, &ip->ip_tos);
		if (!key_checktunnelsanity(sa, AF_INET,
			    (caddr_t)&ip->ip_src, (caddr_t)&ip->ip_dst)) {
			log(LOG_NOTICE, "ipsec tunnel address mismatch in IPv4 ESP input: %s %s\n",
				ipsec4_logpacketstr(ip, spi),
				ipsec_logsastr(sa));
			ipsecstat.in_inval++;
			goto bad;
		}

#if 0 /* XXX should call ipfw rather than ipsec_inn_reject, shouldn't it ? */
		/* drop it if it does not match the default policy */
		if (ipsec4_in_reject(m, NULL)) {
			ipsecstat.in_polvio++;
			goto bad;
		}
#endif

		key_sa_recordxfer(sa, m);

		s = splimp();
		if (IF_QFULL(&ipintrq)) {
			ipsecstat.in_inval++;
			goto bad;
		}
		IF_ENQUEUE(&ipintrq, m);
		m = NULL;
		schednetisr(NETISR_IP); /*can be skipped but to make sure*/
		splx(s);
		nxt = IPPROTO_DONE;
	} else {
		/*
		 * strip off ESP header and IV.
		 * We do deep-copy since KAME requires packet to be placed
		 * in a single mbuf.
		 */
		size_t stripsiz;

		stripsiz = esplen + ivlen;

		ip = mtod(m, struct ip *);
		ovbcopy((caddr_t)ip, (caddr_t)(((u_char *)ip) + stripsiz), off);
		m->m_data += stripsiz;
		m->m_len -= stripsiz;
		m->m_pkthdr.len -= stripsiz;

		ip = mtod(m, struct ip *);
#ifdef IPLEN_FLIPPED
		ip->ip_len = ip->ip_len - stripsiz;
#else
		ip->ip_len = htons(ntohs(ip->ip_len) - stripsiz);
#endif
		ip->ip_p = nxt;

		key_sa_recordxfer(sa, m);

		if (nxt != IPPROTO_DONE)
			(*inetsw[ip_protox[nxt]].pr_input)(m, off, nxt);
		else
			m_freem(m);
		m = NULL;
	}

	if (sa) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP esp4_input call free SA:%p\n", sa));
		key_freesa(sa);
	}
	ipsecstat.in_success++;
	return;

bad:
	if (sa) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP esp4_input call free SA:%p\n", sa));
		key_freesa(sa);
	}
	if (m)
		m_freem(m);
	return;
}
#endif /* INET */

#ifdef INET6
int
esp6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	int off = *offp;
	struct ip6_hdr *ip6;
	struct esp *esp;
	struct esptail *esptail;
	u_int32_t spi;
	struct secas *sa = NULL;
	size_t taillen;
	u_int16_t nxt;
	struct esp_algorithm *algo;
	int ivlen;
	size_t esplen;
	int s;

	/* sanity check for alignment. */
	if (off % 4 != 0 || m->m_pkthdr.len % 4 != 0) {
		printf("IPv6 ESP input: packet alignment problem "
			"(off=%d, pktlen=%d)\n", off, m->m_pkthdr.len);
		ipsec6stat.in_inval++;
		goto bad;
	}

	IP6_EXTHDR_CHECK(m, off, sizeof(struct esp), IPPROTO_DONE);

	ip6 = mtod(m, struct ip6_hdr *);
	esp = (struct esp *)(((u_int8_t *)ip6) + off);

	if (ntohs(ip6->ip6_plen) == 0) {
		printf("IPv6 ESP input: ESP with IPv6 jumbogram is not supported.\n");
		ipsec6stat.in_inval++;
		goto bad;
	}

	/* find the sassoc. */
	spi = esp->esp_spi;

	if ((sa = key_allocsa(AF_INET6,
	                      (caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst,
	                      IPPROTO_ESP, spi)) == 0) {
		printf("IPv6 ESP input: no key association found for spi %u;"
			"dropping the packet for simplicity\n",
			(u_int32_t)ntohl(spi));
		ipsec6stat.in_nosa++;
		goto bad;
	}
	KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
		printf("DP esp6_input called to allocate SA:%p\n", sa));
	if (sa->state != SADB_SASTATE_MATURE
	 && sa->state != SADB_SASTATE_DYING) {
		printf("IPv6 ESP input: non-mature/dying SA found for spi %u; "
			"dropping the packet for simplicity\n",
			(u_int32_t)ntohl(spi));
		ipsec6stat.in_badspi++;
		goto bad;
	}
	if (sa->alg_enc == SADB_EALG_NONE) {
		printf("IPv6 ESP input: unspecified encryption algorithm "
			"for spi %u;"
			"dropping the packet for simplicity\n",
			(u_int32_t)ntohl(spi));
		ipsec6stat.in_badspi++;
		goto bad;
	}

	algo = &esp_algorithms[sa->alg_enc];	/*XXX*/

	/* check if we have proper ivlen information */
	ivlen = sa->ivlen;
	if (ivlen < 0) {
		log(LOG_NOTICE, "inproper ivlen in IPv6 ESP input: %s %s\n",
			ipsec6_logpacketstr(ip6, spi),
			ipsec_logsastr(sa));
		ipsec6stat.in_badspi++;
		goto bad;
	}

	if (!((sa->flags & SADB_X_EXT_OLD) == 0 && sa->replay
	 && (sa->alg_auth && sa->key_auth)))
		goto noreplaycheck;

	if (sa->alg_auth == SADB_AALG_NULL)
		goto noreplaycheck;

	/*
	 * check for sequence number.
	 */
	if (ipsec_chkreplay(ntohl(((struct newesp *)esp)->esp_seq), sa))
		; /*okey*/
	else {
		ipsec6stat.in_espreplay++;
		log(LOG_AUTH, "replay packet in IPv6 ESP input: %s %s\n",
			ipsec6_logpacketstr(ip6, spi),
			ipsec_logsastr(sa));
		goto bad;
	}

	/* check ICV */
    {
	struct mbuf *n;
	size_t len;
	u_char sum0[AH_MAXSUMSIZE];
	u_char sum[AH_MAXSUMSIZE];
	struct ah_algorithm *sumalgo;
	size_t siz;

	sumalgo = &ah_algorithms[sa->alg_auth];
	siz = (((*sumalgo->sumsiz)(sa) + 3) & ~(4 - 1));
	if (AH_MAXSUMSIZE < siz) {
		printf("internal error: AH_MAXSUMSIZE must be larger than %lu\n",
		    (u_long)siz);
		ipsec6stat.in_inval++;
		goto bad;
	}

	n = m;
	len = m->m_pkthdr.len;
	len -= siz;	/*XXX*/
	while (n && 0 < len) {
		if (len < n->m_len)
			break;
		len -= n->m_len;
		n = n->m_next;
	}
	if (!n) {
		printf("mbuf chain problem?\n");
		ipsec6stat.in_inval++;
		goto bad;
	}
	m_copydata(n, len, siz, &sum0[0]);

	if (esp_auth(m, off, m->m_pkthdr.len - off - siz, sa, sum)) {
		log(LOG_AUTH, "auth fail in IPv6 ESP input: %s %s\n",
			ipsec6_logpacketstr(ip6, spi),
			ipsec_logsastr(sa));
		ipsec6stat.in_espauthfail++;
		goto bad;
	}

	if (bcmp(sum0, sum, siz) != 0) {
		log(LOG_AUTH, "auth fail in IPv6 ESP input: %s %s\n",
			ipsec6_logpacketstr(ip6, spi),
			ipsec_logsastr(sa));
		ipsec6stat.in_espauthfail++;
		goto bad;
	}

	/* strip off */
	m->m_pkthdr.len -= siz;
	n->m_len -= siz;
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - siz);

	m->m_flags |= M_AUTHIPDGM;
	ipsec6stat.in_espauthsucc++;
    }

	/*
	 * update sequence number.
	 */
	if ((sa->flags & SADB_X_EXT_OLD) == 0 && sa->replay) {
		(void)ipsec_updatereplay(ntohl(((struct newesp *)esp)->esp_seq), sa);
	}

noreplaycheck:

	/* process main esp header. */
	if (sa->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		esplen = sizeof(struct esp);
	} else {
		/* RFC 2406 */
		if (sa->flags & SADB_X_EXT_DERIV)
			esplen = sizeof(struct esp);
		else
			esplen = sizeof(struct newesp);
	}

	IP6_EXTHDR_CHECK(m, off, esplen + ivlen, IPPROTO_DONE);	/*XXX*/

	/*
	 * decrypt the packet.
	 */
	if (!algo->decrypt)
		panic("internal error: no decrypt function");
	if ((*algo->decrypt)(m, off, sa, algo, ivlen)) {
		log(LOG_AUTH, "decrypt fail in IPv6 ESP input: %s %s\n",
			ipsec6_logpacketstr(ip6, spi),
			ipsec_logsastr(sa));
		ipsec6stat.in_inval++;
		goto bad;
	}
	ipsec6stat.in_esphist[sa->alg_enc]++;

	m->m_flags |= M_DECRYPTED;

#ifdef garbled_data_found_on_mbuf_after_packet
    {
	/*
	 * For simplicity, we'll trim the packet so that there's no extra
	 * part appended after IP packet.
	 * This is rare case for some odd drivers, so there should be no
	 * performance hit.
	 */

	/*
	 * Note that, in ip_input, ip_len was already flipped and header
	 * length was subtracted from ip_len.
	 */
#ifdef IPLEN_FLIPPED
	if (m->m_pkthdr.len != hlen + ip->ip_len)
#else
	if (m->m_pkthdr.len != hlen + ntohs(ip->ip_len))
#endif
	{
		size_t siz;
		struct mbuf *n;

#ifdef IPLEN_FLIPPED
		siz = hlen + ip->ip_len;
#else
		siz = hlen + ntohs(ip->ip_len);
#endif

		/* find the final mbuf */
		for (n = m; n; n = n->m_next) {
			if (n->m_len < siz)
				siz -= n->m_len;
			else
				break;
		}
		if (!n) {
			printf("invalid packet\n");
			ipsec6stat.in_inval++;
			goto bad;
		}

		/* trim the final mbuf */
		if (n->m_len < siz) {
			printf("invalid size: %d %d\n", n->m_len, siz);
			ipsec6stat.in_inval++;
			goto bad;
		}
		n->m_len = siz;

		/* dispose the rest of the packet */
		m_freem(n->m_next);
		n->m_next = NULL;

#ifdef IPLEN_FLIPPED
		m->m_pkthdr.len = hlen + ip->ip_len;
#else
		m->m_pkthdr.len = hlen + ntohs(ip->ip_len);
#endif
	}
    }
#endif

    {
	/*
	 * find the trailer of the ESP.
	 */
	struct mbuf *n;		/*the last mbuf on the mbuf chain, m_len > 0 */
	struct mbuf *o;		/*the last mbuf on the mbuf chain */
	
	o = m;
	n = NULL;
	while (o) {
		if (0 < o->m_len)
			n = o;
		o = o->m_next;
	}
	if (!n || n->m_len < sizeof(struct esptail)) {
		printf("IPv6 ESP input: assertion on pad part failed; "
			"dropping the packet\n");
		ipsec6stat.in_inval++;
		goto bad;
	}

	esptail = (struct esptail *)
		(mtod(n, u_int8_t *) + n->m_len - sizeof(struct esptail));
	nxt = esptail->esp_nxt;
	taillen = esptail->esp_padlen + 2;

	if (m->m_pkthdr.len < taillen
	 || m->m_pkthdr.len - taillen < sizeof(struct ip6_hdr)) {	/*?*/
		log(LOG_NOTICE, "bad pad length in IPv6 ESP input: %s %s\n",
			ipsec6_logpacketstr(ip6, spi),
			ipsec_logsastr(sa));
		ipsec6stat.in_inval++;
		goto bad;
	}

	/*
	 * XXX strip off the padding.
	 */
	if (taillen < n->m_len) {
		/* trailing pad data is included in the last mbuf item. */
		n->m_len -= taillen;
		m->m_pkthdr.len -= taillen;
	} else {
		/* trailing pad data spans on multiple mbuf item. */
		size_t siz;

		siz = m->m_pkthdr.len;
		if (siz < taillen) {
			log(LOG_NOTICE, "bad packet length in IPv6 ESP input: %s %s\n",
				ipsec6_logpacketstr(ip6, spi),
				ipsec_logsastr(sa));
			ipsec6stat.in_inval++;
			goto bad;
		}
		siz -= taillen;

		/* find the final mbuf */
		for (n = m; n; n = n->m_next) {
			if (n->m_len < siz)
				siz -= n->m_len;
			else
				break;
		}
		if (!n) {
			printf("invalid packet\n");
			ipsec6stat.in_inval++;
			goto bad;
		}

		/* trim the final mbuf */
		if (n->m_len < siz) {
			printf("invalid size: %d %lu\n", n->m_len, (u_long)siz);
			ipsec6stat.in_inval++;
			goto bad;
		}
		n->m_len = siz;

		/* dispose the rest of the packet */
		m_freem(n->m_next);
		n->m_next = NULL;

		m->m_pkthdr.len -= taillen;
	}

	ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - taillen);
    }

	/* was it transmitted over the IPsec tunnel SA? */
	if (ipsec6_tunnel_validate(ip6, nxt, sa) && nxt == IPPROTO_IPV6) {
		/*
		 * strip off all the headers that precedes ESP header.
		 *	IP6 xx ESP IP6' payload -> IP6' payload
		 *
		 * XXX more sanity checks
		 * XXX relationship with gif?
		 */
		u_int32_t flowinfo;	/*net endian*/
		flowinfo = ip6->ip6_flow;
		m_adj(m, off + esplen + ivlen);
		if (m->m_len < sizeof(*ip6)) {
			/*
			 * m_pullup is prohibited in KAME IPv6 input processing
			 * but there's no other way!
			 */
			m = m_pullup(m, sizeof(*ip6));
			if (!m) {
				ipsec6stat.in_inval++;
				goto bad;
			}
		}
		ip6 = mtod(m, struct ip6_hdr *);
		/* ECN consideration. */
		ip6_ecn_egress(ip6_ipsec_ecn, &flowinfo, &ip6->ip6_flow);
		if (!key_checktunnelsanity(sa, AF_INET6,
			    (caddr_t)&ip6->ip6_src, (caddr_t)&ip6->ip6_dst)) {
			log(LOG_NOTICE, "ipsec tunnel address mismatch in IPv6 ESP input: %s %s\n",
				ipsec6_logpacketstr(ip6, spi),
				ipsec_logsastr(sa));
			ipsec6stat.in_inval++;
			goto bad;
		}

#if 0 /* XXX should call ipfw rather than ipsec_inn_reject, shouldn't it ? */
		/* drop it if it does not match the default policy */
		if (ipsec6_in_reject(m, NULL)) {
			ipsec6stat.in_polvio++;
			goto bad;
		}
#endif

		key_sa_recordxfer(sa, m);

		s = splimp();
		if (IF_QFULL(&ip6intrq)) {
			ipsec6stat.in_inval++;
			goto bad;
		}
		IF_ENQUEUE(&ip6intrq, m);
		m = NULL;
		schednetisr(NETISR_IPV6); /*can be skipped but to make sure*/
		splx(s);
		nxt = IPPROTO_DONE;
	} else {
		/*
		 * strip off ESP header and IV.
		 * We do deep-copy since KAME requires packet to be placed
		 * in a single mbuf.
		 */
		size_t stripsiz;
		char *prvnxtp;

		/*
		 * Set the next header field of the previous header correctly.
		 */
		prvnxtp = ip6_get_prevhdr(m, off); /* XXX */
		*prvnxtp = nxt;

		stripsiz = esplen + ivlen;

		ip6 = mtod(m, struct ip6_hdr *);
		ovbcopy((caddr_t)ip6, (caddr_t)(((u_char *)ip6) + stripsiz),
			off);
		m->m_data += stripsiz;
		m->m_len -= stripsiz;
		m->m_pkthdr.len -= stripsiz;

		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) - stripsiz);

		key_sa_recordxfer(sa, m);
	}

	*offp = off;
	*mp = m;

	if (sa) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP esp6_input call free SA:%p\n", sa));
		key_freesa(sa);
	}
	ipsec6stat.in_success++;
	return nxt;

bad:
	if (sa) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP esp6_input call free SA:%p\n", sa));
		key_freesa(sa);
	}
	if (m)
		m_freem(m);
	return IPPROTO_DONE;
}
#endif /* INET6 */
