/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
#if 0
static char sccsid[] = "@(#)mbuf.c	8.1 (Berkeley) 6/6/93";
#endif
static const char rcsid[] =
  "$FreeBSD: src/usr.bin/netstat/mbuf.c,v 1.15.2.1 1999/08/29 15:31:32 peter Exp $";
#endif /* not lint */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <err.h>
#include <stdio.h>
#include "netstat.h"

#define	YES	1
typedef int bool;

struct	mbstat mbstat;

static struct mbtypes {
	int	mt_type;
	char	*mt_name;
} mbtypes[] = {
	{ MT_DATA,	"data" },
	{ MT_OOBDATA,	"oob data" },
	{ MT_CONTROL,	"ancillary data" },
	{ MT_HEADER,	"packet headers" },
#ifdef MT_SOCKET
	{ MT_SOCKET,	"socket structures" },			/* XXX */
#endif
#ifdef MT_PCB
	{ MT_PCB,	"protocol control blocks" },		/* XXX */
#endif
#ifdef MT_RTABLE
	{ MT_RTABLE,	"routing table entries" },		/* XXX */
#endif
#ifdef MT_HTABLE
	{ MT_HTABLE,	"IMP host table entries" },		/* XXX */
#endif
#ifdef MT_ATABLE
	{ MT_ATABLE,	"address resolution tables" },
#endif
	{ MT_FTABLE,	"fragment reassembly queue headers" },	/* XXX */
	{ MT_SONAME,	"socket names and addresses" },
#ifdef MT_SOOPTS
	{ MT_SOOPTS,	"socket options" },
#endif
#ifdef MT_RIGHTS
	{ MT_RIGHTS,	"access rights" },
#endif
#ifdef MT_IFADDR
	{ MT_IFADDR,	"interface addresses" },		/* XXX */
#endif
	{ 0, 0 }
};

int nmbtypes = sizeof(mbstat.m_mtypes) / sizeof(short);
bool seen[256];			/* "have we seen this type yet?" */

/*
 * Print mbuf statistics.
 */
void
mbpr()
{
	register int totmem, totfree, totmbufs;
	register int i;
	register struct mbtypes *mp;
	int name[3], nmbclusters;
	size_t nmbclen, mbstatlen;

	name[0] = CTL_KERN;
	name[1] = KERN_IPC;
	name[2] = KIPC_MBSTAT;
	mbstatlen = sizeof mbstat;
	if (sysctl(name, 3, &mbstat, &mbstatlen, 0, 0) < 0) {
		warn("sysctl: retrieving mbstat");
		return;
	}

	name[2] = KIPC_NMBCLUSTERS;
	nmbclen = sizeof(int);
	if (sysctl(name, 3, &nmbclusters, &nmbclen, 0, 0) < 0) {
		warn("sysctl: retrieving nmbclusters");
		return;
	}
#undef MSIZE
#define MSIZE		(mbstat.m_msize)
#undef MCLBYTES
#define	MCLBYTES	(mbstat.m_mclbytes)

	if (nmbtypes != 256) {
		warnx("unexpected change to mbstat; check source");
		return;
	}

	totmbufs = 0;
	for (mp = mbtypes; mp->mt_name; mp++)
		totmbufs += mbstat.m_mtypes[mp->mt_type];
	printf("%u/%lu mbufs in use:\n", totmbufs, mbstat.m_mbufs);
	for (mp = mbtypes; mp->mt_name; mp++)
		if (mbstat.m_mtypes[mp->mt_type]) {
			seen[mp->mt_type] = YES;
			printf("\t%u mbufs allocated to %s\n",
			    mbstat.m_mtypes[mp->mt_type], mp->mt_name);
		}
	seen[MT_FREE] = YES;
	for (i = 0; i < nmbtypes; i++)
		if (!seen[i] && mbstat.m_mtypes[i]) {
			printf("\t%u mbufs allocated to <mbuf type %d>\n",
			    mbstat.m_mtypes[i], i);
		}
	printf("%lu/%lu/%u mbuf clusters in use (current/peak/max)\n",
		mbstat.m_clusters - mbstat.m_clfree, mbstat.m_clusters,
		nmbclusters);
	totmem = mbstat.m_mbufs * MSIZE + mbstat.m_clusters * MCLBYTES;
	totfree = mbstat.m_clfree * MCLBYTES + 
		MSIZE * (mbstat.m_mbufs - totmbufs);
	printf("%u Kbytes allocated to network (%d%% in use)\n",
		totmem / 1024, (unsigned) (totmem - totfree) * 100 / totmem);
	printf("%lu requests for memory denied\n", mbstat.m_drops);
	printf("%lu requests for memory delayed\n", mbstat.m_wait);
	printf("%lu calls to protocol drain routines\n", mbstat.m_drain);

	if (mbstat.m_exthdrget || mbstat.m_exthdrget0) {
#define	p(f, m) if (mbstat.f || sflag <= 1) \
    printf(m, (unsigned long long)mbstat.f, plural(mbstat.f))
#define	p1(f, m) if (mbstat.f || sflag <= 1) \
    printf(m, (unsigned long long)mbstat.f)
		p(m_exthdrget, "%llu use%s of IP6_EXTHDR_GET\n");
		p(m_exthdrget0, "%llu use%s of IP6_EXTHDR_GET0\n");
		p(m_pulldowns, "%llu call%s to m_pulldown\n");
		p(m_pulldown_alloc,
		    "%llu mbuf allocation%s in m_pulldown\n");
		if (mbstat.m_pulldown_copy != 1) {
			p1(m_pulldown_copy,
			    "%llu mbuf copies in m_pulldown\n");
		} else {
			p1(m_pulldown_copy,
			    "%llu mbuf copy in m_pulldown\n");
		}
		p(m_pullups, "%llu call%s to m_pullup\n");
		p(m_pullup_alloc, "%llu mbuf allocation%s in m_pullup\n");
		if (mbstat.m_pullup_copy != 1) {
			p1(m_pullup_copy,
			    "%llu mbuf copies in m_pullup\n");
		} else {
			p1(m_pullup_copy, "%llu mbuf copy in m_pullup\n");
		}
		p(m_pullup_fail, "%llu failure%s in m_pullup\n");
		p(m_pullup2, "%llu call%s to m_pullup2\n");
		p(m_pullup2_alloc,
		    "%llu mbuf allocation%s in m_pullup2\n");
		if (mbstat.m_pullup2_copy != 1) {
			p1(m_pullup2_copy,
			    "%llu mbuf copies in m_pullup2\n");
		} else {
			p1(m_pullup2_copy,
			    "%llu mbuf copy in m_pullup2\n");
		}
		p(m_pullup2_fail, "%llu failure%s in m_pullup2\n");
#undef p
#undef p1
	}
}
