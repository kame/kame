/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: print-ppp.c,v 1.26 97/06/12 14:21:29 leres Exp $ (LBL)";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include <ctype.h>
#include <netdb.h>
#include <pcap.h>
#include <stdio.h>
#ifdef __bsdi__
#include <net/slcompress.h>
#include <net/if_ppp.h>
#endif

#include "interface.h"
#include "addrtoname.h"
#include "ppp.h"

/* XXX This goes somewhere else. */
#define PPP_HDRLEN 4

/* Standard PPP printer */
void
ppp_if_print(u_char *user, const struct pcap_pkthdr *h,
	     register const u_char *p)
{
	register u_int length = h->len;
	register u_int caplen = h->caplen;
	const struct ip *ip;
	u_int proto;

	ts_print(&h->ts);

	if (caplen < PPP_HDRLEN) {
		printf("[|ppp]");
		goto out;
	}

	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	proto = ntohs(*(u_short *)&p[2]);
	packetp = p;
	snapend = p + caplen;

	if (eflag)
		printf("%c %4d %02x %04x: ", p[0] ? 'O' : 'I', length,
		       p[1], proto);

	length -= PPP_HDRLEN;
	ip = (struct ip *)(p + PPP_HDRLEN);
	switch (proto) {
	case ETHERTYPE_IP:
	case PPP_IP:
		ip_print((const u_char *)ip, length);
		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		ip6_print((const u_char *)ip, length);
		break;
#endif
	}
	if (xflag)
		default_print((const u_char *)ip, caplen - PPP_HDRLEN);
out:
	putchar('\n');
}

#ifdef __bsdi__
/* proto type to string mapping */
static struct tok ptype2str[] = {
	{ PPP_VJC,	"VJC" },
	{ PPP_VJNC,	"VJNC" },
	{ PPP_OSI,	"OSI" },
	{ PPP_LCP,	"LCP" },
	{ PPP_IPCP,	"IPCP" },
	{ 0,		NULL }
};
#endif

#define PPP_BSDI_HDRLEN 24

/* BSD/OS specific PPP printer */
void
ppp_bsdos_if_print(u_char *user, const struct pcap_pkthdr *h,
	     register const u_char *p)
{
#ifdef __bsdi__
	register u_int length = h->len;
	register u_int caplen = h->caplen;
	register int hdrlength;
	u_short ptype;
	const u_char *q;
	int i;

	ts_print(&h->ts);

	if (caplen < PPP_BSDI_HDRLEN) {
		printf("[|ppp]");
		goto out;
	}

	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;
	hdrlength = 0;

#if 0
	if (p[0] == PPP_ADDRESS && p[1] == PPP_CONTROL) {
		if (eflag) 
			printf("%02x %02x ", p[0], p[1]);
		p += 2;
		hdrlength = 2;
	}

	if (eflag) 
		printf("%d ", length);
	/* Retrieve the protocol type */
	if (*p & 01) {
		/* Compressed protocol field */
		ptype = *p;
		if (eflag) 
			printf("%02x ", ptype);
		p++;
		hdrlength += 1;
	} else {
		/* Un-compressed protocol field */
		ptype = ntohs(*(u_short *)p);
		if (eflag) 
			printf("%04x ", ptype);
		p += 2;
		hdrlength += 2;
	}
#else
	ptype = 0;	/*XXX*/
	if (eflag)
		printf("%c ", p[SLC_DIR] ? 'O' : 'I');
	if (p[SLC_LLHL]) {
		/* link level header */
		struct ppp_header *ph;

		q = p + SLC_BPFHDRLEN;
		ph = (struct ppp_header *)q;
		if (ph->phdr_addr == PPP_ADDRESS
		 && ph->phdr_ctl == PPP_CONTROL) {
			if (eflag) 
				printf("%02x %02x ", q[0], q[1]);
			ptype = ntohs(ph->phdr_type);
			if (eflag && (ptype == PPP_VJC || ptype == PPP_VJNC)) {
				printf("%s ", tok2str(ptype2str,
						"proto-#%d", ptype));
			}
		} else {
			if (eflag) {
				printf("LLH=[");
				for (i = 0; i < p[SLC_LLHL]; i++)
					printf("%02x", q[i]);
				printf("] ");
			}
		}
		if (eflag) 
			printf("%d ", length);
	}
	if (p[SLC_CHL]) {
		q = p + SLC_BPFHDRLEN + p[SLC_LLHL];

		switch (ptype) {
		case PPP_VJC:
			ptype = vjc_print(q, length - (q - p), ptype);
			hdrlength = PPP_BSDI_HDRLEN;
			p += hdrlength;
			if (ptype == PPP_IP)
				ip_print(p, length);
			goto printx;
		case PPP_VJNC:
			ptype = vjc_print(q, length - (q - p), ptype);
			hdrlength = PPP_BSDI_HDRLEN;
			p += hdrlength;
			if (ptype == PPP_IP)
				ip_print(p, length);
			goto printx;
		default:
			if (eflag) {
				printf("CH=[");
				for (i = 0; i < p[SLC_LLHL]; i++)
					printf("%02x", q[i]);
				printf("] ");
			}
			break;
		}
	}

	hdrlength = PPP_BSDI_HDRLEN;
#endif

	length -= hdrlength;
	p += hdrlength;

	if (ptype == PPP_IP)
		ip_print(p, length);
	else
		printf("%s ", tok2str(ptype2str, "proto-#%d", ptype));

printx:
	if (xflag)
		default_print((const u_char *)p, caplen - hdrlength);
out:
	putchar('\n');
#endif /* __bsdi__ */
}
