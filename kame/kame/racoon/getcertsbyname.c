/*	$KAME: getcertsbyname.c,v 1.1 2001/04/11 06:11:55 sakane Exp $	*/

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

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>

#ifdef DNSSEC_DEBUG
#include <stdio.h>
#include <strings.h>
#endif

#include "netdb_dnssec.h"

/* XXX should it use ci_errno to hold errno instead of h_errno ? */
extern int h_errno;

void
freecertinfo(ci)
	struct certinfo *ci;
{
	struct certinfo *next;

	do {
		next = ci->ci_next;
		if (ci->ci_cert)
			free(ci->ci_cert);
		free(ci);
		ci = next;
	} while (ci);
}

/*
 * get CERT RR by FQDN and create certinfo structure chain.
 */
int
getcertsbyname(name, res)
	char *name;
	struct certinfo **res;
{
	caddr_t answer = NULL, p;
	int buflen, anslen, len;
	HEADER *hp;
	int qdcount, ancount, rdlength;
	char *cp, *eom;
	char hostbuf[1024];	/* XXX */
	int qtype, qclass, keytag, algorithm;
	struct certinfo head, *cur;
	int error = -1;

	/* initialize res */
	*res = NULL;

	memset(&head, 0, sizeof(head));
	cur = &head;

	/* get CERT RR */
	buflen = 512;
	do {

		buflen *= 2;
		p = realloc(answer, buflen);
		if (!p) {
#ifdef DNSSEC_DEBUG
			printf("realloc: %s", strerror(errno));
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		answer = p;

		anslen = res_query(name,  C_IN, T_CERT, answer, buflen);
		if (anslen == -1)
			goto end;

	} while (buflen < anslen);

#ifdef DNSSEC_DEBUG
	printf("get a DNS packet len=%d\n", anslen);
#endif

	/* parse CERT RR */
	eom = answer + anslen;

	hp = (HEADER *)answer;
	qdcount = ntohs(hp->qdcount);
	ancount = ntohs(hp->ancount);

	/* question section */
	if (qdcount != 1) {
#ifdef DNSSEC_DEBUG
		printf("query count is not 1.\n");
#endif
		h_errno = NO_RECOVERY;
		goto end;
	}
	cp = (char *)(hp + 1);
	len = dn_expand(answer, eom, cp, hostbuf, sizeof(hostbuf));
	if (len < 0) {
#ifdef DNSSEC_DEBUG
		printf("dn_expand failed.\n");
#endif
		goto end;
	}
	cp += len;
	GETSHORT(qtype, cp);		/* QTYPE */
	GETSHORT(qclass, cp);		/* QCLASS */

	/* answer section */
	while (ancount-- && cp < eom) {
		len = dn_expand(answer, eom, cp, hostbuf, sizeof(hostbuf));
		if (len < 0) {
#ifdef DNSSEC_DEBUG
			printf("dn_expand failed.\n");
#endif
			goto end;
		}
		cp += len;
		GETSHORT(qtype, cp);	/* TYPE */
		GETSHORT(qclass, cp);	/* CLASS */
		cp += INT32SZ;		/* TTL */
		GETSHORT(rdlength, cp);	/* RDLENGTH */

		/* CERT RR */
		if (qtype != T_CERT) {
#ifdef DNSSEC_DEBUG
			printf("not T_CERT\n");
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		GETSHORT(qtype, cp);	/* type */
		rdlength -= INT16SZ;
		GETSHORT(keytag, cp);	/* key tag */
		rdlength -= INT16SZ;
		algorithm = *cp++;	/* algorithm */
		rdlength -= 1;
		if (cp + rdlength > eom) {
#ifdef DNSSEC_DEBUG
			printf("rdlength is too long.\n");
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
#ifdef DNSSEC_DEBUG
		printf("type=%d keytag=%d alg=%d len=%d\n",
			qtype, keytag, algorithm, rdlength);
#endif

		/* create new certinfo */
		cur->ci_next = malloc(sizeof(*cur));
		if (!cur->ci_next) {
#ifdef DNSSEC_DEBUG
			printf("malloc(certinfo): %s", strerror(errno));
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		cur = cur->ci_next;
		memset(cur, 0, sizeof(*cur));
		cur->ci_type = qtype;
		cur->ci_keytag = keytag;
		cur->ci_algorithm = algorithm;
		cur->ci_certlen = rdlength;
		cur->ci_cert = malloc(rdlength);
		if (!cur->ci_cert) {
#ifdef DNSSEC_DEBUG
			printf("malloc(cert): %s", strerror(errno));
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		memcpy(cur->ci_cert, cp, rdlength);
		cp += rdlength;
	}

	*res = head.ci_next;
	error = 0;

end:
	if (answer)
		free(answer);
	if (error && head.ci_next)
		freecertinfo(head.ci_next);

	return error;
}

#ifdef DNSSEC_DEBUG
int
b64encode(p, len)
	char *p;
	int len;
{
	static const char b64t[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/=";

	while (len > 2) {
                printf("%c", b64t[(p[0] >> 2) & 0x3f]);
                printf("%c", b64t[((p[0] << 4) & 0x30) | ((p[1] >> 4) & 0x0f)]);
                printf("%c", b64t[((p[1] << 2) & 0x3c) | ((p[2] >> 6) & 0x03)]);
                printf("%c", b64t[p[2] & 0x3f]);
		len -= 3;
		p += 3;
	}

	if (len == 2) {
                printf("%c", b64t[(p[0] >> 2) & 0x3f]);
                printf("%c", b64t[((p[0] << 4) & 0x30)| ((p[1] >> 4) & 0x0f)]);
                printf("%c", b64t[((p[1] << 2) & 0x3c)]);
                printf("%c", '=');
        } else if (len == 1) {
                printf("%c", b64t[(p[0] >> 2) & 0x3f]);
                printf("%c", b64t[((p[0] << 4) & 0x30)]);
                printf("%c", '=');
                printf("%c", '=');
	}

	return 0;
}

int
main(ac, av)
	int ac;
	char **av;
{
	struct certinfo *res, *p;
	int i;

	if (ac < 2) {
		printf("Usage: a.out (FQDN)\n");
		exit(1);
	}

	i = getcertsbyname(*(av + 1), &res);
	if (i != 0) {
		herror("getcertsbyname");
		exit(1);
	}
	printf("getcertsbyname succeeded.\n");

	i = 0;
	for (p = res; p; p = p->ci_next) {
		printf("certinfo[%d]:\n", i);
		printf("\tci_type=%d\n", p->ci_type);
		printf("\tci_keytag=%d\n", p->ci_keytag);
		printf("\tci_algorithm=%d\n", p->ci_algorithm);
		printf("\tci_certlen=%d\n", p->ci_certlen);
		printf("\tci_cert: ");
		b64encode(p->ci_cert, p->ci_certlen);
		printf("\n");
		i++;
	}

	freecertinfo(res);

	exit(0);
}
#endif
