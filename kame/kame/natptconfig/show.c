/*	$KAME: show.c,v 1.15 2001/09/02 19:32:28 fujisawa Exp $	*/

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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>

#include <arpa/inet.h>

#include <netinet6/natpt_defs.h>

#include "defs.h"
#include "miscvar.h"
#include "showvar.h"
#include "cfparse.h"


/*
 *
 */

#define	TYPE_INT		1


kvm_t		*kd;

static struct nlist	nl[] =
{
#define	NL_TR			0
	{ "_ip6_protocol_tr" },
#define	NL_PREFIX		1
	{ "_natpt_prefix" },
#define NL_CSLHEAD		2
	{ "_csl_head" },
#define NL_TSLHEAD		3
	{ "_tsl_head" },
#define NL_DEBUG		4
	{ "_natpt_debug" },
#define NL_DUMP			5
	{ "_natpt_dump" },
	{ NULL },
};


int		 readNL		__P((void *, int, int));
int		 openKvm	__P((void));
int		 readKvm	__P((void *, int, void *));
void		 closeKvm	__P((void));

void		 makeCSlotLine	__P((char *, int, struct cSlot *));
void		 makeTSlotLine	__P((char *, int, struct tSlot *,
				     struct tcpstate *, int));


/*
 *
 */

void
showPrefix()
{
	const char *fn = __FUNCTION__;

	struct in6_addr	prefix;
	char		in6txt[INET6_ADDRSTRLEN];

	if (readNL((void *)&prefix, sizeof(prefix), NL_PREFIX) <= 0)
		err(1, "%s(): failure on read prefix", fn);

	inet_ntop(AF_INET6, (char *)&prefix, in6txt, INET6_ADDRSTRLEN);
	printf("prefix: %s\n", in6txt);
}


void
showRules(int all)
{
	const char *fn = __FUNCTION__;

	int			 num = 0;
	struct cSlot		 csl;
	TAILQ_HEAD(,cSlot)	 csl_head;
	char			 Wow[BUFSIZ];

	if (readNL(&csl_head, sizeof(csl_head), NL_CSLHEAD) <= 0)
		err(1, "%s(): failure on read csl_head", fn);

	if ((csl_head.tqh_first == NULL)
	    && (csl_head.tqh_last == NULL))
		errx(0, "%s(): cSlot not initialized", fn);

	if (TAILQ_EMPTY(&csl_head))
		errx(0, "No Rules.\n");

	readKvm(&csl, sizeof(struct cSlot), TAILQ_FIRST(&csl_head));
	while (TRUE) {
		makeCSlotLine(Wow, sizeof(Wow), &csl);
		printf("%3d: %s\n", num, Wow);
		if (TAILQ_NEXT(&csl, csl_list) == NULL)
			break;
		readKvm(&csl, sizeof(struct cSlot), TAILQ_NEXT(&csl, csl_list));
		num++;
	}
}


void
showXlate(int type, int interval)
{
	const char *fn = __FUNCTION__;

	struct tSlot		tsl;
	struct tcpstate		ts;
	TAILQ_HEAD(,tSlot)	tsl_head;
	char			Wow[BUFSIZ];

	if (readNL(&tsl_head, sizeof(tsl_head), NL_TSLHEAD) <= 0)
		err(1, "%s(): line %d: failure on read tsl_head",
		    fn, __LINE__);

	if ((tsl_head.tqh_first == NULL)
	    && (tsl_head.tqh_last == NULL))
		errx(0, "%s(): cSlot does not initialized", fn);

	while (TRUE) {
		writeXlateHeader(type);
		if (!TAILQ_EMPTY(&tsl_head)) {
			readKvm(&tsl, sizeof(struct tSlot),
				TAILQ_FIRST(&tsl_head));
			while (TRUE) {
				if (tsl.suit.tcps){
					readKvm(&ts, sizeof(struct tcpstate),
						tsl.suit.tcps);
					makeTSlotLine(Wow, sizeof(Wow),
						      &tsl, &ts, type);
				} else {
					makeTSlotLine(Wow, sizeof(Wow),
						      &tsl, NULL, type);
				}

				printf("%s\n", Wow);
				if (TAILQ_NEXT(&tsl, tsl_list) == NULL)
					break;
				readKvm(&tsl, sizeof(struct tSlot),
					TAILQ_NEXT(&tsl, tsl_list));
			}
		}

		if (interval <= 0)
			break;

		sleep(interval);
		if (readNL(&tsl_head, sizeof(tsl_head), NL_TSLHEAD) <= 0)
			err(1, "%s(): line %d: failure on read tsl_head",
			    fn, __LINE__);
	}
}


void
writeXlateHeader(int type)
{
	if (type == SLONG) {
		;
	} else {
		printf("%-6s",	"Proto");
		printf("%-22s", "Local Address (src)");
		printf("%-22s", "Local Address (dst)");
		printf("%-22s", "Remote Address (src)");
		printf("%-22s", "Remote Address (dst)");
		printf("%6s",  "Ipkts");
		printf("%6s",  "Opkts");
		printf(" ");

		printf("%-8s",	"  Idle");
		printf("%-8s",	" (state)");
		printf("\n");
	}

}


void
showVariables()
{
	showVariable(NL_TR,    TYPE_INT);
	showVariable(NL_DEBUG, TYPE_INT);
	showVariable(NL_DUMP,  TYPE_INT);
}


void
showVariable(int n_idx, int type)
{
	int	val;

	switch (type) {
	case TYPE_INT:
		readNL(&val, sizeof(int), n_idx);
		printf("%16s: 0x%08x (%d)\n",
		       nl[n_idx].n_name, val, val);
		break;
	}
}


void
showMapping()
{
	const char *fn = __FUNCTION__;

	int	map;

	if (readNL((void *)&map, sizeof(map), NL_TR) <= 0)
		err(1, "%s(): failure on read mapping", fn);

	printf("mapping: %s\n", map ? "enable" : "disable");
}


/*
 *
 */

int
readNL(void *buf, int nbytes, int n_idx)
{
	if ((kd == NULL) && (openKvm() < 0))
		return (-1);

	return (readKvm(buf, nbytes, (void *)nl[n_idx].n_value));
}


int
openKvm()
{
	const char *fn = __FUNCTION__;

	int	rv;

	if ((kd = kvm_open(NULL, NULL, NULL, O_RDONLY, "kvm_open")) == NULL)
		err(errno, "%s(): open failure", fn);

	if ((rv = kvm_nlist(kd, nl)) < 0)
		err(errno, "%s(): read failure", fn);

	return (rv);
}


int
readKvm(void *buf, int nbytes, void *pos)
{
	const char *fn = __FUNCTION__;

	int	rv;

	if (nbytes <= 0)
		return (-1);

	if (kd <= (kvm_t *)0)
		return (-1);

	if ((rv = kvm_read(kd, (u_long)pos, buf, nbytes)) <= 0)
		err(errno, "%s(): read failure", fn);

	return (rv);
}


void
closeKvm()
{
	kvm_close(kd);
}


void
clean_show()
{
	if (kd != NULL)
		closeKvm();
}
