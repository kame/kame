/*	$KAME: show.c,v 1.40 2002/12/18 10:27:52 fujisawa Exp $	*/

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
#include <sys/queue.h>
#include <sys/socket.h>

#include <errno.h>
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

#include <netinet/tcp_fsm.h>

#include <arpa/inet.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_soctl.h>

#include "defs.h"
#include "miscvar.h"
#include "showvar.h"
#include "cfparse.h"


/*
 *
 */

#define	TYPE_INT		1


kvm_t		*kd;


int		 readTQH	__P((void *, int, int, int));
int		 openKvm	__P((void));
int		 readKvm	__P((void *, int, void *));
void		 closeKvm	__P((void));

void		 makeCSlotLine	__P((char *, int, struct cSlot *));
void		 makeCUILine	__P((char *, int, struct cSlot *));
void		 makeTSlotLine	__P((char *, int, struct tSlot *,
				     struct tcpstate *, int));
void		 showVariableSubsid __P((int, int));

/* in misc.c */
int		 readSessions		__P((struct sessions *));


/*
 *
 */

void
showFragment()
{
	const char *fn = __FUNCTION__;

	int	fragment;

	if (getValue(NATPTCTL_FORCEFRAGMENT4, (caddr_t)&fragment) <= 0)
		err(1, "%s(): failure on read fragment", fn);

	printf("fragment: %d\n", fragment);
}


void
showRules(int cui)
{
	const char *fn = __FUNCTION__;

	struct cSlot		 csl;
	TAILQ_HEAD(,cSlot)	 csl_head;
	char			 Wow[BUFSIZ];

	if (readTQH(&csl_head, sizeof(csl_head), NATPTCTL_CSLHEAD, 0) <= 0)
		err(1, "%s(): failure on read csl_head", fn);

	if ((csl_head.tqh_first == NULL)
	    && (csl_head.tqh_last == NULL))
		errx(0, "%s(): cSlot not initialized", fn);

	if (TAILQ_EMPTY(&csl_head))
		errx(0, "No Rules.");

	readKvm(&csl, sizeof(struct cSlot), TAILQ_FIRST(&csl_head));
	while (TRUE) {
		if (cui)
			makeCUILine(Wow, sizeof(Wow), &csl);
		else
			makeCSlotLine(Wow, sizeof(Wow), &csl);
		printf("%5d: %s\n", csl.rnum, Wow);
		if (TAILQ_NEXT(&csl, csl_list) == NULL)
			break;
		readKvm(&csl, sizeof(struct cSlot), TAILQ_NEXT(&csl, csl_list));
	}
}


void
showSessions(int protos)
{
	struct sessions	 sess;
	char		*heading;

	if (readSessions(&sess) == 0)
		return ;

	heading = NULL;
	if ((protos == 0) || (protos & PROTO_TCP)) {
		heading = "proto:    count    close    estab      fin      syn";
	}

	if (heading) {
		printf("%s\n", heading);
	}

	if ((protos == 0) || (protos & PROTO_TCP)) {
		printf("%5s:", "tcp");
		printf("%9d", sess.tcp);
		printf("%9d", sess.tcps[TCPS_CLOSED]);
		printf("%9d", sess.tcps[TCPS_ESTABLISHED]);
		printf("%9d", sess.tcps[TCPS_FIN_WAIT_1]+sess.tcps[TCPS_FIN_WAIT_2]);
		printf("%9d", sess.tcps[TCPS_SYN_SENT]);
		printf("\n");
	}

	if ((protos == 0) || (protos & PROTO_UDP)) {
		printf("%5s:%9d\n", "udp", sess.udp);
	}

	if ((protos == 0) || (protos & PROTO_ICMP)) {
		printf("%5s:%9d\n", "icmp", sess.icmp);
	}

	if (protos == 0) {
		printf("%5s:%9d\n", "misc", sess.others);
	}
}


void
showXlate(int type, int copy, int interval)
{
	const char *fn = __FUNCTION__;

	struct tSlot		tsl;
	struct tcpstate		ts;
	TAILQ_HEAD(,tSlot)	tsl_head;
	char			Wow[BUFSIZ];

	if (readTQH(&tsl_head, sizeof(tsl_head), NATPTCTL_TSLHEAD, copy) <= 0)
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
				if ((tsl.ip_p == IPPROTO_TCP)
				    && (tsl.suit.tcps)) {
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

		if (copy)
			releaseTQH();

		if (interval <= 0)
			break;

		sleep(interval);
		if (readTQH(&tsl_head, sizeof(tsl_head), NATPTCTL_TSLHEAD, copy) <= 0)
			err(1, "%s(): line %d: failure on read tsl_head",
			    fn, __LINE__);
	}
}


void
writeXlateHeader(int type)
{
	/* 22 means strlen("255.255.255.255.65535 ") */
	/* 46 means strlen("0123:4567:89ab:cdef:0123:4567:89ab:cdef.65535 ") */

	switch (type) {
	case XLATE_TRACE:
		printf("%-6s",	"Proto");
		printf("%-22s", "Local Address (src)");
		printf("%-22s", "Remote Address (dst)");
		printf("%6s",  "Ipkts");
		printf("%6s",  "Opkts");
		printf(" ");

		printf("%-8s",	"  Idle");
		printf("%-8s",	" (state)");
		break;

	case XLATE_SHORT:
		printf("%-6s",	"Proto");
		printf("%-22s", "Local Address (src)");
		printf("%-22s", "Remote Address (src)");
		printf("%6s",  "Ipkts");
		printf("%6s",  "Opkts");
		printf(" ");

		printf("%-8s",	"  Idle");
		printf("%-8s",	" (state)");
		break;

	case XLATE_REGULAR:
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
		break;

	case XLATE_LONG:
		printf("%-6s",	"Proto");
		printf("%-46s", "Local Address (src)");
		printf("%-46s", "Local Address (dst)");
		printf("%-46s", "Remote Address (src)");
		printf("%-46s", "Remote Address (dst)");
		printf("%6s",  "Ipkts");
		printf("%6s",  "Opkts");
		printf(" ");

		printf("%-8s",	"  Idle");
		printf("%-8s",	" (state)");
		break;
	}

	printf("\n");
}


void
showTimer()
{
	const char *fn = __FUNCTION__;

	int	timer;

	if (getValue(NATPTCTL_TSLOTTIMER, (caddr_t)&timer) <= 0)
		err(1, "%s(): failure on read", fn);

	printf("timer: tslot=%d\n", timer);
}


void
showTTLs()
{
	const char *fn = __FUNCTION__;

	int	icmp, tcp, udp;

	if (getValue(NATPTCTL_MAXTTYICMP, (caddr_t)&icmp) <= 0)
		err(1, "%s(): failure on read", fn);
	if (getValue(NATPTCTL_MAXTTYTCP, (caddr_t)&tcp) <= 0)
		err(1, "%s(): failure on read", fn);
	if (getValue(NATPTCTL_MAXTTYUDP, (caddr_t)&udp) <= 0)
		err(1, "%s(): failure on read", fn);

	printf("maxTTLs: icmp=%d, tcp=%d, udp=%d\n", icmp, tcp, udp);
}


void
showVariable(int ctlName)
{
	const char *fn = __FUNCTION__;

	int	val;
	char	in6txt[INET6_ADDRSTRLEN];
	struct in6_addr	prefix;
	struct natptctl_names ctlnames[] = NATPTCTL_NAMES;

	switch (ctlnames[ctlName].ctl_type) {
	case NATPTCTL_IN6ADDR:
		if (getValue(ctlName, (caddr_t)&prefix) <= 0)
			err(1, "%s(): failure on read prefix", fn);

		inet_ntop(AF_INET6, (char *)&prefix, in6txt, INET6_ADDRSTRLEN);
		printf("%s: %s\n", ctlnames[ctlName].ctl_name, in6txt);
		break;

	default:
		if (getValue(ctlName, (caddr_t)&val) <= 0)
			err(1, "%s(): failure on read", fn);

		if (ctlName == NATPTCTL_ENABLE)
			printf("mapping: %s\n", val ? "enable" : "disable");
		else
			printf("%s: %d\n", ctlnames[ctlName].ctl_name, val);

		break;
	}
}


int
showVariables(char *word)
{
	int			 type;
	int			 idx;
	struct natptctl_names	 ctlnames[] = NATPTCTL_NAMES;

	type = 0;
	if (word != NULL) {
		if (*word == '?') {
			printf("	show variables\n");
			printf("	show variables all\n");
			printf("	show variables tslot\n");
			return (0);
		}
		else if (strncasecmp(word, "all", strlen("all")) == 0)
			type = NATPTCTL_ALL;
		else if (strncasecmp(word, "tslot", strlen("tslot")) == 0)
			type = NATPTCTL_TSLOT;
		else if (strncasecmp(word, "caddr", strlen("caddr")) == 0)
			type = NATPTCTL_CADDR;
		else {
			char	*name;

			for (idx = 0; ctlnames[idx].ctl_name; idx++) {
				name = ctlnames[idx].ctl_name;
				if (strncasecmp(word, name, strlen(name)) == 0) {
					showVariableSubsid(idx, NATPTCTL_ALL);
					return (0);
				}
			}
		}
	}

	for (idx = 0; ctlnames[idx].ctl_name; idx++) {
		showVariableSubsid(idx, type);
	}

	return (0);
}


void
showVariableSubsid(int idx, int type)
{
	const char *fn = __FUNCTION__;

	int			 val;
	char			 Bow[128];
	char			 Wow[INET6_ADDRSTRLEN];
	struct natptctl_names	 ctlnames[] = NATPTCTL_NAMES;

	if (type == NATPTCTL_ALL)
		;
	else if (type == NATPTCTL_TSLOT) {
		if ((ctlnames[idx].ctl_attr & NATPTCTL_TSLOT) == 0)
			return;
	}
	else if (type == NATPTCTL_CADDR) {
		if ((ctlnames[idx].ctl_attr & NATPTCTL_CADDR) == 0)
			return;
	}
	else if ((ctlnames[idx].ctl_attr & NATPTCTL_DEFAULT) == 0)
		return;

	if (getValue(idx, (caddr_t)&Bow) <= 0) {
		err(errno, "%s(): getvalue failure", fn);
	}

	printf("%16s: ", ctlnames[idx].ctl_name);

	switch (ctlnames[idx].ctl_type) {
	case NATPTCTL_INT:
		val = *(int *)&Bow;
		printf("0x%08x (%d)", val, val);
		break;

	case NATPTCTL_IN6ADDR:
		inet_ntop(AF_INET6, &Bow, Wow, sizeof(Wow));
		printf("%s", Wow);
		break;

	case NATPTCTL_CADDR_T:
		printf("%p", *(caddr_t *)&Bow);
		break;
	}

	printf("\n");
}


/*
 *
 */

int
readTQH(void *buf, int nbytes, int n_idx, int copy)
{
	const char *fn = __FUNCTION__;

	caddr_t	addr;

	if ((kd == NULL) && (openKvm() < 0))
		return (-1);

	switch (n_idx) {
	case NATPTCTL_CSLHEAD:
		if (getValue(n_idx, (caddr_t)&addr) <= 0)
			err(errno, "%s(): getvalue failure", fn);
		break;

	case NATPTCTL_TSLHEAD:
		if (copy)
			addr = prepareTQH(NATPT_duplicateXLate);
		else
			addr = prepareTQH(NATPT_originalXLate);

		if (addr == NULL)
			return (0);
		break;

	default:
		err(0, "%s(): invalid n_idx: %d\n", fn, n_idx);
		break;
	}

	return (readKvm(buf, nbytes, addr));
}


int
openKvm()
{
	const char *fn = __FUNCTION__;

	if ((kd = kvm_open(NULL, NULL, NULL, O_RDONLY, "kvm_open")) == NULL)
		err(errno, "%s(): open failure", fn);

	return (1);
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
