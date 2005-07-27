/*	$KAME: mld6_var.h,v 1.19 2005/07/27 11:00:01 suz Exp $	*/

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

#ifndef _NETINET6_MLD6_VAR_H_
#define _NETINET6_MLD6_VAR_H_

#ifdef _KERNEL

#define MLD_RANDOM_DELAY(X) (arc4random() % (X) + 1)

/*
 * States for MLD stop-listening processing
 */
#define MLD_OTHERLISTENER			0
#define MLD_IREPORTEDLAST			1
#define MLD_REPORTPENDING			2 /* implementation specific */

/*
 * States for the MLDv2's state table.
 */
#define	MLD_QUERY_PENDING_MEMBER	2	/* pending General Query */
#define	MLD_G_QUERY_PENDING_MEMBER	3	/* pending Grp-specific Query */
#define	MLD_SG_QUERY_PENDING_MEMBER	4	/* pending Grp-Src-specific Q.*/

/*
 * We must remember what version the subnet's querier is.
 * We conveniently use the MLD message type for the proper
 * membership report to keep this state.
 */
#define MLD_V1_ROUTER				MLD_LISTENER_REPORT
#define MLD_V2_ROUTER				MLDV2_LISTENER_REPORT

/*
 * MLDv2 default variables
 */
#define MLD_TIMER_SCALE		1000
#define	MLD_DEF_RV		2	/* Default Robustness Variable */
#define	MLD_DEF_QI		125	/* Query Interval (125 sec.) */
#define	MLD_DEF_QRI		10000	/* Query Response Interval (10 sec.) */
#define	MLD_OQPT ((MLD_DEF_RV * MLD_DEF_QI) + MLD_DEF_QRI/MLD_TIMER_SCALE/2)
		/* Other Querier Present Timer */
#define	MLD_MALI ((MLD_DEF_RV * MLD_DEF_QI) + MLD_DEF_QRI/MLD_TIMER_SCALE)
		/* Multicast Address Listener Interval */
#define	MLD_START_INTVL		MLD_DEF_QI/4
#define	MLD_START_CNT		MLD_DEF_RV
#define	MLD_LAST_INTVL		1000	/* Last Member Query Interval (1 sec) */
#define	MLD_LAST_CNT		MLD_DEF_RV
#define MLD_UNSOL_INTVL         10      /* Unsolicited Report Interval (sec) */
#define	MLDV2_UNSOL_INTVL	1	/* Unsolicited Report Interval (sec) */
#define	MLD_DEF_QUERY		10	/* v1 Max. Response Time (sec.) */

extern int mld_debug;

#define mldlog(x)	do { if (mld_debug) log x; } while (/*CONSTCOND*/ 0)

void	mld_init(void);
void	mld_input(struct mbuf *, int);
#if defined(MLDV2) && !defined(__FreeBSD__)
int	mld_sysctl(int *, u_int, void *, size_t *, void *, size_t);
#endif

#ifdef MLDV2
int	in6_is_mld_target(struct in6_addr *);
#endif
#endif /* _KERNEL */

#endif /* _NETINET6_MLD6_VAR_H_ */
