/*	$KAME: pdelegate.h,v 1.4 2001/03/05 12:41:30 itojun Exp $	*/

/*
 * Copyright (C) 2001 WIDE Project.
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
 * draft-haberman-ipngwg-auto-prefix-00.txt (with a change on ipngwg)
 */

#define ICMP6_PREFIX_REQUEST		150	/*XXX local agreement*/
#define ICMP6_PR_DELEGATOR_QUERY	0
#define ICMP6_PR_INITIAL_REQUEST	1
#define ICMP6_PR_RENEWAL_REQUEST	2
#define ICMP6_PR_PREFIX_RETURN		3

#define ICMP6_PREFIX_DELEGATION		151	/*XXX local agreement*/
#define ICMP6_PD_PREFIX_DELEGATOR	0
#define ICMP6_PD_AUTH_REQUIRED		1
#define ICMP6_PD_AUTH_FAILED		2
#define ICMP6_PD_PREFIX_UNAVAIL		3
#define ICMP6_PD_PREFIX_DELEGATED	4
#define ICMP6_PD_PREFIX_RETURNED	5

#define ICMP6_PD_QUERY_INTERVAL		5 /* seconds */
#define ICMP6_PD_QUERY_RETRY_MAX	3 /* times */
#define ICMP6_PD_INITIAL_INTERVAL	5 /* seconds */
#define ICMP6_PD_INITIAL_RETRY_MAX	3 /* times */

#define ALLDELEGATORS		"ff02::20"	/*XXX local agreement*/

/* 5.1 Prefix Request */
struct icmp6_prefix_request {
	struct icmp6_hdr icmp6_pr_hdr;
	struct in6_addr	icmp6_pr_prefix;
};
#define icmp6_pr_flaglen	icmp6_data8[0]
#define ICMP6_PR_FLAGS_SCOPE	0x80
#define ICMP6_PR_LEN_MASK	0x7f
#define icmp6_pr_rtcap	icmp6_data16[1]

/* 5.2 Prefix Delegation */
struct icmp6_prefix_delegation {
	struct icmp6_hdr icmp6_pd_hdr;
	struct in6_addr	icmp6_pd_prefix;
	u_int16_t icmp6_pd_rtlen;
	/* variable-length routing information follows */
};
#define icmp6_pd_flaglen	icmp6_data8[0]
#define ICMP6_PD_FLAGS_SCOPE	0x80
#define ICMP6_PD_LEN_MASK	0x7f
#define icmp6_pd_lifetime	icmp6_data16[1]
#define icmp6_pd_rtproto	icmp6_data3[1]
