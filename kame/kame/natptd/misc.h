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
 *
 *	$Id: misc.h,v 1.1 2000/01/07 15:08:35 fujisawa Exp $
 */

static char *ns_ops[] =
{
    "",
    " inv_q",
    " stat",
    " op3",
    " notify",
    " op5",
    " op6",
    " op7",
    " op8",
    " updataA",
    " updateD",
    " updateDA",
    " updateM",
    " updateMA",
    " zoneInit",
    " zoneRef",
};


static char *ns_resp[] =
{
    "",
    " FormErr",
    " ServFail",
    " NXDomain",
    " NotImp",
    " Refused",
    " Resp6",
    " Resp7",
    " Resp8",
    " Resp9",
    " Resp10",
    " Resp11",
    " Resp12",
    " Resp13",
    " Resp14",
    " NoChange",
};


struct tok
{
    int		 val;
    char	*str;
};


static struct tok Qtype2str[] =
{
    { T_A,	"A" },
    { T_NS,	"NS" },
    { T_MD,	"MD" },
    { T_MF,	"MF" },
    { T_CNAME,	"CNAME" },
    { T_SOA,	"SOA" },
    { T_MB,	"MB" },
    { T_MG,	"MG" },
    { T_MR,	"MR" },
    { T_NULL,	"NULL" },
    { T_WKS,	"WKS" },
    { T_PTR,	"PTR" },
    { T_HINFO,	"HINFO" },
    { T_MINFO,	"MINFO" },
    { T_MX,	"MX" },
    { T_TXT,	"TXT" },
    { T_RP,	"RP" },
    { T_AFSDB,	"AFSDB" },
    { T_X25,	"X25" },
    { T_ISDN,	"ISDN" },
    { T_RT,	"RT" },
    { T_NSAP,	"NSAP" },
    { T_NSAP_PTR, "NSAP_PTR" },
    { T_SIG,	"SIG" },
    { T_KEY,	"KEY" },
    { T_PX,	"PX" },
    { T_GPOS,	"GPOS" },
    { T_AAAA,	"AAAA" },
    { T_LOC,	"LOC " },
    { T_NXT,	"NXT " },
    { T_EID,	"EID " },
    { T_NIMLOC,	"NIMLOC " },
    { T_SRV,	"SRV " },
    { T_ATMA,	"ATMA " },
    { T_NAPTR,	"NAPTR " },
#ifndef	T_A6
#define	T_A6	38			/* IP6 address (ipngwg-dns-lookups) */
#endif
    { T_A6,	"A6 " },
#ifndef T_UINFO
#define T_UINFO 100
#endif
    { T_UINFO,	"UINFO" },
#ifndef T_UID
#define T_UID 101
#endif
    { T_UID,	"UID" },
#ifndef T_GID
#define T_GID 102
#endif
    { T_GID,	"GID" },
#ifndef T_UNSPEC
#define T_UNSPEC	103		/* Unspecified format (binary data) */
    { T_UNSPEC,	"UNSPEC" },
#endif
#ifndef	T_UNSPECA
#define	T_UNSPECA	104		/* "unspecified ascii". Ugly MIT hack */
#endif
    { T_UNSPECA,"UNSPECA" },
    { T_AXFR,	"AXFR" },
    { T_MAILB,	"MAILB" },
    { T_MAILA,	"MAILA" },
    { T_ANY,	"ANY" },
    { 0,	 NULL }
};
