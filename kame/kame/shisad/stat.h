/*      $KAME: stat.h,v 1.2 2005/01/12 03:23:33 t-momose Exp $  */
/*
 * Copyright (C) 2004 WIDE Project.  All rights reserved.
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

struct mip6stat {
        u_quad_t mip6s_mobility;        /* Mobility Header received */
        u_quad_t mip6s_omobility;       /* Mobility Header sent */
        u_quad_t mip6s_hoti;            /* HoTI received */
        u_quad_t mip6s_ohoti;           /* HoTI sent */
        u_quad_t mip6s_coti;            /* CoTI received */
        u_quad_t mip6s_ocoti;           /* CoTI sent */
        u_quad_t mip6s_hot;             /* HoT received */
        u_quad_t mip6s_ohot;            /* HoT sent */
        u_quad_t mip6s_cot;             /* CoT received */
        u_quad_t mip6s_ocot;            /* CoT sent */
        u_quad_t mip6s_bu;              /* BU received */
        u_quad_t mip6s_obu;             /* BU sent */
        u_quad_t mip6s_ba;              /* BA received */
        u_quad_t mip6s_ba_hist[256];    /* BA status input histgram */
        u_quad_t mip6s_oba;             /* BA sent */
        u_quad_t mip6s_oba_hist[256];   /* BA status output histgram */
        u_quad_t mip6s_br;              /* BR received */
        u_quad_t mip6s_obr;             /* BR sent */
        u_quad_t mip6s_be;              /* BE received */
        u_quad_t mip6s_be_hist[256];    /* BE status input histogram */
        u_quad_t mip6s_obe;             /* BE sent */
        u_quad_t mip6s_obe_hist[256];   /* BE status output histogram */
	u_quad_t mip6s_dhreq;		/* DHAAD request received */
	u_quad_t mip6s_odhreq;		/* DHAAD request sent */
	u_quad_t mip6s_dhreply;		/* DHAAD reply received */
	u_quad_t mip6s_odhreply;	/* DHAAD reply sent */
	u_quad_t mip6s_mps;		/* MPS received */
	u_quad_t mip6s_omps;		/* MPS sent */
	u_quad_t mip6s_mpa;		/* MPA received */
	u_quad_t mip6s_ompa;		/* MPA sent */
        u_quad_t mip6s_hao;             /* HAO received */
        u_quad_t mip6s_unverifiedhao;   /* unverified HAO received */
        u_quad_t mip6s_ohao;            /* HAO sent */
        u_quad_t mip6s_rthdr2;          /* RTHDR2 received */
        u_quad_t mip6s_orthdr2;         /* RTHDR2 sent */
        u_quad_t mip6s_revtunnel;       /* reverse tunnel input */
        u_quad_t mip6s_orevtunnel;      /* reverse tunnel output */
        u_quad_t mip6s_checksum;        /* bad checksum */
        u_quad_t mip6s_payloadproto;    /* payload proto != no nxt header */
        u_quad_t mip6s_unknowntype;     /* unknown MH type value */
        u_quad_t mip6s_nohif;           /* not my home address */
        u_quad_t mip6s_nobue;           /* no related BUE */
        u_quad_t mip6s_hinitcookie;     /* home init cookie mismatch */
        u_quad_t mip6s_cinitcookie;     /* careof init cookie mismatch */
        u_quad_t mip6s_unprotected;     /* not IPseced signaling */
        u_quad_t mip6s_haopolicy;       /* BU is discarded due to bad HAO */
        u_quad_t mip6s_rrauthfail;      /* RR authentication failed */
        u_quad_t mip6s_seqno;           /* seqno mismatch */
        u_quad_t mip6s_paramprobhao;    /* ICMP paramprob for HAO received */
        u_quad_t mip6s_paramprobmh;     /* ICMP paramprob for MH received */
        u_quad_t mip6s_invalidcoa;      /* Invalid Care-of address */
        u_quad_t mip6s_invalidopt;      /* Invalid mobility options */
        u_quad_t mip6s_circularrefered; /* Circular reference */
        u_quad_t mip6s_mhtoosmall;      /* MH too small */
};

extern struct mip6stat mip6stat;
