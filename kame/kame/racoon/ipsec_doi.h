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
/* YIPS @(#)$Id: ipsec_doi.h,v 1.9 2000/01/11 13:06:24 itojun Exp $ */

/* refered to RFC2407 */

#define IPSEC_DOI 1

/* 4.2 IPSEC Situation Definition */
#define IPSECDOI_SIT_IDENTITY_ONLY           0x00000001
#define IPSECDOI_SIT_SECRECY                 0x00000002
#define IPSECDOI_SIT_INTEGRITY               0x00000004

/* 4.4.1 IPSEC Security Protocol Identifiers */
  /* 4.4.2 IPSEC ISAKMP Transform Values */
#define IPSECDOI_PROTO_ISAKMP                        1
#define   IPSECDOI_KEY_IKE                             1

/* 4.4.1 IPSEC Security Protocol Identifiers */
#define IPSECDOI_PROTO_IPSEC_AH                      2
  /* 4.4.3 IPSEC AH Transform Values */
#define   IPSECDOI_AH_MD5                              2
#define   IPSECDOI_AH_SHA                              3
#define   IPSECDOI_AH_DES                              4

/* 4.4.1 IPSEC Security Protocol Identifiers */
#define IPSECDOI_PROTO_IPSEC_ESP                     3
  /* 4.4.4 IPSEC ESP Transform Identifiers */
#define   IPSECDOI_ESP_DES_IV64                        1
#define   IPSECDOI_ESP_DES                             2
#define   IPSECDOI_ESP_3DES                            3
#define   IPSECDOI_ESP_RC5                             4
#define   IPSECDOI_ESP_IDEA                            5
#define   IPSECDOI_ESP_CAST                            6
#define   IPSECDOI_ESP_BLOWFISH				7
#define   IPSECDOI_ESP_3IDEA                           8
#define   IPSECDOI_ESP_DES_IV32                        9
#define   IPSECDOI_ESP_RC4                            10
#define   IPSECDOI_ESP_NULL                           11

/* 4.4.1 IPSEC Security Protocol Identifiers */
#define IPSECDOI_PROTO_IPCOMP                        4
  /* 4.4.5 IPSEC IPCOMP Transform Identifiers */
#define   IPSECDOI_IPCOMP_OUI                          1
#define   IPSECDOI_IPCOMP_DEFLATE                      2
#define   IPSECDOI_IPCOMP_LZS                          3

/* 4.5 IPSEC Security Association Attributes */
#define IPSECDOI_ATTR_SA_LD_TYPE              1 /* B */
#define   IPSECDOI_ATTR_SA_LD_TYPE_DEFAULT      1
#define   IPSECDOI_ATTR_SA_LD_TYPE_SEC          1
#define   IPSECDOI_ATTR_SA_LD_TYPE_KB           2
#define   IPSECDOI_ATTR_SA_LD_TYPE_MAX          3
#define IPSECDOI_ATTR_SA_LD                   2 /* V */
#define   IPSECDOI_ATTR_SA_LD_SEC_DEFAULT      28800 /* 8 hours */
#define IPSECDOI_ATTR_GRP_DESC                3 /* B */
#define IPSECDOI_ATTR_ENC_MODE                4 /* B */
	/* default value: host dependent */
#define   IPSECDOI_ATTR_ENC_MODE_DEFAULT        2
#define   IPSECDOI_ATTR_ENC_MODE_TUNNEL         1
#define   IPSECDOI_ATTR_ENC_MODE_TRNS           2
#define IPSECDOI_ATTR_AUTH                    5 /* B */
#define   IPSECDOI_ATTR_AUTH_HMAC_MD5           1
#define   IPSECDOI_ATTR_AUTH_HMAC_SHA1          2
#define   IPSECDOI_ATTR_AUTH_DES_MAC            3
#define   IPSECDOI_ATTR_AUTH_KPDK               4 /*RFC-1826(Key/Pad/Data/Key)*/
	/*
	 * When negotiating ESP without authentication, the Auth
	 * Algorithm attribute MUST NOT be included in the proposal.
	 * When negotiating ESP without confidentiality, the Auth
	 * Algorithm attribute MUST be included in the proposal and
	 * the ESP transform ID must be ESP_NULL.
	*/
#define IPSECDOI_ATTR_KEY_LENGTH              6 /* B */
#define IPSECDOI_ATTR_KEY_ROUNDS              7 /* B */
#define IPSECDOI_ATTR_COMP_DICT_SIZE          8 /* B */
#define IPSECDOI_ATTR_COMP_PRIVALG            9 /* V */

/* 4.6.1 Security Association Payload */
struct ipsecdoi_pl_sa {
	struct isakmp_gen h;
	struct ipsecdoi_sa_b {
		u_int32_t doi; /* Domain of Interpretation */
		u_int32_t sit; /* Situation */
	} b;
	/* followed by Leveled Domain Identifier and so on. */
};

struct ipsecdoi_secrecy_h {
	u_int16_t len;
	u_int16_t reserved;
	/* followed by the value */
};

/* 4.6.2 Identification Payload Content */
struct ipsecdoi_pl_id {
	struct isakmp_gen h;
	struct ipsecdoi_id_b {
		u_int8_t type;		/* ID Type */
		u_int8_t proto_id;	/* Protocol ID */
		u_int16_t port;		/* Port */
	} b;
	/* followed by Identification Data */
};

#define IPSECDOI_ID_IPV4_ADDR                        1
#define IPSECDOI_ID_FQDN                             2
#define IPSECDOI_ID_USER_FQDN                        3
#define IPSECDOI_ID_IPV4_ADDR_SUBNET                 4
#define IPSECDOI_ID_IPV6_ADDR                        5
#define IPSECDOI_ID_IPV6_ADDR_SUBNET                 6
#define IPSECDOI_ID_IPV4_ADDR_RANGE                  7
#define IPSECDOI_ID_IPV6_ADDR_RANGE                  8
#define IPSECDOI_ID_DER_ASN1_DN                      9
#define IPSECDOI_ID_DER_ASN1_GN                      10
#define IPSECDOI_ID_KEY_ID                           11

/* The use for checking proposal payload. This is not exchange type. */
#define IPSECDOI_TYPE_PH1	0
#define IPSECDOI_TYPE_PH2	1

struct isakmpsa;
struct ipsecsa;
struct ipsecsakeys;
struct ipsecdoi_pl_sa;

extern int ipsecdoi_checkph1proposal __P((struct ipsecdoi_pl_sa *sa, struct ph1handle *iph1));
extern int ipsecdoi_checkph2proposal __P((struct ipsecdoi_pl_sa *sa, struct ph2handle *iph2));

extern int ipsecdoi_checkid1 __P((struct ph1handle *iph1));
extern int ipsecdoi_setid1 __P((struct ph1handle *iph1));
extern int ipsecdoi_setid2 __P((struct ph2handle *iph2));
extern int ipsecdoi_id2sockaddr __P((vchar_t *buf, struct sockaddr *saddr,
	u_int8_t *prefixlen, u_int16_t *ul_proto));

extern vchar_t *ipsecdoi_setph1proposal __P((struct isakmpsa *proposal));
extern vchar_t *ipsecdoi_setph2proposal __P((struct ipsecsa *proposal, struct ipsecsakeys *keys));
extern int ipsecdoi_get_defaultlifetime __P((void));
extern int ipsecdoi_checkalgtypes __P((int proto_id, int enc, int auth, int comp));
extern int ipproto2doi __P((int proto));

extern int ipsecdoi_fixsakeys __P((struct ph2handle *iph2));
extern int ipsecdoi_initsakeys __P((struct ph2handle *iph2));

extern void ipsecdoi_printsa __P((const struct ipsecsa *));

