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
/* YIPS @(#)$Id: strnames.c,v 1.6 2000/01/18 23:06:59 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>

#include <stdio.h>

#include "var.h"
#include "strnames.h"
#include "algorithm.h"

static char *num2str __P((int n));

static char *
num2str(n)
	int n;
{
	static char buf[20];

	snprintf(buf, sizeof(buf), "%d", n);

	return buf;
}

static char *name_ipsecdoi_proto[] = {
	"",
	"ISAKMP",
	"AH",
	"ESP",
	"IPCOMP",
};

char *
s_ipsecdoi_proto(proto)
	int proto;
{
	if (ARRAYLEN(name_ipsecdoi_proto) > proto)
		return name_ipsecdoi_proto[proto];
	return NULL;
}

static char *name_ipsecdoi_trns_isakmp[] = {
	"",
	"IKE",
};

static char *name_ipsecdoi_trns_ah[] = {
	"",
	"",
	"MD5",
	"SHA",
	"DES",
};

static char *name_ipsecdoi_trns_esp[] = {
	"",
	"DES_IV64",
	"DES",
	"3DES",
	"RC5",
	"IDEA",
	"CAST",
	"BLOWFISH",
	"3IDEA",
	"DES_IV32",
	"RC4",
	"NULL",
};

static char *name_ipsecdoi_trns_ipcomp[] = {
	"",
	"OUI",
	"DEFLATE",
	"3IDEA",
	"DES_IV32",
	"RC4",
	"NULL",
};

static char **name_ipsecdoi_trns[] = {
	0,
	name_ipsecdoi_trns_isakmp,
	name_ipsecdoi_trns_ah,
	name_ipsecdoi_trns_esp,
	name_ipsecdoi_trns_ipcomp,
};

char *
s_ipsecdoi_trns(proto, trns)
	int proto, trns;
{
	if (ARRAYLEN(name_ipsecdoi_trns) > proto)
		return name_ipsecdoi_trns[proto][trns];
	return NULL;
}

static char *name_oakley_attr[] = {
	"",
	"Encryption Algorithm",
	"Hash Algorithm",
	"Authentication Method",
	"Group Description",
	"Group Type",
	"Group Prime/Irreducible Polynomial",
	"Group Generator One",
	"Group Generator Two",
	"Group Curve A",
	"Group Curve B",
	"Life Type",
	"Life Duration",
	"PRF",
	"Key Length",
	"Field Size",
	"Group Order",
};

char *
s_oakley_attr(type)
	int type;
{
	if (ARRAYLEN(name_oakley_attr) > type)
		return name_oakley_attr[type];
	return NULL;
}

static char *name_attr_isakmp_enc[] = {
	"",
	"DES-CBC",
	"IDEA-CBC",
	"Blowfish-CBC",
	"RC5-R16-B64-CBC",
	"3DES-CBC",
	"CAST-CBC",
};

static char *name_attr_isakmp_hash[] = {
	"",
	"MD5",
	"SHA",
	"Tiger",
};

static char *name_attr_isakmp_method[] = {
	"",
	"pre-shared key",
	"DSS signatures",
	"RSA signatures",
	"Encryption with RSA",
	"Revised encryption with RSA",
};

static char *name_attr_isakmp_desc[] = {
	"",
	"768-bit MODP group",
	"1024-bit MODP group",
	"EC2N group on GP[2^155]",
	"EC2N group on GP[2^185]",
	"1536-bit MODP group",
};

static char *name_attr_isakmp_group[] = {
	"",
	"MODP",
	"ECP",
	"EC2N",
};

static char *name_attr_isakmp_ltype[] = {
	"",
	"seconds",
	"kilobytes"
};

static char **name_attr_isakmp_v[] = {
	0,
	name_attr_isakmp_enc,
	name_attr_isakmp_hash,
	name_attr_isakmp_method,
	name_attr_isakmp_desc,
	name_attr_isakmp_group,
	0,
	0,
	0,
	0,
	0,
	name_attr_isakmp_ltype,
	0,
	0,
	0,
	0,
	0,
};

char *
s_oakley_attr_v(type, val)
	int type, val;
{
	if (ARRAYLEN(name_attr_isakmp_v) > type
	 && name_attr_isakmp_v[type] != 0)
		return name_attr_isakmp_v[type][val];
	return NULL;
}

char *
s_oakley_attr_method(type)
	int type;
{
	if (ARRAYLEN(name_attr_isakmp_method) > type)
		return name_attr_isakmp_method[type];
	return NULL;
}

static char *name_attr_ipsec[] = {
	"",
	"SA Life Type",
	"SA Life Duration",
	"Group Description",
	"Encription Mode",
	"Authentication Algorithm",
	"Key Length",
	"Key Rounds",
	"Compression Dictionary Size",
	"Compression Private Algorithm"
};

char *
s_ipsecdoi_attr(type)
	int type;
{
	if (ARRAYLEN(name_attr_ipsec) > type)
		return name_attr_ipsec[type];
	return NULL;
}

static char *name_attr_ipsec_ltype[] = {
	"",
	"seconds",
	"kilobytes"
};

static char *name_attr_ipsec_enc_mode[] = {
	"",
	"Tunnel",
	"Transport"
};

char *
s_ipsecdoi_encmode(mode)
	int mode;
{
	if (ARRAYLEN(name_attr_ipsec_enc_mode) > mode)
		return name_attr_ipsec_enc_mode[mode];
	return "";
}

static char *name_attr_ipsec_auth[] = {
	"",
	"hmac-md5",
	"hmac-sha",
	"des-mac",
	"kpdk",
};

static char **name_attr_ipsec_v[] = {
	0,
	name_attr_ipsec_ltype,
	0,
	0,
	name_attr_ipsec_enc_mode,
	name_attr_ipsec_auth,
	0,
	0,
	0,
	0,
};

char *
s_ipsecdoi_attr_v(type, val)
	int type, val;
{
	if (ARRAYLEN(name_attr_ipsec_v) > type
	 && name_attr_ipsec_v[type] != 0)
		return name_attr_ipsec_v[type][val];
	return NULL;
}

static char *name_ipsec_level[] = {
	"",
	"use",
	"require",
	"unique"
};

char *
s_ipsec_level(level)
	int level;
{
	if (ARRAYLEN(name_ipsec_level) > level)
		return name_ipsec_level[level];
	return NULL;
}

static char *name_algclass[] = {
	"ipsec enc",
	"ipsec auth",
	"ipsec comp",
	"isakmp enc",
	"isakmp hash",
	"isakmp dh",
	"isakmp ameth",
};

char *
s_algclass(class)
	int class;
{
	if (ARRAYLEN(name_algclass) > class)
		return name_algclass[class];
	return NULL;
}

static char *name_algstrength[] = {
	"extra high",
	"high",
	"normal",
};

char *
s_algstrength(s)
	int s;
{
	if (ARRAYLEN(name_algstrength) > s)
		return name_algstrength[s];
	return NULL;
}

static char **name_algtype[] = {
	name_ipsecdoi_trns_esp,
	name_ipsecdoi_trns_ah,
	name_ipsecdoi_trns_ipcomp,
	name_attr_isakmp_enc,
	name_attr_isakmp_hash,
	name_attr_isakmp_desc,
	name_attr_isakmp_method,
};

char *
s_algtype(class, n)
	int class, n;
{
	if (ARRAYLEN(name_algtype) > class)
		return name_algtype[class][n];
	return NULL;
}

static char *name_ipsecdoi_ident[] = {
	"",
	"IPv4_address",
	"FQDN",
	"User_FQDN",
	"IPv4_subnet",
	"IPv6_address",
	"IPv6_subnet",
	"IPv4_address_range",
	"IPv6_address_range",
	"DER_ASN1_DN",
	"DER_ASN1_GN",
	"KEY_ID",
};

char *
s_ipsecdoi_ident(type)
	int type;
{
	if (ARRAYLEN(name_ipsecdoi_ident) > type)
		return name_ipsecdoi_ident[type];
	return NULL;
}

static char *name_isakmp_etype[] = {
	"None", "Base", "Identity Protection", "Authentication Only",
	"Aggressive", "Informational", "unknown","unknown",
	"unknown","unknown", "unknown","unknown",
	"unknown","unknown","unknown","unknown",
	"unknown","unknown","unknown","unknown",
	"unknown","unknown","unknown","unknown",
	"unknown","unknown","unknown","unknown",
	"unknown","unknown", "unknown","unknown",
	"Quick", "New Group",
};

char *
s_isakmp_etype(etype)
	u_int8_t etype;
{
	if (ARRAYLEN(name_isakmp_etype) > etype)
		return name_isakmp_etype[etype];

	return NULL;
} 

static char *name_pfkey_type[] = {
	"",
	"GETSPI",
	"UPDATE",
	"ADD",
	"DELETE",
	"GET",
	"ACQUIRE",
	"REGISTER",
	"EXPIRE",
	"FLUSH",
	"DUMP",
	"X_PROMISC",
	"X_PCHANGE",
	"X_SPDUPDATE",
	"X_SPDADD",
	"X_SPDDELETE",
	"X_SPDGET",
	"X_SPDACQUIRE",
	"X_SPDDUMP",
	"X_SPDFLUSH",
};

char *
s_pfkey_type(type)
	u_int8_t type;
{
	if (ARRAYLEN(name_pfkey_type) > type)
		return name_pfkey_type[type];

	return NULL;
}

static char *name_pfkey_satype[] = {
	"UNSPEC",
	"",
	"AH",
	"ESP",
	"",
	"RSVP",
	"OSPFV2",
	"RIPV2",
	"MIP",
	"IPCOMP",
};

char *
s_pfkey_satype(type)
	u_int8_t type;
{
	if (ARRAYLEN(name_pfkey_satype) > type)
		return name_pfkey_satype[type];

	return NULL;
}

static char *name_isakmp_notify_msg[] = {
	NULL,
	"INVALID-PAYLOAD-TYPE",
	"DOI-NOT-SUPPORTED",
	"SITUATION-NOT-SUPPORTED",
	"INVALID-COOKIE",
	"INVALID-MAJOR-VERSION",
	"INVALID-MINOR-VERSION",
	"INVALID-EXCHANGE-TYPE",
	"INVALID-FLAGS",
	"INVALID-MESSAGE-ID",
	"INVALID-PROTOCOL-ID",
	"INVALID-SPI",
	"INVALID-TRANSFORM-ID",
	"ATTRIBUTES-NOT-SUPPORTED",
	"NO-PROPOSAL-CHOSEN",
	"BAD-PROPOSAL-SYNTAX",
	"PAYLOAD-MALFORMED",
	"INVALID-KEY-INFORMATION",
	"INVALID-ID-INFORMATION",
	"INVALID-CERT-ENCODING",
	"INVALID-CERTIFICATE",
	"CERT-TYPE-UNSUPPORTED",
	"INVALID-CERT-AUTHORITY",
	"INVALID-HASH-INFORMATION",
	"AUTHENTICATION-FAILED",
	"INVALID-SIGNATURE",
	"ADDRESS-NOTIFICATION",
	"NOTIFY-SA-LIFETIME",
	"CERTIFICATE-UNAVAILABLE",
	"UNSUPPORTED-EXCHANGE-TYPE",
	"UNEQUAL-PAYLOAD-LENGTHS",
	NULL
};

char *
s_isakmp_notify_msg(type)
	u_int8_t type;
{
	if (ARRAYLEN(name_isakmp_notify_msg) > type)
		return name_isakmp_notify_msg[type];

	return num2str(type);
}

static char *name_isakmp_nptype[] = {
	"none", "sa", "p", "t", "ke", "id", "cert", "cr", "hash",
	"sig", "nonce", "notify", "delete", "vid"
};

char *
s_isakmp_nptype(type)
	u_int8_t type;
{
	if (ARRAYLEN(name_isakmp_nptype) > type)
		return name_isakmp_nptype[type];

	return num2str(type);
}

