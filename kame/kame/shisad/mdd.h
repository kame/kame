/*      $KAME: mdd.h,v 1.3 2005/10/11 15:24:23 mitsuya Exp $  */
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

#define	BUFSIZE			8196
#define	PA_BUFSIZE		(sizeof "0000:0000:0000:0000:0000:0000:0000:0000%123456789abcdef")
#define	DEFAULT_PREFIXLEN	64

extern struct npih     npi_head;

struct binding {
	LIST_ENTRY(binding)	binding_entries;
	u_int flags;
#define		BF_INUSE	0x00000001
#define		BF_BOUND	0x00000002
#define		BF_HOME		0x00000004
	struct sockaddr_in6	hoa;
	int			hoa_prefixlen;
	struct sockaddr_in6	coa;
	int			coaifindex;
	struct sockaddr_in6	pcoa;
	int			pcoaifindex;
#ifdef MIP_MCOA
	u_int16_t 		bid;
#endif /* MIP_MCOA */
};

struct cif {
	LIST_ENTRY(cif)		cif_entries;
	char *			cif_name;
	int                     cif_linkstatus;
	int			preference;
};

struct coac {
	LIST_ENTRY(coac)	coac_entries;
	struct sockaddr_in6	coa;
	int			preference;
};

LIST_HEAD(bl, binding);
LIST_HEAD(cifl, cif);
LIST_HEAD(coacl, coac);

void usage(void);
struct binding *set_hoa(struct in6_addr *, int);
struct binding *set_hoa_str(char *);
void get_hoalist(void);
int _get_hoalist(void);
void set_coaif(char *, int);
void get_coaiflist(void);
void get_coacandidate(void);
void set_coa(void);
void print_bl(FILE *);
void print_coaiflist(FILE *);
void mainloop(void);
void sync_binding(void);
int get_addr_with_ifl(struct coacl *, struct cifl *);
int get_preference_in_ifl(int, struct cifl *);
int in6_addrscope(struct in6_addr *);
int chbinding(struct sockaddr_in6 *, struct sockaddr_in6 *, u_int16_t);
int returntohome(struct sockaddr_in6 *, struct sockaddr_in6 *, int);
int get_ifl(struct cifl *);
int del_if_from_ifl(struct cifl *, int);
int in6_addr2ifindex(struct in6_addr *);
void recv_home_hint(int, struct sockaddr_in6 *, int);
int in6_is_one_of_hoa(struct ifa_msghdr *, struct bl *);
int in6_is_on_homenetwork(struct ifa_msghdr *, struct bl *);
int in6_matchlen(struct in6_addr *, struct in6_addr *);

int probe_ifstatus(int);
extern int sock_dg6;


