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
/* YIPS @(#)$Id: cfparse.h,v 1.3 1999/08/13 15:19:24 sakane Exp $ */

#define YIPSD_CONF_FILE "/usr/local/etc/racoon.conf"
#define BUFSIZE    5120

struct isakmp_cf_t {
	u_int32_t len;
	u_int8_t t_no;
	u_int8_t t_id;
	vchar_t  *data;
	struct isakmp_cf_t *next;
};

struct isakmp_cf_p {
	u_int32_t len;
	u_int8_t p_no;
	u_int8_t proto_id;
	/* u_int8_t spi_size; */
	u_int8_t num_t;
	/* vchar_t *spi; */
	struct isakmp_cf_t *t;
	struct isakmp_cf_p *next;
};

struct isakmp_cf_sa {
	u_int32_t len;
	u_int32_t doi;
	u_int32_t sit;
	struct isakmp_cf_p *p;
};

struct isakmp_cf_phase {
	int etype;
	struct isakmp_cf_sa sa;	/* SA */
		/*
		 * XXX each parameters should not be encoded as SA payload,
		 * shouldn't they ?  because we can't check each parameters
		 */
	vchar_t *id_b;		/* ID body */
	vchar_t *pskey;		/* pre-shared key */
	u_int pfsgroup;		/* PFS group to be used. */
	const struct dh *pfsdh;
};

struct isakmp_conf {
	struct sockaddr *remote;	/* remote IP address, net byte order */
	struct isakmp_cf_phase *ph[2];	/* 0: isakmp, 1: ipsec */
	vchar_t *vendorid;		/* vendor ID */

	char *exec_path;		/* PATH for command execution */
	char *exec_command;		/* post-command */
	char *exec_success;		/* if success when execute command */
	char *exec_failure;		/* if failure when execute command */

	struct isakmp_conf *next;
};

#if defined(YIPS_DEBUG)
#  define DP(str) YIPSDEBUG(DEBUG_CONF, cfdebug_print(str, yytext, yyleng))
#  define YYD_ECHO \
    { YIPSDEBUG(DEBUG_CONF, printf("<%d>", yy_start); ECHO ; printf("\n");); }
#  define YIPSDP(cmd) YIPSDEBUG(DEBUG_CONF, cmd)
#  define PLOG printf
#else
#  define DP(str)
#  define YYD_ECHO
#  define YIPSDP(cmd)
#  define PLOG(cmd)
#endif /* defined(YIPS_DEBUG) */

/* cfparse.y */
extern char *racoon_conf;
extern struct isakmp_conf cftab;

extern void cf_init __P((void));
extern int re_cfparse __P((void));
extern int cf_post_config __P((void));
extern int yyparse __P((void));

/* cftoken.l */
extern void yyerror __P((char *, ...));
extern void yywarn __P((char *, ...));
extern int cfparse __P((void));
