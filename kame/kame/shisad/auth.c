/*	$KAME: auth.c,v 1.1 2006/06/09 11:29:58 t-momose Exp $	*/

/*
 * Copyright (C) 2006 WIDE Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>

#include "callout.h"
#include "fdlist.h"
#include "shisad.h"

LIST_HEAD(haauth_users_head, haauth_users) haauth_users_head = LIST_HEAD_INITIALIZER(haauth_users_head);

static int ha_auth(struct in6_addr *, struct in6_addr *,
		   struct ip6_mh_opt_authentication *, struct ip6_mh *,
		   mip6_authenticator_t *);
void aaa_auth_start(void);
int aaa_auth_done(int);
static void ha_auth_init();
static void aaa_auth_init();

char *auth_database = "/usr/local/v6/etc/authdata";

void
auth_init()
{
	ha_auth_init();
	aaa_auth_init();
}


/*
  return value:
  status codes of BA
*/
int
auth_opt(hoa, coa, mh, mopt, authmethod, authmethod_done)
	struct in6_addr *hoa, *coa;
	struct ip6_mh *mh;
	struct mip6_mobility_options *mopt;
	int *authmethod, *authmethod_done;
{
	int i, statuscode = IP6_MH_BAS_ACCEPTED;
	struct ip6_mh_opt_authentication *mopt_auth;
	mip6_authenticator_t authenticator;

	for (i = 0; i < 2; i++) {
		if ((mopt_auth = mopt->opt_authentication[i]) == NULL)
			continue;
		
		switch (mopt_auth->ip6moauth_subtype) {
			
		case IP6_MH_AUTHOPT_SUBTYPE_MNHA:
			/* To authorize:
			   pick parameters
			   calculate authenticate
			*/
			*authmethod |= BC_AUTH_MNHA;
			if (ha_auth(hoa, coa, mopt_auth, mh, &authenticator) ==  0 &&
			    memcmp((caddr_t)&authenticator, (caddr_t)(mopt_auth + 1), MIP6_AUTHENTICATOR_SIZE) == 0)
				statuscode = IP6_MH_BAS_ACCEPTED;
			else
				statuscode = IP6_MH_BAS_AUTH_FAIL;
			*authmethod_done |= BC_AUTH_MNHA;
			break;
			
		case IP6_MH_AUTHOPT_SUBTYPE_MNAAA:
			/* To authorize: send a query to an AAA later.
			   This is an asynchoronous process because an
			   AAA server is usually another entity.
			*/
			/* Make a query here */
			aaa_auth_start();
			*authmethod |= BC_AUTH_MNAAA;
			break;
			
		default:
			syslog(LOG_ERR, "Unknown subtype in mobiliy message authentication");
			break;
		}
	}

	return (statuscode);
}

/*
  Ret. val. 0: authenticator was retrieved,  non-zero: error has been occured

*/
static int
ha_auth(hoa, coa, mopt_auth, mh, authenticator)
	struct in6_addr *hoa, *coa;
	struct ip6_mh_opt_authentication *mopt_auth;
	struct ip6_mh *mh;
	mip6_authenticator_t *authenticator;
{
	u_int16_t cksum;
	struct haauth_users *hausers;

	hausers = find_haauth_users(ntohl(mopt_auth->ip6moauth_mobility_spi));
	if (hausers == NULL)
		return (-1);

	cksum = mh->ip6mh_cksum;
	mh->ip6mh_cksum = 0;
	mip6_calculate_authenticator((mip6_kbm_t *)hausers->sharedkey, hoa, coa,
				     (caddr_t)mh, (mh->ip6mh_len + 1) << 3,
				     (caddr_t)(mopt_auth + 1) - (caddr_t)mh,
				     MIP6_AUTHENTICATOR_SIZE, authenticator);
	mh->ip6mh_cksum = cksum;

	return (0);
}

struct haauth_users *
find_haauth_users(spi)
	u_int32_t spi;
{
	struct haauth_users *hausers;

	LIST_FOREACH(hausers, &haauth_users_head, hauthusers_entry) {
		if (hausers->mobility_spi == spi)
			return (hausers);
	}

	return (NULL);
}

/*
  Read and construct MN-HA authenticator database

  The format of authentication Database is described as followed:
---  
# the line started '#' shows comment.
# one data is described in one line. spi followed by shared key separated by space
10000		'shared-key in 20byte'  # byte's' is trimmed 
10001           0x0102030405060708090a0b0c0d0e0f10111213
---  
 */
static void
ha_auth_init()
{
	char *p, *spip, *sharedkeyp, *last;
	char read_buffer[1024];
	FILE *keytable;
	struct haauth_users *hausers;

	if ((keytable = fopen(auth_database, "r")) == NULL) {
		syslog(LOG_ERR, "Opening authentication database was failed (%s)", auth_database);
		return;
	}
	
	while (fgets(read_buffer, sizeof(read_buffer), keytable) != NULL) {
		if ((p = strchr(read_buffer, '\n')) == NULL)
			continue; /* the line was too long */
		*p = '\0';

		p = read_buffer;
		while (isspace(*p))
			p++;
		if (*p == '#')
			continue;	/* comment line */

		if ((spip = strtok_r(p, " \t", &last)) == NULL)
			continue;

		hausers = malloc(sizeof(*hausers));
		memset(hausers, '\0', sizeof(*hausers));
		hausers->mobility_spi = atoi(spip);
		
		sharedkeyp = strtok_r(NULL, " \t", &last);
		if (*sharedkeyp == '\'' || *sharedkeyp == '\"') {
			int i = 0;
			
			sharedkeyp++;
			while (sharedkeyp[i] != '\'' && sharedkeyp[i] && '\"'
			       && i < MIP6_AUTHENTICATOR_SIZE) {
				i++;
			}
			memcpy(hausers->sharedkey, sharedkeyp, i);
		} else {
			/* it might be hex */
			if (*sharedkeyp == '0' &&
			    *(sharedkeyp + 1) == 'x') {
				char *ep;
				char *hexchr = "0123456789ABCDEFabcdef";
				int loopend = 0, i = 0;
				u_int v;

				sharedkeyp += 2;
				ep = sharedkeyp + strlen(sharedkeyp);
				do {
					if (!strchr(hexchr, *sharedkeyp) ||
					    !strchr(hexchr, *(sharedkeyp + 1)))
						loopend = 1;
					sscanf(sharedkeyp, "%2x", &v);
					((u_int8_t *)&hausers->sharedkey)[i] = v & 0xff;
					sharedkeyp += 2;
				} while ((sharedkeyp < ep) && !loopend);
			}
		}
		LIST_INSERT_HEAD(&haauth_users_head, hausers, hauthusers_entry);
	}

	fclose(keytable);
}

int aaa_socket;

static void
aaa_auth_init()
{
	/* Normally, the function will do following process:
	   1) Open  socket to the AAA server
	   2) register it's handle
	*/
//	new_fd_list(aaa_socket, POLLIN, aaa_auth_done);
} 

void
aaa_auth_start()
{
	/* Send a query packet here with the aaa_socket */
	/* And start a timer to resend if needed */
}

void
aaa_auth_stop()
{
}

/*
 *  This function would be called with a file descriptor, which
 *  indicates a socket to talk an AAA server.
 *
 *  What implementors should do here are:
 *  1) 
 */
int
aaa_auth_done(fd)
	int fd;
{
#if  0
	struct binding_cache *bc;

	bc = find_bc_somehow();
	
	/* Judge the validity of this result somehow */
		
	if (success) {
		/* the authentication was succeeded. */
		bc->authmethod_done |= BC_AUTH_MNAAA;
		if (bc->authmethod ^ bc->authmethod_done == 0)
			bc->bc_state &= ~BC_STATE_UNDER_AUTH;
		mip6_bc_validate(bc);
		if ((bc->bc_state == BC_STATE_VALID) &&
		    !IN6_IS_ADDR_LINKLOCAL(addr)) {
			if (bc->bc_flags & (IP6_MH_BU_ACK | IP6_MH_BU_HOME))
				send_ba(&bc->bc_myaddr, &bc->bc_realcoa,
					&bc->bc_coa, &bc->bc_hoa, bc->bc_flags,
					NULL, IP6_MH_BAS_ACCEPTED,
					bc->bc_seqno, bc->bc_lifetime, bc->bc_bid, 0);
		}
	} else {
		/* the authentication was failed. */
		send_ba(&bc->bc_myaddr, &bc->bc_realcoa,
			&bc->bc_coa, &bc->bc_hoa, bc->bc_flags,
			NULL, IP6_MH_BAS_XXX,
			bc->bc_seqno, bc->bc_lifetime, bc->bc_bid, 0);
		mip6_bc_delete(bc);
	}
#endif
	return 0;
}
