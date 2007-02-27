/*	$KAME: auth.c,v 1.4 2007/02/27 01:44:12 keiichi Exp $	*/

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
#include <unistd.h>
#include <ctype.h>
#include <poll.h>
#include <syslog.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip6mh.h>

#include "callout.h"
#include "fdlist.h"
#include "shisad.h"
#include "command.h"
#include "config.h"

LIST_HEAD(haauth_users_head, haauth_users) haauth_users_head = LIST_HEAD_INITIALIZER(haauth_users_head);
struct sockaddr_in6 aaa_server = {sizeof(struct sockaddr_in6), AF_INET6, 0, 0};

static int ha_auth(struct in6_addr *, struct in6_addr *,
		   struct ip6_mh_opt_authentication *, struct ip6_mh *,
		   mip6_authenticator_t *);
void aaa_auth_start(struct in6_addr *, struct in6_addr *,
		    struct ip6_mh_opt_mn_id *, struct ip6_mh *);
int aaa_auth_reply_from_aaa(int);
static void ha_auth_init();
static void aaa_auth_init();
#if 0
static void aaa_auth_done(int);
#endif
static int get_secret(char *, int, u_int8_t *, int *);

char *auth_database = SYSCONFDIR "/authdata";

void
auth_init(if_params, config_params)
	struct config_entry *if_params;
	struct config_entry *config_params;
{
	if (if_params != NULL) {
		config_get_string(CFT_AUTHDATABASE, &auth_database, if_params);
	}
	if (config_params != NULL) {
		config_get_string(CFT_AUTHDATABASE, &auth_database, config_params);
	}
	syslog(LOG_INFO, "auth_database: %s", auth_database);
	
	ha_auth_init();
	aaa_auth_init();
}


/*
  return value: status code of BA
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
			/* pick parameters and 
			   calculate authenticator with
			   the parameters to authenticate.
			*/
			*authmethod |= BC_AUTH_MNHA;
			*authmethod_done |= BC_AUTH_MNHA;
			if (ha_auth(hoa, coa, mopt_auth, mh, &authenticator) ==  0 &&
			    memcmp((caddr_t)&authenticator, (caddr_t)(mopt_auth + 1), MIP6_AUTHENTICATOR_SIZE) == 0) {
				statuscode = IP6_MH_BAS_ACCEPTED;
			} else {
				statuscode = IP6_MH_BAS_AUTH_FAIL;
				syslog(LOG_ERR,
				       "authenticator received from BU(Hoa:[%s], SPI=%d): %s",
				       ip6_sprintf(hoa),
				       ntohl(mopt_auth->ip6moauth_mobility_spi),
				       hexdump(mopt_auth + 1, MIP6_AUTHENTICATOR_SIZE));
				syslog(LOG_ERR, "Calculated authenticator: %s",
				       hexdump(&authenticator, MIP6_AUTHENTICATOR_SIZE));
			}
			break;
			
		case IP6_MH_AUTHOPT_SUBTYPE_MNAAA:
			/* To authorize: send a query to an AAA server.
			   This is an asynchoronous process because an
			   AAA server is usually another entity.
			*/
			aaa_auth_start(hoa, coa, mopt->opt_mnid, mh);
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
	if (hausers == NULL) {
		syslog(LOG_INFO, "No such user(spi=%d) was registered",
		       ntohl(mopt_auth->ip6moauth_mobility_spi));
		return (-1);
	}

	cksum = mh->ip6mh_cksum;
	mh->ip6mh_cksum = 0;
	calculate_authenticator(hausers->sharedkey, hausers->keylen, coa, hoa,
				(caddr_t)mh,
				(caddr_t)(mopt_auth + 1) - (caddr_t)mh,
				(caddr_t)(mopt_auth + 1) - (caddr_t)mh,
				0,
				(u_int8_t *)authenticator, MIP6_AUTHENTICATOR_SIZE);
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

struct haauth_users *
find_haauth_users_with_hoa(hoa)
	struct in6_addr *hoa;
{
	struct haauth_users *hausers;

	LIST_FOREACH(hausers, &haauth_users_head, hauthusers_entry) {
		if (IN6_ARE_ADDR_EQUAL(&hausers->hoa, hoa))
			return (hausers);
	}

	return (NULL);
}

static int
get_secret(sharedkeyp, secretkey_size, secretkey, keylen)
	char *sharedkeyp;
	int secretkey_size;
	u_int8_t *secretkey;
	int *keylen;
{
	if (sharedkeyp == NULL)
		return (-1);

	if (*sharedkeyp == '\'' || *sharedkeyp == '\"') {
		int i = 0;
		
		sharedkeyp++;
		while (sharedkeyp[i] != '\'' && sharedkeyp[i] != '\"'
		       && i < secretkey_size) {
			i++;
		}
		if (sharedkeyp[i] != '\'' && sharedkeyp[i] != '\"') {
			syslog(LOG_WARNING, "shared key is too long. truncated.");
			i = secretkey_size;
		}
		memcpy(secretkey, sharedkeyp, i);
		*keylen = i;
	} else 	if (*sharedkeyp == '0' && *(sharedkeyp + 1) == 'x') {
		/* it might be a sequence of hex */
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
			((u_int8_t *)secretkey)[i++]
				= v & 0xff;
			sharedkeyp += 2;
		} while (i < secretkey_size && (sharedkeyp < ep) && !loopend);
		if (i == secretkey_size && sharedkeyp < ep)
			syslog(LOG_WARNING, "shared key is too long. truncated.");
		*keylen = i;
	} else {
		syslog(LOG_ERR, "No secret was found");
		return (-1);
	}

	return (0);
}

/*
  Read and construct MN-HA authenticator database

  The format of authentication Database is described as followed:
---  
# the line started '#' shows comment.
# one data is described in one line. The line contains 'HoA', 'SPI' and 16octets secret separated with space(including TAB).
2001:DB8:0:80be::1000 10000	'shared-key in 16'  # The string 'bytes' to be trailed is trimmed 
2001:DB8:0:80be::1001 10001           0x0102030405060708090a0b0c0d0e0f10
---  
 */
static void
ha_auth_init()
{
	int error;
	char *p, *spip, *last, *addr;
	char read_buffer[1024];
	FILE *keytable;
	struct haauth_users *hausers;
	struct addrinfo hints, *res0;

	if ((keytable = fopen(auth_database, "r")) == NULL) {
		syslog(LOG_ERR,
		       "Authdata: Opening authentication database was failed (%s)",
		       auth_database);
		return;
	}
	
	while (fgets(read_buffer, sizeof(read_buffer), keytable) != NULL) {
		int base = 10;
		
		read_buffer[sizeof(read_buffer) - 1] = '\0';
		if ((p = strchr(read_buffer, '\n')) == NULL &&
		    strlen(read_buffer) >= sizeof(read_buffer) - 1) {
			syslog(LOG_ERR, "Authdata: The line was too long. [%1024s]",
			       read_buffer);
			continue; /* the line was too long */
		}
		*p = '\0';

		p = read_buffer;
		while (isspace(*p))
			p++;
		if (*p == '#')
			continue;	/* comment line */
		
		hausers = malloc(sizeof(*hausers));
		memset(hausers, '\0', sizeof(*hausers));
		
		if ((spip = addr = strtok_r(p, " \t", &last)) == NULL) {
			free(hausers);
			continue;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_NUMERICHOST;
		if ((error = getaddrinfo(addr, NULL, &hints, &res0)) != 0) {
			syslog(LOG_ERR, "Authdata: Failed to get HoA[%s] because %s",
			       addr, gai_strerror(error));
		} else if (res0->ai_family != AF_INET6) {
			syslog(LOG_ERR, "Authdata: Not IPv6 address [%s]", addr);
		} else {
			hausers->hoa = ((struct sockaddr_in6 *)res0->ai_addr)->sin6_addr;
			freeaddrinfo(res0);
		
			if ((spip = strtok_r(NULL, " \t", &last)) == NULL) {
				free(hausers);
				continue;
			}
		}

		if (spip[0] == '0' && spip[1] == 'x') {
			spip += 2; /* for '0x' */
			base = 16;
		}
		hausers->mobility_spi = strtol(spip, NULL, base);
		if (get_secret(strtok_r(NULL, " \t", &last), SECRETKEY_SIZE,
			       hausers->sharedkey, &hausers->keylen) < 0) {
			free(hausers);
			continue;
		}
		
		if (debug)
			syslog(LOG_INFO, "%s  spi: %d  [%s]\n",
			       ip6_sprintf(&hausers->hoa),
			       hausers->mobility_spi,
			       hexdump(hausers->sharedkey, hausers->keylen));
		LIST_INSERT_HEAD(&haauth_users_head, hausers, hauthusers_entry);
	}

	fclose(keytable);
}

void
command_show_authdata(s, dummy)
	int s;
	char *dummy;
{
	struct haauth_users *hausers;

	command_printf(s, "Authentication database\n");
	LIST_FOREACH(hausers, &haauth_users_head, hauthusers_entry) {
		command_printf(s, "%s %d [%s]\n",
			       ip6_sprintf(&hausers->hoa),
			       hausers->mobility_spi,
			       hexdump(hausers->sharedkey, hausers->keylen));
	}
}

static void
aaa_auth_init()
{
} 

void
aaa_auth_start(hoa, coa, mopt_mnid, mh)
	struct in6_addr *hoa, *coa;
	struct ip6_mh_opt_mn_id *mopt_mnid;
	struct ip6_mh *mh;
{
#if 0
	int mnid_len;
	char *mnid;

	if ((mopt_mnid == NULL) ||
	    (mopt_mnid->ip6mnmnid_subtype != 1)) {
		syslog(LOG_ERR, "No MN ID option was found.");
		return;
	}
	mnid_len = mopt_mnid->ip6momnid_len - 1; /* '-1' is for the subtype field */
	if (mnid_len <= 0) {
		syslog(LOG_ERR, "MN ID length is too short.");
		return;
	}
	mnid = (char *)(mopt_mnid + 1);

	if ((aaa_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		syslog(LOG_ERR,
		       "Opening UDP socket to the AAA server was failed.");
		return;
	}
	new_fd_list(aaa_socket, POLLIN, aaa_auth_reply_from_aaa);
#endif
}

void
aaa_auth_stop(hoa)
	struct in6_addr *hoa;
{
}

/*
 *  This function would be called with a file descriptor, which
 *  indicates a socket to talk an AAA server.
 *
 *  What implementors should do here are:
 *  1) Receive a reply packet from AAA
 *  2) Validate the message in the packet
 *  3) Judge the result from the AAA
 *  4) Pass to aaa_auth_done()
 */
int
aaa_auth_reply_from_aaa(fd)
	int fd;
{
#if 0
	/* Judge the result from the AAA */
	aaa_auth_done(success);
#endif
	return (0);
}

#if 0
static void
aaa_auth_done(success)
	int success;
{
	struct binding_cache *bc = NULL;

	/* Find a binding cache somehow */

	if (!bc)
		return;

	if (success) {
		/* the authentication was succeeded. */
		bc->bc_authmethod_done |= BC_AUTH_MNAAA;
		if ((bc->bc_authmethod ^ bc->bc_authmethod_done) == 0)
			bc->bc_state &= ~BC_STATE_UNDER_AUTH;
		/* XXX is (void) OK? */
		(void)mip6_validate_bc(bc);
		if ((bc->bc_state == BC_STATE_VALID) &&
		    !IN6_IS_ADDR_LINKLOCAL(&bc->bc_hoa)) {
			if (bc->bc_flags & (IP6_MH_BU_ACK | IP6_MH_BU_HOME))
				send_ba(&bc->bc_myaddr, &bc->bc_realcoa,
					&bc->bc_coa, &bc->bc_hoa, bc->bc_flags,
					NULL, IP6_MH_BAS_ACCEPTED,
					bc->bc_seqno, bc->bc_lifetime, 0, 0/*bc->bc_bid*/, bc->bc_mobility_spi);
		}
	} else {
		/* the authentication was failed. */
		send_ba(&bc->bc_myaddr, &bc->bc_realcoa,
			&bc->bc_coa, &bc->bc_hoa, bc->bc_flags,
			NULL, IP6_MH_BAS_AUTH_FAIL,
			bc->bc_seqno, bc->bc_lifetime, 0, 0/*bc->bc_bid*/, bc->bc_mobility_spi);
		mip6_bc_delete(bc);
	}

}
#endif
