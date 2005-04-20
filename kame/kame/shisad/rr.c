/*      $KAME: rr.c,v 1.1 2005/04/20 04:10:25 t-momose Exp $  */
/*
 * Copyright (C) 2005 WIDE Project.  All rights reserved.
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

#include <string.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <netinet/ip6mh.h>
#include <netinet/icmp6.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "callout.h"
#include "shisad.h"

#ifdef MIP_CN
struct mip6_nonces_info nonces_array[MIP6_NONCE_HISTORY];
struct mip6_nonces_info *nonces_head;
#endif
void
mip6_calculate_kbm(home_token, careof_token, kbm)
        mip6_token_t *home_token;
        mip6_token_t *careof_token;  /* could be NULL */
        mip6_kbm_t *kbm;       /* needs at least MIP6_KBM_LEN bytes */
{
	SHA_CTX sha1_ctx; 

        SHA1_Init(&sha1_ctx);
        SHA1_Update(&sha1_ctx, (caddr_t)home_token, sizeof(*home_token));
        if (careof_token != NULL)
                SHA1_Update(&sha1_ctx, (caddr_t)careof_token,
		    sizeof(*careof_token));
        SHA1_Final((u_int8_t *)kbm, &sha1_ctx);
}

/*
 *   <------------------ datalen ------------------->
 *                  <-- exclude_data_len ---> 
 *   ---------------+-----------------------+--------
 *   ^              <--                   -->
 *   data     The area excluded from calculation Auth.
 *   - - - - - - - ->
 *     exclude_offset
 */
void
mip6_calculate_authenticator(key_bm, addr1, addr2, data, datalen,
			     exclude_offset, exclude_data_len, authenticator)
	mip6_kbm_t *key_bm;		/* Kbm */
	struct in6_addr *addr1, *addr2;
	caddr_t data;
	size_t datalen;
	int exclude_offset;
	size_t exclude_data_len;
	mip6_authenticator_t *authenticator;
{
	int restlen;
	HMAC_CTX hmac_ctx;
	u_int8_t sha1result[20];

#if 0
	if (debug) {
		syslog(LOG_INFO, "kbm = %s\n",
		       hexdump(key_bm, MIP6_KBM_SIZE));
		syslog(LOG_INFO, "addr1 = %s\n",
		       ip6_sprintf(addr1));
		syslog(LOG_INFO, "addr2 = %s\n",
		       ip6_sprintf(addr2));
		syslog(LOG_INFO, "datalen = %d\n", datalen);
		syslog(LOG_INFO, "exclude_offset = %d\n", exclude_offset);
		syslog(LOG_INFO, "exclude_data_len = %d\n", exclude_data_len);
	}
#endif

#ifndef __NetBSD__
	HMAC_CTX_init(&hmac_ctx);
#endif
	HMAC_Init(&hmac_ctx, (u_int8_t *)key_bm, sizeof(*key_bm), EVP_sha1());
	HMAC_Update(&hmac_ctx, (u_int8_t *)addr1, sizeof(*addr1));
	HMAC_Update(&hmac_ctx, (u_int8_t *)addr2, sizeof(*addr2));
	HMAC_Update(&hmac_ctx, (u_int8_t *)data, exclude_offset);

	/* 
	 * Exclude authdata field in the mobility option to calculate
	 * authdata But it should be included padding area 
	 */

	restlen = datalen - (exclude_offset + exclude_data_len);
	if (restlen > 0) {
		HMAC_Update(&hmac_ctx, 
			    (u_int8_t *) data + exclude_offset + exclude_data_len,
			    restlen);
	}

	HMAC_Final(&hmac_ctx, (u_int8_t *)sha1result, NULL);
	memcpy((void *)authenticator, (const void *)sha1result, 
	    MIP6_AUTHENTICATOR_SIZE);
	if (debug)
		syslog(LOG_INFO, "authenticator = %s\n", 
		       hexdump(authenticator, MIP6_AUTHENTICATOR_SIZE));
}

#ifdef MIP_CN
void 
init_nonces()
{
	int i;

	memset(&nonces_array, 0, sizeof(nonces_array));
	nonces_head = &nonces_array[0];
	
	/* ajusting next pointer */
	for (i = 0; i < (MIP6_NONCE_HISTORY - 1); i++) 
		nonces_array[i].next  = &nonces_array[i + 1];
	nonces_array[MIP6_NONCE_HISTORY - 1].next = &nonces_array[0];
	
	/* ajusting prev pointer */
	for (i = 1; i < MIP6_NONCE_HISTORY; i++)
		nonces_array[i].prev  = &nonces_array[i - 1];
	nonces_array[0].prev = &nonces_array[MIP6_NONCE_HISTORY - 1];

	nonces_head = generate_nonces(&nonces_array[0]);
};


struct mip6_nonces_info *
generate_nonces(ninfo)
	struct mip6_nonces_info *ninfo;
{
	(void)RAND_pseudo_bytes(ninfo->node_key, MIP6_NODEKEY_SIZE);
	(void)RAND_pseudo_bytes(ninfo->nonce, MIP6_NONCE_SIZE);

	ninfo->nonce_index = (nonces_head->nonce_index + 1); /* incremented */
	time(&ninfo->nonce_lasttime); /* timestamp */

	return (ninfo);
};



struct mip6_nonces_info *
get_nonces(index)
	u_int16_t index;
{
        time_t now;
	int i;

	/* 
	 * if the index of requesting nonces is zero, it must return
	 * an appropriate nonce. If the nonce_head's lasttime was
	 * stamped within MIP6_NONCE_REFRESH, get_nonces() uses the
	 * nonces. Otherwise, it generates new nonces and point the
	 * new one by nonce_head.  
	 */
	if (index == 0) {
		now = time(0);
		if ((now - nonces_head->nonce_lasttime) 
		    >= MIP6_NONCE_REFRESH)
			nonces_head = generate_nonces((nonces_head->next));

		return (nonces_head);
	}
	
	/* 
	 * On the other hand, if index is specified, try to get the
	 * correpsondent nonces.  If the nonces are not available or
	 * its lifetime is expired (beyond MIP6_MAX_NONCE_LIFE), it
	 * ends up to use the nonces which index is specified.  
	 */
        for (i = 0; i < MIP6_NONCE_HISTORY; i ++) {
		now = time(0);

                if (nonces_array[i].nonce_index == index &&
		    ((now - nonces_array[i].nonce_lasttime) 
		     <= MIP6_MAX_NONCE_LIFE))
			return (&nonces_array[i]);
	}

        return (NULL);
};

void
create_keygentoken(addr, nonces, token, need_one)
        struct in6_addr *addr; 
	struct mip6_nonces_info *nonces;        
        u_int8_t *token;
        u_int8_t need_one;
{
        u_int8_t token_tmp[20];
        HMAC_CTX hmac_ctx; 

#ifndef __NetBSD__
	HMAC_CTX_init(&hmac_ctx);
#endif

	memset(&token_tmp, 0, sizeof(token_tmp));

        HMAC_Init(&hmac_ctx, (u_int8_t *)nonces->node_key, 
		  sizeof(nonces->node_key), EVP_sha1());
        HMAC_Update(&hmac_ctx, (u_int8_t *)addr, sizeof(struct in6_addr)); 

	if (debug)
		syslog(LOG_INFO, "addr = %s\n", ip6_sprintf(addr));

        HMAC_Update(&hmac_ctx, (u_int8_t *)nonces->nonce, sizeof(nonces->nonce)); 

	if (debug)
		syslog(LOG_INFO, "nonce = %s\n", 
		       hexdump(nonces->nonce, sizeof(nonces->nonce)));

        HMAC_Update(&hmac_ctx, &need_one, sizeof(need_one)); 
        HMAC_Final(&hmac_ctx, (u_int8_t *)token_tmp, NULL); 

        memcpy(token, token_tmp, MIP6_TOKEN_SIZE);
}
#endif /* MIP_CN */
