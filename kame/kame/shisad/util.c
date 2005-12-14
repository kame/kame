/*      $KAME: util.c,v 1.5 2005/12/14 08:17:51 t-momose Exp $  */

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

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/syslog.h>

#include <netdb.h>
#include <netinet/in.h>

extern int namelookup;

const char *
ip6_sprintf(addr)
	const struct in6_addr *addr;
{
	static int ip6round = 0;
	static char ip6buf[8][NI_MAXHOST];
	struct sockaddr_in6 sin6;
	int flags = 0;

	if (namelookup == 0)
		flags |= NI_NUMERICHOST;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *addr;

	/*
	 * XXX: This is a special workaround for KAME kernels.
	 * sin6_scope_id field of SA should be set in the future.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr) ||
	    IN6_IS_ADDR_MC_NODELOCAL(&sin6.sin6_addr)) {
		/* XXX: override is ok? */
		sin6.sin6_scope_id = (u_int32_t)ntohs(*(u_short *)&sin6.sin6_addr.s6_addr[2]);
		*(u_short *)&sin6.sin6_addr.s6_addr[2] = 0;
	}

	ip6round = (ip6round + 1) & 7;

	if (getnameinfo((struct sockaddr *)&sin6, sizeof(sin6),
			ip6buf[ip6round], NI_MAXHOST, NULL, 0, flags) != 0)
		return ("?");

	return (ip6buf[ip6round]);
}

char *
hexdump(addr_arg, len)
	void *addr_arg;
	size_t len;
{
	char *p, *addr = (char *)addr_arg;
	static char buffer[128];	/* Up to 128 chrs */
	char *hexchr = "0123456789abcdef";
	
	p = buffer;
	while (len-- && p - buffer < 128) {
		*p++ = hexchr[(*addr >> 4) & 0x0f];
		*p++ = hexchr[(*addr     ) & 0x0f];
		addr++;
	}
	*p = '\0';

	return (buffer);
}

int
in6_mask2len(mask, lim0)
        struct in6_addr *mask;
        u_char *lim0;
{
        int x = 0, y;
        u_char *lim = lim0, *p;

        /* ignore the scope_id part */
        if (lim0 == NULL || lim0 - (u_char *)mask > sizeof(*mask))
                lim = (u_char *)mask + sizeof(*mask);
        for (p = (u_char *)mask; p < lim; x++, p++) {
                if (*p != 0xff)
                        break;
        }
        y = 0;
        if (p < lim) {
                for (y = 0; y < 8; y++) {
                        if ((*p & (0x80 >> y)) == 0)
                                break;
                }
        }

        /*
         * when the limit pointer is given, do a stricter check on the
         * remaining bits.
         */
        if (p < lim) {
                if (y != 0 && (*p & (0x00ff >> y)) != 0)
                        return (-1);
                for (p = p + 1; p < lim; p++)
                        if (*p != 0)
                                return (-1);
        }

        return (x * 8 + y);
}

int
inet_are_prefix_equal(p1, p2, len)
        void *p1, *p2;
        int len;
{
        int bytelen, bitlen;
	u_int8_t *cp1, *cp2;

        /* sanity check */
        if (0 > len || len > 128) {
                syslog(LOG_ERR, "inet_are_prefix_equal:"
		       "invalid prefix length(%d)\n", len);
                return (0);
        }

        bytelen = len / 8;
        bitlen = len % 8;

        if (memcmp(p1, p2, bytelen))
                return (0);
	cp1 = p1;
	cp2 = p2;
        if (bitlen != 0 &&
            *(cp1 + bytelen) >> (8 - bitlen) !=
            *(cp2 + bytelen) >> (8 - bitlen))
                return (0);

        return (1);
}
