/*	$KAME: dns6conv.c,v 1.1 2001/01/13 06:26:17 jinmei Exp $ */

/*
 * Copyright (C) 2001 WIDE Project.
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
#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

enum {default_beg_bit = 64, default_end_bit = 128}; 
static enum {a6, bitlabel, nibble} fmttype;

static struct sockaddr_in6 *cut __P((const struct sockaddr_in6 *, int, int));
static char *cut_bitlabel __P((const struct in6_addr *, int, int));
static void print_bitstring __P((const char *, int));
static void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	char *addr;
	const char *fmtstr = NULL;
	int ch, beg, end, error;
	struct addrinfo hints, *res;
	struct sockaddr_in6 *bin6;
	char hostbuf[NI_MAXHOST];

	beg = default_beg_bit;
	end = default_end_bit;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_NUMERICHOST;

	while ((ch = getopt(argc, argv, "b:e:f:")) != -1) {
		switch(ch) {
		case 'b':
			beg = atoi(optarg);
			break;
		case 'e':
			end = atoi(optarg);
			break;
		case 'f':
			fmtstr = optarg;
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();
	addr = argv[0];

	if (fmtstr != NULL) {
		if (strncasecmp(fmtstr, "a6", 2) == 0)
			fmttype = a6;
		else if (strncasecmp(fmtstr, "bit", 3) == 0)
			fmttype = bitlabel;
		else if (strncasecmp(fmtstr, "nibble", 6) == 0)
			fmttype = nibble;
		else
			errx(1, "unknown format type: %s", fmtstr);
	}

	if ((error = getaddrinfo((const char *)addr, NULL, &hints, &res))
	    != 0)
		errx(1, "getaddrinfo(%s): %s", addr, gai_strerror(error));

	/* bit length validation: 0 <= beg < end <= 128 */
	if (beg < 0 || end < 0 || beg > 128 || end > 128 || beg > end)
		errx(1, "beginbit(%d) or endbit(%d) are invalid", beg, end);

	switch(fmttype) {
	case a6:
		if ((bin6 = cut((const struct sockaddr_in6 *)res->ai_addr,
				beg, end)) == NULL)
			exit(1);

		if ((error = getnameinfo((struct sockaddr *)bin6,
					 sizeof(*bin6), hostbuf,
					 sizeof(hostbuf), NULL, 0,
					 NI_NUMERICHOST)) != 0)
			errx(1, "getnameinfo failed: error = %d", error);

		printf("%s\n", hostbuf);
		break;
	case bitlabel:
	{
		const char *ap;

		ap = cut_bitlabel(&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
				  beg, end);
		print_bitstring(ap, end - beg);
		break;
	}
	case nibble:
		warnx("format type not supported yet.");
		break;
	}

	exit(0);
}

static struct sockaddr_in6 *
cut(src, beg, end)
	const struct sockaddr_in6 *src;
	int beg, end;
{
	static struct sockaddr_in6 ret;
	char *cp;
	const char *bp;
	int i, bbyte, ebyte;

	memset(&ret, 0, sizeof(ret)); /* just for safety */
	ret = *src;
	bp = (const char *)&src->sin6_addr;
	cp = (char *)&ret.sin6_addr;

	/*
	 *      <------- beg ------>
	 *      <--- bbyte --->
	 * src: xxxxxxxxxxxxxxxxxxxxBBaaaaaaaaaaaaaaEEyyyyyyyyyyy
	 * dst: 00000000000000000000BBaaaaaaaaaaaaaaEE00000000000
	 *      <---------------- end --------------->
	 *      <------------- ebyte -------------->
	 */
	bbyte = (beg & ~7) / 8;
	ebyte = (end & ~7) / 8;

	for (i = 0; i < bbyte; i++)
		cp[i] = 0;
	cp[bbyte] = (bp[bbyte] & (0x00ff >> (beg % 8))) & 0xff;
	if ((end % 8) != 0)
		cp[ebyte] = (bp[ebyte] & (0xff << (8 - (end % 8))));
	for (i = ebyte + 1; i < 16; i++)
		cp[i] = 0;

	return(&ret);
}

static char *
cut_bitlabel(a6, beg, end)
	const struct in6_addr *a6;
	int beg, end;
{
	static char ret[sizeof(struct in6_addr)];
	const u_char *bp = (const u_char *)a6;
	char *cp = ret;
	int bbyte, resid, sft;

	bbyte = (beg & ~7) / 8;
	bp += bbyte;
	resid = end - beg;
	sft = beg % 8;
	memset(ret, 0, sizeof(ret));

	while(resid > 0) {
		*cp = ((*bp << sft) & (0xff << sft)) & 0xff;
		if ((resid -= (8 - sft)) <= 0)
			break;
		bp++;
		*cp |= ((*bp >> (8 - sft)) & 0xff);
		cp++;
		resid -= sft;
	}

	return(ret);
}

static void
print_bitstring(cp, blen)
	const char *cp;
	int blen;
{
	char pbuf[NI_MAXHOST]; /* XXX */
	char *dn = pbuf, tc;
	int b;

	for (b = blen; b > 7; b -= 8, cp++)
		dn += sprintf(dn, "%02x", *cp & 0xff);
	if (b > 4) {
		tc = *cp++;
		dn += sprintf(dn, "%02x", tc & (0xff << (8 - b)));
	} else if (b > 0) {
		tc = *cp++;
		dn += sprintf(dn, "%1x", ((tc >> 4) & 0x0f) & (0x0f << (4 - b))); 
	}
	dn += sprintf(dn, "/%d", blen);

	printf("%s\n", pbuf);

	return;
}

static void
usage()
{
	fprintf(stderr,
		"usage: dns6conv [-b begbit] [-e endbit] "
		"[-f format] IPv6address\n");

	exit(1);
}
