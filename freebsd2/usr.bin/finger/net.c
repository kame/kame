/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Tony Nardo of the Johns Hopkins University/Applied Physics Lab.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
#if 0
static char sccsid[] = "@(#)net.c	8.4 (Berkeley) 4/28/95";
#else
static const char rcsid[] =
	"$Id: net.c,v 1.6.2.4 1998/07/17 04:17:53 jkh Exp $";
#endif
#endif /* not lint */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <db.h>
#include <err.h>
#include <unistd.h>
#include <pwd.h>
#include <utmp.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/uio.h>
#include "finger.h"

void
netfinger(name)
	char *name;
{
	extern int lflag;
	extern int Tflag;
	register FILE *fp;
	register int c, lastc;
	struct addrinfo hints, *res, *res0;
	int error;
	char *emsg = NULL;
	int s;
	char *alist[1], *host;
	struct iovec iov[3];
	struct msghdr msg;

	if (!(host = rindex(name, '@')))
		return;
	*host++ = '\0';
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;
	error = getaddrinfo(host, "finger", &hints, &res0);
	if (error) {
		warnx("%s: %s", gai_strerror(error), host);
		return;
	}

	msg.msg_name = NULL;	/*later*/
	msg.msg_namelen = 0;	/*later*/
	msg.msg_iov = iov;
	msg.msg_iovlen = 0;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	/* -l flag for remote fingerd  */
	if (lflag) {
		iov[msg.msg_iovlen].iov_base = "/W ";
		iov[msg.msg_iovlen++].iov_len = 3;
	}
	/* send the name followed by <CR><LF> */
	iov[msg.msg_iovlen].iov_base = name;
	iov[msg.msg_iovlen++].iov_len = strlen(name);
	iov[msg.msg_iovlen].iov_base = "\r\n";
	iov[msg.msg_iovlen++].iov_len = 2;

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0) {
			emsg = "socket";
			continue;
		}

		msg.msg_name = (void *)res->ai_addr;
		msg.msg_namelen = res->ai_addrlen;

		/*
		 * Try T/TCP first, then normal TCP.  -T disables T/TCP.
		 */
		if (!Tflag) {
			if (sendmsg(s, &msg, 0) >= 0)
				break;
		}

		if (errno != ENOTCONN) {
			close(s);
			s = -1;
			emsg = "sendmsg";
			continue;
		}

		/* T/TCP failed on this address family - try normal TCP */
		if (connect(s, res->ai_addr, res->ai_addrlen)) {
			close(s);
			s = -1;
			emsg = "connect";
			continue;
		}

		if (sendmsg(s, &msg, 0) < 0) {
			close(s);
			s = -1;
			emsg = "sendmsg";
			continue;
		}

		break;
	}
	if (s < 0) {
		if (emsg != NULL)
			warn(emsg);
		return;
	}

	/* have network connection; identify the host connected with */
	(void)printf("[%s]\n", res0->ai_canonname ? res0->ai_canonname : host);

	/*
	 * Read from the remote system; once we're connected, we assume some
	 * data.  If none arrives, we hang until the user interrupts.
	 *
	 * If we see a <CR> or a <CR> with the high bit set, treat it as
	 * a newline; if followed by a newline character, only output one
	 * newline.
	 *
	 * Otherwise, all high bits are stripped; if it isn't printable and
	 * it isn't a space, we can simply set the 7th bit.  Every ASCII
	 * character with bit 7 set is printable.
	 */
	lastc = 0;
	if ((fp = fdopen(s, "r")) != NULL) {
		while ((c = getc(fp)) != EOF) {
			if (c == 0x0d) {
				if (lastc == '\r')	/* ^M^M - skip dupes */
					continue;
				c = '\n';
				lastc = '\r';
			} else {
				if (!isprint(c) && !isspace(c)) {
					c &= 0x7f;
					c |= 0x40;
				}
				if (lastc != '\r' || c != '\n')
					lastc = c;
				else {
					lastc = '\n';
					continue;
				}
			}
			putchar(c);
		}
		if (lastc != '\n')
			putchar('\n');

		if (ferror(fp)) {
			/*
			 * Assume that whatever it was set errno...
			 */
			perror("finger: read");
		}
		(void)fclose(fp);
	}
}
