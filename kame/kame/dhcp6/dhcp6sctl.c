/*	$KAME: dhcp6sctl.c,v 1.5 2004/06/12 12:49:51 jinmei Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#include <netinet/in.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <err.h>

#include <control.h>

static char *ctladdr = DEFAULT_CONTROL_ADDR;
static char *ctlport = DEFAULT_CONTROL_PORT;

static int make_command __P((int, char **, char **, size_t *));
static int parse_duid __P((char *, int *, char *));
static void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int cc, ch, s, error;
	char *cbuf;
	size_t clen;
	struct addrinfo hints, *res0, *res;

	while ((ch = getopt(argc, argv, "p:s:")) != -1) {
		switch (ch) {
		case 'p':
			ctlport = optarg;
			break;
		case 's':
			ctladdr = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (make_command(argc, argv, &cbuf, &clen))
		exit(1);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(ctladdr, ctlport, &hints, &res0);
	if (error != 0)
		errx(1, "getaddrinfo failed: %s", gai_strerror(error));
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s < 0) {
			warn("socket");
			continue;
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			warn("connect");
			s = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(res0);
	if (s < 0) {
		warnx("failed to connect to the server");
		exit(1);
	}

	cc = write(s, cbuf, clen);
	if (cc < 0)
		err(1, "write command");
	if (cc != clen)
		errx(1, "failed to send complete command");

	close(s);
	free(cbuf);

	exit(0);
}

static int
make_command(argc, argv, bufp, lenp)
	int argc;
	char **argv, **bufp;
	size_t *lenp;
{
	struct dhcp6ctl ctl;
	char *buf = NULL, *bp;
	int len, duidlen;
	struct dhcp6ctl_iaspec iaspec;
	u_int32_t p32;

	if (argc == 0) {
		warnx("command is too short");
		goto fail;
	}

	memset(&ctl, 0, sizeof(ctl));
	ctl.version = htons(DHCP6CTL_VERSION);

	if (strcmp(argv[0], "reload") == 0) {
		ctl.command = htons(DHCP6CTL_COMMAND_RELOAD);
		ctl.len = 0;
		len = sizeof(ctl);
		if ((buf = malloc(len)) == NULL) {
			warn("malloc failed");
			goto fail;
		}
		memcpy(buf, &ctl, len);
	} else if (strcmp(argv[0], "remove") == 0) {
		/*
		 * right now we only accept the form of
		 * "remove binding IA iatype IAID duid"
		 */
		if (argc < 6)
			warnx("short command for %s", argv[0]);

		/* XXX: should be more generic!! */
		if (strcmp(argv[1], "binding") == 0 &&
		    strcmp(argv[2], "IA") == 0 &&
		    strcmp(argv[3], "IA_PD") == 0) {
			if (parse_duid(argv[5], &duidlen, NULL)) {
				warnx("failed to parse duid: %s", argv[5]);
				goto fail;
			}
			len = sizeof(ctl) + 8 + sizeof(iaspec) + duidlen;
			if ((buf = malloc(len)) == NULL) {
				warn("malloc failed");
				goto fail;
			}

			ctl.command = htons(DHCP6CTL_COMMAND_REMOVE);
			ctl.len = htons(len - sizeof(ctl));
			memcpy(buf, &ctl, sizeof(ctl));

			bp = buf + sizeof(ctl);

			p32 = htonl(DHCP6CTL_BINDING);
			memcpy(bp, &p32, sizeof(p32));
			bp += sizeof(p32);

			p32 = htonl(DHCP6CTL_BINDING_IA);
			memcpy(bp, &p32, sizeof(p32));
			bp += sizeof(p32);

			iaspec.type = htonl(DHCP6CTL_IA_PD);
			iaspec.id = htonl((u_int32_t)atoi(argv[4]));
			iaspec.duidlen = htonl(duidlen);
			memcpy(bp, &iaspec, sizeof(iaspec));
			bp += sizeof(iaspec);

			if (parse_duid(argv[5], &duidlen, bp)) {
				warnx("failed to parse duid: %s", argv[5]);
				goto fail;
			}
		}
	} else {
		warnx("unknown command: %s", argv[0]);
		goto fail;
	}

	*lenp = len;
	*bufp = buf;

	return (0);

  fail:
	if (buf != NULL)
		free(buf);
	return (-1);
}

static int
parse_duid(str, lenp, buf)
	char *str;
	int *lenp;
	char *buf;
{
	char *cp, *bp;
	int duidlen, slen;
	unsigned int x;

	/* calculate DUID len */
	slen = strlen(str);
	if (slen < 2)
		goto bad;
	duidlen = 1;
	slen -= 2;
	if ((slen % 3) != 0)
		goto bad;
	duidlen += (slen / 3);
	if (duidlen > 128) {
		warn("too long DUID (%d bytes)", duidlen);
		return (-1);
	}

	*lenp = duidlen;
	if (buf == NULL)
		return (0);

	for (cp = str, bp = buf; *cp != '\0';) {
		/* this should not happen, but check it for safety. */
		if (bp - buf > duidlen)
			goto bad;

		if (sscanf(cp, "%02x", &x) != 1)
			goto bad;
		*bp++ = x;
		cp += 2;

		switch (*cp) {
		case ':':
			cp++;
			break;
		case '\0':
			goto done;
		default:
			goto bad;
		}
	}
  done:
	return (0);

  bad:
	return (-1);
}

static void
usage()
{
	fprintf(stderr, "usage: dhcp6sctl [-p port] [-s server_address] "
	    "commands...\n");

	exit(1);
}
