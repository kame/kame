/*	$KAME: dhcp6sctl.c,v 1.6 2004/06/17 06:23:40 jinmei Exp $	*/

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

static inline int put16 __P((char **, int *, u_int16_t));
static inline int put32 __P((char **, int *, u_int32_t));
static inline int putval __P((char **, int *, void *, size_t));

static int make_command __P((int, char **, char **, size_t *));
static int make_remove_command __P((int, char **, char **, int *));
static int make_binding_object __P((int, char **, char **, int *));
static int make_ia_object __P((int, char **, char **, int *));
static int parse_duid __P((char *, int *, char **, int *));
static void usage __P((void));

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int cc, ch, s, error, passed;
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
	
	if ((passed = make_command(argc, argv, &cbuf, &clen)) < 0)
		errx(1, "failed to make command buffer");
	argc -= passed;
	argv += passed;
	if (argc != 0)
		warnx("redundant command argument after \"%s\"", argv[0]);

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

static inline int
put16(bpp, lenp, val)
	char **bpp;
	int *lenp;
	u_int16_t val;
{
	char *bp = *bpp;
	int len = *lenp;

	if (len < sizeof(val))
		return (-1);

	val = htons(val);
	memcpy(bp, &val, sizeof(val));
	bp += sizeof(val);
	len -= sizeof(val);

	*bpp = bp;
	*lenp = len;

	return (0);
}

static inline int
put32(bpp, lenp, val)
	char **bpp;
	int *lenp;
	u_int32_t val;
{
	char *bp = *bpp;
	int len = *lenp;

	if (len < sizeof(val))
		return (-1);

	val = htonl(val);
	memcpy(bp, &val, sizeof(val));
	bp += sizeof(val);
	len -= sizeof(val);

	*bpp = bp;
	*lenp = len;

	return (0);
}

static inline int
putval(bpp, lenp, val, valsize)
	char **bpp;
	int *lenp;
	void *val;
	size_t valsize;
{
	char *bp = *bpp;
	int len = *lenp;

	if (len < valsize)
		return (-1);

	memcpy(bp, val, valsize);
	bp += valsize;
	len -= valsize;

	*bpp = bp;
	*lenp = len;

	return (0);
}

static int
make_command(argc, argv, bufp, lenp)
	int argc;
	char **argv, **bufp;
	size_t *lenp;
{
	struct dhcp6ctl ctl;
	char commandbuf[4096];	/* XXX: ad-hoc value */
	char *bp, *buf;
	int buflen, len, duidlen;
	int argc_passed = 0, passed;
	u_int32_t p32;

	if (argc == 0) {
		warnx("command is too short");
		return (-1);
	}

	bp = commandbuf + sizeof(ctl);
	buflen = sizeof(commandbuf) - sizeof(ctl);

	memset(&ctl, 0, sizeof(ctl));
	ctl.version = htons(DHCP6CTL_VERSION);

	if (strcmp(argv[0], "reload") == 0)
		ctl.command = htons(DHCP6CTL_COMMAND_RELOAD);
	else if (strcmp(argv[0], "remove") == 0) {
		if ((passed = make_remove_command(argc - 1, argv + 1,
		    &bp, &buflen)) < 0) {
			return (-1);
		}
		argc_passed += passed;
		ctl.command = htons(DHCP6CTL_COMMAND_REMOVE);
	} else {
		warnx("unknown command: %s", argv[0]);
		return (-1);
	}

	len = bp - commandbuf;
	ctl.len = htons(len - sizeof(ctl));
	memcpy(commandbuf, &ctl, sizeof(ctl));

	if ((buf = malloc(len)) == NULL) {
		warn("memory allocation failed");
		return (-1);
	}
	memcpy(buf, commandbuf, len);

	*lenp = len;
	*bufp = buf;

	argc_passed++;

	return (argc_passed);
}

static int
make_remove_command(argc, argv, bpp, lenp)
	int argc, *lenp;
	char **argv, **bpp;
{
	int argc_passed = 0, passed;

	if (argc == 0) {
		warnx("make_remove_command: command is too short");
		return (-1);
	}

	if (strcmp(argv[0], "binding") == 0) {
		if (put32(bpp, lenp, DHCP6CTL_BINDING))
			goto fail;
		if ((passed = make_binding_object(argc - 1, argv + 1,
		    bpp, lenp)) < 0) {
			return (-1);
		}
		argc_passed += passed;
	} else {
		warnx("remove target not supported: %s", argv[0]);
		return (-1);
	}

	argc_passed++;
	return (argc_passed);

  fail:
	warnx("make_remove_command failed");
	return (-1);
}

static int
make_binding_object(argc, argv, bpp, lenp)
	int argc, *lenp;
	char **argv, **bpp;
{
	int argc_passed = 0, passed;

	if (argc == 0) {
		/* or allow this as "all"? */
		warnx("make_binding_object: command is too short");
		return (-1);
	}

	if (strcmp(argv[0], "IA") == 0) {
		if (put32(bpp, lenp, DHCP6CTL_BINDING_IA))
			goto fail;
		if ((passed = make_ia_object(argc - 1, argv + 1,
		    bpp, lenp)) < 0) {
			return (-1);
		}
		argc_passed += passed;
	} else {
		warn("unknown binding type: %s", argv[0]);
		return (-1);
	}

	argc_passed++;
	return (argc_passed);

  fail:
	warnx("make_binding_object: failed");
	return (-1);
}

static int
make_ia_object(argc, argv, bpp, lenp)
	int argc, *lenp;
	char **argv, **bpp;
{
	struct dhcp6ctl_iaspec iaspec;
	int duidlen, dummylen = 0;
	int argc_passed = 0, passed = 0;
	char *dummy = NULL;

	if (argc < 3) {
		/*
		 * Right now, we require all three parameters of
		 * <IA type, IAID, DUID>.  This should be more flexible in
		 * the future.
		 */
		warnx("command is too short for an IA spec");
		return (-1);
	}
	argc_passed += 3;

	memset(&iaspec, 0, sizeof(iaspec));

	if (strcmp(argv[0], "IA_PD") == 0)
		iaspec.type = htonl(DHCP6CTL_IA_PD);
	else {
		warnx("IA type not supported: %s", argv[0]);
		return (-1);
	}

	iaspec.id = htonl((u_int32_t)atoi(argv[1]));

	if (parse_duid(argv[2], &duidlen, &dummy, &dummylen))
		goto fail;
	iaspec.duidlen = htonl(duidlen);

	if (putval(bpp, lenp, &iaspec, sizeof(iaspec)))
		goto fail;

	if (parse_duid(argv[2], &duidlen, bpp, lenp))
		goto fail;

	return (argc_passed);

  fail:
	warnx("make_ia_object: failed");
	return (-1);
}

static int
parse_duid(str, lenp, bufp, buflenp)
	char *str;
	int *lenp;
	char **bufp;
	int *buflenp;
{
	char *buf = *bufp;
	char *cp, *bp;
	int duidlen, slen, buflen;
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

	buflen = *buflenp;
	if (buflen < duidlen)
		goto bad;

	for (cp = str, bp = buf; *cp != '\0';) {
		if (bp - buf >= buflen)
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
	*bufp = bp;
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
