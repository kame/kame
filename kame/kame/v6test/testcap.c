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

/*
 * Copyright (c) 1983 The Regents of the University of California.
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
static char sccsid[] = "@(#)remcap.c	5.5 (Berkeley) 2/2/91";
#endif /* not lint */

/*
 * remcap - routines for dealing with the remote host data base
 *
 * derived from termcap
 */
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include "pathnames.h"

#define	TESTBUFSIZ	2048
#define MAXHOP		32		/* max number of tc= indirections */
#define	E_TERMCAP	RM = _PATH_V6TESTCONF

char	*RM;

static char *tbuf;
static int hopcount;	/* detect infinite loops in termcap, init 0 */
static char *tskip();
static char *tdecode();
static char *remotefile;

extern char *conffile;

/*
 * Get an entry for terminal name in buffer bp,
 * from the termcap file.  Parse is very rudimentary;
 * we just notice escaped newlines.
 */
tgetent(char *bp, char *name)
{
	char lbuf[BUFSIZ], *cp;
	int found;
	FILE *fp;

	remotefile = cp = conffile ? conffile : _PATH_V6TESTCONF;
	if (found = getent(bp, name, cp)) {
		/* duplicate entry detection */
		found = 0;
		if ((fp = fopen(cp, "r")) == NULL) {
			perror("fopen");
			exit(1);
		}
		while(fgets(lbuf, BUFSIZ, fp)) {
			tbuf = lbuf;
			if (tnamatch(name))
				found++;
			if (found > 1) {
				fprintf(stderr,
					"v6test: duplicate entry: %s\n", name);
				break;
			}
		}
		fclose(fp);
	}
	return(found);
}

int
getent(char *bp, char *name, char *cp)
{
	register int c;
	register int i = 0, cnt = 0;
	char ibuf[TESTBUFSIZ];
	int tf;

	tbuf = bp;
	tf = 0;
	/*
	 * TERMCAP can have one of two things in it. It can be the
	 * name of a file to use instead of /etc/termcap. In this
	 * case it better start with a "/". Or it can be an entry to
	 * use so we don't have to read the file. In this case it
	 * has to already have the newlines crunched out.
	 */
	if (cp && *cp)
		tf = open(RM = cp, O_RDONLY);
	if (tf == 0)
		tf = open(E_TERMCAP, O_RDONLY);
	if (tf < 0)
		return (-1);
	for (;;) {
		cp = bp;
		for (;;) {
			if (i == cnt) {
				cnt = read(tf, ibuf, TESTBUFSIZ);
				if (cnt <= 0) {
					close(tf);
					return (0);
				}
				i = 0;
			}
			c = ibuf[i++];
			if (c == '\n') {
				if (cp > bp && cp[-1] == '\\') {
					cp--;
					continue;
				}
				break;
			}
			if (cp >= bp+TESTBUFSIZ) {
				write(2,"Remcap entry too long\n", 23);
				break;
			} else
				*cp++ = c;
		}
		*cp = 0;

		/*
		 * The real work for the match.
		 */
		if (tnamatch(name)) {
			close(tf);
			return (tnchktc());
		}
	}
}

/*
 * tnchktc: check the last entry, see if it's tc=xxx. If so,
 * recursively find xxx and append that entry (minus the names)
 * to take the place of the tc=xxx entry. This allows termcap
 * entries to say "like an HP2621 but doesn't turn on the labels".
 * Note that this works because of the left to right scan.
 */
tnchktc()
{
	register char *p, *q;
	char tcname[16];	/* name of similar terminal */
	char tcbuf[TESTBUFSIZ];
	char *holdtbuf = tbuf;
	int l;

	p = tbuf + strlen(tbuf) - 2; /* before the last colon */
	while (*--p != ':')
		if (p<tbuf) {
			write(2, "Bad remcap entry\n", 18);
			return (0);
		}
	p++;
	/* p now points to beginning of last field */
	if (p[0] != 't' || p[1] != 'c' || isalpha(p[2]))
		return (1);
	strcpy(tcname, p+3);
	q = tcname;
	while (*q && *q != ':')
		q++;
	*q = 0;
	if (++hopcount > MAXHOP) {
		write(2, "Infinite tc= loop\n", 18);
		return (0);
	}
	if (getent(tcbuf, tcname, remotefile) != 1) {
		if (strcmp(remotefile, _PATH_V6TESTCONF) == 0)
			return (0);
		else if (getent(tcbuf, tcname, _PATH_V6TESTCONF) != 1)
			return (0);
	}
	for (q = tcbuf; *q++ != ':'; )
		;
	l = p - holdtbuf + strlen(q);
	if (l > TESTBUFSIZ) {
		write(2, "Remcap entry too long\n", 23);
		q[TESTBUFSIZ - (p-holdtbuf)] = 0;
	}
	strcpy(p, q);
	tbuf = holdtbuf;
	return (1);
}

/*
 * Tnamatch deals with name matching.  The first field of the termcap
 * entry is a sequence of names separated by |'s, so we compare
 * against each such name.  The normal : terminator after the last
 * name (before the first field) stops us.
 */
tnamatch(char *np)
{
	register char *Np, *Bp;

	Bp = tbuf;
	if (*Bp == '#')
		return (0);
	for (;;) {
		for (Np = np; *Np && *Bp == *Np; Bp++, Np++)
			continue;
		if (*Np == 0 && (*Bp == '|' || *Bp == ':' || *Bp == 0))
			return (1);
		while (*Bp && *Bp != ':' && *Bp != '|')
			Bp++;
		if (*Bp == 0 || *Bp == ':')
			return (0);
		Bp++;
	}
}

/*
 * Skip to the next field.  Notice that this is very dumb, not
 * knowing about \: escapes or any such.  If necessary, :'s can be put
 * into the termcap file in octal.
 */
static char *
tskip(char *bp)
{
	int dquote;

	dquote = 0;
	while (*bp) {
		switch (*bp) {
		case ':':
			if (!dquote)
				goto breakbreak;
			else
				bp++;
			break;
		case '\\':
			bp++;
			if (isdigit(*bp)) {
				while (isdigit(*bp++))
					;
			} else
				bp++;
		case '"':
			dquote = !dquote;
			bp++;
			break;
		default:
			bp++;
			break;
		}
	}
 breakbreak:
	if (*bp == ':')
		bp++;
	return (bp);
}

char *
nexthdr(char **bufp)
{
	register char *bp = *bufp;

	if (*bp == 0)
		return(0);
	while (*bp == ' ' || *bp == '\t' || *bp == ':')
		bp++;
	*bufp = tskip(bp);
	*(*bufp - 1) = '\0';
	return(bp);
}

/*
 * Return the (numeric) option id.
 * Numeric options look like
 *	li#80
 * i.e. the option string is separated from the numeric value by
 * a # character.  If the option is not found we return -1.
 * Note that we handle octal numbers beginning with 0.
 */
tgetnum(char *id, char *pbuf)
{
	register long int i;
	register base;
	register char *bp = pbuf;

	for (;;) {
		bp = tskip(bp);
		if (*bp == 0)
			return (-1);
		if (strncmp(bp, id, strlen(id)) != 0)
			continue;
		bp += strlen(id);
		if (*bp == '@')
			return (-1);
		if (*bp != '#')
			continue;
		bp++;
		base = 10;
		if (*bp == '0')
			base = 8;
		i = 0;
		while (isdigit(*bp))
			i *= base, i += *bp++ - '0';
		return (i);
	}
}

/*
 * Handle a flag option.
 * Flag options are given "naked", i.e. followed by a : or the end
 * of the buffer.  Return 1 if we find the option, or 0 if it is
 * not given.
 */
tgetflag(char *id, char *pbuf)
{
	register char *bp = pbuf;

	for (;;) {
		bp = tskip(bp);
		if (!*bp)
			return (0);
		if (strncmp(bp, id, strlen(id)) == 0) {
			bp += strlen(id);
			if (!*bp || *bp == ':')
				return (1);
			else if (*bp == '@')
				return (0);
		}
	}
}

/*
 * Get a string valued option.
 * These are given as
 *	cl=^Z
 * Much decoding is done on the strings, and the strings are
 * placed in area, which is a ref parameter which is updated.
 * No checking on area overflow.
 */
char *
tgetstr(char *id, char **area, char *pbuf)
{
	register char *bp = pbuf;

	for (;;) {
		bp = tskip(bp);
		if (!*bp)
			return (0);
		if (strncmp(bp, id, strlen(id)) != 0)
			continue;
		bp += strlen(id);
		if (*bp == '@')
			return (0);
		if (*bp != '=')
			continue;
		bp++;
		return (tdecode(bp, area));
	}
}

/*
 * Tdecode does the grung work to decode the
 * string capability escapes.
 */
static char *
tdecode(char *str, char **area)
{
	register char *cp;
	register int c;
	register char *dp;
	int i;
	char term;

	term = ':';
	cp = *area;
 again:
	if (*str == '"') {
		term = '"';
		str++;
	}
	while ((c = *str++) && c != term) {
		switch (c) {

		case '^':
			c = *str++ & 037;
			break;

		case '\\':
			dp = "E\033^^\\\\::n\nr\rt\tb\bf\f\"\"";
			c = *str++;
		nextc:
			if (*dp++ == c) {
				c = *dp++;
				break;
			}
			dp++;
			if (*dp)
				goto nextc;
			if (isdigit(c)) {
				c -= '0', i = 2;
				do
					c <<= 3, c |= *str++ - '0';
				while (--i && isdigit(*str));
			}
			break;
		}
		*cp++ = c;
	}
	if (c == term && term != ':') {
		term = ':';
		goto again;
	}
	*cp++ = 0;
	str = *area;
	*area = cp;
	return (str);
}
