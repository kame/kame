/*	$OpenBSD: devopen.c,v 1.3 1997/07/21 06:58:14 pefo Exp $ */

/*
 * Copyright (c) 1997 Per Fogelstrom
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
 *	This product includes software developed under OpenBSD by
 *	Per Fogelstrom.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <lib/libsa/stand.h>

static int
a2i(ch)
    char *ch;
{
	unsigned int v;

	v = *ch - '0';
	if(v > 9)
		v = 0;
	return(v);
}

int
devopen(f, fname, file)
	struct open_file *f;
	const char *fname;
	char **file;	/* out */
{
	const char *cp;
	char *ncp;
	struct devsw *dp;
	unsigned int c;
	int ctlr = 0, unit = 0, part = 0;
	char namebuf[20];
	int rc, n;

	cp = fname;
	ncp = namebuf;

	while ((c = *cp++) != '\0' && c != '(') {
		*ncp++ = c;
	}
	*ncp = '\0';

	if(c == '(') {
		/* get controller number */
		ctlr = a2i(cp);
		cp += 2;
		/* get SCSI device number */
		unit = a2i(cp);
		cp += 2;
		/* get partition number */
		part = a2i(cp);
		cp += 2;
		if (cp[-1] != ')')
			return (ENXIO);
	}

	dp = devsw;
	n = ndevs;
	while(n--) {
		if (strcmp (namebuf, dp->dv_name) == 0) {
			rc = (dp->dv_open)(f, ctlr, unit, part);
			if (!rc) {
				f->f_dev = dp;
				if (file && *cp != '\0')
					*file = (char *)cp;
			}
			return (rc);
		}
		dp++;
	}
	return ENXIO;
}
