/*	$KAME: timestamp.c,v 1.1 2001/12/28 06:38:19 k-sugyou Exp $	*/

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

/*
 * $Id: timestamp.c,v 1.1 2001/12/28 06:38:19 k-sugyou Exp $
 */

/*
 * Copyright (C) 2000 NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of NEC Corporation or any of its affiliates shall not be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NEC CORPORATION ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL NEC CORPORATION BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>

int tflag = 1;
int32_t thiszone;               /* seconds offset from gmt to local time */

int32_t
gmt2local(time_t t)
{
	register int dt, dir;
	register struct tm *gmt, *loc;
	struct tm sgmt;

	if (t == 0)
		t = time(NULL);
	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
		(loc->tm_min - gmt->tm_min) * 60;

	/*
	 * If the year or julian day is different, we span 00:00 GMT
	 * and must add or subtract a day. Check the year first to
	 * avoid problems when the julian day wraps.
	 */
	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}

void
ts_print(FILE *fp, register const struct timeval *tvp)
{
	register int s;

	if (tflag > 0) {
		/* Default */
		s = (tvp->tv_sec + thiszone) % 86400;
		(void)fprintf(fp, "%02d:%02d:%02d.%06u ",
			      s / 3600, (s % 3600) / 60, s % 60,
			      (u_int32_t)tvp->tv_usec);
	} else if (tflag < 0) {
		/* Unix timeval style */
		(void)fprintf(fp, "%u.%06u ",
		(u_int32_t)tvp->tv_sec, (u_int32_t)tvp->tv_usec);
	}
}
