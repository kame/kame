/*	$KAME: gaistatd.c,v 1.1 2001/07/04 08:02:59 jinmei Exp $ */

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
#include <sys/un.h>

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

struct gai_orderstat
{
	struct timeval start;
	struct timeval end;
	pid_t pid;
	int entries;
};

#define PATH_STATFILE "/var/run/gaistat"
#define PATH_LOGIFLE "/var/log/gai.log"

static void timeval_sub __P((struct timeval *, struct timeval *,
			     struct timeval *));

int
main()
{
	int s;
	struct sockaddr_un sun;
	struct gai_orderstat stat;

	unlink(PATH_STATFILE);

	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		exit(1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	sun.sun_len = sizeof(sun);
	strncpy(sun.sun_path, PATH_STATFILE, sizeof(sun.sun_path));
	if (bind(s, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		exit(2);

	while(1) {
		int cc;
		struct sockaddr_un from;
		struct timeval delay;
		socklen_t fromlen;
		static char timebuf[64], *timestr, *crp;
		FILE *fp;

		fromlen = sizeof(from);
		cc = recvfrom(s, &stat, sizeof(stat), 0,
			      (struct sockaddr *)&from, &fromlen);

		if (cc != sizeof(stat))
			continue; /* bogus input, ignore it. */

		memset(&delay, 0, sizeof(delay));
		timeval_sub(&stat.end, &stat.start, &delay);

		timestr = ctime(&stat.start.tv_sec);
		strncpy(timebuf, timestr, sizeof(timebuf));
		if (timebuf[sizeof(timebuf) - 1] != '\0')
			timebuf[sizeof(timebuf) - 1] = '\0';
		if ((crp = strchr(timebuf, '\n')) != NULL)
			*crp = '\0';

		if ((fp = fopen(PATH_LOGIFLE, "a+")) == NULL)
			continue;
		fprintf(fp, "%s (%lu.%06lu): pid=%d, delay=%lu.%06lu, "
			"entries=%d\n", timebuf,
			(u_long)stat.start.tv_sec, (u_long)stat.start.tv_usec,
			stat.pid, (u_long)delay.tv_sec, (u_long)delay.tv_usec,
			stat.entries);
		fclose(fp);
	}
}

/* result := a - b (assuming a > b) */
static void
timeval_sub(a, b, result)
	struct timeval *a, *b, *result;
{
	if (a->tv_usec > b->tv_usec) {
		result->tv_usec = a->tv_usec - b->tv_usec;
		result->tv_sec = a->tv_sec - b->tv_sec;
	} else {
		result->tv_usec = 1000000 + b->tv_usec - a->tv_usec;
		result->tv_sec = a->tv_sec - b->tv_sec - 1;
	}
}
