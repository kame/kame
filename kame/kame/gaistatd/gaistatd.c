/*	$KAME: gaistatd.c,v 1.7 2001/07/22 03:22:42 itojun Exp $	*/

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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/proc.h>

#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <kvm.h>
#include <limits.h>
#include <err.h>
#include <stdlib.h>

struct gai_orderstat		/* XXX: for statistics only */
{
	struct timeval start0;
	struct timeval end0;
	struct timeval start1;
	struct timeval end1;
	pid_t pid;
	int numeric;
	int entries;
	int rulestat[16];
};

#define PATH_STATFILE "/var/run/gaistat"
#define PATH_LOGIFLE "/var/log/gai.log"

int main __P((void));
static void timeval_sub __P((struct timeval *, struct timeval *,
			     struct timeval *));

int
main()
{
	int i, s;
	struct sockaddr_un sun;
	struct gai_orderstat st;
	char buf[_POSIX2_LINE_MAX];
	kvm_t *kvmd;

	unlink(PATH_STATFILE);

	if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	sun.sun_len = sizeof(sun);
	strncpy(sun.sun_path, PATH_STATFILE, sizeof(sun.sun_path));
	if (bind(s, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		err(1, "bind");

	if ((kvmd  = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, buf)) == NULL)
		errx(1, "kvm_openfiles failed");

	/* daemonize */
	daemon(0, 0);

	while(1) {
		int cc, cnt;
		struct sockaddr_un from;
		struct timeval delay0, delay1;
		socklen_t fromlen;
		static char timebuf[64], *timestr, *crp;
		struct kinfo_proc *proc;
		const char *procname = NULL;
		FILE *fp;

		fromlen = sizeof(from);
		cc = recvfrom(s, &st, sizeof(st), 0,
		    (struct sockaddr *)&from, &fromlen);

		if (cc != sizeof(st))
			continue; /* bogus input, ignore it. */

		if ((proc = kvm_getprocs(kvmd, KERN_PROC_PID, st.pid, &cnt))
		    != NULL) {
			procname = proc->kp_proc.p_comm;
		}
		if (procname == NULL)
			procname = "???";

		memset(&delay0, 0, sizeof(delay0));
		timeval_sub(&st.end0, &st.start0, &delay0);
		memset(&delay1, 0, sizeof(delay1));
		timeval_sub(&st.end1, &st.start1, &delay1);
		timestr = ctime(&st.start0.tv_sec);
		strncpy(timebuf, timestr, sizeof(timebuf));
		if (timebuf[sizeof(timebuf) - 1] != '\0')
			timebuf[sizeof(timebuf) - 1] = '\0';
		if ((crp = strchr(timebuf, '\n')) != NULL)
			*crp = '\0';

		if ((fp = fopen(PATH_LOGIFLE, "a+")) == NULL)
			continue;
		fprintf(fp, "%s (%lu.%06lu): pid=%d, proc=%s, "
			"delay0=%lu.%06lu, delay1=%lu.%06lu, numeric=%d, "
			"entries=%d, ", timebuf,
			(u_long)st.start0.tv_sec,
			(u_long)st.start0.tv_usec,
			st.pid, procname, (u_long)delay0.tv_sec,
			(u_long)delay0.tv_usec, (u_long)delay1.tv_sec,
			(u_long)delay1.tv_usec, st.numeric, st.entries);
		fprintf(fp, " rulestat: ");
		for (i = 0; i < 16; i++) {
			fprintf(fp, "%d, ", st.rulestat[i]);
		}
		fputc('\n', fp);
		fclose(fp);
	}
}

/* result := a - b (assuming a > b) */
static void
timeval_sub(a, b, result)
	struct timeval *a, *b, *result;
{

	result->tv_usec = a->tv_usec - b->tv_usec;
	result->tv_sec = a->tv_sec - b->tv_sec;
	while (result->tv_usec < 0) {
		result->tv_usec += 1000000;
		result->tv_sec--;
	}
}
