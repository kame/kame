/*
 * Copyright (C) 1999 WIDE Project.
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

/*	$Id: mprecv.c,v 1.2 1999/12/07 14:03:57 itojun Exp $	*/

#include "mping.h"

struct lost_history {
	time_t	lh_time;	/* expected arrival time of first lost packet */
	u_long	lh_duration;	/* duration of lost packets */
	int	lh_reported;	/* if 1, it is already logged */
};

struct session {
	u_long	s_rid;			/* struct index */
	struct	sockaddr_in6 saddr;
	struct	timeval s_interval;
	u_long	s_count;		/* packet count */
	u_long	s_id;			/* session id */
	u_long	ss_init;		/* initial sequence # */
	u_long	ss_last;		/* last sequence # */
	struct	timeval	st_init;	/* initial received */
	struct	timeval	st_last;	/* last received */

	u_long	sl_count;		/* lost count */
	u_long	sl_packet;		/* lost packet count */
	struct	lost_history	s_lh[MAX_LOST_HISTORY];
	int	s_lh_overflow;

	u_long	si_num;			/* number of samples */
	double 	si_sum;			/* sum of receive interval */
	double 	si_sum2;		/* sum of sqr(receive interval) */

	struct session *s_next;
};

struct session *slist;

char *port = DEFAULT_PORT;
char *maddr = NULL;
char *ifname = NULL;
int daemonize = 0;
int verbose = 0;
int interval = DEFAULT_LOG_INTERVAL;
char *logfile = DEFAULT_LOGFILE;
char *dumpfile = DEFAULT_DUMPFILE;
time_t ses_expire = DEFAULT_SESSION_EXPIRE;
FILE *lfp = NULL;
int srid = 1;
char *argv0;
int nhistory = MAX_LOST_HISTORY;

struct mping *mp;
struct addrinfo *res;

static char *month[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

void receive __P((int));
void move_lost_history __P((struct session *));
void log_open __P((char *, char *));
void log_close __P((void));
void log_date_msg __P((char *));
void log_sp __P((struct session *, int));
void log_output __P((int));
void clear_interval __P((int));
void usage __P((void));

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch, s, error;
	struct addrinfo hints;
	FILE *fp;

	argv0 = *argv;
	while ((ch = getopt(argc, argv, "di:m:p:vD:H:L:T:X:")) != -1)
		switch (ch) {
		case 'd':
			daemonize = 1;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'm':
			maddr = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'D':
			dumpfile = optarg;
			break;
		case 'H':
			nhistory = atoi(optarg);
			if (nhistory > MAX_LOST_HISTORY) {
				fprintf(stderr, "Max # of lost history is %d\n",
					MAX_LOST_HISTORY);
				nhistory = MAX_LOST_HISTORY;
			}
			break;
		case 'L':
			logfile = optarg;
			break;
		case 'T':
			interval = atoi(optarg);
			break;
		case 'X':
			ses_expire = atoi(optarg) * 3600 * 24;
			break;
		default:
			usage();
			exit(0);
		}
	argc -= optind;
	argv += optind;

	if (daemonize && getuid() != 0) {
		fprintf(stderr, "Only superuser can specify daemon mode\n");
		exit(-1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(maddr, port, &hints, &res);
	if (error)
		err(1, "%s", gai_strerror(error));

	if (verbose) {
		int i;
		u_char *p;

		fprintf(stderr, "%s configuration is:\n", argv0);
		fprintf(stderr, "\tport:        %s\n", port);
		fprintf(stderr, "\tai_family:   %d\n", res->ai_family);
		fprintf(stderr, "\tai_socktype: %d\n", res->ai_socktype);
		fprintf(stderr, "\tai_protocol: %d\n", res->ai_protocol);
		fprintf(stderr, "\tai_addrlen:  %d\n", res->ai_addrlen);
		fprintf(stderr, "\tai_addr:     ");
		for (i = res->ai_addrlen, p = (u_char *)res->ai_addr;
			i; i--, p++) {
			fprintf(stderr, "%02x ", *p);
			if (i == 21)
				fprintf(stderr, "\n\t\t     ");
		}
		fprintf(stderr, "\n");
	}

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
		err(1, NULL);
	if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
		err(1, NULL);

	if (IN6_IS_ADDR_MULTICAST(&(((struct sockaddr_in6 *)(res->ai_addr))->sin6_addr))) {
		struct ipv6_mreq mreq6;

		if (ifname == NULL) {
			fprintf(stderr, "ifname is required for multicast\n");
			exit(-1);
		}

		if ((mreq6.ipv6mr_interface = if_nametoindex(ifname)) == 0)
			err(1, "if_nametoindex");
		if (verbose)
			fprintf(stderr, "\tifindex: %d\n",
				mreq6.ipv6mr_interface);
		memcpy(&mreq6.ipv6mr_multiaddr,
			&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
			sizeof(mreq6.ipv6mr_multiaddr));
		if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			&mreq6, sizeof(mreq6)))
			err(1, "setsockopt(IPV6_JOIN_GROUP)");
	}

	if (daemonize && verbose == 0) {
		if (daemon(0, 0) != 0)
			err(1, "daemon");
		if ((fp = fopen(PID_FILE, "w")) == NULL)
			err(1, PID_FILE);
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	} else {
		lfp = stdout;
	}

	log_open(logfile, "a");
	log_date_msg("mprecv start");
	log_close();

	signal(SIGINT, log_output);
	signal(SIGTERM, log_output);
	signal(SIGQUIT, log_output);
	signal(SIGINFO, log_output);
	signal(SIGALRM, log_output);
	signal(SIGWINCH, clear_interval);

	alarm(interval);

	for (;;) {
		receive(s);
	}

	exit(0);
	/*NOTREACHED*/
}

void
receive(s)
	int s;
{
	int cc, fromlen;
	double t_int;
	struct timeval tv;
	struct sockaddr_in6 from6;
	struct session *sp;
	struct mping *mp;
	u_char *buf[MAX_MSGSIZE];

	fromlen = sizeof(from6);
	cc = recvfrom(s, buf, sizeof(buf), 0,
			(struct sockaddr *)&from6, &fromlen);
	if (cc < 0)
		err(1, "recvfrom");
	if (verbose)
		printf("%d bytes recvd\n", cc);
	mp = (struct mping *)buf;
	for (sp = slist; sp; sp = sp->s_next) {
		if (IN6_ARE_ADDR_EQUAL(&from6.sin6_addr,
			&sp->saddr.sin6_addr))
			break;
	}
	gettimeofday(&tv, NULL);
	if (sp == NULL)	{			/* allocate new session */
		sp = (struct session *)malloc(sizeof(struct session));
		memset(sp, 0, sizeof(struct session));
		sp->s_next = slist;
		slist = sp;
		memcpy(&sp->saddr, &from6, sizeof(struct sockaddr_in6));
		sp->st_init = tv;
		sp->ss_init = mp->m_seq;
		sp->s_rid = srid++;
		sp->s_id = mp->m_sessid;
		sp->ss_last = mp->m_seq;
		log_open(logfile, "a");
		log_date_msg("new sender detected");
		log_sp(sp, 0);
		log_close();
	} else if (sp->s_id != mp->m_sessid) {	/* sender restarted */
		/* dump info regarding the last session */
		log_open(logfile, "a");
		log_date_msg("session terminiation detected");
		log_sp(sp, 0);
		log_close();
		sp->st_init = tv;
		sp->ss_init = mp->m_seq;
		sp->s_id = mp->m_sessid;
		sp->s_count = 0;
		sp->sl_count = 0;
		sp->sl_packet = 0;
		move_lost_history(sp);
		sp->s_lh[0].lh_time = 0;
		sp->s_lh[0].lh_duration = 0;
		sp->s_lh[0].lh_reported = 0;
	} else if (sp->ss_last > 0 && sp->ss_last + 1 < mp->m_seq) {
		move_lost_history(sp);
		sp->s_lh[0].lh_time =
			sp->st_last.tv_sec + mp->m_interval.tv_sec;
		sp->s_lh[0].lh_duration = tv.tv_sec - sp->s_lh[0].lh_time;
		sp->s_lh[0].lh_reported = 0;
		sp->sl_count++;
		sp->sl_packet += mp->m_seq - (sp->ss_last + 1);
	} else if (sp->ss_last > 0) {
		sp->si_num++;
		t_int = tv.tv_sec - sp->st_last.tv_sec +
			(tv.tv_usec - sp->st_last.tv_usec) * 0.000001;
		sp->si_sum += t_int;
		sp->si_sum2 += t_int * t_int;
	}
	sp->s_interval = mp->m_interval;
	sp->st_last = tv;
	sp->ss_last = mp->m_seq;
	sp->s_count++;
}

void
move_lost_history(sp)
	struct session *sp;
{
	int i;

	if (sp->s_lh[nhistory - 1].lh_time > 0)
		sp->s_lh_overflow++;
	for (i = nhistory - 2; i > 0; i--) {
		sp->s_lh[i + 1] = sp->s_lh[i];
	}
	sp->s_lh[0].lh_time = 0;
	sp->s_lh[0].lh_duration = 0;
}

void
log_open(fname, mode)
	char *fname, *mode;
{
	if (lfp != stdout) {
		if ((lfp = fopen(fname, mode)) == NULL)
			err(1, "%s", fname);
	}
}

void
log_close()
{
	if (lfp != stdout) {
		fclose(lfp);
		lfp = NULL;
	}
}

/*
 * Print heading line of each log chunk
 */
void
log_date_msg(msg)
	char *msg;
{
	time_t t;
	struct tm *tm;

	t = time(0);
	tm = localtime(&t);
	fprintf(lfp, "%s %2d %02d:%02d:%02d ========== %s\n",
		month[tm->tm_mon],
		tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, msg);
}

/*
 * Write log information to specified session
 */
void
log_sp(sp, force)
	struct session *sp;
	int force;
{
	int i;
	double mean, mean2, sd;
	time_t t;
	struct tm *tm;
	struct lost_history *lhp;
	char buf[BUFSIZ];

	getnameinfo((struct sockaddr *)&sp->saddr, sizeof(sp->saddr),
		buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
	fprintf(lfp, "[%02ld] host %s (%lu)\n", sp->s_rid,
		buf, sp->s_id);
	t = (time_t)sp->st_last.tv_sec;
	tm = localtime(&t);
	fprintf(lfp, "[%02ld] last read %s %2d %02d:%02d:%02d,",
		sp->s_rid, month[tm->tm_mon],
		tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
	fprintf(lfp, " elapsed %lu sec, last read %lu sec ago\n",
		sp->st_last.tv_sec - sp->st_init.tv_sec,
		time(0) - sp->st_last.tv_sec);
	fprintf(lfp, "[%02ld] seq init %lu last %lu diff %lu\n", sp->s_rid,
		sp->ss_init, sp->ss_last,
		sp->ss_last - sp->ss_init);
	if (sp->si_num > 0) {
		mean = sp->si_sum / sp->si_num;
		mean2 =  sp->si_sum2 / sp->si_num;
		sd = sqrt(mean2 - mean * mean);
		fprintf(lfp, "[%02ld] %ld sample mean %6.3f sec sd %6.3f sec\n",
			sp->s_rid, sp->si_num, mean, sd);
	}
	fprintf(lfp, "[%02ld] count total %ld lost %ld lost packets %ld\n",
		sp->s_rid, sp->s_count, sp->sl_count, sp->sl_packet);
	for (i = nhistory - 1; i >= 0; i--) {
		lhp = &sp->s_lh[i];
		if (lhp->lh_reported != 0 && force == 0)
			continue;
		if (lhp->lh_time > 0) {
			tm = localtime(&lhp->lh_time);
			fprintf(lfp, "[%02ld] last lost %s %2d %02d:%02d:%02d,",
				sp->s_rid, month[tm->tm_mon],
				tm->tm_mday, tm->tm_hour, tm->tm_min,
				tm->tm_sec);
			fprintf(lfp, " for %ld sec\n", lhp->lh_duration);
			lhp->lh_reported = 1;
		}
	}
	if (sp->s_lh_overflow > 0)
		fprintf(lfp, "[%02ld] %d lost history overwritten\n",
			sp->s_rid, sp->s_lh_overflow);
	if (force == 0)
		sp->s_lh_overflow = 0;
}

void
log_output(sig)
	int sig;
{
	struct session *sp;
	int force;

	force = 0;
	switch (sig) {
	case SIGALRM:
		log_open(logfile, "a");
		log_date_msg("periodic log dump");
		break;
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		log_open(logfile, "a");
		log_date_msg("mprecv terminating");
		break;
	case SIGINFO:
		log_open(dumpfile, "w");
		log_date_msg("operator driven log dump");
		force = 1;
		break;
	}

	for (sp = slist; sp; sp = sp->s_next)
		log_sp(sp, force);

	log_close();

	if (sig == SIGALRM)
		alarm(interval);
	if (sig == SIGINT || sig == SIGTERM || sig == SIGQUIT) {
		fclose(lfp);
		unlink(PID_FILE);
		exit(0);
	}
}

void
clear_interval(sig)
	int sig;
{
	struct session *sp;

	for (sp = slist; sp; sp = sp->s_next) {
		sp->si_num = 0;
		sp->si_sum = 0.0;
		sp->si_sum2 = 0.0;
	}
}

void
usage()
{
	fprintf(stderr, "Usage: %s [-d][-p port][-v][-D dumpfile][-L logfile][-T loginterval]-i interface -m mcastaddr\n", argv0);
}
