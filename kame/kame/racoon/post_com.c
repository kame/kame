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
/* YIPS @(#)$Id: post_com.c,v 1.1 1999/08/08 23:31:24 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(s)	((unsigned)(s) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(s)	(((s) & 255) == 0)
#endif
#include <sys/socket.h>

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "var.h"
#include "vmbuf.h"
#include "cfparse.h"
#include "isakmp.h"
#include "post_com.h"
#include "debug.h"
#include "misc.h"

/* the name of environment value. */
static char *info_name = "RACOON_INFO";
static char *info_dlm  = " ";

static char *exec_success = NULL;
static char *exec_failure = NULL;

static int do_child_process __P((struct isakmp_ph1 *iph1));
static int do_grandchild_process __P((char *command));
static int do_exec __P((char *str));
static RETSIGTYPE get_signal __P((int sig));
static int next_command __P((int ret));
static char **get_argv __P((char *str));
static int set_envval __P((struct isakmp_ph1 *iph1));
static int set_path __P((struct isakmp_ph1 *iph1));
static int set_info __P((struct isakmp_ph1 *iph1));

int post_command(struct isakmp_ph1 *iph1)
{
	pid_t pid;

	YIPSDEBUG(DEBUG_STAMP, plog(LOCATION, "begin.\n"));

	if ((pid = fork()) < 0) {
		plog(LOCATION, "fork (%s)\n", strerror(errno));
		return -1;
	}

	/* exit if parant's process. */
	if (pid != 0)
		return pid;

	do_child_process(iph1);
	/*NOTREACHED*/
	return -1;
}

static int do_child_process(struct isakmp_ph1 *iph1)
{
	pid_t pid;
	sigset_t sigmask;

	/* set environment value */
	if (set_envval(iph1) < 0)
		exit (1);
	
	/* child's process */
	if ((pid = fork()) < 0) {
		plog(LOCATION, "2nd fork (%s)\n", strerror(errno));
		exit (1);
	}

	if (pid != 0) {
		/* sleep if child's process. */
		sigemptyset(&sigmask);
		signal(SIGCHLD, get_signal);

		exec_success = iph1->cfp->exec_success;
		exec_failure = iph1->cfp->exec_failure;

		sigsuspend(&sigmask);
	}

	do_grandchild_process(iph1->cfp->exec_command);
	/*NOTREACHED*/
	return -1;
}

static int do_grandchild_process(char *command)
{
	/* exec command if grandchild's process. */
	YIPSDEBUG(DEBUG_STAMP,
		plog(LOCATION,
			"exec_command begin [%s]\n", command));

	if ((errno = do_exec(command)) != 0)
		exit(errno);

	exit(0);
}

static int do_exec(char *str)
{
	char **av;

	if ((av = get_argv(str)) == NULL)
		return errno;

	if (execvp(av[0], av) < 0)
		return errno;

	return 0;
}

static RETSIGTYPE get_signal(int sig)
{
	int s, ret;

	wait(&s);
	ret = WEXITSTATUS(s);

	YIPSDEBUG(DEBUG_PCOMM,
		plog(LOCATION, "get SIGCHLD, %s\n", strerror(ret)));

	next_command(ret);
}

static int next_command(int ret)
{
	if (ret == 0) {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "exec_success [%s]\n", exec_success));

		do_exec(exec_success);
	} else {
		YIPSDEBUG(DEBUG_STAMP,
			plog(LOCATION, "exec_failure [%s]\n", exec_failure));
		do_exec(exec_failure);
	}
	exit(0);
}

static char **get_argv(char *str)
{
	char *buf;
	char **av, *p;
	int i;

	i = 2;
	for (p = buf; *p != NULL; p++)
		if (*p == ' ')
			i++;

	if ((av = (char **)malloc(i * sizeof(*av))) == NULL) {
		plog(LOCATION, "malloc (%s)", strerror(errno));
		return NULL;
	}

	buf = strdup(str);

	i = 0;
	while ((p = strsep(&buf, " \t")) != NULL)
		av[i++] = strdup(p);
	av[i] = NULL;

	free(buf);

	return av;
}

/* set the parameters of phase 1 to environment value. */
static int set_envval(struct isakmp_ph1 *iph1)
{
	/* set racoon_information */
	if (set_path(iph1) < 0)
		return -1;
	if (set_info(iph1) < 0)
		return -1;

	return 0;
}

static int set_path(struct isakmp_ph1 *iph1)
{
	/* ignore if path is NULL. */
	if (iph1->cfp->exec_path == NULL)
		return 0;

	/* update PATH */
	if (setenv("PATH", iph1->cfp->exec_path, 1) < 0) {
		plog(LOCATION, "setenv (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int set_info(struct isakmp_ph1 *iph1)
{
	char addr1[BUFADDRSIZE], addr2[BUFADDRSIZE], serv[10];
	char *env = NULL;
	int len;

	/* set racoon_information */
	GETNAMEINFO(iph1->local, addr1, serv);
	GETNAMEINFO(iph1->remote, addr2, serv);

	/* get length */
	len = strlen(addr1)
		+ strlen(info_dlm)
		+ strlen(addr2)
		+ 1;	/* NULL */

	if ((env = malloc(len)) == NULL) {
		plog(LOCATION, "malloc (%s)\n", strerror(errno));
		goto bad;
	}

	strcpy(env, addr1);
	strcat(env, info_dlm);
	strcat(env, addr2);

	if (setenv(info_name, env, 1) < 0) {
		plog(LOCATION, "setenv (%s)\n", strerror(errno));
		goto bad;
	}

	free(env);
	return 0;

    bad:
	if (env != NULL)
		free(env);
	return -1;
}
