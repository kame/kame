/*	$KAME: command.c,v 1.1 2004/12/09 02:18:31 t-momose Exp $	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <poll.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "fdlist.h"
#include "command.h"

static struct sockaddr_in6 sin6_ci;
char *prompt = "> ";


void command_help(int, char *);
void quit_ui(int, char *);
int command_in(int);
int new_connection(int);
#define disp_prompt(s)	write((s), prompt, strlen(prompt))

struct command_table basic_command_table[] = {
	{"help", command_help, "Show help"},
	{"?", command_help, "Show help"},
	{"quit", quit_ui, "Quit the shell"},
};
struct command_table *commands;

int
command_init(p, cmdset, cmdset_size, port)
	char *p;
	struct command_table *cmdset;
	size_t cmdset_size;
	u_short port;
{
	int i, s;
	int s_optval = 1;
	struct command_table *c;

	s = socket(PF_INET6, SOCK_STREAM, 0);
	if (s < 0) {
		perror("command: socket");
		return (-1);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			&s_optval, sizeof(s_optval)) == -1) {
		perror("command: setsockopt");
		return (-1);
	}

	/* Configuration channel is bound to only IPv6 */
	bzero(&sin6_ci, sizeof(sin6_ci));
	sin6_ci.sin6_family = AF_INET6;
	sin6_ci.sin6_len = sizeof(sin6_ci);
	sin6_ci.sin6_addr = in6addr_loopback;
	sin6_ci.sin6_port = htons(port);
	if (bind(s, (struct sockaddr *)&sin6_ci, sizeof(sin6_ci)) < 0) {
		perror("command: bind");
		goto bad;
	}
	if (listen(s, 1) < 0) {
		perror("command: listen");
		goto bad;
	}

	commands = malloc((cmdset_size + sizeof(basic_command_table) / sizeof(struct command_table) + 1) * sizeof(struct command_table));
	if (commands == NULL) {
		perror("command: malloc");
		goto bad;
	}
	c = commands;
	for (i = 0; i < sizeof(basic_command_table) / sizeof(struct command_table); i++)
		*c++ = basic_command_table[i];
	for (i = 0; i < cmdset_size; i++)
		*c++ = cmdset[i];
	bzero(c, sizeof(struct command_table));

	new_fd_list(s, POLLIN, new_connection);
	prompt = p;

	return (s);

 bad:
	close(s);
	return (-1);
}

int
new_connection(s)
	int s;
{
	int ss;
	struct sockaddr_in6 sin6;
	size_t sin6len;

	sin6len = sizeof(struct sockaddr_in6);
	if ((ss = accept(s, (struct sockaddr *)&sin6, &sin6len)) < 0) {
		perror("command: accept");
		return -1;
	}
	
	new_fd_list(ss, POLLIN, command_in);
	disp_prompt(ss);
	return (0);
}

int
command_in(s)
	int s;
{
	int bytes;
	char buffer[2048];
	struct command_table *ctbl;
	char *errmsg = "??? unknown command\n";
	
	bytes = read(s, buffer, 2048);

	buffer[bytes] = '\0';
	while (strlen(buffer) && isspace(buffer[strlen(buffer) - 1]))
		buffer[strlen(buffer) - 1] = '\0';
	if (strlen(buffer) == 0)
		goto prompt;

	for (ctbl = commands; ctbl->command != NULL; ctbl++) {
		if (strncmp(ctbl->command, buffer, strlen(ctbl->command)) == 0) {
			char *arg = buffer + strlen(ctbl->command);

			while (isspace(*arg))
				arg++;
			(*ctbl->cmdfunc)(s, arg);
			goto prompt;
		}
	}

	write(s, errmsg, strlen(errmsg));

 prompt:
	disp_prompt(s);
	return (0);
}

void
command_help(s, line)
	int s;
	char *line;
{
	char msg[1024];
	struct command_table *ctbl;
	
	for (ctbl = commands; ctbl->command != NULL; ctbl++) {
		sprintf(msg, "%-10s - %s\n", ctbl->command, ctbl->helpmsg);
		write(s, msg, strlen(msg));
	}
}

void
quit_ui(s, line)
	int s;
	char *line;
{
	char *msg = "bye bye\n";

	write(s, msg, strlen(msg));
	delete_fd_list_entry(s);
	close(s);
}
