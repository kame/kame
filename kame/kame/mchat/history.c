/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
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
#include <sys/queue.h>
#include <stdlib.h>
#include <string.h>
#include "history.h"

struct entry {
	CIRCLEQ_ENTRY(entry) lists;

	char *buf;
};

CIRCLEQ_HEAD(listhead, entry) head;

int max_hist = 256;
static int n_hist;
static int cur_hist;

/*
 *	When history is "4444", "333", "22", "1",
 *	cur	next()	prev()
 *	0	null	4444
 *	1	null	333
 *	2	4444	22
 *	3	333	1
 *	4	22	null
 *	5	1	null
 */
char *
next_hist()
{
	struct entry *np;
	int i;

	np = CIRCLEQ_FIRST(&head);

	if (np == (void *)&head)
		return NULL;

	if (cur_hist == 0)
		return NULL;

	if (cur_hist == 1) {
		cur_hist--;
		return NULL;
	}

	cur_hist--;

	for (i = 0; i < cur_hist - 1; i++)
		np = CIRCLEQ_NEXT(np, lists);

	return np->buf;
}

char *
prev_hist()
{
	struct entry *np;
	int i;

	np = CIRCLEQ_FIRST(&head);

	if (np == (void *)&head)
		return NULL;

	if (cur_hist == n_hist)
		return CIRCLEQ_LAST(&head)->buf;

	for (i = 0; i < cur_hist; i++)
		np = CIRCLEQ_NEXT(np, lists);

	cur_hist++;

	return np->buf;
}

/*
 * buf must be terminated by '\0'
 */
int
ins_hist(buf)
	char *buf;
{
	struct entry *new;
	int len;

	len = strlen(buf) + 1;	/* + '\0' */

	if (n_hist > max_hist) {
		free(CIRCLEQ_LAST(&head)->buf);
		free(CIRCLEQ_LAST(&head));
	}

	if ((new = (struct entry *)malloc(sizeof(struct entry))) == NULL)
		return -1;
	if ((new->buf = (char *)malloc(len)) == NULL) {
		free(new);
		return -1;
	}

	memcpy(new->buf, buf, len);

	CIRCLEQ_INSERT_HEAD(&head, new, lists);
	n_hist++;

	return 0;
}

void
flush_hist()
{
	while (CIRCLEQ_FIRST(&head) != (void *)&head) {
		struct entry *curelm;
		curelm = CIRCLEQ_FIRST(&head);
		CIRCLEQ_REMOVE(&head, curelm, lists);
		free(curelm->buf);
		free(curelm);
	}
}

void
init_curhist()
{
	cur_hist = 0;
}

void
init_hist()
{
	CIRCLEQ_INIT(&head);
	init_curhist();
	n_hist = 0;
}

#ifdef HDEBUG
main()
{
	struct entry *np;
	int i;

	init_hist();

	ins_hist("1");
	ins_hist("22");
	ins_hist("333");
	ins_hist("4444");

	CIRCLEQ_FOREACH(np, &head, lists) {
		printf("%s\n", np->buf);
	}

	printf("next = %s\n", next_hist());
	printf("prev = %s\n", prev_hist());
	printf("prev = %s\n", prev_hist());
	printf("prev = %s\n", prev_hist());
	printf("prev = %s\n", prev_hist());
	printf("prev = %s\n", prev_hist());
	printf("next = %s\n", next_hist());
	printf("next = %s\n", next_hist());
	printf("next = %s\n", next_hist());
	printf("next = %s\n", next_hist());
	printf("next = %s\n", next_hist());

	flush_hist();
}
#endif
