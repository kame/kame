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
/* YIPS @(#)$Id: schedule.c,v 1.1.1.1 1999/08/08 23:31:25 itojun Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>

#include "var.h"
#include "vmbuf.h"
#include "schedule.h"
#include "admin.h"
#include "misc.h"
#include "debug.h"

struct schedtab sctab;

static int sched_check __P((struct sched *, int));
static int sched_free __P((struct sched *));
static struct sched *sched_search __P((sched_index *));

static int sched_copy_index __P((sched_index *, sched_index *));

/*
 * schedule handler
 *   return:
 *     number of schedule.
 */
int
schedular(num)
	int num;
{
	static time_t oldt = 0;
	time_t newt, diff;
	struct sched *sc, *next;

	newt = time((time_t *)0);
	if (num)
		diff = newt - oldt;
	else
		diff = 0;

	oldt = newt;

	num = 0;
	for (sc = sctab.head; sc; sc = next) {
		next = sc->next;

		switch (sc->status) {
		case SCHED_ON:
			if (sched_check(sc, diff) < 0) {
				return(-1);
			}
			num++;
			break;

		case SCHED_DEAD:
			if (sched_free(sc) < 0) {
				return(-1);
			}
			break;

		case SCHED_OFF:
		default:
			/* ignore */
			break;
		}
	}

	YIPSDEBUG(DEBUG_SCHED2,
		plog(LOCATION, "# of schedule = %d.\n", num));

	return(num);
}

/* check timer */
static int
sched_check(sc, diff)
	struct sched *sc;
	int diff;
{
	int error = -1;

	if (sc->tick - diff <= 0) {

		YIPSDEBUG(DEBUG_SCHED2,
		    plog(LOCATION, "tick over #%s\n", sched_pindex(&sc->index)));

		/* check try counter */
		if (sc->try - 1 <= 0) {
			YIPSDEBUG(DEBUG_SCHED2,
			    plog(LOCATION, "try over #%s\n", sched_pindex(&sc->index)));

			if (sc->f_over != 0) {
				(void)(sc->f_over)(sc);
			} else {
				YIPSDEBUG(DEBUG_SCHED,
				    plog(LOCATION, "f_over() is null. why ?\n"));
				goto end;
			}

		} else {
			if (sc->f_try != 0) {
				(void)(sc->f_try)(sc);
			} else {
				YIPSDEBUG(DEBUG_SCHED,
				    plog(LOCATION, "f_try() is null. why ?\n"));
				goto end;
			}

			sc->try--;
		}

	} else
		sc->tick -= diff;

	error = 0;

end:
	return(error);
}

/*
 * sched_add
 *   allocate to schedule, and copy to index.
 */
struct sched *
sched_add(tick, f_try, try, f_over, ptr1, ptr2, id)
	u_int tick, try;
	int (*f_try)(), (*f_over)();
	caddr_t ptr1, ptr2;
	int id;
{
	struct sched *new;
	static sched_index index = 1;

	/* diagnostic */
	if (sched_search(&index) != 0) {
		YIPSDEBUG(DEBUG_SCHED,
		    plog(LOCATION, "why already exists, (%s)\n", sched_pindex(&index)));
		return(0);
	}

	if ((new = (struct sched *)malloc(sizeof(*new))) == 0) {
		YIPSDEBUG(DEBUG_SCHED,
		    plog(LOCATION, "malloc (%s)\n", strerror(errno)));
		return(0);
	}

	memset((char *)new, 0, sizeof(*new));
	new->status = SCHED_ON;
	new->tick   = tick;
	new->try    = try;
	new->f_try  = f_try;
	new->f_over = f_over;
	new->ptr1   = ptr1;
	new->ptr2   = ptr2;
	new->identifier   = id;

	sched_copy_index(&new->index, &index);

	/* add to schedule table */
	new->next = (struct sched *)0;
	new->prev = sctab.tail;

	if (sctab.tail == 0)
		sctab.head = new;
	else
		sctab.tail->next = new;
	sctab.tail = new;
	sctab.len++;

	YIPSDEBUG(DEBUG_SCHED,
	    plog(LOCATION, "add schedule, tick=%u (#%s)\n",
	    tick, sched_pindex(&index)));

	/* increment index */
	index++;

	return(new);
}

void
sched_kill(sc)
	struct sched **sc;
{
	YIPSDEBUG(DEBUG_SCHED,
	    plog(LOCATION,
		"kill schedule, (%s)\n", sched_pindex(&(*sc)->index)));

	(*sc)->status = SCHED_DEAD;
	(*sc)->tick = 0;
	(*sc)->try = 0;

	*sc = NULL;

	return;
}

/* free schedule */
static int
sched_free(sc)
	struct sched *sc;
{
	if (sched_search(&sc->index) == 0) {
		YIPSDEBUG(DEBUG_SCHED,
		    plog(LOCATION, "not exists, (%s)\n", sched_pindex(&sc->index)));
		return(-1);
	}

	/* reap from schedule table */
	/* middle */
	if (sc->prev && sc->next) {
		sc->prev->next = sc->next;
		sc->next->prev = sc->prev;
	} else
	/* tail */
	if (sc->prev && sc->next == 0) {
		sc->prev->next = (struct sched *)0;
		sctab.tail = sc->prev;
	} else
	/* head */
	if (sc->prev == 0 && sc->next) {
		sc->next->prev = (struct sched *)0;
		sctab.head = sc->next;
	} else {
	/* last one */
		sctab.head = (struct sched *)0;
		sctab.tail = (struct sched *)0;
	}

	sctab.len--;

#if 0
	YIPSDEBUG(DEBUG_SCHED,
	    plog(LOCATION, "free schedule (%s)\n", sched_pindex(&sc->index)));
#endif

	(void)free(sc);

	return(0);
}

/* search schedule */
static struct sched *
sched_search(index)
	sched_index *index;
{
	struct sched *sc;

	for (sc = sctab.head; sc; sc = sc->next) {
		if (memcmp((char *)&sc->index, (char *)index, sizeof(*index)) == 0)
			return(sc);
	}

	return(0);
}

/*
 * copy index to dst from src
 */
static int
sched_copy_index(dst, src)
	sched_index *dst, *src;
{
	memcpy((caddr_t)dst, (caddr_t)src, sizeof(*dst));

	return(0);
}

vchar_t *
sched_dump()
{
	struct sched *dst, *src;
	vchar_t *buf;
	int tlen;

	tlen = sizeof(struct sched) * sctab.len;

	if ((buf = vmalloc(tlen)) == NULL) {
		plog(LOCATION, "vmalloc(%s)\n", strerror(errno));
		return NULL;
	}
	dst = (struct sched *)buf->v;
	for (src = sctab.head; src; src = src->next) {
		memcpy((caddr_t)dst, (caddr_t)src, sizeof(*dst));
		dst++;
	}

	return buf;
}

/*
 * make strings of index of schedule.
 */
char *
sched_pindex(index)
	sched_index *index;
{
	static char buf[48];
	caddr_t p = (caddr_t)index;
	int len = sizeof(*index);
	int i, j;

	for (j = 0, i = 0; i < len; i++) {
		snprintf((char *)&buf[j], sizeof(buf) - j, "%02x", p[i]);
		j += 2;
	}

	return buf;
}

/* initialize schedule table */
int
sched_init(void)
{
	memset((char *)&sctab, 0, sizeof(sctab));
	return 0;
}

