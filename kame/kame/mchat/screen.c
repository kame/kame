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
#include <sys/ioctl.h>
#include <termios.h>
#include <curses.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
#include <err.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include "screen.h"
#include "history.h"

#ifdef CTRL
#undef CTRL
#endif
#define CTRL(x)	(((x) & ~0x20) - '@')

#ifdef min
#undef min
#endif
#define min(a,b)	((a) < (b) ? (a) : (b))

struct window {
	WINDOW *w;
	int wl;		/* lines of window */
	int wc;		/* colums of window */
	int wy;		/* window y position in screen */
	int wx;		/* window x position in screen */
	char *wbuf;	/* buffer of window */
	int cy;		/* cursor y position in window */
	int cx;		/* cursor x position in window */
#if notyet
	char *lbuf;
#endif
	int bl;		/* length of line buffer */
	int bx;		/* x position in buffer */
#define ISWCTOP(wp)	((wp)->cy == 0)
#define ISWCBOTTOM(wp)	((wp)->cy == (wp)->wl - 1)
#define ISWCLEFT(wp)	((wp)->cx == 0)
#define ISWCRIGHT(wp)	((wp)->cx == (wp)->wc - 1)
#define ISWCEND(wp)	(ISWCBOTTOM(wp) && ISWCRIGHT(wp))
#define ISWCHOME(wp)	(ISWCTOP(wp) && ISWCLEFT(wp))
};

#define WGROSS(wp)	((wp)->wl * (wp)->wc)

extern int dumbterm;
extern int debug;

static struct window wroot, wrecv, wstat, wsend, wcent;

static int wsend_lines = 3;
static int use_curses = 0;

static int wvprintw __P((struct window *w, const char *fmt, va_list ap));
static int wvnprintw __P((struct window *w, const char *fmt, va_list ap));
static void init_window __P((struct window *w, int wl, int wc, int wy, int wx));
static void sigwinch __P((int sig));
static void del_window __P((struct window *w));
static void wputstr __P((WINDOW *w, char *buf, int begin, int end));
static void w_printinfo __P((struct window *wp));
static void w_printdebug __P((struct window *wp));
static void w_putremain __P((struct window *wp, char *buf));
static void w_deleteline __P((struct window *wp));
static void w_curback __P((struct window *wp, char *buf));
static void w_refresh __P((struct window *wp, char *buf));

int
init_screen(init)
	int init;
{
	struct winsize ws;
	WINDOW *wp;

	signal(SIGWINCH, SIG_DFL);

	/* get screen size */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
		err(1, "ioctl");
#if 0
	if (ws.ws_row == 0)
		ws.ws_row = 24;
	if (ws.ws_col == 0)
		ws.ws_col = 80;
#endif

	/* if dumb mode is requested, obey. */
	if (dumbterm) {
		use_curses = 0;
		return 0;
	}

	/* if screen became too small or bogus size, use dumb terminal. */
	if (ws.ws_col < 10 || ws.ws_row < 10) {
		fprintf(stderr, ">> terminal too small.\n");
		use_curses = 0;
		return 0;
	}

	/* if initscr() failed, use dumb terminal. */
	wp = initscr();
	if (wp == NULL) {
		use_curses = 0;
		return 0;
	}
	wroot.w = wp;
	use_curses = 1;
	wroot.wl = ws.ws_row;
	wroot.wc = ws.ws_col;
	resetty();

	signal(SIGWINCH, sigwinch);

	init_window(&wsend, wsend_lines, ws.ws_col,
			ws.ws_row - wsend_lines - 1, 0);
	init_window(&wcent, 1, ws.ws_col, ws.ws_row - wsend_lines - 2, 0);
	init_window(&wstat, 1, ws.ws_col, ws.ws_row - 1, 0);
	init_window(&wrecv, ws.ws_row - wsend_lines - 1 - 1, ws.ws_col, 0, 0);

	scrollok(wrecv.w, TRUE);
	wmove(wrecv.w, 0, 0);

	scrollok(wsend.w, TRUE);
	wmove(wsend.w, 0, 0);
	noecho();
	cbreak();

	/* draw center line */
    {
	int i = wcent.wc;
	while (i--)
		waddch(wcent.w, '-');
    }

	wrefresh(wrecv.w);
	wrefresh(wcent.w);
	wrefresh(wsend.w);

	return 0;
}

int
wmsgcheck(msgbuf, maxlen)
	char *msgbuf;
	int maxlen;
{
	struct window *wp = &wsend;
	int c;
	int i;

	if (!use_curses) {
		memset(msgbuf, 0, maxlen);
		i = read(STDIN_FILENO, msgbuf, maxlen);
		if (msgbuf[i - 1] == '\n')
			msgbuf[i - 1] = '\0';
		return 1;
	}

	c = wgetch(wp->w);
	if (wp->bl == maxlen)
		return 0;

   {
	int y, x;
	getyx(wp->w, y, x);
	assert(wp->cy == y && wp->cx == x);
   }

	switch (c) {
	/*
	 * move cursor
	 */
	case CTRL('A'):	/* move cursor to the head of buffer */
		if (wp->bx == 0)
			return 0;
		if (wp->bl >= WGROSS(wp)) {
			wclear(wp->w);
			wmove(wp->w, 0, 0);
			wputstr(wp->w, msgbuf, 0, WGROSS(wp));
			wp->cy = 0;
			wp->cx = 0;
		} else {
			wp->cy = wp->cy - wp->bx / wp->wc;
			wp->cx = 0;
		}
		wmove(wp->w, wp->cy, wp->cx);
		wp->bx = 0;
		break;
	case CTRL('E'): /* move cursor to the end of buffer */
		if (wp->bx == wp->bl)
			return 0;
		if (wp->bl >= WGROSS(wp)) {
			wclear(wp->w);
			wmove(wp->w, 0, 0);
			wputstr(wp->w, msgbuf, 0, wp->bl);
			getyx(wp->w, wp->cy, wp->cx);
			if (ISWCEND(wp)) {
				scroll(wp->w);
				wp->cy = wp->wl - 1;
				wp->cx = 0;
			}
		} else {
			wp->cy = wp->cy + (wp->bl - wp->bx) / wp->wc;
			wp->cx = wp->bl % wp->wc;
		}
		wmove(wp->w, wp->cy, wp->cx);
		wp->bx = wp->bl;
		break;
	case CTRL('B'): /* move cursor to backward */
		if (wp->bx == 0)
			return 0;
		w_curback(wp, msgbuf);
		break;
	case CTRL('F'): /* move cursor to forward */
		if (wp->bx == wp->bl)
			return 0;
		if (ISWCEND(wp)) {
			scroll(wp->w);
			wmove(wp->w, wp->cy, 0);
			wputstr(wp->w, msgbuf, wp->bx + 1, min(wp->bx + 1 + wp->wc, wp->bl));
			wp->cy = wp->wl - 1;
			wp->cx = 0;
		} else if (ISWCRIGHT(wp)) {
			wp->cy++;
			wp->cx = 0;
		} else {
			wp->cx++;
		}
		wmove(wp->w, wp->cy, wp->cx);
		wp->bx++;
		break;
	case CTRL('I'): /* IGNORE tab */
		return 0;
		break;
	case CTRL('L'):	/* refresh screen */
		w_refresh(wp, msgbuf);
		break;

	/*
	 * edit buffer
	 */
	case CTRL('U'):	/* erase line */
		w_deleteline(wp);
		break;
	case CTRL('K'):	/* erase eol */
	    {
		int j;
		wclrtoeol(wp->w);
		j = min(wp->wl - 1, (wp->bl / wp->wc) - (wp->bx / wp->wc));
		wmove(wp->w, wp->cy + 1, 0);
		for (i = 0; i < j; i++)
			wdeleteln(wp->w);
		wmove(wp->w, wp->cy, wp->cx);
		wp->bl = wp->bx;
	    }
		break;
	case '\b':	/* erase backword */
		if (wp->bx == 0)
			return 0;
		w_curback(wp, msgbuf);

		for (i = wp->bx; i < wp->bl; i++)
			msgbuf[i] = msgbuf[i + 1];
		/* XXX... */
		msgbuf[wp->bl - 1] = ' ';
		w_putremain(wp, msgbuf);
		wmove(wp->w, wp->cy, wp->cx);
		wp->bl--;
		break;
	case CTRL('W'): /* backward word erase */
		/* Not yet... */
	    {
		int bx;
		int f = isalnum(msgbuf[wp->bx]);
			
		if (wp->bx == 0)
			return 0;

		for (bx = wp->bx; isgraph(msgbuf[bx]) == 0; bx--)
			;
		for (; bx != 0; bx--) {
			if (f && isalnum(msgbuf[bx]))
				continue;
			if (isgraph(msgbuf[bx]))
				continue;
			break;
		}
		memcpy(msgbuf + bx, msgbuf + wp->bx, wp->bl - wp->bx);
		wp->bl = bx + wp->bl - wp->bx;
		wp->bx = bx;
	    }

		w_refresh(wp, msgbuf);
		break;
	case CTRL('P'):
		w_deleteline(wp);
	    {
		char *p;

		/* get history */
		p = prev_hist();
		if (p == NULL)
			break;
		wp->bl = strlen(p);
		wp->bx = wp->bl;
		memcpy(msgbuf, p, wp->bl);

		/* draw a history */
		wputstr(wp->w, msgbuf, 0, wp->bl);
		getyx(wp->w, wp->cy, wp->cx);
	    }
		break;
		
	case CTRL('N'):
		w_deleteline(wp);
	    {
		char *p;

		/* get history */
		p = next_hist();
		if (p == NULL)
			break;
		wp->bl = strlen(p);
		wp->bx = wp->bl;
		memcpy(msgbuf, p, wp->bl);

		/* draw a history */
		wputstr(wp->w, msgbuf, 0, wp->bl);
		getyx(wp->w, wp->cy, wp->cx);
	    }
		break;

	case '\r':	/* commit message */
	case '\n':	/* commit message */
		wmove(wp->w, wp->cy, wp->bl);
		waddch(wp->w, c);
		wrefresh(wp->w);
		getyx(wp->w, wp->cy, wp->cx);

		if (wp->bl == 0) {
			/* to avoid `enter key' storm */
			wrecv_print("\n");
			return 0;
		}

		msgbuf[wp->bl] = '\0';

		ins_hist(msgbuf);
		init_curhist();

		wp->bl = 0;
		wp->bx = 0;
		return 1;

	case CTRL('G'):	/* refresh status line */
		w_printinfo(wp);
		break;
	case CTRL('X'):	/* for debug ? */
		debug = debug ? 0 : 1;
		break;
	case 0x7f: /* IGNORE delete */
		return 0;
		break;
	default:
		waddch(wp->w, c);
		w_putremain(wp, msgbuf);
		wmove(wp->w, wp->cy, wp->cx);

		if (ISWCEND(wp)) {
			scroll(wp->w);
			wmove(wp->w, wp->cy, 0);
			wputstr(wp->w, msgbuf, wp->bx + 1,
				min(wp->bx + 1 + wp->wc, wp->bl));
			wp->cy = wp->wl - 1;
			wp->cx = 0;
		} else if (ISWCRIGHT(wp)) {
			wp->cy++;
			wp->cx = 0;
		} else {
			wp->cx++;
		}

		for (i = wp->bl; i >= wp->bx; i--)
			msgbuf[i + 1] = msgbuf[i];
		msgbuf[wp->bx++] = c;
		wp->bl++;
		wmove(wp->w, wp->cy, wp->cx);
		break;
	}

	if (debug)
		w_printdebug(wp);
	else
		w_printinfo(wp);

	wrefresh(wp->w);

	return 0;
}

void
wrecv_print(const char *fmt, ...)
{
	va_list ap;
#if 0
	int x, y;
#endif

	if (!use_curses) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		return;
	}

#if 0
	getyx(wrecv.w, y, x);
	if (y >= wrecv.wl) {
		wmove(wrecv.w, 0, 0);
		wdeleteln(wrecv.w);
		wmove(wrecv.w, wrecv.wl - 1, 0);
		winsertln(wrecv.w);
		wrefresh(wrecv.w);

		touchwin(wcent.w);
		wrefresh(wcent.w);
		touchwin(wsend.w);
		getyx(wsend.w, y, x);
		wmove(wsend.w, y, x);
		wrefresh(wsend.w);
	}
#endif

	va_start(ap, fmt);
	(void)wvprintw(&wrecv, fmt, ap);
	va_end(ap);
}

void
wstat_print(const char *fmt, ...)
{
	va_list ap;

	if (!use_curses) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		return;
	}

	wdeleteln(wstat.w);
	wmove(wstat.w, 0, 0);

	va_start(ap, fmt);
	(void)wvnprintw(&wstat, fmt, ap);
	va_end(ap);

	wrefresh(wstat.w);
	wrefresh(wsend.w);
}

void
wstat_setmsg(buf, len)
	char *buf;
	int len;
{
	memcpy(wstat.wbuf, buf, min(len, WGROSS(&wstat)));
	w_printinfo(&wstat);
}

static int
wvprintw(struct window *w, const char *fmt, va_list ap)
{
	char msg[BUFSIZ];	/* XXX */

	assert(use_curses == 1);

	(void)vsnprintf(msg, BUFSIZ, fmt, ap);

	wprintw(w->w, msg);
	wrefresh(w->w);

	return 0;
}

static int
wvnprintw(struct window *w, const char *fmt, va_list ap)
{
	char *msg;

	assert(use_curses == 1);

	msg = (char *)malloc(w->wc + 1);
	if (msg == NULL)
		return -1;

	(void)vsnprintf(msg, w->wc + 1, fmt, ap);

	wprintw(w->w, msg);
	wrefresh(w->w);

	free(msg);

	return 0;
}

void
close_screen()
{
	if (!use_curses)
		return;

	move(wroot.wl, 0);
	refresh();
	endwin();
}

static void
init_window(w, wl, wc, wy, wx)
	struct window *w;
	int wl, wc, wy, wx;
{
	assert(use_curses == 1);
	w->wl = wl;
	w->wc = wc;
	w->wy = wy;
	w->wx = wx;

	w->wbuf = calloc(1, w->wl * w->wc);
	if (w->wbuf == NULL)
		err(1, "calloc");

	w->cy = 0;
	w->cx = 0;
	w->bl = 0;
	w->bx = 0;
	w->w = newwin(w->wl, w->wc, w->wy, w->wx);
}

static void
sigwinch(sig)
	int sig;
{
	del_window(&wsend);
	del_window(&wcent);
	del_window(&wstat);
	del_window(&wrecv);
	endwin();
	init_screen(0);
}

static void
del_window(w)
	struct window *w;
{
	free(w->wbuf);
	delwin(w->w);
}

/*
 * wputstr(w, buf, begin, end)
 */
static void
wputstr(w, buf, begin, end)
	WINDOW *w;
	char *buf;
	int begin, end;
{
	int i;
	for (i = begin; i < end; i++)
		waddch(w, buf[i]);
}

static void
w_printinfo(wp)
	struct window *wp;
{
	wstat_print("%s", wstat.wbuf);
}

static void
w_printdebug(wp)
	struct window *wp;
{
	wstat_print("cy=%d cx=%d bl=%d bx=%d wl=%d wc=%d root=%d:%d",
		wp->cy, wp->cx,
		wp->bl, wp->bx,
		wp->wl, wp->wc,
		wroot.wl, wroot.wc);
}

static void
w_putremain(wp, buf)
	struct window *wp;
	char *buf;
{
	scrollok(wp->w, FALSE);
	wputstr(wp->w, buf, wp->bx,
		min(((wp->bx / wp->wc) + wp->wl) * wp->wc, wp->bl));
	scrollok(wp->w, TRUE);
}

static void
w_deleteline(wp)
	struct window *wp;
{
	int i;

	if (wp->bl >= (wp->wl * wp->wc)) {
		wclear(wp->w);
		wp->cy = 0;
		wp->cx = 0;
	} else {
		wdeleteln(wp->w);
		for (i = 0; i < wp->bl / wp->wc; i++) {
			wp->cy--;
			wmove(wp->w, wp->cy, 0);
			wdeleteln(wp->w);
		}
		wp->cx = 0;
	}
	wmove(wp->w, wp->cy, wp->cx);
	wp->bl = 0;
	wp->bx = 0;
}

static void
w_curback(wp, buf)
	struct window *wp;
	char *buf;
{
	if (ISWCHOME(wp)) {
		wclear(wp->w);
		wmove(wp->w, 0, 0);
		wputstr(wp->w, buf, wp->bx - wp->wc, min(wp->wl * wp->wc, wp->bl));
		wp->cy = 0;
		wp->cx = wp->wc - 1;
	} else if (ISWCLEFT(wp)) {
		wp->cy--;
		wp->cx = wp->wc - 1;
	} else {
		wp->cx--;
	}
	wmove(wp->w, wp->cy, wp->cx);
	wp->bx--;
}

static void
w_refresh(wp, buf)
	struct window *wp;
	char *buf;
{
	wclear(wp->w);
	wmove(wp->w, 0, 0);
	wputstr(wp->w, buf, 0, wp->bl);
	getyx(wp->w, wp->cy, wp->cx);
	wp->bx = wp->bl;
}
