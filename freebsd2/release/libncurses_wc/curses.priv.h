
/* This work is copyrighted. See COPYRIGHT.OLD & COPYRIGHT.NEW for   *
*  details. If they are missing then this copy is in violation of    *
*  the copyright conditions.                                        */

/*
 *	curses.priv.h
 *
 *	Header file for curses library objects which are private to
 *	the library.
 *
 */

#include "version.h"

#ifndef __GNUC__
#define inline
#endif

#ifndef NOACTION
#include <unistd.h>
typedef struct sigaction sigaction_t;
#else
#include "SigAction.h"
#endif

#include "curses.h"

#define min(a,b)	((a) > (b)  ?  (b)  :  (a))
#define max(a,b)	((a) < (b)  ?  (b)  :  (a))

#define FG(n)	((n) & 0x0f)
#define BG(n)	(((n) & 0xf0) >> 4)

#define CHANGED     -1

#ifdef KANJI
#define Iskanji(ch)	((ch) & 0x00000080UL)

#define _UC(c)	((unsigned char)(c))

	/* shift jis code */
#define is_sjis_kana(c)	     ((_UC(c)>=0xA1 && _UC(c)<=0xDF))
#define is_sjis_kanji(c)     ((_UC(c)>=0x81 && _UC(c)<=0x9F) || \
				(_UC(c)>=0xE0 && _UC(c)<=0xFC))
#define is_sjis_kanji2(c)    ((_UC(c)>=0x40 && _UC(c)<=0x7E) || \
				(_UC(c)>=0x80 && _UC(c)<=0xFC))
	/* EUC code */
#define is_euc_kana(c)	(_UC(c)==0x8E)	/* SS1 */
#define is_euc_kanji(c)	(_UC(c)>=0xA1 && _UC(c)<=0xFE)
#define is_euc_kanji2(c)(_UC(c)>=0xA1 && _UC(c)<=0xFE)
	/* JIS code */
#define is_jis_kanji(c)	(_UC(c)>=0x21 && _UC(c)<=0x7E)
extern char *kanji_chk;
extern void kanji_flag(chtype *line, int len);
#endif /* KANJI */

extern WINDOW	*newscr;

#ifdef TRACE
#define T(a)	if (_tracing & TRACE_ORDINARY) _tracef a
#define TR(n, a)	if (_tracing & (n)) _tracef a
extern int _tracing;
extern char *visbuf(const char *);
#else
#define T(a)
#define TR(n, a)
#endif

extern int _outch(int);
extern void init_acs(void);
extern void tstp(int);
extern WINDOW *makenew(int, int, int, int);
extern int timed_wait(int fd, int wait, int *timeleft);

struct try {
        struct try      *child;     /* ptr to child.  NULL if none          */
        struct try      *sibling;   /* ptr to sibling.  NULL if none        */
        unsigned char    ch;        /* character at this node               */
        unsigned short   value;     /* code of string so far.  0 if none.   */
};

/*
 * Structure for soft labels.
 */

typedef struct {
	char dirty;			/* all labels have changed */
	char hidden;			/* soft lables are hidden */
	WINDOW *win;
 	struct slk_ent {
 	    char text[9];		/* text for the label */
 	    char form_text[9];		/* formatted text (left/center/...) */
 	    int x;			/* x coordinate of this field */
 	    char dirty;			/* this label has changed */
 	    char visible;		/* field is visible */
	} ent[8];
} SLK;

#define FIFO_SIZE	32

struct screen {
   	FILE		*_ifp;	    	/* input file ptr for this terminal     */
   	FILE		*_ofp;	    	/* output file ptr for this terminal    */
   	int		_checkfd;
#ifdef MYTINFO
	struct _terminal *_term;
#else
	struct term	*_term;	    	/* used by terminfo stuff               */
#endif
	WINDOW		*_curscr;   	/* windows specific to a given terminal */
	WINDOW		*_newscr;
	WINDOW		*_stdscr;
	struct try  	*_keytry;   	/* "Try" for use with keypad mode       */
	unsigned int	_fifo[FIFO_SIZE]; 	/* Buffer for pushed back characters    */
	signed char	_fifohead,
			_fifotail,
			_fifopeek;
	bool		_endwin;
	chtype		_current_attr;
	bool		_coloron;
	int		_cursor;	/* visibility of the cursor		*/
	int         	_cursrow;   	/* Row and column of physical cursor    */
	int         	_curscol;
	bool		_nl;	    	/* True if NL -> CR/NL is on	    	*/
	bool		_raw;	    	/* True if in raw mode                  */
	int		_cbreak;    	/* 1 if in cbreak mode                  */
                       		    	/* > 1 if in halfdelay mode		*/
	bool		_echo;	    	/* True if echo on                      */
	bool		_nlmapping; 	/* True if terminal is really doing     */
				    	/* NL mapping (fn of raw and nl)    	*/
 	SLK		*_slk;	    	/* ptr to soft key struct / NULL    	*/
	int		_costs[9];  	/* costs of cursor movements for mvcur  */
	int		_costinit;  	/* flag wether costs[] is initialized   */
};

extern struct screen	*SP;

extern int _slk_format;			/* format specified in slk_init() */

#define MAXCOLUMNS    135
#define MAXLINES      66
#define UNINITIALISED ((struct try * ) -1)
