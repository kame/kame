/*
 * Configuration for w3m
 */

#ifndef _CONFIGURED_
#define _CONFIGURED_

/* User Configuration */

/* 
   If you define DICT, you can use dictionary look-up function
   in w3m. See README.dict for detail.
*/
#undef DICT

/*
   If you define USE_MARK, you can use set-mark (C-SPC),
   goto-next-mark (ESC p), goto-next-mark (ESC n) and
   mark-by-regexp (").
*/
#undef USE_MARK

/*
   If you want to use IPv6, define this symbol.
 */
#define INET6

/**********************************************************/
#ifdef makefile_parameter

BIN_DIR = @PREFIX@/bin
HELP_DIR = @PREFIX@/lib/w3m
HELP_FILE = w3mhelp_ja.html
SYS_LIBRARIES =  -lcurses -ltermcap
LOCAL_LIBRARIES = -L/usr/local/v6/lib -linet6
MYCFLAGS = -I./gc 
KEYBIND_SRC = keybind.c
KEYBIND_OBJ = keybind.o
EXT=
GCLIB=gc/gc.a
GCTARGET=gc/gc.a
#else


#define DISPLAY_CODE 'E'

#define JA 0
#define EN 1
#define LANG JA
#define KANJI_SYMBOLS
#undef COLOR
#define MOUSE
#define MENU

#define DEF_EDITOR "/usr/bin/vi"
#define DEF_MAILER "/usr/bin/mail"
#define DEF_EXT_BROWSER "@PREFIX@/bin/netscape"
#define HELP_FILE "@PREFIX@/lib/w3m/w3mhelp.html"
#define BOOKMARK "~/.w3m/bookmark.html"
#define KEYMAP_FILE  "~/.w3m/keymap"
#define MENU_FILE    "~/.w3m/menu"
#define USER_MAILCAP "~/.mailcap"
#define SYS_MAILCAP  "/etc/mailcap"

#define TERMIOS
#define DIRENT
#define STRCASECMP
#define STRCHR
#define STRERROR
#define SYS_ERRLIST
#undef NOBCOPY
#define GETDTABLESIZE
#define GETCWD
#define GETWD
#define HAVE_SETENV
#define HAVE_PUTENV
#define HAVE_QSORT


#define SETJMP(env) sigsetjmp(env,1)
#define LONGJMP(env,val) siglongjmp(env,val)
#define JMP_BUF sigjmp_buf

typedef void MySignalHandler;
#define SIGNAL_ARG int _dummy
#define SIGNAL_ARGLIST 0
#define SIGNAL_RETURN return

#undef TABLE_EXPAND
#define NOWRAP 1
#define NEW_FORM 1
#define MATRIX 1
#undef NO_FLOAT_H

#endif /* makefile_parameter */
#endif /* _CONFIGURED_ */

