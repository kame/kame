
/*
**	lib_kanji.c
**
**
*/

#include <string.h>
#include <stdlib.h>
#include "curses.priv.h"

#ifdef KANJI
static char kanji_flag_tb[BUFSIZ];
char *kanji_chk;

void kanji_flag(chtype *line, int len)
{
	char *p, *s;

	if (kanji_chk != NULL && kanji_chk != kanji_flag_tb)
		free(kanji_chk);
	if (len > BUFSIZ)
		kanji_chk = malloc(len);
	else
		kanji_chk = kanji_flag_tb;
	memset(kanji_chk, 0, len);
#if 0
	if ((p=getenv("LANG")) == NULL)
		return;
	if (strcmp(p, "ja_JP.EUC") == 0) {
		s = kanji_chk;
		for (; len-- > 0; ++line, ++s) {
			if (is_euc_kanji(*line)) {
				*s = 01;	/* kanji first char */
				*++s = 02;	/* kanji second char */
				++line;
			}
		}
	}
	else if (strcmp(p, "ja_JP.SJIS") == 0) {
		s = kanji_chk;
		for (; len-- > 0; ++line, ++s) {
			if (is_sjis_kanji(*line)) {
				*s = 01;	/* kanji first char */
				*++s = 02;	/* kanji second char */
				++line;
			}
		}
	}
#endif
#if 0	/* allways kanji char check (EUC or SJIS) */
	/* kanji char (EUC or SJIS) has 0x80 bit */
	s = kanji_chk;
	for (; len-- > 0; ++line, ++s) {
		if (*line & 0x80) {
			*s = 01;	/* kanji first char */
			*++s = 02;	/* kanji second char */
			++line;
		}
	}
#endif
#if 1
	/* For EUC/Big5 only */
	s = kanji_chk;
	for (; len-- > 0; ++line, ++s) {
		if ((*line & 0xff) > 0xa0) {
			*s = 1;		/* kanji first char */
			*++s = 2;	/* kanji second char */
			++line;
		}
	}
#endif
}
#endif /* KANJI */
