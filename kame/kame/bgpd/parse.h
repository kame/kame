/*
 * Copyright (C) 1998 WIDE Project.
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

void             conf_check             __P((char *));
void             parse_bgp_yes          __P((char *));


/* Skip white space */
#define SKIP_WHITE(i) \
  for (   ; (i) < LINE_MAX ; (i)++) { \
    if (buf[(i)] == '\n' || buf[(i)] == '#') { \
      memset(buf, 0,LINE_MAX);\
      memset(atom,0,LINE_MAX);\
      fgets(buf,  LINE_MAX, fp);\
      ++line;\
      (i) = -1;\
    } else {\
      if ((buf[(i)] != ' ') && (buf[(i)] != '\t'))\
	break;\
    }\
  }


/* read an atom  */
#define READ_ATOM(i, j)  \
      memset(atom, 0, LINE_MAX);                            \
      for ( (j) = 0   ; (i) < LINE_MAX ; (i)++, (j)++ ) {   \
	if ((buf[(i)] == ' ')  || (buf[(i)] == '\t') ||     \
	    (buf[(i)] == '\n') || (buf[(i)] == ';'))        \
           break;                                           \
	atom[(j)] = buf[(i)]; \
      }

/* end of a sentence */
#define SENTENCE_END(i)  \
      SKIP_WHITE((i)); \
      if (buf[(i)++] != ';') { \
         syslog(LOG_ERR, "%s:%d syntax error: \';\' expected", filename, line); \
         fatalx("parse error: \';\' expected"); \
      }

