/*

Copyright (c) 1995  Paul Traina

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL PAUL TRAINA BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of Paul Traina shall
not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization
from the author.

*/

/*
 * krb4auth
 *
 * Generate Kerberos Version 4 session ticket
 */
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef BIND_HACK
#  include <arpa/nameser.h>
#  include <resolv.h>
#endif

#include <krb.h>

#include "krb4auth.h"		/* keep us honest */

#define	KRB_TK_DIR "/tmp/tkt_"	/* where to put the ticket */

/*
 * Krb4GetTKFile
 *
 * provide the name of the file where we may store credentials
 * the return value should be freed when unused.
 */

char *
Krb4GetTKFile (uid)
    uid_t uid;
{
    char *filename;

    filename = malloc(10 + sizeof(KRB_TK_DIR));

    if (filename)
	sprintf(filename, "%s%d", KRB_TK_DIR, uid);

    return (filename);
}

/*
 * Krb4GetCred
 *
 * Given a username, password, and storage location, get kerberos
 * credentials if we can.  Return non-zero on failure.
 */

int
Krb4GetCred (name, passwd, tickets)
    char *name;
    char *passwd;
    char *tickets;
{
    char realm[REALM_SZ];
    int result;

#ifdef BIND_HACK
    _res.retrans = 1;
#endif

    krb_set_tkt_string(tickets);

    /* find our local realm */
    if (krb_get_lrealm(realm, 1) != KSUCCESS)
	(void) strncpy(realm, KRB_REALM, sizeof(realm));

    result = krb_get_pw_in_tkt(name, "", realm, "krbtgt", realm,
			       DEFAULT_TKT_LIFE, passwd);

    switch (result) {
    case INTK_OK:
    case INTK_W_NOTALL:
	return 0;

    /* these errors should be silent so the kerberos database can't be probed */
    case KDC_NULL_KEY:
    case KDC_PR_UNKNOWN:
    case INTK_BADPW:
    case KDC_PR_N_UNIQUE:
    case -1:
	break;

    default:
	LogError("Unknown kerberos error: user=%s %s\n",
	    name, krb_err_txt[result]);
    }
    return 1;
}
