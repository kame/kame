/*
 * Copyright (c) 1999 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Magnus Braathen <magnus.braathen@era.ericsson.se>
 *
 * $Id: mip6config.h,v 1.3 2000/02/09 14:34:02 itojun Exp $
 *
 */

#define PROGNAME "mip6config" /* name of the program */

struct config_tmpl {
    char *comstring;
    int (*parse) __P((char *, int));
#if defined(__FreeBSD__) && __FreeBSD__ < 3
    int command;
#else
    u_long command;
#endif
};
