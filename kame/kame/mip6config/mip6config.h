/*
 * Copyright (c) 1999 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Magnus Braathen <magnus.braathen@era.ericsson.se>
 *
 * $Id: mip6config.h,v 1.1 2000/02/07 17:27:08 itojun Exp $
 *
 */

#define PROGNAME "mip6config: " /* name of the program */

struct config_tmpl {
    unsigned char *comstring;
    int (*parse)(char *, int);
    int command;
};
