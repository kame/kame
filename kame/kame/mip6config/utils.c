/*
 * Copyright (C) 1995, 1996, 1997, 1998, 1999 and 2000 WIDE Project.
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

/*
 * Copyright (c) 1999 and 2000 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:  Hesham Soliman <Hesham.Soliman@ericsson.com.au>
 *          Magnus Braathen <Magnus.Braathen@era.ericsson.se>
 *
 * $Id: utils.c,v 1.1 2000/02/07 17:27:08 itojun Exp $
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet6/mip6_common.h>
#include "mip6config.h"

void print_err(int error)
{
    switch (error) {
        
    case ERR_UNKNOWNCMD :
        printf(PROGNAME "unknown command\n");
        break;

    case ADDR_NOT_FOUND :
        printf(PROGNAME "address not found\n");
        break;
        
    case WRITE_ERROR:
        printf(PROGNAME "write error\n");
        break;
        
    case FILE_OPEN_ERR:
        printf(PROGNAME "open error\n");
        break;
        
    case SYS_CALL_FAILED:
        printf(PROGNAME "operation failed in module\n");
        break;
        
    case INVALID_IFNAME:
        printf(PROGNAME "invalid interface name\n");
        break;
        
    case MN_HA_FUNC_NOT_ALLOWED:
        printf(PROGNAME "host can not be MN and HA simultaneously\n");
        break;
        
    case FUNC_NOT_ALLOWED:
        printf(PROGNAME "function configuration is not allowed\n");
        break;
        
    case FUNC_ALREADY_CONFIG:
        printf(PROGNAME "function was already configured\n");
        break;

    default:
        printf(PROGNAME "unknown error %d\n", error);
        break;
    }
}
