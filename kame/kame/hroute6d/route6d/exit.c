/* 
 * $Id: exit.c,v 1.2 2003/01/21 09:28:39 suz Exp $
 */

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

/* 
 * Copyright(C)1997 by Hitachi, Ltd.
 * Hitachi Id: exit.c,v 1.2 1997/12/22 09:56:45 sumikawa Exp $
 */

#include "defs.h"
#include "pathnames.h"

extern int Cflag;

/* 
 * Release all resources held by route6d daemon.
 */
void
release_resources(void)
{
	if (trace_file_ptr != NULL)
		fclose(trace_file_ptr);
	if (admin_sock > -1) {
		close(admin_sock);
		unlink(ADM_RIP6_UDS);
	}
	if (rip6_sock > -1)
		close(rip6_sock);
	flush_local_cache();
	if (rt6_sock > -1)
		close(rt6_sock);
	if (snd_data)
		free(snd_data);
	if (rcv_data)
		free(rcv_data);
	closelog();

	/* 
	 * if there is already a route6d process, it is detected by 
	 * initialize_pidfile() and route6d stops there (except in
	 * case of configuration check mode).  So when you reach here, 
	 * you can remove RT6_PID without considering the other route6d.
	 */
	if (!Cflag)
		unlink(RT6_PID);
	return;
}

/* 
 * Log & Quit
 */
void
quit_route6d(char *s, int ret_code)
{
	if (s)
		syslog(LOG_ERR, "%s: %m", s);
	release_resources();
	exit(ret_code);
}
