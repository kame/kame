/*	$KAME: pathnames.h,v 1.9 2001/06/25 04:54:29 itojun Exp $	*/

/*
 * Copyright (c) 1998-2001
 * The University of Southern California/Information Sciences Institute.
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
 *  Questions concerning this software should be directed to
 *  Mickael Hoerdt (hoerdt@clarinet.u-strasbg.fr) LSIIT Strasbourg.
 *
 */
/*
 * This program has been derived from pim6dd.        
 * The pim6dd program is covered by the license in the accompanying file
 * named "LICENSE.pim6dd".
 */
/*
 * This program has been derived from pimd.        
 * The pimd program is covered by the license in the accompanying file
 * named "LICENSE.pimd".
 *
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#ifndef PATHNAMES_H
#define PATHNAMES_H

#define _PATH_PIM6D_CONF	"/usr/local/v6/etc/pim6sd.conf"
#define _PATH_PIM6D_LOGFILE	"/var/log/pim6sd.log"

#if (defined(BSD) && (BSD >= 199103))
	#define _PATH_PIM6D_PID		"/var/run/pim6sd.pid"
	#define _PATH_PIM6D_GENID	"/var/run/pim6sd.genid"
	#define _PATH_PIM6D_DUMP	"/var/run/pim6sd.dump"
	#define _PATH_PIM6D_CACHE	"/var/run/pim6sd.cache"
	#define _PATH_PIM6D_STAT	"/var/run/pim6sd.stat"
#else
	#define _PATH_PIM6D_PID		"/etc/pim6sd.pid"
	#define _PATH_PIM6D_GENID	"/etc/pim6sd.genid"
	#define _PATH_PIM6D_DUMP	"/etc/pim6sd.dump"
	#define _PATH_PIM6D_CACHE	"/etc/pim6sd.cache"
	#define _PATH_PIM6D_STAT	"/etc/pim6sd.stat"
#endif

#endif
