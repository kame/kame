/*	$NetBSD: netbsd32_compat_13.c,v 1.3 1999/03/25 16:22:49 mrg Exp $	*/

/*
 * Copyright (c) 1998 Matthew R. Green
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/syscallargs.h>

#include <compat/netbsd32/netbsd32.h>
#include <compat/netbsd32/netbsd32_syscallargs.h>

int
compat_13_compat_netbsd32_sigaltstack13(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct compat_13_compat_netbsd32_sigaltstack13_args /* {
		syscallarg(const netbsd32_sigaltstack13p_t) nss;
		syscallarg(netbsd32_sigaltstack13p_t) oss;
	} */ *uap = v;
	struct compat_13_sys_sigaltstack_args ua;
	struct sigaltstack13 nss13, oss13;
	struct netbsd32_sigaltstack13 *s32nss13, *s32oss13;
	int rv;

	SCARG(&ua, nss) = &nss13;
	SCARG(&ua, oss) = &oss13;

	s32nss13 = (struct netbsd32_sigaltstack13 *)(u_long)SCARG(uap, nss);
	s32oss13 = (struct netbsd32_sigaltstack13 *)(u_long)SCARG(uap, oss);

	nss13.ss_sp = (char *)(u_long)s32nss13->ss_sp;
	nss13.ss_size = s32nss13->ss_size;
	nss13.ss_flags = s32nss13->ss_flags;

	rv = compat_13_sys_sigaltstack(p, &ua, retval);

	s32oss13->ss_sp = (netbsd32_charp)(u_long)oss13.ss_sp;
	s32oss13->ss_size = oss13.ss_size;
	s32oss13->ss_flags = oss13.ss_flags;

	return (rv);
}
