dnl Copyright (c) 1999 WIDE Project. All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl 1. Redistributions of source code must retain the above copyright
dnl    notice, this list of conditions and the following disclaimer.
dnl 2. Redistributions in binary form must reproduce the above copyright
dnl    notice, this list of conditions and the following disclaimer in the
dnl    documentation and/or other materials provided with the distribution.
dnl 3. Neither the name of the project nor the names of its contributors
dnl    may be used to endorse or promote products derived from this software
dnl    without specific prior written permission.
dnl 
dnl THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
dnl ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
dnl IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
dnl ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
dnl FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
dnl DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
dnl OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
dnl HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
dnl LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
dnl OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
dnl SUCH DAMAGE.

dnl
dnl Checks to see if AF_INET6 is defined
AC_DEFUN(AC_CHECK_AF_INET6, [
	AC_MSG_CHECKING(for AF_INET6)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <sys/socket.h>],
		[int a = AF_INET6],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
		if test $$1 = yes ; then
			AC_DEFINE(HAVE_AF_INET6)
	fi
])

dnl
dnl Checks to see if the sockaddr struct has the 4.4 BSD sa_len member
dnl borrowed from LBL libpcap
AC_DEFUN(AC_CHECK_SA_LEN, [
	AC_MSG_CHECKING(if sockaddr struct has sa_len member)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <sys/socket.h>],
		[u_int i = sizeof(((struct sockaddr *)0)->sa_len)],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
		if test $$1 = yes ; then
			AC_DEFINE(HAVE_SOCKADDR_SA_LEN)
	fi
])

dnl
dnl Checks for portable prototype declaration macro
AC_DEFUN(AC_CHECK_PORTABLE_PROTO,  [
	AC_MSG_CHECKING(for __P)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <unistd.h>],
		[int f __P(())],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_PORTABLE_PROTOTYPE)
	fi
])

dnl checks for u_intXX_t
AC_DEFUN(AC_CHECK_BITTYPES, [
	$1=yes
dnl check for u_int8_t
	AC_MSG_CHECKING(for u_int8_t)
	AC_CACHE_VAL(ac_cv_u_int8_t,
	AC_TRY_COMPILE([
#		include <sys/types.h>],
		[u_int8_t i],
		ac_cv_u_int8_t=yes,
		ac_cv_u_int8_t=no))
	AC_MSG_RESULT($ac_cv_u_int8_t)
	if test $ac_cv_u_int8_t = yes; then
		AC_DEFINE(HAVE_U_INT8_T)
	else
		$1=no
	fi
dnl check for u_int16_t
	AC_MSG_CHECKING(for u_int16_t)
	AC_CACHE_VAL(ac_cv_u_int16_t,
	AC_TRY_COMPILE([
#		include <sys/types.h>],
		[u_int16_t i],
		ac_cv_u_int16_t=yes,
		ac_cv_u_int16_t=no))
	AC_MSG_RESULT($ac_cv_u_int16_t)
	if test $ac_cv_u_int16_t = yes; then
		AC_DEFINE(HAVE_U_INT16_T)
	else
		$1=no
	fi
dnl check for u_int32_t
	AC_MSG_CHECKING(for u_int32_t)
	AC_CACHE_VAL(ac_cv_u_int32_t,
	AC_TRY_COMPILE([
#		include <sys/types.h>],
		[u_int32_t i],
		ac_cv_u_int32_t=yes,
		ac_cv_u_int32_t=no))
	AC_MSG_RESULT($ac_cv_u_int32_t)
	if test $ac_cv_u_int32_t = yes; then
		AC_DEFINE(HAVE_U_INT32_T)
	else
		$1=no
	fi
])

dnl
dnl Checks for addrinfo structure
AC_DEFUN(AC_STRUCT_ADDRINFO, [
	AC_MSG_CHECKING(for addrinfo)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <netdb.h>],
		[struct addrinfo a],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_ADDRINFO)
	else
		AC_DEFINE(NEED_ADDRINFO_H)
	fi
])

dnl
dnl Checks for NI_MAXSERV
AC_DEFUN(AC_NI_MAXSERV, [
	AC_MSG_CHECKING(for NI_MAXSERV)
	AC_CACHE_VAL($1,
	AC_EGREP_CPP(yes, [#include <netdb.h>
#ifdef NI_MAXSERV
yes
#endif],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 != yes; then
		AC_DEFINE(NEED_ADDRINFO_H)
	fi
])

dnl
dnl Checks for NI_NAMEREQD
AC_DEFUN(AC_NI_NAMEREQD, [
	AC_MSG_CHECKING(for NI_NAMEREQD)
	AC_CACHE_VAL($1,
	AC_EGREP_CPP(yes, [#include <netdb.h>
#ifdef NI_NOFQDN
yes
#endif],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 != yes; then
		AC_DEFINE(NEED_ADDRINFO_H)
	fi
])

dnl
dnl Checks for sockaddr_storage structure
AC_DEFUN(AC_STRUCT_SA_STORAGE, [
	AC_MSG_CHECKING(for sockaddr_storage)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <sys/socket.h>],
		[struct sockaddr_storage s],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_SOCKADDR_STORAGE)
	fi
])

dnl
dnl Checks for macro of IP address size
AC_DEFUN(AC_CHECK_ADDRSZ, [
	$1=yes
dnl check for INADDRSZ
	AC_MSG_CHECKING(for INADDRSZ)
	AC_CACHE_VAL(ac_cv_inaddrsz,
	AC_TRY_COMPILE([
#		include <arpa/nameser.h>],
		[int a = INADDRSZ],
		ac_cv_inaddrsz=yes,
		ac_cv_inaddrsz=no))
	AC_MSG_RESULT($ac_cv_inaddrsz)
	if test $ac_cv_inaddrsz = yes; then
		AC_DEFINE(HAVE_INADDRSZ)
	else
		$1=no
	fi
dnl check for IN6ADDRSZ
	AC_MSG_CHECKING(for IN6ADDRSZ)
	AC_CACHE_VAL(ac_cv_in6addrsz,
	AC_TRY_COMPILE([
#		include <arpa/nameser.h>],
		[int a = IN6ADDRSZ],
		ac_cv_in6addrsz=yes,
		ac_cv_in6addrsz=no))
	AC_MSG_RESULT($ac_cv_in6addrsz)
	if test $ac_cv_in6addrsz = yes; then
		AC_DEFINE(HAVE_IN6ADDRSZ)
	else
		$1=no
	fi
])

dnl
dnl check for RES_USE_INET6
AC_DEFUN(AC_CHECK_RES_USE_INET6, [
	AC_MSG_CHECKING(for RES_USE_INET6)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <netinet/in.h>
#		include <resolv.h>],
		[int a = RES_USE_INET6],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_RES_USE_INET6)
	fi
])

dnl
dnl check for AAAA
AC_DEFUN(AC_CHECK_AAAA, [
	AC_MSG_CHECKING(for AAAA)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <arpa/nameser.h>],
		[int a = T_AAAA],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_AAAA)
	fi
])

dnl
dnl check for struct res_state_ext
AC_DEFUN(AC_STRUCT_RES_STATE_EXT, [
	AC_MSG_CHECKING(for res_state_ext)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <netinet/in.h>
#		include <netinet6/in6.h>
#		include <resolv.h>],
		[struct __res_state_ext e],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_RES_STATE_EXT)
	fi
])

dnl
dnl check for struct res_state_ext
AC_DEFUN(AC_STRUCT_RES_STATE, [
	AC_MSG_CHECKING(for nsort in res_state)
	AC_CACHE_VAL($1,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <netinet/in.h>
#		include <netinet6/in6.h>
#		include <resolv.h>],
		[struct __res_state e; e.nsort = 0],
		$1=yes,
		$1=no))
	AC_MSG_RESULT($$1)
	if test $$1 = yes; then
		AC_DEFINE(HAVE_NEW_RES_STATE)
	fi
])

dnl
dnl check for h_errno
AC_DEFUN(AC_VAR_H_ERRNO, [
	AC_MSG_CHECKING(for h_errno)
	AC_CACHE_VAL(ac_cv_var_h_errno,
	AC_TRY_COMPILE([
#		include <sys/types.h>
#		include <netdb.h>],
		[int foo = h_errno;],
		ac_cv_var_h_errno=yes,
		ac_cv_var_h_errno=no))
	AC_MSG_RESULT($ac_cv_var_h_errno)
	if test "$ac_cv_var_h_errno" = "yes"; then
		AC_DEFINE(HAVE_H_ERRNO)
	fi
])
