/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$SuMiRe: pm_extern.h,v 1.9 1998/09/14 19:49:39 shin Exp $
//#	$Id: pm_extern.h,v 1.1 1999/08/12 12:41:08 shin Exp $
//#
//#------------------------------------------------------------------------
*/

/*
//##
//#------------------------------------------------------------------------
//#	pm_aTT.c
//#------------------------------------------------------------------------
*/

aTT		*ckAppearance		__P((int, u_long, u_short));
aTT		*pm_asAttEntry		__P((IPAssoc *));
aTT		*addAttEntry		__P((IPAssoc *, AliasPair *));
aTT		*registAttEntry		__P((aTT *));
void		 pm_removeAttEntry	__P((aTT *));

int		 init_aTT		__P((void));
void	 	 init_hash		__P((void));


/*
//##
//#------------------------------------------------------------------------
//#	pm_ams.c
//#------------------------------------------------------------------------
*/

gAddr		*getGlobalAddr		__P((natBox *, struct in_addr *, int));
gAddr		*isGlobalAddr		__P((resCtrl *, struct in_addr *));
void		 giveBackGlobalAddr	__P((struct in_addr *));
void		 getBackGlobalAddr	__P((resCtrl *, gAddr *, int));

AliasPair	*pm_getMapEntry		__P((IPAssoc *));

int		 setVirtualAddr		__P((struct in_addr *));
int		 unsetVirtualAddr	__P((struct in_addr *));
int		 setRealAddr		__P((struct in_addr *));
int		 unsetRealAddr		__P((struct in_addr *));
#if defined(orphan)
virtualAddr	*hasRealAddress		__P((struct in_addr *));
#endif
virtualAddr	*isInVirtualAddress	__P((struct in_addr *));
realAddr	*isInRealAdddress	__P((struct in_addr *));
void		 init_ams		__P((void));


/*
//##
//#------------------------------------------------------------------------
//#	pm_dispatch.c
//#------------------------------------------------------------------------
*/

int	pm_in		__P((struct ifnet *, struct ip *, struct mbuf *));
int	pm_out		__P((struct ifnet *, struct ip *, struct mbuf *));

pmBox	*pm_asPmBoxName		__P((char *));
pmBox	*pm_asPmBoxIfnet	__P((struct ifnet *));
pmBox	*pm_setPmBox		__P((char *));

void	_getSelfAddr		__P((void));

#if PMDEBUG
extern	int	 pm_debug;
#endif


/*
//##
//#------------------------------------------------------------------------
//#	pm_filter.c
//#------------------------------------------------------------------------
*/

/*
 * pm_filter is execute the filter program starting at pc on the packet p.
 * wirelen is the length of the original packet.
 * buflen is the amount of data present (when p is in mbuf chain).
 */
u_long	pm_filter(Cell *, struct mbuf *);


/*
 * pm_setfunc is store the external(buitin) function to the jump table.
 * you must set function for PM_DONAT and PM_DOIPOPT before running
 * pm_filter routine.
 */

int	pm_setfunc	__P((int, u_long (*func)(u_char *, struct mbuf *, u_long)));

void	init_filter	__P((void));


/*
//##
//#------------------------------------------------------------------------
//#	pm_list.c
//#------------------------------------------------------------------------
*/

Cell		*LST_cons		__P((void *c_car, void *c_cdr));
void		 LST_free		__P((Cell *cell));
Cell		*LST_last		__P((Cell *list));
int		 LST_length		__P((Cell *));
Cell		*LST_hookup		__P((Cell *, void *));
Cell		*LST_hookup_list	__P((Cell **, void *));
Cell		*LST_remove_elem	__P((Cell **, void *));


/*
//##
//#------------------------------------------------------------------------
//#	pm_log.c
//#------------------------------------------------------------------------
*/

void	 pm_logatt	__P((int, aTT *));
void	 pm_logroute	__P((struct mbuf *, struct _fwdRoute *));
void	 pm_logip	__P((int, struct mbuf *));
void	 pm_log		__P((int, int, void *, size_t));

u_long	 pm_ipopt	__P((u_char *, struct mbuf *, u_long));
u_long	 pm_packetlog	__P((u_char *, struct mbuf *, u_long));
u_long	 pm_icmp	__P((u_char *, struct mbuf *, u_long));

#if defined(__bsdi__)
char	*inet_ntoa	__P((struct in_addr));
#endif

char	*itoh		__P((char *, int));


/*
//##
//#------------------------------------------------------------------------
//#	pm_nat.c
//#------------------------------------------------------------------------
*/

u_long	 pm_nat		__P((InOut, u_char *, struct mbuf *, u_long));
void	 pm_debugProbe	__P((char *mesg));


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/
