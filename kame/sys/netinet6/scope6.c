/*	$KAME: scope6.c,v 1.1 2000/04/18 08:02:25 jinmei Exp $	*/

/*
 * Copyright (C) 2000 WIDE Project.
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

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <net/route.h>
#include <net/if.h>

#include <netinet/in.h>

struct scope6_id {
	/*
	 * 16 is correspondent to 4bit multicast scop field.
	 * i.e. from node-local to global with some reserved/unassigned types.
	 */
	u_int32_t s6id_list[16];
};
struct scope6_id *scope6_ids = NULL;

void
scope6_ifattach(ifp)
	struct ifnet *ifp;
{
	static size_t if_indexlim = 8;

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 */
	if (scope6_ids == NULL || if_index >= if_indexlim) {
		size_t n;
		caddr_t q;

		while (if_index >= if_indexlim)
			if_indexlim <<= 1;

		/* grow scope index array */
		n = if_indexlim * sizeof(struct scope6_id);
		/* XXX: need new malloc type? */
		q = (caddr_t)malloc(n, M_IFADDR, M_WAITOK);
		bzero(q, n);
		if (scope6_ids) {
			bcopy((caddr_t)scope6_ids, q, n/2);
			free((caddr_t)scope6_ids, M_IFADDR);
		}
		scope6_ids = (struct scope6_id *)q;
	}

#define SID scope6_ids[ifp->if_index]

	/* don't initialize if called twice */
	if (SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL])
		return;

	/*
	 * XXX: IPV6_ADDR_SCOPE_xxx macros are not standard.
	 * Should we rather hardcode here?
	 */
	SID.s6id_list[IPV6_ADDR_SCOPE_LINKLOCAL] = ifp->if_index;
	SID.s6id_list[IPV6_ADDR_SCOPE_SITELOCAL] = 1;
	SID.s6id_list[IPV6_ADDR_SCOPE_ORGLOCAL] = 1;
#undef SID
}

int
scope6_set(ifp, idlist)
	struct ifnet *ifp;
	u_int32_t *idlist;
{
	int i;
	int error = 0;

	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	for (i = 0; i < 16; i++) {
		if (idlist[i] &&
		    idlist[i] != scope6_ids[ifp->if_index].s6id_list[i]) {
			if (i == IPV6_ADDR_SCOPE_LINKLOCAL &&
			    idlist[i] > if_index) {
				/*
				 * XXX: theoretically, there should be no
				 * relationship between link IDs and interface
				 * IDs, but we check the consistency for
				 * safety in later use.
				 */
				return(EINVAL);
			}

			/*
			 * XXX: we must need lots of work in this case,
			 * but we simply set the new value in this initial
			 * implementation.
			 */
			scope6_ids[ifp->if_index].s6id_list[i] = idlist[i];
		}
	}

	return(error);
}

int
scope6_get(ifp, idlist)
	struct ifnet *ifp;
	u_int32_t *idlist;
{
	if (scope6_ids == NULL)	/* paranoid? */
		return(EINVAL);

	bcopy(scope6_ids[ifp->if_index].s6id_list, idlist,
	      sizeof(scope6_ids[ifp->if_index].s6id_list));

	return(0);
}
