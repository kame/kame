/*
 * Copyright (c) 2001,2002 Sebastien Petit <spe@bsdfr.org>
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. Obviously, it
 *    would be nice if you gave credit where credit is due but requiring it
 *    would be too onerous.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastien Petit.
 * 4. Neither the name of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: vrrp_list.c,v 1.1 2002/07/09 07:19:20 ono Exp $
 */

#include "vrrp_list.h"

/*
 * We use a double chained list with sentinels ---  --- |f|->|d|->NULL
 * NULL<-| |<-| | ---  ---
 */

/*
 * Initialise la liste chainee avec un premier element: l'adresse reelle du
 * VRID
 */
char 
vrrp_list_initialize(struct vrrp_vr * vr, struct ether_addr * ethaddr)
{
	vr->vr_if->p = (struct vrrp_ethaddr_list *) malloc(sizeof(*(vr->vr_if->p)));
	vr->vr_if->d = (struct vrrp_ethaddr_list *) malloc(sizeof(*(vr->vr_if->d)));
	if (!vr->vr_if->p || !vr->vr_if->d) {
		syslog(LOG_ERR, "Can't allocate memory for vrrp_list_initialize: %m");
		return -1;
	}
	bzero(vr->vr_if->p, sizeof(*vr->vr_if->p));
	bzero(vr->vr_if->d, sizeof(*vr->vr_if->d));
	vr->vr_if->p->previous = NULL;
	vr->vr_if->p->next = vr->vr_if->d;
	vr->vr_if->d->previous = vr->vr_if->p;
	vr->vr_if->d->next = NULL;
	printf("ethaddr = %X:%X:%X:%X:%X:%X\n", ethaddr->octet[0], ethaddr->octet[1], ethaddr->octet[2], ethaddr->octet[3], ethaddr->octet[4], ethaddr->octet[5]);
	if (vrrp_list_add(vr, *ethaddr) == -1) {
		free(vr->vr_if->p);
		free(vr->vr_if->d);
		return -1;
	}
	return 0;
}

/*
 * Ajoute un nouvel element dans la liste
 */
char 
vrrp_list_add(struct vrrp_vr * vr, struct ether_addr ethaddr)
{
	struct vrrp_ethaddr_list *n;

	if (!(n = (struct vrrp_ethaddr_list *) malloc(sizeof(*n)))) {
		syslog(LOG_ERR, "Can't allocate memory for vrrp_list_add: %m");
		return -1;
	}
	bzero(n, sizeof(*n));
	bcopy(&ethaddr, &n->ethaddr, sizeof(ethaddr));
	n->previous = vr->vr_if->d->previous;
	n->next = vr->vr_if->d;
	vr->vr_if->d->previous->next = n;
	vr->vr_if->d->previous = n;

	return 0;
}

/*
 * Enleve un element de la liste
 */
char 
vrrp_list_delete(struct vrrp_vr * vr, struct ether_addr ethaddr)
{
	struct vrrp_ethaddr_list *e = vr->vr_if->p;

	while (e->next && bcmp(&ethaddr, &e->ethaddr, sizeof(ethaddr)))
		e = e->next;
	if (!e->next)
		return -1;
	e->next->previous = e->previous;
	e->previous->next = e->next;
	free(e);

	return 0;
}

struct ether_addr 
vrrp_list_get_first(struct vrrp_vr * vr)
{
	return vr->vr_if->p->next->ethaddr;
}

/*
 * Renvoie l'adresse MAC du dernier element
 */
struct ether_addr 
vrrp_list_get_last(struct vrrp_vr * vr)
{
	return vr->vr_if->d->previous->ethaddr;
}

void 
vrrp_list_destroy(struct vrrp_vr * vr)
{
	vr->vr_if->d = vr->vr_if->d->previous;
	while (vr->vr_if->d != vr->vr_if->p) {
		free(vr->vr_if->d->next);
		vr->vr_if->d = vr->vr_if->d->previous;
	}
	free(vr->vr_if->d);
	free(vr->vr_if->p);

	return;
}
