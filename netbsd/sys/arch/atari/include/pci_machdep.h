/*	$NetBSD: pci_machdep.h,v 1.4 1999/03/19 03:35:59 cgd Exp $	*/

/*
 * Copyright (c) 1996 Leo Weppelman.  All rights reserved.
 * Copyright (c) 1996 Christopher G. Demetriou.  All rights reserved.
 * Copyright (c) 1994 Charles M. Hannum.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Charles M. Hannum.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ATARI_PCI_MACHDEP_H_
#define _ATARI_PCI_MACHDEP_H_

#include <atari/atari/intr.h>
/*
 * Types provided to machine-independent PCI code
 */
typedef void	*pci_chipset_tag_t;

typedef u_long	pcitag_t;
typedef int	pci_intr_handle_t;

typedef struct	{
	int		ipl;	/* ipl requested			*/
	int		imask;	/* bitmask for MFP-register		*/
	int		(*ifunc) __P((void *));	/* function to call	*/
	void		*iarg;	/* argument for 'ifunc'			*/
	struct intrhand	*ihand;	/* save this for disestablishing	*/
} pci_intr_info_t;

/*
 * Functions provided to machine-independent PCI code.
 */
void		pci_attach_hook __P((struct device *, struct device *,
			struct pcibus_attach_args *));
int		pci_bus_maxdevs __P((pci_chipset_tag_t, int));
pcitag_t	pci_make_tag __P((pci_chipset_tag_t, int, int, int));
pcireg_t	pci_conf_read __P((pci_chipset_tag_t, pcitag_t, int));
void		pci_conf_write __P((pci_chipset_tag_t, pcitag_t, int,
			pcireg_t));
int		pci_intr_map __P((pci_chipset_tag_t, pcitag_t, int, int,
			pci_intr_handle_t *));
const char	*pci_intr_string __P((pci_chipset_tag_t, pci_intr_handle_t));
void		*pci_intr_establish __P((pci_chipset_tag_t, pci_intr_handle_t,
			int, int (*)(void *), void *));
void		pci_intr_disestablish __P((pci_chipset_tag_t, void *));

#endif /* _ATARI_PCI_MACHDEP_H_ */
