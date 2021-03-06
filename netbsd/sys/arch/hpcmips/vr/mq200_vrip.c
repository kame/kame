/*	$NetBSD: mq200_vrip.c,v 1.1.2.1 2000/08/06 03:58:23 takemura Exp $	*/

/*-
 * Copyright (c) 2000 Takemura Shin
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
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>

#include <machine/bus.h>

#include <hpcmips/vr/vripreg.h>
#include <hpcmips/vr/vripvar.h>
#include <hpcmips/vr/vrgiureg.h>
#include <hpcmips/dev/mq200var.h>

#include "locators.h"

struct mq200_vrip_softc {
	struct mq200_softc	sc_mq200;
};

static int	mq200_vrip_probe __P((struct device *, struct cfdata *,
				      void *));
static void	mq200_vrip_attach __P((struct device *, struct device *,
				       void *));

struct cfattach mqvideo_vrip_ca = {
	sizeof(struct mq200_vrip_softc), mq200_vrip_probe, mq200_vrip_attach
};

static int
mq200_vrip_probe(parent, cf, aux)
	struct device *parent;
	struct cfdata *cf;
	void *aux;
{
	struct vrip_attach_args *va = aux;
	bus_space_handle_t ioh;
	int res;

	if (va->va_addr == VRIPCF_ADDR_DEFAULT)
		return (0);

	if (bus_space_map(va->va_iot, va->va_addr, va->va_size, 0, &ioh)) {
		printf(": can't map i/o space\n");
		return 0;
	}
	res = mq200_probe(va->va_iot, ioh);
	bus_space_unmap(va->va_iot, ioh, va->va_size);

	return (res);
}


static void
mq200_vrip_attach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	struct mq200_vrip_softc *vsc = (void *)self;
	struct mq200_softc *sc = &vsc->sc_mq200;
	struct vrip_attach_args *va = aux;

	sc->sc_baseaddr = va->va_addr;
	sc->sc_iot = va->va_iot;
	if (bus_space_map(va->va_iot, va->va_addr, va->va_size, 0,
			  &sc->sc_ioh)) {
		printf(": can't map bus space\n");
		return;
	}

	mq200_attach(sc);
}
