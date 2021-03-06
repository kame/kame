/*	$NetBSD: dk.c,v 1.4 2003/10/21 12:24:11 itohy Exp $	*/

/*	$OpenBSD: dk.c,v 1.5 1999/04/20 20:01:01 mickey Exp $	*/

/*
 * Copyright 1996 1995 by Open Software Foundation, Inc.   
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 * 
 */

#include "libsa.h"

#include <sys/param.h>
#include <sys/disklabel.h>
#include <sys/reboot.h>
#include <machine/pdc.h>
#include <machine/iomod.h>

#include "dev_hppa.h"

const char *dk_disklabel(struct hppa_dev *, struct disklabel *);

iodcio_t dkiodc;	/* boot IODC entry point */

const char *
dk_disklabel(struct hppa_dev *dp, struct disklabel *label)
{
	char buf[DEV_BSIZE];
	size_t ret;

	if (iodcstrategy(dp, F_READ, LABELSECTOR, DEV_BSIZE, buf, &ret) ||
	    ret != DEV_BSIZE)
		return "cannot read disklabel";

	return (getdisklabel(buf, label));
}

int
dkopen(struct open_file *f, ...)
{
	struct disklabel *lp;
	struct hppa_dev *dp = f->f_devdata;
	const char *st;
	u_int i;

#ifdef	DEBUG
	if (debug)
		printf("dkopen(%p)\n", f);
#endif

	if (!(dp->pz_dev = pdc_findev(-1, PCL_RANDOM)))
		return ENXIO;

	lp = dp->label;
	st = NULL;
#ifdef DEBUG
	if (debug)
		printf ("disklabel\n");
#endif
	if ((st = dk_disklabel(dp, lp)) != NULL) {
#ifdef DEBUG
		if (debug)
			printf ("dkopen: %s\n", st);
#endif
		return ERDLAB;
	} else {
		i = B_PARTITION(dp->bootdev);
#ifdef DEBUG
		if (debug)
			printf("bootdev 0x%x, partition %u\n", dp->bootdev, i);
#endif
		if (i >= lp->d_npartitions || !lp->d_partitions[i].p_size) {
			return (EPART);
		}
	}
#ifdef DEBUGBUG
	if (debug)
		printf ("dkopen() ret\n");
#endif
	return (0);
}

int
dkclose(struct open_file *f)
{
	free(f->f_devdata, sizeof(struct hppa_dev));
	f->f_devdata = NULL;
	return 0;
}
