/*
 * Copyright (C) 1997-1999
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: altq_conf.c,v 1.1.1.1 1999/10/02 05:52:29 itojun Exp $
 */

#ifdef ALTQ
#ifndef _NO_OPT_ALTQ_H_
#include "opt_altq.h"
#if !defined(__FreeBSD__) || (__FreeBSD__ > 2)
#include "opt_inet.h"
#endif
#endif /* !_NO_OPT_ALTQ_H_ */

/*
 * altq device interface.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#if defined(__FreeBSD__) && defined(DEVFS)
#include <sys/devfsext.h>
#endif /*DEVFS*/
#include <net/if.h>
#include <net/altq_conf.h>
#include <netinet/altq.h>

#ifdef CBQ
altqdev_decl(cbq);
#endif
#ifdef WFQ
altqdev_decl(wfq);
#endif
#ifdef AFMAP
altqdev_decl(afm);
#endif
#ifdef FIFOQ
altqdev_decl(fifoq);
#endif
#ifdef RED
altqdev_decl(red);
#endif
#ifdef RIO
altqdev_decl(rio);
#endif
#ifdef LOCALQ
altqdev_decl(localq);
#endif
#ifdef HFSC
altqdev_decl(hfsc);
#endif
#ifdef CDNR
altqdev_decl(cdnr);
#endif
#ifdef BLUE
altqdev_decl(blue);
#endif

/*
 * altq minor device (discipline) table
 */
static struct altqsw altqsw[] = {				/* minor */
	{"noq",	noopen,		noclose,	noioctl},  /* 0 (reserved) */
#ifdef CBQ
	{"cbq",	cbqopen,	cbqclose,	cbqioctl},	/* 1 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 1 */
#endif
#ifdef WFQ
	{"wfq",	wfqopen,	wfqclose,	wfqioctl},	/* 2 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 2 */
#endif
#ifdef AFMAP
	{"afm",	afmopen,	afmclose,	afmioctl},	/* 3 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 3 */
#endif
#ifdef FIFOQ
	{"fifoq", fifoqopen,	fifoqclose,	fifoqioctl},	/* 4 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 4 */
#endif
#ifdef RED
	{"red", redopen,	redclose,	redioctl},	/* 5 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 5 */
#endif
#ifdef RIO
	{"rio", rioopen,	rioclose,	rioioctl},	/* 6 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 6 */
#endif
#ifdef LOCALQ
	{"localq",localqopen,	localqclose,	localqioctl}, /* 7 (local use) */
#else
	{"noq",	noopen,		noclose,	noioctl},  /* 7 (local use) */
#endif
#ifdef HFSC
	{"hfsc",hfscopen,	hfscclose,	hfscioctl},	/* 8 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 8 */
#endif
#ifdef CDNR
	{"cdnr",cdnropen,	cdnrclose,	cdnrioctl},	/* 9 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 9 */
#endif
#ifdef BLUE
	{"blue",blueopen,	blueclose,	blueioctl},	/* 10 */
#else
	{"noq",	noopen,		noclose,	noioctl},	/* 10 */
#endif
};

/*
 * altq major device support
 */
int	naltqsw = sizeof (altqsw) / sizeof (altqsw[0]);

static	d_open_t	altqopen;
static	d_close_t	altqclose;
static	d_ioctl_t	altqioctl;
#ifdef __FreeBSD__
static void altq_drvinit __P((void *));
#else
void	altqattach __P((int));
#endif

#if defined(__FreeBSD__)
#define CDEV_MAJOR 96		 /* FreeBSD official number */
#elif defined(__NetBSD__)
#define CDEV_MAJOR 65		 /* not official */
#endif

#ifndef __NetBSD__
static struct cdevsw altq_cdevsw = 
        { altqopen,	altqclose,	noread,	        nowrite,
	  altqioctl,	nostop,		nullreset,	nodevtotty,
 	  seltrue,	nommap,		NULL,	"altq",	NULL,	-1 };
#else
static struct cdevsw altq_cdevsw = cdev__oci_init(1,altq);
#endif

static int
altqopen(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	int unit = minor(dev);

	if (unit < naltqsw)
		return (*altqsw[unit].d_open)(dev, flag, fmt, p);

	return ENXIO;
}

static int
altqclose(dev, flag, fmt, p)
	dev_t dev;
	int flag, fmt;
	struct proc *p;
{
	int unit = minor(dev);

	if (unit < naltqsw)
		return (*altqsw[unit].d_close)(dev, flag, fmt, p);

	return ENXIO;
}

static int
altqioctl(dev, cmd, addr, flag, p)
	dev_t dev;
	ioctlcmd_t cmd;
	caddr_t addr;
	int flag;
	struct proc *p;
{
	int unit = minor(dev);

	if (unit < naltqsw)
		return (*altqsw[unit].d_ioctl)(dev, cmd, addr, flag, p);

	return ENXIO;
}


static int altq_devsw_installed = 0;

#ifdef __FreeBSD__
#ifdef DEVFS
static	void *altq_devfs_token[sizeof (altqsw) / sizeof (altqsw[0])];
#endif

static void
altq_drvinit(unused)
	void *unused;
{
	dev_t dev;
#ifdef DEVFS
	int i;
#endif

	if (!altq_devsw_installed) {
		dev = makedev(CDEV_MAJOR,0);
		cdevsw_add(&dev,&altq_cdevsw,NULL);
		altq_devsw_installed = 1;
#ifdef DEVFS
		for (i=0; i<naltqsw; i++)
			altq_devfs_token[i] =
				devfs_add_devswf(&altq_cdevsw, i, DV_CHR,
						 0, 0, 0644, altqsw[i].d_name);
#endif
		printf("altq: major number is %d\n", CDEV_MAJOR);
	}
}

SYSINIT(altqdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,altq_drvinit,NULL)

#else /* !__FreeBSD__ */

void
altqattach(int unused)
{
	if (!altq_devsw_installed) {
		bcopy(&altq_cdevsw,
		      &cdevsw[CDEV_MAJOR],
		      sizeof(struct cdevsw));
		altq_devsw_installed = 1;
		printf("altq: major number is %d\n", CDEV_MAJOR);
	}
}

#endif /* !__FreeBSD__ */

#ifdef ALTQ_KLD
/*
 * KLD support
 */
static int altq_module_register __P((struct altq_module_data *));
static int altq_module_deregister __P((struct altq_module_data *));

static struct altq_module_data *altq_modules[ALTQT_MAX];
static struct altqsw noqdisc = {"noq", noopen, noclose, noioctl};

void altq_module_incref(type)
	int type;
{
	if (type < 0 || type >= ALTQT_MAX || altq_modules[type] == NULL)
		return;

	altq_modules[type]->ref++;
}

void altq_module_declref(type)
	int type;
{
	if (type < 0 || type >= ALTQT_MAX || altq_modules[type] == NULL)
		return;

	altq_modules[type]->ref--;
}

static int 
altq_module_register(mdata)
	struct altq_module_data *mdata;
{
	int type = mdata->type;

	if (type < 0 || type >= ALTQT_MAX)
		return (EINVAL);
	if (altqsw[type].d_open != noopen)
		return (EBUSY);
	altqsw[type] = *mdata->altqsw;	/* set discipline functions */
	altq_modules[type] = mdata;	/* save module data pointer */
	return (0);
}

static int 
altq_module_deregister(mdata)
	struct altq_module_data *mdata;
{
	int type = mdata->type;

	if (type < 0 || type >= ALTQT_MAX)
		return (EINVAL);
	if (mdata != altq_modules[type])
		return (EINVAL);
	if (altq_modules[type]->ref > 0)
		return (EBUSY);
	altqsw[type] = noqdisc;
	altq_modules[type] = NULL;
	return (0);
}

int
altq_module_handler(mod, cmd, arg)
    module_t	mod;
    int cmd;
    void * arg;
{
	struct altq_module_data *data = (struct altq_module_data *)arg;
	int	error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = altq_module_register(data);
		break;

	case MOD_UNLOAD:
		error = altq_module_deregister(data);
		break;

	default:
		error = EINVAL;
		break;
	}

	return(error);
}
	
#endif  /* ALTQ_KLD */

#endif /* ALTQ */
