/* $NetBSD: conf.c,v 1.47.2.1 2001/05/01 10:42:41 he Exp $ */

/*-
 * Copyright (c) 1991 The Regents of the University of California.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *      @(#)conf.c	7.9 (Berkeley) 5/28/91
 */

#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */

__KERNEL_RCSID(0, "$NetBSD: conf.c,v 1.47.2.1 2001/05/01 10:42:41 he Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/vnode.h>

#include <machine/conf.h>

#include <vm/vm.h>		/* XXX for _PMAP_MAY_USE_PROM_CONSOLE */

#include "fdc.h"
bdev_decl(fd);
bdev_decl(sw);
#include "st.h"
bdev_decl(st);
#include "cd.h"
bdev_decl(cd);
#include "wd.h"
bdev_decl(wd);
#include "sd.h"
bdev_decl(sd);
#include "vnd.h"
bdev_decl(vnd);
#include "raid.h"
bdev_decl(raid);
#include "ccd.h"
bdev_decl(ccd);
#include "md.h"
bdev_decl(md);
#include "ca.h"
bdev_decl(ca);

struct bdevsw	bdevsw[] =
{
	bdev_disk_init(NFDC,fd),	/* 0: PC-ish floppy disk driver */
	bdev_swap_init(1,sw),		/* 1: swap pseudo-device */
	bdev_tape_init(NST,st),		/* 2: SCSI tape */
	bdev_disk_init(NCD,cd),		/* 3: SCSI CD-ROM */
	bdev_disk_init(NWD,wd),		/* 4: IDE disk driver */
	bdev_notdef(),			/* 5 */
	bdev_disk_init(NMD,md),		/* 6: memory disk driver */
	bdev_disk_init(NCCD,ccd),	/* 7: concatenated disk driver */
	bdev_disk_init(NSD,sd),		/* 8: SCSI disk driver */
	bdev_disk_init(NVND,vnd),	/* 9: vnode disk driver */
	bdev_lkm_dummy(),		/* 10 */
	bdev_lkm_dummy(),		/* 11 */
	bdev_lkm_dummy(),		/* 12 */
	bdev_lkm_dummy(),		/* 13 */
	bdev_lkm_dummy(),		/* 14 */
	bdev_lkm_dummy(),		/* 15 */
	bdev_disk_init(NRAID,raid),	/* 16: RAIDframe disk driver */
	bdev_disk_init(NCA,ca),		/* 17: Compaq array */
};
int	nblkdev = sizeof (bdevsw) / sizeof (bdevsw[0]);

/* open, close, write, ioctl */
#define cdev_lpt_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), (dev_type_read((*))) enodev, \
	dev_init(c,n,write), dev_init(c,n,ioctl), (dev_type_stop((*))) enodev, \
	0, seltrue, (dev_type_mmap((*))) enodev }

/* open, close, read, ioctl, poll */
#define cdev_satlink_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_init(c,n,read), \
	(dev_type_write((*))) enodev, dev_init(c,n,ioctl), \
	(dev_type_stop((*))) enodev, 0, dev_init(c,n,poll), \
	(dev_type_mmap((*))) enodev }

cdev_decl(cn);
cdev_decl(ctty);
#define	mmread  mmrw
#define	mmwrite mmrw
cdev_decl(mm);
cdev_decl(sw);
#include "pty.h"
#define	ptstty		ptytty
#define	ptsioctl	ptyioctl
cdev_decl(pts);
#define	ptctty		ptytty
#define	ptcioctl	ptyioctl
cdev_decl(ptc);
cdev_decl(log);
#include "tun.h"
cdev_decl(tun);
cdev_decl(sd);
cdev_decl(vnd);
cdev_decl(ccd);
dev_type_open(filedescopen);
#include "bpfilter.h"
cdev_decl(bpf);
cdev_decl(st);
cdev_decl(cd);
#include "ch.h"
cdev_decl(ch);
#include "audio.h"
cdev_decl(audio);
#include "com.h"
cdev_decl(com);
cdev_decl(kbd);
cdev_decl(ms);
#include "lpt.h"
cdev_decl(lpt);
cdev_decl(md);
cdev_decl(raid);
#include "ses.h"
cdev_decl(ses);
#include "ss.h"
cdev_decl(ss);
#include "uk.h"
cdev_decl(uk);
cdev_decl(fd);
#include "ipfilter.h"
cdev_decl(ipl);
cdev_decl(wd);
#include "satlink.h"
cdev_decl(satlink);
#include "midi.h"
cdev_decl(midi);
#include "sequencer.h"
cdev_decl(music);

#include "a12dc.h"
#include "scc.h"
#include "zstty.h"

#include "cy.h"
cdev_decl(cy);
#include "cz.h"
cdev_decl(cztty);

#include "se.h"
#include "rnd.h"

#include "wsdisplay.h"
cdev_decl(wsdisplay);
#include "wskbd.h"
cdev_decl(wskbd);
#include "wsmouse.h"
cdev_decl(wsmouse);
#include "wsmux.h"
cdev_decl(wsmux);

#include "spkr.h"
cdev_decl(spkr);

#include "scsibus.h"
cdev_decl(scsibus);

#include "esh.h"
cdev_decl(esh_fp);

#include "usb.h"
cdev_decl(usb); 
#include "uhid.h"
cdev_decl(uhid);
#include "ugen.h"
cdev_decl(ugen);
#include "ulpt.h"
cdev_decl(ulpt);
#include "ucom.h"
cdev_decl(ucom);

#ifdef __I4B_IS_INTEGRATED
/* open, close, ioctl */
#define cdev_i4bctl_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), (dev_type_read((*))) enodev, \
	(dev_type_write((*))) enodev, dev_init(c,n,ioctl), \
	(dev_type_stop((*))) enodev, 0, seltrue, \
	(dev_type_mmap((*))) enodev }

/* open, close, read, write */
#define	cdev_i4brbch_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_init(c,n,read), \
	dev_init(c,n,write), dev_init(c,n,ioctl), \
	(dev_type_stop((*))) enodev, \
	0, dev_init(c,n,poll), (dev_type_mmap((*))) enodev }

/* open, close, read, write */
#define	cdev_i4btel_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_init(c,n,read), \
	dev_init(c,n,write), (dev_type_ioctl((*))) enodev, \
	(dev_type_stop((*))) enodev, \
	0, dev_init(c,n,poll), (dev_type_mmap((*))) enodev, D_TTY }

/* open, close, read, ioctl */
#define cdev_i4btrc_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_init(c,n,read), \
	(dev_type_write((*))) enodev, dev_init(c,n,ioctl), \
	(dev_type_stop((*))) enodev, 0, (dev_type_poll((*))) enodev, \
	(dev_type_mmap((*))) enodev }

/* open, close, read, poll, ioctl */
#define cdev_i4b_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_init(c,n,read), \
	(dev_type_write((*))) enodev, dev_init(c,n,ioctl), \
	(dev_type_stop((*))) enodev, 0, dev_init(c,n,poll), \
	(dev_type_mmap((*))) enodev }	

#include "i4b.h"
#include "i4bctl.h"
#include "i4btrc.h"
#include "i4brbch.h"
#include "i4btel.h"
cdev_decl(i4b);
cdev_decl(i4bctl);
cdev_decl(i4btrc);
cdev_decl(i4brbch);
cdev_decl(i4btel);
#endif

struct cdevsw	cdevsw[] =
{
	cdev_cn_init(1,cn),		/* 0: virtual console */
	cdev_ctty_init(1,ctty),		/* 1: controlling terminal */
	cdev_mm_init(1,mm),		/* 2: /dev/{null,mem,kmem,...} */
	cdev_swap_init(1,sw),		/* 3: /dev/drum (swap pseudo-device) */
	cdev_tty_init(NPTY,pts),	/* 4: pseudo-tty slave */
	cdev_ptc_init(NPTY,ptc),	/* 5: pseudo-tty master */
	cdev_log_init(1,log),		/* 6: /dev/klog */
	cdev_bpftun_init(NTUN,tun),	/* 7: network tunnel */
	cdev_disk_init(NSD,sd),		/* 8: SCSI disk */
	cdev_disk_init(NVND,vnd),	/* 9: vnode disk driver */
	cdev_fd_init(1,filedesc),	/* 10: file descriptor pseudo-dev */
	cdev_bpftun_init(NBPFILTER,bpf),/* 11: Berkeley packet filter */
	cdev_tape_init(NST,st),		/* 12: SCSI tape */
	cdev_disk_init(NCD,cd),		/* 13: SCSI CD-ROM */
	cdev_ch_init(NCH,ch),		/* 14: SCSI autochanger */
#if NZSTTY > 0
	cdev_tty_init(NZSTTY,zs),	/* 15: SCC 8530 serial port tty */
#else
	cdev_tty_init(NSCC,scc),	/* 15: scc 8530 serial interface */
#endif
	cdev_lkm_init(NLKM,lkm),	/* 16: loadable module driver */
	cdev_lkm_dummy(),		/* 17 */
	cdev_lkm_dummy(),		/* 18 */
	cdev_lkm_dummy(),		/* 19 */
	cdev_lkm_dummy(),		/* 20 */
	cdev_lkm_dummy(),		/* 21 */
	cdev_lkm_dummy(),		/* 22 */
#ifdef _PMAP_MAY_USE_PROM_CONSOLE
	cdev_tty_init(1,prom),          /* 23: XXX prom console */
#else
	cdev_notdef(),			/* 23 */
#endif
	cdev_audio_init(NAUDIO,audio),	/* 24: generic audio I/O */
	cdev_wsdisplay_init(NWSDISPLAY,
	    wsdisplay),			/* 25: frame buffers, etc. */
	cdev_tty_init(NCOM,com),	/* 26: ns16550 UART */
	cdev_disk_init(NCCD,ccd),	/* 27: concatenated disk driver */
	cdev_disk_init(NMD,md),		/* 28: memory disk driver */
	cdev_mouse_init(NWSKBD, wskbd),	/* 29: keyboards */
	cdev_mouse_init(NWSMOUSE,
	    wsmouse),			/* 30: mice */
	cdev_lpt_init(NLPT,lpt),	/* 31: parallel printer */
	cdev_scanner_init(NSS,ss),	/* 32: SCSI scanner */
	cdev_uk_init(NUK,uk),		/* 33: SCSI unknown */
	cdev_disk_init(NFDC,fd),	/* 34: PC-ish floppy disk driver */
	cdev_ipf_init(NIPFILTER,ipl),	/* 35: ip-filter device */
	cdev_disk_init(NWD,wd),		/* 36: IDE disk driver */
	cdev_se_init(NSE,se),		/* 37: Cabletron SCSI<->Ethernet */
	cdev_satlink_init(NSATLINK,satlink), /* 38: planetconnect satlink */
	cdev_rnd_init(NRND,rnd),	/* 39: random source pseudo-device */
	cdev_tty_init(NA12DC,a12dc),	/* 40: Avalon A12 detached console */
	cdev_spkr_init(NSPKR,spkr),	/* 41: PC speaker */
	cdev_scsibus_init(NSCSIBUS,scsibus), /* 42: SCSI bus */
	cdev_disk_init(NRAID,raid),	/* 43: RAIDframe disk driver */
	cdev_esh_init(NESH, esh_fp),	/* 44: HIPPI (esh) raw device */
	cdev_usb_init(NUSB,usb),	/* 45: USB controller */
	cdev_usbdev_init(NUHID,uhid),	/* 46: USB generic HID */
	cdev_lpt_init(NULPT,ulpt),	/* 47: USB printer */
	cdev_ugen_init(NUGEN,ugen),	/* 48: USB generic driver */
	cdev_midi_init(NMIDI,midi),	/* 49: MIDI I/O */
	cdev_midi_init(NSEQUENCER,sequencer),	/* 50: sequencer I/O */
#ifdef __I4B_IS_INTEGRATED
	cdev_i4b_init(NI4B, i4b),		/* 51: i4b main device */
	cdev_i4bctl_init(NI4BCTL, i4bctl),	/* 52: i4b control device */
	cdev_i4brbch_init(NI4BRBCH, i4brbch),	/* 53: i4b raw b-chnl access */
	cdev_i4btrc_init(NI4BTRC, i4btrc),	/* 54: i4b trace device */
	cdev_i4btel_init(NI4BTEL, i4btel),	/* 55: i4b phone device */
#else
	cdev_notdef(),			/* 51 */
	cdev_notdef(),			/* 52 */
	cdev_notdef(),			/* 53 */
	cdev_notdef(),			/* 54 */
	cdev_notdef(),			/* 55 */
#endif
	cdev_mouse_init(NWSMUX, wsmux),	/* 56: ws multiplexor */
	cdev_tty_init(NUCOM, ucom),	/* 57: USB tty */
	cdev_ses_init(NSES,ses),	/* 58: SCSI SES/SAF-TE */
	cdev_disk_init(NCA,ca),		/* 59: Compaq array */
	cdev_tty_init(NCY,cy),		/* 60: Cyclades Cyclom-Y serial */
	cdev_tty_init(NCZ,cztty),	/* 61: Cyclades-Z serial */
#ifdef ALTQ
	cdev_notdef(),			/* 62: ALTQ */
#endif
};
int	nchrdev = sizeof (cdevsw) / sizeof (cdevsw[0]);

int	mem_no = 2; 	/* major device number of memory special file */

/*
 * Swapdev is a fake device implemented
 * in sw.c used only internally to get to swstrategy.
 * It cannot be provided to the users, because the
 * swstrategy routine munches the b_dev and b_blkno entries
 * before calling the appropriate driver.  This would horribly
 * confuse, e.g. the hashing routines. Instead, /dev/drum is
 * provided as a character (raw) device.
 */
dev_t	swapdev = makedev(1, 0);

/*
 * Returns true if dev is /dev/mem or /dev/kmem.
 */
int
iskmemdev(dev)
	dev_t dev;
{

	return (major(dev) == mem_no && minor(dev) < 2);
}

/*
 * Returns true if dev is /dev/zero.
 */
int
iszerodev(dev)
	dev_t dev;
{

	return (major(dev) == mem_no && minor(dev) == 12);
}

static int chrtoblktbl[] = {
	/* XXXX This needs to be dynamic for LKMs. */
	/*VCHR*/	/*VBLK*/
	/*  0 */	NODEV,
	/*  1 */	NODEV,
	/*  2 */	NODEV,
	/*  3 */	NODEV,
	/*  4 */	NODEV,
	/*  5 */	NODEV,
	/*  6 */	NODEV,
	/*  7 */	NODEV,
	/*  8 */	8,		/* sd */
	/*  9 */	9,		/* vnd */
	/* 10 */	NODEV,
	/* 11 */	NODEV,
	/* 12 */	2,		/* st */
	/* 13 */	3,		/* cd */
	/* 14 */	NODEV,
	/* 15 */	NODEV,
	/* 16 */	NODEV,
	/* 17 */	NODEV,
	/* 18 */	NODEV,
	/* 19 */	NODEV,
	/* 20 */	NODEV,
	/* 21 */	NODEV,
	/* 22 */	NODEV,
	/* 23 */	NODEV,
	/* 24 */	NODEV,
	/* 25 */	NODEV,
	/* 26 */	NODEV,
	/* 27 */	7,		/* ccd */
	/* 28 */	6,		/* md */
	/* 29 */	NODEV,
	/* 30 */	NODEV,
	/* 31 */	NODEV,
	/* 32 */	NODEV,
	/* 33 */	NODEV,
	/* 34 */	0,		/* fd */
	/* 35 */	NODEV,
	/* 36 */	4,		/* wd */
	/* 37 */	NODEV,
	/* 38 */	NODEV,
	/* 39 */	NODEV,
	/* 40 */	NODEV,
	/* 41 */	NODEV,
	/* 42 */	NODEV,
	/* 43 */	16,
	/* 44 */	NODEV,
	/* 45 */	NODEV,
	/* 46 */	NODEV,
	/* 47 */	NODEV,
	/* 48 */	NODEV,
	/* 49 */	NODEV,
	/* 50 */	NODEV,
	/* 51 */	NODEV,
	/* 52 */	NODEV,
	/* 53 */	NODEV,
	/* 54 */	NODEV,
	/* 55 */	NODEV,
	/* 56 */	NODEV,
	/* 57 */	NODEV,
	/* 58 */	NODEV,
	/* 59 */	17,
	/* 60 */	NODEV,
	/* 61 */	NODEV,
};

/*
 * Convert a character device number to a block device number.
 */
dev_t
chrtoblk(dev)
	dev_t dev;
{
	int blkmaj;

	if (major(dev) >= nchrdev)
		return (NODEV);
	blkmaj = chrtoblktbl[major(dev)];
	if (blkmaj == NODEV)
		return (NODEV);
	return (makedev(blkmaj, minor(dev)));
}
