/*	$NetBSD: conf.h,v 1.4 2002/04/19 01:43:49 wiz Exp $	*/

/*
 * Copyright (c) 1997 Mark Brinicombe.
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
 *	This product includes software developed by Mark Brinicombe
 *	for the NetBSD Project.
 * 4. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * RiscBSD kernel project
 *
 * conf.h
 *
 * Prototypes for device driver functions
 */
 
#include <sys/conf.h>

bdev_decl(wd);
cdev_decl(wd);
bdev_decl(sw);
cdev_decl(sw);
bdev_decl(fd);
cdev_decl(fd);
bdev_decl(md);
cdev_decl(md);
bdev_decl(raid);
cdev_decl(raid);

/* Character device declarations */

/* open, close, read, write, ioctl, tty, mmap -- XXX should be a tty */
#define	cdev_physcon_init(c,n)	cdev__ttym_init(c,n,0)

/* open, close, ioctl */
#define	cdev_beep_init(c,n)	cdev__oci_init(c,n)

/* open, close, read, ioctl */
#define	cdev_kbd_init(c,n)	cdev__ocri_init(c,n)

/* open, close, ioctl, mmap */
#define	cdev_vidcvid_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_noimpl(read,enodev), \
	dev_noimpl(write,enodev), dev_init(c,n,ioctl), \
	dev_noimpl(stop,enodev), 0, seltrue, dev_init(c,n,mmap), 0 }

/* open, close, read, write, ioctl */
#define	cdev_iic_init(c,n)	cdev__ocrwi_init(c,n)
#define	cdev_rtc_init(c,n)	cdev__ocrwi_init(c,n)

/* open, close, read, ioctl */
#define	cdev_prof_init(c,n)	cdev__ocri_init(c,n)

cdev_decl(physcon);
cdev_decl(vidcconsole);
cdev_decl(com);
cdev_decl(lpt);
cdev_decl(qms);
cdev_decl(opms);
cdev_decl(beep);
cdev_decl(kbd);
cdev_decl(iic);
cdev_decl(rtc);
cdev_decl(fcom);
cdev_decl(pc);
#ifdef	OFW
cdev_decl(ofcons_);
cdev_decl(ofd);
cdev_decl(ofrtc);
#endif
cdev_decl(scr);
cdev_decl(prof);
#define	ofromread  ofromrw
#define	ofromwrite ofromrw
cdev_decl(ofrom);
cdev_decl(joy);
cdev_decl(usb);
cdev_decl(uhid);
cdev_decl(ugen);
cdev_decl(ulpt);
cdev_decl(ucom);
cdev_decl(urio);
cdev_decl(uscanner);
cdev_decl(vc_nb_);
cdev_decl(wsdisplay);
cdev_decl(wskbd);
cdev_decl(wsmouse);
cdev_decl(wsmux);
cdev_decl(scsibus);
cdev_decl(openfirm);
