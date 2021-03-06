/*
 * The new sysinstall program.
 *
 * This is probably the last attempt in the `sysinstall' line, the next
 * generation being slated to essentially a complete rewrite.
 *
 * $Id: floppy.c,v 1.16.2.9 1998/10/28 10:59:45 jkh Exp $
 *
 * Copyright (c) 1995
 *	Jordan Hubbard.  All rights reserved.
 * Copyright (c) 1995
 * 	Gary J Palmer. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    verbatim and that no modifications are made prior to this
 *    point in the file.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY JORDAN HUBBARD ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JORDAN HUBBARD OR HIS PETS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, LIFE OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/* These routines deal with getting things off of floppy media */

#include "sysinstall.h"
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>

#define MSDOSFS
#include <sys/mount.h>
#undef MSDOSFS

static Boolean floppyMounted;

char *distWanted;

Boolean
mediaInitFloppy(Device *dev)
{
    struct msdosfs_args dosargs;
    struct ufs_args u_args;
    char *mountpoint;

    if (floppyMounted)
	return TRUE;

    mountpoint = (char *)dev->private;
    if (Mkdir(mountpoint)) {
	msgConfirm("Unable to make %s directory mountpoint for %s!", mountpoint, dev->devname);
	return FALSE;
    }

    msgDebug("Init floppy called for %s distribution.\n", distWanted ? distWanted : "some");

    if (!variable_get(VAR_NONINTERACTIVE)) {
	if (!distWanted)
	    msgConfirm("Please insert floppy in %s", dev->description);
	else
	    msgConfirm("Please insert floppy containing %s in %s",
			distWanted, dev->description);
    }

    memset(&dosargs, 0, sizeof dosargs);
    dosargs.fspec = dev->devname;
    dosargs.uid = dosargs.gid = 0;
    dosargs.mask = 0777;

    memset(&u_args, 0, sizeof(u_args));
    u_args.fspec = dev->devname;

    if (mount(MOUNT_MSDOS, mountpoint, MNT_RDONLY, (caddr_t)&dosargs) == -1) {
	if (mount(MOUNT_UFS, mountpoint, MNT_RDONLY, (caddr_t)&u_args) == -1) {
	    msgConfirm("Error mounting floppy %s (%s) on %s : %s", dev->name, dev->devname, mountpoint,
		       strerror(errno));
	    return FALSE;
	}
    }
    msgDebug("initFloppy: mounted floppy %s successfully on %s\n", dev->devname, mountpoint);
    floppyMounted = TRUE;
    distWanted = NULL;
    return TRUE;
}

FILE *
mediaGetFloppy(Device *dev, char *file, Boolean probe)
{
    char	buf[PATH_MAX];
    FILE	*fp;
    int		nretries = 5;

    snprintf(buf, PATH_MAX, "%s/%s", (char *)dev->private, file);

    if (isDebug())
	msgDebug("Request for %s from floppy on %s, probe is %d.\n", buf, (char *)dev->private, probe);
    if (!file_readable(buf)) {
	if (probe)
	    return NULL;
	else {
	    while (!file_readable(buf)) {
		if (!--nretries) {
		    msgConfirm("GetFloppy: Failed to get %s after retries;\ngiving up.", buf);
		    return NULL;
		}
		distWanted = buf;
		mediaShutdownFloppy(dev);
		if (!mediaInitFloppy(dev))
		    return NULL;
	    }
	}
    }
    fp = fopen(buf, "r");
    return fp;
}

void
mediaShutdownFloppy(Device *dev)
{
    char *mountpoint = (char *)dev->private;

    if (floppyMounted) {
	if (unmount(mountpoint, MNT_FORCE) != 0)
	    msgDebug("Umount of floppy on %s failed: %s (%d)\n", mountpoint, strerror(errno), errno);
	else {
	    floppyMounted = FALSE;
	    msgDebug("Floppy unmounted successfully.\n");
	    if (!variable_get(VAR_NONINTERACTIVE))
		msgConfirm("You may remove the floppy from %s",
			   dev->description);
	}
    }
}
