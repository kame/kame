#	$NetBSD: Makefile,v 1.5.4.1 2000/10/09 13:43:29 fvdl Exp $

TOP=	${.CURDIR}/..

.include "${TOP}/Makefile.inc"

IMAGE=	boot-tiny.fs
KERN!=	cd $(.CURDIR)/../kernel-ramdisk/; \
        printf "xxx: .MAKE\n\t@echo \$${.OBJDIR}/netbsd.INSTALL_TINY.gz\n" | \
	${MAKE} -s -f-

DISKTYPE=	floppy5
DISKSIZE=	2400
BLOCK8K=	149

.include "${TOP}/bootfloppy-common/Makefile.inc"
