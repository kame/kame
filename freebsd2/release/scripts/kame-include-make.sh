#!/bin/sh
cd /usr/include || exit 1
cd /usr/src/kame/freebsd2
make includes
make install-includes
mv /usr/src/sys /usr/src/sys.old
ln -s /usr/src/kame/freebsd2/sys /usr/src/sys
cd /usr/src/sys/i386/include
cp apm_bios.h if_cnwioctl.h clock.h cpu.h scc.h wavelan.h /usr/include/machine
cp /usr/src/sys/pccard/*.h /usr/include/pccard
