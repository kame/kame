#!/bin/sh
test ! -d /usr/src/sys && exit 1
cp /stand/KAME/GENERIC.PAO.v6 /usr/src/sys/i386/conf
cd /usr/src/sys/i386/conf
config GENERIC.PAO.v6
cd ../../compile/GENERIC.PAO.v6
make depend && make && make install
