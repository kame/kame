#!/bin/sh
cp -p /stand/PAO/etc/rc.pccard /etc
cp -p /stand/PAO/etc/pccard_ether* /etc
cp -p /stand/PAO/etc/pccard.conf /etc
mv /etc/rc.conf /etc/rc.conf.orig
cp -p /stand/PAO/etc/rc.conf /etc
cd /dev
sh MAKEDEV apm card0 card1 card2 card3 bpf0 bpf1 bpf2 bpf3
ln -s apm apm0
