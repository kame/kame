#!/bin/sh
release=`sysctl -n kern.osrelease`
src=/usr/src/sys
dst=/usr/src/sys.$release
test -e $dst && exit 1
mkdir $dst
tar -cpBf - -C $src . | tar -xpBf - -C $dst
