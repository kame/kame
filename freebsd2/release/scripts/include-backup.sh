#!/bin/sh
release=`sysctl -n kern.osrelease`
src=/usr/include
dst=/usr/include.$release
test -e $dst && exit 1
mkdir $dst
tar -cpBf - -C $src . | tar -xpBf - -C $dst
