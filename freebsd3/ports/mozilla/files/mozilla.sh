#!/bin/sh
#
# $FreeBSD: ports/www/mozilla/files/mozilla.sh,v 1.1 2000/02/04 07:45:33 reg Exp $

cd @PREFIX@/lib/mozilla
exec ./mozilla $*
