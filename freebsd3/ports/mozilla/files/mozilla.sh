#!/bin/sh
#
# $FreeBSD: ports/www/mozilla/files/mozilla.sh,v 1.2 2000/08/03 14:39:06 sobomax Exp $

cd @PREFIX@/lib/mozilla
exec ./mozilla $*
