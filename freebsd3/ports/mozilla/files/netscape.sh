#!/bin/sh
#
#	$Id: netscape.sh,v 1.1 1999/08/17 09:10:05 itojun Exp $

export MOZILLA_HOME; MOZILLA_HOME=${MOZILLA_HOME:=@PREFIX@/lib/mozilla}
export MOZILLA_BIN; MOZILLA_BIN=${MOZILLA_BIN:=@PREFIX@/lib/mozilla/bin}
export CLASSPATH ; CLASSPATH=.:$MOZILLA_HOME
export XCMSDB; XCMSDB=/dev/null

LD_LIBRARY_PATH=$MOZILLA_BIN exec $MOZILLA_BIN/moz-export $*
