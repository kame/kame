#! /bin/sh
#
# build script for KAME buildlab.  may not be useful for normal usage.
# $KAME: build.sh,v 1.5 2001/02/05 00:58:21 itojun Exp $
#

echo the script is only for KAME buildlab, it is not useful in general
exit 1

PATH=/usr/pkg/bin:/usr/local/bin:/usr/X11R6/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
HOME=/home/buildlab
export HOME

x=`find /var/tmp -name autobuild\* -print`
if test "x" != "x$x"; then
	mail -s "two autobuilds running: $hostname around $date" buildlab@kame.net <<EOF
two autobuilds are running.
EOF
	exit 0
fi

if ! test -f $HOME/.cvspass; then
	cat <<EOF >$HOME/.cvspass
:pserver:anoncvs@anoncvs.kame.net:/cvsroot/kame Ay=0=h<Z
EOF
fi

cd ~buildlab/k/kame
hostname=`hostname`
hosttop=`echo $hostname | sed -e 's/\..*//'`
date=`date`
make TARGET=$hosttop AUTOBUILD_COOKIE=/var/tmp/done.$$ autobuild 2>&1 | tee /var/tmp/autobuild.$$ | mail -s "$hostname autobuild at $date" $hosttop@buildlab.kame.net
if ! test -f /var/tmp/done.$$; then
	mail -s "autobuild failure: $hostname around $date" buildlab@kame.net <<EOF
autobuild on $hostname seem to have failed.
started: $date
finished: `date`
result URL: http://master.buildlab.kame.net/$hosttop/
EOF
fi
rm /var/tmp/autobuild.$$
rm /var/tmp/done.$$
