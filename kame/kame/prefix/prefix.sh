#!/bin/sh

iface=$1
prefix=$2

usage() {
    echo "usage: prefix interface prefix [set|delete]"
}

if [ -z $iface -o -z $prefix ]; then
    usage
    exit 1
fi

if [ -z $3 ]; then
    command=set
else
    command=$3
fi

case $command in
    set)
	laddr=`ifconfig $iface inet6 | grep 'inet6 fe80:' | head -1 | awk '{print $2}'` 
	if [ -z $laddr ]; then
	    echo "prefix: no interface ID found"
	    exit 1
	fi
	hostid=`echo $laddr | sed -e 's/fe80::/fe80::/' -e 's/fe80:://' -e 's/%.*//'`
	address=$2\:$hostid
	echo $address
	exec ifconfig $iface inet6 $address prefixlen 64 alias
    ;;
    delete)
    	addrs=`ifconfig ed0 inet6 | grep "inet6 $prefix" |  awk '{print $2}'`
	for a in $addrs; do
	    ifconfig $iface inet6 $a -alias
	done
    ;;
    *)
    usage
    exit 1
    ;;
esac
