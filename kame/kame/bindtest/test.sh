#! /bin/sh

while getopts "o:" option
do
    case $option in
    o)
    	otheraddr=$OPTARG
	shift
	;;
    esac
    shift
done

bindtest='./bindtest -s'
port=9999
platform=$1
if test "x$platform" = "x"; then
	platform=foo
fi
if test "x$otheraddr" = "x" -o "x$otheraddr" = "x127.0.0.1" ; then
	echo "speciy an additional (not 127.0.0.1) IPv4 address on the test node."
	echo "sample usage: sh test.sh -o 10.0.0.1 result.txt"
	exit 1
fi
otheraddr6=::ffff:$otheraddr

# In the following sequence, the order of TCP tests is important.
# Since -1 or -2 options would make some TIME_WAIT sockets, tests without the
# SO_REUSExxx socket options must be done before others.
($bindtest -v

$bindtest -p $port -o $otheraddr
$bindtest -6 -p $port -o $otheraddr
$bindtest -A -p $port -o $otheraddr
$bindtest -A -6 -p $port -o $otheraddr
$bindtest -P -p $port -o $otheraddr
$bindtest -P -6 -p $port -o $otheraddr
$bindtest -AP -p $port -o $otheraddr
$bindtest -AP -6 -p $port -o $otheraddr

$bindtest -t -p $port
$bindtest -t -6 -p $port

$bindtest -t -A -1 -p $port
$bindtest -l -t -A -1 -p $port
$bindtest -t -A -1 -6 -p $port
$bindtest -l -t -A -1 -6 -p $port

$bindtest -t -A -o $otheraddr -p $port
$bindtest -t -A -o $otheraddr6 -p $port
$bindtest -l -t -A -o $otheraddr -p $port
$bindtest -l -t -A -o $otheraddr6 -p $port
$bindtest -t -A -o $otheraddr -6 -p $port
$bindtest -t -A -o $otheraddr6 -6 -p $port
$bindtest -l -t -A -o $otheraddr -6 -p $port
$bindtest -l -t -A -o $otheraddr6 -6 -p $port

$bindtest -t -A -2 -p $port
$bindtest -l -t -A -2 -p $port
$bindtest -t -A -2 -6 -p $port
$bindtest -l -t -A -2 -6 -p $port

$bindtest -t -A -o $otheraddr -p $port
$bindtest -t -A -o $otheraddr6 -p $port
$bindtest -l -t -A -o $otheraddr -p $port
$bindtest -l -t -A -o $otheraddr6 -p $port
$bindtest -t -A -o $otheraddr -6 -p $port
$bindtest -t -A -o $otheraddr6 -6 -p $port
$bindtest -l -t -A -o $otheraddr -6 -p $port
$bindtest -l -t -A -o $otheraddr6 -6 -p $port

$bindtest -t -P -1 -p $port
$bindtest -l -t -P -1 -p $port
$bindtest -t -P -1 -6 -p $port
$bindtest -l -t -P -1 -6 -p $port

$bindtest -t -P -o $otheraddr -p $port
$bindtest -t -P -o $otheraddr6 -p $port
$bindtest -l -t -P -o $otheraddr -p $port
$bindtest -l -t -P -o $otheraddr6 -p $port
$bindtest -t -P -o $otheraddr -6 -p $port
$bindtest -t -P -o $otheraddr6 -6 -p $port
$bindtest -l -t -P -o $otheraddr -6 -p $port
$bindtest -l -t -P -o $otheraddr6 -6 -p $port

$bindtest -t -P -2 -p $port
$bindtest -l -t -P -2 -p $port
$bindtest -t -P -2 -6 -p $port
$bindtest -l -t -P -2 -6 -p $port

$bindtest -t -P -o $otheraddr -p $port
$bindtest -t -P -o $otheraddr6 -p $port
$bindtest -l -t -P -o $otheraddr -p $port
$bindtest -l -t -P -o $otheraddr6 -p $port
$bindtest -t -P -o $otheraddr -6 -p $port
$bindtest -t -P -o $otheraddr6 -6 -p $port
$bindtest -l -t -P -o $otheraddr -6 -p $port
$bindtest -l -t -P -o $otheraddr6 -6 -p $port

$bindtest -t -AP -1 -p $port
$bindtest -l -t -AP -1 -p $port
$bindtest -t -AP -1 -6 -p $port
$bindtest -l -t -AP -1 -6 -p $port

$bindtest -t -AP -o $otheraddr -p $port
$bindtest -t -AP -o $otheraddr6 -p $port
$bindtest -l -t -AP -o $otheraddr -p $port
$bindtest -l -t -AP -o $otheraddr6 -p $port
$bindtest -t -AP -o $otheraddr -6 -p $port
$bindtest -t -AP -o $otheraddr6 -6 -p $port
$bindtest -l -t -AP -o $otheraddr -6 -p $port
$bindtest -l -t -AP -o $otheraddr6 -6 -p $port

$bindtest -t -AP -2 -p $port
$bindtest -l -t -AP -2 -p $port
$bindtest -t -AP -2 -6 -p $port
$bindtest -l -t -AP -2 -6 -p $port

echo
uname -a) > $platform
