#! /bin/sh

bindtest='./bindtest -s'
port=9999
platform=$1
if test "x$platform" = "x"; then
	platform=foo
fi

# In the following sequence, the order of TCP tests is important.
# Since -1 or -2 options would make some TIME_WAIT sockets, tests without the
# SO_REUSExxx socket options must be done before others.
($bindtest -p $port
$bindtest -p -6 $port
$bindtest -A -p $port
$bindtest -A -p -6 $port
$bindtest -P -p $port
$bindtest -P -p -6 $port
$bindtest -AP -p $port
$bindtest -AP -p -6 $port
$bindtest -t -p $port
$bindtest -t -p -6 $port
$bindtest -t -A -1 -p $port
$bindtest -t -A -1 -p -6 $port
$bindtest -t -A -2 -p $port
$bindtest -t -A -2 -p -6 $port
$bindtest -t -P -1 -p $port
$bindtest -t -P -1 -p -6 $port
$bindtest -t -P -2 -p $port
$bindtest -t -P -2 -p -6 $port
$bindtest -t -AP -1 -p $port
$bindtest -t -AP -1 -p -6 $port
$bindtest -t -AP -2 -p $port
$bindtest -t -AP -2 -p -6 $port
echo
uname -a) > $platform
