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
$bindtest -6 -p $port
$bindtest -A -p $port
$bindtest -A -6 -p $port
$bindtest -P -p $port
$bindtest -P -6 -p $port
$bindtest -AP -p $port
$bindtest -AP -6 -p $port
$bindtest -t -p $port
$bindtest -t -6 -p $port
$bindtest -t -A -1 -p $port
$bindtest -l -t -A -1 -p $port
$bindtest -t -A -1 -6 -p $port
$bindtest -l -t -A -1 -6 -p $port
$bindtest -t -A -2 -p $port
$bindtest -l -t -A -2 -p $port
$bindtest -t -A -2 -6 -p $port
$bindtest -l -t -A -2 -6 -p $port
$bindtest -t -P -1 -p $port
$bindtest -l -t -P -1 -p $port
$bindtest -t -P -1 -6 -p $port
$bindtest -l -t -P -1 -6 -p $port
$bindtest -t -P -2 -p $port
$bindtest -l -t -P -2 -p $port
$bindtest -t -P -2 -6 -p $port
$bindtest -l -t -P -2 -6 -p $port
$bindtest -t -AP -1 -p $port
$bindtest -l -t -AP -1 -p $port
$bindtest -t -AP -1 -6 -p $port
$bindtest -l -t -AP -1 -6 -p $port
$bindtest -t -AP -2 -p $port
$bindtest -l -t -AP -2 -p $port
$bindtest -t -AP -2 -6 -p $port
$bindtest -l -t -AP -2 -6 -p $port
echo
uname -a) > $platform
