#! /bin/sh

bindtest='./bindtest -s'
port=9999
platform=$1
if test "x$platform" = "x"; then
	platform=foo
fi

($bindtest -p $port
$bindtest -A -p $port
$bindtest -P -p $port
$bindtest -AP -p $port
$bindtest -t -p $port
$bindtest -t -A -p $port
$bindtest -t -P -p $port
$bindtest -t -AP -p $port
echo
uname -a) > $platform
