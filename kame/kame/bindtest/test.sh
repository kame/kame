#! /bin/sh

bindtest='./bindtest -s'
port=9999
platform=foo

($bindtest -p $port; echo; uname -a) > $platform.dgram.0
($bindtest -A -p $port; echo; uname -a) > $platform.dgram.reuseaddr
($bindtest -P -p $port; echo; uname -a) > $platform.dgram.reuseport
($bindtest -AP -p $port; echo; uname -a) > $platform.dgram.reuseaddrport
($bindtest -t -p $port; echo; uname -a) > $platform.stream.0
($bindtest -t -A -p $port; echo; uname -a) > $platform.stream.reuseaddr
($bindtest -t -P -p $port; echo; uname -a) > $platform.stream.reuseport
($bindtest -t -AP -p $port; echo; uname -a) > $platform.stream.reuseaddrport
