#!/bin/sh

# Example of setting up SAs and SPD entry between e.g. Mobile Node and
# Home Agent.

local=3ffe:200:8:0:202:b3ff:fe21:d983
local_spi=1400
remote=3ffe:200:8:0:202:b3ff:fe21:cacd
remote_spi=1500

setkey -c <<EOF

spdflush;
flush;

add $remote $local ah $remote_spi -m transport -A hmac-md5 \
"1234567890123456";
add $local $remote ah $local_spi  -m transport -A hmac-md5 \
"1234567890123456";

spdadd $local $remote any -P out ipsec
	ah/transport/$local-$remote/require;

EOF
