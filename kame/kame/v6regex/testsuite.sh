interface=`ifconfig -l | awk '{print $1}'`

echo '==> valid IPv4 address'
./v6regex 127.0.0.1
./v6regex 0.0.0.0
./v6regex 255.255.255.255

echo '==> still valid'
./v6regex 10
./v6regex 10.1

echo '==> invalid IPv4 address'
./v6regex 999.999.999.999
./v6regex 255.255.255.256

echo '==> valid IPv6 address'
./v6regex ::
./v6regex ::1
./v6regex 0::
./v6regex 0::0
./v6regex 0:1:2:3:4:5:6:7
./v6regex ::10.1.1.1
./v6regex ::ffff:10.1.1.1
./v6regex ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
./v6regex 0000:0000:0000:0000:0000:0000:0000:0000

echo '==> invalid IPv6 address'
./v6regex ::10.1.1
./v6regex 0::0:0:0::0
./v6regex ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffff
./v6regex gggg:gggg:gggg:gggg:gggg:gggg:gggg:gggg

echo '==> with KAME scoped'
./v6regex fe80::1@10
./v6regex fe80::1@$interface

echo '==> with KAME scoped, should be considered invalid.'
# site-local is a bit controversial but the code does not support it yet.
./v6regex fe80::1@mumbojumbo
./v6regex fec0::1@$interface
./v6regex 3ffe::1@$interface

echo '==> with new scoped proposal'
./v6regex 10%fe80::1
./v6regex $interface%fe80::1

echo '==> with new scoped proposal, should be considered invalid'
# again, site-local is a bit controversial.
./v6regex mumbojumbo%fe80::1
./v6regex $interface%fec0::1
./v6regex $interface%3ffe::1
