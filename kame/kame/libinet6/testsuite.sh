#
TEST=./test
#TEST='./test -v'

$TEST ::1 http
$TEST ::1 echo
$TEST ::1 tftp
$TEST 127.0.0.1 http
$TEST 127.0.0.1 echo
$TEST 127.0.0.1 tftp
$TEST localhost http
$TEST localhost echo
$TEST localhost tftp

$TEST '' http
$TEST '' echo
$TEST '' tftp
$TEST '' 80
$TEST -p '' http
$TEST -p '' echo
$TEST -p '' tftp
$TEST -p '' 80
$TEST -S '' 80
$TEST -D '' 80

$TEST ::1 ''
$TEST 127.0.0.1 ''
$TEST localhost ''
$TEST '' ''
