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
