#!/usr/bin/perl

require 'getopts.pl';
do Getopts('b:');


if (@ARGV != 2) {
    print "Usage: aaaa2a6.pl zonefile prefixname\n";
    exit(1);
}

$zonefile = @ARGV[0];
$pname = @ARGV[1];
if ($opt_b) {
    $beg = $opt_b;
} else {
    $beg = 64;
}

open(ZONE, $zonefile) || die "failed to open $zonefile\n";

while (<ZONE>) {
    $line++;

    # match "^DNSname". keep it for later abbreviated records.
    # XXX: not 100% reliable.
    if (/^(\S+)/) {
	$name0 = $1;
    }

    # match "^[DNSname] [TTL] IN AAAA IPv6address"
    if (/^(\S*)\s+(\S*)\s*IN\s+AAAA\s+(\S+)/) {
	$name = $1;
	$ttl = $2;
	$addr = $3;

	if (! $name) {
	    if (! $name0) {
		print "no owner can be found for a AAAA RR (line $line)\n";
		exit(1);
	    }
	    $name = $name0;
	}

	$prefix = `dns6conv -b $beg $addr`;
	if (! $prefix) {
	    exit(1);
	}
	chop($prefix);
	printf "%-12s%4s IN A6 $beg %-24s$pname\n", $name, $ttl, $prefix;
    }
}
