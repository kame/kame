#! @LOCALPREFIX@/bin/perl
# $Id: dsadd.pl,v 1.2 2003/01/10 09:10:13 sakane Exp $
# Dead SA Detection

require 'getopts.pl';

$ping6 = '/sbin/ping6';
$ping = '/sbin/ping';
$setkey = '/usr/sbin/setkey';
$logger = '/usr/bin/logger';

$opt_c = 2;	# see -c option.
$opt_E = 0;	# see -E option.
$opt_S = 0;	# see -S option.
$opt_i = 300;	# see -i option.
$opt_L = 0;	# see -L option.
$opt_P = 'user.notice';	# see -P option.

sub usage
{
	print "Usage: dsadd [-c number] [-i time] [-P priorify] [-LESd]\n";
	print "\t-c: specify the number of icmp echo packet to be sent.\n";
	print "\t-i: if the current round takes more than the specified\n";
	print "\t    time in seconds the next round will start immediately\n";
	print "\t    after the current will finish.  otherwise the next will\n";
	print "\t    start after the specified time from the current first\n";
	print "\t    check.\n";
	print "\t-P: specify the priority used by logger(1).\n";
	print "\t-L: force to check only once.\n";
	print "\t-E: don't delete the SA even if the SA looks dead.\n";
	print "\t-S: don't tell syslog(8) what the SA has been deleted.\n";
	print "\t-d: debug mode.\n";
	exit 0;
}

do Getopts('c:i:LESdh');
&usage if ($opt_h);
$debug++ if ($opt_d);

select(STDOUT); $| = 1;
open(OLDERR, ">&STDERR");
open(STDERR, ">&STDOUT");

AGAIN:
%sa_dst = ();
$nextround = time + $opt_i;

%sa_dst = &getsa;

foreach $k (keys %sa_dst) {

	print "\nchecking $k\n" if ($debug);

	if (&pinging($k, 0)) {
		print "  ### seems dead.\n" if ($debug);
		&delete_sa($k) if (! $opt_E);
		next;
	}

	print "  ### seems alive.\n" if ($debug);
}

$interval = $nextround - time;

exit 0 if ($opt_L);

if ($interval > 0) {
	print "\nthe next round will start ${interval}(s) after.\n" if ($debug);
	sleep $interval;
}

goto AGAIN;

#
sub getsa
{
	my ($key, $src, $dst, $proto, $mode, $spi);
	my %sa;

	open(IN, "$setkey -D |");
	while (<IN>) {
		if (/^[^\t]/) {
			($src, $dst) = split(/\s+/, $_);
		} elsif (/^\t(esp|ah) mode=(\w+) spi=\d+\((0x[0-9a-f]+)\)/) {
			$proto = $1;
			$mode = $2;
			$spi = $3;
			$key = "$src $dst $proto $spi $mode";
			$sa{$key} = "$dst";
		}
	}
	close(IN);

	return %sa;
}

sub pinging
{
	my ($key, $need_policy) = @_;
	my ($pingcmd, $policy, $dead, $check);

	$check = 0;
	$dead = 0;

	if ($need_policy) {
		$policy = "-P 'out none'";
	} else {
		$policy = '';
	}

	if ($sa_dst{$key} =~ /:/) {
		$pingcmd = $ping6;
	} else {
		$pingcmd = $ping;
	}

	print "  $pingcmd -nq -c $opt_c $policy $sa_dst{$key}\n" if ($debug);
	open(IN, "$pingcmd -nq -c $opt_c $policy $sa_dst{$key} |");
	while (<IN>) {
		print "  $_" if ($debug && !/^$/);
		if (/100% packet loss/) {
			$dead++;
			last;
		}
		$check++;
	}
	close(IN);

	$dead++ if (!$check);

	return $dead;
}

sub delete_sa
{
	my ($key) = @_;
	my ($cmd, $src, $dst, $proto, $spi, $mode);

	eval "(\$src, \$dst, \$proto, \$spi, \$mode) = qw/$key/";
	$cmd = sprintf "delete $src $dst $proto $spi;";
	print "  $cmd\n" if ($debug);

	system("$logger -p $opt_P -t dsadd \"SA deleted src=$src dst=$dst proto=$proto spi=$spi mode=$mode\"") if (! $opt_S);

	open(OUT, "| $setkey -c");
	print OUT "$cmd\n";
	close(OUT);

	return;
}
