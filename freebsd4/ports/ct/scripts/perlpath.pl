#!/usr/bin/perl
#
# modify perl path
#

$path = shift @ARGV;

while($ARGV = shift @ARGV){
	open(IN,"<$ARGV") || die "cannot open file $ARGV\n";
	@a=<IN>;
	close(IN);

	$a[0]="#!$path\n";

	open(OUT,">$ARGV") || die "cannot open file $ARGV\n";
	print OUT @a;
	close(OUT);
	chmod(0755,$ARGV) || die "cannot change mode $ARGV\n";
}
