#
# perl prepare.pl kame <osname>
#

$debug = 1;
$test = 0;

die if (scalar(@ARGV) != 2);

$src = $ARGV[0];
$dst = $ARGV[1];

&dig($src, "../$src", $dst);

sub dig {
	local($curdir, $src, $dst) = @_;
	local(@all);
	local(%exclude);

	print "start: $curdir, $src, $dst\n";

	opendir(DIR, $curdir);
	@all = readdir(DIR);
	closedir(DIR);

	if (-f "$dst/.prepare") {
		%exclude = ();
		open(IN, "< $dst/.prepare");
		while (<IN>) {
			s/\n$//;
			if (/^exclude\s+(\S+)$/) {
				$exclude{$1}++;
			}
		}
		close(IN);
		print "exclude in $dst: " . join(keys %exclude) . "\n"
			if ($debug);
	}
	foreach $i (@all) {
		next if ($i eq '.');
		next if ($i eq '..');
		next if ($i eq 'CVS');
		next if ($i =~ /\.orig$/);
		next if ($i =~ /\.rej$/);
		if (-d "$curdir/$i") {
			&dig("$curdir/$i", "../$src/$i", "$dst/$i");
		} elsif (-f "$curdir/$i") {
			if (! -d "$dst") {
				print "mkdir -p $dst\n" if $debug;
				system "mkdir -p $dst";
			}

			if (-f "$dst/$i" && ! -l "$dst/$i") {
				print "conflict: $dst/$i\n";
			} else {
				if (-l "$dst/$i") {
					print "unlink $dst/$i (symlink)\n" if $debug;
					unlink "$dst/$i";
				}
				if ($exclude{$i}) {
					print "exclude $dst/$i\n" if $debug;
				} else {
					print "ln -s $src/$i $dst/$i\n" if $debug;
					symlink "$src/$i", "$dst/$i" if (!$test);
				}
			}
		}
	}
}
