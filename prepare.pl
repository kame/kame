#
# perl prepare.pl kame <osname>
# $Id: prepare.pl,v 1.10 1999/08/17 15:02:43 itojun Exp $
#

$debug = 1;
$test = 0;

die if (scalar(@ARGV) != 2);

$src = $ARGV[0];
$dst = $ARGV[1];

die "$src not found" if (! -d $src);
die "$dst not found" if (! -d $dst);

&dig($src, "../$src", $dst);

sub dig {
	local($curdir, $src, $dst) = @_;
	local(@all);
	local(%exclude);
	local(%linkdir);

	print "start: $curdir, $src, $dst\n";

	opendir(DIR, $curdir);
	@all = readdir(DIR);
	closedir(DIR);

	if (-f "$dst/.prepare") {
		%exclude = ();
		%linkdir = ();
		open(IN, "< $dst/.prepare");
		while (<IN>) {
			s/\s*\n$//;
			s/^\s*//;
			s/\#.*//;
			if (/^exclude\s+(\S+)$/) {
				$exclude{$1}++;
			}
			if (/^linkdir\s+(\S+)$/) {
				$linkdir{$1}++;
			}
		}
		close(IN);
		print "exclude in $dst: " . join(' ', keys %exclude) . "\n"
			if ($debug);
	}
	foreach $i (@all) {
		next if ($i eq '.');
		next if ($i eq '..');
		next if ($i eq 'CVS');
		next if ($i =~ /\.orig$/);
		next if ($i =~ /\.rej$/);
		next if ($i =~ /^\.\#/);	# cvs temporary

		if ($exclude{$i}) {
			print "exclude $dst/$i\n" if $debug;
			next;
		}

		if (-d "$curdir/$i" && !$linkdir{$i}) {
			&dig("$curdir/$i", "../$src/$i", "$dst/$i");
		} else {
			if (! -d "$dst") {
				print "mkdir -p $dst\n" if $debug;
				system "mkdir -p $dst" if (!$test);
			}

			if (-f "$dst/$i" && ! -l "$dst/$i") {
				print "conflict: $dst/$i\n";
			} else {
				if (-l "$dst/$i") {
					print "unlink $dst/$i (symlink)\n" if $debug;
					unlink "$dst/$i" if (!$test);
				}
				print "ln -s $src/$i $dst/$i\n" if $debug;
				symlink("$src/$i", "$dst/$i") if (!$test);
			}
		}
	}
}
