#
# perl prepare.pl kame <osname>
# $Id: prepare.pl,v 1.12 1999/10/04 15:21:43 itojun Exp $
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
	local(%conflict);
	local(%rename);

	print "start: $curdir, $src, $dst\n";

	opendir(DIR, $curdir);
	@all = readdir(DIR);
	closedir(DIR);

	if (-f "$dst/.prepare") {
		%exclude = ();
		%linkdir = ();
		%conflict = ();
		%rename = ();
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
			if (/^conflict\s+(\S+)$/) {
				$conflict{$1}++;
			}
			if (/^rename\s+(\S+)\s+(\S+)$/) {
				$rename{$1} = $2;
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

		if ($rename{$i}) {
			$j = $rename{$i};
		} else {
			$j = $i;
		}

		if (-d "$curdir/$i" && !$linkdir{$i}) {
			&dig("$curdir/$i", "../$src/$i", "$dst/$i");
		} else {
			if (! -d "$dst") {
				print "mkdir -p $dst\n" if $debug;
				system "mkdir -p $dst" if (!$test);
			}

			if (-f "$dst/$j" && ! -l "$dst/$j") {
				print "conflict: $dst/$j\n";
				exit 1 if (!defined $conflict{$j});
			} else {
				if (-l "$dst/$j") {
					print "unlink $dst/$j (symlink)\n" if $debug;
					unlink "$dst/$j" if (!$test);
				}
				print "ln -s $src/$i $dst/$j\n" if $debug;
				symlink("$src/$i", "$dst/$j") if (!$test);
			}
		}
	}
}
