#! /usr/pkg/bin/perl

#	$KAME: dynupdate.pl,v 1.1 2001/02/20 03:16:34 itojun Exp $

# Copyright (C) 2001 WIDE Project.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

#
# issue a DNS dynamic update request using BIND9 nsupdate.
#
# "secret": TSIG key (look at BIND9 ARM section on TSIG key generation)
#	if you don't define $tsigkey, the script will not use TSIG.
#	in this case your zone becomes very insecure.  we do not recomment that.
# yourhost.dyn.your.domain ($name.$domain): FQDN of your machine
#

$nsupdate = '/usr/pkg/bin/nsupdate';
#$tsigkey = 'dyn.your.domain:secret';
$name = 'yourhost';
$domain = 'dyn.your.domain';
$ttl = 3600;

open(ADDRS, "ifconfig -a |") || die;

while (<ADDRS>) {
	next if !/^\tinet6/;
	next if /\bdetached\b/;
	next if /\bdeprecated\b/;
	next if !/\binet6 [23][0-9a-f][0-9a-f][0-9a-f]:/;
	s/^\tinet6 //;
	push(@addrs, (split(/\s+/, $_))[0]);
}

if (defined $tsigkey) {
	open(DOIT, "| $nsupdate -y $tsigkey >/dev/null") || die;
} else {
	open(DOIT, "| $nsupdate >/dev/null") || die;
}

print DOIT "update delete $name.$domain AAAA $i\n";
foreach $i (@addrs) {
	print DOIT "update add $name.$domain $ttl AAAA $i\n";
}
print DOIT "\n\n";
close(DOIT);
exit 0;
