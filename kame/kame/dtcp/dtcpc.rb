#! @PREFIX@/ruby

#
# dtcpc, Turmpet Dynamic Tunel Configuration Protocol client
#

#
# Copyright (C) 1999 WIDE Project.
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
# $Id: dtcpc.rb,v 1.1 1999/08/08 23:29:23 itojun Exp $
#

require "socket"
require "thread"
require "md5"

# XXX should be derived from system headers
IPPROTO_IPV6 = 41
IPV6_FAITH = 29
TUNIF = "gif"
TIMEOUT = 60
TUNTIMEOUT = 300
DEBUG = false

def usage()
  STDERR.print "usage: #{File.basename($0)} [-d] [-i if] [-p port] [-t tuntype] [-u username] server\n"
end

def seed()
  m = MD5.new(Time.now.to_s)
  m.update($$.to_s)
  m.update(Socket.gethostname())
  return m.digest.unpack("H32")[0].tr('a-f', 'A-F')
end

def authenticate(user, seed, pass)
  m = MD5.new(user)
  m.update(seed)
  m.update(pass)
  return m.digest.unpack("H32")[0].tr('a-f', 'A-F')
end

#------------------------------------------------------------

port = 20200
username = `whoami`
username.chomp!()
ousername = username
password = ''
intface = 'gif0'
tuntype = 'tunnelonly'
$debug = DEBUG

# # test pattern
# challenge = '0B1517C87D516A5FA65BED722D51A04F'
# response = authenticate('foo', challenge, 'bar')
# if response == 'DAC487C8DFBBF9EE5C7F8CDCC37B62A3'
#   STDERR.print "good!\n"
# else
#   STDERR.print "something bad in authenticate()\n"
# end
# exit 0

while ARGV[0] =~ /^-/ do
  case ARGV[0]
  when /-d/
    $debug = !$debug
  when /-i/
    ARGV.shift
    intface = ARGV[0]
  when /-p/
    ARGV.shift
    port = ARGV[0]
  when /-t/
    ARGV.shift
    tuntype = ARGV[0]
  when /-u/
    ARGV.shift
    username = ARGV[0]
  else
    usage()
    exit 0
  end
  ARGV.shift
end

if ARGV.length != 1
  usage()
  exit 1
end

dst = ARGV[0]

tty = open('/dev/tty', 'r')
system("stty -echo")
STDERR.print "password for #{username}: "
password = tty.readline
tty.close()
password.chomp!()
system("stty sane")
STDERR.print "\n"

res = []
t = Socket.getaddrinfo(dst, port, Socket::PF_INET, Socket::SOCK_STREAM, nil)
if (t.size <= 0)
  STDERR.print "FATAL: getaddrinfo failed (dst=#{dst} port=#{port})\n"
  exit 1
end
res += t

sockpool = []
names = []
listenthreads = []

s = nil
server = []
res.each do |i|
  begin
    s = TCPsocket.open(i[3], i[1])
  rescue
    next
  end
  server = i
  break
end

if server == []
  STDERR.print "could not connect to #{dst} port #{port}\n"
  exit 1
end

me = s.addr()[3]

STDERR.print "logging in to #{server[3]} port #{server[1]}\n"
# get greeting
t = s.readline
STDERR.print '>>', t if $debug
challenge = t.split(/ /)[1]

#STDERR.print "authenticate(#{username} #{challenge} #{password}): "
response = authenticate(username, challenge, password)
#STDERR.print response, "\n"
s.print "tunnel #{username} #{response} #{tuntype}\r\n"
STDERR.print ">>tunnel #{username} #{response} #{tuntype}\n" if $debug

t = s.readline
STDERR.print '>>', t if $debug
if (t =~ /^\+OK/)
  t.gsub!(/[\r\n]/, '')
  a = t.split(/ /)
  if me != a[1]
    STDERR.print "failed, you are behind a NAT box (#{me} != #{a[1]})\n"
    s.print "quit\r\n"
    s.shutdown(1)
    exit 1
  end
  STDERR.print "gifconfig #{intface} #{a[1]} #{a[2]}\n" if $debug
  system("gifconfig #{intface} #{a[1]} #{a[2]}")
  # global address for the tunnel is given
  if a.length == 5
    STDERR.print "ifconfig #{intface} inet6 #{a[3]} #{a[4]} prefixlen 126 alias\n" if $debug
    system("ifconfig #{intface} inet6 #{a[3]} #{a[4]} prefixlen 126 alias")
  end
  STDERR.print "ifconfig #{intface} up\n" if $debug
  system("ifconfig #{intface} up")
  STDERR.print "tunnel to #{a[2]} established.\n"
  STDERR.print "route add -inet6 default -interface #{intface}\n" if $debug
  system("route add -inet6 default -interface #{intface}")
  STDERR.print "default route was configured.\n"
  begin
    while TRUE
      STDERR.print "sleep(60)\n" if $debug
      sleep 60
      s.print "ping\r\n"
      STDERR.print ">>ping\n" if $debug
      t = s.readline
      STDERR.print '>>', t if $debug
    end
  ensure
    s.print "quit\r\n"
    s.shutdown(1)
    if a.length == 5
      STDERR.print "ifconfig #{intface} inet6 #{a[3]} #{a[4]} -alias\n" if $debug
      system("ifconfig #{intface} inet6 #{a[3]} #{a[4]} -alias")
    end
    STDERR.print "ifconfig #{intface} down\n" if $debug
    system("ifconfig #{intface} down")
    STDERR.print "route delete -inet6 default\n" if $debug
    system("route delete -inet6 default")
    exit 0
  end
  exit 0
else
  t.gsub!(/[\r\n]*$/, '')
  STDERR.print "failed, reason: #{t}"
  s.print "quit\r\n"
  s.shutdown(1)
  exit 1
end
