#! @PREFIX@/ruby

#
# dtcpd, Turmpet Dynamic Tunel Configuration Protocol daemon
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
# $Id: dtcps.rb,v 1.1 1999/08/08 23:29:24 itojun Exp $
#

require "socket"
require "thread"
require "md5"
require "dbm"
require "etc"

# XXX should be derived from system headers
IPPROTO_IPV6 = 41
IPV6_FAITH = 29
TUNIF = "gif"
AUTHTIMEOUT = 60
TUNTIMEOUT = 300
# must be less than 10, against RIPng and PIM6 - useless
TRAFFICTIMEOUT = 0
POPAUTHUID = 'pop'
DEBUG = false

def daemon(nochdir, noclose)
  pid = fork
  if pid == -1
    return -1
  elsif pid != nil
    exit 0
  end

  Process.setsid()

  Dir.chdir('/') if (nochdir == 0)
  if noclose == 0
    devnull = open("/dev/null", "rw")
    $stdin.reopen(devnull)
    $stdout.reopen(devnull)
    p = pipe
    pid = fork
    if pid == -1
      $stderr.reopen(devnull)
    elsif pid == nil
      p[1].close
      STDIN.reopen(p[0])
      p[0].close
      exec("logger -t #{File.basename($0)} -p daemon.notice")
    else
      p[0].close
      $stderr.reopen(p[1])
      p[1].close
    end
  end
  return 0
end

def logmsg(msg)
  $stderr.print msg
end

def debugmsg(msg)
  $stderr.print msg if ($debug)
end

# TODO: check for duplicated tunnel configuration
def gettunnel(me, her)
  tmpfile = "/tmp/gettunnel#{$$}.#{me}-#{her}"
  system("ifconfig -a |grep #{TUNIF} | grep -v UP > #{tmpfile}")
  f = open(tmpfile, "r")
  s = f.readline
  f.close
  File::unlink(tmpfile)
  s = s[0, s.index(':')]
  debugmsg("gifconfig #{s} #{me} #{her}\n")
  system("gifconfig #{s} #{me} #{her}")
  debugmsg("ifconfig #{s} up\n")
  system("ifconfig #{s} up")
  return s
end

def tunnelsetup(s, user, type)
  me = s.addr()[3]
  her = s.peeraddr()[3]
  debugmsg("#{s}: tunnel #{me} -> #{her}\n")

  case type
  when 'host'
    if $prefix == nil
      debugmsg("#{s}: tunnel type #{type} not supported\n")
      return nil, "unsupported tunnel type #{type}"
    end

    tunif = gettunnel(me, her)
    if (tunif == nil)
      debugmsg("#{s}: tunnel interface sold out\n")
      return nil, 'tunnel interface sold out'
    end
    debugmsg("#{s}: tunnel interface #{tunif}\n")

    if tunif =~ /(\d+)$/
      tunid = $1.to_i
      heraddr = sprintf("%s%04x", $prefix, (tunid + 1) * 4 + 2)
      myaddr = sprintf("%s%04x", $prefix, (tunid + 1) * 4 + 1)
      debugmsg("ifconfig #{tunif} inet6 #{myaddr} #{heraddr} prefixlen 126 alias\n")
      system("ifconfig #{tunif} inet6 #{myaddr} #{heraddr} prefixlen 126 alias")
      x = [tunif, her, me, heraddr, myaddr]
      err = nil
    else
      tunnelcleanup([tunif, her, me])
      x = nil
      err = 'internal error: tunnel interface name format is wrong'
    end
  when 'tunnelonly'
    tunif = gettunnel(me, her)
    if (tunif == nil)
      debugmsg("#{s}: could not configure tunnel\n")
      return nil, 'tunnel interface sold out'
    end
    debugmsg("#{s}: tunnel interface #{tunif}\n")
    x = [tunif, her, me]
    err = nil
  else
    debugmsg("#{s}: unsupported tunnel type #{type}\n")
    err = "unsupported tunnel type #{type}"
    x = nil
  end
  return x, err
end

def getipkts(intface)
  tmpfile = "/tmp/getipkts#{$$}.#{intface}"
  system("netstat -in -I #{intface} > #{tmpfile}")
  f = open(tmpfile, "r")
  s = f.readline
  s = f.readline
  f.close
  File::unlink(tmpfile)
  t = s.split(/[ \t]+/)
  if t.length < 5
    debugmsg("#{intface} ipkts unknown, returning -1\n")
  end
  debugmsg("#{intface} ipkts = #{t[t.length - 5]}\n")
  return t[t.length - 5]
end

def checktraffic(tun)
  return if TRAFFICTIMEOUT == 0
  ipkts = getipkts(tun[0])
  while TRUE
    sleep TRAFFICTIMEOUT
    i = getipkts(tun[0])
    next if i == -1
    break if ipkts >= i
    ipkts = i
  end
end

def tunnelcleanup(tun)
  logmsg("#{tun[0]} disconnected\n")
  if tun.length == 5
    debugmsg("ifconfig #{tun[0]} inet6 #{tun[4]} #{tun[3]} -alias\n")
    system("ifconfig #{tun[0]} inet6 #{tun[4]} #{tun[3]} -alias")
  end
  debugmsg("ifconfig #{tun[0]} down\n")
  system("ifconfig #{tun[0]} down")
end

def service_dtcp(sock, name)
  debugmsg("service_dtcp(#{sock}, #{name})\n")
  while TRUE
    debugmsg("service_dtcp(#{sock}, #{name}) accepting\n")
    sa = sock.accept
    debugmsg("service_dtcp(#{sock}, #{name}) accepted #{sa}\n")
    Thread.start {
      threads = []
      debugmsg("accepted #{sa} -> #{Thread.current}\n")
      s = sa
      tun = []

      # send challenge
      challenge = seed()
      s.print "+OK #{challenge} KAME tunnel server\r\n"

      # check response
      # tunnel itojun RESPONSE type
      while TRUE
	t = select([s], [], [s], tun == [] ? AUTHTIMEOUT : TUNTIMEOUT)
	if t == nil
	  s.print "-ERR connection timed out, disconnecting\r\n"
	  break
	end
	if s.eof?
	  break
	end
	response = s.readline
	response.gsub!(/[\n\r]/, '')
	if response != ''
	  t = response.split(/ /)
	  t[0].tr!('A-Z', 'a-z')
	else
	  t = ['']
	end
	debugmsg("#{s}: got <#{response}>\n")
	case t[0]
	when 'tunnel'
	  if (t.length != 4)
	    debugmsg("client #{s} sent wrong #{t[0]} command\n")
	    debugmsg("#{s}: sent <-ERR authentication failed.>\n")
	    s.print "-ERR authentication failed.\r\n"
	    next
	  end
	  user = t[1]
	  type = t[3]
	  pass = getpopauth(user)
	  if pass == nil
	    logmsg("client #{s} has no password in database for #{user}\n")
	    debugmsg("#{s}: sent <-ERR authentication failed.>\n")
	    s.print "-ERR authentication failed.\r\n"
	    next
	  end
	  # get password from the username
#	  $stderr.print "authenticate(#{user} #{challenge} #{pass}): "
#	  debugmsg(authenticate(user, challenge, pass) + "\n")
#	  debugmsg("target: #{t[2]}\n")
 	  if (authenticate(user, challenge, pass) == t[2])
	    debugmsg("client #{s.addr()[3]} on #{s}\n")
	    logmsg("client #{s.addr()[3]} authenticated as #{user}\n")
	    auth = true
	    tun, err = tunnelsetup(s, user, type)
	    if tun == nil
	      logmsg("failed to configure for #{user} type #{type}: #{err}\n")
	      debugmsg("#{s}: sent <-ERR #{err}>\n")
	      s.print "-ERR #{err}\r\n"
	    else
	      t = tun[1, tun.length - 1]
	      logmsg("#{tun[0]} configured for #{user} type #{type}: " + t.join(' ') + "\n")
	      debugmsg("#{s}: sent <+OK #{t.join(' ')}>\n")
	      s.print "+OK ", t.join(' '), "\r\n"
	    end
	  else
	    logmsg("client #{s} not authenticated\n")
	    debugmsg("#{s}: sent <-ERR authentication failed.>\n")
	    s.print "-ERR authentication failed.\r\n"
	  end
	when 'ping'
	  debugmsg("#{s}: sent <+OK hi, happy to hear from you>\n")
	  s.print "+OK hi, happy to hear from you\r\n"
	when 'help'
	  debugmsg("#{s}: sent <+OK valid commands are: TUNNEL PING QUIT>\n")
	  s.print "+OK valid commands are: TUNNEL PING QUIT\r\n"
	when 'quit'
	  debugmsg("#{s}: sent <+OK see you soon.>\n")
	  s.print "+OK see you soon.\r\n"
	  break
	else
	  debugmsg("client #{s} sent invalid command #{t[0]}\n")
	  debugmsg("#{s}: sent <-ERR invalid command>\n")
	  s.print "-ERR invalid command\r\n"
	end
      end
      if tun != []
	checktraffic(tun)
	tunnelcleanup(tun)
      end
      s.flush
      s.shutdown(1)
      debugmsg("shutdown #{s} #{Thread.current}\n")
    }
  end
  debugmsg("service_dtcp(#{sock}, #{name}) finished\n")
end

def usage()
  $stderr.print "usage: #{File.basename($0)} [-dD] [-p port] [prefix]\n"
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

# NOTE: strings are terminated by "\0"...
def getpopauth(user)
  pw = Etc.getpwnam(POPAUTHUID)
  if pw == nil
    debugmsg("no user named pop\n")
    return nil
  end
  origuid = Process.euid
  # XXX begin seteuid(pop)
  Process.euid = pw[2]
  f = DBM.open('/usr/local/etc/popper/pop.auth', nil)
  if f == nil
    debugmsg("no password database found\n")
    Process.euid = origuid
    return nil
  end
  p = f[user + "\0"]
  f.close
  Process.euid = origuid
  # XXX end seteuid(pop)
  if p == nil
    debugmsg("no relevant password database item found\n")
    return nil
  end
  if p[p.length - 1] == 0
    p = p[0, p.length - 1]
  end
  for i in 0 .. p.length - 1
    p[i] = [p[i] ^ 0xff].pack('C')
  end
  debugmsg("ok, relevant password database item found\n")
  return p
end

#------------------------------------------------------------

port = 20200
$prefix = nil
$daemonize = true
$debug = DEBUG

while ARGV[0] =~ /^-/ do
  case ARGV[0]
  when /-p/
    ARGV.shift
    port = ARGV[0]
  when /-d/
    $debug = !$debug
  when /-D/
    $daemonize = !$daemonize
  else
    usage()
    exit 0
  end
  ARGV.shift
end

case ARGV.length
when 0
  $prefix = nil
when 1
  $prefix = ARGV[0]
  if $prefix !~ /^[0-9a-fA-f:]*::$/
    usage()
    exit 1
  end
else
  usage()
  exit 1
end

res = []
t = Socket.getaddrinfo(nil, port, Socket::PF_INET, Socket::SOCK_STREAM,
      nil, Socket::AI_PASSIVE)
if (t.size <= 0)
  $stderr.print "FATAL: getaddrinfo failed (port=#{port})\n"
  exit 1
end
res += t

if $daemonize
  daemon(0, 0)
end

sockpool = []
names = []
listenthreads = []

res.each do |i|
  s = TCPserver.new(i[3], i[1])
  n = Socket.getnameinfo(s.getsockname, Socket::NI_NUMERICHOST|Socket::NI_NUMERICSERV).join(" port ")
  s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
  sockpool.push s
  names.push n
end

if $debug
  (0 .. sockpool.size - 1).each do |i|
    debugmsg("listen[#{i}]: #{sockpool[i]} #{names[i]}\n")
  end
end

(0 .. sockpool.size - 1).each do |i|
  listenthreads[i] = Thread.start {
    debugmsg("listen[#{i}]: thread #{Thread.current}\n")
    service_dtcp(sockpool[i], names[i])
  }
end

for i in listenthreads
  if VERSION =~ /^1\.2/
    Thread.join(i)
  else
    i.join
  end
end

exit 0
