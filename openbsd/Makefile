.include <bsd.own.mk>			# for configuration variables.

SUBDIR=	lib include bin sbin usr.bin usr.sbin libexec share

#build:
#	$(MAKE) includes
#	$(MAKE)
#	$(MAKE) install

includes:
	(cd $(.CURDIR)/include; $(MAKE) includes)

PREFIX= /usr/local/v6
DIRS=	$(PREFIX) $(PREFIX)/bin $(PREFIX)/sbin $(PREFIX)/lib $(PREFIX)/etc \
	$(PREFIX)/libexec $(PREFIX)/man $(PREFIX)/share/doc/kame
SECTIONS=1 2 3 4 5 6 7 8 9 n

beforeinstall:
	for i in $(DIRS); do \
		[ -d $$i ] || mkdir -p $$i; \
	done
	for i in $(SECTIONS); do \
		[ -d $(PREFIX)/man/man$$i ] || mkdir -p $(PREFIX)/man/man$$i; \
		[ -d $(PREFIX)/man/cat$$i ] || mkdir -p $(PREFIX)/man/cat$$i; \
	done

afterinstall:
	cp kame/rtadvd/rtadvd.conf $(PREFIX)/etc/rtadvd.conf.sample
	cp kame/bgpd/bgpd.conf $(PREFIX)/etc/bgpd.conf.sample
	if test -x $(PREFIX)/sbin/inet6d; then \
		cp kame/inet6d/inet6d.conf $(PREFIX)/etc/inet6d.conf.sample; \
	fi
	cp kame/etc/rc.net6 $(PREFIX)/etc/rc.net6.sample
	for i in $(DOCS); do \
		if test -f ../$$i; then \
			cp ../$$i $(PREFIX)/share/doc/kame; \
		fi \
	done

.include <bsd.subdir.mk>
.include "../Makefile.inc"
