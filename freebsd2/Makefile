.include <bsd.own.mk>			# for configuration variables.

SUBDIR=	lib libexec sbin usr.bin usr.sbin share

#build:
#	$(MAKE) includes
#	$(MAKE)
#	$(MAKE) install

PREFIX= /usr/local/v6
DIRS=	$(PREFIX) $(PREFIX)/bin $(PREFIX)/sbin $(PREFIX)/lib $(PREFIX)/etc \
	$(PREFIX)/libexec $(PREFIX)/man $(PREFIX)/share/doc/kame
SECTIONS=1 2 3 4 5 6 7 8 9 n
DOCS=	CHANGELOG COPYRIGHT COPYRIGHT.jp IMPLEMENTATION INSTALL INSTALL.cvsup \
	INSTALL.anoncvs README RELNOTES TODO USAGE

beforeinstall:
	for i in $(DIRS); do \
		[ -d $$i ] || mkdir -p $$i; \
	done
	for i in $(SECTIONS); do \
		[ -d $(PREFIX)/man/man$$i ] || mkdir -p $(PREFIX)/man/man$$i; \
		[ -d $(PREFIX)/man/cat$$i ] || mkdir -p $(PREFIX)/man/cat$$i; \
	done

.include <bsd.subdir.mk>
