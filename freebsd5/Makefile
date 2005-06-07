.include <bsd.own.mk>			# for configuration variables.

SUBDIR= lib sbin share usr.bin usr.sbin

includes:
	(cd ${.CURDIR}/include; $(MAKE))
install-includes:
	(cd ${.CURDIR}/include; $(MAKE) install)

PREFIX= /usr/local/v6
DIRS=	$(PREFIX) $(PREFIX)/bin $(PREFIX)/sbin $(PREFIX)/lib $(PREFIX)/etc \
	$(PREFIX)/man $(PREFIX)/share/doc/kame
SECTIONS=1 2 3 4 5 6 7 8 9 n

beforeinstall:
	for i in $(DIRS); do \
		[ -d ${DESTDIR}$$i ] || mkdir -p $${DESTDIR}$$i; \
	done
	for i in $(SECTIONS); do \
		[ -d ${DESTDIR}$(PREFIX)/man/man$$i ] || \
			mkdir -p ${DESTDIR}$(PREFIX)/man/man$$i; \
		[ -d ${DESTDIR}$(PREFIX)/man/cat$$i ] ||\
			mkdir -p ${DESTDIR}$(PREFIX)/man/cat$$i; \
	done

afterinstall:
	cp ${.CURDIR}/kame/rtadvd/rtadvd.conf \
		${DESTDIR}$(PREFIX)/etc/rtadvd.conf.sample
	cp ${.CURDIR}/kame/bgpd/bgpd.conf \
		${DESTDIR}$(PREFIX)/etc/bgpd.conf.sample
	cp ${.CURDIR}/kame/ip6addrctl/ip6addrctl.conf.sample \
		${DESTDIR}$(PREFIX)/etc/ip6addrctl.conf.sample
	cp ${.CURDIR}/kame/shisad/sampleconf/*.sample \
		${DESTDIR}$(PREFIX)/etc/
	for i in $(DOCS); do \
		if test -f ${.CURDIR}/../$$i; then \
			cp ${.CURDIR}/../$$i \
				${DESTDIR}$(PREFIX)/share/doc/kame; \
		fi \
	done
	cp ${.CURDIR}/INSTALL \
		${DESTDIR}${PREFIX}/share/doc/kame/INSTALL.freebsd4
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 555 \
		${.CURDIR}/kame/send-pr/send-pr \
		${DESTDIR}${PREFIX}/bin/kame-send-pr

.include <bsd.subdir.mk>
.include "../Makefile.inc"
