.include <bsd.own.mk>			# for configuration variables.

SUBDIR= lib libexec sbin share usr.bin usr.sbin

includes:
	(cd ${.CURDIR}/include; $(MAKE))
install-includes:
	(cd ${.CURDIR}/include; $(MAKE) install)

PREFIX= /usr/local/v6
DIRS=	$(PREFIX) $(PREFIX)/bin $(PREFIX)/sbin $(PREFIX)/lib $(PREFIX)/etc \
	$(PREFIX)/libexec $(PREFIX)/man $(PREFIX)/share/doc/kame
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
#	cp ${.CURDIR}/kame/rtadvd/rtadvd.conf \
#		${DESTDIR}$(PREFIX)/etc/rtadvd.conf.sample
	cp ${.CURDIR}/kame/bgpd/bgpd.conf \
		${DESTDIR}$(PREFIX)/etc/bgpd.conf.sample
	cp ${.CURDIR}/kame/racoon/samples/racoon.conf.sample \
		${DESTDIR}$(PREFIX)/etc/
	cp ${.CURDIR}/kame/racoon/samples/psk.txt.sample \
		${DESTDIR}$(PREFIX)/etc/
#	if test -x ${DESTDIR}$(PREFIX)/sbin/inet6d || \
#	test -x ${DESTDIR}$(PREFIX)/sbin/inet46d; then \
#		cp ${.CURDIR}/kame/inet6d/inet6d.conf \
#			${DESTDIR}$(PREFIX)/etc/inet6d.conf.sample; \
#	fi
#	cp ${.CURDIR}/kame/etc/rc.net6 \
#		${DESTDIR}$(PREFIX)/etc/rc.net6.sample
	for i in $(DOCS); do \
		if test -f ${.CURDIR}/../$$i; then \
			cp ${.CURDIR}/../$$i \
				${DESTDIR}$(PREFIX)/share/doc/kame; \
		fi \
	done
	cp kame/mip6config/README_MIP6.txt $(PREFIX)/share/doc/kame
	cp kame/mip6config/QUICKSTART $(PREFIX)/share/doc/kame
	cp ${.CURDIR}/INSTALL ${PREFIX}/share/doc/kame/INSTALL.freebsd4
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 555 \
		${.CURDIR}/kame/etc/MAKEDEV.altq ${DESTDIR}/dev
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 555 \
		${.CURDIR}/kame/send-pr/send-pr \
		${DESTDIR}${PREFIX}/bin/kame-send-pr

.include <bsd.subdir.mk>
.include "../Makefile.inc"
