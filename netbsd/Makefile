.include <bsd.own.mk>			# for configuration variables.

SUBDIR=	lib include libexec sbin usr.bin usr.sbin share sys

#build:
#	$(MAKE) includes
#	$(MAKE)
#	$(MAKE) install

PREFIX= /usr/local/v6
DIRS=	${PREFIX} ${PREFIX}/bin ${PREFIX}/sbin ${PREFIX}/lib ${PREFIX}/etc \
	${PREFIX}/libexec ${PREFIX}/man ${PREFIX}/share/doc/kame
SECTIONS=1 2 3 4 5 6 7 8 9 n

beforeinstall:
	for i in ${DIRS}; do \
		[ -d ${DESTDIR}$$i ] || mkdir -p ${DESTDIR}$$i; \
	done
	for i in ${SECTIONS}; do \
		[ -d ${DESTDIR}${PREFIX}/man/man$$i ] || mkdir -p ${DESTDIR}${PREFIX}/man/man$$i; \
		[ -d ${DESTDIR}${PREFIX}/man/cat$$i ] || mkdir -p ${DESTDIR}${PREFIX}/man/cat$$i; \
	done

afterinstall:
	cp ${.CURDIR}/kame/rtadvd/rtadvd.conf \
		${DESTDIR}${PREFIX}/etc/rtadvd.conf.sample
	cp ${.CURDIR}/kame/bgpd/bgpd.conf \
		${DESTDIR}${PREFIX}/etc/bgpd.conf.sample
	if test -x ${PREFIX}/sbin/inet6d; then \
		cp ${.CURDIR}/kame/inet6d/inet6d.conf \
			${DESTDIR}${PREFIX}/etc/inet6d.conf.sample; \
	fi
	cp ${.CURDIR}/kame/etc/rc.net6 ${PREFIX}/etc/rc.net6.sample
	for i in ${DOCS}; do \
		if test -f ${.CURDIR}/../$$i; then \
			cp ${.CURDIR}/../$$i ${DESTDIR}${PREFIX}/share/doc/kame; \
		fi \
	done
	cp ${.CURDIR}/INSTALL ${DESTDIR}${PREFIX}/share/doc/kame/INSTALL.netbsd
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 555 \
		${.CURDIR}/kame/etc/MAKEDEV.altq ${DESTDIR}/dev
.include <bsd.subdir.mk>
