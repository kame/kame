TARGET?=	bogus

all:
	@(echo '**** WARNING: Read through INSTALL and platform/INSTALL, '; \
	echo '    and follow the steps documented'.; \
	exit 1)

prepare::
	(cd ${.CURDIR}; perl prepare.pl kame ${TARGET})

clean::
	(cd ${.CURDIR}; find ${TARGET} -type l -print | perl -nle unlink)

# only for developers
bsdi3:
	(cd ${.CURDIR}; set CVSROOT=cvs.kame.net:/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -d bsdi3 -P kame/bsdi3)

bsdi4:
	(cd ${.CURDIR}; set CVSROOT=cvs.kame.net:/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -d bsdi4 -P kame/bsdi4)

PLAT=	freebsd2 freebsd3 kame netbsd openbsd bsdi3 bsdi4
# DOCS is defined in Makefile.inc
TOOLS=	Makefile Makefile.inc prepare.pl

update: update-doc update-plat
update-doc:
	(cd ${.CURDIR}; cvs update -d -P ${DOCS} ${TOOLS})
update-plat:
	(cd ${.CURDIR}; \
	for i in kame ${TARGET}; do \
		if test -d $$i; then \
			(cd $$i; cvs update -d -P); \
		fi \
	done)
update-all: update-doc
	(cd ${.CURDIR}; \
	for i in ${PLAT}; do \
		if test -d $$i; then \
			(cd $$i; cvs update -d -P); \
		fi \
	done)

# % cvs co kame/Makefile
# % cd kame
# % make TARGET=foo tree
tree:
	(cd ${.CURDIR}; \
	$(MAKE) update-doc; \
	if test $(TARGET) = bsdi3  -o $(TARGET) = bsdi4; then \
		$(MAKE) $(TARGET); \
	else \
		cvs update -d -P $(TARGET); \
	fi; \
	cvs update -d -P kame)

.include "Makefile.inc"
