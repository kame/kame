TARGET?=	netbsd

prepare::
	(cd ${.CURDIR}; perl prepare.pl kame ${TARGET})

clean::
	(cd ${.CURDIR}; find ${TARGET} -type l -print | perl -nle unlink)

# only for developers
bsdi3:
	(cd ${.CURDIR}; set CVSROOT=cvs.kame.net/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -r stable_9909 -d bsdi3 -P kame/bsdi3)

bsdi4:
	(cd ${.CURDIR} set CVSROOT=cvs.kame.net/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -r stable_9909 -d bsdi4 -P kame/bsdi4)

DOC=	CHANGELOG COPYRIGHT COPYRIGHT.jp IMPLEMENTATION INSTALL \
	INSTALL.anoncvs Makefile PORTABILITY VERSION prepare.pl \
	TODO.new-repository
PLAT=	freebsd2 freebsd3 kame netbsd openbsd bsdi3 bsdi4

update: update-doc update-plat
update-doc:
	(cd ${.CURDIR}; cvs update -r stable_9909 -d -P ${DOC})
update-plat:
	(cd ${.CURDIR}; \
	for i in kame ${TARGET}; do \
		if test -d $$i; then \
			(cd $$i; cvs update -r stable_9909 -d -P); \
		fi \
	done)
update-all: update-doc
	(cd ${.CURDIR}; \
	for i in ${PLAT}; do \
		if test -d $$i; then \
			(cd $$i; cvs update -r stable_9909 -d -P); \
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
		cvs update -r stable_9909 -d -P $(TARGET); \
	fi; \
	cvs update -r stable_9909 -d -P kame)
