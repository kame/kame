TARGET?=	netbsd

prepare::
	perl prepare.pl kame ${TARGET}

clean::
	find ${TARGET} -type l -print | perl -nle unlink

# only for developers
bsdi3:
	(set CVSROOT=cvs.kame.net/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -d bsdi3 -P kame/bsdi3)

bsdi4:
	(set CVSROOT=cvs.kame.net/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -d bsdi4 -P kame/bsdi4)

DOC=	CHANGELOG COPYRIGHT COPYRIGHT.jp IMPLEMENTATION INSTALL \
	INSTALL.anoncvs Makefile PORTABILITY VERSION prepare.pl \
	TODO.new-repository
PLAT=	freebsd2 freebsd3 kame netbsd openbsd bsdi3 bsdi4

update: update-doc update-plat
update-doc:
	cvs update -d -P ${DOC}
update-plat:
	for i in kame ${TARGET}; do \
		if test -d $$i; then \
			(cd $$i; cvs update -d -P); \
		fi \
	done
update-all: update-doc
	for i in ${PLAT}; do \
		if test -d $$i; then \
			(cd $$i; cvs update -d -P); \
		fi \
	done
