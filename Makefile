TARGET?=	netbsd

prepare::
	perl prepare.pl kame ${TARGET}

# only for developers
bsdi3:
	(set CVSROOT=cvs.kame.net/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -d bsdi3 -P kame/bsdi3)

bsdi4:
	(set CVSROOT=cvs.kame.net/cvsroot/kame-local; export CVSROOT; cvs -d cvs.kame.net:/cvsroot/kame-local co -d bsdi4 -P kame/bsdi4)
