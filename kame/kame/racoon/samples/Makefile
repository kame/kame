HOSTNAME!=	/bin/hostname

.if ${HOSTNAME} == "lychee.itojun.org"
SRC=	206.175.160.20
.elif ${HOSTNAME} == "cardamom.itojun.org"
SRC=	206.175.160.21
.endif

TARGETS=	cardamom.conf lychee.conf ssh.conf

all: $(TARGETS)

lychee.conf: sandiego.pl
	perl sandiego.pl $(SRC) 206.175.160.20 > lychee.conf
cardamom.conf: sandiego.pl
	perl sandiego.pl $(SRC) 206.175.160.21 > cardamom.conf
ssh.conf: sandiego.pl
	perl sandiego.pl $(SRC) 194.100.55.1 > ssh.conf

clean:
	-rm -f $(TARGETS)
