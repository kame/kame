PREFIX?=	/usr/local
SYS_INCLUDES?=	-I/usr/src/sys-altq

PROGS=		pvctxctl pvcsif pvcbridge
TXCTL_OBJS=	pvctxctl.o
SIF_OBJS=	pvcsif.o if_nameindex.o
BRIDGE_OBJS=	pvcbridge.o
MAN4=		pvc.4
MAN8=		pvcsif.8 pvctxctl.8 pvcbridge.8

CFLAGS=		-g -Wall -static
DEFINES=	$(SYS_DEFINES)
INCLUDES=	-I. $(SYS_INCLUDES)

all: $(PROGS)

install: $(PROGS)
	$(INSTALL) $(COPY) -m 0755 $(PROGS) $(PREFIX)/sbin
	$(INSTALL) $(COPY) -m 0644 $(MAN4) $(PREFIX)/man/man4
	$(INSTALL) $(COPY) -m 0644 $(MAN8) $(PREFIX)/man/man8

pvctxctl: $(TXCTL_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(TXCTL_OBJS) $(SYS_LIBS)

pvcsif: $(SIF_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(SIF_OBJS) $(SYS_LIBS)

pvcbridge: $(BRIDGE_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(BRIDGE_OBJS) $(SYS_LIBS)

.c.o: 
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $*.c

clean:;		-rm -f $(PROGS) *.o core *.core *.bak ,* *~ "#"*

