/*
 * Copyright (C) 2002
 * 	Hidetoshi Shimokawa. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *
 *	This product includes software developed by Hidetoshi Shimokawa.
 *
 * 4. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $FreeBSD: src/sys/dev/firewire/if_fwe.c,v 1.1.2.10 2003/03/20 02:02:28 simokawa Exp $
 */

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/bus.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_vlan_var.h>
#include <net/route.h>

#include <netinet/in.h>

#include <dev/firewire/firewire.h>
#include <dev/firewire/firewirereg.h>
#include <dev/firewire/if_fwevar.h>

#define FWEDEBUG	if (fwedebug) printf
#define TX_MAX_QUEUE	(FWMAXQUEUE - 1)
#define RX_MAX_QUEUE	FWMAXQUEUE

/* network interface */
static void fwe_start __P((struct ifnet *));
static int fwe_ioctl __P((struct ifnet *, u_long, caddr_t));
static void fwe_init __P((void *));

static void fwe_output_callback __P((struct fw_xfer *));
static void fwe_as_output __P((struct fwe_softc *, struct ifnet *));
static void fwe_as_input __P((struct fw_xferq *));

static int fwedebug = 0;
static int stream_ch = 1;

MALLOC_DEFINE(M_FWE, "if_fwe", "Ethernet over FireWire interface");
SYSCTL_INT(_debug, OID_AUTO, if_fwe_debug, CTLFLAG_RW, &fwedebug, 0, "");
SYSCTL_DECL(_hw_firewire);
SYSCTL_NODE(_hw_firewire, OID_AUTO, fwe, CTLFLAG_RD, 0,
	"Ethernet Emulation Subsystem");
SYSCTL_INT(_hw_firewire_fwe, OID_AUTO, stream_ch, CTLFLAG_RW, &stream_ch, 0,
	"Stream channel to use");

#ifdef DEVICE_POLLING
#define FWE_POLL_REGISTER(func, fwe, ifp)			\
	if (ether_poll_register(func, ifp)) {			\
		struct firewire_comm *fc = (fwe)->fd.fc;	\
		fc->set_intr(fc, 0);				\
	}

#define FWE_POLL_DEREGISTER(fwe, ifp)				\
	do {							\
		struct firewire_comm *fc = (fwe)->fd.fc;	\
		ether_poll_deregister(ifp);			\
		fc->set_intr(fc, 1);				\
	} while(0)						\

static poll_handler_t fwe_poll;

static void
fwe_poll(struct ifnet *ifp, enum poll_cmd cmd, int count)
{
	struct fwe_softc *fwe;
	struct firewire_comm *fc;

	fwe = ((struct fwe_eth_softc *)ifp->if_softc)->fwe;
	fc = fwe->fd.fc;
	if (cmd == POLL_DEREGISTER) {
		/* enable interrupts */
		fc->set_intr(fc, 1);
		return;
	}
	fc->poll(fc, (cmd == POLL_AND_CHECK_STATUS)?0:1, count);
}
#else
#define FWE_POLL_REGISTER(func, fwe, ifp)
#define FWE_POLL_DEREGISTER(fwe, ifp)
#endif
static void
fwe_identify(driver_t *driver, device_t parent)
{
	BUS_ADD_CHILD(parent, 0, "if_fwe", device_get_unit(parent));
}

static int
fwe_probe(device_t dev)
{
	device_t pa;

	pa = device_get_parent(dev);
	if(device_get_unit(dev) != device_get_unit(pa)){
		return(ENXIO);
	}

	device_set_desc(dev, "Ethernet over FireWire");
	return (0);
}

static int
fwe_attach(device_t dev)
{
	struct fwe_softc *fwe;
	struct ifnet *ifp;
	int unit, s;
	u_char *eaddr;
	struct fw_eui64 *eui;

	fwe = ((struct fwe_softc *)device_get_softc(dev));
	unit = device_get_unit(dev);

	bzero(fwe, sizeof(struct fwe_softc));
	/* XXX */
	fwe->stream_ch = stream_ch;
	fwe->dma_ch = -1;

	fwe->fd.fc = device_get_ivars(dev);
	fwe->fd.dev = dev;
	fwe->fd.post_explore = NULL;
	fwe->eth_softc.fwe = fwe;

	fwe->pkt_hdr.mode.stream.tcode = FWTCODE_STREAM;
	fwe->pkt_hdr.mode.stream.sy = 0;
	fwe->pkt_hdr.mode.stream.chtag = fwe->stream_ch;

	/* generate fake MAC address: first and last 3bytes from eui64 */
#define LOCAL (0x02)
#define GROUP (0x01)
	eaddr = &fwe->eth_softc.arpcom.ac_enaddr[0];

	eui = &fwe->fd.fc->eui;
	eaddr[0] = (FW_EUI64_BYTE(eui, 0) | LOCAL) & ~GROUP;
	eaddr[1] = FW_EUI64_BYTE(eui, 1);
	eaddr[2] = FW_EUI64_BYTE(eui, 2);
	eaddr[3] = FW_EUI64_BYTE(eui, 5);
	eaddr[4] = FW_EUI64_BYTE(eui, 6);
	eaddr[5] = FW_EUI64_BYTE(eui, 7);
	printf("if_fwe%d: Fake Ethernet address: "
		"%02x:%02x:%02x:%02x:%02x:%02x\n", unit,
		eaddr[0], eaddr[1], eaddr[2], eaddr[3], eaddr[4], eaddr[5]);

	/* fill the rest and attach interface */	
	ifp = &fwe->fwe_if;
	ifp->if_softc = &fwe->eth_softc;

	ifp->if_unit = unit;
	ifp->if_name = "fwe";
	ifp->if_init = fwe_init;
	ifp->if_output = ether_output;
	ifp->if_start = fwe_start;
	ifp->if_ioctl = fwe_ioctl;
	ifp->if_mtu = ETHERMTU;
	ifp->if_flags = (IFF_BROADCAST|IFF_SIMPLEX|IFF_MULTICAST);
	ifp->if_snd.ifq_maxlen = TX_MAX_QUEUE;

	s = splimp();
#if __FreeBSD_version >= 500000
	ether_ifattach(ifp, eaddr);
#else
	ether_ifattach(ifp, 1);
#endif
	splx(s);

        /* Tell the upper layer(s) we support long frames. */
	ifp->if_data.ifi_hdrlen = sizeof(struct ether_vlan_header);
#if __FreeBSD_version >= 500000
	ifp->if_capabilities |= IFCAP_VLAN_MTU;
#endif


	FWEDEBUG("interface %s%d created.\n", ifp->if_name, ifp->if_unit);
	return 0;
}

static void
fwe_stop(struct fwe_softc *fwe)
{
	struct firewire_comm *fc;
	struct fw_xferq *xferq;
	struct ifnet *ifp = &fwe->fwe_if;
	struct fw_xfer *xfer, *next;
	int i;

	fc = fwe->fd.fc;

	FWE_POLL_DEREGISTER(fwe, ifp);

	if (fwe->dma_ch >= 0) {
		xferq = fc->ir[fwe->dma_ch];

		if (xferq->flag & FWXFERQ_RUNNING)
			fc->irx_disable(fc, fwe->dma_ch);
		xferq->flag &= 
			~(FWXFERQ_MODEMASK | FWXFERQ_OPEN | 
				FWXFERQ_EXTBUF | FWXFERQ_HANDLER);
		xferq->hand =  NULL;

		for (i = 0; i < xferq->bnchunk; i ++)
			m_freem(xferq->bulkxfer[i].mbuf);
		free(xferq->bulkxfer, M_FWE);

		for (xfer = STAILQ_FIRST(&fwe->xferlist); xfer != NULL;
					xfer = next) {
			next = STAILQ_NEXT(xfer, link);
			fw_xfer_free(xfer);
		}
		STAILQ_INIT(&fwe->xferlist);

		xferq->bulkxfer =  NULL;
		fwe->dma_ch = -1;
	}

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);
}

static int
fwe_detach(device_t dev)
{
	struct fwe_softc *fwe;
	int s;

	fwe = (struct fwe_softc *)device_get_softc(dev);
	s = splimp();

	fwe_stop(fwe);
#if __FreeBSD_version >= 500000
	ether_ifdetach(&fwe->fwe_if);
#else
	ether_ifdetach(&fwe->fwe_if, 1);
#endif

	splx(s);
	return 0;
}

static void
fwe_init(void *arg)
{
	struct fwe_softc *fwe = ((struct fwe_eth_softc *)arg)->fwe;
	struct firewire_comm *fc;
	struct ifnet *ifp = &fwe->fwe_if;
	struct fw_xferq *xferq;
	struct fw_xfer *xfer;
	int i;

	FWEDEBUG("initializing %s%d\n", ifp->if_name, ifp->if_unit);

	/* XXX keep promiscoud mode */
	ifp->if_flags |= IFF_PROMISC;

	fc = fwe->fd.fc;
#define START 0
	if (fwe->dma_ch < 0) {
		xferq = NULL;
		for (i = START; i < fc->nisodma; i ++) {
			xferq = fc->ir[i];
			if ((xferq->flag & FWXFERQ_OPEN) == 0)
				break;
		}

		if (xferq == NULL) {
			printf("no free dma channel\n");
			return;
		}
		fwe->dma_ch = i;
		fwe->stream_ch = stream_ch;
		fwe->pkt_hdr.mode.stream.chtag = fwe->stream_ch;
		/* allocate DMA channel and init packet mode */
		xferq->flag |= FWXFERQ_OPEN | FWXFERQ_EXTBUF;
		xferq->flag &= ~0xff;
		xferq->flag |= fwe->stream_ch & 0xff;
		/* register fwe_input handler */
		xferq->sc = (caddr_t) fwe;
		xferq->hand = fwe_as_input;
		xferq->flag |= FWXFERQ_HANDLER;
		xferq->bnchunk = RX_MAX_QUEUE;
		xferq->bnpacket = 1;
		xferq->psize = MCLBYTES;
		xferq->queued = 0;
		xferq->bulkxfer = (struct fw_bulkxfer *) malloc(
			sizeof(struct fw_bulkxfer) * xferq->bnchunk, M_FWE, 0);
		if (xferq->bulkxfer == NULL) {
			printf("if_fwe: malloc failed\n");
			return;
		}
		STAILQ_INIT(&xferq->stvalid);
		STAILQ_INIT(&xferq->stfree);
		STAILQ_INIT(&xferq->stdma);
		xferq->stproc = NULL;
		for (i = 0; i < xferq->bnchunk; i ++) {
			xferq->bulkxfer[i].mbuf = 
#if __FreeBSD_version >= 500000
				m_getcl(M_TRYWAIT, MT_DATA, M_PKTHDR);
#else
				m_getcl(M_WAIT, MT_DATA, M_PKTHDR);
#endif
			xferq->bulkxfer[i].buf =
				mtod(xferq->bulkxfer[i].mbuf, char *);
			STAILQ_INSERT_TAIL(&xferq->stfree,
				&xferq->bulkxfer[i], link);
		}
		STAILQ_INIT(&fwe->xferlist);
		for (i = 0; i < TX_MAX_QUEUE; i++) {
			xfer = fw_xfer_alloc(M_FWE);
			if (xfer == NULL)
				break;
			xfer->send.off = 0;
			xfer->spd = 2;
			xfer->fc = fwe->fd.fc;
			xfer->retry_req = fw_asybusy;
			xfer->sc = (caddr_t)fwe;
			xfer->act.hand = fwe_output_callback;
			STAILQ_INSERT_TAIL(&fwe->xferlist, xfer, link);
		}
	} else
		xferq = fc->ir[fwe->dma_ch];


	/* start dma */
	if ((xferq->flag & FWXFERQ_RUNNING) == 0)
		fc->irx_enable(fc, fwe->dma_ch);

	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	FWE_POLL_REGISTER(fwe_poll, fwe, ifp);
#if 0
	/* attempt to start output */
	fwe_start(ifp);
#endif
}


static int
fwe_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct fwe_softc *fwe = ((struct fwe_eth_softc *)ifp->if_softc)->fwe;
	struct ifstat *ifs = NULL;
	int s, error, len;

	switch (cmd) {
		case SIOCSIFFLAGS:
			s = splimp();
			if (ifp->if_flags & IFF_UP) {
				if (!(ifp->if_flags & IFF_RUNNING))
					fwe_init(&fwe->eth_softc);
			} else {
				if (ifp->if_flags & IFF_RUNNING)
					fwe_stop(fwe);
			}
			/* XXX keep promiscoud mode */
			ifp->if_flags |= IFF_PROMISC;
			splx(s);
			break;
		case SIOCADDMULTI:
		case SIOCDELMULTI:
			break;

		case SIOCGIFSTATUS:
			s = splimp();
			ifs = (struct ifstat *)data;
			len = strlen(ifs->ascii);
			if (len < sizeof(ifs->ascii))
				snprintf(ifs->ascii + len,
					sizeof(ifs->ascii) - len,
					"\tch %d dma %d\n",
						fwe->stream_ch, fwe->dma_ch);
			splx(s);
			break;
#if __FreeBSD_version >= 500000
		default:
#else
		case SIOCSIFADDR:
		case SIOCGIFADDR:
		case SIOCSIFMTU:
#endif
			s = splimp();
			error = ether_ioctl(ifp, cmd, data);
			splx(s);
			return (error);
#if __FreeBSD_version < 500000
		default:
			return (EINVAL);
#endif
	}

	return (0);
}

static void
fwe_output_callback(struct fw_xfer *xfer)
{
	struct fwe_softc *fwe;
	struct ifnet *ifp;
	int s;

	fwe = (struct fwe_softc *)xfer->sc;
	ifp = &fwe->fwe_if;
	/* XXX error check */
	FWEDEBUG("resp = %d\n", xfer->resp);
	if (xfer->resp != 0)
		ifp->if_oerrors ++;
		
	m_freem(xfer->mbuf);
	xfer->send.buf = NULL;
#if 0
	fw_xfer_unload(xfer);
#else
	xfer->state = FWXF_INIT;
	xfer->resp = 0;
	xfer->retry = 0;
#endif
	s = splimp();
	STAILQ_INSERT_TAIL(&fwe->xferlist, xfer, link);
	splx(s);
#if 1
	/* XXX for queue full */
	if (ifp->if_snd.ifq_head != NULL)
		fwe_start(ifp);
#endif
}

static void
fwe_start(struct ifnet *ifp)
{
	struct fwe_softc *fwe = ((struct fwe_eth_softc *)ifp->if_softc)->fwe;
	int s;

#if 1
	FWEDEBUG("%s%d starting\n", ifp->if_name, ifp->if_unit);

	if (fwe->dma_ch < 0) {
		struct mbuf	*m = NULL;

		FWEDEBUG("%s%d not ready.\n", ifp->if_name, ifp->if_unit);

		s = splimp();
		do {
			IF_DEQUEUE(&ifp->if_snd, m);
			if (m != NULL)
				m_freem(m);
			ifp->if_oerrors ++;
		} while (m != NULL);
		splx(s);

		return;
	}

#endif
	s = splimp();
	ifp->if_flags |= IFF_OACTIVE;

	if (ifp->if_snd.ifq_len != 0)
		fwe_as_output(fwe, ifp);

	ifp->if_flags &= ~IFF_OACTIVE;
	splx(s);
}

#define HDR_LEN 4
#ifndef ETHER_ALIGN
#define ETHER_ALIGN 2
#endif
/* Async. stream output */
static void
fwe_as_output(struct fwe_softc *fwe, struct ifnet *ifp)
{
	struct mbuf *m;
	struct fw_xfer *xfer;
	struct fw_xferq *xferq;
	struct fw_pkt *fp;
	int i = 0;

	xfer = NULL;
	xferq = fwe->fd.fc->atq;
	while (xferq->queued < xferq->maxq - 1) {
		xfer = STAILQ_FIRST(&fwe->xferlist);
		if (xfer == NULL) {
			printf("if_fwe: lack of xfer\n");
			return;
		}
		IF_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;
		STAILQ_REMOVE_HEAD(&fwe->xferlist, link);
#if __FreeBSD_version >= 500000
		BPF_MTAP(ifp, m);
#else
		if (ifp->if_bpf != NULL)
			bpf_mtap(ifp, m);
#endif

		/* keep ip packet alignment for alpha */
		M_PREPEND(m, ETHER_ALIGN, M_DONTWAIT);
		fp = (struct fw_pkt *)&xfer->dst; /* XXX */
		xfer->dst = *((int32_t *)&fwe->pkt_hdr);
		fp->mode.stream.len = htons(m->m_pkthdr.len);
		xfer->send.buf = (caddr_t) fp;
		xfer->mbuf = m;
		xfer->send.len = m->m_pkthdr.len + HDR_LEN;

		if (fw_asyreq(fwe->fd.fc, -1, xfer) != 0) {
			/* error */
			ifp->if_oerrors ++;
			/* XXX set error code */
			fwe_output_callback(xfer);
		} else {
			ifp->if_opackets ++;
			i++;
		}
	}
#if 0
	if (i > 1)
		printf("%d queued\n", i);
#endif
	if (i > 0)
		xferq->start(fwe->fd.fc);
}

#if 0
#if __FreeBSD_version >= 500000
static void
fwe_free(void *buf, void *args)
{
	FWEDEBUG("fwe_free:\n");
	free(buf, M_FW);
}

#else
static void
fwe_free(caddr_t buf, u_int size)
{
	int *p;
	FWEDEBUG("fwe_free:\n");
	p = (int *)buf;
	(*p) --;
	if (*p < 1)
		free(buf, M_FW);
}

static void
fwe_ref(caddr_t buf, u_int size)
{
	int *p;

	FWEDEBUG("fwe_ref: called\n");
	p = (int *)buf;
	(*p) ++;
}
#endif
#endif

/* Async. stream output */
static void
fwe_as_input(struct fw_xferq *xferq)
{
	struct mbuf *m;
	struct ifnet *ifp;
	struct fwe_softc *fwe;
	struct fw_bulkxfer *sxfer;
	struct fw_pkt *fp;
	u_char *c;
#if __FreeBSD_version < 500000
	struct ether_header *eh;
#endif

	fwe = (struct fwe_softc *)xferq->sc;
	ifp = &fwe->fwe_if;
#if 0
	FWE_POLL_REGISTER(fwe_poll, fwe, ifp);
#endif
	while ((sxfer = STAILQ_FIRST(&xferq->stvalid)) != NULL) {
		STAILQ_REMOVE_HEAD(&xferq->stvalid, link);
#if 0
		xferq->queued --;
#endif
		if (sxfer->resp != 0)
			ifp->if_ierrors ++;
		fp = (struct fw_pkt *)sxfer->buf;
		/* XXX */
		if (fwe->fd.fc->irx_post != NULL)
			fwe->fd.fc->irx_post(fwe->fd.fc, fp->mode.ld);
		m = sxfer->mbuf;

		/* insert rbuf */
		sxfer->mbuf = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
		sxfer->buf = mtod(sxfer->mbuf, char *);
		STAILQ_INSERT_TAIL(&xferq->stfree, sxfer, link);

		m->m_data += HDR_LEN + ETHER_ALIGN;
		c = mtod(m, char *);
#if __FreeBSD_version < 500000
		eh = (struct ether_header *)c;
		m->m_data += sizeof(struct ether_header);
#endif
		m->m_len = m->m_pkthdr.len =
				ntohs(fp->mode.stream.len) - ETHER_ALIGN;
		m->m_pkthdr.rcvif = ifp;
#if 0
		FWEDEBUG("%02x %02x %02x %02x %02x %02x\n"
			 "%02x %02x %02x %02x %02x %02x\n"
			 "%02x %02x %02x %02x\n"
			 "%02x %02x %02x %02x\n"
			 "%02x %02x %02x %02x\n"
			 "%02x %02x %02x %02x\n",
			 c[0], c[1], c[2], c[3], c[4], c[5],
			 c[6], c[7], c[8], c[9], c[10], c[11],
			 c[12], c[13], c[14], c[15],
			 c[16], c[17], c[18], c[19],
			 c[20], c[21], c[22], c[23],
			 c[20], c[21], c[22], c[23]
		 );
#endif
#if __FreeBSD_version >= 500000
		(*ifp->if_input)(ifp, m);
#else
		ether_input(ifp, eh, m);
#endif
		ifp->if_ipackets ++;
	}
	if (STAILQ_FIRST(&xferq->stfree) != NULL)
		fwe->fd.fc->irx_enable(fwe->fd.fc, fwe->dma_ch);
}


static devclass_t fwe_devclass;

static device_method_t fwe_methods[] = {
	/* device interface */
	DEVMETHOD(device_identify,	fwe_identify),
	DEVMETHOD(device_probe,		fwe_probe),
	DEVMETHOD(device_attach,	fwe_attach),
	DEVMETHOD(device_detach,	fwe_detach),
	{ 0, 0 }
};

static driver_t fwe_driver = {
        "if_fwe",
	fwe_methods,
	sizeof(struct fwe_softc),
};


DRIVER_MODULE(if_fwe, firewire, fwe_driver, fwe_devclass, 0, 0);
MODULE_VERSION(if_fwe, 1);
MODULE_DEPEND(if_fwe, firewire, 1, 1, 1);
