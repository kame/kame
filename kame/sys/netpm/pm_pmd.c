/*	$KAME: pm_pmd.c,v 1.2 2000/02/22 14:07:13 itojun Exp $	*/

/*
//##
//#------------------------------------------------------------------------
//# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
//# All rights reserved.
//# 
//# Redistribution and use in source and binary forms, with or without
//# modification, are permitted provided that the following conditions
//# are met:
//# 1. Redistributions of source code must retain the above copyright
//#    notice, this list of conditions and the following disclaimer.
//# 2. Redistributions in binary form must reproduce the above copyright
//#    notice, this list of conditions and the following disclaimer in the
//#    documentation and/or other materials provided with the distribution.
//# 3. Neither the name of the project nor the names of its contributors
//#    may be used to endorse or promote products derived from this software
//#    without specific prior written permission.
//# 
//# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
//# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
//# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
//# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
//# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
//# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
//# SUCH DAMAGE.
//#
//#	$SuMiRe: pm_pmd.c,v 1.11 1998/09/14 19:49:54 shin Exp $
//#	$Id: pm_pmd.c,v 1.2 2000/02/22 14:07:13 itojun Exp $
//#
//#------------------------------------------------------------------------
*/

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_pm.h"
#endif

#include <sys/param.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/malloc.h>
#endif
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/socket.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include <sys/sockio.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/mbuf.h>
#include <sys/syslog.h>

#if defined(__FreeBSD__)
# include <sys/kernel.h>
# if defined(PM_USE_IOCTL)
#   include "pm.h"
# endif
# if defined(DEVFS)
#  include <sys/devfsext.h>
# endif
#endif	/* __FreeBSD__ */

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include <netinet/ip.h>


#include "netpm/pm_insns.h"
#include "netpm/pm_defs.h"
#include "netpm/pm_log.h"
#include "netpm/pm_list.h"
#include "netpm/pm_ioctl.h"
#include "netpm/pm_extern.h"


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	PM_NUNIT	2

struct	pmdsoftc
{
    int		sc_init;
    int		sc_open;
}  pmdsoftc;


#if defined(PM_USE_IOCTL)
#if defined(__bsdi__)

typedef	u_long	cmd_t;

static	int	pmopen		__P((dev_t, int, int, struct proc *));
static	int	pmclose		__P((dev_t, int, int, struct proc *));
static	int	pmread		__P((dev_t, struct uio *, int));
static	int	pmioctl		__P((dev_t, cmd_t, caddr_t, int, struct proc *));
static	int	pmselect	__P((dev_t, int, struct proc *));

struct	cfdriver    pmcd =
{
    NULL, "pm", NULL, NULL, DV_DULL, 0,
};


struct	devsw	    pmsw =
{
    &pmcd,
    pmopen, pmclose, pmread, nowrite, pmioctl, pmselect, nommap,
    nostrat, nodump,  nopsize, 0,
    nostop,
};
#endif	/* __bsdi__ */

#if defined(__FreeBSD__)

typedef	int	cmd_t;

#define	PMD_NAME	"pmd"
#define	PMLOG_NAME	"pmlog"
#define	CDEV_MAJOR	20

static	pm_devsw_installed = 0;

#if defined(DEVFS)
static	void	*pm_devfs_token[NPM+1];
#endif

static	d_open_t	pmopen;
static	d_close_t	pmclose;
static	d_read_t	pmread;
static	d_ioctl_t	pmioctl;
static	d_select_t	pmselect;

static	struct	cdevsw	pm_cdevsw =
{
    pmopen,     pmclose,   pmread,     nowrite,
    pmioctl,    nostop,    nullreset,  nodevtotty,
    pmselect,   nommap,    nostrategy, PMD_NAME,     NULL,       -1,
};

static	void
pm_drvinit(void *ununsed)
{
    dev_t	dev;

    if (!pm_devsw_installed)
    {
	dev = makedev(CDEV_MAJOR, 0);
	cdevsw_add(&dev, &pm_cdevsw, NULL);
	pm_devsw_installed = 1;
#if defined(DEVFS)
	pm_devfs_token[0] =
	    devfs_add_devswf(&pm_cdevsw, 0, DV_CHR, 0, 0, 0644, PMD_NAME);
	pm_devfs_token[1] =
	    devfs_add_devswf(&pm_cdevsw, 1, DV_CHR, 0, 0, 0644, PMLOG_NAME);
#endif
    }
}

SYSINIT(pmdev, SI_SUB_DRIVERS, SI_ORDER_MIDDLE+CDEV_MAJOR, pm_drvinit, NULL)

#endif	/* __FreeBSD__ */
#endif	/* PM_USE_IOCTL	*/


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

extern	Cell	*pmBoxList;
extern	Cell	*globalFree;
extern	Cell	*selfAddr;

extern	int	 doNatFil;
extern	int	 fr_nat;
extern	int	 fr_filter;


#if defined(__bsdi__)
	void	pmattach		__P((int n));
#endif
#if defined(__FreeBSD__)
	void	pmattach		__P((void *));
#endif

static	int	_pmattach		__P((void));

#if defined(PM_USE_SOCKET)
int	pm_soctl			__P((struct mbuf *, struct socket *));
#endif

static	int	_pmConfigInterface	__P((caddr_t));
static	int	_pmGetSelfaddr		__P((void));
static	int	_pmSetSelfaddrFlag	__P((caddr_t));
static	int	_pmSetGlobalAddress	__P((caddr_t));
static	int	_pmRemoveGlobalAddress	__P((caddr_t));
static	int	_pmFlushGlobalAddress	__P((caddr_t));
static	void	_flushGlobal		__P((natBox *));
static	int	_pmSetNatRule		__P((caddr_t));
static	int	_configNatStatic	__P((natBox *, struct _msgBox *, natRuleEntry *));
static	int	_configNatDynamic	__P((natBox *, struct _msgBox *, natRuleEntry *));
static	int	_pmRemoveNatRule	__P((caddr_t));
static	void	_freeNatRuleEnt		__P((resCtrl *, natRuleEnt *, int));
static	void	_freeAddrBlock		__P((resCtrl *, addrBlock *, int));
static	int	_pmFlushNatRule		__P((caddr_t));
static	void	_flushNatRule		__P((natBox *));
static	void	_flushNatRuleSubsidary	__P((resCtrl *, Cell **, int));
static	int	_pmSetFilRule		__P((caddr_t));
static	int	_pmAddFilRule		__P((caddr_t));
static	int	_pmFlushFilRule		__P((caddr_t));
static	int	_pmSetImmRule		__P((caddr_t));
static	int	_pmRemoveImmRule	__P((caddr_t));
static	int	_pmBindImmRule		__P((struct _msgBox *));
static	int	_pmUnBindImmRule	__P((struct _msgBox *));
#if	obsolete
static	int	_pmRemoveAttEntry	__P((caddr_t));
#endif
static	int	_pmEnableNat		__P((void));
static	int	_pmDisableNat		__P((void));
static	int	_pmEnableFilter		__P((void));
static	int	_pmDisableFilter	__P((void));
static	int	_pmAttachNatFil		__P((void));
static	int	_pmDetachNatFil		__P((void));


static	void	_addFilRuleSubsidiary	__P((Cell **, struct _msgBox *));
static	void	_flushFilRule		__P((pmBox *));
static	void	_flushFilRuleSubsidiary	__P((Cell **));

#if defined(PM_USE_SOCKET)
extern	int	_pmSetLogLevel		__P((caddr_t addr));
extern	void	init_pmlog		__P((void));
extern	int	open_pmlog		__P((int, int, struct proc *));
extern	int	close_pmlog		__P((int, int, struct proc *));
extern	int	read_pmlog		__P((struct uio *, int));
extern  int	select_pmlog		__P((int, struct proc *));
#endif

extern	int	init_dispatcher		__P((void));

extern	int	_pmAddRoute		__P((caddr_t));
extern	int	_pmRemoveRoute		__P((caddr_t));
extern	int	_pmFlushRoute		__P((void));
extern	int	_pmAttachRoute		__P((void));
extern	int	_pmDetachRoute		__P((void));

/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

/*
 * Called at boot time, to establish the pseudo-device.
 * (Note, this happens after real hardware devices are connected via
 * pmattach.)
 */

#if defined(__bsdi__)
void
pmattach(int n)
{
    _pmattach();
}

#endif	/* __bsdi__ */

#if defined(__FreeBSD__)
PSEUDO_SET(pmattach, pm);

void
pmattach(void *dummy)
{
    _pmattach();
}

#endif	/* __FreeBSD__ */

static	int
_pmattach()
{
    if (pmdsoftc.sc_init)
    {
#if !defined(PM_USE_SOCKET)
	printf("pm: already initialized.\n");
#endif
	return (EBUSY);
    }

    pmdsoftc.sc_init = 1;
    pmdsoftc.sc_open = 0;

#if !defined(PM_USE_SOCKET)
    init_pmlog();
#endif

    init_aTT();
    init_ams();
    init_hash();
    init_filter();

#if defined(__bsdi__)
    aprint_naive ("pm: attached\n");
    aprint_normal("pm: attached\n");
#else
    printf("pm: attached.\n");
#endif

    return (0);
}


#if defined(PM_USE_IOCTL)
static	int
pmopen(dev_t dev, int flags, int mode, struct proc *p)
{
    int		rv;

    if (minor(dev) >= PM_NUNIT)
	return (ENXIO);

    if (minor(dev) == 1)
    {
	rv = open_pmlog(flags, mode, p);
	return (rv);
    }

    if (pmdsoftc.sc_open)
	return (EBUSY);

    pmdsoftc.sc_open = 1;

    return (0);
}


static	int
pmclose(dev_t dev, int flags, int mode, struct proc *p)
{
    int		rv;

    if (minor(dev) >= PM_NUNIT)
	return (ENXIO);

    if (minor(dev) == 1)
    {
	rv = close_pmlog(flags, mode, p);
	return (rv);
    }

    pmdsoftc.sc_open  = 0;

    return (0);
}


static	int
pmread(dev_t dev, struct uio *uio, int flag)
{
    int		rv;

    if (minor(dev) >= PM_NUNIT)
	return (ENXIO);

    if (minor(dev) == 1)
    {
	rv = read_pmlog(uio, flag);
	return (rv);
    }

    return (0);
}


static	int
pmioctl(dev_t dev, cmd_t cmd, caddr_t addr, int flag, struct proc *p)
{
    int     error = 0;

    init_dispatcher();

    switch (cmd)
    {
      case PMIOCDEBUG:
	printf("pmd: enter debug.\n");
	return (0);

      case PMIOCSETLOGLVL:	return (_pmSetLogLevel(addr));
      case PMIOCCONF:		return (_pmConfigInterface(addr));
      case PMIOCGETADDR:	return (_pmGetSelfaddr());
      case PMIOCSETADDRFLG:	return (_pmSetSelfaddrFlag(addr));

      case PMIOCSETGLOBAL:	return (_pmSetGlobalAddress(addr));
      case PMIOCREMGLOBAL:	return (_pmRemoveGlobalAddress(addr));
      case PMIOCFLGLOBAL:	return (_pmFlushGlobalAddress(addr));

      case PMIOCSETNAT:		return (_pmSetNatRule(addr));
      case PMIOCREMNAT:		return (_pmRemoveNatRule(addr));
      case PMIOCFLNAT:		return (_pmFlushNatRule(addr));

      case PMIOCSETFRULE:	return (_pmSetFilRule(addr));
      case PMIOCADDFRULE:	return (_pmAddFilRule(addr));
      case PMIOCFLFRULE:	return (_pmFlushFilRule(addr));

      case PMIOCSETIMM:		return (_pmSetImmRule(addr));
      case PMIOCREMIMM:		return (_pmRemoveImmRule(addr));
#if	obsolete
      case PMIOCAREM:		return (_pmRemoveAttEntry(addr));
#endif

      case PMIOCADDROUTE:	return (_pmAddRoute(addr));
      case PMIOCREMROUTE:	return (_pmRemoveRoute(addr));
      case PMIOCFLROUTE:	return (_pmFlushRoute());

      case PMIOCENBLNAT:	return (_pmEnableNat());
      case PMIOCDSBLNAT:	return (_pmDisableNat());

      case PMIOCENBLFIL:	return (_pmEnableFilter());
      case PMIOCDSBLFIL:	return (_pmDisableFilter());

      case PMIOCPMENB:		return (_pmAttachNatFil());
      case PMIOCPMDSB:		return (_pmDetachNatFil());

      case PMIOCENROUTE:	return (_pmAttachRoute());
      case PMIOCDSROUTE:	return (_pmDetachRoute());

      default:
	return (EINVAL);
    }

#if defined(__bsdi__)
    aprint_debug("pmd: ioctl\n");
#else
    printf("pmd: ioctl\n");
#endif

    return (0);
}


static	int
pmselect(dev_t dev, int rw, struct proc *p)
{
    int	    rv;
    int     s = splhigh();

    if (minor(dev) >= PM_NUNIT)
	return (ENXIO);

    if (minor(dev) == 1)
    {
	rv = select_pmlog(rw, p);
	splx(s);
	return (rv);
    }
    
    splx(s);
    return (0);
}
#endif	/* defined(PM_USE_IOCTL)	*/


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#if defined(PM_USE_SOCKET)
int
pm_soctl(struct mbuf *m, struct socket *so)
{
    int			 len, error;
    struct _msgBox	*pmm;

    error = 0;
    init_dispatcher();

    if ((m == NULL)
	|| (((m->m_len < sizeof(long)))
	    && ((m = m_pullup(m, sizeof(long))) == 0)))
	return (ENOBUFS);
    if (m->m_flags & M_PKTHDR)
	len = m->m_pkthdr.len;
    else
	len = m->m_len;
    if (len != sizeof(struct _msgBox))
	return (EINVAL);

    switch ((mtod(m, struct _msgBox *))->msgtype)
    {
      case PMIOCCONF:		return (_pmConfigInterface(mtod(m, caddr_t)));
      case PMIOCGETADDR:	return (_pmGetSelfaddr());
      case PMIOCSETADDRFLG:	return (_pmSetSelfaddrFlag(mtod(m, caddr_t)));

      case PMIOCSETGLOBAL:	return (_pmSetGlobalAddress(mtod(m, caddr_t)));
      case PMIOCREMGLOBAL:	return (_pmRemoveGlobalAddress(mtod(m, caddr_t)));
      case PMIOCFLGLOBAL:	return (_pmFlushGlobalAddress(mtod(m, caddr_t)));

      case PMIOCSETNAT:		return (_pmSetNatRule(mtod(m, caddr_t)));
      case PMIOCREMNAT:		return (_pmRemoveNatRule(mtod(m, caddr_t)));
      case PMIOCFLNAT:		return (_pmFlushNatRule(mtod(m, caddr_t)));

      case PMIOCSETFRULE:	return (_pmSetFilRule(mtod(m, caddr_t)));
      case PMIOCADDFRULE:	return (_pmAddFilRule(mtod(m, caddr_t)));
      case PMIOCFLFRULE:	return (_pmFlushFilRule(mtod(m, caddr_t)));

      case PMIOCSETIMM:		return (_pmSetImmRule(mtod(m, caddr_t)));
      case PMIOCREMIMM:		return (_pmRemoveImmRule(mtod(m, caddr_t)));

      case PMIOCADDROUTE:	return (_pmAddRoute(mtod(m, caddr_t)));
      case PMIOCREMROUTE:	return (_pmRemoveRoute(mtod(m, caddr_t)));
      case PMIOCFLROUTE:	return (_pmFlushRoute());

      case PMIOCENBLNAT:	return (_pmEnableNat());
      case PMIOCDSBLNAT:	return (_pmDisableNat());
      case PMIOCENBLFIL:	return (_pmEnableFilter());
      case PMIOCDSBLFIL:	return (_pmDisableFilter());

#if defined(not_used)
      case PMIOCENBLROUTE:	
      case PMIOCDSBLROUTE:	
#endif

      case PMIOCPMENB:		return (_pmAttachNatFil());
      case PMIOCPMDSB:		return (_pmDetachNatFil());

      case PMIOCENROUTE:	return (_pmAttachRoute());
      case PMIOCDSROUTE:	return (_pmDetachRoute());

      default:
	return (EOPNOTSUPP);
    }

    return (error);
}
#endif


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

static	int
_pmConfigInterface(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    pmBox		*pmb;

    if (((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	&& ((pmb = pm_setPmBox(mbx->m_ifName)) == NULL))
	return (ENXIO);

    if (pmb->side != NoSide)
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] interface `%s\' already configured.", mbx->m_ifName);
	pm_log(LOG_MSG, LOG_WARNING, WoW, strlen(WoW));
	return (EALREADY);
    }

    {
	char	 WoW[LLEN];
	char	*s;

	if (mbx->flags == IF_EXTERNAL)
	    pmb->side = OutSide, s = "outside";
	else
	    pmb->side = InSide,  s = "inside";

	sprintf(WoW, "[pm] interface `%s\' set as %s.",	mbx->m_ifName, s);
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }

    return (0);
}


static	int
_pmGetSelfaddr()
{
    if (selfAddr != NULL)
	return (EALREADY);

    _getSelfAddr();
    return (0);
}


static	int
_pmSetSelfaddrFlag(caddr_t addr)
{
    Cell		*p;
    struct in_addr	 inaddr;
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    SelfAddr		*self;

    inaddr = *(struct in_addr *)mbx->m_aux;

    for (p = selfAddr; p; p = CDR(p))
    {
	self = (SelfAddr *)CAR(p);

	if (self->ifaddr.s_addr == inaddr.s_addr)
	{
	    if (mbx->flags & RESETFLAG)
		self->addrflags &= mbx->flags;
	    else
		self->addrflags |= mbx->flags;
	    return (0);
	}
    }

    return (ENXIO);
}


static	int
_pmSetGlobalAddress(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    gAddr		*gap;
    struct in_addr	*iap, *iapp;
    pmBox		*pmb;
    int			 iter;

    if (((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	&& ((pmb = pm_setPmBox(mbx->m_ifName)) == NULL))
	return (ENXIO);

    if (pmb->natBox == NULL)
    {
	MALLOC(pmb->natBox, natBox *, sizeof(natBox), M_PM, M_WAITOK);
	bzero(pmb->natBox, sizeof(natBox));
    }

    MALLOC(iap, struct in_addr *, sizeof(struct in_addr) * mbx->nums, M_PM, M_WAITOK);
    copyin(mbx->freight, iap, sizeof(struct in_addr) * mbx->nums);

    for (iter = 0, iapp = iap; iter < mbx->nums; iter++, iapp++)
    {
	if (isGlobalAddr(&pmb->natBox->global, iapp) != NULL)
	    continue;

	MALLOC(gap, gAddr *, sizeof(gAddr), M_PM, M_WAITOK);
	bzero(gap, sizeof(gAddr));
	gap->addr = *iapp;
	gap->linkc  = 0;
	pmb->natBox->global._free++;
	LST_hookup_list(&pmb->natBox->global.free, gap);
	{
	    char	WoW[LLEN];
	    
	    sprintf(WoW, "[pm] assigned global addr %s.", inet_ntoa(gap->addr));
	    pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
	}
    }
    FREE(iap, M_PM);
    return (0);
}


static	int
_pmRemoveGlobalAddress(caddr_t addr)
{
    gAddr		*gac;
    struct in_addr	*iap, *iapp;
    pmBox		*pmb;
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    int			 iter;

    if ((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	return (ENXIO);

    if (pmb->natBox == NULL)
	return (ENXIO);

    MALLOC(iap, struct in_addr *, mbx->size * mbx->nums, M_PM, M_WAITOK);
    copyin(mbx->freight, iap, mbx->size * mbx->nums);

    for (iter = 0, iapp = iap; iter < mbx->nums; iter++, iapp++)
    {
	if ((iapp->s_addr == (-1))
	    || ((gac = isGlobalAddr(&pmb->natBox->global, iapp)) == NULL))
	    continue;
	
	if (gac->linkc > 1)
	    continue;

	if (LST_remove_elem(&pmb->natBox->global.free, gac) != NULL)
	{
	    FREE(gac, M_PM);
	    pmb->natBox->global._free--;
	}
    }

    FREE(iap, M_PM);
    return (0);
}


static	int
_pmFlushGlobalAddress(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    pmBox		*pmb;

    if (*mbx->m_aux != '\0')
    {
	if ((pmb = pm_asPmBoxName(mbx->m_ifName)) == SAME)
	    return (ENXIO);

	_flushGlobal(pmb->natBox);
    }
    else
    {
	Cell	*p;

	for (p = pmBoxList; p; p = CDR(p))
	    _flushGlobal(((pmBox *)CAR(p))->natBox);
    }

    return (0);
}


static	void
_flushGlobal(natBox *nBox)
{
    Cell	*p0, *p1;
    gAddr	*gac;

    if (nBox == NULL)
	return ;

    p0 = nBox->global.free;
    while (p0)
    {
	p1 = p0;
	p0 = CDR(p0);
	gac = (gAddr *)CAR(p1);
	if (LST_remove_elem(&nBox->global.free, gac) != NULL)
	{
	    FREE(gac, M_PM);
	    nBox->global._free--;
	}
    }
}


static	int
_pmSetNatRule(caddr_t addr)
{
    int			 rv;
    pmBox		*pmb;
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    natRuleEntry	*ncep;
    
    rv = 0;
    if (((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	&& ((pmb = pm_setPmBox(mbx->m_ifName)) == NULL))
	return (ENXIO);

    if (pmb->natBox == NULL)
    {
	MALLOC(pmb->natBox, natBox *, sizeof(natBox), M_PM, M_WAITOK);
	bzero(pmb->natBox, sizeof(natBox));
    }

    MALLOC(ncep, natRuleEntry *, mbx->nums * mbx->size, M_PM, M_WAITOK);
    copyin(mbx->freight, ncep, mbx->nums * mbx->size);

    switch(ncep->type)
    {
      case NAT_STATIC:
	rv = _configNatStatic (pmb->natBox, mbx, ncep);
	break;

      case NAT_DYNAMIC:
	rv = _configNatDynamic(pmb->natBox, mbx, ncep);
	break;
    }

    FREE(ncep, M_PM);
    return (rv);
}


static	int
_configNatStatic(natBox *nBox, struct _msgBox *ncp, natRuleEntry *ncep)
{
    addrBlock	*ap;
    gAddr	*gac;
    natRuleEnt	*nac;

    if ((gac = getGlobalAddr(nBox, &ncep->addr[1].addr[0], ncep->type)) == NULL)
	return (EINVAL);

    MALLOC(nac, natRuleEnt *, sizeof(natRuleEnt), M_PM, M_WAITOK);
    bzero(nac, sizeof(natRuleEnt));

    MALLOC(ap, addrBlock *, sizeof(addrBlock), M_PM, M_WAITOK);
    bzero(ap, sizeof(addrBlock));
    *ap = ncep->addr[0];
    ap->type = IN_ADDR_SINGLE;
    ap->ptrn.s_addr = 0;
    LST_hookup_list(&nac->local, ap);

    MALLOC(ap, void *, sizeof(addrBlock), M_PM, M_WAITOK);
    bzero(ap, sizeof(addrBlock));
    *ap = ncep->addr[1];
    ap->type  = IN_ADDR_SINGLE;
    ap->gList = NULL;
    LST_hookup_list(&ap->gList, gac);
    LST_hookup_list(&nac->foreign, ap);
    nac->gAddrLen = 1;

    LST_hookup_list(&nBox->natStatic, nac);

    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] nat:map static %s -> %s",
		inet_ntoa(((addrBlock *)CAR(nac->local))->addr[0]),
		inet_ntoa(((addrBlock *)CAR(nac->foreign))->addr[0]));
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }

    return (0);
}


static	int
_configNatDynamic(natBox *nBox, struct _msgBox *nrp, natRuleEntry *nre)
{
    int		 iter;
    natRuleEnt	*nac;

    union
    {
	addrBlock   *s;
	char	    *c;
    }		     blk;

    MALLOC(nac, natRuleEnt *, sizeof(natRuleEnt), M_PM, M_WAITOK);
    bzero(nac, sizeof(natRuleEnt));

    blk.s = nre->addr;
    for (iter = 0; iter < nre->srcCnt; iter++)
    {
	addrBlock	*sap;

	MALLOC(sap, addrBlock *, sizeof(addrBlock), M_PM, M_WAITOK);
	*(addrBlock *)sap = *blk.s;
	switch (sap->type)
	{
	  case IN_ADDR_SINGLE:
	  case IN_ADDR_RANGE:
	    sap->ptrn.s_addr = 0;
	    break;

	  case IN_ADDR_MASK:
	    sap->ptrn.s_addr = sap->addr[0].s_addr & sap->addr[1].s_addr;
	    break;
	}
	LST_hookup_list(&nac->local, sap);
	blk.c += sizeof(addrBlock);
    }

    for (iter = 0; iter < nre->dstCnt; iter++)
    {
	int		 cnt, ite;
	gAddr		*gac;
	addrBlock	*dap;

	MALLOC(dap, addrBlock *, sizeof(addrBlock), M_PM, M_WAITOK);
	*(addrBlock *)dap = *blk.s;
	dap->policy   = nre->policy;
	dap->gList    = NULL;
	dap->gAddrCur = NULL;
	LST_hookup_list(&nac->foreign, dap);
	blk.c += sizeof(addrBlock);

	cnt = *(int *)blk.c;
	blk.c += sizeof(int);
	for (ite = 0; ite < cnt; ite++)
	{
	    if ((gac = getGlobalAddr(nBox, (struct in_addr *)blk.s, nre->type)) == NULL)
		continue;

	    LST_hookup_list(&dap->gList, gac);
	    blk.c += sizeof(int);
	}
    }

/*  CDR(LST_last(nac->foreign)) = nac->foreign;		-- make RingList    */
    nac->gAddrLen = nre->dstCnt;

    nac->type     = nre->type;
    nac->policy   = nre->policy;

    LST_hookup_list(&nBox->natDynamic, nac);
    return (0);
}


static	int
_pmRemoveNatRule(caddr_t addr)
{
    Cell		*p0, *p1, **anchor;
    pmBox		*pmb;
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    int			*m, idx0, idx1;
    int			 rv;

    if ((pmb = pm_asPmBoxName(mbx->m_aux)) == NULL)
	return (ENXIO);

    if (pmb->natBox == NULL)
	return (ENXIO);

    MALLOC(m, int *, mbx->nums * mbx->size, M_PM, M_WAITOK);
    copyin(mbx->freight, m, mbx->nums * mbx->size);

    switch (mbx->flags)
    {
      case NAT_STATIC:	anchor = &pmb->natBox->natStatic;	break;
      case NAT_DYNAMIC:	anchor = &pmb->natBox->natDynamic;	break;
    }

    for (p0 = *anchor, idx0 = idx1 = 0; p0; idx0++)
    {
	p1 = p0;
	p0 = CDR(p0);
	if (idx0 == m[idx1])
	{
	    int		 s;
	    natRuleEnt	*nre;

	    idx1++;
	    nre = (natRuleEnt *)CAR(p1);
	    s = splnet();
	    LST_remove_elem(anchor, nre);
	    splx(s);
	    _freeNatRuleEnt(&pmb->natBox->global, nre, mbx->flags);
	}
	if ((m[idx1] == -1) || (idx1 >= mbx->nums))
	    break;
    }

    FREE(m, M_PM);

    return (0);
}


static	int
_pmFlushNatRule(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    pmBox		*pmb;

    if (*mbx->m_ifName != '\0')
    {
	if ((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	    return (ENXIO);

	_flushNatRule(pmb->natBox);
    }
    else
    {
	Cell	*p;

	for (p = pmBoxList; p; p = CDR(p))
	    _flushNatRule(((pmBox *)CAR(p))->natBox);
    }

    return (0);
}


static	void
_flushNatRule(natBox *nBox)
{
    if (nBox == NULL)
	return ;

    _flushNatRuleSubsidary(&nBox->global, &nBox->natStatic,  NAT_STATIC);
    _flushNatRuleSubsidary(&nBox->global, &nBox->natDynamic, NAT_DYNAMIC);
}


static	void
_flushNatRuleSubsidary(resCtrl *res, Cell **hook, int type)
{
    int		 s;
    Cell	*p0, *p1;
    natRuleEnt	*nre;

    if ((hook == NULL)
	|| (*hook == NULL))
	return ;

    p0 = *hook;
    while (p0)
    {
	p1 = p0;
	p0 = CDR(p0);
	nre = (natRuleEnt *)CAR(p1);
	s = splnet();
	LST_remove_elem(hook, nre);
	splx(s);
	_freeNatRuleEnt(res, nre, type);
    }
}


static	void
_freeNatRuleEnt(resCtrl *res, natRuleEnt *nre, int type)
{
    Cell	*p0, *p1;

    if (nre->local)
    {
	p0 = nre->local;
	while (p0)
	{
	    p1 = p0;
	    p0 = CDR(p0);
	    _freeAddrBlock(res, (addrBlock *)CAR(p1), type);
	    LST_free(p1);
	}
    }

    if (nre->foreign)
    {
	p0 = nre->foreign;
	while (p0)
	{
	    p1 = p0;
	    p0 = CDR(p0);
	    _freeAddrBlock(res, (addrBlock *)CAR(p1), type);
	    LST_free(p1);
	}
    }
    FREE(nre, M_PM);
}


static	void
_freeAddrBlock(resCtrl *res, addrBlock *blk, int type)
{
    if (blk->gList)
    {
	Cell	*p0, *p1;

	p0 = blk->gList;
	while (p0)
	{
	    p1 = p0;
	    p0 = CDR(p0);
	    getBackGlobalAddr(res, (gAddr *)CAR(p1), type);
	    LST_free(p1);
	}
    }
    FREE(blk, M_PM);
}


static	int
_pmSetFilRule(caddr_t addr)
{
    return (0);
}


static	int
_pmAddFilRule(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    pmBox		*pmb;

    if (((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	&& ((pmb = pm_setPmBox(mbx->m_ifName)) == NULL))
	return (ENXIO);

    if (pmb->filBox == NULL)
    {
	MALLOC(pmb->filBox, filBox *, sizeof(filBox), M_PM, M_WAITOK);
	bzero(pmb->filBox, sizeof(filBox));
    }

    switch ((mbx->flags) & 0x3)
    {
      case FIL_BEFORE:
	if (mbx->flags & FIL_INPUT)
	    _addFilRuleSubsidiary(&pmb->filBox->i.filRuleMae, mbx);
	else
	    _addFilRuleSubsidiary(&pmb->filBox->o.filRuleMae, mbx);
	break;

      case FIL_AFTER:
	if (mbx->flags & FIL_INPUT)
	    _addFilRuleSubsidiary(&pmb->filBox->i.filRuleAto, mbx);
	else
	    _addFilRuleSubsidiary(&pmb->filBox->o.filRuleAto, mbx);
	break;

      default:
	return (EINVAL);
    }

    return (0);
}


static	int
_pmFlushFilRule(caddr_t addr)
{
    struct _msgBox	*pbx = (struct _msgBox *)addr;
    pmBox		*pmb;

    if (*pbx->m_ifName != '\0')
    {
	if ((pmb = pm_asPmBoxName(pbx->m_ifName)) == NULL)
	    return (ENXIO);

	_flushFilRule(pmb);
    }
    else
    {
	Cell	*p;

	for (p = pmBoxList; p; p = CDR(p))
	    _flushFilRule((pmBox *)CAR(p));
    }

    return (0);
}


static	int
_pmSetImmRule(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    immEntry		 ie;
    int			 rv = 0;

    switch (mbx->flags)
    {
      case IMM_VIRTUAL:
	copyin(mbx->freight, &ie, sizeof(immEntry));
	rv = setVirtualAddr(&ie.virtual);
	break;

      case IMM_REAL:
	copyin(mbx->freight, &ie, sizeof(immEntry));
	rv = setRealAddr(&ie.real[0]);
	break;

      case IMM_BIND:
	rv = _pmBindImmRule(mbx);
	break;

      default:
	rv = EINVAL;
    }
    return (rv);
}


static	int
_pmRemoveImmRule(caddr_t addr)
{
    struct _msgBox	*mbx = (struct _msgBox *)addr;
    immEntry	 ie;
    int		 rv = 0;

    switch (mbx->flags)
    {
      case IMM_VIRTUAL:
	copyin(mbx->freight, &ie, sizeof(immEntry));
	rv = unsetVirtualAddr(&ie.virtual);
	break;

      case IMM_REAL:
	copyin(mbx->freight, &ie, sizeof(immEntry));
	rv = unsetRealAddr(&ie.real[0]);
	break;

      case IMM_BIND:
	rv = _pmUnBindImmRule(mbx);
	break;

      default:
	rv = EINVAL;
    }
    return (rv);
}


#if defined(__FreeBSD__)
extern	Cell	*immBind;
extern	Cell	*immRealPool;
#endif


static	int
_pmBindImmRule(struct _msgBox *mbx)
{
    int		 size, iter;
    immEntry	*ie;
    virtualAddr	*va;
    realAddr	*ra;
    pmBox	*pmb;
    int		 s;

#if defined(__bsdi__)
    extern	Cell	*immBind;
    extern	Cell	*immRealPool;
#endif

    if (((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	&& ((pmb = pm_setPmBox(mbx->m_ifName)) == NULL))
	return (ENXIO);

    if (pmb->natBox == NULL)
    {
	MALLOC(pmb->natBox, natBox *, sizeof(natBox), M_PM, M_WAITOK);
	bzero(pmb->natBox, sizeof(natBox));
    }

    size = mbx->nums * sizeof(struct in_addr);
    MALLOC(ie, immEntry *, size, M_PM, M_WAITOK);
    bzero(ie, size);

    copyin(mbx->freight, ie, size);

    s = splnet();

    if ((va = isInVirtualAddress(&ie->virtual)) != NULL)
    {
	for (iter = 0; iter < mbx->nums - 1; iter++)
	{
	    if (((ra = isInRealAdddress(&ie->real[iter])) != NULL)
		&& ((ra->ra_flags & RIP_BINDED) == 0))
	    {
		Cell	*p;

		va->NumOfRrealaddr++;
		ra->ra_flags |= RIP_BINDED;
		if (va->realAddrHead)
		{
		    p = LST_cons(ra, va->realAddrHead);
		    CDR(va->realAddrTail) = p;
		    va->realAddrTail = p;
		}
		else
		{
		    p = LST_cons(ra, NIL);

		    va->realAddrHead =
			va->realAddrTail =
			    CDR(p) = p;
		}

#if defined(PM_SYSLOG)
		log(LOG_NOTICE, "[ld] bind %s -> %s\n",
		    inet_ntoa(va->virtualAddr), inet_ntoa(ra->realAddr));
#endif
	    }
	}

	if (va->NumOfRrealaddr == 1)
	    LST_hookup_list(&pmb->natBox->immBind, va);
    }

    splx(s);

    FREE(ie, M_PM);
    return (0);
}


static	int
_pmUnBindImmRule(struct _msgBox *mbx)
{
    int		 size, iter;
    immEntry	*ie;
    virtualAddr	*va;
    realAddr	*ra;
    pmBox	*pmb;
    int		 s;

#if defined(__bsdi__)
    extern	Cell	*immBind;
    extern	Cell	*immRealPool;
#endif

    if (((pmb = pm_asPmBoxName(mbx->m_ifName)) == NULL)
	&& ((pmb = pm_setPmBox(mbx->m_ifName)) == NULL))
	return (ENXIO);

    if (pmb->natBox == NULL)
    {
	MALLOC(pmb->natBox, natBox *, sizeof(natBox), M_PM, M_WAITOK);
	bzero(pmb->natBox, sizeof(natBox));
    }

    size = mbx->nums * sizeof(struct in_addr);
    MALLOC(ie, immEntry *, size, M_PM, M_WAITOK);
    bzero(ie, size);

    copyin(mbx->freight, ie, size);

    s = splnet();

    if ((va = isInVirtualAddress(&ie->virtual)) != NULL)
    {
	for (iter = 0; iter < mbx->nums - 1; iter++)
	{
	    if (((ra = isInRealAdddress(&ie->real[iter])) != NULL)
		&& ((ra->ra_flags & RIP_BINDED) != 0))
	    {
		ra->ra_flags &= ~RIP_BINDED;
		va->NumOfRrealaddr--;
		switch (va->NumOfRrealaddr)
		{
		  case 0:
		    LST_free(va->realAddrHead);
		    va->realAddrHead = va->realAddrTail = NULL;
		    break;

		  case 1:
		    if (ra == (realAddr *)CAR(va->realAddrHead))
		    {
			LST_free(va->realAddrHead);
			CDR(va->realAddrTail)
			    = va->realAddrHead = va->realAddrTail;
		    }
		    else
		    {
			LST_free(va->realAddrTail);
			CDR(va->realAddrHead)
			    = va->realAddrTail = va->realAddrHead;
		    }
		    break;

		  default:
		    {
			register	Cell	*p;

			if (ra == (realAddr *)CAR(va->realAddrHead))
			{
			    p = va->realAddrHead;
			    va->realAddrHead
				= CDR(va->realAddrTail) = CDR(p);
			    LST_free(p);
			}
			else if (ra == (realAddr *)CAR(va->realAddrTail))
			{
			    for (p = va->realAddrHead; ; p = CDR(p))
			    {
				if (CDR(p) == va->realAddrTail)
				    break;
			    }
			    va->realAddrTail = p;
			    p = CDR(p);
			    CDR(va->realAddrTail) = va->realAddrHead;
			    LST_free(p);
			}
			else
			{
			    LST_remove_elem(&va->realAddrHead, ra);
			}
		    }
		    break;
		}

#if defined(PM_SYSLOG)
		log(LOG_NOTICE, "[ld] no bind %s -> %s\n",
		    inet_ntoa(va->virtualAddr), inet_ntoa(ra->realAddr));
#endif
	    }
	}

	if (va->NumOfRrealaddr == 0)
	    LST_remove_elem(&pmb->natBox->immBind, va);
    }

    splx(s);

    FREE(ie, M_PM);
    return (0);
}


#if	obsolete
static	int
_pmRemoveAttEntry(caddr_t addr)
{
    natRule	*nrp = (natRule *)addr;
    natEntry	*nep, ne;
    int		 iter;

    nep = nrp->nrEntry;
    for (iter = 1; iter <= nrp->nrLen; iter++)
    {
	copyin(nep, &ne, sizeof(natEntry));
	pm_removeAttEntry(ne.type, 
			  ne.inaddr[0].s_addr, ne.inport[0],
			  ne.exaddr[0].s_addr, ne.export[0]);  
	nep++;
    }
    return (EOPNOTSUPP);
}
#endif


static	int
_pmEnableNat()
{
    fr_nat   = TRUE;
    doNatFil = fr_nat | fr_filter;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[pm] nat enabled.\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] nat enabled.\n");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


static	int
_pmDisableNat()
{
    fr_nat   = FALSE;
    doNatFil = fr_nat | fr_filter;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[pm] nat disabled.\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] nat disabled.\n");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


static	int
_pmEnableFilter()
{
    fr_filter = TRUE;
    doNatFil = fr_nat | fr_filter;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[pm] filter enabled.\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] filter enabled.");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


static	int
_pmDisableFilter()
{
    fr_filter = FALSE;
    doNatFil = fr_nat | fr_filter;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[pm] filter disabled.\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] filter disabled.");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


static	int
_pmAttachNatFil()
{
    doNatFil = TRUE;
    fr_nat   = TRUE;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[ld] enable\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] enabled.");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


static	int
_pmDetachNatFil()
{
    doNatFil = FALSE;
    fr_nat   = FALSE;

#if defined(PM_SYSLOG)
    log(LOG_DEBUG, "[ld] disable\n");
#else
    {
	char	WoW[LLEN];

	sprintf(WoW, "[pm] disabled.");
	pm_log(LOG_MSG, LOG_INFO, WoW, strlen(WoW));
    }
#endif

    return (0);
}


/*
//##
//#------------------------------------------------------------------------
//#
//#------------------------------------------------------------------------
*/

#define	SZPMPROG	sizeof(struct pm_program)

static	void
_addFilRuleSubsidiary(Cell **hook, struct _msgBox *mbx)
{
    int		 frNum;
    int		 ib, rb;
    char	*uadInsns, *kadInsns;
    char	*uadRules, *kadRules;
    struct pm_program	*pmp;
    Cell		*p;

    uadInsns = mbx->m_frInsns;
    uadRules = mbx->m_frRules;
    kadRules = NULL;

    for (frNum = 1; frNum <= mbx->nums; frNum++)
    {
	copyin(uadInsns, &ib, sizeof(int));
	uadInsns += sizeof(struct pm_program);
	MALLOC(kadInsns, char *, ib+SZPMPROG, M_PM, M_WAITOK);
	copyin(uadInsns, kadInsns+SZPMPROG, ib);
	uadInsns += ib;

	pmp = (struct pm_program *)kadInsns;
	pmp->pm_len = ib / sizeof(struct pm_program);
	pmp->pm_insns = (struct pm_insn *)(kadInsns+SZPMPROG);

	if (uadRules != NULL)
	{
	    copyin(uadRules, &rb, sizeof(int));
	    uadRules += sizeof(int);
	    MALLOC(kadRules, char *, rb, M_PM, M_WAITOK);
	    copyin(uadRules, kadRules, rb);
	    uadRules += rb;
	}

	p = LST_cons(kadInsns, kadRules);
	LST_hookup_list(hook, p);
    }
}


static	void
_flushFilRule(pmBox *pmb)
{
    if ((pmb == NULL)
	|| (pmb->filBox == NULL))
	return ;

    _flushFilRuleSubsidiary(&pmb->filBox->i.filRuleMae);
    _flushFilRuleSubsidiary(&pmb->filBox->o.filRuleMae);
    _flushFilRuleSubsidiary(&pmb->filBox->i.filRuleAto);
    _flushFilRuleSubsidiary(&pmb->filBox->o.filRuleAto);
}


static	void
_flushFilRuleSubsidiary(Cell **hook)
{
    int		 s;
    Cell	*p0, *p1;
    Cell	*guru;

    if ((hook == NULL)
	|| (*hook == NULL))
	return ;

    p0 = *hook;
    s = splnet();
    while (p0)
    {
	p1 = p0;
	p0 = CDR(p0);
	guru = CAR(p1);
	if (CAR(guru))		FREE(CAR(guru), M_PM);
	if (CDR(guru))		FREE(CDR(guru), M_PM);
	LST_free(guru);
	LST_remove_elem(hook, guru);
    }
    splx(s);
}
