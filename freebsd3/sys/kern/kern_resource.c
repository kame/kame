/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	@(#)kern_resource.c	8.5 (Berkeley) 1/21/94
 * $Id: kern_resource.c,v 1.38.2.1 1999/02/25 14:36:29 bde Exp $
 */

#include "opt_compat.h"
#include "opt_rlimit.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/resourcevar.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_prot.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

static int donice __P((struct proc *curp, struct proc *chgp, int n));
static int dosetrlimit __P((struct proc *p, u_int which, struct rlimit *limp));

/*
 * Resource controls and accounting.
 */

#ifndef _SYS_SYSPROTO_H_
struct getpriority_args {
	int	which;
	int	who;
};
#endif
int
getpriority(curp, uap)
	struct proc *curp;
	register struct getpriority_args *uap;
{
	register struct proc *p;
	register int low = PRIO_MAX + 1;

	switch (uap->which) {

	case PRIO_PROCESS:
		if (uap->who == 0)
			p = curp;
		else
			p = pfind(uap->who);
		if (p == 0)
			break;
		low = p->p_nice;
		break;

	case PRIO_PGRP: {
		register struct pgrp *pg;

		if (uap->who == 0)
			pg = curp->p_pgrp;
		else if ((pg = pgfind(uap->who)) == NULL)
			break;
		for (p = pg->pg_members.lh_first; p != 0;
		     p = p->p_pglist.le_next) {
			if (p->p_nice < low)
				low = p->p_nice;
		}
		break;
	}

	case PRIO_USER:
		if (uap->who == 0)
			uap->who = curp->p_ucred->cr_uid;
		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next)
			if (p->p_ucred->cr_uid == uap->who &&
			    p->p_nice < low)
				low = p->p_nice;
		break;

	default:
		return (EINVAL);
	}
	if (low == PRIO_MAX + 1)
		return (ESRCH);
	curp->p_retval[0] = low;
	return (0);
}

#ifndef _SYS_SYSPROTO_H_
struct setpriority_args {
	int	which;
	int	who;
	int	prio;
};
#endif
/* ARGSUSED */
int
setpriority(curp, uap)
	struct proc *curp;
	register struct setpriority_args *uap;
{
	register struct proc *p;
	int found = 0, error = 0;

	switch (uap->which) {

	case PRIO_PROCESS:
		if (uap->who == 0)
			p = curp;
		else
			p = pfind(uap->who);
		if (p == 0)
			break;
		error = donice(curp, p, uap->prio);
		found++;
		break;

	case PRIO_PGRP: {
		register struct pgrp *pg;

		if (uap->who == 0)
			pg = curp->p_pgrp;
		else if ((pg = pgfind(uap->who)) == NULL)
			break;
		for (p = pg->pg_members.lh_first; p != 0;
		    p = p->p_pglist.le_next) {
			error = donice(curp, p, uap->prio);
			found++;
		}
		break;
	}

	case PRIO_USER:
		if (uap->who == 0)
			uap->who = curp->p_ucred->cr_uid;
		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next)
			if (p->p_ucred->cr_uid == uap->who) {
				error = donice(curp, p, uap->prio);
				found++;
			}
		break;

	default:
		return (EINVAL);
	}
	if (found == 0)
		return (ESRCH);
	return (error);
}

static int
donice(curp, chgp, n)
	register struct proc *curp, *chgp;
	register int n;
{
	register struct pcred *pcred = curp->p_cred;

	if (pcred->pc_ucred->cr_uid && pcred->p_ruid &&
	    pcred->pc_ucred->cr_uid != chgp->p_ucred->cr_uid &&
	    pcred->p_ruid != chgp->p_ucred->cr_uid)
		return (EPERM);
	if (n > PRIO_MAX)
		n = PRIO_MAX;
	if (n < PRIO_MIN)
		n = PRIO_MIN;
	if (n < chgp->p_nice && suser(pcred->pc_ucred, &curp->p_acflag))
		return (EACCES);
	chgp->p_nice = n;
	(void)resetpriority(chgp);
	return (0);
}

/* rtprio system call */
#ifndef _SYS_SYSPROTO_H_
struct rtprio_args {
	int		function;
	pid_t		pid;
	struct rtprio	*rtp;
};
#endif

/*
 * Set realtime priority
 */

/* ARGSUSED */
int
rtprio(curp, uap)
	struct proc *curp;
	register struct rtprio_args *uap;
{
	register struct proc *p;
	register struct pcred *pcred = curp->p_cred;
	struct rtprio rtp;
	int error;

	error = copyin(uap->rtp, &rtp, sizeof(struct rtprio));
	if (error)
		return (error);

	if (uap->pid == 0)
		p = curp;
	else
		p = pfind(uap->pid);

	if (p == 0)
		return (ESRCH);

	switch (uap->function) {
	case RTP_LOOKUP:
		return (copyout(&p->p_rtprio, uap->rtp, sizeof(struct rtprio)));
	case RTP_SET:
		if (pcred->pc_ucred->cr_uid && pcred->p_ruid &&
		    pcred->pc_ucred->cr_uid != p->p_ucred->cr_uid &&
		    pcred->p_ruid != p->p_ucred->cr_uid)
		        return (EPERM);
		/* disallow setting rtprio in most cases if not superuser */
		if (suser(pcred->pc_ucred, &curp->p_acflag)) {
			/* can't set someone else's */
			if (uap->pid)
				return (EPERM);
			/* can't set realtime priority */
/*
 * Realtime priority has to be restricted for reasons which should be
 * obvious. However, for idle priority, there is a potential for
 * system deadlock if an idleprio process gains a lock on a resource
 * that other processes need (and the idleprio process can't run
 * due to a CPU-bound normal process). Fix me! XXX
 */
#if 0
 			if (RTP_PRIO_IS_REALTIME(rtp.type))
#endif
			if (rtp.type != RTP_PRIO_NORMAL)
				return (EPERM);
		}
		switch (rtp.type) {
#ifdef RTP_PRIO_FIFO
		case RTP_PRIO_FIFO:
#endif
		case RTP_PRIO_REALTIME:
		case RTP_PRIO_NORMAL:
		case RTP_PRIO_IDLE:
			if (rtp.prio > RTP_PRIO_MAX)
				return (EINVAL);
			p->p_rtprio = rtp;
			return (0);
		default:
			return (EINVAL);
		}

	default:
		return (EINVAL);
	}
}

#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
#ifndef _SYS_SYSPROTO_H_
struct osetrlimit_args {
	u_int	which;
	struct	orlimit *rlp;
};
#endif
/* ARGSUSED */
int
osetrlimit(p, uap)
	struct proc *p;
	register struct osetrlimit_args *uap;
{
	struct orlimit olim;
	struct rlimit lim;
	int error;

	if ((error =
	    copyin((caddr_t)uap->rlp, (caddr_t)&olim, sizeof(struct orlimit))))
		return (error);
	lim.rlim_cur = olim.rlim_cur;
	lim.rlim_max = olim.rlim_max;
	return (dosetrlimit(p, uap->which, &lim));
}

#ifndef _SYS_SYSPROTO_H_
struct ogetrlimit_args {
	u_int	which;
	struct	orlimit *rlp;
};
#endif
/* ARGSUSED */
int
ogetrlimit(p, uap)
	struct proc *p;
	register struct ogetrlimit_args *uap;
{
	struct orlimit olim;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	olim.rlim_cur = p->p_rlimit[uap->which].rlim_cur;
	if (olim.rlim_cur == -1)
		olim.rlim_cur = 0x7fffffff;
	olim.rlim_max = p->p_rlimit[uap->which].rlim_max;
	if (olim.rlim_max == -1)
		olim.rlim_max = 0x7fffffff;
	return (copyout((caddr_t)&olim, (caddr_t)uap->rlp, sizeof(olim)));
}
#endif /* COMPAT_43 || COMPAT_SUNOS */

#ifndef _SYS_SYSPROTO_H_
struct __setrlimit_args {
	u_int	which;
	struct	rlimit *rlp;
};
#endif
/* ARGSUSED */
int
setrlimit(p, uap)
	struct proc *p;
	register struct __setrlimit_args *uap;
{
	struct rlimit alim;
	int error;

	if ((error =
	    copyin((caddr_t)uap->rlp, (caddr_t)&alim, sizeof (struct rlimit))))
		return (error);
	return (dosetrlimit(p, uap->which, &alim));
}

static int
dosetrlimit(p, which, limp)
	struct proc *p;
	u_int which;
	struct rlimit *limp;
{
	register struct rlimit *alimp;
	int error;

	if (which >= RLIM_NLIMITS)
		return (EINVAL);
	alimp = &p->p_rlimit[which];

	/*
	 * Preserve historical bugs by treating negative limits as unsigned.
	 */
	if (limp->rlim_cur < 0)
		limp->rlim_cur = RLIM_INFINITY;
	if (limp->rlim_max < 0)
		limp->rlim_max = RLIM_INFINITY;

	if (limp->rlim_cur > alimp->rlim_max ||
	    limp->rlim_max > alimp->rlim_max)
		if ((error = suser(p->p_ucred, &p->p_acflag)))
			return (error);
	if (limp->rlim_cur > limp->rlim_max)
		limp->rlim_cur = limp->rlim_max;
	if (p->p_limit->p_refcnt > 1 &&
	    (p->p_limit->p_lflags & PL_SHAREMOD) == 0) {
		p->p_limit->p_refcnt--;
		p->p_limit = limcopy(p->p_limit);
		alimp = &p->p_rlimit[which];
	}

	switch (which) {

	case RLIMIT_CPU:
		if (limp->rlim_cur > RLIM_INFINITY / (rlim_t)1000000)
			p->p_limit->p_cpulimit = RLIM_INFINITY;
		else
			p->p_limit->p_cpulimit = 
			    (rlim_t)1000000 * limp->rlim_cur;
		break;
	case RLIMIT_DATA:
		if (limp->rlim_cur > MAXDSIZ)
			limp->rlim_cur = MAXDSIZ;
		if (limp->rlim_max > MAXDSIZ)
			limp->rlim_max = MAXDSIZ;
		break;

	case RLIMIT_STACK:
		if (limp->rlim_cur > MAXSSIZ)
			limp->rlim_cur = MAXSSIZ;
		if (limp->rlim_max > MAXSSIZ)
			limp->rlim_max = MAXSSIZ;
		/*
		 * Stack is allocated to the max at exec time with only
		 * "rlim_cur" bytes accessible.  If stack limit is going
		 * up make more accessible, if going down make inaccessible.
		 */
		if (limp->rlim_cur != alimp->rlim_cur) {
			vm_offset_t addr;
			vm_size_t size;
			vm_prot_t prot;

			if (limp->rlim_cur > alimp->rlim_cur) {
				prot = VM_PROT_ALL;
				size = limp->rlim_cur - alimp->rlim_cur;
				addr = USRSTACK - limp->rlim_cur;
			} else {
				prot = VM_PROT_NONE;
				size = alimp->rlim_cur - limp->rlim_cur;
				addr = USRSTACK - alimp->rlim_cur;
			}
			addr = trunc_page(addr);
			size = round_page(size);
			(void) vm_map_protect(&p->p_vmspace->vm_map,
					      addr, addr+size, prot, FALSE);
		}
		break;

	case RLIMIT_NOFILE:
		if (limp->rlim_cur > maxfilesperproc)
			limp->rlim_cur = maxfilesperproc;
		if (limp->rlim_max > maxfilesperproc)
			limp->rlim_max = maxfilesperproc;
		break;

	case RLIMIT_NPROC:
		if (limp->rlim_cur > maxprocperuid)
			limp->rlim_cur = maxprocperuid;
		if (limp->rlim_max > maxprocperuid)
			limp->rlim_max = maxprocperuid;
		break;
	}
	*alimp = *limp;
	return (0);
}

#ifndef _SYS_SYSPROTO_H_
struct __getrlimit_args {
	u_int	which;
	struct	rlimit *rlp;
};
#endif
/* ARGSUSED */
int
getrlimit(p, uap)
	struct proc *p;
	register struct __getrlimit_args *uap;
{

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	return (copyout((caddr_t)&p->p_rlimit[uap->which], (caddr_t)uap->rlp,
	    sizeof (struct rlimit)));
}

/*
 * Transform the running time and tick information in proc p into user,
 * system, and interrupt time usage.
 */
void
calcru(p, up, sp, ip)
	struct proc *p;
	struct timeval *up;
	struct timeval *sp;
	struct timeval *ip;
{
	int64_t totusec;
	u_int64_t u, st, ut, it, tot;
	int s;
	struct timeval tv;

	/* XXX: why spl-protect ?  worst case is an off-by-one report */
	s = splstatclock();
	st = p->p_sticks;
	ut = p->p_uticks;
	it = p->p_iticks;
	splx(s);

	tot = st + ut + it;
	if (tot == 0) {
		st = 1;
		tot = 1;
	}

	totusec = p->p_runtime;
#ifdef SMP
	if (p->p_oncpu != (char)0xff) {
#else
	if (p == curproc) {
#endif
		/*
		 * Adjust for the current time slice.  This is actually fairly
		 * important since the error here is on the order of a time
		 * quantum, which is much greater than the sampling error.
		 */
		microuptime(&tv);
		totusec += (tv.tv_usec - p->p_switchtime.tv_usec) +
		    (tv.tv_sec - p->p_switchtime.tv_sec) * (int64_t)1000000;

		/*
		 * Copy the time that was just read to `switchtime' in case
		 * we are being called from exit1().  Exits don't go through
		 * mi_switch(), so `switchtime' doesn't get set in the normal
		 * way.  We set it here instead of more cleanly in exit1()
		 * to avoid losing track of the time between the calls to
		 * microuptime().  Similarly for `switchticks'.
		 */
		switchtime = tv;
		switchticks = ticks;
	}
	if (totusec < 0) {
		/* XXX no %qd in kernel.  Truncate. */
		printf("calcru: negative time of %ld usec for pid %d (%s)\n",
		       (long)totusec, p->p_pid, p->p_comm);
		totusec = 0;
	}
	u = totusec;
	st = (u * st) / tot;
	sp->tv_sec = st / 1000000;
	sp->tv_usec = st % 1000000;
	ut = (u * ut) / tot;
	up->tv_sec = ut / 1000000;
	up->tv_usec = ut % 1000000;
	if (ip != NULL) {
		it = (u * it) / tot;
		ip->tv_sec = it / 1000000;
		ip->tv_usec = it % 1000000;
	}
}

#ifndef _SYS_SYSPROTO_H_
struct getrusage_args {
	int	who;
	struct	rusage *rusage;
};
#endif
/* ARGSUSED */
int
getrusage(p, uap)
	register struct proc *p;
	register struct getrusage_args *uap;
{
	register struct rusage *rup;

	switch (uap->who) {

	case RUSAGE_SELF:
		rup = &p->p_stats->p_ru;
		calcru(p, &rup->ru_utime, &rup->ru_stime, NULL);
		break;

	case RUSAGE_CHILDREN:
		rup = &p->p_stats->p_cru;
		break;

	default:
		return (EINVAL);
	}
	return (copyout((caddr_t)rup, (caddr_t)uap->rusage,
	    sizeof (struct rusage)));
}

void
ruadd(ru, ru2)
	register struct rusage *ru, *ru2;
{
	register long *ip, *ip2;
	register int i;

	timevaladd(&ru->ru_utime, &ru2->ru_utime);
	timevaladd(&ru->ru_stime, &ru2->ru_stime);
	if (ru->ru_maxrss < ru2->ru_maxrss)
		ru->ru_maxrss = ru2->ru_maxrss;
	ip = &ru->ru_first; ip2 = &ru2->ru_first;
	for (i = &ru->ru_last - &ru->ru_first; i >= 0; i--)
		*ip++ += *ip2++;
}

/*
 * Make a copy of the plimit structure.
 * We share these structures copy-on-write after fork,
 * and copy when a limit is changed.
 */
struct plimit *
limcopy(lim)
	struct plimit *lim;
{
	register struct plimit *copy;

	MALLOC(copy, struct plimit *, sizeof(struct plimit),
	    M_SUBPROC, M_WAITOK);
	bcopy(lim->pl_rlimit, copy->pl_rlimit, sizeof(struct plimit));
	copy->p_lflags = 0;
	copy->p_refcnt = 1;
	return (copy);
}
