/* $Id: altq_cbq.h,v 1.1.1.1 1999/10/02 05:52:42 itojun Exp $ */
/*
 * Copyright (c) Sun Microsystems, Inc. 1993-1998 All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the SMCC Technology
 *      Development Group at Sun Microsystems, Inc.
 *
 * 4. The name of the Sun Microsystems, Inc nor may not be used to endorse or
 *      promote products derived from this software without specific prior
 *      written permission.
 *
 * SUN MICROSYSTEMS DOES NOT CLAIM MERCHANTABILITY OF THIS SOFTWARE OR THE
 * SUITABILITY OF THIS SOFTWARE FOR ANY PARTICULAR PURPOSE.  The software is
 * provided "as is" without express or implied warranty of any kind.
 *  
 * These notices must be retained in any copies of any part of this software.
 */

#ifndef _NETINET_ALTQ_CBQ_H_
#define	_NETINET_ALTQ_CBQ_H_

/* #pragma ident "@(#)cbq.h  1.18     98/05/13 SMI" */

#include <sys/ioccom.h>
#include <netinet/altq.h>
#include <netinet/altq_red.h>
#include <netinet/altq_rio.h>
#include <netinet/altq_classq.h>

#ifdef __cplusplus
extern "C" {
#endif 

/*
 * Define a well known class handles
 */
#define NULL_CLASS_HANDLE	0xffffffff
#define	ROOT_CLASS_HANDLE	0xfffffffe
#define	DEFAULT_CLASS_HANDLE	0xfffffffd
#define	CTL_CLASS_HANDLE	0xfffffffc

/*
 * Define structures associated with IOCTLS for cbq.
 */

/*
 * Define the CBQ interface structure.  This must be included in all
 * IOCTL's such that the CBQ driver may find the appropriate CBQ module
 * associated with the network interface to be affected.
 */
typedef struct cbq_interface {
	char	cbq_ifacename[IFNAMSIZ];
	u_int	cbq_ifacelen;
} cbq_iface_t;

/* 
 * Define IOCTLs for CBQ.
 */
#define CBQ_ENABLE		_IOW('Q', 1, struct cbq_interface)
#define CBQ_DISABLE		_IOW('Q', 2, struct cbq_interface)

#define	CBQ_ADD_FILTER		_IOWR('Q', 3, struct cbq_add_filter)

struct cbq_add_filter {
	cbq_iface_t		cbq_iface;
	u_long			cbq_class_handle;
	struct flow_filter	cbq_filter;

	u_long			cbq_filter_handle;
};

#define	CBQ_DEL_FILTER		_IOW('Q', 4, struct cbq_delete_filter)

struct cbq_delete_filter {
	cbq_iface_t	cbq_iface;
	u_long		cbq_filter_handle;
};

#define CBQ_ADD_CLASS		_IOWR('Q', 5, struct cbq_add_class)

typedef struct cbq_class_spec {
	u_int		priority;
	u_int		nano_sec_per_byte;
	u_int		maxq;
	u_int		maxidle;
	int		minidle;	
	u_int		offtime;
	u_long		parent_class_handle;
	u_long		borrow_class_handle;

	u_int		pktsize;
	int		flags;
} cbq_class_spec_t;

/* class flags shoud be same as class flags in rm_class.h */
#define CBQCLF_RED		0x0001	/* use RED */
#define CBQCLF_ECN		0x0002  /* use RED/ECN */
#define CBQCLF_RIO		0x0004  /* use RIO */
#define CBQCLF_FLOWVALVE	0x0008	/* use flowvalve (aka penalty-box) */
#define CBQCLF_CLEARDSCP	0x0010  /* clear diffserv codepoint */

/* class flags only for root class */
#define CBQCLF_WRR		0x0100	/* weighted-round robin */
#define CBQCLF_EFFICIENT	0x0200  /* work-conserving */

/* class flags for special classes */
#define CBQCLF_ROOTCLASS	0x1000	/* root class */
#define CBQCLF_DEFCLASS		0x2000	/* default class */
#define CBQCLF_CTLCLASS		0x4000	/* control class */
#define CBQCLF_CLASSMASK	0xf000	/* class mask */

#define CBQ_MAXQSIZE	200

struct cbq_add_class {
	cbq_iface_t		cbq_iface;

	cbq_class_spec_t	cbq_class;	
	u_long			cbq_class_handle;
};

#define CBQ_DEL_CLASS		_IOW('Q', 6, struct cbq_delete_class)

struct cbq_delete_class {
	cbq_iface_t	cbq_iface;
	u_long		cbq_class_handle;
};

#define CBQ_CLEAR_HIERARCHY	_IOW('Q', 7, struct cbq_interface)
#define	CBQ_ENABLE_STATS	_IOW('Q', 8, struct cbq_interface)
#define	CBQ_DISABLE_STATS	_IOW('Q', 9, struct cbq_interface)

typedef struct _cbq_class_stats_ {
	u_int		handle;
	u_int		depth;

	u_int		npackets;	/* packets sent in this class */
	u_int		over;		/* # times went over limit */
	u_int		borrows;	/* # times tried to borrow */
	u_int		drops;		/* # times dropped packets */
	u_int		overactions;	/* # times invoked overlimit action */
	u_int		delays;		/* # times invoked delay actions */
	u_quad_t	nbytes;		/* bytes sent in this class */
	u_quad_t	drop_bytes;	/* bytes dropped in this class */

	/* other static class parameters useful for debugging */
	int		priority;
	int		maxidle;
	int		minidle;
	int		offtime;
	int		qmax;
	int		ns_per_byte;
	int		wrr_allot;

	int		qcnt;		/* # packets in queue */
	int		avgidle;

	/* red and rio related info */
	int		qtype;
	struct redstats	red[3];
} class_stats_t;

struct cbq_getstats {
	cbq_iface_t	iface;
	int		nclasses;
	class_stats_t	*stats;
};

struct cbq_riometer {
	struct cbq_interface iface;
	u_long		class_handle;	/* class handle */
	int		rate;		/* service rate in bits-per-second */
	int		depth;		/* token-bucket depth in bytes */
	int		codepoint;	/* codepoint to write into ds-field */
	int		flags;		/* see below */
};

#define CBQRIOF_METERONLY	0x01	/* meter only, no rio dropper */
#define CBQRIOF_CLEARCODEPOINT	0x02	/* clear codepoint */

/* number of classes are returned in nclasses field */
#define	CBQ_GETSTATS		_IOWR('Q', 10, struct cbq_getstats)

struct cbq_modify_class {
	cbq_iface_t		cbq_iface;

	cbq_class_spec_t	cbq_class;	
	u_long			cbq_class_handle;
};

#define CBQ_MODIFY_CLASS	_IOWR('Q', 11, struct cbq_modify_class)

#define	CBQ_IF_ATTACH		_IOW('Q', 16, struct cbq_interface)
#define	CBQ_IF_DETACH		_IOW('Q', 17, struct cbq_interface)

#define	CBQ_ACC_ENABLE		_IOW('Q', 18, struct cbq_interface)
#define	CBQ_ACC_DISABLE		_IOW('Q', 19, struct cbq_interface)
#define	CBQ_ADD_RIOMETER	_IOWR('Q',20, struct cbq_riometer)

#if defined(KERNEL) || defined(_KERNEL)
/*
 * Define macros only good for kernel drivers and modules.
 */

#define	DISABLE		0x00
#define ENABLE		0x01
#define	ACC_DISABLE	0x02
#define ACC_ENABLE	0x03

#define CBQ_WATCHDOG    	(HZ / 20)
#define CBQ_TIMEOUT		10
#define	CBQ_LS_TIMEOUT		(20 * hz / 1000)

#define CBQ_MAX_CLASSES	256
#define CBQ_MAX_FILTERS 256

/*
 * Define State structures.
 */
typedef struct cbqstate {
	struct cbqstate		*cbq_next;
	int			cbq_qlen;	/* # of packets in cbq */
	struct rm_class		**cbq_class_tbl;

	struct rm_ifdat		ifnp;
	struct callout_handle	callout_handle;	/* handle for timeouts */

	struct acc_classifier	cbq_classifier;
} cbq_state_t;

#endif /* KERNEL */

#ifdef __cplusplus
}
#endif 

#endif /* !_NETINET_ALTQ_CBQ_H_ */
