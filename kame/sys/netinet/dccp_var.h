/*	$KAME: dccp_var.h,v 1.7 2003/10/23 05:44:35 ono Exp $	*/

/*
 * Copyright (c) 2003 Joacim Häggmark, Magnus Erixzon, Nils-Erik Mattsson 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Id: dccp_var.h,v 1.25 2003/07/31 11:17:15 joahag-9 Exp
 */

#ifndef _NETINET_DCCP_VAR_H_
#define _NETINET_DCCP_VAR_H_

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3)
#ifndef in6pcb
#define in6pcb		inpcb
#endif
#endif

struct dccpcb {
	u_int8_t	state; /* initial, listening, connecting, established,
				  closing, closed etc */
	u_int8_t	who;	/* undef, server, client, listener */

	struct callout	connect_timer;	/* Connection timer */
	struct callout	retrans_timer;	/* Retransmit timer */
	struct callout	close_timer;	/* Closing timer */
	struct callout	timewait_timer;	/* Time wait timer */

	u_int32_t	retrans;

	u_int32_t	seq_snd;
	u_int32_t       ack_snd; /* ack num to send in Ack or DataAck packet */
	u_int32_t	gsn_rcv; /* Greatest received sequence number */

	/* values representing last incoming packet. are set in dccp_input */
	u_int32_t	seq_rcv;        /* Seq num of received packet */
	u_int32_t       ack_rcv;        /* Ack num received in Ack or DataAck packet */
	u_int8_t        type_rcv;       /* Type of packet received */
	u_int32_t       len_rcv;        /* Length of data received */
        u_int8_t        ndp_rcv;        /* ndp value of received packet */

	u_int8_t	cslen;		/* How much of outgoing packets
					   are covered by the checksum */
	u_int8_t	pref_cc;	/* Client prefered CC */
	u_int8_t	ndp;		/* Number of non data packets */
	u_int32_t	loss_window;	/* Loss window (defaults to 1000)  */
	u_int16_t	ack_ratio;	/* Ack Ratio Feature */
	int8_t		cc_in_use[2];	/* Current CC in use
					   (in each direction) */
	void 		*cc_state[2];
	struct inpcb	*d_inpcb;	/* Pointer back to Internet PCB  */
	u_int32_t	d_maxseg;	/* Maximum segment size */
        char	        options[DCCP_MAX_OPTIONS];
	u_int8_t	optlen;
        char	        features[DCCP_MAX_OPTIONS];
	u_int8_t	featlen;

	u_int32_t	avgpsize;	/* Average packet size */

	/* variables for the local (receiver-side) ack vector */
	u_char *ackvector;  /* For acks, 2 bits per packet */
	u_char *av_hp;  /* head ptr for ackvector */
	u_int16_t av_size;
	u_int32_t av_hs, av_ts; /* highest/lowest seq no in ackvector */
	
	u_int8_t remote_ackvector; /* Is recv side using AckVector? */
};

struct inp_dp {
	struct inpcb inp;
	struct dccpcb dp;
};

#if defined(_NETINET_IN_PCB_H_) && defined(_SYS_SOCKETVAR_H_)
struct xdccpcb {
	size_t		xd_len;
	struct	inpcb	xd_inp;
	struct	dccpcb	xd_dp;
#ifdef __FreeBSD__
	struct	xsocket	xd_socket;
#endif
};
#endif

#define	intodccpcb(ip)	((struct dccpcb *)(ip)->inp_ppcb)
#define	in6todccpcb(ip)	((struct dccpcb *)(ip)->inp_ppcb)

struct	dccpstat {
	u_long	dccps_connattempt;	/* Initiated connections */
	u_long	dccps_connects;		/* Established connections */
	u_long	dccps_ipackets;		/* Total input packets */
	u_long	dccps_ibytes;		/* Total input bytes */
	u_long	dccps_drops;		/* Dropped packets  */
	u_long	dccps_badsum;		/* Checksum error */
	u_long	dccps_badlen;		/* Bad length */
	u_long	dccps_badseq;		/* Sequence number not inside loss_window  */
	u_long	dccps_noport;		/* No socket on port */

        /* TFRC Sender */
        u_long  tfrcs_send_conn;        /* Number of conn used TFRC sender */
        u_long  tfrcs_send_noopt;       /* No options on feedback packet */
        u_long  tfrcs_send_nomem;       /* Send refused: No mem for history */
        u_long  tfrcs_send_fbacks;      /* Correct feedback packets received */
        u_long  tfrcs_send_erropt;      /* Err add option on data */
  
        /* TFRC Receiver */
        u_long  tfrcs_recv_conn;        /* Number of conn used TFRC receiver */
        u_long  tfrcs_recv_noopt;       /* Packet lost: No options on packet */
        u_long  tfrcs_recv_nomem;       /* Packet lost: No mem for history */
        u_long  tfrcs_recv_losts;       /* Detected lost packets */
        u_long  tfrcs_recv_fbacks;      /* Feedback packets sent */
        u_long  tfrcs_recv_erropt;      /* Err add option on feedback */      

	/* TCPlike Sender */
	u_long  tcplikes_send_conn;     /* Connections established */
	u_long  tcplikes_send_reploss;  /* Data packets reported lost */
	u_long  tcplikes_send_assloss;  /* Data packets assumed lost */
	u_long  tcplikes_send_ackrecv;  /* Acknowledgement (w/ Ack Vector) packets received */
	u_long  tcplikes_send_missack;  /* Ack packets assumed lost */
	u_long  tcplikes_send_badseq;   /* Bad sequence number on outgoing packet */
	u_long  tcplikes_send_memerr;   /* Memory allocation errors */
	
	/* TCPlike Receiver */
	u_long  tcplikes_recv_conn;     /* Connections established */
	u_long  tcplikes_recv_datarecv; /* Number of data packets received */
	u_long  tcplikes_recv_ackack;   /* Ack-on-acks received */
	u_long  tcplikes_recv_acksent;  /* Acknowledgement (w/ Ack Vector) packets sent */
	u_long  tcplikes_recv_memerr;   /* Memory allocation errors */
	
	/*	Some CCID statistic should also be here */

	u_long	dccps_opackets;		/* Total output packets */
	u_long	dccps_obytes;		/* Total output bytes */
};

/*
 *	DCCP States
 */

#define DCCPS_CLOSED	0
#define DCCPS_LISTEN	1
#define DCCPS_REQUEST	2
#define DCCPS_RESPOND	3
#define DCCPS_ESTAB	4
#define DCCPS_SERVER_CLOSE	5
#define DCCPS_CLIENT_CLOSE	6
#define DCCPS_TIME_WAIT 7

#ifdef DCCPSTATES
const char *dccpstates[] = {
	"CLOSED",	"LISTEN",	"REQEST",	"RESPOND",
	"ESTABLISHED",	"SERVER-CLOSE",	"CLIENT-CLOSE", "TIME_WAIT",
};
#endif

#define DCCP_UNDEF	0
#define DCCP_LISTENER	1
#define DCCP_SERVER	2
#define DCCP_CLIENT	3

#define DCCP_SEQ_LT(a, b)	((int)(((a) << 8) - ((b) << 8)) < 0)
#define DCCP_SEQ_GT(a, b)	((int)(((a) << 8) - ((b) << 8)) > 0)

/*
 * Names for DCCP sysctl objects
 */
#define	DCCPCTL_DEFCCID		1	/* Default CCID */
#define DCCPCTL_STATS		2	/* statistics (read-only) */
#define DCCPCTL_PCBLIST		3

#define DCCPCTL_NAMES { \
	{ 0, 0 }, \
	{ "defccid", CTLTYPE_INT }, \
	{ "stats", CTLTYPE_STRUCT }, \
}

#ifdef _KERNEL
#ifdef __FreeBSD__
SYSCTL_DECL(_net_inet_dccp);
#endif

extern struct	pr_usrreqs dccp_usrreqs;
extern struct	inpcbhead dccpb;
extern struct	inpcbinfo dccpbinfo;
extern u_long	dccp_sendspace;
extern u_long	dccp_recvspace;
extern struct	dccpstat dccpstat; /* dccp statistics */
extern int	dccp_log_in_vain; /* if we should log connections to
				     ports w/o listeners */

/* These four functions are called from inetsw (in_proto.c) */
void	dccp_init(void);
#ifdef __FreeBSD__
void	dccp_input(struct mbuf *, int);
void	dccp_ctlinput(int, struct sockaddr *, void *);
int	dccp_ctloutput(struct socket *, struct sockopt *);
#else
void	dccp_input(struct mbuf *, ...);
void*	dccp_ctlinput(int, struct sockaddr *, void *);
int	dccp_ctloutput(int , struct socket *, int, int, struct mbuf **);
int	dccp_sysctl(int *, u_int, void *, size_t *, void *, size_t);
#ifdef __NetBSD__
int	dccp_usrreq(struct socket *, int, struct mbuf *, struct mbuf *, struct mbuf *, struct proc *);
#else /* OpenBSD */
int	dccp_usrreq(struct socket *, int, struct mbuf *, struct mbuf *, struct mbuf *);
#endif
#endif

#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
struct inpcb *
#else
void
#endif
	dccp_notify(struct inpcb *, int);
struct dccpcb *
	dccp_newdccpcb(struct inpcb *);

int	dccp_shutdown(struct socket *);

int     dccp_output(struct dccpcb *, u_int8_t);

int     dccp_add_option(struct dccpcb *, u_int8_t, char *, u_int8_t);

/* No cc functions */
void* dccp_nocc_init(struct dccpcb *);
void  dccp_nocc_free(void *);
int   dccp_nocc_send_packet(void*, long);
void  dccp_nocc_send_packet_sent(void *, int, long);
void  dccp_nocc_packet_recv(void*, char *, int);

#endif

#endif
