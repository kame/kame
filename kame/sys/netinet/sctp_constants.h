/*	$KAME: sctp_constants.h,v 1.8 2003/04/21 06:26:10 itojun Exp $	*/
/*	Header: /home/sctpBsd/netinet/sctp_constants.h,v 1.61 2002/04/04 16:53:46 randall Exp	*/

#ifndef __sctp_constants_h__
#define __sctp_constants_h__

/*
 * Copyright (c) 2001, 2002 Cisco Systems, Inc.
 * All rights reserved.
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
 *      This product includes software developed by Cisco Systems, Inc.
 * 4. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CISCO SYSTEMS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL CISCO SYSTEMS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*#define SCTP_AUDITING_ENABLED 1 used for debug/auditing */
#define SCTP_AUDIT_SIZE 256

#define SCTP_CWND_LOG_SIZE 127	/* can only get one mclusters worth */ 
/* Places that CWND log can happen from */
#define SCTP_CWND_LOG_FROM_FR	1
#define SCTP_CWND_LOG_FROM_RTX	2
#define SCTP_CWND_LOG_FROM_BRST	3
#define SCTP_CWND_LOG_FROM_SS	4
#define SCTP_CWND_LOG_FROM_CA	5
#define SCTP_CWND_LOG_FROM_SAT	6

/* if you want to support the TCP model, uncomment the following define */
#define SCTP_TCP_MODEL_SUPPORT	1

/* number of associations by default for zone allocation */
#define SCTP_MAX_NUM_OF_ASOC	1000
/* how many addresses per assoc remote and local */
#define SCTP_SCALE_FOR_ADDR	2

/* default AUTO_ASCONF mode enable(1)/disable(0) value (sysctl) */
#define SCTP_DEFAULT_AUTO_ASCONF	0

/*
 * If you wish to use MD5 instead of SLA uncomment the line below.
 * Why you would like to do this:
 * a) There may be IPR on SHA-1, or so the FIP-180-1 page says,
 * b) MD5 is 3 times faster (has coded here).
 *
 * The disadvantage is it is thought that MD5 has been cracked... see RFC2104.
 */
/*#define USE_MD5 1 */
/*
 * Note: I can't seem to get this to compile now for some reason- the
 * kernel can't link in the md5 crypto
 */

/* DEFINE HERE WHAT CRC YOU WANT TO USE */
#define SCTP_USECRC_RFC2960  1
/*#define SCTP_USECRC_FLETCHER 1*/
/*#define SCTP_USECRC_SSHCRC32 1*/
/*#define SCTP_USECRC_FASTCRC32 1*/
/*#define SCTP_USECRC_CRC32 1*/
/*#define SCTP_USECRC_TCP32 1*/
/*#define SCTP_USECRC_CRC16SMAL 1*/
/*#define SCTP_USECRC_CRC16 1 */
/*#define SCTP_USECRC_MODADLER 1*/

#ifndef SCTP_ADLER32_BASE
#define SCTP_ADLER32_BASE 65521
#endif

#define SCTP_CWND_POSTS_LIST 256
/*
 * the SCTP protocol signature
 * this includes the version number encoded in the last 4 bits
 * of the signature.
 */
#define PROTO_SIGNATURE_A	0x30000000
#define SCTP_VERSION_NUMBER	0x3

#define MAX_TSN	0xffffffff
#define MAX_SEQ	0xffff

/* option:
 * If you comment out the following you will receive the old
 * behavior of obeying cwnd for the fast retransmit algorithm.
 * With this defined a FR happens right away with-out waiting
 * for the flightsize to drop below the cwnd value (which is
 * reduced by the FR to 1/2 the inflight packets).
 */
#define SCTP_IGNORE_CWND_ON_FR 1

/*
 * Adds implementors guide behavior to only use newest highest
 * update in SACK gap ack's to figure out if you need to stroke
 * a chunk for FR.
 */
#define SCTP_NO_FR_UNLESS_SEGMENT_SMALLER 1

/* default max I can burst out after a fast retransmit */
#define SCTP_DEF_MAX_BURST 4

/* Packet transmit states in the sent field */
#define SCTP_DATAGRAM_UNSENT 		0
#define SCTP_DATAGRAM_SENT   		1
#define SCTP_DATAGRAM_RESEND1		2 /* not used (in code, but may hit this value) */
#define SCTP_DATAGRAM_RESEND2		3 /* not used (in code, but may hit this value) */
#define SCTP_DATAGRAM_RESEND3		4 /* not used (in code, but may hit this value) */
#define SCTP_DATAGRAM_RESEND		5
#define SCTP_DATAGRAM_ACKED		10010
#define SCTP_DATAGRAM_INBOUND		10011
#define SCTP_READY_TO_TRANSMIT		10012
#define SCTP_DATAGRAM_MARKED		20010
#define SCTP_FORWARD_TSN_SKIP		30010

/* SCTP chunk types */
#define SCTP_DATA		0x00
#define SCTP_INITIATION		0x01
#define SCTP_INITIATION_ACK	0x02
#define SCTP_SELECTIVE_ACK	0x03
#define SCTP_HEARTBEAT_REQUEST	0x04
#define SCTP_HEARTBEAT_ACK	0x05
#define SCTP_ABORT_ASSOCIATION	0x06
#define SCTP_SHUTDOWN		0x07
#define SCTP_SHUTDOWN_ACK	0x08
#define SCTP_OPERATION_ERROR	0x09
#define SCTP_COOKIE_ECHO	0x0a
#define SCTP_COOKIE_ACK		0x0b
#define SCTP_ECN_ECHO		0x0c
#define SCTP_ECN_CWR		0x0d
#define SCTP_SHUTDOWN_COMPLETE	0x0e

/* draft-ietf-tsvwg-addip-sctp */
#define SCTP_ASCONF		0xc1
#define	SCTP_ASCONF_ACK		0x80

/* draft-ietf-stewart-prsctp */
#define SCTP_FORWARD_CUM_TSN	0xc0

/* draft-ietf-stewart-pktdrpsctp */
#define SCTP_PACKET_DROPPED	0x81


/* ABORT and SHUTDOWN COMPLETE FLAG */
#define SCTP_HAD_NO_TCB		0x01

/* Packet dropped flags */
#define SCTP_FROM_MIDDLE_BOX	SCTP_HAD_NO_TCB
#define SCTP_SUMMARY_PRESENT	0x02
#define SCTP_BADCRC		0x04
#define SCTP_PACKET_TRUNCATED	0x08

#define SCTP_SAT_NETWORK_MIN	     400	/* min ms for RTT to set satellite time */
#define SCTP_SAT_NETWORK_BURST_INCR  2		/* how many times to multiply maxburst in sat */
/* Data Chuck Specific Flags */
#define SCTP_DATA_FRAG_MASK	0x03
#define SCTP_DATA_MIDDLE_FRAG	0x00
#define SCTP_DATA_LAST_FRAG	0x01
#define SCTP_DATA_FIRST_FRAG	0x02
#define SCTP_DATA_NOT_FRAG	0x03
#define SCTP_DATA_UNORDERED	0x04

#define SCTP_CRC_ENABLE_BIT	0x01	/* lower bit of reserved */

/* align to 32-bit sizes */
#define SCTP_SIZE32(x)	(((x+3) >> 2) << 2)

#define IS_SCTP_CONTROL(a) (a->chunk_type != SCTP_DATA)
#define IS_SCTP_DATA(a) (a->chunk_type == SCTP_DATA)

/* SCTP parameter types */
#define SCTP_HEARTBEAT_INFO	0x0001
#define SCTP_IPV4_ADDRESS	0x0005
#define SCTP_IPV6_ADDRESS	0x0006
#define SCTP_STATE_COOKIE	0x0007
#define SCTP_UNRECOG_PARAM	0x0008
#define SCTP_COOKIE_PRESERVE	0x0009
#define SCTP_HOSTNAME_ADDRESS	0x000b
#define SCTP_SUPPORTED_ADDRTYPE	0x000c
#define SCTP_ECN_CAPABLE	0x8000
/* draft-ietf-tsvwg-usctp */
#define SCTP_UNRELIABLE_STREAM	0xc000
/* draft-ietf-tsvwg-addip-sctp */
#define SCTP_ADD_IP_ADDRESS	0xc001
#define SCTP_DEL_IP_ADDRESS	0xc002
#define SCTP_ERROR_CAUSE_IND	0xc003
#define SCTP_SET_PRIM_ADDR	0xc004
#define SCTP_SUCCESS_REPORT	0xc005
#define SCTP_ULP_ADAPTION	0xc006

/* Notification error codes */
#define SCTP_NOTIFY_DATAGRAM_UNSENT	0x0001
#define SCTP_NOTIFY_DATAGRAM_SENT	0x0002
#define SCTP_FAILED_THRESHOLD		0x0004
#define SCTP_HEARTBEAT_SUCCESS		0x0008
#define SCTP_RESPONSE_TO_USER_REQ	0x000f
#define SCTP_INTERNAL_ERROR		0x0010
#define SCTP_SHUTDOWN_GUARD_EXPIRES	0x0020
#define SCTP_RECEIVED_SACK		0x0040
#define SCTP_PEER_FAULTY		0x0080

/* Error causes used in SCTP op-err's and aborts */
#define SCTP_CAUSE_INV_STRM		0x001
#define SCTP_CAUSE_MISS_PARAM		0x002
#define SCTP_CAUSE_STALE_COOKIE		0x003
#define SCTP_CAUSE_OUT_OF_RESC		0x004
#define SCTP_CAUSE_UNRESOLV_ADDR	0x005
#define SCTP_CAUSE_UNRECOG_CHUNK	0x006
#define SCTP_CAUSE_INVALID_PARAM	0x007
/* This one is also the same as SCTP_UNRECOG_PARAM above */
#define SCTP_CAUSE_UNRECOG_PARAM	0x008
#define SCTP_CAUSE_NOUSER_DATA		0x009
#define SCTP_CAUSE_COOKIE_IN_SHUTDOWN	0x00a
#define SCTP_CAUSE_RESTART_W_NEWADDR	0x00b
#define SCTP_CAUSE_USER_INITIATED_ABT	0x00c
#define SCTP_CAUSE_PROTOCOL_VIOLATION	0x00d

/* Error's from add ip */
#define SCTP_CAUSE_DELETEING_LAST_ADDR	0x100
#define SCTP_CAUSE_OPERATION_REFUSED	0x101
#define SCTP_CAUSE_DELETING_SRC_ADDR	0x102
#define SCTP_CAUSE_ILLEGAL_ASCONF	0x103

/* bits for TOS field */
#define SCTP_ECT0_BIT		0x02
#define SCTP_ECT1_BIT		0x02
#define SCTP_CE_BITS		0x03

/* below turns off above */
#define SCTP_FLEXIBLE_ADDRESS	0x20
#define SCTP_NO_HEARTBEAT	0x40

/* mask to get sticky */
#define SCTP_STICKY_OPTIONS_MASK        0x0c

/* MTU discovery flags */
#define SCTP_DONT_FRAGMENT	0x0100
#define SCTP_FRAGMENT_OK	0x0200
#define SCTP_PR_SCTP_ENABLED	0x0400
#define SCTP_PR_SCTP_BUFFER	0x0800

/* Chunk flags */
#define SCTP_WINDOW_PROBE	0x01
#define SCTP_FWDTSN_MARKED_DOWN	0x02

/*
 * SCTP states for internal state machine
 * XXX (should match "user" values)
 */
#define SCTP_STATE_EMPTY		0x0000
#define SCTP_STATE_INUSE		0x0001
#define SCTP_STATE_COOKIE_WAIT		0x0002
#define SCTP_STATE_COOKIE_ECHOED	0x0004
#define SCTP_STATE_OPEN			0x0008
#define SCTP_STATE_SHUTDOWN_SENT	0x0010
#define SCTP_STATE_SHUTDOWN_RECEIVED	0x0020
#define SCTP_STATE_SHUTDOWN_ACK_SENT	0x0040
#define SCTP_STATE_SHUTDOWN_PENDING	0x0080
#define SCTP_STATE_CLOSED_SOCKET	0x0100
#define SCTP_STATE_MASK			0x007f


/* SCTP reachability state for each address */
#define SCTP_ADDR_NOT_REACHABLE		0x001
#define SCTP_ADDR_REACHABLE		0x002
#define SCTP_ADDR_NOHB			0x004
#define SCTP_ADDR_BEING_DELETED		0x008
#define SCTP_ADDR_NOT_IN_ASSOC		0x010
#define SCTP_ADDR_WAS_PRIMARY		0x020
#define SCTP_ADDR_SWITCH_PRIMARY	0x040
#define SCTP_ADDR_OUT_OF_SCOPE		0x080
#define SCTP_ADDR_DOUBLE_SWITCH		0x100
#define SCTP_ADDR_UNCONFIRMED		0x200

#define SCTP_ACTIVE     SCTP_ADDR_REACHABLE
#define SCTP_INACTIVE   SCTP_ADDR_NOT_REACHABLE
#define SCTP_REACHABLE_MASK             0x203

/* bound address types (e.g. valid address types to allow) */
#define SCTP_BOUND_V6		0x01
#define SCTP_BOUND_V4		0x02

/* How long a cookie lives in seconds */
#define SCTP_DEFAULT_COOKIE_LIFE	60

/* resource limit of streams */
#define MAX_SCTP_STREAMS	2048

/* max number of unreliable streams sets */
#define MAX_UNRELSTREAM_SETS	10

/* guess at how big to make the TSN mapping array */
#define SCTP_MAPPING_ARRAY	512

/*
 * Here we define the timer types used by the implementation
 * as arguments in the set/get timer type calls.
 */
#define SCTP_TIMER_INIT 	0
#define SCTP_TIMER_RECV 	1
#define SCTP_TIMER_SEND 	2
#define SCTP_TIMER_HEARTBEAT	3
#define SCTP_TIMER_PMTU		4
#define SCTP_TIMER_MAXSHUTDOWN	5
#define SCTP_TIMER_SIGNATURE	6
/*
 * number of timer types in the base SCTP structure used in
 * the set/get and has the base default.
 */
#define SCTP_NUM_TMRS	7

/* timer types */
#define SCTP_TIMER_TYPE_NONE		0
#define SCTP_TIMER_TYPE_SEND		1
#define SCTP_TIMER_TYPE_INIT		2
#define SCTP_TIMER_TYPE_RECV		3
#define SCTP_TIMER_TYPE_SHUTDOWN	4
#define SCTP_TIMER_TYPE_HEARTBEAT	5
#define SCTP_TIMER_TYPE_COOKIE		6
#define SCTP_TIMER_TYPE_NEWCOOKIE	7
#define SCTP_TIMER_TYPE_PATHMTURAISE	8
#define SCTP_TIMER_TYPE_SHUTDOWNACK	9
#define SCTP_TIMER_TYPE_ASCONF		10
#define SCTP_TIMER_TYPE_SHUTDOWNGUARD	11
#define SCTP_TIMER_TYPE_AUTOCLOSE	12
#define SCTP_TIMER_TYPE_EVENTWAKE	13

/*
 * Number of ticks before the soxwakeup() event that
 * is delayed is sent AFTER the accept() call
 */
#define SCTP_EVENTWAKEUP_WAIT_TICKS	3000

/*
 * Of course we really don't collect stale cookies, being folks
 * of decerning taste. However we do count them, if we get too
 * many before the association comes up.. we give up. Below is
 * the constant that dictates when we give it up...this is a
 * implemenation dependent treatment. In ours we do not ask for
 * a extension of time, but just retry this many times...
 */
#define SCTP_MAX_STALE_COOKIES_I_COLLECT 10

/* max number of TSN's dup'd that I will hold */
#define SCTP_MAX_DUP_TSNS	20

/*
 * Here we define the types used when setting the retry amounts.
 */
/* constants for type of set */
#define SCTP_MAXATTEMPT_INIT	2
#define SCTP_MAXATTEMPT_SEND	3

/* Maximum TSN's we will summarize in a drop report */

#define SCTP_MAX_DROP_REPORT 16

/* How many drop re-attempts we make on  INIT/COOKIE-ECHO */
#define SCTP_RETRY_DROPPED_THRESH 4

/* And the max we will keep a history of in the tcb 
 * which MUST be lower than 256.
 */

#define SCTP_MAX_DROP_SAVE_REPORT 16

/*
 * Here we define the default timers and the default number
 * of attemts we make for each respective side (send/init).
 */

/* init timer def = 1 sec */
#define SCTP_INIT_SEC	(1*hz)

/* send timer def = 1 seconds */
#define SCTP_SEND_SEC	(1*hz)

/* recv timer def = 200ms (in nsec) */
#define SCTP_RECV_SEC	(2000/hz)

/* 30 seconds + RTO (in ms) */
#define SCTP_HB_DEFAULT	(30000)

/* Max time I will wait for Shutdown to complete */
#define SCTP_DEF_MAX_SHUTDOWN (180*hz)


/* This is how long a secret lives, NOT how long a cookie lives
 * how many ticks the current secret will live.
 */
#define SCTP_DEFAULT_SECRET_LIFE (3600 * hz)

#define SCTP_RTO_UPPER_BOUND	(60000)	/* 60 sec in ms */
#define SCTP_RTO_UPPER_BOUND_SEC 60	/* for the init timer */
#define SCTP_RTO_LOWER_BOUND	(1000)	/* 1 sec in ms */
#define SCTP_RTO_INITIAL	(3000)	/* 3 sec in ms */

#define SCTP_DEF_MAX_INIT	8
#define SCTP_DEF_MAX_SEND	10

#define SCTP_DEF_PMTU_RAISE	(600 * hz)  /* 10 min between raise attempts */
#define SCTP_DEF_PMTU_MIN	600

#define SCTP_MSEC_IN_A_SEC	1000
#define SCTP_USEC_IN_A_SEC	1000000
#define SCTP_NSEC_IN_A_SEC	1000000000

#define SCTP_MAX_OUTSTANDING_DG	10000

/* How many streams I request initally by default */
#define SCTP_OSTREAM_INITIAL 10

#define SCTP_SEG_TO_RWND_UPD 32 /* How many smallest_mtu's need to increase before
                                 * a window update sack is sent (should be a
                                 * power of 2).
                                 */
#define SCTP_SCALE_OF_RWND_TO_UPD       4       /* Incr * this > hiwat, send 
                                                 * window update. Should be a
                                                 * power of 2.
                                                 */
#define SCTP_RESV_CONTROL_FRM_RWND     (2400) /* Reserve 40 entries of control 60 * 40 */

/* This constant (SCTP_MAX_READBUFFER) define
 * how big the read/write buffer is
 * when we enter the fd event notification
 * the buffer is put on the stack, so the bigger
 * it is the more stack you chew up, however it
 * has got to be big enough to handle the bigest
 * message this O/S will send you. In solaris
 * with sockets (not TLI) we end up at a value
 * of 64k. In TLI we could do partial reads to
 * get it all in with less hassel.. but we
 * write to sockets for generality.
 */
#define SCTP_MAX_READBUFFER	65536
#define SCTP_ADDRMAX		20


/* SCTP DEBUG Switch parameters */
#define SCTP_DEBUG_TIMER1  0x00000001
#define SCTP_DEBUG_TIMER2  0x00000002
#define SCTP_DEBUG_TIMER3  0x00000004
#define SCTP_DEBUG_TIMER4  0x00000008
#define SCTP_DEBUG_OUTPUT1 0x00000010
#define SCTP_DEBUG_OUTPUT2 0x00000020
#define SCTP_DEBUG_OUTPUT3 0x00000040
#define SCTP_DEBUG_OUTPUT4 0x00000080
#define SCTP_DEBUG_UTIL1   0x00000100
#define SCTP_DEBUG_UTIL2   0x00000200
#define SCTP_DEBUG_INPUT1  0x00001000
#define SCTP_DEBUG_INPUT2  0x00002000
#define SCTP_DEBUG_INPUT3  0x00004000
#define SCTP_DEBUG_INPUT4  0x00008000
#define SCTP_DEBUG_ASCONF1 0x00010000
#define SCTP_DEBUG_ASCONF2 0x00020000
#define SCTP_DEBUG_OUTPUT5 0x00040000
#define SCTP_DEBUG_PCB1    0x00100000
#define SCTP_DEBUG_PCB2    0x00200000
#define SCTP_DEBUG_PCB3    0x00400000
#define SCTP_DEBUG_PCB4    0x00800000
#define SCTP_DEBUG_INDATA1 0x01000000
#define SCTP_DEBUG_INDATA2 0x02000000
#define SCTP_DEBUG_INDATA3 0x04000000
#define SCTP_DEBUG_INDATA4 0x08000000
#define SCTP_DEBUG_USRREQ1 0x10000000
#define SCTP_DEBUG_USRREQ2 0x20000000
#define SCTP_DEBUG_PEEL1   0x40000000
#define SCTP_DEBUG_ALL     0x7ff3f3ff
#define SCTP_DEBUG_NOISY   0x00040000

/* What sender needs to see to avoid SWS or we consider peers rwnd 0 */
#define SCTP_SWS_SENDER_DEF	1420

/*
 * SWS is scaled to the sb_hiwat of the socket.
 * A value of 2 is hiwat/4, 1 would be hiwat/2 etc.
 */
/* What receiver needs to see in sockbuf or we tell peer its 1 */
#define SCTP_SWS_RECEIVER_DEF	3000


/* amount peer is obligated to have in rwnd or I will abort */
#define SCTP_MIN_RWND	1500

#define SCTP_WINDOW_MIN	1500	/* smallest rwnd can be */
#define SCTP_WINDOW_MAX 1048576	/* biggest I can grow rwnd to
				 * My playing around suggests a
				 * value greater than 64k does not
				 * do much, I guess via the kernel
				 * limitations on the stream/socket.
				 */

#define SCTP_MAX_BUNDLE_UP	256	/* max number of chunks to bundle */

/*  I can handle a 1meg re-assembly */
#define SCTP_DEFAULT_MAXMSGREASM 1048576

#define SCTP_DEFAULT_MAXWINDOW	32768	/* default rwnd size */
#define SCTP_DEFAULT_MAXSEGMENT 1500	/* MTU size, this is the default
                                         * to which we set the smallestMTU
					 * size to. This governs what is the
					 * largest size we will use, of course
					 * PMTU will raise this up to
					 * the largest interface MTU or the
					 * ceiling below if there is no
					 * SIOCGIFMTU.
					 */
#define DEFAULT_CHUNK_BUFFER	2048
#define DEFAULT_PARAM_BUFFER	512

#define SCTP_DEFAULT_MINSEGMENT 512	/* MTU size ... if no mtu disc */
#define SCTP_HOW_MANY_SECRETS	2	/* how many secrets I keep */

#define SCTP_NUMBER_OF_SECRETS	8	/* or 8 * 4 = 32 octets */
#define SCTP_SECRET_SIZE	32	/* number of octets in a 256 bits */

#ifdef USE_MD5
#define SCTP_SIGNATURE_SIZE	16	/* size of a MD5 signature */
#else
#define SCTP_SIGNATURE_SIZE	20	/* size of a SLA-1 signature */
#endif /* USE_MD5 */

#define SCTP_SIGNATURE_ALOC_SIZE 20

/*
 * SCTP upper layer notifications
 */
#define SCTP_NOTIFY_ASSOC_UP		1
#define SCTP_NOTIFY_ASSOC_DOWN		2
#define SCTP_NOTIFY_INTERFACE_DOWN	3
#define SCTP_NOTIFY_INTERFACE_UP	4
#define SCTP_NOTIFY_DG_FAIL		5
#define SCTP_NOTIFY_STRDATA_ERR 	6
#define SCTP_NOTIFY_ASSOC_ABORTED	7
#define SCTP_NOTIFY_PEER_OPENED_STREAM	8
#define SCTP_NOTIFY_STREAM_OPENED_OK	9
#define SCTP_NOTIFY_ASSOC_RESTART	10
#define SCTP_NOTIFY_HB_RESP             11
#define SCTP_NOTIFY_ASCONF_SUCCESS	12
#define SCTP_NOTIFY_ASCONF_FAILED	13
#define SCTP_NOTIFY_PEER_SHUTDOWN	14
#define SCTP_NOTIFY_ASCONF_ADD_IP	15
#define SCTP_NOTIFY_ASCONF_DELETE_IP	16
#define SCTP_NOTIFY_ASCONF_SET_PRIMARY	17
#define SCTP_NOTIFY_PARTIAL_DELVIERY_INDICATION 18
#define SCTP_NOTIFY_ADAPTION_INDICATION         19
#define SCTP_NOTIFY_MAX			19

/* clock variance is 10ms */
#define SCTP_CLOCK_GRANULARITY	10

#define IP_HDR_SIZE 40		/* we use the size of a IP6 header here
				 * this detracts a small amount for ipv4
				 * but it simplifies the ipv6 addition
				 */

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132	/* the Official IANA number :-) */
#endif /* !IPPROTO_SCTP */

#define SCTP_MAX_DATA_BUNDLING		80
#define SCTP_MAX_CONTROL_BUNDLING	20

/* modular comparison */
/* True if a > b (mod = M) */
#define compare_with_wrap(a, b, M) ((a > b) && ((a - b) < ((M >> 1)+1))) || \
              ((b > a) && ((b - a) > ((M >> 1)+1)))


/* Mapping array manipulation routines */
#define SCTP_IS_TSN_PRESENT(arry, gap) ((arry[(gap>>3)] >> (gap&0x07)) & 0x01)
#define SCTP_SET_TSN_PRESENT(arry, gap) (arry[(gap>>3)] |= (0x01 << ((gap&0x07))))
#define SCTP_UNSET_TSN_PRESENT(arry, gap) (arry[(gap>>3)] &= ((~(0x01 << ((gap&0x07)))) & 0xff))

/* pegs */
#define SCTP_NUMBER_OF_PEGS 40
/* peg index's */
#define SCTP_PEG_SACKS_SEEN 0 /* XX */
#define SCTP_PEG_SACKS_SENT 1 /* XX */
#define SCTP_PEG_TSNS_SENT  2 /* XX */
#define SCTP_PEG_TSNS_RCVD  3 /* XX */
#define SCTP_DATAGRAMS_SENT 4 /* XX */
#define SCTP_DATAGRAMS_RCVD 5 /* XX */
#define SCTP_RETRANTSN_SENT 6 /* XX */
#define SCTP_DUPTSN_RECVD   7 /* XX */
#define SCTP_HB_RECV	    8 /* XX */
#define SCTP_HB_ACK_RECV    9 /* XX */
#define SCTP_HB_SENT	   10 /* XX */
#define SCTP_WINDOW_PROBES 11 /* XX */
#define SCTP_DATA_DG_RECV  12 /* XX */
#define SCTP_TMIT_TIMER    13 /* XX */
#define SCTP_RECV_TIMER    14 /* XX */
#define SCTP_HB_TIMER      15 /* XX */
#define SCTP_FAST_RETRAN   16 /* XX */
#define SCTP_TIMERS_EXP    17 /* XX */
#define SCTP_FR_INAWINDOW  18 /* XX */
#define SCTP_RWND_BLOCKED  19 /* XX */
#define SCTP_CWND_BLOCKED  20 /* XX */
#define SCTP_RWND_DROPS    21 /* XX */
#define SCTP_BAD_STRMNO    22 /* XX */
#define SCTP_BAD_SSN_WRAP  23 /* XX */
#define SCTP_DROP_NOMEMORY 24 /* XX */
#define SCTP_DROP_FRAG     25 /* XX */
#define SCTP_BAD_VTAGS     26 /* XX */
#define SCTP_BAD_CSUM      27 /* XX */
#define SCTP_INPKTS        28 /* XX */
#define SCTP_IN_MCAST      29 /* XX */
#define SCTP_HDR_DROPS     30 /* XX */
#define SCTP_NOPORTS	   31 /* XX */
#define SCTP_CWND_NOFILL   32 /* XX */
#define SCTP_CALLS_TO_CO   33 /* XX */
#define SCTP_CO_NODATASNT  34 /* XX */
#define SCTP_CWND_INCRS    35 /* XX */
#define SCTP_MAX_BURST_APL 36 /* XX */
#define SCTP_EXPRESS_ROUTE 37 /* XX */
#define SCTP_NO_COPY_IN    38 /* XX */
#define SCTP_CACHED_SRC    39 /* XX */
/*
 * This value defines the number of vtag block time wait entry's
 * per list element.  Each entry will take 2 4 byte ints (and of
 * course the overhead of the next pointer as well). Using 15 as
 * an example will yield * ((8 * 15) + 8) or 128 bytes of overhead
 * for each timewait block that gets initialized. Increasing it to
 * 31 would yeild 256 bytes per block.
 */
/* Undef the following turns on per EP behavior */
#define SCTP_VTAG_TIMEWAIT_PER_STACK 1
#ifdef SCTP_VTAG_TIMEWAIT_PER_STACK
#define SCTP_NUMBER_IN_VTAG_BLOCK 15
#else
/* The hash list is smaller if we are on a ep basis */
#define SCTP_NUMBER_IN_VTAG_BLOCK 3
#endif
/*
 * If we use the STACK option, we have an array of this size head
 * pointers. This array is mod'd the with the size to find which
 * bucket and then all entries must be searched to see if the tag
 * is in timed wait. If so we reject it.
 */
#define SCTP_STACK_VTAG_HASH_SIZE 31

/*
 * If we use the per-endpoint model than we do not have a hash
 * table of entries but instead have a single head pointer and
 * we must crawl through the entire list.
 */

/*
 * Number of seconds of time wait, tied to MSL value (2 minutes),
 * so 2 * MSL = 4 minutes or 480 seconds.
 */
#define SCTP_TIME_WAIT 480

/*
 * For U-SCTP
 */
#define SCTP_STRM_RELIABLE   0
#define SCTP_STRM_UNRELIABLE 1

#define IN4_ISPRIVATE_ADDRESS(a) \
   ((((u_char *)&(a)->s_addr)[0] == 10) || \
    ((((u_char *)&(a)->s_addr)[0] == 172) && \
     (((u_char *)&(a)->s_addr)[1] >= 16) && \
     (((u_char *)&(a)->s_addr)[1] <= 32)) || \
    ((((u_char *)&(a)->s_addr)[0] == 192) && \
     (((u_char *)&(a)->s_addr)[1] == 168)))

#define IN4_ISLOOPBACK_ADDRESS(a) \
    ((((u_char *)&(a)->s_addr)[0] == 127) && \
     (((u_char *)&(a)->s_addr)[1] == 0) && \
     (((u_char *)&(a)->s_addr)[2] == 0) && \
     (((u_char *)&(a)->s_addr)[3] == 1))


/* for FreeBSD, NetBSD, and OpenBSD */
#ifdef _KERNEL

#if defined(__FreeBSD__)
#define SCTP_GETTIME_TIMEVAL(x)	(microuptime(x))
#define SCTP_GETTIME_TIMESPEC(x) (nanouptime(x))
#else
#define SCTP_GETTIME_TIMEVAL(x)	(microtime(x))
#define SCTP_GETTIME_TIMESPEC(x) (nanotime(x))
#endif /* __FreeBSD__ */


#ifdef SCTP_TCP_MODEL_SUPPORT
#define sctp_sowwakeup(inp, so) \
do { \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) { \
		inp->sctp_flags |= SCTP_PCB_FLAGS_WAKEOUTPUT; \
	} else { \
		sowwakeup(so); \
	} \
} while(0)

#define sctp_sorwakeup(inp, so) \
do { \
	if (inp->sctp_flags & SCTP_PCB_FLAGS_DONT_WAKE) { \
		inp->sctp_flags |= SCTP_PCB_FLAGS_WAKEINPUT; \
	} else { \
		sorwakeup(so); \
	} \
} while(0)
#else

#define sctp_sowwakeup(inp, so) \
do { \
	sowwakeup(so); \
} while(0)

#define sctp_sorwakeup(inp, so) \
do { \
	sorwakeup(so); \
} while(0)
#endif /* SCTP_TCP_MODEL_SUPPORT */

#endif /* _KERNEL */
#endif
