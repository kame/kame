/*
 * Copyright (c) 2003 Magnus Erixzon
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
 *
 * Headerfile for TCP-like congestion control for DCCP
 *
 * Current Revision:
 *
 * $Source: /usr/home/sumikawa/kame/kame/kame/sys/netinet/dccp_tcplike.h,v $
 * $Revision: 1.2 $
 * $Author: ono $
 * $Date: 2003/10/17 12:08:25 $
 *
 * Revision history:
 *
 * $Log: dccp_tcplike.h,v $
 * Revision 1.2  2003/10/17 12:08:25  ono
 * make it compilable on freebsd4
 *
 * Revision 1.27  2003/06/01 13:16:30  magerx-9
 * Correct(?) handling of Ack Ratio
 *
 * Revision 1.26  2003/05/31 23:30:49  magerx-9
 * Not sure whats new.. Something is, I guess
 *
 * Revision 1.25  2003/05/29 09:38:09  magerx-9
 * Minor improvement on congestion control
 *
 * Revision 1.24  2003/05/28 08:27:59  magerx-9
 * cwndlist back to type charlist
 *
 * Revision 1.23  2003/05/26 13:35:28  magerx-9
 * checkin before i change cwndvector (again)
 *
 * Revision 1.22  2003/05/26 08:19:28  magerx-9
 * fixors
 *
 * Revision 1.21  2003/05/26 01:21:18  magerx-9
 * bah
 *
 * Revision 1.19  2003/05/15 19:46:44  magerx-9
 * Dont halt
 *
 * Revision 1.18  2003/05/13 15:15:02  magerx-9
 * Changed name on some dccp_cc_sw functions
 *
 * Revision 1.17  2003/05/13 11:49:22  joahag-9
 * Added copyright text
 *
 * Revision 1.16  2003/05/13 00:40:24  magerx-9
 * Barf barf barf
 *
 * Revision 1.15  2003/05/05 23:47:08  magerx-9
 * Bug fixing. Redesign of cwndvector
 *
 * Revision 1.14  2003/04/25 15:48:09  nilmat-8
 * DCCP: Fixed get_option, added buflen check
 *       Exchange connection establishment och cc recv packet in dccp_input
 * TFRC: Receiver sends feedback
 * REST: Update type on cc_send_ack_recv
 *
 * Revision 1.13  2003/04/23 15:58:47  magerx-9
 * Changed def of cc_recv_packet. options is now an argument
 *
 * Revision 1.12  2003/04/23 14:22:36  magerx-9
 * Changed definition of cc_recv_packet
 *
 * Revision 1.11  2003/04/22 00:48:51  magerx-9
 * Changed cwndvector
 *
 * Revision 1.10  2003/04/21 11:46:44  nilmat-8
 * Change type and meaning on cc_send_packet_sent.
 *
 * Revision 1.9  2003/04/21 01:39:44  magerx-9
 * Minor updates
 *
 * Revision 1.8  2003/04/20 16:30:40  magerx-9
 * Minor adjustments according to nilmat
 *
 * Revision 1.7  2003/04/20 15:33:18  magerx-9
 * Adjustments to conform to new code standards
 *
 * Revision 1.6  2003/04/04 22:35:41  magerx-9
 * Added cwndvector_t
 *
 * Revision 1.5  2003/04/02 23:26:09  magerx-9
 * Removed unused vars and defines
 *
 * Revision 1.4  2003/03/31 11:34:16  magerx-9
 * Minor fixes, for initial compilation
 *
 * Revision 1.3  2003/03/31 11:30:40  magerx-9
 * Minor fixes, for initial compilation
 *
 * Revision 1.2  2003/03/31 11:29:21  magerx-9
 * Minor fixes, for initial compilation
 *
 * Revision 1.1  2003/03/31 11:06:48  magerx-9
 * Initial revision
 *
 *
 **/

#ifndef _NETINET_DCCP_TCPLIKE_H_
#define _NETINET_DCCP_TCPLIKE_H_

/* 
 * TCPlike sender 
 */

/* Parameter to decide when a packet is considered lost */
#define TCPLIKE_NUMDUPACK 3
/* Upperbound timeout value */
#define TIMEOUT_UBOUND 30*hz
#define TCPLIKE_MIN_RTT (hz >> 3)
#define TCPLIKE_INITIAL_CWND 3
#define TCPLIKE_INITIAL_CWNDVECTOR 512

/* TCPlike sender congestion control block (ccb) */
struct tcplike_send_ccb
{
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	struct mtx mutex;
#endif
	struct dccpcb *pcb; /* Pointer to associated dccpcb */
	u_int32_t cwnd; /* congestion window */
	u_int32_t ssthresh;
	u_int32_t oldcwnd_ts; /* old cwnd tail seqnr */
	
	u_int16_t rtt; /* estimated round trip-time */
	u_int16_t rto; /* Timeout value */
	u_int16_t rtt_d;
	
	int16_t outstanding; /* Number of unacked packets sent */
	u_int16_t rcvr_ackratio; /* Receiver ack ratio */

	u_int16_t acked_in_win; /* No of acked packets in the window */
	u_int8_t acked_windows; /* No of acked windows with no lost Acks */

	u_int32_t ack_last; /* Last ok Ack packet */
	u_int32_t ack_miss; /* oldest missing Ack packet */
	
	struct callout_handle rto_timer;

	u_char *cwndvector;  /* 2 bits per packet */
	u_char *cv_hp;  /* head ptr for cwndvector */
	u_int16_t cv_size;
	u_int32_t cv_hs, cv_ts; /* lowest/highest seq no in cwndvector */

	u_int8_t sample_rtt;
	u_int32_t timestamp;

	u_int32_t rcvd_ack, lost_ack;
};

#ifdef _KERNEL

/* Functions declared in struct dccp_cc_sw */

/* Initialises the sender side
 * args: pcb  - pointer to dccpcb of associated connection
 * returns: pointer to a tcplike_send_ccb struct on success, otherwise 0
 */ 
void *tcplike_send_init(struct dccpcb *pcb); 

/* Free the sender side
 * args: ccb - ccb of sender
 */
void tcplike_send_free(void *ccb);

/* Ask TCPlike wheter one can send a packet or not 
 * args: ccb  -  ccb block for current connection
 * returns: 0 if ok, else <> 0.
 */ 
int tcplike_send_packet(void *ccb, long datasize);
void tcplike_send_packet_sent(void *ccb, int moreToSend, long datasize);

/* Notify that an ack package was received
 * args: ccb  -  ccb block for current connection
 */
void tcplike_send_packet_recv(void *ccb, char *, int);

#endif

/* 
 * TFRC Receiver 
 */

struct ack_list
{
	u_int32_t localseq, ackthru;
	struct ack_list *next;
};

/* TCPlike receiver congestion control block (ccb) */
struct tcplike_recv_ccb {
#if defined(__FreeBSD__) && __FreeBSD_version >= 500000
	struct mtx mutex;
#endif
	struct dccpcb *pcb;               /* Pointer to associated dccpcb */
	/* No ack ratio or vector here. it's a global feature */
	struct ack_list *av_list;
	u_int16_t unacked; /* no of unacked packets */
};

#ifdef _KERNEL

/* Functions declared in struct dccp_cc_sw */

/* Initialises the receiver side
 * args: pcb  -  pointer to dccpcb of associated connection
 * returns: pointer to a tcplike_recv_ccb struct on success, otherwise 0
 */ 
void *tcplike_recv_init(struct dccpcb *pcb); 

/* Free the receiver side
 * args: ccb - ccb of recevier
 */
void tcplike_recv_free(void *ccb);

/*
 * Tell TCPlike that a packet has been received
 * args: ccb  -  ccb block for current connection 
 */
void tcplike_recv_packet_recv(void *ccb, char *, int);

/*
int tcplike_option_recv();
*/
#endif

#endif
