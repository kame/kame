/*
 * Copyright (C) 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include "include.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "aspath.h"
#include "bgp_var.h"
#include "in6.h"

static int bgp_read __P((struct rpcb *, int));
static void bgp_read_header __P((struct rpcb *));
static void bgp_read_data __P((struct rpcb *));

/*
 *    bgp_input()
 *             called by  main_listen_accept()  only.
 */
void
bgp_input(struct rpcb *bnp)
{
  if (bnp->rp_socket == -1)             /* in main_listen_accept() loop. */
    fatalx("<bgp_input>: invalid socket");

  switch(bnp->rp_inputmode) {
   case BGP_READ_HEADER:
	   bgp_read_header(bnp);
	   break;
   case BGP_READ_DATA:
	   bgp_read_data(bnp);
	   break;
   default:
	   syslog(LOG_ERR, "<%s>: RPCB input mode is corrupted(%d), bnp:%p",
		  __FUNCTION__, bnp->rp_socket, bnp);
	   fatalx("BUG in BGP read");
  }

  return;
}

static void
bgp_read_header(bnp)
	struct rpcb *bnp;
{
	int length;
	struct bgphdr *bh;

	/*
	 * One method that can be used in this situation is to first try to read
	 * just the message header. For the KEEPALIVE message type, this is a
	 * complete message; for other message types, the header should first be
	 * verified, in particular the total length. If all checks are
	 * successful, the specified length, minus the size of the message
	 * header is the amount of data left to read. [draft-ietf-idr-bgp4-08.txt]
	 */
	if (bgp_read(bnp, BGP_HEADER_LEN) < BGP_HEADER_LEN)
		return;		/* read has not completed or error occured */

	/* OK, whole header is read. */
	bnp->rp_inputmode = BGP_READ_DATA; /* change state */
	bh = (struct bgphdr *)bnp->rp_inpkt;

	/* Length (2-octet) */
	length = ntohs(bh->bh_length);

	if (length < BGP_HEADER_LEN || length > BGPMAXPACKETSIZE) {
		syslog(LOG_ERR,
		       "<%s>: invalid BGP data length(%d) from %s",
		       __FUNCTION__, length, bgp_peerstr(bnp));
		bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH,
			   2, (byte *)&bh->bh_length);
	}

	/*
	 * We don't have any warranty to read the remaining data, so we return
	 * here and call select() again unless the whole data is just the header.
	 * In the latter case, call bgp_read_data directly.
	 */
	bnp->rp_inlen = length;
	if (bnp->rp_inlen == bnp->rp_incc)
		bgp_read_data(bnp);
	return;
}

static void
bgp_read_data(bnp)
	struct rpcb *bnp;
{
	struct bgphdr *bh;
	int length;
	extern char *bgp_msgstr[], *bgp_statestr[];

	/* read remaining data(if any) */
	if (bnp->rp_incc < bnp->rp_inlen &&
	    bgp_read(bnp, bnp->rp_inlen) < bnp->rp_inlen) 
		return;		/* read has not completed or error occured */

	/* read has completed */
	bnp->rp_inputmode = BGP_READ_HEADER;
	bnp->rp_incc = 0;
	length = bnp->rp_inlen;
	bnp->rp_inlen = 0;

	bh = (struct bgphdr *)bnp->rp_inpkt;
	IFLOG(LOG_BGPINPUT) {
	  syslog(LOG_DEBUG,
		 "BGP+ RECV %s+%d -> %s+%d",
		 ip6str(&bnp->rp_addr.sin6_addr, 0),
		 ntohs(bnp->rp_addr.sin6_port),
		 ip6str(&bnp->rp_myaddr.sin6_addr, 0),
		 ntohs(bnp->rp_myaddr.sin6_port));

	  if (BGP_TYPE_VALID(bh->bh_type))
	    syslog(LOG_DEBUG,
		   "BGP+ RECV message type %d (%s) length %d, state=%s",
		   bh->bh_type,
		   bgp_msgstr[bh->bh_type],
		   length,
		   bgp_statestr[bnp->rp_state]);
	}

	switch (bh->bh_type) {
	 case BGP_OPEN:
		 if (length < BGP_HEADER_LEN + 10) {
			 /* Bad Message Length */
			 syslog(LOG_ERR,
				"<%s>: invalid BGP_OPEN data length(%d) from %s",
				__FUNCTION__, length, bgp_peerstr(bnp));
			 bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH,
				    2, (byte *)&bh->bh_length);
			 return;
		 }
		 bgp_update_stat(bnp, BGPS_OPENRCVD);
		 bgp_process_open(bnp);
		 break;

	 case BGP_UPDATE:
		 if (length < BGP_HEADER_LEN + 4 ) {
			 /* Bad Message Length */
			 syslog(LOG_ERR,
				"<%s>: invalid BGP_UPDATE data length(%d) "
				"from %s",
				__FUNCTION__, length, bgp_peerstr(bnp));
			 bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH,
				    2, (byte *)&bh->bh_length);
			 return;
		 }
		 bgp_update_stat(bnp, BGPS_UPDATERCVD);
		 bgp_process_update(bnp);
		 break;

	 case BGP_NOTIFY:
		 bgp_update_stat(bnp, BGPS_NOTIFYRCVD);
		 bgp_process_notification(bnp);
		 break;

	 case BGP_KEEPALIVE:
		 if (length != BGP_HEADER_LEN) {
			 /* Bad Message Length */
			 syslog(LOG_ERR,
				"<%s>: invalid BGP_KEEPALIVE data length(%d) "
				"from %s",
				__FUNCTION__, length, bgp_peerstr(bnp));
			 bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH,
				    2, (byte *)&bh->bh_length);
			 return;
		 }
		 bgp_update_stat(bnp, BGPS_UPDATERCVD);
		 bgp_process_keepalive(bnp);
		 break;

	 default:
		 /*
		  * If the Type field of the message header is not recognized,
		  * then the Error Subcode is set to Bad Message Type.
		  * The Data field contains the erroneous Type field.
		  */
		 syslog(LOG_ERR,
			"<%s>: unrecognized BGP data type(%d) from %s",
			__FUNCTION__, bh->bh_type, bgp_peerstr(bnp));
		 bgp_notify(bnp, BGP_ERR_HEADER, BGP_ERRHDR_TYPE,
			    1, &bh->bh_type);
		 break;
	}
} /* End of bgp_input() */

/*
 * Read specified length data from a bgp socket. The function simply exits
 * after a single call of read() even if the whole data aren't
 * read. So caller must carefully use this function.
 */
static int
bgp_read(struct rpcb *bnp, int total)
{
	int cc;
	u_char rcvmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))]; /* XXX tmp */
	struct msghdr rcvmh;
	struct iovec iov[2];

	/* We can safely call read without block only once */
#ifdef OLDADVAPI
	cc = read(bnp->rp_socket, &bnp->rp_inpkt[bnp->rp_incc],
		  total - bnp->rp_incc);
#else
	memset(&rcvmh, 0, sizeof(rcvmh));
	rcvmh.msg_controllen = sizeof(rcvmsgbuf);
	rcvmh.msg_control = (caddr_t)rcvmsgbuf;
	iov[0].iov_base = (caddr_t)&bnp->rp_inpkt[bnp->rp_incc];
	iov[0].iov_len = total - bnp->rp_incc;
	rcvmh.msg_iov = iov;
	rcvmh.msg_iovlen = 1;
	cc = recvmsg(bnp->rp_socket, &rcvmh, 0);

	if (cc == 0 && rcvmh.msg_controllen > 0) {
		syslog(LOG_INFO, "<%s>: get control data only (ignored)",
		       __FUNCTION__);
		return(-1);
	}
#endif

	if (cc == 0) {
		/* This would occur when the peer close the connection */
		syslog(LOG_NOTICE, "<%s>: connection was reset by %s",
		       __FUNCTION__, bgp_peerstr(bnp));
		bgp_cease(bnp);
		return(-1);
	}
	if (cc < 0) {
		syslog(LOG_ERR,
		       "<%s>: read from peer %s (%s AS %d) failed: %s",
		       __FUNCTION__,
		       ip6str(&bnp->rp_addr.sin6_addr, 0),
		       ((bnp->rp_mode & BGPO_IGP) ?
			"Internal" : "External"),
		       (int)bnp->rp_as, strerror(errno));
		bgp_cease(bnp);
		return(-1);
	}

	/* read succeed. update the watermark */
	bnp->rp_incc += cc;
	return(bnp->rp_incc);
}
