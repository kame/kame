/*	$KAME: sctp_sys_calls.c,v 1.9 2004/08/17 06:08:53 itojun Exp $ */

/*
 * Copyright (C) 2002, 2003, 2004 Cisco Systems Inc,
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp.h>

int
sctp_connectx(int fd, struct sockaddr *addrs, int addrcnt)
{
	int i,len,ret,cnt,*aa;
	char *buf;
	struct sockaddr *at;
	len = sizeof(int);
	at = addrs;
	cnt = 0;
	/* validate all the addresses and get the size */
	for (i=0; i < addrcnt; i++) {
		if ((at->sa_family != AF_INET) &&
		   (at->sa_family != AF_INET6)) {
			errno = EINVAL;
			return (-1);
		}
		len += at->sa_len;
		at = (struct sockaddr *)((caddr_t)at + at->sa_len);
		cnt++;
	}
	/* do we have any? */
	if (cnt == 0) {
		errno = EINVAL;
		return(-1);
	}
	buf = malloc(len);
	if(buf == NULL) {
		return(ENOMEM);
	}
	aa = (int *)buf;
	*aa = cnt;
	aa++;
	memcpy((caddr_t)aa,addrs,(len-sizeof(int)));
	ret = setsockopt(fd, IPPROTO_SCTP, SCTP_CONNECT_X, (void *)buf,
			 (unsigned int)len);
	return (ret);
}


int
sctp_bindx(int fd, struct sockaddr *addrs, int addrcnt, int flags)
{
	struct sctp_getaddresses *gaddrs;
	struct sockaddr *sa;
	int i, sz, fam, argsz;

	if ((flags != SCTP_BINDX_ADD_ADDR) && 
	    (flags != SCTP_BINDX_REM_ADDR)) {
		errno = EFAULT;
		return(-1);
	}
	argsz = (sizeof(struct sockaddr_storage) +
	    sizeof(struct sctp_getaddresses));
	gaddrs = (struct sctp_getaddresses *)calloc(1, argsz);
	if (gaddrs == NULL) {
		errno = ENOMEM;
		return(-1);
	}
	gaddrs->sget_assoc_id = 0;
	sa = addrs;
	for (i = 0; i < addrcnt; i++) {
		sz = sa->sa_len;
		fam = sa->sa_family;
		((struct sockaddr_in *)&addrs[i])->sin_port = ((struct sockaddr_in *)sa)->sin_port;
		if ((fam != AF_INET) && (fam != AF_INET6)) {
			errno = EINVAL;
			return(-1);
		}
		memcpy(gaddrs->addr, sa, sz);
		if (setsockopt(fd, IPPROTO_SCTP, flags, 
			       gaddrs, (unsigned int)argsz) != 0) {
			free(gaddrs);
			return(-1);
		}
		memset(gaddrs->addr, 0, argsz);
		sa = (struct sockaddr *)((caddr_t)sa + sz);
	}
	free(gaddrs);
	return(0);
}


int
sctp_opt_info(int fd, sctp_assoc_t id, int opt, void *arg, size_t *size)
{
	if ((opt == SCTP_RTOINFO) || 
 	    (opt == SCTP_ASSOCINFO) || 
	    (opt == SCTP_PRIMARY_ADDR) || 
	    (opt == SCTP_SET_PEER_PRIMARY_ADDR) || 
	    (opt == SCTP_PEER_ADDR_PARAMS) || 
	    (opt == SCTP_STATUS) || 
	    (opt == SCTP_GET_PEER_ADDR_INFO)) { 
		*(sctp_assoc_t *)arg = id;
		return(getsockopt(fd, IPPROTO_SCTP, opt, arg, (int *)size));
	}else{
		errno = EOPNOTSUPP;
		return(-1);
	}
}

int
sctp_getpaddrs(int fd, sctp_assoc_t id, struct sockaddr **raddrs)
{
	struct sctp_getaddresses *addrs;
	struct sockaddr *sa;
	struct sockaddr *re;
	sctp_assoc_t asoc;
	caddr_t lim;
	unsigned int siz;
	int cnt;

	if (raddrs == NULL) {
		errno = EFAULT;
		return(-1);
	}
	asoc = id;
	siz = sizeof(sctp_assoc_t);  
	if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_REMOTE_ADDR_SIZE,
	    &asoc, &siz) != 0) {
		return(-1);
	}
	siz = (unsigned int)asoc;
	siz += sizeof(struct sctp_getaddresses);
	addrs = calloc((unsigned long)1, (unsigned long)siz);
	if (addrs == NULL) {
		errno = ENOMEM;
		return(-1);
	}
	memset(addrs, 0, (size_t)siz);
	addrs->sget_assoc_id = id;
	/* Now lets get the array of addresses */
	if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_PEER_ADDRESSES,
	    addrs, &siz) != 0) {
		free(addrs);
		return(-1);
	}
	re = (struct sockaddr *)&addrs->addr[0];
	*raddrs = re;
	cnt = 0;
	sa = (struct sockaddr *)&addrs->addr[0];
	lim = (caddr_t)addrs + siz;
	while ((caddr_t)sa < lim) {
		cnt++;
		sa = (struct sockaddr *)((caddr_t)sa + sa->sa_len);
		if (sa->sa_len == 0)
			break;
	}
	return(cnt);
}

void sctp_freepaddrs(struct sockaddr *addrs)
{
	/* Take away the hidden association id */
	void *fr_addr;
	fr_addr = (void *)((caddr_t)addrs - sizeof(sctp_assoc_t));
	/* Now free it */
	free(fr_addr);
}

int
sctp_getladdrs (int fd, sctp_assoc_t id, struct sockaddr **raddrs)
{
	struct sctp_getaddresses *addrs;
	struct sockaddr *re;
	caddr_t lim;
	struct sockaddr *sa;
	int size_of_addresses;
	unsigned int siz;
	int cnt;

	if (raddrs == NULL) {
		errno = EFAULT;
		return(-1);
	}
	size_of_addresses = 0;
	siz = sizeof(int);  
	if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_LOCAL_ADDR_SIZE,
	    &size_of_addresses, &siz) != 0) {
		return(-1);
	}
	if (size_of_addresses == 0) {
		errno = ENOTCONN;
		return(-1);
	}
	siz = size_of_addresses + sizeof(struct sockaddr_storage);
	siz += sizeof(struct sctp_getaddresses);
	addrs = calloc((unsigned long)1, (unsigned long)siz);
	if (addrs == NULL) {
		errno = ENOMEM;
		return(-1);
	}
	memset(addrs, 0, (size_t)siz);
	addrs->sget_assoc_id = id;
	/* Now lets get the array of addresses */
	if (getsockopt(fd, IPPROTO_SCTP, SCTP_GET_LOCAL_ADDRESSES, addrs,
	    &siz) != 0) {
		free(addrs);
		return(-1);
	}
	re = (struct sockaddr *)&addrs->addr[0];
	*raddrs = re;
	cnt = 0;
	sa = (struct sockaddr *)&addrs->addr[0];
	lim = (caddr_t)addrs + siz;
	while ((caddr_t)sa < lim) {
		cnt++;
		sa = (struct sockaddr *)((caddr_t)sa + sa->sa_len);
		if (sa->sa_len == 0)
			break;
	}
	return(cnt);
}

void sctp_freeladdrs(struct sockaddr *addrs)
{
	/* Take away the hidden association id */
	void *fr_addr;
	fr_addr = (void *)((caddr_t)addrs - sizeof(sctp_assoc_t));
	/* Now free it */
	free(fr_addr);
}


int
sctp_sendmsg(int s, 
	     const void *data, 
	     size_t len,
	     const struct sockaddr *to,
	     socklen_t tolen,
	     u_int32_t ppid,
	     u_int32_t flags,
	     u_int16_t stream_no,
	     u_int32_t timetolive,
	     u_int32_t context)
{
	int sz;
	struct msghdr msg;
	struct iovec iov[2];
	char controlVector[256];
	char whoset=0;
	struct sctp_sndrcvinfo *s_info;
	struct cmsghdr *cmsg;
	struct sockaddr *who=NULL;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;

	if (to->sa_len == 0) {
		/* For the lazy app, that did not
		 * set sa_len, we attempt to set for them.
		 */
 		if(to->sa_family == AF_INET){
			memcpy(&in,to,sizeof(in));
			in.sin_len = sizeof(in);
			who = (struct sockaddr *)&in;
			whoset = 1;
		}else if(to->sa_family == AF_INET6){
			memcpy(&in6,to,sizeof(in6));
			in6.sin6_len = sizeof(in6);
			who = (struct sockaddr *)&in6;
			whoset = 1;
		}
	}
	iov[0].iov_base = (char *)data;
	iov[0].iov_len = len;
	iov[1].iov_base = NULL;
	iov[1].iov_len = 0;

	if(whoset)
		msg.msg_name = (caddr_t)who;
	else
		msg.msg_name = (caddr_t)to;
	msg.msg_namelen = in.sin_len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (caddr_t)controlVector;
  
	cmsg = (struct cmsghdr *)controlVector;

	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN (sizeof(struct sctp_sndrcvinfo) );
	s_info = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);

	s_info->sinfo_stream = stream_no;
	s_info->sinfo_ssn = 0;
	s_info->sinfo_flags = flags;
	s_info->sinfo_ppid = ppid;
	s_info->sinfo_context = context;
	s_info->sinfo_assoc_id = 0;
	s_info->sinfo_timetolive = timetolive;
	errno = 0;
	msg.msg_controllen = cmsg->cmsg_len;
	sz = sendmsg(s, &msg, 0);
	return(sz);
}

ssize_t
sctp_send(int sd, const void *data, size_t len,
	  const struct sctp_sndrcvinfo *sinfo,
	  int flags)
{
	int sz;
	struct msghdr msg;
	struct iovec iov[2];
	struct sctp_sndrcvinfo *s_info;
	char controlVector[256];
	struct cmsghdr *cmsg;

	iov[0].iov_base = (char *)data;
	iov[0].iov_len = len;
	iov[1].iov_base = NULL;
	iov[1].iov_len = 0;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (caddr_t)controlVector;
  
	cmsg = (struct cmsghdr *)controlVector;

	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN (sizeof(struct sctp_sndrcvinfo) );
	s_info = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
	/* copy in the data */
	*s_info = *sinfo;
	errno = 0;
	msg.msg_controllen = cmsg->cmsg_len;
	sz = sendmsg(sd, &msg, flags);
	return(sz);
}


ssize_t
sctp_recvmsg (int s, 
	      void *dbuf, 
	      size_t len,
	      struct sockaddr *from,
	      socklen_t *fromlen,
	      struct sctp_sndrcvinfo *sinfo,
	      int *msg_flags)
{
	struct sctp_sndrcvinfo *s_info;
	ssize_t sz;
	struct msghdr msg;
	struct iovec iov[2];
	char controlVector[2048];
	struct cmsghdr *cmsg;
	iov[0].iov_base = dbuf;
	iov[0].iov_len = len;
	iov[1].iov_base = NULL;
	iov[1].iov_len = 0;
	msg.msg_name = (caddr_t)from;
	msg.msg_namelen = *fromlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (caddr_t)controlVector;
	msg.msg_controllen = sizeof(controlVector);
	errno = 0;
	sz = recvmsg(s,&msg,0);

	s_info = NULL;
	len = sz;
	*msg_flags = msg.msg_flags;
	*fromlen = msg.msg_namelen;
	if ((msg.msg_controllen) && sinfo) {
		/* parse through and see if we find
		 * the sctp_sndrcvinfo (if the user wants it).
		 */
		cmsg = (struct cmsghdr *)controlVector;
		while (cmsg) {
			if (cmsg->cmsg_level == IPPROTO_SCTP) {
				if (cmsg->cmsg_type == SCTP_SNDRCV) {
					/* Got it */
					s_info = (struct sctp_sndrcvinfo *)CMSG_DATA(cmsg);
					/* Copy it to the user */
					*sinfo = *s_info;
					break;
				}
			}
			cmsg = CMSG_NXTHDR(&msg,cmsg);
		}
	}
	return(sz);
}

#ifdef SYS_sctp_peeloff
int
sctp_peeloff(sd, assoc_id)
      int sd;
      sctp_assoc_t assoc_id;
{
	return (syscall(SYS_sctp_peeloff, sd, assoc_id));
}
#endif
