/*	$Header: /usr/home/sumikawa/kame/kame/kame/kame/sctp/libsctp/sctp_sys_calls.c,v 1.1 2002/09/17 23:38:13 itojun Exp $ */

/*
 * Copyright (C) 2002 Cisco Systems Inc,
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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netinet/sctp_uio.h>
#include <netinet/sctp.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int
sctp_bindx(int fd, struct sockaddr_storage *addrs, int addrcnt,
	   int flags)
{
  struct sctp_getaddresses *gaddrs;
  int i,sz;

  if((flags != SCTP_BINDX_ADD_ADDR) &&
     (flags != SCTP_BINDX_REM_ADDR)){
    errno = EFAULT;
    return(-1);
  }
  sz = (sizeof(struct sockaddr_storage) + 
	sizeof(struct sctp_getaddresses));
  gaddrs = (struct sctp_getaddresses *)calloc(1,sz);
  if(gaddrs == NULL){
    errno = ENOMEM;
    return(-1);
  }
  gaddrs->sget_assoc_id = 0;
  for(i=0;i<addrcnt;i++){
    sz = ((struct sockaddr *)&addrs[i])->sa_len;
    memcpy(gaddrs->addr,&addrs[i],sz);
    if(setsockopt(fd,IPPROTO_SCTP,
		  flags, &gaddrs,
		  (unsigned int)sizeof(gaddrs)) != 0){
      free(gaddrs);
      return(-1);
    }
    memset(gaddrs->addr,0,sz);
  }
  free(gaddrs);
  return(0);
}

int
sctp_getpaddrs (int fd, sctp_assoc_t id,struct sockaddr_storage **raddrs)
{
  struct sctp_getaddresses *addrs;
  struct sockaddr *sa;
  struct sockaddr_storage *re;
  sctp_assoc_t asoc;
  caddr_t lim;
  unsigned int siz;
  int cnt;

  if(raddrs == NULL){
    errno = EFAULT;
    return(-1);
  }
  asoc = id;
  siz = sizeof(sctp_assoc_t);  
  if(getsockopt(fd,IPPROTO_SCTP,
		  SCTP_GET_REMOTE_ADDR_SIZE, &asoc, &siz) != 0) {
    return(-1);
  }
  siz = (unsigned int)asoc;
  siz += sizeof(struct sctp_getaddresses);
  addrs = calloc((unsigned long)1,(unsigned long)siz);
  if(addrs == NULL){
    errno = ENOMEM;
    return(-1);
  }
  memset(addrs,0,(size_t)siz);
  addrs->sget_assoc_id = id;
  /* Now lets get the array of addresses */
  if(getsockopt(fd,IPPROTO_SCTP,
		SCTP_GET_PEER_ADDRESSES, addrs, &siz) != 0) {
    free(addrs);
    return(-1);
  }
  re = (struct sockaddr_storage *)&addrs->addr[0];
  *raddrs = re;
  cnt = 0;
  sa = (struct sockaddr *)&addrs->addr[0];
  lim = (caddr_t)addrs + siz;
  while((caddr_t)sa < lim){
    cnt++;
    sa = (struct sockaddr *)((caddr_t)sa + sa->sa_len);
    if(sa->sa_len == 0)
      break;
  }
  return(cnt);
}

void sctp_freepaddrs (struct sockaddr_storage *addrs)
{
  /* Take away the hidden association id */
  void *fr_addr;
  fr_addr = (void *)((caddr_t)addrs - sizeof(sctp_assoc_t));
  /* Now free it */
  free(fr_addr);
}

int
sctp_getladdrs (int fd, sctp_assoc_t id,struct sockaddr_storage **raddrs)
{
  struct sctp_getaddresses *addrs;
  struct sockaddr_storage *re;
  caddr_t lim;
  struct sockaddr *sa;
  int size_of_addresses;
  unsigned int siz;
  int cnt;

  if(raddrs == NULL){
    errno = EFAULT;
    return(-1);
  }
  size_of_addresses = 0;
  siz = sizeof(int);  
  if(getsockopt(fd,IPPROTO_SCTP,
		  SCTP_GET_LOCAL_ADDR_SIZE, &size_of_addresses, &siz) != 0) {
    return(-1);
  }
  if(size_of_addresses == 0){
    errno = ENOTCONN;
    return(-1);
  }
  siz = size_of_addresses + sizeof(struct sockaddr_storage);
  siz += sizeof(struct sctp_getaddresses);
  addrs = calloc((unsigned long)1,(unsigned long)siz);
  if(addrs == NULL){
    errno = ENOMEM;
    return(-1);
  }
  memset(addrs,0,(size_t)siz);
  addrs->sget_assoc_id = id;
  /* Now lets get the array of addresses */
  if(getsockopt(fd,IPPROTO_SCTP,
		SCTP_GET_LOCAL_ADDRESSES, addrs, &siz) != 0) {
    free(addrs);
    return(-1);
  }
  re = (struct sockaddr_storage *)&addrs->addr[0];
  *raddrs = re;
  cnt = 0;
  sa = (struct sockaddr *)&addrs->addr[0];
  lim = (caddr_t)addrs + siz;
  while((caddr_t)sa < lim){
    cnt++;
    sa = (struct sockaddr *)((caddr_t)sa + sa->sa_len);
    if(sa->sa_len == 0)
      break;
  }
  return(cnt);
}

void sctp_freeladdrs(struct sockaddr_storage *addrs)
{
  /* Take away the hidden association id */
  void *fr_addr;
  fr_addr = (void *)((caddr_t)addrs - sizeof(sctp_assoc_t));
  /* Now free it */
  free(fr_addr);
}

#ifdef SYS_sctp_peeloff
int
sctp_peeloff(sd, assoc_id)
      int sd;
      sctp_assoc_t *assoc_id;
{
    return (syscall(SYS_sctp_peeloff, sd, assoc_id));
}
#endif
