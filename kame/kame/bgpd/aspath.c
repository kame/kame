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
#include "aspath.h"
#include "bgp.h"
#include "router.h"
#include "task.h"
#include "rt_table.h"
#include "bgp_var.h"
#include "in6.h"


/*
 *  Path Attribute Type
 */
char *pa_typestr[] = {
  "",
  "Origin",
  "ASPath",
  "NextHop",
  "Metric",                /* only into IBGP */
  "LocalPref",             /* only into IBGP */
  "AtomicAggregate",
  "Aggregator",
  "Communities",
  "OriginatorID",          /* only into IBGP */
  "ClusterList",           /* only into IBGP */
  "",
  "",
  "",
  "MPReachNLRI",
  "MPUnReachNLRI"};

char *origin_str[] = {
  "IGP",
  "EGP",
  "INCOMPLETE"};

/*
 *  prepend_aspath()
 * If the 3rd argument COPY is non-zero, a new aspath will be allocated
 * and the AS path in the 2nd argument PATH will copied into the new aspath.
 * If COPY is zero, PATH will be modified.
 */
struct aspath *
prepend_aspath(an, path, copy)
     u_int16_t        an;       /* host byte order */
     struct aspath *path;
     int copy;
{
  struct asnum  *asn;
  struct asseg  *asg;
  struct aspath *asp;

  if (path == NULL) {
    if (!copy)
	    return(NULL);
    MALLOC(asp, struct aspath);
    asp->asp_next = asp->asp_prev = asp;
    asp->asp_len               = 1;   /* It's made first */
    asp->asp_segment           = bgp_new_asseg(an);
    asp->asp_segment->asg_type = PA_PATH_SEQ;
    return asp;
  }
  else {
	  if (copy)
		  asp = aspathcpy(path);
	  else
		  asp = path;
  }

  if (asp->asp_segment == NULL) {
    asg = bgp_new_asseg(an);
    asg->asg_type    = PA_PATH_SEQ;
    asp->asp_segment = asg;
    asp->asp_len     = 1;
    return asp;
  }

  switch (path->asp_segment->asg_type) {
  case PA_PATH_SET:
    asg = bgp_new_asseg(an);
    asg->asg_type = PA_PATH_SEQ;
    insque(asg, asp->asp_segment->asg_prev);
    asp->asp_len++;     
    asp->asp_segment = asg;
    break;
  case PA_PATH_SEQ:
    asn = bgp_new_asnum(an);
    asg = asp->asp_segment;
    insque(asn, asg->asg_asn->asn_prev);
    asg->asg_len++;
    asg->asg_asn = asn;
    break;
  default:
    fatalx("<prepend_aspath>: internal error");
    break;
  }
  return asp;
}


/*
 *   aspath2msg()
 *     DESCRIPTION:   compose a part of message, from an aspath strcuture.
 *
 *     RETURN VALUES: composed length (i.e. "data length")
 */
int
aspath2msg(aspath, i)
     struct aspath *aspath;
     int            i;      /* tracer */
{
  struct asnum *asn;
  struct asseg *asg;
  u_int16_t     netasnum;
  int           j;                /* tracer (local) */
  int           palen, slen;
#ifdef DEBUG
  int           l, bufwlen;
  char          buf[LINE_MAX];   /* debugging   */ 
#endif

  extern byte   outpkt[];

#ifdef DEBUG
  l = 0;
  memset(buf, 0, LINE_MAX);
#endif

  j = i;
  if (aspath == NULL)
    return 0;

  if ((asg = aspath->asp_segment) == NULL)
    return 0;

  for (palen = 0 ; palen < aspath->asp_len ; palen++ ) {

    if (!asg)
      fatalx("<aspath2msg>: internal error");
#ifdef DEBUG
    if (asg->asg_type == PA_PATH_SET) {
      strcpy(&buf[l], "set(");
      l += 4;
    }
#endif

    outpkt[j++] = asg->asg_type; /* path segment type   (1-octet) */
    outpkt[j++] = asg->asg_len;  /* path segment length (1-octet) */
                                 /*                 number of ASs */
    asn = asg->asg_asn;
                                 /* path segment value, 2-octet-AS-number(s) */
    for (slen = 0; slen < asg->asg_len; slen++) {
      if (!asn)
	fatalx("<aspath2msg>: internal error");
      netasnum = htons(asn->asn_num);
      memcpy(&outpkt[j], &netasnum, PA_LEN_AS);
#ifdef DEBUG
      bufwlen = sprintf(&buf[l], "%u ", asn->asn_num);
      l += bufwlen;
#endif
      j += PA_LEN_AS;
      asn = asn->asn_next;
    }
#ifdef DEBUG
    if (asg->asg_type == PA_PATH_SET) {
      strcpy(&buf[l-1], ") ");
      l++;
    }
#endif
    asg = asg->asg_next;
  }

#ifdef DEBUG
  syslog(LOG_DEBUG, "BGP+ SEND\t\t%s", buf);
#endif

  if (j - i > 0xff)
    fatalx("<aspath2msg>: Too long ASpath");

  return (j - i);       /* composed length */
}



/*
 *    msg2aspath()
 *      DESCRIPTION:   compose an ASpath structure, from incoming msg.
 *
 *      RETURN VALUES: Pointer to aspath:  normally.
 *                     NULL:  If the msg is invalid, (errno = EINVAL) iw97,
 *                               or, a loop is detected. (errno = 0)
 *                               (treated as BGP_ERRUPD_ASPATH)
 */
struct aspath *
msg2aspath(bnp, i, len, errorp)
     struct rpcb *bnp;
     int   i;     /* tracer                 */
     int   len;   /* data length in octets  */
     int  *errorp;
{
  struct aspath *asp;
  struct asseg  *asg;
  struct asnum  *asn;
  int            j, k;            /* tracer (local)  */
  int            l, bufwlen;
  char           buf[LINE_MAX];   /* debugging   */ 

  extern u_int16_t my_as_number;

  *errorp = 0;
  l = 0;
  memset(buf, 0, LINE_MAX);

  MALLOC(asp, struct aspath);

  if (len == 0)
    return asp;    /* special case (for IBGP) */

  j = i;
  while(1) {
    MALLOC(asg, struct asseg);

    (asp->asp_len)++;

    asg->asg_type = bnp->rp_inpkt[j++];  /* path segment type   (1-octet) */

    switch (asg->asg_type) {     /* validation */
    case PA_PATH_SET: 
      strcpy(&buf[l], "set(");
      l += 4;
      break;
    case PA_PATH_SEQ:
      break;
    default:
	syslog(LOG_ERR, "<msg2aspath>: Invalid Path Segment Type (%d)",
	       asg->asg_type);
      free_aspath(asp);
      return NULL;
      break;
    }

    asg->asg_len  = bnp->rp_inpkt[j++];  /* path segment length (1-octet) */

    for (k = 0; k < asg->asg_len; k++) {
      asn = bgp_new_asnum(ntohs(*(u_int16_t *)&bnp->rp_inpkt[j]));
      bufwlen = sprintf(&buf[l], "%u ", asn->asn_num);
      l += bufwlen;

      if (my_as_number == asn->asn_num) {    /* loop detection */ 
	syslog(LOG_ERR, "<%s>: ASpath loop detected: %s from %s",
	       __FUNCTION__, buf, ip6str(&bnp->rp_gaddr));
	free_aspath(asp);
	return NULL;
      }
      ins_asnum(asn, asg);   /* if SET, sorted. if SEQ, not sorted */
      j += PA_LEN_AS;
    }

    if (asg->asg_type == PA_PATH_SET) {
      strcpy(&buf[l-1], ") ");
      l++;
    }

    if (asp->asp_segment) {
      insque(asg, asp->asp_segment->asg_prev);  /* append asg to the last */
    } else {
      asg->asg_next    = asg;
      asg->asg_prev    = asg;
      asp->asp_segment = asg;
    }
    if (j-i >  len) {
      free_aspath(asp);
      *errorp = EINVAL;
      return NULL;   /* the msg was invalid */
    }

    if (j-i == len) {
#ifdef DEBUG
      syslog(LOG_DEBUG, "BGP+ RECV\t\t%s", buf);
#endif
      return asp;
    }
  }
}



/*
 *   ins_asnum()
 *     DESCRIPTION: if SET, insert "asnum" into SORTed list of "asnum".
 *                  if SEQ, append.
 *
 *     RETURN VALUES: none.
 *                     
 */
void
ins_asnum(asn, asg)
     struct asnum *asn;
     struct asseg *asg;
{
  struct asnum *n;

  if (asg->asg_asn == NULL) {
    asn->asn_next = asn->asn_prev = asn;
    asg->asg_asn  = asn;
    return;
  }

  n = asg->asg_asn;   /* the head */

  switch (asg->asg_type) {
  case PA_PATH_SEQ:
    insque(asn, n->asn_prev); /* append */
    break;
  case PA_PATH_SET:

    while(n) {
      if ( asn->asn_num < n->asn_num ) {        /* host byte order    */
	insque(asn, n->asn_prev);
	if (n == asg->asg_asn )                 /* head ?             */
	  asg->asg_asn = asn;                   /* head is re-headed  */
	return;
      }
      if ((n = n->asn_next) == asg->asg_asn) {  /* last ? */
	insque(asn, n);
	return;
      }
    }
    break;
  }
  return;
}




/*
 *  free_aspath()
 */
void
free_aspath(asp)
     struct aspath *asp;
{
  if (asp == NULL)
    return;

  free_asseg(asp->asp_segment);
  free_clstrlist(asp->asp_clstr);
  free_optatr_list(asp->asp_optatr);

  free(asp);
}

/*
 *  free_asseg()
 */
void
free_asseg(asg)
  struct asseg *asg;
{
  struct asseg *a;

  if (asg == NULL)
    return;

  while(1) {
    if (asg == asg->asg_next)
      break;
  
    a = asg->asg_next;
    remque(a);
    free_asnum(a->asg_asn);    a->asg_asn = NULL;
    free(a);
  }

  free_asnum(asg->asg_asn);    asg->asg_asn = NULL;
  free(asg);
}


/*
 *  free_asnum()
 */
void
free_asnum(asn)
  struct asnum *asn;
{
  struct asnum *a;

  while(1) {
    if (asn == asn->asn_next)
      break;

    a = asn->asn_next;
    remque(a);
    free(a);
  }
  free(asn);
}

/*
 *  aspathcpy()
 */
struct aspath *
aspathcpy(asp)
     struct aspath *asp;
{
  struct aspath *cpy;

  if (asp == NULL)
    return NULL;

  MALLOC(cpy, struct aspath);

  memcpy(cpy, asp, sizeof(struct aspath));
  cpy->asp_clstr     = clstrlistcpy(asp->asp_clstr);
  cpy->asp_segment   = assegcpy(asp->asp_segment, asp->asp_len);
  cpy->asp_optatr    = copy_optatr_list(asp->asp_optatr);

  return cpy;
}



/*
 *  assegcpy()
 */
struct asseg *
assegcpy(asg, len)
     struct asseg *asg;
     int           len;
{
  struct asseg *cpy, *cpy2, *src;
  int           i;

  if (asg == NULL || len == 0)
    return NULL;

  src = asg;

  MALLOC(cpy, struct asseg);
  cpy->asg_next = cpy->asg_prev = cpy;
  cpy->asg_type = src->asg_type;
  cpy->asg_len  = src->asg_len;
  cpy->asg_asn  = asnumcpy(src->asg_asn, src->asg_len);
  src  = src->asg_next;

  for (i = 1; i < len ; i++) {

    MALLOC(cpy2, struct asseg);
    cpy2->asg_type = src->asg_type;
    cpy2->asg_len  = src->asg_len;
    cpy2->asg_asn  = asnumcpy(src->asg_asn, src->asg_len);

    insque(cpy2, cpy);
    cpy = cpy2;

    src  = src->asg_next;
  }

  return cpy->asg_next;
}



/*
 *  asnumcpy()
 */
struct asnum *
asnumcpy(asn, len)
     struct asnum *asn;
     int           len;
{
  struct asnum *cpy, *cpy2, *src;
  int           i;

  /* by jinmei */
  if ((src = asn))
    cpy = bgp_new_asnum(src->asn_num);

  for (i = 1; i < len ; i++) {

    src  = src->asn_next;
    cpy2 = bgp_new_asnum(src->asn_num);
    insque(cpy2, cpy);

    cpy = cpy2;
  }

  return cpy->asn_next;
}


/*
 *  bgp_new_asseg()
 *     DESCRIPTION: segment Type is not set.
 */
struct asseg *
bgp_new_asseg(an)
     u_int16_t an;
{
  struct asseg *asg;

  MALLOC(asg, struct asseg);
  asg->asg_next = asg->asg_prev = asg;
  asg->asg_len  = 1;
  asg->asg_asn  = bgp_new_asnum(an);

  return asg;
}


/*
 *  bgp_new_asnum()
 */
struct asnum *
bgp_new_asnum(an)
     u_int16_t an;
{
  struct asnum *asn;

  MALLOC(asn, struct asnum);
  asn->asn_next = asn->asn_prev = asn;
  asn->asn_num  = an;

  return asn;
}


/*
 *   equal_asseg()
 *     RETURN VALUE: 1 or 0
 *     NOTE: AS numbers are assumed to be already sorted by their AS number
 */
int
equal_asseg(asg1, asg2)
     struct asseg *asg1;
     struct asseg *asg2;
{
  struct asnum *asn1, *asn2;
  int i;

  if (asg1 == NULL && asg2 == NULL) /* both are empty AS PATH */
	  return 1;
  else if (!asg1 || !asg2)	/* one is empty but the other not */
	  return 0;

  if (asg1->asg_type != asg2->asg_type ||
      asg1->asg_len  != asg2->asg_len)
    return 0;

  switch (asg1->asg_type) {
  case PA_PATH_SET: case PA_PATH_SEQ:
    asn1 = asg1->asg_asn;
    asn2 = asg2->asg_asn;
    for(i = 0;  i < asg1->asg_type; i++) {
      if (asn1->asn_num != asn2->asn_num) 
	return 0;
      asn1 = asn1->asn_next;
      asn2 = asn2->asn_next;
    }
    return 1;
    break;
  default:
    fatalx("<equal_asseg>: unknown AS Segment Type");
    return 0;
    break;
  }
}



/*
 *   equal_aspath()
 *     RETURN VALUE: 1 :   equal
 *                   0 : not equal
 *                  
 */
int
equal_aspath(asp1, asp2)
     struct aspath *asp1;
     struct aspath *asp2;
{
  struct asseg *asg1, *asg2;
  int i;

  if (asp1 == NULL && asp2 == NULL)
    return 1;

  if (!asp1 || !asp2)
    return 0;

  if (asp1->asp_len != asp2->asp_len)
    return 0;

  asg1 = asp1->asp_segment;
  asg2 = asp2->asp_segment;

  for (i = 0; i < asp1->asp_len; i++) {
    if (!equal_asseg(asg1, asg2))
      return 0;
    asg1 = asg1->asg_next;
    asg2 = asg2->asg_next;
  }
  
  if (asp1->asp_origin  != asp2->asp_origin ||
      asp1->asp_atomagg != asp2->asp_atomagg )
    return 0;


  return 1;  /* equal */
}



/*
 *   aspath2cost()
 *     RETURN VALUES: >= 0
 */
u_char
aspath2cost(asp)
     struct aspath *asp;
{
  struct asseg *asg;
  u_char cost;
  int    i;

  if (asp == NULL) return 0;


  if ((asg = asp->asp_segment) == NULL)	/* empty AS path */
	  return 0;		/* appropriate cost?? */

  cost = 1;

  for(i = 0; i < asp->asp_len ;  i++) {

    switch (asg->asg_type) {
    case PA_PATH_SET:
      cost++;
      break;
    case PA_PATH_SEQ:
      cost += asg->asg_len;
      break;
    default:
      fatalx("<aspath2cost>: BUG !");
      break;
    }

    asg = asg->asg_next;
  }

  return cost;
}


/*
 *   aspath2tag()
 *     RETURN VALUES:
 */
u_int16_t
aspath2tag(asp)
     struct aspath *asp;
{
  if (asp == NULL)
    return 0;

  if (!(asp->asp_segment &&
	asp->asp_segment->asg_asn))
    return 0;


  return (asp->asp_segment->asg_asn->asn_num);
}


/*
 *  prepend_clstrlist()
 */
struct clstrlist *
prepend_clstrlist(id, cllist)
     u_int32_t         id;       /* host byte order */
     struct clstrlist *cllist;
{
  struct clstrlist *cllh, *cllt;

  if (cllist == NULL) {
    cllh = bgp_new_clstrlist(id);
    return cllh;
  }

  cllt = clstrlistcpy(cllist);
  cllh = bgp_new_clstrlist(id);
  insque(cllh, cllt->cll_prev);

  return cllh;
}



/*
 *   clstrlistcpy()
 */
struct clstrlist *
clstrlistcpy(cll)
     struct clstrlist *cll;
{
  struct clstrlist *cpy, *cpy2, *src;
  
  if (cll == NULL)
    return NULL;

  src = cll;
  cpy = bgp_new_clstrlist(src->cll_id);

  while (src->cll_next != cll) {
    src = src->cll_next;
    cpy2 = bgp_new_clstrlist(src->cll_id);
    insque(cpy2, cpy);

    cpy = cpy2;
  }

  return cpy->cll_next;
}

    
  


/*
 *    msg2clstrlist()
 *      DESCRIPTION:   compose an CLUSTER_LIST structure, from incoming msg.
 *
 *      RETURN VALUES: Pointer to clstrlist:  normally.
 *                     NULL:  If the msg is invalid, or,
 *                                        a loop is detected.
 * [rfc1966]
 *    Using this attribute an RR can identify if the routing information is
 *  looped back to the same cluster due to mis-configuration. If the local
 *  CLUSTER_ID is found in the cluster-list, the advertisement will be ignored.
 */
struct clstrlist *
msg2clstrlist(bnp, i, len)
     struct rpcb   *bnp;
     int            i;     /* tracer                 */
     int            len;   /* data length in octets  */
{
  struct clstrlist *cllhead, *cll;
  int    j, l;
  int    bufwlen;
  char   buf[LINE_MAX];  /* debugging */

  extern u_int32_t clusterId;
  extern byte      IamRR;


  if (len == 0)
    return NULL;

  l = 0;
  memset(buf, 0, LINE_MAX);

  cllhead = cll = NULL;

  j = i;
  while (1){
    MALLOC(cll, struct clstrlist);

    memcpy((char *)&cll->cll_id, &bnp->rp_inpkt[j], PA_LEN_CLUSTER);
    bufwlen = sprintf(&buf[l], "%u ", cll->cll_id);
    l += bufwlen;

    if (IamRR                   &&
	clusterId != 0          &&    /*    global      */
	clusterId == cll->cll_id) {   /* loop detection */ 
      syslog(LOG_ERR, "<msg2clstrlist>: Cluster-list loop detected: %s", buf);
      free_clstrlist(cll);
      return NULL;
    }

    if (cllhead) {
      insque(cll, cllhead->cll_prev);
    } else {
      cll->cll_next = cll;
      cll->cll_prev = cll;
      cllhead = cll;
    }

    if ((j += PA_LEN_CLUSTER) >= len)
      break;
  }
#ifdef DEBUG
  syslog(LOG_DEBUG, "BGP+ RECV\t\t%s", buf);
#endif
  return cllhead;
  
}





/*
 *   clstrlist2msg()
 *     DESCRIPTION:   compose a part of message, from an clstrlist strcuture.
 *
 *     RETURN VALUES: composed length (i.e. "data length")
 */
int
clstrlist2msg(cll, i)
     struct clstrlist *cll;
     int               i;      /* tracer */
{
  struct clstrlist *icll;
  int               j;         /* tracer (local) */

#ifdef DEBUG
  int           l, bufwlen;
  char          buf[LINE_MAX];   /* debugging   */ 
#endif

  extern byte   outpkt[];

#ifdef DEBUG
  l = 0;
  memset(buf, 0, LINE_MAX);
#endif

  j = i;
  if (cll == NULL)
    return 0;

  icll = cll;
  while(1) {
    memcpy(&outpkt[j], &icll->cll_id, PA_LEN_CLUSTER);
#ifdef DEBUG
    bufwlen = sprintf(&buf[l], "%u ", icll->cll_id);
    l += bufwlen;
#endif
    j += PA_LEN_CLUSTER;
    
    if ((icll = icll->cll_next) == cll)
      break;
  }

#ifdef DEBUG
  syslog(LOG_DEBUG, "BGP+ SEND\t\t%s", buf);
#endif

  if (j - i > 0xff)
    fatalx("<clstrlist2msg>: Too long CLUSTER_LIST");

  return (j - i);       /* composed length */
}

/*
 *  bgp_new_clstrlist()
 */
struct clstrlist *
bgp_new_clstrlist(id)
     u_int32_t id;
{
  struct clstrlist *cll;

  MALLOC(cll, struct clstrlist);
  cll->cll_next = cll;
  cll->cll_prev = cll;
  cll->cll_id   = id;  

  return cll;
}

/*
 *    free_clstrlist()
 */
void
free_clstrlist(cll)
     struct clstrlist *cll;
{
  struct clstrlist *fcll;

  if (cll == NULL)
    return;

  if (cll->cll_next == NULL) {
    free(cll);
    return;
  }

  while (1) {
    if ((fcll  = cll->cll_next) &&   /* changed */
	 fcll != cll            ) {
      remque(fcll);
      free(fcll);
    } else {
      break;
    }
  }

  free(cll);
  return;
}

struct optatr *
add_optatr(optatr, optdata, len)
	struct optatr *optatr;
	char *optdata;
	int len;
{
	struct optatr *newoptatr;

	/* allocate memory */
	MALLOC(newoptatr, struct optatr);
	if ((newoptatr->data = malloc(len)) == NULL)
		fatalx("malloc");

	/* set values */
	newoptatr->len = len;
	memcpy(newoptatr->data, optdata, len);

	/* link into the chain */
	newoptatr->next = optatr;
	
	return(newoptatr);
}

struct optatr *
copy_optatr_list(src)
	struct optatr *src;
{
	struct optatr *dst = NULL;

	for(; src; src = src->next)
		dst = add_optatr(dst, src->data, src->len);

	return(dst);
}

void
free_optatr_list(optatr)
	struct optatr *optatr;
{
	struct optatr *next = NULL;

	while(optatr) {
		next = optatr->next;
		free(optatr->data);
		free(optatr);
		optatr = next;
	}

	return;
}
