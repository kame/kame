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
#include "rt_table.h"
#include "aspath.h"
#include "bgp_var.h"
#include "parse.h"
#include "ripng.h"
#include "ripng_var.h"
#include "in6.h"

/*  parsed bitmap   */
#define C_MYASNUM        1
#define C_ROUTERID       2   /*  BGP id  */
#define C_HOLDTIME       3

#define C_PROTO          4

#define C_BGP            5
#define C_RIP            6
#define C_DIRECT         7
#define C_INTERFACE      8

#define C_YES            9
#define C_NO             10

#define C_GROUP          11
#define C_TYPE           12
#define C_EXTERNAL       13
#define C_INTERNAL       14
#define C_PEERAS         15
#define C_PEER           16
#define C_AS             17
#define C_PREFERENCE     18

#define C_EXPORT         19

#define C_NORIPIN        20
#define C_NORIPOUT       21
#define C_DEFAULT        22
#define C_RESTRICTIN     23

#define C_ALL            24

#define C_IBGP           25
#define C_RR             26
#define C_CLIENT         27
#define C_CLUSTERID      28

#define C_AGGREGATE      29
#define C_EXPLICIT       30

#define C_SYNC           31
#define C_ORIGINATE      32

#define C_PREPEND	 33

#define C_METRICIN	 34

#define C_RESTRICTOUT	35
#define C_FILTERIN	36
#define C_FILTEROUT	37

#define C_DUMPFILE	38

#define C_NEXTHOPSELF	39
#define C_LOCALADDR	40

#define C_SITELOCAL	41

#define C_BGP_SBSIZE	42

#define PARSE_MAX_BITS   C_BGP_SBSIZE


/*  possiblly compatiblized with gated.conf */
char *sysatom[] = {
  "",
  "autonomoussystem",
  "routerid",
  "holdtime",

  "proto",

  "bgp",
  "rip",
  "direct",
  "interface",

  "yes",
  "no",
  "group",
  "type",
  "external",
  "internal",
  "peeras",
  "peer",
  "as",
  "preference",
  "export",
  "noripin",
  "noripout",
  "default",
  "restrictin",
  "all",
  "ibgp",
  "iamroutereflector",
  "client",
  "clusterid",
  "aggregate",
  "explicit",
  "synchronization",
  "originate",
  "prepend",
  "metricin",
  "restrictout",
  "filterin",
  "filterout",

  "dumpfile",

  "nexthopself",
  "lcladdr",

  "sitelocal",

  "bgpsbsize"
};

static int          i, j, line;
static FILE        *fp;
static struct rpcb *bnp;
static char         buf[LINE_MAX];
static char         atom[LINE_MAX];
static bitstr_t     bit_decl(parsedflag, PARSE_MAX_BITS);
static int	    set_filter(struct filtinfo **headp, char *filtstr,
			       char *filename, int line);

/*
 *  conf_check()
 *   ARGUMENT
 *      filename: config file's name
 *   DESCRIPTION
 *      only called at initialization.
 */
void
conf_check(char *filename)
{
  struct rpcb                *ibgpbnp;

  /* global variables */
  extern byte             bgpyes, ripyes;
  extern int              bgpsock;
  extern struct rpcb     *bgb;
  extern u_int16_t        my_as_number;
  extern u_int32_t        bgpIdentifier;
  extern u_int32_t        clusterId;
  extern u_int16_t        bgpHoldtime;
  extern byte             IamRR;
  extern fd_set           fdmask;
  extern int              ripsock;
  extern struct rt_entry *aggregations;

  bit_nclear(parsedflag, 0, PARSE_MAX_BITS-1);

  line = 0;

  if ((fp = fopen(filename, "r")) == NULL) {
    fatal("<conf_check>: fopen");
  }

  while (memset(buf,0,LINE_MAX), ++line,
	 fgets(buf, LINE_MAX, fp) != NULL
	 ) {

    if (buf[0] == '#' || buf[0] == '\n') continue;

    i = 0;
    SKIP_WHITE(i);

    /*
     *	"dumpfile FILENAME"
     */
    if (strncasecmp(&buf[i], sysatom[C_DUMPFILE], strlen(sysatom[C_DUMPFILE]))
	== 0) {
	    extern char *dumpfile; /* defined in dump.c */

	    i += strlen(sysatom[C_DUMPFILE]);
	    SKIP_WHITE(i); READ_ATOM(i, j);
	    if ((dumpfile = malloc(strlen(atom) + 1)) == NULL) /* XXX */
		    fatalx("malloc");
	    strcpy(dumpfile, atom);
	    SENTENCE_END(i);

	    continue;
    }

    /*
     * socket buffer size
     */
    if (strncasecmp(&buf[i], sysatom[C_BGP_SBSIZE], strlen(sysatom[C_BGP_SBSIZE]))
	== 0) {
      if (bit_test(parsedflag, C_BGP_SBSIZE)) {
	syslog(LOG_ERR, "%s:%d %s doubly defined",
	       filename, line, sysatom[C_BGP_SBSIZE]);
	fatalx("<conf_check>: doubly defined");
      }
      bit_set(parsedflag, C_BGP_SBSIZE);
      i += strlen(sysatom[C_BGP_SBSIZE]);
      SKIP_WHITE(i); READ_ATOM(i, j);

      bgpsbsize = atoi(atom);  /* XXX: need validation? */

      SENTENCE_END(i);
      continue;
    }

    /*
     *   "bgp yes {...}"
     */
    if (strncasecmp(&buf[i], sysatom[C_BGP], strlen(sysatom[C_BGP]))
	== 0) {
      parse_bgp_yes(filename);
      continue;
    }
    /*
     *   "aggregate prfx/plen {...}"
     */
    if (strncasecmp(&buf[i], sysatom[C_AGGREGATE],strlen(sysatom[C_AGGREGATE]))
	== 0) {
      struct rt_entry *aggregated;
      char in6txt[INET6_ADDRSTRLEN];

      memset(in6txt, 0, INET6_ADDRSTRLEN);
      MALLOC(aggregated, struct rt_entry);
      aggregated->rt_proto.rtp_type = RTPROTO_AGGR;

      i += strlen(sysatom[C_AGGREGATE]);
      SKIP_WHITE(i); READ_ATOM(i, j);

      if (inet_ptox(AF_INET6, atom,
		    &aggregated->rt_ripinfo.rip6_dest,
		    &aggregated->rt_ripinfo.rip6_plen) < 1) {
	syslog(LOG_ERR, "%s:%d inet_ptox() failed", filename, line);
	terminate();
      }

      mask_nclear(&aggregated->rt_ripinfo.rip6_dest, 
		  aggregated->rt_ripinfo.rip6_plen);

      SKIP_WHITE(i);
      if (buf[i++] != '{') {
	syslog(LOG_ERR,
	       "%s:%d syntax error, missing \'{\'", filename, line);
	fatalx("<conf_check>: syntax error");
      }

      while(1) {
	SKIP_WHITE(i);
	if (strncasecmp(&buf[i], sysatom[C_EXPLICIT],strlen(sysatom[C_EXPLICIT]))
	    == 0) {
	  SKIP_WHITE(i);
	  if (buf[i++] != '{') {
	    syslog(LOG_ERR,
		   "%s:%d syntax error, missing \'{\'", filename, line);
	    fatalx("<conf_check>: syntax error");
	  }
	  while(11) {
	    struct rt_entry *explt;

	    SKIP_WHITE(i); READ_ATOM(i, j);

	    if (*atom == '}') break;

	    MALLOC(explt, struct rt_entry);
	    if (inet_ptox(AF_INET6, atom,
			  &explt->rt_ripinfo.rip6_dest,
			  &explt->rt_ripinfo.rip6_plen) < 1) {
	      syslog(LOG_ERR, "%s:%d inet_ptox() failed", filename, line);
	      terminate();
	    }

	    /* aggregatablity check */	  
	    if (aggregated != aggregatable(explt)) {
	      syslog(LOG_ERR, "%s:%d NOT aggregatable", filename, line);
	      fatalx("<conf_check>: NOT aggregatable");
	    }


	    if (aggregated->rt_aggr.ag_explt != NULL) {
	      if (find_rte(explt, aggregated->rt_aggr.ag_explt)) {
		syslog(LOG_ERR,
		       "%s:%d explicit route doubly defined", filename,line);
		fatalx("<conf_check>: explicit route doubly defined");
	      }
	      insque(explt, aggregated->rt_aggr.ag_explt);
	    } else {
	      explt->rt_next = explt;
	      explt->rt_prev = explt;
	      aggregated->rt_aggr.ag_explt = explt;
	    }
	    SENTENCE_END(i);
	  } /* while(11) */
	  SENTENCE_END(i);	

	  continue;
	  /* End-of-"explicit" */
	}

	/*
	 *   "proto" ..?
	 */
	if (strncasecmp(&buf[i], sysatom[C_PROTO], strlen(sysatom[C_PROTO]))
	    == 0) {
	  struct rtproto  *rtp;
	  MALLOC(rtp, struct rtproto);
	  
	  i += strlen(sysatom[C_PROTO]);
	  SKIP_WHITE(i);

	  /*
	   *   "direct"
	   */
	  if (strncasecmp(&buf[i], sysatom[C_DIRECT], strlen(sysatom[C_DIRECT]))
	      == 0) {
	    struct ifinfo *ifp;

	    i += strlen(sysatom[C_DIRECT]);
	    SKIP_WHITE(i);

	    /*     "interface .."    */ 
	    if (strncasecmp(&buf[i], sysatom[C_INTERFACE], strlen(sysatom[C_INTERFACE]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_INTERFACE]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_INTERFACE]);
	    SKIP_WHITE(i); READ_ATOM(i, j);
	    if ((ifp = find_if_by_name(atom)) == NULL) {/* find  "ifinfo" */
	      syslog(LOG_ERR, "%s:%d interface \'%s\' not found",
		     filename, line, atom);
	      fatalx("<conf_check>: interface not found");
	    }
	    
	    SKIP_WHITE(i);
	    if (buf[i++] != '{') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'{\'", filename, line);
	      fatalx("<conf_check>: syntax error");	  
	    }
	    SKIP_WHITE(i);
	    /*
	     *   "ALL"
	     */
	    if (strncasecmp(&buf[i], sysatom[C_ALL], strlen(sysatom[C_ALL]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_ALL]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_ALL]);
	    
	    rtp->rtp_type = RTPROTO_IF;
	    rtp->rtp_if   = ifp;


	    if (aggregated->rt_aggr.ag_rtp != NULL) {
	      if (find_rtp(rtp, aggregated->rt_aggr.ag_rtp)) {
		syslog(LOG_ERR,
		       "%s:%d protocol I/F doubly defined", filename,line);
		fatalx("<conf_check>: protocol I/F doubly defined");
	      }
	      insque(rtp, aggregated->rt_aggr.ag_rtp);
	    } else {
	      rtp->rtp_next = rtp;
	      rtp->rtp_prev = rtp;
	      aggregated->rt_aggr.ag_rtp = rtp;
	    }

	    SENTENCE_END(i);
	    SKIP_WHITE(i);
	    if (buf[i++] != '}') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'}\'", filename, line);
	      fatalx("<conf_check>: syntax error");
	    }
	    SENTENCE_END(i);
	    /* End-of-"direct" */
	  } else {
	    syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	    fatalx("<conf_check>: syntax error");	      
	  }
	  continue;
	  /* End-of-"proto" */
	}

	break;  /* while(1) */

      }  /* End-of-while(1) */

      if (buf[i++] != '}') {
	syslog(LOG_ERR,
	       "%s:%d syntax error, missing \'}\'", filename, line);
	fatalx("<conf_check>: syntax error");
      }

      SENTENCE_END(i);

      if (aggregations) {
	if (find_rte(aggregated, aggregations)) {
	  syslog(LOG_ERR,
		 "%s:%d aggregate route doubly defined", filename,line);
	  fatalx("<conf_check>: aggregate route doubly defined");
	}
	insque(aggregated, aggregations);
      } else {
	aggregated->rt_next = aggregated;
	aggregated->rt_prev = aggregated;
	aggregations = aggregated;
      }

      continue;
    }

    /*
     *   "autonomoussystem"
     */
    if (strncasecmp(&buf[i], sysatom[C_MYASNUM], strlen(sysatom[C_MYASNUM]))
	== 0) {
      if (bit_test(parsedflag, C_MYASNUM)) {
	syslog(LOG_ERR, "%s:%d %s doubly defined",
	       filename, line, sysatom[C_MYASNUM]);
	fatalx("<conf_check>: doubly defined");
      }
      bit_set(parsedflag, C_MYASNUM);
      i += strlen(sysatom[C_MYASNUM]);
      SKIP_WHITE(i); READ_ATOM(i, j);

      my_as_number = atoi(atom);  /* (global) */

      SENTENCE_END(i);
      continue;
    }


    /*
     *   "routerid" (my BGP-ID)
     */
    if (strncasecmp(&buf[i], sysatom[C_ROUTERID], strlen(sysatom[C_ROUTERID])) == 0) 
      {
	if (bit_test(parsedflag, C_ROUTERID)) {
	  syslog(LOG_ERR, "<conf_check>: %s:%d %s doubly defined",
		 filename, line, sysatom[C_ROUTERID]);
	  fatalx("<conf_check>: doubly defined");
	}
	bit_set(parsedflag ,C_ROUTERID);
	i += strlen(sysatom[C_ROUTERID]);
	SKIP_WHITE(i); READ_ATOM(i, j);

	if (inet_pton(AF_INET, atom, (void *)&bgpIdentifier) != 1)
	  bgpIdentifier = htonl(atoi(atom));  /* (global) */

	SENTENCE_END(i);
	continue;
      }



    /*
     *   "IamRR" (Route Reflector)
     */
    if (strncasecmp(&buf[i], sysatom[C_RR], strlen(sysatom[C_RR])) == 0) 
      {
	if (bit_test(parsedflag, C_RR)) {
	  syslog(LOG_ERR, "<conf_check>: %s:%d %s doubly defined",
		 filename, line, sysatom[C_RR]);
	  fatalx("<conf_check>: doubly defined");
	}
	bit_set(parsedflag ,C_RR);
	i += strlen(sysatom[C_RR]);
	IamRR = 1;  /* (global) */
	SENTENCE_END(i);
	continue;
      }

    /*
     *   "clusterId" (when I am Route Reflecter)
     */
    if (strncasecmp(&buf[i], sysatom[C_CLUSTERID], strlen(sysatom[C_CLUSTERID]))
 == 0) 
      {
        if (bit_test(parsedflag, C_CLUSTERID)) {
          syslog(LOG_ERR, "<conf_check>: %s:%d %s doubly defined",
                 filename, line, sysatom[C_CLUSTERID]);
          fatalx("<conf_check>: doubly defined");
        }
        bit_set(parsedflag ,C_CLUSTERID);
        i += strlen(sysatom[C_CLUSTERID]);
        SKIP_WHITE(i); READ_ATOM(i, j);

        clusterId = atoi(atom);  /* (global) */

        SENTENCE_END(i);
        continue;
      }

    /*
     *   "holdtime" (in sec.)
     */
    if (strncasecmp(&buf[i], sysatom[C_HOLDTIME], strlen(sysatom[C_HOLDTIME]))
	== 0) {

      if (bit_test(parsedflag ,C_HOLDTIME)) {
	syslog(LOG_ERR,
	       "<conf_check>: %s:%d %s doubly defined",
	       filename, line, sysatom[C_HOLDTIME]);
	fatalx("<conf_check>: doubly defined");
      }
      bit_set(parsedflag ,C_HOLDTIME);
      i += strlen(sysatom[C_HOLDTIME]);
      SKIP_WHITE(i); READ_ATOM(i, j);

      bgpHoldtime = atoi(atom);  /* (global) */

      if (!HOLDTIME_ISCORRECT(bgpHoldtime)) {
	syslog(LOG_ERR,
	       "<conf_check>: %s:%d Invalid holdtime %d",
	       filename, line, bgpHoldtime);
	fatalx("<conf_check>: Invalid holdtime");
      }
      SENTENCE_END(i);
      continue;
    }

    /*
     *   "rip yes {...}"
     */
    if (strncasecmp(&buf[i], sysatom[C_RIP], strlen(sysatom[C_RIP]))
	== 0) {
      if (bit_test(parsedflag, C_RIP)) {
	syslog(LOG_ERR,
	       "%s:%d %s doubly defined", filename, line, sysatom[C_RIP]);
	fatalx("<conf_check>: doubly defined");
      }
      bit_set(parsedflag, C_RIP);

      i += strlen(sysatom[C_RIP]);
      SKIP_WHITE(i);

      if (strncasecmp(&buf[i], sysatom[C_YES], strlen(sysatom[C_YES]))
	  == 0)	{
	ripyes = 1;
	i += strlen(sysatom[C_YES]);
      } else {
	if (strncasecmp(&buf[i], sysatom[C_NO], strlen(sysatom[C_NO]))
	    == 0) {
	  i += strlen(sysatom[C_NO]);
	} else {
	  syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	  fatalx("<conf_check>: syntax error");
	}
      }


      SKIP_WHITE(i);
      if (buf[i++] != '{') {
	syslog(LOG_ERR,
	       "%s:%d syntax error, missing \'{\'", filename, line);
	fatalx("<conf_check>: syntax error");
      }

      if (ripyes)
	rip_init();   /**  rip_init() **/

      while(1) {
	SKIP_WHITE(i);

	/*     "interface .."  (options)  */ 
	if (strncasecmp(&buf[i], sysatom[C_INTERFACE], strlen(sysatom[C_INTERFACE]))
	    == 0) {
	  struct ifinfo *ifp;
	  struct ripif    *ripif;
	  i += strlen(sysatom[C_INTERFACE]);
	  SKIP_WHITE(i); READ_ATOM(i, j);
	  if ((ifp   = find_if_by_name(atom)) &&  /* find  "ifinfo" */
	      (ripif = find_rip_by_index(ifp->ifi_ifn->if_index))) {
	    while(1) {
	      SKIP_WHITE(i);
	      if (strncasecmp(&buf[i], sysatom[C_NORIPIN], strlen(sysatom[C_NORIPIN]))
		  == 0) {
		ripif->rip_mode |= IFS_NORIPIN;
		i += strlen(sysatom[C_NORIPIN]);
		continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_NORIPOUT], strlen(sysatom[C_NORIPOUT]))
		  == 0) {
		ripif->rip_mode |= IFS_NORIPOUT;
		i += strlen(sysatom[C_NORIPOUT]);
		continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_DEFAULT], strlen(sysatom[C_DEFAULT]))
		  == 0) {
		i += strlen(sysatom[C_DEFAULT]);
		SKIP_WHITE(i);
		if (strncasecmp(&buf[i], sysatom[C_ORIGINATE], strlen(sysatom[C_ORIGINATE]))
		    == 0) {
		    ripif->rip_mode |= IFS_DEFAULTORIGINATE;
		    i += strlen(sysatom[C_ORIGINATE]);
		} else {
		  syslog(LOG_ERR,
			 "%s:%d syntax error, missing any valid words after \'%s\'",
			 filename, line, sysatom[C_DEFAULT]);
		  fatalx("<conf_check>: syntax error");
		}
		continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_METRICIN],
			      strlen(sysatom[C_METRICIN])) == 0) {
		      int metric;

		      i += strlen(sysatom[C_METRICIN]);
		      SKIP_WHITE(i);
		      READ_ATOM(i, j);
		      metric = atoi(atom);
		      if (metric == 0 || metric > RIPNG_METRIC_UNREACHABLE) {
			      syslog(LOG_ERR,
				     "%s: %d syntax error, invalid RIPng "
				     "metric(%s)", filename, line, atom);
			      fatalx("<conf_check>: syntax error");
		      }
		      ripif->rip_metricin = metric;

		      continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_FILTERIN],
			      strlen(sysatom[C_FILTERIN])) == 0) {
		      /* "filterin prfx/plen": incoming route filter */
		      i += strlen(sysatom[C_FILTERIN]);
		      SKIP_WHITE(i); READ_ATOM(i, j);
		      if (set_filter(&ripif->rip_filterin, atom,
				     filename, line)) {
			      /*
			       * non zero return value means exact match
			       * to default route
			       */
			      ripif->rip_mode |= IFS_DEFAULT_FILTERIN;
		      }
			      
		      continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_RESTRICTIN],
			      strlen(sysatom[C_RESTRICTIN])) == 0) {
		      /* "restrictin prfx/plen": incoming route restriction */
		      i += strlen(sysatom[C_RESTRICTIN]);
		      SKIP_WHITE(i); READ_ATOM(i, j);
		      if (set_filter(&ripif->rip_restrictin, atom,
				     filename, line))
			      ripif->rip_mode |= IFS_DEFAULT_RESTRICTIN;

		      continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_FILTEROUT],
			      strlen(sysatom[C_FILTEROUT])) == 0) {
		      /* "filter prfx/plen": outgoing route filter */
		      i += strlen(sysatom[C_FILTEROUT]);
		      SKIP_WHITE(i); READ_ATOM(i, j);
		      if (set_filter(&ripif->rip_filterout, atom,
				     filename, line))
			      ripif->rip_mode |= IFS_DEFAULT_FILTEROUT;

		      continue;
	      }
	      if (strncasecmp(&buf[i], sysatom[C_RESTRICTOUT],
			      strlen(sysatom[C_RESTRICTOUT])) == 0) {
		      /* "filter prfx/plen": outgoing route restriction */
		      i += strlen(sysatom[C_RESTRICTOUT]);
		      SKIP_WHITE(i); READ_ATOM(i, j);
		      if (set_filter(&ripif->rip_restrictout, atom,
				     filename, line))
			      ripif->rip_mode |= IFS_DEFAULT_RESTRICTOUT;

		      continue;
	      }
	      break; /* while */ /* No match. */
	    } /* while */

	  } else {
	    syslog(LOG_ERR,
		   "%s:%d interface %s misconfigure", filename, line, atom);
	    fatalx("interface misconfigure");
	  }
	  SENTENCE_END(i);
	} else
	  /* "sitelocal [yes|no]" */
	  if (strncasecmp(&buf[i], sysatom[C_SITELOCAL],
			  strlen(sysatom[C_SITELOCAL])) == 0) {
	    if (bit_test(parsedflag, C_SITELOCAL)) {
	      syslog(LOG_ERR,
		     "%s:%d %s doubly defined", filename, line,
		     sysatom[C_SITELOCAL]);
	      fatalx("<conf_check>: doubly defined");
	    }
	    bit_set(parsedflag, C_SITELOCAL);
	    
	    i += strlen(sysatom[C_SITELOCAL]);
	    SKIP_WHITE(i);

	    if (strncasecmp(&buf[i], sysatom[C_YES], strlen(sysatom[C_YES]))
		== 0) {
	      rip_use_sitelocal = 1;
	      i += strlen(sysatom[C_YES]);
	    } else if (strncasecmp(&buf[i], sysatom[C_NO],
				   strlen(sysatom[C_NO])) == 0) {
	      rip_use_sitelocal = 0;
	      i += strlen(sysatom[C_NO]);
	    }
	    else {
	      syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	      fatalx("<conf_check>: syntax error");
	    }

	    SENTENCE_END(i);
	}
	else
	  break;
      } /* end-of-while */

      if (buf[i++] != '}') {
	syslog(LOG_ERR,
	       "%s:%d syntax error, missing \'}\'", filename, line);
	fatalx("syntax error");
      }
      SKIP_WHITE(i);
      SENTENCE_END(i);
      continue;
    }

    /*
     *    export proto bgp as ... {
     *        proto ... ;
     *        proto ... ;
     *    };
     */
    if (strncasecmp(&buf[i], sysatom[C_EXPORT], strlen(sysatom[C_EXPORT]))
	== 0) {
      struct rpcb   *asp;         /* export to */
      u_int16_t  easnum;      /* export to */

      i += strlen(sysatom[C_EXPORT]);
      SKIP_WHITE(i);

      if (strncasecmp(&buf[i], sysatom[C_PROTO], strlen(sysatom[C_PROTO]))
	  != 0) {
	syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
	       filename, line, sysatom[C_PROTO]);
	fatalx("<conf_check>: parse error");
      }
      i += strlen(sysatom[C_PROTO]);
      SKIP_WHITE(i);


      if (strncasecmp(&buf[i], sysatom[C_BGP], strlen(sysatom[C_BGP]))
	  == 0) {
	i += strlen(sysatom[C_BGP]);
	SKIP_WHITE(i);


	if (strncasecmp(&buf[i], sysatom[C_AS], strlen(sysatom[C_AS]))
	    != 0) {
	  syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		 filename, line, sysatom[C_AS]);
	  fatalx("<conf_check>: syntax error");
	}
	i += strlen(sysatom[C_AS]);
	SKIP_WHITE(i); READ_ATOM(i, j);

	/*
	 *   "as"        (to be exported to)
	 */
	if ((easnum = atoi(atom)) == 0 ||
	    easnum == my_as_number) {
	  syslog(LOG_ERR, "%s:%d invalid AS number", filename, line);
	  fatalx("<conf_check>: invalid AS number");
	}
	if ((asp = find_peer_by_as(easnum)) == NULL) {  /* already ? */
	  syslog(LOG_ERR, "%s:%d AS %d not defined",
		 filename, line, easnum);
	  fatalx("<conf_check>: AS not defined");
	}
	SKIP_WHITE(i);

	if (buf[i++] != '{') {
	  syslog(LOG_ERR, "%s:%d syntax error, missing \'{\'", filename, line);
	  fatalx("<conf_check>: syntax error");
	}

	while(1) {
	  struct rtproto  *rtp;
	  MALLOC(rtp, struct rtproto);
	  
	  SKIP_WHITE(i);
	  /*
	   *   "proto" ..?
	   */
	  if (strncasecmp(&buf[i], sysatom[C_PROTO], strlen(sysatom[C_PROTO]))
	      == 0) {
	    i += strlen(sysatom[C_PROTO]);
	    SKIP_WHITE(i);
	  } else {
	    free(rtp); rtp = NULL;
	  }

	  /*
	   *   "direct"
	   */
	  if (strncasecmp(&buf[i], sysatom[C_DIRECT], strlen(sysatom[C_DIRECT]))
	      == 0) {
	    struct ifinfo *ifp;

	    i += strlen(sysatom[C_DIRECT]);
	    SKIP_WHITE(i);

	    /*     "interface .."    */ 
	    if (strncasecmp(&buf[i], sysatom[C_INTERFACE], strlen(sysatom[C_INTERFACE]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_INTERFACE]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_INTERFACE]);
	    SKIP_WHITE(i); READ_ATOM(i, j);
	    if ((ifp = find_if_by_name(atom)) == NULL) {/* find  "ifinfo" */
	      syslog(LOG_ERR, "%s:%d interface \'%s\' not found",
		     filename, line, atom);
	      fatalx("<conf_check>: interface not found");
	    }

	    SKIP_WHITE(i);
	    if (buf[i++] != '{') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'{\'", filename, line);
	      fatalx("<conf_check>: syntax error");	  
	    }
	    SKIP_WHITE(i);
	    /*
	     *   "ALL"
	     */
	    if (strncasecmp(&buf[i], sysatom[C_ALL], strlen(sysatom[C_ALL]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_ALL]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_ALL]);

	    rtp->rtp_type = RTPROTO_IF;
	    rtp->rtp_if   = ifp;

	    if (asp->rp_adj_ribs_out != NULL) {         /* struct rtproto */
	      if (find_rtp(rtp, asp->rp_adj_ribs_out)) {
		syslog(LOG_ERR,
		       "%s:%d origination I/F doubly defined", filename,line);
		fatalx("<conf_check>: origination I/F doubly defined");
	      }
	      insque(rtp, asp->rp_adj_ribs_out);
	    } else {
	      rtp->rtp_next = rtp;
	      rtp->rtp_prev = rtp;
	      asp->rp_adj_ribs_out = rtp;
	    }

	    SENTENCE_END(i);
	    SKIP_WHITE(i);
	    if (buf[i++] != '}') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'}\'", filename, line);
	      fatalx("<conf_check>: syntax error");
	    }
	    SENTENCE_END(i);
	    continue;
	    /***   direct End   ***/
	  }	

	  /*
	   *  "bgp"
	   */
	  if (strncasecmp(&buf[i], sysatom[C_BGP], strlen(sysatom[C_BGP]))
	      == 0) {
	    struct rpcb *ibnp;   /* origin */
	    int      iasnum; 

	    i += strlen(sysatom[C_BGP]);
	    SKIP_WHITE(i);

	    /*     "as [..]"    */ 
	    if (strncasecmp(&buf[i], sysatom[C_AS], strlen(sysatom[C_AS]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_AS]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_AS]);
	    SKIP_WHITE(i); READ_ATOM(i, j);
	    if ((iasnum = atoi(atom)) == 0 ||
		iasnum == my_as_number) {
	      syslog(LOG_ERR, "%s:%d: invalid AS number", filename, line);
	      fatalx("<conf_check>: invalid AS number");
	    }
	    if ((ibnp = find_peer_by_as(iasnum)) == NULL) { /* already ? */
	      syslog(LOG_ERR, "%s:%d AS %d not defined",
		     filename, line, iasnum);
	      fatalx("<conf_check>: AS not defined");
	    }

	    SKIP_WHITE(i);
	    if (buf[i++] != '{') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'{\'", filename, line);
	      fatalx("<conf_check>: syntax error");	  
	    }
	    SKIP_WHITE(i);
	    /*
	     *   "ALL"
	     */
	    if (strncasecmp(&buf[i], sysatom[C_ALL], strlen(sysatom[C_ALL]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_ALL]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_ALL]);
	  
	    rtp->rtp_type = RTPROTO_BGP;
	    rtp->rtp_bgp  = ibnp;


	    if (asp->rp_adj_ribs_out != NULL) {         /* struct rtproto */
	      if (find_rtp(rtp, asp->rp_adj_ribs_out)) {
		syslog(LOG_ERR,
		       "%s:%d originating BGP peer doubly defined",
		       filename, line);
		fatalx("<conf_check>: originating BGP peer doubly defined");
	      }
	      insque(rtp, asp->rp_adj_ribs_out);
	    } else {
	      rtp->rtp_next = rtp->rtp_prev = rtp;
	      asp->rp_adj_ribs_out = rtp;
	    }

	    SENTENCE_END(i);  SKIP_WHITE(i);
	    if (buf[i++] != '}') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'}\'", filename, line);
	      fatalx("<conf_check>: syntax error");
	    }
	    SENTENCE_END(i);
	    continue;
	    /***    bgp End    ***/
	  }




	  /*
	   *   "rip"
	   */
	  if (strncasecmp(&buf[i], sysatom[C_RIP], strlen(sysatom[C_RIP]))
	      == 0) {
	    struct ripif            *ripif;
	    extern  struct ripif    *ripifs;

	    i += strlen(sysatom[C_RIP]);
	    SKIP_WHITE(i);
	    if (buf[i++] != '{') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'{\'", filename, line);
	      fatalx("<conf_check>: syntax error");	  
	    }
	    SKIP_WHITE(i);
	    /*
	     *   "ALL"
	     */
	    if (strncasecmp(&buf[i], sysatom[C_ALL], strlen(sysatom[C_ALL]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_ALL]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_ALL]);

	    if (!ripyes || !ripifs) {
	      syslog(LOG_ERR, "%s:%d RIPng not configured", filename, line);
	      fatalx("<conf_check>: RIPng not configured");
	    }

	    ripif = ripifs;  /* "ripifs"  is global-RIP-list */ 	  
	    while(ripif) {
	      rtp->rtp_type = RTPROTO_RIP;
	      rtp->rtp_rip  = ripif;

	      if (asp->rp_adj_ribs_out != NULL) {    /* struct rtproto */
		if (find_rtp(rtp, asp->rp_adj_ribs_out)) {
		  syslog(LOG_ERR, "%s:%d original rtproto doubly defined",
			 filename, line);
		  fatalx("<conf_check>: original rtproto doubly defined");
		}
		insque(rtp, asp->rp_adj_ribs_out);
	      } else {
		rtp->rtp_next = rtp->rtp_prev = rtp;
		asp->rp_adj_ribs_out = rtp;
	      }

	      MALLOC(rtp, struct rtproto);
	      if ((ripif = ripif->rip_next) == ripifs) { /* global */
		free(rtp); rtp = NULL;
		break;
	      }
	    } /* while rip-ring */

	    SENTENCE_END(i); SKIP_WHITE(i);
	    if (buf[i++] != '}') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'}\'", filename, line);
	      fatalx("<conf_check>: syntax error");
	    }
	    SENTENCE_END(i);
	    continue;
	    /***    rip End   ***/
	  }



	  /*
	   *  "IBGP"
	   */
	  if (strncasecmp(&buf[i], sysatom[C_IBGP], strlen(sysatom[C_IBGP]))
	      == 0) {
	    struct rpcb *ibnp;   /* origin */

	    i += strlen(sysatom[C_IBGP]);
	    SKIP_WHITE(i);
	    if (buf[i++] != '{') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'{\'", filename, line);
	      fatalx("<conf_check>: syntax error");	  
	    }
	    SKIP_WHITE(i);
	    /*
	     *   "ALL"
	     */
	    if (strncasecmp(&buf[i], sysatom[C_ALL], strlen(sysatom[C_ALL]))
		!= 0) {
	      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
		     filename, line, sysatom[C_ALL]);
	      fatalx("<conf_check>: syntax error");
	    }
	    i += strlen(sysatom[C_ALL]);

	    ibnp = bgb;  /* global */
	    while(1) {
	      if (ibnp->rp_mode & BGPO_IGP) {
		rtp->rtp_type = RTPROTO_BGP;
		rtp->rtp_bgp  = ibnp;

		if (asp->rp_adj_ribs_out != NULL) {    /* struct rtproto */
		  if (find_rtp(rtp, asp->rp_adj_ribs_out)) {
		    syslog(LOG_ERR,
			   "%s:%d originating BGP peer doubly defined",
			   filename, line);
		    fatalx("<conf_check>: originating BGP peer doubly defined");
		  }
		  insque(rtp, asp->rp_adj_ribs_out);
		} else {
		  rtp->rtp_next = rtp->rtp_prev = rtp;
		  asp->rp_adj_ribs_out = rtp;
		}
		MALLOC(rtp, struct rtproto);
	      }
	      if ((ibnp = ibnp->rp_next) == bgb) {
		free(rtp); rtp = NULL;
		break;
	      }
	    } /* while bgp-ring */
	    SENTENCE_END(i); SKIP_WHITE(i);
	    if (buf[i++] != '}') {
	      syslog(LOG_ERR,
		     "%s:%d syntax error, missing \'}\'", filename, line);
	      fatalx("<conf_check>: syntax error");
	    }
	    SENTENCE_END(i);
	    continue;
	    /***   IBGP End    ***/
	  }

	  /**  proto-switching End  **/
	  if (buf[i++] == '}')
	    break;
	  else {
	    syslog(LOG_ERR,
		   "%s:%d syntax error, missing \'}\'", filename, line);
	    fatalx("<conf_check>: syntax error");
	  }
	} /*  while(1)  */
	SKIP_WHITE(i);
	SENTENCE_END(i);
	continue;


      } else {

	syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	fatalx("<conf_check>: syntax error");
	/* error */
      }
    }
    /**  nothing matched  **/
    syslog(LOG_ERR, "<conf_check>: %s:%d syntax error", filename, line);
    fatalx("<conf_check>: syntax error");
  }
    
  /************************************************************************/

  if (ripyes)
	  rip_import_init();

  if (bgpyes) {
    struct sockaddr_in6 bgpsin;        /* my address      */
    int on;

    if (!(bit_test(parsedflag, C_MYASNUM))) {
      dperror("<conf_check>: My AS number not defined");
      terminate();
    }

    if ((bgpsock = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
      dperror("<conf_check>: socket");
      terminate();
    }

    on = 1;
    if (setsockopt(bgpsock, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
	dperror("<conf_check>: setsockopt(SO_REUSEPORT)");
	/* error, but not so serious */
    }

    memset(&bgpsin,   0, sizeof(bgpsin));    /* sockaddr_in6  */
    bgpsin.sin6_len      = sizeof(struct sockaddr_in6);
    bgpsin.sin6_family   = AF_INET6;
    bgpsin.sin6_port     = htons(BGP_PORT);
    bgpsin.sin6_flowinfo = 0;

    if (bind(bgpsock, (struct sockaddr *)&bgpsin, sizeof(bgpsin)) < 0) {
      dperror("<conf_check>: bind");
      terminate();
    }

    on = 1;
#ifdef ADVANCEDAPI
    if (setsockopt(bgpsock, IPPROTO_IPV6, IPV6_PKTINFO,
		   &on, sizeof(on)) < 0)
      fatal("<conf_check>: setsockopt: IPV6_PKTINFO");
#endif

    if (listen(bgpsock, 5) < 0) {
      dperror("<conf_check>: listen");
      terminate();
    }

    FD_SET(bgpsock, &fdmask);           /* (global) */
    

    if (!(bit_test( parsedflag, C_HOLDTIME)))
      bgpHoldtime = BGP_HOLDTIME;       /* default   */


    ibgpbnp = bgb;
    while(ibgpbnp){
      if (ibgpbnp->rp_mode & BGPO_IGP)
	ibgpbnp->rp_as = my_as_number;
      if ((ibgpbnp = ibgpbnp->rp_next) == bgb)
	break;
    }

  } else {
    bgpsock = 0;
  }

  if (!(bit_test(parsedflag, C_ROUTERID))) {
    if ((bgpIdentifier = get_32id()) == 0)
      fatalx("<conf_check>: bgpIdentifier should be defined");
  }

  if (!(bit_test(parsedflag, C_RIP)))
    ripsock = 0;                        /* don't RIP */

  /* REACHED */
}





/*
 *   "bgp yes {...}"
 */
void
parse_bgp_yes(char *filename) {

  u_int16_t asnum;
  u_int32_t peerid;
  extern struct rpcb *bgb;
  extern byte         bgpyes;

  if (bit_test(parsedflag, C_BGP)) {
    syslog(LOG_ERR, "%s:%d %s doubly defined", filename, line, sysatom[C_BGP]);
    fatalx("doubly defined");
  }
  bit_set(parsedflag, C_BGP);

  bgb = bgp_new_peer();      /*   Initialized one becomes the head.  */
  bgb->rp_next = bgb->rp_prev = bgb;
  bnp = bgb;

  i += strlen(sysatom[C_BGP]);
  SKIP_WHITE(i);

  if (strncasecmp(&buf[i], sysatom[C_YES], strlen(sysatom[C_YES]))
      == 0)	{
    bgpyes = 1;
    i += strlen(sysatom[C_YES]);
  } else {
    if (strncasecmp(&buf[i], sysatom[C_NO], strlen(sysatom[C_NO]))
	== 0) {
      i += strlen(sysatom[C_NO]);
    } else {
      syslog(LOG_ERR, "%s:%d syntax error", filename, line);
      fatalx("syntax error");
    }
  }


  SKIP_WHITE(i);
  if (buf[i++] != '{') {
    syslog(LOG_ERR, "%s:%d syntax error, missing \'{\'", filename, line);
    fatalx("syntax error");
  }

  SKIP_WHITE(i);
      
  while(1) {
    /*
     *   "Group Type"
     */
    if (strncasecmp(&buf[i], sysatom[C_GROUP], strlen(sysatom[C_GROUP]))
	!= 0) {
      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
	     filename, line, sysatom[C_GROUP]);
      fatalx("syntax error");
    } 

    i += strlen(sysatom[C_GROUP]);
    SKIP_WHITE(i);
    if (strncasecmp(&buf[i], sysatom[C_TYPE], strlen(sysatom[C_TYPE]))
	!= 0)	{
      syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
	     filename, line, sysatom[C_TYPE]);
      fatalx("syntax error");
    } 
    i += strlen(sysatom[C_TYPE]);
    SKIP_WHITE(i);
    /*
     *       "External peeras"
     */
    if (strncasecmp(&buf[i], sysatom[C_EXTERNAL], strlen(sysatom[C_EXTERNAL]))
	== 0) {

      i += strlen(sysatom[C_EXTERNAL]);
      SKIP_WHITE(i);
      if (strncasecmp(&buf[i], sysatom[C_PEERAS], strlen(sysatom[C_PEERAS]))
	  != 0)	{
	syslog(LOG_ERR, "%s:%d syntax error, missing \'%s\'",
	       filename, line, sysatom[C_PEERAS]);
	fatalx("syntax error");
      } 
      i += strlen(sysatom[C_PEERAS]);
      SKIP_WHITE(i); READ_ATOM(i, j);
      if ((asnum = atoi(atom)) == 0) {
	syslog(LOG_ERR, "%s:%d invalid AS number", filename, line);
	fatalx("invalid AS number");
      }
      if (find_peer_by_as(asnum)) {
	syslog(LOG_ERR, "%s:%d AS %d doubly defined", filename, line, asnum);
	fatalx("AS number doubly defined");
      }
      bnp->rp_as = asnum;
    } else {
      
      /*
       *       "Internal [routerid ...]"
       */
      if (strncasecmp(&buf[i], sysatom[C_INTERNAL],strlen(sysatom[C_INTERNAL]))
	  == 0) {
	i += strlen(sysatom[C_INTERNAL]);
	SKIP_WHITE(i);
	peerid = 0; /* init */

	if (strncasecmp(&buf[i], sysatom[C_ROUTERID], strlen(sysatom[C_ROUTERID]))
	  == 0)	{
	  i += strlen(sysatom[C_ROUTERID]);
	  SKIP_WHITE(i); READ_ATOM(i, j);

	  /* IPv4 address format : jinmei */
	  if (inet_pton(AF_INET, atom, (void *)&peerid) != 1)
	    peerid = htonl(atoi(atom));

	  if (peerid == 0) {
	    syslog(LOG_ERR, "%s:%d invalid Router ID", filename, line);
	    fatalx("invalid Router ID");
	  } else if (rpcblookup(bgb, peerid)) {
	    syslog(LOG_ERR,
		   "%s:%d PEER ID %d doubly defined", filename, line, peerid);
	    fatalx("Peer ID doubly defined");
	  }
	  bnp->rp_mode |= BGPO_IDSTATIC;  /* (1998/5/21) */
	}
	bnp->rp_id    = peerid; /* net-order */
	bnp->rp_mode |= BGPO_IGP;

      } else {  /* External nor Internal */
	syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	fatalx("syntax error"); 
      }
    }

    SKIP_WHITE(i);
    if (buf[i++] != '{') {
      syslog(LOG_ERR, "%s:%d syntax error, missing \'{\'", filename, line);
      fatalx("syntax error");	  
    }

    SKIP_WHITE(i);
    /*
     *   "peer|client" ...   [interface ..]
     */
    if (strncasecmp(&buf[i], sysatom[C_CLIENT], strlen(sysatom[C_CLIENT]))
	== 0) {
      if (bnp->rp_mode & BGPO_IGP) {
	bnp->rp_mode |= BGPO_RRCLIENT;
	i += strlen(sysatom[C_CLIENT]);
      } else {
	syslog(LOG_ERR, "%s:%d External peer (%d) cannot be a RRclient",
	       filename, line, bnp->rp_as);
	fatalx("External peer cannot be a RRclient");
      }
    } else {
      if (strncasecmp(&buf[i], sysatom[C_PEER], strlen(sysatom[C_PEER]))
	  == 0) {
	i += strlen(sysatom[C_PEER]);
      } else {
	syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	fatalx("syntax error");
      }
    }

    SKIP_WHITE(i); READ_ATOM(i, j);

    bnp->rp_addr.sin6_len      = sizeof(struct sockaddr_in6);
    bnp->rp_addr.sin6_family   = AF_INET6;
    bnp->rp_addr.sin6_port     = htons(BGP_PORT);
    bnp->rp_addr.sin6_flowinfo = 0;
    if (inet_pton(AF_INET6, atom, &bnp->rp_addr.sin6_addr) < 1) {
      syslog(LOG_ERR, "%s:%d inet_pton() failed", filename, line);
      terminate();
    }

    if (IN6_IS_ADDR_LINKLOCAL(&bnp->rp_addr.sin6_addr))
      bnp->rp_laddr = bnp->rp_addr.sin6_addr; /* copy  */
    else
      bnp->rp_gaddr = bnp->rp_addr.sin6_addr; /* ummh  */

    {
	    struct ifinfo *ife_dummy = NULL; /* XXX */
	    if (in6_is_addr_onlink(&bnp->rp_addr.sin6_addr, &ife_dummy))
		    bnp->rp_mode |= BGPO_ONLINK;
    }

    while(1) {
      SKIP_WHITE(i);
      /*     [interface ..]  (e.x. for link-local address)  */ 
      if (strncasecmp(&buf[i], sysatom[C_INTERFACE], strlen(sysatom[C_INTERFACE]))
	  == 0) {
	i += strlen(sysatom[C_INTERFACE]);
	SKIP_WHITE(i); READ_ATOM(i, j);
	if ((bnp->rp_ife = find_if_by_name(atom))) { /* find "ifinfo" */
	  bnp->rp_mode |= BGPO_IFSTATIC;
	} else {
	  syslog(LOG_ERR,
		 "%s:%d interface %s misconfigure", filename, line, atom);
	  fatalx("interface misconfigure");
	}
      } 
      else if (strncasecmp(&buf[i],
		      sysatom[C_PREFERENCE], strlen(sysatom[C_PREFERENCE]))
	  == 0) {
	      /*     [preference ..]  (for this peer)  */ 
	      if (bnp->rp_mode & BGPO_IGP) {
		      syslog(LOG_ERR,
			     "%s:%d %s can only be specified for an EBGP peer",
			     filename, line, sysatom[C_PREFERENCE]);
		      fatalx("<conf_check>: invalid peer option");
	      }
	      i += strlen(sysatom[C_PREFERENCE]);
	      SKIP_WHITE(i); READ_ATOM(i, j);
	      bnp->rp_prefer = htonl(atoi(atom));
      }
      else if (strncasecmp(&buf[i], sysatom[C_NO], strlen(sysatom[C_NO])) == 0) {
	    /*   [no synchronization]  (for this peer)  */ 
	    i += strlen(sysatom[C_NO]);
	    SKIP_WHITE(i);
	    if (strncasecmp(&buf[i], sysatom[C_SYNC], strlen(sysatom[C_SYNC])) == 0) {
	      bnp->rp_mode |= BGPO_NOSYNC;
	      i += strlen(sysatom[C_SYNC]);
	      SKIP_WHITE(i);
	    } else {
	      syslog(LOG_ERR, "%s:%d syntax error", filename, line);
	      fatalx("syntax error");
	    }
	  }
      else if (strncasecmp(&buf[i], sysatom[C_PREPEND], strlen(sysatom[C_PREPEND]))
	  == 0) {
	      if (bnp->rp_mode & BGPO_IGP) {
		      syslog(LOG_ERR,
			     "%s:%d %s can only be specified for an EBGP peer",
			     filename, line, sysatom[C_PREPEND]);
		      fatalx("<conf_check>: invalid peer option");
	      }
	      i += strlen(sysatom[C_PREPEND]);
	      SKIP_WHITE(i);
	      if (isdigit(buf[i])) {
		      READ_ATOM(i, j);
		      bnp->rp_ebgp_as_prepends = atoi(atom);
	      }
	      else
		      bnp->rp_ebgp_as_prepends = BGP_DEF_ASPREPEND;
      }
      else if (strncasecmp(&buf[i], sysatom[C_NEXTHOPSELF],
			   strlen(sysatom[C_NEXTHOPSELF])) == 0) {
	      if ((bnp->rp_mode & BGPO_IGP) == 0) {
		      syslog(LOG_ERR,
			     "%s:%d %s can only be specified for an IBGP peer",
			     filename, line, sysatom[C_NEXTHOPSELF]);
		      fatalx("<conf_check>: invalid peer option");
	      }
	      i += strlen(sysatom[C_NEXTHOPSELF]);
	      bnp->rp_mode |= BGPO_NEXTHOPSELF;
      }
      else if (strncasecmp(&buf[i], sysatom[C_LOCALADDR],
			   strlen(sysatom[C_LOCALADDR])) == 0) {
	      if (!IN6_IS_ADDR_UNSPECIFIED(&bnp->rp_lcladdr.sin6_addr)) {
		      syslog(LOG_ERR,
			     "%s:%d BGP localaddr doubly defined",
			     filename, line);
		      fatalx("<conf_check>: perse failed");
	      }
	      i += strlen(sysatom[C_LOCALADDR]);
	      SKIP_WHITE(i); READ_ATOM(i, j);
	      memcpy(&bnp->rp_lcladdr.sin6_addr, atom, sizeof(struct in6_addr));
	      if (inet_pton(AF_INET6, atom, &bnp->rp_lcladdr.sin6_addr) < 1) {
		      syslog(LOG_ERR, "%s:%d inet_pton() failed for %s",
			     filename, line, atom);
		      fatalx("<conf_check>: perse failed");
	      }
	      if (IN6_IS_ADDR_LINKLOCAL(&bnp->rp_lcladdr.sin6_addr)) {
		      syslog(LOG_ERR,
			     "%s:%d BGP local addr must not be a link-local(%s)",
			     filename, line, atom);
		      fatalx("<conf_check>: perse failed");
	      }
	      bnp->rp_lcladdr.sin6_len = sizeof(struct sockaddr_in6);
	      bnp->rp_lcladdr.sin6_family = AF_INET6;
      }
      else
	      break; /* while */
    }

    if (IN6_IS_ADDR_LINKLOCAL(&bnp->rp_addr.sin6_addr) &&
	bnp->rp_ife == NULL) {
      syslog(LOG_ERR,
	     "%s:%d link-local address needs it's associating I/F",
	     filename, line);
      fatalx("interface misconfigure");
    }

    if (bnp != bgb)
      insque(bnp, bgb);
    bnp = bgp_new_peer();   /* for next. But the LastOne maybe garbage */

    SENTENCE_END(i);
    SKIP_WHITE(i);

    if (buf[i++] != '}') {
      syslog(LOG_ERR, "%s:%d syntax error, missing \'}\'", filename, line);
      fatalx("syntax error");
    }
    SENTENCE_END(i);

    SKIP_WHITE(i);
    if (buf[i] == '}')
      break;
  } /* while */
  i++;
  SKIP_WHITE(i);
  SENTENCE_END(i);
  if (!bgpyes) {
    free(bgb);
    bgb = NULL;
  }
}

static int
set_filter(struct filtinfo **headp, char *filtstr, char *filename, int line)
{
	struct filtinfo *filter;
	char in6txt[INET6_ADDRSTRLEN];

	/* At first, check if the string means a special filter */
	if (!strncasecmp(filtstr, "default", strlen("default")))
		return(1);	/* XXX: adhoc */

	memset(in6txt, 0, INET6_ADDRSTRLEN);
	MALLOC(filter, struct filtinfo);
	memset(filter, 0, sizeof(struct filtinfo));

	if (inet_ptox(AF_INET6, filtstr,
		      &filter->filtinfo_addr,
		      &filter->filtinfo_plen) < 1) {
		syslog(LOG_ERR,
		       "%s:%d inet_ptox() failed", filename, line);
		terminate();
	}
	mask_nclear(&filter->filtinfo_addr, filter->filtinfo_plen);

	if (*headp) {
		if (find_filter(*headp, filter)) {
			syslog(LOG_ERR,
			       "%s:%d route filter doubly defined",
			       filename, line);
			fatalx("route filter doubly defined");
		}
		insque(filter, *headp);
	} else {
		filter->filtinfo_next =
			filter->filtinfo_prev = filter;
		*headp = filter;
	}

	return(0);
}
