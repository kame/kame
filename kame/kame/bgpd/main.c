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
#include "in6.h"

#include "ripng.h"
#include "ripng_var.h"
#include "parse.h"
#include "ospf.h"
#ifdef USE_LEX_YACC
#include "cfparse.h"
#endif 

int confcheck = 0;		/* configuration check only */
int              rtsock;       /* the routing socket               */
pid_t            pid;
fd_set           fdmask;
fd_set           currentmask;

struct ifinfo   *ifentry;      /* interface list                   */
struct rt_entry *aggregations; /* aggregate-generated routes       */
task            *taskhead;

byte             bgpyes, ripyes, ospfyes;

unsigned long debug;

#define  PIDFILENAME  "/var/run/bgpd.pid"
#define CONFFILENAME  "/usr/local/v6/etc/bgpd.conf"

extern void bgpd_dump_file();

static int do_dump;
static void bgpd_set_dump_file();

/*
 *  Main
 */ 
int
main(argc, argv)
     int    argc;
     char **argv;
{
  struct rpcb *bnp;
  FILE        *pfp;
  int          foreground = 0;
  int          ch;
  char *conf = NULL;

  extern struct rpcb *bgb;
  extern task        *taskhead;
  extern byte         IamRR;
  extern u_int32_t    clusterId;

  /* Global var initialize */
  bgpyes    = ripyes  = 0;
  ospfyes = 0;             /* XXX: experimental */
  bgb = NULL;
  taskhead  = NULL;
  IamRR     = 0;
  clusterId = 0;
  aggregations = NULL;

  FD_ZERO(&fdmask);  

  /* get options */
  while ((ch = getopt(argc, argv, "Cc:f")) != EOF){
    switch (ch){
    case 'C':
      confcheck++;
      break;
    case 'c':
      conf = optarg;
      break;
    case 'f':
      foreground = 1;
      break;
    default:
      fprintf(stderr, "usage: bgpd [-c conf_file] [-f]\n");
      fprintf(stderr, "\t-f: Run foreground.\n");
      fprintf(stderr, "\t-c: Specify the configuration file.\n");
      exit(1);
    }
  }

  if (confcheck == 0 && foreground == 0) {
    if ((pid = fork()) < 0){
      fprintf(stderr, "Cannot fork: %s\n", strerror(errno));
      exit(1);
    } else if (pid > 0) {
      /* Parent process */
      exit(0);
    }
  }

  pid = getpid();
  setitimer(ITIMER_REAL, NULL, NULL);

 {
  char *ident;
  ident = strrchr(*argv, '/');
  if (!ident)
    ident = *argv;
  else
    ident++;
  openlog(ident, LOG_NDELAY|LOG_PID, LOG_DAEMON);
 }
  syslog(LOG_NOTICE, "IPv6 routing started, pid %d ******************", pid);


  /* write PID file */
  if (confcheck == 0) { 
    pfp = fopen(PIDFILENAME, "w");
    if (pfp == NULL) {
      fprintf(stderr, "Cannot open PID file: %s. Exit.\n", strerror(errno));
      exit(1);
    }

    fprintf(pfp, "%d\n", pid);
    fclose(pfp);
  }

  loconfig("lo0");
  ifconfig();
  if (confcheck == 0)
    krt_init();

#ifdef USE_LEX_YACC
  if (cfparse(1, conf ? conf : CONFFILENAME))
    exit(1);
  if (confcheck)
    exit(0);

  /* initialization after parsing configuration */
  install_static();
  if (ripyes) {
    rip_sockinit();
    rip_import_init();
  }
  if (bgpyes) {
    bgp_paraminit();
    bgp_sockinit();
  }
#else
  conf_check(conf ? conf : CONFFILENAME);
#endif

  aggr_ifinit();

  if (signal(SIGALRM, (void *)alarm_handler) < 0)
    fatal("<main>: SIGALRM");
  if (signal(SIGPIPE, (void *)pipe_handler) < 0)
    fatal("<main>: SIGPIPE");
  if (signal(SIGINT, (void *)bgpdexit) < 0)
    fatal("<main>: SIGINT");
  if (signal(SIGTERM, (void *)bgpdexit) < 0)
    fatal("<main>: SIGTERM");
  if (signal(SIGUSR1, (void *)bgpd_set_dump_file) < 0)
    fatal("<main>: USR1");

  if (bgpyes) {
    ibgpconfig();   /* setup [rfc1966] */
    bnp = bgb;
    while(bnp) {
      if (!(bnp->rp_mode & BGPO_PASSIVE))
	bgp_connect_start(bnp);                /* "bnp" won't be lost */
      if ((bnp = bnp->rp_next) == bgb)
	break;
    }
  }

  if (ripyes)
    rip_query_dump();


  if (ospfyes)
    ospf_init();
  
  main_listen_accept();


  /* NOT REACHED */
  return 1;
}



/*
 *
 *  main_listen_accept() - process an incoming connection.
 *                          called by main() only once.
 */
void
main_listen_accept()
{
  int    s;                          /* accepted descriptor    */
  struct sockaddr_in6 fromaddr;      /* accepted address       */
  int                 fromaddrlen;
  int                   myaddrlen;   /* length of my address   */
  struct rpcb          *bnp;
#ifdef ADVANCEDAPI
  int                   on;          /* socket option          */
#endif

#ifdef DEBUG
  char                in6txt[INET6_ADDRSTRLEN];
#endif

  extern struct rpcb *bgb;
  extern int          bgpsock, ripsock, ospfsock;

  memset(&fromaddr, 0, sizeof(fromaddr));
#ifdef DEBUG
  memset(in6txt,    0, INET6_ADDRSTRLEN);
#endif

  while (1) {                                            /* outer */
    sigset_t set, oset;

    while (1) {
      FD_COPY(&fdmask, &currentmask);

      if (do_dump) {		/* SIGUSR1 */
	      do_dump = 0;
	      bgpd_dump_file();
      }

      if (select(FD_SETSIZE, &currentmask, NULL,NULL,NULL) < 0) {
	if (errno == EINTR) {
	  /* interrupted by SIGALRM */
	} else {
	  fatal("<main_listen_accept>: select");
	}
      } else {
	/* an Event occurs.  break inner while */
	break;
      }
    }

    sigemptyset(&oset);
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    if ((sigprocmask(SIG_BLOCK, &set, &oset)) != 0)
      fatal("<main_listen_accept>: sigprocmask");



    /*
     *   Passive open BGP connection:  accept()
     */
    if (bgpyes &&
	FD_ISSET(bgpsock, &currentmask)) {
      int alen;

      /* purge ancillary data (if any) on the listening socket */
      if (ioctl(bgpsock, FIONREAD, &alen) <0)/* XXX is there a smarter way? */
	fatal("<main_listen_accept>: ioctl(FIONREAD)");
      if (alen > 0) {
	      if (read(bgpsock, NULL, 0) < 0)
		      fatal("<main_listen_accept>: read on the listening socket");
	      /* XXX: make sure to purge all ancillary data before accepting */
	      continue;
      }

      /*
       * Accept the BGP connection.
       */
      fromaddrlen = sizeof(fromaddr);
      if ((s = accept(bgpsock,
		      (struct sockaddr *)&fromaddr,
		      (int *)&fromaddrlen)) < 0) {
	fatal("<main_listen_accept>: accept");
      }

      bnp = bgp_new_peer();
      bnp->rp_mode   |= BGPO_PASSIVE;
      bnp->rp_socket  = s;
      bnp->rp_addr    = fromaddr;          /* copy */  /* passive */

#ifdef DEBUG
      syslog(LOG_DEBUG, "<main_listen_accept>: %s now accepted",
	     inet_ntop(AF_INET6, &bnp->rp_addr.sin6_addr,
		       in6txt, INET6_ADDRSTRLEN));
#endif
      if (IN6_IS_ADDR_LINKLOCAL(&fromaddr.sin6_addr))
	bnp->rp_laddr = fromaddr.sin6_addr; /* copy */
      else
	bnp->rp_gaddr = fromaddr.sin6_addr; /* ummh */

      {
	    struct ifinfo *ife_dummy = NULL; /* XXX */
	    if (in6_is_addr_onlink(&fromaddr.sin6_addr, &ife_dummy))
		    bnp->rp_mode |= BGPO_ONLINK;
      }

      insque(bnp, bgb);

      /*  my address  (insufficient information) */
      myaddrlen = sizeof(bnp->rp_myaddr);
      if (getsockname(bnp->rp_socket,
		      (struct sockaddr *)&bnp->rp_myaddr, &myaddrlen) != 0) {
	fatal("<main_listen_accept>: getsockname");
      }
#ifdef ADVANCEDAPI
      on = 1;
#ifdef IPV6_RECVPKTINFO
      if (setsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		     &on, sizeof(on)) < 0)
	fatal("<main_listen_accept>: setsockopt(IPV6_RECVPKTINFO)");
#endif /* old adv. API */
      if (setsockopt(bnp->rp_socket, IPPROTO_IPV6, IPV6_PKTINFO,
		     &on, sizeof(on)) < 0)
	fatal("<main_listen_accept>: setsockopt(IPV6_PKTINFO)");
#endif

      bgp_send_open(bnp);
    }   /* End of "bgpsock" */

    /* Check BGP external-links of their discriptors */
    if (bgpyes) {
      bnp = bgb;
      while(bnp) {
	if (bnp->rp_socket != -1) {        /* Skip which is idling */

	  if (FD_ISSET(bnp->rp_socket, &currentmask)) {

	    FD_CLR(bnp->rp_socket, &currentmask);
	    bgp_input(bnp);

	    if ((bnp = bgb) ==  NULL)  /* peers-queue maybe changed */
	      break;
	    else
	      continue;
	  }
	}
	if ((bnp = bnp->rp_next) == bgb)
	  break;
      }
    }

    /* Check RIP  */
    if (ripyes) {
      if (FD_ISSET(ripsock, &currentmask))
	rip_input();
    }


    /* Check OSPF  */
    if (ospfyes) {
      if (FD_ISSET(ospfsock, &currentmask))
	ospf_input();
    }

    /* check parent/child pipe... for connect() */
    if (bgpyes) {
      bnp = bgb;
      while(bnp) {
	if (bnp->rp_sfd[0] != -1) {        /* Skip which is no use */

	  if (FD_ISSET(bnp->rp_sfd[0], &currentmask)) {

	    FD_CLR(bnp->rp_sfd[0], &currentmask);
	    connect_process(bnp);

	    if ((bnp = bgb) ==  NULL)  /* peers-queue maybe changed */
	      break;
	    else
	      continue;
	  }
	}
	if ((bnp = bnp->rp_next) == bgb)
	  break;
      }
    }


    if ((sigprocmask(SIG_UNBLOCK, &set, &oset)) != 0)
      fatal("<main_listen_accept>: sigprocmask");

  }  /* while (outer) */


  fatalx("<main_listen_accept>: invalidly reached.");
}

/*
 *   alarm_handler()
 */
void 
alarm_handler()
{
  switch (taskhead->tsk_timename) {
  case BGP_CONNECT_TIMER:
    switch (taskhead->tsk_bgp->rp_state) {
    case BGPSTATE_CONNECT : case BGPSTATE_ACTIVE : 
      connect_try(taskhead->tsk_bgp);
      break;
    default:
      fatalx("<alarm_handler>: unexpected bgp-status");
      break;
    }
    break;

  case BGP_HOLD_TIMER:
    bgp_holdtimer_expired(taskhead);
    break;

  case BGP_KEEPALIVE_TIMER:
    switch (taskhead->tsk_bgp->rp_state) {
    case BGPSTATE_OPENCONFIRM : case BGPSTATE_ESTABLISHED : 
      bgp_send_keepalive(taskhead->tsk_bgp);
      break;
    default:
      fatalx("<alarm_handler>: unexpected bgp-status");
      break;
    }
    break;

  case RIP_DUMP_TIMER:
    rip_dump();
    break;
  case RIP_LIFE_TIMER:
    rip_life_expired();
    break;
  case RIP_GARBAGE_TIMER:
    rip_garbage_expired();
    break;

  case OSPF_HELLO_TIMER:
    ospf_hello();
    break;

  default:
    fatalx("<alarm_handler>: invalid timer name");
  }
}

/*
 *  pipe_handler()
 */
void pipe_handler()
{
#ifdef DEBUG
  syslog(LOG_DEBUG, "SIGPIPE received.");
#endif

  return;
}

/*
 * bgpd_set_dump_file()
 * signal handler for SIGUSR1. Set 
 */
static void
bgpd_set_dump_file()
{
	do_dump = 1;
}

/*
 *  fatal()
 */
void
fatal(msg)
        char    *msg;
{
        perror(msg);
        syslog(LOG_ERR, "%s: %s", msg, strerror(errno));
        bgpdexit();
}

void
fatalx(msg)
	char *msg;
{
	fprintf(stderr, "%s\n", msg);
	syslog(LOG_ERR, "%s", msg);
	bgpdexit();
}

/* debugging log  */
void
dperror(msg)
        char    *msg;
{
        perror(msg);
        syslog(LOG_ERR, "%s: %s", msg, strerror(errno));
}


/*
 *   bgpdexit()
 */
void
bgpdexit()
{
  struct rpcb         *bnp;
  struct ripif        *ripif;
  struct ifinfo *ife;

  extern int           bgpsock;
  extern struct rpcb  *bgb;
  extern struct ripif *ripifs;

  alarm(0);  /* turns off any scheduled alarm. */

  if (bgpyes) {
    bnp = bgb;
    while(bnp) {
      bgp_send_notification(bnp, BGP_CEASE, BGP_ERR_UNSPEC, 0, NULL);
      bgp_flush(bnp);
      if ((bnp = bnp->rp_next) == bgb)
	break;
    }
    close(bgpsock);
  }

  if (ripyes) {
    ripif = ripifs;
    while(ripif) {
      while(ripif->rip_adj_ribs_in)
	rip_erase_rte(ripif->rip_adj_ribs_in);
      if ((ripif = ripif->rip_next) == ripifs)
	break;
    }
  }

  /* removed all static routes */
  ife = ifentry;
  while(ife) {
	  struct rt_entry *irte;

	  irte = ife->ifi_rte;
	  while(irte) {
		  if (irte->rt_flags & (RTF_BGPDIFSTATIC | RTF_BGPDGWSTATIC))
			  (void)delroute(irte, NULL);

		  if ((irte = irte->rt_next) == ife->ifi_rte)
			  break;
	  }

	  if ((ife = ife->ifi_next) == ifentry)
		  break;
  }

  terminate();
}

/*
 *   terminate()
 */
void
terminate() 
{
  close(rtsock);
  syslog(LOG_NOTICE, "IPv6 routing Terminated *************************");
  closelog();
  unlink(PIDFILENAME);
  exit(1);
}
