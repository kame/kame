/*
 * ipsec.c: PF_KEY/SPMIF interface with racoon2 framework
 * Francis.Dupont@fdupont.fr, August 2006
 */

#define	IPSEC_BUL_AFTER_BA
#undef	IPSEC_BUL_IDASAP

#ifdef MIP_IPSEC
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <stdarg.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/pfkeyv2.h>
#ifndef SADB_X_MIGRATE
#error "SADB_X_MIGRATE must be defined!"
#endif

#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_var.h>
#endif
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif /* __NetBSD__ */
#include <net/mipsock.h>
#include <netinet/in.h>
#include <netinet/ip6mh.h>
#include <netinet/ip6.h>
#include <netinet6/mip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "callout.h"
#include "stat.h"
#include "shisad.h"
#include "fsm.h"

#define HAVE_STDARG_H 1
#define HAVE_SA_LEN 1
#define HAVE_FUNC_MACRO 1

#include "racoon.h"

#ifdef MIP_MN
static int sadb_add_callback(struct rcpfk_msg *);
#endif
static int sadb_x_migrate_callback(struct rcpfk_msg *);

#ifdef MIP_HA
static int is_matching(struct rc_addrlist *, struct in6_addr *);
static int bc_request_add(struct binding_cache *);
static int bc_request_remove(struct binding_cache *);
static int bc_request_update(struct binding_cache *);
#endif
#ifdef MIP_MN
static int bul_request_add(struct binding_update_list *);
static int bul_request_remove(struct binding_update_list *);
static int bul_request_update(struct binding_update_list *);
static int bul_requestaba_add(struct binding_update_list *);
static int bul_requestaba_remove(struct binding_update_list *);
static int bul_requestaba_update(struct binding_update_list *);
#endif
static void policy_add(struct rcf_selector *);
static void policy_delete(struct rcf_selector *);
static void migrate(struct rcf_selector *, struct in6_addr *,
		    struct in6_addr *);
static int policy_add_callback(void *, int);
static int policy_delete_callback(void *, int);
static int migrate_callback(void *, int);

static int sadbsock = 1;		/* PF_KEY socket */
static int spmifsock = 1;		/* SPMIF socket */

#ifdef MIP_HA
LIST_HEAD(, ipsec_mn) ipsec_mn_head;	/* IPsec MN info list */
#endif
#ifdef MIP_MN
LIST_HEAD(, ipsec_ha) ipsec_ha_head;	/* IPsec HA info list */
#endif

static struct rcpfk_cb rcpfk_callback =	/* PF_KEY callbacks */
{
	0,		/* getspi */
	0,		/* update */
#ifdef MIP_MN
	sadb_add_callback,
#else
	0,		/* add */
#endif
	0,		/* expire */
	0,		/* acquire */
	0,		/* delete */
	0,		/* get */
	0,		/* spdupdate */
	0,		/* spdadd */
	0,		/* spddelete */
	0,		/* spddelete2 */
	0,		/* spdexpire */
	0,		/* spdget */
	0,		/* spddump */
	sadb_x_migrate_callback,
};

/* init */

int
ipsec_init(char *conffile)
{
	struct rcpfk_msg param;

	if (rcf_read(conffile, 0) < 0) {
		syslog(LOG_ERR, "can't parse ipsecconfigfile %s\n", conffile);
		return -1;
	}

	param.flags = 0;
	if (rcpfk_init(&param, &rcpfk_callback) != 0)
		return -1;
	sadbsock = param.so;
	if (debug)
		syslog(LOG_INFO, "sadbsock: %d\n", sadbsock);

	spmifsock = spmif_init();
	if (debug)
		syslog(LOG_INFO, "spmifsock: %d\n", spmifsock);
	if (spmifsock < 0)
		return -1;

#ifdef MIP_HA
	LIST_INIT(&ipsec_mn_head);
#endif
#ifdef MIP_MN
	LIST_INIT(&ipsec_ha_head);
#endif

	return 0;
}

/* fini */

void
ipsec_clean(void)
{
	struct rcpfk_msg param;

	(void)spmif_post_quit(spmifsock);
	spmif_clean(spmifsock);
	spmifsock = -1;

	bzero(&param, sizeof(param));
	param.so = sadbsock;
	(void) rcpfk_clean(&param);
	sadbsock = -1;

	(void) rcf_clean();
}

/* return the PF_KEY socket */

int
sadb_socket(void)
{
	return sadbsock;
}

/* return the SPMIF socket */

int
spmif_socket(void)
{
	return spmifsock;
}

/* some input available for PF_KEY */

int
sadb_poll(int fd)
{
	struct rcpfk_msg param;

	if (fd != sadbsock) {
		syslog(LOG_ERR, "sadb_poll on bad socket\n");
		return -1;
	}

	bzero(&param, sizeof(param));
	param.so = fd;
#ifdef MIP_MN
	param.flags = PFK_FLAG_SEEADD;
#endif
	if (rcpfk_handler(&param) != 0) {
		syslog(LOG_ERR, "sadb_poll: %s\n",
		       param.eno ? param.estr : "unknown error");
		return  -1;
	}

	return 0;
}

/* some input available for SPMIF */

int
spmif_poll(int fd)
{
	if (fd != spmifsock) {
		syslog(LOG_ERR, "spmif_poll on bad socket\n");
		return -1;
	}
	if (spmif_handler(fd) != 0) {
		syslog(LOG_ERR, "spmd I/F broken: fatal!\n");
		(void) kill(getpid(), SIGTERM);
	}
	return 0;
}		

/* check keymanagement get sysctl variable net.inet6.mip6.use_ipsec */

int
use_ipsec(void)
{
	int mib[4], flag;
	size_t len;
	extern int keymanagement;

	if (keymanagement == 0) {
		if (debug)
			syslog(LOG_INFO, "keymanagement is off\n");
		return 0;
	}

	mib[0] = CTL_NET;
	mib[1] = PF_INET6;
	mib[2] = IPPROTO_MH;
	mib[3] = MIP6CTL_USE_IPSEC;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
		syslog(LOG_ERR, "%s sysctl() %s",
		       __FUNCTION__, strerror(errno));
		return 0;
	}
	if (len != sizeof(int)) {
		syslog(LOG_ERR, "%s sysctl() bad length\n", __FUNCTION__);
		return 0;
	}
	if (sysctl(mib, 4, &flag, &len, NULL, 0) < 0) {
		syslog(LOG_ERR, "%s sysctl() %s",
		       __FUNCTION__, strerror(errno));
		return 0;
	}
	if (len != sizeof(int)) {
		syslog(LOG_ERR, "%s sysctl() bad length?\n", __FUNCTION__);
		return 0;
	}
	if (flag == 0) {
		if (debug)
			syslog(LOG_INFO, "use_ipsec is off\n");
		return 0;
	}

	mib[3] = MIP6CTL_USE_MIGRATE;

	if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
		syslog(LOG_ERR, "%s sysctl() %s",
		       __FUNCTION__, strerror(errno));
		return 0;
	}
	if (len != sizeof(int)) {
		syslog(LOG_ERR, "%s sysctl() bad length\n", __FUNCTION__);
		return 0;
	}
	if (sysctl(mib, 4, &flag, &len, NULL, 0) < 0) {
		syslog(LOG_ERR, "%s sysctl() %s",
		       __FUNCTION__, strerror(errno));
		return 0;
	}
	if (len != sizeof(int)) {
		syslog(LOG_ERR, "%s sysctl() bad length?\n", __FUNCTION__);
		return 0;
	}
	if (flag != 0) {
		if (debug)
			syslog(LOG_INFO, "use_migrate is on\n");
		return 0;
	}
	return 1;
}

#ifdef MIP_MN

/* callback function on SADB_ADD */

static
int sadb_add_callback(struct rcpfk_msg *rc)
{
	/*
	 * The idea is to look at if the new SA is for a pending HRBU
	 */
	struct binding_update_list *bul;
	struct in6_addr *sa, *da;

	if (debug)
		syslog(LOG_INFO, "see an ADD for SPI %d\n", rc->spi);

	/* suitable IPsec SA? */
	if (!rc || rc->satype != RCT_SATYPE_ESP ||
	    rc->samode == RCT_IPSM_TUNNEL ||
	    !rc->sa_src || rc->sa_src->sa_family != AF_INET6 ||
	    !rc->sa_dst || rc->sa_dst->sa_family != AF_INET6)
		return 0;
	sa = &((struct sockaddr_in6 *)rc->sa_src)->sin6_addr;
	da = &((struct sockaddr_in6 *)rc->sa_src)->sin6_addr;

	if (debug)
		syslog(LOG_INFO, "SA from %s to %s\n",
		       ip6_sprintf(sa), ip6_sprintf(da));

	/* get the HR BUL from the hoa */
	bul = bul_get_homeflag(sa);
	if (bul == NULL || !IN6_ARE_ADDR_EQUAL(da, &bul->bul_peeraddr))
		return 0;

	/* send the HR BU */
	if (send_bu(bul) < 0)
		return 0;

	bul_set_retrans_timer(bul, bul->bul_retrans_time);
	return 0;
}
#endif

/* callback function on SADB_X_MIGRATE */

static int
sadb_x_migrate_callback(struct rcpfk_msg *rc)
{
	struct rcf_selector *s;
	struct rcf_policy *p;
	extern struct rcf_selector *rcf_selector_head;

	if (rc->sa_src->sa_family != AF_INET6 ||
	    rc->sa_dst->sa_family != AF_INET6)
		return 0;

	if ((rcs_cmpsa(rc->sa_src, rc->sa2_src) == 0) &&
	     (rcs_cmpsa(rc->sa_dst, rc->sa2_dst) == 0))
		return 0;

	/* migrate the primary selector */

	for (s = rcf_selector_head; s; s = s->next) {
		if (rc->dir != s->direction)
			continue;
		/* XXX match only on the reqid! */
		if (rc->reqid != s->reqid)
			continue;
		p = s->pl;
		if (p == NULL)
			continue;
		if (p->my_sa_ipaddr == NULL ||
		    p->my_sa_ipaddr->type != RCT_ADDR_INET)
			continue;
		if (p->peers_sa_ipaddr == NULL ||
		    p->peers_sa_ipaddr->type != RCT_ADDR_INET)
			continue;

		bcopy(&((struct sockaddr_in6 *)rc->sa2_src)->sin6_addr,
		      &((struct sockaddr_in6 *)p->my_sa_ipaddr->a.ipaddr)->sin6_addr, 
		       sizeof(struct in6_addr));
		bcopy(&((struct sockaddr_in6 *)rc->sa2_dst)->sin6_addr,
		      &((struct sockaddr_in6 *)p->peers_sa_ipaddr->a.ipaddr)->sin6_addr, 
		       sizeof(struct in6_addr));
		if (debug)
			syslog(LOG_INFO,
			       "move selector(%.*s)\n",
			       (int)s->sl_index->l,
			       s->sl_index->v);
	}
	return 0;
}

/* check if an address list matches */

static int
is_matching(struct rc_addrlist *al, struct in6_addr *addr)
{
	struct sockaddr_in6 *sin6;

	if (al->type != RCT_ADDR_INET)
		return 0;
	if (al->a.ipaddr->sa_family != AF_INET6)
		return 0;
	if (al->prefixlen && al->prefixlen != 128)
		return 0;
	sin6 = (struct sockaddr_in6 *)al->a.ipaddr;
	return IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, addr);
}

#ifdef MIP_HA

struct ipsec_mn {				/* MN related infos */
	LIST_ENTRY(ipsec_mn) chain;		/* chaining */
	struct rcf_remote *rm_info;		/* remote entry */
	struct rcf_selector *sl_out, *sl_in;	/* tunnel selectors */
	struct binding_cache *back;		/* back pointer */
};

/* IPsec BC/MN request */

int
ipsec_bc_request(struct binding_cache *bc, int command)
{
	switch (command) {
	case MIPM_BC_ADD:
		return bc_request_add(bc);
	case MIPM_BC_UPDATE:
		return bc_request_update(bc);
	case MIPM_BC_REMOVE:
		return bc_request_remove(bc);
	case MIPM_BC_FLUSH:
	default:
		syslog(LOG_ERR, "bad ipsec_bc_request command %d\n", command);
		return -1;
	}
}

/* release IPsec related infos for a MN */

void
ipsec_bc_data_release(struct binding_cache *bc)
{
	struct ipsec_mn *mn;

	mn = (struct ipsec_mn *)bc->bc_ipsec_data;
	if (mn == NULL)
		return;

	if (debug)
		syslog(LOG_INFO, "dangling IPsec for %s\n",
		       ip6_sprintf(&bc->bc_hoa));
	if (mn->rm_info)
		rcf_free_remote(mn->rm_info);
	if (mn->sl_out)
		rcf_free_selector(mn->sl_out);
	if (mn->sl_in)
		rcf_free_selector(mn->sl_in);
	LIST_REMOVE(mn, chain);
	bc->bc_ipsec_data = NULL;
	free(mn);
}

/* get IPsec stuff for an incoming MN */

static int
bc_request_add(struct binding_cache *bc)
{
	struct ipsec_mn *mn;
	struct rcf_selector *s, *s_next;

	/* deal only with home registration */
	if ((bc->bc_flags & IP6_MH_BU_HOME) == 0)
		return 0;
	/* XXX not yet MR */
	if (bc->bc_flags & IP6_MH_BU_ROUTER)
		return 0;
#ifdef MIP_MCOA
	/* XXX not yet MCOA (if there is something to do) */
	if (bc->bc_bid)
		return 0;
#endif
	/* XXX is it critical? */
	if (debug && (bc->bc_flags & IP6_MH_BU_KEYM) == 0)
		syslog(LOG_INFO, "%s HRBU has no K flag\n",
		       ip6_sprintf(&bc->bc_hoa));
	/* only primary */
	if (IN6_IS_ADDR_LINKLOCAL(&bc->bc_hoa))
		return 0;

	/* get the ipsec_mn structure */
	mn = (struct ipsec_mn *)bc->bc_ipsec_data;
	if (mn != NULL)
		return 0;
	mn = (struct ipsec_mn *)malloc(sizeof(*mn));
	if (mn == NULL) {
		syslog(LOG_ERR, "failed to allocate ipsec_mn\n");
		return -1;
	}
	bzero(mn, sizeof(*mn));

	/* get the outbound selector */
	if (rcf_get_selectorlist(&s)) {
		syslog(LOG_ERR, "can't get selector list\n");
		goto bad;
	}
	for (; s; s_next = s->next, rcf_free_selector(s), s = s_next) {
		if (mn->sl_out)
			continue;
		if (s->src == NULL || s->dst == NULL)
			continue;
		if (s->pl == NULL || s->pl->ips == NULL)
			continue;
		if (s->direction != RCT_DIR_OUTBOUND)
			continue;
		if (s->reqid == 0 || s->tagged)
			continue;
		if (s->pl->action != RCT_ACT_AUTO_IPSEC ||
		    s->pl->ipsec_mode != RCT_IPSM_TUNNEL ||
		    s->pl->ipsec_level != RCT_IPSL_UNIQUE)
			continue;
		if (s->pl->my_sa_ipaddr == NULL ||
		    s->pl->peers_sa_ipaddr == NULL)
			continue;
		if (s->upper_layer_protocol != IPPROTO_MH &&
		    s->upper_layer_protocol != RC_PROTO_ANY)
			continue;
		if (is_matching(s->src, &bc->bc_myaddr) &&
		    is_matching(s->dst, &bc->bc_hoa))
			mn->sl_out = s;
	}
	if (mn->sl_out == NULL) {
		if (debug)
			syslog(LOG_INFO,
			       "can't get selector for %s\n",
			       ip6_sprintf(&bc->bc_hoa));
		goto bad;
	}

	/* get the inbound selector */
	if (rcf_get_rvrs_selector(mn->sl_out, &mn->sl_in)) {
		if (debug)
			syslog(LOG_INFO,
			       "can't get inbound selector for %s\n",
			       ip6_sprintf(&bc->bc_hoa));
		goto bad;
	}

	/* get the remote entry */
	if (rcf_get_remotebyindex(mn->sl_out->pl->rm_index, &mn->rm_info)) {
		if (debug)
			syslog(LOG_INFO,
			       "can't find remote for %s\n",
			       ip6_sprintf(&bc->bc_hoa));
		goto bad;
	}

	/* check the remote entry */
	if (mn->rm_info->ikev1 &&
	    mn->rm_info->ikev1->mobility_role == RCT_MOB_MN)
		;
	else if (mn->rm_info->ikev2 &&
		 mn->rm_info->ikev2->mobility_role == RCT_MOB_MN)
		;
	else if (mn->rm_info->kink &&
		 mn->rm_info->kink->mobility_role == RCT_MOB_MN)
		;
	else {
		if (debug)
			syslog(LOG_INFO,
			       "%s remote is not for a MN\n",
			       ip6_sprintf(&bc->bc_hoa));
		goto bad;
	}

	/* perform side effects */
	LIST_INSERT_HEAD(&ipsec_mn_head, mn, chain);
	bc->bc_ipsec_data = mn;
	mn->back = bc;
	if (mn->sl_out->pl->install == RCT_BOOL_OFF)
		policy_add(mn->sl_out);

	return 0;

    bad:
	if (mn->rm_info)
		rcf_free_remote(mn->rm_info);
	if (mn->sl_out)
		rcf_free_selector(mn->sl_out);
	if (mn->sl_in)
		rcf_free_selector(mn->sl_in);
	LIST_REMOVE(mn, chain);
	bc->bc_ipsec_data = NULL;
	free(mn);
	return -1;
}

/* remove IPsec stuff for a leaving MN */

static int
bc_request_remove(struct binding_cache *bc)
{
	struct ipsec_mn *mn;
	struct rcf_selector *s;

	mn = (struct ipsec_mn *)bc->bc_ipsec_data;
	if (mn == NULL)
		return 0;

	/* reget selectors */
	if (rcf_get_selector(vmem2str(mn->sl_out->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)mn->sl_out->sl_index->l,
		       mn->sl_out->sl_index->v);
		goto del;
	}
	rcf_free_selector(mn->sl_out);
	mn->sl_out = s;
	if (rcf_get_selector(vmem2str(mn->sl_in->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)mn->sl_in->sl_index->l,
		       mn->sl_in->sl_index->v);
		goto del;
	}
	rcf_free_selector(mn->sl_in);
	mn->sl_in = s;

	/* migrate to home */
	migrate(mn->sl_out, &bc->bc_myaddr, &bc->bc_hoa);
	migrate(mn->sl_in, &bc->bc_hoa, &bc->bc_myaddr);

    del:
	if (mn->sl_out->pl->install == RCT_BOOL_OFF) {
		policy_delete(mn->sl_out);
		policy_delete(mn->sl_in);
	}
	rcf_free_remote(mn->rm_info);
	rcf_free_selector(mn->sl_out);
	rcf_free_selector(mn->sl_in);
	LIST_REMOVE(mn, chain);
	bc->bc_ipsec_data = NULL;
	free(mn);
	return 0;
}

/* update IPsec stuff for a moving MN */

static int
bc_request_update(struct binding_cache *bc)
{
	struct ipsec_mn *mn;
	struct rcf_selector *s;

	mn = (struct ipsec_mn *)bc->bc_ipsec_data;
	if (mn == NULL)
		return 0;

	/* reget selectors */
	if (rcf_get_selector(vmem2str(mn->sl_out->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)mn->sl_out->sl_index->l,
		       mn->sl_out->sl_index->v);
		return -1;
	}
	rcf_free_selector(mn->sl_out);
	mn->sl_out = s;
	if (rcf_get_selector(vmem2str(mn->sl_in->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)mn->sl_in->sl_index->l,
		       mn->sl_in->sl_index->v);
		return -1;
	}
	rcf_free_selector(mn->sl_in);
	mn->sl_in = s;

	/* migrate */
	migrate(mn->sl_out, &bc->bc_myaddr, &bc->bc_coa);
	migrate(mn->sl_in, &bc->bc_coa, &bc->bc_myaddr);

	return 0;
}

#endif

#ifdef MIP_MN

struct ipsec_ha {				/* HA related infos */
	LIST_ENTRY(ipsec_ha) chain;		/* chaining */
	struct rcf_remote *rm_info;		/* remote entry */
	struct rcf_selector *sl_out, *sl_in;	/* tunnel selectors */
	struct binding_update_list *back;	/* back pointer */
};

/* IPsec BUL/HA request */

int
ipsec_bul_request(struct binding_update_list *bul, int command)
{
	switch (command) {
	case MIPM_BUL_ADD:
		return bul_request_add(bul);
	case MIPM_BUL_UPDATE:
		return bul_request_update(bul);
	case MIPM_BUL_REMOVE:
		return bul_request_remove(bul);
	case MIPM_BUL_ADD | MIPM_BUL_AFTER_BA:
		return bul_requestaba_add(bul);
	case MIPM_BUL_UPDATE | MIPM_BUL_AFTER_BA:
		return bul_requestaba_update(bul);
	case MIPM_BUL_REMOVE | MIPM_BUL_AFTER_BA:
		return bul_requestaba_remove(bul);
	case MIPM_BUL_FLUSH:
	case MIPM_BUL_FLUSH | MIPM_BUL_AFTER_BA:
	default:
		syslog(LOG_ERR, "bad ipsec_bul_request command %x\n", command);
		return -1;
	}
}

/* release IPsec related infos for an HA */

void
ipsec_bul_data_release(struct binding_update_list *bul)
{
	struct ipsec_ha *ha;

	ha = (struct ipsec_ha *)bul->bul_ipsec_data;
	if (ha == NULL)
		return;

	syslog(LOG_INFO, "dangling IPsec for %s\n",
	       ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
	if (ha->rm_info)
		rcf_free_remote(ha->rm_info);
	if (ha->sl_out)
		rcf_free_selector(ha->sl_out);
	if (ha->sl_in)
		rcf_free_selector(ha->sl_in);
	LIST_REMOVE(ha, chain);
	bul->bul_ipsec_data = NULL;
	free(ha);
}

/* get IPsec stuff for a new HA */

static int
#ifdef IPSEC_BUL_AFTER_BA
bul_request_add(struct binding_update_list *bul)
#endif
#ifdef IPSEC_BUL_IDASAP
bul_requestaba_add(struct binding_update_list *bul)
#endif
{
	return 0;
}

static int
#ifdef IPSEC_BUL_AFTER_BA
bul_requestaba_add(struct binding_update_list *bul)
#endif
#ifdef IPSEC_BUL_IDASAP
bul_request_add(struct binding_update_list *bul)
#endif
{
	struct ipsec_ha *ha;
	struct rcf_selector *s, *s_next;

	/* deal only with HAs */
	if ((bul->bul_flags & IP6_MH_BU_HOME) == 0)
		return 0;
	/* XXX not yet MR */
	if (bul->bul_flags & IP6_MH_BU_ROUTER)
		return 0;
#ifdef MIP_MCOA
	/* XXX not yet MCOA (if there is something to do) */
	if (bul->bul_bid)
		return 0;
#endif
	if (bul->bul_hoainfo == NULL) {
		syslog(LOG_ERR, "bul without hoainfo?!\n");
		return -1;
	}
	/* XXX is it critical? */
	if (debug && (bul->bul_flags & IP6_MH_BU_KEYM) == 0)
		syslog(LOG_INFO, "%s HRBU has no K flag\n",
		       ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));

	/* get the ipsec_ha structure */
	ha = (struct ipsec_ha *)bul->bul_ipsec_data;
	if (ha != NULL)
		return 0;
	ha = (struct ipsec_ha *)malloc(sizeof(*ha));
	if (ha == NULL) {
		syslog(LOG_ERR, "failed to allocate ipsec_ha\n");
		return -1;
	}
	bzero(ha, sizeof(*ha));

	/* get the outbound selector */
	if (rcf_get_selectorlist(&s)) {
		syslog(LOG_ERR, "can't get selector list\n");
		goto bad;
	}
	for (; s; s_next = s->next, rcf_free_selector(s), s = s_next) {
		if (ha->sl_out)
			continue;
		if (s->src == NULL || s->dst == NULL)
			continue;
		if (s->pl == NULL || s->pl->ips == NULL)
			continue;
		if (s->direction != RCT_DIR_OUTBOUND)
			continue;
		if (s->reqid == 0 || s->tagged)
			continue;
		if (s->pl->action != RCT_ACT_AUTO_IPSEC ||
		    s->pl->ipsec_mode != RCT_IPSM_TUNNEL ||
		    s->pl->ipsec_level != RCT_IPSL_UNIQUE)
			continue;
		if (s->pl->my_sa_ipaddr == NULL ||
		    s->pl->peers_sa_ipaddr == NULL)
			continue;
		if (s->upper_layer_protocol != IPPROTO_MH &&
		    s->upper_layer_protocol != RC_PROTO_ANY)
			continue;
		if (is_matching(s->src, &bul->bul_hoainfo->hinfo_hoa) &&
		    is_matching(s->dst, &bul->bul_peeraddr))
			ha->sl_out = s;
	}
	if (ha->sl_out == NULL) {
		if (debug)
			syslog(LOG_INFO,
			       "can't get selector for %s\n",
			       ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
		goto bad;
	}

	/* get the inbound selector */
	if (rcf_get_rvrs_selector(ha->sl_out, &ha->sl_in)) {
		if (debug)
			syslog(LOG_INFO,
			       "can't get inbound selector for %s\n",
			       ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
		goto bad;
	}

	/* get the remote entry */
	if (rcf_get_remotebyindex(ha->sl_out->pl->rm_index, &ha->rm_info)) {
		if (debug)
			syslog(LOG_INFO,
			       "can't find remote for %s\n",
			       ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
		goto bad;
	}

	/* check the remote entry */
	if (ha->rm_info->ikev1 &&
	    ha->rm_info->ikev1->mobility_role == RCT_MOB_HA)
		;
	else if (ha->rm_info->ikev2 &&
		 ha->rm_info->ikev2->mobility_role == RCT_MOB_HA)
		;
	else if (ha->rm_info->kink &&
		 ha->rm_info->kink->mobility_role == RCT_MOB_HA)
		;
	else {
		if (debug)
			syslog(LOG_INFO,
			       "%s remote is not for an HA\n",
			       ip6_sprintf(&bul->bul_hoainfo->hinfo_hoa));
		goto bad;
	}

	/* perform side effects */
	LIST_INSERT_HEAD(&ipsec_ha_head, ha, chain);
	bul->bul_ipsec_data = ha;
	ha->back = bul;
	if (ha->sl_out->pl->install == RCT_BOOL_OFF)
		policy_add(ha->sl_out);

	return 0;

    bad:
	if (ha->rm_info)
		rcf_free_remote(ha->rm_info);
	if (ha->sl_out)
		rcf_free_selector(ha->sl_out);
	if (ha->sl_in)
		rcf_free_selector(ha->sl_in);
	LIST_REMOVE(ha, chain);
	bul->bul_ipsec_data = NULL;
	free(ha);
	return -1;
}

/* remove IPsec stuff for an unavailable HA */

static int
#ifdef IPSEC_BUL_AFTER_BA
bul_request_remove(struct binding_update_list *bul)
#endif
#ifdef IPSEC_BUL_IDASAP
bul_requestaba_remove(struct binding_update_list *bul)
#endif
{
	return 0;
}

static int
#ifdef IPSEC_BUL_AFTER_BA
bul_requestaba_remove(struct binding_update_list *bul)
#endif
#ifdef IPSEC_BUL_IDASAP
bul_request_remove(struct binding_update_list *bul)
#endif
{
	struct ipsec_ha *ha;
	struct rcf_selector *s;

	ha = (struct ipsec_ha *)bul->bul_ipsec_data;
	if (ha == NULL)
		return 0;

	/* reget selectors */
	if (rcf_get_selector(vmem2str(ha->sl_out->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)ha->sl_out->sl_index->l,
		       ha->sl_out->sl_index->v);
		goto del;
	}
	rcf_free_selector(ha->sl_out);
	ha->sl_out = s;
	if (rcf_get_selector(vmem2str(ha->sl_in->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)ha->sl_in->sl_index->l,
		       ha->sl_in->sl_index->v);
		goto del;
	}
	rcf_free_selector(ha->sl_in);
	ha->sl_in = s;

	/* migrate to home */
	migrate(ha->sl_out, &bul->bul_hoainfo->hinfo_hoa, &bul->bul_peeraddr);
	migrate(ha->sl_in, &bul->bul_peeraddr, &bul->bul_hoainfo->hinfo_hoa);

    del:
	if (ha->sl_out->pl->install == RCT_BOOL_OFF) {
		policy_delete(ha->sl_out);
		policy_delete(ha->sl_in);
	}
	rcf_free_remote(ha->rm_info);
	rcf_free_selector(ha->sl_out);
	rcf_free_selector(ha->sl_in);
	LIST_REMOVE(ha, chain);
	bul->bul_ipsec_data = NULL;
	free(ha);
	return 0;
}

/* update IPsec stuff for an HA after a movement */

static int
#ifdef IPSEC_BUL_AFTER_BA
bul_request_update(struct binding_update_list *bul)
#endif
#ifdef IPSEC_BUL_IDASAP
bul_requestaba_update(struct binding_update_list *bul)
#endif
{
	return 0;
}

static int
#ifdef IPSEC_BUL_AFTER_BA
bul_requestaba_update(struct binding_update_list *bul)
#endif
#ifdef IPSEC_BUL_IDASAP
bul_request_update(struct binding_update_list *bul)
#endif
{
	struct ipsec_ha *ha;
	struct rcf_selector *s;

	ha = (struct ipsec_ha *)bul->bul_ipsec_data;
	if (ha == NULL)
		return 0;

	/* reget selectors */
	if (rcf_get_selector(vmem2str(ha->sl_out->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)ha->sl_out->sl_index->l,
		       ha->sl_out->sl_index->v);
		return -1;
	}
	rcf_free_selector(ha->sl_out);
	ha->sl_out = s;
	if (rcf_get_selector(vmem2str(ha->sl_in->sl_index), &s) < 0) {
		syslog(LOG_ERR, "Can't reget my selector %.*s\n",
		       (int)ha->sl_in->sl_index->l,
		       ha->sl_in->sl_index->v);
		return -1;
	}
	rcf_free_selector(ha->sl_in);
	ha->sl_in = s;

	/* migrate */
	migrate(ha->sl_out, &bul->bul_coa, &bul->bul_peeraddr);
	migrate(ha->sl_in, &bul->bul_peeraddr, &bul->bul_coa);

	return 0;
}

/* check if IPsec is usable for a correspondent */

int
bul_can_use_ipsec(struct binding_update_list *bul)
{
	struct rcf_selector *s;
	struct rcf_remote *r;
	extern struct rcf_selector *rcf_selector_head;

	/* already checked */
	if (bul->bul_state & MIP6_BUL_STATE_USEIPSEC)
		return 1;

	/* XXX not yet MR */
	if (bul->bul_flags & IP6_MH_BU_ROUTER)
		return 0;
#ifdef MIP_MCOA
	/* XXX not yet MCOA (if there is something to do) */
	if (bul->bul_bid)
		return 0;
#endif
	if (bul->bul_hoainfo == NULL) 
		return 0;

	/* get the outbound selector */
	for (s = rcf_selector_head; s; s = s->next) {
		if (s->src == NULL || s->dst == NULL)
			continue;
		if (s->pl == NULL || s->pl->ips == NULL)
			continue;
		if (s->direction != RCT_DIR_OUTBOUND)
			continue;
		if (s->tagged)
			continue;
		if (s->pl->install != RCT_BOOL_ON &&
		    (bul->bul_flags & IP6_MH_BU_HOME) == 0)
			continue;		/* XXX parano */
		if (s->pl->action != RCT_ACT_AUTO_IPSEC ||
		    s->pl->ipsec_mode != RCT_IPSM_TRANSPORT)
			continue;
		if (s->upper_layer_protocol != IPPROTO_MH &&
		    ((bul->bul_flags & IP6_MH_BU_HOME) ||
		     s->upper_layer_protocol != RC_PROTO_ANY))
			continue;
		if (is_matching(s->src, &bul->bul_hoainfo->hinfo_hoa) &&
		    is_matching(s->dst, &bul->bul_peeraddr))
			break;
	}
	if (s == NULL)
		return 0;
	if (rcf_get_remotebyindex(s->pl->rm_index, &r))
		return 0;
	if (r->ikev1 &&
	    (r->ikev1->mobility_role == RCT_MOB_CN ||
	     r->ikev1->mobility_role == RCT_MOB_HA))
		;
	else if (r->ikev2 &&
	    (r->ikev2->mobility_role == RCT_MOB_CN ||
	     r->ikev2->mobility_role == RCT_MOB_HA))
		;
	else if (r->kink &&
	    (r->kink->mobility_role == RCT_MOB_CN ||
	     r->kink->mobility_role == RCT_MOB_HA))
		;
	else {
		rcf_free_remote(r);
		return 0;
	}
	rcf_free_remote(r);

#if 0
	bul->bul_state |= MIP6_BUL_STATE_USEIPSEC;
#endif
	return 1;
}

#endif

/* add policies */

static void
policy_add(struct rcf_selector *s)
{
	(void) spmif_post_policy_add(spmifsock,
				     policy_add_callback,
				     s,
				     s->sl_index,
				     0L,
				     RCT_IPSM_TUNNEL,
				     s->src->a.ipaddr,
				     s->dst->a.ipaddr,
				     s->pl->my_sa_ipaddr->a.ipaddr,
				     s->pl->peers_sa_ipaddr->a.ipaddr);
}

/* delete a policy */

static void
policy_delete(struct rcf_selector *s)
{
	(void) spmif_post_policy_delete(spmifsock,
					policy_delete_callback,
					s,
					s->sl_index);
}

static void
migrate(struct rcf_selector *s, struct in6_addr *sa, struct in6_addr *da)
{
	struct sockaddr_in6 nsrc, ndst;

	bzero(&nsrc, sizeof(nsrc));
	nsrc.sin6_family = AF_INET6;
	nsrc.sin6_len = sizeof(nsrc);
	bcopy(sa, &nsrc.sin6_addr, sizeof(*sa));
	bzero(&ndst, sizeof(ndst));
	ndst.sin6_family = AF_INET6;
	ndst.sin6_len = sizeof(ndst);
	bcopy(da, &ndst.sin6_addr, sizeof(*da));

	(void) spmif_post_migrate(spmifsock,
				  migrate_callback,
				  s,
				  s->sl_index,
				  s->pl->my_sa_ipaddr->a.ipaddr,
				  s->pl->peers_sa_ipaddr->a.ipaddr,
				  (struct sockaddr *)&nsrc,
				  (struct sockaddr *)&ndst);
}

/* policy_add callback */

static int
policy_add_callback(void *tag, int result)
{
	struct rcf_selector *s = (struct rcf_selector *)tag;

	if (result < 0 && debug)
		syslog(LOG_INFO,
		       "policy add failed for selector %.*s\n",
		       (int)s->sl_index->l, s->sl_index->v);
	return result;
}

/* policy_delete callback */

static int
policy_delete_callback(void *tag, int result)
{
	struct rcf_selector *s = (struct rcf_selector *)tag;

	if (result < 0 && debug)
		syslog(LOG_INFO,
		       "policy delete failed for selector %.*s\n",
		       (int)s->sl_index->l, s->sl_index->v);
	return result;
}

/* migrate callback */

static int
migrate_callback(void *tag, int result)
{
	struct rcf_selector *s = (struct rcf_selector *)tag;

	if (result < 0 && debug)
		syslog(LOG_INFO,
		       "x_migrate failed for selector %.*s\n",
		       (int)s->sl_index->l, s->sl_index->v);
	return result;
}

#endif
