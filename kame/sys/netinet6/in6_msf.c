/*	$KAME: in6_msf.c,v 1.41 2006/09/05 04:25:48 suz Exp $	*/

/*
 * Copyright (c) 2002 INRIA. All rights reserved.
 *
 * Implementation of Multicast Listener Discovery, Version 2.
 * Developed by Hitoshi Asaeda, INRIA, August 2002.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of INRIA nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

#ifdef __FreeBSD__
#include "opt_inet6.h"
#include "opt_mrouting.h"
#endif

#if defined(__NetBSD__)
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/protosw.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/mld6_var.h>
#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <netinet6/in6_pcb.h>
#endif
#include <net/net_osdep.h>
#include <netinet6/in6_msf.h>

#ifdef HAVE_NRL_INPCB
#define in6pcb		inpcb
#define in6p_moptions	inp_moptions6
#endif

#ifdef MLDV2

#define I6AS_LIST_ALLOC(iasl) do {					\
	MALLOC((iasl), struct in6_addr_slist *,				\
		sizeof(struct in6_addr_slist), M_MSFILTER, M_NOWAIT);	\
	if ((iasl) == NULL) {						\
		error = ENOBUFS;					\
		break;							\
	}								\
	bzero((iasl), sizeof(struct in6_addr_slist));			\
	MALLOC((iasl)->head, struct i6as_head *,			\
		sizeof(struct i6as_head), M_MSFILTER, M_NOWAIT);	\
	if ((iasl)->head == NULL) {					\
		FREE((iasl), M_MSFILTER);				\
		error = ENOBUFS;					\
		break;							\
	}								\
	LIST_INIT((iasl)->head);					\
	(iasl)->numsrc = 0;						\
} while (/*CONSTCOND*/ 0)

#define	IN6M_SOURCE_LIST(mode)						\
	(((mode) == MCAST_INCLUDE) ? in6m->in6m_source->i6ms_in		\
				   : in6m->in6m_source->i6ms_ex)
#define IN6M_SOURCE_LIST_NONALLOC(mode)					\
	(IN6M_SOURCE_LIST(mode) == NULL ||				\
	(mode == MCAST_INCLUDE &&					\
	    LIST_EMPTY(in6m->in6m_source->i6ms_in->head)) ||		\
	(mode == MCAST_EXCLUDE &&					\
	    LIST_EMPTY(in6m->in6m_source->i6ms_ex->head)))

#define	in6mm_src	in6m->in6m_source
#define	IN6M_LIST_EMPTY(name)						\
	((in6mm_src->i6ms_##name == NULL) ||				\
	 ((in6mm_src->i6ms_##name != NULL) &&				\
	  (in6mm_src->i6ms_##name->numsrc == 0)))

static int in6_merge_msf_head(struct in6_multi *, struct in6_addr_slist *,
			      u_int, u_int);
static void in6_undo_new_msf_curhead(struct in6_multi *,
				     struct sockaddr_in6 *);
static void in6_clear_pending_report(struct in6_multi *, u_int);
static int in6_merge_pending_report(struct in6_multi *,
				    struct in6_addr_source *, u_int8_t);
static int in6_copy_msf_source_list(struct in6_addr_slist *,
				    struct in6_addr_slist *, u_int);

/*
 * Add source addresses to multicast address record.
 */
int
in6_addmultisrc(in6m, numsrc, ss, mode, init, newhead, newmode, newnumsrc)
	struct in6_multi *in6m;
	u_int16_t numsrc;
	struct sockaddr_storage *ss;
	u_int mode;
	int init;
	struct i6as_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in6_addr_slist *iasl;
	struct in6_addr_source *ias;
	u_int16_t *fnumsrc = NULL;
	u_int16_t i, j;
	int ref_count;
	int error = 0;

	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;

	if (in6m->in6m_source == NULL) {
		/*
		 * Even if upstream router does not control MLDv2, in6m_source
		 * is allocated, in order to change the behavior to an MLDv2
		 * capable node gracefully.
		 */
		MALLOC(in6m->in6m_source, struct in6_multi_source *,
				sizeof(struct in6_multi_source),
				M_MSFILTER, M_NOWAIT);
		if (in6m->in6m_source == NULL)
			return ENOBUFS;
		bzero(in6m->in6m_source, sizeof(struct in6_multi_source));

		MALLOC(in6m->in6m_source->i6ms_timer_ch, struct callout *,
		    sizeof(struct callout), M_MSFILTER, M_NOWAIT);
		if (in6m->in6m_source->i6ms_timer_ch == NULL) {
			FREE(in6m->in6m_source, M_MSFILTER);
			return ENOBUFS;
		}
#ifdef __FreeBSD__
		callout_init(in6m->in6m_source->i6ms_timer_ch, 0);
#elif defined(__NetBSD__)
		callout_init(in6m->in6m_source->i6ms_timer_ch);
#elif defined(__OpenBSD__)
		bzero(in6m->in6m_source->i6ms_timer_ch, sizeof(struct callout));
#endif

		I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_cur);
		if (error != 0) {
			FREE(in6m->in6m_source->i6ms_timer_ch, M_MSFILTER);
			FREE(in6m->in6m_source, M_MSFILTER);
			return error;
		}
		I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_rec);
		if (error != 0) {
			FREE(in6m->in6m_source->i6ms_cur->head, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_cur, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_timer_ch, M_MSFILTER);
			FREE(in6m->in6m_source, M_MSFILTER);
			return error;
		}
		in6m->in6m_source->i6ms_mode = MCAST_INCLUDE;
		in6m->in6m_source->i6ms_grpjoin = 0;
		in6m->in6m_source->i6ms_timer = 0;
		in6m->in6m_source->i6ms_robvar = 0;
		in6m->in6m_state = MLD_OTHERLISTENER;
	}

	/*
	 * If numsrc is 0, mode must be MCAST_EXCLUDE here, which
	 * means (*,G) join. In this case, skip an initial process
	 * to create source list head.
	 */
	i = j = 0;
	if (numsrc == 0) {
		if (mode != MCAST_EXCLUDE)
			return EINVAL;
		goto after_source_list_addition;
	}
	if (ss == NULL) {
		return EINVAL;
	}

	if (IN6M_SOURCE_LIST_NONALLOC(mode)) {
		for (; i < numsrc; i++) {
			if (IN6_IS_ADDR_UNSPECIFIED(&SIN6(&ss[0])->sin6_addr))
				continue;
			MALLOC(ias, struct in6_addr_source *, sizeof(*ias),
				M_MSFILTER, M_NOWAIT);
			if (ias == NULL)
				return ENOBUFS;

			bcopy(&ss[0], &ias->i6as_addr, ss[0].ss_len);
			ias->i6as_refcount = 1;
			if (IN6M_SOURCE_LIST(mode) == NULL) {
				if (mode == MCAST_INCLUDE)
					I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_in);
				else
					I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_ex);
				if (error != 0) {
					FREE(ias, M_MSFILTER);
					return error;
				}
			}
			if (mode == MCAST_INCLUDE)
				LIST_INSERT_HEAD(in6m->in6m_source->i6ms_in->head,
				    ias, i6as_list);
			else
				LIST_INSERT_HEAD(in6m->in6m_source->i6ms_ex->head,
				    ias, i6as_list);
			j = 1; /* the number of added source */
			break;
		}
		if (i == numsrc)
			return EINVAL;

		++i; /* the number of checked sources */
	}

	iasl = IN6M_SOURCE_LIST(mode);
	fnumsrc = &iasl->numsrc;
	/* the number of sources is limited */
	if (*fnumsrc >= mldmaxsrcfilter) {
		mldlog((LOG_DEBUG, "in6_addmultisrc: number of source already reached max filter count.\n"));
		return EINVAL; /* XXX */
	}

	for (; i < numsrc; i++) {
		if (SS_IS_ADDR_UNSPECIFIED((struct sockaddr *)&ss[i]))
			continue; /* skip */
		ref_count = in6_merge_msf_source_addr(iasl, SIN6(&ss[i]),
						      IMS_ADD_SOURCE);
		if (ref_count < 0) {
			in6_undomultisrc(in6m, i, ss, mode, IMS_ADD_SOURCE);
			return ENOBUFS;
		} else if (ref_count != 1)
			continue;

		/* ref_count == 1 means new source */
		++j; /* the number of added sources  */
		if ((*fnumsrc + j) == mldmaxsrcfilter) {
			/*
			 * XXX Kernel accepts to keep as many requested
			 * sources as possible. It tries to fit sources
			 * within a rest of the number of the limitation,
			 * and after reaching max, it stops insertion with
			 * returning no error.
			 * This is implementation specific issue.
			 */
			++i; /* adjusted the number of srcs */
			mldlog((LOG_DEBUG, "in6_addmultisrc: number of source is over max filter count. Adjusted.\n"));
			break;
		}
	}

after_source_list_addition:
	/*
	 * When mode is EXCLUDE, and it's an initial request,
	 * add group join count, regardless of the number of sources.
	 */
	if (mode == MCAST_EXCLUDE && init) {
		++in6m->in6m_source->i6ms_grpjoin;
	}

	if (numsrc != 0)
		/* New numsrc must be set before in6_get_new_msf_state()
		 * is called. */
		*fnumsrc += j;
	error = in6_get_new_msf_state(in6m, newhead, newmode, newnumsrc);
	if (error != 0) {
		mldlog((LOG_DEBUG, "in6_addmultisrc: in6_get_new_msf_state returns %d\n", error));
		if (mode == MCAST_EXCLUDE && init)
			--in6m->in6m_source->i6ms_grpjoin;
		if (numsrc != 0) {
			/* numsrc must be returned back before undo */
			*fnumsrc -= j;
			in6_undomultisrc(in6m, i,ss, mode, IMS_ADD_SOURCE);
		}
		return error;
	}

	return 0;
}

/*
 * Delete source addresses from multicast address record.
 */
int
in6_delmultisrc(in6m, numsrc, ss, mode, final, newhead, newmode, newnumsrc)
	struct in6_multi *in6m;
	u_int16_t numsrc;
	struct sockaddr_storage *ss;
	u_int mode;
	int final;
	struct i6as_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in6_addr_slist *iasl = NULL;
	struct in6_addr_source *ias, *nias;
	u_int16_t *fnumsrc = NULL;
	u_int16_t i, j;
	int ref_count;
	int error;

	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;

	/*
	 * If numsrc is 0, mode must be MCAST_EXCLUDE here, which means
	 * (*,G) leave. Also, if there was no group join request for this
	 * group, it's invalid.
	 */
	i = j = 0;
	if (numsrc == 0) {
		if ((mode != MCAST_EXCLUDE) ||
				(in6m->in6m_source->i6ms_grpjoin == 0))
			return EINVAL;
		goto after_source_list_deletion;
	}
	if (ss == NULL) {
		return EINVAL;
	}

	if (IN6M_SOURCE_LIST_NONALLOC(mode))
		return EADDRNOTAVAIL;
	iasl = IN6M_SOURCE_LIST(mode);
	fnumsrc = &iasl->numsrc;

	for (; i < numsrc; i++) {
		if (SS_IS_ADDR_UNSPECIFIED(&ss[i]))
			continue; /* skip */
		ref_count = in6_merge_msf_source_addr(iasl, SIN6(&ss[i]),
						     IMS_DELETE_SOURCE);
		if (ref_count < 0) {
			mldlog((LOG_DEBUG, "in6_delmultisrc: found source %s not exist in %s mode?\n",
			       ip6_sprintf(&SIN6(&ss[i])->sin6_addr),
			       mode == MCAST_INCLUDE ? "include" :
			       mode == MCAST_EXCLUDE ? "exclude" :
			       "???"));
			in6_undomultisrc(in6m, i, ss, mode, IMS_DELETE_SOURCE);
			return EADDRNOTAVAIL;
		}
		if (ref_count == 0)
			++j; /* the number of deleted sources */
	}

after_source_list_deletion:
	/*
	 * Each source which was removed from EXCLUDE source list is also
	 * removed from an EXCLUDE source list reaching max count, if there
	 * is no (*,G) join state.
	 */
	if (mode == MCAST_EXCLUDE) {
		if (final) { /* socket made request leave from group. */
			if (in6m->in6m_source->i6ms_grpjoin <= 0)
				return EADDRNOTAVAIL;
			--in6m->in6m_source->i6ms_grpjoin;
		}
	}

	if (numsrc != 0) {
		/* new numsrc is needed by in6_get_new_msf_state() */
		*fnumsrc -= j;
	}
	error = in6_get_new_msf_state(in6m, newhead, newmode, newnumsrc);
	if (error != 0) {
		mldlog((LOG_DEBUG, "in6_delmultisrc: in6_get_new_msf_state returns %d\n", error));
		if (mode == MCAST_EXCLUDE && final)
			++in6m->in6m_source->i6ms_grpjoin;
		if (numsrc != 0) {
			/* numsrc must be returned back before undo */
			*fnumsrc += j;
			in6_undomultisrc(in6m, numsrc, ss, mode,
					 IMS_DELETE_SOURCE);
		}
		return error;
	}

	/*
	 * Each source whose i6as_refcount is 0 is removed after the process
	 * to merge each source has done successfully.
	 */
	if (numsrc != 0) {
		for (ias = LIST_FIRST(iasl->head); ias; ias = nias) {
			nias = LIST_NEXT(ias, i6as_list);
			if (ias->i6as_refcount == 0) {
				LIST_REMOVE(ias, i6as_list);
				FREE(ias, M_MSFILTER);
			}
		}
	}

	return 0;
}

int
in6_modmultisrc(in6m, numsrc, ss, mode, old_num, old_ss, old_mode, grpjoin,
			newhead, newmode, newnumsrc)
	struct in6_multi *in6m;
	u_int16_t numsrc, old_num;
	struct sockaddr_storage *ss, *old_ss;
	u_int mode, old_mode;
	u_int grpjoin;
	struct i6as_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in6_addr_slist *iasl, *oiasl = NULL;
	struct in6_addr_source *ias, *nias;
	u_int16_t *fnumsrc = NULL, *ofnumsrc = NULL;
	u_int16_t i, j, k;
	int ref_count;
	int error = 0;

	if (old_mode != MCAST_INCLUDE && old_mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;
	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;
	if (in6m->in6m_source == NULL) {
		/*
		 * Even if upstream router does not control MLDv2, in6m_source
		 * is allocated, in order to behave as an MLDv2 capable node
		 * in any time.
		 */
		MALLOC(in6m->in6m_source, struct in6_multi_source *,
			sizeof(struct in6_multi_source), M_MSFILTER, M_NOWAIT);
		if (in6m->in6m_source == NULL)
			return ENOBUFS;
		bzero(in6m->in6m_source, sizeof(struct in6_multi_source));

		MALLOC(in6m->in6m_source->i6ms_timer_ch, struct callout *,
		    sizeof(struct callout), M_MSFILTER, M_NOWAIT);
		if (in6m->in6m_source->i6ms_timer_ch == NULL)
			return ENOBUFS;
#ifdef __FreeBSD__
		callout_init(in6m->in6m_source->i6ms_timer_ch, 0);
#elif defined(__NetBSD__)
		callout_init(in6m->in6m_source->i6ms_timer_ch);
#elif defined(__OpenBSD__)
		bzero(in6m->in6m_source->i6ms_timer_ch, sizeof(struct callout));
#endif

		I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_cur);
		if (error != 0) {
			FREE(in6m->in6m_source, M_MSFILTER);
			return error;
		}
		I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_rec);
		if (error != 0) {
			FREE(in6m->in6m_source->i6ms_cur->head, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_cur, M_MSFILTER);
			FREE(in6m->in6m_source, M_MSFILTER);
			return error;
		}
		in6m->in6m_source->i6ms_mode = MCAST_INCLUDE;
		in6m->in6m_source->i6ms_grpjoin = 0;
		in6m->in6m_source->i6ms_timer = 0;
		in6m->in6m_source->i6ms_robvar = 0;
		in6m->in6m_state = MLD_OTHERLISTENER;
	}

	/*
	 * Delete unneeded sources.
	 */
	if (old_num != 0) {
		if (IN6M_SOURCE_LIST(old_mode) == NULL)
			return EADDRNOTAVAIL;
		oiasl = IN6M_SOURCE_LIST(old_mode);
		ofnumsrc = &oiasl->numsrc;
	}

	i = j = k = 0;
	for (; i < old_num; i++) {
		ref_count = in6_merge_msf_source_addr(oiasl, SIN6(&old_ss[i]),
						      IMS_DELETE_SOURCE);
		if (ref_count < 0) {
			in6_undomultisrc(in6m, i, old_ss, old_mode,
					 IMS_DELETE_SOURCE);
			return EADDRNOTAVAIL; /* strange since msf was deleted*/
		} else if (ref_count == 0)
			++j; /* the number of deleted sources */
	}
	i = 0; /* reset */

	/* no need to change source list if there is no source */
	if (numsrc == 0)
		goto after_source_list_modification;

	if (IN6M_SOURCE_LIST_NONALLOC(mode)) {
		for (i = 0; i < numsrc; i++) {
			if (SS_IS_ADDR_UNSPECIFIED(&ss[i]))
				continue; /* skip */

			MALLOC(ias, struct in6_addr_source *, sizeof(*ias),
			       M_MSFILTER, M_NOWAIT);
			if (ias == NULL)
				return ENOBUFS;
			bcopy(&ss[i], &ias->i6as_addr, ss[i].ss_len);
			ias->i6as_refcount = 1;

			if (IN6M_SOURCE_LIST(mode) == NULL) {
				if (mode == MCAST_INCLUDE)
					I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_in);
				else
					I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_ex);
				if (error != 0) {
					FREE(ias, M_MSFILTER);
					return error;
				}
			}
			if (mode == MCAST_INCLUDE)
				LIST_INSERT_HEAD(in6m->in6m_source->i6ms_in->head,
				    ias, i6as_list);
			else
				LIST_INSERT_HEAD(in6m->in6m_source->i6ms_ex->head,
				    ias, i6as_list);

			k = 1; /* the number of added source */
			break;
		}
		if (i == numsrc)
			return EINVAL;
		++i; /* adjusted the number of checked sources */
	}

	iasl = IN6M_SOURCE_LIST(mode);
	fnumsrc = &iasl->numsrc;
	/* the number of sources is limited */
	if (*fnumsrc >= mldmaxsrcfilter) {
		mldlog((LOG_DEBUG, "in6_modmultisrc: number of source already reached max filter count.\n"));
		return EINVAL; /* XXX */
	}

	for (; i < numsrc; i++) {
		if (SS_IS_ADDR_UNSPECIFIED((struct sockaddr *)&ss[i]))
			continue; /* skip */
		ref_count = in6_merge_msf_source_addr(iasl, SIN6(&ss[i]),
						      IMS_ADD_SOURCE);
		if (ref_count < 0) {
			in6_undomultisrc(in6m, i, ss, mode, IMS_ADD_SOURCE);
			if (old_num != 0)
				in6_undomultisrc(in6m, old_num, old_ss,
						 old_mode, IMS_DELETE_SOURCE);
			return ENOBUFS;
		} else if (ref_count != 1)
			continue;

		/* ref_count == 1 means new source */
		++k; /* the number of added sources  */
		if ((*fnumsrc + k) == mldmaxsrcfilter) {
			/*
			 * XXX Kernel accepts to keep as many requested
			 * sources as possible. It tries to fit sources within
			 * a rest of the number of the limitation, and after
			 * reaching max, it stops insertion with returning no
			 * error.
			 * This is implementation specific issue.
			 */
			++i; /* adjusted the number of sources */
			mldlog((LOG_DEBUG, "in6_modmultisrc: number of source is over max filter count. Adjusted.\n"));
			break;
		}
	}

after_source_list_modification:
	/*
	 * If new request is EX{anything} -> IN{anything}
	 * decrease i6ms_grpjoin.
	 * If new request is IN{non NULL} -> EX{anything}
	 * increase i6ms_grpjoin.
	 */
	if (old_mode != mode && mode == MCAST_INCLUDE)
		--in6m->in6m_source->i6ms_grpjoin;
	else if (old_mode != mode && mode == MCAST_EXCLUDE)
		++in6m->in6m_source->i6ms_grpjoin;

	/* New numsrc must be set before in6_get_new_msf_state() is called. */
	if (old_num != 0)
		*ofnumsrc -= j;
	if (numsrc != 0)
		*fnumsrc += k;

	error = in6_get_new_msf_state(in6m, newhead, newmode, newnumsrc);
	if (error != 0) {
		mldlog((LOG_DEBUG, "in6_modmultisrc: in6_get_new_msf_state error %d\n", error));
		if (old_mode != mode && mode == MCAST_INCLUDE)
			++in6m->in6m_source->i6ms_grpjoin;
		else if (old_mode != mode && mode == MCAST_EXCLUDE)
			--in6m->in6m_source->i6ms_grpjoin;

		if (grpjoin && mode == MCAST_INCLUDE)
			++in6m->in6m_source->i6ms_grpjoin;
		else if (!grpjoin && mode == MCAST_EXCLUDE)
			--in6m->in6m_source->i6ms_grpjoin;

		if (old_num != 0) {
			/* numsrc must be returned back before undo */
			*ofnumsrc += j;
			in6_undomultisrc(in6m, old_num, old_ss, old_mode,
					 IMS_DELETE_SOURCE);
		}
		if (numsrc != 0) {
			/* numsrc must be returned back before undo */
			*fnumsrc -= k;
			in6_undomultisrc(in6m, numsrc, ss, mode, IMS_ADD_SOURCE);
		}
		return error;
	}

	/*
	 * Each source whose i6as_refcount is 0 is removed after the process
	 * to merge each source has done successfully.
	 */
	if (old_num != 0) {
		for (ias = LIST_FIRST(oiasl->head); ias; ias = nias) {
			nias = LIST_NEXT(ias, i6as_list);
			if (ias->i6as_refcount == 0) {
				LIST_REMOVE(ias, i6as_list);
				FREE(ias, M_MSFILTER);
			}
		}
	}

	return 0;
}

/*
 * Undo source list change.
 * This should be called with numsrc != 0.
 */
void
in6_undomultisrc(in6m, numsrc, ss, mode, req)
	struct in6_multi *in6m;
	u_int16_t numsrc;
	struct sockaddr_storage *ss;
	u_int mode;
	int req;
{
	struct i6as_head head;
	struct in6_addr_source *ias, *nias = NULL;
	u_int16_t i;

	if (mode == MCAST_INCLUDE)
		LIST_FIRST(&head) = LIST_FIRST(in6m->in6m_source->i6ms_in->head);
	else if (mode == MCAST_EXCLUDE)
		LIST_FIRST(&head) = LIST_FIRST(in6m->in6m_source->i6ms_ex->head);
	else
		return;

	for (i = 0; i < numsrc && &ss[i] != NULL; i++) {
		if (SS_IS_ADDR_UNSPECIFIED(&ss[i]))
			continue; /* skip */
		for (ias = LIST_FIRST(&head); ias; ias = nias) {
			nias = LIST_NEXT(ias, i6as_list);
			/* sanity check */
			if (ias->i6as_addr.sin6_family != ss[i].ss_family)
				continue;

			if (SS_CMP(&ias->i6as_addr, <, &ss[i]))
				continue;
			if (SS_CMP(&ias->i6as_addr, >, &ss[i])) {
				/* XXX strange. this should never occur. */
				mldlog((LOG_DEBUG, "in6_undomultisrc: list corrupted. panic!\n"));
				continue; /* XXX */
			}

			/* same src addr found */
			if (req == IMS_ADD_SOURCE) {
				if (--ias->i6as_refcount == 0) {
					LIST_REMOVE(ias, i6as_list);
					FREE(ias, M_MSFILTER);
				}
			} else /* IMS_DELETE_SOURCE */
				++ias->i6as_refcount;
			LIST_FIRST(&head) = nias;
			break;
		}
	}
	if (mode == MCAST_INCLUDE) {
		if (numsrc != 0 && in6m->in6m_source->i6ms_in->numsrc == 0) {
			FREE(in6m->in6m_source->i6ms_in->head, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_in, M_MSFILTER);
			in6m->in6m_source->i6ms_in = NULL;
		}
	}
	if (mode == MCAST_EXCLUDE) {
		if (numsrc != 0 && in6m->in6m_source->i6ms_ex->numsrc == 0) {
			FREE(in6m->in6m_source->i6ms_ex->head, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_ex, M_MSFILTER);
			in6m->in6m_source->i6ms_ex = NULL;
		}
	}
}

/*
 * Get new source filter mode and source list head when the multicast
 * reception state of an interface is changed.
 */
int
in6_get_new_msf_state(in6m, newhead, newmode, newnumsrc)
	struct in6_multi *in6m;
	struct i6as_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in6_addr_source *in_ias, *ex_ias, *newias, *nias, *lastp = NULL;
	struct i6as_head inhead, exhead;
	u_int filter;
	u_int8_t cmd;
	int i;
	int error = 0;

	/* Case 1: Some socket requested (*,G) join. */
	if ((in6mm_src->i6ms_grpjoin != 0) && IN6M_LIST_EMPTY(ex)) {
		/* IN{NULL} -> EX{NULL} */
		if (LIST_EMPTY(in6mm_src->i6ms_cur->head)) {
			if (in6mm_src->i6ms_mode == MCAST_INCLUDE) {
				mldlog((LOG_DEBUG, "case 1.1:IN{NULL}->EX{NULL}\n"));
				in6_clear_all_pending_report(in6m);

				/*
				 * To make TO_EX transmission, non-null
				 * i6ms_toex is required.
				 * See mld_send_state_change_report().
				 */
				I6AS_LIST_ALLOC(in6mm_src->i6ms_toex);
			}
			goto change_state_1;
		}

		/* IN{non NULL} -> EX{NULL} */
		if (in6mm_src->i6ms_mode == MCAST_INCLUDE) {
			mldlog((LOG_DEBUG, "case 1.2:IN{non-NULL}->EX{NULL}\n"));
			in6_clear_all_pending_report(in6m);

			/* To make TO_EX transmission */
			I6AS_LIST_ALLOC(in6mm_src->i6ms_toex);
			goto free_source_list_1;
		 }

		/* EX{non NULL} -> EX{NULL} */
		if (in6mm_src->i6ms_ex != NULL) {
			mldlog((LOG_DEBUG, "case 1.3:EX{non-NULL}->EX{NULL}\n"));
			filter = REPORT_FILTER2;
			LIST_FOREACH(ex_ias, in6mm_src->i6ms_ex->head,
				     i6as_list) {
				error = in6_merge_pending_report(in6m, ex_ias,
								ALLOW_NEW_SOURCES);
				if (error != 0) {
					/*
					 * If error occured, clear pending
					 * report and return error.
					 */
					in6_clear_pending_report(in6m, filter);
					return error;
				}
			}
		}

	free_source_list_1:
		in6_free_msf_source_list(in6mm_src->i6ms_cur->head);
		in6mm_src->i6ms_cur->numsrc = 0;

	change_state_1:
		*newmode = MCAST_EXCLUDE;
		*newnumsrc = 0;
		return error;
	}

	/* Case 2: There is no member for this group. */
	if (IN6M_LIST_EMPTY(in) && IN6M_LIST_EMPTY(ex)) {
		/* EX{NULL} -> IN{NULL} */
		if (LIST_EMPTY(in6mm_src->i6ms_cur->head)) {
			if (in6mm_src->i6ms_mode == MCAST_EXCLUDE) {
				mldlog((LOG_DEBUG, "case 2.1: EX{NULL}->IN{NULL}\n"));
				in6_clear_all_pending_report(in6m);

				/*
				 * To make TO_IN transmission, non-null
				 * i6ms_toin is required.
				 * See mld_send_state_change_report().
				 */
				I6AS_LIST_ALLOC(in6mm_src->i6ms_toin);
			}
			goto change_state_2;
		}

		/* EX{non NULL} -> IN{NULL} */
		if (in6mm_src->i6ms_mode == MCAST_EXCLUDE) {
			mldlog((LOG_DEBUG, "case 2.2: EX{non-NULL}->IN{NULL}\n"));
			filter = REPORT_FILTER4;
			in6_clear_all_pending_report(in6m);

			/* To make TO_IN transmission */
			I6AS_LIST_ALLOC(in6mm_src->i6ms_toin);
			goto free_source_list_2;
		}

		/* IN{non NULL} -> IN{NULL} */
		mldlog((LOG_DEBUG, "case 2.3: IN{non-NULL}->IN{NULL}\n"));
		filter = REPORT_FILTER1;
		LIST_FOREACH(in_ias, in6mm_src->i6ms_cur->head, i6as_list) {
			error = in6_merge_pending_report(in6m, in_ias,
							 BLOCK_OLD_SOURCES);
			if (error != 0) {
				/*
			 	 * If error occured, clear pending report and
				 * return error.
				 */
				 in6_clear_pending_report(in6m, filter);
				 return error;
			 }
		}

	free_source_list_2:
		in6_free_msf_source_list(in6mm_src->i6ms_cur->head);
		in6mm_src->i6ms_cur->numsrc = 0;

	change_state_2:
		*newmode = MCAST_INCLUDE;
		*newnumsrc = 0;
		return error;
	}

	/* Case 3: Source list of EXCLUDE filter is set for this group. */
	if (IN6M_LIST_EMPTY(in)) {
		mldlog((LOG_DEBUG, "case 3: Source list of EXCLUDE filter is set for this group\n"));
		/* IN{NULL} -> EX{non NULL} or EX{NULL} -> EX{non NULL} */
		if (LIST_EMPTY(in6mm_src->i6ms_cur->head)) {
			error = in6_copy_msf_source_list(in6mm_src->i6ms_ex,
							 in6mm_src->i6ms_cur,
							 in6mm_src->i6ms_grpjoin);
			if (error != 0)
				return error;

			i = in6mm_src->i6ms_cur->numsrc;
			if (in6mm_src->i6ms_mode == MCAST_INCLUDE) {
				mldlog((LOG_DEBUG, "case 3.1:IN{NULL}->EX{non-NULL}\n"));
				filter = REPORT_FILTER3;
				cmd = CHANGE_TO_EXCLUDE_MODE;
				in6_clear_all_pending_report(in6m);
			} else {
				mldlog((LOG_DEBUG, "case 3.2:EX{NULL}->EX{non-NULL}\n"));
				filter = REPORT_FILTER2;
				cmd = BLOCK_OLD_SOURCES;
			}
			LIST_FOREACH(ex_ias, in6mm_src->i6ms_ex->head, i6as_list) {
				if (ex_ias->i6as_refcount != in6mm_src->i6ms_grpjoin)
					continue; /* skip */
				error = in6_merge_pending_report(in6m, ex_ias,
								 cmd);
				if (error != 0) {
					/*
					 * If error occured, clear curhead and
					 * pending report, and return error.
					 */
					 in6_free_msf_source_list
						(in6mm_src->i6ms_cur->head);
					 in6mm_src->i6ms_cur->numsrc = 0;
					 in6_clear_pending_report(in6m, filter);
					 return error;
				 }
			 }
			 goto change_state_3;
		}

		/* EX{non NULL} -> EX{non NULL} */
		if (in6mm_src->i6ms_mode == MCAST_EXCLUDE) {
			mldlog((LOG_DEBUG, "case 3.3:EX{non-NULL}->EX{non-NULL}\n"));
			filter = REPORT_FILTER2;
			error = in6_merge_msf_head(in6m, in6mm_src->i6ms_ex,
						   in6mm_src->i6ms_grpjoin, filter);
			if (error != 0)
				return error;

			for (i = 0, newias = LIST_FIRST(in6mm_src->i6ms_cur->head);
			     newias; newias = nias) {
				nias = LIST_NEXT(newias, i6as_list);
				if (newias->i6as_refcount == 0) {
					LIST_REMOVE(newias, i6as_list);
					FREE(newias, M_MSFILTER);
					continue;
				}
				newias->i6as_refcount = 1;
				++i;
			}
			goto change_state_3;
		}

		/* IN{non NULL} -> EX{non NULL} */
		mldlog((LOG_DEBUG, "case 3.4:IN{non-NULL}->EX{non-NULL}\n"));
		filter = REPORT_FILTER3;
		in6_free_msf_source_list(in6mm_src->i6ms_cur->head);
		in6mm_src->i6ms_cur->numsrc = 0;
		error = in6_copy_msf_source_list(in6mm_src->i6ms_ex,
						 in6mm_src->i6ms_cur,
						 in6mm_src->i6ms_grpjoin);
		if (error != 0)
			return error;

		i = in6mm_src->i6ms_cur->numsrc;
		in6_clear_all_pending_report(in6m);
		LIST_FOREACH(ex_ias, in6mm_src->i6ms_ex->head, i6as_list) {
			if (ex_ias->i6as_refcount != in6mm_src->i6ms_grpjoin)
				continue; /* skip */
			error = in6_merge_pending_report(in6m, ex_ias,
							 CHANGE_TO_EXCLUDE_MODE);
			if (error != 0) {
				/*
				 * If error occured, clear curhead and pending
				 * report, and return error.
				 */
				 in6_free_msf_source_list
						(in6mm_src->i6ms_cur->head);
				 in6mm_src->i6ms_cur->numsrc = 0;
				 in6_clear_pending_report(in6m, filter);
				 return error;
			}
		}

	change_state_3:
		*newmode = MCAST_EXCLUDE;
		*newnumsrc = i;
		return 0;
	}

	/* Case 4: Source list of INCLUDE filter is set for this group. */
	if (IN6M_LIST_EMPTY(ex)) {
		/* IN{NULL} -> IN{non NULL} or EX{NULL} -> IN{non NULL} */
		if (LIST_EMPTY(in6mm_src->i6ms_cur->head)) {
			error = in6_copy_msf_source_list(in6mm_src->i6ms_in,
							 in6mm_src->i6ms_cur,
							 (u_int)0);
			if (error != 0)
				return error;

			i = in6mm_src->i6ms_cur->numsrc;
			if (in6m->in6m_source->i6ms_mode == MCAST_INCLUDE) {
				mldlog((LOG_DEBUG, "case 4.1:IN{NULL}->IN{non-NULL}\n"));
				filter = REPORT_FILTER1;
				cmd = ALLOW_NEW_SOURCES;
			} else {
				mldlog((LOG_DEBUG, "case 4.2:EX{NULL}->IN{non-NULL}\n"));
				filter = REPORT_FILTER4;
				cmd = CHANGE_TO_INCLUDE_MODE;
				in6_clear_all_pending_report(in6m);
			}
			LIST_FOREACH(in_ias, in6mm_src->i6ms_in->head, i6as_list) {
				if (in_ias->i6as_refcount == 0)
					continue; /* skip */
				error = in6_merge_pending_report(in6m, in_ias,
							 	 cmd);
				if (error != 0) {
					/*
					 * If error occured, clear curhead and
					 * pending report, and return error.
					 */
					 in6_free_msf_source_list
						(in6mm_src->i6ms_cur->head);
					 in6mm_src->i6ms_cur->numsrc = 0;
					 in6_clear_pending_report(in6m, filter);
					 return error;
				}
			}
			goto change_state_4;
		}

		/* IN{non NULL} -> IN{non NULL} */
		if (in6mm_src->i6ms_mode == MCAST_INCLUDE) {
			mldlog((LOG_DEBUG, "case 4.3:IN{non NULL}->IN{non-NULL}\n"));
			filter = REPORT_FILTER1;
			error = in6_merge_msf_head(in6m, in6mm_src->i6ms_in,
						   (u_int)0, filter);
			if (error != 0)
				return error;
			for (i = 0, newias = LIST_FIRST(in6mm_src->i6ms_cur->head);
			     newias; newias = nias) {
				nias = LIST_NEXT(newias, i6as_list);
				if (newias->i6as_refcount == 0) {
					LIST_REMOVE(newias, i6as_list);
					FREE(newias, M_MSFILTER);
				} else {
					newias->i6as_refcount = 1;
					++i;
				}
			}
			goto change_state_4;
		}

		/* EX{non NULL} -> IN{non NULL} (since EX list was left) */
		mldlog((LOG_DEBUG, "case 4.4:EX{non NULL}->IN{non-NULL}\n"));
		filter = REPORT_FILTER4;
		in6_free_msf_source_list(in6mm_src->i6ms_cur->head);
		in6mm_src->i6ms_cur->numsrc = 0;
		error = in6_copy_msf_source_list(in6mm_src->i6ms_in,
						 in6mm_src->i6ms_cur, (u_int)0);
		if (error != 0)
			return error;

		i = in6mm_src->i6ms_cur->numsrc;
		in6_clear_all_pending_report(in6m);
		LIST_FOREACH(in_ias, in6mm_src->i6ms_in->head, i6as_list) {
			if (in_ias->i6as_refcount == 0)
				continue; /* skip */
			error = in6_merge_pending_report(in6m, in_ias,
							CHANGE_TO_INCLUDE_MODE);
			if (error != 0) {
				/*
				 * If error occured, clear curhead and pending
				 * report, and return error.
				 */
				 in6_free_msf_source_list
						(in6mm_src->i6ms_cur->head);
				 in6mm_src->i6ms_cur->numsrc = 0;
				 in6_clear_pending_report(in6m, filter);
				 return error;
			}
		}

	change_state_4:
		*newmode = MCAST_INCLUDE;
		*newnumsrc = i;
		return 0;
	}

	/* Case 5: INCLUDE and EXCLUDE source lists coexist with this group. */
	mldlog((LOG_DEBUG, "case 5: INCLUDE and EXCLUDE source lists coexist with this group.\n"));
	LIST_FIRST(&inhead) = LIST_FIRST(in6mm_src->i6ms_in->head);
	LIST_FIRST(&exhead) = LIST_FIRST(in6mm_src->i6ms_ex->head);
	MALLOC(*newhead, struct i6as_head *, sizeof(struct i6as_head),
	       M_MSFILTER, M_NOWAIT);
	if (*newhead == NULL)
		return ENOBUFS;
	LIST_INIT(*newhead);
	*newnumsrc = 0;

	LIST_FOREACH(ex_ias, &exhead, i6as_list) {
		if (ex_ias->i6as_refcount != in6mm_src->i6ms_grpjoin)
			continue;

		LIST_FOREACH(in_ias, &inhead, i6as_list) {
			if (in_ias->i6as_refcount == 0)
				continue; /* skip */
			/* sanity check */
			if (in_ias->i6as_addr.sin6_family != ex_ias->i6as_addr.sin6_family)
				continue;

			if (SS_CMP(&in_ias->i6as_addr, <, &ex_ias->i6as_addr))
				continue;
			if (SS_CMP(&ex_ias->i6as_addr, ==, &in_ias->i6as_addr)) {
				LIST_FIRST(&inhead) = LIST_NEXT(in_ias,
								i6as_list);
				break;
			}

			/* ex_ias should be recorded in new curhead here */
			MALLOC(newias, struct in6_addr_source *,
			       sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				in6_free_msf_source_list(*newhead);
				FREE(*newhead, M_MSFILTER);
				*newnumsrc = 0;
				return ENOBUFS;
			}
			if (LIST_EMPTY(*newhead)) {
				LIST_INSERT_HEAD(*newhead, newias, i6as_list);
			} else {
				LIST_INSERT_AFTER(lastp, newias, i6as_list);
			}
			++(*newnumsrc);
			bcopy(&ex_ias->i6as_addr, &newias->i6as_addr, ex_ias->i6as_addr.sin6_len);
			lastp = newias;
			LIST_FIRST(&inhead) = in_ias;
			break;
		}
		if (!in_ias) {
			LIST_INIT(&inhead); /* stop INCLUDE source scan */
			MALLOC(newias, struct in6_addr_source *, sizeof(*newias),
			       M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				in6_free_msf_source_list(*newhead);
				FREE(*newhead, M_MSFILTER);
				*newnumsrc = 0;
				return ENOBUFS;
			}
			if (LIST_EMPTY(*newhead)) {
				LIST_INSERT_HEAD(*newhead, newias, i6as_list);
			} else {
				LIST_INSERT_AFTER(lastp, newias, i6as_list);
			}
			++(*newnumsrc);
			bcopy(&ex_ias->i6as_addr, &newias->i6as_addr, ex_ias->i6as_addr.sin6_len);
			lastp = newias;
		}
	}

	*newmode = MCAST_EXCLUDE;
	if (*newnumsrc == 0) {
		if (in6mm_src->i6ms_cur->numsrc != 0) {
			/* IN{non NULL}/EX{non NULL} -> EX{NULL} */
			in6_free_msf_source_list(in6mm_src->i6ms_cur->head);
			FREE(*newhead, M_MSFILTER);
			*newhead = NULL;
		}
		if (in6mm_src->i6ms_mode == MCAST_INCLUDE) {
			/*
			 * To make TO_EX with NULL source list transmission,
			 * non-null i6ms_toex is required.
			 * See mld_send_state_change_report().
			 */
			I6AS_LIST_ALLOC(in6mm_src->i6ms_toex);
			if (error != 0)
				; /* XXX give up TO_EX transmission */
		}
	}

	return 0;
}

/*
 * Merge MSF new head to current head. This also merge pending report if
 * needed.
 * This must not be called for Filter-Mode-Change request.
 * In order to use the intersection of EXCLUDE source lists, refcount is
 * prepared. If refcount is 0, all sources except i6as_refcount = 0 are
 * compared with sources of curhead. If it's not 0, only sources whose
 * i6as_refcount = refcount are compared with them.
 * After this finishes successfully, new current head whose refcount is 0
 * will be clean up, and new timer for merged report will be set.
 */
static int
in6_merge_msf_head(in6m, iasl, refcount, filter)
	struct in6_multi *in6m;
	struct in6_addr_slist *iasl;
	u_int refcount;
	u_int filter;
{
	struct i6as_head head;
	struct in6_addr_source *ias = NULL, *curias = NULL, *newias, *lastp = NULL;
	int error;

	if ((filter != REPORT_FILTER1) && (filter != REPORT_FILTER2))
		return EOPNOTSUPP;

	LIST_FIRST(&head) = LIST_FIRST(iasl->head);
	LIST_FOREACH(curias, in6m->in6m_source->i6ms_cur->head, i6as_list) {
		lastp = curias;
		LIST_FOREACH(ias, &head, i6as_list) {
			if ((ias->i6as_refcount == 0) ||
			    (refcount != 0 && ias->i6as_refcount != refcount))
				continue; /* skip */

			/* sanity check */
			if (curias->i6as_addr.sin6_family != ias->i6as_addr.sin6_family)
				continue;

			if (SS_CMP(&curias->i6as_addr, ==, &ias->i6as_addr)) {
				++curias->i6as_refcount;
				LIST_FIRST(&head) = LIST_NEXT(ias, i6as_list);
				break;
			}

			if (SS_CMP(&curias->i6as_addr, <, &ias->i6as_addr)) {
				if (filter == REPORT_FILTER1)
					error = in6_merge_pending_report
							(in6m, curias,
							 BLOCK_OLD_SOURCES);
				else
					error = in6_merge_pending_report
							(in6m, curias,
							 ALLOW_NEW_SOURCES);
				if (error != 0) {
					/*
					 * If error occured, undo curhead
					 * modification, clear pending report,
					 * and return error.
					 */
					in6_undo_new_msf_curhead
						(in6m, &curias->i6as_addr);
					/* XXX But do we really clear pending
					 * report? */
					in6_clear_pending_report(in6m, filter);
					mldlog((LOG_DEBUG, "in6_merge_msf_head: merge fail for FILTER%d\n", filter));
					return error;
				}
				curias->i6as_refcount = 0;
				LIST_FIRST(&head) = ias;
				break;
			}

			/* ias should be recorded in new curhead here */
			MALLOC(newias, struct in6_addr_source *,
			       sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				in6_undo_new_msf_curhead(in6m, &ias->i6as_addr);
				in6_clear_pending_report(in6m, filter); /*XXX*/
				mldlog((LOG_DEBUG, "in6_merge_msf_head: malloc fail\n"));
				return ENOBUFS;
			}
			if (filter == REPORT_FILTER1)
				error = in6_merge_pending_report
						(in6m, ias, ALLOW_NEW_SOURCES);
			else
				error = in6_merge_pending_report
						(in6m, ias, BLOCK_OLD_SOURCES);
			if (error != 0) {
				in6_undo_new_msf_curhead(in6m, &ias->i6as_addr);
				in6_clear_pending_report(in6m, filter); /*XXX*/
				mldlog((LOG_DEBUG, "in6_merge_msf_head: merge fail for FILTER%d\n", filter));
				return error;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_BEFORE(curias, newias, i6as_list);
		}
		if (!ias) {
			LIST_INIT(&head); /* stop list scan */
			if (filter == REPORT_FILTER1)
				error = in6_merge_pending_report
					(in6m, curias, BLOCK_OLD_SOURCES);
			else
				error = in6_merge_pending_report
					(in6m, curias, ALLOW_NEW_SOURCES);
			if (error != 0) {
				in6_undo_new_msf_curhead
						(in6m, &curias->i6as_addr);
				in6_clear_pending_report(in6m, filter); /*XXX*/
				mldlog((LOG_DEBUG, "in6_merge_msf_head: merge fail for FILTER%d\n", filter));
				return error;
			}
			curias->i6as_refcount = 0;
		}
	}

	if (ias == NULL)
		return 0; /* already finished merging each ias in curhead */

	LIST_FOREACH(ias, &head, i6as_list) {
		if ((ias->i6as_refcount == 0) ||
		    (refcount != 0 && ias->i6as_refcount != refcount))
			continue;

		MALLOC(newias, struct in6_addr_source *, sizeof(*newias),
		       M_MSFILTER, M_NOWAIT);
		if (newias == NULL) {
			mldlog((LOG_DEBUG, "in6_merge_msf_head: malloc fail\n"));
			in6_undo_new_msf_curhead(in6m, &ias->i6as_addr);
			in6_clear_pending_report(in6m, filter); /* XXX */
			return ENOBUFS;
		}
		if (filter == REPORT_FILTER1)
			error = in6_merge_pending_report(in6m, ias,
							 ALLOW_NEW_SOURCES);
		else
			error = in6_merge_pending_report(in6m, ias,
							 BLOCK_OLD_SOURCES);
		if (error != 0) {
			in6_undo_new_msf_curhead(in6m, &ias->i6as_addr);
			in6_clear_pending_report(in6m, filter); /* XXX */
			mldlog((LOG_DEBUG, "in6_merge_msf_head: merge fail for FILTER%d\n", filter));
			return error;
		}
		bcopy(&ias->i6as_addr, &newias->i6as_addr,
		      ias->i6as_addr.sin6_len);
		newias->i6as_refcount = 1;
		LIST_INSERT_AFTER(lastp, newias, i6as_list);
		lastp = newias;
	}

	return 0;
}

static void
in6_undo_new_msf_curhead(in6m, src)
	struct in6_multi *in6m;
	struct sockaddr_in6 *src;
{
	struct in6_addr_source *ias = NULL;

	LIST_FOREACH(ias, in6m->in6m_source->i6ms_cur->head, i6as_list) {
		/* sanity check */
		if (ias->i6as_addr.sin6_family != src->sin6_family)
			continue;

		if (SS_CMP(&ias->i6as_addr, >=, src))
			return;

		if (ias->i6as_refcount == 1) {
			/* Remove newly added source */
			LIST_REMOVE(ias, i6as_list);
			FREE(ias, M_MSFILTER);
		} else /* refcount is 0 or 2 */
			ias->i6as_refcount = 1;
	}
}

/*
 * After getting new source filter mode and source list head, to transmit a
 * State-Change Report from that interface, the interface state for the
 * affected group before and after the latest change is compared and merged
 * with the contents of the pending report.
 * This is called only when new mode is EXCLUDE.
 *
 * Note: In order to ensure a new State-Change Report does not break the
 * protocol robustness, following procedures would be applied;
 * When the new State-Change Report is Source-List-Change, and if there is
 * some pending responce of Filter-Mode-Change record or there is same
 * source record in a pending source list of opposite filter mode, e.g.,
 * BLOCK if ALLOW is the new request, then the pending message is
 * immediately transmitted before preparing new Source-List-Change record.
 * When the new State-Change Report is Filter-Mode-Change, clear the same
 * source records in pending source lists of opposite filter mode, e.g.,
 * for TO_IN request, remove the requested sources from BLOCK and TO_EX
 * pending source lists.
 */
/* This returns;
 *	more than 0: error
 *	0: nop for local group address or pending source list changed
 *	-1: no pending source list change (not an error)
 *	    only the case of sending an ALLOW or BLOCK State-Change Report
 */
int
in6_merge_msf_state(in6m, newhead, newmode, newnumsrc)
	struct in6_multi *in6m;
	struct i6as_head *newhead;	/* new i6ms_cur->head */
	u_int newmode;
	u_int16_t newnumsrc;
{
	struct in6_addr_source *ias = NULL, *newias, *nias;
	struct i6as_head curhead;	/* current i6ms_cur->head */
	u_int filter;
	int chg_flag = 0;
	int error = 0;

	/*
	 * Classify source filter mode pattern to merge pending State-Change
	 * Report easily.
	 * As for Filter-Mode-Change records, new record should not be merged
	 * with pending report even if exists. In this case, old pending
	 * record which has not transfered completely is cleared before new
	 * record is recorded. XXX my spec.
	 */
	if ((in6m->in6m_source->i6ms_mode == MCAST_EXCLUDE) &&
				(newmode == MCAST_EXCLUDE)) {
		filter = REPORT_FILTER2;
	} else if ((in6m->in6m_source->i6ms_mode == MCAST_INCLUDE) &&
				(newmode == MCAST_EXCLUDE)) {
		filter = REPORT_FILTER3;
		if (in6m->in6m_source->i6ms_toex != NULL) {
			in6_free_msf_source_list
					(in6m->in6m_source->i6ms_toex->head);
			in6m->in6m_source->i6ms_toex->numsrc = 0;
		}
	} else
		return EOPNOTSUPP; /* never occured... */
	mldlog((LOG_DEBUG, "in6_merge_msf_state: REPORT_FILTER%d\n", filter));

	/*
	 * If some error, e.g., ENOBUFS, will be occured later, State-Change
	 * Report won't be sent. However, filtered source list change has
	 * done, so it doesn't undo. This is not a big problem, since the
	 * responce for General Query, Current-State Record, will report
	 * every filtered source after some delay, even State-Change Report
	 * missed. This is simpler way.
	 */
	LIST_FIRST(&curhead) = LIST_FIRST(in6m->in6m_source->i6ms_cur->head);
	/* use following ias when newhead points NULL */
	ias = LIST_FIRST(in6m->in6m_source->i6ms_cur->head);
	LIST_FOREACH(newias, newhead, i6as_list) {
		LIST_FOREACH(ias, &curhead, i6as_list) {
			/* sanity check */
			if (ias->i6as_addr.sin6_family != newias->i6as_addr.sin6_family)
				continue;

			if (SS_CMP(&ias->i6as_addr, <, &newias->i6as_addr)) {
				if (filter == REPORT_FILTER3)
					continue;
				error = in6_merge_pending_report
						(in6m, ias, ALLOW_NEW_SOURCES);
				if (error != 0) {
					mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
					goto giveup;
				}
				++chg_flag;
				continue;
			}

			if (SS_CMP(&ias->i6as_addr, ==, &newias->i6as_addr)) {
				if (filter == REPORT_FILTER3) {
					error = in6_merge_pending_report
							(in6m, newias,
							CHANGE_TO_EXCLUDE_MODE);
					if (error != 0) {
						mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
						goto giveup;
					}
					++chg_flag;
				}
				LIST_FIRST(&curhead) = LIST_NEXT(ias, i6as_list);
				break;
			}

			/* i6as_addr > newias->i6as_addr */
			if (filter == REPORT_FILTER2) {
				error = in6_merge_pending_report
						(in6m, newias,
						BLOCK_OLD_SOURCES);
				if (error != 0) {
					mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
					goto giveup;
				}
				++chg_flag;
			} else if (filter == REPORT_FILTER3) {
				error = in6_merge_pending_report
						(in6m, newias,
						CHANGE_TO_EXCLUDE_MODE);
				if (error != 0) {
					mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
					goto giveup;
				}
				++chg_flag;
			}
			LIST_FIRST(&curhead) = ias;
			break;
		}
		if (error) {
			mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
			goto giveup;
		}

		if (!ias) {
			LIST_INIT(&curhead); /* stop list scan */
			if (filter == REPORT_FILTER2) {
				error = in6_merge_pending_report
						(in6m, newias,
						 BLOCK_OLD_SOURCES);
				if (error != 0) {
					mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
					goto giveup;
				}
				++chg_flag;
			} else if (filter == REPORT_FILTER3) {
				error = in6_merge_pending_report
						(in6m, newias,
						 CHANGE_TO_EXCLUDE_MODE);
				if (error != 0) {
					mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
					goto giveup;
				}
				++chg_flag;
			}
		}
	}
	if (error != 0) {
		mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
		goto giveup;
	}

	if (!newias && ias) {
		LIST_FOREACH(ias, &curhead, i6as_list) {
			if (filter != REPORT_FILTER2)
				break;

			error = in6_merge_pending_report
					(in6m, ias, ALLOW_NEW_SOURCES);
			if (error != 0) {
				mldlog((LOG_DEBUG, "in6_merge_msf_state: giveup!(line %d)\n", __LINE__));
				goto giveup;
			}
			++chg_flag;
		}
	}

	/*
	 * If there was no pending source list change, don't update robvar
	 * and group timer. (return code is 0.)
	 * Note that, in this case, an ALLOW or a BLOCK State-Change Report
	 * will not be newly sent, but a TO_IN or a TO_EX State-Change Report
	 * will be sent later.
	 */
	if (!chg_flag && (filter == REPORT_FILTER2)) {
		return 0;
	}

giveup:
	/*
	 * Make newhead a current filtered source list head and change to a
	 * new mode, and make this report the first of Robustness Variable
	 * transmissions of State-Change Reports.
	 * For Filter-Mode-Change records, each Source-List-Change record and
	 * contradictory pending record are cleared. XXX my spec.
	 */
	if (!LIST_EMPTY(in6m->in6m_source->i6ms_cur->head)) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_cur->head);
		in6m->in6m_source->i6ms_cur->numsrc = 0;
	}
	in6m->in6m_source->i6ms_mode = newmode;
	for (ias = LIST_FIRST(newhead); ias; ias = nias) {
		nias = LIST_NEXT(ias, i6as_list);
		if (LIST_EMPTY(in6m->in6m_source->i6ms_cur->head)) {
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_cur->head,
					 ias, i6as_list);
		} else {
			LIST_INSERT_AFTER(newias, ias, i6as_list);
		}
		newias = ias;
	}
	in6m->in6m_source->i6ms_cur->numsrc = newnumsrc;
	if (error == 0) {
		if (filter == REPORT_FILTER3) {
			if (in6m->in6m_source->i6ms_alw != NULL) {
				in6_free_msf_source_list
					(in6m->in6m_source->i6ms_alw->head);
				in6m->in6m_source->i6ms_alw->numsrc = 0;
			}
			if (in6m->in6m_source->i6ms_blk != NULL) {
				in6_free_msf_source_list
					(in6m->in6m_source->i6ms_blk->head);
				in6m->in6m_source->i6ms_blk->numsrc = 0;
			}
			if (in6m->in6m_source->i6ms_toin != NULL) {
				in6_free_msf_source_list
					(in6m->in6m_source->i6ms_toin->head);
				in6m->in6m_source->i6ms_toin->numsrc = 0;
			}
		}
	} else {
		mldlog((LOG_DEBUG, "in6_merge_msf_state: Pending source list merge failed. State-Change Report won't be sent.\n"));
		in6_clear_pending_report(in6m, filter);
	}

	return error;
}

void
in6_clear_all_pending_report(in6m)
	struct in6_multi *in6m;
{
	in6_clear_pending_report(in6m, REPORT_FILTER1); /* covering FILTER2 */
	in6_clear_pending_report(in6m, REPORT_FILTER3);
	in6_clear_pending_report(in6m, REPORT_FILTER4);
}

/*
 * If pending source merge was failed, source filter mode and current list
 * head are updated (since these are correct) but new State-Change report
 * will not be sent. That change is notified by responce of later Queries.
 */
static void
in6_clear_pending_report(in6m, filter)
	struct in6_multi *in6m;
	u_int filter;
{
	if ((filter == REPORT_FILTER1) || (filter == REPORT_FILTER2)) {
		if (in6m->in6m_source->i6ms_alw != NULL) {
			in6_free_msf_source_list
					(in6m->in6m_source->i6ms_alw->head);
			in6m->in6m_source->i6ms_alw->numsrc = 0;
		}
		if (in6m->in6m_source->i6ms_blk != NULL) {
			in6_free_msf_source_list
					(in6m->in6m_source->i6ms_blk->head);
			in6m->in6m_source->i6ms_blk->numsrc = 0;
		}
	/*
	 * TO_IN and TO_EX lists must be completely removed.
	 */
	} else if (filter == REPORT_FILTER3) {
		if (in6m->in6m_source->i6ms_toex != NULL) {
			in6_free_msf_source_list
					(in6m->in6m_source->i6ms_toex->head);
			FREE(in6m->in6m_source->i6ms_toex->head, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_toex, M_MSFILTER);
			in6m->in6m_source->i6ms_toex = NULL;
		}
	} else {
		if (in6m->in6m_source->i6ms_toin != NULL) {
			in6_free_msf_source_list
					(in6m->in6m_source->i6ms_toin->head);
			FREE(in6m->in6m_source->i6ms_toin->head, M_MSFILTER);
			FREE(in6m->in6m_source->i6ms_toin, M_MSFILTER);
			in6m->in6m_source->i6ms_toin = NULL;
		}
	}
}

/*
 * The transmission of the merged State-Change Report terminates
 * retransmissions of the earlier State-Change Reports for the same multicast
 * address, and becomes the first of [Robustness Variable] transmissions of
 * State-Change Reports.
 * In order to ensure that state changes do not break the protocol logic,
 * contradictory pending records are freed. XXX my spec.
 */
static int
in6_merge_pending_report(in6m, ias, type)
	struct in6_multi *in6m;
	struct in6_addr_source *ias;
	u_int8_t type;
{
	struct in6_addr_source *newias;
	int ref_count;
	int error = 0;

	switch (type) {
	case ALLOW_NEW_SOURCES:
		if (in6m->in6m_source->i6ms_alw == NULL) {
			I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_alw);
			if (error != 0)
				return error;
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				/*
				 * We don't remove i6ms_alw created above,
				 * since it may be needed to re-create later.
				 * This will be finally cleaned when every
				 * application leaves from this group.
				 */
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_alw->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_alw->numsrc = 1;
		} else if (LIST_EMPTY(in6m->in6m_source->i6ms_alw->head)) {
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_alw->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_alw->numsrc = 1;
		} else if ((ref_count = in6_merge_msf_source_addr
						(in6m->in6m_source->i6ms_alw,
						 &ias->i6as_addr,
						 IMS_ADD_SOURCE)) < 0) {
			mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++in6m->in6m_source->i6ms_alw->numsrc;
		/* If merge fail occurs, return error, no undo. Otherwise,
		 * clear the same source address for opposite filter (i.e.,
		 * BLOCK if ALLOW is the new request) if it exists. */
		if (in6m->in6m_source->i6ms_blk != NULL)
			in6_free_msf_source_addr(in6m->in6m_source->i6ms_blk,
						 &ias->i6as_addr);
		return 0;

	case BLOCK_OLD_SOURCES:
		if (in6m->in6m_source->i6ms_blk == NULL) {
			I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_blk);
			if (error != 0)
				return error;
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_blk->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_blk->numsrc = 1;
		} else if (LIST_EMPTY(in6m->in6m_source->i6ms_blk->head)) {
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_blk->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_blk->numsrc = 1;
		} else if ((ref_count = in6_merge_msf_source_addr
						(in6m->in6m_source->i6ms_blk,
						 &ias->i6as_addr,
						 IMS_ADD_SOURCE)) < 0) {
			mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++in6m->in6m_source->i6ms_blk->numsrc;
		if (in6m->in6m_source->i6ms_alw != NULL)
			in6_free_msf_source_addr(in6m->in6m_source->i6ms_alw,
						 &ias->i6as_addr);
		return 0;

	case CHANGE_TO_INCLUDE_MODE:
		if (in6m->in6m_source->i6ms_toin == NULL) {
			I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_toin);
			if (error != 0)
				return error;
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_toin->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_toin->numsrc = 1;
		} else if (LIST_EMPTY(in6m->in6m_source->i6ms_toin->head)) {
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_toin->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_toin->numsrc = 1;
		} else if ((ref_count = in6_merge_msf_source_addr
						(in6m->in6m_source->i6ms_toin,
						 &ias->i6as_addr,
						 IMS_ADD_SOURCE)) < 0) {
			mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++in6m->in6m_source->i6ms_toin->numsrc;
		return 0;

	case CHANGE_TO_EXCLUDE_MODE:
		if (in6m->in6m_source->i6ms_toex == NULL) {
			I6AS_LIST_ALLOC(in6m->in6m_source->i6ms_toex);
			if (error != 0)
				return error;
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_toex->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_toex->numsrc = 1;
		} else if (LIST_EMPTY(in6m->in6m_source->i6ms_toex->head)) {
			MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(&ias->i6as_addr, &newias->i6as_addr,
			      ias->i6as_addr.sin6_len);
			newias->i6as_refcount = 1;
			LIST_INSERT_HEAD(in6m->in6m_source->i6ms_toex->head,
					 newias, i6as_list);
			in6m->in6m_source->i6ms_toex->numsrc = 1;
		} else if ((ref_count = in6_merge_msf_source_addr
						(in6m->in6m_source->i6ms_toex,
						 &ias->i6as_addr,
						 IMS_ADD_SOURCE)) < 0) {
			mldlog((LOG_DEBUG, "in6_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++in6m->in6m_source->i6ms_toex->numsrc;
		return 0;
	}
	return EOPNOTSUPP; /* XXX */
}

/*
 * Copy each source address from original head to new one, in order to
 * make a new current state source list.
 * If refcount is 0, all sources except i6as_refcount = 0 are copied.
 * If it's not 0, only sources whose i6as_refcount = refcount are copied.
 */
static int
in6_copy_msf_source_list(iasl, newiasl, refcount)
	struct in6_addr_slist *iasl, *newiasl;
	u_int refcount;
{
	struct in6_addr_source *ias, *newias, *lastp = NULL;
	u_int16_t i = 0;

	if ((newiasl == NULL) || !LIST_EMPTY(newiasl->head))
		return EINVAL;

	LIST_FOREACH(ias, iasl->head, i6as_list) {
		if ((ias->i6as_refcount == 0) ||
			(refcount != 0 && ias->i6as_refcount != refcount))
			continue;
		MALLOC(newias, struct in6_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
		if (newias == NULL) {
			in6_free_msf_source_list(newiasl->head);
			newiasl->numsrc = 0;
			mldlog((LOG_DEBUG, "in6_copy_msf_source_list: ENOBUFS\n"));
			return ENOBUFS;
		}
		if (LIST_EMPTY(newiasl->head)) {
			LIST_INSERT_HEAD(newiasl->head, newias, i6as_list);
		} else {
			LIST_INSERT_AFTER(lastp, newias, i6as_list);
		}
		bcopy(&ias->i6as_addr, &newias->i6as_addr,
		      ias->i6as_addr.sin6_len);
		newias->i6as_refcount = 1;
		++i;
		lastp = newias;
	}
	newiasl->numsrc = i;
	return 0;
}

void
in6_free_all_msf_source_list(in6m)
	struct in6_multi *in6m;
{
	if ((in6m == NULL) || (in6m->in6m_source == NULL))
		return;

	if (in6m->in6m_source->i6ms_cur != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_cur->head);
		if (in6m->in6m_source->i6ms_cur->head != NULL)
			FREE(in6m->in6m_source->i6ms_cur->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_cur, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_rec != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_rec->head);
		if (in6m->in6m_source->i6ms_rec->head != NULL)
			FREE(in6m->in6m_source->i6ms_rec->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_rec, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_in != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_in->head);
		if (in6m->in6m_source->i6ms_in->head != NULL)
			FREE(in6m->in6m_source->i6ms_in->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_in, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_ex != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_ex->head);
		if (in6m->in6m_source->i6ms_ex->head != NULL)
			FREE(in6m->in6m_source->i6ms_ex->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_ex, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_alw != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_alw->head);
		if (in6m->in6m_source->i6ms_alw->head != NULL)
			FREE(in6m->in6m_source->i6ms_alw->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_alw, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_blk != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_blk->head);
		if (in6m->in6m_source->i6ms_blk->head != NULL)
			FREE(in6m->in6m_source->i6ms_blk->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_blk, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_toin != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_toin->head);
		if (in6m->in6m_source->i6ms_toin->head != NULL)
			FREE(in6m->in6m_source->i6ms_toin->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_toin, M_MSFILTER);
	}
	if (in6m->in6m_source->i6ms_toex != NULL) {
		in6_free_msf_source_list(in6m->in6m_source->i6ms_toex->head);
		if (in6m->in6m_source->i6ms_toex->head != NULL)
			FREE(in6m->in6m_source->i6ms_toex->head, M_MSFILTER);
		FREE(in6m->in6m_source->i6ms_toex, M_MSFILTER);
	}
	FREE(in6m->in6m_source, M_MSFILTER);
}

void
in6_free_msf_source_list(head)
	struct i6as_head *head;
{
	struct in6_addr_source *ias, *nias;

	if (head == NULL)
		return;
	for (ias = LIST_FIRST(head); ias; ias = nias) {
		nias = LIST_NEXT(ias, i6as_list);
		LIST_REMOVE(ias, i6as_list);
		FREE(ias, M_MSFILTER);
	}
	LIST_INIT(head);
}

void
in6_free_msf_source_addr(iasl, src)
	struct in6_addr_slist *iasl;
	struct sockaddr_in6 *src;
{
	struct in6_addr_source *ias, *nias;

	if (iasl == NULL)
		return;
	for (ias = LIST_FIRST(iasl->head); ias; ias = nias) {
		nias = LIST_NEXT(ias, i6as_list);
		/* sanity check */
		if (ias->i6as_addr.sin6_family != src->sin6_family)
			continue;

		if (SS_CMP(&ias->i6as_addr, <, src))
			continue;
		else if (SS_CMP(&ias->i6as_addr, ==, src)) {
			LIST_REMOVE(ias, i6as_list);
			FREE(ias, M_MSFILTER);
			--iasl->numsrc;
			break;
		} else
			break; /* source address not match */
	}
	if (iasl->numsrc == 0)
		LIST_INIT(iasl->head);
}

/*
 * Merge source address into appropriate filter's source list of the interface.
 * This should not be called when there is no iasl entry.
 * This returns;
 *	when request is to add source address;
 *		more than 0: source reference count
 *		-1: error (ENOBUFS)
 *	when request is to delete source address;
 *		more than or equal to 0: source reference count
 *		-1: error (EADDRNOTAVAIL)
 */
int
in6_merge_msf_source_addr(iasl, src, req)
	struct in6_addr_slist *iasl;	/* target source list */
	struct sockaddr_in6 *src;	/* source to be merged */
	int req;			/* request to add or delete */
{
	struct in6_addr_source *ias, *newias, *lastp = NULL;

	LIST_FOREACH(ias, iasl->head, i6as_list) {
		lastp = ias;
		/* sanity check */
		if (ias->i6as_addr.sin6_family != src->sin6_family)
			continue;

		if (SS_CMP(&ias->i6as_addr, ==, src)) {
			if (req == IMS_ADD_SOURCE)
				return (++ias->i6as_refcount);
			return (--ias->i6as_refcount);
		}
		if (SS_CMP(&ias->i6as_addr, <=, src))
			continue;

		/* here's the place to insert the source address entry */
		if (req != IMS_ADD_SOURCE) {
			mldlog((LOG_DEBUG, "in_merge_msf_source_addr: %s cannot be deleted!?\n",
			       ip6_sprintf(SIN6_ADDR(src))));
			return -1;
		}
		MALLOC(newias, struct in6_addr_source *,
			sizeof(*newias), M_MSFILTER, M_NOWAIT);
		if (newias == NULL)
			return -1;
		LIST_INSERT_BEFORE(ias, newias, i6as_list);
		bcopy(src, &newias->i6as_addr, src->sin6_len);
		newias->i6as_refcount = 1;
		return (newias->i6as_refcount);
	}

	/*
	 * creates a new source address in the specified source filter,
	 * as there's no source address at all.
	 */
	if (req != IMS_ADD_SOURCE) {
		mldlog((LOG_DEBUG, "in6_merge_msf_source_addr: source address cannot be deleted? (really occurs?)\n"));
		return -1;
	}
	MALLOC(newias, struct in6_addr_source *,
		sizeof(*newias), M_MSFILTER, M_NOWAIT);
	if (newias == NULL) {
		mldlog((LOG_DEBUG, "in_merge_msf_source_addr: %s cannot be deleted!?\n", ip6_sprintf(SIN6_ADDR(src))));
		return -1;
	}

	if (LIST_EMPTY(iasl->head)) {
		LIST_INSERT_HEAD(iasl->head, newias, i6as_list);
	} else {
		LIST_INSERT_AFTER(lastp, newias, i6as_list);
	}
	bcopy(src, &newias->i6as_addr, src->sin6_len);
	newias->i6as_refcount = 1;
	return (newias->i6as_refcount);
}

/*
 * Set multicast source filter of a socket (SIOCSMSFILTER)
 */
int
sock6_setmopt_srcfilter(sop, grpfp)
	struct socket *sop;
	struct group_filter **grpfp;
{
	struct in6pcb *ipcbp;
	struct ip6_moptions *imop;
	struct in6_multi_mship *imm = NULL;
	struct sock_msf *msf;
	struct ifnet *ifp;
	struct group_filter ogrpf;
	struct group_filter *grpf;
	struct sockaddr *sa_grp;
	struct sockaddr_storage *ss, *ss_src, *old_ss;
	u_int16_t add_num, old_num;
	u_int old_mode;
	struct sockaddr *dst;
	struct route ro;
	struct sock_msf_source *msfsrc, *nmsfsrc;
	struct in6_addr_slist *iasl = NULL;
	struct in6_addr_source *ias;
	int error = 0;
	int init, final;
	int j;
	int s;

	if (*grpfp == NULL)
		return EINVAL;

	error = copyin((void *)*grpfp, (void *)&ogrpf, GROUP_FILTER_SIZE(0));
	if (error != 0) {
		mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: copyin error.\n"));
		return error;
	}
	grpf = &ogrpf;

	if (grpf->gf_numsrc >= mldsomaxsrc) {
		mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: the number of sources is reached to max count.\n"));
		return EINVAL;
	}
	if (grpf->gf_group.ss_family != AF_INET6)
		return EPFNOSUPPORT;

	sa_grp = (struct sockaddr *) &grpf->gf_group;
	if (sa_grp->sa_family != AF_INET6)
		return EPFNOSUPPORT;
	if (!IN6_IS_ADDR_MULTICAST(SIN6_ADDR(sa_grp)))
		return EINVAL;
	if (grpf->gf_numsrc != 0 && !in6_is_mld_target(SIN6_ADDR(sa_grp)))
		return EINVAL;

	/*
	 * Get a pointer of ifnet structure to the interface.
	 */
	if ((grpf->gf_interface < 0) || (if_indexlim <= grpf->gf_interface))
		return ENXIO;	/* XXX EINVAL? */
	/*
	 * If no interface was explicitly specified, choose an appropriate
	 * one according to the given multicast address.
	 */
	if (grpf->gf_interface == 0) {
		bzero((caddr_t)&ro, sizeof(ro));
		ro.ro_rt = NULL;
		dst = (struct sockaddr *) satosin6(&ro.ro_dst);
		bcopy(sa_grp, dst, sa_grp->sa_len);
		rtalloc((struct route *)&ro);
		if (ro.ro_rt == NULL)
			return EADDRNOTAVAIL;
		ifp = ro.ro_rt->rt_ifp;
		rtfree(ro.ro_rt);
	} else {
#ifdef __FreeBSD__
		ifp = ifnet_byindex(grpf->gf_interface);
#else
		ifp = ifindex2ifnet[grpf->gf_interface];
#endif
	}

	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0)
		return EADDRNOTAVAIL;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	s = splsoftnet();
#else
	s = splnet();
#endif

	/*
	 * If there are no multicast options associated with this socket,
	 * add them.
	 */
	if ((ipcbp = (struct in6pcb *)sop->so_pcb) == NULL) {
		splx(s);
		return EINVAL;
	}
	if ((imop = ipcbp->in6p_moptions) == NULL) {
		imop = (struct ip6_moptions *)
			malloc(sizeof(*imop), M_IPMOPTS, M_NOWAIT);
		if (imop == NULL) {
			splx(s);
			return ENOBUFS;
		}
		imop->im6o_multicast_ifp = ifp;
		imop->im6o_multicast_hlim = ip6_defmcasthlim;
		imop->im6o_multicast_loop = (ip6_mrouter != NULL);
		LIST_INIT(&imop->im6o_memberships);
		ipcbp->in6p_moptions = imop;
	}

	IN6_LOOKUP_MSHIP(SIN6(sa_grp)->sin6_addr, ifp, imop, imm);
	if (imm != NULL) {
		msf = imm->i6mm_msf;
		if (grpf->gf_fmode == MCAST_EXCLUDE &&
		    grpf->gf_numsrc == 0 &&
		    msf != NULL &&
		    msf->msf_grpjoin != 0 &&
		    msf->msf_blknumsrc == 0) {
			splx(s);
			return EADDRINUSE;
		}
		init = 0;
	} else {
		if ((grpf->gf_fmode == MCAST_INCLUDE) &&
		    (grpf->gf_numsrc == 0)) {
			splx(s);
			return EADDRNOTAVAIL;
		}
		imm = (struct in6_multi_mship *)
			malloc(sizeof(*imm), M_IPMADDR, M_NOWAIT);
		if (!imm) {
			splx(s);
			return ENOBUFS;
		}
		IMO_MSF_ALLOC(imm->i6mm_msf);
		if (error != 0) {
			splx(s);
			FREE(imm, M_IPMADDR);
			return error;
		}
		msf = imm->i6mm_msf;
		LIST_INSERT_HEAD(&imop->im6o_memberships, imm,
				 i6mm_chain);
		init = 1;
	}

	/*
	 * Prepare sock_storage for in6_addmulti2(), in6_delmulti2(), and
	 * in6_modmulti2(). Input source lists are sorted below.
	 */
	if (grpf->gf_numsrc != 0) {
		I6AS_LIST_ALLOC(iasl);
		if (error != 0) {
			if (init) {
				IMO_MSF_FREE(msf);
				LIST_REMOVE(imm, i6mm_chain);
				FREE(imm, M_IPMADDR);
			}
			splx(s);
			return error;
		}
		MALLOC(ss, struct sockaddr_storage *, sizeof(*ss),
		       M_IPMOPTS, M_NOWAIT);
		if (ss == NULL) {
			error = ENOBUFS;
			goto nocopy;
		}
		for (j = 0; j < grpf->gf_numsrc; j++) {
			error = copyin((void *)&(*grpfp)->gf_slist[j],
				       (void *)ss,
				       (*grpfp)->gf_slist[j].ss_len);
			if (error != 0) /* EFAULT */
				break;
			if (ss->ss_family == AF_INET) {
#if defined(__NetBSD__) || defined(__OpenBSD__)
				if (IN_BADCLASS(SIN_ADDR(ss)) ||
				    (SIN_ADDR(ss) & IN_CLASSA_NET) == 0)
#else
				if (IN_BADCLASS(ntohl(SIN_ADDR(ss))) ||
				    (ntohl(SIN_ADDR(ss)) & IN_CLASSA_NET) == 0)
#endif
				{
					error = EINVAL;
					break;
				}
			} else if (ss->ss_family == AF_INET6) {
				if (error != 0)
					break;
			} else {
				error = EAFNOSUPPORT;
				break;
			}

			if (SS_IS_ADDR_MULTICAST(ss) ||
			    SS_IS_ADDR_UNSPECIFIED(ss)) {
				error = EINVAL;
				break;
			}

			/*
			 * Sort and validate source lists. Duplicate addresses
			 * can be checked here.
			 */
			if (in6_merge_msf_source_addr(iasl, SIN6(ss),
						      IMS_ADD_SOURCE) != 1) {
				error = EINVAL;
				break;
			}
		}

	nocopy:
		if (error != 0) {
			in6_free_msf_source_list(iasl->head);
			FREE(iasl->head, M_MSFILTER);
			FREE(iasl, M_MSFILTER);
			if (init) {
				IMO_MSF_FREE(msf);
				LIST_REMOVE(imm, i6mm_chain);
				FREE(imm, M_IPMADDR);
			}
			splx(s);
			return error;
		}

		/*
		 * Copy source lists to ss_src.
		 */
		MALLOC(ss_src, struct sockaddr_storage *,
		       sizeof(struct sockaddr_storage) * grpf->gf_numsrc,
		       M_IPMOPTS, M_NOWAIT);
		if (ss_src == NULL) {
			in6_free_msf_source_list(iasl->head);
			FREE(iasl->head, M_MSFILTER);
			FREE(iasl, M_MSFILTER);
			if (init) {
				IMO_MSF_FREE(msf);
				LIST_REMOVE(imm, i6mm_chain);
				FREE(imm, M_IPMADDR);
			}
			splx(s);
			return ENOBUFS;
		}
		for (j = 0, ias = LIST_FIRST(iasl->head);
		     j < grpf->gf_numsrc && ias;
		     j++, ias = LIST_NEXT(ias, i6as_list)) {
			bcopy(&ias->i6as_addr, &ss_src[j],
			      ias->i6as_addr.sin6_len);
		}
		in6_free_msf_source_list(iasl->head);
		FREE(iasl->head, M_MSFILTER);
		FREE(iasl, M_MSFILTER);
	} else
		ss_src = NULL;

	/*
	 * Prepare old msf source list space.
	 */
	old_ss = NULL;
	old_mode = MCAST_INCLUDE;
	msf = imm->i6mm_msf;
	if (msf->msf_grpjoin != 0 && msf->msf_blknumsrc == 0)
		old_mode = MCAST_EXCLUDE;
	else if (msf->msf_numsrc != 0) {
		MALLOC(old_ss, struct sockaddr_storage *,
		       sizeof(*old_ss) * msf->msf_numsrc,
		       M_IPMOPTS, M_NOWAIT);
		if (old_ss == NULL) {
			if (ss_src != NULL)
				FREE(ss_src, M_IPMOPTS);
			splx(s);
			return ENOBUFS;
		}
		old_mode = MCAST_INCLUDE;
	} else if (msf->msf_blknumsrc != 0) {
		MALLOC(old_ss, struct sockaddr_storage *,
			sizeof(*old_ss) * msf->msf_blknumsrc,
			M_IPMOPTS, M_NOWAIT);
		if (old_ss == NULL) {
			if (ss_src != NULL)
				FREE(ss_src, M_IPMOPTS);
			splx(s);
			return ENOBUFS;
		}
		old_mode = MCAST_EXCLUDE;
	}

	/*
	 * Set new source addresses to the msf. And insert old source
	 * addresses to old_ss if needed.
	 */
	add_num = old_num = 0;
	error = in6_setmopt_source_list(msf, grpf->gf_numsrc,
					ss_src, grpf->gf_fmode,
					&add_num, &old_num, old_ss);
	if (error != 0) {
		if (old_ss != NULL)
			FREE(old_ss, M_IPMOPTS);
		if (ss_src != NULL)
			FREE(ss_src, M_IPMOPTS);
		if (init) {
			IMO_MSF_FREE(msf);
			LIST_REMOVE(imm, i6mm_chain);
			FREE(imm, M_IPMADDR);
		}
		splx(s);
		return error;
	}

	/*
	 * Everything looks good; add a new record to the multicast address
	 * list for the given interface and/or delete an unneeded record
	 * from the multicast address list.
	 * But if some error occurs when source list is added to the list,
	 * undo msf list change.
	 */
	final = 0;
	if ((grpf->gf_fmode == MCAST_INCLUDE) && (grpf->gf_numsrc == 0)) {
		final = 1;
		if (msf->msf_grpjoin != 0 && msf->msf_blknumsrc == 0) {
			in6_delmulti2(imm->i6mm_maddr, &error, 0, NULL,
				      MCAST_EXCLUDE, final);
			if (error != 0) {
				mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: error must be 0! panic!\n"));
				splx(s);
				return error;
			}
		} else {
			in6_delmulti2(imm->i6mm_maddr, &error, old_num,
				     old_ss, old_mode, final);
			if (error != 0) {
				mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: error %d. undo for IN{non NULL}/EX{non NULL} -> IN{NULL}\n", error));
				in6_undomopt_source_list(msf, grpf->gf_fmode);
				if (old_num != 0)
					FREE(old_ss, M_IPMOPTS);
				splx(s);
				return error;
			}
		}
	} else if ((grpf->gf_fmode == MCAST_EXCLUDE) &&
				(grpf->gf_numsrc == 0)) {
		if (old_num > 0) {
			imm->i6mm_maddr =
				in6_modmulti2(&SIN6(sa_grp)->sin6_addr,
					      ifp, &error,
					      0, NULL, MCAST_EXCLUDE, old_num,
					      old_ss, old_mode, init, 0);
		} else {
			imm->i6mm_maddr =
				in6_addmulti2(&SIN6(sa_grp)->sin6_addr,
					      ifp, &error,
					      0, NULL, MCAST_EXCLUDE, init, 0);
		}
		if (error != 0) {
			mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: error %d. undo for IN{non NULL}/EX{non NULL} -> EX{NULL} or IN{NULL} -> EX{NULL}\n", error));
			in6_undomopt_source_list(msf, grpf->gf_fmode);
			if (old_num != 0)
				FREE(old_ss, M_IPMOPTS);
			if (init) {
				IMO_MSF_FREE(msf);
				LIST_REMOVE(imm, i6mm_chain);
				FREE(imm, M_IPMADDR);
			}
			splx(s);
			return error;
		}
	} else {
		/* no change or only delete some sources */
		if (add_num == 0) {
			if (old_num == 0) {
				mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: no change\n"));
				splx(s);
				return 0;
			}
			if (imm == NULL) {
				mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: NULL pointer?\n"));
				splx(s);
				return EOPNOTSUPP;
			}
			in6_delmulti2(imm->i6mm_maddr, &error, old_num,
				      old_ss, old_mode, final);
			if (error != 0) {
				mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: in6_delmulti2 retuned error=%d. undo.\n", error));
				in6_undomopt_source_list(msf, grpf->gf_fmode);
				FREE(old_ss, M_IPMOPTS);
				if (ss_src != NULL)
					FREE(ss_src, M_IPMOPTS);
				splx(s);
				return error;
			}
		} else {
			imm->i6mm_maddr =
				in6_modmulti2(&SIN6(sa_grp)->sin6_addr,
					      ifp, &error,
					      grpf->gf_numsrc, ss_src,
					      grpf->gf_fmode, old_num,
					      old_ss, old_mode, init,
					      msf->msf_grpjoin);
			if (error != 0) {
				mldlog((LOG_DEBUG, "sock6_setmopt_srcfilter: in6_modmulti2 returned error=%d. undo.\n", error));
				in6_undomopt_source_list(msf, grpf->gf_fmode);
				if (old_num != 0)
					FREE(old_ss, M_IPMOPTS);
				if (ss_src != NULL)
					FREE(ss_src, M_IPMOPTS);
				if (init) {
					IMO_MSF_FREE(msf);
					LIST_REMOVE(imm, i6mm_chain);
					FREE(imm, M_IPMADDR);
				}
				splx(s);
				return error;
			}
		}
	}

	/*
	 * If application requests mode change with filtered sources, clean
	 * up old msf list.
	 * If there is some old msfsrc in a msf list, clean up.
	 * And all remaining refcounts are set to 1.
	 */
	if (grpf->gf_fmode == MCAST_INCLUDE) {
		if (old_mode == MCAST_EXCLUDE)
			in6_freemopt_source_list(msf, NULL, msf->msf_blkhead);
		else {
			for (msfsrc = LIST_FIRST(msf->msf_head);
			     msfsrc; msfsrc = nmsfsrc) {
				nmsfsrc = LIST_NEXT(msfsrc, list);
				if (msfsrc->refcount == 0) {
					LIST_REMOVE(msfsrc, list);
					FREE(msfsrc, M_IPMOPTS);
					--msf->msf_numsrc;
				} else
					msfsrc->refcount = 1;
			}
		}
	} else {
		if (old_mode == MCAST_INCLUDE)
			in6_freemopt_source_list(msf, msf->msf_head, NULL);
		else {
			for (msfsrc = LIST_FIRST(msf->msf_blkhead);
			     msfsrc; msfsrc = nmsfsrc) {
				nmsfsrc = LIST_NEXT(msfsrc, list);
				if (msfsrc->refcount == 0) {
					LIST_REMOVE(msfsrc, list);
					FREE(msfsrc, M_IPMOPTS);
					--msf->msf_blknumsrc;
				} else
					msfsrc->refcount = 1;
			}
		}
	}

	if (grpf->gf_fmode == MCAST_INCLUDE) {
		msf->msf_grpjoin = 0;
	} else { /* grpf->gf_fmode == MCAST_EXCLUDE)*/
		msf->msf_grpjoin = 1;
	}


	if (grpf->gf_numsrc == 0) {
		in6_freemopt_source_list(msf, msf->msf_head, msf->msf_blkhead);
		/*
		 * Remove the gap in the membership array if there is no
		 * msf member.
		 */
		if (final) {
			IMO_MSF_FREE(msf);
			LIST_REMOVE(imm, i6mm_chain);
			FREE(imm, M_IPMADDR);
		}
	}

	if (old_ss != NULL)
		FREE(old_ss, M_IPMOPTS);
	if (ss_src != NULL)
		FREE(ss_src, M_IPMOPTS);

	splx(s);
	return 0;
}

/*
 * Get multicast source filter of a socket (SIOCGMSFILTER)
 */
int
sock6_getmopt_srcfilter(sop, grpfp)
	struct socket *sop;
	struct group_filter **grpfp;
{
	struct in6pcb *ipcbp;
	struct ip6_moptions *imop;
	struct in6_multi_mship *imm;
	struct sock_msf *msf;
	struct ifnet *ifp;
	struct group_filter ogrpf;
	struct group_filter *grpf;
	struct sockaddr *sa_grp;
	struct sock_msf_source *msfsrc;
	struct msf_head head;
	u_int16_t numsrc;
	int i;
	int error;

	if (*grpfp == NULL)
		return EINVAL;

	if ((error = copyin((void *)*grpfp, (void *)&ogrpf,
			GROUP_FILTER_SIZE(0))) != 0) {
		mldlog((LOG_DEBUG, "sock6_getmopt_srcfilter: copyin error.\n"));
		return error;
	} else
		grpf = &ogrpf;

	/*
	 * Get a pointer of ifnet structure to the interface.
	 */
	if ((grpf->gf_interface < 0) || (if_indexlim <= grpf->gf_interface))
		return EADDRNOTAVAIL;
	if (grpf->gf_interface == 0)
		ifp = NULL;
	else {
#ifdef __FreeBSD__
		ifp = ifnet_byindex(grpf->gf_interface);
#else
		ifp = ifindex2ifnet[grpf->gf_interface];
#endif
		if (ifp == NULL)
			return EINVAL;
	}

	if ((ipcbp = (struct in6pcb *)sop->so_pcb) == NULL)
		return EINVAL;
	if ((imop = ipcbp->in6p_moptions) == NULL)
		return EINVAL;

	sa_grp = (struct sockaddr *) &grpf->gf_group;
	if (sa_grp->sa_family != AF_INET6)
		return EPFNOSUPPORT;
	if (!IN6_IS_ADDR_MULTICAST(&SIN6(sa_grp)->sin6_addr))
		return EINVAL;

	IN6_LOOKUP_MSHIP(SIN6(sa_grp)->sin6_addr, ifp, imop, imm);
	if (imm == NULL) {
		/* no msf entry */
		grpf->gf_numsrc = 0;
		grpf->gf_fmode = MCAST_INCLUDE;
		error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0));
		return error;
	}

	msf = imm->i6mm_msf;

	if (msf->msf_grpjoin != 0 && msf->msf_blknumsrc == 0) {
		/* (*,G) join */
		grpf->gf_numsrc = 0;
		grpf->gf_fmode = MCAST_EXCLUDE;
		error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0));
		return error;
	} else if ((msf->msf_numsrc == 0) && (msf->msf_blknumsrc == 0)) {
		/* no msf entry */
		grpf->gf_numsrc = 0;
		grpf->gf_fmode = MCAST_INCLUDE;
		error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0));
		return error;
	}

	if (msf->msf_numsrc > 0) {
		grpf->gf_fmode = MCAST_INCLUDE;
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
		numsrc = min(msf->msf_numsrc, grpf->gf_numsrc);
	} else {
		grpf->gf_fmode = MCAST_EXCLUDE;
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
		numsrc = min(msf->msf_blknumsrc, grpf->gf_numsrc);
	}
	grpf->gf_numsrc = numsrc;
	if ((error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0))) != 0)
		return error;

	for (msfsrc = LIST_FIRST(&head), i = 0; numsrc > i && msfsrc;
	     ++i, msfsrc = LIST_NEXT(msfsrc, list)) {
		error = copyout((void *)&msfsrc->src,
				(void *)&((*grpfp)->gf_slist[i]),
				msfsrc->src.ss_len);
		if (error != 0) {
			return error;
		}
	}

	return 0;
}

int
in6_getmopt_source_list(msf, numsrc, oss, mode)
	struct sock_msf *msf;
	u_int16_t *numsrc;
	struct sockaddr_storage **oss;
	u_int *mode;
{
	return (in_getmopt_source_list(msf, numsrc, oss, mode));
}

int
in6_setmopt_source_addr(ss, msf, optname)
	struct sockaddr_storage *ss;
	struct sock_msf *msf;
	int optname;
{
	return (in_setmopt_source_addr(ss, msf, optname));
}

int
in6_setmopt_source_list(msf, numsrc, ss, mode, add_num, old_num, old_ss)
	struct sock_msf *msf;
	u_int16_t numsrc;
	struct sockaddr_storage *ss, *old_ss;
	u_int mode;
	u_int16_t *add_num, *old_num;
{
	return (in_setmopt_source_list(msf, numsrc, ss, mode, add_num,
				       old_num, old_ss));
}

void
in6_undomopt_source_addr(msf, optname)
	struct sock_msf *msf;
	int optname;
{
	if (optname != MCAST_JOIN_SOURCE_GROUP &&
	    optname != MCAST_LEAVE_SOURCE_GROUP &&
	    optname != MCAST_BLOCK_SOURCE &&
	    optname != MCAST_UNBLOCK_SOURCE)
		return;
	in_cleanmopt_source_addr(msf, optname);
}

void
in6_cleanmopt_source_addr(msf, optname)
	struct sock_msf *msf;
	int optname;
{
	if (optname != MCAST_JOIN_SOURCE_GROUP &&
	    optname != MCAST_LEAVE_SOURCE_GROUP &&
	    optname != MCAST_BLOCK_SOURCE &&
	    optname != MCAST_UNBLOCK_SOURCE)
		return;

	in_cleanmopt_source_addr(msf, optname);
}

void
in6_undomopt_source_list(msf, mode)
	struct sock_msf *msf;
	u_int mode;
{
	in_undomopt_source_list(msf, mode);
}

void
in6_freemopt_source_list(msf, msf_head, msf_blkhead)
	struct sock_msf *msf;
	struct msf_head *msf_head;
	struct msf_head *msf_blkhead;
{
	in_freemopt_source_list(msf, msf_head, msf_blkhead);
}

/*
 * check if the given IP address matches with the MSF (per-interface
 * source filter). return 1/0 if matches/not matches, respectively.
 */
int
match_msf6_per_if(in6m, src, dst)
	struct in6_multi *in6m;
	struct in6_addr *src;
	struct in6_addr *dst;
{
	struct in6_multi_source *in6ms;
	struct in6_addr_source *i6as;

	in6ms = in6m->in6m_source;
	/* in6ms is NULL only in case of ff02::1 and ffx{0,1}:: */
	if (in6ms == NULL) {
		/* assumes ffx{0,1} case has already been eliminated */
		if (!in6_is_mld_target(dst))
			return 1;
		mldlog((LOG_DEBUG, "grp found, but src is NULL. impossible"));
		return 0;
	}
	if (in6ms->i6ms_grpjoin != 0) {
		if (in6ms->i6ms_mode != MCAST_EXCLUDE)
			return 0;	/* XXX: impossible */
		if (in6ms->i6ms_cur == NULL || in6ms->i6ms_cur->numsrc == 0)
			return 1;
	}

	if (in6ms->i6ms_cur == NULL || in6ms->i6ms_cur->head == NULL)
		return 0;

	LIST_FOREACH(i6as, in6ms->i6ms_cur->head, i6as_list) {
		if (i6as->i6as_addr.sin6_family != AF_INET6)
			continue;
		if (!IN6_ARE_ADDR_EQUAL(&i6as->i6as_addr.sin6_addr, src))
			continue;

		if (in6ms->i6ms_mode == MCAST_INCLUDE)
			return 1;
		else
			return 0;
	}

	/* no source-filter matched */
	if (in6ms->i6ms_mode == MCAST_INCLUDE)
		return 0;
	return 1;
}

/*
 * check if the given IP address matches with the MSF (per-socket
 * source filter).  return 1/0 if matches/not matches, respectively.
 */
int
match_msf6_per_socket(in6p, src, dst)
	struct in6pcb *in6p;
	struct in6_addr *src;
	struct in6_addr *dst;
{
	struct sock_msf *msf;
	struct ip6_moptions *im6o;
	struct in6_multi_mship *imm;
	struct sock_msf_source *msfsrc;

	if ((im6o = in6p->in6p_moptions) == NULL)
		return 0;

	for (imm = LIST_FIRST(&im6o->im6o_memberships); imm != NULL;
	     imm = LIST_NEXT(imm, i6mm_chain)) {
		if (!IN6_ARE_ADDR_EQUAL(&imm->i6mm_maddr->in6m_addr, dst))
			continue;

		msf = imm->i6mm_msf;
		if (msf == NULL)
			continue;

		/* receive data from any source */
		if (msf->msf_grpjoin != 0 && msf->msf_blknumsrc == 0)
			return 1;

		/* 1. search allow-list */
		if (msf->msf_numsrc == 0)
			goto search_block_list;
		LIST_FOREACH(msfsrc, msf->msf_head, list) {
			if (msfsrc->src.ss_family != AF_INET6)
				continue;
			if (IN6_ARE_ADDR_EQUAL(SIN6_ADDR(&msfsrc->src), src))
				return 1;
		}

		/* 2. search_block_list */
	search_block_list:
		if (msf->msf_blknumsrc == 0)
			goto end_of_search;
		LIST_FOREACH(msfsrc, msf->msf_blkhead, list) {
			if (msfsrc->src.ss_family != AF_INET6)
				continue;
			if (IN6_ARE_ADDR_EQUAL(SIN6_ADDR(&msfsrc->src), src))
				return 0;
		}
		return 1;

	end_of_search:
		;
	}

	/* no group address matched */
	return 0;
}
#ifdef __FreeBSD__
#ifdef MLDV2_DEBUG
static void
print_in6_addr_slist(struct in6_addr_slist *ias, char *heading)
{
	struct in6_addr_source *tmp;

	if (ias == NULL) {
		log(LOG_DEBUG, "\t\t%s(none)\n", heading);
		return;
	}
	log(LOG_DEBUG, "\t\t%s(%d)\n", heading, ias->numsrc);

	LIST_FOREACH(tmp, ias->head, i6as_list) {
		struct in6_addr dummy = SIN6(&tmp->i6as_addr)->sin6_addr;
		log(LOG_DEBUG, "\t\tsrc %s (ref=%d)\n",
		    ip6_sprintf(&dummy), tmp->i6as_refcount);
	}
}

void
dump_in6_multisrc(void)
{
	int s = splnet();
	struct ifnet *ifp;

	for (ifp = TAILQ_FIRST(&ifnet); ifp; ifp = TAILQ_NEXT(ifp, if_list)) {
		struct ifmultiaddr *ifma;
		struct in6_multi *in6m = NULL;
		struct in6_multi_source *ims = NULL;

		log(LOG_DEBUG, "interface %s\n", if_name(ifp));
		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link)
		{
			if (ifma->ifma_addr == NULL) {
				log(LOG_DEBUG, "\tEnd of Group\n");
				continue;
			}
			log(LOG_DEBUG, "\tAF=%d\n", ifma->ifma_addr->sa_family);
			if (ifma->ifma_addr->sa_family != AF_INET6) {
				continue;
			}
			log(LOG_DEBUG, "\tgroup %s (ref=%d)\n",
			    ip6_sprintf(&SIN6(ifma->ifma_addr)->sin6_addr),
			    ifma->ifma_refcount);

			in6m = (struct in6_multi *) ifma->ifma_protospec;
			if (in6m == NULL) {
				log(LOG_DEBUG, "\tno in6_multi\n");
				continue;
			}
			log(LOG_DEBUG, "\ttimer=%d, state=%d\n", in6m->in6m_timer, in6m->in6m_state);
			ims = in6m->in6m_source;
			if (ims == NULL) {
				log(LOG_DEBUG, "\t\tno in6_source_list\n");
				continue;
			}
			log(LOG_DEBUG, "\t\tmode=%d, grpjoin=%d\n", ims->i6ms_mode, ims->i6ms_grpjoin);
			print_in6_addr_slist(ims->i6ms_cur, "cur");
			print_in6_addr_slist(ims->i6ms_rec, "rec");
			print_in6_addr_slist(ims->i6ms_in, "in");
			print_in6_addr_slist(ims->i6ms_ex, "ex");
			print_in6_addr_slist(ims->i6ms_alw, "allow");
			print_in6_addr_slist(ims->i6ms_blk, "block");
			print_in6_addr_slist(ims->i6ms_toin, "toinc");
			print_in6_addr_slist(ims->i6ms_toex, "toexc");
		}
	}
	splx(s);
}
#endif /* MLDV2_DEBUG */
#endif /* FreeBSD */
#endif /* MLDV2 */
