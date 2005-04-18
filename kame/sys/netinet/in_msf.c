/*
 * Copyright (c) 2002 INRIA. All rights reserved.
 *
 * Implementation of Internet Group Management Protocol, Version 3.
 * Developed by Hitoshi Asaeda, INRIA, February 2002.
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

#ifdef __FreeBSD__
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_mrouting.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#include "opt_mrouting.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif

#include <net/if.h>
#include <net/route.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_mroute.h>
#include <netinet/igmp.h>
#include <netinet/igmp_var.h>
#include <netinet/in_msf.h>

#if defined(IGMPV3) || defined(MLDV2)

#ifdef IGMPV3

static int in_merge_msf_head(struct in_multi *, struct in_addr_slist *,
		u_int, u_int);
static void in_undo_new_msf_curhead(struct in_multi *, struct sockaddr_in *);
static void in_clear_pending_report(struct in_multi *, u_int);
static int in_merge_pending_report(struct in_multi *,
		struct in_addr_source *, u_int8_t);
static int in_copy_msf_source_list(struct in_addr_slist *,
		struct in_addr_slist *, u_int);

#define IAS_LIST_ALLOC(iasl) do {					\
	MALLOC((iasl), struct in_addr_slist *,				\
		sizeof(struct in_addr_slist), M_MSFILTER, M_NOWAIT);	\
	if ((iasl) == NULL) {						\
		error = ENOBUFS;					\
		break;							\
	}								\
	bzero((iasl), sizeof(struct in_addr_slist));			\
	MALLOC((iasl)->head, struct ias_head *,				\
		sizeof(struct ias_head), M_MSFILTER, M_NOWAIT);		\
	if ((iasl)->head == NULL) {					\
		FREE((iasl), M_MSFILTER);				\
		error = ENOBUFS;					\
		break;							\
	}								\
	LIST_INIT((iasl)->head);					\
	(iasl)->numsrc = 0;						\
} while (/*CONSTCOND*/ 0)

#define	INM_SOURCE_LIST(mode)						\
	(((mode) == MCAST_INCLUDE) ? inm->inm_source->ims_in		\
				   : inm->inm_source->ims_ex)
#ifndef in_hosteq
#define in_hosteq(s,t)	((s).s_addr == (t).s_addr)
#endif

#ifndef in_nullhost
#define in_nullhost(x)  ((x).s_addr == INADDR_ANY)
#endif

/*
 * Add source addresses to multicast address record.
 */
int
in_addmultisrc(inm, numsrc, ss, mode, init, newhead, newmode, newnumsrc)
	struct in_multi *inm;
	u_int16_t numsrc;
	struct sockaddr_storage *ss;
	u_int mode;
	int init;
	struct ias_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in_addr_slist *iasl;
	struct in_addr_source *ias;
	u_int16_t *fnumsrc = NULL;
	struct sockaddr_in *sin;
	u_int16_t i, j;
	int ref_count;
	int error = 0;

	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;

	if (inm->inm_source == NULL) {
		/*
		 * Even if upstream router does not control IGMPv3, inm_source
		 * is allocated, in order to change the behavior to an IGMPv3
		 * capable node gracefully.
		 */
		MALLOC(inm->inm_source, struct in_multi_source *,
				sizeof(struct in_multi_source),
				M_MSFILTER, M_NOWAIT);
		if (inm->inm_source == NULL)
			return ENOBUFS;
		bzero(inm->inm_source, sizeof(struct in_multi_source));

		IAS_LIST_ALLOC(inm->inm_source->ims_cur);
		if (error != 0) {
			FREE(inm->inm_source, M_MSFILTER);
			return error;
		}
		IAS_LIST_ALLOC(inm->inm_source->ims_rec);
		if (error != 0) {
			FREE(inm->inm_source->ims_cur->head, M_MSFILTER);
			FREE(inm->inm_source->ims_cur, M_MSFILTER);
			FREE(inm->inm_source, M_MSFILTER);
			return error;
		}
		inm->inm_source->ims_mode = MCAST_INCLUDE;
		inm->inm_source->ims_excnt = 0;
		inm->inm_source->ims_grpjoin = 0;
		inm->inm_source->ims_timer = 0;
		inm->inm_source->ims_robvar = 0;
#ifdef __FreeBSD__
		inm->inm_state = IGMP_OTHERMEMBER;/* set by joingroup()? */
#else
		inm->inm_state = IGMP_IDLE_MEMBER;/* set by joingroup()? */
#endif
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

	if (INM_SOURCE_LIST(mode) == NULL ||
	    LIST_EMPTY(INM_SOURCE_LIST(mode)->head)) {
		sin = SIN(&ss[0]);
		for (; i < numsrc; i++) {
			if (SIN_ADDR(sin) == INADDR_ANY)
				continue;
			MALLOC(ias, struct in_addr_source *, sizeof(*ias),
				M_MSFILTER, M_NOWAIT);
			if (ias == NULL)
				return ENOBUFS;

			bcopy(sin, &ias->ias_addr, sin->sin_len);
			ias->ias_refcount = 1;
			if (INM_SOURCE_LIST(mode) == NULL) {
				IAS_LIST_ALLOC(INM_SOURCE_LIST(mode));
				if (error != 0) {
					FREE(ias, M_MSFILTER);
					return error;
				}
			}
			LIST_INSERT_HEAD(INM_SOURCE_LIST(mode)->head,
					 ias, ias_list);
			j = 1; /* the number of added source */
			break;
		}
		if (i == numsrc)
			return EINVAL;

		++i; /* the number of checked sources */
	}

	iasl = INM_SOURCE_LIST(mode);
	fnumsrc = &iasl->numsrc;
	/* the number of sources is limited */
	if (*fnumsrc >= igmpmaxsrcfilter) {
		igmplog((LOG_DEBUG, "in_addmultisrc: "
			"number of source already reached max filter count"));
		return EINVAL; /* XXX */
	}

	for (; i < numsrc; i++) {
		sin = SIN(&ss[i]);
		if (SIN_ADDR(sin) == INADDR_ANY)
			continue; /* skip */
		ref_count = in_merge_msf_source_addr(iasl, sin,
						     IMS_ADD_SOURCE);
		if (ref_count < 0) {
			in_undomultisrc(inm, i, ss, mode, IMS_ADD_SOURCE);
			return ENOBUFS;
		} else if (ref_count != 1)
			continue;

		/* ref_count == 1 means new source */
		++j; /* the number of added sources  */
		if ((*fnumsrc + j) == igmpmaxsrcfilter) {
			/*
			 * XXX Kernel accepts to keep as many requested
			 * sources as possible. It tries to fit sources
			 * within a rest of the number of the limitation,
			 * and after reaching max, it stops insertion with
			 * returning no error.
			 * This is implementation specific issue.
			 */
			++i; /* adjusted the number of srcs */
			igmplog((LOG_DEBUG, "in_addmultisrc: number of source "
				"is over max filter count. Adjusted."));
			break;
		}
	}

after_source_list_addition:
	/*
	 * When mode is EXCLUDE, add group join count if (*,G) join was
	 * requested, or generate an EXCLUDE source list reaching max count.
	 */
	if (mode == MCAST_EXCLUDE) {
		if (init) /* only when socket made initial request. */
			++inm->inm_source->ims_excnt;
		if (numsrc == 0)
			/* Received (*,G) join request. */
			++inm->inm_source->ims_grpjoin;
	}

	if (numsrc != 0)
		/* New numsrc must be set before in_get_new_msf_state()
		 * is called. */
		*fnumsrc += j;
	error = in_get_new_msf_state(inm, newhead, newmode, newnumsrc);
	if (error != 0) {
		igmplog((LOG_DEBUG, "in_addmultisrc: in_get_new_msf_state "
			"returns %d\n", error));
		if ((mode == MCAST_EXCLUDE) && init)
			--inm->inm_source->ims_excnt;
		if (numsrc != 0) {
			/* numsrc must be returned back before undo */
			*fnumsrc -= j;
			in_undomultisrc(inm, i, ss, mode, IMS_ADD_SOURCE);
		}
		return error;
	}

	return 0;
}

/*
 * Delete source addresses from multicast address record.
 */
int
in_delmultisrc(inm, numsrc, ss, mode, final, newhead, newmode, newnumsrc)
	struct in_multi *inm;
	u_int16_t numsrc;
	struct sockaddr_storage *ss;
	u_int mode;
	int final;
	struct ias_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in_addr_slist *iasl = NULL;
	struct in_addr_source *ias, *nias;
	struct sockaddr_in *sin;
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
				(inm->inm_source->ims_grpjoin == 0))
			return EINVAL;
		goto after_source_list_deletion;
	}
	if (ss == NULL) {
		return EINVAL;
	}

	if (INM_SOURCE_LIST(mode) == NULL ||
	    LIST_EMPTY(INM_SOURCE_LIST(mode)->head))
		return EADDRNOTAVAIL;
	iasl = INM_SOURCE_LIST(mode);
	fnumsrc = &iasl->numsrc;

	for (; i < numsrc; i++) {
		sin = SIN(&ss[i]);
		if (SIN_ADDR(sin) == INADDR_ANY)
			continue; /* skip */
		ref_count = in_merge_msf_source_addr(iasl, sin,
						     IMS_DELETE_SOURCE);
		if (ref_count < 0) {
			in_undomultisrc(inm, i, ss, mode, IMS_DELETE_SOURCE);
			return EADDRNOTAVAIL;
		} else if (ref_count == 0)
			++j; /* the number of deleted sources */
	}

after_source_list_deletion:
	/*
	 * Each source which was removed from EXCLUDE source list is also
	 * removed from an EXCLUDE source list reaching max count if there
	 * is no (*,G) join state.
	 */
	if (mode == MCAST_EXCLUDE) {
		if (numsrc == 0) {
			/* Received (*,G) leave request. */
			if (inm->inm_source->ims_grpjoin > 0)
				--inm->inm_source->ims_grpjoin;
			else
				return EADDRNOTAVAIL;
		}
		if (final) /* only when socket made request leave from group. */
			--inm->inm_source->ims_excnt;
	}

	if (numsrc != 0)
		/* new numsrc is needed by in_get_new_msf_state() */
		*fnumsrc -= j;
	error = in_get_new_msf_state(inm, newhead, newmode, newnumsrc);
	if (error != 0) {
		igmplog((LOG_DEBUG, "in_delmultisrc: in_get_new_msf_state "
			"returns %d\n", error));
		if ((mode == MCAST_EXCLUDE) && final)
			++inm->inm_source->ims_excnt;
		if (numsrc != 0) {
			/* numsrc must be returned back before undo */
			*fnumsrc += j;
			in_undomultisrc(inm, numsrc, ss, mode,
					IMS_DELETE_SOURCE);
		}
		return error;
	}

	/*
	 * Each source whose ias_refcount is 0 is removed after the process
	 * to merge each source has done successfully.
	 */
	if (numsrc != 0) {
		for (ias = LIST_FIRST(iasl->head); ias; ias = nias) {
			nias = LIST_NEXT(ias, ias_list);
			if (ias->ias_refcount == 0) {
				LIST_REMOVE(ias, ias_list);
				FREE(ias, M_MSFILTER);
			}
		}
	}

	return 0;
}

int
in_modmultisrc(inm, numsrc, ss, mode, old_num, old_ss, old_mode, grpjoin,
			newhead, newmode, newnumsrc)
	struct in_multi *inm;
	u_int16_t numsrc, old_num;
	struct sockaddr_storage *ss, *old_ss;
	u_int mode, old_mode;
	u_int grpjoin;
	struct ias_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in_addr_slist *iasl, *oiasl = NULL;
	struct in_addr_source *ias, *nias;
	u_int16_t *fnumsrc = NULL, *ofnumsrc = NULL;
	struct sockaddr_in *sin;
	u_int16_t i, j, k;
	int ref_count;
	int error = 0;

	if (old_mode != MCAST_INCLUDE && old_mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;
	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE)
		return EOPNOTSUPP;
	if (inm->inm_source == NULL) {
		/*
		 * Even if upstream router does not control IGMPv3, inm_source
		 * is allocated, in order to behave as an IGMPv3 capable node
		 * in any time.
		 */
		MALLOC(inm->inm_source, struct in_multi_source *,
			sizeof(struct in_multi_source), M_MSFILTER, M_NOWAIT);
		if (inm->inm_source == NULL)
			return ENOBUFS;
		bzero(inm->inm_source, sizeof(struct in_multi_source));

		IAS_LIST_ALLOC(inm->inm_source->ims_cur);
		if (error != 0) {
			FREE(inm->inm_source, M_MSFILTER);
			return error;
		}
		IAS_LIST_ALLOC(inm->inm_source->ims_rec);
		if (error != 0) {
			FREE(inm->inm_source->ims_cur->head, M_MSFILTER);
			FREE(inm->inm_source->ims_cur, M_MSFILTER);
			FREE(inm->inm_source, M_MSFILTER);
			return error;
		}
		inm->inm_source->ims_mode = MCAST_INCLUDE;
		inm->inm_source->ims_excnt = 0;
		inm->inm_source->ims_grpjoin = 0;
		inm->inm_source->ims_timer = 0;
		inm->inm_source->ims_robvar = 0;
#ifdef __FreeBSD__
		inm->inm_state = IGMP_OTHERMEMBER;/* set by joingroup()? */
#else
		inm->inm_state = IGMP_IDLE_MEMBER;/* set by joingroup()? */
#endif
	}

	/*
	 * Delete unneeded sources.
	 */
	if (old_num != 0) {
		if (INM_SOURCE_LIST(old_mode) == NULL)
			return EADDRNOTAVAIL;
		oiasl = INM_SOURCE_LIST(old_mode);
		ofnumsrc = &oiasl->numsrc;
	}

	i = j = k = 0;
	for (; i < old_num; i++) {
		sin = SIN(&old_ss[i]);
		ref_count = in_merge_msf_source_addr(oiasl, sin,
						     IMS_DELETE_SOURCE);
		if (ref_count < 0) {
			in_undomultisrc(inm, i, old_ss, old_mode,
					IMS_DELETE_SOURCE);
			return EADDRNOTAVAIL; /* strange since msf was deleted*/
		} else if (ref_count == 0)
			++j; /* the number of deleted sources */
	}
	i = 0; /* reset */

	/*
	 * Change grpjoin count for (*,G) operation or add new filtered
	 * sources for (S,G) operation.
	 */
	if (numsrc == 0) {
		if (mode == MCAST_INCLUDE) /* (*,G) leave */
			--inm->inm_source->ims_grpjoin;
		else /* (*,G) join */
			++inm->inm_source->ims_grpjoin;
		goto after_source_list_modification;
	}

	if (INM_SOURCE_LIST(mode) == NULL ||
	    LIST_EMPTY(INM_SOURCE_LIST(mode)->head)) {
		for (i = 0; i < numsrc; i++) {
			sin = SIN(&ss[i]);
			if (SIN_ADDR(sin) == INADDR_ANY)
				continue; /* skip */

			MALLOC(ias, struct in_addr_source *, sizeof(*ias),
			       M_MSFILTER, M_NOWAIT);
			if (ias == NULL)
				return ENOBUFS;
			bcopy(sin, &ias->ias_addr, sin->sin_len);
			ias->ias_refcount = 1;
			if (INM_SOURCE_LIST(mode) == NULL) {
				IAS_LIST_ALLOC(INM_SOURCE_LIST(mode));
				if (error != 0) {
					FREE(ias, M_MSFILTER);
					return error;
				}
			}
			LIST_INSERT_HEAD(INM_SOURCE_LIST(mode)->head, ias,
					 ias_list);
			k = 1; /* the number of added source */
			break;
		}
		if (i == numsrc)
			return EINVAL;
		++i; /* adjusted the number of checked sources */
	}

	iasl = INM_SOURCE_LIST(mode);
	fnumsrc = &iasl->numsrc;
	/* the number of sources is limited */
	if (*fnumsrc >= igmpmaxsrcfilter) {
		igmplog((LOG_DEBUG, "in_modmultisrc: number of source "
			"already reached max filter count.\n"));
		return EINVAL; /* XXX */
	}

	for (; i < numsrc; i++) {
		sin = SIN(&ss[i]);
		if (SIN_ADDR(sin) == INADDR_ANY)
			continue; /* skip */
		ref_count = in_merge_msf_source_addr(iasl, sin,
						     IMS_ADD_SOURCE);
		if (ref_count < 0) {
			in_undomultisrc(inm, i, ss, mode, IMS_ADD_SOURCE);
			if (old_num != 0)
				in_undomultisrc(inm, old_num, old_ss, old_mode,
						IMS_DELETE_SOURCE);
			return ENOBUFS;
		} else if (ref_count != 1)
			continue;

		/* ref_count == 1 means new source */
		++k; /* the number of added sources  */
		if ((*fnumsrc + k) == igmpmaxsrcfilter) {
			/*
			 * XXX Kernel accepts to keep as many requested
			 * sources as possible. It tries to fit sources within
			 * a rest of the number of the limitation, and after
			 * reaching max, it stops insertion with returning no
			 * error.
			 * This is implementation specific issue.
			 */
			++i; /* adjusted the number of sources */
			igmplog((LOG_DEBUG, "in_modmultisrc: number of source "
				"is over max filter count. Adjusted.\n"));
			break;
		}
	}

after_source_list_modification:
	/*
	 * If new request is Filter-Mode-Change request to MCAST_INCLUDE,
	 * decrease ims_excnt.
	 * If new request is Filter-Mode-Change request to MCAST_EXCLUDE,
	 * increase ims_excnt.
	 * If new request is EX{NULL} -> EX{non NULL} or
	 * EX{NULL} -> IN{non NULL}, decrease ims_grpjoin.
	 */
	if (old_mode != mode && mode == MCAST_INCLUDE)
		--inm->inm_source->ims_excnt;
	else if (old_mode != mode && mode == MCAST_EXCLUDE)
		++inm->inm_source->ims_excnt;
	if (numsrc != 0 && grpjoin)
		--inm->inm_source->ims_grpjoin;

	/* New numsrc must be set before in_get_new_msf_state() is called. */
	if (old_num != 0)
		*ofnumsrc -= j;
	if (numsrc != 0)
		*fnumsrc += k;

	error = in_get_new_msf_state(inm, newhead, newmode, newnumsrc);
	if (error != 0) {
		igmplog((LOG_DEBUG, "in_modmultisrc: in_get_new_msf_state "
			"error %d\n", error));
		if (old_mode != mode && mode == MCAST_INCLUDE)
			++inm->inm_source->ims_excnt;
		else if (old_mode != mode && mode == MCAST_EXCLUDE)
			--inm->inm_source->ims_excnt;
		if (numsrc != 0 && grpjoin)
			++inm->inm_source->ims_grpjoin;
		if (old_num != 0) {
			/* numsrc must be returned back before undo */
			*ofnumsrc += j;
			in_undomultisrc(inm, old_num, old_ss, old_mode,
					IMS_DELETE_SOURCE);
		}
		if (numsrc != 0) {
			/* numsrc must be returned back before undo */
			*fnumsrc -= k;
			in_undomultisrc(inm, numsrc, ss, mode, IMS_ADD_SOURCE);
		}
		return error;
	}

	/*
	 * Each source whose ias_refcount is 0 is removed after the process
	 * to merge each source has done successfully.
	 */
	if (old_num != 0) {
		for (ias = LIST_FIRST(oiasl->head); ias; ias = nias) {
			nias = LIST_NEXT(ias, ias_list);
			if (ias->ias_refcount == 0) {
				LIST_REMOVE(ias, ias_list);
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
in_undomultisrc(inm, numsrc, ss, mode, req)
	struct in_multi *inm;
	u_int16_t numsrc;
	struct sockaddr_storage *ss;
	u_int mode;
	int req;
{
	struct ias_head head;
	struct sockaddr_in *sin;
	struct in_addr_source *ias, *nias;
	u_int16_t i;

	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE)
		return;
	LIST_FIRST(&head) = LIST_FIRST(INM_SOURCE_LIST(mode)->head);

	for (i = 0; i < numsrc && SIN(&ss[i]) != NULL; i++) {
		sin = SIN(&ss[i]);
		if (SIN_ADDR(sin) == INADDR_ANY)
			continue; /* skip */
		for (ias = LIST_FIRST(&head); ias; ias = nias) {
			nias = LIST_NEXT(ias, ias_list);

			/* sanity check */
			if (ias->ias_addr.sin_family != sin->sin_family)
				continue;
			
			if (SS_CMP(&ias->ias_addr, <, sin))
				continue;
			if (SS_CMP(&ias->ias_addr, >, sin)) {
				/* XXX strange. this should never occur. */
				printf("in_undomultisrc: list corrupted. panic!\n");
				continue; /* XXX */
			}

			/* same src addr found */
			if (req == IMS_ADD_SOURCE) {
				if (--ias->ias_refcount == 0) {
					LIST_REMOVE(ias, ias_list);
					FREE(ias, M_MSFILTER);
				}
			} else /* IMS_DELETE_SOURCE */
				++ias->ias_refcount;
			LIST_FIRST(&head) = nias;
			break;
		}
	}
	if ((numsrc != 0) && (INM_SOURCE_LIST(mode)->numsrc == 0)) {
		FREE(INM_SOURCE_LIST(mode)->head, M_MSFILTER);
		FREE(INM_SOURCE_LIST(mode), M_MSFILTER);
		INM_SOURCE_LIST(mode) = NULL;
		if (mode == MCAST_EXCLUDE)
			inm->inm_source->ims_excnt = 0; /* this must be unneeded... */
	}
}

/*
 * Get new source filter mode and source list head when the multicast
 * reception state of an interface is changed.
 */
int
in_get_new_msf_state(inm, newhead, newmode, newnumsrc)
	struct in_multi *inm;
	struct ias_head **newhead;
	u_int *newmode;
	u_int16_t *newnumsrc;
{
	struct in_addr_source *in_ias, *ex_ias, *newias, *nias, *lastp = NULL;
	struct ias_head inhead, exhead;
	struct sockaddr_in *sin;
	u_int filter;
	u_int8_t cmd;
	int i;
	int error = 0;

#define inmm_src inm->inm_source
#define INM_LIST_EMPTY(name) \
	((inmm_src->ims_##name == NULL) || \
	 ((inmm_src->ims_##name != NULL) && (inmm_src->ims_##name->numsrc == 0)))

	/* Case 1: Some socket requested (*,G) join. */
	if (inmm_src->ims_grpjoin != 0) {
		igmplog((LOG_DEBUG, "case 1: Some socket requested (*,G) "
			"join.\n"));
		/* IN{NULL} -> EX{NULL} */
		if (LIST_EMPTY(inmm_src->ims_cur->head)) {
			if (inmm_src->ims_mode == MCAST_INCLUDE) {
				igmplog((LOG_DEBUG,
					"case 1.1:IN{NULL}->EX{NULL}\n"));
				in_clear_all_pending_report(inm);

				/*
				 * To make TO_EX transmission, non-null
				 * ims_toex is required.
				 * See igmp_send_state_change_report().
				 */
				IAS_LIST_ALLOC(inmm_src->ims_toex);
				if (error != 0)
					; /* XXX give up TO_EX transmission */
			}
			goto change_state_1;
		}

		/* IN{non NULL} -> EX{NULL} */
		if (inmm_src->ims_mode == MCAST_INCLUDE) {
			igmplog((LOG_DEBUG,
				"case 1.2:IN{non-NULL}->EX{NULL}\n"));
			in_clear_all_pending_report(inm);

			/* To make TO_EX transmission */
			IAS_LIST_ALLOC(inmm_src->ims_toex);
			if (error != 0)
				; /* XXX */
			goto free_source_list_1;
		 }

		/* EX{non NULL} -> EX{NULL} */
		if (inmm_src->ims_ex != NULL) {
			igmplog((LOG_DEBUG,
				"case 1.3:EX{non-NULL}->EX{NULL}\n"));
			filter = REPORT_FILTER2;
			LIST_FOREACH(ex_ias, inmm_src->ims_ex->head,
				     ias_list) {
				error = in_merge_pending_report(inm, ex_ias,
								ALLOW_NEW_SOURCES);
				if (error != 0) {
					/*
					 * If error occured, clear pending
					 * report and return error.
					 */
					in_clear_pending_report(inm, filter);
					return error;
				}
			}
		}

	free_source_list_1:
		in_free_msf_source_list(inmm_src->ims_cur->head);
		inmm_src->ims_cur->numsrc = 0;

	change_state_1:
		*newmode = MCAST_EXCLUDE;
		*newnumsrc = 0;
		return 0;
	}

	/* Case 2: There is no member for this group. */
	if (INM_LIST_EMPTY(in) && INM_LIST_EMPTY(ex)) {
		igmplog((LOG_DEBUG,
			"case 2: there is no member of this group\n"));
		/* EX{NULL} -> IN{NULL} */
		if (LIST_EMPTY(inmm_src->ims_cur->head)) {
			if (inmm_src->ims_mode == MCAST_EXCLUDE) {
				igmplog((LOG_DEBUG,
					"case 2.1: EX{NULL}->IN{NULL}\n"));
				in_clear_all_pending_report(inm);

				/*
				 * To make TO_IN transmission, non-null
				 * ims_toin is required.
				 * See igmp_send_state_change_report().
				 */
				IAS_LIST_ALLOC(inmm_src->ims_toin);
				if (error != 0)
					; /* XXX give up TO_IN transmission */
			}
			goto change_state_2;
		}

		/* EX{non NULL} -> IN{NULL} */
		if (inmm_src->ims_mode == MCAST_EXCLUDE) {
			igmplog((LOG_DEBUG,
				"case 2.2: EX{non-NULL}->IN{NULL}\n"));
			filter = REPORT_FILTER4;
			in_clear_all_pending_report(inm);

			/* To make TO_IN transmission */
			IAS_LIST_ALLOC(inmm_src->ims_toin);
			if (error != 0)
				; /* XXX */
			goto free_source_list_2;
		}

		/* IN{non NULL} -> IN{NULL} */
		igmplog((LOG_DEBUG, "case 2.3: IN{non-NULL}->IN{NULL}\n"));
		filter = REPORT_FILTER1;
		LIST_FOREACH(in_ias, inmm_src->ims_cur->head, ias_list) {
			error = in_merge_pending_report(inm, in_ias,
							BLOCK_OLD_SOURCES);
			if (error != 0) {
				/*
			 	 * If error occured, clear pending report and
				 * return error.
				 */
				 in_clear_pending_report(inm, filter);
				 return error;
			 }
		}

	free_source_list_2:
		in_free_msf_source_list(inmm_src->ims_cur->head);
		inmm_src->ims_cur->numsrc = 0;

	change_state_2:
		*newmode = MCAST_INCLUDE;
		*newnumsrc = 0;
		return 0;
	}

	/* Case 3: Source list of EXCLUDE filter is set for this group. */
	if (INM_LIST_EMPTY(in)) {
		igmplog((LOG_DEBUG, "case 3: Source list of EXCLUDE filter "
			"is set for this group\n"));
		/* IN{NULL} -> EX{non NULL} or EX{NULL} -> EX{non NULL} */
		if (LIST_EMPTY(inmm_src->ims_cur->head)) {
			error = in_copy_msf_source_list(inmm_src->ims_ex,
							inmm_src->ims_cur,
							inmm_src->ims_excnt);
			if (error != 0)
				return error;

			i = inmm_src->ims_cur->numsrc;
			if (inmm_src->ims_mode == MCAST_INCLUDE) {
				igmplog((LOG_DEBUG,
					"case 3.1:IN{NULL}->EX{non-NULL}\n"));
				filter = REPORT_FILTER3;
				cmd = CHANGE_TO_EXCLUDE_MODE;
				in_clear_all_pending_report(inm);
			} else {
				igmplog((LOG_DEBUG,
					"case 3.2:EX{NULL}->EX{non-NULL}\n"));
				filter = REPORT_FILTER2;
				cmd = BLOCK_OLD_SOURCES;
			}
			LIST_FOREACH(ex_ias, inmm_src->ims_ex->head, ias_list) {
				if (ex_ias->ias_refcount != inmm_src->ims_excnt)
					continue; /* skip */
				error = in_merge_pending_report(inm, ex_ias,
								cmd);
				if (error != 0) {
					/*
					 * If error occured, clear curhead and
					 * pending report, and return error.
					 */
					 in_free_msf_source_list
						(inmm_src->ims_cur->head);
					 inmm_src->ims_cur->numsrc = 0;
					 in_clear_pending_report(inm, filter);
					 return error;
				 }
			 }
			 goto change_state_3;
		}

		/* EX{non NULL} -> EX{non NULL} */
		if (inmm_src->ims_mode == MCAST_EXCLUDE) {
			igmplog((LOG_DEBUG,
				"case 3.3:EX{non-NULL}->EX{non-NULL}\n"));
			filter = REPORT_FILTER2;
			error = in_merge_msf_head(inm, inmm_src->ims_ex,
						  inmm_src->ims_excnt, filter);
			if (error != 0)
				return error;

			for (i = 0, newias = LIST_FIRST(inmm_src->ims_cur->head);
			     newias; newias = nias) {
				nias = LIST_NEXT(newias, ias_list);
				if (newias->ias_refcount == 0) {
					LIST_REMOVE(newias, ias_list);
					FREE(newias, M_MSFILTER);
					continue;
				}
				newias->ias_refcount = 1;
				++i;
			}
			goto change_state_3;
		}

		/* IN{non NULL} -> EX{non NULL} */
		igmplog((LOG_DEBUG, "case 3.4:IN{non-NULL}->EX{non-NULL}\n"));
		filter = REPORT_FILTER3;
		in_free_msf_source_list(inmm_src->ims_cur->head);
		inmm_src->ims_cur->numsrc = 0;
		error = in_copy_msf_source_list(inmm_src->ims_ex,
						inmm_src->ims_cur,
						inmm_src->ims_excnt);
		if (error != 0)
			return error;
		i = inmm_src->ims_cur->numsrc;
		in_clear_all_pending_report(inm);
		LIST_FOREACH(ex_ias, inmm_src->ims_ex->head, ias_list) {
			if (ex_ias->ias_refcount != inmm_src->ims_excnt)
				continue; /* skip */
			error = in_merge_pending_report(inm, ex_ias,
							CHANGE_TO_EXCLUDE_MODE);
			if (error != 0) {
				/*
				 * If error occured, clear curhead and pending
				 * report, and return error.
				 */
				 in_free_msf_source_list
						(inmm_src->ims_cur->head);
				 inmm_src->ims_cur->numsrc = 0;
				 in_clear_pending_report(inm, filter);
				 return error;
			}
		}

	change_state_3:
		*newmode = MCAST_EXCLUDE;
		*newnumsrc = i;
		return 0;
	}

	/* Case 4: Source list of INCLUDE filter is set for this group. */
	if (INM_LIST_EMPTY(ex)) {
		igmplog((LOG_DEBUG, "case 4: Source list of INCLUDE filter "
			"is set for this group\n"));
		/* IN{NULL} -> IN{non NULL} or EX{NULL} -> IN{non NULL} */
		if (LIST_EMPTY(inmm_src->ims_cur->head)) {
			error = in_copy_msf_source_list(inmm_src->ims_in,
							inmm_src->ims_cur,
							(u_int)0);
			if (error != 0)
				return error;

			i = inmm_src->ims_cur->numsrc;
			if (inm->inm_source->ims_mode == MCAST_INCLUDE) {
				igmplog((LOG_DEBUG, "case 4.1:IN{NULL}->"
					"IN{non-NULL}\n"));
				filter = REPORT_FILTER1;
				cmd = ALLOW_NEW_SOURCES;
			} else {
				igmplog((LOG_DEBUG, "case 4.2:EX{NULL}->"
					"IN{non-NULL}\n"));
				filter = REPORT_FILTER4;
				cmd = CHANGE_TO_INCLUDE_MODE;
				in_clear_all_pending_report(inm);
			}
			LIST_FOREACH(in_ias, inmm_src->ims_in->head, ias_list) {
				if (in_ias->ias_refcount == 0)
					continue; /* skip */
				error = in_merge_pending_report(inm, in_ias,
								cmd);
				if (error != 0) {
					/*
					 * If error occured, clear curhead and
					 * pending report, and return error.
					 */
					 in_free_msf_source_list
						(inmm_src->ims_cur->head);
					 inmm_src->ims_cur->numsrc = 0;
					 in_clear_pending_report(inm, filter);
					 return error;
				}
			}
			goto change_state_4;
		}

		/* IN{non NULL} -> IN{non NULL} */
		if (inmm_src->ims_mode == MCAST_INCLUDE) {
			igmplog((LOG_DEBUG, "case 4.3:IN{non NULL}->"
				"IN{non-NULL}\n"));
			filter = REPORT_FILTER1;
			error = in_merge_msf_head(inm, inmm_src->ims_in,
						  (u_int)0, filter);
			if (error != 0)
				return error;
			for (i = 0, newias = LIST_FIRST(inmm_src->ims_cur->head);
			     newias; newias = nias) {
				nias = LIST_NEXT(newias, ias_list);
				if (newias->ias_refcount == 0) {
					LIST_REMOVE(newias, ias_list);
					FREE(newias, M_MSFILTER);
				} else {
					newias->ias_refcount = 1;
					++i;
				}
			}
			goto change_state_4;
		}

		/* EX{non NULL} -> IN{non NULL} (since EX list was left) */
		igmplog((LOG_DEBUG, "case 4.4:EX{non NULL}->IN{non-NULL}\n"));
		filter = REPORT_FILTER4;
		in_free_msf_source_list(inmm_src->ims_cur->head);
		inmm_src->ims_cur->numsrc = 0;
		error = in_copy_msf_source_list(inmm_src->ims_in,
						inmm_src->ims_cur, (u_int)0);
		if (error != 0)
			return error;

		i = inmm_src->ims_cur->numsrc;
		in_clear_all_pending_report(inm);
		LIST_FOREACH(in_ias, inmm_src->ims_in->head, ias_list) {
			if (in_ias->ias_refcount == 0)
				continue; /* skip */
			error = in_merge_pending_report(inm, in_ias,
							CHANGE_TO_INCLUDE_MODE);
			if (error != 0) {
				/*
				 * If error occured, clear curhead and pending
				 * report, and return error.
				 */
				 in_free_msf_source_list
						(inmm_src->ims_cur->head);
				 inmm_src->ims_cur->numsrc = 0;
				 in_clear_pending_report(inm, filter);
				 return error;
			}
		}

	change_state_4:
		*newmode = MCAST_INCLUDE;
		*newnumsrc = i;
		return 0;
	}

	/* Case 5: INCLUDE and EXCLUDE source lists coexist with this group. */
	igmplog((LOG_DEBUG, "case 5: INCLUDE and EXCLUDE source lists "
		"coexist with this group.\n"));
	LIST_FIRST(&inhead) = LIST_FIRST(inmm_src->ims_in->head);
	LIST_FIRST(&exhead) = LIST_FIRST(inmm_src->ims_ex->head);
	MALLOC(*newhead, struct ias_head *, sizeof(struct ias_head),
	       M_MSFILTER, M_NOWAIT);
	if (*newhead == NULL)
		return ENOBUFS;
	LIST_INIT(*newhead);
	*newnumsrc = 0;

	LIST_FOREACH(ex_ias, &exhead, ias_list) {
		if (ex_ias->ias_refcount != inmm_src->ims_excnt)
			continue;
		sin = &ex_ias->ias_addr;
		LIST_FOREACH(in_ias, &inhead, ias_list) {
			if (in_ias->ias_refcount == 0)
				continue; /* skip */

			/* sanity check */
			if (in_ias->ias_addr.sin_family != sin->sin_family)
				continue;
			if (SS_CMP(&in_ias->ias_addr, <, sin))
				continue;
			
			/* sanity check */
			if (ex_ias->ias_addr.sin_family != in_ias->ias_addr.sin_family)
				continue;
			if (SS_CMP(&ex_ias->ias_addr, ==, &in_ias->ias_addr)) {
				LIST_FIRST(&inhead) = LIST_NEXT(in_ias,
								ias_list);
				break;
			}

			/* ex_ias should be recorded in new curhead here */
			MALLOC(newias, struct in_addr_source *,
			       sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				in_free_msf_source_list(*newhead);
				FREE(*newhead, M_MSFILTER);
				*newnumsrc = 0;
				return ENOBUFS;
			}
			if (LIST_EMPTY(*newhead)) {
				LIST_INSERT_HEAD(*newhead, newias, ias_list);
			} else {
				LIST_INSERT_AFTER(lastp, newias, ias_list);
			}
			++(*newnumsrc);
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			lastp = newias;
			LIST_FIRST(&inhead) = in_ias;
			break;
		}
		if (!in_ias) {
			LIST_INIT(&inhead); /* stop INCLUDE source scan */
			MALLOC(newias, struct in_addr_source *, sizeof(*newias),
			       M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				in_free_msf_source_list(*newhead);
				FREE(*newhead, M_MSFILTER);
				*newnumsrc = 0;
				return ENOBUFS;
			}
			if (LIST_EMPTY(*newhead)) {
				LIST_INSERT_HEAD(*newhead, newias, ias_list);
			} else {
				LIST_INSERT_AFTER(lastp, newias, ias_list);
			}
			++(*newnumsrc);
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			lastp = newias;
		}
	}

	*newmode = MCAST_EXCLUDE;
	if (*newnumsrc == 0) {
		if (inmm_src->ims_cur->numsrc != 0) {
			/* IN{non NULL}/EX{non NULL} -> EX{NULL} */
			in_free_msf_source_list(inmm_src->ims_cur->head);
			FREE(*newhead, M_MSFILTER);
			*newhead = NULL;
		}
		if (inmm_src->ims_mode == MCAST_INCLUDE) {
			/*
			 * To make TO_EX with NULL source list transmission,
			 * non-null ims_toex is required.
			 * See igmp_send_state_change_report().
			 */
			IAS_LIST_ALLOC(inmm_src->ims_toex);
			if (error != 0)
				; /* XXX give up TO_EX transmission */
		}
	}

	return 0;
#undef inmm_src
#undef INM_EMPTY_LIST
}

/*
 * Merge MSF new head to current head. This also merge pending report if
 * needed.
 * This must not be called for Filter-Mode-Change request.
 * In order to use the intersection of EXCLUDE source lists, refcount is
 * prepared. If refcount is 0, all sources except ias_refcount = 0 are
 * compared with sources of curhead. If it's not 0, only sources whose
 * ias_refcount = refcount are compared with them.
 * After this finishes successfully, new current head whose refcount is 0
 * will be clean up, and new timer for merged report will be set.
 */
static int
in_merge_msf_head(inm, iasl, refcount, filter)
	struct in_multi *inm;
	struct in_addr_slist *iasl;
	u_int refcount;
	u_int filter;
{
	struct ias_head head;
	struct in_addr_source *ias = NULL, *curias, *newias, *lastp = NULL;
	struct sockaddr_in *sin;
	int error;

	if ((filter != REPORT_FILTER1) && (filter != REPORT_FILTER2))
		return EOPNOTSUPP;

	LIST_FIRST(&head) = LIST_FIRST(iasl->head);
	LIST_FOREACH(curias, inm->inm_source->ims_cur->head, ias_list) {
		lastp = curias;
		LIST_FOREACH(ias, &head, ias_list) {
			if ((ias->ias_refcount == 0) ||
			    (refcount != 0 && ias->ias_refcount != refcount))
				continue; /* skip */

			sin = &ias->ias_addr;
			
			/* sanity check */
			if (curias->ias_addr.sin_family != sin->sin_family)
				continue;
			if (SS_CMP(&curias->ias_addr, ==, sin)) {
				++curias->ias_refcount;
				LIST_FIRST(&head) = LIST_NEXT(ias, ias_list);
				break;
			}

			if (SS_CMP(&curias->ias_addr, <, sin)) {
				if (filter == REPORT_FILTER1)
					error = in_merge_pending_report
							(inm, curias,
							 BLOCK_OLD_SOURCES);
				else
					error = in_merge_pending_report
							(inm, curias,
							 ALLOW_NEW_SOURCES);
				if (error != 0) {
					/*
					 * If error occured, undo curhead
					 * modification, clear pending report,
					 * and return error.
					 */
					in_undo_new_msf_curhead
						(inm, &curias->ias_addr);
					/* XXX But do we really clear pending
					 * report? */
					in_clear_pending_report(inm, filter);
					igmplog((LOG_DEBUG,
						"in_merge_msf_head: merge fail "
						"for FILTER%d\n", filter));
					return error;
				}
				curias->ias_refcount = 0;
				LIST_FIRST(&head) = ias;
				break;
			}

			/* ias should be recorded in new curhead here */
			MALLOC(newias, struct in_addr_source *, sizeof(*newias),
			       M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				in_undo_new_msf_curhead(inm, sin);
				in_clear_pending_report(inm, filter); /* XXX */
				igmplog((LOG_DEBUG, "in_merge_msf_head: "
					"malloc fail\n"));
				return ENOBUFS;
			}
			if (filter == REPORT_FILTER1)
				error = in_merge_pending_report
						(inm, ias, ALLOW_NEW_SOURCES);
			else
				error = in_merge_pending_report
						(inm, ias, BLOCK_OLD_SOURCES);
			if (error != 0) {
				in_undo_new_msf_curhead(inm, sin);
				in_clear_pending_report(inm, filter); /* XXX */
				igmplog((LOG_DEBUG, "in_merge_msf_head: "
					"merge fail for FILTER%d\n", filter));
				return error;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_BEFORE(curias, newias, ias_list);
		}
		if (!ias) {
			LIST_INIT(&head); /* stop list scan */
			if (filter == REPORT_FILTER1)
				error = in_merge_pending_report
						(inm, curias, BLOCK_OLD_SOURCES);
			else
				error = in_merge_pending_report
						(inm, curias, ALLOW_NEW_SOURCES);
			if (error != 0) {
				in_undo_new_msf_curhead
						(inm, &curias->ias_addr);
				in_clear_pending_report(inm, filter); /* XXX */
				igmplog((LOG_DEBUG, "in_merge_msf_head: "
					"merge fail for FILTER%d\n", filter));
				return error;
			}
			curias->ias_refcount = 0;
		}
	}

	if (ias == NULL)
		return 0; /* already finished merging each ias in curhead */

	LIST_FOREACH(ias, &head, ias_list) {
		if ((ias->ias_refcount == 0) ||
		    (refcount != 0 && ias->ias_refcount != refcount))
			continue;

		MALLOC(newias, struct in_addr_source *, sizeof(*newias),
		       M_MSFILTER, M_NOWAIT);
		if (newias == NULL) {
			igmplog((LOG_DEBUG, "in_merge_msf_head: malloc fail\n"));
			in_undo_new_msf_curhead(inm, &ias->ias_addr);
			in_clear_pending_report(inm, filter); /* XXX */
			return ENOBUFS;
		}
		if (filter == REPORT_FILTER1)
			error = in_merge_pending_report(inm, ias,
							ALLOW_NEW_SOURCES);
		else
			error = in_merge_pending_report(inm, ias,
							BLOCK_OLD_SOURCES);
		if (error != 0) {
			in_undo_new_msf_curhead(inm, &ias->ias_addr);
			in_clear_pending_report(inm, filter); /* XXX */
			igmplog((LOG_DEBUG, "in_merge_msf_head: merge fail "
				"for FILTER%d\n", filter));
			return error;
		}
		newias->ias_addr = ias->ias_addr;
		newias->ias_refcount = 1;
		LIST_INSERT_AFTER(lastp, newias, ias_list);
		lastp = newias;
	}

	return 0;
}

static void
in_undo_new_msf_curhead(inm, sin)
	struct in_multi *inm;
	struct sockaddr_in *sin;
{
	struct in_addr_source *ias;

	LIST_FOREACH(ias, inm->inm_source->ims_cur->head, ias_list) {
		/* sanity check */
		if (ias->ias_addr.sin_family != sin->sin_family)
			continue;
	
		if (SS_CMP(&ias->ias_addr, >=, sin))
			return;

		if (ias->ias_refcount == 1) {
			/* Remove newly added source */
			LIST_REMOVE(ias, ias_list);
			FREE(ias, M_MSFILTER);
		} else /* refcount is 0 or 2 */
			ias->ias_refcount = 1;
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
in_merge_msf_state(inm, newhead, newmode, newnumsrc)
	struct in_multi *inm;
	struct ias_head *newhead;	/* new ims_cur->head */
	u_int newmode;
	u_int16_t newnumsrc;
{
	struct in_addr_source *ias, *newias, *nias;
	struct ias_head curhead;	/* current ims_cur->head */
	struct sockaddr_in *sin;
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
	if ((inm->inm_source->ims_mode == MCAST_EXCLUDE) &&
				(newmode == MCAST_EXCLUDE)) {
		filter = REPORT_FILTER2;
	} else if ((inm->inm_source->ims_mode == MCAST_INCLUDE) &&
				(newmode == MCAST_EXCLUDE)) {
		filter = REPORT_FILTER3;
		if (inm->inm_source->ims_toex != NULL) {
			in_free_msf_source_list
					(inm->inm_source->ims_toex->head);
			inm->inm_source->ims_toex->numsrc = 0;
		}
	} else
		return EOPNOTSUPP; /* never occured... */

	/*
	 * If some error, e.g., ENOBUFS, will be occured later, State-Change
	 * Report won't be sent. However, filtered source list change has
	 * done, so it doesn't undo. This is not a big problem, since the
	 * responce for General Query, Current-State Record, will report
	 * every filtered source after some delay, even State-Change Report
	 * missed. This is simpler way.
	 */
	LIST_FIRST(&curhead) = LIST_FIRST(inm->inm_source->ims_cur->head);
	/* use following ias when newhead points NULL */
	ias = LIST_FIRST(inm->inm_source->ims_cur->head);
	LIST_FOREACH(newias, newhead, ias_list) {
		sin = &newias->ias_addr;
		LIST_FOREACH(ias, &curhead, ias_list) {
			/* sanity check */
			if (ias->ias_addr.sin_family != sin->sin_family)
				continue;
			if (ias->ias_addr.sin_family != newias->ias_addr.sin_family)
				continue;
			
			if (SS_CMP(&ias->ias_addr, <, sin)) {
				if (filter == REPORT_FILTER2)
					continue;
				error = in_merge_pending_report
						(inm, ias, ALLOW_NEW_SOURCES);
				if (error != 0)
					break;
				else
					++chg_flag;
			} else if (SS_CMP(&ias->ias_addr, ==,
					  &newias->ias_addr)) {
				if (filter == REPORT_FILTER3) {
					error = in_merge_pending_report
							(inm, newias,
							CHANGE_TO_EXCLUDE_MODE);
					if (error != 0)
						break;
					else
						++chg_flag;
				}
				LIST_FIRST(&curhead) = LIST_NEXT(ias, ias_list);
				break;
			} else {
				if (filter == REPORT_FILTER2) {
					error = in_merge_pending_report
							(inm, newias,
							BLOCK_OLD_SOURCES);
					if (error != 0)
						break;
					else
						++chg_flag;
				} else if (filter == REPORT_FILTER3) {
					error = in_merge_pending_report
							(inm, newias,
							CHANGE_TO_EXCLUDE_MODE);
					if (error != 0)
						break;
					else
						++chg_flag;
				}
				LIST_FIRST(&curhead) = ias;
				break;
			}
		}
		if (error)
			break;
		else if (!ias) {
			LIST_INIT(&curhead); /* stop list scan */
			if (filter == REPORT_FILTER2) {
				error = in_merge_pending_report
						(inm, newias,
						 BLOCK_OLD_SOURCES);
				if (error != 0)
					break;
				else
					++chg_flag;
			} else if (filter == REPORT_FILTER3) {
				error = in_merge_pending_report
						(inm, newias,
						 CHANGE_TO_EXCLUDE_MODE);
				if (error != 0)
					break;
				else
					++chg_flag;
			}
		}
	}
	if (error)
		goto giveup;
	else if (!newias && ias) {
		LIST_FOREACH(ias, &curhead, ias_list) {
			if (filter == REPORT_FILTER2) {
				error = in_merge_pending_report
						(inm, ias, ALLOW_NEW_SOURCES);
				if (error != 0)
					goto giveup;
				else
					++chg_flag;
			} else
				break;
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
	if (!LIST_EMPTY(inm->inm_source->ims_cur->head)) {
		in_free_msf_source_list(inm->inm_source->ims_cur->head);
		inm->inm_source->ims_cur->numsrc = 0;
	}
	inm->inm_source->ims_mode = newmode;
	for (ias = LIST_FIRST(newhead); ias; ias = nias) {
		nias = LIST_NEXT(ias, ias_list);
		if (LIST_EMPTY(inm->inm_source->ims_cur->head)) {
			LIST_INSERT_HEAD(inm->inm_source->ims_cur->head,
					 ias, ias_list);
		} else {
			LIST_INSERT_AFTER(newias, ias, ias_list);
		}
		newias = ias;
	}
	inm->inm_source->ims_cur->numsrc = newnumsrc;
	if (error == 0) {
		if (filter == REPORT_FILTER3) {
			if (inm->inm_source->ims_alw != NULL) {
				in_free_msf_source_list
					(inm->inm_source->ims_alw->head);
				inm->inm_source->ims_alw->numsrc = 0;
			}
			if (inm->inm_source->ims_blk != NULL) {
				in_free_msf_source_list
					(inm->inm_source->ims_blk->head);
				inm->inm_source->ims_blk->numsrc = 0;
			}
			if (inm->inm_source->ims_toin != NULL) {
				in_free_msf_source_list
					(inm->inm_source->ims_toin->head);
				inm->inm_source->ims_toin->numsrc = 0;
			}
		}
	} else {
		igmplog((LOG_DEBUG, "in_merge_msf_state: Pending source "
			"list merge failed. State-Change Report won't be "
			"sent.\n"));
		in_clear_pending_report(inm, filter);
	}

	return error;
}

void
in_clear_all_pending_report(inm)
	struct in_multi *inm;
{
	in_clear_pending_report(inm, REPORT_FILTER1); /* covering FILTER2 */
	in_clear_pending_report(inm, REPORT_FILTER3);
	in_clear_pending_report(inm, REPORT_FILTER4);
}

/*
 * If pending source merge was failed, source filter mode and current list
 * head are updated (since these are correct) but new State-Change report
 * will not be sent. That change is notified by responce of later Queries.
 */
static void
in_clear_pending_report(inm, filter)
	struct in_multi *inm;
	u_int filter;
{
	if ((filter == REPORT_FILTER1) || (filter == REPORT_FILTER2)) {
		if (inm->inm_source->ims_alw != NULL) {
			in_free_msf_source_list(inm->inm_source->ims_alw->head);
			inm->inm_source->ims_alw->numsrc = 0;
		}
		if (inm->inm_source->ims_blk != NULL) {
			in_free_msf_source_list(inm->inm_source->ims_blk->head);
			inm->inm_source->ims_blk->numsrc = 0;
		}
	/*
	 * TO_IN and TO_EX lists must be completely removed.
	 */
	} else if (filter == REPORT_FILTER3) {
		if (inm->inm_source->ims_toex != NULL) {
			in_free_msf_source_list
					(inm->inm_source->ims_toex->head);
			FREE(inm->inm_source->ims_toex->head, M_MSFILTER);
			FREE(inm->inm_source->ims_toex, M_MSFILTER);
			inm->inm_source->ims_toex = NULL;
		}
	} else {
		if (inm->inm_source->ims_toin != NULL) {
			in_free_msf_source_list
					(inm->inm_source->ims_toin->head);
			FREE(inm->inm_source->ims_toin->head, M_MSFILTER);
			FREE(inm->inm_source->ims_toin, M_MSFILTER);
			inm->inm_source->ims_toin = NULL;
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
in_merge_pending_report(inm, ias, type)
	struct in_multi *inm;
	struct in_addr_source *ias;
	u_int8_t type;
{
	struct in_addr_source *newias;
	struct sockaddr_in *sin = &ias->ias_addr;
	int ref_count;
	int error = 0;

	switch (type) {
	case ALLOW_NEW_SOURCES:
		if (inm->inm_source->ims_alw == NULL) {
			IAS_LIST_ALLOC(inm->inm_source->ims_alw);
			if (error != 0)
				return error;
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG,
					"in_merge_pending_report: ENOBUFS\n"));
				/*
				 * We don't remove ims_alw created above,
				 * since it may be needed to re-create later.
				 * This will be finally cleaned when every
				 * application leaves from this group.
				 */
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_alw->head,
					 newias, ias_list);
			inm->inm_source->ims_alw->numsrc = 1;
		} else if (LIST_EMPTY(inm->inm_source->ims_alw->head)) {
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG,
					"in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_alw->head,
					 newias, ias_list);
			inm->inm_source->ims_alw->numsrc = 1;
		} else if ((ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_alw, sin,
					 IMS_ADD_SOURCE)) < 0) {
			igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++inm->inm_source->ims_alw->numsrc;
		/* If merge fail occurs, return error, no undo. Otherwise,
		 * clear the same source address for opposite filter (i.e.,
		 * BLOCK if ALLOW is the new request) if it exists. */
		if (inm->inm_source->ims_blk != NULL)
			in_free_msf_source_addr
					(inm->inm_source->ims_blk, sin);
		return 0;

	case BLOCK_OLD_SOURCES:
		if (inm->inm_source->ims_blk == NULL) {
			IAS_LIST_ALLOC(inm->inm_source->ims_blk);
			if (error != 0)
				return error;
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_blk->head,
					 newias, ias_list);
			inm->inm_source->ims_blk->numsrc = 1;
		} else if (LIST_EMPTY(inm->inm_source->ims_blk->head)) {
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_blk->head,
					 newias, ias_list);
			inm->inm_source->ims_blk->numsrc = 1;
		} else if ((ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_blk, sin,
					 IMS_ADD_SOURCE)) < 0) {
			igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++inm->inm_source->ims_blk->numsrc;
		if (inm->inm_source->ims_alw != NULL)
			in_free_msf_source_addr
					(inm->inm_source->ims_alw, sin);
		return 0;

	case CHANGE_TO_INCLUDE_MODE:
		if (inm->inm_source->ims_toin == NULL) {
			IAS_LIST_ALLOC(inm->inm_source->ims_toin);
			if (error != 0)
				return error;
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_toin->head,
					 newias, ias_list);
			inm->inm_source->ims_toin->numsrc = 1;
		} else if (LIST_EMPTY(inm->inm_source->ims_toin->head)) {
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_toin->head,
					 newias, ias_list);
			inm->inm_source->ims_toin->numsrc = 1;
		} else if ((ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_toin, sin,
					 IMS_ADD_SOURCE)) < 0) {
			igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++inm->inm_source->ims_toin->numsrc;
		return 0;

	case CHANGE_TO_EXCLUDE_MODE:
		if (inm->inm_source->ims_toex == NULL) {
			IAS_LIST_ALLOC(inm->inm_source->ims_toex);
			if (error != 0)
				return error;
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_toex->head,
					 newias, ias_list);
			inm->inm_source->ims_toex->numsrc = 1;
		} else if (LIST_EMPTY(inm->inm_source->ims_toex->head)) {
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL) {
				igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
				return ENOBUFS;
			}
			bcopy(sin, &newias->ias_addr, sin->sin_len);
			newias->ias_refcount = 1;
			LIST_INSERT_HEAD(inm->inm_source->ims_toex->head,
					 newias, ias_list);
			inm->inm_source->ims_toex->numsrc = 1;
		} else if ((ref_count = in_merge_msf_source_addr
					(inm->inm_source->ims_toex, sin,
					 IMS_ADD_SOURCE)) < 0) {
			igmplog((LOG_DEBUG, "in_merge_pending_report: ENOBUFS\n"));
			return ENOBUFS;
		} else if (ref_count == 1)
			++inm->inm_source->ims_toex->numsrc;
		return 0;
	}
	return EOPNOTSUPP; /* XXX */
}

/*
 * Copy each source address from original head to new one, in order to 
 * make a new current state source list.
 * If refcount is 0, all sources except ias_refcount = 0 are copied.
 * If it's not 0, only sources whose ias_refcount = refcount are copied.
 */
static int
in_copy_msf_source_list(iasl, newiasl, refcount)
	struct in_addr_slist *iasl, *newiasl;
	u_int refcount;
{
	struct in_addr_source *ias, *newias, *lastp = NULL;
	u_int16_t i = 0;

	if ((newiasl == NULL) || !LIST_EMPTY(newiasl->head))
		return EINVAL;

	LIST_FOREACH(ias, iasl->head, ias_list) {
		if ((ias->ias_refcount == 0) ||
			(refcount != 0 && ias->ias_refcount != refcount))
			continue;
		MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
		if (newias == NULL) {
			in_free_msf_source_list(newiasl->head);
			newiasl->numsrc = 0;
			return ENOBUFS;
		}
		if (LIST_EMPTY(newiasl->head)) {
			LIST_INSERT_HEAD(newiasl->head, newias, ias_list);
		} else {
			LIST_INSERT_AFTER(lastp, newias, ias_list);
		}
		newias->ias_addr = ias->ias_addr;
		newias->ias_refcount = 1;
		++i;
		lastp = newias;
	}
	newiasl->numsrc = i;
	return 0;
}

void
in_free_all_msf_source_list(inm)
	struct in_multi *inm;
{
	if ((inm == NULL) || (inm->inm_source == NULL))
		return;

	if (inm->inm_source->ims_cur != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_cur->head);
		if (inm->inm_source->ims_cur->head != NULL)
			FREE(inm->inm_source->ims_cur->head, M_MSFILTER);
		FREE(inm->inm_source->ims_cur, M_MSFILTER); 
	}
	if (inm->inm_source->ims_rec != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_rec->head);
		if (inm->inm_source->ims_rec->head != NULL)
			FREE(inm->inm_source->ims_rec->head, M_MSFILTER);
		FREE(inm->inm_source->ims_rec, M_MSFILTER);
	}
	if (inm->inm_source->ims_in != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_in->head);
		if (inm->inm_source->ims_in->head != NULL)
			FREE(inm->inm_source->ims_in->head, M_MSFILTER); 
		FREE(inm->inm_source->ims_in, M_MSFILTER);
	}
	if (inm->inm_source->ims_ex != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_ex->head);
		if (inm->inm_source->ims_ex->head != NULL)
			FREE(inm->inm_source->ims_ex->head, M_MSFILTER);
		FREE(inm->inm_source->ims_ex, M_MSFILTER);
	}
	if (inm->inm_source->ims_alw != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_alw->head);
		if (inm->inm_source->ims_alw->head != NULL)
			FREE(inm->inm_source->ims_alw->head, M_MSFILTER);
		FREE(inm->inm_source->ims_alw, M_MSFILTER);
	}
	if (inm->inm_source->ims_blk != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_blk->head);
		if (inm->inm_source->ims_blk->head != NULL)
			FREE(inm->inm_source->ims_blk->head, M_MSFILTER);
		FREE(inm->inm_source->ims_blk, M_MSFILTER);
	}
	if (inm->inm_source->ims_toin != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_toin->head);
		if (inm->inm_source->ims_toin->head != NULL)
			FREE(inm->inm_source->ims_toin->head, M_MSFILTER);
		FREE(inm->inm_source->ims_toin, M_MSFILTER);
	}
	if (inm->inm_source->ims_toex != NULL) {
		in_free_msf_source_list(inm->inm_source->ims_toex->head);
		if (inm->inm_source->ims_toex->head != NULL)
			FREE(inm->inm_source->ims_toex->head, M_MSFILTER);
		FREE(inm->inm_source->ims_toex, M_MSFILTER);
	}
	FREE(inm->inm_source, M_MSFILTER);
}

void
in_free_msf_source_list(head)
	struct ias_head *head;
{
	struct in_addr_source *ias, *nias;

	if (head == NULL)
		return;
	for (ias = LIST_FIRST(head); ias; ias = nias) {
		nias = LIST_NEXT(ias, ias_list);
		LIST_REMOVE(ias, ias_list);
		FREE(ias, M_MSFILTER);
	}
	LIST_INIT(head);
}

void
in_free_msf_source_addr(iasl, sin)
	struct in_addr_slist *iasl;
	struct sockaddr_in *sin;
{
	struct in_addr_source *ias, *nias;

	if (iasl == NULL)
		return;
	for (ias = LIST_FIRST(iasl->head); ias; ias = nias) {
		nias = LIST_NEXT(ias, ias_list);
		if (ias->ias_addr.sin_family != sin->sin_family)
			continue;
      
		if (SS_CMP(&ias->ias_addr, <, sin))
			continue;
		else if (SS_CMP(&ias->ias_addr, ==, sin)) {
			LIST_REMOVE(ias, ias_list);
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
in_merge_msf_source_addr(iasl, src, req)
	struct in_addr_slist *iasl;	/* target source list */
	struct sockaddr_in *src;	/* source to be merged */
	int req;			/* request to add or delete */
{
	struct in_addr_source *ias, *newias, *lastp = NULL;

	LIST_FOREACH(ias, iasl->head, ias_list) {
		lastp = ias;
		/* sanity check */
		if (ias->ias_addr.sin_family != src->sin_family)
			continue;
		
		if (SS_CMP(&ias->ias_addr, ==, src)) {
			if (req == IMS_ADD_SOURCE)
				return (++ias->ias_refcount);
			else
				return (--ias->ias_refcount);
		} else if (SS_CMP(&ias->ias_addr, >, src)) {
			if (req == IMS_ADD_SOURCE) {
				MALLOC(newias, struct in_addr_source *,
					sizeof(*newias), M_MSFILTER, M_NOWAIT);
				if (newias == NULL)
					return -1;
				LIST_INSERT_BEFORE(ias, newias, ias_list);
				bcopy(src, &newias->ias_addr, src->sin_len);
				newias->ias_refcount = 1;
				return (newias->ias_refcount);
			} else {
				igmplog((LOG_DEBUG, "in_merge_msf_source_addr: source address cannot be deleted?\n"));
				return -1;
			}
		}
	}
	if (!ias) {
		if (req == IMS_ADD_SOURCE) {
			MALLOC(newias, struct in_addr_source *,
				sizeof(*newias), M_MSFILTER, M_NOWAIT);
			if (newias == NULL)
				return -1;
			else {
				if (LIST_EMPTY(iasl->head)) {
					LIST_INSERT_HEAD(iasl->head, newias,
							 ias_list);
				} else {
					LIST_INSERT_AFTER(lastp, newias,
							  ias_list);
				}
				bcopy(src, &newias->ias_addr, src->sin_len);
				newias->ias_refcount = 1;
				return (newias->ias_refcount);
			}
		} else {
			igmplog((LOG_DEBUG, "in_merge_msf_source_addr: source address cannot be deleted?\n"));
			return -1;
		}
	}
	return 0;
}

/*
 * Set multicast source filter of a socket (SIOCSIPMSFILTER) 
 */
int
ip_setmopt_srcfilter(sop, imsfp)
	struct socket *sop;
	struct ip_msfilter **imsfp;
{
	struct inpcb *ipcbp;
	struct ip_moptions *imop;
	struct ifnet *ifp;
	struct ip_msfilter oimsf;
	struct ip_msfilter *imsf;
	struct sockaddr_storage *ss_src, *old_ss;
	u_int16_t add_num, old_num;
	u_int old_mode;
	struct sockaddr_in *sin;
	struct sock_msf_source *msfsrc, *nmsfsrc;
	struct in_addr_slist *iasl;
	struct in_addr_source *ias;
	struct sockaddr_in src;
	struct route ro;
	struct sockaddr_in *dst;
	int i, j;
	int error = 0;
	int init, final;
	int s;
#if !defined(__FreeBSD__) && defined(MROUTING)
	extern struct socket *ip_mrouter;
#endif

	if (*imsfp == NULL)
		return EINVAL;

	if ((error = copyin((void *)*imsfp, (void *)&oimsf,
			IP_MSFILTER_SIZE(0))) != 0) {
		igmplog((LOG_DEBUG, "ip_setmopt_srcfilter: copyin error.\n"));
		return error;
	} else
		imsf = &oimsf;

	if ((imsf->imsf_numsrc >= igmpsomaxsrc)) {
		igmplog((LOG_DEBUG, "ip_setmopt_srcfilter: "
			"the number of sources is invalid\n"));
		return EINVAL;
	}
#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (!IN_MULTICAST(imsf->imsf_multiaddr.s_addr))
#else
	if (!IN_MULTICAST(ntohl(imsf->imsf_multiaddr.s_addr)))
#endif
	{
		igmplog((LOG_DEBUG, "ip_setmopt_srcfilter: "
			"the group address is invalid\n"));
		return EINVAL;
	}
	if (imsf->imsf_numsrc != 0)
		return EINVAL;
	if (!is_igmp_target(&imsf->imsf_multiaddr))
		return EINVAL;

	/*
	 * Get a pointer of ifnet structure to the interface.
	 */
	if (in_nullhost(imsf->imsf_interface)) {
		bzero((caddr_t)&ro, sizeof(ro));
		ro.ro_rt = NULL;
		dst = satosin(&ro.ro_dst);
		dst->sin_len = sizeof(*dst);
		dst->sin_family = AF_INET;
		dst->sin_addr = imsf->imsf_multiaddr;
		rtalloc(&ro);
		if (ro.ro_rt == NULL)
			return EADDRNOTAVAIL;
		ifp = ro.ro_rt->rt_ifp;
		rtfree(ro.ro_rt);
	} else {
		ifp = ip_multicast_if (&imsf->imsf_interface, NULL);
	}
	/*
	 * See if we found an interface, and confirm that it supports multicast.
	 */
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
	if ((ipcbp = (struct inpcb *)sop->so_pcb) == NULL) {
		igmplog((LOG_DEBUG, "ip_setmopt_srcfilter: inpcb is NULL\n"));
		splx(s);
		return EINVAL;
	}
	if ((imop = ipcbp->inp_moptions) == NULL) {
		imop = (struct ip_moptions *)
			malloc(sizeof(*imop), M_IPMOPTS, M_NOWAIT);
		if (imop == NULL) {
			splx(s);
			return ENOBUFS;
		}
		imop->imo_multicast_ifp = ifp;
		imop->imo_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
#ifdef RSVP_ISI
		imop->imo_multicast_vif = -1;
#endif
#ifdef MROUTING
		imop->imo_multicast_loop = (ip_mrouter != NULL);
#else
		imop->imo_multicast_loop = 0;
#endif
		imop->imo_num_memberships = 0;
		ipcbp->inp_moptions = imop;
	}

	/*
	 * Find the membership in the membership array.
	 */
	for (i = 0; i < imop->imo_num_memberships; i++) {
		if ((imop->imo_membership[i]->inm_ifp == ifp) &&
		    in_hosteq(imop->imo_membership[i]->inm_addr,
			      imsf->imsf_multiaddr))
			break;
	}

	if (i < imop->imo_num_memberships) {
		/*
		 * If this request is (*,G) join and it was already requested
		 * previously, return EADDRINUSE.
		 */
		if ((imsf->imsf_fmode == MCAST_EXCLUDE) &&
				(imsf->imsf_numsrc == 0) &&
				(imop->imo_msf[i]->msf_grpjoin != 0)) {
			splx(s);
			return EADDRINUSE;
		}
		init = 0;
	} else {
		/*
		 * If (*,G) leave is requested when there is no group record,
		 * return EADDRNOTAVAIL.
		 */
		if ((imsf->imsf_fmode == MCAST_INCLUDE) &&
				(imsf->imsf_numsrc == 0)) {
			splx(s);
			return EADDRNOTAVAIL;
		}
		IMO_MSF_ALLOC(imop->imo_msf[i]);
		if (error != 0) {
			splx(s);
			return error;
		}
		init = 1;
	}

	/*
	 * Prepare sock_storage for in_addmulti2(), in_delmulti2(), and
	 * in_modmulti2(). Inputted sources are sorted below.
	 */
	if (imsf->imsf_numsrc != 0) {
		IAS_LIST_ALLOC(iasl);
		if (error != 0) {
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return error;
		}
		for (j = 0; j < imsf->imsf_numsrc; j++) {
			bzero(&src, sizeof(src));
			src.sin_family = AF_INET;
			src.sin_len = sizeof(src);
			error = copyin((void *)&(*imsfp)->imsf_slist[j],
				       (void *)&src.sin_addr,
				       sizeof(src.sin_addr));
			if (error != 0) /* EFAULT */
				break;

			if ((ntohl(src.sin_addr.s_addr) & IN_CLASSA_NET) == 0) {
				error = EINVAL;
				break;
			}
#ifdef __FreeBSD__
			if (IN_MULTICAST(ntohl(src.sin_addr.s_addr)) ||
			    IN_BADCLASS(ntohl(src.sin_addr.s_addr)))
#else
			if (IN_MULTICAST(src.sin_addr.s_addr) ||
			    IN_BADCLASS(src.sin_addr.s_addr))
#endif
			{
				error = EINVAL;
				break;
			}

			/*
			 * Sort and validate source lists. Duplicate addresses
			 * can be checked here.
			 */
			if (in_merge_msf_source_addr(iasl, &src,
						     IMS_ADD_SOURCE) != 1) {
				error = EINVAL;
				break;
			}
		}
		if (error != 0) {
			in_free_msf_source_list(iasl->head);
			FREE(iasl->head, M_MSFILTER);
			FREE(iasl, M_MSFILTER);
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return error;
		}

		/*
		 * Copy source lists to ss_src.
		 */
		MALLOC(ss_src, struct sockaddr_storage *,
			sizeof(struct sockaddr_storage) * imsf->imsf_numsrc,
			M_IPMOPTS, M_NOWAIT);
		if (ss_src == NULL) {
			in_free_msf_source_list(iasl->head);
			FREE(iasl->head, M_MSFILTER);
			FREE(iasl, M_MSFILTER);
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return ENOBUFS;
		}
		for (j = 0, ias = LIST_FIRST(iasl->head);
		     j < imsf->imsf_numsrc && ias;
		     j++, ias = LIST_NEXT(ias, ias_list)) {
			sin = SIN(&ss_src[j]);
			bcopy(&ias->ias_addr, sin, ias->ias_addr.sin_len);
		}
		in_free_msf_source_list(iasl->head);
		FREE(iasl->head, M_MSFILTER);
		FREE(iasl, M_MSFILTER);
	} else
		ss_src = NULL;

	/*
	 * Prepare old msf source list space.
	 */
	old_ss = NULL;
	old_mode = MCAST_INCLUDE;
	if (imop->imo_msf[i]->msf_grpjoin != 0)
		old_mode = MCAST_EXCLUDE;
	else if (imop->imo_msf[i]->msf_numsrc != 0) {
		MALLOC(old_ss, struct sockaddr_storage *,
			sizeof(*old_ss) * imop->imo_msf[i]->msf_numsrc,
			M_IPMOPTS, M_NOWAIT);
		if (old_ss == NULL) {
			if (ss_src != NULL)
				FREE(ss_src, M_IPMOPTS);
			splx(s);
			return ENOBUFS;
		}
		old_mode = MCAST_INCLUDE;
	} else if (imop->imo_msf[i]->msf_blknumsrc != 0) {
		MALLOC(old_ss, struct sockaddr_storage *,
			sizeof(*old_ss) * imop->imo_msf[i]->msf_blknumsrc,
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
	error = in_setmopt_source_list(imop->imo_msf[i], imsf->imsf_numsrc,
				       ss_src, imsf->imsf_fmode,
				       &add_num, &old_num, old_ss);
	if (error != 0) {
		if (old_ss != NULL)
			FREE(old_ss, M_IPMOPTS);
		if (ss_src != NULL)
			FREE(ss_src, M_IPMOPTS);
		if (init)
			IMO_MSF_FREE(imop->imo_msf[i]);
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
	if ((imsf->imsf_fmode == MCAST_INCLUDE) && (imsf->imsf_numsrc == 0)) {
		final = 1;
		if (imop->imo_msf[i]->msf_grpjoin != 0) {
			/* EX{NULL} -> IN{NULL} */
			in_delmulti2(imop->imo_membership[i], 0, NULL,
					MCAST_EXCLUDE, final, &error);
			if (error != 0) {
				printf("in_setmopt_srcfilter: error must be 0! panic!\n");
				splx(s);
				return error;
			}
		} else {
			/* IN{non NULL}/EX{non NULL} -> IN{NULL} */
			in_delmulti2(imop->imo_membership[i], old_num, old_ss,
					old_mode, final, &error);
			if (error != 0) {
				igmplog((LOG_DEBUG, "in_setmopt_srcfilter: "
					"error %d. undo for "
					"IN{non NULL}/EX{non NULL}->IN{NULL}\n",
					error));
				in_undomopt_source_list
					(imop->imo_msf[i], imsf->imsf_fmode);
				if (old_num != 0)
					FREE(old_ss, M_IPMOPTS);
				splx(s);
				return error;
			}
		}
	} else if ((imsf->imsf_fmode == MCAST_EXCLUDE) &&
					(imsf->imsf_numsrc == 0)) {
		if (old_num > 0) {
			/* IN{non NULL}/EX{non NULL} -> EX{NULL} */
			imop->imo_membership[i] =
				in_modmulti2(&imsf->imsf_multiaddr, ifp,
					0, NULL, MCAST_EXCLUDE, old_num, old_ss,
					old_mode, init, 0, &error);
		} else {
			/* IN{NULL} -> EX{NULL} */
			imop->imo_membership[i] =
				in_addmulti2(&imsf->imsf_multiaddr, ifp,
					0, NULL, MCAST_EXCLUDE, init, &error);
		}
		if (error != 0) {
			igmplog((LOG_DEBUG, "in_setmopt_srcfilter: error %d. "
				"undo for IN{non NULL}/EX{non NULL}->EX{NULL} "
				"or IN{NULL}->EX{NULL}\n", error));
			in_undomopt_source_list
					(imop->imo_msf[i], imsf->imsf_fmode);
			if (old_num != 0)
				FREE(old_ss, M_IPMOPTS);
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return error;
		}
	} else {
		/* Something -> IN{non NULL}/EX{non NULL} */
		 /* no change or only delete some sources */
		if (add_num == 0) {
			if (old_num == 0) {
				igmplog((LOG_DEBUG, "in_setmcast_srcfilter: "
					"no change\n"));
				splx(s);
				return 0;
			}
			if (imop->imo_membership[i] == NULL) {
				igmplog((LOG_DEBUG, "in_setmcast_srcfilter: "
					"NULL pointer?\n"));
				splx(s);
				return EOPNOTSUPP;
			}
			in_delmulti2(imop->imo_membership[i], old_num, old_ss,
					old_mode, final, &error);
			if (error != 0) {
				igmplog((LOG_DEBUG, "in_setmcast_srcfilter: "
					"in_delmulti2 retuned error=%d. undo.\n",
					error));
				in_undomopt_source_list
					(imop->imo_msf[i], imsf->imsf_fmode);
				FREE(old_ss, M_IPMOPTS);
				if (ss_src != NULL)
					FREE(ss_src, M_IPMOPTS);
				splx(s);
				return error;
			}
		} else {
			imop->imo_membership[i] =
				in_modmulti2(&imsf->imsf_multiaddr, ifp,
					imsf->imsf_numsrc, ss_src,
					imsf->imsf_fmode, old_num, old_ss,
					old_mode, init,
					imop->imo_msf[i]->msf_grpjoin, &error);
			if (error != 0) {
				igmplog((LOG_DEBUG, "in_setmopt_srcfilter: "
					"in_modmulti2 returned error=%d. undo.\n",
					error));
				in_undomopt_source_list
					(imop->imo_msf[i], imsf->imsf_fmode);
				if (old_num != 0)
					FREE(old_ss, M_IPMOPTS);
				if (ss_src != NULL)
					FREE(ss_src, M_IPMOPTS);
				if (init)
					IMO_MSF_FREE(imop->imo_msf[i]);
				splx(s);
				return error;
			}
		}
	}

	/*
	 * If application requests mode change with filtered sources, clean
	 * up old msf list.
	 * If there is some old msfsrc in an msf list, clean up.
	 * And all remaining refcounts are set to 1.
	 */
	if (imsf->imsf_fmode == MCAST_INCLUDE) {
		if (old_mode == MCAST_EXCLUDE)
			in_freemopt_source_list(imop->imo_msf[i],
					NULL, imop->imo_msf[i]->msf_blkhead);
		else {
			for (msfsrc = LIST_FIRST(imop->imo_msf[i]->msf_head);
					msfsrc; msfsrc = nmsfsrc) {
				nmsfsrc = LIST_NEXT(msfsrc, list);
				if (msfsrc->refcount == 0) {
					LIST_REMOVE(msfsrc, list);
					FREE(msfsrc, M_IPMOPTS);
					--imop->imo_msf[i]->msf_numsrc;
				} else
					msfsrc->refcount = 1;
			}
		}
	} else {
		if (old_mode == MCAST_INCLUDE)
			in_freemopt_source_list(imop->imo_msf[i],
					imop->imo_msf[i]->msf_head, NULL);
		else {
			for (msfsrc = LIST_FIRST(imop->imo_msf[i]->msf_blkhead);
					msfsrc; msfsrc = nmsfsrc) {
				nmsfsrc = LIST_NEXT(msfsrc, list);
				if (msfsrc->refcount == 0) {
					LIST_REMOVE(msfsrc, list);
					FREE(msfsrc, M_IPMOPTS);
					--imop->imo_msf[i]->msf_blknumsrc;
				} else
					msfsrc->refcount = 1;
			}
		}
	}

	if (init)
		++imop->imo_num_memberships;

	if (imsf->imsf_numsrc == 0) {
		in_freemopt_source_list(imop->imo_msf[i],
					imop->imo_msf[i]->msf_head,
					imop->imo_msf[i]->msf_blkhead);
		if (imsf->imsf_fmode == MCAST_EXCLUDE)
			imop->imo_msf[i]->msf_grpjoin = 1;
		/*
		 * Remove the gap in the membership array if there is no
		 * msf member.
		 */
		if (final) {
			IMO_MSF_FREE(imop->imo_msf[i]);
			for (++i; i < imop->imo_num_memberships; ++i) {
				imop->imo_membership[i-1]
						= imop->imo_membership[i];
				imop->imo_msf[i-1] = imop->imo_msf[i];
			}
			--imop->imo_num_memberships;
		}
	} else if (imop->imo_msf[i]->msf_grpjoin)
		imop->imo_msf[i]->msf_grpjoin = 0;

	if (old_ss != NULL)
		FREE(old_ss, M_IPMOPTS);
	if (ss_src != NULL)
		FREE(ss_src, M_IPMOPTS);

	splx(s);
	return error;
}

/*
 * Get multicast source filter of a socket (SIOCGIPMSFILTER) 
 */
int
ip_getmopt_srcfilter(sop, imsfp)
	struct socket *sop;
	struct ip_msfilter **imsfp;
{
	struct inpcb *ipcbp;
	struct ip_moptions *imop;
	struct ifnet *ifp;
	struct ip_msfilter oimsf;
	struct ip_msfilter *imsf;
	struct sock_msf_source *msfsrc;
	struct sockaddr_in *sin;
	struct msf_head head;
	u_int16_t numsrc;
	int i, j;
	int error;

	if (*imsfp == NULL)
		return EINVAL;

	if ((error = copyin((void *)*imsfp, (void *)&oimsf,
			IP_MSFILTER_SIZE(0))) != 0) {
		igmplog((LOG_DEBUG, "ip_getmopt_srcfilter: copyin error.\n"));
		return error;
	} else
		imsf = &oimsf;

	/*
	 * Get a pointer of ifnet structure to the interface.
	 */
	if (in_nullhost(imsf->imsf_interface))
		ifp = NULL;
	else {
		INADDR_TO_IFP(imsf->imsf_interface, ifp);
		if (ifp == NULL)
			return EADDRNOTAVAIL;
	}

	if ((ipcbp = (struct inpcb *)sop->so_pcb) == NULL) {
		igmplog((LOG_DEBUG, "ip_getmopt_srcfilter: inpcb is NULL\n"));
		return EINVAL;
	}
	if ((imop = ipcbp->inp_moptions) == NULL)
		return EINVAL;

	/*
	 * Find the membership in the membership array.
	 */
	for (i = 0; i < imop->imo_num_memberships; i++) {
		if ((ifp == NULL || imop->imo_membership[i]->inm_ifp == ifp) &&
		    in_hosteq(imop->imo_membership[i]->inm_addr,
			      imsf->imsf_multiaddr))
			break;
	}
	if (i == imop->imo_num_memberships) {
		/* no msf entry */
		/* XXX return error if inputted address is not class-d? */
		imsf->imsf_numsrc = 0;
		imsf->imsf_fmode = MCAST_INCLUDE;
		error = copyout((void *)imsf, (void *)*imsfp,
				IP_MSFILTER_SIZE(0));
		return error;
	}

	if (imop->imo_msf[i]->msf_grpjoin != 0) {
		/* (*,G) join */
		imsf->imsf_numsrc = 0;
		imsf->imsf_fmode = MCAST_EXCLUDE;
		error = copyout((void *)imsf, (void *)*imsfp,
				IP_MSFILTER_SIZE(0));
		return error;
	} else if ((imop->imo_msf[i]->msf_numsrc == 0) &&
			(imop->imo_msf[i]->msf_blknumsrc == 0)) {
		/* no msf entry */
		imsf->imsf_numsrc = 0;
		imsf->imsf_fmode = MCAST_INCLUDE;
		error = copyout((void *)imsf, (void *)*imsfp,
				IP_MSFILTER_SIZE(0));
		return error;
	}

	if (imsf->imsf_fmode != MCAST_INCLUDE &&
			imsf->imsf_fmode != MCAST_EXCLUDE) {
		if (imop->imo_msf[i]->msf_numsrc > 0)
			imsf->imsf_fmode = MCAST_INCLUDE;
		else
			imsf->imsf_fmode = MCAST_EXCLUDE;
	}
	if (imsf->imsf_fmode == MCAST_INCLUDE) {
		LIST_FIRST(&head) = LIST_FIRST(imop->imo_msf[i]->msf_head);
		numsrc = min(imop->imo_msf[i]->msf_numsrc, imsf->imsf_numsrc);
	} else {
		LIST_FIRST(&head) = LIST_FIRST(imop->imo_msf[i]->msf_blkhead);
		numsrc = min(imop->imo_msf[i]->msf_blknumsrc,imsf->imsf_numsrc);
	}
	imsf->imsf_numsrc = numsrc;
	if ((error = copyout((void *)imsf, (void *)*imsfp,
				IP_MSFILTER_SIZE(0))) != 0)
		return error;

	for (msfsrc = LIST_FIRST(&head), j = 0; numsrc > j && msfsrc;
			++j, msfsrc = LIST_NEXT(msfsrc, list)) {
		sin = SIN(&msfsrc->src);
		error = copyout((void *)&sin,
				(void *)&(*imsfp)->imsf_slist[j],
				sin->sin_len);
		if (error != 0) {
			return error;
		}
	}

	return 0;
}

/*
 * Set multicast source filter of a socket (SIOCSMSFILTER) 
 */
int
sock_setmopt_srcfilter(sop, grpfp)
	struct socket *sop;
	struct group_filter **grpfp;
{
	struct inpcb *ipcbp;
	struct ip_moptions *imop;
	struct ifnet *ifp;
	struct group_filter ogrpf;
	struct group_filter *grpf;
	struct sockaddr_in *in_grp;
	struct sockaddr_storage *ss_src, *old_ss;
	u_int16_t add_num, old_num;
	u_int old_mode;
	struct sockaddr_in *sin, *dst;
	struct sockaddr_in src;
	struct route ro;
	struct sock_msf_source *msfsrc, *nmsfsrc;
	struct in_addr_slist *iasl;
	struct in_addr_source *ias;
	int i, j;
	int error = 0;
	int init, final;
	int s;
#if !defined(__FreeBSD__) && defined(MROUTING)
	extern struct socket *ip_mrouter;
#endif

	if (*grpfp == NULL)
		return EINVAL;

	error = copyin((void *)*grpfp, (void *)&ogrpf, GROUP_FILTER_SIZE(0));
	if (error != 0) {
		igmplog((LOG_DEBUG, "sock_setmopt_srcfilter: copyin error.\n"));
		return error;
	}
	grpf = &ogrpf;

	if (grpf->gf_numsrc >= igmpsomaxsrc) {
		igmplog((LOG_DEBUG, "sock_setmopt_srcfilter: the number of sources is reached to max count.\n"));
		return EINVAL;
	}
	if (grpf->gf_group.ss_family != AF_INET)
		return EPFNOSUPPORT;

	in_grp = SIN(&grpf->gf_group);
	if ((grpf->gf_numsrc != 0))
		return EINVAL;
#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (!IN_MULTICAST(in_grp->sin_addr.s_addr))
#else
	if (!IN_MULTICAST(ntohl(in_grp->sin_addr.s_addr)))
#endif
		return EINVAL;
	if (!is_igmp_target(&in_grp->sin_addr))
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
		dst = satosin(&ro.ro_dst);
		dst->sin_len = sizeof(*dst);
		dst->sin_family = AF_INET;
		dst->sin_addr = in_grp->sin_addr;
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
	if ((ipcbp = (struct inpcb *)sop->so_pcb) == NULL) {
		splx(s);
		return EINVAL;
	}
	if ((imop = ipcbp->inp_moptions) == NULL) {
		imop = (struct ip_moptions *)
			malloc(sizeof(*imop), M_IPMOPTS, M_NOWAIT);
		if (imop == NULL) {
			splx(s);
			return ENOBUFS;
		}
		imop->imo_multicast_ifp = ifp;
		imop->imo_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
#ifdef RSVP_ISI
		imop->imo_multicast_vif = -1;
#endif
#ifdef MROUTING
		imop->imo_multicast_loop = (ip_mrouter != NULL);
#else
		imop->imo_multicast_loop = 0;
#endif
		imop->imo_num_memberships = 0;
		ipcbp->inp_moptions = imop;
	}

	/*
	 * Find the membership in the membership array.
	 */
	for (i = 0; i < imop->imo_num_memberships; i++) {
		if ((imop->imo_membership[i]->inm_ifp == ifp) &&
		    in_hosteq(imop->imo_membership[i]->inm_addr,
			      in_grp->sin_addr))
			break;
	}

	if (i < imop->imo_num_memberships) {
		if ((grpf->gf_fmode == MCAST_EXCLUDE) &&
		    (grpf->gf_numsrc == 0) &&
		    (imop->imo_msf[i]->msf_grpjoin != 0)) {
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
		IMO_MSF_ALLOC(imop->imo_msf[i]);
		if (error != 0) {
			splx(s);
			return error;
		}
		init = 1;
	}

	/*
	 * Prepare sock_storage for in_addmulti2(), in_delmulti2(), and
	 * in_modmulti2(). Inputted source lists are sorted below.
	 */
	if (grpf->gf_numsrc != 0) {
		IAS_LIST_ALLOC(iasl);
		if (error != 0) {
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return error;
		}
		for (j = 0; j < grpf->gf_numsrc; j++) {
			error = copyin((void *)&((*grpfp)->gf_slist[j]),
				       (void *)&src, sizeof(struct sockaddr_in));
			if (error != 0) /* EFAULT */
				break;
			if ((ntohl(src.sin_addr.s_addr) & IN_CLASSA_NET) == 0) {
				error = EINVAL;
				break;
			}
#ifdef __FreeBSD__
			if (IN_MULTICAST(ntohl(src.sin_addr.s_addr)) ||
			    IN_BADCLASS(ntohl(src.sin_addr.s_addr)))
#else
			if (IN_MULTICAST(src.sin_addr.s_addr) ||
			    IN_BADCLASS(src.sin_addr.s_addr))
#endif
			{
				error = EINVAL;
				break;
			}

			/*
			 * Sort and validate source lists. Duplicate addresses
			 * can be checked here.
			 */
			if (in_merge_msf_source_addr(iasl, &src,
						     IMS_ADD_SOURCE) != 1) {
				error = EINVAL;
				break;
			}
		}
		if (error != 0) {
			in_free_msf_source_list(iasl->head);
			FREE(iasl->head, M_MSFILTER);
			FREE(iasl, M_MSFILTER);
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
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
			in_free_msf_source_list(iasl->head);
			FREE(iasl->head, M_MSFILTER);
			FREE(iasl, M_MSFILTER);
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return ENOBUFS;
		}
		for (j = 0, ias = LIST_FIRST(iasl->head);
		     j < grpf->gf_numsrc && ias;
		     j++, ias = LIST_NEXT(ias, ias_list)) {
			sin = SIN(&ss_src[j]);
			bcopy(&ias->ias_addr, sin, ias->ias_addr.sin_len);
		}
		in_free_msf_source_list(iasl->head);
		FREE(iasl->head, M_MSFILTER);
		FREE(iasl, M_MSFILTER);
	} else
		ss_src = NULL;

	/*
	 * Prepare old msf source list space.
	 */
	old_ss = NULL;
	old_mode = MCAST_INCLUDE;
	if (imop->imo_msf[i]->msf_grpjoin != 0)
		old_mode = MCAST_EXCLUDE;
	else if (imop->imo_msf[i]->msf_numsrc != 0) {
		MALLOC(old_ss, struct sockaddr_storage *,
			sizeof(*old_ss) * imop->imo_msf[i]->msf_numsrc,
			M_IPMOPTS, M_NOWAIT);
		if (old_ss == NULL) {
			if (ss_src != NULL)
				FREE(ss_src, M_IPMOPTS);
			splx(s);
			return ENOBUFS;
		}
		old_mode = MCAST_INCLUDE;
	} else if (imop->imo_msf[i]->msf_blknumsrc != 0) {
		MALLOC(old_ss, struct sockaddr_storage *,
			sizeof(*old_ss) * imop->imo_msf[i]->msf_blknumsrc,
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
	error = in_setmopt_source_list(imop->imo_msf[i], grpf->gf_numsrc,
				       ss_src, grpf->gf_fmode, &add_num,
				       &old_num, old_ss);
	if (error != 0) {
		if (old_ss != NULL)
			FREE(old_ss, M_IPMOPTS);
		if (ss_src != NULL)
			FREE(ss_src, M_IPMOPTS);
		if (init)
			IMO_MSF_FREE(imop->imo_msf[i]);
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
		if (imop->imo_msf[i]->msf_grpjoin != 0) {
			in_delmulti2(imop->imo_membership[i], 0, NULL,
				    MCAST_EXCLUDE, final, &error);
			if (error != 0) {
				printf("sock_setmopt_srcfilter: error must be 0! panic!\n");
				splx(s);
				return error;
			}
		} else {
			in_delmulti2(imop->imo_membership[i], old_num, old_ss,
					old_mode, final, &error);
			if (error != 0) {
				igmplog((LOG_DEBUG, "sock_setmopt_srcfilter: "
					"error %d. undo for "
					"IN{non NULL}/EX{non NULL}->IN{NULL}\n",
					error));
				in_undomopt_source_list
					(imop->imo_msf[i], grpf->gf_fmode);
				if (old_num != 0)
					FREE(old_ss, M_IPMOPTS);
				splx(s);
				return error;
			}
		}
	} else if ((grpf->gf_fmode == MCAST_EXCLUDE) &&
					(grpf->gf_numsrc == 0)) {
		if (old_num > 0) {
			imop->imo_membership[i] =
				in_modmulti2(&in_grp->sin_addr, ifp,
					0, NULL, MCAST_EXCLUDE, old_num, old_ss,
					old_mode, init, 0, &error);
		} else {
			imop->imo_membership[i] =
				in_addmulti2(&in_grp->sin_addr, ifp,
					0, NULL, MCAST_EXCLUDE, init, &error);
		}
		if (error != 0) {
			igmplog((LOG_DEBUG, "sock_setmopt_srcfilter: error %d. "
				"undo for IN{non NULL}/EX{non NULL}->EX{NULL} "
				"or IN{NULL}->EX{NULL}\n", error));
			in_undomopt_source_list
					(imop->imo_msf[i], grpf->gf_fmode);
			if (old_num != 0)
				FREE(old_ss, M_IPMOPTS);
			if (init)
				IMO_MSF_FREE(imop->imo_msf[i]);
			splx(s);
			return error;
		}
	} else {
		if (add_num == 0) { /* only delete some sources */
			if (imop->imo_membership[i] == NULL) {
				printf("sock_setmopt_srcfilter: NULL pointer?\n");
				splx(s);
				return EOPNOTSUPP;
			}
			in_delmulti2(imop->imo_membership[i], old_num, old_ss,
					old_mode, final, &error);
			if (error != 0) {
				igmplog((LOG_DEBUG, "sock_setmopt_srcfilter: "
					"in_delmulti2 retuned error=%d. undo.\n",
					error));
				in_undomopt_source_list
					(imop->imo_msf[i], grpf->gf_fmode);
				FREE(old_ss, M_IPMOPTS);
				if (ss_src != NULL)
					FREE(ss_src, M_IPMOPTS);
				splx(s);
				return error;
			}
		} else {
			imop->imo_membership[i] =
				in_modmulti2(&in_grp->sin_addr, ifp,
					grpf->gf_numsrc, ss_src,
					grpf->gf_fmode, old_num, old_ss,
					old_mode, init,
					imop->imo_msf[i]->msf_grpjoin, &error);
			if (error != 0) {
				igmplog((LOG_DEBUG, "sock_setmopt_srcfilter: "
					"in_modmulti2 returned error=%d. undo.\n",
					error));
				in_undomopt_source_list
					(imop->imo_msf[i], grpf->gf_fmode);
				if (old_num != 0)
					FREE(old_ss, M_IPMOPTS);
				if (ss_src != NULL)
					FREE(ss_src, M_IPMOPTS);
				if (init)
					IMO_MSF_FREE(imop->imo_msf[i]);
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
			in_freemopt_source_list(imop->imo_msf[i],
					NULL, imop->imo_msf[i]->msf_blkhead);
		else {
			for (msfsrc = LIST_FIRST(imop->imo_msf[i]->msf_head);
					msfsrc; msfsrc = nmsfsrc) {
				nmsfsrc = LIST_NEXT(msfsrc, list);
				if (msfsrc->refcount == 0) {
					LIST_REMOVE(msfsrc, list);
					FREE(msfsrc, M_IPMOPTS);
					--imop->imo_msf[i]->msf_numsrc;
				} else
					msfsrc->refcount = 1;
			}
		}
	} else {
		if (old_mode == MCAST_INCLUDE)
			in_freemopt_source_list(imop->imo_msf[i],
					imop->imo_msf[i]->msf_head, NULL);
		else {
			for (msfsrc = LIST_FIRST(imop->imo_msf[i]->msf_blkhead);
					msfsrc; msfsrc = nmsfsrc) {
				nmsfsrc = LIST_NEXT(msfsrc, list);
				if (msfsrc->refcount == 0) {
					LIST_REMOVE(msfsrc, list);
					FREE(msfsrc, M_IPMOPTS);
					--imop->imo_msf[i]->msf_blknumsrc;
				} else
					msfsrc->refcount = 1;
			}
		}
	}

	if (init)
		++imop->imo_num_memberships;

	if (grpf->gf_numsrc == 0) {
		in_freemopt_source_list(imop->imo_msf[i],
					imop->imo_msf[i]->msf_head,
					imop->imo_msf[i]->msf_blkhead);
		if (grpf->gf_fmode == MCAST_EXCLUDE)
			imop->imo_msf[i]->msf_grpjoin = 1;
		/*
		 * Remove the gap in the membership array if there is no
		 * msf member.
		 */
		if (final) {
			IMO_MSF_FREE(imop->imo_msf[i]);
			for (++i; i < imop->imo_num_memberships; ++i) {
				imop->imo_membership[i-1]
						= imop->imo_membership[i];
				imop->imo_msf[i-1] = imop->imo_msf[i];
			}
			--imop->imo_num_memberships;
		}
	} else if (imop->imo_msf[i]->msf_grpjoin)
		imop->imo_msf[i]->msf_grpjoin = 0;

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
sock_getmopt_srcfilter(sop, grpfp)
	struct socket *sop;
	struct group_filter **grpfp;
{
	struct inpcb *ipcbp;
	struct ip_moptions *imop;
	struct ifnet *ifp;
	struct group_filter ogrpf;
	struct group_filter *grpf;
	struct sockaddr_in *in_grp;
	struct sock_msf_source *msfsrc;
	struct sockaddr_in *sin;
	struct msf_head head;
	u_int16_t numsrc;
	int i, j;
	int error;

	if (*grpfp == NULL)
		return EINVAL;

	if ((error = copyin((void *)*grpfp, (void *)&ogrpf,
			GROUP_FILTER_SIZE(0))) != 0) {
		igmplog((LOG_DEBUG, "sock_getmopt_srcfilter: copyin error.\n"));
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

	if ((ipcbp = (struct inpcb *)sop->so_pcb) == NULL)
		return EINVAL;
	if ((imop = ipcbp->inp_moptions) == NULL)
		return EINVAL;

	if (grpf->gf_group.ss_family == AF_INET) {
		in_grp = SIN(&grpf->gf_group);
#if defined(__NetBSD__) || defined(__OpenBSD__)
		if (!IN_MULTICAST(in_grp->sin_addr.s_addr))
#else
		if (!IN_MULTICAST(ntohl(in_grp->sin_addr.s_addr)))
#endif
			return EINVAL;
	} else
		return EPFNOSUPPORT;

	/*
	 * Find the membership in the membership array.
	 */
	for (i = 0; i < imop->imo_num_memberships; i++) {
		if ((ifp == NULL || imop->imo_membership[i]->inm_ifp == ifp) &&
		    in_hosteq(imop->imo_membership[i]->inm_addr,
			      in_grp->sin_addr))
			break;
	}
	if (i == imop->imo_num_memberships) {
		/* no msf entry */
		grpf->gf_numsrc = 0;
		grpf->gf_fmode = MCAST_INCLUDE;
		error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0));
		return error;
	}

	if (imop->imo_msf[i]->msf_grpjoin != 0) {
		/* (*,G) join */
		grpf->gf_numsrc = 0;
		grpf->gf_fmode = MCAST_EXCLUDE;
		error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0));
		return error;
	} else if ((imop->imo_msf[i]->msf_numsrc == 0) &&
			(imop->imo_msf[i]->msf_blknumsrc == 0)) {
		/* no msf entry */
		grpf->gf_numsrc = 0;
		grpf->gf_fmode = MCAST_INCLUDE;
		error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0));
		return error;
	}

	if (grpf->gf_fmode != MCAST_INCLUDE &&
			grpf->gf_fmode != MCAST_EXCLUDE) {
		if (imop->imo_msf[i]->msf_numsrc > 0)
			grpf->gf_fmode = MCAST_INCLUDE;
		else
			grpf->gf_fmode = MCAST_EXCLUDE;
	}
	if (grpf->gf_fmode == MCAST_INCLUDE) {
		LIST_FIRST(&head) = LIST_FIRST(imop->imo_msf[i]->msf_head);
		numsrc = min(imop->imo_msf[i]->msf_numsrc, grpf->gf_numsrc);
	} else {
		LIST_FIRST(&head) = LIST_FIRST(imop->imo_msf[i]->msf_blkhead);
		numsrc = min(imop->imo_msf[i]->msf_blknumsrc, grpf->gf_numsrc);
	}
	grpf->gf_numsrc = numsrc;
	if ((error = copyout((void *)grpf, (void *)*grpfp,
				GROUP_FILTER_SIZE(0))) != 0)
		return error;

	for (msfsrc = LIST_FIRST(&head), j = 0; numsrc > j && msfsrc;
	     ++j, msfsrc = LIST_NEXT(msfsrc, list)) {
		sin = SIN(&msfsrc->src);
		error = copyout((void *)sin,
				(void *)&((*grpfp)->gf_slist[j]),
				sin->sin_len);
		if (error != 0) {
			return error;
		}
	}

	return 0;
}
#endif /* IGMPV3 */

/*
 * Followings are Protocol-Independent functions.
 * Keep the ability when these are modified.
 */

/*
 * In order to clean up filtered source list when group leave is requested,
 * each source address is inserted in a buffer.
 */
int
in_getmopt_source_list(msf, numsrc, oss, mode)
	struct sock_msf *msf;
	u_int16_t *numsrc;
	struct sockaddr_storage **oss;
	u_int *mode;
{
	struct sockaddr_storage *ss = NULL;
	struct sock_msf_source *msfsrc;
	int i;

	if (msf->msf_numsrc != 0) {
		MALLOC(ss, struct sockaddr_storage *,
		       sizeof(*ss) * msf->msf_numsrc, M_IPMOPTS, M_WAITOK);
		for (i = 0, msfsrc = LIST_FIRST(msf->msf_head);
				i < msf->msf_numsrc && msfsrc;
				i++, msfsrc = LIST_NEXT(msfsrc, list)) {
			/* Move unneeded sources to ss */
			bcopy(&msfsrc->src, &ss[i], sizeof(ss[i]));
		}
		if (i != msf->msf_numsrc || msfsrc != NULL)
			return EOPNOTSUPP; /* panic ? */
		*numsrc = msf->msf_numsrc;
		*mode = MCAST_INCLUDE;
	} else if (msf->msf_blknumsrc != 0) {
		MALLOC(ss, struct sockaddr_storage *,
		       sizeof(*ss) * msf->msf_blknumsrc, M_IPMOPTS, M_WAITOK);
		for (i = 0, msfsrc = LIST_FIRST(msf->msf_blkhead);
				i < msf->msf_blknumsrc && msfsrc;
				i++, msfsrc = LIST_NEXT(msfsrc, list)) {
			/* Move unneeded sources to ss */
			bcopy(&msfsrc->src, &ss[i], sizeof(ss[i]));
		}
		if (i != msf->msf_blknumsrc || msfsrc != NULL)
			return EOPNOTSUPP; /* panic ? */
		*numsrc = msf->msf_blknumsrc;
		*mode = MCAST_EXCLUDE;
	} else if (msf->msf_grpjoin >= 1) {
		*numsrc = 0;
		*mode = MCAST_EXCLUDE;
	} else
		return EADDRNOTAVAIL;

	/* This allocated buffer must be freed by caller */
	*oss = ss;
	return 0;
}


/*
 * Set or delete source address to/from the msf.
 * If requested source address was already in the socket list when the
 * command is to add source filter, or if requested source address was not in
 * the socket list when the command is to delete source filter, return
 * EADDRNOTAVAIL.
 * If there is not enough memory, return ENOBUFS.
 * Otherwise, 0 will be returned, which means okay.
 */
int
in_setmopt_source_addr(ss, msf, optname)
	struct sockaddr_storage *ss;
	struct sock_msf *msf;
	int optname;
{
	struct sock_msf_source *msfsrc, *newsrc, *lastp = NULL;
	struct msf_head head;
	u_int16_t *curnumsrc;
#if defined(__NetBSD__) || defined(__OpenBSD__)	
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	/*
	 * Create multicast source filter list on the socket.
	 */
	if (IGMP_JOINLEAVE_OPS(optname)) {
		if (!LIST_EMPTY(msf->msf_head)) {
			LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
			curnumsrc = &msf->msf_numsrc;
			goto merge_msf_list;
		}
		if (IGMP_MSFOFF_OPS(optname)) {
			splx(s);
			return EADDRNOTAVAIL;
		}
		msfsrc = (struct sock_msf_source *)malloc(sizeof(*msfsrc),
							  M_IPMOPTS, M_NOWAIT);
		if (msfsrc == NULL) {
			splx(s);
			return ENOBUFS;
		}
		bcopy(&ss[0], &msfsrc->src, ss[0].ss_len);
		msfsrc->refcount = 2;
		LIST_INSERT_HEAD(msf->msf_head, msfsrc, list);
		msf->msf_numsrc = 1;
		splx(s);
		return 0;
	} else if (IGMP_BLOCK_OPS(optname)) {
		if (!LIST_EMPTY(msf->msf_blkhead)) {
			LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
			curnumsrc = &msf->msf_blknumsrc;
			goto merge_msf_list;
		}
		if (IGMP_MSFOFF_OPS(optname)) {
			splx(s);
			return EADDRNOTAVAIL;
		}
		msfsrc = (struct sock_msf_source *)malloc(sizeof(*msfsrc),
							  M_IPMOPTS, M_NOWAIT);
		if (msfsrc == NULL) {
			splx(s);
			return ENOBUFS;
		}
		bcopy(&ss[0], &msfsrc->src, ss[0].ss_len);
		msfsrc->refcount = 2;
		LIST_INSERT_HEAD(msf->msf_blkhead, msfsrc, list);
		msf->msf_blknumsrc = 1;
		splx(s);
		return 0;
	} else {
		splx(s);
		return EINVAL;
	}

	/*
	 * Merge to recorded msf list.
	 */
merge_msf_list:
	LIST_FOREACH(msfsrc, &head, list) {
		lastp = msfsrc;

		if (ss->ss_family != msfsrc->src.ss_family)
			continue;
		
		if (SS_CMP(ss, >, &msfsrc->src))
			continue;
		if (SS_CMP(ss, ==, &msfsrc->src)) {
			if (IGMP_MSFON_OPS(optname)) {
				splx(s);
				return EADDRNOTAVAIL;
			}
			msfsrc->refcount = 0;
			msfsrc = LIST_FIRST(&head); /* set non NULL */
			break;
		}
		/* creates a new entry here */
		if (!IGMP_MSFON_OPS(optname)) {
			splx(s);
			return EADDRNOTAVAIL;
		}
		newsrc = (struct sock_msf_source *)malloc(sizeof(*newsrc),
							  M_IPMOPTS, M_NOWAIT);
		if (newsrc == NULL) {
			splx(s);
			return ENOBUFS;
		}
		bcopy(ss, &newsrc->src, ss->ss_len);
		newsrc->refcount = 2;
		LIST_INSERT_BEFORE(msfsrc, newsrc, list);
		break;
	}
	if (!msfsrc) {
		if (!IGMP_MSFON_OPS(optname)) {
			splx(s);
			return EADDRNOTAVAIL;
		}
		newsrc = (struct sock_msf_source *)malloc(sizeof(*newsrc),
							  M_IPMOPTS, M_NOWAIT);
		if (newsrc == NULL) {
			splx(s);
			return ENOBUFS;
		}
		bcopy(ss, &newsrc->src, ss->ss_len);
		newsrc->refcount = 2;
		LIST_INSERT_AFTER(lastp, newsrc, list);
	}

	if (IGMP_MSFON_OPS(optname))
		++(*curnumsrc);
	else if (IGMP_MSFOFF_OPS(optname))
		--(*curnumsrc);

	splx(s);
	return 0;
}

/*
 * Set or delete source addresses to/from the msf.
 * For advanced API, every request overwrites existing msf.
 * If (*,G) join was requested even it was previously requested for this msf,
 * return EADDRINUSE.
 * If (*,G) leave was requested when there is no (*,G) join status for this
 * msf, return EADDRNOTAVAIL.
 * If there is not enough memory, return ENOBUFS.
 * If the argument is invalid, return EINVAL.
 * Otherwise, 0 will be returned, which means okay.
 */
int
in_setmopt_source_list(msf, numsrc, ss, mode, add_num, old_num, old_ss)
	struct sock_msf *msf;
	u_int16_t numsrc;
	struct sockaddr_storage *ss, *old_ss;
	u_int mode;
	u_int16_t *add_num, *old_num;
{
	struct sockaddr *src = NULL, *lsrc;
	struct sock_msf_source *msfsrc, *nmsfsrc, *cursrc, *newsrc, *lastp;
	struct msf_head head;
	u_int16_t *curnumsrc;
	u_int curmode;
	u_int16_t i, j;

	if (mode != MCAST_INCLUDE && mode != MCAST_EXCLUDE) {
		return EINVAL;
	}
	i = j = 0;
	msfsrc = lastp = NULL;

	/*
	 * Create multicast source filter list on the socket.
	 */
	if (numsrc == 0) {
		if (msf->msf_numsrc != 0) {
			for (j = 0, cursrc = LIST_FIRST(msf->msf_head);
			     j < msf->msf_numsrc && cursrc;
			     j++, cursrc = LIST_NEXT(cursrc, list)) {
				/* Move unneeded sources to old_ss */
				bcopy(&cursrc->src, &old_ss[j],
				      cursrc->src.ss_len);
				cursrc->refcount = 0;
			}
			msf->msf_numsrc = 0;
		} else if (msf->msf_blknumsrc != 0) {
			for (j = 0, cursrc = LIST_FIRST(msf->msf_blkhead);
			     j < msf->msf_blknumsrc && cursrc;
			     j++, cursrc = LIST_NEXT(cursrc, list)) {
				/* Move unneeded sources to old_ss */
				bcopy(&cursrc->src, &old_ss[j],
				      cursrc->src.ss_len);
				cursrc->refcount = 0;
			}
			msf->msf_blknumsrc = 0;
		}
		*old_num = j;
		return 0;
	}

	if (mode == MCAST_INCLUDE) {
		if (msf->msf_blknumsrc != 0) {
			/* Filter-Mode-Change request */
			for (j = 0, cursrc = LIST_FIRST(msf->msf_blkhead);
			     j < msf->msf_blknumsrc && cursrc;
			     j++, cursrc = LIST_NEXT(cursrc, list)) {
				/* Move unneeded sources to old_ss */
				bcopy(&cursrc->src, &old_ss[j],
				      cursrc->src.ss_len);
				cursrc->refcount = 0;
			}
			msf->msf_blknumsrc = 0;
			*old_num = j;
			curmode = MCAST_EXCLUDE;
		} else
			curmode = MCAST_INCLUDE;
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
		curnumsrc = &msf->msf_numsrc;
	} else {
		if (msf->msf_numsrc != 0) {
			/* Filter-Mode-Change request */
			for (j = 0, cursrc = LIST_FIRST(msf->msf_head);
			     j < msf->msf_numsrc && cursrc;
			     j++, cursrc = LIST_NEXT(cursrc, list)) {
				/* Move unneeded sources to old_ss */
				bcopy(&cursrc->src, &old_ss[j],
				      cursrc->src.ss_len);
				cursrc->refcount = 0;
			}
			msf->msf_numsrc = 0;
			*old_num = j;
			curmode = MCAST_INCLUDE;
		} else
			curmode = MCAST_EXCLUDE;
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
		curnumsrc = &msf->msf_blknumsrc;
	}

	for (i = 0; i < numsrc; i++) {
		u_char len, family;

		src = (struct sockaddr *)&ss[i];
		len = src->sa_len;
		family = src->sa_family;

		/* Note that ss lists are already ordered smaller first. */
		if (src->sa_family != AF_INET && src->sa_family != AF_INET6)
			continue; /* XXX unexpected */

		if (SS_IS_ADDR_UNSPECIFIED(src))
			continue; /* skip */

		LIST_FOREACH(msfsrc, &head, list) {
			lastp = msfsrc;
			lsrc = (struct sockaddr *)&msfsrc->src;

			/* sanity check */
			if (lsrc->sa_len != src->sa_len ||
			    lsrc->sa_family != src->sa_family)
				continue;
			if (lsrc->sa_family != AF_INET && 
			    lsrc->sa_family != AF_INET6)
				continue;

			if (SS_CMP(lsrc, ==, src)) {
				/*
				 * Overwrite unspecified address to ss[i]. 
				 * This entry will be ignored by 
				 * in*_addmultisrc() or in*_modmultisrc() 
				 * in order to skip the join procedure for 
				 * this source.
				 */
				bzero(src, len);
				src->sa_len = len;
				src->sa_family = family;
				LIST_FIRST(&head) = LIST_NEXT(msfsrc, list);
				break;
			} else if (SS_CMP(lsrc, >, src)) {
				MALLOC(newsrc, struct sock_msf_source *,
					sizeof(*newsrc), M_IPMOPTS, M_NOWAIT);
				if (newsrc == NULL) {
					in_undomopt_source_list(msf, mode);
					return ENOBUFS;
				}
				bcopy(src, &newsrc->src, len);
				newsrc->refcount = 2;
				LIST_INSERT_BEFORE(msfsrc, newsrc, list);
				LIST_FIRST(&head) = msfsrc;
				++(*add_num);
				break;
			} else
				msfsrc->refcount = 0; /* will be removed */
		}
		if (!msfsrc) {
			LIST_INIT(&head); /* stop list scan */
			MALLOC(newsrc, struct sock_msf_source *,
				sizeof(*newsrc), M_IPMOPTS, M_NOWAIT);
			if (newsrc == NULL) {
				in_undomopt_source_list(msf, mode);
				return ENOBUFS;
			}
			bcopy(src, &newsrc->src, src->sa_len);
			newsrc->refcount = 2;
			if (mode == MCAST_INCLUDE && LIST_EMPTY(msf->msf_head)) {
				LIST_INSERT_HEAD(msf->msf_head, newsrc, list);
			} else if (mode == MCAST_EXCLUDE &&
					LIST_EMPTY(msf->msf_blkhead)) {
				LIST_INSERT_HEAD(msf->msf_blkhead,
						 newsrc, list);
			} else {
				LIST_INSERT_AFTER(lastp, newsrc, list);
			}
			++(*add_num);
			lastp = newsrc;
		}
	}
	if (msfsrc) {
		/* 
		 * Remaining sources will be removed.
		 */
		LIST_FOREACH(msfsrc, &head, list)
			msfsrc->refcount = 0;
	}

	/*
	 * Copy old sources from corresponding msf list.
	 * If application requests Filter-Mode-Change, msfsrc and old_ss were
	 * already created above.
	 * If application doesn't request Filter-Mode-Change, it requests
	 * Source-List-Change, then old_ss is newly filled here, which
	 * consists of old sources having refcount = 0.
	 */
	if (mode == curmode) {
		if (mode == MCAST_INCLUDE)
			LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
		else
			LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
		for (i = j = 0, msfsrc = LIST_FIRST(&head);
		     i < (*curnumsrc + *add_num) && msfsrc;
		     i++, msfsrc = nmsfsrc) {
			nmsfsrc = LIST_NEXT(msfsrc, list);
			if (msfsrc->refcount == 0) {
				if (old_ss) {
					/* Move unneeded sources to old_ss */
					bcopy(&msfsrc->src, &old_ss[j],
					      msfsrc->src.ss_len);
					j++;
				} else {
					in_undomopt_source_list(msf, mode);
					igmplog((LOG_DEBUG, "in_setmopt_source_list: cannot insert to old_ss. undo\n"));
					return EOPNOTSUPP;
				}
			}
		}
		*old_num = j;
	}
	*curnumsrc += *add_num; /* including refcount=0's sources yet */

	return 0;
}

/*
 * Undo msf changes for Basic APIs.
 */
void
in_undomopt_source_addr(msf, optname)
	struct sock_msf *msf;
	int optname;
{
	struct sock_msf_source *msfsrc, *nmsfsrc;
	struct msf_head head;
	u_int16_t *curnumsrc = NULL;

	if (IGMP_JOINLEAVE_OPS(optname)) {
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
		curnumsrc = &msf->msf_numsrc;
	} else if (IGMP_BLOCK_OPS(optname)) {
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
		curnumsrc = &msf->msf_blknumsrc;
	}

	for (msfsrc = LIST_FIRST(&head); msfsrc; msfsrc = nmsfsrc) {
		nmsfsrc = LIST_NEXT(msfsrc, list);
		if (IGMP_MSFON_OPS(optname)) {
			if (msfsrc->refcount == 2) {
				LIST_REMOVE(msfsrc, list);
				FREE(msfsrc, M_IPMOPTS);
				--(*curnumsrc);
				break;
			}
		} else {
			if (msfsrc->refcount == 0) {
				msfsrc->refcount = 1;
				++(*curnumsrc);
				break;
			}
		}
	}

	if ((msf->msf_numsrc == 0) && (msf->msf_blknumsrc == 0) &&
			(msf->msf_grpjoin == 0)) {
		IMO_MSF_FREE(msf);
	} else if (*curnumsrc == 0) {
		LIST_INIT(&head);
	}
}

/*
 * Undo msf changes for Advanced APIs.
 */
void
in_undomopt_source_list(msf, mode)
	struct sock_msf *msf;
	u_int mode;
{
	struct sock_msf_source *msfsrc, *nmsfsrc;
	struct msf_head head;
	u_int16_t *curnumsrc = NULL;

	if (mode == MCAST_INCLUDE) {
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
		curnumsrc = &msf->msf_numsrc;
	} else if (mode == MCAST_EXCLUDE) {
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
		curnumsrc = &msf->msf_blknumsrc;
	} else
		return;

	for (msfsrc = LIST_FIRST(&head); msfsrc; msfsrc = nmsfsrc) {
		nmsfsrc = LIST_NEXT(msfsrc, list);
		if (msfsrc->refcount == 2) {
			LIST_REMOVE(msfsrc, list);
			FREE(msfsrc, M_IPMOPTS);
			--(*curnumsrc);
		} else if (msfsrc->refcount == 0) {
			msfsrc->refcount = 1;
			++(*curnumsrc);
		}
	}

	if ((msf->msf_numsrc == 0) && (msf->msf_blknumsrc == 0) &&
	    (msf->msf_grpjoin == 0)) {
		IMO_MSF_FREE(msf);
	} else if (*curnumsrc == 0) {
		LIST_INIT(&head);
	}
}

void
in_freemopt_source_list(msf, msf_head, msf_blkhead)
	struct sock_msf *msf;
	struct msf_head *msf_head;
	struct msf_head *msf_blkhead;
{
	struct sock_msf_source *msfsrc, *nmsfsrc;

	if (msf == NULL)
		return;

	if (msf_head != NULL) {
		for (msfsrc = LIST_FIRST(msf_head); msfsrc; msfsrc = nmsfsrc) {
			nmsfsrc = LIST_NEXT(msfsrc, list);
			LIST_REMOVE(msfsrc, list);
			FREE(msfsrc, M_IPMOPTS);
		}
		LIST_INIT(msf->msf_head);
		msf->msf_numsrc = 0;
	}
	if (msf_blkhead != NULL) {
		for (msfsrc = LIST_FIRST(msf_blkhead); msfsrc; msfsrc = nmsfsrc) {
			nmsfsrc = LIST_NEXT(msfsrc, list);
			LIST_REMOVE(msfsrc, list);
			FREE(msfsrc, M_IPMOPTS);
		}
		LIST_INIT(msf->msf_blkhead);
		msf->msf_blknumsrc = 0;
	}
}

/*
 * Confirm source address addition or deletion ordered by Basic APIs.
 * This adjusts refcount of added source or cleans up an unneeded source.
 * Note that numsrc was already adjusted.
 */
void
in_cleanmopt_source_addr(msf, optname)
	struct sock_msf *msf;
	int optname;
{
	struct sock_msf_source *msfsrc, *nmsfsrc;
	struct msf_head head;
	u_int16_t *curnumsrc = NULL;

	if (IGMP_JOINLEAVE_OPS(optname)) {
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_head);
		curnumsrc = &msf->msf_numsrc;
	} else if (IGMP_BLOCK_OPS(optname)) {
		LIST_FIRST(&head) = LIST_FIRST(msf->msf_blkhead);
		curnumsrc = &msf->msf_blknumsrc;
	}

	for (msfsrc = LIST_FIRST(&head); msfsrc; msfsrc = nmsfsrc) {
		nmsfsrc = LIST_NEXT(msfsrc, list);
		if (IGMP_MSFON_OPS(optname)) {
			if (msfsrc->refcount == 2) {
				msfsrc->refcount = 1;
				break;
			}
		} else {
			if (msfsrc->refcount == 0) {
				LIST_REMOVE(msfsrc, list);
				FREE(msfsrc, M_IPMOPTS);
				break;
			}
		}
	}

	if ((msf->msf_numsrc == 0) && (msf->msf_blknumsrc == 0) &&
			(msf->msf_grpjoin == 0)) {
		IMO_MSF_FREE(msf);
	} else if (*curnumsrc == 0) {
		LIST_INIT(&head);
	}
}

int
sa_cmp(struct sockaddr *a, struct sockaddr *b)
{
	char *addr_a, *addr_b;
	int i, size, diff;

	/* assumes a and b are in the same address family */
	if (a == NULL || b == NULL || a->sa_family != b->sa_family) {
		printf("sa_cmp: improper pair of sockaddrs is given\n");
		return 0;
	}

	/* extract address part from sockaddr */
	switch (a->sa_family) {
	case AF_INET:
		addr_a = (char *) &(((struct sockaddr_in *) a)->sin_addr);
		addr_b = (char *) &(((struct sockaddr_in *) b)->sin_addr);
		size = sizeof(((struct sockaddr_in *) a)->sin_addr);
		break;
	case AF_INET6:
		addr_a = (char *) &(((struct sockaddr_in6 *) a)->sin6_addr);
		addr_b = (char *) &(((struct sockaddr_in6 *) b)->sin6_addr);
		size = sizeof(((struct sockaddr_in6 *) a)->sin6_addr);
		break;
	default:
		/* unsupported */
		printf("ss_cmp: unsupported sockaddr is given\n");
		return 0;
	}

	diff = 0;
	/* compare each byte in these addresses */
	for (i = 0; i < size; i++) {
		unsigned char byte_a = *addr_a++;
		unsigned char byte_b = *addr_b++;
		diff = byte_a - byte_b;
		if (diff != 0)
			return diff;
	}
	/* 
	 * if everything is same, check sin6_scope_id 
	 * (IPv6 link-local only; other scope handling it a ToDo task)
	 */
	if (a->sa_family == AF_INET6 &&
	    IN6_IS_SCOPE_LINKLOCAL(&((struct sockaddr_in6 *) a)->sin6_addr)) {
		int scope_a = ((struct sockaddr_in6 *) a)->sin6_scope_id;
		int scope_b = ((struct sockaddr_in6 *) b)->sin6_scope_id;

		return scope_a - scope_b;
	}

	/* everything is completely same */
	return 0;
}

/*
 * check if the given IP address matches with the MSF (per-interface
 * source filter). return 1/0 if matches/not matches, respectively.
 */
int
match_msf4_per_if(inm, src, dst)
	struct in_multi *inm;
	struct in_addr *src;
	struct in_addr *dst;
{
	struct in_multi_source *inms;
	struct in_addr_source *ias;

	inms = inm->inm_source;
	/* inms is NULL only in case of 224.0.0.0/24 */
	if (inms == NULL) {
		/* assumes 224.0.0.1 case has already been eliminated */
		if (!is_igmp_target(&dst))
			return 1;
		igmplog((LOG_DEBUG, "grp found, but src is NULL. impossible\n"));
		return 0;
	}
	if (inms->ims_grpjoin > 0)
		return 1;

	if (inms->ims_cur == NULL || inms->ims_cur->head == NULL)
		return 0;

	LIST_FOREACH(ias, inms->ims_cur->head, ias_list) {
		if (ias->ias_addr.sin_family != AF_INET)
			continue;
		if (ias->ias_addr.sin_addr.s_addr != src->s_addr)
			continue;

		if (inms->ims_mode == MCAST_INCLUDE)
			return 1;
		else
			return 0;
	}
	
	/* no source-filter matched */
	if (inms->ims_mode == MCAST_INCLUDE)
		return 0;
	return 1;
}

/*
 * check if the given IP address matches with the MSF (per-socket
 * source filter).  return 1/0 if matches/not matches, respectively.
 */
int
match_msf4_per_socket(inp, src, dst)
	struct inpcb *inp;
	struct in_addr *src;
	struct in_addr *dst;
{
	int i;
	struct sock_msf *msf;
	struct ip_moptions *imo;
	struct sock_msf_source *msfsrc;
	
	/*
	 * Broadcast data should be accepted; this function assumes that 
	 * dst is not a normal unicast address.
	 */
#if defined(__NetBSD__) || defined(__OpenBSD__)
	if (!IN_MULTICAST(dst->s_addr))
#else
	if (!IN_MULTICAST(ntohl(dst->s_addr)))
#endif
		return 1;
		
	if ((imo = inp->inp_moptions) == NULL)
		return 0;
	for (i = 0; i < imo->imo_num_memberships; i++) {
		if (imo->imo_membership[i]->inm_addr.s_addr != dst->s_addr)
			continue;
		
		msf = imo->imo_msf[i];
		if (msf == NULL)
			continue;

		/* receive data from any source */
		if (msf->msf_grpjoin != 0 && msf->msf_blknumsrc == 0)
			return 1;

		/* 1. search allow-list */
		if (msf->msf_numsrc == 0)
			goto search_block_list;
		
		LIST_FOREACH(msfsrc, msf->msf_head, list) {
			if (msfsrc->src.ss_family != AF_INET)
				continue;
			if (SIN_ADDR(&msfsrc->src) == src->s_addr)
				return 1;
		}
		
		/* 2. search_block_list */
	search_block_list:
		if (msf->msf_blknumsrc == 0)
			goto end_of_search;
		LIST_FOREACH(msfsrc, msf->msf_blkhead, list) {
			if (msfsrc->src.ss_family != AF_INET)
				continue;
			if (SIN_ADDR(&msfsrc->src) == src->s_addr)
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
#ifdef IGMPV3_DEBUG
static void
print_in_addr_slist(struct in_addr_slist *ias, char *heading)
{
	struct in_addr_source *tmp;

	if (ias == NULL) {
		printf("\t\t%s(none)\n", heading);
		return;
	}
	printf("\t\t%s(%d)\n", heading, ias->numsrc);

	LIST_FOREACH(tmp, ias->head, ias_list) {
		struct in_addr dummy = tmp->ias_addr.sin_addr;
		printf("\t\tsrc %s (ref=%d)\n",
		    inet_ntoa(dummy), tmp->ias_refcount);
	}
}

void
dump_in_multisrc(void)
{
	int s = splnet();
	struct ifnet *ifp;

	for (ifp = TAILQ_FIRST(&ifnet); ifp; ifp = TAILQ_NEXT(ifp, if_list)) {
		struct ifmultiaddr *ifma;
		struct in_multi *inm = NULL;
		struct in_multi_source *ims = NULL;

		printf("interface %s\n", ifp->if_name);
		LIST_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr == NULL) {
				printf("\tEnd of Group\n");
				continue;
			}
			printf("\tAF=%d\n", ifma->ifma_addr->sa_family);
			if (ifma->ifma_addr->sa_family != AF_INET) {
				continue;
			}
			printf("\tgroup %s (ref=%d)\n",
			    inet_ntoa(SIN(ifma->ifma_addr)->sin_addr),
			    ifma->ifma_refcount);

			inm = (struct in_multi *) ifma->ifma_protospec;
			if (inm == NULL) {
				printf("\tno in_multi\n");
				continue;
			}
			printf("\ttimer=%d, state=%d\n", inm->inm_timer, inm->inm_state);
			ims = inm->inm_source;
			if (ims == NULL) {
				printf("\t\tno in_source_list\n");
				continue;
			}
			printf("\t\tmode=%d, grpjoin=%d\n", ims->ims_mode, ims->ims_grpjoin);
			print_in_addr_slist(ims->ims_cur, "cur");
			print_in_addr_slist(ims->ims_rec, "rec");
			print_in_addr_slist(ims->ims_in, "in");
			print_in_addr_slist(ims->ims_ex, "ex");
			print_in_addr_slist(ims->ims_alw, "allow");
			print_in_addr_slist(ims->ims_blk, "block");
			print_in_addr_slist(ims->ims_toin, "toinc");
			print_in_addr_slist(ims->ims_toex, "toexc");
		}
	}
	splx(s);
}
#endif /* IGMPV3_DEBUG */
#endif /* FreeBSD */
#endif /* IGMPV3 or MLDV2 */
