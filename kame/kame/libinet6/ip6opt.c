/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <string.h>
#include <stdio.h>

static int ip6optlen(u_int8_t *opt, u_int8_t *lim);
static void inet6_insert_padopt(u_char *p, int len);

/*
 * This function returns the number of bytes required to hold an option
 * when it is stored as ancillary data, including the cmsghdr structure
 * at the beginning, and any padding at the end (to make its size a
 * multiple of 8 bytes).  The argument is the size of the structure
 * defining the option, which must include any pad bytes at the
 * beginning (the value y in the alignment term "xn + y"), the type
 * byte, the length byte, and the option data.
 */
int
inet6_option_space(nbytes)
	int nbytes;
{
	nbytes += 2;	/* we need space for nxt-hdr and length fields */
	return(CMSG_SPACE((nbytes + 7) & ~7));
}

/*
 * This function is called once per ancillary data object that will
 * contain either Hop-by-Hop or Destination options.  It returns 0 on
 * success or -1 on an error.
 */
int
inet6_option_init(bp, cmsgp, type)
	void *bp;
	struct cmsghdr **cmsgp;
	int type;
{
	register struct cmsghdr *ch = (struct cmsghdr *)bp;

	/* argument validation */
	if (type != IPV6_HOPOPTS && type != IPV6_DSTOPTS)
		return(-1);
	
	ch->cmsg_level = IPPROTO_IPV6;
	ch->cmsg_type = type;
	ch->cmsg_len = CMSG_LEN(0);

	*cmsgp = ch;
	return(0);
}

/*
 * This function appends a Hop-by-Hop option or a Destination option
 * into an ancillary data object that has been initialized by
 * inet6_option_init().  This function returns 0 if it succeeds or -1 on
 * an error.
 * multx is the value x in the alignment term "xn + y" described
 * earlier.  It must have a value of 1, 2, 4, or 8.
 * plusy is the value y in the alignment term "xn + y" described
 * earlier.  It must have a value between 0 and 7, inclusive.
 */
int
inet6_option_append(cmsg, typep, multx, plusy)
	struct cmsghdr *cmsg;
	const u_int8_t *typep;
	int multx;
	int plusy;
{
	int padlen, optlen, off;
	register u_char *bp = (u_char *)cmsg + cmsg->cmsg_len;
	struct ip6_ext *eh = (struct ip6_ext *)CMSG_DATA(cmsg);

	/* argument validation */
	if (multx != 1 && multx != 2 && multx != 4 && multx != 8)
		return(-1);
	if (plusy < 0 || plusy > 7)
		return(-1);
	if (typep[0] > 255)
		return(-1);

	/*
	 * If this is the first option, allocate space for the
	 * first 2 bytes(for next header and length fields) of
	 * the option header.
	 */
	if (bp == (u_char *)eh) {
		bp += 2;
		cmsg->cmsg_len += 2;
	}

	/* calculate pad length before the option. */
	off = bp - (u_char *)eh;
	padlen = (((off % multx) + (multx - 1)) & ~(multx - 1)) -
		(off % multx);
	padlen += plusy;
	padlen %= multx;	/* keep the pad as short as possible */
	/* insert padding */
	inet6_insert_padopt(bp, padlen);
	cmsg->cmsg_len += padlen;
	bp += padlen;

	/* copy the option */
	if (typep[0] == IP6OPT_PAD1)
		optlen = 1;
	else
		optlen = typep[1] + 2;
	memcpy(bp, typep, optlen);
	bp += optlen;
	cmsg->cmsg_len += optlen;

	/* calculate pad length after the option and insert the padding */
	off = bp - (u_char *)eh;
	padlen = ((off + 7) & ~7) - off;
	inet6_insert_padopt(bp, padlen);
	bp += padlen;
	cmsg->cmsg_len += padlen;

	/* update the length field of the ip6 option header */
	eh->ip6e_len = ((bp - (u_char *)eh) >> 3) - 1;

	return(0);
}

/*
 * This function appends a Hop-by-Hop option or a Destination option
 * into an ancillary data object that has been initialized by
 * inet6_option_init().  This function returns a pointer to the 8-bit
 * option type field that starts the option on success, or NULL on an
 * error.
 * The difference between this function and inet6_option_append() is
 * that the latter copies the contents of a previously built option into
 * the ancillary data object while the current function returns a
 * pointer to the space in the data object where the option's TLV must
 * then be built by the caller.
 * 
 */
u_int8_t *
inet6_option_alloc(cmsg, datalen, multx, plusy)
	struct cmsghdr *cmsg;
	int datalen;
	int multx;
	int plusy;
{
	int padlen, off;
	register u_int8_t *bp = (u_char *)cmsg + cmsg->cmsg_len;
	u_int8_t *retval;
	struct ip6_ext *eh = (struct ip6_ext *)CMSG_DATA(cmsg);

	/* argument validation */
	if (multx != 1 && multx != 2 && multx != 4 && multx != 8)
		return(NULL);
	if (plusy < 0 || plusy > 7)
		return(NULL);

	/*
	 * If this is the first option, allocate space for the
	 * first 2 bytes(for next header and length fields) of
	 * the option header.
	 */
	if (bp == (u_char *)eh) {
		bp += 2;
		cmsg->cmsg_len += 2;
	}

	/* calculate pad length before the option. */
	off = bp - (u_char *)eh;
	padlen = (((off % multx) + (multx - 1)) & ~(multx - 1)) -
		(off % multx);
	padlen += plusy;
	padlen %= multx;	/* keep the pad as short as possible */
	/* insert padding */
	inet6_insert_padopt(bp, padlen);
	cmsg->cmsg_len += padlen;
	bp += padlen;

	/* keep space to store specified length of data */
	retval = bp;
	bp += datalen;
	cmsg->cmsg_len += datalen;

	/* calculate pad length after the option and insert the padding */
	off = bp - (u_char *)eh;
	padlen = ((off + 7) & ~7) - off;
	inet6_insert_padopt(bp, padlen);
	bp += padlen;
	cmsg->cmsg_len += padlen;

	/* update the length field of the ip6 option header */
	eh->ip6e_len = ((bp - (u_char *)eh) >> 3) - 1;

	return(retval);
}

/*
 * This function processes the next Hop-by-Hop option or Destination
 * option in an ancillary data object.  If another option remains to be
 * processed, the return value of the function is 0 and *tptrp points to
 * the 8-bit option type field (which is followed by the 8-bit option
 * data length, followed by the option data).  If no more options remain
 * to be processed, the return value is -1 and *tptrp is NULL.  If an
 * error occurs, the return value is -1 and *tptrp is not NULL.
 * (RFC 2292, 6.3.5)
 */
int
inet6_option_next(cmsg, tptrp)
	const struct cmsghdr *cmsg;
	u_int8_t **tptrp;
{
	struct ip6_ext *ip6e;
	int hdrlen, optlen;
	u_int8_t *lim;

	if (cmsg->cmsg_level != IPPROTO_IPV6 ||
	    (cmsg->cmsg_type != IPV6_HOPOPTS &&
	     cmsg->cmsg_type != IPV6_DSTOPTS))
		return(-1);

	/* message length validation */
	if (cmsg->cmsg_len < CMSG_SPACE(sizeof(struct ip6_ext)))
		return(-1);
	ip6e = (struct ip6_ext *)CMSG_DATA(cmsg);
	hdrlen = (ip6e->ip6e_len + 1) << 3;
	if (cmsg->cmsg_len < CMSG_SPACE(hdrlen))
		return(-1);

	/*
	 * If the caller does not specify the starting point,
	 * simply return the 1st option.
	 * Otherwise, search the option list for the next option.
	 */
	lim = (u_int8_t *)ip6e + hdrlen;
	if (*tptrp == NULL)
		*tptrp = (u_int8_t *)(ip6e + 1);
	else {
		if ((optlen = ip6optlen(*tptrp, lim)) == 0)
			return(-1);

		*tptrp = *tptrp + optlen;
	}
	if (*tptrp >= lim) {	/* there is no option */
		*tptrp = NULL;
		return(-1);
	}
	/*
	 * Finally, checks if the next option is safely stored in the
	 * cmsg data.
	 */
	if (ip6optlen(*tptrp, lim) == 0)
		return(-1);
	else
		return(0);
}

/*
 * This function is similar to the inet6_option_next() function,
 * except this function lets the caller specify the option type to be
 * searched for, instead of always returning the next option in the
 * ancillary data object.
 * Note: RFC 2292 says the type of tptrp is u_int8_t *, but we think
 *       it's a typo. The variable should be type of u_int8_t **.
 */
int
inet6_option_find(cmsg, tptrp, type)
	const struct cmsghdr *cmsg;
	u_int8_t **tptrp;
	int type;
{
	struct ip6_ext *ip6e;
	int hdrlen, optlen;
	u_int8_t *optp, *lim;

	if (cmsg->cmsg_level != IPPROTO_IPV6 ||
	    (cmsg->cmsg_type != IPV6_HOPOPTS &&
	     cmsg->cmsg_type != IPV6_DSTOPTS))
		return(-1);

	/* message length validation */
	if (cmsg->cmsg_len < CMSG_SPACE(sizeof(struct ip6_ext)))
		return(-1);
	ip6e = (struct ip6_ext *)CMSG_DATA(cmsg);
	hdrlen = (ip6e->ip6e_len + 1) << 3;
	if (cmsg->cmsg_len < CMSG_SPACE(hdrlen))
		return(-1);	

	/*
	 * If the caller does not specify the starting point,
	 * search from the beginning of the option list.
	 * Otherwise, search from *the next option* of the specified point.
	 */
	lim = (u_int8_t *)ip6e + hdrlen;
	if (*tptrp == NULL)
		*tptrp = (u_int8_t *)(ip6e + 1);
	else {
		if ((optlen = ip6optlen(*tptrp, lim)) == 0)
			return(-1);

		*tptrp = *tptrp + optlen;
	}
	for (optp = *tptrp; optp < lim; optp += optlen) {
		if (*optp == type) {
			*tptrp = optp;
			return(0);
		}
		if ((optlen = ip6optlen(optp, lim)) == 0)
			return(-1);
	}

	/* search failed */
	*tptrp = NULL;
	return(-1);
}

/*
 * Calculate the length of a given IPv6 option. Also checks
 * if the option is safely stored in user's buffer according to the
 * calculated length and the limitation of the buffer.
 */
static int
ip6optlen(opt, lim)
	u_int8_t *opt, *lim;
{
	int optlen;

	if (*opt == IP6OPT_PAD1)
		optlen = 1;
	else {
		/* is there enough space to store type and len? */
		if (opt + 2 > lim)
			return(0);
		optlen = *(opt + 1) + 2;
	}
	if (opt + optlen <= lim)
		return(optlen);

	return(0);
}

static void
inet6_insert_padopt(u_char *p, int len)
{
	switch(len) {
	 case 0:
		 return;
	 case 1:
		 p[0] = IP6OPT_PAD1;
		 return;
	 default:
		 p[0] = IP6OPT_PADN;
		 p[1] = len - 2; 
		 memset(&p[2], 0, len - 2);
		 return;
	}
}

/*
 * The following functions are defined in a successor of RFC2292, aka
 * rfc2292bis.
 */

/*
 * This function parses received IPv6 options headers returning the next
 * option.  Extbuf and extlen specifies the options header.  Prevlen
 * should either be zero (for the first option) or the length returned
 * by a previous call to inet6_opt_next() or inet6_opt_find().  It
 * specifies the position where to continue scanning the extension
 * buffer.  The next option is returned by updating typep, lenp, and
 * databufp.  This function returns the updated "previous" length
 * computed by advancing past the option that was returned.  This
 * returned "previous" length can then be passed to subsequent calls to
 * inet6_opt_next().  This function does not return any PAD1 or PADN
 * options.  When there are no more options the return value is -1.
 *
 * [rfc2292bis-01, 10.5]
 */
int
inet6_opt_next(void *extbuf, size_t extlen, int prevlen, u_int8_t *typep,
	       size_t *lenp, void **databufp)
{
	u_int8_t *optp, *lim;
	int optlen;

	/* Validate extlen. XXX: is the variable really necessary?? */
	if (extlen == 0 || (extlen % 8))
		return(-1);
	lim = (u_int8_t *)extbuf + extlen;

	/*
	 * If this is the first time this function called for this options
	 * header, simply return the 1st option.
	 * Otherwise, search the option list for the next option.
	 */
	if (prevlen == 0) {
		optp = (u_int8_t *)((struct ip6_hbh *)extbuf + 1);
	}
	else {
		optp = (u_int8_t *)extbuf + prevlen;
		if ((optlen = ip6optlen(optp, lim)) == 0)
			goto optend;
		optp += optlen;
	}

	/* Find the next option skipping any padding options. */
	while(optp < lim) {
		switch(*optp) {
		case IP6OPT_PAD1:
			optp++;
			break;
		case IP6OPT_PADN:
			if ((optlen = ip6optlen(optp, lim)) == 0)
				goto optend;
			optp += optlen;
			break;
		default:	/* found */
			if ((optlen = ip6optlen(optp, lim)) == 0)
				goto optend;
			*typep = *optp;
			*lenp = optlen;
			*databufp = optp + 2;
			return(optp - (u_int8_t *)extbuf);
		}
	}

  optend:
	*databufp = NULL; /* for safety */
	return(-1);
}

/*
 * This function is similar to the inet6_opt_next() function, except
 * this function lets the caller specify the option type to be searched for,
 * instead of always returning the next option in the extension header.
 *
 * If an option of the specified type is located, the function returns
 * the updated "previous" total length computed by advancing past the
 * option that was returned and past any options that didn't match the
 * type.  This returned "previous" length can then be passed to
 * subsequent calls to inet6_opt_find() for finding the next occurance
 * of the same option type.
 *
 * If an option of the specified type is not located, the return value
 * is -1.  If an error occurs, the return value is -1.
 *
 * [rfc2292bis-01, 10.6]
 */
int
inet6_opt_find(void *extbuf, size_t extlen, int prevlen, u_int8_t type,
	       size_t *lenp, void **databufp)
{
	u_int8_t *optp, *lim;
	int optlen;

	/* Validate extlen. XXX: is the variable really necessary?? */
	if (extlen == 0 || (extlen % 8))
		return(-1);
	lim = (u_int8_t *)extbuf + extlen;

	/*
	 * If this is the first time this function called for this options
	 * header, simply return the 1st option.
	 * Otherwise, search the option list for the next option.
	 */
	if (prevlen == 0) {
		optp = (u_int8_t *)((struct ip6_hbh *)extbuf + 1);
	}
	else {
		optp = (u_int8_t *)extbuf + prevlen;
		if ((optlen = ip6optlen(optp, lim)) == 0)
			goto optend;
		optp += optlen;
	}

	/* Find the specified option */
	while(optp < lim) {
		if ((optlen = ip6optlen(optp, lim)) == 0)
			goto optend;

		if (*optp == type) { /* found */
			*lenp = optlen;
			*databufp = optp + 2;
			return(optp - (u_int8_t *)extbuf);
		}

		optp += optlen;
	}

  optend:
	*databufp = NULL; /* for safety */
	return(-1);
}

/*
 * Databuf should be a pointer returned by inet6_opt_next() or
 * inet6_opt_find().  This function extracts data items of various sizes
 * (1, 2, 4, or 8 bytes) in the data portion of the option. Val should
 * point to the destination for the extracted data.  Offset specifies
 * from where in the data portion of the option the value should be
 * extracted; the first byte after the option type and length is
 * accessed by specifying an offset of zero.
 * 
 * The function returns the offset for the next field (i.e., offset +
 * vallen) which can be used when extracting option content with
 * multiple fields.
 *
 * [rfc2292bis-01, 10.7]
 */
int
inet6_opt_get_val(void *databuf, size_t offset, void *val, int vallen)
{
	/* we can't assume alignment here */
	memcpy(val, databuf + offset, vallen);

	return(offset + vallen);
}
