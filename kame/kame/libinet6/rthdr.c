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

size_t
inet6_rthdr_space(type, seg)
    int type, seg;
{
    switch(type) {
     case IPV6_RTHDR_TYPE_0:
	 if (seg < 1 || seg > 23)
	     return(0);
#ifdef COMPAT_RFC2292
	 return(CMSG_SPACE(sizeof(struct in6_addr) * (seg - 1)
			   + sizeof(struct ip6_rthdr0)));
#else
	 return(CMSG_SPACE(sizeof(struct in6_addr) * seg
			   + sizeof(struct ip6_rthdr0)));
#endif 
     default:
#ifdef DEBUG
	 fprintf(stderr, "inet6_rthdr_space: unknown type(%d)\n", type);
#endif 
	 return(0);
    }
}

struct cmsghdr *
inet6_rthdr_init(bp, type)
    void *bp;
    int type;
{
    register struct cmsghdr *ch = (struct cmsghdr *)bp;
    register struct ip6_rthdr *rthdr = (struct ip6_rthdr *)(ch + 1);

    ch->cmsg_level = IPPROTO_IPV6;
    ch->cmsg_type = IPV6_RTHDR;

    switch(type) {
     case IPV6_RTHDR_TYPE_0:
#ifdef COMPAT_RFC2292
	 ch->cmsg_len = CMSG_LEN(sizeof(struct ip6_rthdr0) - sizeof(struct in6_addr));
#else
	 ch->cmsg_len = CMSG_LEN(sizeof(struct ip6_rthdr0));
#endif 

	 bzero(rthdr, sizeof(struct ip6_rthdr0));
	 rthdr->ip6r_type = IPV6_RTHDR_TYPE_0;
	 return(ch);
     default:
#ifdef DEBUG
	 fprintf(stderr, "inet6_rthdr_init: unknown type(%d)\n", type);
#endif 
	 return(NULL);
    }
}

/* ARGSUSED */
int
inet6_rthdr_add(cmsg, addr, flags)
    struct cmsghdr *cmsg;
    const struct in6_addr *addr;
    u_int flags;
{
    register struct ip6_rthdr *rthdr = (struct ip6_rthdr *)(cmsg + 1);

    switch(rthdr->ip6r_type) {
     case IPV6_RTHDR_TYPE_0:
     {
	 struct ip6_rthdr0 *rt0 = (struct ip6_rthdr0 *)rthdr;
	 if (flags != IPV6_RTHDR_LOOSE && flags != IPV6_RTHDR_STRICT) {
#ifdef DEBUG
	     fprintf(stderr, "inet6_rthdr_add: unsupported flag(%d)\n", flags);
#endif 
	     return(-1);
	 }
	 if (rt0->ip6r0_segleft == 23) {
#ifdef DEBUG
	     fprintf(stderr, "inet6_rthdr_add: segment overflow\n");
#endif 
	     return(-1);
	 }

#ifdef COMPAT_RFC1883		/* XXX */
	 if (flags == IPV6_RTHDR_STRICT) {
	     int c, b;
	     c = rt0->ip6r0_segleft / 8;
	     b = rt0->ip6r0_segleft % 8;
	     rt0->ip6r0_slmap[c] |= (1 << (7 - b));
	 }
#endif 
	 rt0->ip6r0_segleft++;
	 bcopy(addr, (caddr_t)rt0 + ((rt0->ip6r0_len + 1) << 3),
	       sizeof(struct in6_addr));
	 rt0->ip6r0_len += sizeof(struct in6_addr) >> 3;
	 cmsg->cmsg_len = CMSG_LEN((rt0->ip6r0_len + 1) << 3);
	 break;
     }
     default:
#ifdef DEBUG
	 fprintf(stderr, "inet6_rthdr_add: unknown type(%d)\n",
		 rthdr->ip6r_type);
#endif 
	 return(-1);
    }

    return(0);
}

/* ARGSUSED */
int
inet6_rthdr_lasthop(cmsg, flags)
    struct cmsghdr *cmsg;
    unsigned int flags;
{
    register struct ip6_rthdr *rthdr = (struct ip6_rthdr *)(cmsg + 1);

    switch(rthdr->ip6r_type) {
     case IPV6_RTHDR_TYPE_0:
     {
	 struct ip6_rthdr0 *rt0 = (struct ip6_rthdr0 *)rthdr;
#ifdef COMPAT_RFC1883		/* XXX */
	 if (flags != IPV6_RTHDR_LOOSE && flags != IPV6_RTHDR_STRICT) {
#ifdef DEBUG
	     fprintf(stderr, "inet6_rthdr_lasthop: unsupported flag(%d)\n", flags);
#endif 
	     return(-1);
	 }
#endif /* COMPAT_RFC1883 */
	 if (rt0->ip6r0_segleft > 23) {
#ifdef DEBUG
	     fprintf(stderr, "inet6_rthdr_add: segment overflow\n");
#endif 
	     return(-1);
	 }
#ifdef COMPAT_RFC1883		/* XXX */
	 if (flags == IPV6_RTHDR_STRICT) {
	     int c, b;
	     c = rt0->ip6r0_segleft / 8;
	     b = rt0->ip6r0_segleft % 8;
	     rt0->ip6r0_slmap[c] |= (1 << (7 - b));
	 }
#endif /* COMPAT_RFC1883 */
	 break;
     }
     default:
#ifdef DEBUG
	 fprintf(stderr, "inet6_rthdr_lasthop: unknown type(%d)\n",
		 rthdr->ip6r_type);
#endif 
	 return(-1);
    }

    return(0);
}

#if 0
int
inet6_rthdr_reverse(in, out)
    const struct cmsghdr *in;
    struct cmsghdr *out;
{
#ifdef DEBUG
    fprintf(stderr, "inet6_rthdr_reverse: not implemented yet\n");
#endif 
    return -1;
}
#endif

int
inet6_rthdr_segments(cmsg)
    const struct cmsghdr *cmsg;
{
    register struct ip6_rthdr *rthdr = (struct ip6_rthdr *)(cmsg + 1);

    switch(rthdr->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
      {
	struct ip6_rthdr0 *rt0 = (struct ip6_rthdr0 *)rthdr;

	if (rt0->ip6r0_len % 2 || 46 < rt0->ip6r0_len) {
#ifdef DEBUG
	    fprintf(stderr, "inet6_rthdr_segments: invalid size(%d)\n",
		rt0->ip6r0_len);
#endif 
	    return -1;
	}

	return (rt0->ip6r0_len * 8) / sizeof(struct in6_addr);
      }

    default:
#ifdef DEBUG
	fprintf(stderr, "inet6_rthdr_segments: unknown type(%d)\n",
	    rthdr->ip6r_type);
#endif 
	return -1;
    }
}

struct in6_addr *
inet6_rthdr_getaddr(cmsg, index)
    struct cmsghdr *cmsg;
    int index;
{
    register struct ip6_rthdr *rthdr = (struct ip6_rthdr *)(cmsg + 1);

    switch(rthdr->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
      {
	struct ip6_rthdr0 *rt0 = (struct ip6_rthdr0 *)rthdr;
	int naddr;

	if (rt0->ip6r0_len % 2 || 46 < rt0->ip6r0_len) {
#ifdef DEBUG
	    fprintf(stderr, "inet6_rthdr_getaddr: invalid size(%d)\n",
		rt0->ip6r0_len);
#endif 
	    return NULL;
	}
	naddr = (rt0->ip6r0_len * 8) / sizeof(struct in6_addr);
	if (index <= 0 || naddr < index) {
#ifdef DEBUG
	    fprintf(stderr, "inet6_rthdr_getaddr: invalid index(%d)\n", index);
#endif 
	    return NULL;
	}
	return(((struct in6_addr *)(rt0 + 1)) + index - 1);
      }

    default:
#ifdef DEBUG
	fprintf(stderr, "inet6_rthdr_getaddr: unknown type(%d)\n",
	    rthdr->ip6r_type);
#endif 
	return NULL;
    }
}

int
inet6_rthdr_getflags(cmsg, index)
    const struct cmsghdr *cmsg;
    int index;
{
    register struct ip6_rthdr *rthdr = (struct ip6_rthdr *)(cmsg + 1);

    switch(rthdr->ip6r_type) {
    case IPV6_RTHDR_TYPE_0:
      {
	struct ip6_rthdr0 *rt0 = (struct ip6_rthdr0 *)rthdr;
	int naddr;

	if (rt0->ip6r0_len % 2 || 46 < rt0->ip6r0_len) {
#ifdef DEBUG
	    fprintf(stderr, "inet6_rthdr_getflags: invalid size(%d)\n",
		rt0->ip6r0_len);
#endif 
	    return -1;
	}
	naddr = (rt0->ip6r0_len * 8) / sizeof(struct in6_addr);
	if (index < 0 || naddr < index) {
#ifdef DEBUG
	    fprintf(stderr, "inet6_rthdr_getflags: invalid index(%d)\n", index);
#endif 
	    return -1;
	}
#ifdef COMPAT_RFC1883		/* XXX */
	if (rt0->ip6r0_slmap[index / 8] & (0x80 >> (index % 8)))
	    return IPV6_RTHDR_STRICT;
	else
	    return IPV6_RTHDR_LOOSE;
#else
	return IPV6_RTHDR_LOOSE;
#endif /* COMPAT_RFC1883 */
      }

    default:
#ifdef DEBUG
	fprintf(stderr, "inet6_rthdr_getflags: unknown type(%d)\n",
	    rthdr->ip6r_type);
#endif 
	return -1;
    }
}

/*
 * The following functions are defined in a successor of RFC2292, aka
 * rfc2292bis.
 */

/*
 * This function returns the number of bytes required to hold a Routing
 * header of the specified type containing the specified number of
 * segments (addresses).
 * If the return value is 0, then either the type of the Routing header
 * is not supported by this implementation or the number of segments is
 * invalid for this type of Routing header.
 */
size_t
inet6_rth_space(int type, int segments)
{
	switch(type) {
	case IPV6_RTHDR_TYPE_0:
		return(((segments * 2) + 1) << 3);
	default:
		return(0);	/* type not suppported */
	}
}

/*
 * This function initializes the buffer pointed to by bp to contain a
 * Routing header of the specified type and sets ip6r_len based on the
 * segments parameter. bp_len is only used to verify that the buffer is
 * large enough.  The ip6r_segleft field is set to zero;
 * inet6_rth_add() will increment it.
 * Upon success the return value is the pointer to the buffer (bp), and
 * this is then used as the first argument to inet6_rth_add() function.
 * Upon an error the return value is NULL.
 */
void *
inet6_rth_init(void *bp, int bp_len, int type, int segments)
{
	struct ip6_rthdr *rth = (struct ip6_rthdr *)bp;
	struct ip6_rthdr0 *rth0;

	switch(type) {
	case IPV6_RTHDR_TYPE_0:
		/* length validation */
		if (bp_len < inet6_rth_space(IPV6_RTHDR_TYPE_0, segments))
			return(NULL);

		memset(bp, 0, bp_len);
		rth0 = (struct ip6_rthdr0 *)rth;
		rth0->ip6r0_len = segments * 2;
		rth0->ip6r0_type = IPV6_RTHDR_TYPE_0;
		rth0->ip6r0_segleft = 0;
		rth0->ip6r0_reserved = 0;
		break;
	default:
		return(NULL);	/* type not supported */
	}

	return(bp);
}

/*
 * This function adds the IPv6 address pointed to by addr to the end of
 * the Routing header being constructed.
 * If successful, the segleft member of the Routing Header is updated to
 * account for the new address in the Routing header and the return
 * value of the function is 0.  Upon an error the return value of the
 * function is -1.
 */
int
inet6_rth_add(void *bp, const struct in6_addr *addr)
{
	struct ip6_rthdr *rth = (struct ip6_rthdr *)bp;
	struct ip6_rthdr0 *rth0;
	struct in6_addr *nextaddr;

	switch(rth->ip6r_type) {
	case IPV6_RTHDR_TYPE_0:
		rth0 = (struct ip6_rthdr0 *)rth;
		nextaddr = (struct in6_addr *)(rth0 + 1) + rth0->ip6r0_segleft;
		*nextaddr = *addr;
		rth0->ip6r0_segleft++;
		break;
	default:
		return(-1);	/* type not supported */
	}

	return(0);
}

/*
 * This function takes a Routing header extension header (pointed to by
 * the first argument) and writes a new Routing header that sends
 * datagrams along the reverse of that route.  Both arguments are
 * allowed to point to the same buffer (that is, the reversal can occur
 * in place).
 * The return value of the function is 0 on success, or -1 upon an
 * error.
 */
int
inet6_rth_reverse(const void *in, void *out)
{
	struct ip6_rthdr *rth_in = (struct ip6_rthdr *)in;
	struct ip6_rthdr0 *rth0_in, *rth0_out;
	int i, segments;

	switch(rth_in->ip6r_type) {
	case IPV6_RTHDR_TYPE_0:
		rth0_in = (struct ip6_rthdr0 *)in;
		rth0_out = (struct ip6_rthdr0 *)out;

		/* parameter validation XXX too paranoid? */
		if (rth0_in->ip6r0_len % 2)
			return(-1);
		segments = rth0_in->ip6r0_len / 2;

		/* we can't use memcpy here, since in and out may overlap */
		memmove((void *)rth0_out, (void *)rth0_in,
			((rth0_in->ip6r0_len) + 1) << 3);
		rth0_out->ip6r0_segleft = segments;

		/* reverse the addresses */
		for (i = 0; i < segments / 2; i++) {
			struct in6_addr addr_tmp, *addr1, *addr2;

			addr1 = (struct in6_addr *)(rth0_out + 1) + i;
			addr2 = (struct in6_addr *)(rth0_out + 1) +
				(segments - i - 1);
			addr_tmp = *addr1;
			*addr1 = *addr2;
			*addr2 = addr_tmp;
		}
		
		break;
	default:
		return(-1);	/* type not supported */
	}

	return(0);
}

/*
 * This function returns the number of segments (addresses) contained in
 * the Routing header described by bp.  On success the return value is
 * zero or greater.  The return value of the function is -1 upon an
 * error.
 */
int
inet6_rth_segments(const void *bp)
{
	struct ip6_rthdr *rh = (struct ip6_rthdr *)bp;
	struct ip6_rthdr0 *rh0;
	int addrs;

	switch(rh->ip6r_type) {
	case IPV6_RTHDR_TYPE_0:
		rh0 = (struct ip6_rthdr0 *)bp;

		/*
		 * Validation for a type-0 routing header.
		 * Is this too strict?
		 */
		if ((rh0->ip6r0_len % 2) != 0 ||
		    (addrs = (rh0->ip6r0_len >> 1)) < rh0->ip6r0_segleft)
			return(-1);

		return(addrs);
	default:
		return(-1);	/* unknown type */
	}
}

/*
 * This function returns a pointer to the IPv6 address specified by
 * index (which must have a value between 0 and one less than the value
 * returned by inet6_rth_segments()) in the Routing header described by
 * bp. An application should first call inet6_rth_segments() to obtain
 * the number of segments in the Routing header.
 *
 * Upon an error the return value of the function is NULL.
 */
struct in6_addr *
inet6_rth_getaddr(const void *bp, int index)
{
	struct ip6_rthdr *rh = (struct ip6_rthdr *)bp;
	struct ip6_rthdr0 *rh0;
	int rthlen, addrs;

	switch(rh->ip6r_type) {
	case IPV6_RTHDR_TYPE_0:
		 rh0 = (struct ip6_rthdr0 *)bp;
		 rthlen = (rh0->ip6r0_len + 1) << 3;
		 
		/*
		 * Validation for a type-0 routing header.
		 * Is this too strict?
		 */
		if ((rthlen % 2) != 0 ||
		    (addrs = (rthlen >> 1)) < rh0->ip6r0_segleft)
			return(NULL);

		if (index < 0 || addrs <= index)
			return(NULL);

		return(((struct in6_addr *)(rh0 + 1)) + index);
	default:
		return(NULL);	/* unknown type */
		break;
	}
}
