/*	$KAME: if_nameindex.h,v 1.2 2001/08/16 07:43:13 itojun Exp $	*/

#ifndef _IF_NAMEINDEX_H_
#define _IF_NAMEINDEX_H_

#if !defined(INET6) && !defined(__OpenBSD__) && !defined(HAVE_IF_NAMEINDEX)

struct if_nameindex {
  unsigned int   if_index;  /* 1, 2, ... */
  char          *if_name;   /* null terminated name: "le0", ... */
};

struct if_nameindex *if_nameindex(void);
void if_freenameindex(struct if_nameindex *);

#endif

#endif /* _IF_NAMEINDEX_H_ */
