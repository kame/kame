/*	$KAME: rtsock_mip.c,v 1.6 2001/01/23 17:19:19 itojun Exp $	*/

/* to be included from net/rtsock.c - ugly but necessary for portability */
/*
 * Mobile IPv6 addition.
 * Send a routing message to all routing socket listeners.
 */
void
rt_mip6msg(cmd, ifp, rt)
	int cmd;
	struct ifnet *ifp;
	struct rtentry *rt;
{
	struct rt_addrinfo info;
	struct sockaddr *sa = 0;
	struct mbuf *m = 0;
#ifdef __NetBSD__
	struct rt_msghdr rtm;
#else
	struct rt_msghdr *rtm;
#endif

#ifdef MIP6_DEBUG
	printf("route_cb.any_count = %d\n", route_cb.any_count);
#endif
	bzero((caddr_t)&info, sizeof(info));

	if (rt == 0 || ifp == 0)
		return;
	netmask = rt_mask(rt);
	dst = sa = rt_key(rt);
	gate = rt->rt_gateway;
	genmask = rt->rt_genmask;
#ifdef __NetBSD__
	bzero(&rtm, sizeof(rtm));
	rtm.rtm_index = ifp->if_index;
	rtm.rtm_flags |= rt->rt_flags;
	rtm.rtm_rmx = rt->rt_rmx;
	rtm.rtm_addrs = info.rti_addrs;
	rtm.rtm_flags |= RTF_DONE;
	if ((m = rt_msg1(cmd, &info, (caddr_t)&rtm, sizeof(rtm))) == NULL) {
#ifdef MIP6_DEBUG
		printf("failure... \n");
#endif
		return;
	}
#else
	if ((m = rt_msg1(cmd, &info)) == NULL) {
#ifdef MIP6_DEBUG
		printf("failure... \n");
#endif
		return;
	}
	rtm = mtod(m, struct rt_msghdr *);
	rtm->rtm_index = ifp->if_index;
	rtm->rtm_flags |= rt->rt_flags;
	rtm->rtm_rmx = rt->rt_rmx;
	rtm->rtm_addrs = info.rti_addrs;
	rtm->rtm_flags |= RTF_DONE;
#endif

	route_proto.sp_protocol = sa ? sa->sa_family : 0;
#ifdef __bsdi__
	raw_input(m, NULL, &route_proto, &route_src, &route_dst);
#else
	raw_input(m, &route_proto, &route_src, &route_dst);
#endif
}
