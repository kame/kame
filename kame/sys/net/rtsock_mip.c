/* to be included from net/rtsock.c - ugly but necessary for portability */
/*
 * Mobile IPv6 addition.
 * Send a routing message to all routing socket listeners.
 */
void
rt_mip6msg(cmd, ifp, rt)
	int cmd;
	struct ifnet *ifp;
	register struct rtentry *rt;
{
	struct rt_addrinfo info;
	struct sockaddr *sa = 0;
	struct mbuf *m = 0;
	register struct rt_msghdr *rtm;

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

	route_proto.sp_protocol = sa ? sa->sa_family : 0;
	raw_input(m, &route_proto, &route_src, &route_dst);
}
