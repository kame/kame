--- ppp/ncpaddr.c.orig	Tue Feb 26 14:42:35 2002
+++ ppp/ncpaddr.c	Tue Feb 26 16:14:15 2002
@@ -175,12 +175,19 @@
 adjust_linklocal(struct sockaddr_in6 *sin6)
 {
     /* XXX: ?????!?!?!!!!!  This is horrible ! */
+#if 0
+    /*
+     * The kernel does not understand sin6_scope_id for routing at this moment.
+     * We should rather keep the embedded ID.
+     * jinmei@kame.net, 20011026
+     */
     if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
         IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr)) {
       sin6->sin6_scope_id =
         ntohs(*(u_short *)&sin6->sin6_addr.s6_addr[2]);
       *(u_short *)&sin6->sin6_addr.s6_addr[2] = 0;
     }
+#endif
 }
 #endif
 
@@ -421,8 +428,13 @@
     sin6.sin6_family = AF_INET6;
     sin6.sin6_addr = addr->ncpaddr_ip6addr;
     adjust_linklocal(&sin6);
+#ifdef NI_WITHSCOPEID
     if (getnameinfo((struct sockaddr *)&sin6, sizeof sin6, res, sizeof(res),
                     NULL, 0, NI_WITHSCOPEID | NI_NUMERICHOST) != 0)
+#else
+    if (getnameinfo((struct sockaddr *)&sin6, sizeof sin6, res, sizeof(res),
+                    NULL, 0, NI_NUMERICHOST) != 0)
+#endif
       break;
 
     return res;
