--- ppp/ipv6cp.c.orig	Tue Feb 26 14:42:35 2002
+++ ppp/ipv6cp.c	Tue Feb 26 16:14:15 2002
@@ -123,6 +123,7 @@
   struct ncprange myrange;
   struct sockaddr_storage ssdst, ssgw, ssmask;
   struct sockaddr *sadst, *sagw, *samask;
+  u_int16_t linkid;
 
   sadst = (struct sockaddr *)&ssdst;
   sagw = (struct sockaddr *)&ssgw;
@@ -133,10 +134,14 @@
 
   myaddr.s6_addr[0] = 0xfe;
   myaddr.s6_addr[1] = 0x80;
+  /* XXX: embed link scope ID to disambiguate the zone. */
+  linkid = htons(bundle->iface->index);
+  memcpy(&myaddr.s6_addr[2], &linkid, sizeof(linkid));
   *(u_int32_t *)(myaddr.s6_addr + 12) = htonl(mytok);
 
   hisaddr.s6_addr[0] = 0xfe;
   hisaddr.s6_addr[1] = 0x80;
+  memcpy(&hisaddr.s6_addr[2], &linkid, sizeof(linkid));
   *(u_int32_t *)(hisaddr.s6_addr + 12) = htonl(histok);
 
   ncpaddr_setip6(&ipv6cp->myaddr, &myaddr);
@@ -381,7 +386,15 @@
   log_Printf(LogIPV6CP, "myaddr %s hisaddr = %s\n",
              tbuff, ncpaddr_ntoa(&ipv6cp->hisaddr));
 
-  /* XXX: Call radius_Account() and system_Select() */
+  /* XXX: Call radius_Account() */
+  if (system_Select(fp->bundle, tbuff, LINKUPFILE, NULL, NULL) < 0) {
+    if (bundle_GetLabel(fp->bundle)) {
+      if (system_Select(fp->bundle, bundle_GetLabel(fp->bundle),
+                       LINKUPFILE, NULL, NULL) < 0)
+        system_Select(fp->bundle, "MYADDR6", LINKUPFILE, NULL, NULL);
+    } else
+      system_Select(fp->bundle, "MYADDR6", LINKUPFILE, NULL, NULL);
+  }
 
   fp->more.reqs = fp->more.naks = fp->more.rejs = ipv6cp->cfg.fsm.maxreq * 3;
   log_DisplayPrompts();
@@ -401,7 +414,16 @@
     snprintf(addr, sizeof addr, "%s", ncpaddr_ntoa(&ipv6cp->myaddr));
     log_Printf(LogIPV6CP, "%s: LayerDown: %s\n", fp->link->name, addr);
 
-    /* XXX: Call radius_Account() and system_Select() */
+    /* XXX: Call radius_Account() */
+
+    if (system_Select(fp->bundle, addr, LINKDOWNFILE, NULL, NULL) < 0) {
+      if (bundle_GetLabel(fp->bundle)) {
+         if (system_Select(fp->bundle, bundle_GetLabel(fp->bundle),
+                          LINKDOWNFILE, NULL, NULL) < 0)
+         system_Select(fp->bundle, "MYADDR6", LINKDOWNFILE, NULL, NULL);
+      } else
+        system_Select(fp->bundle, "MYADDR6", LINKDOWNFILE, NULL, NULL);
+    }
 
     ipv6cp_Setup(ipv6cp);
   }
