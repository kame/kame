--- ipv6cp.c	2002/06/03 06:37:11	1.1.1.1
+++ ipv6cp.c	2002/06/10 11:51:48	1.4
@@ -34,12 +34,15 @@
 #include <net/route.h>
 #include <sys/select.h>
 #include <net/if.h>
+#include <net/if_types.h>
+#include <net/if_dl.h>
 #include <sys/un.h>
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <termios.h>
+#include <ifaddrs.h>
 
 #include "layer.h"
 #include "defs.h"
@@ -106,17 +109,87 @@
   fsm_NullRecvResetAck
 };
 
-static u_int32_t
-GenerateToken(void)
+static void
+SetInterfaceID(u_char *ifid, int userandom)
 {
-  /* Generate random number which will be used as negotiation token */
-  randinit();
+  struct ifaddrs *ifa, *ifap = NULL;
+  struct sockaddr_dl *sdl;
+  const u_long i32_max = 0xffffffff;
+  u_long r1, r2;
+
+  /* configure an interface ID based on Section 4.1 of RFC 2472 */
+  memset(ifid, 0, IPV6CP_IFIDLEN);
+
+  /*
+   * 1) If an IEEE global identifier (EUI-48 or EUI-64) is
+   * available anywhere on the node, it should be used to construct
+   * the tentative Interface-Identifier due to its uniqueness
+   * properties.
+   */
+  if (userandom)
+    goto randomid;
+  if (getifaddrs(&ifap) < 0)
+    goto randomid;
+	
+  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
+    char *cp;
+
+    if (ifa->ifa_addr->sa_family != AF_LINK)
+      continue;
+
+    sdl = (struct sockaddr_dl *)ifa->ifa_addr;
+    if (sdl->sdl_alen < 6)
+      continue;
+    /* we're only interested in IEEE hardware addresses */
+    switch(sdl->sdl_type) {
+    case IFT_ETHER:
+    case IFT_FDDI:
+      /* XXX need more cases? */
+      break;
+    default:
+      continue;
+    }
+
+    cp = (char *)(sdl->sdl_data + sdl->sdl_nlen);
+    ifid[0] = cp[0];
+    ifid[0] ^= 0x02; /* reverse the u/l bit*/
+    ifid[1] = cp[1];
+    ifid[2] = cp[2];
+    ifid[3] = 0xff;
+    ifid[4] = 0xfe;
+    ifid[5] = cp[3];
+    ifid[6] = cp[4];
+    ifid[7] = cp[5];
+
+    freeifaddrs(ifap);
+    return;
+  }
+
+  freeifaddrs(ifap);
 
-  return random() + 1;
+  /*
+   * 2) If an IEEE global identifier is not available a different source
+   * of uniqueness should be used.
+   * XXX: we skip this case.
+   */
+
+  /*
+   * 3) If a good source of uniqueness cannot be found, it is
+   * recommended that a random number be generated.  In this case the
+   * "u" bit of the interface identifier MUST be set to zero (0).
+   */
+ randomid:
+  randinit();
+  r1 = (((u_long)random()) % i32_max) + 1;
+  r2 = (((u_long)random()) % i32_max) + 1;
+  memcpy(ifid, &r1, sizeof(r1));
+  memcpy(ifid + 4, &r2, sizeof(r2));
+  ifid[0] &= 0xfd;
+  return;
 }
 
 static int
-ipcp_SetIPv6address(struct ipv6cp *ipv6cp, u_int32_t mytok, u_int32_t histok)
+ipcp_SetIPv6address(struct ipv6cp *ipv6cp, u_char *myifid, u_char *hisifid)
 {
   struct bundle *bundle = ipv6cp->fsm.bundle;
   struct in6_addr myaddr, hisaddr;
@@ -133,11 +206,17 @@
 
   myaddr.s6_addr[0] = 0xfe;
   myaddr.s6_addr[1] = 0x80;
-  *(u_int32_t *)(myaddr.s6_addr + 12) = htonl(mytok);
+  memcpy(&myaddr.s6_addr[8], myifid, IPV6CP_IFIDLEN);
+#if 0
+  myaddr.s6_addr[8] |= 0x02;	/* set 'universal' bit */
+#endif
 
   hisaddr.s6_addr[0] = 0xfe;
   hisaddr.s6_addr[1] = 0x80;
-  *(u_int32_t *)(hisaddr.s6_addr + 12) = htonl(histok);
+  memcpy(&hisaddr.s6_addr[8], hisifid, IPV6CP_IFIDLEN);
+#if 0
+  hisaddr.s6_addr[8] |= 0x02;	/* set 'universal' bit */
+#endif
 
   ncpaddr_setip6(&ipv6cp->myaddr, &myaddr);
   ncpaddr_setip6(&ipv6cp->hisaddr, &hisaddr);
@@ -187,17 +266,20 @@
   ipv6cp->cfg.fsm.maxreq = DEF_FSMTRIES;
   ipv6cp->cfg.fsm.maxtrm = DEF_FSMTRIES;
 
-  ipv6cp->my_token = GenerateToken();
-  while ((ipv6cp->peer_token = GenerateToken()) == ipv6cp->my_token)
-    ;
+  SetInterfaceID(ipv6cp->my_ifid, 0);
+  do {
+    SetInterfaceID(ipv6cp->his_ifid, 1);
+  } while (memcmp(ipv6cp->his_ifid, ipv6cp->my_ifid, IPV6CP_IFIDLEN) == 0);
 
   if (probe.ipv6_available) {
     n = 100;
     while (n &&
-           !ipcp_SetIPv6address(ipv6cp, ipv6cp->my_token, ipv6cp->peer_token)) {
-      n--;
-      while (n && (ipv6cp->my_token = GenerateToken()) == ipv6cp->peer_token)
-        n--;
+           !ipcp_SetIPv6address(ipv6cp, ipv6cp->my_ifid, ipv6cp->his_ifid)) {
+      do {
+	n--;
+    	SetInterfaceID(ipv6cp->my_ifid, 1);
+      } while (n
+	&& memcmp(ipv6cp->his_ifid, ipv6cp->my_ifid, IPV6CP_IFIDLEN) == 0);
     }
   }
 
@@ -296,7 +378,7 @@
 int
 ipv6cp_InterfaceUp(struct ipv6cp *ipv6cp)
 {
-  if (!ipcp_SetIPv6address(ipv6cp, ipv6cp->my_token, ipv6cp->peer_token)) {
+  if (!ipcp_SetIPv6address(ipv6cp, ipv6cp->my_ifid, ipv6cp->his_ifid)) {
     log_Printf(LogERROR, "ipv6cp_InterfaceUp: unable to set ipv6 address\n");
     return 0;
   }
@@ -458,14 +540,14 @@
   /* Send config REQ please */
   struct physical *p = link2physical(fp->link);
   struct ipv6cp *ipv6cp = fsm2ipv6cp(fp);
-  u_char buff[6];
+  u_char buff[IPV6CP_IFIDLEN+2];
   struct fsm_opt *o;
 
   o = (struct fsm_opt *)buff;
 
   if ((p && !physical_IsSync(p)) || !REJECTED(ipv6cp, TY_TOKEN)) {
-    memcpy(o->data, &ipv6cp->my_token, 4);
-    INC_FSM_OPT(TY_TOKEN, 6, o);
+    memcpy(o->data, ipv6cp->my_ifid, IPV6CP_IFIDLEN);
+    INC_FSM_OPT(TY_TOKEN, IPV6CP_IFIDLEN + 2, o);
   }
 
   fsm_Output(fp, CODE_CONFIGREQ, fp->reqid, buff, (u_char *)o - buff,
@@ -488,7 +570,7 @@
 static const char *
 protoname(int proto)
 {
-  static const char *cftypes[] = { "TOKEN", "COMPPROTO" };
+  static const char *cftypes[] = { "IFACEID", "COMPPROTO" };
 
   if (proto > 0 && proto <= sizeof cftypes / sizeof *cftypes)
     return cftypes[proto - 1];
@@ -497,18 +579,22 @@
 }
 
 static void
-ipv6cp_ValidateToken(struct ipv6cp *ipv6cp, u_int32_t token,
-                     struct fsm_decode *dec)
+ipv6cp_ValidateInterfaceID(struct ipv6cp *ipv6cp, u_char *ifid,
+			   struct fsm_decode *dec)
 {
   struct fsm_opt opt;
+  u_char zero[IPV6CP_IFIDLEN];
 
-  if (token != 0 && token != ipv6cp->my_token)
-    ipv6cp->peer_token = token;
+  memset(zero, 0, IPV6CP_IFIDLEN);
 
+  if (memcmp(ifid, zero, IPV6CP_IFIDLEN) != 0
+      && memcmp(ifid, ipv6cp->my_ifid, IPV6CP_IFIDLEN) != 0)
+    memcpy(ipv6cp->his_ifid, ifid, IPV6CP_IFIDLEN);
+
   opt.hdr.id = TY_TOKEN;
-  opt.hdr.len = 6;
-  memcpy(opt.data, &ipv6cp->peer_token, 4);
-  if (token == ipv6cp->peer_token)
+  opt.hdr.len = IPV6CP_IFIDLEN + 2;
+  memcpy(opt.data, &ipv6cp->his_ifid, IPV6CP_IFIDLEN);
+  if (memcmp(ifid, ipv6cp->his_ifid, IPV6CP_IFIDLEN) == 0)
     fsm_ack(dec, &opt);
   else
     fsm_nak(dec, &opt);
@@ -522,9 +608,11 @@
   struct ipv6cp *ipv6cp = fsm2ipv6cp(fp);
   int n;
   char tbuff[100];
-  u_int32_t token;
+  u_char ifid[IPV6CP_IFIDLEN], zero[IPV6CP_IFIDLEN];
   struct fsm_opt *opt;
 
+  memset(zero, 0, IPV6CP_IFIDLEN);
+
   while (end - cp >= sizeof(opt->hdr)) {
     if ((opt = fsm_readopt(&cp)) == NULL)
       break;
@@ -534,40 +622,51 @@
 
     switch (opt->hdr.id) {
     case TY_TOKEN:
-      memcpy(&token, opt->data, 4);
-      log_Printf(LogIPV6CP, "%s 0x%08lx\n", tbuff, (unsigned long)token);
+      memcpy(ifid, opt->data, IPV6CP_IFIDLEN);
+      log_Printf(LogIPV6CP, "%s 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", tbuff,
+		 ifid[0], ifid[1], ifid[2], ifid[3], ifid[4], ifid[5], ifid[6], ifid[7]);
 
       switch (mode_type) {
       case MODE_REQ:
         ipv6cp->peer_tokenreq = 1;
-        ipv6cp_ValidateToken(ipv6cp, token, dec);
+        ipv6cp_ValidateInterfaceID(ipv6cp, ifid, dec);
         break;
 
       case MODE_NAK:
-        if (token == 0) {
+        if (memcmp(ifid, zero, IPV6CP_IFIDLEN) == 0) {
           log_Printf(log_IsKept(LogIPV6CP) ? LogIPV6CP : LogPHASE,
-                     "0x00000000: Unacceptable token!\n");
+		     "0x0000000000000000: Unacceptable IntefaceID!\n");
           fsm_Close(&ipv6cp->fsm);
-        } else if (token == ipv6cp->peer_token)
+        } else if (memcmp(ifid, ipv6cp->his_ifid, IPV6CP_IFIDLEN) == 0) {
           log_Printf(log_IsKept(LogIPV6CP) ? LogIPV6CP : LogPHASE,
-                    "0x%08lx: Unacceptable token!\n", (unsigned long)token);
-        else if (token != ipv6cp->my_token) {
+		     "0x%02x%02x%02x%02x%02x%02x%02x%02x: "
+		     "Unacceptable IntefaceID!\n",
+		     ifid[0], ifid[1], ifid[2], ifid[3],
+		     ifid[4], ifid[5], ifid[6], ifid[7]);
+        } else if (memcmp(ifid, ipv6cp->my_ifid, IPV6CP_IFIDLEN) != 0) {
           n = 100;
-          while (n && !ipcp_SetIPv6address(ipv6cp, token, ipv6cp->peer_token)) {
-            n--;
-            while (n && (token = GenerateToken()) == ipv6cp->peer_token)
-              n--;
-          }
+	  while (n && !ipcp_SetIPv6address(ipv6cp, ifid, ipv6cp->his_ifid)) {
+	    do {
+	      n--;
+	      SetInterfaceID(ifid, 1);
+	    } while (n && memcmp(ifid, ipv6cp->his_ifid, IPV6CP_IFIDLEN) == 0);
+	  }
 
           if (n == 0) {
             log_Printf(log_IsKept(LogIPV6CP) ? LogIPV6CP : LogPHASE,
-                       "0x00000000: Unacceptable token!\n");
+                       "0x0000000000000000: Unacceptable IntefaceID!\n");
             fsm_Close(&ipv6cp->fsm);
           } else {
-            log_Printf(LogIPV6CP, "%s changing token: 0x%08lx --> 0x%08lx\n",
-                       tbuff, (unsigned long)ipv6cp->my_token,
-                       (unsigned long)token);
-            ipv6cp->my_token = token;
+	    log_Printf(LogIPV6CP, "%s changing IntefaceID: "
+		       "0x%02x%02x%02x%02x%02x%02x%02x%02x "
+		       "--> 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", tbuff,
+		       ipv6cp->my_ifid[0], ipv6cp->my_ifid[1],
+		       ipv6cp->my_ifid[2], ipv6cp->my_ifid[3],
+		       ipv6cp->my_ifid[4], ipv6cp->my_ifid[5],
+		       ipv6cp->my_ifid[6], ipv6cp->my_ifid[7],
+		       ifid[0], ifid[1], ifid[2], ifid[3],
+		       ifid[4], ifid[5], ifid[6], ifid[7]);
+            memcpy(ipv6cp->my_ifid, ifid, IPV6CP_IFIDLEN);
             bundle_AdjustFilters(fp->bundle, &ipv6cp->myaddr, NULL);
           }
         }
@@ -600,7 +699,8 @@
          */
         ipv6cp->peer_tokenreq = 1;
       }
-      ipv6cp_ValidateToken(ipv6cp, 0, dec);
+      memset(ifid, 0, IPV6CP_IFIDLEN);
+      ipv6cp_ValidateInterfaceID(ipv6cp, ifid, dec);
     }
     fsm_opt_normalise(dec);
   }
