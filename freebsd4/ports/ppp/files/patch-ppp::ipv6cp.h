--- ppp/ipv6cp.h.orig	Tue Aug 14 17:05:51 2001
+++ ppp/ipv6cp.h	Tue Feb 26 16:23:48 2002
@@ -32,6 +32,8 @@
 #define	TY_TOKEN	1
 #define	TY_COMPPROTO	2
 
+#define	IPV6CP_IFIDLEN	8		/* RFC2472 */
+
 struct ipv6cp {
   struct fsm fsm;			/* The finite state machine */
 
@@ -41,8 +43,8 @@
 
   unsigned peer_tokenreq : 1;		/* Any TY_TOKEN REQs from the peer ? */
 
-  u_int32_t my_token;			/* Token I'm willing to use */
-  u_int32_t peer_token;			/* Token he's willing to use */
+  u_char my_ifid[IPV6CP_IFIDLEN];	/* Local Interface Identifier */
+  u_char his_ifid[IPV6CP_IFIDLEN];	/* Peer Interface Identifier */
 
   struct ncpaddr myaddr;		/* Local address */
   struct ncpaddr hisaddr;		/* Peer address */
