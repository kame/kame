--- src/ftp.c.orig	Thu Sep 10 05:21:36 1998
+++ src/ftp.c	Tue Jun 13 09:33:55 2000
@@ -1192,7 +1192,7 @@
       else if (f->tstamp == -1)
 	logprintf (LOG_NOTQUIET, _("%s: corrupt time-stamp.\n"), u->local);
 
-      if (f->perms && dlthis)
+      if (f->perms && f->type == FT_PLAINFILE && dlthis)
 	chmod (u->local, f->perms);
       else
 	DEBUGP (("Unrecognized permissions for %s.\n", u->local));
