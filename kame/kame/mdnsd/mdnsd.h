#define MDNS_PORT	"53"
#define MDNS_GROUP6	"ff02::1"

extern const char *dnsserv;
extern const char *intface;
extern int insock;
extern int af;
extern const char *hostname;

/* mdnsd.c */
extern int ismyaddr __P((const struct sockaddr *));

/* mainloop.c */
extern void mainloop __P((void));
