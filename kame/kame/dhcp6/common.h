extern int dump;
extern int debug;
#define dprintf(x)	{ if (debug) fprintf x; }
extern char *device;

#if 0
#define PCAP_TIMEOUT	100	/*ms*/

/* client.c */
void poll_register __P((void (*)()));
void callback_register __P((int, pcap_t *, void (*)()));

/* client4.c */
void client4_init __P((void));
#endif
