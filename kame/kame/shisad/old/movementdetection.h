#define DEFAULT_CONFFILE "./mdd.conf"
#define DEFAULT_POLL 0
#define DEFAULT_DEBUG 0
#define DEFAULT_PRIORITY 0
#define DEFAULT_LINKWIFIHIGH 30
#define DEFAULT_LINKWIFILOW  15
#define DEFAULT_LINKCHECK 10 

#define DEBUG_NONE   0
#define DEBUG_NORMAL 1
#define DEBUG_HIGH   2

#define DEBUGHIGH (mddinfo.debug >= DEBUG_HIGH) 
#define DEBUGNORM (mddinfo.debug >= DEBUG_NORMAL)
#define DEBUGNONE (mddinfo.debug == DEBUG_NONE)

struct mdd_info {
	int debug;
	struct timeval poll;
	int linkpoll;
	int dns;
	int multiplecoa;
	int nondaemon;

	int rtsock;
	int mipsock;
	int linksock;

	int whereami;
#define IAMHOME    1
#define IAMFOREIGN 2
#define IAMV4      3
	struct in6_addr hoa;
	struct if_info *coaif;

	LIST_HEAD(, if_info) ifinfo_head;
};

struct if_info {
	LIST_ENTRY(if_info) ifinfo_entry;
	char ifname[IFNAMSIZ];
	u_int16_t ifindex;

	struct sockaddr_storage coa;/* Current CoA */
	struct sockaddr_storage pcoa;/* Previous CoA */

	time_t lastsent;

	int ipv4;
	int priority;
	u_int16_t bid;
	int linkstatus;
};
