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

#define DEBUGHIGH (babyinfo.debug >= DEBUG_HIGH) 
#define DEBUGNORM (babyinfo.debug >= DEBUG_NORMAL)
#define DEBUGNONE (babyinfo.debug == DEBUG_NONE)

struct mdd_info {
	int debug;
	int linkpoll;
	int dns;
	int nondaemon;

	int rtsock;
	int mipsock;
	int linksock;

	int whereami;
#define IAMHOME    1
#define IAMFOREIGN 2

	struct if_info *coaif;
	LIST_HEAD(, if_info) ifinfo_head;

	u_int16_t hoa_index;
	LIST_HEAD(, hoa_info) hoainfo_head;

};

struct hoa_info {
	LIST_ENTRY(hoa_info) hoainfo_entry;

	struct sockaddr_storage hoa;/* HoA */
};


struct if_info {
	LIST_ENTRY(if_info) ifinfo_entry;
	char ifname[IFNAMSIZ];
	u_int16_t ifindex;

	struct sockaddr_storage coa;/* Current CoA */
	struct sockaddr_storage pcoa;/* Previous CoA */

	time_t lastsent;

	int priority;
	int linkstatus;
};
