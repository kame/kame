 /*
  * Figure out if UNIX passwords are permitted for any combination of user
  * name, group member, terminal port, host_name or network:
  *
  * Programmatic interface: skeyaccess(user, port, host, addr)
  *
  * All arguments are null-terminated strings. Specify a null character pointer
  * where information is not available.
  *
  * When no address information is given this code performs the host (internet)
  * address lookup itself. It rejects addresses that appear to belong to
  * someone else.
  *
  * When compiled with -DPERMIT_CONSOLE always permits UNIX passwords with
  * console logins, no matter what the configuration file says.
  *
  * To build a stand-alone test version, compile with -DTEST and run it off an
  * skey.access file in the current directory:
  *
  * Command-line interface: ./skeyaccess user port [host_or_ip_addr]
  *
  * Errors are reported via syslogd.
  *
  * Author: Wietse Venema, Eindhoven University of Technology.
  */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <grp.h>
#include <ctype.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <netdb.h>

#include "pathnames.h"

 /*
  * Token input with one-deep pushback.
  */
static char *prev_token = 0;		/* push-back buffer */
static char *line_pointer = NULL;
static char *first_token();
static int line_number;
static void unget_token();
static char *get_token();
static char *need_token();
static char *need_internet_addr();

 /*
  * Various forms of token matching.
  */
#define match_host_name(l)	match_token((l)->host_name)
#define match_port(l)		match_token((l)->port)
#define match_user(l)		match_token((l)->user)
static int match_internet_addr();
static int match_group();
static int match_token();
static int is_internet_addr();
static struct sockaddr_storage *convert_internet_addr();
static struct sockaddr_storage *lookup_internet_addr();

#define MAX_ADDR	32
#define PERMIT		1
#define DENY		0

#ifndef CONSOLE
#define CONSOLE		"console"
#endif
#ifndef VTY_PREFIX
#define VTY_PREFIX      "ttyv"
#endif

struct login_info {
    char   *host_name;			/* host name */
    struct sockaddr_storage *internet_addr;	/* null terminated list */
    char   *user;			/* user name */
    char   *port;			/* login port */
};

static int _skeyaccess __P(( FILE *, struct login_info * ));

static int
numstr2addr(addr, name)
	struct sockaddr *addr;
	char *name;
{
#ifdef HAVE_GETADDRINFO
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(name, NULL, &hints, &res);
	if (error)
		return error;
	else {
		memcpy(addr, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);
		return 0;
	}
#else
	struct in_addr in;
	struct sockaddr_in *sin;
#ifdef INET6
	struct in6_addr in6;
	struct sockaddr_in6 *sin6;
#endif

	if (inet_pton(AF_INET, name, &in) == 1) {
		sin = (struct sockaddr_in *)addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		memcpy(&sin->sin_addr, &in, sizeof(in));
		return 0;
	}
#ifdef INET6
	if (inet_pton(AF_INET6, name, &in6) == 1) {
		sin6 = (struct sockaddr_in6 *)addr;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_len = sizeof(*sin6);
		memcpy(&sin6->sin6_addr, &in6, sizeof(in6));
		return 0;
	}
#endif
		
	return -1;
#endif
}

static int
addr2str(addr, name, namelen)
	struct sockaddr *addr;
	char *name;
	int namelen;
{
#ifdef HAVE_GETNAMEINFO
	return getnameinfo(addr, addr->sa_len, name, namelen, NULL, 0, 0);
#else
	struct hostent *hp;
	
	switch (addr->sa_family) {
	case AF_INET:
		hp = gethostbyaddr((char *)&((struct sockaddr_in *)addr)->sin_addr,
			sizeof(struct in_addr), AF_INET);
		break;
#ifdef INET6
	case AF_INET6:
		hp = gethostbyaddr((char *)&((struct sockaddr_in6 *)addr)->sin6_addr,
			sizeof(struct in6_addr), AF_INET6);
		break;
#endif
	default:
		hp = NULL;
	}

	if (!hp)
		return -1;
	if (namelen <= 0)
		return -1;
	strncpy(name, hp->h_name, namelen);
	name[namelen - 1] = 0;
	return 0;
#endif
}

#ifdef TEST
static int
addr2numstr(addr, name, namelen)
	struct sockaddr *addr;
	char *name;
	int namelen;
{
#ifdef HAVE_GETNAMEINFO
	return getnameinfo(addr, addr->sa_len, name, namelen, NULL, 0,
			NI_NUMERICHOST);
#else
	switch (addr->sa_family) {
	case AF_INET:
		if (inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr,
				name, namelen) == NULL) {
			return -1;
		} else
			return 0;
#ifdef INET6
	case AF_INET6:
		if (inet_ntop(AF_INET6,
				&((struct sockaddr_in6 *)addr)->sin6_addr,
				name, namelen) == NULL) {
			return -1;
		} else
			return 0;
#endif
	default:
		return 0;
	}
#endif
}
#endif /*TEST*/

/* skeyaccess - find out if UNIX passwords are permitted */

int     skeyaccess(user, port, host, addr)
char   *user;
char   *port;
char   *host;
char   *addr;
{
    FILE   *fp;
    struct login_info login_info;
    int     result;

    /*
     * Assume no restriction on the use of UNIX passwords when the s/key
     * acces table does not exist.
     */
    if ((fp = fopen(_PATH_SKEYACCESS, "r")) == 0) {
#ifdef TEST
	fprintf(stderr, "No file %s, thus no access control\n", _PATH_SKEYACCESS);
#endif
	return (PERMIT);
    }

    /*
     * Bundle up the arguments in a structure so we won't have to drag around
     * boring long argument lists.
     *
     * Look up the host address when only the name is given. We try to reject
     * addresses that belong to someone else.
     */
    login_info.user = user;
    login_info.port = port;

    if (host != 0 && !is_internet_addr(host)) {
	login_info.host_name = host;
    } else {
	login_info.host_name = 0;
    }

    if (addr != 0 && is_internet_addr(addr)) {
	login_info.internet_addr = convert_internet_addr(addr);
    } else if (host != 0) {
	if (is_internet_addr(host)) {
	    login_info.internet_addr = convert_internet_addr(host);
	} else {
	    login_info.internet_addr = lookup_internet_addr(host);
	}
    } else {
	login_info.internet_addr = 0;
    }

    /*
     * Print what we think the user wants us to do.
     */
#ifdef TEST
    printf("port: %s\n", login_info.port);
    printf("user: %s\n", login_info.user);
    printf("host: %s\n", login_info.host_name ? login_info.host_name : "none");
    printf("addr: ");
    if (login_info.internet_addr == 0) {
	printf("none\n");
    } else {
	int     i;
	char hostbuf[MAXHOSTNAMELEN];

	for (i = 0; login_info.internet_addr[i].ss_len; i++) {
	    if (login_info.internet_addr[i].ss_family == 0)
		strcpy(hostbuf, "(see error log)");
	    else {
		addr2numstr((struct sockaddr *)&login_info.internet_addr[i],
			hostbuf, sizeof(hostbuf));
	    }
	    printf("%s%s", hostbuf, 
		   login_info.internet_addr[i + 1].ss_len ? " " : "\n");
	}
    }
#endif
    result = _skeyaccess(fp, &login_info);
    fclose(fp);
    return (result);
}

/* _skeyaccess - find out if UNIX passwords are permitted */

static int _skeyaccess(fp, login_info)
FILE   *fp;
struct login_info *login_info;
{
    char    buf[BUFSIZ];
    char   *tok;
    int     match;
    int     permission=DENY;

#ifdef PERMIT_CONSOLE
    if (login_info->port != 0 &&
	(strcmp(login_info->port, CONSOLE) == 0 ||
	 strncmp(login_info->port, VTY_PREFIX, sizeof(VTY_PREFIX) - 1) == 0
	)
       )
	return (1);
#endif

    /*
     * Scan the s/key access table until we find an entry that matches. If no
     * match is found, assume that UNIX passwords are disallowed.
     */
    match = 0;
    while (match == 0 && (tok = first_token(buf, sizeof(buf), fp))) {
	if (strncasecmp(tok, "permit", 4) == 0) {
	    permission = PERMIT;
	} else if (strncasecmp(tok, "deny", 4) == 0) {
	    permission = DENY;
	} else {
	    syslog(LOG_ERR, "%s: line %d: bad permission: %s",
		   _PATH_SKEYACCESS, line_number, tok);
	    continue;				/* error */
	}

	/*
	 * Process all conditions in this entry until we find one that fails.
	 */
	match = 1;
	while (match != 0 && (tok = get_token())) {
	    if (strcasecmp(tok, "hostname") == 0) {
		match = match_host_name(login_info);
	    } else if (strcasecmp(tok, "port") == 0) {
		match = match_port(login_info);
	    } else if (strcasecmp(tok, "user") == 0) {
		match = match_user(login_info);
	    } else if (strcasecmp(tok, "group") == 0) {
		match = match_group(login_info);
	    } else if (strcasecmp(tok, "internet") == 0) {
		match = match_internet_addr(login_info);
	    } else if (is_internet_addr(tok)) {
		unget_token(tok);
		match = match_internet_addr(login_info);
	    } else {
		syslog(LOG_ERR, "%s: line %d: bad condition: %s",
		       _PATH_SKEYACCESS, line_number, tok);
		match = 0;
	    }
	}
    }
    return (match ? permission : DENY);
}

/* match_internet_addr - match internet network address */

static int match_internet_addr(login_info)
struct login_info *login_info;
{
    char *tok;
    struct sockaddr_storage pattern;
    struct sockaddr_storage mask;
    struct sockaddr_storage *addrp;

    if (login_info->internet_addr == 0)
	return (0);
    if ((tok = get_token()) == 0) {
	syslog(LOG_ERR, "%s: line %d: internet address expected",
	       _PATH_SKEYACCESS, line_number);
	return (0);
    }
    if (strchr(tok, '/')) {
	/* addr/masklen */
	char *a, *p, *q;
	int masklen, max;

	a = strdup(tok);
	p = strchr(a, '/');
	if (!p)
	    return 0;
	*p++ = '\0';
	if (numstr2addr(&pattern, a)) {
	    syslog(LOG_ERR, "%s: line %d: bad internet address: %s",
		   _PATH_SKEYACCESS, line_number, a);
	    return 0;
	}

	for (q = p; q && *q; q++) {
	    if (!isdigit(*q))
		q = NULL;
	}
	if (!q || sscanf(p, "%d", &masklen) != 1) {
	    syslog(LOG_ERR, "%s: line %d: bad mask value: %s",
		   _PATH_SKEYACCESS, line_number, p);
	    return 0;
	}

	memset(&mask, 0, sizeof(mask));
	mask.ss_family = pattern.ss_family;
	mask.ss_len = pattern.ss_len;
	switch (pattern.ss_family) {
	case AF_INET:
	    p = (char *)&((struct sockaddr_in *)&mask)->sin_addr;
	    max = 32;
	    break;
	case AF_INET6:
	    p = (char *)&((struct sockaddr_in6 *)&mask)->sin6_addr;
	    max = 128;
	    break;
	default:
	    return 0;
	}
	if (masklen < 0 || max < masklen) {
	    syslog(LOG_ERR, "%s: line %d: bad mask length: %d (max %d)",
		   _PATH_SKEYACCESS, line_number, masklen, max);
	    return 0;
	}
	memset(p, 0xff, masklen / 8);
	if (masklen % 8)
	    p[masklen / 8] = (0xff00 >> (masklen % 8)) & 0xff;
    } else {
	/* addr mask */
	if (numstr2addr(&pattern, tok)) {
	    syslog(LOG_ERR, "%s: line %d: bad internet address: %s",
		   _PATH_SKEYACCESS, line_number, tok);
	    return 0;
	}

	if ((tok = need_internet_addr()) == 0)
	    return (0);
	if (numstr2addr(&mask, tok))
	    return 0;
	if (pattern.ss_family != mask.ss_family)
	    return 0;
    }

    /*
     * See if any of the addresses matches a pattern in the control file. We
     * have already tried to drop addresses that belong to someone else.
     */

    for (addrp = login_info->internet_addr; addrp->ss_len; addrp++) {
	if (pattern.ss_family != addrp->ss_family)
	    continue;
	switch (addrp->ss_family) {
	case AF_INET:
	  {
	    struct sockaddr_in *sin = (struct sockaddr_in *)addrp;
	    struct in_addr masked;
	    masked = sin->sin_addr;
	    masked.s_addr &= ((struct sockaddr_in *)&mask)->sin_addr.s_addr;
	    if (masked.s_addr == ((struct sockaddr_in *)&pattern)->sin_addr.s_addr)
		return 1;
	    break;
	  }
#ifdef INET6
	case AF_INET6:
	  {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addrp;
	    struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)&mask;
	    struct sockaddr_in6 *pattern6 = (struct sockaddr_in6 *)&pattern;
	    struct in6_addr masked;
	    int i;
	    masked = sin6->sin6_addr;
	    for (i = 0; i < (int)sizeof(struct in6_addr); i++)
		    masked.s6_addr[i] &= mask6->sin6_addr.s6_addr[i];
	    if (IN6_ARE_ADDR_EQUAL(&masked, &pattern6->sin6_addr))
		return 1;
	    break;
	  }
#endif
	default:
	    break;
	}
    }
    return 0;
}

/* match_group - match username against group */

static int match_group(login_info)
struct login_info *login_info;
{
    struct group *group;
    char   *tok;
    char  **memp;

    if ((tok = need_token()) && (group = getgrnam(tok))) {
	for (memp = group->gr_mem; *memp; memp++)
	    if (strcmp(login_info->user, *memp) == 0)
		return (1);
    }
    return (0);					/* XXX endgrent() */
}

/* match_token - get and match token */

static int match_token(str)
char   *str;
{
    char   *tok;

    return (str && (tok = need_token()) && strcasecmp(str, tok) == 0);
}

/* first_token - read line and return first token */

static char *first_token(buf, len, fp)
char   *buf;
int     len;
FILE   *fp;
{
    char   *cp;

    prev_token = 0;
    for (;;) {
	if (fgets(buf, len, fp) == 0)
	    return (0);
	line_number++;
	buf[strcspn(buf, "\r\n#")] = 0;
#ifdef TEST
	if (buf[0])
	    printf("rule: %s\n", buf);
#endif
	line_pointer = buf;
	while ((cp = strsep(&line_pointer, " \t")) != NULL && *cp == '\0')
		;
	if (cp != NULL)
	    return (cp);
    }
}

/* unget_token - push back last token */

static void unget_token(cp)
char   *cp;
{
    prev_token = cp;
}

/* get_token - retrieve next token from buffer */

static char *get_token()
{
    char   *cp;

    if ( (cp = prev_token) ) {
	prev_token = 0;
    } else {
	while ((cp = strsep(&line_pointer, " \t")) != NULL && *cp == '\0')
		;
    }
    return (cp);
}

/* need_token - complain if next token is not available */

static char *need_token()
{
    char   *cp;

    if ((cp = get_token()) == 0)
	syslog(LOG_ERR, "%s: line %d: premature end of rule",
	       _PATH_SKEYACCESS, line_number);
    return (cp);
}

/* need_internet_addr - complain if next token is not an internet address */

static char *need_internet_addr()
{
    char   *cp;

    if ((cp = get_token()) == 0) {
	syslog(LOG_ERR, "%s: line %d: internet address expected",
	       _PATH_SKEYACCESS, line_number);
	return (0);
    } else if (!is_internet_addr(cp)) {
	syslog(LOG_ERR, "%s: line %d: bad internet address: %s",
	       _PATH_SKEYACCESS, line_number, cp);
	return (0);
    } else {
	return (cp);
    }
}

/* is_internet_addr - determine if string is a dotted quad decimal address */

static int is_internet_addr(str)
char   *str;
{
#ifdef HAVE_GETADDRINFO
    struct addrinfo hints, *res;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    error = getaddrinfo(str, NULL, &hints, &res);
    if (error)
	return 0;
    else {
	freeaddrinfo(res);
	return 1;
    }
#else
    struct in_addr in;
#ifdef INET6
    struct in6_addr in6;
#endif

    if (inet_pton(AF_INET, str, &in) == 1)
	return 1;
#ifdef INET6
    if (inet_pton(AF_INET6, str, &in6) == 1)
	return 1;
#endif
    return 0;
#endif
}

/* lookup_internet_addr - look up internet addresses with extreme prejudice */

static struct sockaddr_storage *lookup_internet_addr(host)
char   *host;
{
    static struct sockaddr_storage list[MAX_ADDR + 1];
    char    buf[MAXHOSTNAMELEN + 1];
    int     i;
    char hostbuf[MAXHOSTNAMELEN];
#ifdef HAVE_GETADDRINFO
    struct addrinfo hints, *res, *res0;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST|AI_CANONNAME;
    error = getaddrinfo(host, NULL, &hints, &res0);
    if (error)
	return 0;

    /*
     * Save a copy of the results before gethostbyaddr() clobbers them.
     */
    i = 0;
    for (res = res0; i < MAX_ADDR && res; res = res->ai_next) {
	memcpy((char *)&list[i], res->ai_addr, res->ai_addrlen);
	i++;
    }
    memset(&list[i], 0, sizeof(list[i]));

    if (res0->ai_canonname)
	strncpy(buf, res0->ai_canonname, MAXHOSTNAMELEN);
    else
	buf[0] = '\0';
    freeaddrinfo(res0);
#else
    struct hostent *hp;
    struct sockaddr_in *sin;
#ifdef INET6
    struct sockaddr_in6 *sin6;
#endif
    int j;

    i = 0;
    buf[0] = '\0';

#ifdef INET6
    hp = gethostbyname2(host, AF_INET6);
    for (j = 0; hp && i < MAX_ADDR && hp->h_addr_list[j]; j++) {
	sin6 = (struct sockaddr_in6 *)&list[i];
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);
	memcpy(&sin6->sin6_addr, hp->h_addr_list[j], hp->h_length);
	i++;
    }
    if (hp)
	strncpy(buf, hp->h_name, sizeof(buf));
#endif
    hp = gethostbyname2(host, AF_INET);
    for (j = 0; hp && i < MAX_ADDR && hp->h_addr_list[j]; j++) {
	sin = (struct sockaddr_in *)&list[i];
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	memcpy(&sin->sin_addr, hp->h_addr_list[j], hp->h_length);
	i++;
    }
    if (hp)
	strncpy(buf, hp->h_name, sizeof(buf));
#endif
    buf[MAXHOSTNAMELEN] = 0;	/*for safety*/

    /*
     * Wipe addresses that appear to belong to someone else. We will get
     * false alarms when when the hostname comes from DNS, while its
     * addresses are listed under different names in local databases.
     */
#define NEQ(x,y)	(strcasecmp((x),(y)) != 0)
#define NEQ3(x,y,n)	(strncasecmp((x),(y), (n)) != 0)

    while (--i >= 0) {
	if (addr2str((struct sockaddr *)&list[i], hostbuf, sizeof(hostbuf))) {
	    syslog(LOG_ERR, "some of address not registered for host %s", buf);
	    list[i].ss_family = 0;
	}
	if (NEQ(buf, hostbuf) && NEQ3(buf, "localhost.", 10)) {
	    syslog(LOG_ERR, "address registered for host %s and %s",
		   hostbuf, buf);
	    list[i].ss_family = 0;
	}
    }
    return (list);
}

/* convert_internet_addr - convert string to internet address */

static struct sockaddr_storage *convert_internet_addr(string)
char   *string;
{
    static struct sockaddr_storage list[2];

    if (numstr2addr(&list[0], string)) {
	syslog(LOG_ERR, "invalid hostname %s\n", string);
	exit(1);
    }
    memset(&list[1], 0, sizeof(list[1]));
    return (list);
}

#ifdef TEST

main(argc, argv)
int     argc;
char  **argv;
{
    struct hostent *hp;
    char    host[MAXHOSTNAMELEN + 1];
    int     verdict;
    char   *user;
    char   *port;

    if (argc != 3 && argc != 4) {
	fprintf(stderr, "usage: %s user port [host_or_ip_address]\n", argv[0]);
	exit(0);
    }
    if (_PATH_SKEYACCESS[0] != '/')
	printf("Warning: this program uses control file: %s\n", _PATH_SKEYACCESS);
    openlog("login", LOG_PID, LOG_AUTH);

    user = argv[1];
    port = argv[2];
    if (argv[3]) {
	strncpy(host, (hp = gethostbyname(argv[3])) ?
		hp->h_name : argv[3], MAXHOSTNAMELEN);
	host[MAXHOSTNAMELEN] = 0;
    }
    verdict = skeyaccess(user, port, argv[3] ? host : (char *) 0, (char *) 0);
    printf("UNIX passwords %spermitted\n", verdict ? "" : "NOT ");
    return (0);
}

#endif
