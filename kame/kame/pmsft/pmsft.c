/*
 * $KAME: pmsft.c,v 1.1 2004/08/09 02:04:36 suz Exp $
 * pmsft - test a IGMPv3/MLDv2 host stack, using protocol independent API
 * based on wilbertdg@hetnet.nl's pmsft, supporting only IGMPv3
 */

#define MAX_ADDRS		500

#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

int s = -1;

/*
 * Prototypes
 */
void process_file(char *);
void process_cmd(char*, FILE *fp);
void usage();
int comp_sas(const void *, const void *);

int
main(int argc, char **argv)
{
	int i;
	char line[BUFSIZ], *p;

	/* Process commands until user wants to quit */
	while (1) {
		printf("pmsft> ");
		if (fgets(line, sizeof(line), stdin) == NULL)
			return 0;

		if (line[0] != 'f') {
			process_cmd(line, stdin);
			continue;
		}

		/* process the given file */
		for (i = 1; isblank(line[i]); i++)
			;
		if ((p = (char*) strchr(line, '\n')) != NULL)
			*p = '\0';
		process_file(&line[i]);
	}
}

/*
 * Process commands from a file
 */
void
process_file(char *fname)
{
	char *lineptr;
	char line[BUFSIZ];
	FILE *fp;

	/* Try to open the file and feed all commands to process_cmd() */
	if ((fp = fopen(fname, "r")) == NULL) {
		errx(1, "fopen");
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		/* Skip comments and empty lines */
		lineptr = line;
		while (isblank(*lineptr)) 
			lineptr++;
		if (*lineptr != '#' && *lineptr != '\n')
			process_cmd(lineptr, fp);
	}
	fclose(fp);
	return;
}

/*
 * Process a line/command
 */
void
process_cmd(char *cmd, FILE *fp)
{
	struct group_req gr;
	struct group_source_req gsr;
	struct group_filter *gfp;
	struct addrinfo hints, *res, *res0;
	int error;
	char buffer[GROUP_FILTER_SIZE(MAX_ADDRS)], *p;
	char str1[NI_MAXHOST], str2[NI_MAXHOST], *line, ifname[IFNAMSIZ];
	int i, n, opt, level;

	/* Skip whitespaces */
	line = cmd + 1;
	while (isblank(*line)) 
		line++;

	switch (*cmd) {
	case '?':
		/* Show usage */
		usage();
		break;

	case 'q':
		/* Quit */
		if (s > 0)
			close(s);
		exit(0);

	case 's':
		/* Wait for some time */
		if (sscanf(line, "%d", &n) != 1) {
			warnx("invalid format");
			break;
		}
		if (n < 1) {
			warnx("invalid value");
			break;
		}
		for (i = 0; i < n; i++)
			sleep(1);
		break;

	case 'j':
	case 'l':
		/* Join or leave a multicast group */
		if (sscanf(line, "%s %s", str1, ifname) != 2) {
			warnx("invalid format"); 
			break;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICHOST;
		error = getaddrinfo(str1, NULL, &hints, &res0);
		if (error) {
			warnx("%s", gai_strerror(error));
			break;
		}
		for (res = res0; res; res = res->ai_next) {
			if (s < 0)
				s = socket(res->ai_family, res->ai_socktype,
					   res->ai_protocol);
			if (s < 0)
				continue;
			break;  /* okay we got one */
		}
		memcpy(&gr.gr_group, res->ai_addr, res->ai_addrlen);
		if ((gr.gr_interface = if_nametoindex(ifname)) == 0) {
			perror("if_nametoindex");
			break;
		}
		opt = (*cmd == 'j') ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP;
		level = gr.gr_group.ss_family == AF_INET6 ? IPPROTO_IPV6 :
			gr.gr_group.ss_family == AF_INET ? IPPROTO_IP : 0;
		if (setsockopt(s, level, opt, &gr, sizeof(gr)) == -1)
			perror("MCAST_JOIN/LEAVE_GROUP");
		freeaddrinfo(res0);
		break;

	case 'i':
	case 'e':
		/* 
		 * Set the socket to include or exclude filter mode, and
		 * add some sources to the filterlist, using the full-state,
		 * or advanced api 
		 */
		if (sscanf(line, "%s %s %d", str1, ifname, &n) != 3) {
			warnx("invalid format");
			break;
		}
		if (n > MAX_ADDRS) {
			warnx("invalid value");
			break;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICHOST;
		error = getaddrinfo(str1, NULL, &hints, &res0);
		if (error) {
			warnx("%s", gai_strerror(error));
			break;
		}
		for (res = res0; res; res = res->ai_next) {
			if (s < 0)
				s = socket(res->ai_family, res->ai_socktype,
					   res->ai_protocol);
			if (s < 0)
				continue;
			break;  /* okay we got one */
		}

		/* Prepare argument */
		gfp = (struct group_filter*) buffer;
		memcpy(&gfp->gf_group, res->ai_addr, res->ai_addrlen);
		gfp->gf_fmode = (*cmd == 'i') ? MCAST_INCLUDE : MCAST_EXCLUDE;
		if ((gfp->gf_interface = if_nametoindex(ifname)) == 0) {
			perror("if_nametoindex");
			break;
		}
		gfp->gf_numsrc = n;
		freeaddrinfo(res0);

		for (i = 0; i < n; i++) {
			fgets(str1, sizeof(str1), fp);
			if ((p = (char*) strchr(str1, '\n')) != NULL)
				*p = '\0';

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_flags = AI_NUMERICHOST;
			error = getaddrinfo(str1, NULL, &hints, &res0);
			if (error) {
				warnx("%s", gai_strerror(error));
				break;
			}
			for (res = res0; res; res = res->ai_next) {
				break;  /* okay we got one */
			}
			memcpy(&gfp->gf_slist[i], res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res0);
		}
		/* Execute ioctl() */
		if (ioctl(s, SIOCSMSFILTER, (void*) gfp) != 0) {
			perror("SIOCSMSFILTER");
		}
		break;

	case 't':
	case 'b':
		/* Allow or block traffic from a source, using the delta based api */
		if (sscanf(line, "%s %s %s", str1, ifname, str2) != 3) {
			warnx("invalid format");
			break;
		}
		gfp = (struct group_filter*) buffer;
		if ((gfp->gf_interface = if_nametoindex(ifname)) == 0) {
			perror("if_nametoindex");
			break;
		}
		gfp->gf_numsrc = 0;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICHOST;
		error = getaddrinfo(str1, NULL, &hints, &res0);
		if (error) {
			warnx("%s", gai_strerror(error));
			break;
		}
		for (res = res0; res; res = res->ai_next) {
			if (s < 0)
				s = socket(res->ai_family, res->ai_socktype,
					   res->ai_protocol);
			if (s < 0)
				continue;
			break;  /* okay we got one */
		}
		memcpy(&gfp->gf_group, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res0);

		/* First find out current filter mode */
		if (ioctl(s, SIOCGMSFILTER, gfp) != 0) {
			/* 
			 * It's only okay for 't' to fail, since the operation
			 * MCAST_JOIN_SOURCE_GROUP on a non existing membership
			 * should result in a new membership
			 */
			if (*cmd != 't') {
				perror("SIOCGMSFILTER");
				break;
			}
			gfp->gf_fmode = MCAST_INCLUDE;
		}
		if (gfp->gf_fmode == MCAST_EXCLUDE) {
			/* Any source */
			opt = (*cmd == 't') ? 
				MCAST_UNBLOCK_SOURCE : MCAST_BLOCK_SOURCE;
		} else {
			/* Controlled source */
			opt = (*cmd == 't') ? 
				MCAST_JOIN_SOURCE_GROUP : MCAST_LEAVE_SOURCE_GROUP;
		}

		/* Prepare argument */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICHOST;
		error = getaddrinfo(str2, NULL, &hints, &res0);
		if (error) {
			warnx("%s", gai_strerror(error));
			break;
		}
		for (res = res0; res; res = res->ai_next) {
			break;  /* okay we got one */
		}
		memcpy(&gsr.gsr_source, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res0);

		if ((gsr.gsr_interface = if_nametoindex(ifname)) == 0) {
			perror("if_nametoindex");
			break;
		}
		memcpy(&gsr.gsr_group, &gfp->gf_group, gfp->gf_group.ss_len);

		/* Execute setsockopt() */ 
		level = gsr.gsr_group.ss_family == AF_INET6 ? IPPROTO_IPV6 :
			gsr.gsr_group.ss_family == AF_INET ? IPPROTO_IP : 0;
		if (setsockopt(s, level, opt, &gsr, sizeof(gsr)) == -1)
			perror("setsockopt");	
		break;

	case 'g':
		/* Get and show the current filter mode, and the sources in the list */
		if (sscanf(line, "%s %s %d", str1, ifname, &n) != 3) {
			warnx("invalid format");
			break;
		}

		/* Prepare argument */
		gfp = (struct group_filter*) buffer;
		if ((gfp->gf_interface = if_nametoindex(ifname)) == 0) {
			perror("if_nametoindex");
			break;
		}
		gfp->gf_numsrc = n;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICHOST;
		error = getaddrinfo(str1, NULL, &hints, &res0);
		if (error) {
			warnx("%s", gai_strerror(error));
			break;
		}
		for (res = res0; res; res = res->ai_next) {
			if (s < 0)
				s = socket(res->ai_family, res->ai_socktype,
					   res->ai_protocol);
			if (s < 0)
				continue;
			break;  /* okay we got one */
		}
		memcpy(&gfp->gf_group, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res0);

		/* Execute ioctl() */
		if (ioctl(s, SIOCGMSFILTER, gfp) != 0) {
			perror("SIOCGMSFILTER");
			break;
		}

		printf("%s\n",
		       gfp->gf_fmode == MCAST_INCLUDE ? "include" : "exclude");
		if (n > gfp->gf_numsrc) {
			n = gfp->gf_numsrc;
			qsort(gfp->gf_slist, n,
			      sizeof(struct sockaddr_storage), &comp_sas);
			for (i = 0; i < n; i++) {
				char hbuf[NI_MAXHOST];
				struct sockaddr *sa;
				
				sa = (struct sockaddr *)&gfp->gf_slist[i];

				error = getnameinfo(sa, sa->sa_len,
						    hbuf, sizeof(hbuf),
						    NULL, 0, NI_NUMERICHOST);
				if (error) {
					warnx("%s", gai_strerror(error));
					continue;
				}
				printf("%s\n", hbuf);
			}
		}
		break;

	case '\n':
	default:
		break;
	}
}

/*
 * Print usage information
 */
void usage()
{
	printf("j group-addr ifname          "
		"- join IP multicast group\n");
	printf("l group-addr ifname          "
		"- leave IP multicast group\n");
	printf("i group-addr ifname n        "
		"- set n include mode src filters "
		"(followed by n lines of src-addrs)\n");
	printf("e group-addr ifname n        "
		"- set n exclude mode src filters "
		"(followed by n lines of src-addrs)\n");
	printf("t group-addr ifname src-addr "
		"- allow traffic from src\n");
	printf("b group-addr ifname src-addr "
		"- block traffic from src\n");
	printf("g group-addr ifname n        "
		"- get and show (max n) src filters\n");
	printf("f filename                   "
		"- read command(s) from file\n");
	printf("s seconds                    "
		"- sleep for some time\n");
	printf("q                            "
		"- quit\n");
}

int 
comp_sas(const void *a, const void *b)
{
	struct sockaddr *sa, *sb;
	char ha[NI_MAXHOST], hb[NI_MAXHOST];
	sa = (struct sockaddr *) a;
	sb = (struct sockaddr *) b;

	getnameinfo(sa, sa->sa_len, ha, sizeof(ha), NULL, 0, NI_NUMERICHOST);
	getnameinfo(sb, sb->sa_len, hb, sizeof(hb), NULL, 0, NI_NUMERICHOST);
	return strncmp(ha, hb, sizeof(ha));
}
