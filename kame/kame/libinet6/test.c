#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

struct addrinfo ai;

char host[NI_MAXHOST];
char serv[NI_MAXSERV];

static void
usage()
{
	fprintf(stderr, "usage: test [-DpS46] host serv\n");
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct addrinfo *res;
	int error, i;
	char *p, *q;
	extern int optind;
	int c;

	memset(&ai, 0, sizeof(ai));
	ai.ai_family = PF_UNSPEC;
	ai.ai_flags |= AI_CANONNAME;
	while ((c = getopt(argc, argv, "DpS46")) != EOF) {
		switch (c) {
		case 'D':
			ai.ai_socktype = SOCK_DGRAM;
			break;
		case 'p':
			ai.ai_flags |= AI_PASSIVE;
			break;
		case 'S':
			ai.ai_socktype = SOCK_STREAM;
			break;
		case '4':
			ai.ai_family = PF_INET;
			break;
		case '6':
			ai.ai_family = PF_INET6;
			break;
		default:
			usage();
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2){
		usage();
		exit(1);
	}

	p = *argv[0] ? argv[0] : NULL;
	q = *argv[1] ? argv[1] : NULL;
	error = getaddrinfo(p, q, &ai, &res);
	if (error) {
		printf("%s\n", gai_strerror(error));
		exit(1);
	}

	i = 1;
	do {
		printf("ai%d:\n", i);
		printf("\tfamily %d\n", res->ai_family);
		printf("\tsocktype %d\n", res->ai_socktype);
		printf("\tprotocol %d\n", res->ai_protocol);
		printf("\taddrlen %d\n", res->ai_addrlen);
		if (res->ai_canonname) printf("\t%s\n", res->ai_canonname);
		error = getnameinfo(res->ai_addr, res->ai_addr->sa_len,
				    host, sizeof(host), serv, sizeof(serv),
				    NI_NUMERICHOST | NI_WITHSCOPEID);
		if (error) {
			printf("error %d\n", error);
			exit(1);
		}
		printf("\thost %s\n", host);
		printf("\tserv %s\n", serv);
		i++;
	} while ((res = res->ai_next) != NULL);

	exit(0);
}
