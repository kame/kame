#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

struct addrinfo ai;

char host[1024];
char serv[1024];

int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct addrinfo *res;
	int error, i;
	char *p, *q;

	if (argc != 3){
		fprintf(stderr, "error: argc\n");
		exit(1);
	}

	ai.ai_flags |= AI_CANONNAME;
	ai.ai_family = PF_UNSPEC;
	ai.ai_socktype = SOCK_STREAM;
		
	p = *argv[1] ? argv[1] : NULL;
	q = *argv[2] ? argv[2] : NULL;
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
				    NI_NUMERICHOST);
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
