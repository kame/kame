#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <netinet/in.h>

int main __P((int, char **));
static void usage __P((void));
static struct addrinfo *getres __P((int, const char *, const char *));
static const char *printres __P((struct addrinfo *));
static int test __P((const char *, struct addrinfo *, struct addrinfo *));

static struct addrinfo *wild4, *wild6;
static struct addrinfo *specific4, *specific6;
static char *port = NULL;

int
main(argc, argv)
	int argc;
	char **argv;
{
	int ch;
	extern int optind;
	extern char *optarg;

	while ((ch = getopt(argc, argv, "p:")) != EOF) {
		switch (ch) {
		case 'p':
			port = strdup(optarg);
			break;
		default:
			usage();
			exit(1);
		}
	}

#if 0
	if (port == NULL)
		port = allocport();
#endif

	if (port == NULL) {
		errx(1, "no port specified");
		/*NOTREACHED*/
	}

	wild4 = getres(AF_INET, NULL, port);
	wild6 = getres(AF_INET6, NULL, port);
	specific4 = getres(AF_INET, "127.0.0.1", port);
	specific6 = getres(AF_INET6, "::1", port);

#define TESTIT(x, y)	test(#x " then " #y, (x), (y));
	TESTIT(wild4, wild6);
	TESTIT(wild6, wild4);

	exit(0);
}

static void
usage()
{
	fprintf(stderr, "usage: bindtest -p port\n");
}

static struct addrinfo *
getres(af, host, port)
	int af;
	const char *host;
	const char *port;
{
	struct addrinfo hints, *res;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(host, port, &hints, &res);
	return res;
}

static const char *
printres(res)
	struct addrinfo *res;
{
	char hbuf[MAXHOSTNAMELEN], pbuf[10];
	static char buf[sizeof(hbuf) + sizeof(pbuf)];

	getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf),
		pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV);
	snprintf(buf, sizeof(buf), "%s/%s", hbuf, pbuf);
	return buf;
}

static int
test(title, a, b)
	const char *title;
	struct addrinfo *a;
	struct addrinfo *b;
{
	int sa = -1, sb = -1;

	fprintf(stderr, "%s\n", title);

	fprintf(stderr, "\tallocating socket for %s\n", printres(a));
	sa = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (sa < 0) {
		fprintf(stderr, "\tfailed socket for %s, %s\n",
			printres(a), strerror(errno));
		goto fail;
	}
	fprintf(stderr, "\tallocating socket for %s\n", printres(b));
	sb = socket(b->ai_family, b->ai_socktype, b->ai_protocol);
	if (sb < 0) {
		fprintf(stderr, "\tfailed socket for %s, %s\n",
			printres(b), strerror(errno));
		goto fail;
	}

	fprintf(stderr, "\tbind socket for %s\n", printres(a));
	if (bind(sa, a->ai_addr, a->ai_addrlen) < 0) {
		fprintf(stderr, "\tfailed bind for %s, %s\n",
			printres(a), strerror(errno));
		goto fail;
	}

	fprintf(stderr, "\tbind socket for %s\n", printres(b));
	if (bind(sb, b->ai_addr, b->ai_addrlen) < 0) {
		fprintf(stderr, "\tfailed bind for %s, %s\n",
			printres(b), strerror(errno));
		goto fail;
	}

	if (sa >= 0)
		close(sa);
	if (sb >= 0)
		close(sb);
	return 0;

fail:
	if (sa >= 0)
		close(sa);
	if (sb >= 0)
		close(sb);
	return -1;
}
