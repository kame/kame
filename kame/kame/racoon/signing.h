#define MAX_SIZE_DATA 1000
#define USERS_PATH	"/root/PKI/USERS/"
#define CA_PATH		"/root/PKI/CA/"

#define PRIVKEYFILE	"secret.pem"
#define CERTFILE	"cert.pem"
#define CERTREQFILE	"cr.pem"

extern int eay_check_x509cert __P((char *idstr,
	int certtype, char *cert, int certlen));
