#define MAX_SIZE_DATA 1000
#define USERS_PATH	"/root/PKI/USERS/"
#define CA_PATH		"/root/PKI/CA/"

#define PRIVKEYFILE	"secret.pem"
#define CERTFILE	"cert.pem"
#define CERTREQFILE	"cr.pem"

extern int sign __P((void *, int , char *, char **, int *));
extern int check_signature __P((void *, int , char *, char *, int ));
extern int get_certificate __P((char *, int *, char **));
extern int check_certificate __P((char *, char *, int ));

