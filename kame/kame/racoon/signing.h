#define MAX_SIZE_DATA 1000
#define USERS_PATH	"/root/PKI/USERS/"
#define CA_PATH		"/root/PKI/CA/"

extern int eay_check_x509cert __P((char *idstr,
	int certtype, char *cert, int certlen));
