#define MAX_SIZE_DATA 1000
#define USERS_PATH	"/root/PKI/USERS/"
#define CA_PATH		"/root/PKI/CA/"


/*
 *	sign is a signature function
 *	Input: 	void *input_data
 *		int size_of_input_data
 *		char *user
 *	Output:	char *signature
 *		int *signature_size
 *
 *	User will be used to fetch the user signing key. If such user
 *	does not exist, or the key is not correctly retrieved, then "sign"
 *	returns -1. If everything goes well, it returns 0.
 */
int sign(void *, int , char *, char **, int *);


/*
 *	check_signature is a signature checking function
 *	Input: 	void *input_data
 *		int   input_data_size
 *		char *user
 *		char *signature
 *		int signature_size
 *
 *	User will be used to fetch the user public key certificate. If
 *	such user does not exist, or the public key is not correctly retrieved
 *	from the certificate, then "sign" returns -1. If everything goes
 *	well, it returns 0.
 */
int check_signature(void *, int , char *, char *, int );


//////////////////////////////////////////////////////////////////////////////////////////
// 					TO GET A CERTIFICATE
// Input:
//	a user name "user" (we check his public key certificate)
// Output:
//	return int: 0 if the cert is OK or -1 otherwise.
//	int *: set certificate_size
//	char **: points to a certificate pointer
//////////////////////////////////////////////////////////////////////////////////////////
int get_certificate(char *, int *, char **);


//////////////////////////////////////////////////////////////////////////////////////////
// 					MAIN CERTIFICATE CHECKING FUNCTION
// Input:
//	a char * user name
// 		precise the location of the to-be-stored certificate
//		In case there was already a certificate here, it is erased.
//	a char * certificate to check
//	its size int
//
// Output:
//	return int: 0 if cert is OK or -1 otherwise.
//
//////////////////////////////////////////////////////////////////////////////////////////
int check_certificate(char *, char *, int );
