/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Fri, 12 Nov 1999 +0100:
 *    This file is contributed from Eric Lemiere <elemiere@matra-ms2i.f>, MS&I.
 * Sun Jan  9 06:23:42 JST 2000
 *    Merged into new racoon with trivial modification.
 */
/* $Id: signing.c,v 1.5 2000/02/07 10:51:22 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <rsa.h>
#include <evp.h>
#include <objects.h>
#include <x509.h>
#include <bio.h>
#include <err.h>
#include <pem.h>
#include <ssl.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"
#include "localconf.h"
#include "signing.h"

/* get openssl/ssleay version number */
#ifdef HAVE_OPENSSLV_H
#include <opensslv.h>
#define SSLVER	OPENSSL_VERSION_NUMBER
#else
#ifdef HAVE_CVERSION_H
#include <cversion.h>
#define SSLVER	SSLEAY_VERSION_NUMBER
#endif
#endif

/* Buffer used:	3072 bytes for data to be signed
 *		1024 bytes for signature buffer
 */
#define BUFFER_SIZE 4096
#define BUFFER_SIZE_PATH 256

#ifdef WIN16
#define MS_CALLBACK	_far _loadds
#else
#define MS_CALLBACK
#endif 

BIO *bio_err=NULL;

/*
 *	sign is a signature function
 *	Input: 	void *donnees_source
 *		int taille_donnees_source
 *		char *user
 *	Output:	char **signature
 *		int *taille_signature
 *
 *	user will be used to fetch the user signing key. If such user
 *	does not exist, or the key is not correctly retrieved, then "sign"
 *	returns -1. If everything goes well, it returns 0.
 */
int
sign(donnees_source, taille_donnees_source, user, signature, taille_signature)
	void *donnees_source;
	int taille_donnees_source;
	char *user;
	char **signature;
	int *taille_signature;
{
	/* Declaration */
	static char	keyfile[]		= USERS_PATH;
	char		buf[BUFFER_SIZE],
			*sig_buf,
			*data,
			*sig;
	int		err,
			sig_len			= BUFFER_SIZE;
	EVP_MD_CTX	md_ctx;
	EVP_PKEY	*pkey;
	FILE		*fp;


	/* Initialization */
	ERR_load_crypto_strings();
	data	=	&(buf[0]);
	*data	=	'\0';
	sig_buf	=	data + 3072;


/* Read private key (what if it is password-ciphered?)*/
	strcat(data, keyfile);
	strcat(data, user);
	strcat(data, PRIVKEYFILE);
	fp = fopen (data, "r");
	if (fp == NULL) return (-1);
#if (defined(SSLVER) && SSLVER >= 0x0940)
	pkey = (EVP_PKEY*)PEM_ASN1_read (  (char *(*)())d2i_PrivateKey,
        	                           PEM_STRING_EVP_PKEY,
                	                   fp,
                        	           NULL, NULL, NULL);
#else
	pkey = (EVP_PKEY*)PEM_ASN1_read (  (char *(*)())d2i_PrivateKey,
        	                           PEM_STRING_EVP_PKEY,
                	                   fp,
                        	           NULL, NULL);
#endif
	if (pkey == NULL) {  ERR_print_errors_fp (stderr);    return (-1);  }
	fclose (fp);

/* Do the signature (it only takes a private key, with no consistency to
 * whether it is consistent with the associated public key certificate or not!
 */
	memcpy((void *) data, donnees_source, taille_donnees_source);
	EVP_SignInit   (&md_ctx, EVP_md5());
	EVP_SignUpdate (&md_ctx, data, taille_donnees_source);
	err = EVP_SignFinal (	&md_ctx,
				sig_buf, 
				&sig_len,
				pkey);
	if (err != 1) {  ERR_print_errors_fp (stderr);    return (-1);  }
	EVP_PKEY_free (pkey);
/* End of user-signature, length sig_len, contained in sig_buf*/

/* Set the output and return */
	*taille_signature 	= 	sig_len;
	sig		 	= 	(char *) malloc(sig_len);
	memcpy(sig, sig_buf, sig_len);	
	*signature	 	= 	(char *) sig;

	return(0);
}



/*
 *	check_signature is a signature checking function
 *	Input: 	void *donnees_source
 *		int   taille_donnees_source
 *		char *user
 *		char *signature
 *		int taille_signature
 *
 *	user will be used to fetch the user public key certificate. If
 *	such user does not exist, or the public key is not correctly retrieved
 *	from the certificate, then "sign" returns -1. If everything goes
 *	well, it returns 0.
 */
int
check_signature(donnees_source, taille_donnees_source, user, signature, taille_signature)
	void *donnees_source;
	int taille_donnees_source;
	char *user;
	char *signature;
	int taille_signature;
{
	/* Declaration */
	static const char	certfile[]		= USERS_PATH;
	char			buf[BUFFER_SIZE],
				*data,
				*sig_buf;
	int 			err;
	EVP_MD_CTX      	md_ctx;
	EVP_PKEY 		*pkey;
	FILE 			*fp;
	X509 			*x509;


/* Initialization */
	data = &(buf[0]);
	*data = '\0';			// Omitting this line is bad, as strcat needs a \0 to begin copying!
	sig_buf = data + 3072;


/* Read the public key certificate and get the public key from the user directory*/
	strcat(data,certfile);
	strcat(data,user);
	strcat(data, CERTFILE);
	fp 	= fopen (data, "r");   if (fp == NULL) {printf("Bad user. Stop.\n");return (-1);}

#if (defined(SSLVER) && SSLVER >= 0x0940)
	x509 	= (X509 *)PEM_ASN1_read ((char *(*)())d2i_X509,
        	                           PEM_STRING_X509,
                	                   fp, NULL, NULL, NULL);
#else
	x509 	= (X509 *)PEM_ASN1_read ((char *(*)())d2i_X509,
        	                           PEM_STRING_X509,
                	                   fp, NULL, NULL);
#endif
	if (x509 == NULL) {  ERR_print_errors_fp (stderr);    return (-1);  }
	fclose (fp);
  	pkey	= X509_extract_key(x509);
	if (pkey == NULL) {  ERR_print_errors_fp (stderr);    return (-1);  }
/* Got public key from CA in pkey */


/* Verify the signature */
	EVP_VerifyInit   (&md_ctx, EVP_md5());
	memcpy(data, donnees_source, taille_donnees_source);
	memcpy(sig_buf, (void *)signature, taille_signature);
	EVP_VerifyUpdate (&md_ctx, data, taille_donnees_source);
	err 	= EVP_VerifyFinal (&md_ctx,
        	                   sig_buf,
                	           taille_signature,
                        	   pkey);
/* Signature verified */


/* Returns */
	EVP_PKEY_free (pkey);
	if (err != 1){
		ERR_print_errors_fp (stderr);
		return (-1);
	}
	return(0);
}

#if 0
static EVP_PKEY *
getsecretkey(certtype, idtype, subject)
	int certtype;
	int idtype;
	char *subject;
{
	char path[MAXPATHLEN];
	FILE *fp;
	EVP_PKEY *pkey = NULL;

	switch (certtype) {
	case ISAKMP_CERT_PKCS7:
	case ISAKMP_CERT_X509SIGN:
		/* make secret file name */
		snprintf(path, sizeof(path), "%s/%s/%s/%s",
			lcconf->pathinfo[LC_PATHTYPE_CERT],
			s_ipsecdoi_ident(idtype),
			subject, PRIVKEYFILE);

		/* Read private key */
		fp = fopen (path, "r");
		if (fp == NULL)
			return NULL
		pkey = PEM_read_PrivateKey(fp, NULL, NULL);
		fclose (fp);
		break;
	default:
		return NULL;
	}

	if (pkey == NULL)
		return NULL;

	return pkey;
}

static EVP_PKEY *
getpubkey(certtype, idtype, subject)
	int certtype;
	int idtype;
	char *subject;
{
	char path[MAXPATHLEN];
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;

	switch (certtype) {
	case ISAKMP_CERT_PKCS7:
	case ISAKMP_CERT_X509SIGN:
		/* make secret file name */
		snprintf(path, sizeof(path), "%s/%s/%s/%s",
			lcconf->pathinfo[LC_PATHTYPE_CERT],
			s_ipsecdoi_ident(idtype),
			subject, CERTFILE);

		/* Read private key */
		fp = fopen (path, "r");
		if (fp == NULL)
			return NULL
		x509 = PEM_read_X509(fp, NULL, NULL);
		fclose (fp);
		break;
	default:
		return NULL;
	}

	if (x509 == NULL)
		return NULL;
  
	/* Get public key - eay */
	pkey = X509_get_pubkey(x509);
	if (pkey == NULL)
		return NULL;

	return pkey;
}
#endif
  
//////////////////////////////////////////////////////////////////////////////////////////
// 					TO GET A CERTIFICATE
// Input:
//	a user name "user" (we check his public key certificate)
// Output:
//	return int: 0 if the cert is OK or -1 otherwise.
//	int *: set certificate_size
//	char **: points to a certificate pointer
//////////////////////////////////////////////////////////////////////////////////////////
int
get_certificate(user, certificate_size, certificate)
	char *user;
	int *certificate_size;
	char **certificate;
{

/* Declaration */
	static const char	certfile[]		= USERS_PATH;
	struct stat 		*statistics;
	char			buf[BUFFER_SIZE_PATH],
				*data;
	FILE 			*fp			= 	NULL;
	X509 			*x509;


/* Initialization */
	*certificate = NULL;
	data = &(buf[0]);
	*data = '\0';			// Omitting this line is bad, as strcat needs a \0 to begin copying!


/* Read the public key certificate: we also check that ASN.1 format is OK
 * as we only need to copy the file itself into the payload (or the ASN.1 itself:
 * we should indeed filter the decoded data, but not the formated head and tail
 * lines (if so, SSLeay would fail to check).
 */
 	strcat(data,certfile);
	strcat(data,user);
	strcat(data, CERTFILE);

	fp 	= fopen (data, "r");   if (fp == NULL) return (-1);
	statistics = (struct stat*) malloc(sizeof(stat));
	fstat(fileno(fp), statistics);
	*certificate_size = statistics->st_size;
	free(statistics);
#if (defined(SSLVER) && SSLVER >= 0x0940)
	x509 	= (X509 *)PEM_ASN1_read ((char *(*)())d2i_X509,
        	                           PEM_STRING_X509,
                	                   fp, NULL, NULL, NULL);
#else
	x509 	= (X509 *)PEM_ASN1_read ((char *(*)())d2i_X509,
        	                           PEM_STRING_X509,
                	                   fp, NULL, NULL);
#endif
	fclose (fp);
	if (x509 == NULL) {  ERR_print_errors_fp (stderr);    return (-1);  }
/* Got public key certificate and its size */

	{
	   unsigned char buf[10000];
	   size_t nb = *certificate_size;
	   int    fd = -1;
	   
           fd = open(data,O_RDONLY);
	   if (read(fd, buf, nb)!=nb)
	      printf ("Error reading certificate file %s\n", data);
	   close (fd);
	   *certificate = malloc(nb);
	   memcpy(*certificate, buf, nb);
        }

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
// 					TO CHECK A CERTIFICATE
//
// Three functions for certificate validation steps.
//
//////////////////////////////////////////////////////////////////////////////////////////
static int MS_CALLBACK cb(int ok, X509_STORE_CTX *ctx);
static int check(X509_STORE *ctx,char *file);
static int v_verbose=0;


int
verify_certificate(CApath, CAfile, cert_to_check)
	char *CApath;
	char *CAfile;
	char *cert_to_check;
{

	int i = 0;
	X509_STORE *cert_ctx=NULL;
	X509_LOOKUP *lookup=NULL;

	cert_ctx=X509_STORE_new();
	if (cert_ctx == NULL) goto end;
	X509_STORE_set_verify_cb_func(cert_ctx,cb);

	ERR_load_crypto_strings();

	if (bio_err == NULL)
		if ((bio_err=BIO_new(BIO_s_file())) != NULL)
			BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_file());
	if (lookup == NULL) return(-1);
	if (!X509_LOOKUP_load_file(lookup,CAfile,X509_FILETYPE_PEM))
		X509_LOOKUP_load_file(lookup,NULL,X509_FILETYPE_DEFAULT);

	lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir());
	if (lookup == NULL) return(-1);
	if (!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM))
		X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);


	ERR_clear_error();
	i = check(cert_ctx,cert_to_check);
end:
	if (cert_ctx != NULL) X509_STORE_free(cert_ctx);
	return(i == 1?0:-1);
}



static int
check(ctx, file)
	X509_STORE *ctx;
	char *file;
{

	X509 *x=NULL;
	BIO *in=NULL;
	int i=0,ret=0;
	X509_STORE_CTX csc;

	in=BIO_new(BIO_s_file());
	if (in == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}

	if (file == NULL)
		BIO_set_fp(in,stdin,BIO_NOCLOSE);
	else
		{
		if (BIO_read_filename(in,file) <= 0)
			{
			perror(file);
			goto end;
			}
		}

#if (defined(SSLVER) && SSLVER >= 0x0940)
	x=PEM_read_bio_X509(in,NULL,NULL,NULL);
#else
	x=PEM_read_bio_X509(in,NULL,NULL);
#endif

	if (x == NULL)
		{
		fprintf(stdout,"%s: unable to load certificate file\n",
			(file == NULL)?"stdin":file);
		ERR_print_errors(bio_err);
		goto end;
		}
//	fprintf(stdout,"%s: ",(file == NULL)?"stdin":file);

	X509_STORE_CTX_init(&csc,ctx,x,NULL);
	i=X509_verify_cert(&csc);
	X509_STORE_CTX_cleanup(&csc);

end:
	if (i)
		{
//		fprintf(stdout,"OK\n");
		ret=1;
		}
	else
		ERR_print_errors(bio_err);
	if (x != NULL) X509_free(x);
	if (in != NULL) BIO_free(in);

	return(i);
}

static int MS_CALLBACK
cb(ok, ctx)
	int ok;
	X509_STORE_CTX *ctx;
{

	char buf[256];

	if (!ok)
		{
		/* since we are just checking the certificates, it is
		 * ok if they are self signed. */
		if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
			ok=1;
		else
			{
			X509_NAME_oneline(
				X509_get_subject_name(ctx->current_cert),buf,256);
			printf("%s\n",buf);
			printf("error %d at %d depth lookup:%s\n",ctx->error,
				ctx->error_depth,
				X509_verify_cert_error_string(ctx->error));
			if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED)
				ok=1;
			}
		}
	if (!v_verbose)
		ERR_clear_error();
	return(ok);
}


//////////////////////////////////////////////////////////////////////////////////////////
// 					MAIN CERTIFICATE CHECKING FUNCTION
// Input:
//	a char * user name
// 		precise the location of the to-be-stored certificate
//		In case there was already a certificate here, it is erased.
//	a char * certificate to check
//	its size
//
// Output:
//	return int: 0 if cert is OK or -1 otherwise.
//
//////////////////////////////////////////////////////////////////////////////////////////
int
check_certificate(user, cryptCert, certificate_size)
	char *user;
	char *cryptCert;
	int certificate_size;
{

	static  char	certfile[]		= USERS_PATH;
	char	buf[BUFFER_SIZE],
		buf_string[BUFFER_SIZE],
		*file_name,
		*file_name_temp,
		*CA_FILE			= CA_PATH "cacert.pem";
	int	ret = -1;
	FILE	*fp;


/* Initialization */
	file_name 		= 	&(buf[0]);
	file_name_temp 		= 	file_name + 2048;
	*file_name 		= 	'\0';
	*file_name_temp 	= 	'\0';
	buf_string[0]	 	= 	'\0';

/* Storing the certificate binary to a temporary file */
	strcat(file_name,certfile);
	strcat(file_name,user);
	// Verify that the directory exists: if so, nothing is damaged.
	// Notice that in case of failure, this directory is not destroyed.
	mkdir(file_name, 493);
	strcat(file_name, CERTFILE);
	strcat(file_name_temp, file_name);
	strcat(file_name_temp, ".temp");
	
	fp = fopen(file_name_temp, "w+");
	fwrite((void *) cryptCert, certificate_size, 1, fp);
	fclose(fp);
/* Cert stored */

	ret = verify_certificate(CA_PATH, CA_FILE, file_name_temp);

	if (ret == 0){
		strcat((char *) &buf_string, "mv ");
		strcat((char *) &buf_string, file_name_temp);
		strcat((char *) &buf_string, " ");
		strcat((char *) &buf_string, file_name);
		system((char *) &(buf_string[0]));
		// We store the certificate, not knowing if it comes from
		// remote or local: a boolean should be needed in the function
		// call to prevent this.
	}
	else{
		strcat((char *) &buf_string, "rm ");
		strcat((char *) &buf_string, file_name_temp);
		system((char *) &(buf_string[0]));
		printf("Verification unveils a bad certificate! Use a local cert or stop if it is local.\n");
	}

	return(ret);
}


