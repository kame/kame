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
/* $Id: signing.c,v 1.11 2000/02/09 05:18:09 sakane Exp $ */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

/* get openssl/ssleay version number */
#ifdef INCLUDE_PATH_OPENSSL
# ifdef HAVE_OPENSSL_OPENSSLV_H
#  include <openssl/opensslv.h>
#  define SSLVER	OPENSSL_VERSION_NUMBER
# endif
#else
# ifdef HAVE_OPENSSLV_H
#  include <opensslv.h>
#  define SSLVER	OPENSSL_VERSION_NUMBER
# else
#  ifdef HAVE_CVERSION_H
#   include <cversion.h>
#   define SSLVER	SSLEAY_VERSION_NUMBER
#  endif
# endif
#endif

#ifdef INCLUDE_PATH_OPENSSL
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#else
#include <rsa.h>
#include <evp.h>
#include <objects.h>
#include <x509.h>
#include <bio.h>
#include <err.h>
#include <pem.h>
#include <ssl.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"
#include "localconf.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "strnames.h"
#include "signing.h"

#ifdef WIN16
#define MS_CALLBACK	_far _loadds
#else
#define MS_CALLBACK
#endif 

BIO *bio_err=NULL;

#if 0
static int verify_certificate
	__P((char *CApath, char *CAfile, char *cert_to_check));
#endif

#if 0
//////////////////////////////////////////////////////////////////////////////////////////
// 					TO CHECK A CERTIFICATE
//
// Three functions for certificate validation steps.
//
//////////////////////////////////////////////////////////////////////////////////////////

/*
 * MAIN CERTIFICATE CHECKING FUNCTION
 * Input:
 *	a char * user name
 * 		precise the location of the to-be-stored certificate
 *		In case there was already a certificate here, it is erased.
 *	a char * certificate to check
 *	its size int
 *
 * Output:
 *	return int: 0 if cert is OK or -1 otherwise.
 *
 */
static int MS_CALLBACK cb(int ok, X509_STORE_CTX *ctx);
static int check(X509_STORE *ctx,char *file);
static int v_verbose=0;

static int
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
#endif

/*
 * check certificate
 */
int
eay_check_x509cert(idstr, certtype, cert, certlen)
	char *idstr;
	int certtype;
	char *cert;
	int certlen;
{
#if 1
	return 0;
#else
	static  char	certfile[]		= USERS_PATH;
	char	buf[BUFSIZ],
		buf_string[BUFSIZ],
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
#endif
}


