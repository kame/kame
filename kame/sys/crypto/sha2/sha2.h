/*
 * sha2.h
 *
 * Version 0.8
 *
 * Written by Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright 2000 Aaron D. Gifford.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __SHA2_H__
#define __SHA2_H__

#ifdef __cplusplus
extern "C" {
#endif

/*** SHA-256/384/512 Machine Architecture Definitions *****************/
/*
 * Define this if your machine is LITTLE_ENDIAN, otherwise
 * comment it out or #undef it.
 */
#define LITTLE_ENDIAN

/*
 * Define each of the below types according to your
 * architecture to make sure that they are EXACTLY
 * the required length (and no longer):
 */
typedef unsigned char		sha2_byte;		/* 8 bit type (1 byte)   */
typedef unsigned short		sha2_doublebyte;	/* 16 bit type (2 bytes) */
typedef unsigned long		sha2_word32;		/* 32 bit type (4 bytes) */
typedef unsigned long long	sha2_word64;		/* 64 bit type (8 bytes) */

/*** SHA-256/384/512 Various Length Definitions ***********************/

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA256_SHORT_BLOCK_LENGTH	(SHA256_BLOCK_LENGTH - 8)

#define SHA384_BLOCK_LENGTH		128
#define SHA384_DIGEST_LENGTH		48
#define SHA384_DIGEST_STRING_LENGTH	(SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA384_SHORT_BLOCK_LENGTH	(SHA384_BLOCK_LENGTH - 16)

#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)
#define SHA512_SHORT_BLOCK_LENGTH	(SHA512_BLOCK_LENGTH - 16)


/*** SHA-256/384/512 Context Structures *******************************/
/* The SHA context structures: */
typedef struct _SHA256_CTX {
	sha2_word32	state[8];
	sha2_word64	bitcount;
	sha2_byte	buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;

typedef struct _SHA512_CTX {
	sha2_word64	state[8];
	sha2_word64	bitcount[2];
	sha2_byte	buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;

typedef SHA512_CTX SHA384_CTX;


/*** SHA-256/384/512 Function Prototypes ******************************/

#ifndef NOPROTO

void SHA256_Init(SHA256_CTX *context);
void SHA256_Update(SHA256_CTX *context, sha2_byte *data, unsigned int len);
void SHA256_Final(sha2_byte digest[SHA256_DIGEST_LENGTH], SHA256_CTX* context);
char *SHA256_End(SHA256_CTX* context, char buffer[SHA256_DIGEST_STRING_LENGTH]);

void SHA384_Init(SHA384_CTX *context);
void SHA384_Update(SHA384_CTX *context, sha2_byte *data, unsigned int len);
void SHA384_Final(sha2_byte digest[SHA384_DIGEST_LENGTH], SHA384_CTX* context);
char *SHA384_End(SHA384_CTX* context, char buffer[SHA384_DIGEST_STRING_LENGTH]);

void SHA512_Init(SHA512_CTX *context);
void SHA512_Update(SHA512_CTX *context, sha2_byte *data, unsigned int len);
void SHA512_Final(sha2_byte digest[SHA512_DIGEST_LENGTH], SHA512_CTX* context);
char *SHA512_End(SHA512_CTX* context, char buffer[SHA512_DIGEST_STRING_LENGTH]);

#else /* NOPROTO */

void SHA256_Init();
void SHA256_Update();
void SHA256_Final();
char *SHA256_End();

void SHA384_Init();
void SHA384_Update();
void SHA384_Final();
char *SHA384_End();

void SHA512_Init();
void SHA512_Update();
void SHA512_Final();
char *SHA512_End();

#endif /* NOPROTO */

#ifdef	__cplusplus
}
#endif /* __cplusplus */

#endif /* __SHA2_H__ */

