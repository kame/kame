/*
 * sha2.c
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


#include <string.h>	/* bzero() and memcpy() */
#include "sha2.h"


#ifdef LITTLE_ENDIAN
/*** ENDIAN REVERSAL MACROS *******************************************/
#define REVERSE16(w)	(((w) >> 8) | ((w) << 8))
#define REVERSE32(w)	(((w) << 24) | \
			 (((w) & 0x0000ff00) <<  8) | \
			 (((w) & 0x00ff0000) >>  8) | \
			 ((w) >> 24))
#define REVERSE64(w)	(((w) << 56) | \
			 (((w) & 0x000000000000ff00) << 40) | \
			 (((w) & 0x0000000000ff0000) << 24) | \
			 (((w) & 0x00000000ff000000) <<  8) | \
			 (((w) & 0x000000ff00000000) >>  8) | \
			 (((w) & 0x0000ff0000000000) >> 24) | \
			 (((w) & 0x00ff000000000000) >> 40) | \
			 ((w) >> 56))
#endif /* LITTLE_ENDIAN */

/*
 * Macro for incrementally adding the unsigned 64-bit integer n to the
 * unsigned 128-bit integer (represented using a two-element array of
 * 64-bit words):
 */
#define ADDINC128(w,n)	{ \
	(w)[0] += (sha2_word64)(n); \
	if ((w)[0] < (n)) { \
		(w)[1]++; \
	} \
}


/*** THE SIX LOGICAL FUNCTIONS ****************************************/
/*
 * Bit shifting and rotation (used by the six SHA-XYZ logical functions:
 *
 *   NOTE:  The naming of R and S appears backwards here (R is a SHIFT and
 *   S is a ROTATION) because the SHA-256/384/512 description document
 *   (see http://csrc.nist.gov/cryptval/shs/sha256-384-512.pdf) uses this
 *   same "backwards" definition.
 */
/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define R(b,x) 		((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define S32(b,x)		(((x) >> (b)) | ((x) << (32 - (b))))
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define S64(b,x)		(((x) >> (b)) | ((x) << (64 - (b))))

/* Two of six logical functions used in SHA-256, SHA-384, and SHA-512: */
#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Four of six logical functions used in SHA-256: */
#define Sigma0_256(x)	(S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x)	(S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x)	(S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))
#define sigma1_256(x)	(S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

/* Four of six logical functions used in SHA-384 and SHA-512: */
#define Sigma0_512(x)	(S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1_512(x)	(S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define sigma0_512(x)	(S64( 1, (x)) ^ S64( 8, (x)) ^ R( 7,   (x)))
#define sigma1_512(x)	(S64(19, (x)) ^ S64(61, (x)) ^ R( 6,   (x)))


/*** SHA-XYZ INITIAL HASH VALUES AND CONSTANTS ************************/
/* Hash constant words K for SHA-256: */
const static sha2_word32 K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Initial hash value H for SHA-256: */
const static sha2_word32 sha256_initial_hash_value[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

/* Hash constant words K for SHA-384 and SHA-512: */
const static sha2_word64 K512[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/* Initial hash value H for SHA-384 */
const static sha2_word64 sha384_initial_hash_value[8] = {
	0xcbbb9d5dc1059ed8,
	0x629a292a367cd507,
	0x9159015a3070dd17,
	0x152fecd8f70e5939,
	0x67332667ffc00b31,
	0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7,
	0x47b5481dbefa4fa4
};

/* Initial hash value H for SHA-512 */
const static sha2_word64 sha512_initial_hash_value[8] = {
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179
};


/*** SHA-256: *********************************************************/
void SHA256_Init(SHA256_CTX *context) {
	if (context == (SHA256_CTX*)0) {
		return;
	}
	memcpy(context->state, sha256_initial_hash_value, SHA256_DIGEST_LENGTH);
	bzero(context->buffer, SHA256_BLOCK_LENGTH);
	context->bitcount = 0;
};

void SHA256_Transform(SHA256_CTX *context) {
	sha2_word32	a, b, c, d;
	sha2_word32	e, f, g, h;
	sha2_word32	T1, T2, *W256 = (sha2_word32*)context->buffer;
	int		j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	for (j = 0; j < 16; j++) {
#ifdef LITTLE_ENDIAN
		/* Convert TO host byte order */
		W256[j] = REVERSE32(W256[j]);
#endif
		/* Apply the SHA-256 compression function to update a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	for (j = 16; j < 64; j++) {
		/* Compute expanded message block */
		W256[j%16] += sigma1_256(W256[(j-2)%16]) + W256[(j-7)%16] + sigma0_256(W256[(j-15)%16]);

		/* Apply the SHA-256 compression function to update a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j%16];
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
};

void SHA256_Update(SHA256_CTX *context, sha2_byte *data, unsigned int len) {
	unsigned int	freespace, usedspace;

	/* Quick sanity check: */
	if (context == (SHA256_CTX*)0 || data == (sha2_byte*)0 || len < 1) {
		return;
	}

	usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
	if (usedspace > 0) {
		/* Calculate how much free space is available in the buffer */
		freespace = SHA256_BLOCK_LENGTH - usedspace;

		if (len >= freespace) {
			/* Fill the buffer completely and process it */
			memcpy(&context->buffer[usedspace], data, freespace);
			context->bitcount += freespace << 3;
			len -= freespace;
			data += freespace;
			SHA256_Transform(context);
		} else {
			/* The buffer is not yet full */
			memcpy(&context->buffer[usedspace], data, len);
			context->bitcount += len << 3;
			return;
		}
	}
	while (len >= SHA256_BLOCK_LENGTH) {
		/* Process as many complete blocks as we can */
		memcpy(context->buffer, data, SHA256_BLOCK_LENGTH);
		SHA256_Transform(context);
		context->bitcount += SHA256_BLOCK_LENGTH << 3;
		len -= SHA256_BLOCK_LENGTH;
		data += SHA256_BLOCK_LENGTH;
	}
	if (len > 0) {
		/* There's left-overs, so save 'em */
		memcpy(context->buffer, data, len);
		context->bitcount += len << 3;
	}
};

void SHA256_Final(sha2_byte digest[], SHA256_CTX* context) {
	sha2_word32	*d = (sha2_word32*)digest;
	unsigned int	usedspace;

	if (context == (SHA256_CTX*)0) {
		/* Hey, ya gotta at least pass in a context! */
		return;
	}

	usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LENGTH;
	if (usedspace > 0) {
#ifdef LITTLE_ENDIAN
		/* Convert FROM host byte order */
		context->bitcount = REVERSE64(context->bitcount);
#endif
		/* Append a 1 bit to start padding */
		context->buffer[usedspace++] = 0x80;
		if (usedspace < SHA256_SHORT_BLOCK_LENGTH) {
			bzero(&context->buffer[usedspace], SHA256_SHORT_BLOCK_LENGTH - usedspace);
			*(sha2_word64*)&context->buffer[SHA256_SHORT_BLOCK_LENGTH] = context->bitcount;
		} else {
			if (usedspace < SHA256_BLOCK_LENGTH) {
				bzero(&context->buffer[usedspace], SHA256_BLOCK_LENGTH - usedspace);
			}
			SHA256_Transform(context);
			bzero(context->buffer, SHA256_SHORT_BLOCK_LENGTH);
			*(sha2_word64*)&context->buffer[SHA256_SHORT_BLOCK_LENGTH] = context->bitcount;
		}
	}
	SHA256_Transform(context);

	/* Save the hash data for output (IF a digest buffer was provided) */
	if (d != (sha2_word32*)0) {
#ifdef LITTLE_ENDIAN
		/* Convert TO host byte order */
		int	j;
		for (j = 0; j < 8; j++) {
			*d++ = REVERSE32(context->state[j]);
		}
#else
		memcpy(d, context->state, SHA256_DIGEST_LENGTH);
#endif
	}

	/* Zero out state data */
	bzero(context, sizeof(context));
};

char *SHA256_End(SHA256_CTX* context, char buffer[]) {
	sha2_byte	digest[SHA256_DIGEST_LENGTH], *d = digest;
	int		i;

	if (context == (SHA256_CTX*)0 || buffer == (char*)0) {
		return (char*)0;
	}
	SHA256_Final(digest, context);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		*buffer++ = ((*d & 0xf0) >> 4) + ((*d & 0xf0) > 0x90 ? 'a' - 10 : '0');
		*buffer++ = (*d & 0x0f) + ((*d & 0x0f) > 0x09 ? 'a' - 10 : '0');
		d++;
	}
	*buffer = 0x00;
	bzero(digest, SHA256_DIGEST_LENGTH);
	return buffer;
}


/*** SHA-512: *********************************************************/
void SHA512_Init(SHA512_CTX *context) {
	if (context == (SHA512_CTX*)0) {
		return;
	}
	memcpy(context->state, sha512_initial_hash_value, SHA512_DIGEST_LENGTH);
	bzero(context->buffer, SHA512_BLOCK_LENGTH);
	context->bitcount[0] = context->bitcount[1] =  0;
};

void SHA512_Transform(SHA512_CTX *context) {
	sha2_word64	a, b, c, d;
	sha2_word64	e, f, g, h;
	sha2_word64	T1, T2, *W512 = (sha2_word64*)context->buffer;
	int		j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	for (j = 0; j < 16; j++) {
#ifdef LITTLE_ENDIAN
		/* Convert TO host byte order */
		W512[j] = REVERSE64(W512[j]);
#endif
		/* Apply the SHA-512 compression function to update a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + W512[j];
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	for (j = 16; j < 80; j++) {
		/* Compute expanded message block */
		W512[j%16] += sigma1_512(W512[(j-2)%16]) + W512[(j-7)%16] + sigma0_512(W512[(j-15)%16]);

		/* Apply the SHA-512 compression function to update a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + W512[j%16];
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
};

void SHA512_Update(SHA512_CTX *context, sha2_byte *data, unsigned int len) {
	unsigned int	freespace, usedspace;

	/* Quick sanity check: */
	if (context == (SHA512_CTX*)0 || data == (sha2_byte*)0 || len < 1) {
		return;
	}

	usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LENGTH;
	if (usedspace > 0) {
		/* Calculate how much free space is available in the buffer */
		freespace = SHA512_BLOCK_LENGTH - usedspace;

		if (len >= freespace) {
			/* Fill the buffer completely and process it */
			memcpy(&context->buffer[usedspace], data, freespace);
			ADDINC128(context->bitcount, freespace << 3);
			len -= freespace;
			data += freespace;
			SHA512_Transform(context);
		} else {
			/* The buffer is not yet full */
			memcpy(&context->buffer[usedspace], data, len);
			ADDINC128(context->bitcount, len << 3);
			return;
		}
	}
	while (len >= SHA512_BLOCK_LENGTH) {
		/* Process as many complete blocks as we can */
		memcpy(context->buffer, data, SHA512_BLOCK_LENGTH);
		SHA512_Transform(context);
		ADDINC128(context->bitcount, SHA512_BLOCK_LENGTH << 3);
		len -= SHA512_BLOCK_LENGTH;
		data += SHA512_BLOCK_LENGTH;
	}
	if (len > 0) {
		/* There's left-overs, so save 'em */
		memcpy(context->buffer, data, len);
		ADDINC128(context->bitcount, len << 3);
	}
};

void SHA512_Last(SHA512_CTX* context) {
	unsigned int	usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LENGTH;

	if (usedspace > 0) {
#ifdef LITTLE_ENDIAN
		/* Convert FROM host byte order */
		context->bitcount[0] = REVERSE64(context->bitcount[0]);
		context->bitcount[1] = REVERSE64(context->bitcount[1]);
#endif
		/* Append a 1 bit to start padding */
		context->buffer[usedspace++] = 0x80;
		if (usedspace < SHA512_SHORT_BLOCK_LENGTH) {
			bzero(&context->buffer[usedspace], SHA512_SHORT_BLOCK_LENGTH - usedspace);
			*(sha2_word64*)&context->buffer[SHA512_SHORT_BLOCK_LENGTH] = context->bitcount[1];
			*(sha2_word64*)&context->buffer[SHA512_SHORT_BLOCK_LENGTH+8] = context->bitcount[0];
		} else {
			if (usedspace < SHA512_BLOCK_LENGTH) {
				bzero(&context->buffer[usedspace], SHA512_BLOCK_LENGTH - usedspace);
			}
			SHA512_Transform(context);
			bzero(context->buffer, SHA512_BLOCK_LENGTH - 2);
			*(sha2_word64*)&context->buffer[SHA512_SHORT_BLOCK_LENGTH] = context->bitcount[1];
			*(sha2_word64*)&context->buffer[SHA512_SHORT_BLOCK_LENGTH+8] = context->bitcount[0];
		}
	}
	SHA512_Transform(context);
}

void SHA512_Final(sha2_byte digest[], SHA512_CTX* context) {
	sha2_word64	*d = (sha2_word64*)digest;

	if (context == (SHA512_CTX*)0) {
		/* Hey, ya gotta at least pass in a context! */
		return;
	}

	SHA512_Last(context);

	/* Save the hash data for output (IF a digest buffer was provided) */
	if (d != (sha2_word64*)0) {
#ifdef LITTLE_ENDIAN
		/* Convert TO host byte order */
		int	j;
		for (j = 0; j < 8; j++) {
			*d++ = REVERSE64(context->state[j]);
		}
#else
		memcpy(d, context->state, SHA512_DIGEST_LENGTH);
#endif
	}

	/* Zero out state data */
	bzero(context, sizeof(context));
};

char *SHA512_End(SHA512_CTX* context, char buffer[]) {
	sha2_byte	digest[SHA512_DIGEST_LENGTH], *d = digest;
	int		i;

	if (context == (SHA512_CTX*)0 || buffer == (char*)0) {
		return (char*)0;
	}
	SHA512_Final(digest, context);
	for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
		*buffer++ = ((*d & 0xf0) >> 4) + ((*d & 0xf0) > 0x90 ? 'a' - 10 : '0');
		*buffer++ = (*d & 0x0f) + ((*d & 0x0f) > 0x09 ? 'a' - 10 : '0');
		d++;
	}
	*buffer = 0x00;
	bzero(digest, SHA512_DIGEST_LENGTH);
	return buffer;
}


/*** SHA-384: *********************************************************/
void SHA384_Init(SHA384_CTX *context) {
	if (context == (SHA384_CTX*)0) {
		return;
	}
	memcpy(context->state, sha384_initial_hash_value, SHA512_DIGEST_LENGTH);
	bzero(context->buffer, SHA384_BLOCK_LENGTH);
	context->bitcount[0] = context->bitcount[1] = 0;
};

void SHA384_Update(SHA384_CTX *context, sha2_byte *data, unsigned int len) {
	SHA512_Update((SHA512_CTX*)context, data, len);
};

void SHA384_Final(sha2_byte digest[], SHA384_CTX* context) {
	sha2_word64	*d = (sha2_word64*)digest;

	if (context == (SHA384_CTX*)0) {
		/* Hey, ya gotta at least pass in a context! */
		return;
	}

	SHA512_Last((SHA512_CTX*)context);

	/* Save the hash data for output (IF a digest buffer was provided) */
	if (d != (sha2_word64*)0) {
#ifdef LITTLE_ENDIAN
		/* Convert TO host byte order */
		int	j;
		for (j = 0; j < 6; j++) {
			*d++ = REVERSE64(context->state[j]);
		}
#else
		memcpy(d, context->state, SHA384_DIGEST_LENGTH);
#endif
	}

	/* Zero out state data */
	bzero(context, sizeof(context));
};

char *SHA384_End(SHA384_CTX* context, char buffer[]) {
	sha2_byte	digest[SHA384_DIGEST_LENGTH], *d = digest;
	int		i;

	if (context == (SHA384_CTX*)0 || buffer == (char*)0) {
		return (char*)0;
	}
	SHA384_Final(digest, context);
	for (i = 0; i < SHA384_DIGEST_LENGTH; i++) {
		*buffer++ = ((*d & 0xf0) >> 4) + ((*d & 0xf0) > 0x90 ? 'a' - 10 : '0');
		*buffer++ = (*d & 0x0f) + ((*d & 0x0f) > 0x09 ? 'a' - 10 : '0');
		d++;
	}
	*buffer = 0x00;
	bzero(digest, SHA384_DIGEST_LENGTH);
	return buffer;
}

