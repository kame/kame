/* rijndael-api-fst.c   v2.0   August '99
 * Optimised ANSI C code
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen
 */

#include <stdlib.h>
#include <string.h>

#include "rijndael-alg-fst.h"
#include "rijndael-api-fst.h"

int makeKey(keyInstance *key, BYTE direction, int keyLen, char *keyMaterial)
{
	word8 k[MAXKC][4];
	int i, j, t;
	
	if (key == NULL) {
		return BAD_KEY_INSTANCE;
	}

	if ((direction == DIR_ENCRYPT) || (direction == DIR_DECRYPT)) {
		key->direction = direction;
	} else {
		return BAD_KEY_DIR;
	}

	if ((keyLen == 128) || (keyLen == 192) || (keyLen == 256)) { 
		key->keyLen = keyLen;
	} else {
		return BAD_KEY_MAT;
	}

	if ( keyMaterial ) {
		strncpy(key->keyMaterial, keyMaterial, keyLen/4);
	}

	ROUNDS = keyLen/32 + 6;

	/* initialize key schedule: */
 	for(i = 0; i < key->keyLen/8; i++) {
		t = key->keyMaterial[2*i];
		if ((t >= '0') && (t <= '9')) j = (t - '0') << 4;
		else if ((t >= 'a') && (t <= 'f')) j = (t - 'a' + 10) << 4; 
		else if ((t >= 'A') && (t <= 'F')) j = (t - 'A' + 10) << 4; 
		else return BAD_KEY_MAT;
		
		t = key->keyMaterial[2*i+1];
		if ((t >= '0') && (t <= '9')) j ^= (t - '0');
		else if ((t >= 'a') && (t <= 'f')) j ^= (t - 'a' + 10); 
		else if ((t >= 'A') && (t <= 'F')) j ^= (t - 'A' + 10); 
		else return BAD_KEY_MAT;
		
		k[i / 4][i % 4] = (word8) j; 
	}
	rijndaelKeySched (k, key->keyLen, key->keySched);
	if (direction == DIR_DECRYPT)
		rijndaelKeyEnctoDec (key->keyLen, key->keySched);

	return TRUE;
}

int cipherInit(cipherInstance *cipher, BYTE mode, char *IV)
{
	int i, j, t;
	
	if ((mode == MODE_ECB) || (mode == MODE_CBC) || (mode == MODE_CFB1)) {
		cipher->mode = mode;
	} else {
		return BAD_CIPHER_MODE;
	}
	

	if (IV != NULL) {
 		for(i = 0; i < 16; i++) {
			t = IV[2*i];
			if ((t >= '0') && (t <= '9')) j = (t - '0') << 4;
			else if ((t >= 'a') && (t <= 'f')) j = (t - 'a' + 10) << 4; 
			else if ((t >= 'A') && (t <= 'F')) j = (t - 'A' + 10) << 4; 
			else return BAD_CIPHER_INSTANCE;
		
			t = IV[2*i+1];
			if ((t >= '0') && (t <= '9')) j ^= (t - '0');
			else if ((t >= 'a') && (t <= 'f')) j ^= (t - 'a' + 10); 
			else if ((t >= 'A') && (t <= 'F')) j ^= (t - 'A' + 10); 
			else return BAD_CIPHER_INSTANCE;
			
			cipher->IV[i] = (word8) j;
		} 
	}

	return TRUE;
}


int blockEncrypt(cipherInstance *cipher,
	keyInstance *key, BYTE *input, int inputLen, BYTE *outBuffer)
{
	int i, k, numBlocks;
	word8 block[16], iv[4][4];

	if (cipher == NULL ||
		key == NULL ||
		key->direction == DIR_DECRYPT) {
		return BAD_CIPHER_STATE;
	}
	

	numBlocks = inputLen/128;
	
	switch (cipher->mode) {
	case MODE_ECB: 
		for (i = numBlocks; i > 0; i--) {
			
			rijndaelEncrypt (input, outBuffer, key->keySched);
			
			input += 16;
			outBuffer += 16;
		}
		break;
		
	case MODE_CBC:
#if STRICT_ALIGN 
		memcpy(block,cipher->IV,16); 
#else
		*((word32*)block) =  *((word32*)(cipher->IV));
		*((word32*)(block+4)) =  *((word32*)(cipher->IV+4));
		*((word32*)(block+8)) =  *((word32*)(cipher->IV+8));
		*((word32*)(block+12)) =  *((word32*)(cipher->IV+12));
#endif
		
		for (i = numBlocks; i > 0; i--) {
			*((word32*)block) ^= *((word32*)(input));
			*((word32*)(block+4)) ^= *((word32*)(input+4));
			*((word32*)(block+8)) ^= *((word32*)(input+8));
			*((word32*)(block+12)) ^= *((word32*)(input+12));

			rijndaelEncrypt (block, outBuffer, key->keySched);
			
			input += 16;
			outBuffer += 16;
		}
		break;
	
	case MODE_CFB1:
#if STRICT_ALIGN 
		memcpy(iv,cipher->IV,16); 
#else
		*((word32*)iv[0]) = *((word32*)(cipher->IV));
		*((word32*)iv[1]) = *((word32*)(cipher->IV+4));
		*((word32*)iv[2]) = *((word32*)(cipher->IV+8));
		*((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif
		for (i = numBlocks; i > 0; i--) {
			for (k = 0; k < 128; k++) {
				*((word32*)block) = *((word32*)iv[0]);
				*((word32*)(block+4)) = *((word32*)iv[1]);
				*((word32*)(block+8)) = *((word32*)iv[2]);
				*((word32*)(block+12)) = *((word32*)iv[3]);

				rijndaelEncrypt (block, block, key->keySched);
				outBuffer[k/8] ^= (block[0] & 0x80) >> (k & 7);
				iv[0][0] = (iv[0][0] << 1) | (iv[0][1] >> 7);
				iv[0][1] = (iv[0][1] << 1) | (iv[0][2] >> 7);
				iv[0][2] = (iv[0][2] << 1) | (iv[0][3] >> 7);
				iv[0][3] = (iv[0][3] << 1) | (iv[1][0] >> 7);
				iv[1][0] = (iv[1][0] << 1) | (iv[1][1] >> 7);
				iv[1][1] = (iv[1][1] << 1) | (iv[1][2] >> 7);
				iv[1][2] = (iv[1][2] << 1) | (iv[1][3] >> 7);
				iv[1][3] = (iv[1][3] << 1) | (iv[2][0] >> 7);
				iv[2][0] = (iv[2][0] << 1) | (iv[2][1] >> 7);
				iv[2][1] = (iv[2][1] << 1) | (iv[2][2] >> 7);
				iv[2][2] = (iv[2][2] << 1) | (iv[2][3] >> 7);
				iv[2][3] = (iv[2][3] << 1) | (iv[3][0] >> 7);
				iv[3][0] = (iv[3][0] << 1) | (iv[3][1] >> 7);
				iv[3][1] = (iv[3][1] << 1) | (iv[3][2] >> 7);
				iv[3][2] = (iv[3][2] << 1) | (iv[3][3] >> 7);
				iv[3][3] = (iv[3][3] << 1) | (outBuffer[k/8] >> (7-(k&7))) & 1;
			}
		}
		break;
	
	default:
		return BAD_CIPHER_STATE;
	}
	
	return numBlocks*128;
}

int blockDecrypt(cipherInstance *cipher,
	keyInstance *key, BYTE *input, int inputLen, BYTE *outBuffer)
{
	int i, k, numBlocks;
	word8 block[16], iv[4][4];

	if (cipher == NULL ||
		key == NULL ||
		cipher->mode != MODE_CFB1 && key->direction == DIR_ENCRYPT) {
		return BAD_CIPHER_STATE;
	}
	

	numBlocks = inputLen/128;
	
	switch (cipher->mode) {
	case MODE_ECB: 
		for (i = numBlocks; i > 0; i--) { 

			rijndaelDecrypt (input, outBuffer, key->keySched);

			input += 16;
			outBuffer += 16;

		}
		break;
		
	case MODE_CBC:
		/* first block */ 

		rijndaelDecrypt (input, block, key->keySched);
#if STRICT_ALIGN
		memcpy(outBuffer,cipher->IV,16); 
  		*((word32*)(outBuffer)) ^= *((word32*)block);
  		*((word32*)(outBuffer+4)) ^= *((word32*)(block+4));
  		*((word32*)(outBuffer+8)) ^= *((word32*)(block+8));
  		*((word32*)(outBuffer+12)) ^= *((word32*)(block+12));
#else
  		*((word32*)(outBuffer)) = *((word32*)block) ^ *((word32*)(cipher->IV));
  		*((word32*)(outBuffer+4)) = *((word32*)(block+4)) ^ *((word32*)(cipher->IV+4));
  		*((word32*)(outBuffer+8)) = *((word32*)(block+8)) ^ *((word32*)(cipher->IV+8));
  		*((word32*)(outBuffer+12)) = *((word32*)(block+12)) ^ *((word32*)(cipher->IV+12));
#endif
		
		/* next blocks */
		for (i = numBlocks-1; i > 0; i--) { 
		
			rijndaelDecrypt (input, block, key->keySched);
			
			*((word32*)(outBuffer+16)) = *((word32*)block) ^
					*((word32*)(input-16));
			*((word32*)(outBuffer+20)) = *((word32*)(block+4)) ^
					*((word32*)(input-12));
			*((word32*)(outBuffer+24)) = *((word32*)(block+8)) ^
					*((word32*)(input-8));
			*((word32*)(outBuffer+28)) = *((word32*)(block+12)) ^
					*((word32*)(input-4));
			
			input += 16;
			outBuffer += 16;
		}
		break;
	
	case MODE_CFB1:
#if STRICT_ALIGN 
		memcpy(iv,cipher->IV,16); 
#else
		*((word32*)iv[0]) = *((word32*)(cipher->IV));
		*((word32*)iv[1]) = *((word32*)(cipher->IV+4));
		*((word32*)iv[2]) = *((word32*)(cipher->IV+8));
		*((word32*)iv[3]) = *((word32*)(cipher->IV+12));
#endif
		for (i = numBlocks; i > 0; i--) {
			for (k = 0; k < 128; k++) {
				*((word32*)block) = *((word32*)iv[0]);
				*((word32*)(block+4)) = *((word32*)iv[1]);
				*((word32*)(block+8)) = *((word32*)iv[2]);
				*((word32*)(block+12)) = *((word32*)iv[3]);

				rijndaelEncrypt (block, block, key->keySched);
				iv[0][0] = (iv[0][0] << 1) | (iv[0][1] >> 7);
				iv[0][1] = (iv[0][1] << 1) | (iv[0][2] >> 7);
				iv[0][2] = (iv[0][2] << 1) | (iv[0][3] >> 7);
				iv[0][3] = (iv[0][3] << 1) | (iv[1][0] >> 7);
				iv[1][0] = (iv[1][0] << 1) | (iv[1][1] >> 7);
				iv[1][1] = (iv[1][1] << 1) | (iv[1][2] >> 7);
				iv[1][2] = (iv[1][2] << 1) | (iv[1][3] >> 7);
				iv[1][3] = (iv[1][3] << 1) | (iv[2][0] >> 7);
				iv[2][0] = (iv[2][0] << 1) | (iv[2][1] >> 7);
				iv[2][1] = (iv[2][1] << 1) | (iv[2][2] >> 7);
				iv[2][2] = (iv[2][2] << 1) | (iv[2][3] >> 7);
				iv[2][3] = (iv[2][3] << 1) | (iv[3][0] >> 7);
				iv[3][0] = (iv[3][0] << 1) | (iv[3][1] >> 7);
				iv[3][1] = (iv[3][1] << 1) | (iv[3][2] >> 7);
				iv[3][2] = (iv[3][2] << 1) | (iv[3][3] >> 7);
				iv[3][3] = (iv[3][3] << 1) | (input[k/8] >> (7-(k&7))) & 1;
				outBuffer[k/8] ^= (block[0] & 0x80) >> (k & 7);
			}
		}
		break;

	default:
		return BAD_CIPHER_STATE;
	}
	
	return numBlocks*128;
}


/**
 *	cipherUpdateRounds:
 *
 *	Encrypts/Decrypts exactly one full block a specified number of rounds.
 *	Only used in the Intermediate Value Known Answer Test.	
 *
 *	Returns:
 *		TRUE - on success
 *		BAD_CIPHER_STATE - cipher in bad state (e.g., not initialized)
 */
int cipherUpdateRounds(cipherInstance *cipher,
	keyInstance *key, BYTE *input, int inputLen, BYTE *outBuffer, int rounds)
{
	int j;
	word8 block[4][4];

	if (cipher == NULL ||
		key == NULL) {
		return BAD_CIPHER_STATE;
	}

	for (j = 3; j >= 0; j--) {
		/* parse input stream into rectangular array */
  		*((word32*)block[j]) = *((word32*)(input+4*j));
	}

	switch (key->direction) {
	case DIR_ENCRYPT:
		rijndaelEncryptRound (block, key->keySched, rounds);
	break;
		
	case DIR_DECRYPT:
		rijndaelDecryptRound (block, key->keySched, rounds);
	break;
		
	default: return BAD_KEY_DIR;
	} 

	for (j = 3; j >= 0; j--) {
		/* parse rectangular array into output ciphertext bytes */
		*((word32*)(outBuffer+4*j)) = *((word32*)block[j]);
	}
	
	return TRUE;
}
