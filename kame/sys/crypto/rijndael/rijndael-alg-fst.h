/* rijndael-alg-fst.h   v2.0   August '99
 * Optimised ANSI C code
 */
#ifndef __RIJNDAEL_ALG_H
#define __RIJNDAEL_ALG_H

#define MAXKC				(256/32)
#define MAXROUNDS			14

typedef unsigned char		word8;	
typedef unsigned short		word16;	
typedef unsigned int		word32;

int ROUNDS;

int rijndaelKeySched (word8 k[MAXKC][4], int keyBits,  
		word8 rk[MAXROUNDS+1][4][4]);
int rijndaelKeyEnctoDec (int keyBits, word8 W[MAXROUNDS+1][4][4]);
int rijndaelEncrypt (word8 a[16], word8 b[16], 
		word8 rk[MAXROUNDS+1][4][4]);
int rijndaelEncryptRound (word8 a[4][4],  
		word8 rk[MAXROUNDS+1][4][4], int rounds);
int rijndaelDecrypt (word8 a[16], word8 b[16],
		word8 rk[MAXROUNDS+1][4][4]);
int rijndaelDecryptRound (word8 a[4][4],  
		word8 rk[MAXROUNDS+1][4][4], int rounds);

#endif /* __RIJNDAEL_ALG_H */
