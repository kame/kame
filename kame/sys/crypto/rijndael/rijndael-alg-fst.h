/* rijndael-alg-fst.h   v2.0   August '99
 * Optimised ANSI C code
 */
#ifndef __RIJNDAEL_ALG_H
#define __RIJNDAEL_ALG_H

#define RIJNDAEL_MAXKC				(256/32)
#define RIJNDAEL_MAXROUNDS			14

int rijndaelKeySched __P((u_int8_t[RIJNDAEL_MAXKC][4], int,
	u_int8_t[RIJNDAEL_MAXROUNDS+1][4][4]));
int rijndaelKeyEnctoDec __P((int, u_int8_t[RIJNDAEL_MAXROUNDS+1][4][4]));
int rijndaelEncrypt __P((u_int8_t[16], u_int8_t[16],
	u_int8_t[RIJNDAEL_MAXROUNDS+1][4][4]));
int rijndaelEncryptRound __P((u_int8_t[4][4],
	u_int8_t[RIJNDAEL_MAXROUNDS+1][4][4], int));
int rijndaelDecrypt __P((u_int8_t[16], u_int8_t[16],
	u_int8_t[RIJNDAEL_MAXROUNDS+1][4][4]));
int rijndaelDecryptRound __P((u_int8_t[4][4],
	u_int8_t[RIJNDAEL_MAXROUNDS+1][4][4], int));

#endif /* __RIJNDAEL_ALG_H */
