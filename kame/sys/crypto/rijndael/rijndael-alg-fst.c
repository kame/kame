/* rijndael-alg-fst.c   v2.0   August '99
 * Optimised ANSI C code
 * authors: v1.0: Antoon Bosselaers
 *          v2.0: Vincent Rijmen
 */

#include <stdio.h>
#include <stdlib.h>

#include "rijndael-alg-fst.h"

#define SC	((BC - 4) >> 1)

#include "boxes-fst.dat"

static word8 shifts[3][4][2] = {
   0, 0,
   1, 3,
   2, 2,
   3, 1,
   
   0, 0,
   1, 5,
   2, 4,
   3, 3,
   
   0, 0,
   1, 7,
   3, 5,
   4, 4
}; 


word8 mul(word8 a, word8 b) {
   /* multiply two elements of GF(2^m)
    * needed for MixColumn and InvMixColumn
    */
	if (a && b)
		return Alogtable[(Logtable[a] + Logtable[b])%255];
	else
		return 0;
}

void KeyAddition(word8 a[4][4], word8 rk[4][4], word8 BC) {
	/* Exor corresponding text input and round key input bytes
	 */
	int i, j;
	
	for(i = 0; i < BC; i++)
   	for(j = 0; j < 4; j++)
			a[i][j] ^= rk[i][j];
}

void ShiftRow(word8 a[4][4], word8 d, word8 BC) {
	/* Row 0 remains unchanged
	 * The other three rows are shifted a variable amount
	 */
	word8 tmp[4];
	int i, j;
	
	for(i = 1; i < 4; i++) {
		for(j = 0; j < BC; j++)
			tmp[j] = a[(j + shifts[SC][i][d]) % BC][i];
		for(j = 0; j < BC; j++)
			a[j][i] = tmp[j];
	}
}

void Substitution(word8 a[4][4], word8 box[256], word8 BC) {
	/* Replace every byte of the input by the byte at that place
	 * in the nonlinear S-box
	 */
	int i, j;
	
	for(i = 0; i < BC; i++)
		for(j = 0; j < 4; j++)
			a[i][j] = box[a[i][j]] ;
}
   
void MixColumn(word8 a[4][4], word8 BC) {
        /* Mix the four bytes of every column in a linear way
	 */
	word8 b[4][4];
	int i, j;
		
	for(j = 0; j < BC; j++)
		for(i = 0; i < 4; i++)
			b[j][i] = mul(2,a[j][i])
				^ mul(3,a[j][(i + 1) % 4])
				^ a[j][(i + 2) % 4]
				^ a[j][(i + 3) % 4];
	for(i = 0; i < 4; i++)
		for(j = 0; j < BC; j++)
			a[j][i] = b[j][i];
}

void InvMixColumn(word8 a[4][4], word8 BC) {
        /* Mix the four bytes of every column in a linear way
	 * This is the opposite operation of Mixcolumn
	 */
	int j;

	for(j = 0; j < BC; j++)
		*((word32*)a[j]) = *((word32*)U1[a[j][0]])
								^ *((word32*)U2[a[j][1]])
								^ *((word32*)U3[a[j][2]])
								^ *((word32*)U4[a[j][3]]);


}

int rijndaelKeySched (word8 k[MAXKC][4], int keyBits, word8 W[MAXROUNDS+1][4][4])
{
	/* Calculate the necessary round keys
	 * The number of calculations depends on keyBits and blockBits
	 */ 
	int j, r, t, rconpointer = 0;
	word8 tk[MAXKC][4];
	int KC = ROUNDS - 6;
	
	for(j = KC-1; j >= 0; j--)
		*((word32*)tk[j]) = *((word32*)k[j]);
	r = 0;
	t = 0;
	/* copy values into round key array */
	for(j = 0; (j < KC) && (r < (ROUNDS+1)); ) {
		for (; (j < KC) && (t < 4); j++, t++)
			*((word32*)W[r][t]) = *((word32*)tk[j]);
		if (t == 4) {
			r++;
			t = 0;
		}
	}
		
	while (r < (ROUNDS+1)) { /* while not enough round key material calculated */
		/* calculate new values */
		tk[0][0] ^= S[tk[KC-1][1]];
		tk[0][1] ^= S[tk[KC-1][2]];
		tk[0][2] ^= S[tk[KC-1][3]];
		tk[0][3] ^= S[tk[KC-1][0]];
		tk[0][0] ^= rcon[rconpointer++];

		if (KC != 8)
			for(j = 1; j < KC; j++)
				*((word32*)tk[j]) ^= *((word32*)tk[j-1]);
		else {
			for(j = 1; j < KC/2; j++)
				*((word32*)tk[j]) ^= *((word32*)tk[j-1]);
			tk[KC/2][0] ^= S[tk[KC/2 - 1][0]];
			tk[KC/2][1] ^= S[tk[KC/2 - 1][1]];
			tk[KC/2][2] ^= S[tk[KC/2 - 1][2]];
			tk[KC/2][3] ^= S[tk[KC/2 - 1][3]];
			for(j = KC/2 + 1; j < KC; j++)
				*((word32*)tk[j]) ^= *((word32*)tk[j-1]);
		}
		/* copy values into round key array */
		for(j = 0; (j < KC) && (r < (ROUNDS+1)); ) {
			for (; (j < KC) && (t < 4); j++, t++)
				*((word32*)W[r][t]) = *((word32*)tk[j]);
			if (t == 4) {
				r++;
				t = 0;
			}
		}
	}		

	return 0;
}

int rijndaelKeyEnctoDec (int keyBits, word8 W[MAXROUNDS+1][4][4])
{
	int r;

	for (r = 1; r < ROUNDS; r++) {
		InvMixColumn(W[r], 4);
	}
	return 0;
}	

int rijndaelEncrypt (word8 a[16], word8 b[16], word8 rk[MAXROUNDS+1][4][4])
{
	/* Encryption of one block. 
	 */
	int r;
   word8 temp[4][4];

    *((word32*)temp[0]) = *((word32*)a) ^ *((word32*)rk[0][0]);
    *((word32*)temp[1]) = *((word32*)(a+4)) ^ *((word32*)rk[0][1]);
    *((word32*)temp[2]) = *((word32*)(a+8)) ^ *((word32*)rk[0][2]);
    *((word32*)temp[3]) = *((word32*)(a+12)) ^ *((word32*)rk[0][3]);
    *((word32*)b) = *((word32*)T1[temp[0][0]])
           ^ *((word32*)T2[temp[1][1]])
           ^ *((word32*)T3[temp[2][2]]) 
           ^ *((word32*)T4[temp[3][3]]);
    *((word32*)(b+4)) = *((word32*)T1[temp[1][0]])
           ^ *((word32*)T2[temp[2][1]])
           ^ *((word32*)T3[temp[3][2]]) 
           ^ *((word32*)T4[temp[0][3]]);
    *((word32*)(b+8)) = *((word32*)T1[temp[2][0]])
           ^ *((word32*)T2[temp[3][1]])
           ^ *((word32*)T3[temp[0][2]]) 
           ^ *((word32*)T4[temp[1][3]]);
    *((word32*)(b+12)) = *((word32*)T1[temp[3][0]])
           ^ *((word32*)T2[temp[0][1]])
           ^ *((word32*)T3[temp[1][2]]) 
           ^ *((word32*)T4[temp[2][3]]);
   for(r = 1; r < ROUNDS-1; r++) {
		*((word32*)temp[0]) = *((word32*)b) ^ *((word32*)rk[r][0]);
		*((word32*)temp[1]) = *((word32*)(b+4)) ^ *((word32*)rk[r][1]);
		*((word32*)temp[2]) = *((word32*)(b+8)) ^ *((word32*)rk[r][2]);
		*((word32*)temp[3]) = *((word32*)(b+12)) ^ *((word32*)rk[r][3]);
   *((word32*)b) = *((word32*)T1[temp[0][0]])
           ^ *((word32*)T2[temp[1][1]])
           ^ *((word32*)T3[temp[2][2]]) 
           ^ *((word32*)T4[temp[3][3]]);
   *((word32*)(b+4)) = *((word32*)T1[temp[1][0]])
           ^ *((word32*)T2[temp[2][1]])
           ^ *((word32*)T3[temp[3][2]]) 
           ^ *((word32*)T4[temp[0][3]]);
   *((word32*)(b+8)) = *((word32*)T1[temp[2][0]])
           ^ *((word32*)T2[temp[3][1]])
           ^ *((word32*)T3[temp[0][2]]) 
           ^ *((word32*)T4[temp[1][3]]);
   *((word32*)(b+12)) = *((word32*)T1[temp[3][0]])
           ^ *((word32*)T2[temp[0][1]])
           ^ *((word32*)T3[temp[1][2]]) 
           ^ *((word32*)T4[temp[2][3]]);
   }
   /* last round is special */   
	*((word32*)temp[0]) = *((word32*)b) ^ *((word32*)rk[ROUNDS-1][0]);
	*((word32*)temp[1]) = *((word32*)(b+4)) ^ *((word32*)rk[ROUNDS-1][1]);
	*((word32*)temp[2]) = *((word32*)(b+8)) ^ *((word32*)rk[ROUNDS-1][2]);
	*((word32*)temp[3]) = *((word32*)(b+12)) ^ *((word32*)rk[ROUNDS-1][3]);
   b[0] = T1[temp[0][0]][1];
   b[1] = T1[temp[1][1]][1];
   b[2] = T1[temp[2][2]][1]; 
   b[3] = T1[temp[3][3]][1];
   b[4] = T1[temp[1][0]][1];
   b[5] = T1[temp[2][1]][1];
   b[6] = T1[temp[3][2]][1]; 
   b[7] = T1[temp[0][3]][1];
   b[8] = T1[temp[2][0]][1];
   b[9] = T1[temp[3][1]][1];
   b[10] = T1[temp[0][2]][1]; 
   b[11] = T1[temp[1][3]][1];
   b[12] = T1[temp[3][0]][1];
   b[13] = T1[temp[0][1]][1];
   b[14] = T1[temp[1][2]][1]; 
   b[15] = T1[temp[2][3]][1];
	*((word32*)b) ^= *((word32*)rk[ROUNDS][0]);
	*((word32*)(b+4)) ^= *((word32*)rk[ROUNDS][1]);
	*((word32*)(b+8)) ^= *((word32*)rk[ROUNDS][2]);
	*((word32*)(b+12)) ^= *((word32*)rk[ROUNDS][3]);

	return 0;
}

int rijndaelEncryptRound (word8 a[4][4], 
		word8 rk[MAXROUNDS+1][4][4], int rounds)
/* Encrypt only a certain number of rounds.
 * Only used in the Intermediate Value Known Answer Test.
 */
{
	int r;
   word8 temp[4][4];


	/* make number of rounds sane */
	if (rounds > ROUNDS) rounds = ROUNDS;

	*((word32*)a[0]) = *((word32*)a[0]) ^ *((word32*)rk[0][0]);
	*((word32*)a[1]) = *((word32*)a[1]) ^ *((word32*)rk[0][1]);
	*((word32*)a[2]) = *((word32*)a[2]) ^ *((word32*)rk[0][2]);
	*((word32*)a[3]) = *((word32*)a[3]) ^ *((word32*)rk[0][3]);

	for(r = 1; (r <= rounds) && (r < ROUNDS); r++) {
		*((word32*)temp[0]) = *((word32*)T1[a[0][0]])
           ^ *((word32*)T2[a[1][1]])
           ^ *((word32*)T3[a[2][2]]) 
           ^ *((word32*)T4[a[3][3]]);
		*((word32*)temp[1]) = *((word32*)T1[a[1][0]])
           ^ *((word32*)T2[a[2][1]])
           ^ *((word32*)T3[a[3][2]]) 
           ^ *((word32*)T4[a[0][3]]);
		*((word32*)temp[2]) = *((word32*)T1[a[2][0]])
           ^ *((word32*)T2[a[3][1]])
           ^ *((word32*)T3[a[0][2]]) 
           ^ *((word32*)T4[a[1][3]]);
		*((word32*)temp[3]) = *((word32*)T1[a[3][0]])
           ^ *((word32*)T2[a[0][1]])
           ^ *((word32*)T3[a[1][2]]) 
           ^ *((word32*)T4[a[2][3]]);
		*((word32*)a[0]) = *((word32*)temp[0]) ^ *((word32*)rk[r][0]);
		*((word32*)a[1]) = *((word32*)temp[1]) ^ *((word32*)rk[r][1]);
		*((word32*)a[2]) = *((word32*)temp[2]) ^ *((word32*)rk[r][2]);
		*((word32*)a[3]) = *((word32*)temp[3]) ^ *((word32*)rk[r][3]);
   }
	if (rounds == ROUNDS) {
   	/* last round is special */   
   	temp[0][0] = T1[a[0][0]][1];
   	temp[0][1] = T1[a[1][1]][1];
   	temp[0][2] = T1[a[2][2]][1]; 
   	temp[0][3] = T1[a[3][3]][1];
   	temp[1][0] = T1[a[1][0]][1];
   	temp[1][1] = T1[a[2][1]][1];
   	temp[1][2] = T1[a[3][2]][1]; 
   	temp[1][3] = T1[a[0][3]][1];
   	temp[2][0] = T1[a[2][0]][1];
   	temp[2][1] = T1[a[3][1]][1];
   	temp[2][2] = T1[a[0][2]][1]; 
   	temp[2][3] = T1[a[1][3]][1];
   	temp[3][0] = T1[a[3][0]][1];
   	temp[3][1] = T1[a[0][1]][1];
   	temp[3][2] = T1[a[1][2]][1]; 
   	temp[3][3] = T1[a[2][3]][1];
		*((word32*)a[0]) = *((word32*)temp[0]) ^ *((word32*)rk[ROUNDS][0]);
		*((word32*)a[1]) = *((word32*)temp[1]) ^ *((word32*)rk[ROUNDS][1]);
		*((word32*)a[2]) = *((word32*)temp[2]) ^ *((word32*)rk[ROUNDS][2]);
		*((word32*)a[3]) = *((word32*)temp[3]) ^ *((word32*)rk[ROUNDS][3]);
	}

	return 0;
}   


int rijndaelDecrypt (word8 a[16], word8 b[16], word8 rk[MAXROUNDS+1][4][4])
{
	int r;
   word8 temp[4][4];
	

    *((word32*)temp[0]) = *((word32*)a) ^ *((word32*)rk[ROUNDS][0]);
    *((word32*)temp[1]) = *((word32*)(a+4)) ^ *((word32*)rk[ROUNDS][1]);
    *((word32*)temp[2]) = *((word32*)(a+8)) ^ *((word32*)rk[ROUNDS][2]);
    *((word32*)temp[3]) = *((word32*)(a+12)) ^ *((word32*)rk[ROUNDS][3]);
    *((word32*)b) = *((word32*)T5[temp[0][0]])
           ^ *((word32*)T6[temp[3][1]])
           ^ *((word32*)T7[temp[2][2]]) 
           ^ *((word32*)T8[temp[1][3]]);
   *((word32*)(b+4)) = *((word32*)T5[temp[1][0]])
           ^ *((word32*)T6[temp[0][1]])
           ^ *((word32*)T7[temp[3][2]]) 
           ^ *((word32*)T8[temp[2][3]]);
   *((word32*)(b+8)) = *((word32*)T5[temp[2][0]])
           ^ *((word32*)T6[temp[1][1]])
           ^ *((word32*)T7[temp[0][2]]) 
           ^ *((word32*)T8[temp[3][3]]);
   *((word32*)(b+12)) = *((word32*)T5[temp[3][0]])
           ^ *((word32*)T6[temp[2][1]])
           ^ *((word32*)T7[temp[1][2]]) 
           ^ *((word32*)T8[temp[0][3]]);
   for(r = ROUNDS-1; r > 1; r--) {
		*((word32*)temp[0]) = *((word32*)b) ^ *((word32*)rk[r][0]);
		*((word32*)temp[1]) = *((word32*)(b+4)) ^ *((word32*)rk[r][1]);
		*((word32*)temp[2]) = *((word32*)(b+8)) ^ *((word32*)rk[r][2]);
		*((word32*)temp[3]) = *((word32*)(b+12)) ^ *((word32*)rk[r][3]);
		*((word32*)b) = *((word32*)T5[temp[0][0]])
           ^ *((word32*)T6[temp[3][1]])
           ^ *((word32*)T7[temp[2][2]]) 
           ^ *((word32*)T8[temp[1][3]]);
		*((word32*)(b+4)) = *((word32*)T5[temp[1][0]])
           ^ *((word32*)T6[temp[0][1]])
           ^ *((word32*)T7[temp[3][2]]) 
           ^ *((word32*)T8[temp[2][3]]);
		*((word32*)(b+8)) = *((word32*)T5[temp[2][0]])
           ^ *((word32*)T6[temp[1][1]])
           ^ *((word32*)T7[temp[0][2]]) 
           ^ *((word32*)T8[temp[3][3]]);
		*((word32*)(b+12)) = *((word32*)T5[temp[3][0]])
           ^ *((word32*)T6[temp[2][1]])
           ^ *((word32*)T7[temp[1][2]]) 
           ^ *((word32*)T8[temp[0][3]]);
   }
   /* last round is special */   
	*((word32*)temp[0]) = *((word32*)b) ^ *((word32*)rk[1][0]);
	*((word32*)temp[1]) = *((word32*)(b+4)) ^ *((word32*)rk[1][1]);
	*((word32*)temp[2]) = *((word32*)(b+8)) ^ *((word32*)rk[1][2]);
	*((word32*)temp[3]) = *((word32*)(b+12)) ^ *((word32*)rk[1][3]);
   b[0] = S5[temp[0][0]];
   b[1] = S5[temp[3][1]];
   b[2] = S5[temp[2][2]]; 
   b[3] = S5[temp[1][3]];
   b[4] = S5[temp[1][0]];
   b[5] = S5[temp[0][1]];
   b[6] = S5[temp[3][2]]; 
   b[7] = S5[temp[2][3]];
   b[8] = S5[temp[2][0]];
   b[9] = S5[temp[1][1]];
   b[10] = S5[temp[0][2]]; 
   b[11] = S5[temp[3][3]];
   b[12] = S5[temp[3][0]];
   b[13] = S5[temp[2][1]];
   b[14] = S5[temp[1][2]]; 
   b[15] = S5[temp[0][3]];
	*((word32*)b) ^= *((word32*)rk[0][0]);
	*((word32*)(b+4)) ^= *((word32*)rk[0][1]);
	*((word32*)(b+8)) ^= *((word32*)rk[0][2]);
	*((word32*)(b+12)) ^= *((word32*)rk[0][3]);

	return 0;
}


int rijndaelDecryptRound (word8 a[4][4],  
	word8 rk[MAXROUNDS+1][4][4], int rounds)
/* Decrypt only a certain number of rounds.
 * Only used in the Intermediate Value Known Answer Test.
 * Operations rearranged such that the intermediate values
 * of decryption correspond with the intermediate values
 * of encryption.
 */
{
	int r;
	

	/* make number of rounds sane */
	if (rounds > ROUNDS) rounds = ROUNDS;

        /* First the special round:
	 *   without InvMixColumn
	 *   with extra KeyAddition
	 */
	KeyAddition(a,rk[ROUNDS],4);
	Substitution(a,Si,4);
	ShiftRow(a,1,4);              
	
	/* ROUNDS-1 ordinary rounds
	 */
	for(r = ROUNDS-1; r > rounds; r--) {
		KeyAddition(a,rk[r],4);
		InvMixColumn(a,4);      
		Substitution(a,Si,4);
		ShiftRow(a,1,4);                
	}
	
	if (rounds == 0) {
		/* End with the extra key addition
		 */	
		KeyAddition(a,rk[0],4);
	}    

	return 0;
}
