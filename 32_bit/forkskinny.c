#include "forkskinny.h"

#include <string.h>
#include <stdint.h>

#include "api.h"

/* 7-bit round constant */
const uint8_t RC[87] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d, 0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73, 0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57, 0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d, 0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53, 0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15, 0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02, 0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71, 0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b, 0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25, 0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10};

#if CRYPTO_BLOCKSIZE == 16
void skinny_round_128(uint32_t state[4], uint32_t *keyCells, int i);
void skinny_round_inv_128(uint32_t state[4], uint32_t *keyCells, int i);
void advanceKeySchedule_128(uint32_t *keyCells);
void reverseKeySchedule_128(uint32_t *keyCells);

/* Note: we are rotating the cells right, which actually moves
   the values up closer to the MSB.  That is, we do a left shift
   on the word to rotate the cells in the word right */
#define skinny128_rotate_right(x, count) (x << count) | (x >> (32 - count))

void forkEncrypt_128(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s){

	uint32_t state[4], L[4], keyCells[TWEAKEY_BLOCKSIZE_RATIO*4];
	int i;

	/* Load state and key */
	memcpy(state,input,16);
	memcpy(keyCells,userkey,32);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	memcpy(&keyCells[8],&userkey[32],16);
#endif

	/* Before fork */
	for(i = 0; i < CRYPTO_NBROUNDS_BEFORE; i++)
		skinny_round_128(state, keyCells, i);

	/* Save fork if both output blocks are needed */
	if (s == ENC_BOTH)
		memcpy(L,state,16);

	/* Right branch (C1) */
	if ((s == ENC_C1) | (s == ENC_BOTH)){
		for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_128(state, keyCells, i);

		/* Move result to output buffer*/
		memcpy(C1,state,16);
	}

	/* Reinstall L as state if necessary */
	if (s == ENC_BOTH)
		memcpy(state,L,16);

	/* Left branch (C0) */
	if ((s == ENC_C0) | (s == ENC_BOTH)){

		/* Add branch constant */
		state[0] ^= 0x08040201;  state[1] ^= 0x82412010;  state[2] ^= 0x28140a05;  state[3] ^= 0x8844a251;

		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_128(state, keyCells, i);

		/* Move result to output buffer */
		memcpy(C0,state,16);
	}

	/* Null pointer for invalid outputs */
	if (s == ENC_C0)
		C1 = NULL;
	else if (s == ENC_C1)
		C0 = NULL;
}

void forkInvert_128(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s){

	uint32_t state[4], L[4], keyCells[TWEAKEY_BLOCKSIZE_RATIO*4];
	int i;

	/* Load state and key */
	memcpy(state,input,16);
	memcpy(keyCells,userkey,32);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	memcpy(&keyCells[8],&userkey[32],16);
#endif

	if (b == 1){

		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_128(keyCells);

		/* From C1 to fork*/
		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE; i--)
			skinny_round_inv_128(state, keyCells, i);

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,16);

		if ((s == INV_INVERSE) | (s == INV_BOTH)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_128(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(inverse,state,16);
		}

		/* Reinstall fork if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,16);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_128(keyCells);
		}

		if ((s == INV_OTHER) | (s == INV_BOTH)) {
			/* Set correct keyschedule */
			for (i=0; i<CRYPTO_NBROUNDS_AFTER; i++)
				advanceKeySchedule_128(keyCells);

			/* Add branch constant */
			state[0] ^= 0x08040201;  state[1] ^= 0x82412010;  state[2] ^= 0x28140a05;  state[3] ^= 0x8844a251;

			/* From fork to C0 */
			for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
				skinny_round_128(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(C_other,state,16);
		}
	}
	else {
		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_128(keyCells);

		/* From C0 to fork */
		for(i = CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i--)
			skinny_round_inv_128(state, keyCells, i);

		/* Add branch constant */
		state[0] ^= 0x08040201;  state[1] ^= 0x82412010;  state[2] ^= 0x28140a05;  state[3] ^= 0x8844a251;

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,16);

		/* Set correct keyschedule */
		for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
			reverseKeySchedule_128(keyCells);

		if ((s == INV_BOTH) | (s == INV_INVERSE)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_128(state, keyCells, i);

			/* Move result into output buffer */
			memcpy(inverse,state,16);
		}

		/* Reinstall fork and correct key schedule if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,16);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_128(keyCells);
		}

		if ((s == INV_BOTH) | (s == INV_OTHER)) {
			/* From fork to C1 */
			for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) // for i in range(nbRounds)
				skinny_round_128(state, keyCells, i);

			/* Move result to output buffer */
			memcpy(C_other,state,16);
		}
	}

	/* Null pointer for invalid outputs */
	if (s == INV_INVERSE)
		C_other = NULL;
	else if (s == INV_OTHER)
		inverse = NULL;
}


uint32_t skinny128_sbox(uint32_t x);
uint32_t skinny128_inv_sbox(uint32_t x);

void skinny_round_128(uint32_t state[4], uint32_t *keyCells, int i){
	uint32_t temp;

	/* SubCell */
	state[0] = skinny128_sbox(state[0]);
	state[1] = skinny128_sbox(state[1]);
	state[2] = skinny128_sbox(state[2]);
	state[3] = skinny128_sbox(state[3]);

	/* AddConstants */
	state[0] ^= ((uint32_t) (RC[i] & 0xf));
	state[0] ^= 0x00020000;	//Indicate tweak material
	state[1] ^= ((uint32_t) ((RC[i]>>4) & 0x7));
	state[2] ^= 0x00000002;

	/* AddKey  */
	state[0] ^= keyCells[0];	state[1] ^= keyCells[1]; 	//TK1
	state[0] ^= keyCells[4];	state[1] ^= keyCells[5];		//TK2
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	state[0] ^= keyCells[8];	state[1] ^= keyCells[9];	//TK3
#endif

	/* Advance TKS */
	advanceKeySchedule_128(keyCells);

	/* ShiftRows */
	state[1] = skinny128_rotate_right(state[1], 8);
	state[2] = skinny128_rotate_right(state[2], 16);
	state[3] = skinny128_rotate_right(state[3], 24);

	/* MixColumns */
	state[1] ^= state[2];
	state[2] ^= state[0];
	temp = state[3] ^ state[2];
	state[3] = state[2];
	state[2] = state[1];
	state[1] = state[0];
	state[0] = temp;

}

void skinny_round_inv_128(uint32_t state[4], uint32_t *keyCells, int i){
	uint32_t temp;

	/* MixColumn_inv */
	temp = state[3];
	state[3] = state[0];
	state[0] = state[1];
	state[1] = state[2];
	state[3] ^= temp;
	state[2] = temp ^ state[0];
	state[1] ^= state[2];

	/* ShiftRows_inv */
	state[1] = skinny128_rotate_right(state[1], 24);
	state[2] = skinny128_rotate_right(state[2], 16);
	state[3] = skinny128_rotate_right(state[3], 8);

	/* Reverse TKS */
	reverseKeySchedule_128(keyCells);

	/* AddKey_inv */
	state[0] ^= keyCells[0];	state[1] ^= keyCells[1];		//TK1
	state[0] ^= keyCells[4];	state[1] ^= keyCells[5];		//TK2
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	state[0] ^= keyCells[8];	state[1] ^= keyCells[9];	//TK3
#endif

	/* AddConstants	*/
	state[0] ^= ((uint32_t) (RC[i] & 0xf));
	state[0] ^= 0x00020000; // Indicate tweak material
	state[1] ^= ((uint32_t) ((RC[i]>>4) & 0x7));
	state[2] ^= 0x00000002;

	/* SubCell_inv */
	state[0] = skinny128_inv_sbox(state[0]);
	state[1] = skinny128_inv_sbox(state[1]);
	state[2] = skinny128_inv_sbox(state[2]);
	state[3] = skinny128_inv_sbox(state[3]);

}


uint32_t skinny128_sbox(uint32_t x)
{
	/* Original version from the specification is equivalent to:
	 *
	 * #define SBOX_MIX(x)
	 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
	 * #define SBOX_SWAP(x)
	 *     (((x) & 0xF9F9F9F9U) |
	 *     (((x) >> 1) & 0x02020202U) |
	 *     (((x) << 1) & 0x04040404U))
	 * #define SBOX_PERMUTE(x)
	 *     ((((x) & 0x01010101U) << 2) |
	 *      (((x) & 0x06060606U) << 5) |
	 *      (((x) & 0x20202020U) >> 5) |
	 *      (((x) & 0xC8C8C8C8U) >> 2) |
	 *      (((x) & 0x10101010U) >> 1))
	 *
	 * x = SBOX_MIX(x);
	 * x = SBOX_PERMUTE(x);
	 * x = SBOX_MIX(x);
	 * x = SBOX_PERMUTE(x);
	 * x = SBOX_MIX(x);
	 * x = SBOX_PERMUTE(x);
	 * x = SBOX_MIX(x);
	 * return SBOX_SWAP(x);
	 *
	 * However, we can mix the bits in their original positions and then
	 * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
	 * final permutation.  This reduces the number of shift operations.
	 *
	 * We can further reduce the number of NOT operations from 7 to 2
	 * using the technique from https://github.com/kste/skinny_avx to
	 * convert NOR-XOR operations into AND-XOR operations by converting
	 * the S-box into its NOT-inverse.
	 */
	uint32_t y;

	/* Mix the bits */
	x = ~x;
	x ^= (((x >> 2) & (x >> 3)) & 0x11111111U);
	y  = (((x << 5) & (x << 1)) & 0x20202020U);
	x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y;
	y  = (((x << 2) & (x << 1)) & 0x80808080U);
	x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y;
	y  = (((x >> 5) & (x << 1)) & 0x04040404U);
	x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
	x = ~x;

	/* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [2 7 6 1 3 0 4 5] */
	return 	((x & 0x08080808U) << 1) |
			((x & 0x32323232U) << 2) |
			((x & 0x01010101U) << 5) |
			((x & 0x80808080U) >> 6) |
			((x & 0x40404040U) >> 4) |
			((x & 0x04040404U) >> 2);
}

uint32_t skinny128_inv_sbox(uint32_t x)
{
	/* Original version from the specification is equivalent to:
	 *
	 * #define SBOX_MIX(x)
	 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
	 * #define SBOX_SWAP(x)
	 *     (((x) & 0xF9F9F9F9U) |
	 *     (((x) >> 1) & 0x02020202U) |
	 *     (((x) << 1) & 0x04040404U))
	 * #define SBOX_PERMUTE_INV(x)
	 *     ((((x) & 0x08080808U) << 1) |
	 *      (((x) & 0x32323232U) << 2) |
	 *      (((x) & 0x01010101U) << 5) |
	 *      (((x) & 0xC0C0C0C0U) >> 5) |
	 *      (((x) & 0x04040404U) >> 2))
	 *
	 * x = SBOX_SWAP(x);
	 * x = SBOX_MIX(x);
	 * x = SBOX_PERMUTE_INV(x);
	 * x = SBOX_MIX(x);
	 * x = SBOX_PERMUTE_INV(x);
	 * x = SBOX_MIX(x);
	 * x = SBOX_PERMUTE_INV(x);
	 * return SBOX_MIX(x);
	 *
	 * However, we can mix the bits in their original positions and then
	 * delay the SBOX_PERMUTE_INV and SBOX_SWAP steps to be performed with one
	 * final permutation.  This reduces the number of shift operations.
	 */
	uint32_t y;

	/* Mix the bits */
	x = ~x;
	y  = (((x >> 1) & (x >> 3)) & 0x01010101U);
	x ^= (((x >> 2) & (x >> 3)) & 0x10101010U) ^ y;
	y  = (((x >> 6) & (x >> 1)) & 0x02020202U);
	x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
	y  = (((x << 2) & (x << 1)) & 0x80808080U);
	x ^= (((x >> 1) & (x << 2)) & 0x04040404U) ^ y;
	y  = (((x << 5) & (x << 1)) & 0x20202020U);
	x ^= (((x << 4) & (x << 5)) & 0x40404040U) ^ y;
	x = ~x;

	/* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [5 3 0 4 6 7 2 1] */
	return  ((x & 0x01010101U) << 2) |
			((x & 0x04040404U) << 4) |
			((x & 0x02020202U) << 6) |
			((x & 0x20202020U) >> 5) |
			((x & 0xC8C8C8C8U) >> 2) |
			((x & 0x10101010U) >> 1);
}


#define skinny128_LFSR2(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x << 1) & 0xFEFEFEFEU) ^ \
             (((_x >> 7) ^ (_x >> 5)) & 0x01010101U); \
    } while (0)


#define skinny128_LFSR3(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x >> 1) & 0x7F7F7F7FU) ^ \
              (((_x << 7) ^ (_x << 1)) & 0x80808080U); \
    } while (0)

/* LFSR2 and LFSR3 are inverses of each other */
#define skinny128_inv_LFSR2(x) skinny128_LFSR3(x)
#define skinny128_inv_LFSR3(x) skinny128_LFSR2(x)

#define skinny128_permute_tk(tk) \
    do { \
        /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
        uint32_t row2 = tk[2]; \
        uint32_t row3 = tk[3]; \
        tk[2] = tk[0]; \
        tk[3] = tk[1]; \
        row3 = (row3 << 16) | (row3 >> 16); \
        tk[0] = ((row2 >>  8) & 0x000000FFU) | \
                ((row2 << 16) & 0x00FF0000U) | \
                ( row3        & 0xFF00FF00U); \
        tk[1] = ((row2 >> 16) & 0x000000FFU) | \
                 (row2        & 0xFF000000U) | \
                ((row3 <<  8) & 0x0000FF00U) | \
                ( row3        & 0x00FF0000U); \
    } while (0)

#define skinny128_inv_permute_tk(tk) \
    do { \
        /* PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1] */ \
        uint32_t row0 = tk[0]; \
        uint32_t row1 = tk[1]; \
        tk[0] = tk[2]; \
        tk[1] = tk[3]; \
        tk[2] = ((row0 >> 16) & 0x000000FFU) | \
                ((row0 <<  8) & 0x0000FF00U) | \
                ((row1 << 16) & 0x00FF0000U) | \
                ( row1        & 0xFF000000U); \
        tk[3] = ((row0 >> 16) & 0x0000FF00U) | \
                ((row0 << 16) & 0xFF000000U) | \
                ((row1 >> 16) & 0x000000FFU) | \
                ((row1 <<  8) & 0x00FF0000U); \
    } while (0)

/* ADVANCE THE KEY SCHEDULE ONCE */
void advanceKeySchedule_128(uint32_t *keyCells)
{
	// update the subtweakey states with the permutation
	skinny128_permute_tk(keyCells);
	skinny128_permute_tk((&keyCells[4]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_permute_tk((&keyCells[8]));
#endif

	//update the subtweakey states with the LFSRs
	//TK2
	skinny128_LFSR2(keyCells[4]);
	skinny128_LFSR2(keyCells[5]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_LFSR3(keyCells[8]);
	skinny128_LFSR3(keyCells[9]);
#endif
}

/* REVERSE THE KEY SCHEDULE ONCE (used in decryption and reconstruction) */
void reverseKeySchedule_128(uint32_t *keyCells){

	// update the subtweakey states with the permutation
	skinny128_inv_permute_tk(keyCells);
	skinny128_inv_permute_tk((&keyCells[4]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny128_inv_permute_tk((&keyCells[8]));
#endif

	// update the subtweakey states with the LFSRs
	//TK2
	skinny128_inv_LFSR2(keyCells[6]);
	skinny128_inv_LFSR2(keyCells[7]);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	skinny128_inv_LFSR3(keyCells[10]);
	skinny128_inv_LFSR3(keyCells[11]);
#endif

}

#else

void skinny_round_64(uint16_t state[4], uint16_t *keyCells, int i);
void skinny_round_inv_64(uint16_t state[4], uint16_t *keyCells, int i);
void advanceKeySchedule_64(uint16_t *keyCells);
void reverseKeySchedule_64(uint16_t *keyCells);

#define load_16(src)  ((((uint16_t)((src)[0])) << 8) | ((uint16_t)((src)[1])))

#define store_16(dest, x) do { \
        uint16_t _x = (x); \
        (dest)[0] = (uint8_t)(_x >> 8); \
        (dest)[1] = (uint8_t)_x; \
    } while (0)

void forkEncrypt_64(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s){

	uint16_t state[4], L[4], keyCells[TWEAKEY_BLOCKSIZE_RATIO*4];
	int i;

	/* Load state and key */
	state[0] = load_16(input);
	state[1] = load_16(input + 2);
	state[2] = load_16(input + 4);
	state[3] = load_16(input + 6);
	keyCells[0] = load_16(userkey);
	keyCells[1] = load_16(userkey + 2);
	keyCells[2] = load_16(userkey + 4);
	keyCells[3] = load_16(userkey + 6);
	keyCells[4] = load_16(userkey + 8);
	keyCells[5] = load_16(userkey + 10);
	keyCells[6] = load_16(userkey + 12);
	keyCells[7] = load_16(userkey + 14);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	keyCells[8] = load_16(userkey + 16);
	keyCells[9] = load_16(userkey + 18);
	keyCells[10] = load_16(userkey + 20);
	keyCells[11] = load_16(userkey + 22);
#endif

	/* Before fork */
	for(i = 0; i < CRYPTO_NBROUNDS_BEFORE; i++)
		skinny_round_64(state, keyCells, i);

	/* Save fork if both output blocks are needed */
	if (s == ENC_BOTH)
		memcpy(L,state,8);

	/* Right branch (C1) */
	if ((s == ENC_C1) | (s == ENC_BOTH)){
		for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_64(state, keyCells, i);

		/* Move result to output buffer*/
		store_16(C1  , state[0]);
		store_16(C1+2, state[1]);
		store_16(C1+4, state[2]);
		store_16(C1+6, state[3]);
	}

	/* Reinstall L as state if necessary */
	if (s == ENC_BOTH)
		memcpy(state,L,8);

	/* Left branch (C0) */
	if ((s == ENC_C0) | (s == ENC_BOTH)){

		/* Add branch constant */
		state[0] ^= 0x1249U;  state[1] ^= 0x36daU;  state[2] ^= 0x5b7fU;  state[3] ^= 0xec81U;

		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			skinny_round_64(state, keyCells, i);

		/* Move result to output buffer */
		store_16(C0  , state[0]);
		store_16(C0+2, state[1]);
		store_16(C0+4, state[2]);
		store_16(C0+6, state[3]);
	}

	/* Null pointer for invalid outputs */
	if (s == ENC_C0)
		C1 = NULL;
	else if (s == ENC_C1)
		C0 = NULL;

}

void forkInvert_64(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s){

	uint16_t state[4], L[4], keyCells[TWEAKEY_BLOCKSIZE_RATIO*4];
	int i;

	/* Load state and key */
	state[0] = load_16(input);
	state[1] = load_16(input + 2);
	state[2] = load_16(input + 4);
	state[3] = load_16(input + 6);
	keyCells[0] = load_16(userkey);
	keyCells[1] = load_16(userkey + 2);
	keyCells[2] = load_16(userkey + 4);
	keyCells[3] = load_16(userkey + 6);
	keyCells[4] = load_16(userkey + 8);
	keyCells[5] = load_16(userkey + 10);
	keyCells[6] = load_16(userkey + 12);
	keyCells[7] = load_16(userkey + 14);
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	keyCells[8] = load_16(userkey + 16);
	keyCells[9] = load_16(userkey + 18);
	keyCells[10] = load_16(userkey + 20);
	keyCells[11] = load_16(userkey + 22);
#endif

	if (b == 1){

		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_64(keyCells);

		/* From C1 to fork*/
		for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE; i--)
			skinny_round_inv_64(state, keyCells, i);

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,8);

		if ((s == INV_INVERSE) | (s == INV_BOTH)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_64(state, keyCells, i);

			/* Move result to output buffer */
			store_16(inverse  , state[0]);
			store_16(inverse+2, state[1]);
			store_16(inverse+4, state[2]);
			store_16(inverse+6, state[3]);
		}

		/* Reinstall fork if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,8);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_64(keyCells);
		}

		if ((s == INV_OTHER) | (s == INV_BOTH)) {
			/* Set correct keyschedule */
			for (i=0; i<CRYPTO_NBROUNDS_AFTER; i++)
				advanceKeySchedule_64(keyCells);

			/* Add branch constant */
			state[0] ^= 0x1249U;  state[1] ^= 0x36daU;  state[2] ^= 0x5b7fU;  state[3] ^= 0xec81U;

			/* From fork to C0 */
			for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
				skinny_round_64(state, keyCells, i);

			/* Move result to output buffer */
			store_16(C_other  , state[0]);
			store_16(C_other+2, state[1]);
			store_16(C_other+4, state[2]);
			store_16(C_other+6, state[3]);
		}
	}
	else {
		/* Advance the key schedule in order to decrypt */
		for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
			advanceKeySchedule_64(keyCells);

		/* From C0 to fork */
		for(i = CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i--)
			skinny_round_inv_64(state, keyCells, i);

		/* Add branch constant */
		state[0] ^= 0x1249U;  state[1] ^= 0x36daU;  state[2] ^= 0x5b7fU;  state[3] ^= 0xec81U;

		/* Save fork if both blocks are needed */
		if (s == INV_BOTH)
			memcpy(L,state,8);

		/* Set correct keyschedule */
		for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
			reverseKeySchedule_64(keyCells);

		if ((s == INV_BOTH) | (s == INV_INVERSE)) {
			/* From fork to M */
			for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
				skinny_round_inv_64(state, keyCells, i);

			/* Move result into output buffer */
			store_16(inverse  , state[0]);
			store_16(inverse+2, state[1]);
			store_16(inverse+4, state[2]);
			store_16(inverse+6, state[3]);
		}

		/* Reinstall fork and correct key schedule if necessary */
		if (s == INV_BOTH) {
			memcpy(state,L,8);

			for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
				advanceKeySchedule_64(keyCells);
		}

		if ((s == INV_BOTH) | (s == INV_OTHER)) {
			/* From fork to C1 */
			for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) // for i in range(nbRounds)
				skinny_round_64(state, keyCells, i);

			/* Move result to output buffer */
			store_16(C_other  , state[0]);
			store_16(C_other+2, state[1]);
			store_16(C_other+4, state[2]);
			store_16(C_other+6, state[3]);		
			}
	}

	/* Null pointer for invalid outputs */
	if (s == INV_INVERSE)
		C_other = NULL;
	else if (s == INV_OTHER)
		inverse = NULL;
}


/* Note: we are rotating the cells right, which actually moves
   the values up closer to the MSB.  That is, we do a left shift
   on the word to rotate the cells in the word right */
#define skinny64_rotate_right(x, count) (x >> count) | (x << (16 - count))

uint16_t skinny64_sbox(uint16_t x);
uint16_t skinny64_inv_sbox(uint16_t x);

void skinny_round_64(uint16_t state[4], uint16_t *keyCells, int i){
	uint16_t temp;

	/* SubCell */
	state[0] = skinny64_sbox(state[0]); state[1] = skinny64_sbox(state[1]); state[2] = skinny64_sbox(state[2]); state[3] = skinny64_sbox(state[3]);

	/* AddConstants */
	state[0] ^=  ((RC[i] & 0xf) << 12);
	state[0] ^= 0x0020;	//Indicate tweak material
	state[1] ^= ((RC[i] & 0x70) << 8);
	state[2] ^= 0x2000;

	/* AddKey  */
	state[0] ^= keyCells[0];	state[1] ^= keyCells[1]; 	//TK1
	state[0] ^= keyCells[4];	state[1] ^= keyCells[5];		//TK2
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	state[0] ^= keyCells[8];	state[1] ^= keyCells[9];	//TK3
#endif

	/* Advance TKS */
	advanceKeySchedule_64(keyCells);

	/* ShiftRows */
	state[1] = skinny64_rotate_right(state[1], 4);
	state[2] = skinny64_rotate_right(state[2], 8);
	state[3] = skinny64_rotate_right(state[3], 12);

	/* MixColumns */
	state[1] ^= state[2];
	state[2] ^= state[0];
	temp = state[3] ^ state[2];
	state[3] = state[2];
	state[2] = state[1];
	state[1] = state[0];
	state[0] = temp;

}

void skinny_round_inv_64(uint16_t state[4], uint16_t *keyCells, int i){
	uint16_t temp;

	/* MixColumn_inv */
	temp = state[3];
	state[3] = state[0];
	state[0] = state[1];
	state[1] = state[2];
	state[3] ^= temp;
	state[2] = temp ^ state[0];
	state[1] ^= state[2];

	/* ShiftRows_inv */
	state[1] = skinny64_rotate_right(state[1], 12);
	state[2] = skinny64_rotate_right(state[2], 8);
	state[3] = skinny64_rotate_right(state[3], 4);

	/* Reverse TKS */
	reverseKeySchedule_64(keyCells);

	/* AddKey_inv */
	state[0] ^= keyCells[0];	state[1] ^= keyCells[1];		//TK1
	state[0] ^= keyCells[4];	state[1] ^= keyCells[5];		//TK2
#if TWEAKEY_BLOCKSIZE_RATIO == 3
	state[0] ^= keyCells[8];	state[1] ^= keyCells[9];	//TK3
#endif

	/* AddConstants */
	state[0] ^=  ((RC[i] & 0xf) << 12);
	state[0] ^= 0x0020;	//Indicate tweak material
	state[1] ^= ((RC[i] & 0x70) << 8);
	state[2] ^= 0x2000;

	/* SubCell_inv */
	state[0] = skinny64_inv_sbox(state[0]); state[1] = skinny64_inv_sbox(state[1]); state[2] = skinny64_inv_sbox(state[2]); state[3] = skinny64_inv_sbox(state[3]);

}


uint16_t skinny64_sbox(uint16_t x){
	x = ~x;
	x = (((x >> 3) & (x >> 2)) & 0x1111U) ^ x;
	x = (((x << 1) & (x << 2)) & 0x8888U) ^ x;
	x = (((x << 1) & (x << 2)) & 0x4444U) ^ x;
	x = (((x >> 2) & (x << 1)) & 0x2222U) ^ x;
	x = ~x;
	return ((x >> 1) & 0x7777U) | ((x << 3) & 0x8888U);
}

uint16_t skinny64_inv_sbox(uint16_t x){
	x = ~x;
	x = (((x >> 3) & (x >> 2)) & 0x1111U) ^ x;
	x = (((x << 1) & (x >> 2)) & 0x2222U) ^ x;
	x = (((x << 1) & (x << 2)) & 0x4444U) ^ x;
	x = (((x << 1) & (x << 2)) & 0x8888U) ^ x;
	x = ~x;
	return ((x << 1) & 0xEEEEU) | ((x >> 3) & 0x1111U);
}

#define permute_tk_64(tk) \
	do { \
	/* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
	uint16_t row2 = tk[2]; \
	uint16_t row3 = tk[3]; \
	tk[2] = tk[0]; \
	tk[3] = tk[1]; \
	row3 = (row3 << 8) | (row3 >> 8); \
	tk[0] = ((row2 << 4) & 0xF000U) | \
			((row2 >> 8) & 0x00F0U) | \
			( row3       & 0x0F0FU); \
	tk[1] = ((row2 << 8) & 0xF000U) | \
			((row3 >> 4) & 0x0F00U) | \
			( row3       & 0x00F0U) | \
			( row2       & 0x000FU); \
	} while(0)


#define inv_permute_tk_64(tk) \
	do { \
	/* PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1] */ \
	uint16_t row0 = tk[0]; \
	uint16_t row1 = tk[1]; \
	tk[0] = tk[2]; \
	tk[1] = tk[3]; \
	tk[2] = ((row0 << 8) & 0xF000U) | \
			((row0 >> 4) & 0x0F00U) | \
			((row1 >> 8) & 0x00F0U) | \
			( row1       & 0x000FU); \
	tk[3] = ((row1 << 8) & 0xF000U) | \
			((row0 << 8) & 0x0F00U) | \
			((row1 >> 4) & 0x00F0U) | \
			((row0 >> 8) & 0x000FU); \
	} while(0)

#define skinny64_LFSR2(x) \
    do { \
        uint16_t _x = (x); \
        (x) = ((_x << 1) & 0xEEEEU) ^ (((_x >> 3) ^ (_x >> 2)) & 0x1111U); \
    } while (0)

#define skinny64_LFSR3(x) \
    do { \
        uint16_t _x = (x); \
        (x) = ((_x >> 1) & 0x7777U) ^ ((_x ^ (_x << 3)) & 0x8888U); \
    } while (0)

/* LFSR2 and LFSR3 are inverses of each other */
#define skinny64_inv_LFSR2(x) skinny64_LFSR3(x)
#define skinny64_inv_LFSR3(x) skinny64_LFSR2(x)

/* ADVANCE THE KEY SCHEDULE ONCE */
void advanceKeySchedule_64(uint16_t *keyCells){
	// update the subtweakey states with the permutation
	permute_tk_64(keyCells);
	permute_tk_64((&keyCells[4]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	permute_tk_64((&keyCells[8]));
#endif

	//update the subtweakey states with the LFSRs
	//TK2
	skinny64_LFSR2(keyCells[4]);
	skinny64_LFSR2(keyCells[5]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny64_LFSR3(keyCells[8]);
	skinny64_LFSR3(keyCells[9]);
#endif
}

/* REVERSE THE KEY SCHEDULE ONCE (used in decryption and reconstruction) */
void reverseKeySchedule_64(uint16_t *keyCells){
	//update the subtweakey states with the LFSRs
	//TK2
	skinny64_inv_LFSR2(keyCells[4]);
	skinny64_inv_LFSR2(keyCells[5]);
	//TK3
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	skinny64_inv_LFSR3(keyCells[8]);
	skinny64_inv_LFSR3(keyCells[9]);
#endif

	// update the subtweakey states with the permutation
	inv_permute_tk_64(keyCells);
	inv_permute_tk_64((&keyCells[4]));
#if TWEAKEY_BLOCKSIZE_RATIO ==3
	inv_permute_tk_64((&keyCells[8]));
#endif

}
#endif

