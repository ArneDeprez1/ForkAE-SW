/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "internal-forkskinny.h"
#include "internal-skinnyutil.h"

/**
 * \brief 7-bit round constants for all ForkSkinny block ciphers.
 */
static unsigned char const RC[87] = {0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d, 0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73, 0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57, 0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d, 0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53, 0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15, 0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02, 0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71, 0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b,0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25, 0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10};

static const uint32_t T[256] = {0x65656565, 0x4c4c4c4c, 0x6a6a6a6a, 0x42424242, 0x4b4b4b4b, 0x63636363, 0x43434343, 0x6b6b6b6b, 0x55555555, 0x75757575, 0x5a5a5a5a, 0x7a7a7a7a, 0x53535353, 0x73737373, 0x5b5b5b5b, 0x7b7b7b7b, 0x35353535, 0x8c8c8c8c, 0x3a3a3a3a, 0x81818181, 0x89898989, 0x33333333, 0x80808080, 0x3b3b3b3b, 0x95959595, 0x25252525, 0x98989898, 0x2a2a2a2a, 0x90909090, 0x23232323, 0x99999999, 0x2b2b2b2b, 0xe5e5e5e5, 0xcccccccc, 0xe8e8e8e8, 0xc1c1c1c1, 0xc9c9c9c9, 0xe0e0e0e0, 0xc0c0c0c0, 0xe9e9e9e9, 0xd5d5d5d5, 0xf5f5f5f5, 0xd8d8d8d8, 0xf8f8f8f8, 0xd0d0d0d0, 0xf0f0f0f0, 0xd9d9d9d9, 0xf9f9f9f9, 0xa5a5a5a5, 0x1c1c1c1c, 0xa8a8a8a8, 0x12121212, 0x1b1b1b1b, 0xa0a0a0a0, 0x13131313, 0xa9a9a9a9, 0x05050505, 0xb5b5b5b5, 0x0a0a0a0a, 0xb8b8b8b8, 0x03030303, 0xb0b0b0b0, 0x0b0b0b0b, 0xb9b9b9b9, 0x32323232, 0x88888888, 0x3c3c3c3c, 0x85858585, 0x8d8d8d8d, 0x34343434, 0x84848484, 0x3d3d3d3d, 0x91919191, 0x22222222, 0x9c9c9c9c, 0x2c2c2c2c, 0x94949494, 0x24242424, 0x9d9d9d9d, 0x2d2d2d2d, 0x62626262, 0x4a4a4a4a, 0x6c6c6c6c, 0x45454545, 0x4d4d4d4d, 0x64646464, 0x44444444, 0x6d6d6d6d, 0x52525252, 0x72727272, 0x5c5c5c5c, 0x7c7c7c7c, 0x54545454, 0x74747474, 0x5d5d5d5d, 0x7d7d7d7d, 0xa1a1a1a1, 0x1a1a1a1a, 0xacacacac, 0x15151515, 0x1d1d1d1d, 0xa4a4a4a4, 0x14141414, 0xadadadad, 0x02020202, 0xb1b1b1b1, 0x0c0c0c0c, 0xbcbcbcbc, 0x04040404, 0xb4b4b4b4, 0x0d0d0d0d, 0xbdbdbdbd, 0xe1e1e1e1, 0xc8c8c8c8, 0xecececec, 0xc5c5c5c5, 0xcdcdcdcd, 0xe4e4e4e4, 0xc4c4c4c4, 0xedededed, 0xd1d1d1d1, 0xf1f1f1f1, 0xdcdcdcdc, 0xfcfcfcfc, 0xd4d4d4d4, 0xf4f4f4f4, 0xdddddddd, 0xfdfdfdfd, 0x36363636, 0x8e8e8e8e, 0x38383838, 0x82828282, 0x8b8b8b8b, 0x30303030, 0x83838383, 0x39393939, 0x96969696, 0x26262626, 0x9a9a9a9a, 0x28282828, 0x93939393, 0x20202020, 0x9b9b9b9b, 0x29292929, 0x66666666, 0x4e4e4e4e, 0x68686868, 0x41414141, 0x49494949, 0x60606060, 0x40404040, 0x69696969, 0x56565656, 0x76767676, 0x58585858, 0x78787878, 0x50505050, 0x70707070, 0x59595959, 0x79797979, 0xa6a6a6a6, 0x1e1e1e1e, 0xaaaaaaaa, 0x11111111, 0x19191919, 0xa3a3a3a3, 0x10101010, 0xabababab, 0x06060606, 0xb6b6b6b6, 0x08080808, 0xbabababa, 0x00000000, 0xb3b3b3b3, 0x09090909, 0xbbbbbbbb, 0xe6e6e6e6, 0xcececece, 0xeaeaeaea, 0xc2c2c2c2, 0xcbcbcbcb, 0xe3e3e3e3, 0xc3c3c3c3, 0xebebebeb, 0xd6d6d6d6, 0xf6f6f6f6, 0xdadadada, 0xfafafafa, 0xd3d3d3d3, 0xf3f3f3f3, 0xdbdbdbdb, 0xfbfbfbfb, 0x31313131, 0x8a8a8a8a, 0x3e3e3e3e, 0x86868686, 0x8f8f8f8f, 0x37373737, 0x87878787, 0x3f3f3f3f, 0x92929292, 0x21212121, 0x9e9e9e9e, 0x2e2e2e2e, 0x97979797, 0x27272727, 0x9f9f9f9f, 0x2f2f2f2f, 0x61616161, 0x48484848, 0x6e6e6e6e, 0x46464646, 0x4f4f4f4f, 0x67676767, 0x47474747, 0x6f6f6f6f, 0x51515151, 0x71717171, 0x5e5e5e5e, 0x7e7e7e7e, 0x57575757, 0x77777777, 0x5f5f5f5f, 0x7f7f7f7f, 0xa2a2a2a2, 0x18181818, 0xaeaeaeae, 0x16161616, 0x1f1f1f1f, 0xa7a7a7a7, 0x17171717, 0xafafafaf, 0x01010101, 0xb2b2b2b2, 0x0e0e0e0e, 0xbebebebe, 0x07070707, 0xb7b7b7b7, 0x0f0f0f0f, 0xbfbfbfbf, 0xe2e2e2e2, 0xcacacaca, 0xeeeeeeee, 0xc6c6c6c6, 0xcfcfcfcf, 0xe7e7e7e7, 0xc7c7c7c7, 0xefefefef, 0xd2d2d2d2, 0xf2f2f2f2, 0xdededede, 0xfefefefe, 0xd7d7d7d7, 0xf7f7f7f7, 0xdfdfdfdf, 0xffffffff};

static const uint32_t AC_column0[87] = {0x1000101, 0x3000303, 0x7000707, 0xf000f0f, 0xf000f0f, 0xf000f0f, 0xe000e0e, 0xd000d0d, 0xb000b0b, 0x7000707, 0xf000f0f, 0xf000f0f, 0xe000e0e, 0xc000c0c, 0x9000909, 0x3000303, 0x7000707, 0xf000f0f, 0xe000e0e, 0xd000d0d, 0xa000a0a, 0x5000505, 0xb000b0b, 0x7000707, 0xe000e0e, 0xc000c0c, 0x8000808, 0x0, 0x1000101, 0x3000303, 0x6000606, 0xd000d0d, 0xb000b0b, 0x7000707, 0xe000e0e, 0xd000d0d, 0xa000a0a, 0x4000404, 0x9000909, 0x3000303, 0x6000606, 0xc000c0c, 0x8000808, 0x1000101, 0x2000202, 0x5000505, 0xa000a0a, 0x5000505, 0xb000b0b, 0x6000606, 0xc000c0c, 0x8000808, 0x0, 0x0, 0x1000101, 0x2000202, 0x5000505, 0xb000b0b, 0x7000707, 0xf000f0f, 0xe000e0e, 0xc000c0c, 0x8000808, 0x1000101, 0x3000303, 0x7000707, 0xe000e0e, 0xd000d0d, 0xb000b0b, 0x6000606, 0xd000d0d, 0xb000b0b, 0x6000606, 0xc000c0c, 0x9000909, 0x2000202, 0x4000404, 0x9000909, 0x2000202, 0x5000505, 0xa000a0a, 0x4000404, 0x9000909, 0x2000202, 0x4000404, 0x8000808, 0x0};
static const uint32_t AC_column1[87] = {0x0, 0x0, 0x0, 0x0, 0x10000, 0x30000, 0x70000, 0x70000, 0x70000, 0x70000, 0x60000, 0x50000, 0x30000, 0x70000, 0x70000, 0x70000, 0x60000, 0x40000, 0x10000, 0x30000, 0x70000, 0x70000, 0x60000, 0x50000, 0x20000, 0x50000, 0x30000, 0x70000, 0x60000, 0x40000, 0x0, 0x0, 0x10000, 0x30000, 0x60000, 0x50000, 0x30000, 0x70000, 0x60000, 0x50000, 0x20000, 0x40000, 0x10000, 0x30000, 0x60000, 0x40000, 0x0, 0x10000, 0x20000, 0x50000, 0x20000, 0x50000, 0x30000, 0x60000, 0x40000, 0x0, 0x0, 0x0, 0x10000, 0x20000, 0x50000, 0x30000, 0x70000, 0x70000, 0x60000, 0x40000, 0x0, 0x10000, 0x30000, 0x70000, 0x60000, 0x50000, 0x30000, 0x60000, 0x50000, 0x30000, 0x60000, 0x40000, 0x10000, 0x20000, 0x40000, 0x10000, 0x20000, 0x50000, 0x20000, 0x40000, 0x10000};


/**
 * \brief Number of rounds of ForkSkinny-128-256 before forking.
 */
#define FORKSKINNY_128_256_ROUNDS_BEFORE 21

/**
 * \brief Number of rounds of ForkSkinny-128-256 after forking.
 */
#define FORKSKINNY_128_256_ROUNDS_AFTER 27

/**
 * \brief State information for ForkSkinny-128-256.
 */
typedef struct
{
    uint32_t TK1[4];        /**< First part of the tweakey */
    uint32_t TK2[4];        /**< Second part of the tweakey */
    uint32_t S[4];          /**< Current block state */

} forkskinny_128_256_state_t;

#define TK_to_column_256(columns, state) \
	do { \
		uint32_t TK0 = state->TK1[0] ^ state->TK2[0];\
		uint32_t TK1 = state->TK1[1] ^ state->TK2[1]; \
		uint32_t tk00 = TK0 & 0xFF; \
		uint32_t tk01 = TK0 & 0xFF00;\
		uint32_t tk02 = TK0 & 0xFF0000;\
		uint32_t tk03 = TK0 & 0xFF000000;\
		columns[0] = tk00 << 24 | (TK1 & 0xFF000000) >> 8 	| tk00 << 8  | tk00; \
		columns[1] = tk01 << 16 | (TK1 & 0xFF) 	   << 16	| tk01  	 | tk01 >> 8; \
		columns[2] = tk02 << 8  | (TK1 & 0xFF00)     << 8 	| tk02 >> 8  | tk02 >> 16; \
		columns[3] = tk03       | (TK1 & 0xFF0000)  		| tk03 >> 16 | tk03 >> 24; \
	} while(0)

/**
 * \brief Applies one round of ForkSkinny-128-256.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_round_table
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3;
    uint32_t tk_columns[4];

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    TK_to_column_256(tk_columns, state);

    state->S[0] = (T[s0 & 0xff]&0xff00ffff) ^ (T[(s3>>8) & 0xff]&0x00ff0000) ^ (T[(s2>>16) & 0xff]&0xffff00ff) ^ (T[(s1>>24)]&0xff) ^ tk_columns[0] ^ AC_column0[round];
    state->S[1] = (T[s1 & 0xff]&0xff00ffff) ^ (T[(s0>>8) & 0xff]&0x00ff0000) ^ (T[(s3>>16) & 0xff]&0xffff00ff) ^ (T[(s2>>24)]&0xff) ^ tk_columns[1] ^ AC_column1[round];
    state->S[2] = (T[s2 & 0xff]&0xff00ffff) ^ (T[(s1>>8) & 0xff]&0x00ff0000) ^ (T[(s0>>16) & 0xff]&0xffff00ff) ^ (T[(s3>>24)]&0xff) ^ tk_columns[2] ^ 0x00020200;
    state->S[3] = (T[s3 & 0xff]&0xff00ffff) ^ (T[(s2>>8) & 0xff]&0x00ff0000) ^ (T[(s1>>16) & 0xff]&0xffff00ff) ^ (T[(s0>>24)]&0xff) ^ tk_columns[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
}

#define load_column(dest, src) \
	do { \
		dest[0] = (src[12]) << 24 | (src[8])  << 16 | (src[4]) << 8 | (src[0]); \
		dest[1] = (src[13]) << 24 | (src[9])  << 16 | (src[5]) << 8 | (src[1]); \
		dest[2] = (src[14]) << 24 | (src[10]) << 16 | (src[6]) << 8 | (src[2]); \
		dest[3] = (src[15]) << 24 | (src[11]) << 16 | (src[7]) << 8 | (src[3]); \
	} while(0)

#define store_column(dest, src) \
	do { \
		dest[0] = (uint8_t) (src[0]); 	 dest[1] = (uint8_t) (src[1]); 	  dest[2] = (uint8_t) (src[2]);    dest[3] = (uint8_t) (src[3]); \
		dest[4] = (uint8_t) (src[0]>>8); dest[5] = (uint8_t) (src[1]>>8); dest[6] = (uint8_t) (src[2]>>8); dest[7] = (uint8_t) (src[3]>>8); \
		dest[8] = (uint8_t) (src[0]>>16);dest[9] = (uint8_t) (src[1]>>16);dest[10]= (uint8_t) (src[2]>>16);dest[11]= (uint8_t)(src[3]>>16); \
		dest[12]= (uint8_t) (src[0]>>24);dest[13]= (uint8_t) (src[1]>>24);dest[14]= (uint8_t) (src[2]>>24);dest[15]= (uint8_t)(src[3]>>24); \
	} while(0)

void forkskinny_128_256_encrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);

    /* State stored per column */
    load_column(state.S, input);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_128_256_ROUNDS_BEFORE; ++round) {
        forkskinny_128_256_round_table(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                         FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
            forkskinny_128_256_round_table(&state, round);
        }
        store_column(output_right, state.S);
        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
    	state.S[0] ^= 0x51051001; /* Branching constant */
    	state.S[1] ^= 0xa20a2002;
    	state.S[2] ^= 0x44144104;
    	state.S[3] ^= 0x88288208;

        for (round = (FORKSKINNY_128_256_ROUNDS_BEFORE +
                      FORKSKINNY_128_256_ROUNDS_AFTER);
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                          FORKSKINNY_128_256_ROUNDS_AFTER * 2); ++round) {
            forkskinny_128_256_round_table(&state, round);
        }
        store_column(output_left, state.S);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                         FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
            forkskinny_128_256_round_table(&state, round);
        }
        store_column(output_right, state.S);
    }
}

/**
 * \brief Applies one round of ForkSkinny-128-256.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_round
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny128_sbox(s0);
    skinny128_sbox(s1);
    skinny128_sbox(s2);
    skinny128_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Shift the cells in the rows right, which moves the cell
     * values up closer to the MSB.  That is, we do a left rotate
     * on the word to rotate the cells in the word right */
    s1 = leftRotate8(s1);
    s2 = leftRotate16(s2);
    s3 = leftRotate24(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1 and TK2 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
}

/**
 * \brief Applies one round of ForkSkinny-128-256 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_inv_round
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left, which moves the cell
     * values down closer to the LSB.  That is, we do a right
     * rotate on the word to rotate the cells in the word left */
    s1 = rightRotate8(s1);
    s2 = rightRotate16(s2);
    s3 = rightRotate24(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny128_inv_sbox(s0);
    skinny128_inv_sbox(s1);
    skinny128_inv_sbox(s2);
    skinny128_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_256_decrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    forkskinny_128_256_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                             FORKSKINNY_128_256_ROUNDS_AFTER * 2); ++round) {
        skinny128_permute_tk(state.TK1);
        skinny128_permute_tk(state.TK2);
        skinny128_LFSR2(state.TK2[0]);
        skinny128_LFSR2(state.TK2[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_128_256_ROUNDS_BEFORE +
                  FORKSKINNY_128_256_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER); --round) {
        forkskinny_128_256_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_128_256_ROUNDS_AFTER; ++round) {
        skinny128_inv_LFSR2(state.TK2[0]);
        skinny128_inv_LFSR2(state.TK2[1]);
        skinny128_inv_permute_tk(state.TK1);
        skinny128_inv_permute_tk(state.TK2);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_128_256_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_128_256_inv_round(&state, round - 1);
    }
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
            round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
        forkskinny_128_256_round(&fstate, round);
    }
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

/**
 * \brief Number of rounds of ForkSkinny-128-384 before forking.
 */
#define FORKSKINNY_128_384_ROUNDS_BEFORE 25

/**
 * \brief Number of rounds of ForkSkinny-128-384 after forking.
 */
#define FORKSKINNY_128_384_ROUNDS_AFTER 31

/**
 * \brief State information for ForkSkinny-128-384.
 */
typedef struct
{
    uint32_t TK1[4];        /**< First part of the tweakey */
    uint32_t TK2[4];        /**< Second part of the tweakey */
    uint32_t TK3[4];        /**< Third part of the tweakey */
    uint32_t S[4];          /**< Current block state */

} forkskinny_128_384_state_t;

#define TK_to_column_384(columns, state) \
	do { \
		uint32_t TK0 = state->TK1[0] ^ state->TK2[0] ^ state->TK3[0];\
		uint32_t TK1 = state->TK1[1] ^ state->TK2[1] ^ state->TK3[1];\
		uint32_t tk00 = TK0 & 0xFF; \
		uint32_t tk01 = TK0 & 0xFF00;\
		uint32_t tk02 = TK0 & 0xFF0000;\
		uint32_t tk03 = TK0 & 0xFF000000;\
		columns[0] = tk00 << 24 | (TK1 & 0xFF000000) >> 8 	| tk00 << 8  | tk00; \
		columns[1] = tk01 << 16 | (TK1 & 0xFF) 	   << 16	| tk01  	 | tk01 >> 8; \
		columns[2] = tk02 << 8  | (TK1 & 0xFF00)     << 8 	| tk02 >> 8  | tk02 >> 16; \
		columns[3] = tk03       | (TK1 & 0xFF0000)  		| tk03 >> 16 | tk03 >> 24; \
	} while(0)

/**
 * \brief Applies one round of ForkSkinny-128-384.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_round_table
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3;
    uint32_t tk_columns[4];

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    TK_to_column_384(tk_columns, state);

    state->S[0] = (T[s0 & 0xff]&0xff00ffff) ^ (T[(s3>>8) & 0xff]&0x00ff0000) ^ (T[(s2>>16) & 0xff]&0xffff00ff) ^ (T[(s1>>24)]&0xff) ^ tk_columns[0] ^ AC_column0[round];
    state->S[1] = (T[s1 & 0xff]&0xff00ffff) ^ (T[(s0>>8) & 0xff]&0x00ff0000) ^ (T[(s3>>16) & 0xff]&0xffff00ff) ^ (T[(s2>>24)]&0xff) ^ tk_columns[1] ^ AC_column1[round];
    state->S[2] = (T[s2 & 0xff]&0xff00ffff) ^ (T[(s1>>8) & 0xff]&0x00ff0000) ^ (T[(s0>>16) & 0xff]&0xffff00ff) ^ (T[(s3>>24)]&0xff) ^ tk_columns[2] ^ 0x00020200;
    state->S[3] = (T[s3 & 0xff]&0xff00ffff) ^ (T[(s2>>8) & 0xff]&0x00ff0000) ^ (T[(s1>>16) & 0xff]&0xffff00ff) ^ (T[(s0>>24)]&0xff) ^ tk_columns[3];
    /* Permute TK1, TK2, and TK3 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_permute_tk(state->TK3);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
    skinny128_LFSR3(state->TK3[0]);
    skinny128_LFSR3(state->TK3[1]);
}

void forkskinny_128_384_encrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.TK3[0] = le_load_word32(key + 32);
    state.TK3[1] = le_load_word32(key + 36);
    state.TK3[2] = le_load_word32(key + 40);
    state.TK3[3] = le_load_word32(key + 44);

    /* State stored per column */
    load_column(state.S, input);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_128_384_ROUNDS_BEFORE; ++round) {
        forkskinny_128_384_round_table(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                         FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
            forkskinny_128_384_round_table(&state, round);
        }
        store_column(output_right, state.S);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x51051001; /* Branching constant */
    	state.S[1] ^= 0xa20a2002;
    	state.S[2] ^= 0x44144104;
    	state.S[3] ^= 0x88288208;
        for (round = (FORKSKINNY_128_384_ROUNDS_BEFORE +
                      FORKSKINNY_128_384_ROUNDS_AFTER);
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                          FORKSKINNY_128_384_ROUNDS_AFTER * 2); ++round) {
            forkskinny_128_384_round_table(&state, round);
        }
        store_column(output_left, state.S);

    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                         FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
            forkskinny_128_384_round_table(&state, round);
        }
        store_column(output_right, state.S);
    }
}

/**
 * \brief Applies one round of ForkSkinny-128-384.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_round
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny128_sbox(s0);
    skinny128_sbox(s1);
    skinny128_sbox(s2);
    skinny128_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Shift the cells in the rows right, which moves the cell
     * values up closer to the MSB.  That is, we do a left rotate
     * on the word to rotate the cells in the word right */
    s1 = leftRotate8(s1);
    s2 = leftRotate16(s2);
    s3 = leftRotate24(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_permute_tk(state->TK3);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
    skinny128_LFSR3(state->TK3[0]);
    skinny128_LFSR3(state->TK3[1]);
}

/**
 * \brief Applies one round of ForkSkinny-128-384 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_inv_round
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_LFSR3(state->TK3[0]);
    skinny128_inv_LFSR3(state->TK3[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);
    skinny128_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left, which moves the cell
     * values down closer to the LSB.  That is, we do a right
     * rotate on the word to rotate the cells in the word left */
    s1 = rightRotate8(s1);
    s2 = rightRotate16(s2);
    s3 = rightRotate24(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny128_inv_sbox(s0);
    skinny128_inv_sbox(s1);
    skinny128_inv_sbox(s2);
    skinny128_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_384_decrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    forkskinny_128_384_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.TK3[0] = le_load_word32(key + 32);
    state.TK3[1] = le_load_word32(key + 36);
    state.TK3[2] = le_load_word32(key + 40);
    state.TK3[3] = le_load_word32(key + 44);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                             FORKSKINNY_128_384_ROUNDS_AFTER * 2); ++round) {
        skinny128_permute_tk(state.TK1);
        skinny128_permute_tk(state.TK2);
        skinny128_permute_tk(state.TK3);
        skinny128_LFSR2(state.TK2[0]);
        skinny128_LFSR2(state.TK2[1]);
        skinny128_LFSR3(state.TK3[0]);
        skinny128_LFSR3(state.TK3[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_128_384_ROUNDS_BEFORE +
                  FORKSKINNY_128_384_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER); --round) {
        forkskinny_128_384_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_128_384_ROUNDS_AFTER; ++round) {
        skinny128_inv_LFSR2(state.TK2[0]);
        skinny128_inv_LFSR2(state.TK2[1]);
        skinny128_inv_LFSR3(state.TK3[0]);
        skinny128_inv_LFSR3(state.TK3[1]);
        skinny128_inv_permute_tk(state.TK1);
        skinny128_inv_permute_tk(state.TK2);
        skinny128_inv_permute_tk(state.TK3);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_128_384_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_128_384_inv_round(&state, round - 1);
    }
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
            round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
        forkskinny_128_384_round(&fstate, round);
    }
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

/**
 * \brief Number of rounds of ForkSkinny-64-192 before forking.
 */
#define FORKSKINNY_64_192_ROUNDS_BEFORE 17

/**
 * \brief Number of rounds of ForkSkinny-64-192 after forking.
 */
#define FORKSKINNY_64_192_ROUNDS_AFTER 23

/**
 * \brief State information for ForkSkinny-64-192.
 */
typedef struct
{
    uint16_t TK1[4];    /**< First part of the tweakey */
    uint16_t TK2[4];    /**< Second part of the tweakey */
    uint16_t TK3[4];    /**< Third part of the tweakey */
    uint16_t S[4];      /**< Current block state */

} forkskinny_64_192_state_t;

/**
 * \brief Applies one round of ForkSkinny-64-192.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 *
 * Note: The cells of each row are order in big-endian nibble order
 * so it is easiest to manage the rows in bit-endian byte order.
 */
static void forkskinny_64_192_round
    (forkskinny_64_192_state_t *state, unsigned round)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny64_sbox(s0);
    skinny64_sbox(s1);
    skinny64_sbox(s2);
    skinny64_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          ((rc & 0x0F) << 12) ^ 0x0020;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
          ((rc & 0x70) << 8);
    s2 ^= 0x2000;

    /* Shift the cells in the rows right */
    s1 = rightRotate4_16(s1);
    s2 = rightRotate8_16(s2);
    s3 = rightRotate12_16(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny64_permute_tk(state->TK1);
    skinny64_permute_tk(state->TK2);
    skinny64_permute_tk(state->TK3);
    skinny64_LFSR2(state->TK2[0]);
    skinny64_LFSR2(state->TK2[1]);
    skinny64_LFSR3(state->TK3[0]);
    skinny64_LFSR3(state->TK3[1]);
}

void forkskinny_64_192_encrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = be_load_word16(key);
    state.TK1[1] = be_load_word16(key + 2);
    state.TK1[2] = be_load_word16(key + 4);
    state.TK1[3] = be_load_word16(key + 6);
    state.TK2[0] = be_load_word16(key + 8);
    state.TK2[1] = be_load_word16(key + 10);
    state.TK2[2] = be_load_word16(key + 12);
    state.TK2[3] = be_load_word16(key + 14);
    state.TK3[0] = be_load_word16(key + 16);
    state.TK3[1] = be_load_word16(key + 18);
    state.TK3[2] = be_load_word16(key + 20);
    state.TK3[3] = be_load_word16(key + 22);
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_64_192_ROUNDS_BEFORE; ++round) {
        forkskinny_64_192_round(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint16_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                         FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x1249U;  /* Branching constant */
        state.S[1] ^= 0x36daU;
        state.S[2] ^= 0x5b7fU;
        state.S[3] ^= 0xec81U;
        for (round = (FORKSKINNY_64_192_ROUNDS_BEFORE +
                      FORKSKINNY_64_192_ROUNDS_AFTER);
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                          FORKSKINNY_64_192_ROUNDS_AFTER * 2); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_left,     state.S[0]);
        be_store_word16(output_left + 2, state.S[1]);
        be_store_word16(output_left + 4, state.S[2]);
        be_store_word16(output_left + 6, state.S[3]);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                         FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);
    }
}

/**
 * \brief Applies one round of ForkSkinny-64-192 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_64_192_inv_round
    (forkskinny_64_192_state_t *state, unsigned round)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny64_inv_LFSR2(state->TK2[0]);
    skinny64_inv_LFSR2(state->TK2[1]);
    skinny64_inv_LFSR3(state->TK3[0]);
    skinny64_inv_LFSR3(state->TK3[1]);
    skinny64_inv_permute_tk(state->TK1);
    skinny64_inv_permute_tk(state->TK2);
    skinny64_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left */
    s1 = leftRotate4_16(s1);
    s2 = leftRotate8_16(s2);
    s3 = leftRotate12_16(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          ((rc & 0x0F) << 12) ^ 0x0020;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
          ((rc & 0x70) << 8);
    s2 ^= 0x2000;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny64_inv_sbox(s0);
    skinny64_inv_sbox(s1);
    skinny64_inv_sbox(s2);
    skinny64_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_decrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    forkskinny_64_192_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = be_load_word16(key);
    state.TK1[1] = be_load_word16(key + 2);
    state.TK1[2] = be_load_word16(key + 4);
    state.TK1[3] = be_load_word16(key + 6);
    state.TK2[0] = be_load_word16(key + 8);
    state.TK2[1] = be_load_word16(key + 10);
    state.TK2[2] = be_load_word16(key + 12);
    state.TK2[3] = be_load_word16(key + 14);
    state.TK3[0] = be_load_word16(key + 16);
    state.TK3[1] = be_load_word16(key + 18);
    state.TK3[2] = be_load_word16(key + 20);
    state.TK3[3] = be_load_word16(key + 22);
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                             FORKSKINNY_64_192_ROUNDS_AFTER * 2); ++round) {
        skinny64_permute_tk(state.TK1);
        skinny64_permute_tk(state.TK2);
        skinny64_permute_tk(state.TK3);
        skinny64_LFSR2(state.TK2[0]);
        skinny64_LFSR2(state.TK2[1]);
        skinny64_LFSR3(state.TK3[0]);
        skinny64_LFSR3(state.TK3[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_64_192_ROUNDS_BEFORE +
                  FORKSKINNY_64_192_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER); --round) {
        forkskinny_64_192_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x1249U;
    state.S[1] ^= 0x36daU;
    state.S[2] ^= 0x5b7fU;
    state.S[3] ^= 0xec81U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_64_192_ROUNDS_AFTER; ++round) {
        skinny64_inv_LFSR2(state.TK2[0]);
        skinny64_inv_LFSR2(state.TK2[1]);
        skinny64_inv_LFSR3(state.TK3[0]);
        skinny64_inv_LFSR3(state.TK3[1]);
        skinny64_inv_permute_tk(state.TK1);
        skinny64_inv_permute_tk(state.TK2);
        skinny64_inv_permute_tk(state.TK3);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_64_192_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_64_192_inv_round(&state, round - 1);
    }
    be_store_word16(output_left,     state.S[0]);
    be_store_word16(output_left + 2, state.S[1]);
    be_store_word16(output_left + 4, state.S[2]);
    be_store_word16(output_left + 6, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
            round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
        forkskinny_64_192_round(&fstate, round);
    }
    be_store_word16(output_right,     fstate.S[0]);
    be_store_word16(output_right + 2, fstate.S[1]);
    be_store_word16(output_right + 4, fstate.S[2]);
    be_store_word16(output_right + 6, fstate.S[3]);
}

