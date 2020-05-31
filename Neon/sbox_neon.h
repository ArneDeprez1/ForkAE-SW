/*
 * sbox_neon.h
 */

#ifndef SBOX_NEON_H_
#define SBOX_NEON_H_

#include <stdint.h>

extern void skinny128_sbox_neon(uint32_t *state);

extern void skinny64_sbox_neon(uint16_t *state);

extern void skinny64_parallel_sbox_neon(uint16_t *state1, uint16_t *state2);


#endif /* SBOX_NEON_H_ */
