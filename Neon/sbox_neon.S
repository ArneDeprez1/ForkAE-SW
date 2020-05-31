.text 

.global skinny128_sbox_neon
.func skinny128_sbox_neon, skinny128_sbox_neon
.type skinny128_sbox_neon, %function
/*
 * r0 = *state
 */
skinny128_sbox_neon:
	vld1.32 {q0}, [r0]				//load state in 128bit register q0

	/* SBOX S_8 */
	vmvn.i32 q0, q0
	vmov.i32 q8, #0x11111111
	vshr.u32 q1, q0, #2
	vshr.u32 q2, q0, #3
	vmov.i32 q9, #0x20202020
	vand q1, q1, q2
	vmov.i32 q10, #0x40404040
	vand q1, q1, q8
	vmov.i32 q11, #0x80808080
	veor q0, q0, q1
	vmov.i32 q12, #0x02020202
	vshl.u32 q1, q0, #5
	vshl.u32 q2, q0, #1
	vmov.i32 q13, #0x04040404
	vand q1, q1, q2
	vmov.i32 q14, #0x08080808
	vand q3, q1, q9
	vshl.u32 q1, q0, #5
	vshl.u32 q2, q0, #4
	veor q0, q0, q3
	vand q1, q1, q2
	vmov.i32 q15, #0x32323232
	vand q1, q1, q10
	vmov.i32 q8, #0x01010101
	veor q0, q0, q1
	vshl.u32 q1, q0, #2
	vshl.u32 q2, q0, #1
	vand q1, q1, q2
	vand q3, q1, q11
	vshr.u32 q1, q0, #2
	vshl.u32 q2, q0, #1
	veor q0, q0, q3
	vand q1, q1, q2
	vand q1, q1, q12
	veor q0, q0, q1
	vshr.u32 q1, q0, #5
	vshl.u32 q2, q0, #1
	vand q1, q1, q2
	vand q3, q1, q13
	vshr.u32 q1, q0, #1
	vshr.u32 q2, q0, #2
	veor q0, q0, q3
	vand q1, q1, q2
	vand q1, q1, q14
	veor q0, q0, q1
	vmvn.i32 q0, q0
	vand q1,  q0, q14
	vand q2,  q0, q15
	vand q3,  q0, q8
	vand q8,  q0, q11
	vand q9,  q0, q10
	vand q10, q0, q13
	vshl.u32 q1,  q1,  #1
	vshl.u32 q2,  q2,  #2
	vshl.u32 q3,  q3,  #5
	vshr.u32 q8,  q8,  #6
	vshr.u32 q9,  q9,  #4
	vshr.u32 q10, q10, #2
	vorr q0, q1, q2
	vorr q1, q3, q8
	vorr q2, q9, q10
	vorr q3, q0, q1
	vorr q0, q3, q2
	
	vst1.32 {q0}, [r0]
	bx lr
.endfunc

.text

.global skinny64_parallel_sbox_neon
.func skinny64_parallel_sbox_neon, skinny64_parallel_sbox_neon
.type skinny64_parallel_sbox_neon, %function
/*
 * r0 = *state1, 	r1 = *state2
 */
skinny64_parallel_sbox_neon:
	vld1.16 {d0}, [r0]		// load state1 in Neon register
	vld1.16 {d1}, [r1]		// load state2 in Neon register

	/* SBOX S_4 */				// q0 contains both states
	vmvn q0, q0
	vmov.u16 q8, #0x1111
	vmov.u16 q9, #0x8888
	vshr.u16 q1, q0, #3
	vshr.u16 q2, q0, #2
	vand q1, q1, q2
	vmov.u16 q10, #0x4444
	vand q1, q1, q8
	vmov.u16 q11, #0x2222
	veor q0, q0, q1
	vshl.u16 q1, q0, #1
	vshl.u16 q2, q0, #2
	vand q1, q1, q2
	vmov.u16 q12, #0x7777
	vand q1, q1, q9
	veor q0, q0, q1
	vshl.u16 q1, q0, #1
	vshl.u16 q2, q0, #2
	vand q1, q1, q2
	vand q1, q1, q10
	veor q0, q0, q1
	vshr.u16 q1, q0, #2
	vshl.u16 q2, q0, #1
	vand q1, q1, q2
	vand q1, q1, q11
	veor q0, q0, q1
	vmvn q0, q0
	vshr.u16 q1, q0, #1
	vshl.u16 q2, q0, #3
	vand q1, q1, q12
	vand q2, q2, q9
	vorr q0, q1, q2

	vst1.16 {d0}, [r0]		// store state1
	vst1.16 {d1}, [r1]		// store state2
	bx lr
.endfunc

.text

.global skinny64_sbox_neon
.func skinny64_sbox_neon, skinny64_sbox_neon
.type skinny64_sbox_neon, %function
/*
 * r0 = *state
 */
skinny64_sbox_neon:
	vld1.16 {d0}, [r0]		// load state in 64-bit Neon register

	/* SBOX S_4 */
	vmvn d0, d0
	vmov.u16 d3, #0x1111
	vmov.u16 d4, #0x8888
	vshr.u16 d1, d0, #3
	vshr.u16 d2, d0, #2
	vand d1, d1, d2
	vmov.u16 d5, #0x4444
	vand d1, d1, d3
	vmov.u16 d6, #0x2222
	veor d0, d0, d1
	vshl.u16 d1, d0, #1
	vshl.u16 d2, d0, #2
	vand d1, d1, d2
	vmov.u16 d7, #0x7777
	vand d1, d1, d4
	veor d0, d0, d1
	vshl.u16 d1, d0, #1
	vshl.u16 d2, d0, #2
	vand d1, d1, d2
	vand d1, d1, d5
	veor d0, d0, d1
	vshr.u16 d1, d0, #2
	vshl.u16 d2, d0, #1
	vand d1, d1, d2
	vand d1, d1, d6
	veor d0, d0, d1
	vmvn d0, d0
	vshr.u16 d1, d0, #1
	vshl.u16 d2, d0, #3
	vand d1, d1, d7
	vand d2, d2, d4
	vorr d0, d1, d2

	vst1.16 {d0}, [r0]
	bx lr
.endfunc

