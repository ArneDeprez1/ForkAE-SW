# ForkAE
This directory contains software implementations of the lightweight cipher [ForkAE](https://www.esat.kuleuven.be/cosic/forkae/). 

ForkAE is a second round candidate of the [NIST lightweight cryptography competition](https://csrc.nist.gov/projects/lightweight-cryptography/round-2-candidates), the specification of the cipher, and its different instances can be found [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/forkae-spec-round2.pdf)

## 8-bit Implementation
In the 8-bit implementation, the ForkSkinny primitive of ForkAE and its round function and tweakey schedule are implemented in C with 8-bit variables. This implementation was mainly used as as an example of how ForkAE can be implemented using byte-sized words and as a stepping stone in designing more optimized 32-bit implementations. 

## 32-bit Implementations
All 32-bit implementations in this repository are based on Rhys Weatherley's implementation of ForkAE, which is available in his [lightweight-crypto repository](https://github.com/rweather/lightweight-crypto). His software is released under the MIT license, which is copied here. 
Modifications were made to the `forkskinny.c` file and files were added where needed to allow for more optimized implementations of the ForkSkinny primitive.

### 32-bit
This implementation, written in plain C, is designed to be portable and have good performance across a broad range of 32-bit  embedded platforms. Just as in Rhys Weatherley's implementation, its is implemented in a manner that should execute in constant time with constant cache behaviour.

Functionality was added to preprocess the tweakey schedule at the beginning of ForkSkinny encryption and decryption and store the round-tweakey material for every round. This allows for faster decryption as the tweakey schedule does not have to be fast-forwarded or reversed. The speed-up comes at the cost of a higher memory usage. 

### Lookup Table Implementation
In this implementation, in order to allow for faster execution, the round function and its inverse are transformed into a combination of table-lookups, much like the T-table implementation of AES. The implementation included here uses 1 lookup table for encryption and 1 for decryption (1 kB each).

This implementation is __vulnerable to cache-attacks__ and should only be used in situations/platforms where such an attack is not possible. 

### Neon SIMD Implementation
This implementation is specifically designed for Arm processors with a [Neon SIMD](https://developer.arm.com/architectures/instruction-sets/simd-isas/neon) extension. The files `sbox_neon.S` and corresponding header file `sbox_neon.h` were added and contain a Neon assembly implementation of the 128-bit and 64-bit S-boxes used in ForkAE. 

For the instance PAEF-ForkSkinny-64-192, an implementation is included that calculates the two branches of ForkSkinny in parallel.

## Supercop
The 'supercop' directory contains the same implementations as listed above but with the files organized in directories compliant with NIST and supercop guidelines.

## Documentation
At this moment the repository contains only the source code of the different implementations and limited documentation.
I plan on adding more detailed documentation and some example makefiles in the future.
