/**
 * @file sha256.c
 * @brief SHA-256 implementation.
 * @details This is a portable implementation of the SHA-256 algorithm.
 */

#include "sha256.h"
#include <string.h>  // For memcpy, memset

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * @brief Right rotation (circular shift) operation.
 * @param value The 32-bit value to rotate.
 * @param bits Number of bits to rotate (0-31).
 * @return The rotated value.
 */
static uint32_t rotr(uint32_t value, int bits) {
    return (value >> bits) | (value << (32 - bits));
}

/**
 * @brief SHA-256 choice function.
 * @param x First 32-bit word.
 * @param y Second 32-bit word.
 * @param z Third 32-bit word.
 * @return Result of the choice function.
 */
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

/**
 * @brief SHA-256 majority function.
 * @param x First 32-bit word.
 * @param y Second 32-bit word.
 * @param z Third 32-bit word.
 * @return Result of the majority function.
 */
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

/**
 * @brief SHA-256 sigma0 function.
 * @param x 32-bit input word.
 * @return Transformed word.
 */
static uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

/**
 * @brief SHA-256 sigma1 function.
 * @param x 32-bit input word.
 * @return Transformed word.
 */
static uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

/**
 * @brief SHA-256 gamma0 function.
 * @param x 32-bit input word.
 * @return Transformed word.
 */
static uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

/**
 * @brief SHA-256 gamma1 function.
 * @param x 32-bit input word.
 * @return Transformed word.
 */
static uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    // Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint8_t block[64];
    uint64_t bit_len = len * 8;
    size_t block_len = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i == len || block_len == 64) {
            if (block_len < 64) {
                memset(block + block_len, 0, 64 - block_len);
                if (i == len) block[block_len] = 0x80;
            }
            if (block_len <= 56) {
                for (int j = 0; j < 8; j++) {
                    block[56 + j] = (bit_len >> (56 - j * 8)) & 0xFF;
                }
            }

            uint32_t w[64];
            for (int t = 0; t < 16; t++) {
                w[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | 
                       (block[t * 4 + 2] << 8) | block[t * 4 + 3];
            }
            for (int t = 16; t < 64; t++) {
                w[t] = gamma1(w[t - 2]) + w[t - 7] + gamma0(w[t - 15]) + w[t - 16];
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
                     e = h[4], f = h[5], g = h[6], h_val = h[7];

            for (int t = 0; t < 64; t++) {
                uint32_t t1 = h_val + sigma1(e) + ch(e, f, g) + k[t] + w[t];
                uint32_t t2 = sigma0(a) + maj(a, b, c);
                h_val = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;

            block_len = 0;
        }
        if (i < len) {
            block[block_len++] = data[i];
        }
    }

    // Convert hash to big-endian byte array
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (h[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = h[i] & 0xFF;
    }
}
