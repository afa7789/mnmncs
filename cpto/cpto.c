/**
 * @file cpto.c
 * @brief SHA-256, SHA-512, and other cryptography implementations.
 * @details This is a portable implementation of cryptography algorithms.
 */
#include "cpto.h"
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

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t ch64(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ ((~x) & z);
}

static inline uint64_t maj64(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint64_t sigma0_64(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

static inline uint64_t sigma1_64(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

static inline uint64_t gamma0_64(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

static inline uint64_t gamma1_64(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// SHA-512 round constants.
static const uint64_t k512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

void sha512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]) {
    // SHA-512 works on 1024-bit (128-byte) blocks.
    const size_t block_size = 128;
    uint8_t block[128];
    size_t block_len = 0;

    // Initialize hash values (first 64 bits of the fractional parts of the square roots of the first eight primes)
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    // Calculate bit length. Note: For simplicity we assume len*8 fits in 64 bits.
    uint64_t bit_len_low = (uint64_t)len * 8;
    uint64_t bit_len_high = 0; // For very long messages, this should be computed properly.

    size_t i = 0;
    // Process the data, similar to the SHA-256 loop.
    for (; i <= len; i++) {
        // When we've reached the end of data or the block is full, process the block.
        if (i == len || block_len == block_size) {
            if (i == len) {
                // Append the '1' bit.
                block[block_len++] = 0x80;
            }
            // If there isn't enough space to append length (16 bytes)...
            if (block_len > block_size - 16) {
                // Pad the remainder of the block with zeros.
                memset(block + block_len, 0, block_size - block_len);
                // Process this block.
                uint64_t w[80];
                for (int t = 0; t < 16; t++) {
                    w[t] = ((uint64_t)block[t * 8] << 56) |
                           ((uint64_t)block[t * 8 + 1] << 48) |
                           ((uint64_t)block[t * 8 + 2] << 40) |
                           ((uint64_t)block[t * 8 + 3] << 32) |
                           ((uint64_t)block[t * 8 + 4] << 24) |
                           ((uint64_t)block[t * 8 + 5] << 16) |
                           ((uint64_t)block[t * 8 + 6] << 8) |
                           ((uint64_t)block[t * 8 + 7]);
                }
                for (int t = 16; t < 80; t++) {
                    w[t] = gamma1_64(w[t - 2]) + w[t - 7] + gamma0_64(w[t - 15]) + w[t - 16];
                }

                uint64_t a = h[0], b = h[1], c = h[2], d = h[3],
                         e = h[4], f = h[5], g = h[6], hh = h[7];

                for (int t = 0; t < 80; t++) {
                    uint64_t t1 = hh + sigma1_64(e) + ch64(e, f, g) + k512[t] + w[t];
                    uint64_t t2 = sigma0_64(a) + maj64(a, b, c);
                    hh = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                h[0] += a; h[1] += b; h[2] += c; h[3] += d;
                h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

                block_len = 0;
            }

            if (block_len <= block_size - 16) {
                // Pad until the last 16 bytes.
                memset(block + block_len, 0, (block_size - 16) - block_len);
                block_len = block_size - 16;
            }

            // Append the 128-bit length (we assume bit_len_high is zero).
            for (int j = 0; j < 8; j++) {
                block[block_size - 16 + j] = (bit_len_high >> (56 - 8 * j)) & 0xFF;
            }
            for (int j = 0; j < 8; j++) {
                block[block_size - 8 + j] = (bit_len_low >> (56 - 8 * j)) & 0xFF;
            }

            // Process the final block.
            uint64_t w[80];
            for (int t = 0; t < 16; t++) {
                w[t] = ((uint64_t)block[t * 8] << 56) |
                       ((uint64_t)block[t * 8 + 1] << 48) |
                       ((uint64_t)block[t * 8 + 2] << 40) |
                       ((uint64_t)block[t * 8 + 3] << 32) |
                       ((uint64_t)block[t * 8 + 4] << 24) |
                       ((uint64_t)block[t * 8 + 5] << 16) |
                       ((uint64_t)block[t * 8 + 6] << 8) |
                       ((uint64_t)block[t * 8 + 7]);
            }
            for (int t = 16; t < 80; t++) {
                w[t] = gamma1_64(w[t - 2]) + w[t - 7] + gamma0_64(w[t - 15]) + w[t - 16];
            }

            uint64_t a = h[0], b = h[1], c = h[2], d = h[3],
                     e = h[4], f = h[5], g = h[6], hh = h[7];

            for (int t = 0; t < 80; t++) {
                uint64_t t1 = hh + sigma1_64(e) + ch64(e, f, g) + k512[t] + w[t];
                uint64_t t2 = sigma0_64(a) + maj64(a, b, c);
                hh = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

            block_len = 0;
        }
        if (i < len) {
            block[block_len++] = data[i];
        }
    }

    // Convert hash values to a big-endian byte array.
    for (int i = 0; i < 8; i++) {
        digest[i * 8] = (h[i] >> 56) & 0xFF;
        digest[i * 8 + 1] = (h[i] >> 48) & 0xFF;
        digest[i * 8 + 2] = (h[i] >> 40) & 0xFF;
        digest[i * 8 + 3] = (h[i] >> 32) & 0xFF;
        digest[i * 8 + 4] = (h[i] >> 24) & 0xFF;
        digest[i * 8 + 5] = (h[i] >> 16) & 0xFF;
        digest[i * 8 + 6] = (h[i] >> 8) & 0xFF;
        digest[i * 8 + 7] = h[i] & 0xFF;
    }
}

/**
 * @brief HMAC-SHA512 implementation.
 * @param key The key to use for HMAC.
 * @param keylen Length of the key.
 * @param data The data to hash.
 * @param datalen Length of the data.
 * @param digest The output buffer for the HMAC digest.
 */
void hmac_sha512(const uint8_t *key, size_t keylen,
                const uint8_t *data, size_t datalen,
                uint8_t digest[SHA512_DIGEST_SIZE]){
    uint8_t k[SHA512_BLOCK_SIZE] = {0};
    uint8_t o_key_pad[SHA512_BLOCK_SIZE];
    uint8_t i_key_pad[SHA512_BLOCK_SIZE];
    
    // Prepare key
    if (keylen > SHA512_BLOCK_SIZE) {
        sha512(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }
    
    // Create pads
    for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }
    
    // Inner hash
    uint8_t inner_hash[SHA512_DIGEST_SIZE];
    uint8_t inner_data[SHA512_BLOCK_SIZE + datalen];
    memcpy(inner_data, i_key_pad, SHA512_BLOCK_SIZE);
    memcpy(inner_data + SHA512_BLOCK_SIZE, data, datalen);
    sha512(inner_data, SHA512_BLOCK_SIZE + datalen, inner_hash);
    
    // Outer hash
    uint8_t outer_data[SHA512_BLOCK_SIZE + SHA512_DIGEST_SIZE];
    memcpy(outer_data, o_key_pad, SHA512_BLOCK_SIZE);
    memcpy(outer_data + SHA512_BLOCK_SIZE, inner_hash, SHA512_DIGEST_SIZE);
    sha512(outer_data, SHA512_BLOCK_SIZE + SHA512_DIGEST_SIZE, digest);
}

/**
 * @brief PBKDF2-HMAC-SHA512 implementation.
 * @param password The password to derive the key from.
 * @param password_len Length of the password.
 * @param salt The salt to use.
 * @param salt_len Length of the salt.
 * @param iterations Number of iterations.
 * @param output The output buffer for the derived key.
 * @param output_len Length of the derived key.
 */
void pbkdf2_hmac_sha512(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *output, size_t output_len) {

    uint8_t counter[4] = {0, 0, 0, 1};
    uint8_t U[SHA512_DIGEST_SIZE];
    uint8_t T[SHA512_DIGEST_SIZE];
    uint8_t salt_plus_counter[salt_len + 4];
    
    memcpy(salt_plus_counter, salt, salt_len);
    
    while (output_len > 0) {
        // Prepare salt || counter
        memcpy(salt_plus_counter + salt_len, counter, 4);
        
        // First iteration
        hmac_sha512(password, password_len, 
                   salt_plus_counter, salt_len + 4, 
                   U);
        memcpy(T, U, SHA512_DIGEST_SIZE);
        
        // Subsequent iterations
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha512(password, password_len, 
                       U, SHA512_DIGEST_SIZE, 
                       U);
            for (size_t j = 0; j < SHA512_DIGEST_SIZE; j++) {
                T[j] ^= U[j];
            }
        }
        
        // Copy to output
        size_t to_copy = output_len < SHA512_DIGEST_SIZE ? output_len : SHA512_DIGEST_SIZE;
        memcpy(output, T, to_copy);
        output += to_copy;
        output_len -= to_copy;
        
        // Increment counter
        for (int i = 3; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }
}