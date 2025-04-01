/**
 * @file sha256.h
 * @brief SHA-256 cryptographic hash function implementation.
 * @details Provides a standalone implementation of the SHA-256 algorithm.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>  // For uint8_t, uint32_t, uint64_t
#include <stddef.h>  // For size_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes the SHA-256 hash of the input data.
 * @param[in] data Pointer to the input data to be hashed.
 * @param[in] len Length of the input data in bytes.
 * @param[out] hash Buffer to store the resulting 32-byte hash.
 * @note The output buffer must be at least 32 bytes long.
 */
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

void sha512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]);
void hmac_sha512(const uint8_t *key, size_t keylen, 
                const uint8_t *data, size_t datalen, 
                uint8_t digest[SHA512_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // SHA256_H
