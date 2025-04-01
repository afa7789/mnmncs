/**
 * @file cpto.h
 * @brief cryptographic hash function implementations.
 * @details Provides a standalone implementation of algorithms.
 */

#ifndef CPTO_H
#define CPTO_H

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

/**
 * @brief SHA-512 implementation.
 * @param data Input data to hash.
 * @param len Length of the input data in bytes.
 * @param digest Output buffer for the 64-byte hash.
 */
void sha512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]);
/**
 * @brief HMAC-SHA512 implementation.
 * @param key The key to use for HMAC.
 * @param keylen Length of the key.
 * @param data The data to hash.
 * @param datalen Length of the data.
 * @param digest Output buffer for the HMAC digest.
 */
void hmac_sha512(const uint8_t *key, size_t keylen, 
    const uint8_t *data, size_t datalen, 
    uint8_t digest[SHA512_DIGEST_SIZE]);

/**
 * @brief PBKDF2-HMAC-SHA512 implementation.
 * @param password The password to derive the key from.
 * @param password_len Length of the password.
 * @param salt The salt to use.
 * @param salt_len Length of the salt.
 * @param iterations Number of iterations.
 * @param output The output buffer for the derived key.
 * @param output_len Length of the derived key.
 * @note The output buffer must be at least `output_len` bytes long.
 */
void pbkdf2_hmac_sha512(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *output, size_t output_len);
#ifdef __cplusplus
}
#endif

#endif // CPTO_H
