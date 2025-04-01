/**
 * @file bip32_key_derivation.c
 * @brief BIP-32 master key derivation from BIP-39 seed
 * @author Refactored by Claude
 * @date April 1, 2025
 *
 * This file implements functionality to derive BIP-32 master keys from a BIP-39 seed,
 * and convert them to WIF (Wallet Import Format) and xprv formats.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "cpto/cpto.h"  /* Custom crypto header */

/** @brief Type definition for byte to improve readability */
typedef unsigned char byte;

/** @brief Size of SHA-512 digest in bytes */
#define SHA512_DIGEST_SIZE 64

/** @brief Expected BIP-39 seed length in bytes */
#define BIP39_SEED_LENGTH 64

/** @brief Private key length in bytes */
#define PRIVATE_KEY_LENGTH 32

/** @brief Chain code length in bytes */
#define CHAIN_CODE_LENGTH 32

/** @brief Version byte for mainnet private key */
#define WIF_VERSION_BYTE 0x80

/** @brief BIP-32 root key for HMAC derivation */
#define BIP32_KEY "Bitcoin seed"

/** @brief Error codes for functions */
enum {
    SUCCESS = 0,
    ERROR_INVALID_INPUT = -1,
    ERROR_INVALID_LENGTH = -2,
    ERROR_INTERNAL = -3
};

/**
 * @brief Implementation of Base58 encoding for Bitcoin addresses and keys
 * 
 * @param[out] output Base58-encoded output string
 * @param[in] input Binary input data
 * @param[in] input_len Length of input data in bytes
 * @return Length of the encoded string
 */
size_t base58_encode(byte *output, const byte *input, size_t input_len) {
    /* Declare Base58 alphabet */
    const char *alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    /* Count leading zeros */
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == 0) {
        zeros++;
    }
    
    /* Calculate output size: worst case is 1.4x input size */
    size_t output_size = input_len * 138 / 100 + 1;
    byte buffer[output_size];
    memset(buffer, 0, output_size);
    
    /* Convert binary to Base58 */
    for (size_t i = zeros; i < input_len; i++) {
        uint32_t carry = input[i];
        size_t j = 0;
        
        for (size_t k = output_size - 1; k >= 0; k--, j++) {
            if (j < output_size) {
                carry += 256 * buffer[k];
                buffer[k] = carry % 58;
                carry /= 58;
            }
            
            if (carry == 0 && j >= output_size - 1) {
                break;
            }
        }
    }
    
    /* Skip leading zeros in result */
    size_t result_start = 0;
    while (result_start < output_size && buffer[result_start] == 0) {
        result_start++;
    }
    
    /* Add leading '1' chars for each leading zero byte */
    size_t output_index = 0;
    for (size_t i = 0; i < zeros; i++) {
        output[output_index++] = '1';
    }
    
    /* Convert to Base58 alphabet */
    for (size_t i = result_start; i < output_size; i++) {
        output[output_index++] = alphabet[buffer[i]];
    }
    
    output[output_index] = '\0';
    return output_index;
}

/**
 * @brief Converts a hexadecimal string to binary data
 *
 * @param[out] bin Pointer to the output binary buffer
 * @param[in] hex Input hexadecimal string (null-terminated)
 * @param[in] bin_len Expected length of the binary output in bytes
 * @return 0 on success, negative error code on failure
 * 
 * @note The hex string length must be exactly 2 * bin_len characters
 */
static int hex_to_bin(byte *bin, const char *hex, size_t bin_len) {
    if (bin == NULL || hex == NULL) {
        return ERROR_INVALID_INPUT;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) {
        return ERROR_INVALID_LENGTH;
    }
    
    for (size_t i = 0; i < bin_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bin[i]) != 1) {
            return ERROR_INVALID_INPUT;
        }
    }
    
    return SUCCESS;
}

/**
 * @brief Prints binary data as a hexadecimal string
 *
 * @param[in] label Descriptive label for the output
 * @param[in] data Pointer to the binary data to print
 * @param[in] len Length of the data in bytes
 */
static void print_hex(const char *label, const byte *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * @brief Derives BIP-32 master key and chain code from a BIP-39 seed
 *
 * @param[in] seed Pointer to the BIP-39 seed
 * @param[in] seed_len Length of the seed in bytes
 * @param[out] private_key_out Buffer to store the master private key (32 bytes)
 * @param[out] chain_code_out Buffer to store the chain code (32 bytes)
 * @return 0 on success, negative error code on failure
 * 
 * @note Uses HMAC-SHA512 with "Bitcoin seed" as key per BIP-32 specification
 * @note Output buffers must be at least 32 bytes each
 */
static int derive_bip32_master_key(
    const byte *seed, 
    size_t seed_len,
    byte *private_key_out, 
    byte *chain_code_out
) {
    if (seed == NULL || private_key_out == NULL || chain_code_out == NULL) {
        return ERROR_INVALID_INPUT;
    }
    
    if (seed_len != BIP39_SEED_LENGTH) {
        fprintf(stderr, "Invalid seed length: %zu bytes (expected %d)\n", 
                seed_len, BIP39_SEED_LENGTH);
        return ERROR_INVALID_LENGTH;
    }
    
    byte master_key[SHA512_DIGEST_SIZE];
    
    /* HMAC-SHA512 with key "Bitcoin seed" and message as the seed */
    hmac_sha512(
        (const uint8_t *)BIP32_KEY, strlen(BIP32_KEY),
        seed, seed_len,
        master_key
    );
    
    /* First 32 bytes are the master private key */
    memcpy(private_key_out, master_key, PRIVATE_KEY_LENGTH);
    
    /* Last 32 bytes are the chain code */
    memcpy(chain_code_out, master_key + PRIVATE_KEY_LENGTH, CHAIN_CODE_LENGTH);
    
    return SUCCESS;
}

/**
 * @brief Converts a private key to WIF (Wallet Import Format)
 *
 * @param[in] private_key 32-byte private key
 * @param[out] wif_key Output buffer for WIF key (should be at least 53 bytes)
 * @return 0 on success, negative error code on failure
 */
static int private_key_to_wif(const byte *private_key, byte *wif_key) {
    if (private_key == NULL || wif_key == NULL) {
        return ERROR_INVALID_INPUT;
    }

    byte versioned_key[PRIVATE_KEY_LENGTH + 1 + 4]; /* Key + version + checksum */
    byte checksum[32];

    /* Prepend version byte (0x80 for mainnet) */
    versioned_key[0] = WIF_VERSION_BYTE;
    memcpy(versioned_key + 1, private_key, PRIVATE_KEY_LENGTH);

    /* Double SHA-256 checksum */
    sha256(versioned_key, PRIVATE_KEY_LENGTH + 1, checksum);
    sha256(checksum, 32, checksum);

    /* Append first 4 bytes of checksum */
    memcpy(versioned_key + PRIVATE_KEY_LENGTH + 1, checksum, 4);

    /* Base58Check encode */
    size_t len = base58_encode(wif_key, versioned_key, PRIVATE_KEY_LENGTH + 1 + 4);
    if (len == 0) {
        return ERROR_INTERNAL;
    }
    
    wif_key[len] = '\0';
    return SUCCESS;
}

/**
 * @brief Generate extended private key (xprv) from master private key and chain code
 *
 * @param[in] private_key 32-byte private key
 * @param[in] chain_code 32-byte chain code
 * @param[out] xprv Output buffer for xprv (should be at least 112 bytes)
 * @return 0 on success, negative error code on failure
 */
static int generate_xprv(const byte *private_key, const byte *chain_code, byte *xprv) {
    if (private_key == NULL || chain_code == NULL || xprv == NULL) {
        return ERROR_INVALID_INPUT;
    }

    /* xprv format:
     * 4 bytes: version
     * 1 byte: depth
     * 4 bytes: parent fingerprint
     * 4 bytes: child number
     * 32 bytes: chain code
     * 33 bytes: private key (0x00 + 32-byte key)
     * 4 bytes: checksum
     * Total: 82 bytes
     */
    byte xprv_raw[82];
    
    /* xprv version bytes */
    byte version[4] = {0x04, 0x88, 0xAD, 0xE4};
    
    /* Build xprv structure */
    memcpy(xprv_raw, version, 4);
    memset(xprv_raw + 4, 0, 9);  /* Depth, fingerprint, and child number */
    memcpy(xprv_raw + 13, chain_code, 32);
    xprv_raw[45] = 0x00;  /* Prepend 0x00 to private key */
    memcpy(xprv_raw + 46, private_key, 32);

    /* Calculate checksum (first 4 bytes of double SHA-256) */
    byte checksum[32];
    sha256(xprv_raw, 78, checksum);
    sha256(checksum, 32, checksum);
    
    memcpy(xprv_raw + 78, checksum, 4);

    /* Base58 encode the extended key */
    size_t len = base58_encode(xprv, xprv_raw, 82);
    if (len == 0) {
        return ERROR_INTERNAL;
    }
    
    xprv[len] = '\0';
    return SUCCESS;
}

/**
 * @brief Print xprv and WIF formats of a private key
 *
 * @param[in] private_key 32-byte private key
 * @param[in] chain_code 32-byte chain code
 * @return 0 on success, negative error code on failure
 */
static int print_xprv_and_wif(const byte *private_key, const byte *chain_code) {
    if (private_key == NULL || chain_code == NULL) {
        return ERROR_INVALID_INPUT;
    }

    byte xprv[112]; /* Base58 encoding can expand data */
    byte wif_key[53]; /* Base58 encoding of a 38-byte payload */

    /* Generate xprv */
    int result = generate_xprv(private_key, chain_code, xprv);
    if (result != SUCCESS) {
        fprintf(stderr, "Failed to generate xprv\n");
        return result;
    }

    printf("Electrum using xpriv\n\n");
    printf("xprv: %s\n\n", xprv); 
    printf("To create a spending wallet, please enter a master private key (xprv/yprv/zprv).\n");
    printf("NewWallet -> standardWallet -> use a masterKey -> PASTER the Xpriv above.\n");

    /* Generate WIF */
    result = private_key_to_wif(private_key, wif_key);
    if (result != SUCCESS) {
        fprintf(stderr, "Failed to generate WIF\n");
        return result;
    }

    printf("Electrum using WIF\n\n");
    printf("WIF: %s\n\n", wif_key);
    printf("The WIF is a Single-Key Wallet. \"Enter a list of Bitcoin addresses (this will create a watching-only wallet), or a list of private keys.\"\n");
    printf("New Wallet -> Import Bitcoin addresses or private keys -> paste it and click next -> setup password, done.\n");

    return SUCCESS;
}

/**
 * @brief Prints right-aligned exit message with ASCII art
 */
void print_ending() {
    printf("\n");
    printf("%80s", "₿☀🦄ᚠ - you can just build things\n");
    printf("\n");
}


/**
 * @brief Processes a BIP-39 seed in hex format and derives/displays BIP-32 master key
 *
 * @param[in] seed_hex Hexadecimal string of the BIP-39 seed (128 characters)
 * @return 0 on success, negative error code on failure
 */
static int process_bip32_seed(const char *seed_hex) {
    if (seed_hex == NULL) {
        return ERROR_INVALID_INPUT;
    }
    
    byte seed[BIP39_SEED_LENGTH];
    byte private_key[PRIVATE_KEY_LENGTH];
    byte chain_code[CHAIN_CODE_LENGTH];
    int result;
    
    /* Convert hex seed to binary */
    result = hex_to_bin(seed, seed_hex, sizeof(seed));
    if (result != SUCCESS) {
        fprintf(stderr, "Invalid seed hex string\n");
        return result;
    }
    
    /* Derive BIP-32 master key */
    result = derive_bip32_master_key(seed, sizeof(seed), private_key, chain_code);
    if (result != SUCCESS) {
        fprintf(stderr, "Failed to derive master key\n");
        return result;
    }
    
    /* Print results */
    printf("Input BIP-39 Seed (hex):\n");
    print_hex("Seed", seed, sizeof(seed));
    printf("\nBIP-32 Master Key Derivation Results:\n");
    print_hex("Master Private Key", private_key, sizeof(private_key));
    print_hex("Master Chain Code", chain_code, sizeof(chain_code));
    printf("\n");

    /* Print xprv and WIF formats */
    result = print_xprv_and_wif(private_key, chain_code);
    print_ending();
    if (result != SUCCESS) {
        return result;
    }
    
    return SUCCESS;
}

/**
 * @brief Main function demonstrating BIP-32 master key derivation
 *
 * @param[in] argc Number of command-line arguments
 * @param[in] argv Array of command-line argument strings
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure
 * 
 * @note Expects one argument: 128-character hex string representing BIP-39 seed
 * @note Usage: ./program <seed_hex>
 */
int main(int argc, char *argv[]) {
    printf("\n\nBIP-32 creating pubkey and privkey to import.\n\n");
    /* Check if seed hex is provided as command-line argument */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <64-byte-seed-in-hex>\n", argv[0]);
        fprintf(stderr, "Example: %s 2f00201a843bf367ed45fda52ea0d3aba21ee730ad1a93189e67ae0e6faae4bb3a32629b955d1cfcde3becc25f2e39519e1e5d9ee8318c6217b11bcedb9f9683\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    if (process_bip32_seed(argv[1]) != SUCCESS) {
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}