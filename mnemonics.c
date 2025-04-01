/**
 * @file mnemonics.c
 * @brief :) 
 * @details Provides a implementation of BIP-39.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdint.h>
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>

#include "sha256/sha256.h"  // Include your header

// Platform-specific headers and functions
#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <unistd.h>
    #include <sys/random.h>  // For getrandom()
    #include <errno.h>       // For errno
#endif


#define MNEMONIC_MAX_LENGTH 16  ///< Maximum expected length of a mnemonic line.
#define MAX_FILES 100  // Maximum files in the folder
#define PATH_MAX 4096  // Maximum path length

// Function prototypes
void print_header();
void print_help();
void print_entropy(unsigned char *buffer,size_t length);
void print_hash(unsigned char *buffer);
void print_ending();
void print_mnemonics(const char **words, size_t num_words, size_t words_per_line);
void print_files_list(char *files[], int count);

void generate_entropy(unsigned char *buffer, size_t length);
void entropy_checksum_and_concat(unsigned char **buffer,size_t *length);
void concat_arrays(unsigned char **dest, size_t *dest_size, unsigned char *src, size_t src_size);

void free_words(char **words, size_t count);
char **read_mnemonics(const char *filename, size_t *num_lines);
size_t entropy_to_index(const unsigned char *chunk, size_t mnemonics_count);
char **generate_mnemonics(const unsigned char *entropy, size_t num_bytes, const char *filename, size_t *num_words);

int is_valid_number(int num);
int receive_input(int argc, char *argv[], int *num_out, char **filename_out);
int process_command_line(int argc, char *argv[], int *num_out, int *file_index_out, 
    char *files[], int file_count);
int get_wordlist_files(char *files[], int max_files);
int process_interactive_mode(int *num_out, int *file_index_out, 
        char *files[], int file_count);
int get_wordlist_files(char *files[], int max_files);
void cleanup_files_list(char *files[], int count);

// ============ CRYPTOGRAPHY ============

/**
 * @brief Generates cryptographically secure entropy
 * @param buffer Output buffer to store entropy
 * @param length Number of bytes to generate (must be ≤ 256)
 * @note Uses platform-specific RNG:
 *       - Windows: BCryptGenRandom()
 *       - Linux: getrandom() or /dev/urandom fallback
 *       - macOS: /dev/urandom
 * @warning Exits program on failure
 */
void generate_entropy(unsigned char *buffer, size_t length) {
    #ifdef _WIN32
        // Windows implementation
        NTSTATUS status = BCryptGenRandom(
            NULL,
            buffer,
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        if (status != 0) {
            fprintf(stderr, "BCryptGenRandom failed: 0x%x\n", status);
            exit(EXIT_FAILURE);
        }
    #else
        // Linux/macOS implementation
        #if defined(__linux__) && defined(SYS_getrandom)
            // Try getrandom() first (Linux-specific)
            ssize_t result = getrandom(buffer, length, 0);
            if (result == (ssize_t)length) return;
            if (result == -1 && errno != ENOSYS) {
                perror("getrandom failed");
                exit(EXIT_FAILURE);
            }
            // Fall through to /dev/urandom if getrandom isn't available
        #endif
        
        // Universal Unix fallback
        FILE *f = fopen("/dev/urandom", "rb");
        if (f == NULL) {
            perror("Failed to open /dev/urandom");
            exit(EXIT_FAILURE);
        }
        if (fread(buffer, 1, length, f) != length) {
            perror("Failed to read from /dev/urandom");
            fclose(f);
            exit(EXIT_FAILURE);
        }
        fclose(f);
    #endif
}

/**
 * @brief Prints the characters in the entropy mainly for  
 * @param buffer Output buffer to store entropy
 * @param length Number of the buffer size to be able to print
 */
void print_entropy(unsigned char *buffer, size_t length) {
    // Print entropy in hex (same on all platforms)
    printf("Entropy (hex): ");
    for (size_t i = 0; i < length; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

/**
 * @brief Prints the characters in the hash mainly for 
 * @param buffer Output buffer to store hash
 */
void print_hash(unsigned char *buffer) {
    // Print hash in hex (same on all platforms)
    printf("Hash (hex): ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

/**
 * @brief Concatenate two array of bytes and also increase the parameter related to the length of original array.
 * @param dest Initial array of the concat
 * @param dest_size Size of the array dest
 * @param src Src array, we want to concat
 * @param src_size Size of the src array
 */
 void concat_arrays(unsigned char **dest, size_t *dest_size, unsigned char *src, size_t src_size) {
    *dest = realloc(*dest, *dest_size + src_size); // Resize the array
    if (*dest == NULL) {
        perror("realloc failed");
        exit(1);
    }
    memcpy(*dest + *dest_size, src, src_size); // Copy the source data
    *dest_size += src_size; // Update the size
}

/** 
 * @brief Create the checksum for it and concat at the ending of the entropy 
 * @param buffer The buffer of the entropy
 * @param length The size of the buffer
 */
void entropy_checksum_and_concat(unsigned char **buffer, size_t *length) {
    if (!buffer || !*buffer || !length || *length == 0) {
        printf("Invalid parameters\n");
        return;
    }

    uint8_t hash[32];
    size_t length_o = *length;

    sha256((const uint8_t *)*buffer, length_o, hash);
    print_hash(hash);
    printf("With CS concat ");

    size_t checksum_bits = *length / 32;  // e.g., 256 / 32 = 8 bits = 1 byte
    concat_arrays(buffer, length, hash, checksum_bits);  // Pass double pointer
    print_entropy(*buffer, *length);
}

// ============ MNEMONICS =========== 

/**
 * @brief Reads a file into an array of strings (one per line).
 * @param filename The name of the file to read.
 * @param num_lines Output parameter to store the number of lines read.
 * @return A dynamically allocated array of strings (must be freed by the caller), or NULL on failure.
 */
char **read_mnemonics(const char *filename, size_t *num_lines) {
    if (!filename || !num_lines) return NULL;

    FILE *file = fopen(filename, "r");
    if (!file) return NULL;

    // Count lines first to allocate exact memory needed.
    size_t count = 0;
    char ch;
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') count++;
    }
    rewind(file);

    char **lines = malloc(count * sizeof(char *));
    if (!lines) {
        fclose(file);
        return NULL;
    }

    char buffer[MNEMONIC_MAX_LENGTH];
    size_t i = 0;
    while (fgets(buffer, sizeof(buffer), file)) {
        buffer[strcspn(buffer, "\n")] = '\0';  // Remove newline.
        lines[i] = strdup(buffer);
        if (!lines[i]) {
            // Cleanup on failure.
            for (size_t j = 0; j < i; j++) free(lines[j]);
            free(lines);
            fclose(file);
            return NULL;
        }
        i++;
    }
    fclose(file);

    *num_lines = count;
    return lines;
}

/**
 * @brief Converts 11 bytes of entropy into an index within `mnemonics` range.
 * @param chunk Pointer to 11 bytes of entropy data.
 * @param mnemonics_count Total number of available mnemonics.
 * @return A valid index in the range [0, mnemonics_count - 1].
 */
size_t entropy_to_index(const unsigned char *chunk, size_t mnemonics_count) {
    assert(chunk && mnemonics_count > 0);

    // Treat the 11 bytes as a big-endian integer and mod by mnemonics_count.
    uint64_t value = 0;
    for (int i = 0; i < 11; i++) {
        value = (value << 8) | chunk[i];
    }
    return value % mnemonics_count;
}

/**
 * @brief Generates a mnemonic phrase from entropy data.
 * @param entropy The entropy array (must be at least `11 * num_words` bytes long).
 * @param num_bytes Total size of the entropy array in bytes.
 * @param filename The file containing mnemonics (one per line).
 * @param num_words Output parameter to store the number of words generated.
 * @return A dynamically allocated array of selected mnemonics (must be freed by the caller), or NULL on failure.
 */
char **generate_mnemonics(
    const unsigned char *entropy,
    size_t num_bytes,
    const char *filename,
    size_t *num_words
) {
    if (!entropy || !filename || !num_words || num_bytes % 11 != 0) {
        return NULL;
    }

    size_t mnemonics_count = 0;
    char **mnemonics = read_mnemonics(filename, &mnemonics_count);
    if (!mnemonics || mnemonics_count == 0) {
        printf("Error: Failed to read mnemonics from file: %s.\n", filename);
        return NULL;
    }

    *num_words = num_bytes / 11;
    char **selected_words = malloc(*num_words * sizeof(char *));
    if (!selected_words) {
        for (size_t i = 0; i < mnemonics_count; i++) free(mnemonics[i]);
        free(mnemonics);
        return NULL;
    }

    for (size_t i = 0; i < *num_words; i++) {
        const unsigned char *chunk = entropy + (i * 11);
        size_t index = entropy_to_index(chunk, mnemonics_count);
        selected_words[i] = strdup(mnemonics[index]);
        if (!selected_words[i]) {
            // Cleanup on failure.
            for (size_t j = 0; j < i; j++) free(selected_words[j]);
            free(selected_words);
            for (size_t j = 0; j < mnemonics_count; j++) free(mnemonics[j]);
            free(mnemonics);
            return NULL;
        }
    }

    // Free the mnemonics array (no longer needed).
    for (size_t i = 0; i < mnemonics_count; i++) free(mnemonics[i]);
    free(mnemonics);

    return selected_words;
}

/**
 * @brief Frees an array of strings.
 * @param words The array to free.
 * @param count Number of strings in the array.
 */
void free_words(char **words, size_t count) {
    if (!words) return;
    for (size_t i = 0; i < count; i++) free(words[i]);
    free(words);
}

/**
 * @brief Prints an array of mnemonic words in a formatted way.
 * @param words Array of strings (mnemonics) to print.
 * @param num_words Number of words in the array.
 * @param words_per_line Number of words to print per line (default: 6).
 */
void print_mnemonics(const char **words, size_t num_words, size_t words_per_line) {
    if (!words || num_words == 0) {
        fprintf(stderr, "Error: No mnemonics to print.\n");
        return;
    }

    if (words_per_line == 0) {
        words_per_line = 6; // Default to 6 words per line
    }

    for (size_t i = 0; i < num_words; i++) {
        if (words[i]) {
            printf("%s", words[i]);
            
            // Add space if not the last word in the line or array
            if ((i + 1) % words_per_line != 0 && i != num_words - 1) {
                printf(" ");
            }
            
            // Newline after `words_per_line` words
            if ((i + 1) % words_per_line == 0 || i == num_words - 1) {
                printf("\n");
            }
        }
    }
}

// ============ PRINTERS ============
/**
 * @brief Prints ASCII art program header
 */
void print_header() {
    printf("\n");
    printf("  ▓█   ▒█▓   ▒█░   ░█▓   ▓█░   ██   ▒█▒   ▓█░   ██   ░█▒        █▓      ░██   █▒\n");
    printf("▓████▓█████▓██████████████████████▓█████▓███████████▓█████▓  ░██████▓ ▒████████\n");
    printf(" ▒████ ████▓░████░ ▓███▒░███▓ ▒███▓ ▓███▒░████ ░████░▒████ ░███▓███▒▓███░▓███▓ \n");
    printf("  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ░███░ ████  ████  ████  ███▒ █▒ ▓███   █▓  \n");
    printf("  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ░███░ ▓███  ████  ████  ███▒    ████▓░███▒ \n");
    printf("  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▓ ░███░ ████  ████  ████  ███▒    ███████████\n");
    printf("  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ▒███░ ████  ████  ████  ███▒      ▓█▒  ███▓\n");
    printf("  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ▒███░ ████  ████  ████  ███▒     ▒█░   ███▓\n");
    printf(" ░████ ▒███▓ ▓███░ ▓███▒ ████░░███▓ ▒███▒ ████░ ████  ████  █████░▓██████▓ ████\n");
    printf(" █████▓█████░▓████▓█████ ██████████▒█████░▓████▒█████ ████▓░▓█████▓█████████▒  \n");
    printf("  ░█▓   ░█▒   ░█▓    █▒   ▒█░   ██    █▓   ░█▓   ▓█▒   ▒█▒    ░██ █░    ██░    \n");
}

/**
 * @brief Displays detailed usage instructions
 */
void print_help() {
    printf("=== Implementation of BIP-39 in c programming language. ===\n\n");
    printf("This program receives two inputs to generate mnemonics with secure entropy generation.\n\n");
    printf("HOW TO USE:\n");
    printf("1. Command line mode: ./program <number> <file_index>\n");
    printf("   - <number> must be between 128-256 and a multiple of 32\n");
    printf("   - <file_index> must correspond to a valid file in the data folder\n\n");
    printf("2. Interactive mode: Simply run './program' without arguments\n");
    printf("   - You'll be prompted to enter a number (128-256, multiple of 32)\n");
    printf("   - Then you'll see a list of files from the './data' folder\n");
    printf("   - Select a file by entering its number\n\n");
    printf("Note: The program will generate cryptographically secure entropy\n");
    printf("      and display it in hexadecimal format before exiting.\n\n");
}

/**
 * @brief Prints right-aligned exit message with ASCII art
 */
void print_ending() {
    printf("\n");
    printf("%80s", "♠♡♦♧ - don't trust, verify\n");  // Right-aligned in 80-char width
    printf("\n");
}

// ============ INFO INPUT ============

/**
 * @brief Validates if a number is in the BIP-39 entropy range
 * @param num Number to validate
 * @return 1 if valid (128-256 and multiple of 32), 0 otherwise
 */
int is_valid_number(int num) {
    return (num >= 128 && num <= 256 && num % 32 == 0);
}
/**
 * @brief Unified input processor (CLI or interactive)
 * @param argc Argument count
 * @param argv Argument vector
 * @param num_out Output for validated number
 * @param filename_out Output for selected filename (must be freed by caller)
 * @return 1 on success, 0 if no input processed, -1 on error
 */
 int receive_input(int argc, char *argv[], int *num_out, char **filename_out) {
    // Get available files first
    char *files[MAX_FILES];
    int file_count = get_wordlist_files(files, MAX_FILES);
    if (file_count <= 0) {
        fprintf(stderr, "No wordlists found in ./wordlists directory\n");
        return -1;
    }

    int file_index = -1;
    int result;
    
    // Try CLI first
    if ((result = process_command_line(argc, argv, num_out, &file_index, files, file_count)) != 0) {
        if (result < 0) {
            cleanup_files_list(files, file_count);
            return -1;
        }
    } 
    // Fall back to interactive
    else if ((result = process_interactive_mode(num_out, &file_index, files, file_count)) <= 0) {
        cleanup_files_list(files, file_count);
        return result;
    }

    // Validate selected index
    if (file_index < 0 || file_index >= file_count) {
        cleanup_files_list(files, file_count);
        return -1;
    }

    // Build full path
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "./wordlists/%s", files[file_index]);
    *filename_out = strdup(path);

    // Cleanup
    cleanup_files_list(files, file_count);
    return 1;
}

/**
 * @brief Helper to cleanup files list
 * @param files Array of filenames
 * @param count Number of files in array
 */
void cleanup_files_list(char *files[], int count) {
    for (int i = 0; i < count; i++) {
        free(files[i]);
    }
}

/**
 * @brief Processes command-line arguments
 * @param argc Argument count
 * @param argv Argument vector
 * @param num_out Output for validated number
 * @param file_index_out Output for selected file index
 * @param files Array of available filenames
 * @param file_count Number of available files
 * @return 1 on success, 0 if insufficient args, -1 on error
 */
int process_command_line(int argc, char *argv[], int *num_out, int *file_index_out, 
                        char *files[], int file_count) {
    if (argc < 3) return 0;

    // Validate number
    int num = atoi(argv[1]);
    if (!is_valid_number(num)) {
        fprintf(stderr, "Invalid number. Must be 128-256 and divisible by 32\n");
        return -1;
    }
    *num_out = num;

    // Check if argument is numeric index
    if (isdigit(argv[2][0])) {
        int choice = atoi(argv[2]);
        if (choice < 1 || choice > file_count) {
            fprintf(stderr, "Invalid selection. Available options (1-%d):\n", file_count);
            print_files_list(files, file_count);
            return -1;
        }
        *file_index_out = choice - 1;
    }
    // Check if argument is filename
    else {
        bool found = false;
        for (int i = 0; i < file_count; i++) {
            if (strcmp(argv[2], files[i]) == 0) {
                *file_index_out = i;
                found = true;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Wordlist not found. Available options:\n");
            print_files_list(files, file_count);
            return -1;
        }
    }

    return 1;
}

/**
 * @brief Handles interactive user input
 * @param num_out Output for validated number
 * @param file_index_out Output for selected file index
 * @param files Array of available filenames
 * @param file_count Number of available files
 * @return 1 on success, -1 on error
 */
int process_interactive_mode(int *num_out, int *file_index_out, 
                            char *files[], int file_count) {
    // Get number
    printf("Enter number (128-256, divisible by 32): ");
    if (scanf("%d", num_out) != 1 || !is_valid_number(*num_out)) {
        fprintf(stderr, "Invalid number\n");
        return -1;
    }

    // Display files
    printf("\nAvailable wordlists:\n");
    print_files_list(files, file_count);

    // Get selection
    printf("\nChoose wordlist (1-%d): ", file_count);
    int choice;
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > file_count) {
        fprintf(stderr, "Invalid selection\n");
        return -1;
    }
    *file_index_out = choice - 1;

    return 1;
}

/**
 * @brief Prints the list of available files with 1-based numbering
 * @param files Array of filenames
 * @param count Number of files
 */
void print_files_list(char *files[], int count) {
    for (int i = 0; i < count; i++) {
        printf("%2d: %s\n", i+1, files[i]);
    }
}

/**
 * @brief Gets list of available wordlist files
 * @param files Output array for filenames (must be freed by caller)
 * @param max_files Maximum number of files to return
 * @return Number of files found, or -1 on error
 */
int get_wordlist_files(char *files[], int max_files) {
    DIR *dir = opendir("./wordlists");
    if (!dir) return -1;

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) && count < max_files) {
        if (entry->d_type == DT_REG) {
            files[count] = strdup(entry->d_name);
            if (!files[count]) {
                // Cleanup on allocation failure
                while (count-- > 0) free(files[count]);
                closedir(dir);
                return -1;
            }
            count++;
        }
    }
    closedir(dir);
    return count;
}

/**
 * @brief Program entry point
 * @param argc Argument count
 * @param argv Argument vector
 * @return EXIT_SUCCESS (0) or EXIT_FAILURE (1)
 * @note Flow:
 *       1. Prints header
 *       2. Shows help if no args
 *       3. Processes input (CLI or interactive)
 *       4. Generates and displays entropy
 */
int main(int argc, char *argv[]) {
    print_header();

    // Only show help if no command line arguments
    if (argc < 3) {
        print_help();
    }
    
    size_t num=0;
    char *filename = NULL;
    int result = receive_input(argc, argv, &num, &filename);

    // printf("num: %d \n",num);
    // If you use 256 bits you get a 24-word mnemonic)
    unsigned char *entropy = malloc(num);
    generate_entropy(entropy, num);
    print_entropy(entropy,num);
    entropy_checksum_and_concat(&entropy, &num);
    // print_entropy(entropy,num); // Print the buffer with the hash
    // size_t num_bytes = sizeof(entropy);
    size_t num_words = 0;
    char **words = generate_mnemonics(entropy, num, filename, &num_words);
    printf("\nnum_words %d\n",num_words);
    print_mnemonics((const char **)words, num_words, 4);
    free_words(words, num_words);
    print_ending();
    return 0;
}

