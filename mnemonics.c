#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
// Platform-specific headers and functions
#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <unistd.h>
    #include <sys/random.h>  // For getrandom()
    #include <errno.h>       // For errno
#endif

#define MAX_FILES 100  // Maximum files in the folder

// Function prototypes
void print_header();
void print_help();

void generate_entropy(unsigned char *buffer, size_t length);

int is_valid_number(int num);
int receive_input(int argc, char *argv[], int *num_out, char **filename_out);
int process_command_line(int argc, char *argv[], int *num_out, char **filename_out);
int process_interactive_mode(int *num_out, char **filename_out);


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

// ============ PRINTERS ============
/**
 * @brief Prints ASCII art program header
 */
void print_header() {
    printf("\n");
    printf("  ██   ▒██░   ██░    ██▒   ██░   ▓█▓   ▒██   ▓██   ▓██░       ███      ░███░  ▓░\n");
    printf("████████████████████████████████████████████████████████▓  ▒███████▓▒▓████████░ \n");
    printf(" ░████ ░████  ████  ░████  ████  ▓███▒ ▒███░ ▒███▓  ████  ████░▓██ ░███▒ ▒███░\n");  
    printf("  ███▓  ████  ████   ████  ████  ▒███  ░███░  ███▒  ▓███  ▓███  ▓░ ░███▒  ░█\n");    
    printf("  ███▓  ████  ████   ████  ████  ▒███  ░███░  ███▒  ▓███  ▓███     ▓████ ▓███\n");   
    printf("  ████  ████  ████   ███▓  ████  ▒███  ░███░  ███▓  ▓███  ▓███     ███████████▓ \n");
    printf("  ███▓  ████  ████   ████  ████  ▓███  ░███░  ███▓  ▓███  ▒███       ░█▓  ▒███▒\n"); 
    printf("  ███▓  ████  ████   ████  ████  ▒███  ░███░  ███▓  ▓███  ▒███       ▓▓   ▒███▒\n"); 
    printf("  ███▓  ████  ████   ████  ████  ▓███  ▒███▓ ░███▓  ████  ▓████  ▒▓▓████▓ ▒███▓\n"); 
    printf(" █████▒█████▓░███████████▓▒███████████▒▓██████████▓░████▓▒███████▓██████████▒\n");
    printf("  ▓██░  ▒██▓   ▓██░  ░██▓   ██▓   ███   ▒██░  ▒██░   ▓██     ▓█▓░█░    ███     \n");
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
    // Try command line first
    int result = process_command_line(argc, argv, num_out, filename_out);
    
    // Fall back to interactive if CLI processing didn't occur
    if (result == 0) {
        result = process_interactive_mode(num_out, filename_out);
    }
    
    return result;
}

/**
 * @brief Processes command-line arguments
 * @param argc Argument count
 * @param argv Argument vector
 * @param num_out Output for validated number
 * @param filename_out Output for filename (must be freed by caller)
 * @return 1 on success, 0 if insufficient args, -1 on error
 */
int process_command_line(int argc, char *argv[], int *num_out, char **filename_out) {
    if (argc < 3) return 0;  // Not enough args
    
    int num = atoi(argv[1]);
    if (!is_valid_number(num)) {
        fprintf(stderr, "Error: Number must be 128-256 and divisible by 32\n");
        return -1;
    }
    
    *num_out = num;
    *filename_out = strdup(argv[2]);  // Caller must free
    return 1;
}

/**
 * @brief Handles interactive user input
 * @param num_out Output for validated number
 * @param filename_out Output for selected filename (must be freed by caller)
 * @return 1 on success, -1 on error
 * @note Lists files from ./wordlists directory
 */
int process_interactive_mode(int *num_out, char **filename_out) {
    // Get number
    printf("Enter number (128-256, divisible by 32): ");
    scanf("%d", num_out);
    if (!is_valid_number(*num_out)) {
        fprintf(stderr, "Error: Invalid number\n");
        return -1;
    }

    // List files
    DIR *dir = opendir("./wordlists");
    if (!dir) {
        fprintf(stderr, "Error: Couldn't open data directory\n");
        return -1;
    }

    struct dirent *entry;
    char *files[MAX_FILES];
    int count = 0;

    printf("\nAvailable files:\n");
    while ((entry = readdir(dir)) && count < MAX_FILES) {
        if (entry->d_type == DT_REG) {
            files[count] = strdup(entry->d_name);
            printf("%2d: %s\n", count+1, files[count]);
            count++;
        }
    }
    closedir(dir);

    if (count == 0) {
        fprintf(stderr, "Error: No files found\n");
        return -1;
    }

    // Get selection
    int choice;
    printf("\nChoose file (1-%d): ", count);
    scanf("%d", &choice);

    if (choice < 1 || choice > count) {
        fprintf(stderr, "Error: Invalid selection\n");
        for (int i = 0; i < count; i++) free(files[i]);
        return -1;
    }

    *filename_out = files[choice-1];
    
    // Free unselected files
    for (int i = 0; i < count; i++) {
        if (i != choice-1) free(files[i]);
    }

    return 1;
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
    
    int num;
    char *filename = NULL;
    int result = receive_input(argc, argv, &num, &filename);

    //  entropy part
    unsigned char entropy[32]; // 256 bits (for 24-word mnemonic)
    generate_entropy(entropy, sizeof(entropy));

    // Print entropy in hex (same on all platforms)
    printf("Entropy (hex): ");
    for (size_t i = 0; i < sizeof(entropy); i++) {
        printf("%02x", entropy[i]);
    }
    printf("\n");

    return 0;
}

