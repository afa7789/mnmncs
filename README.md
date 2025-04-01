<pre>                                                                                
                                                                               ░
 ░██░  ███   ██▓   ▒██▒  ██▓   ███   ██▓  ▒██░  ███▓ ▓██▓      ▒██▓     ▓███▒ ▒▓
▓█████████████████████████████████████████████████████████▒ ▓███████▓▓████████▓ 
  ███▒ ░███░ ████   ███░ ▒███  ▓███  ▓██▓  ███▒ ░███░ ▒███  ███▒ ██  ███▒  ▒█▒  
  ███░  ███  ▓███   ███  ░███  ▒███  ▓██▓  ███░ ░███░ ▒███  ▓██▒     ███▓  █▓   
  ███▒  ███  ▓███   ███  ░███  ▒███  ▓██▓  ███▒ ░███░ ▒███  ▓██▒    ███████████ 
  ███▒  ███  ▓███   ███  ▒███  ▒███  ▓██▓  ███▒ ░███░ ▒███  ▓██▒     ░███░ ████ 
  ███░  ███  ▓███   ███  ▒███  ▒███  ███▓  ███▒ ░███░ ▒███  ▓██▒      ░█   ▓███ 
  ███░  ███  ▓███   ███░ ▒███  ▒███  ███▓  ███▒ ░███░ ▒███  ▓███   ▓ ███▓  ▓███ 
 █████░█████ ███████████░▓████░█████ ██████████▓█████▒▓████░███████▓█████████▓  
  ███   ███   ███▓  ███░  ███  ░███   ██▓  ▓██░  ███▒  ███    ▒██▒▓▓   ▒███     
</pre>

# Mnemonics
Implementation of BIP-39 in the C Programming Language.
In this binary (or code), we receive the number of bits as expected by the BIP-39 standard, which ranges from 128 to 256 bits. Using this, we will generate the mnemonic words, as well as the private key and public key.

## What We Are Doing

- **Generate entropy**: Create a sequence of random bits of size `N`, ranging from 128 to 256 bits (more bits provide better security). The number of bits must be a multiple of 32 (e.g., 128, 192, 256, etc.).
- **Determine the checksum (CS)**:
  - Divide the size of the entropy (in bits) by 32. The result, `N`, determines the number of bits to be used for the hash.
  - Compute the checksum (CS) by applying the SHA256 method to the previously generated entropy.
- **Concatenate entropy and checksum**:
  - Perform the concatenation: `INITIAL ENTROPY + CHECKSUM`.
- **Split into groups**:
  - Divide the concatenated result into groups of 11 bits each.
- **Map bits to words**:
  - For each group of 11 bits, convert the bits to a decimal (or hexadecimal) value.
  - Use this value as an index to select a word from a predefined wordlist.
- **Create the mnemonic**:
  - Combine the selected words into a single string and display the resulting mnemonic on the screen.
- **Perform the PBKDF2 operation**:
  - Use the mnemonic (the string of words) as input for the PBKDF2 operation.
  - **Salt**: Combine the mnemonic string with an optional passphrase.
  - **Output**: Generate 512 bits (64 bytes).
- **Generate deterministic wallets**:
  - Use the resulting seed to generate deterministic wallets using BIP-0032 or similar methods.

## Building:

On Windows: Requires linking with bcrypt.lib:

```
gcc program.c -lbcrypt -o program.exe  # MinGW
cl program.c /link bcrypt.lib          # MSVC
```

On Linux: 
```
gcc -o program program.c
```
