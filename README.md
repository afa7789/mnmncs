                                                                                
  ██   ▒██░   ██░    ██▒   ██░   ▓█▓   ▒██   ▓██   ▓██░       ███      ░███░  ▓░
████████████████████████████████████████████████████████▓  ▒███████▓▒▓████████░ 
 ░████ ░████  ████  ░████  ████  ▓███▒ ▒███░ ▒███▓  ████  ████░▓██ ░███▒ ▒███░  
  ███▓  ████  ████   ████  ████  ▒███  ░███░  ███▒  ▓███  ▓███  ▓░ ░███▒  ░█    
  ███▓  ████  ████   ████  ████  ▒███  ░███░  ███▒  ▓███  ▓███     ▓████ ▓███   
  ████  ████  ████   ███▓  ████  ▒███  ░███░  ███▓  ▓███  ▓███     ███████████▓ 
  ███▓  ████  ████   ████  ████  ▓███  ░███░  ███▓  ▓███  ▒███       ░█▓  ▒███▒ 
  ███▓  ████  ████   ████  ████  ▒███  ░███░  ███▓  ▓███  ▒███       ▓▓   ▒███▒ 
  ███▓  ████  ████   ████  ████  ▓███  ▒███▓ ░███▓  ████  ▓████  ▒▓▓████▓ ▒███▓ 
 █████▒█████▓░███████████▓▒███████████▒▓██████████▓░████▓▒███████▓██████████▒   
  ▓██░  ▒██▓   ▓██░  ░██▓   ██▓   ███   ▒██░  ▒██░   ▓██     ▓█▓░█░    ███     


# Mnemonics
Implementation of BIP-39 in c programming language.
In this binary // code we receive the number of bits as expecte by the BIP, between 128 to 256 and will create the mnemonics words and the private key plus public key

## What we are doing in it:
-> Generate entropy (random bits of size N), it can have from 128 to 256 (the more bits the better), but the number of bits must be a multiple of 32. (128, 192, 256, etc...)
-> Take the size (number of bits) of this entropy and divide it by 32, the result N, determines the number of BITS that will be used in the hash with the SHA256 method of the entropy that was previously generated, and this determines the CS (checksum)
-> We then do the concatenation of entropy + checksum.
concatenation = INITIAL ENTROPY + CHECKSUM
-> this concatenation will be separated into groups of 11 bits.
-> for each group of 11 bits we will take a word from a Wordlist (already predefined), the value converted from bits to hex//decimal is the index of this wordlist. -> Add each of these words to a string and display them on the screen :)
-> Using the mnemonic (the words), perform the "PBKDF2" operation
-> Salt: The "mnemonic" string + optionally a passphrase.
-> Output: 512 bits (64 bytes).
-> This seed can be later used to generate deterministic wallets using BIP-0032 or similar methods.

Basic prerequisites for doing the above:
-> generate entropy (Secure Random Number Generation)
-> Be able to SHA256 something.
-> concatenate BITS

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
