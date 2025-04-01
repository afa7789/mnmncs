<pre>                                                                                
  ▓█   ▒█▓   ▒█░   ░█▓   ▓█░   ██   ▒█▒   ▓█░   ██   ░█▒        █▓      ░██   █▒
▓████▓█████▓██████████████████████▓█████▓███████████▓█████▓  ░██████▓ ▒████████ 
 ▒████ ████▓░████░ ▓███▒░███▓ ▒███▓ ▓███▒░████ ░████░▒████ ░███▓███▒▓███░▓███▓  
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ░███░ ████  ████  ████  ███▒ █▒ ▓███   █▓   
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ░███░ ▓███  ████  ████  ███▒    ████▓░███▒  
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▓ ░███░ ████  ████  ████  ███▒    ███████████ 
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ▒███░ ████  ████  ████  ███▒      ▓█▒  ███▓ 
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ▒███░ ████  ████  ████  ███▒     ▒█░   ███▓ 
 ░████ ▒███▓ ▓███░ ▓███▒ ████░░███▓ ▒███▒ ████░ ████  ████  █████░▓██████▓ ████ 
 █████▓█████░▓████▓█████ ██████████▒█████░▓████▒█████ ████▓░▓█████▓█████████▒   
  ░█▓   ░█▒   ░█▓    █▒   ▒█░   ██    █▓   ░█▓   ▓█▒   ▒█▒    ░██ █░    ██░     
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

## Running it:

```
gcc -w mnemonics.c cpto/cpto.c  -o out && ./out 256 1
```

### Example Output
<pre>
➜  mnmncs git:(master) ✗ gcc -w mnemonics.c cpto/cpto.c  -o out && ./out 256 1

  ▓█   ▒█▓   ▒█░   ░█▓   ▓█░   ██   ▒█▒   ▓█░   ██   ░█▒        █▓      ░██   █▒
▓████▓█████▓██████████████████████▓█████▓███████████▓█████▓  ░██████▓ ▒████████
 ▒████ ████▓░████░ ▓███▒░███▓ ▒███▓ ▓███▒░████ ░████░▒████ ░███▓███▒▓███░▓███▓ 
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ░███░ ████  ████  ████  ███▒ █▒ ▓███   █▓  
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ░███░ ▓███  ████  ████  ███▒    ████▓░███▒ 
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▓ ░███░ ████  ████  ████  ███▒    ███████████
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ▒███░ ████  ████  ████  ███▒      ▓█▒  ███▓
  ███▓ ░███░ ▓███  ▒███░ ▓██▓  ███▒ ▒███░ ████  ████  ████  ███▒     ▒█░   ███▓
 ░████ ▒███▓ ▓███░ ▓███▒ ████░░███▓ ▒███▒ ████░ ████  ████  █████░▓██████▓ ████
 █████▓█████░▓████▓█████ ██████████▒█████░▓████▒█████ ████▓░▓█████▓█████████▒  
  ░█▓   ░█▒   ░█▓    █▒   ▒█░   ██    █▓   ░█▓   ▓█▒   ▒█▒    ░██ █░    ██░    
Entropy (hex): c816cdaa0573e1bd3c459b257621f6a73847edc42637896d706d9b10d70ad9bfcbf87067a481c2796ed27e2800274370a0f92e2fa5196909770b40eae6897342f95b5941133f590e650a34e4d2705cadbe842e661b689cd9b5a1cd4d9e592224cb6bd71fabe3555ce00abddcddecb29e61134ff30fde2e7ae695c895a29c982fce3d67d5bc70a9eeeaffbdf10347444060918974ab65057193698346149e974d842d8f504e8ca6f060e0e8bb68b97e42980ec4375a1b7f5848f140f8b4d152e4c1845f9d0293a29432c62aa6be9d7eac3c3f4f2c5d779f3d75e460a903e775eaf7fb543d650befd8db1aa416f8ee9c06fb975e7f106a44c02b109a4162d0b657
Hash (hex): 8f06c5922403b39b9549701db27d89f70c2797fc937086ec2abd6e85f8834304
With CS concat Entropy (hex): c816cdaa0573e1bd3c459b257621f6a73847edc42637896d706d9b10d70ad9bfcbf87067a481c2796ed27e2800274370a0f92e2fa5196909770b40eae6897342f95b5941133f590e650a34e4d2705cadbe842e661b689cd9b5a1cd4d9e592224cb6bd71fabe3555ce00abddcddecb29e61134ff30fde2e7ae695c895a29c982fce3d67d5bc70a9eeeaffbdf10347444060918974ab65057193698346149e974d842d8f504e8ca6f060e0e8bb68b97e42980ec4375a1b7f5848f140f8b4d152e4c1845f9d0293a29432c62aa6be9d7eac3c3f4f2c5d779f3d75e460a903e775eaf7fb543d650befd8db1aa416f8ee9c06fb975e7f106a44c02b109a4162d0b6578f06c5922403b39b

mnemonics words 24:
recall shoulder west shallow
coffee clock olympic open
kit rural fresh wide
trigger honey antenna sign
chimney fame maple benefit
law indicate clump inflict

BIP-39 Seed (hex): 2e3b9a265e97bc70437ab23a80faa0ee6038bb0fb7a1fdd6592f0ebec3e421768cdfe1c99d480ceba699c7cd0432fe83a425671fc7c3a3c18386a075170eb740

                                             ♠♡♦♧ - don't trust, verify
</pre>

## BIP-32 getting pub and priv key

After you get the private_key you can also run the `bip32.c` to get the private_key and WIF to be able to import in Electrum.

- building it:
`gcc -w bip32.c cpto/cpto.c -o bip32`

- running: 
`./bip32 2f00201a843bf367ed45fda52ea0d3aba21ee730ad1a93189e67ae0e6faae4bb3a32629b955d1cfcde3becc25f2e39519e1e5d9ee8318c6217b11bcedb9f9683`

- output example:
```
➜  mnmncs git:(master) ✗ ./bip32 2f00201a843bf367ed45fda52ea0d3aba21ee730ad1a93189e67ae0e6faae4bb3a32629b955d1cfcde3becc25f2e39519e1e5d9ee8318c6217b11bcedb9f9683


 BIP-32 creating pubkey and privkey to importInput BIP-39 Seed (hex):
Seed: 2f00201a843bf367ed45fda52ea0d3aba21ee730ad1a93189e67ae0e6faae4bb3a32629b955d1cfcde3becc25f2e39519e1e5d9ee8318c6217b11bcedb9f9683

BIP-32 Master Key Derivation Results:
Master Private Key: 673cb61cbdeb67b8ecce8c44021defa992787c546569327b4328fe809de31ccb
Master Chain Code: 6552afdf4bc3a927795fb55a2ac9a7374747be8023329937157a95cae49b200f

Electrum using xpriv

xprv: xprv9s21ZrQH143K34sBvFpfdXVRV7hj5YXScWB3oSQBZuh74XLM1eYMZybGPy9eggeB92J2Ts7QGK5Z189k9xoopp5j1tBAfH7CEhbbdP5CDUH

To create a spending wallet, please enter a master private key (xprv/yprv/zprv).
NewWallet -> standardWallet -> use a masterKey -> PASTER the Xpriv above.
Electrum using WIF

WIF: 5JbkdquZp2ddnnng1FAsdmRjZLiEdEtk3j6HwNL7iCaoZVrguzQ

The WIF is a Single-Key Wallet. "Enter a list of Bitcoin addresses (this will create a watching-only wallet), or a list of private keys."
New Wallet -> Import Bitcoin addresses or private keys -> paste it and click next -> setup password, done.

                                      ₿☀🦄ᚠ - you can just build things
```