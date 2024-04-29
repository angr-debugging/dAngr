// gcc -o aes_example generateDemoKey.c -lcrypto
#include "openssl/aes.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void initialize_aes_key(const char* userkey, AES_KEY *key) {
    // Code to initialize AES key
    int encryptKey;
    encryptKey = AES_set_encrypt_key((const unsigned char*)userkey,128,key);
    if (encryptKey < 0) {
        fprintf(stderr, "AES key initialization failed.\n");
        exit(1);
    }
}

void AES_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const AES_KEY *key) {
    AES_ecb_encrypt(plaintext, ciphertext, key, 0);
}

char* obfuscate(char* secret, char* randomValue){
     // Calculate the lengths of the input strings
    size_t randomLen = strlen(randomValue);
    size_t secretLen = strlen(secret);

    // Allocate memory for the obfuscated key
    char* obfuscatedKey = (char*)malloc(randomLen + secretLen + 1);
    if (obfuscatedKey == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
    }
      // XOR operation to obfuscate the key
    for (size_t i = 0; i < randomLen; i++) {
        obfuscatedKey[i] = randomValue[i] ^ secret[i % secretLen];
    }

    // Copy the remaining part of the secret if it's longer than the randomValue
    for (size_t i = randomLen; i < randomLen + secretLen; i++) {
        obfuscatedKey[i] = secret[i - randomLen] ^ randomValue[i % randomLen];
    }

    // Null-terminate the obfuscated key
    obfuscatedKey[randomLen + secretLen] = '\0';

    return obfuscatedKey;
}

int main(){
    char* secret = "VerySafeSecret";
    char* randomVal = "12345678910";
    const unsigned char plaintext[] = "dAngrIsVeryNice";
    unsigned char ciphertext[AES_BLOCK_SIZE]; 

    printf("An AES encrypted message is created. The AES key is ininitialized using an obfuscated key.\nThis obfuscated key is created based on a secret and randomVal\n");

    printf("The goal of reverse engineering would be to find the obfuscated key used to genenerate an AES Key\n\n");
    printf("Manually reversing the obfuscate function, could take a lot of time in the case of a more complex obfuscation algorithm\n");
    printf("This is where dAngr comes in, instead of spending time on reversing the obfuscation algorithm to recreate the obfuscated key,\nwe can simply step though this code using dAngr and get the obfuscated key\n");
    printf("dAngr provides a gdb like interface, and also works on non-native binaries.\n");


    printf("(In a more realistic scenario, the random value and secret would not be discoverable in the same file in cleartext ;) )\n");

    char* obfuscatedKey = obfuscate(secret, randomVal);
    //printf("obfuscated key: %s\n", obfuscatedKey);
    // Initialize AES key using the obfuscated key
    AES_KEY aesKey;
    initialize_aes_key(obfuscatedKey, &aesKey);
    //printf("aes key: %s\n", &aesKey);

    //printf("encrypting plaintext\n");
    // Encrypt plaintext using the initialized key
    AES_encrypt(plaintext, ciphertext, &aesKey);
    //printf("ciphertext: %s\n", &ciphertext);

    printf("\nCiphertext: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    return 0;

}