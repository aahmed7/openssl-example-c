#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* WARNING: these keys are exposed just for purpose of testing. */
/* For production, DO NOT HARDCODE KEYS into the code. */
static const unsigned char salt[] = "BAA4C5A6E18B54A4";
static const unsigned char key[] =
    "A55AF00D8345F614F7677334A8B5BA3A0A21AFEDA7E7E41C951BE4393658C3FC";
static const unsigned char iv[] = "4A03FB2A6E1434C386180A5358680F54";
static const unsigned int  keyLength = 256;
unsigned char              enc_out[AES_BLOCK_SIZE];  // Set to 16 bytes

void aes_encrypt() {
    AES_KEY       enc_key;
    unsigned char text[] = "hello world!";

    AES_set_encrypt_key(key, keyLength, &enc_key);
    AES_encrypt(text, enc_out, &enc_key);
}

void aes_decrypt() {
    AES_KEY       dec_key;
    unsigned char dec_out[AES_BLOCK_SIZE];

    AES_set_decrypt_key(key, keyLength, &dec_key);
    AES_decrypt(enc_out, dec_out, &dec_key);

    printf("%s\n", enc_out);
    printf("%s\n", dec_out);
}

int main(void) {
    aes_encrypt();
    aes_decrypt();

    return 0;
}