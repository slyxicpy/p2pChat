#include "../include/crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


int cryptoRandomBytes(uint8_t *buffer, size_t size){
    if(RAND_bytes(buffer, size) != 1){
        fprintf(stderr, "[err] no se pudo generar bytes\n");
        return -1;
    }
    return 0;
}

int cryptoHashPassword(
    const char *password,
    size_t pwdLen,
    const uint8_t *salt,
    CryptoHash *result
){
    uint8_t localSalt[CRYPTO_SALT_SIZE];

    if(salt == NULL){
        if(cryptoRandomBytes(localSalt, CRYPTO_SALT_SIZE) != 0){
            return -1;
        }
        salt = localSalt;
    }

    memcpy(result->salt, salt, CRYPTO_SALT_SIZE);
    result->iterations = PBKDF2_ITERATIONS;

    if(PKCS5_PBKDF2_HMAC(
            password,
            pwdLen,
            salt,
            CRYPTO_SALT_SIZE,
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            CRYPTO_HASH_SIZE,
            result->hash
        ) != 1){
        fprintf(stderr, "[error]error in PBKDF2\n");
        return -1;
    }
    return 0;
}

int cryptoVerifyPassword(
    const char *password,
    size_t pwdLen,
    const CryptoHash *storedHash
){
    CryptoHash computed;
    if(cryptoHashPassword(password, pwdLen, storedHash->salt, &computed) != 0){
        return -1;
    }

    if(CRYPTO_memcmp(computed.hash, storedHash->hash, CRYPTO_HASH_SIZE) == 0){
        return 1;
    }

    return 0;
}


int cryptoEncryptMessage(
    const uint8_t *plaintext,
    size_t plaintextLen,
    const uint8_t key[CRYPTO_KEY_SIZE],
    CryptoMessage *result
){
    EVP_CIPHER_CTX *ctx = NULL;
    int len, cipherTextLen;

    if(cryptoRandomBytes(result->nonce, CRYPTO_NONCE_SIZE) != 0){
        return -1;
    }

    result->ciphertext = malloc(plaintextLen);
    if(result->ciphertext == NULL){
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        free(result->ciphertext);
        return -1;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, result->nonce) != 1){
        EVP_CIPHER_CTX_free(ctx);
        free(result->ciphertext);
        return -1;
    }

    if(EVP_EncryptUpdate(ctx, result->ciphertext, &len, plaintext, plaintextLen) != 1){
        EVP_CIPHER_CTX_free(ctx);
        free(result->ciphertext);
        return -1;
    }

    cipherTextLen = len;

    if(EVP_EncryptFinal_ex(ctx, result->ciphertext + len, &len) != 1){
        EVP_CIPHER_CTX_free(ctx);
        free(result->ciphertext);
        return -1;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CRYPTO_TAG_SIZE, result->tag) != 1){
        EVP_CIPHER_CTX_free(ctx);
        free(result->ciphertext);
        return -1;
    }

    result->ciphertextLen = cipherTextLen;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


int cryptoDecryptMessage(
    const CryptoMessage *encrypted,
    const uint8_t key[CRYPTO_KEY_SIZE],
    uint8_t **plaintext,
    size_t *plaintextLen
){
    EVP_CIPHER_CTX *ctx = NULL;
    int len, totalLen;

    // Alocar buffer para plaintext
    *plaintext = malloc(encrypted->ciphertextLen);
    if (*plaintext == NULL) {
        return -1;
    }

    // Crear contexto
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(*plaintext);
        return -1;
    }

    // Inicializar descifrado
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, encrypted->nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }

    // Descifrar
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, encrypted->ciphertext, encrypted->ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    totalLen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CRYPTO_TAG_SIZE,
                            (void*)encrypted->tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cryptoSecureZero(*plaintext, totalLen);
        free(*plaintext);
        *plaintext = NULL;
        return -1;
    }
    totalLen += len;

    *plaintextLen = totalLen;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


void cryptoSecureZero(void *ptr, size_t size){
    OPENSSL_cleanse(ptr, size);
}


void cryptoFreeMessage(CryptoMessage *msg){
    if(msg == NULL) return;
    if(msg->ciphertext != NULL){
        cryptoSecureZero(msg->ciphertext, msg->ciphertextLen);
        free(msg->ciphertext);
        msg->ciphertext = NULL;
    }
    cryptoSecureZero(msg->nonce, CRYPTO_NONCE_SIZE);
    cryptoSecureZero(msg->tag, CRYPTO_TAG_SIZE);
}


// Utilities

void cryptoBytesToHex(const uint8_t *bytes, size_t len, char *hexOut) {

    const char *hexChars = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        hexOut[i * 2] = hexChars[(bytes[i] >> 4) & 0x0F];
        hexOut[i * 2 + 1] = hexChars[bytes[i] & 0x0F];
    }
    hexOut[len * 2] = '\0';
}

int cryptoHexToBytes(const char *hex, uint8_t *bytesOut, size_t maxLen) {
    /*
     * Convierte hexadecimal a bytes
     */
    size_t hexLen = strlen(hex);

    if (hexLen % 2 != 0) {
        return -1;
    }

    size_t byteLen = hexLen / 2;
    if (byteLen > maxLen) {
        return -1;  // Buffer pequeño
    }

    for (size_t i = 0; i < byteLen; i++) {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        bytesOut[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    return byteLen;
}





