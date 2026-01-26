// crypto.h
/*
hashing pass
cifred msg(chacha20-poly1305)
gen digits randoms secures
*/

#ifndef CRYPTO_H
#define CRYPTO_H

//#include <cstddef>
#include <stddef.h>
#include <stdint.h>
//#include <cstdint>
//#include <stdint.h>
//#include <stddef.h>

// constants crypto

#define CRYPTO_SALT_SIZE 32        /* 256 bits de salt */
#define CRYPTO_HASH_SIZE 32        /* SHA-256 output */
#define CRYPTO_KEY_SIZE 32         /* ChaCha20 key size */
#define CRYPTO_NONCE_SIZE 12       /* ChaCha20 nonce */
#define CRYPTO_TAG_SIZE 16         /* Poly1305 MAC tag */
#define PBKDF2_ITERATIONS 100000   /* OWASP */

// == crypto hash == //
// almacena hash y salt usados
// el salt debe ser random y unico por usser

typedef struct{
    uint8_t hash[CRYPTO_HASH_SIZE]; // hash PBKDF2
    uint8_t salt[CRYPTO_SALT_SIZE]; // salt used
    uint32_t iterations; // num interations
} CryptoHash;


// == crypto msg == //
// use chacha20-poly1305 (AEAD - auth encryption with associated data)
// [ADV] previene ataques de manipulacion del ciphertext

typedef struct{
    uint8_t *ciphertext; // data cifrada
    size_t ciphertextLen; // logitud to ciphertext
    uint8_t nonce[CRYPTO_NONCE_SIZE]; // nonce = never reusar
    uint8_t tag[CRYPTO_TAG_SIZE]; // MAC tag para auth
} CryptoMessage;



// == gen digits random == //
// [Ghx] bets use /dev/urandom in linux(best entropia)
// [WARN] no use rand() is predecible

// buffer Buffer donde escribir the bytes
// size Num de bytes a generar

int cryptoRandomBytes(uint8_t *buffer, size_t size);



// == hashing passwd == //
// deriva clave secura a la pass
// the salt previene rainbow tables
// las iteraciones encarecen ataks de fuerza bruta

// gen salt random
// aplica PBKDF2 CON 100k iteraciones
// returna hash(256Bytes)

int cryptoHashPassword(
    const char *password,
    size_t padLen,
    const uint8_t *salt,
    CryptoHash *result
);


// == verify password == //
// use comparacion de tiempo constante
// prevenir timming ataks

int cryptoVerifyPassword(
    const char *password,
    size_t padLen,
    const CryptoHash *storedHash
);


// == crypto msgs == //
// cifra mensaje con chacha20-poly1305

// genera nonce random
// cifrado plaintext
// genera MAC con tag Poly1305
// returna ciphertext + nonce + tag

int cryptoEncryptMessage(
    const uint8_t *plaintext,
    size_t plaintextLen,
    const uint8_t key[CRYPTO_KEY_SIZE],
    CryptoMessage *result
);


// == decrypt msg == //
// descifra mensaje con chacha20-poly1305

// verifica el MAC tag(Poly1305)
// si es valido descifra, else = rechazo mensaje

int cryptoDecryptMessage(
    const CryptoMessage *encrypted,
    const uint8_t key[CRYPTO_KEY_SIZE],
    uint8_t **plaintext,
    size_t *plaintextLen
);


// == gestor memory == //
// libera memoria sensible de forma segura

// memset() puede ser optimizado por el compilador
// claves en memoria pueden ser leidas
// garantizado borrado real(reescritura)

// explicit_bzero() u volatile

void cryptoSecureZero(void *ptr, size_t size);


// libera CryptoMessage y libera memory
void cryptoFreeMessage(CryptoMessage *msg);





/* utilities */

// N1 = convierte bytes array to hexodecimal
void cryptoBytesToHex(const uint8_t *bytes, size_t len, char *hexOut);

// N2 = convierte hexodecimal to bytes
int cryptoHexToBytes(const char *hex, uint8_t *bytesOut, size_t maxLen);

#endif // !CRYPTO
