#ifndef NEURO_LWC_ASCON_AEAD_H
#define NEURO_LWC_ASCON_AEAD_H

#include <stddef.h>
#include <stdint.h>

#define ASCON_AEAD_KEY_BYTES   16
#define ASCON_AEAD_NONCE_BYTES 16
#define ASCON_AEAD_TAG_BYTES   16

typedef enum {
    ASCON_AEAD_OK = 0,
    ASCON_AEAD_INVALID_ARGUMENT = -1,
    ASCON_AEAD_BUFFER_TOO_SMALL = -2,
    ASCON_AEAD_AUTH_FAILED = -3
} ascon_aead_status;

/* Output format: ciphertext followed by the authentication tag.
 * Required capacity: plaintext_len + ASCON_AEAD_TAG_BYTES.
 * Input and output buffers must not overlap.
 */
ascon_aead_status ascon_aead_encrypt(
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t key[ASCON_AEAD_KEY_BYTES],
    const uint8_t nonce[ASCON_AEAD_NONCE_BYTES]
);

/* ciphertext_len includes the authentication tag.
 * Required capacity: ciphertext_len - ASCON_AEAD_TAG_BYTES.
 * Input and output buffers must not overlap.
 * Plaintext must only be used when the return value is ASCON_AEAD_OK.
 */
ascon_aead_status ascon_aead_decrypt(
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t key[ASCON_AEAD_KEY_BYTES],
    const uint8_t nonce[ASCON_AEAD_NONCE_BYTES]
);

#endif