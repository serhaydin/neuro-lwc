#ifndef NEURO_LWC_AES_GCM_H
#define NEURO_LWC_AES_GCM_H

#include <stddef.h>
#include <stdint.h>

#define AES_GCM_KEY_BYTES   16
#define AES_GCM_NONCE_BYTES 12
#define AES_GCM_TAG_BYTES   16

typedef enum {
    AES_GCM_OK = 0,
    AES_GCM_INVALID_ARGUMENT = -1,
    AES_GCM_BUFFER_TOO_SMALL = -2,
    AES_GCM_AUTH_FAILED = -3,
    AES_GCM_INTERNAL_ERROR = -4
} aes_gcm_status;

/*
 * Output format: ciphertext followed by the authentication tag.
 * Required capacity: plaintext_len + AES_GCM_TAG_BYTES.
 * Input and output buffers must not overlap.
 *
 * plaintext and aad may be NULL only when their lengths are zero.
 * ciphertext, ciphertext_len, key and nonce must not be NULL.
 * ciphertext_len is set to zero on failure when provided.
 *
 * Never reuse a nonce with the same key.
 */
aes_gcm_status aes_gcm_encrypt(
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t key[AES_GCM_KEY_BYTES],
    const uint8_t nonce[AES_GCM_NONCE_BYTES]
);

/*
 * ciphertext_len includes the authentication tag.
 * Required capacity: ciphertext_len - AES_GCM_TAG_BYTES.
 * ciphertext_len must be at least AES_GCM_TAG_BYTES.
 * Input and output buffers must not overlap.
 *
 * aad may be NULL only when aad_len is zero.
 * plaintext may be NULL only when the expected plaintext is empty.
 * ciphertext, plaintext_len, key and nonce must not be NULL.
 * plaintext_len is set to zero on failure when provided.
 *
 * Plaintext must only be used when the return value is AES_GCM_OK.
 */
aes_gcm_status aes_gcm_decrypt(
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t key[AES_GCM_KEY_BYTES],
    const uint8_t nonce[AES_GCM_NONCE_BYTES]
);

#endif