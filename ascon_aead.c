#include "ascon_aead.h"
#include "crypto_aead.h"

#include <limits.h>

/* Prevent the compiler from removing the clearing operation. */
static void clear_buffer(uint8_t *buffer, size_t length)
{
    volatile uint8_t *p = buffer;

    while (length > 0) {
        *p++ = 0;
        --length;
    }
}

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
)
{
    uint8_t empty_input = 0;
    unsigned long long output_len = 0;

    if (ciphertext_len == NULL) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    *ciphertext_len = 0;

    if (ciphertext == NULL || key == NULL || nonce == NULL) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    if ((plaintext == NULL && plaintext_len > 0) ||
        (aad == NULL && aad_len > 0)) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    /* Check both our length type and the reference API's length type. */
    if (plaintext_len > SIZE_MAX - ASCON_AEAD_TAG_BYTES ||
        (uintmax_t)plaintext_len >
            (uintmax_t)ULLONG_MAX - ASCON_AEAD_TAG_BYTES ||
        (uintmax_t)aad_len > (uintmax_t)ULLONG_MAX) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    size_t required_capacity = plaintext_len + ASCON_AEAD_TAG_BYTES;

    if (ciphertext_capacity < required_capacity) {
        return ASCON_AEAD_BUFFER_TOO_SMALL;
    }

    /* Supply valid addresses even for empty inputs. */
    const uint8_t *message =
        plaintext_len > 0 ? plaintext : &empty_input;

    const uint8_t *associated_data =
        aad_len > 0 ? aad : &empty_input;

    crypto_aead_encrypt(
        ciphertext,
        &output_len,
        message,
        (unsigned long long)plaintext_len,
        associated_data,
        (unsigned long long)aad_len,
        NULL,
        nonce,
        key
    );

    /*
     * The selected reference implementation always returns 0 for
     * encryption and writes plaintext_len + tag bytes.
     */
    *ciphertext_len = (size_t)output_len;

    return ASCON_AEAD_OK;
}

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
)
{
    uint8_t empty_input = 0;
    uint8_t empty_output = 0;
    unsigned long long output_len = 0;

    if (plaintext_len == NULL) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    *plaintext_len = 0;

    if (ciphertext == NULL || key == NULL || nonce == NULL) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    if (aad == NULL && aad_len > 0) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    if (ciphertext_len < ASCON_AEAD_TAG_BYTES ||
        (uintmax_t)ciphertext_len > (uintmax_t)ULLONG_MAX ||
        (uintmax_t)aad_len > (uintmax_t)ULLONG_MAX) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    size_t required_capacity = ciphertext_len - ASCON_AEAD_TAG_BYTES;

    if (plaintext == NULL && required_capacity > 0) {
        return ASCON_AEAD_INVALID_ARGUMENT;
    }

    if (plaintext_capacity < required_capacity) {
        return ASCON_AEAD_BUFFER_TOO_SMALL;
    }

    uint8_t *message =
        required_capacity > 0 ? plaintext : &empty_output;

    const uint8_t *associated_data =
        aad_len > 0 ? aad : &empty_input;

    int result = crypto_aead_decrypt(
        message,
        &output_len,
        NULL,
        ciphertext,
        (unsigned long long)ciphertext_len,
        associated_data,
        (unsigned long long)aad_len,
        nonce,
        key
    );

    if (result != 0) {
        clear_buffer(message, required_capacity);
        return ASCON_AEAD_AUTH_FAILED;
    }

    *plaintext_len = (size_t)output_len;

    return ASCON_AEAD_OK;
}