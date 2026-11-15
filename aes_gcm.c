#include "aes_gcm.h"

#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"

/* GCM permits at most 2^39 - 256 bits of plaintext per operation. */
#define AES_GCM_MAX_MESSAGE_BYTES UINT64_C(0xFFFFFFFE0)
#define AES_GCM_MAX_AAD_BYTES     (UINT64_MAX / 8)

static aes_gcm_status map_error(int result)
{
    if (result == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        return AES_GCM_AUTH_FAILED;
    }

    if (result == MBEDTLS_ERR_GCM_BAD_INPUT) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    return AES_GCM_INTERNAL_ERROR;
}

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
)
{
    uint8_t empty_input = 0;

    if (ciphertext_len == NULL) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    *ciphertext_len = 0;

    if (ciphertext == NULL || key == NULL || nonce == NULL) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    if ((plaintext == NULL && plaintext_len > 0) ||
        (aad == NULL && aad_len > 0)) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    if (plaintext_len > SIZE_MAX - AES_GCM_TAG_BYTES ||
        (uintmax_t)plaintext_len > AES_GCM_MAX_MESSAGE_BYTES ||
        (uintmax_t)aad_len > AES_GCM_MAX_AAD_BYTES) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    size_t required_capacity = plaintext_len + AES_GCM_TAG_BYTES;

    if (ciphertext_capacity < required_capacity) {
        return AES_GCM_BUFFER_TOO_SMALL;
    }

    const uint8_t *message =
        plaintext_len > 0 ? plaintext : &empty_input;

    const uint8_t *associated_data =
        aad_len > 0 ? aad : &empty_input;

    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    int result = mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key,
        AES_GCM_KEY_BYTES * 8
    );

    if (result == 0) {
        result = mbedtls_gcm_crypt_and_tag(
            &context,
            MBEDTLS_GCM_ENCRYPT,
            plaintext_len,
            nonce,
            AES_GCM_NONCE_BYTES,
            associated_data,
            aad_len,
            message,
            ciphertext,
            AES_GCM_TAG_BYTES,
            ciphertext + plaintext_len
        );
    }

    mbedtls_gcm_free(&context);

    if (result != 0) {
        mbedtls_platform_zeroize(ciphertext, required_capacity);
        return map_error(result);
    }

    *ciphertext_len = required_capacity;

    return AES_GCM_OK;
}

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
)
{
    uint8_t empty_input = 0;
    uint8_t empty_output = 0;

    if (plaintext_len == NULL) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    *plaintext_len = 0;

    if (ciphertext == NULL || key == NULL || nonce == NULL) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    if (aad == NULL && aad_len > 0) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    if (ciphertext_len < AES_GCM_TAG_BYTES) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    size_t message_len = ciphertext_len - AES_GCM_TAG_BYTES;

    if ((uintmax_t)message_len > AES_GCM_MAX_MESSAGE_BYTES ||
        (uintmax_t)aad_len > AES_GCM_MAX_AAD_BYTES) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    if (plaintext == NULL && message_len > 0) {
        return AES_GCM_INVALID_ARGUMENT;
    }

    if (plaintext_capacity < message_len) {
        return AES_GCM_BUFFER_TOO_SMALL;
    }

    uint8_t *message =
        message_len > 0 ? plaintext : &empty_output;

    const uint8_t *associated_data =
        aad_len > 0 ? aad : &empty_input;

    const uint8_t *tag = ciphertext + message_len;

    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);

    int result = mbedtls_gcm_setkey(
        &context,
        MBEDTLS_CIPHER_ID_AES,
        key,
        AES_GCM_KEY_BYTES * 8
    );

    if (result == 0) {
        result = mbedtls_gcm_auth_decrypt(
            &context,
            message_len,
            nonce,
            AES_GCM_NONCE_BYTES,
            associated_data,
            aad_len,
            tag,
            AES_GCM_TAG_BYTES,
            ciphertext,
            message
        );
    }

    mbedtls_gcm_free(&context);

    if (result != 0) {
        mbedtls_platform_zeroize(message, message_len);
        return map_error(result);
    }

    *plaintext_len = message_len;

    return AES_GCM_OK;
}