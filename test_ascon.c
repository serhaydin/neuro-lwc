#include "ascon_aead.h"

#include <stdio.h>
#include <string.h>

static int checks = 0;
static int failures = 0;

#define CHECK(condition, description)                  \
    do {                                               \
        ++checks;                                      \
        if (condition) {                               \
            printf("[PASS] %s\n", description);         \
        } else {                                       \
            printf("[FAIL] %s\n", description);         \
            ++failures;                                \
        }                                              \
    } while (0)

static int is_zero(const uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        if (buffer[i] != 0) {
            return 0;
        }
    }

    return 1;
}

/* Check rejection, zero output length and removal of temporary plaintext. */
static void check_auth_failure(
    const char *description,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *key,
    const uint8_t *nonce
)
{
    uint8_t output[128];
    size_t output_len = 999;

    memset(output, 0xAA, sizeof(output));

    ascon_aead_status status = ascon_aead_decrypt(
        output, sizeof(output), &output_len,
        ciphertext, ciphertext_len,
        aad, aad_len,
        key, nonce
    );

    CHECK(
        status == ASCON_AEAD_AUTH_FAILED &&
        output_len == 0 &&
        is_zero(output, ciphertext_len - ASCON_AEAD_TAG_BYTES),
        description
    );
}

int main(void)
{
    uint8_t key[ASCON_AEAD_KEY_BYTES];
    uint8_t nonce[ASCON_AEAD_NONCE_BYTES];
    uint8_t message[128];
    const uint8_t aad[] = {0x01, 0x02, 0x03, 0x04};

    uint8_t ciphertext[sizeof(message) + ASCON_AEAD_TAG_BYTES];
    uint8_t recovered[sizeof(message)];
    size_t ciphertext_len = 0;
    size_t recovered_len = 0;

    /*
     * Fixed values are for repeatable tests only.
     * Production code must not reuse a nonce with the same key.
     */
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
    }

    for (size_t i = 0; i < sizeof(nonce); ++i) {
        nonce[i] = (uint8_t)(0x10 + i);
    }

    for (size_t i = 0; i < sizeof(message); ++i) {
        message[i] = (uint8_t)i;
    }

    /* 1. Encrypt and decrypt a 128-byte EEG-sized payload. */
    ascon_aead_status status = ascon_aead_encrypt(
        ciphertext, sizeof(ciphertext), &ciphertext_len,
        message, sizeof(message),
        aad, sizeof(aad),
        key, nonce
    );

    CHECK(
        status == ASCON_AEAD_OK &&
        ciphertext_len == sizeof(message) + ASCON_AEAD_TAG_BYTES,
        "Encrypt 128-byte payload"
    );

    /* Later tests require a valid ciphertext. */
    if (status != ASCON_AEAD_OK ||
        ciphertext_len != sizeof(ciphertext)) {
        return 1;
    }

    status = ascon_aead_decrypt(
        recovered, sizeof(recovered), &recovered_len,
        ciphertext, ciphertext_len,
        aad, sizeof(aad),
        key, nonce
    );

    CHECK(
        status == ASCON_AEAD_OK &&
        recovered_len == sizeof(message) &&
        memcmp(message, recovered, sizeof(message)) == 0,
        "Decrypt and recover original payload"
    );

    /* 2. Reject modified ciphertext. */
    uint8_t modified[sizeof(ciphertext)];
    memcpy(modified, ciphertext, sizeof(modified));
    modified[0] ^= 0x01;

    check_auth_failure(
        "Reject modified ciphertext and clear plaintext",
        modified, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    /* 3. Reject a modified authentication tag. */
    memcpy(modified, ciphertext, sizeof(modified));
    modified[ciphertext_len - 1] ^= 0x01;

    check_auth_failure(
        "Reject modified tag and clear plaintext",
        modified, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    /* 4. Reject modified AAD. */
    uint8_t wrong_aad[sizeof(aad)];
    memcpy(wrong_aad, aad, sizeof(wrong_aad));
    wrong_aad[0] ^= 0x01;

    check_auth_failure(
        "Reject modified AAD",
        ciphertext, ciphertext_len,
        wrong_aad, sizeof(wrong_aad), key, nonce
    );

    /* 5. Reject a wrong key. */
    uint8_t wrong_key[sizeof(key)];
    memcpy(wrong_key, key, sizeof(wrong_key));
    wrong_key[0] ^= 0x01;

    check_auth_failure(
        "Reject wrong key",
        ciphertext, ciphertext_len,
        aad, sizeof(aad), wrong_key, nonce
    );

    /* 6. Reject a wrong nonce. */
    uint8_t wrong_nonce[sizeof(nonce)];
    memcpy(wrong_nonce, nonce, sizeof(wrong_nonce));
    wrong_nonce[0] ^= 0x01;

    check_auth_failure(
        "Reject wrong nonce",
        ciphertext, ciphertext_len,
        aad, sizeof(aad), key, wrong_nonce
    );

    /* 7. Reject insufficient output buffers. */
    size_t output_len = 999;

    status = ascon_aead_encrypt(
        modified, sizeof(modified) - 1, &output_len,
        message, sizeof(message),
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == ASCON_AEAD_BUFFER_TOO_SMALL && output_len == 0,
        "Reject small encryption buffer"
    );

    output_len = 999;

    status = ascon_aead_decrypt(
        recovered, sizeof(recovered) - 1, &output_len,
        ciphertext, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == ASCON_AEAD_BUFFER_TOO_SMALL && output_len == 0,
        "Reject small decryption buffer"
    );

    /* 8. Reject inputs shorter than the authentication tag. */
    output_len = 999;

    status = ascon_aead_decrypt(
        recovered, sizeof(recovered), &output_len,
        ciphertext, ASCON_AEAD_TAG_BYTES - 1,
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == ASCON_AEAD_INVALID_ARGUMENT && output_len == 0,
        "Reject ciphertext shorter than tag"
    );

    /* 9. Reject NULL data with a nonzero length. */
    output_len = 999;

    status = ascon_aead_encrypt(
        modified, sizeof(modified), &output_len,
        NULL, 1,
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == ASCON_AEAD_INVALID_ARGUMENT && output_len == 0,
        "Reject NULL plaintext with nonzero length"
    );

    output_len = 999;

    status = ascon_aead_encrypt(
        modified, sizeof(modified), &output_len,
        message, sizeof(message),
        NULL, 1, key, nonce
    );

    CHECK(
        status == ASCON_AEAD_INVALID_ARGUMENT && output_len == 0,
        "Reject NULL AAD with nonzero length"
    );

    status = ascon_aead_encrypt(
        modified, sizeof(modified), NULL,
        message, sizeof(message),
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == ASCON_AEAD_INVALID_ARGUMENT,
        "Reject NULL output-length pointer"
    );

    /* 10. Exercise partial blocks and exact block boundaries. */
    const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 128};

    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t length = lengths[i];
        uint8_t case_nonce[ASCON_AEAD_NONCE_BYTES];
        char description[80];

        memcpy(case_nonce, nonce, sizeof(case_nonce));
        case_nonce[0] = (uint8_t)(0x80 + i);

        ciphertext_len = 0;
        recovered_len = 0;

        status = ascon_aead_encrypt(
            ciphertext, sizeof(ciphertext), &ciphertext_len,
            length > 0 ? message : NULL, length,
            NULL, 0, key, case_nonce
        );

        int passed =
            status == ASCON_AEAD_OK &&
            ciphertext_len == length + ASCON_AEAD_TAG_BYTES;

        if (passed) {
            status = ascon_aead_decrypt(
                length > 0 ? recovered : NULL,
                length,
                &recovered_len,
                ciphertext, ciphertext_len,
                NULL, 0, key, case_nonce
            );

            passed =
                status == ASCON_AEAD_OK &&
                recovered_len == length;

            if (passed && length > 0) {
                passed = memcmp(message, recovered, length) == 0;
            }
        }

        snprintf(
            description, sizeof(description),
            "Round trip: %zu bytes, empty AAD", length
        );

        CHECK(passed, description);
    }

    printf(
        "\nChecks: %d | Passed: %d | Failed: %d\n",
        checks, checks - failures, failures
    );

    return failures == 0 ? 0 : 1;
}