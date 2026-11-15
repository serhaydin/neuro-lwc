#include "aes_gcm.h"

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

    aes_gcm_status status = aes_gcm_decrypt(
        output, sizeof(output), &output_len,
        ciphertext, ciphertext_len,
        aad, aad_len, key, nonce
    );

    CHECK(
        status == AES_GCM_AUTH_FAILED &&
        output_len == 0 &&
        is_zero(output, ciphertext_len - AES_GCM_TAG_BYTES),
        description
    );
}

/* Decode the fixed hexadecimal strings used by the test vectors. */
static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

static int decode_hex(
    const char *hex,
    uint8_t *output,
    size_t capacity,
    size_t *output_len
)
{
    size_t length = strlen(hex);
    *output_len = 0;

    if (length % 2 != 0 || length / 2 > capacity) {
        return 0;
    }

    for (size_t i = 0; i < length / 2; ++i) {
        int high = hex_value(hex[i * 2]);
        int low = hex_value(hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return 0;
        }

        output[i] = (uint8_t)((high << 4) | low);
    }

    *output_len = length / 2;
    return 1;
}

static void test_known_answers(void)
{
    /*
     * Published GCM vectors.
     * expected contains ciphertext followed by the 16-byte tag.
     * Repeated keys/nonces here reproduce fixed test vectors only.
     */
    const struct {
        const char *name;
        const char *key;
        const char *nonce;
        const char *plaintext;
        const char *aad;
        const char *expected;
    } vectors[] = {
        {
            "empty input",
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a"
        },
        {
            "16-byte input",
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "0388dace60b6a392f328c2b971b2fe78"
            "ab6e47d42cec13bdf53a67b21257bddf"
        },
        {
            "60-byte input with AAD",
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a8"
            "6a7a9531534f7da2e4c303d8a318a721"
            "c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
            "5bc94fbc3221a5db94fae95ae7121a47"
        }
    };

    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        uint8_t key[AES_GCM_KEY_BYTES];
        uint8_t nonce[AES_GCM_NONCE_BYTES];
        uint8_t plaintext[60];
        uint8_t aad[20];
        uint8_t expected[76];
        uint8_t ciphertext[76];
        uint8_t recovered[60];

        size_t key_len = 0;
        size_t nonce_len = 0;
        size_t plaintext_len = 0;
        size_t aad_len = 0;
        size_t expected_len = 0;
        size_t ciphertext_len = 0;
        size_t recovered_len = 0;

        char description[100];

        int decoded =
            decode_hex(
                vectors[i].key, key, sizeof(key), &key_len
            ) &&
            decode_hex(
                vectors[i].nonce, nonce, sizeof(nonce), &nonce_len
            ) &&
            decode_hex(
                vectors[i].plaintext,
                plaintext, sizeof(plaintext), &plaintext_len
            ) &&
            decode_hex(
                vectors[i].aad, aad, sizeof(aad), &aad_len
            ) &&
            decode_hex(
                vectors[i].expected,
                expected, sizeof(expected), &expected_len
            );

        if (!decoded ||
            key_len != AES_GCM_KEY_BYTES ||
            nonce_len != AES_GCM_NONCE_BYTES ||
            expected_len != plaintext_len + AES_GCM_TAG_BYTES) {
            CHECK(0, "KAT vector format");
            continue;
        }

        aes_gcm_status status = aes_gcm_encrypt(
            ciphertext, sizeof(ciphertext), &ciphertext_len,
            plaintext, plaintext_len,
            aad, aad_len,
            key, nonce
        );

        snprintf(
            description, sizeof(description),
            "KAT %s: encryption", vectors[i].name
        );

        CHECK(
            status == AES_GCM_OK &&
            ciphertext_len == expected_len &&
            memcmp(ciphertext, expected, expected_len) == 0,
            description
        );

        /* Decrypt the published output, not our encryption output. */
        status = aes_gcm_decrypt(
            recovered, sizeof(recovered), &recovered_len,
            expected, expected_len,
            aad, aad_len,
            key, nonce
        );

        snprintf(
            description, sizeof(description),
            "KAT %s: decryption", vectors[i].name
        );

        CHECK(
            status == AES_GCM_OK &&
            recovered_len == plaintext_len &&
            memcmp(recovered, plaintext, plaintext_len) == 0,
            description
        );
    }
}

int main(void)
{

    test_known_answers();

    uint8_t key[AES_GCM_KEY_BYTES];
    uint8_t nonce[AES_GCM_NONCE_BYTES];
    uint8_t message[128];
    const uint8_t aad[] = {0x01, 0x02, 0x03, 0x04};

    uint8_t ciphertext[sizeof(message) + AES_GCM_TAG_BYTES];
    uint8_t recovered[sizeof(message)];
    uint8_t modified[sizeof(ciphertext)];

    size_t ciphertext_len = 0;
    size_t recovered_len = 0;

    /* Fixed key and nonces are for repeatable tests only. */
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
    }

    for (size_t i = 0; i < sizeof(nonce); ++i) {
        nonce[i] = (uint8_t)(0x10 + i);
    }

    for (size_t i = 0; i < sizeof(message); ++i) {
        message[i] = (uint8_t)i;
    }

    aes_gcm_status status = aes_gcm_encrypt(
        ciphertext, sizeof(ciphertext), &ciphertext_len,
        message, sizeof(message),
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_OK &&
        ciphertext_len == sizeof(ciphertext),
        "Encrypt 128-byte payload"
    );

    /* Remaining tests require a valid ciphertext. */
    if (status != AES_GCM_OK ||
        ciphertext_len != sizeof(ciphertext)) {
        return 1;
    }

    status = aes_gcm_decrypt(
        recovered, sizeof(recovered), &recovered_len,
        ciphertext, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_OK &&
        recovered_len == sizeof(message) &&
        memcmp(message, recovered, sizeof(message)) == 0,
        "Decrypt and recover original payload"
    );

    memcpy(modified, ciphertext, sizeof(modified));
    modified[0] ^= 0x01;

    check_auth_failure(
        "Reject modified ciphertext and clear plaintext",
        modified, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    memcpy(modified, ciphertext, sizeof(modified));
    modified[ciphertext_len - 1] ^= 0x01;

    check_auth_failure(
        "Reject modified tag and clear plaintext",
        modified, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    uint8_t wrong_aad[sizeof(aad)];
    memcpy(wrong_aad, aad, sizeof(wrong_aad));
    wrong_aad[0] ^= 0x01;

    check_auth_failure(
        "Reject modified AAD",
        ciphertext, ciphertext_len,
        wrong_aad, sizeof(wrong_aad), key, nonce
    );

    uint8_t wrong_key[sizeof(key)];
    memcpy(wrong_key, key, sizeof(wrong_key));
    wrong_key[0] ^= 0x01;

    check_auth_failure(
        "Reject wrong key",
        ciphertext, ciphertext_len,
        aad, sizeof(aad), wrong_key, nonce
    );

    uint8_t wrong_nonce[sizeof(nonce)];
    memcpy(wrong_nonce, nonce, sizeof(wrong_nonce));
    wrong_nonce[0] ^= 0x01;

    check_auth_failure(
        "Reject wrong nonce",
        ciphertext, ciphertext_len,
        aad, sizeof(aad), key, wrong_nonce
    );

    size_t output_len = 999;

    status = aes_gcm_encrypt(
        modified, sizeof(modified) - 1, &output_len,
        message, sizeof(message),
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_BUFFER_TOO_SMALL && output_len == 0,
        "Reject small encryption buffer"
    );

    output_len = 999;

    status = aes_gcm_decrypt(
        recovered, sizeof(recovered) - 1, &output_len,
        ciphertext, ciphertext_len,
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_BUFFER_TOO_SMALL && output_len == 0,
        "Reject small decryption buffer"
    );

    output_len = 999;

    status = aes_gcm_decrypt(
        recovered, sizeof(recovered), &output_len,
        ciphertext, AES_GCM_TAG_BYTES - 1,
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_INVALID_ARGUMENT && output_len == 0,
        "Reject ciphertext shorter than tag"
    );

    output_len = 999;

    status = aes_gcm_encrypt(
        modified, sizeof(modified), &output_len,
        NULL, 1, aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_INVALID_ARGUMENT && output_len == 0,
        "Reject NULL plaintext with nonzero length"
    );

    output_len = 999;

    status = aes_gcm_encrypt(
        modified, sizeof(modified), &output_len,
        message, sizeof(message),
        NULL, 1, key, nonce
    );

    CHECK(
        status == AES_GCM_INVALID_ARGUMENT && output_len == 0,
        "Reject NULL AAD with nonzero length"
    );

    status = aes_gcm_encrypt(
        modified, sizeof(modified), NULL,
        message, sizeof(message),
        aad, sizeof(aad), key, nonce
    );

    CHECK(
        status == AES_GCM_INVALID_ARGUMENT,
        "Reject NULL output-length pointer"
    );

    const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 128};

    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t length = lengths[i];
        uint8_t case_nonce[AES_GCM_NONCE_BYTES];
        char description[80];

        memcpy(case_nonce, nonce, sizeof(case_nonce));
        case_nonce[0] = (uint8_t)(0x80 + i);

        ciphertext_len = 0;
        recovered_len = 0;

        status = aes_gcm_encrypt(
            ciphertext, sizeof(ciphertext), &ciphertext_len,
            length > 0 ? message : NULL, length,
            NULL, 0, key, case_nonce
        );

        int passed =
            status == AES_GCM_OK &&
            ciphertext_len == length + AES_GCM_TAG_BYTES;

        if (passed) {
            status = aes_gcm_decrypt(
                length > 0 ? recovered : NULL,
                length, &recovered_len,
                ciphertext, ciphertext_len,
                NULL, 0, key, case_nonce
            );

            passed =
                status == AES_GCM_OK &&
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