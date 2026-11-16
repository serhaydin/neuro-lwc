#include "ascon_aead.h"
#include "aes_gcm.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_BYTES 128
#define AAD_BYTES 12
#define TAG_BYTES 16
#define BATCH_SIZE 1000
#define ROUNDS 30

typedef int (*crypto_function)(
    uint8_t *, size_t, size_t *,
    const uint8_t *, size_t,
    const uint8_t *, size_t,
    const uint8_t *, const uint8_t *
);

typedef struct {
    const char *name;
    size_t nonce_bytes;
    crypto_function encrypt;
    crypto_function decrypt;
} algorithm;

/* Adapters preserve the wrappers' enum return types. */
static int ascon_encrypt_adapter(
    uint8_t *out, size_t capacity, size_t *out_len,
    const uint8_t *in, size_t in_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key, const uint8_t *nonce
)
{
    return ascon_aead_encrypt(
        out, capacity, out_len, in, in_len,
        aad, aad_len, key, nonce
    );
}

static int ascon_decrypt_adapter(
    uint8_t *out, size_t capacity, size_t *out_len,
    const uint8_t *in, size_t in_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key, const uint8_t *nonce
)
{
    return ascon_aead_decrypt(
        out, capacity, out_len, in, in_len,
        aad, aad_len, key, nonce
    );
}

static int aes_encrypt_adapter(
    uint8_t *out, size_t capacity, size_t *out_len,
    const uint8_t *in, size_t in_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key, const uint8_t *nonce
)
{
    return aes_gcm_encrypt(
        out, capacity, out_len, in, in_len,
        aad, aad_len, key, nonce
    );
}

static int aes_decrypt_adapter(
    uint8_t *out, size_t capacity, size_t *out_len,
    const uint8_t *in, size_t in_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key, const uint8_t *nonce
)
{
    return aes_gcm_decrypt(
        out, capacity, out_len, in, in_len,
        aad, aad_len, key, nonce
    );
}

/* Static storage avoids putting the batch buffers on the stack. */
static uint8_t ciphertexts[BATCH_SIZE][PAYLOAD_BYTES + TAG_BYTES];
static uint8_t recovered[BATCH_SIZE][PAYLOAD_BYTES];
static uint8_t nonces[BATCH_SIZE][16];
static size_t encrypted_lengths[BATCH_SIZE];
static size_t decrypted_lengths[BATCH_SIZE];
static int statuses[BATCH_SIZE];

static LARGE_INTEGER frequency;

static LONGLONG ticks(void)
{
    LARGE_INTEGER value;

    if (!QueryPerformanceCounter(&value)) {
        fprintf(stderr, "QueryPerformanceCounter failed.\n");
        exit(EXIT_FAILURE);
    }

    return value.QuadPart;
}

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

static void run_batch(
    const algorithm *alg,
    int round,
    uint64_t *counter
)
{
    uint8_t key[16];
    uint8_t payload[PAYLOAD_BYTES];
    uint8_t aad[AAD_BYTES];

    /* Fixed synthetic inputs are only for this isolated benchmark. */
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
    }

    for (size_t i = 0; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }

    memset(aad, 0xA5, sizeof(aad));

    /* Prepare unique nonces outside the timed sections. */
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        uint64_t value = (*counter)++;

        memset(nonces[i], 0, sizeof(nonces[i]));

        for (size_t j = 0; j < 8; ++j) {
            nonces[i][alg->nonce_bytes - 1 - j] =
                (uint8_t)(value >> (8 * j));
        }
    }

    LONGLONG start = ticks();

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        statuses[i] = alg->encrypt(
            ciphertexts[i],
            sizeof(ciphertexts[i]),
            &encrypted_lengths[i],
            payload,
            sizeof(payload),
            aad,
            sizeof(aad),
            key,
            nonces[i]
        );
    }

    LONGLONG encrypt_ticks = ticks() - start;

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        if (statuses[i] != 0 ||
            encrypted_lengths[i] != PAYLOAD_BYTES + TAG_BYTES) {
            fail("Benchmark encryption failed.");
        }
    }

    start = ticks();

    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        statuses[i] = alg->decrypt(
            recovered[i],
            sizeof(recovered[i]),
            &decrypted_lengths[i],
            ciphertexts[i],
            encrypted_lengths[i],
            aad,
            sizeof(aad),
            key,
            nonces[i]
        );
    }

    LONGLONG decrypt_ticks = ticks() - start;

    /* Validate every recovered payload outside the timed sections. */
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        if (statuses[i] != 0 ||
            decrypted_lengths[i] != PAYLOAD_BYTES ||
            memcmp(recovered[i], payload, sizeof(payload)) != 0) {
            fail("Benchmark decryption validation failed.");
        }
    }

    /* Check rejection outside the timed sections. */
    ciphertexts[0][PAYLOAD_BYTES + TAG_BYTES - 1] ^= 0x01;

    size_t rejected_len = 999;

    int rejected_status = alg->decrypt(
        recovered[0],
        sizeof(recovered[0]),
        &rejected_len,
        ciphertexts[0],
        encrypted_lengths[0],
        aad,
        sizeof(aad),
        key,
        nonces[0]
    );

    ciphertexts[0][PAYLOAD_BYTES + TAG_BYTES - 1] ^= 0x01;

    if (rejected_status == 0 || rejected_len != 0) {
        fail("Benchmark accepted a modified authentication tag.");
    }

    /* Round zero is warm-up and is not reported. */
    if (round == 0) {
        return;
    }

    double encrypt_s =
        (double)encrypt_ticks / (double)frequency.QuadPart;
    double decrypt_s =
        (double)decrypt_ticks / (double)frequency.QuadPart;

    if (encrypt_s <= 0.0 || decrypt_s <= 0.0) {
        fail("Invalid benchmark duration.");
    }

    double payload_mib =
        (double)BATCH_SIZE * PAYLOAD_BYTES / (1024.0 * 1024.0);

    printf(
        "%s,%d,%d,%d,%.6f,%.6f,%.6f,%.6f\n",
        alg->name,
        round,
        PAYLOAD_BYTES,
        BATCH_SIZE,
        encrypt_s * 1e6 / BATCH_SIZE,
        decrypt_s * 1e6 / BATCH_SIZE,
        payload_mib / encrypt_s,
        payload_mib / decrypt_s
    );
}

int main(void)
{
    const algorithm algorithms[] = {
        {
            "ascon", ASCON_AEAD_NONCE_BYTES,
            ascon_encrypt_adapter, ascon_decrypt_adapter
        },
        {
            "aes-gcm", AES_GCM_NONCE_BYTES,
            aes_encrypt_adapter, aes_decrypt_adapter
        }
    };

    uint64_t counters[] = {0, 0};

    if (!QueryPerformanceFrequency(&frequency) ||
        frequency.QuadPart <= 0) {
        fail("High-resolution timer initialization failed.");
    }

    printf(
        "algorithm,round,payload_bytes,iterations,"
        "encrypt_us_per_packet,decrypt_us_per_packet,"
        "encrypt_mib_per_s,decrypt_mib_per_s\n"
    );

    for (int round = 0; round <= ROUNDS; ++round) {
        /* Alternate order to reduce consistent first/second bias. */
        for (int position = 0; position < 2; ++position) {
            int index = (round + position) % 2;

            run_batch(
                &algorithms[index],
                round,
                &counters[index]
            );
        }
    }

    if (fflush(stdout) != 0 || ferror(stdout)) {
        fail("Could not write benchmark output.");
    }

    return EXIT_SUCCESS;
}