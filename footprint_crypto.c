#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(FOOTPRINT_ASCON)

#include "ascon_aead.h"

#define ENCRYPT ascon_aead_encrypt
#define DECRYPT ascon_aead_decrypt
#define NONCE_BYTES ASCON_AEAD_NONCE_BYTES

#elif defined(FOOTPRINT_AES_GCM)

#include "aes_gcm.h"

#define ENCRYPT aes_gcm_encrypt
#define DECRYPT aes_gcm_decrypt
#define NONCE_BYTES AES_GCM_NONCE_BYTES

#else
#error "Select a footprint algorithm."
#endif

#define PAYLOAD_BYTES 128
#define AAD_BYTES 12
#define TAG_BYTES 16

int main(void)
{
    /* Fixed inputs are only for this isolated validation program. */
    uint8_t key[16] = {0};
    uint8_t nonce[NONCE_BYTES] = {0};
    uint8_t aad[AAD_BYTES] = {0};
    uint8_t payload[PAYLOAD_BYTES];
    uint8_t ciphertext[PAYLOAD_BYTES + TAG_BYTES];
    uint8_t recovered[PAYLOAD_BYTES];

    size_t ciphertext_len = 0;
    size_t recovered_len = 0;

    for (size_t i = 0; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }

    int status = ENCRYPT(
        ciphertext,
        sizeof(ciphertext),
        &ciphertext_len,
        payload,
        sizeof(payload),
        aad,
        sizeof(aad),
        key,
        nonce
    );

    if (status != 0 || ciphertext_len != sizeof(ciphertext)) {
        return 1;
    }

    status = DECRYPT(
        recovered,
        sizeof(recovered),
        &recovered_len,
        ciphertext,
        ciphertext_len,
        aad,
        sizeof(aad),
        key,
        nonce
    );

    if (status != 0 || recovered_len != sizeof(payload)) {
        return 2;
    }

    if (memcmp(payload, recovered, sizeof(payload)) != 0) {
        return 3;
    }

    return 0;
}