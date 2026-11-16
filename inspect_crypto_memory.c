#include <stdio.h>

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"

int main(void)
{
    printf("structure,size_bytes\n");

    printf(
        "mbedtls_aes_context,%zu\n",
        sizeof(mbedtls_aes_context)
    );

    printf(
        "mbedtls_cipher_context_t,%zu\n",
        sizeof(mbedtls_cipher_context_t)
    );

    printf(
        "mbedtls_gcm_context,%zu\n",
        sizeof(mbedtls_gcm_context)
    );

    return 0;
}