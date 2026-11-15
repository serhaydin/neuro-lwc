#ifndef NEURO_LWC_MBEDTLS_CONFIG_H
#define NEURO_LWC_MBEDTLS_CONFIG_H

#define MBEDTLS_PLATFORM_C

/* Enable only the required cryptographic modules. */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C

/*
 * Hardware acceleration is intentionally disabled:
 * MBEDTLS_AESNI_C, MBEDTLS_AESCE_C and MBEDTLS_PADLOCK_C
 * are not defined.
 */

#endif