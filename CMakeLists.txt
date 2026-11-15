cmake_minimum_required(VERSION 3.20)

project(neuro_lwc LANGUAGES C)

add_library(ascon_reference STATIC
    third_party/ascon/ref/aead.c
)

target_include_directories(ascon_reference PRIVATE
    third_party/ascon/ref
)
target_include_directories(ascon_reference PUBLIC
    third_party/ascon/include
)

set_target_properties(ascon_reference PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)

add_library(ascon_aead STATIC
        ascon_aead.c
        ascon_aead.h
)

target_link_libraries(ascon_aead PRIVATE ascon_reference)

target_include_directories(ascon_aead PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(ascon_aead PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
)

add_executable(test_ascon test_ascon.c)

target_link_libraries(test_ascon PRIVATE ascon_aead)

set_target_properties(test_ascon PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
)

enable_testing()
add_test(NAME ascon_tests COMMAND test_ascon)

# Mbed TLS configuration
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)

set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

set(MBEDTLS_CONFIG_FILE
        "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_config.h"
        CACHE FILEPATH "" FORCE
)

# Compatibility with the older minimum CMake version in Mbed TLS.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

add_subdirectory(third_party/mbedtls EXCLUDE_FROM_ALL)

add_library(aes_gcm STATIC
        aes_gcm.c
        aes_gcm.h
)

target_link_libraries(aes_gcm PRIVATE mbedcrypto)

target_include_directories(aes_gcm PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(aes_gcm PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
)

add_executable(test_aes_gcm test_aes_gcm.c)

target_link_libraries(test_aes_gcm PRIVATE aes_gcm)

set_target_properties(test_aes_gcm PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
)

add_test(NAME aes_gcm_tests COMMAND test_aes_gcm)

add_library(neuro_crypto SHARED
        ascon_aead.c
        ascon_aead.h
        aes_gcm.c
        aes_gcm.h
)

target_link_libraries(neuro_crypto PRIVATE
        ascon_reference
        mbedcrypto
)

target_include_directories(neuro_crypto PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(neuro_crypto PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        PREFIX ""
        OUTPUT_NAME "neuro_crypto"
)