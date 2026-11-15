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