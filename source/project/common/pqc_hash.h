#ifndef PQC_HASH_H
#define PQC_HASH_H
#include <mbedtls/version.h>
#include <mbedtls/sha256.h>
#include <stddef.h>
#include <stdint.h>
static inline int pqc_sha256(const uint8_t *data, size_t length, uint8_t out[32]) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    return mbedtls_sha256(data,length,out,0);
#elif MBEDTLS_VERSION_NUMBER >= 0x02070000
    return mbedtls_sha256_ret(data,length,out,0);
#else
#error "PQC requires a checked SHA-256 API (Mbed TLS >= 2.7)"
#endif
}
#endif
