#ifndef PQC_DTLS_MBEDTLS_COMPAT_H
#define PQC_DTLS_MBEDTLS_COMPAT_H
#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>

#if MBEDTLS_VERSION_NUMBER >= 0x03020000
typedef uint16_t PqcDtlsGroup;
#define PQC_DTLS_P256 MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1
#define PQC_DTLS_GROUP_NONE 0
static inline void pqc_dtls_tls12(mbedtls_ssl_config *conf) {
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
}
static inline void pqc_dtls_groups(mbedtls_ssl_config *conf, const PqcDtlsGroup *groups) {
    mbedtls_ssl_conf_groups(conf, groups);
}
#else
typedef mbedtls_ecp_group_id PqcDtlsGroup;
#define PQC_DTLS_P256 MBEDTLS_ECP_DP_SECP256R1
#define PQC_DTLS_GROUP_NONE MBEDTLS_ECP_DP_NONE
static inline void pqc_dtls_tls12(mbedtls_ssl_config *conf) {
    mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
}
static inline void pqc_dtls_groups(mbedtls_ssl_config *conf, const PqcDtlsGroup *groups) {
    mbedtls_ssl_conf_curves(conf, groups);
}
#endif

static inline int pqc_dtls_parse_key(mbedtls_pk_context *ctx,
        const unsigned char *key, size_t length, mbedtls_ctr_drbg_context *rng) {
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    return mbedtls_pk_parse_key(ctx, key, length, NULL, 0, mbedtls_ctr_drbg_random, rng);
#else
    (void)rng;
    return mbedtls_pk_parse_key(ctx, key, length, NULL, 0);
#endif
}
#endif
