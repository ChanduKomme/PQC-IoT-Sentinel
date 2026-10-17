#ifndef DTLS_BASELINE_CONFIG_H
#define DTLS_BASELINE_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <mbedtls/ssl_ciphersuites.h>

#ifndef DTLS_SERVER_HOST
#define DTLS_SERVER_HOST ""
#endif

#ifndef DTLS_SERVER_PORT
#define DTLS_SERVER_PORT "5684"
#endif

#ifndef DTLS_SERVER_NAME
#define DTLS_SERVER_NAME "pqc-dtls-receiver"
#endif

#ifndef DTLS_SAMPLE_COUNT
#define DTLS_SAMPLE_COUNT 300u
#endif

#ifndef DTLS_INTER_MESSAGE_DELAY_MS
#define DTLS_INTER_MESSAGE_DELAY_MS 100u
#endif

#ifndef DTLS_READ_TIMEOUT_MS
#define DTLS_READ_TIMEOUT_MS 5000u
#endif

#ifndef DTLS_REPEAT_SESSIONS
#define DTLS_REPEAT_SESSIONS 0u
#endif

#define DTLS_COAP_URI "baseline"
#define DTLS_PAYLOAD "Hello from PQC sender!"
#define DTLS_PAYLOAD_LEN (sizeof(DTLS_PAYLOAD) - 1u)
#define DTLS_MAX_RECORD 512u

/* DTLS 1.2 with ephemeral P-256 ECDHE, ECDSA authentication, AES-256-CCM. */
#define DTLS_BASELINE_CIPHERSUITE MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM
#define DTLS_BASELINE_PROFILE "DTLS-1.2/ECDHE-P-256/ECDSA/AES-256-CCM"

#endif /* DTLS_BASELINE_CONFIG_H */
