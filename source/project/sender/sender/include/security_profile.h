#ifndef SECURITY_PROFILE_H
#define SECURITY_PROFILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_META_MAGIC 0x504D4554u /* PMET */
#define PQC_PK_FINGERPRINT_LEN 32u

#define PQC_PK_AUTH_MODE_TOFU   0u
#define PQC_PK_AUTH_MODE_STRICT 1u

#ifndef PQC_PK_AUTH_MODE
#define PQC_PK_AUTH_MODE PQC_PK_AUTH_MODE_STRICT
#endif

#ifndef PQC_PROTOCOL_VERSION
#define PQC_PROTOCOL_VERSION 3u
#endif

#define PQC_AEAD_KEY_LEN 32u
#define PQC_AEAD_KEY_BITS 256u
#define PQC_AEAD_NONCE_LEN 12u
#define PQC_AEAD_TAG_LEN 16u
#define PQC_CRYPTO_PROFILE "ML-KEM-512/HKDF-SHA-256/AES-256-CCM/HMAC-SHA-256-DEVICE-AUTH"
#define PQC_HKDF_INFO "PQC-IOT-MLKEM512-AES256-CCM-v4"
#define PQC_DEVICE_AUTH_TAG_LEN 32u
#define PQC_DEVICE_AUTH_KEY_LEN 32u
#define PQC_SECURITY_PROFILE_VERSION 4u

#ifndef PQC_SENDER_ID
#define PQC_SENDER_ID 0x53454E31u
#endif

/* Fixed receiver IP (empty string = use last known or discovery) */
#ifndef PQC_GATEWAY_STATIC_IP
#define PQC_GATEWAY_STATIC_IP "192.168.0.196"
#endif

/* 1 = allow broadcast discovery fallback, 0 = static IP only */
#ifndef PQC_ALLOW_BROADCAST_DISCOVERY
#define PQC_ALLOW_BROADCAST_DISCOVERY 0u
#endif

#define PQC_KEY_STATUS_ACTIVE            1u
#define PQC_KEY_STATUS_REVOKED           2u
#define PQC_KEY_STATUS_ROTATION_REQUIRED 3u
#define PQC_KEY_STATUS_RETIRED           4u

#ifndef PQC_KEY_MAX_MESSAGES_DEFAULT
#define PQC_KEY_MAX_MESSAGES_DEFAULT 1000u
#endif

#ifndef PQC_RATE_LIMIT_WINDOW_MS
#define PQC_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_RATE_LIMIT_MAX_REQUESTS
#define PQC_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_META_RATE_LIMIT_MAX_REQUESTS
#define PQC_META_RATE_LIMIT_MAX_REQUESTS 16u
#endif

#ifndef PQC_DATA_RATE_LIMIT_WINDOW_MS
#define PQC_DATA_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_DATA_RATE_LIMIT_MAX_REQUESTS
#define PQC_DATA_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_ALLOWED_SENDER_ID
#define PQC_ALLOWED_SENDER_ID PQC_SENDER_ID
#endif

#ifndef PQC_PEER_TABLE_SIZE
#define PQC_PEER_TABLE_SIZE 8u
#endif

#ifndef PQC_PEER_FAILS_TO_BLOCK
#define PQC_PEER_FAILS_TO_BLOCK 5u
#endif

#ifndef PQC_PEER_BLOCK_MS
#define PQC_PEER_BLOCK_MS 30000u
#endif

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t key_id;
    uint32_t created_at_ms;
    uint32_t expires_at_ms;
    uint32_t message_count;
    uint32_t max_messages;
    uint8_t status;
    uint8_t rotation_required;
    uint8_t reserved0;
    uint8_t reserved1;
    uint8_t fingerprint[PQC_PK_FINGERPRINT_LEN];
} GatewayKeyMetadataPayload;

static const uint8_t kProvisionedGatewayPkFingerprint[PQC_PK_FINGERPRINT_LEN] = {0x07,0x59,0x5E,0x1C,0x83,0xA7,0xE6,0x73,0xDB,0x31,0x68,0x66,0xC7,0x8D,0x74,0x47,0x06,0x39,0xF9,0xC3,0x40,0xC6,0x3D,0xC7,0xB7,0x56,0xF4,0x28,0x45,0x97,0xBE,0x47};

static inline bool pqc_fingerprint_is_provisioned(void) {
    for (size_t i = 0; i < PQC_PK_FINGERPRINT_LEN; ++i) {
        if (kProvisionedGatewayPkFingerprint[i] != 0u) {
            return true;
        }
    }
    return false;
}

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_PROFILE_H */
