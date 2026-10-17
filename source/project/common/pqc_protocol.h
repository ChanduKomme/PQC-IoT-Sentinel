#ifndef PQC_PROTOCOL_H
#define PQC_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "security_profile.h"
#include "pqkem_kem.h"
/* Wire v3 uses little-endian integer fields on BL602. See docs/PROTOCOL.md. */
typedef struct __attribute__((packed)) DataMsg {
    uint8_t type, version;
    uint16_t kem_ct_len, text_len, reserved;
    uint32_t key_id, sender_id, sequence, generation;
    uint8_t nonce[PQC_AEAD_NONCE_LEN];
    uint8_t buf[PQKEM_CIPHERTEXT_BYTES + 64u + PQC_AEAD_TAG_LEN + PQC_DEVICE_AUTH_TAG_LEN];
} DataMsg;
typedef char pqc_header_must_be_36_bytes[(offsetof(DataMsg,buf)==36u)?1:-1];
#define PQC_ACK_INPUT_LEN 42u
static inline void pqc_ack_input(uint8_t out[PQC_ACK_INPUT_LEN], const uint8_t request_tag[32]) {
    /* Domain separation prevents a request tag from being reused as an ACK. */
    memcpy(out, "PQC-ACK-v1", 10u);
    memcpy(out+10u, request_tag, 32u);
}
#endif
