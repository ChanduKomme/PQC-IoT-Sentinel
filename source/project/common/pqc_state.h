#ifndef PQC_STATE_H
#define PQC_STATE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
static inline uint32_t pqc_crc32(const void *data, size_t n) {
    const uint8_t *p=(const uint8_t *)data; uint32_t crc=0xffffffffu;
    while(n--) { crc ^= *p++; for(unsigned i=0;i<8;i++) crc=(crc>>1)^((0u-(crc&1u))&0xedb88320u); }
    return ~crc;
}
static inline bool pqc_reservation_end(uint32_t next, uint32_t block, uint32_t *end) {
    if (!next || !block || next > UINT32_MAX-block || !end) return false;
    *end=next+block; return true;
}
typedef struct __attribute__((packed)) SenderRuntimeState {
    uint32_t sender_id, generation, last_counter;
    uint8_t enabled, reserved[3];
    uint8_t last_request_tag[32], credential_hash[32];
} SenderRuntimeState;
static inline bool pqc_reconcile_sender(SenderRuntimeState *s, uint32_t id,
        uint32_t generation, uint8_t enabled, const uint8_t hash[32]) {
    if (!s || !id || !hash || enabled>1 || (enabled && !generation)) return false;
    if (s->sender_id == id && s->generation > generation) return false;
    if (s->sender_id == id && s->generation == generation) {
        if (memcmp(s->credential_hash,hash,32)!=0) return false;
        s->enabled=enabled; return true; /* preserve counter across revocation */
    }
    memset(s,0,sizeof(*s)); s->sender_id=id; s->generation=generation; s->enabled=enabled;
    memcpy(s->credential_hash,hash,32); return true;
}
#endif
