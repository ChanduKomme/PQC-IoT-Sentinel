#ifndef PQC_SENDER_AUTH_KEY_H
#define PQC_SENDER_AUTH_KEY_H
#include "security_profile.h"
#define PQC_CREDENTIAL_GENERATION 1u
#define PQC_CREDENTIAL_SENDER_ID 0x53454E31u
#if PQC_CREDENTIAL_SENDER_ID != PQC_SENDER_ID
#error "Sender ID does not match the provisioned credential"
#endif
static const uint8_t kPqcSenderAuthKey[PQC_DEVICE_AUTH_KEY_LEN] = {0};
static inline int pqc_sender_auth_key_is_provisioned(void) {
    uint8_t acc=0;for(size_t i=0;i<PQC_DEVICE_AUTH_KEY_LEN;i++)acc|=kPqcSenderAuthKey[i];return acc!=0;
}
#endif
