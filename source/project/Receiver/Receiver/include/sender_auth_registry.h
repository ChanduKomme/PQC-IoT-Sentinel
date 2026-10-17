#ifndef PQC_SENDER_AUTH_REGISTRY_H
#define PQC_SENDER_AUTH_REGISTRY_H
#include "security_profile.h"
typedef struct {uint32_t sender_id,generation;uint8_t enabled;uint8_t auth_key[32];} PqcProvisionedSender;
static const PqcProvisionedSender kPqcProvisionedSenders[PQC_MAX_AUTHORIZED_SENDERS] = {
    {0x53454E31u,1u,0u,{0}},
    {0x53454E32u,1u,0u,{0}}
};
#endif
