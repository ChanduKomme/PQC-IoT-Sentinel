#ifndef SPLUNK_HEC_H
#define SPLUNK_HEC_H
#include <stdio.h>
#include <stdint.h>
#include <task.h>
#ifndef PQC_EXPERIMENT_ID
#define PQC_EXPERIMENT_ID "lab-unset"
#endif
static uint32_t g_event_sender=0,g_event_generation=0,g_event_sequence=0,g_event_counter=0;
static inline void splunk_set_context(uint32_t id,uint32_t generation,uint32_t sequence) {
    g_event_sender=id;g_event_generation=generation;g_event_sequence=sequence;
}
static inline void splunk_send_event(const char *event,const char *severity,const char *action) {
    /* All strings are fixed firmware identifiers or validated build settings. */
    printf("[EVENT] {\"event_type\":\"%s\",\"severity\":\"%s\",\"action\":\"%s\","
           "\"origin\":\"firmware\",\"role\":\"gateway\",\"device_id\":\"gateway-01\","
           "\"experiment_id\":\"%s\",\"sender_id\":%lu,\"generation\":%lu,\"sequence\":%lu,"
           "\"uptime_ticks\":%lu,\"event_counter\":%lu}\r\n",
           event,severity,action,
           PQC_EXPERIMENT_ID,(unsigned long)g_event_sender,(unsigned long)g_event_generation,
           (unsigned long)g_event_sequence,(unsigned long)xTaskGetTickCount(),(unsigned long)++g_event_counter);
}
#endif
