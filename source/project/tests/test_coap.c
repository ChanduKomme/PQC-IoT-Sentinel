#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "coap_minimal.h"
#include "pqc_protocol.h"
int main(void) {
    uint8_t packet[1200],payload[874]={0};CoapMessage msg;
    size_t n=coap_build_post(packet,sizeof(packet),42,"pqkem-data",payload,sizeof(payload));
    assert(n==890 && coap_parse(&msg,packet,n));
    assert(msg.msg_id==42 && msg.payload_len==874 && strcmp(msg.uri_path,"pqkem-data")==0);
    const uint8_t critical[]={0x40,1,0,1,0xe0,0,0};
    const uint8_t empty_marker[]={0x40,1,0,1,255};
    const uint8_t invalid_token[]={0x49,1,0,1};
    const uint8_t embedded_zero[]={0x40,1,0,1,0xb3,'a',0,'b'};
    uint8_t truncated[20]={0x40,2,0,1,0xbe,0,0};memset(truncated+7,'a',13);
    assert(!coap_parse(&msg,critical,sizeof(critical)));
    assert(!coap_parse(&msg,empty_marker,sizeof(empty_marker)));
    assert(!coap_parse(&msg,invalid_token,sizeof(invalid_token)));
    assert(!coap_parse(&msg,embedded_zero,sizeof(embedded_zero)));
    assert(!coap_parse(&msg,truncated,sizeof(truncated)));
    char longpath[33];memset(longpath,'a',32);longpath[32]=0;
    assert(!coap_build_post(packet,sizeof(packet),1,longpath,payload,1));
    assert(!coap_build_post(packet,10,1,"pqkem-data",payload,1));
    assert(!coap_build_post(packet,sizeof(packet),1,"pqkem-data",NULL,1));
    n=coap_build_post(packet,sizeof(packet),1,"segment/longsegment13",payload,1);
    assert(n && coap_parse(&msg,packet,n) && !strcmp(msg.uri_path,"segment/longsegment13"));
    uint8_t input[PQC_ACK_INPUT_LEN], tag[32]={1};pqc_ack_input(input,tag);
    assert(!memcmp(input,"PQC-ACK-v1",10) && !memcmp(input+10,tag,32));
    assert(offsetof(DataMsg,buf)==36);
    puts("PASS: strict CoAP bounds, roundtrip, wire v3 layout and ACK domain");return 0;
}
