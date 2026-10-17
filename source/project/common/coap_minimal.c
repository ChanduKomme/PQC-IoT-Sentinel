#include "coap_minimal.h"
#include <string.h>
static bool extension(uint8_t nibble,const uint8_t *b,size_t n,size_t *at,uint32_t *v) {
    if(nibble<13) { *v=nibble; return true; }
    if(nibble==13) { if(*at>=n)return false; *v=13u+b[(*at)++]; return true; }
    if(nibble==14) { if(n-*at<2u)return false; *v=269u+((uint32_t)b[*at]<<8)+b[*at+1]; *at+=2; return true; }
    return false;
}
bool coap_parse(CoapMessage *m,const uint8_t *b,size_t n) {
    if(!m||!b||n<4)return false;
    memset(m,0,sizeof(*m)); m->ver=b[0]>>6; m->type=(b[0]>>4)&3;
    m->token_len=b[0]&15; m->code=b[1]; m->msg_id=((uint16_t)b[2]<<8)|b[3];
    if(m->ver!=1||m->token_len>8||n-4<m->token_len)return false;
    if(m->code==0 && n!=4)return false;
    size_t at=4+m->token_len, used=0; uint32_t option=0;
    memcpy(m->token,b+4,m->token_len);
    while(at<n) {
        uint8_t head=b[at++];
        if(head==255) { if(at==n)return false; m->payload=b+at; m->payload_len=n-at; return true; }
        uint32_t delta,length;
        if(!extension(head>>4,b,n,&at,&delta)||!extension(head&15,b,n,&at,&length))return false;
        if(delta>65535u-option||length>n-at)return false;
        option+=delta;
        if(option==11) {
            if(!length || used+(used?1u:0u)+length>=COAP_MAX_URI_PATH)return false;
            for(uint32_t i=0;i<length;i++) if(b[at+i]<33||b[at+i]>126||b[at+i]=='/')return false;
            if(used)m->uri_path[used++]='/';
            memcpy(m->uri_path+used,b+at,length); used+=length;
            m->uri_path[used]=0; m->uri_path_len=(uint8_t)used;
        } else if(option&1u) return false; /* unknown critical option */
        at+=length;
    }
    m->payload=b+n; return true;
}
size_t coap_build_simple(uint8_t *b,size_t n,uint8_t type,uint8_t code,uint16_t id,
                        const char *uri,const uint8_t *payload,size_t length) {
    if(!b||n<4||type>3||(length&&!payload))return 0;
    size_t path_len=uri?strlen(uri):0;
    if(path_len>=COAP_MAX_URI_PATH || (code==0&&(path_len||length)))return 0;
    b[0]=(uint8_t)(0x40|(type<<4)); b[1]=code; b[2]=(uint8_t)(id>>8); b[3]=(uint8_t)id;
    size_t at=4; unsigned delta=11;
    const char *p=uri;
    while(p&&*p) {
        if(*p=='/') { p++; continue; }
        const char *end=p; while(*end&&*end!='/')end++;
        size_t count=(size_t)(end-p), ext=count>=13?1:0;
        if(n-at<1+ext+count)return 0;
        for(size_t i=0;i<count;i++)if((unsigned char)p[i]<33||(unsigned char)p[i]>126)return 0;
        b[at++]=(uint8_t)((delta<<4)|(count<13?count:13));
        if(ext)b[at++]=(uint8_t)(count-13);
        memcpy(b+at,p,count); at+=count; delta=0; p=end;
    }
    if(length) { if(n-at<1||length>n-at-1)return 0; b[at++]=255; memcpy(b+at,payload,length); at+=length; }
    return at;
}
