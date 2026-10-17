#ifndef TEST_CCM_H
#define TEST_CCM_H
#include <stddef.h>
typedef struct {int unused;} mbedtls_ccm_context;
#define MBEDTLS_CIPHER_ID_AES 1
void mbedtls_ccm_init(mbedtls_ccm_context *);void mbedtls_ccm_free(mbedtls_ccm_context *);
int mbedtls_ccm_setkey(mbedtls_ccm_context *,int,const unsigned char *,unsigned);
int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *,size_t,const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,unsigned char *,unsigned char *,size_t);
int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *,size_t,const unsigned char *,size_t,const unsigned char *,size_t,const unsigned char *,unsigned char *,const unsigned char *,size_t);
#endif
