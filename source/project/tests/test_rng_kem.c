/* Test-only DRBG substitute. NEVER included by a firmware Makefile. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pqkem_kem.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
static int fail_seed=1,fail_random=0;static uint64_t state=0x213457689abcdef1ULL;
void mbedtls_entropy_init(mbedtls_entropy_context *c){(void)c;}
void mbedtls_entropy_free(mbedtls_entropy_context *c){(void)c;}
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *c){(void)c;}
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *c){(void)c;}
int mbedtls_entropy_func(void *c,unsigned char *p,size_t n){(void)c;(void)p;(void)n;return 0;}
int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *c,int (*f)(void *,unsigned char *,size_t),void *p,const unsigned char *s,size_t n){(void)c;(void)f;(void)p;(void)s;(void)n;return fail_seed?-1:0;}
int mbedtls_ctr_drbg_random(void *c,unsigned char *out,size_t n){
    (void)c;if(fail_random){memset(out,0xaa,n);return -2;}
    while(n--){state^=state<<13;state^=state>>7;state^=state<<17;*out++=(uint8_t)state;}return 0;
}
static int allzero(const uint8_t *p,size_t n){while(n--)if(*p++)return 0;return 1;}
int main(void) {
    uint8_t pk[800],sk[1632],ct[768],a[32],b[32],rnd[12];
    memset(pk,0xaa,sizeof(pk));memset(sk,0xaa,sizeof(sk));
    assert(!pqkem_keygen(pk,sk)&&allzero(pk,sizeof(pk))&&allzero(sk,sizeof(sk)));
    assert(!pqkem_random_bytes(rnd,sizeof(rnd))&&allzero(rnd,sizeof(rnd)));
    fail_seed=0;assert(pqkem_keygen(pk,sk));fail_random=1;
    assert(!pqkem_encapsulate(pk,ct,a)&&allzero(ct,sizeof(ct))&&allzero(a,sizeof(a)));
    assert(!pqkem_keygen(pk,sk)&&allzero(pk,sizeof(pk))&&allzero(sk,sizeof(sk)));
    fail_random=0;
    for(int i=0;i<100;i++) {
        assert(pqkem_keygen(pk,sk)&&pqkem_encapsulate(pk,ct,a)&&pqkem_decapsulate(ct,sk,b));
        assert(!memcmp(a,b,32));ct[i%768]^=1;
        assert(pqkem_decapsulate(ct,sk,b)&&memcmp(a,b,32));
    }
    puts("PASS: entropy failures clear outputs; 100 real scalar KEM roundtrips and implicit-rejection checks");return 0;
}
