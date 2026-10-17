#ifndef TEST_ENTROPY_H
#define TEST_ENTROPY_H
#include <stddef.h>
typedef struct {int unused;} mbedtls_entropy_context;
void mbedtls_entropy_init(mbedtls_entropy_context *);
void mbedtls_entropy_free(mbedtls_entropy_context *);
int mbedtls_entropy_func(void *,unsigned char *,size_t);
#endif
