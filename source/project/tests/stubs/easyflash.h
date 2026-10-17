#ifndef TEST_EASYFLASH_H
#define TEST_EASYFLASH_H
#include <stddef.h>
typedef int EfErrCode;
#define EF_NO_ERR 0
int easyflash_init(void);int ef_save_env(void);
int ef_set_env_blob(const char *,const void *,size_t);
size_t ef_get_env_blob(const char *,void *,size_t,size_t *);
#endif
