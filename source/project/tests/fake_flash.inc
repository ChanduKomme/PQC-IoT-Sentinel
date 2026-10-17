/* State-machine test doubles only. Crypto/network/tasks are not executed. */
static unsigned char fake_blob[8192];static size_t fake_len=0;
static int fail_write=0,stale_read=0,writes=0;static uint32_t fake_ticks=100;
extern "C" int easyflash_init(void){return 0;}
extern "C" int ef_save_env(void){return 0;}
extern "C" int ef_set_env_blob(const char *,const void *p,size_t n){
    if(fail_write)return -1;++writes;
    if(!stale_read){memcpy(fake_blob,p,n);fake_len=n;}return 0;
}
extern "C" size_t ef_get_env_blob(const char *,void *p,size_t n,size_t *length){
    *length=fake_len;if(n>fake_len)n=fake_len;memcpy(p,fake_blob,n);return n;
}
extern "C" uint32_t xTaskGetTickCount(void){return fake_ticks;}
extern "C" int mbedtls_sha256_ret(const unsigned char *p,size_t n,unsigned char *out,int){
    memset(out,0,32);for(size_t i=0;i<n;i++)out[i%32]^=p[i];return 0;
}
