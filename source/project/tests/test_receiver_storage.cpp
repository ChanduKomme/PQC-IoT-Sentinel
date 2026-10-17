#define errno pqc_test_errno
#include "../Receiver/Receiver/main.cpp"
#include <assert.h>
extern "C" {int pqc_test_errno=0;}
#include "fake_flash.inc"
extern "C" bool pqkem_keygen(uint8_t *pk,uint8_t *sk){memset(pk,0xaa,800);memset(sk,0xbb,1632);return true;}
int main() {
    GwKemStore store,loaded;assert(gw_store_init_or_load(&store));
    store.senders[0].last_counter=42;store.senders[0].last_request_tag[0]=7;
    assert(gw_store_save(&store));assert(gw_store_init_or_load(&loaded));
    assert(loaded.senders[0].last_counter==42 && loaded.senders[0].last_request_tag[0]==7);
    assert(!memcmp(store.pk,loaded.pk,800));
    store.senders[0].last_counter=43;stale_read=1;assert(!gw_store_save(&store));stale_read=0;
    fail_write=1;assert(!gw_store_save(&store));fail_write=0;
    fake_blob[0]^=1;assert(!gw_store_init_or_load(&loaded));
    puts("PASS: actual receiver store preserves counters and key, rejects stale readback, write failure and corruption");return 0;
}
