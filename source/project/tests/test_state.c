#include "pqc_state.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    uint32_t end=0;assert(pqc_crc32("123456789",9)==0xcbf43926u);
    assert(pqc_reservation_end(1,256,&end)&&end==257);
    assert(!pqc_reservation_end(0,256,&end));assert(!pqc_reservation_end(UINT32_MAX-4,256,&end));
    uint8_t hash[32]={1},next_hash[32]={2};SenderRuntimeState s={0};
    assert(pqc_reconcile_sender(&s,1,1,1,hash));s.last_counter=600;s.last_request_tag[0]=9;
    assert(pqc_reconcile_sender(&s,1,1,0,hash)&&s.last_counter==600&&!s.enabled);
    assert(pqc_reconcile_sender(&s,1,1,1,hash)&&s.last_counter==600&&s.last_request_tag[0]==9);
    assert(!pqc_reconcile_sender(&s,1,1,1,next_hash));
    assert(pqc_reconcile_sender(&s,1,2,1,next_hash)&&s.last_counter==0&&s.generation==2);
    assert(!pqc_reconcile_sender(&s,1,1,1,hash));
    puts("PASS: CRC, counter overflow, same-generation persistence, rotation, rollback rejection");return 0;
}
