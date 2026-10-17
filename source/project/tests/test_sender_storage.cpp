#define errno pqc_test_errno
#include "../sender/sender/main.cpp"
#include <assert.h>
extern "C" {int pqc_test_errno=0;}
#include "fake_flash.inc"
int main() {
    SenderStateStore state;uint32_t seq=0;
    assert(sender_state_init_or_load(&state));assert(sender_next_sequence(&state,&seq)&&seq==1);
    int before=writes;assert(sender_next_sequence(&state,&seq)&&seq==2);assert(writes==before);
    assert(sender_state_init_or_load(&state));assert(state.next_counter==257);
    assert(sender_next_sequence(&state,&seq)&&seq==257);
    assert(sender_state_init_or_load(&state));fail_write=1;
    assert(!sender_next_sequence(&state,&seq));fail_write=0;assert(!sender_next_sequence(&state,&seq));
    g_sender_store_failed=false;fake_blob[0]^=1;assert(!sender_state_init_or_load(&state));
    puts("PASS: actual sender EasyFlash functions reserve ahead, skip on reboot and halt on write/corruption failures");return 0;
}
