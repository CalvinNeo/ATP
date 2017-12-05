#include "../atp.h"
#include "../atp_impl.h"
#include <iostream>

static atp_context * ctx;

int main(){
    std::cout << get_current_ms();
    // ctx = atp_init();
    // atp_socket atp_sock{ctx};
    return 0;
}