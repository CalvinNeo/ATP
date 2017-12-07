#include "../atp.h"
#include "../atp_impl.h"
#include <iostream>

int main(){
    atp_context * context = atp_init();
    atp_socket * atp_sock = atp_create_socket(context);
    return 0;
}