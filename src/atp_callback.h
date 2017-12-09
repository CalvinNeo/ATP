#pragma once

#include "atp.h"

int atp_default_on_accept(atp_callback_arguments * args);
int atp_default_on_error(atp_callback_arguments * args);
int atp_default_on_recv(atp_callback_arguments * args);
int atp_default_on_peerclose(atp_callback_arguments * args);
int atp_default_on_destroy(atp_callback_arguments * args);
int atp_default_on_state_change(atp_callback_arguments * args);
int atp_default_get_read_buffer_size(atp_callback_arguments * args);
int atp_default_get_random(atp_callback_arguments * args);
int atp_default_sendto(atp_callback_arguments * args);
int atp_default_connect(atp_callback_arguments * args);
int atp_default_bind(atp_callback_arguments * args);
int atp_default_log(atp_callback_arguments * args);
int atp_default_log_normal(atp_callback_arguments * args);
int atp_default_log_debug(atp_callback_arguments * args);