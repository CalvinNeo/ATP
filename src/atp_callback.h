#pragma once

#include "atp.h"

int atp_default_on_accept(atp_callback_arguments * args);
int atp_default_on_error(atp_callback_arguments * args);
int atp_default_on_read(atp_callback_arguments * args);
int atp_default_on_state_change(atp_callback_arguments * args);
int atp_default_get_read_buffer_size(atp_callback_arguments * args);
int atp_default_get_random(atp_callback_arguments * args);
int atp_default_sendto(atp_callback_arguments * args);
int atp_default_connect(atp_callback_arguments * args);
int atp_default_log(atp_callback_arguments * args);
int atp_default_log_normal(atp_callback_arguments * args);
int atp_default_log_debug(atp_callback_arguments * args);
int atp_default_opt_sndbuf(atp_callback_arguments * args);
int atp_default_opt_rcvbuf(atp_callback_arguments * args);