#pragma once

#include <sys/types.h> // ssize_t
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h> // sockaddr
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/uio.h>


#include "error.h"
#include <ctime>
#include <stdint.h>

#include <sys/select.h>
#include <sys/sysctl.h>
#include <poll.h>

#define SA struct sockaddr

typedef void Sigfunc(int);

Sigfunc * signal(int signo, Sigfunc *func);

int make_socket(int family, int type, int protocol, int port, const char * ipaddr_str);