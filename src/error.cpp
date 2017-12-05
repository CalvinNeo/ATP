#include "error.h"
#include <syslog.h>


#define MAXLINE 4096

using namespace std;

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
    int errno_save, n;
    char buf[MAXLINE + 1];

    errno_save = errno; 
    vsnprintf(buf, MAXLINE, fmt, ap);
    n = strlen(buf);
    if (errnoflag)
        snprintf(buf + n, MAXLINE - n, ": %s", strerror(errno_save));
    strcat(buf, "\n");
    
    fflush(stdout);
    fputs(buf, stderr);
    fflush(stderr);
    return;
}


void err_sys(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    err_doit(1, LOG_ERR, fmt, ap);
    va_end(ap);
    exit(1);
}
