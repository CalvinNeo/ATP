#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdarg>
#include <cassert>

void err_sys(const char *fmt, ...);
