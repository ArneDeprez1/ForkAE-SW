#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

#include "platform/platform.h"

#include "xstatus.h"

#include "platform/performance.h"
#include "platform/interface.h"
#include "platform/trng.h"

#undef xil_printf
#undef printf
#undef getchar

#define xil_printf(...) new_printf(__VA_ARGS__)
#define printf(...) new_printf(__VA_ARGS__)
#define getchar(...) new_getchar(__VA_ARGS__)

#endif
