#include <unistd.h>

#import <Foundation/Foundation.h>

#ifndef COMMON_H
#define COMMON_H

#ifdef __LP64__
#define ADDR "0x%llx"
typedef uint64_t kptr_t;
#else
#define ADDR "0x%x"
typedef uint32_t kptr_t;
#endif

#include "../shared/offsets.h"
#include "offsets.h"

#ifdef LOG
#undef LOG
#endif

#ifdef RELEASE
#define LOG(str, args...) \
    do {                  \
    } while (0)
#else
#define LOG(str, args...)         \
    do {                          \
        NSLog(@str "\n", ##args); \
    } while (0)
#endif

#endif
