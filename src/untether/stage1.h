#include "common.h"

#ifndef STAGE1_H
#define STAGE1_H

// stage 1 will use two file descriptors from it's own open calls
// while the open call will return the fd in x0 we would need two gadgets to save/load them leading to more rop calls/more rop gadgets that we would need to slide
// this would increase the config file size by a huge amount and also the time needed to perform the brute force and that's why we hardcode them here
// THE BIG PROBLEM WITH THIS IS THAT IF YOU USE A DAEMON THAT HAS KEEP ALIVE AND YOU HARDCODE THEM THEY MIGHT BE DIFFERENT IN THE FIRST FEW SECONDS OF BOOTING (I believe that this happens because launchd opens some fds later so the number increases)
// IF YOU CHANGE THESE VALUES HERE AND THEN USE IT IN A KEEP ALIVE DAEMON IT WILL CRASH OVER AND OVER AGAIN CAUSE A SOFTBRICK OF THE SYSTEM SO REALLY WATCH OUT WHEN YOU CHANGE THEM/MAKE SURE THEY ARE SET RIGHT WHEN YOU TEST THIS ON A NEW/DIFFERENT IOS VERSION
// see stage1.c on when and how they are used (I think STAGE2_FD will always be DYLD_CACHE_FD + 1)

// When you test directly with racoon, versus testing through a launch daemon, this descriptor may change.
// In my testing on N69AP 11.3, the fd was 5 when testing after the semi-untether and 6 when replacing prdaily right after boot.

#ifdef STAGE1FD_SCREAM_TEST
// Note: The value set here for the scream test can be anything, it will crash before using it
#define DYLD_CACHE_FD 3
#warning Scream test is enabled, untether will crash
#else
#ifdef DYLD_CACHE_FD
#if (DYLD_CACHE_FD < 5 || DYLD_CACHE_FD > 6)
#warning Stage 1 file descriptor is outside known experimental range
#endif
#define STR(x) #x
#define QUOTE(x) STR(x)
#pragma message "Stage 1 file descriptor is: " QUOTE(DYLD_CACHE_FD)
#else
#error Stage 1 file descriptor is not defined
#endif
#endif

#define STAGE2_FD (DYLD_CACHE_FD + 1)

void generate_stage1_rop_chain(offset_struct_t* offsets);
void stage1(int fd, offset_struct_t* offsets);

#endif
