#ifndef JAILBREAK_H
#define JAILBREAK_H

#include <mach/mach.h>
#include <stdint.h>

#include "common.h"

#define JBOPT_POST_ONLY (1 << 0) /* post-exploitation only */
#define JBOPT_EXPLOIT_AUTO (1 << 1)

// Duplicated in offsets.h
#define FLAG_LIGHTSPEED (1 << 2)
#define FLAG_VORTEX (1 << 3)
#define FLAG_SOCK_PORT (1 << 4)

extern offsets_t offs;

extern task_t kernel_task;
extern kptr_t kernel_slide;
extern kptr_t kernproc;

kern_return_t pwn_kernel_sock_port(offsets_t* offsets, task_t* tfp0, kptr_t* kbase, void* controller, void (*sendLog)(void*, NSString*));
kern_return_t pwn_kernel_vortex(offsets_t* offsets, task_t* tfp0, kptr_t* kbase, void* controller, void (*sendLog)(void*, NSString*));
kern_return_t pwn_kernel_lightspeed(offsets_t* offsets, task_t* tfp0, kptr_t* kbase, void* controller, void (*sendLog)(void*, NSString*));

time_t bootsec();
int jailbreak(uint32_t opt, void* controller, void (*sendLog)(void*, NSString*));

#endif
