#ifndef KUTILS_H
#define KUTILS_H

#include <mach/mach.h>

#ifdef __LP64__
typedef uint64_t kptr_t;
#else
typedef uint32_t kptr_t;
#endif

typedef int32_t pid_t;

kptr_t find_proc(pid_t pid);
kptr_t find_proc_by_name(const char* name);
pid_t get_pid_for_name(const char* name);

kptr_t task_self_addr(void);
kptr_t find_port_address(mach_port_name_t port);

#endif
