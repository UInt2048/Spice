#ifndef KMEM_H
#define KMEM_H

#include <mach/mach.h>

#ifdef __LP64__
typedef uint64_t kptr_t;
#else
typedef uint32_t kptr_t;
#endif

void kread(kptr_t kaddr, void* buffer, uint32_t length);
void kwrite(kptr_t kaddr, void* buffer, uint32_t length);

uint32_t rk32(kptr_t kaddr);
uint64_t rk64(kptr_t kaddr);

kptr_t kread_kptr(kptr_t kaddr);

void wk32(kptr_t kaddr, uint32_t val);
void wk64(kptr_t kaddr, uint64_t val);

void kwrite_kptr(kptr_t kaddr, kptr_t val);

kptr_t kalloc(uint64_t size);
void kfree(kptr_t addr, uint64_t size);
void kprotect(kptr_t kaddr, uint32_t size, int prot);

#endif
