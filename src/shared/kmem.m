
#include <mach/mach.h>

#include "common.h"
#include "jailbreak.h"

void kread(kptr_t kaddr, void* buffer, uint32_t length)
{
    mach_vm_size_t outsize = 0;
    kern_return_t err = mach_vm_read_overwrite(kernel_task,
        (mach_vm_address_t)kaddr,
        (mach_vm_size_t)length,
        (mach_vm_address_t)buffer,
        &outsize);
    if (err != KERN_SUCCESS) {
        LOG("tfp0 read failed %s addr: " ADDR " err:%x port:%x\n", mach_error_string(err), kaddr, err, kernel_task);
        return;
    }

    if (outsize != length) {
        LOG("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        return;
    }
}

void kwrite(kptr_t kaddr, void* buffer, uint32_t length)
{
    kern_return_t err;
    err = mach_vm_write(kernel_task,
        (mach_vm_address_t)kaddr,
        (vm_offset_t)buffer,
        (mach_msg_type_number_t)length);

    if (err != KERN_SUCCESS) {
        LOG("tfp0 write failed: %s %x\n", mach_error_string(err), err);
        return;
    }
}

uint32_t rk32(kptr_t kaddr)
{
    uint32_t val = 0x0;
    kread(kaddr, &val, sizeof(val));
    return val;
}

uint64_t rk64(kptr_t kaddr)
{
#ifndef __LP64__
    LOG("Calling rk64... ???");
#endif
    uint64_t lower = rk32(kaddr);
    uint64_t higher = rk32(kaddr + 4);
    uint64_t full = ((higher << 32) | lower);
    return full;
}

kptr_t kread_kptr(kptr_t kaddr)
{
#ifdef __LP64__
    return rk64(kaddr);
#else
    return rk32(kaddr);
#endif
}

void wk32(kptr_t kaddr, uint32_t val)
{
    kwrite(kaddr, &val, sizeof(val));
}

void wk64(kptr_t kaddr, uint64_t val)
{
#ifndef __LP64__
    LOG("Calling wk64... ???");
#endif
    kwrite(kaddr, &val, sizeof(val));
}

void kwrite_kptr(kptr_t kaddr, kptr_t val)
{
    kwrite(kaddr, &val, sizeof(val));
}

kptr_t kalloc(kptr_t size)
{
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    kern_return_t err = mach_vm_allocate(kernel_task, &addr, ksize, VM_FLAGS_ANYWHERE);

    if (err != KERN_SUCCESS) {
        LOG("unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
        return 0;
    }

    return addr;
}

void kfree(kptr_t addr, uint64_t size)
{
    kern_return_t err = mach_vm_deallocate(kernel_task, addr, size);

    if (err != KERN_SUCCESS) {
        LOG("unable to deallocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
    }
}

void kprotect(kptr_t kaddr, uint32_t size, int prot)
{
    kern_return_t err = mach_vm_protect(kernel_task, (mach_vm_address_t)kaddr, (mach_vm_size_t)size, 0, (vm_prot_t)prot);

    if (err != KERN_SUCCESS) {
        LOG("unable to change protection of kernel memory via tfp0: %s %x\n", mach_error_string(err), err);
    }
}
