#ifndef COMMON_H
#define COMMON_H

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <stdint.h>
#ifdef UNTETHERDBG
#import <CoreFoundation/CoreFoundation.h>
extern SInt32 CFUserNotificationDisplayAlert(
    CFTimeInterval timeout,
    CFOptionFlags flags,
    CFURLRef iconURL,
    CFURLRef soundURL,
    CFURLRef localizationURL,
    CFStringRef alertHeader,
    CFStringRef alertMessage,
    CFStringRef defualtButtonTitle,
    CFStringRef alternateButtonTitel,
    CFStringRef otherButtonTitle,
    CFOptionFlags* responseFlags);
#endif

#ifdef __LP64__
#define ADDR "0x%llx"
#else
#define ADDR "0x%x"
#endif

#include "offsets.h"

#ifdef RELEASE
#warning Logging disabled
#define LOG(str, ...) \
    do {              \
    } while (0)
#elif defined UNTETHERDBG
#define LOG(str, ...)                                                                                                                           \
    do {                                                                                                                                        \
        NSLog(@"[%@] " str, @(__func__), ##__VA_ARGS__);                                                                                        \
        CFOptionFlags flags;                                                                                                                    \
        CFStringRef tmp = CFStringCreateWithFormat(NULL, NULL, (__bridge CFStringRef)(@"[%@] " str), @(__func__), ##__VA_ARGS__);               \
        CFUserNotificationDisplayAlert(0, 0, NULL, NULL, NULL, CFSTR("spicy untether"), tmp, CFSTR("w00t"), CFSTR("Ok"), CFSTR("Nvm"), &flags); \
        CFRelease(tmp);                                                                                                                         \
        sleep(1);                                                                                                                               \
    } while (0)
#else
#define LOG(str, ...)                                    \
    do {                                                 \
        NSLog(@"[%@] " str, @(__func__), ##__VA_ARGS__); \
    } while (0)
#endif

#define ASSERT_RET(lbl, str, ret)                 \
    do {                                          \
        kern_return_t _ret = (ret);               \
        LOG(str ": %s", mach_error_string(_ret)); \
        if (_ret != KERN_SUCCESS)                 \
            goto lbl;                             \
    } while (0)
#define ASSERT_PORT(lbl, str, port)  \
    do {                             \
        mach_port_t _port = (port);  \
        LOG(str ": %x", _port);      \
        if (!MACH_PORT_VALID(_port)) \
            goto lbl;                \
    } while (0)
#define ASSERT_RET_PORT(lbl, str, ret, port)                 \
    do {                                                     \
        kern_return_t _ret = (ret);                          \
        mach_port_t _port = (port);                          \
        LOG(str ": %x, %s", _port, mach_error_string(_ret)); \
        if (_ret != KERN_SUCCESS || !MACH_PORT_VALID(_port)) \
            goto lbl;                                        \
    } while (0)

extern kern_return_t bootstrap_look_up(mach_port_t bp, char* name, mach_port_t* sp);
extern mach_port_t mach_reply_port(void);
extern kern_return_t mach_vm_allocate(task_t task, mach_vm_address_t* addr, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t* data, mach_msg_type_number_t* dataCnt);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t* outsize);
extern kern_return_t mach_vm_protect(task_t task, mach_vm_address_t addr, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_prot);
extern kern_return_t mach_vm_map(task_t task, mach_vm_address_t* addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy, vm_prot_t cur, vm_prot_t max, vm_inherit_t inheritance);
extern kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t* dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t* cur_prot, vm_prot_t* max_prot, vm_inherit_t inherit);

typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        kptr_t type;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
#ifdef __LP64__
            uint32_t pad;
#endif
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

/*
typedef volatile union {
    struct {
        // UserClient:
        kptr_t vtab; // fake vtab with:
                     // - getState => OSSerializer::serialize
                     // - getExternalTrapForIndex => OSOrderedSet::getOrderingRef
        uint32_t refs; // 0x100 or smth
#ifdef __LP64__
        uint32_t __pad0;
#endif
        kptr_t args; // point to &portname
        kptr_t zero; // whatever, ignored
        kptr_t relay; // &iokit_user_client_trap
#ifndef __LP64__
        uint32_t __pad;
#endif

        // Trap:
        kptr_t trap; // point to &x0
        kptr_t x0; // (if == 0, set = -1 instead)
        kptr_t func;
        kptr_t delta; // (x0 == 0 ? 1 : 0) << 1

        // Args:
        uint32_t portname; // USERLAND port name of this very object (yes, really)
#ifdef __LP64__
        uint32_t __pad1;
#endif
        uint32_t selector; // whatever, ignored
#ifdef __LP64__
        uint32_t __pad2;
#endif
        kptr_t x1;
        kptr_t x2;
        kptr_t x3;
        kptr_t x4;
        kptr_t x5;
#ifndef __LP64__
        kptr_t __space;
#endif
        kptr_t x6;
    };
    struct {
        uint8_t __madpad[OFF_IOUC_IPC];
        int32_t __ipc;
    };
} fakeuc_t;
*/

#endif
