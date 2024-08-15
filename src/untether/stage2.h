#include "common.h"
#include "img.h"
#include "patchfinder.h"
#include <shared/iokit.h>
#include <shared/offsets.h>

#ifndef STAGE2_H
#define STAGE2_H

// fake msg struct
typedef uint64_t mach_port_poly_t; // this just assumes the type idk if it's acc a uint64_t

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_ports_descriptor_t desc[1];
    char pad[4096];
} ool_message_struct;

#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    uint32_t selector;
    mach_msg_type_number_t scalar_inputCnt;
    /*io_user_scalar_t scalar_input[16];*/
    mach_msg_type_number_t inband_inputCnt;
    char inband_input[24];
    mach_vm_address_t ool_input;
    mach_vm_size_t ool_input_size;
    mach_msg_type_number_t inband_outputCnt;
    mach_msg_type_number_t scalar_outputCnt;
    mach_vm_address_t ool_output;
    mach_vm_size_t ool_output_size;
} MEMLEAK_Request;
typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    mach_msg_type_number_t inband_outputCnt;
    char inband_output[24];
    mach_msg_type_number_t scalar_outputCnt;
    /*io_user_scalar_t scalar_output[16];*/
    mach_vm_size_t ool_output_size;
    mach_msg_trailer_t trailer;
} MEMLEAK_Reply;
#pragma pack()

union {
    MEMLEAK_Request In;
    MEMLEAK_Reply Out;
} MEMLEAK_msg;

#ifndef _STRUCT_ARM_THREAD_STATE
#define _STRUCT_ARM_THREAD_STATE struct __darwin_arm_thread_state
_STRUCT_ARM_THREAD_STATE
{
    __uint32_t __r[13]; /* General purpose register r0-r12 */
    __uint32_t __sp; /* Stack pointer r13 */
    __uint32_t __lr; /* Link register r14 */
    __uint32_t __pc; /* Program counter r15 */
    __uint32_t __cpsr; /* Current program status register */
};
#endif

#ifndef _STRUCT_ARM_THREAD_STATE64
#define _STRUCT_ARM_THREAD_STATE64 struct __darwin_arm_thread_state64
_STRUCT_ARM_THREAD_STATE64
{
    __uint64_t __x[29]; /* General purpose registers x0-x28 */
    __uint64_t __fp; /* Frame pointer x29 */
    __uint64_t __lr; /* Link register x30 */
    __uint64_t __sp; /* Stack pointer x31 */
    __uint64_t __pc; /* Program counter */
    __uint32_t __cpsr; /* Current program status register */
    __uint32_t __pad; /* Same size for 32-bit or 64-bit clients */
};
#endif

// fake port struct defined as volatile because on none smap devs we will place it into userland
typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
#ifdef __LP64__
        uint32_t pad;
#endif
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

#define IO_BITS_ACTIVE 0x80000000
#define IOT_PORT 0
#define IKOT_NONE 0
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29
#define IKOT_CLOCK 25
#define NENT 1

uint64_t get_addr_from_name(offset_struct_t* offsets, char* name);
void stage2(jake_img_t kernel_symbols, offset_struct_t* offsets, offsets_t* lib_offsets, char* base_dir);

#endif
