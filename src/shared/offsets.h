#ifndef OFFSETS_H
#define OFFSETS_H

#ifdef __LP64__
typedef uint64_t kptr_t;
#define OFF_IOUC_IPC 0x9c
#else
typedef uint32_t kptr_t;
#define OFF_IOUC_IPC 0x5c
#endif

typedef uint64_t mach_port_poly_t; // We don't know what it is, but apparently a uint64_t works

#define FLAG_VERIFIED (1 << 0)
// #define FLAG_RESERVED (1 << 1)
#define FLAG_LIGHTSPEED (1 << 2)
#define FLAG_VORTEX (1 << 3)
#define FLAG_SOCK_PORT (1 << 4)

typedef struct {
    struct {
        kptr_t old_cache_addr;
        kptr_t new_cache_addr;
        kptr_t kernel_image_base;
    } constant;

    struct {
        kptr_t copyin; // formerly duplicate
        kptr_t copyout;
        kptr_t current_task;
        kptr_t get_bsdtask_info;
        kptr_t vm_map_wire_external;
        kptr_t vfs_context_current;
        kptr_t vnode_lookup;
        kptr_t osunserializexml;
        kptr_t smalloc;
        kptr_t proc_find; // not set in stage2.m version
        kptr_t proc_rele; // not set in stage2.m version

        kptr_t ipc_port_alloc_special;
        kptr_t ipc_kobject_set;
        kptr_t ipc_port_make_send;
    } funcs;

    struct {
        // Note: Technically this should be adds_r0_bx_lr on 32-bit but it's similar enough
        kptr_t add_x0_x0_ret; // formerly duplicate
    } gadgets;

    struct {
        kptr_t realhost;
        kptr_t zone_map;
        kptr_t kernel_task;
        kptr_t kern_proc;
        kptr_t rootvnode;
        kptr_t osboolean_true;
        kptr_t trust_cache; // formerly duplicate
    } data;

    struct {
        kptr_t iosurface_root_userclient;
    } vtabs;

    struct {
        uint32_t is_task_offset; // formerly duplicate
        uint32_t task_itk_self;
        uint32_t itk_registered; // formerly duplicate
        uint32_t ipr_size; // formerly duplicate
        uint32_t sizeof_task;
        uint32_t proc_task; // not set in stage2.m version
        uint32_t proc_p_csflags; // not set in stage2.m version
        uint32_t task_t_flags; // not set in stage2.m version
        uint32_t task_all_image_info_addr;
        uint32_t task_all_image_info_size;
    } struct_offsets;

    struct {
        uint32_t create_outsize;
        uint32_t create_surface;
        uint32_t set_value;
    } iosurface;

    uint32_t flags;

    struct {
        // Structure offsets
        kptr_t task_bsd_info;
        kptr_t proc_ucred;
#ifdef __LP64__
        kptr_t vm_map_hdr;
#endif
        kptr_t realhost_special;
        kptr_t iouserclient_ipc;
        kptr_t vtab_get_retain_count;
        kptr_t vtab_get_external_trap_for_index;
        // Data
        kptr_t kernel_map;
        // Code
        kptr_t chgproccnt;
        kptr_t kauth_cred_ref;
        kptr_t osserializer_serialize;
#ifdef __LP64__
        kptr_t rop_ldr_x0_x0_0x10;
#else
        kptr_t rop_ldr_r0_r0_0xc;
#endif
    } vortex;

    struct {
        uint32_t task_vm_map;
        uint32_t task_prev;
        uint32_t task_itk_space;
        uint32_t task_bsd_info;

        uint32_t ipc_port_ip_receiver;
        uint32_t ipc_port_ip_kobject;

        uint32_t proc_pid;
        uint32_t proc_p_fd;

        uint32_t filedesc_fd_ofiles;
        uint32_t fileproc_f_fglob;
        uint32_t fileglob_fg_data;

        uint32_t pipe_buffer;
        uint32_t ipc_space_is_table;
        uint32_t size_ipc_entry;
    } socket;

#ifndef IOKIT_H
#define io_connect_t mach_port_t
#define task_t mach_port_t
#define vm_map_t mach_port_t
#define vm_prot_t int
#define vm_inherit_t unsigned int
#define ipc_space_t mach_port_t
#endif
    struct {
        // void (*write) (int fd,void * buf,uint64_t size); // unused, dlsym of _write
        kern_return_t (*IOConnectTrap6)(io_connect_t connect, uint32_t selector, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
        kern_return_t (*mach_ports_lookup)(task_t target_task, mach_port_array_t init_port_set, mach_msg_type_number_t* init_port_count);
        mach_port_name_t (*mach_task_self)(void);
        kern_return_t (*mach_vm_remap)(vm_map_t target_task, mach_vm_address_t* target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance);
        kern_return_t (*mach_port_destroy)(ipc_space_t task, mach_port_name_t name);
        kern_return_t (*mach_port_deallocate)(ipc_space_t task, mach_port_name_t name);
        kern_return_t (*mach_port_allocate)(ipc_space_t task, mach_port_right_t right, mach_port_name_t* name);
        kern_return_t (*mach_port_insert_right)(ipc_space_t task, mach_port_name_t name, mach_port_poly_t right, mach_msg_type_name_t right_type);
        kern_return_t (*mach_ports_register)(task_t target_task, mach_port_array_t init_port_set, uint64_t /*???target_task*/ init_port_array_count);
        mach_msg_return_t (*mach_msg)(mach_msg_header_t* msg, mach_msg_option_t option, mach_msg_size_t send_size, mach_msg_size_t receive_limit, mach_port_t receive_name, mach_msg_timeout_t timeout, mach_port_t notify);
        int (*posix_spawn)(uint64_t pid, const char* path, void*, void*, char* const argv[], char* const envp[]);
    } userland_funcs;
#ifndef IOKIT_H
#undef io_connect_t
#undef task_t
#undef vm_map_t
#undef vm_prot_t
#undef vm_inherit_t
#undef ipc_space_t
#endif
} offsets_t;

uint32_t get_anchor(void);
typedef struct offset_struct offset_struct_t;
bool populate_offsets(offsets_t* liboffsets, struct offset_struct* offsets);

// Credit to https://github.com/0x7ff/maphys/blob/7ffffffab7f4fb1e9644f02a97299e5a28300f3e/maphys.c#L703
// Used in sock_port to get kernel slide
#ifdef __LP64__
#define CPU_DATA_RTCLOCK_DATAP_OFF 0x1A8
#else
#define CPU_DATA_RTCLOCK_DATAP_OFF 0x1D8
#endif

// Used in sock_port primitive function
#ifdef __LP64__
#define OFFSET_IP6PO_MINMTU 164
#else
#define OFFSET_IP6PO_MINMTU 116
#endif

// For kcall.m
#ifdef __LP64__
#define OFFSET_IPC_PORT_IP_KOBJECT 0x68 // "ipc_kobject_server: strange destination rights", scroll up to case 2
#define OFFSET_VTAB_GET_EXTERNAL_TRAP_FOR_INDEX 0xb7 // see offsets.m
#define OFFSET_IOEXTERNALTRAP_OBJECT 0x40 // the offset used by our gadget
#else
#define OFFSET_IPC_PORT_IP_KOBJECT 0x48 // "ipc_kobject_server: strange destination rights", scroll up to case 2
#define OFFSET_VTAB_GET_EXTERNAL_TRAP_FOR_INDEX 0xe1 // see offsets.m
#define OFFSET_IOEXTERNALTRAP_OBJECT 0x30 // the offset used by our gadget
#endif

#define OFFSET_IOEXTERNALTRAP_FUNC OFFSET_IOEXTERNALTRAP_OBJECT + sizeof(kptr_t) // + sizeof(kptr_t)

// For kents.m
#define OFFSET_PROC_P_TEXTVP 0x248
#define OFFSET_VNODE_V_UBCINFO 0x78
#define OFFSET_UBCINFO_CSBLOBS 0x50
#define OFFSET_CSBLOB_CSB_ENTITLEMENTS_BLOB 0x90
#define OFFSET_CSBLOB_HEADER_LEN 0x8
#define OFFSET_CSBLOB_LENGTH 0x4

// For kutils.m
#ifdef __LP64__
#define OFFSET_PROC_NAME 0x268 // found in proc_name
#define OFFSET_PROC_PID 0x10 // found in proc_name
#define OFFSET_PROC_TASK 0x18
#define OFFSET_TASK_ITK_SPACE 0x308
#define OFFSET_ITK_SPACE_IS_TABLE /* note that itk_space == ipc_space */ 0x20
#define SIZEOF_IPC_ENTRY_T 0x18 // division of 0x18 in loop below "the mig dispatch table is too small"
#else
#define OFFSET_PROC_NAME 0x180 // found in proc_name
#define OFFSET_PROC_PID 0x8 // found in proc_name
#define OFFSET_PROC_TASK 0xc
#define OFFSET_TASK_ITK_SPACE 0x1e8
#define OFFSET_ITK_SPACE_IS_TABLE 0x14
#define SIZEOF_IPC_ENTRY_T 0x10 // right bitshift of 4 in loop below "the mig dispatch table is too small"
#endif

#define OFFSET_PROC_LE_PREV sizeof(kptr_t) // from the definition of LIST_ENTRY macro

// For nonce.m
#define OFFSET_SEARCH_NVRAM_PROP 0x590
#define OFFSET_GET_OF_VARIABLE_PERM 0x558
#define OFFSET_VTAB_SIZE 0x620
#define OFFSET_IODTNVRAM_OBJ 0x68

// For root_fs.m
#define OFFSET_VNODE_V_MOUNT 0xd8
#define OFFSET_V_MOUNT_V_FLAG 0x70
#define OFFSET_VNODE_SPEC_INFO 0x78
#define OFFSET_SPEC_INFO_FLAGS 0x10

// For root.m
// Note for understanding these:
// typedef struct ucred *kauth_cred_t;
// typedef struct posix_cred *posix_cred_t;

#ifdef __LP64__
#define OFFSET_PROC_P_UCRED 0x100 // ldr offset in kauth_proc_label_update after lck_mtx_lock
#define OFFSET_UCRED_CR_POSIX 0x18 // found in kauth_cred_find
#define OFFSET_UCRED_CR_LABEL 0x78 // found in kauth_cred_find
#else
#define OFFSET_PROC_P_UCRED 0x98 // ldr offset in kauth_proc_label_update after lck_mtx_lock
#define OFFSET_UCRED_CR_POSIX 0xc // found in kauth_cred_find
#define OFFSET_UCRED_CR_LABEL 0x6c // found in kauth_cred_find
#endif

#define OFFSET_AMFI_SLOT 0
#define OFFSET_SANDBOX_SLOT 1

#endif
