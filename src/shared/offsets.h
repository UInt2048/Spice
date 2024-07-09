#ifndef OFFSETS_H
#define OFFSETS_H

#ifdef __LP64__
typedef uint64_t kptr_t;
#else
typedef uint32_t kptr_t;
#endif

typedef uint64_t mach_port_poly_t; // We don't know what it is, but apparently a uint64_t works

#define FLAG_VERIFIED (1 << 0)
#define FLAG_LIGHTSPEED (1 << 1)
#define FLAG_VORTEX (1 << 2)
#define FLAG_SOCKET (1 << 3)

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

#endif
