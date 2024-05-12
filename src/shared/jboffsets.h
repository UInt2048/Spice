#ifndef JBOFFSETS_H
#define JBOFFSETS_H

// If you forget to enable this when you don't have the right offset in stage1.h,
// you'll receive a segfault in stage 1 (KERN_INVALID_ADDRESS) with pc = OFF_BEAST_GADGET since it won't be mapped
#define STAGE1FD_SCREAM_TEST 0

// Define devices
#define N41_10_3_4 0
#define N69_11_3 0
#define N69_11_4 0
#define N71_11_3_1 1
#define J96_11_1_2 0
#define J96_11_3_1 0

// iPhone 5 (GSM) (iPhone5,1), iOS 10.3.4
#if N41_10_3_4
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
#define OFF_TRUST_CACHE 0x8089c44 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
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

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x000b9c08+0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x000b908c // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4-OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
// #define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
// #define OFF_MAX_SLIDE 0x4810000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
// #define OFF_SLIDE_VALUE 0x4000 // hardcode that one
// #define OFF_PIVOT_X21 0x199bb31a8 // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
// #define OFF_PIVOT_X21_X9 0x50-0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
// #define OFF_MEMMOVE 0x1ab680d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0xa0 // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
// #define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
// #define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
// #define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
// #define OFF_BEAST_GADGET 0x1a1639494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
// #define OFF_STR_X0_GADGET 0x197d94ac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
// #define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
// #define OFF_CBZ_X0_GADGET 0x188cffe5c // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
// #define OFF_CBZ_X0_X16_LOAD 0x1b1c0e000+0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
// #define OFF_ADD_X0_GADGET 0x18518bb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
// #define OFF_ERRNO 0x1b30f1000+0xff8+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
// #define OFF_NDR_RECORD 0x1b1896018+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // address of label _NDR_record, we need to map it before using it
// #define OFF_LONGJMP realsym(dyld_cache_path,"__longjmp") // dlsym of __longjmp
// #define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
// #define OFF_MMAP realsym(dyld_cache_path,"___mmap") // dlsym of ___mmap
// #define OFF_MEMCPY realsym(dyld_cache_path,"_memcpy") // dlsym of _memcpy
// #define OFF_OPEN realsym(dyld_cache_path,"_open") //dlsym of ___open
// #define OFF_FCNTL_RAW realsym(dyld_cache_path,"___fcntl") // dlsym of ___fcntl
// #define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path,"_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0x803e039c // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0x80394f91 // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
#endif

// iPhone 6S Plus (iPhone8,2), iOS 11.3.1
#if N71_11_3_1
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

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x100067c10+0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x1000670e0 // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4-OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4808000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
#define OFF_SLIDE_VALUE 0x4000 // hardcode that one
#define OFF_PIVOT_X21 0x199bb31a8 // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
#define OFF_PIVOT_X21_X9 0x50-0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab688d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a1639494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
#define OFF_STR_X0_GADGET 0x197d94ac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
#define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188cffe5c // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
#define OFF_CBZ_X0_X16_LOAD 0x1b1c16000+0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18518bb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
#define OFF_ERRNO 0x1b30f9000+0xff8+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_NDR_RECORD 0x1b189e018+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // address of label _NDR_record, we need to map it before using it
#define OFF_LONGJMP 0x180b126e8 // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov sp, x2
#define OFF_MMAP 0x18097cbf4 // dlsym of ___mmap
#define OFF_MEMCPY 0x18095d634 // dlsym of _memcpy
#define OFF_OPEN 0x18097ce58 //dlsym of ___open
#define OFF_FCNTL_RAW 0x18097c434 // dlsym of ___fcntl
#define OFF_RAW_MACH_VM_REMAP 0x18097bb58 // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075a98cc // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address

#define OFF_WRITE 0x18095d8b4+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _write
#define OFF_IOCONNECTTRAP6 0x181160730+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _IOConnectTrap6
#define OFF_MACH_PORTS_LOOKUP 0x18095eaf0+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_ports_lookup
#define OFF_MACH_TASK_SELF 0x18097400c+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_task_self
#define OFF_MACH_VM_REMAP OFF_RAW_MACH_VM_REMAP+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // slide _mach_vm_remap
#define OFF_MACH_PORT_DESTROY 0x18095c37c+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_port_destroy
#define OFF_MACH_PORT_DEALLOCATE 0x18095c85c+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_port_deallocate
#define OFF_MACH_PORT_ALLOCATE 0x18095cbe8+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_port_allocate
#define OFF_MACH_PORT_INSERT_RIGHT 0x18095cc44+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_port_insert_right
#define OFF_MACH_PORTS_REGISTER 0x18096c650+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_ports_register
#define OFF_MACH_MSG 0x18095bc38+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _mach_msg
#define OFF_POSIX_SPAWN 0x180976340+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // dlsym of _posix_spawn
	
#endif

// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.1.2
#if J96_11_1_2
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
#endif
// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.3.1
#if J96_11_3_1
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
#endif
// iPhone SE (1st gen) (iPhone8,4), iOS 11.3
#if N69_11_3
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

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x100067c10+0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x1000670e0 // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4-OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4810000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
#define OFF_SLIDE_VALUE 0x4000 // hardcode that one
#define OFF_PIVOT_X21 0x199bb31a8 // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
#define OFF_PIVOT_X21_X9 0x50-0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab680d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a1632494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
#define OFF_STR_X0_GADGET 0x197d94ac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
#define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188cffe5c // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
#define OFF_CBZ_X0_X16_LOAD 0x1b1c0e000+0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18518bb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
#define OFF_ERRNO 0x1b30f1000+0xff8+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_NDR_RECORD 0x1b1896018+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // address of label _NDR_record, we need to map it before using it
#define OFF_LONGJMP realsym(dyld_cache_path,"__longjmp") // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
#define OFF_MMAP realsym(dyld_cache_path,"___mmap") // dlsym of ___mmap
#define OFF_MEMCPY realsym(dyld_cache_path,"_memcpy") // dlsym of _memcpy
#define OFF_OPEN realsym(dyld_cache_path,"_open") //dlsym of ___open
#define OFF_FCNTL_RAW realsym(dyld_cache_path,"___fcntl") // dlsym of ___fcntl
#define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path,"_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075a98cc // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
#endif
// iPhone SE (1st gen) (iPhone8,4), iOS 11.4
#if N69_11_4
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
#define OFF_PROC_P_CSFLAGS 0x2a8// _cs_restricted, first ldr offset (proc->p_csflags)
#define OFF_TASK_T_FLAGS 0x3a0 // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
#define OFF_CREATE_OUTSIZE 0xbc8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient

#define OFF_ISAKMP_CFG_CONFIG_DNS4 0x100067c10+0x8 // second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
#define OFF_LCCONF 0x1000670e0 // "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit)
#define OFF_DNS4_ARRAY_TO_LCCONF -(OFF_ISAKMP_CFG_CONFIG_DNS4-OFF_LCCONF) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // VERIFY! based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4678000 // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
#define OFF_SLIDE_VALUE 0x4000 // hardcode that one
#define OFF_PIVOT_X21 0x199c4b93c // search a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6
#define OFF_PIVOT_X21_X9 0x50-0x38 // VERIFY! this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab7b0d50 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_OLD_CACHE_ADDR 0x180000000 // the first unslid address of the dyld shared cache
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a16e6494 // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
#define OFF_STR_X0_GADGET 0x197e1eac8 // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
#define OFF_STR_X0_GADGET_OFF 0x28 // VERIFY! based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188d340bc // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
#define OFF_CBZ_X0_X16_LOAD 0x1b1d72000+0x4c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18519cb90 // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
#define OFF_ERRNO 0x1b3263000+0xff8+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_NDR_RECORD 0x1b1896018+OFF_NEW_CACHE_ADDR-OFF_OLD_CACHE_ADDR // VERIFY! address of label _NDR_record, we need to map it before using it
#define OFF_LONGJMP realsym(dyld_cache_path,"__longjmp") // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
#define OFF_MMAP realsym(dyld_cache_path,"___mmap") // dlsym of ___mmap
#define OFF_MEMCPY realsym(dyld_cache_path,"_memcpy") // dlsym of _memcpy
#define OFF_OPEN realsym(dyld_cache_path,"_open") //dlsym of ___open
#define OFF_FCNTL_RAW realsym(dyld_cache_path,"___fcntl") // dlsym of ___fcntl
#define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path,"_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075ad8cc // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
#endif

#endif