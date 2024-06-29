#include "common.h"
#include <UIKit/UIDevice.h>
#include <sys/utsname.h>

#include "offsets.h"
#include <untether/offsets.h>

NSString* deviceName()
{
    struct utsname systemInfo;
    uname(&systemInfo);
    return [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
}
#define DEVICE_EQUAL_TO(v) ([deviceName() isEqualToString:v])
#define SYSTEM_VERSION_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

#define CACHE_DIFF (liboffsets->constant.new_cache_addr - liboffsets->constant.old_cache_addr)

uint32_t get_anchor()
{
#ifdef __LP64__
    if (DEVICE_EQUAL_TO(@"iPhone6,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        return (0xfffffff0075fb903 & 0xfffffff); // "unable to determine boot cpu!" in kernelcache, str x9, [x23, 0x78] below, take the lower 7 bits of value in x9 (the registers may vary for you, use instruction info if the #offset in Ghidra is making it hard to see)
    } else if (DEVICE_EQUAL_TO(@"iPhone7,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        return (0xfffffff007607908 & 0xfffffff); // "unable to determine boot cpu!" in kernelcache, str x9, [x23, 0x78] below, take the lower 7 bits of value in x9 (the registers may vary for you, use instruction info if the #offset in Ghidra is making it hard to see)
    } else if (DEVICE_EQUAL_TO(@"iPhone8,2") && SYSTEM_VERSION_EQUAL_TO(@"11.3.1")) {
        return (0xfffffff00761d968 & 0xfffffff); // "unable to determine boot cpu!" in kernelcache, str x9, [x23, 0x78] below, take the lower 7 bits of value in x9 (the registers may vary for you, use instruction info if the #offset in Ghidra is making it hard to see)
    } else if (DEVICE_EQUAL_TO(@"iPhone7,2") && SYSTEM_VERSION_EQUAL_TO(@"11.4")) {
        return (0xfffffff007625998 & 0xfffffff); // "unable to determine boot cpu!" in kernelcache, str x9, [x23, 0x78] below, take the lower 7 bits of value in x9 (the registers may vary for you, use instruction info if the #offset in Ghidra is making it hard to see)
    }
#else
    if (DEVICE_EQUAL_TO(@"iPhone5,1") && SYSTEM_VERSION_EQUAL_TO(@"10.3.4")) {
        return (0x80437798 & 0xfffffff); // on 10.3.4, "serverperfmode", str r1, [r5, 0x3c] near top of function
    }
#endif
    NSLog(@"Failed to find anchor for %@ on %@", deviceName(), [[UIDevice currentDevice] systemVersion]);
    return 0;
}

bool populate_offsets(offsets_t* liboffsets, offset_struct_t* offsets)
{
    bool foundOffsets = false;
#ifdef __LP64__
    if (DEVICE_EQUAL_TO(@"iPhone6,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->constant.verified                       = false; // These offsets are not verified to function correctly on a real device
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff007198b14; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff007198d44; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070e41f4; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff0070f978c; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007143cd8; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071ed630; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071cf1ac; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074c3928; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006851aec; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073db4dc; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073db44c; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070a8368; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070bd4b4; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070a7df4; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073b1900; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075b8b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075d5e50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff007624048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0076240a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff007624088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff007622600; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff00768f828; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e77548; // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // TODO: prove this
        liboffsets->iosurface.create_surface                = 0; // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
        liboffsets->iosurface.set_value                     = 9; // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
        // liboffsets->userland_funcs.IOConnectTrap6 = (void*)(0x181160730 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        // liboffsets->userland_funcs.mach_ports_lookup = (void*)(0x18095eaf0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        // liboffsets->userland_funcs.mach_task_self = (void*)(0x18097400c + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097ab54 + CACHE_DIFF); // dlsym of _mach_vm_remap
        // liboffsets->userland_funcs.mach_port_destroy = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        // liboffsets->userland_funcs.mach_port_deallocate = (void*)(0x18095c85c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        // liboffsets->userland_funcs.mach_port_allocate = (void*)(0x18095cbe8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        // liboffsets->userland_funcs.mach_port_insert_right = (void*)(0x18095cc44 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        // liboffsets->userland_funcs.mach_ports_register = (void*)(0x18096c650 + CACHE_DIFF); // dlsym of _mach_ports_register
        // liboffsets->userland_funcs.mach_msg = (void*)(0x18095bc38 + CACHE_DIFF); // dlsym of _mach_msg
        // liboffsets->userland_funcs.posix_spawn = (void*)(0x180976340 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
        offsets->max_slide                                  = 0x5b44000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199294928; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50 - 0x50; // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
        offsets->memmove                                    = 0x1aa84cbb8; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a0817b40; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x19735db10; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x1889a2758; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b0b53000 + 0xb18; // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x184fc792c; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b2058000 + 0xfe0 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b07d0018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180a856c8; // dlsym of __longjmp
        offsets->stack_pivot                                = offsets->longjmp + 0x2c; // longjmp from mov sp, x2
        offsets->mmap                                       = 0x18097bbf0; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095cd8c; // dlsym of _memcpy
        offsets->open                                       = 0x18097be54; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097b430; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff007081f20; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075898c4; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone7,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->constant.verified                       = false; // These offsets are verified to function correctly on a real device
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a4c64; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a4e94; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f0354; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff0071058ec; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff00714fe38; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9874; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db3f0; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074cfb6c; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b40aec; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073e7720; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073e7690; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b44c8; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070c9614; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b3f54; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073bdb44; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075c4b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075e1e50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff007630048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0076300a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff007630088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff00762e640; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff00769b428; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ee8bc8; // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // TODO: prove this
        liboffsets->iosurface.create_surface                = 0; // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
        liboffsets->iosurface.set_value                     = 9; // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
        // liboffsets->userland_funcs.IOConnectTrap6 = (void*)(0x181160730 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        // liboffsets->userland_funcs.mach_ports_lookup = (void*)(0x18095eaf0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        // liboffsets->userland_funcs.mach_task_self = (void*)(0x18097400c + CACHE_DIFF); // dlsym of _mach_task_self
        // liboffsets->userland_funcs.mach_vm_remap = (void*)(0x18097bb58 + CACHE_DIFF); // dlsym of _mach_vm_remap
        // liboffsets->userland_funcs.mach_port_destroy = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        // liboffsets->userland_funcs.mach_port_deallocate = (void*)(0x18095c85c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        // liboffsets->userland_funcs.mach_port_allocate = (void*)(0x18095cbe8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        // liboffsets->userland_funcs.mach_port_insert_right = (void*)(0x18095cc44 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        // liboffsets->userland_funcs.mach_ports_register = (void*)(0x18096c650 + CACHE_DIFF); // dlsym of _mach_ports_register
        // liboffsets->userland_funcs.mach_msg = (void*)(0x18095bc38 + CACHE_DIFF); // dlsym of _mach_msg
        // liboffsets->userland_funcs.posix_spawn = (void*)(0x180976340 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
        offsets->max_slide                                  = 0x5b3c000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199294928; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50 - 0x50; // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
        offsets->memmove                                    = 0x1aa854bb8; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a081db40; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x19735db10; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x1889a2758; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b0b5b000 + 0xb18; // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x184fc792c; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b2060000 + 0xfe0 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b07d9018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180a856c8; // dlsym of __longjmp
        offsets->stack_pivot                                = offsets->longjmp + 0x2c; // longjmp from mov sp, x2
        offsets->mmap                                       = 0x18097bbf0; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095cd8c; // dlsym of _memcpy
        offsets->open                                       = 0x18097be54; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097b430; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708df20; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075958c4; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone8,2") && SYSTEM_VERSION_EQUAL_TO(@"11.3.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->constant.verified                       = true; // These offsets are verified to function correctly on a real device
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a7090; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a72b4; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f76c4; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710cdc0; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007153484; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9a04; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db710; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e2404; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b18cb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f35b8; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f3528; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b915c; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf30c; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b88d8; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073c96a8; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075dab98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075f7e50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075d5048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075d50a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075d5088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff007644418; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b0ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e84c50; // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // TODO: prove this
        liboffsets->iosurface.create_surface                = 0; // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
        liboffsets->iosurface.set_value                     = 9; // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x181160730 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095eaf0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x18097400c + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097bb58 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095c85c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095cbe8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095cc44 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096c650 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095bc38 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180976340 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
        offsets->max_slide                                  = 0x4808000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199bb31a8; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50 - 0x38; // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
        offsets->memmove                                    = 0x1ab688d20; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a1639494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197d94ac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188cffe5c; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1c16000 + 0x2c8; // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18518bb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b30f9000 + 0xff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b189e018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->stack_pivot                                = offsets->longjmp + 0x2c; // longjmp from mov sp, x2
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce58; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075a98cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone7,2") && SYSTEM_VERSION_EQUAL_TO(@"11.4")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->constant.verified                       = false; // These offsets are not verified to function correctly on a real device
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071aa8f8; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071aab1c; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f4d80; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710a960; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007155060; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071fe470; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071e00f0; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e9574; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b2dcb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f910c; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f907c; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b9328; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf2c8; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b8aa4; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073cecc4; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075e2b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075ffe50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075dd048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075dd0a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075dd088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff00764c468; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b8ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ed9590; // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // TODO: prove this
        liboffsets->iosurface.create_surface                = 0; // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
        liboffsets->iosurface.set_value                     = 9; // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x181160670 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095eaf0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x18097400c + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097bb58 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095c85c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095cbe8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095cc44 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096c650 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095bc38 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180976340 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
        offsets->max_slide                                  = 0x4670000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199c4b93c; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50 - 0x38; // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
        offsets->memmove                                    = 0x1ab7b8d50; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a16ed494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197e1eac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188d340bc; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1da7000 + 0x4c8; // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18519cb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b326b000 + 0xff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1a02018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->stack_pivot                                = offsets->longjmp + 0x2c; // longjmp from mov sp, x2
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce58; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075b18cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
    }
#else
    if (DEVICE_EQUAL_TO(@"iPhone5,1") && SYSTEM_VERSION_EQUAL_TO(@"10.3.4")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->constant.verified                       = false; // These offsets are not verified to function correctly on a real device
        // liboffsets->constant.old_cache_addr = 0x180000000; // static
        // liboffsets->constant.new_cache_addr = 0x1c0000000; // static
        liboffsets->constant.kernel_image_base              = 0x80001000; // static
        liboffsets->funcs.copyin                            = 0x80007b9c; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0x80007c74; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0x8004bd9c; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0x8005c8c2; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0x80091b16; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0x8011307e; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0x800fe61c; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0x8030a478; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0x80fbf410; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0x8027cfbe; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0x8027cf52; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0x80019034; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0x800290b6; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0x80018c54; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0x8025f6bc; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0x80404150; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0x804188e0; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0x80456030; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0x80456144; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0x80456138; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0x80453fa0; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0x80809c44; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0x8066bba8; // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
        liboffsets->struct_offsets.is_task_offset           = 0x18; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0x9c; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x1dc; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x4; // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x3b0; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0xc; // "PMTellAppWithResponse - Suspended", second offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x1b8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x248; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x250; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x258; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0x3c8; // TODO: prove this
        liboffsets->iosurface.create_surface                = 0; // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
        liboffsets->iosurface.set_value                     = 9; // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
        // liboffsets->userland_funcs.IOConnectTrap6 = (void*)(0x181160730 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        // liboffsets->userland_funcs.mach_ports_lookup = (void*)(0x18095eaf0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        // liboffsets->userland_funcs.mach_task_self = (void*)(0x18097400c + CACHE_DIFF); // dlsym of _mach_task_self
        // liboffsets->userland_funcs.mach_vm_remap = (void*)(0x18097bb58 + CACHE_DIFF); // dlsym of _mach_vm_remap
        // liboffsets->userland_funcs.mach_port_destroy = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        // liboffsets->userland_funcs.mach_port_deallocate = (void*)(0x18095c85c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        // liboffsets->userland_funcs.mach_port_allocate = (void*)(0x18095cbe8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        // liboffsets->userland_funcs.mach_port_insert_right = (void*)(0x18095cc44 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        // liboffsets->userland_funcs.mach_ports_register = (void*)(0x18096c650 + CACHE_DIFF); // dlsym of _mach_ports_register
        // liboffsets->userland_funcs.mach_msg = (void*)(0x18095bc38 + CACHE_DIFF); // dlsym of _mach_msg
        // liboffsets->userland_funcs.posix_spawn = (void*)(0x180976340 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x000b908c - (0x000b9c08 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
        // offsets->max_slide = 0x4808000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        // offsets->slide_value = 0x4000; // hardcode that one
        // offsets->pivot_x21 = 0x199bb31a8; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        // offsets->pivot_x21_x9_offset = 0x50-0x38; // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
        // offsets->memmove = 0x1ab688d20; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0xa0; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        // offsets->cache_text_seg_size = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        // offsets->BEAST_GADGET = 0x1a1639494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        // offsets->str_x0_gadget = 0x197d94ac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        // offsets->str_x0_gadget_offset = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        // offsets->cbz_x0_gadget = 0x188cffe5c; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        // offsets->cbz_x0_x16_load = 0x1b1c16000+0x2c8; // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
        // offsets->add_x0_gadget = 0x18518bb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        // offsets->errno_offset = 0x1b30f9000+0xff8+CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        // offsets->mach_msg_offset = 0x1b189e018+CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        // offsets->longjmp = 0x180b126e8; // dlsym of __longjmp
        // offsets->stack_pivot = offsets->longjmp+0x2c; // longjmp from mov sp, x2
        // offsets->mmap = 0x18097cbf4; // dlsym of ___mmap
        // offsets->memcpy = 0x18095d634; // dlsym of _memcpy
        // offsets->open = 0x18097ce58; // dlsym of ___open
        // offsets->fcntl_raw_syscall = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0x803e039c; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0x80394f91; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel that's the right address
    }
#endif
    return foundOffsets;
}