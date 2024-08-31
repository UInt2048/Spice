#include "common.h"
#include <UIKit/UIDevice.h>
#include <sys/utsname.h>

#include "offsets.h"
#include <untether/offsets.h>

NSString* deviceName(void)
{
    struct utsname systemInfo;
    uname(&systemInfo);
    return [NSString stringWithCString:systemInfo.machine
                              encoding:NSUTF8StringEncoding];
}

#define DEVICE_EQUAL_TO(v) \
    ([deviceName() isEqualToString:v])
#define SYSTEM_VERSION() \
    ([[UIDevice currentDevice] systemVersion])
#define SYSTEM_VERSION_EQUAL_TO(v) \
    ([SYSTEM_VERSION() compare:v options:NSNumericSearch] == NSOrderedSame)
// #define SYSTEM_VERSION_GREATER_THAN(v) \
//     ([SYSTEM_VERSION() compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) \
    ([SYSTEM_VERSION() compare:v options:NSNumericSearch] != NSOrderedAscending)
// #define SYSTEM_VERSION_LESS_THAN(v) \
//     ([SYSTEM_VERSION() compare:v options:NSNumericSearch] == NSOrderedAscending)
// #define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) \
//     ([SYSTEM_VERSION() compare:v options:NSNumericSearch] != NSOrderedDescending)

#define CACHE_DIFF \
    (liboffsets->constant.new_cache_addr - liboffsets->constant.old_cache_addr)

// Sort the anchors and offsets in this file by iOS version then alphabetically by internal name

// "unable to determine boot cpu!" in kernelcache, str x9, [x23, 0x78] below,
// take the lower 7 bits of value in x9 (the registers may vary for you,
// use instruction info if the #offset in Ghidra is making it hard to see)
//
// on 10.3.4, "serverperfmode", str r1, [r5, 0x3c] near top of function
uint32_t get_anchor(void)
{
#ifdef __LP64__
    if (DEVICE_EQUAL_TO(@"iPad5,1") && SYSTEM_VERSION_EQUAL_TO(@"11.1.2")) {
        return (0xfffffff0075f90c8 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPad5,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.1")) {
        return (0xfffffff007607908 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone6,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        return (0xfffffff0075fb903 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone7,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        return (0xfffffff007607908 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone8,4") && SYSTEM_VERSION_EQUAL_TO(@"11.3")) {
        return (0xfffffff00761d968 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPad5,1") && SYSTEM_VERSION_EQUAL_TO(@"11.3.1")) {
        return (0xfffffff007625998 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone8,2") && SYSTEM_VERSION_EQUAL_TO(@"11.3.1")) {
        return (0xfffffff00761d968 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone7,2") && SYSTEM_VERSION_EQUAL_TO(@"11.4")) {
        return (0xfffffff007625998 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone8,4") && SYSTEM_VERSION_EQUAL_TO(@"11.4")) {
        return (0xfffffff007621968 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone8,1") && SYSTEM_VERSION_EQUAL_TO(@"11.4.1")) {
        return (0xfffffff0076219a8 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPhone8,4") && SYSTEM_VERSION_EQUAL_TO(@"11.4.1")) {
        return (0xfffffff0076219a8 & 0xfffffff);
    } else if (DEVICE_EQUAL_TO(@"iPod7,1") && SYSTEM_VERSION_EQUAL_TO(@"11.4.1")) {
        return (0xfffffff0076259d8 & 0xfffffff);
    }
#else
    if (DEVICE_EQUAL_TO(@"iPhone5,1") && SYSTEM_VERSION_EQUAL_TO(@"10.3.4")) {
        return (0x80437798 & 0xfffffff);
    }
#endif
    NSLog(@"Failed to find anchor for %@ on %@", deviceName(),
        [[UIDevice currentDevice] systemVersion]);
    return 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
bool populate_offsets(offsets_t* liboffsets, offset_struct_t* offsets)
{
    bool foundOffsets = false;
#ifdef __LP64__
    if (DEVICE_EQUAL_TO(@"iPad5,1") && SYSTEM_VERSION_EQUAL_TO(@"11.1.2")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a05ac; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a07dc; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070ebe88; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff007101550; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff00714a35c; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f4ffc; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071d6c74; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074c485c; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b34a70; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073e09ec; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073e095c; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b0288; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070c5470; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070afd14; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073b71e4; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075b8b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075d5e38; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff007622048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0076220a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff007622088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff00761fa48; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff007687428; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ed89c8; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...) liboffsets->struct_offsets.is_task_offset = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x568; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x1810cd0b0 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095b898 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x1809708b4 + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x180977bb4 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x180959138 + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x180959618 + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x1809599a4 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x180959a00 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x180968f34 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x1809589f4 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180972b5c + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x66dc000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x1990198fc; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1aa0b8bb8; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a0478c70; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197154b10; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x18889d780; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b01d54b8; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x184f6992c; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b167dfe0 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1afe54018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180a817dc; // dlsym of __longjmp
        offsets->mmap                                       = 0x180978c50; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095a3e8; // dlsym of _memcpy
        offsets->open                                       = 0x180978eb4; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x180978490; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708d870; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075898bc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPad5,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a4d18; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a4f48; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f0340; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff0071058d8; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff00714fe24; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9928; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db4c0; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074cfab4; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b2aa84; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073e7690; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073e7600; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b44c8; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070c9600; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b3f54; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073bdbe8; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075c4b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075e1e68; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff007630048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0076300a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff007630088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff00762e640; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff00769b428; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ed5408; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...) liboffsets->struct_offsets.is_task_offset = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x568; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x1810d5f7c + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095e240 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x180973280 + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097ab54 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095bfbc + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095c348 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095c3a4 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096b8d4 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095b398 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x1809755b0 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x60c0000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x1991a0928; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1aa470bb8; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a074bb40; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197269b10; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x18893e758; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b06e3a38; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x184fc992c; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b1bbafe0 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b0360018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180a856c8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097bbf0; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095cd8c; // dlsym of _memcpy
        offsets->open                                       = 0x18097be54; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097b430; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708df20; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075958c4; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone6,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
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
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e77548; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x568; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x1810d2f7c + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095e240 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x180973280 + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097ab54 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095badc + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095bfbc + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095c348 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095c3a4 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096b8d4 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095b398 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x1809755b0 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x5b44000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199294928; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1aa84cbb8; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a0817b40; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x19735db10; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x1889a2758; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b0b53b18; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x184fc792c; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b2058fe0 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b07d0018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180a856c8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097bbf0; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095cd8c; // dlsym of _memcpy
        offsets->open                                       = 0x18097be54; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097b430; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff007081f20; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075898c4; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone7,1") && SYSTEM_VERSION_EQUAL_TO(@"11.2.6")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
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
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ee8bc8; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x1810d2f7c + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095e240 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x180973280 + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097ab54 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095badc + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095bfbc + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095c348 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095c3a4 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096b8d4 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095b398 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x1809755b0 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x5b3c000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199294928; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x50; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1aa854bb8; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a081db40; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x19735db10; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x1889a2758; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b0b5bb18; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x184fc792c; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b2060fe0 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b07d9018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180a856c8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097bbf0; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095cd8c; // dlsym of _memcpy
        offsets->open                                       = 0x18097be54; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097b430; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708df20; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075958c4; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone8,4") && SYSTEM_VERSION_EQUAL_TO(@"11.3")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_VERIFIED | FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a7090; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a72b4; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f76c4; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710cdc0; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007153484; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9a04; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db710; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e2404; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b5ecb0; // found by searching for "sandbox memory allocation failure"
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
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e88c50; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
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
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4810000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199bb31a8; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab680d20; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a1632494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197d94ac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188cffe5c; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1c0e2c8; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18518bb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b30f1ff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1896018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce58; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075a98cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPad5,1") && SYSTEM_VERSION_EQUAL_TO(@"11.3.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_VERIFIED | FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071aa804; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071aaa28; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f4d80; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710a960; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007154fb8; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071fe2f0; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071dff70; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e8f38; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b1acb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f8ba4; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f8b14; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b9328; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf2c8; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b8aa4; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073ce75c; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075e2b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075ffe50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075dd048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075dd0a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075dd088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff00764c468; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b8ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006eb8e10; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...) liboffsets->struct_offsets.is_task_offset = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x181160730 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095eaf0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x18097400c + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x180969bb8 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c37c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095c85c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095cbe8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095cc44 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096c650 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095bc38 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180976340 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4c74000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199bb31a8; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab3b0d20; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a1664494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x199875020; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x19987f230; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b214cc50; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18518bb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b2d65000 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1535018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097b950; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075b18cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone8,2") && SYSTEM_VERSION_EQUAL_TO(@"11.3.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_VERIFIED | FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
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
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e84c50; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
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

        liboffsets->vortex.vtab_get_external_trap_for_index = (0xfffffff006e85208 - liboffsets->vtabs.iosurface_root_userclient) / sizeof(kptr_t); // IOUserClient::getExternalTrapForIndex

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4808000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199bb31a8; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab688d20; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a1639494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197d94ac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188cffe5c; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1c162c8; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18518bb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b30f9ff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b189e018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce58; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075a98cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone7,2") && SYSTEM_VERSION_EQUAL_TO(@"11.4")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
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
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ed9590; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
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

        liboffsets->vortex.rop_ldr_x0_x0_0x10               = 0xfffffff00627eb48; // search the kernel cache for 00 08 40 f9 c0 03 5f d6

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4670000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199c4b93c; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab7b8d50; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a16ed494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197e1eac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188d340bc; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1da74c8; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18519cb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b326bff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1a02018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce58; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075b18cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone8,4") && SYSTEM_VERSION_EQUAL_TO(@"11.4")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_VERIFIED | FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a71cc; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a73f0; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f4c4c; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710a348; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007153574; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9bcc; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db8d8; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e2a58; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b57cb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f3b68; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f3ad8; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b915c; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf30c; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b88d8; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073c9c58; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075deb98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075fbe50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075d9048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075d90a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075d9088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff007648428; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b4ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e88e50; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
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
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4678000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199c4b93c; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab7b0d50; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a16e6494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197e1eac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188d340bc; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1d724c8; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18519cb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b3263ff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1896018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbf4; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d634; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce58; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c434; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e158; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075ad8cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone8,1") && SYSTEM_VERSION_EQUAL_TO(@"11.4.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a72d4; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a74f8; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f4c58; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710a354; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff00715367c; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9cd4; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db9e0; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e2fb4; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b0dcb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f3fe0; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f3f50; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b915c; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf30c; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b88d8; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073ca0d0; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075deb98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075fbe50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075d9048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075d90a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075d9088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff007648468; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b4ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e81010; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x18116031c + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095ead0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x180973fdc + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097bb28 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c35c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095c83c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095cbc8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095cc24 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096c630 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095bc18 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180976310 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4650000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199c5893c; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab7d0d50; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a16fe494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197e2bac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188d369dc; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1d96508; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18519eb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b3287ff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1a1d018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbe8; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d614; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce4c; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c404; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e188; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075ad8cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPhone8,4") && SYSTEM_VERSION_EQUAL_TO(@"11.4.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071a72d4; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071a74f8; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f4c58; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710a354; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff00715367c; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071f9cd4; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071db9e0; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e2fb4; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b57cb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f3fe0; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f3f50; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b915c; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf30c; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b88d8; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073ca0d0; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075deb98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075fbe50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075d9048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075d90a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075d9088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff007648468; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b4ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006e89010; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x18116031c + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095ead0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x180973fdc + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097bb28 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c35c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095c83c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095cbc8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095cc24 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096c630 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095bc18 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180976310 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x4658000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199c5893c; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1ab7c8d50; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a16f7494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197e2bac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188d369dc; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1d8e508; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18519eb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b327fff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b1a14018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbe8; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d614; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce4c; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c404; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e188; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075ad8cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    } else if (DEVICE_EQUAL_TO(@"iPod7,1") && SYSTEM_VERSION_EQUAL_TO(@"11.4.1")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT | FLAG_LIGHTSPEED;
        liboffsets->constant.old_cache_addr                 = 0x180000000; // static (SHARED_REGION_BASE_ARM64 in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x1c0000000; // static (SHARED_REGION_SIZE_ARM64 is 0x40000000 until iOS 12)
        liboffsets->constant.kernel_image_base              = 0xfffffff007004000; // static
        liboffsets->funcs.copyin                            = 0xfffffff0071aaa00; // symbol (_copyin)
        liboffsets->funcs.copyout                           = 0xfffffff0071aac24; // symbol (_copyout)
        liboffsets->funcs.current_task                      = 0xfffffff0070f4d8c; // symbol (_current_task)
        liboffsets->funcs.get_bsdtask_info                  = 0xfffffff00710a96c; // symbol (_get_bsdtask_info)
        liboffsets->funcs.vm_map_wire_external              = 0xfffffff007155168; // symbol (_vm_map_wire_external)
        liboffsets->funcs.vfs_context_current               = 0xfffffff0071fe578; // symbol (_vfs_context_current)
        liboffsets->funcs.vnode_lookup                      = 0xfffffff0071e01f8; // symbol (_vnode_lookup)
        liboffsets->funcs.osunserializexml                  = 0xfffffff0074e9a4c; // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        liboffsets->funcs.smalloc                           = 0xfffffff006b18cb0; // found by searching for "sandbox memory allocation failure"
        liboffsets->funcs.proc_find                         = 0xfffffff0073f9584; // symbol (_proc_find)
        liboffsets->funcs.proc_rele                         = 0xfffffff0073f94f4; // symbol (_proc_rele)
        liboffsets->funcs.ipc_port_alloc_special            = 0xfffffff0070b9328; // \"ipc_processor_init\" in processor_start -> call above
        liboffsets->funcs.ipc_kobject_set                   = 0xfffffff0070cf2c8; // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        liboffsets->funcs.ipc_port_make_send                = 0xfffffff0070b8aa4; // first call in long path of KUNCUserNotificationDisplayFromBundle
        liboffsets->gadgets.add_x0_x0_ret                   = 0xfffffff0073cf13c; // gadget (or _csblob_get_cdhash)
        liboffsets->data.realhost                           = 0xfffffff0075e2b98; // _host_priv_self -> adrp addr
        liboffsets->data.zone_map                           = 0xfffffff0075ffe50; // str 'zone_init: kmem_suballoc failed', first qword above
        liboffsets->data.kernel_task                        = 0xfffffff0075dd048; // symbol (_kernel_task)
        liboffsets->data.kern_proc                          = 0xfffffff0075dd0a0; // symbol (_kernproc)
        liboffsets->data.rootvnode                          = 0xfffffff0075dd088; // symbol (_rootvnode)
        liboffsets->data.osboolean_true                     = 0xfffffff00764c4a8; // __ZN9OSBoolean11withBooleanEb -> first adrp addr (isn't used anywhere tho)
        liboffsets->data.trust_cache                        = 0xfffffff0076b8ee8; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0xfffffff006ee5910; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x28; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0xe0; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x2f0; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x8; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x5c8; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0x18; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x2a8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x3a0; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x3a8; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x3b0; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0xbc8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9
        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x18116031c + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x18095ead0 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x180973fdc + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x18097bb28 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x18095c35c + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x18095c83c + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x18095cbc8 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x18095cc24 + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x18096c630 + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x18095bc18 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x180976310 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x1000670e0 - (0x100067c10 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        offsets->max_slide                                  = 0x53cc000; // read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        offsets->slide_value                                = 0x4000; // hardcode that one
        offsets->pivot_x21                                  = 0x199c5893c; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        offsets->pivot_x21_x9_offset                        = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x1aad7cd50; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0x10c; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        offsets->cache_text_seg_size                        = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        offsets->BEAST_GADGET                               = 0x1a1455494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        offsets->str_x0_gadget                              = 0x197e2bac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        offsets->str_x0_gadget_offset                       = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        offsets->cbz_x0_gadget                              = 0x188d369dc; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        offsets->cbz_x0_x16_load                            = 0x1b1246508; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        offsets->add_x0_gadget                              = 0x18519eb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x1b26e8ff8 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x1b0ecd018 + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x180b126e8; // dlsym of __longjmp
        offsets->mmap                                       = 0x18097cbe8; // dlsym of ___mmap
        offsets->memcpy                                     = 0x18095d614; // dlsym of _memcpy
        offsets->open                                       = 0x18097ce4c; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x18097c404; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0xfffffff00708e188; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0xfffffff0075b18cc; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    }
#else
    if (DEVICE_EQUAL_TO(@"iPhone5,1") && SYSTEM_VERSION_EQUAL_TO(@"10.3.4")) {
        foundOffsets                                        = true; // These offsets exist
        liboffsets->flags                                   = FLAG_SOCK_PORT;
        liboffsets->constant.old_cache_addr                 = 0x1a000000; // static (SHARED_REGION_BASE_ARM in <mach/shared_region.h>)
        liboffsets->constant.new_cache_addr                 = 0x40000000; // static (SHARED_REGION_SIZE_ARM is 0x26000000)
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
        liboffsets->data.trust_cache                        = 0x80809c44; // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to_lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
        liboffsets->vtabs.iosurface_root_userclient         = 0x8066bba8; // search "IOSurfaceRootUserClient", store in function below first reference (or, on iOS 11 only, 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...)
        liboffsets->struct_offsets.is_task_offset           = 0x18; // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
        liboffsets->struct_offsets.task_itk_self            = 0x9c; // first reference of "ipc_task_reset", offset after _lck_mtx_lock
        liboffsets->struct_offsets.itk_registered           = 0x1dc; // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
        liboffsets->struct_offsets.ipr_size                 = 0x4; // "ipc_object_copyout_dest: strange rights", function below, offset of second ldr (ipc_port_request->name->size, long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
        liboffsets->struct_offsets.sizeof_task              = 0x3b0; // str "tasks", mov offset below (size of entire task struct)
        liboffsets->struct_offsets.proc_task                = 0xc; // "PMTellAppWithResponse - Suspended", second ldr offset above (proc->task)
        liboffsets->struct_offsets.proc_p_csflags           = 0x1b8; // _cs_restricted, first ldr offset (proc->p_csflags)
        liboffsets->struct_offsets.task_t_flags             = 0x248; // __ZN12IOUserClient18clientHasPrivilegeEPvPKc, in equal to 0 branch of foregroud strncmp, in function on iOS 10 (task->t_flags)
        liboffsets->struct_offsets.task_all_image_info_addr = 0x250; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_addr, theoretically just +0x8 from t_flags)
        liboffsets->struct_offsets.task_all_image_info_size = 0x258; // "created task is not a member of a resource coalition", search 0x5f (task->all_image_info_size, theoretically just +0x10 from t_flags)
        liboffsets->iosurface.create_outsize                = 0x3c8; // dispatch table starts at 20 * sizeof(kptr_t) after IOUserClient::getExternalTrapForIndex in vtab
        liboffsets->iosurface.create_surface                = 0; // IOSurfaceRootUserClient::s_create_surface is method 0
        liboffsets->iosurface.set_value                     = 9; // IOSurfaceRootUserClient::s_set_value is method 9

        liboffsets->vortex.task_bsd_info                    = 0x22c; // offset from _get_bsdtask_info
        liboffsets->vortex.proc_ucred                       = 0x98; // offset from _proc_ucred
        liboffsets->vortex.realhost_special                 = 0x8; // ldr offset of _host_get_special_port
        liboffsets->vortex.iouserclient_ipc                 = 0x5c; // "%s[0x%qx]::scheduleFinalize\n", ldr offset after _lck_mtx_lock
        liboffsets->vortex.vtab_get_retain_count            = (0x8066bbb4 - liboffsets->vtabs.iosurface_root_userclient) / sizeof(kptr_t); // OSObject::getRetainCount array index from vtabs.iosurface_root_userclient
        liboffsets->vortex.vtab_get_external_trap_for_index = (0x8066bf2c - liboffsets->vtabs.iosurface_root_userclient) / sizeof(kptr_t); // IOUserClient::getExternalTrapForIndex
        liboffsets->vortex.kernel_map                       = liboffsets->data.kernel_task + sizeof(kptr_t); // symbol (_kernel_map)
        liboffsets->vortex.chgproccnt                       = 0x8027cc16; // found by searching for "chgproccnt: procs < 0"
        liboffsets->vortex.kauth_cred_ref                   = 0x8025e78a; // symbol (_kauth_cred_ref)
        liboffsets->vortex.osserializer_serialize           = 0x8030687c; // symbol (__ZNK12OSSerializer9serializeEP11OSSerialize)
        liboffsets->vortex.rop_ldr_r0_r0_0xc                = 0x802d1d44; // search the kernel cache for c0 68 70 47

        liboffsets->socket.task_vm_map                      = 0x14;
        liboffsets->socket.task_prev                        = 0x1c;
        liboffsets->socket.task_itk_space                   = 0x1e8;
        liboffsets->socket.task_bsd_info                    = 0x22c;
        liboffsets->socket.ipc_port_ip_receiver             = 0x44;
        liboffsets->socket.ipc_port_ip_kobject              = 0x48;
        liboffsets->socket.proc_pid                         = 0x8;
        liboffsets->socket.proc_p_fd                        = 0x9c;
        liboffsets->socket.filedesc_fd_ofiles               = 0x0;
        liboffsets->socket.fileproc_f_fglob                 = 0x8;
        liboffsets->socket.fileglob_fg_data                 = 0x28;
        liboffsets->socket.pipe_buffer                      = 0x10;
        liboffsets->socket.ipc_space_is_table               = 0x14;
        liboffsets->socket.size_ipc_entry                   = 0x10;

        liboffsets->userland_funcs.IOConnectTrap6           = (void*)(0x1b0616a6 + CACHE_DIFF); // dlsym of _IOConnectTrap6
        liboffsets->userland_funcs.mach_ports_lookup        = (void*)(0x1a5ca9b4 + CACHE_DIFF); // dlsym of _mach_ports_lookup
        liboffsets->userland_funcs.mach_task_self           = (void*)(0x1a5d8480 + CACHE_DIFF); // dlsym of _mach_task_self
        liboffsets->userland_funcs.mach_vm_remap            = (void*)(0x1a5dc0a6 + CACHE_DIFF); // dlsym of _mach_vm_remap
        liboffsets->userland_funcs.mach_port_destroy        = (void*)(0x1a5c8d58 + CACHE_DIFF); // dlsym of _mach_port_destroy
        liboffsets->userland_funcs.mach_port_deallocate     = (void*)(0x1a5c8af2 + CACHE_DIFF); // dlsym of _mach_port_deallocate
        liboffsets->userland_funcs.mach_port_allocate       = (void*)(0x1a5c92c2 + CACHE_DIFF); // dlsym of _mach_port_allocate
        liboffsets->userland_funcs.mach_port_insert_right   = (void*)(0x1a5c92ea + CACHE_DIFF); // dlsym of _mach_port_insert_right
        liboffsets->userland_funcs.mach_ports_register      = (void*)(0x1a5d2f0e + CACHE_DIFF); // dlsym of _mach_ports_register
        liboffsets->userland_funcs.mach_msg                 = (void*)(0x1a5c86b4 + CACHE_DIFF); // dlsym of _mach_msg
        liboffsets->userland_funcs.posix_spawn              = (void*)(0x1a5d99c4 + CACHE_DIFF); // dlsym of _posix_spawn

        offsets->dns4_array_to_lcconf                       = 0x000b908c - (0x000b9c08 + 0x8); // lcconf = "failed to set my ident: %s", value being offset by 0xb0 (0x6c on 32-bit), then isakmp_config_dns4 = subtract second reference of "No more than %d DNS", first adr in switch case 0x77, add 0x8
        offsets->str_buff_offset                            = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know its offset)
        // offsets->max_slide = 0x4808000; //read 8 bytes at OFF_OLD_CACHE_ADDR + 0xf0
        // offsets->slide_value = 0x4000; // hardcode that one
        // offsets->pivot_x21 = 0x199bb31a8; // search the dyld cache for a8 06 40 f9 09 01 40 f9 29 1d 40 f9 e1 03 00 aa e0 03 08 aa 20 01 3f d6, or original: a8 06 40 f9 09 01 40 f9 29 29 40 f9 e3 07 40 f9 e2 03 00 aa e0 03 08 aa e1 03 16 aa e4 03 14 aa e5 03 13 aa 20 01 3f d6
        // offsets->pivot_x21_x9_offset = 0x38; // 11.3 and higher use 0x38 in the gadget instead of 0x50 (since the original is not present)
        offsets->memmove                                    = 0x34cd640c; // strlcpy second branch, adrp offset in thunk (get from the actual bl instruction, not from decompiler)
        offsets->lcconf_counter_offset                      = 0xa0; // "error allocating splitdns list buffer", switch case 0x87 below, first str offset
        // offsets->cache_text_seg_size = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
        // offsets->BEAST_GADGET = 0x1a1639494; // search the dyld cache for e4 03 16 aa e5 03 14 aa e6 03 15 aa e7 03 13 aa e0 03 1a aa e1 03 19 aa e2 03 18 aa e3 03 17 aa 60 03 3f d6 fd 7b 47 a9 f4 4f 46 a9 f6 57 45 a9 f8 5f 44 a9 fa 67 43 a9 fc 6f 42 a9 e9 23 41 6d ff 03 02 91 c0 03 5f d6
        // offsets->str_x0_gadget = 0x197d94ac8; // search the dyld cache for 60 16 00 f9 00 00 80 52 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6
        // offsets->str_x0_gadget_offset = 0x28; // based on the gadget above (at which offset it stores x0 basically)
        // offsets->cbz_x0_gadget = 0x188cffe5c; // __ZN3rtc9TaskQueue12QueueContext13DeleteContextEPv
        // offsets->cbz_x0_x16_load = 0x1b1c162c8; // decode the gadget above, there will be a jump, follow that jump and decode the adrp and add there
        // offsets->add_x0_gadget = 0x18518bb90; // search the dyld cache for a0 02 14 8b fd 7b 42 a9 f4 4f 41 a9 f6 57 c3 a8 c0 03 5f d6
        offsets->errno_offset                               = 0x385e59d4 + CACHE_DIFF; // we can get that by getting a raw syscall (for example ___mmap, then searching for a branch following that and then searching for an adrp and a str)
        offsets->mach_msg_offset                            = 0x3772a00c + CACHE_DIFF; // address of label _NDR_record, we need to map it before using it
        offsets->longjmp                                    = 0x1a690270; // dlsym of __longjmp
        // offsets->stack_pivot = offsets->longjmp+0x2c; // longjmp from mov sp, x2
        offsets->mmap                                       = 0x1a5c8f18; // dlsym of ___mmap
        offsets->memcpy                                     = 0x1a5c9b64; // dlsym of _memcpy
        offsets->open                                       = 0x1a5dd470; // dlsym of ___open
        offsets->fcntl_raw_syscall                          = 0x1a5dc8bc; // dlsym of ___fcntl
        offsets->rootdomainUC_vtab                          = 0x803e039c; // find __ZTV20RootDomainUserClient in kernel, first non-zero byte
        offsets->swapprefix_addr                            = 0x80394f91; // search for the string "/private/var/vm/swapfile" (or "/var/vm/swapfile" on 10.3.4) in the kernel, that's the right address
    }
#endif

// Socket offsets for 64-bit (TODO: verify)
#ifdef __LP64__
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"12.0")) {
        printf("[i] offsets selected for iOS 12.0 or above\n");
        liboffsets->socket.task_vm_map    = 0x20;
        liboffsets->socket.task_prev      = 0x30;
        liboffsets->socket.task_itk_space = 0x300;
#if __arm64e__
        liboffsets->socket.task_bsd_info = 0x368;
#else
        liboffsets->socket.task_bsd_info = 0x358;
#endif
        liboffsets->socket.ipc_port_ip_receiver = 0x60;
        liboffsets->socket.ipc_port_ip_kobject  = 0x68;
        liboffsets->socket.proc_pid             = 0x60;
        liboffsets->socket.proc_p_fd            = 0x100;
        liboffsets->socket.filedesc_fd_ofiles   = 0x0;
        liboffsets->socket.fileproc_f_fglob     = 0x8;
        liboffsets->socket.fileglob_fg_data     = 0x38;
        liboffsets->socket.pipe_buffer          = 0x10;
        liboffsets->socket.ipc_space_is_table   = 0x20;
        liboffsets->socket.size_ipc_entry       = 0x18;
        liboffsets->iosurface.create_outsize    = 0xdd0;
    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.0")) {
        liboffsets->socket.task_vm_map          = 0x20;
        liboffsets->socket.task_prev            = 0x30;
        liboffsets->socket.task_itk_space       = 0x308;
        liboffsets->socket.task_bsd_info        = 0x368;
        liboffsets->socket.ipc_port_ip_receiver = 0x60;
        liboffsets->socket.ipc_port_ip_kobject  = 0x68;
        liboffsets->socket.proc_pid             = 0x10;
        liboffsets->socket.proc_p_fd            = 0x108;
        liboffsets->socket.filedesc_fd_ofiles   = 0x0;
        liboffsets->socket.fileproc_f_fglob     = 0x8;
        liboffsets->socket.fileglob_fg_data     = 0x38;
        liboffsets->socket.pipe_buffer          = 0x10;
        liboffsets->socket.ipc_space_is_table   = 0x20;
        liboffsets->socket.size_ipc_entry       = 0x18;
        if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"11.1")) {
            printf("[i] offsets selected for iOS 11.1 or above\n");
            liboffsets->iosurface.create_outsize = 0xbc8;
        } else {
            printf("[i] offsets selected for iOS 11.0 to 11.0.3\n");
            liboffsets->iosurface.create_outsize = 0x6c8;
        }
    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
        printf("[i] offsets selected for iOS 10.x\n");
        liboffsets->socket.task_vm_map          = 0x20;
        liboffsets->socket.task_prev            = 0x30;
        liboffsets->socket.task_itk_space       = 0x300;
        liboffsets->socket.task_bsd_info        = 0x360;
        liboffsets->socket.ipc_port_ip_receiver = 0x60;
        liboffsets->socket.ipc_port_ip_kobject  = 0x68;
        liboffsets->socket.proc_pid             = 0x10;
        liboffsets->socket.proc_p_fd            = 0x108;
        liboffsets->socket.filedesc_fd_ofiles   = 0x0;
        liboffsets->socket.fileproc_f_fglob     = 0x8;
        liboffsets->socket.fileglob_fg_data     = 0x38;
        liboffsets->socket.pipe_buffer          = 0x10;
        liboffsets->socket.ipc_space_is_table   = 0x20;
        liboffsets->socket.size_ipc_entry       = 0x18;
        liboffsets->iosurface.create_outsize    = 0x3c8;
    }
#endif

    return foundOffsets;
}
#pragma clang diagnostic pop
