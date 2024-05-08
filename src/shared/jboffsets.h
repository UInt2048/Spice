#ifndef JBOFFSETS_H

// Try to determine offsets_t dynamically
// We need a better solution because the sandbox isn't going to just give these up
#if 0
offsets_t offs;
static offsets_t dynamicOffsets(const char *config_path, const char *racoon_path, const char *dyld_cache_path) {
	init_uland_offsetfinder(racoon_path,dyld_cache_path);

	// init the kernel offset finder (libjake)
	jake_img_t kernel_symbols = malloc(sizeof(jake_img));

#define KERNEL_CACHE_PATH "/System/Library/Caches/com.apple.kernelcaches/kernelcache"
	if (jake_init_image(kernel_symbols, KERNEL_CACHE_PATH)) {
		LOG("Patchfinder init failed\n");
		return (offsets_t){};
	}

	// Duplicate code from stage2.m
#define sym(name) jake_find_symbol(kernel_symbols,name)
	return (offsets_t){
    	.constant = {
        	.kernel_image_base = 0xfffffff007004000, // static
    	},
    	.funcs = {
        	.copyin = sym("_copyin"), // symbol, duplicate
        	.copyout = sym("_copyout"), // symbol 
        	.current_task = sym("_current_task"), // symbol
        	.get_bsdtask_info = sym("_get_bsdtask_info"), // symbol 
        	.vm_map_wire_external = sym("_vm_map_wire_external"), // symbol
        	.vfs_context_current = sym("_vfs_context_current"), // symbol
        	.vnode_lookup = sym("_vnode_lookup"), // symbol
        	.osunserializexml = sym("__Z16OSUnserializeXMLPKcPP8OSString"), // symbol
        	.proc_find = sym("_proc_find"), // symbol
        	.proc_rele = sym("_proc_rele"), // symbol 

        	.smalloc = 0xfffffff006b1acb0, // found by searching for "sandbox memory allocation failure"
        	.ipc_port_alloc_special = 0xfffffff0070b9328, // \"ipc_processor_init\" in processor_start -> call above
        	.ipc_kobject_set = 0xfffffff0070cf2c8, // above _mach_msg_send_from_kernel_proper
        	.ipc_port_make_send = 0xfffffff0070b8aa4, // first call in long path of KUNCUserNotificationDisplayFromBundle
    	},
    	.gadgets = {
        	.add_x0_x0_ret = sym("_csblob_get_cdhash"), // gadget, duplicate
    	},
    	.data = {
        	.kernel_task = sym("_kernel_task"), // symbol 
        	.kern_proc = sym("_kernproc"), // symbol
        	.rootvnode = sym("_rootvnode"), // symbol 

        	.realhost = find_realhost(kernel_symbols), // _host_priv_self -> adrp addr
        	.zone_map = find_zonemap(kernel_symbols), // str 'zone_init: kmem_suballoc failed', first qword above 
        	.osboolean_true = sym("__ZN9OSBoolean11withBooleanEb"), // OSBoolean::withBoolean -> first adrp addr
        	.trust_cache = find_trustcache(kernel_symbols), // "%s: trust cache loaded successfully.\n store above", duplicate
    	},
    	.vtabs = {
        	.iosurface_root_userclient = 0xfffffff006e73590, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    	},
    	.struct_offsets = {
        	.is_task_offset = 0x28, // duplicate
        	.task_itk_self = 0xd8, // first reference of ipc_task_reset, offset after _lck_mtx_lock
        	.itk_registered = 0x2f0, // duplicate
        	.ipr_size = 8, // duplicate, ipc_port_request->name->size
        	.sizeof_task = 0x5c8, // size of entire task struct
        	.proc_task = 0x18, // proc->task
        	.proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        	.task_t_flags = 0x3a0, // task->t_flags, not set in untether version (IOUserClient::clientHasPrivilege, function call after current_task)
        	.task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        	.task_all_image_info_size = 0x3b0,  // task->all_image_info_size
   		},
    	.iosurface = {
        	.create_outsize = 0xbc8,
        	.create_surface = 0,
        	.set_value = 9,
    	},
	};
}
#endif

// iPhone 5 (GSM) (iPhone5,1), iOS 10.3.4
#if N41_10_3_4
#define OFF_KERNEL_IMAGE_BASE 0x80001000 // static
#define OFF_COPYIN 0x80007b9c // symbol
#define OFF_COPYOUT 0x80007c74 // symbol 
#define OFF_CURRENT_TASK 0x8004bd9c // symbol
#define OFF_GET_BSDTASK_INFO 0x8005c8c2 // symbol 
#define OFF_VM_MAP_WIRE_EXTERNAL 0x80091b16 // symbol
#define OFF_VFS_CONTEXT_CURRENT 0x8011307e // symbol
#define OFF_VNODE_LOOKUP 0x800fe61c // symbol
#define OFF_OSUNSERIALIZEXML 0x8030a478 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0x8027cfbe // symbol
#define OFF_PROC_RELE 0x8027cf52 // symbol 
#define OFF_SMALLOC 0x80fbf410 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0x80019034 // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0x800290b6 // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
#define OFF_IPC_PORT_MAKE_SEND 0x80018c54 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0x8025f6bc // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0x80456030 // symbol 
#define OFF_KERN_PROC 0x80456144 // symbol (kernproc)
#define OFF_ROOTVNODE 0x80456138 // symbol 
#define OFF_REALHOST 0x80404150 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0x804188e0 // str 'zone_init: kmem_suballoc failed', first qword above 
#define OFF_OSBOOLEAN_TRUE 0x80453fa0 // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0x8089c44 // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0x8066bba8 // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x18 // "ipc_task_init", lower of two final offsets to a local variable in decompiled code
#define OFF_TASK_ITK_SELF 0x9c // first reference of ipc_task_reset, offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x1dc // "ipc_task_init", first comparison below to parameter, first str offset in not zero branch
#define OFF_IPR_SIZE 0x4 // "ipc_object_copyout_dest: strange rights", offset of second ldr in function below (long path: search all instances of 0x10000003 to find _kernel_rpc_mach_port_construct_trap, needs to have a copyin call, and travel chain)
#define OFF_SIZEOF_TASK 0x3b0 // str "tasks", mov offset below
#define OFF_PROC_TASK 0xc // "PMTellAppWithResponse - Suspended", second offset above
#define OFF_PROC_P_CSFLAGS 0x1b8 // proc->p_csflags (_cs_restricted, first ldr offset)
#define OFF_TASK_T_FLAGS 0x248 // task->t_flags (IOUserClient::clientHasPrivilege, function call after current_task)
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x250 // ("created task is not a member of a resource coalition", search 0x5f) task->all_image_info_addr (theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x258  // ("created task is not a member of a resource coalition", search 0x5f) task->all_image_info_size
#define OFF_CREATE_OUTSIZE 0x3c8 // TODO: prove this
#define OFF_CREATE_SURFACE 0 // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
#define OFF_SET_VALUE 9 // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient

// #define OFF_DNS4_ARRAY_TO_LCCONF -((0x100067c10+0x28-4*8)-0x1000670e0) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
// #define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
// #define OFF_MAX_SLIDE 0x4810000  // just get 8 bytes at offset 30 from the cache
// #define OFF_SLIDE_VALUE 0x4000  // hardcode that one
// #define OFF_PIVOT_X21 0x199bb31a8 // I hope this doesn't change on any version but we need to find the same gadget on all version (gadget and byte seqeunce can be found in stage1.m)
// #define OFF_PIVOT_X21_X9 0x50-0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
// #define OFF_MEMMOVE 0x1ab680d20 // strlcpy second branch
// #define OFF_LCCONF_COUNTER 0x10c // we could try and find that dynamically or we could just hardcode it cause it prob doesn't change on 11.x (TODO: get that dynamically) (this is the offset of the counter variable in the lcconfig struct we use as a write what where primitive. It's used in some sub in racoon but it's hard to patchfind dynamically and as it doesn't change I just hardcoded it)
// #define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
// #define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
// #define OFF_BEAST_GADGET 0x1a1632494 // we can find that because it's part of a function and shouldn't change but it's basically also just byte matching cause if it would change the load order the whole framework would stop loading
// #define OFF_STR_X0_GADGET 0x197d94ac8 // search for the byte sequence again (gadget in rop.h)
// #define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
// #define OFF_CBZ_X0_GADGET 0x188cffe5c // search for the byte sequence (gadget in rop.h)
// #define OFF_CBZ_X0_X16_LOAD 0x1b1c0e000+0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
// #define OFF_ADD_X0_GADGET 0x18518bb90 // raw byte search again (gadget is in rop.h)
// #define OFF_ERRNO 0x1f30f1000+0xff8 // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
// #define OFF_MACH_MSG 0x1f1896018 // don't know what this causes we need to figure it out later (basically I will mmap this address at the start of stage 2 otherwise it will at some point randomly crash in the mach_msg syscall. I don't have a good way to patchfinding this yet but as soon as you have a debugger setup you can generate stage 2 without the mmap call then get a crash and get far from the debugger (or cashlog) and put it here)
// #define OFF_LONGJMP realsym(dyld_cache_path,"__longjmp") // dlsym of __longjmp
// #define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
// #define OFF_MMAP realsym(dyld_cache_path,"__mmap") // dlsym of __mmap
// #define OFF_MEMCPY realsym(dyld_cache_path,"_memcpy") // dlsym of _memcpy
// #define OFF_OPEN realsym(dyld_cache_path,"_open") //dlsym of _open
// #define OFF_FCNTL_RAW realsym(dyld_cache_path,"__fcntl") // dlsym of __fcntl
// #define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path,"_mach_vm_remap") // dlsym of _mach_vm_remap
// #define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel
// #define OFF_SWAPPREFIX_ADDR 0xfffffff0075a98cc // search for the string "/private/var/vm/swapfile" in the kernel that's the right address
// #define OFF_STAGE2_MAX_SIZE 0x200000 // I hardcoded this, if stage 2 ever gets bigger than that you would need to adjust it
// #define OFF_THREAD_MAX_SIZE 0x10000 // there is a seperate thread in stage 2 (the race thread that spams the syscall and this is it's rop stack max size, so be careful when modifing it esp unrolling the loop more so that you never get passed this limit)
// #define OFF_STAGE2_DATABUFFER_LEN 0x10000 // Moved from stage2.m
// #define OFF_STAGE2_BARRIER_BUFFER_SIZE 0x10000 // Moved from stage2.m
// #define OFF_STAGE3_FILEOFFSET 0 // at which place in the file (dylib) stage 3 (the code section) starts
// #define OFF_STAGE3_SIZE 0x10000 // get the file size and round at page boundary
#endif
// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.2.1
#if J96_11_2_1
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff00719e88c // symbol
#define OFF_COPYOUT 0xfffffff00719eab0 // symbol 
#define OFF_CURRENT_TASK 0xfffffff0070e8c0c // symbol
#define OFF_GET_BSDTASK_INFO 0xfffffff0070fe7ec // symbol 
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007148fe8 // symbol
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f2310 // symbol
#define OFF_VNODE_LOOKUP 0xfffffff0071d3f90 // symbol
#define OFF_OSUNSERIALIZEXML 0xfffffff0074dd7e4 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073ed31c // symbol
#define OFF_PROC_RELE 0xfffffff0073ed28c // symbol 
#define OFF_SMALLOC 0xfffffff006822cb0
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070ad1a8
#define OFF_IPC_KOBJECT_SET 0xfffffff0070c3148
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070ac924
#define OFF_ADD_X0_X0_RET 0xfffffff0063fddbc // gadget 
#define OFF_KERNEL_TASK 0xfffffff0075d1048 // symbol 
#define OFF_KERN_PROC 0xfffffff0075d10a0 // symbol (kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d1088 // symbol 
#define OFF_REALHOST 0xfffffff0075d6b98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075f3e50 // str 'zone_init: kmem_suballoc failed', first qword above 
#define OFF_OSBOOLEAN_TRUE 0xfffffff007640468 // OSBoolean::withBoolean -> first adrp addr
#define OFF_TRUST_CACHE 0xfffffff0076ab828
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e73590 // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28
#define OFF_TASK_ITK_SELF 0xd8
#define OFF_ITK_REGISTERED 0x2f0
#define OFF_IPR_SIZE 0x8 // ipc_port_request->name->size
#define OFF_SIZEOF_TASK 0x5c8 // size of entire task struct
#define OFF_PROC_TASK 0x18 // proc->task
#define OFF_PROC_P_CSFLAGS 0x2a8 // proc->p_csflags (_cs_restricted, first ldr offset)
#define OFF_TASK_T_FLAGS 0x3a0 // task->t_flags
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // task->all_image_info_addr (theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // task->all_image_info_size
#define OFF_CREATE_OUTSIZE 0xbc8
#define OFF_CREATE_SURFACE 0
#define OFF_SET_VALUE 9
#endif
// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.3.1
#if J96_11_3_1
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071aa804 // symbol
#define OFF_COPYOUT 0xfffffff0071aaa28 // symbol 
#define OFF_CURRENT_TASK 0xfffffff0070f4d80 // symbol
#define OFF_GET_BSDTASK_INFO 0xfffffff00710a960 // symbol 
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007154fb8 // symbol
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071fe2f0 // symbol
#define OFF_VNODE_LOOKUP 0xfffffff0071dff70 // symbol
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e8f38 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f8ba4 // symbol
#define OFF_PROC_RELE 0xfffffff0073f8b14 // symbol 
#define OFF_SMALLOC 0xfffffff006b1acb0 // isn't used anywhere
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b9328
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf2c8
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b8aa4
#define OFF_ADD_X0_X0_RET 0xfffffff0073ce75c // gadget 
#define OFF_KERNEL_TASK 0xfffffff0075dd048 // symbol 
#define OFF_KERN_PROC 0xfffffff0075dd0a0 // symbol (kernproc)
#define OFF_ROOTVNODE 0xfffffff0075dd088 // symbol 
#define OFF_REALHOST 0xfffffff0075e2b98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075ffe50 // str 'zone_init: kmem_suballoc failed', first qword above 
#define OFF_OSBOOLEAN_TRUE 0xfffffff00764c468 // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b8ee8
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006eb8e10 // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28
#define OFF_TASK_ITK_SELF 0xd8
#define OFF_ITK_REGISTERED 0x2f0
#define OFF_IPR_SIZE 0x8 // ipc_port_request->name->size
#define OFF_SIZEOF_TASK 0x5c8 // size of entire task struct
#define OFF_PROC_TASK 0x18 // proc->task
#define OFF_PROC_P_CSFLAGS 0x2a8 // proc->p_csflags (_cs_restricted, first ldr offset)
#define OFF_TASK_T_FLAGS 0x3a0 // task->t_flags
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // task->all_image_info_addr (theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // task->all_image_info_size
#define OFF_CREATE_OUTSIZE 0xbc8
#define OFF_CREATE_SURFACE 0
#define OFF_CREATE_SURFACE 9
#endif
// iPhone SE (1st gen) (iPhone8,4), iOS 11.3
#if N69_11_3
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071a7090 // symbol
#define OFF_COPYOUT 0xfffffff0071a72b4 // symbol 
#define OFF_CURRENT_TASK 0xfffffff0070f76c4 // symbol
#define OFF_GET_BSDTASK_INFO 0xfffffff00710cdc0 // symbol 
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007153484 // symbol
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f9a04 // symbol
#define OFF_VNODE_LOOKUP 0xfffffff0071db710 // symbol
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e2404 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f35b8  // symbol
#define OFF_PROC_RELE 0xfffffff0073f3528 // symbol 
#define OFF_SMALLOC 0xfffffff006b5ecb0 // found by searching for "sandbox memory allocation failure"
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b915c // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf30c // above _mach_msg_send_from_kernel_proper
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b88d8 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0073c96a8 // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075d5048 // symbol 
#define OFF_KERN_PROC 0xfffffff0075d50a0 // symbol (kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d5088 // symbol 
#define OFF_REALHOST 0xfffffff0075dab98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075f7e50 // str 'zone_init: kmem_suballoc failed', first qword above 
#define OFF_OSBOOLEAN_TRUE 0xfffffff007644418 // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b0ee8 // %s: trust cache loaded successfully.\n store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e88c50 // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28
#define OFF_TASK_ITK_SELF 0xe0 // first reference of ipc_task_reset, offset after _lck_mtx_lock
#define OFF_ITK_REGISTERED 0x2f0
#define OFF_IPR_SIZE 0x8 // ipc_port_request->name->size
#define OFF_SIZEOF_TASK 0x5c8 // size of entire task struct
#define OFF_PROC_TASK 0x18 // proc->task
#define OFF_PROC_P_CSFLAGS 0x2a8 // proc->p_csflags (_cs_restricted, first ldr offset)
#define OFF_TASK_T_FLAGS 0x3a0 // task->t_flags
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // task->all_image_info_addr (theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // task->all_image_info_size
#define OFF_CREATE_OUTSIZE 0xbc8
#define OFF_CREATE_SURFACE 0
#define OFF_SET_VALUE 9

#define OFF_DNS4_ARRAY_TO_LCCONF -((0x100067c10+0x28-4*8)-0x1000670e0) // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4810000  // just get 8 bytes at offset 30 from the cache
#define OFF_SLIDE_VALUE 0x4000  // hardcode that one
#define OFF_PIVOT_X21 0x199bb31a8 // I hope this doesn't change on any version but we need to find the same gadget on all version (gadget and byte seqeunce can be found in stage1.m)
#define OFF_PIVOT_X21_X9 0x50-0x38 // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab680d20 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // we could try and find that dynamically or we could just hardcode it cause it prob doesn't change on 11.x (TODO: get that dynamically) (this is the offset of the counter variable in the lcconfig struct we use as a write what where primitive. It's used in some sub in racoon but it's hard to patchfind dynamically and as it doesn't change I just hardcoded it)
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a1632494 // we can find that because it's part of a function and shouldn't change but it's basically also just byte matching cause if it would change the load order the whole framework would stop loading
#define OFF_STR_X0_GADGET 0x197d94ac8 // search for the byte sequence again (gadget in rop.h)
#define OFF_STR_X0_GADGET_OFF 0x28 // based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188cffe5c // search for the byte sequence (gadget in rop.h)
#define OFF_CBZ_X0_X16_LOAD 0x1b1c0e000+0x2c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18518bb90 // raw byte search again (gadget is in rop.h)
#define OFF_ERRNO 0x1f30f1000+0xff8 // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_MACH_MSG 0x1f1896018 // don't know what this causes we need to figure it out later (basically I will mmap this address at the start of stage 2 otherwise it will at some point randomly crash in the mach_msg syscall. I don't have a good way to patchfinding this yet but as soon as you have a debugger setup you can generate stage 2 without the mmap call then get a crash and get far from the debugger (or cashlog) and put it here)
#define OFF_LONGJMP realsym(dyld_cache_path,"__longjmp") // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
#define OFF_MMAP realsym(dyld_cache_path,"__mmap") // dlsym of __mmap
#define OFF_MEMCPY realsym(dyld_cache_path,"_memcpy") // dlsym of _memcpy
#define OFF_OPEN realsym(dyld_cache_path,"_open") //dlsym of _open
#define OFF_FCNTL_RAW realsym(dyld_cache_path,"__fcntl") // dlsym of __fcntl
#define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path,"_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075a98cc // search for the string "/private/var/vm/swapfile" in the kernel that's the right address
#endif
// iPhone SE (1st gen) (iPhone8,4), iOS 11.4
#if N69_11_4
#define OFF_KERNEL_IMAGE_BASE 0xfffffff007004000 // static
#define OFF_COPYIN 0xfffffff0071a71cc // symbol
#define OFF_COPYOUT 0xfffffff0071a73f0 // symbol 
#define OFF_CURRENT_TASK 0xfffffff0070f4c4c // symbol
#define OFF_GET_BSDTASK_INFO 0xfffffff00710a348 // symbol 
#define OFF_VM_MAP_WIRE_EXTERNAL 0xfffffff007153574 // symbol
#define OFF_VFS_CONTEXT_CURRENT 0xfffffff0071f9bcc // symbol
#define OFF_VNODE_LOOKUP 0xfffffff0071db8d8 // symbol
#define OFF_OSUNSERIALIZEXML 0xfffffff0074e2a58 // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
#define OFF_PROC_FIND 0xfffffff0073f3b68 // symbol
#define OFF_PROC_RELE 0xfffffff0073f3ad8 // symbol 
#define OFF_SMALLOC 0xfffffff006b57cb0 // found by searching for "sandbox memory allocation failure" 
#define OFF_IPC_PORT_ALLOC_SPECIAL 0xfffffff0070b915c // \"ipc_processor_init\" in processor_start -> call above
#define OFF_IPC_KOBJECT_SET 0xfffffff0070cf30c // above _mach_msg_send_from_kernel_proper
#define OFF_IPC_PORT_MAKE_SEND 0xfffffff0070b88d8 // first call in long path of KUNCUserNotificationDisplayFromBundle
#define OFF_ADD_X0_X0_RET 0xfffffff0073c9c58 // gadget (or _csblob_get_cdhash)
#define OFF_KERNEL_TASK 0xfffffff0075d9048 // symbol 
#define OFF_KERN_PROC 0xfffffff0075d90a0 // symbol (kernproc)
#define OFF_ROOTVNODE 0xfffffff0075d9088 // symbol 
#define OFF_REALHOST 0xfffffff0075deb98 // _host_priv_self -> adrp addr
#define OFF_ZONE_MAP 0xfffffff0075fbe50 // str 'zone_init: kmem_suballoc failed', first qword above 
#define OFF_OSBOOLEAN_TRUE 0xfffffff007648428 // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
#define OFF_TRUST_CACHE 0xfffffff0076b4ee8 // %s: trust cache loaded successfully.\n store above
#define OFF_IOSURFACE_ROOT_USERCLIENT 0xfffffff006e88e50 // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
#define OFF_IS_TASK 0x28
#define OFF_TASK_ITK_SELF 0xd8
#define OFF_ITK_REGISTERED 0x2f0
#define OFF_IPR_SIZE 0x8 // ipc_port_request->name->size
#define OFF_SIZEOF_TASK 0x5c8 // size of entire task struct
#define OFF_PROC_TASK 0x18 // proc->task
#define OFF_PROC_P_CSFLAGS 0x2a8 // proc->p_csflags (_cs_restricted, first ldr offset)
#define OFF_TASK_T_FLAGS 0x3a0 // task->t_flags
#define OFF_TASK_ALL_IMAGE_INFO_ADDR 0x3a8 // task->all_image_info_addr (theoretically just +0x8 from t_flags)
#define OFF_TASK_ALL_IMAGE_INFO_SIZE 0x3b0 // task->all_image_info_size
#define OFF_CREATE_OUTSIZE 0xbc8
#define OFF_CREATE_SURFACE 0
#define OFF_SET_VALUE 9

#define OFF_DNS4_ARRAY_TO_LCCONF -((0x100067c10+0x28-4*8)-0x1000670e0 // -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr())
#define OFF_STR_BUFF 8 // VERIFY! based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
#define OFF_MAX_SLIDE 0x4678000 // just get 8 bytes at offset 30 from the cache
#define OFF_SLIDE_VALUE 0x4000  // hardcode that one
#define OFF_PIVOT_X21 0x199c4b93c // I hope this doesn't change on any version but we need to find the same gadget on all version (gadget and byte seqeunce can be found in stage1.m)
#define OFF_PIVOT_X21_X9 0x50-0x38 // VERIFY! this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
#define OFF_MEMMOVE 0x1ab7b0d50 // strlcpy second branch
#define OFF_LCCONF_COUNTER 0x10c // we could try and find that dynamically or we could just hardcode it cause it prob doesn't change on 11.x (TODO: get that dynamically) (this is the offset of the counter variable in the lcconfig struct we use as a write what where primitive. It's used in some sub in racoon but it's hard to patchfind dynamically and as it doesn't change I just hardcoded it)
#define OFF_CACHE_TEXT_SEG_SIZE 0x30000000 // we can get that by parsing the segments from the cache (but this is always enough)
#define OFF_NEW_CACHE_ADDR 0x1c0000000 // you might want to change this because it might not work on the 5S but it should be fine for us
#define OFF_BEAST_GADGET 0x1a16e6494 // we can find that because it's part of a function and shouldn't change but it's basically also just byte matching cause if it would change the load order the whole framework would stop loading
#define OFF_STR_X0_GADGET 0x197e1eac8 // search for the byte sequence again (gadget in rop.h)
#define OFF_STR_X0_GADGET_OFF 0x28 // VERIFY! based on the gadget above (at which offset it stores x0 basically)
#define OFF_CBZ_X0_GADGET 0x188d340bc // search for the byte sequence (gadget in rop.h)
#define OFF_CBZ_X0_X16_LOAD 0x1b1d72000+0x4c8 // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
#define OFF_ADD_X0_GADGET 0x18519cb90 // raw byte search again (gadget is in rop.h)
#define OFF_ERRNO 0x1f3263000+0xff8 // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
#define OFF_MACH_MSG 0x1f1896018 // VERIFY! don't know what this causes we need to figure it out later (basically I will mmap this address at the start of stage 2 otherwise it will at some point randomly crash in the mach_msg syscall. I don't have a good way to patchfinding this yet but as soon as you have a debugger setup you can generate stage 2 without the mmap call then get a crash and get far from the debugger (or cashlog) and put it here)
#define OFF_LONGJMP realsym(dyld_cache_path,"__longjmp") // dlsym of __longjmp
#define OFF_STACK_PIVOT 0x180b12714 // longjmp from mov x2, sp
#define OFF_MMAP realsym(dyld_cache_path,"__mmap") // dlsym of __mmap
#define OFF_MEMCPY realsym(dyld_cache_path,"_memcpy") // dlsym of _memcpy
#define OFF_OPEN realsym(dyld_cache_path,"_open") //dlsym of _open
#define OFF_FCNTL_RAW realsym(dyld_cache_path,"__fcntl") // dlsym of __fcntl
#define OFF_RAW_MACH_VM_REMAP realsym(dyld_cache_path,"_mach_vm_remap") // dlsym of _mach_vm_remap
#define OFF_ROOTDOMAINUC_VTAB 0xfffffff00708e158 // find __ZTV20RootDomainUserClient in kernel
#define OFF_SWAPPREFIX_ADDR 0xfffffff0075ad8cc // search for the string "/private/var/vm/swapfile" in the kernel that's the right address

#endif

#endif