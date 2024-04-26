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
        	.add_x0_x0_ret = sym("_csblob_get_cdhash"), // gadget 
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
offsets_t offs = (offsets_t){
    .constant = {
        .kernel_image_base = 0x80001000, // static
    },
    .funcs = {
        .copyin = 0x80007b9c, // symbol
        .copyout = 0x80007c74, // symbol 
        .current_task = 0x8004bd9c, // symbol
        .get_bsdtask_info = 0x8005c8c2, // symbol 
        .vm_map_wire_external = 0x80091b16, // symbol
        .vfs_context_current = 0x8011307e, // symbol
        .vnode_lookup = 0x800fe61c, // symbol
        .osunserializexml = 0x8030a478, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0x8027cfbe, // symbol
        .proc_rele = 0x8027cf52, // symbol 
        .smalloc = 0x80fbf410, // found by searching for "sandbox memory allocation failure"
        .ipc_port_alloc_special = 0x80019034, // \"ipc_processor_init\" in processor_start -> call above
        .ipc_kobject_set = 0x800290b6, // above _mach_msg_send_from_kernel_proper (2nd above for 10.3.4)
        .ipc_port_make_send = 0x80018c54, // first call in long path of KUNCUserNotificationDisplayFromBundle
    },
    .gadgets = {    
        .add_x0_x0_ret = 0x8025f6bc, // gadget (or _csblob_get_cdhash)
    },
    .data = {
        .kernel_task = 0x80456030, // symbol 
        .kern_proc = 0x80456144, // symbol (kernproc)
        .rootvnode = 0x80456138, // symbol 
        .realhost = 0x80404150, // _host_priv_self -> adrp addr
        .zone_map = 0x804188e0, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0x80453fa0, // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
        .trust_cache = 0x8089c44, // (on iOS 10.3.4, use "%s: trust cache already loaded with matching UUID, ignoring\n", store below call to _lck_mtx_lock in same function) "%s: trust cache loaded successfully.\n" store above
    },
    .vtabs = {
        .iosurface_root_userclient = 0x8066bba8, // (on iOS 10.3.4, search "IOSurfaceRootUserClient", store in function below first reference) 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
    	//.is_task_offset = 0x28,
        .task_itk_self = 0x9c, // first reference of ipc_task_reset, offset after _lck_mtx_lock
        //.itk_registered = 0x2f0,
        //.ipr_size = 0x8, // ipc_port_request->name->size
        //.sizeof_task = 0x5c8, // size of entire task struct
        //.proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x1b8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x248, // task->t_flags (IOUserClient::clientHasPrivilege, function call after current_task)
        .task_all_image_info_addr = 0x250, // ("created task is not a member of a resource coalition", search 0x5f) task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x258,  // ("created task is not a member of a resource coalition", search 0x5f) task->all_image_info_size
    },
    .iosurface = {
        //.create_outsize = 0xbc8, 
        .create_surface = 0, // static, IOSurfaceCreate is method 0 of IOSurfaceRootUserClient
        .set_value = 9, // static, IOSurfaceSetValue is method 9 of IOSurfaceRootUserClient
    },
};
#endif
// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.2.1
#if J96_11_2_1
offsets_t offs = (offsets_t){
    .constant = {
        .kernel_image_base = 0xfffffff007004000, // static
    },
    .funcs = {
        .copyin = 0xfffffff00719e88c, // symbol
        .copyout = 0xfffffff00719eab0, // symbol 
        .current_task = 0xfffffff0070e8c0c, // symbol
        .get_bsdtask_info = 0xfffffff0070fe7ec, // symbol 
        .vm_map_wire_external = 0xfffffff007148fe8, // symbol
        .vfs_context_current = 0xfffffff0071f2310, // symbol
        .vnode_lookup = 0xfffffff0071d3f90, // symbol
        .osunserializexml = 0xfffffff0074dd7e4, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0xfffffff0073ed31c, // symbol
        .proc_rele = 0xfffffff0073ed28c, // symbol 

        .smalloc = 0xfffffff006822cb0,
        .ipc_port_alloc_special = 0xfffffff0070ad1a8,
        .ipc_kobject_set = 0xfffffff0070c3148,
        .ipc_port_make_send = 0xfffffff0070ac924,
    },
    .gadgets = {
        .add_x0_x0_ret = 0xfffffff0063fddbc, // gadget 
    },
    .data = {
        .kernel_task = 0xfffffff0075d1048, // symbol 
        .kern_proc = 0xfffffff0075d10a0, // symbol (kernproc)
        .rootvnode = 0xfffffff0075d1088, // symbol 

        .realhost = 0xfffffff0075d6b98, // _host_priv_self -> adrp addr
        .zone_map = 0xfffffff0075f3e50, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0xfffffff007640468, // OSBoolean::withBoolean -> first adrp addr
        .trust_cache = 0xfffffff0076ab828,
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006e73590, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xd8,
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8, // size of entire task struct
        .proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x3a0, // task->t_flags
        .task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x3b0,  // task->all_image_info_size
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
};
#endif
// iPad mini 4 (Wi-Fi) (iPad5,1), iOS 11.3.1
#if J96_11_3_1
offsets_t offs = (offsets_t){
    .constant = {
        .kernel_image_base = 0xfffffff007004000, // static
    },
    .funcs = {
        .copyin = 0xfffffff0071aa804, // symbol
        .copyout = 0xfffffff0071aaa28, // symbol 
        .current_task = 0xfffffff0070f4d80, // symbol
        .get_bsdtask_info = 0xfffffff00710a960, // symbol 
        .vm_map_wire_external = 0xfffffff007154fb8, // symbol
        .vfs_context_current = 0xfffffff0071fe2f0, // symbol
        .vnode_lookup = 0xfffffff0071dff70, // symbol
        .osunserializexml = 0xfffffff0074e8f38, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0xfffffff0073f8ba4, // symbol
        .proc_rele = 0xfffffff0073f8b14, // symbol 

        .smalloc = 0xfffffff006b1acb0, // isn't used anywhere
        .ipc_port_alloc_special = 0xfffffff0070b9328,
        .ipc_kobject_set = 0xfffffff0070cf2c8,
        .ipc_port_make_send = 0xfffffff0070b8aa4,
    },
    .gadgets = {
        .add_x0_x0_ret = 0xfffffff0073ce75c, // gadget 
    },
    .data = {
        .kernel_task = 0xfffffff0075dd048, // symbol 
        .kern_proc = 0xfffffff0075dd0a0, // symbol (kernproc)
        .rootvnode = 0xfffffff0075dd088, // symbol 

        .realhost = 0xfffffff0075e2b98, // _host_priv_self -> adrp addr
        .zone_map = 0xfffffff0075ffe50, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0xfffffff00764c468, // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
        .trust_cache = 0xfffffff0076b8ee8,
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006eb8e10, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xd8,
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8, // size of entire task struct
        .proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x3a0, // task->t_flags
        .task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x3b0,  // task->all_image_info_size
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
};
#endif
// iPhone SE (1st gen) (iPhone8,4), iOS 11.3
#if N69_11_3
offsets_t offs = (offsets_t){
    .constant = {
        .kernel_image_base = 0xfffffff007004000, // static
    },
    .funcs = {
        .copyin = 0xFFFFFFF0071A7090, // symbol
        .copyout = 0xFFFFFFF0071A72B4, // symbol 
        .current_task = 0xFFFFFFF0070F76C4, // symbol
        .get_bsdtask_info = 0xFFFFFFF00710CDC0, // symbol 
        .vm_map_wire_external = 0xFFFFFFF007153484, // symbol
        .vfs_context_current = 0xFFFFFFF0071F9A04, // symbol
        .vnode_lookup = 0xFFFFFFF0071DB710, // symbol
        .osunserializexml = 0xFFFFFFF0074E2404, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0xFFFFFFF0073F35B8 , // symbol
        .proc_rele = 0xFFFFFFF0073F3528, // symbol 

        .smalloc = 0xFFFFFFF006B5ECB0, // found by searching for "sandbox memory allocation failure"
        .ipc_port_alloc_special = 0xFFFFFFF0070B915C, // \"ipc_processor_init\" in processor_start -> call above
        .ipc_kobject_set = 0xFFFFFFF0070CF30C, // above _mach_msg_send_from_kernel_proper
        .ipc_port_make_send = 0xFFFFFFF0070B88D8, // first call in long path of KUNCUserNotificationDisplayFromBundle
    },
    .gadgets = {
        .add_x0_x0_ret = 0xFFFFFFF0073C96A8, // gadget (or _csblob_get_cdhash)
    },
    .data = {
        .kernel_task = 0xFFFFFFF0075D5048, // symbol 
        .kern_proc = 0xFFFFFFF0075D50A0, // symbol (kernproc)
        .rootvnode = 0xFFFFFFF0075D5088, // symbol 

        .realhost = 0xFFFFFFF0075DAB98, // _host_priv_self -> adrp addr
        .zone_map = 0xFFFFFFF0075F7E50, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0xFFFFFFF007644418, // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
        .trust_cache = 0xFFFFFFF0076B0EE8, // %s: trust cache loaded successfully.\n store above
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006e88c50, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xe0, // first reference of ipc_task_reset, offset after _lck_mtx_lock
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8, // size of entire task struct
        .proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x3a0, // task->t_flags
        .task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x3b0,  // task->all_image_info_size
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
};
#endif
// iPhone SE (1st gen) (iPhone8,4), iOS 11.4
#if N69_11_4
offsets_t offs = (offsets_t){
    .constant = {
        .kernel_image_base = 0xfffffff007004000, // static
    },
    .funcs = {
        .copyin = 0xFFFFFFF0071A71CC, // symbol
        .copyout = 0xFFFFFFF0071A73F0, // symbol 
        .current_task = 0xFFFFFFF0070F4C4C, // symbol
        .get_bsdtask_info = 0xFFFFFFF00710A348, // symbol 
        .vm_map_wire_external = 0xFFFFFFF007153574, // symbol
        .vfs_context_current = 0xFFFFFFF0071F9BCC, // symbol
        .vnode_lookup = 0xFFFFFFF0071DB8D8, // symbol
        .osunserializexml = 0xFFFFFFF0074E2A58, // symbol (__Z16OSUnserializeXMLPKcPP8OSString)
        .proc_find = 0xFFFFFFF0073F3B68, // symbol
        .proc_rele = 0xFFFFFFF0073F3AD8, // symbol 

        .smalloc = 0xFFFFFFF006B57CB0, // found by searching for "sandbox memory allocation failure" 
        .ipc_port_alloc_special = 0xFFFFFFF0070B915C, // \"ipc_processor_init\" in processor_start -> call above
        .ipc_kobject_set = 0xFFFFFFF0070CF30C, // above _mach_msg_send_from_kernel_proper
        .ipc_port_make_send = 0xFFFFFFF0070B88D8, // first call in long path of KUNCUserNotificationDisplayFromBundle
    },
    .gadgets = {
        .add_x0_x0_ret = 0xFFFFFFF0073C9C58, // gadget (or _csblob_get_cdhash)
    },
    .data = {
        .kernel_task = 0xFFFFFFF0075D9048, // symbol 
        .kern_proc = 0xFFFFFFF0075D90A0, // symbol (kernproc)
        .rootvnode = 0xFFFFFFF0075D9088, // symbol 

        .realhost = 0xFFFFFFF0075DEB98, // _host_priv_self -> adrp addr
        .zone_map = 0xFFFFFFF0075FBE50, // str 'zone_init: kmem_suballoc failed', first qword above 
        .osboolean_true = 0xFFFFFFF007648428, // OSBoolean::withBoolean -> first adrp addr (isn't used anywhere tho)
        .trust_cache = 0xFFFFFFF0076B4EE8, // %s: trust cache loaded successfully.\n store above
    },
    .vtabs = {
        .iosurface_root_userclient = 0xfffffff006e88e50, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    },
    .struct_offsets = {
        .is_task_offset = 0x28,
        .task_itk_self = 0xd8,
        .itk_registered = 0x2f0,
        .ipr_size = 0x8, // ipc_port_request->name->size
        .sizeof_task = 0x5c8, // size of entire task struct
        .proc_task = 0x18, // proc->task
        .proc_p_csflags = 0x2a8, // proc->p_csflags (_cs_restricted, first ldr offset)
        .task_t_flags = 0x3a0, // task->t_flags
        .task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        .task_all_image_info_size = 0x3b0,  // task->all_image_info_size
    },
    .iosurface = {
        .create_outsize = 0xbc8,
        .create_surface = 0,
        .set_value = 9,
    },
};
#endif

#endif