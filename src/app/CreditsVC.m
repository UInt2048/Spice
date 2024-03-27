#import "CreditsVC.h"
#import <shared/common.h>

UILabel *creditLabel;
UILabel *offsetLabel;

@implementation CreditsVC

- (id)init
{
    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Credits" image:nil tag:1];
    return ret;
}

- (void)viewWillAppear:(BOOL)animated
{
	[super viewWillAppear:animated];
    CAGradientLayer *gradient = [CAGradientLayer layer];
	gradient.frame = self.view.bounds;
	gradient.colors = @[(id)[UIColor colorWithRed:92.0/255.0 green:201.0/255.0 blue:59.0/255.0 alpha:1.0].CGColor,
		(id)[UIColor colorWithRed:42.0/255.0 green:100.0/255.0 blue:25.0/255.0 alpha:1.0].CGColor];
	[self.view.layer insertSublayer:gradient atIndex:0];
}

// Copied from <shared/jailbreak.m>, don't actually do this
#if 0
offsets_t _offs = (offsets_t){
    #ifdef __LP64__
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
    #endif
};
#else
offsets_t _offs = (offsets_t){
    #ifdef __LP64__
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
    #endif
};
#endif

- (void)loadView
{
    [super loadView];
    
    CAGradientLayer *gradient = [CAGradientLayer layer];
	gradient.frame = self.view.bounds;
	gradient.colors = @[(id)[UIColor colorWithRed:92.0/255.0 green:201.0/255.0 blue:59.0/255.0 alpha:1.0].CGColor,
		(id)[UIColor colorWithRed:42.0/255.0 green:100.0/255.0 blue:25.0/255.0 alpha:1.0].CGColor];
	[self.view.layer insertSublayer:gradient atIndex:0];
    
    creditLabel = [UILabel new];
    creditLabel.translatesAutoresizingMaskIntoConstraints = NO;
    creditLabel.numberOfLines = 0;
    creditLabel.text = @"Credit to @s1guza, @stek29, @sparkey, @littlelailo\nfor creating the untether\nCredit to @UInt2048 for fixing the UI and offsets";
    [creditLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    creditLabel.font = [UIFont systemFontOfSize:14];
    
    [self.view addSubview:creditLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:creditLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:creditLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.7 constant:0.0]];


	offsetLabel = [UILabel new];
    offsetLabel.translatesAutoresizingMaskIntoConstraints = NO;
    offsetLabel.numberOfLines = 0;
    offsetLabel.text = [NSString stringWithFormat:@"\
    kernel_image_base: %x\n\
    copyin: %x\n\
    copyout: %x\n\
    current_task: %x\n\
    get_bsdtask_info: %x\n\
    vm_map_wire_external: %x\n\
    vfs_context_current: %x\n\
    vnode_lookup: %x\n\
    osunserializexml: %x\n\
    proc_find: %x\n\
    proc_rele: %x\n\
    smalloc: %x\n\
    ipc_port_alloc_special: %x\n\
    ipc_kobject_set: %x\n\
    ipc_port_make_send: %x\n\
    add_x0_x0_ret: %x\n\
    kernel_task: %x\n\
    kern_proc: %x\n\
    rootvnode: %x\n\
    realhost: %x\n\
    zone_map: %x\n\
    osboolean_true: %x\n\
    trust_cache: %x\n\
    iosurface_root_userclient: %x\n\
    is_task_offset: %x\n\
    task_itk_self: %x\n\
    itk_registered: %x\n\
    ipr_size: %x\n\
    sizeof_task: %x\n\
    proc_task: %x\n\
    proc_p_csflags: %x\n\
    task_t_flags: %x\n\
    task_all_image_info_addr: %x\n\
    task_all_image_info_size: %x\n\
    create_outsize: %x\n\
    create_surface: %x\n\
    set_value: %x\n\
    ",
    _offs.constant.kernel_image_base,
    _offs.funcs.copyin,
    _offs.funcs.copyout,
    _offs.funcs.current_task,
    _offs.funcs.get_bsdtask_info,
    _offs.funcs.vm_map_wire_external,
    _offs.funcs.vfs_context_current,
    _offs.funcs.vnode_lookup,
    _offs.funcs.osunserializexml,
    _offs.funcs.proc_find,
    _offs.funcs.proc_rele,
    _offs.funcs.smalloc,
    _offs.funcs.ipc_port_alloc_special,
    _offs.funcs.ipc_kobject_set,
    _offs.funcs.ipc_port_make_send,
    _offs.gadgets.add_x0_x0_ret,
    _offs.data.kernel_task,
    _offs.data.kern_proc,
    _offs.data.rootvnode,
    _offs.data.realhost,
    _offs.data.zone_map,
    _offs.data.osboolean_true,
    _offs.data.trust_cache,
    _offs.vtabs.iosurface_root_userclient,
    _offs.struct_offsets.is_task_offset,
    _offs.struct_offsets.task_itk_self,
    _offs.struct_offsets.itk_registered,
    _offs.struct_offsets.ipr_size,
    _offs.struct_offsets.sizeof_task,
    _offs.struct_offsets.proc_task,
    _offs.struct_offsets.proc_p_csflags,
    _offs.struct_offsets.task_t_flags,
    _offs.struct_offsets.task_all_image_info_addr,
    _offs.struct_offsets.task_all_image_info_size,
    _offs.iosurface.create_outsize,
    _offs.iosurface.create_surface,
    _offs.iosurface.set_value
    ];
    [offsetLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    offsetLabel.font = [UIFont systemFontOfSize:14];
	[self.view addSubview:offsetLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:offsetLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:offsetLabel attribute:NSLayoutAttributeBottom relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.7 constant:0.0]];

}

@end
