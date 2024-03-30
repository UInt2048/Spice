#import "CreditsVC.h"

// Copied from <shared/jailbreak.m>, don't actually do this
#import <shared/common.h>
#include <untether/uland_offsetfinder.h>
#include "patchfinder.h"
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
        	.vm_map_wire_external = sym("vm_map_wire_external"), // symbol
        	.vfs_context_current = sym("vfs_context_current"), // symbol
        	.vnode_lookup = sym("_vnode_lookup"), // symbol
        	.osunserializexml = sym("__Z16OSUnserializeXMLPKcPP8OSString"), // symbol
        	.proc_find = sym("_proc_find"), // symbol
        	.proc_rele = sym("_proc_rele"), // symbol 

        	.smalloc = 0xfffffff006b1acb0,
        	.ipc_port_alloc_special = 0xfffffff0070b9328,
        	.ipc_kobject_set = 0xfffffff0070cf2c8,
        	.ipc_port_make_send = 0xfffffff0070b8aa4,
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
        	.osboolean_true = 0, // OSBoolean::withBoolean -> first adrp addr
        	.trust_cache = find_trustcache(kernel_symbols), // duplicate of trust_chain_head_ptr?
    	},
    	.vtabs = {
        	.iosurface_root_userclient = 0, // 'iometa -Csov IOSurfaceRootUserClient kernel', vtab=...
    	},
    	.struct_offsets = {
        	.is_task_offset = 0x28, // duplicate
        	.task_itk_self = 0xd8,
        	.itk_registered = 0x2f0, // duplicate
        	.ipr_size = 8, // duplicate, ipc_port_request->name->size
        	.sizeof_task = 0x5c8, // size of entire task struct
        	.proc_task = 0, // proc->task
        	.proc_p_csflags = 0, // proc->p_csflags (_cs_restricted, first ldr offset)
        	.task_t_flags = 0x3a0, // task->t_flags, not set in untether version
        	.task_all_image_info_addr = 0x3a8, // task->all_image_info_addr (theoretically just +0x8 from t_flags)
        	.task_all_image_info_size = 0x3b0,  // task->all_image_info_size
   		},
    	.iosurface = {
        	.create_outsize = 0,
        	.create_surface = 0,
        	.set_value = 0,
    	},
	};
}

// End copied code

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


#define CONFIG_PATH "etc/racoon/racoon.conf"
#define RACOON_PATH "/usr/sbin/racoon"
#ifdef __LP64__
#define DYLD_CACHE_PATH "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
#else
#define DYLD_CACHE_PATH "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s"
#endif

	offsets_t offs = dynamicOffsets(CONFIG_PATH, RACOON_PATH, DYLD_CACHE_PATH);

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
    is_taskoffset: %x\n\
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
    offs.constant.kernel_image_base,
    offs.funcs.copyin,
    offs.funcs.copyout,
    offs.funcs.current_task,
    offs.funcs.get_bsdtask_info,
    offs.funcs.vm_map_wire_external,
    offs.funcs.vfs_context_current,
    offs.funcs.vnode_lookup,
    offs.funcs.osunserializexml,
    offs.funcs.proc_find,
    offs.funcs.proc_rele,
    offs.funcs.smalloc,
    offs.funcs.ipc_port_alloc_special,
    offs.funcs.ipc_kobject_set,
    offs.funcs.ipc_port_make_send,
    offs.gadgets.add_x0_x0_ret,
    offs.data.kernel_task,
    offs.data.kern_proc,
    offs.data.rootvnode,
    offs.data.realhost,
    offs.data.zone_map,
    offs.data.osboolean_true,
    offs.data.trust_cache,
    offs.vtabs.iosurface_root_userclient,
    offs.struct_offsets.is_task_offset,
    offs.struct_offsets.task_itk_self,
    offs.struct_offsets.itk_registered,
    offs.struct_offsets.ipr_size,
    offs.struct_offsets.sizeof_task,
    offs.struct_offsets.proc_task,
    offs.struct_offsets.proc_p_csflags,
    offs.struct_offsets.task_t_flags,
    offs.struct_offsets.task_all_image_info_addr,
    offs.struct_offsets.task_all_image_info_size,
    offs.iosurface.create_outsize,
    offs.iosurface.create_surface,
    offs.iosurface.set_value
    ];
    [offsetLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    offsetLabel.font = [UIFont systemFontOfSize:14];
	[self.view addSubview:offsetLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:offsetLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:offsetLabel attribute:NSLayoutAttributeBottom relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.7 constant:0.0]];

}

@end
