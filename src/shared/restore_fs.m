// Ripped from https://github.com/Odyssey-Team/Odyssey/blob/9253c774c1c67a943a98f288cd0edb55b892d302/Odyssey/post-exploit/utils/remount.swift#L311-L398

// Copyright 2020, CoolStar. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY COOLSTAR AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifdef __LP64__
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#if __has_include(<sys/snapshot.h>)
#include <sys/snapshot.h>
#else
int fs_snapshot_list(int dirfd, struct attrlist* alist, void* attrbuf, size_t bufsize,
    uint32_t flags);
int fs_snapshot_rename(int dirfd, const char* old, const char* new, uint32_t flags);
#endif

#include "common.h"
#include "iokit.h"
#include "kmem.h"
#include "kutils.h"
#include "root_fs.h"
#include "utils.h"

#import <UIKit/UIKit.h> // alert
#define RB_QUICK 0x400 // quick and ungraceful reboot with file system caches flushed

#define OFFSET_PROC_P_UCRED 0x100
#define SPICE_MOUNT_POINT "/var/tmp/rootfs"
#define SPICE_MOUNT_APPLICATIONS @"/var/tmp/rootfs/Applications"

const char* get_boot_snapshot_name()
{
    io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    CFTypeRef prop = IORegistryEntryCreateCFProperty(chosen, (__bridge CFStringRef) @"boot-manifest-hash", kCFAllocatorDefault, 0);
    IOObjectRelease(chosen);

    if (CFGetTypeID(prop) != CFDataGetTypeID()) {
        LOG("Failed to get boot manifest hash");
        CFRelease(prop);
        return NULL;
    }

    CFIndex len = CFDataGetLength((CFDataRef)prop);
    UInt8 buf[len];
    CFDataGetBytes((CFDataRef)prop, CFRangeMake(0, len), buf);
    CFRelease(prop);

    NSMutableString* name = @"com.apple.os.update-".mutableCopy;
    for (CFIndex i = 0; i < len; ++i) {
        [name appendFormat:@"%02X", buf[i]];
    }

    const char* ret = [name UTF8String];

    LOG("Boot snapshot: %s", ret);

    return ret;
}

kern_return_t restore_root_fs(void* controller)
{
    int snap_count = snapshot_count("/");
    LOG("snap_count: %d", snap_count);

    // if the device *is* a snapshot, we won't be able to count them
    if (snap_count < 0) {
        LOG("RootFS restore not required");
        return KERN_SUCCESS;
    }

    const char* boot_snapshot = get_boot_snapshot_name();
    if (boot_snapshot == NULL) {
        LOG("Boot snapshot not present?");
        return KERN_FAILURE;
    }

    // Remove /var/cache and /var/lib
#define fileMgr [NSFileManager defaultManager]
    [fileMgr removeItemAtPath:@"/var/cache"
                        error:nil];
    [fileMgr removeItemAtPath:@"/var/lib" error:nil];

    // find credz
    uint64_t our_proc = find_proc(getpid());
    uint64_t our_ucred = rk64(our_proc + OFFSET_PROC_P_UCRED);
    uint64_t kern_ucred = rk64(find_proc(0) + OFFSET_PROC_P_UCRED);

    // set kern ucred (bypass perm. check)
    wk64(our_proc + OFFSET_PROC_P_UCRED, kern_ucred);

    mkdir(SPICE_MOUNT_POINT, 0755);
    chown(SPICE_MOUNT_POINT, 0, 0);

    int fd = open("/", O_RDONLY, 0);

    if (fd <= 0) {
        LOG("Failed to get root file descriptor");
        goto fail;
    }

    if (fs_snapshot_rename(fd, "original_rootfs", boot_snapshot, 0) != KERN_SUCCESS) {
        LOG("fs_snapshot_rename failed");
        goto fail;
    }

    if (fs_snapshot_revert(fd, boot_snapshot, 0) != KERN_SUCCESS) {
        LOG("fs_snapshot_revert failed");
        goto fail;
    }

    if (fs_snapshot_mount(fd, SPICE_MOUNT_POINT, boot_snapshot, 0) != KERN_SUCCESS) {
        LOG("fs_snapshot_mount failed");
        goto fail;
    }

    close(fd);

    // Actual restore done, now deregister apps that shouldn't be here
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef resourcesUrl = CFBundleCopyResourcesDirectoryURL(mainBundle);
    int len = 4096;
    char* bundle_path = malloc(len);
    CFURLGetFileSystemRepresentation(resourcesUrl, TRUE, (UInt8*)bundle_path, len);
    LOG("bundle path: %s", bundle_path);

#define COPY_RESOURCE(name, to_path)                                                                                \
    do {                                                                                                            \
        unlink(to_path);                                                                                            \
        [fileMgr copyItemAtPath:[NSString stringWithFormat:@"%s/%s", bundle_path, name] toPath:@to_path error:nil]; \
        chown(to_path, 0, 0);                                                                                       \
        chmod(to_path, 755);                                                                                        \
    } while (0)

#define UICACHE_PATH "/var/containers/Bundle/Application/uicache"

    COPY_RESOURCE("uicache", UICACHE_PATH);

    NSArray* rootApps = [fileMgr contentsOfDirectoryAtPath:@"/Applications" error:nil];

    if (rootApps == nil) {
        rootApps = [NSArray init];
    }

    NSArray* mntApps = [fileMgr contentsOfDirectoryAtPath:SPICE_MOUNT_APPLICATIONS error:nil];

    if (mntApps == nil) {
        mntApps = [NSArray init];
    }

    NSMutableSet* apps = [NSMutableSet setWithArray:rootApps];
    [apps minusSet:[NSMutableSet setWithArray:mntApps]];

    if (apps.count > 0) {
        char* args[2 * apps.count + 2];
        args[0] = UICACHE_PATH;

        size_t i = 0;

        for (NSString* app in apps) {
            LOG("Unregistering %@", app);
            args[++i] = "-u";
            args[++i] = strdup([[NSString stringWithFormat:@"/Applications/%@", app] UTF8String]);
        }

        args[++i] = NULL;

        int status = execprog(UICACHE_PATH, (const char**)args);
        if (status != 0) {
            LOG("posix_spawn failed: %d", status);
        }
    }

    unmount(SPICE_MOUNT_POINT, 0);
    rmdir(SPICE_MOUNT_POINT);
    unlink(UICACHE_PATH);

    // Restore creds
    wk64(our_proc + OFFSET_PROC_P_UCRED, our_ucred);

    // note to self: 0x400 causes hard reboot w/o flushin any fs shit
    // without this, snapshot rename won't come into place
    LOG("Ready to reboot after RootFS");
    UIAlertController* alert = [UIAlertController
        alertControllerWithTitle:@"Restore Complete"
                         message:@"Restore Root FS complete. Reboot to apply changes."
                  preferredStyle:UIAlertControllerStyleAlert];

    UIAlertAction* defaultAction = [UIAlertAction
        actionWithTitle:@"Reboot"
                  style:UIAlertActionStyleDefault
                handler:^(UIAlertAction* action) {
                    if (reboot(RB_QUICK) != 0) {
                        if (reboot(0) != 0) {
                            LOG("Reboot failed, please trigger manually");
                            abort();
                        }
                    }
                }];

    [alert addAction:defaultAction];
    [(UIViewController*)(controller) presentViewController:alert animated:YES completion:nil];

    return KERN_SUCCESS;

fail:
    // Restore creds
    wk64(our_proc + OFFSET_PROC_P_UCRED, our_ucred);

    return KERN_FAILURE;
}
#endif
