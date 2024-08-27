#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mount.h>
#include <sys/snapshot.h>
#include <sys/stat.h>
#include <unistd.h>

#include "iokit.h"
#include "jailbreak.h"
#include "kcall.h"
#include "kents.h"
#include "kmem.h"
#include "kutils.h"
#include "utils.h"

// Kernel.framework -> hfs/hfs_mount.h
struct hfs_mount_args {
    char* fspec; /* block special device to mount */
    uid_t hfs_uid; /* uid that owns hfs files (standard HFS only) */
    gid_t hfs_gid; /* gid that owns hfs files (standard HFS only) */
    mode_t hfs_mask; /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t hfs_encoding; /* encoding for this volume (standard HFS only) */
    struct timezone hfs_timezone; /* user time zone info (standard HFS only) */
    int flags; /* mounting flags, see below */
    int journal_tbuffer_size; /* size in bytes of the journal transaction buffer */
    int journal_flags; /* flags to pass to journal_open/create */
    int journal_disable; /* don't use journaling (potentially dangerous) */
};

typedef struct val_attrs {
    uint32_t length;
    attribute_set_t returned;
    attrreference_t name_info;
} val_attrs_t;

#define RB_QUICK 0x400 // quick and ungraceful reboot with file system caches flushed

// creds https://github.com/sbingner/snappy/blob/master/snappy.m#L90
int snapshot_count(const char* path)
{
    int dirfd = open(path, O_RDONLY);

    struct attrlist attr_list = { 0 };
    int total = 0;

    attr_list.commonattr = ATTR_BULK_REQUIRED;

    char* buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    while ((retcount = fs_snapshot_list(dirfd, &attr_list, buf, 2048, 0)) > 0) {
        total += retcount;
        char* bufref = buf;

        for (int i = 0; i < retcount; i++) {
            val_attrs_t* entry = (val_attrs_t*)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                LOG("found snap: %s", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
            }
            bufref += entry->length;
        }
    }
    free(buf);

    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }

    return total;
}

int snapshot_rename(const char* path, const char* from, const char* to)
{
    int ret = 0;

    int fd = open(path, O_RDONLY);

    ret = fs_snapshot_rename(fd, from, to, 0);

    close(fd);

    return ret;
}

const char* get_root_snapshot_name(const char* path)
{
    int dirfd = open(path, O_RDONLY);

    struct attrlist attr_list = { 0 };
    int total = 0;

    attr_list.commonattr = ATTR_BULK_REQUIRED;

    char* buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    while ((retcount = fs_snapshot_list(dirfd, &attr_list, buf, 2048, 0)) > 0) {
        total += retcount;
        char* bufref = buf;

        for (int i = 0; i < retcount; i++) {
            val_attrs_t* entry = (val_attrs_t*)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                const char* snap_name = (char*)(&entry->name_info) + entry->name_info.attr_dataoffset;
                if (strncmp(snap_name, "com.apple.os.update-", strlen("com.apple.os.update-")) == 0) {
                    return strdup(snap_name);
                }
            }

            bufref += entry->length;
        }
    }

    free(buf);

    return NULL;
}

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

uint64_t vnode_from_path(const char* dev_path)
{
    LOG("finding vnode: %s", dev_path);

    uint64_t vfs_context_current = zm_fix_addr(kexecute(offs.funcs.vfs_context_current, 0));
    LOG("vfs_context_current: %llx", vfs_context_current);

    uint64_t kstr_buf = kalloc(strlen(dev_path) + 1);
    kwrite(kstr_buf, (void*)dev_path, (uint32_t)strlen(dev_path) + 1);

    // note to self: have to use vnode_lookup as you can't
    // get an fd on /dev/disk0s1s1 to pass to vnode_getfromfd
    uint64_t vnode_ptr = kalloc(sizeof(uint64_t));
    kexecute(offs.funcs.vnode_lookup, 4, kstr_buf, 0, vnode_ptr, vfs_context_current);
    uint64_t vnode = rk64(vnode_ptr);
    LOG("got vnode: %llx", vnode);

    kfree(kstr_buf, strlen(dev_path) + 1);
    kfree(vnode_ptr, sizeof(uint64_t));

    if (vnode == 0x0) {
        LOG("failed to get vnode for %s", dev_path);
        return KERN_FAILURE;
    }

    return vnode;
}

kern_return_t patch_device_vnode(const char* dev_path)
{
    LOG("patching vnode for: %s", dev_path);
    uint64_t vnode = vnode_from_path(dev_path);
    if (vnode == 0x0) {
        LOG("failed to patch vnode");
        return KERN_FAILURE;
    }

    // we must 0 this else mount will return 'resource busy'
    uint64_t spec_info = rk64(vnode + 0x78);
    wk32(spec_info + 0x10, 0); // zero our spec_flags

    return KERN_SUCCESS;
}

kern_return_t dunk_on_mac_mount()
{
    kern_return_t ret = 0;

    uint64_t rootfs_vnode = rk64(offs.data.rootvnode + kernel_slide);
    if (rootfs_vnode == 0x0) {
        LOG("failed to find rootfs vnode");
        return KERN_FAILURE;
    }

    uint64_t v_mount = rk64(rootfs_vnode + 0xd8);
    if (v_mount == 0x0) {
        LOG("failed to find v_mount");
        return KERN_FAILURE;
    }

    uint32_t v_flag = rk32(v_mount + 0x70);
    if (v_flag == 0x0) {
        LOG("failed to find v_flag");
        return KERN_FAILURE;
    }

    // unset rootfs flag
    wk32(v_mount + 0x70, v_flag & ~MNT_ROOTFS);

    // remount
    char* name = strdup("/dev/disk0s1s1");
    ret = mount("apfs", "/", MNT_UPDATE, &name);
    LOG("mount ret: %d", ret);

    // read back new flags
    v_mount = rk64(rootfs_vnode + 0xd8);
    v_flag = rk32(v_mount + 0x70);

    // set rootfs flag back & unset nosuid
    v_flag = v_flag | MNT_ROOTFS;
    v_flag = v_flag & ~MNT_NOSUID;
    LOG("new v_flag: %x", v_flag);

    // set new flags
    wk32(v_mount + 0x70, v_flag);

    return ret;
}

kern_return_t remount_root_fs()
{
    kern_return_t ret = KERN_SUCCESS;

    int snap_count = snapshot_count("/");
    LOG("snap_count: %d", snap_count);

    // if the device *is* a snapshot, we won't be able to count them
    if (snap_count <= -1) {
        // rename the snapshot and say bye bye

        // mount the actual device to /var/tmp/rootfs
        if (access("/var/tmp/roofs", F_OK) != 0) {
            mkdir("/var/tmp/rootfs", 0755);

            if (access("/var/tmp/rootfs", F_OK) != 0) {
                LOG("failed to create /var/tmprootfs dir!");
                return KERN_FAILURE;
            }
        }

        ret = patch_device_vnode("/dev/disk0s1s1");
        if (ret != KERN_SUCCESS)
            return ret;

        struct hfs_mount_args mnt_args;
        bzero(&mnt_args, sizeof(mnt_args));
        mnt_args.fspec = "/dev/disk0s1s1";
        mnt_args.hfs_mask = 1;
        gettimeofday(NULL, &mnt_args.hfs_timezone);

        // find credz
        uint64_t our_proc = find_proc(getpid());
        uint64_t our_ucred = rk64(our_proc + 0x100);
        uint64_t kern_ucred = rk64(find_proc(0) + 0x100);

        // set kern ucred (bypass perm. check)
        wk64(our_proc + 0x100, kern_ucred);

        ret = mount("apfs", "/var/tmp/rootfs", 0, &mnt_args);
        if (ret != 0) {
            printf("failed to call mount: %d (%d - %s)\n", ret, errno, strerror(errno));
            return KERN_FAILURE;
        }

        printf("before rename:\n");
        snapshot_count("/var/tmp/rootfs");

        // grab private ents to allow spelunking with apfs
        const char* current_ents = get_current_entitlements(getpid());
        if (current_ents == NULL) {
            printf("failed to get current entitlements!\n");
            return KERN_FAILURE;
        }

        ret = assign_new_entitlements(getpid(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
            "<plist version=\"1.0\">"
            "<dict>"
            "<key>com.apple.private.apfs.revert-to-snapshot</key>"
            "<true/>"
            "<key>com.apple.private.security.disk-device-access</key>"
            "<true/>"
            "<key>com.apple.private.vfs.snapshot</key>"
            "<true/>"
            "</dict>"
            "</plist>");
        if (ret != 0) {
            printf("failed to assign new entitlements!\n");
            return KERN_FAILURE;
        }

        const char* root_snapshot = get_root_snapshot_name("/var/tmp/rootfs");

        if (root_snapshot == NULL) {
            printf("failed to find root snapshot\n");
            return KERN_FAILURE;
        }

        ret = snapshot_rename("/var/tmp/rootfs", root_snapshot, "original_rootfs");

        // restore creds
        wk64(our_proc + 0x100, our_ucred);

        if (ret != 0) {
            printf("failed to rename snapshot from %s to original_rootfs: %d (%d - %s)\n", root_snapshot, ret, errno, strerror(errno));
            return KERN_FAILURE;
        }

        free((void*)root_snapshot);

        printf("after rename:\n");
        snapshot_count("/var/tmp/rootfs");

        // restore ents
        assign_new_entitlements(getpid(), current_ents);
        free((void*)current_ents);

        // now reboot
        // TODO: improve this
        LOG("going down for reboot after renaming...");
        sleep(3);

        // note to self: 0x400 causes hard reboot w/o flushin any fs shit
        // without this, snapshot rename won't come into place
        reboot(RB_QUICK);

        return KERN_SUCCESS;
    }

    return dunk_on_mac_mount();
}

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
#define OFFSET_PROC_P_UCRED 0x100
#define SPICE_MOUNT_POINT "/var/tmp/rootfs"
#define SPICE_MOUNT_APPLICATIONS @"/var/tmp/rootfs/Applications"

kern_return_t restore_root_fs()
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
    LOG("Restore successful. Reboot is required.");
    reboot(0);

    return KERN_SUCCESS;

fail:
    // Restore creds
    wk64(our_proc + OFFSET_PROC_P_UCRED, our_ucred);

    return KERN_FAILURE;
}
#endif
