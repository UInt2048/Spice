#ifndef ROOT_FS_H
#define ROOT_FS_H

int snapshot_count(const char *path);
int mount_unionfs(const char *dmg_path);
kern_return_t remount_root_fs(void);
kern_return_t restore_root_fs(void);

#endif
