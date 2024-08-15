#ifndef ROOT_FS_H
#define ROOT_FS_H

int snapshot_count(const char* path);
int mount_unionfs(const char* dmg_path);
int remount_root_fs(void);

#endif
