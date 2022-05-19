#ifndef FS_FAT32_H_
#define FS_FAT32_H_

#include <fs/fs.h>

#include <drivers/sdhc.h>

#define BPB_SECTOR      0
#define BPB_BytsPerSec 11
#define BPB_SecPerClus 13
#define BPB_RsvdSecCnt 14
#define BPB_RootEntCnt 17
#define BPB_NumFATs    16
#define BPB_FATSz32    36
#define BPB_RootClus   44

//end of cluster marker
#define EOC            0x0ffffff8
#define BAD_CLUSTER    0x0ffffff7

typedef void *fat32_handle_t;
typedef void *fat32_mount_t;

typedef uint32_t FAT_Entry;

errval_t fat32_open(void *st, const char *path, fat32_handle_t *rethandle);

errval_t fat32_create(void *st, const char *path, fat32_handle_t *rethandle);

errval_t fat32_remove(void *st, const char *path);

errval_t fat32_read(void *st, fat32_handle_t handle, void *buffer, size_t bytes,
                    size_t *bytes_read);

errval_t fat32_write(void *st, fat32_handle_t handle, const void *buffer,
                     size_t bytes, size_t *bytes_written);

errval_t fat32_truncate(void *st, fat32_handle_t handle, size_t bytes);

errval_t fat32_tell(void *st, fat32_handle_t handle, size_t *pos);

errval_t fat32_stat(void *st, fat32_handle_t inhandle, struct fs_fileinfo *info);

errval_t fat32_seek(void *st, fat32_handle_t handle, enum fs_seekpos whence,
                    off_t offset);

errval_t fat32_close(void *st, fat32_handle_t inhandle);

errval_t fat32_opendir(void *st, const char *path, fat32_handle_t *rethandle);

errval_t fat32_dir_read_next(void *st, fat32_handle_t inhandle, char **retname,
                             struct fs_fileinfo *info);

errval_t fat32_closedir(void *st, fat32_handle_t dhandle);

errval_t fat32_mkdir(void *st, const char *path);

errval_t fat32_rmdir(void *st, const char *path);

errval_t fat32_mount(const char *uri, fat32_mount_t *retst);

void set_sd(struct sdhc_s *sd);

errval_t fat32_init(void);

#endif