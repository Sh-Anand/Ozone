#ifndef FS_FAT32_H_
#define FS_FAT32_H_

#include <fs/fs.h>

#include <drivers/sdhc.h>

//BPB Info
#define BPB_SECTOR      0
#define BPB_BytsPerSec 11
#define BPB_SecPerClus 13
#define BPB_RsvdSecCnt 14
#define BPB_RootEntCnt 17
#define BPB_NumFATs    16
#define BPB_TotSec32   32
#define BPB_FATSz32    36
#define BPB_RootClus   44

#define DATA_CLUSTER_START 2

//special cluster symbols
#define CLUSTER_FREE   0x0
#define CLUSTER_FREE_MASK ~(0b1111 >> 4)
#define EOC            0x0ffffff8
#define CLUSTER_BAD    0x0ffffff7

//Directory Info
#define DIR_NAME       0x00
#define DIR_NAME_SZ    11
#define DIR_ATTR       0x0b
#define DIR_CRT_TIME   0x0E
#define DIR_CRT_DATE   0x10
#define DIR_LWRT_TIME  0x16
#define DIR_LWRT_DATE  0x18
#define DIR_FST_CLUSTER_HIGH 0x14
#define DIR_FST_CLUSTER_LOW  0x1A
#define DIR_FILE_SIZE  0x1C     

//Directory attributes
#define ATTR_DIRECTORY 0x10

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

errval_t fat32_opendir(const char *path, fat32_handle_t *rethandle);

errval_t fat32_dir_read_next(fat32_handle_t inhandle, char **retname,
                             struct fs_fileinfo *info);

errval_t fat32_closedir(fat32_handle_t dhandle);

errval_t fat32_mkdir(const char *path);

errval_t fat32_rmdir(const char *path);

errval_t fat32_mount(const char *uri, fat32_mount_t *retst);

void set_sd(struct sdhc_s *sd);

errval_t fat32_init(void);

#endif