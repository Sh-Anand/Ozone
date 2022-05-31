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
#define CLUSTER_EOC            0x0ffffff8
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
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN    0x02
#define ATTR_SYSTEM    0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE   0x20
#define ATTR_LONG_NAME ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID
#define DIR_FREE       0xE5
#define DIR_ALL_FREE   0x0
#define DIR_SIZE       32

struct Time {
    uint8_t hour, minute, sec;
};

struct Date {
    uint8_t Year, Month, Day;
};

struct fat32_manager {
    struct sdhc_s *sd;

    //meta data
    int BytsPerSec;
    int SecPerClus;
    int RsvdSecCnt;
    int RootEntCnt;
    int NumFATs;
    int TotSec32;
    int FATSz32;
    int RootClus;

    //computed from meta data
    int FirstDataSector;
    int TotalClusters;
    int BlocksPerSec;

    //tracking data for current cluster; used for getting free blocks
    int FreeClustersToCheckFrom;

    int RootSector;

    struct free_cluster_list *free_clusters;

    char *mount;
};

struct fat32_manager *manager;

/**
 * @brief an entry in the fat32_fs
 */
struct fat32_dirent
{   
    char *name;                     ///< name of the file or directory

    uint8_t Attr;                   ///< attributes (read/hidden/etc)

    struct Time CrtTime, LastWrtTime;     
    struct Date CrtDate, LastWrtDate;

    int FstCluster;

    size_t size;                    ///< the size of the direntry in bytes or files, -1 implies root directory
    size_t refcount;                ///< reference count for open handles

    struct fat32_dirent *parent;    ///< parent directory

    bool is_dir;                    ///< flag indicationg this is a dir

    int sector, sector_offset;      ///< sector in drive and offset into sector that this dirent is in

};

struct fat32_dirent *root_directory;

/**
 * @brief a handle to an open file or directory
 */
struct fat32_handle
{
    char *path;
    bool isdir;
    struct fat32_dirent *dirent;
    off_t pos;
};

typedef void *fat32_handle_t;
typedef void *fat32_mount_t;

typedef uint32_t FAT_Entry;

errval_t fat32_open(const char *path, fat32_handle_t *rethandle);

errval_t fat32_create(const char *path, fat32_handle_t *rethandle);

errval_t fat32_remove(const char *path);

errval_t fat32_read(fat32_handle_t handle, void *buffer, size_t bytes,
                    size_t *bytes_read);

errval_t fat32_write(fat32_handle_t handle, const void *buffer,
                     size_t bytes, size_t *bytes_written);

errval_t fat32_truncate(void *st, fat32_handle_t handle, size_t bytes);

errval_t fat32_tell(fat32_handle_t handle, size_t *pos);

errval_t fat32_stat(fat32_handle_t inhandle, struct fs_fileinfo *info);

errval_t fat32_seek(fat32_handle_t handle, enum fs_seekpos whence,
                    off_t offset);

errval_t fat32_close(fat32_handle_t inhandle);

errval_t fat32_opendir(const char *path, fat32_handle_t *rethandle);

errval_t fat32_dir_read_next(fat32_handle_t inhandle, char **retname,
                             struct fs_fileinfo *info);

errval_t fat32_closedir(fat32_handle_t dhandle);

errval_t fat32_mkdir(const char *path);

errval_t fat32_rmdir(const char *path);

errval_t fat32_mount(const char *uri, fat32_mount_t *retst);

void set_sd(struct sdhc_s *sd);

errval_t fat32_init(char *mnt);

void fat32_preinit(void);

#endif