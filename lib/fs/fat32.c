#include <stdio.h>
#include <string.h>
#include <aos/aos.h>
#include <aos/cache.h>

#include <fs/fs.h>
#include <fs/fat32.h>

#include "fs_internal.h"

struct sdhc_s *sd;

//meta data
int RootClus;
int BytsPerSec;
int SecPerClus;
int RsvdSecCnt;
int RootEntCnt;
int NumFATs;
int FATSz32;

//computed from meta data
int FirstDataSector;

#define FIRST_SECTOR_OF_CLUSTER(n) ((n-2) * SecPerClus) + FirstDataSector
#define FAT_SECTOR(n) RsvdSecCnt + (n * 4 / BytsPerSec)
#define FAT_OFFSET(n) (n*4) % BytsPerSec

int RootSector;

/**
 * @brief an entry in the fat32_fs
 */
struct fat32_dirent
{
    char *name;                     ///< name of the file or directoyr
    size_t size;                    ///< the size of the direntry in bytes or files
    size_t refcount;                ///< reference count for open handles
    struct fat32_dirent *parent;    ///< parent directory

    struct fat32_dirent *next;      ///< parent directory
    struct fat32_dirent *prev;      ///< parent directory

    bool is_dir;                    ///< flag indicationg this is a dir

    union {
        void *data;                 ///< file data pointer
        struct fat32_dirent *dir;   ///< directory pointer
    };
};

/**
 * @brief a handle to an open file or directory
 */
struct fat32_handle
{
    struct fs_handle common;
    char *path;
    bool isdir;
    struct fat32_dirent *dirent;
    union {
        off_t file_pos;
        struct fat32_dirent *dir_pos;
    };
};

void set_sd(struct sdhc_s *sdh) {
    sd = sdh;
}

//Read logical sector <sector> and return a pointer to the info
static errval_t sd_read_sector(int sector, void *data) {
    errval_t err;
    //invalidate the buffer from the cache

    struct capref frame;

    err = frame_alloc(&frame, SDHC_BLOCK_SIZE, NULL);
    if(err_is_fail(err))
        return err;
    
    struct frame_identity f_id;
    err = cap_identify_mappable(frame, &f_id);
    if(err_is_fail(err))
        return err;

    err = sdhc_read_block(sd, sector, f_id.base);
    if(err_is_fail(err))
        return err_push(err, FS_ERR_BLOCK_READ);
    
    void *vaddr;
    err = paging_map_frame_attr(get_current_paging_state(), &vaddr, SDHC_BLOCK_SIZE, frame, VREGION_FLAGS_READ_WRITE_NOCACHE);
    if(err_is_fail(err))
        return err;
    // arm64_dcache_wbinv_range((vm_offset_t)vaddr, SDHC_BLOCK_SIZE);
    // arm64_dcache_wbinv_range((vm_offset_t)data, SDHC_BLOCK_SIZE);

    memcpy(data, vaddr, SDHC_BLOCK_SIZE);
    
    err = cap_destroy(frame);

    return SYS_ERR_OK;
}

errval_t fat32_init(void) { 
    errval_t err;
    
    uint8_t *bpb = malloc(SDHC_BLOCK_SIZE);
    
    err = sd_read_sector(BPB_SECTOR, bpb);
    if(err_is_fail(err))
        return err;


    assert(bpb[510] == 0x55);
    assert(bpb[511] == 0xAA);
    assert((bpb[0] == 0xEB && bpb[2] == 0x90) || bpb[0] == 0xE9);

    //grab all the metadata
    BytsPerSec = *(uint16_t *)(bpb + BPB_BytsPerSec);
    SecPerClus = *(bpb + BPB_SecPerClus);
    RsvdSecCnt = *(uint16_t *)(bpb + BPB_RsvdSecCnt);
    RootEntCnt = *(uint16_t *)(bpb + BPB_RootEntCnt);
    RootClus = *(uint32_t *)(bpb + BPB_RootClus);
    FATSz32 = *(uint32_t *)(bpb + BPB_FATSz32);
    NumFATs = *(uint32_t *)(bpb + BPB_NumFATs);

    assert(RootEntCnt == 0);

    //calculate the first data sector
    FirstDataSector = RsvdSecCnt + (NumFATs * FATSz32);
    //calculat the sector of the root cluster
    RootSector = FIRST_SECTOR_OF_CLUSTER(RootClus);

    DEBUG_PRINTF("BytsPerSec : %d\n", BytsPerSec);
    DEBUG_PRINTF("SecPerClus : %d\n", SecPerClus);
    DEBUG_PRINTF("RsvdSecCnt : %d\n", RsvdSecCnt);
    DEBUG_PRINTF("RootEntCnt : %d\n", RootEntCnt);
    DEBUG_PRINTF("RootClus : %d\n", RootClus);
    DEBUG_PRINTF("FATSz32 : %d\n", FATSz32);
    DEBUG_PRINTF("NumFATs : %d\n", NumFATs);
    DEBUG_PRINTF("FirstDataSector : %d\n", FirstDataSector);
    DEBUG_PRINTF("RootSector : %d\n", RootSector);
    DEBUG_PRINTF("RootFATSector : %d\n", FAT_SECTOR(RootClus));
    DEBUG_PRINTF("RootFATOffset : %d\n", FAT_OFFSET(RootClus));

    uint8_t *fat_sec = malloc(SDHC_BLOCK_SIZE);
    err = sd_read_sector(FAT_SECTOR(RootClus), fat_sec);

    FAT_Entry root_fat = *(FAT_Entry *)(fat_sec + FAT_OFFSET(RootClus));

    DEBUG_PRINTF("FAT Entry of RootCluster : 0x%x\n", root_fat);

    assert(root_fat >= EOC);

    free(bpb);
    free(fat_sec);
    return SYS_ERR_OK; 
}