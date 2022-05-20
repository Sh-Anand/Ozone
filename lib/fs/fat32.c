#include <stdio.h>
#include <string.h>

#include <aos/aos.h>
#include <aos/cache.h>
#include <fs/fs.h>
#include <fs/fat32.h>
#include <fs/list.h>

#include "fs_internal.h"

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

//tracking data for current cluster; used for getting free blocks
#define FREE_CLUSTERS_SCANNED_BLOCKS 2
int FreeClustersToCheckFrom;

#define FIRST_SECTOR_OF_CLUSTER(n) ((n-2) * SecPerClus) + FirstDataSector
#define FAT_SECTOR(n) RsvdSecCnt + (n * 4 / BytsPerSec)
#define FAT_OFFSET(n) (n*4) % BytsPerSec

#define CHECK_ERR(err, msg) ({\
            if(err_is_fail(err)) {\
                DEBUG_ERR(err, msg);\
                return err;\
            }\
})

#define CHECK_ERR_PUSH(err, push) ({\
            if(err_is_fail(err)) {\
                return err_push(err, push);\
            }\
})

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

struct free_cluster_list *free_clusters;

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

static void check_set_bpb_metadata(uint8_t *bpb) {
    assert(bpb[510] == 0x55);
    assert(bpb[511] == 0xAA);
    assert((bpb[0] == 0xEB && bpb[2] == 0x90) || bpb[0] == 0xE9);

    //grab all the metadata
    BytsPerSec = *(uint16_t *)(bpb + BPB_BytsPerSec);
    SecPerClus = *(bpb + BPB_SecPerClus);
    RsvdSecCnt = *(uint16_t *)(bpb + BPB_RsvdSecCnt);
    RootEntCnt = *(uint16_t *)(bpb + BPB_RootEntCnt);
    RootClus = *(uint32_t *)(bpb + BPB_RootClus);
    TotSec32 = *(uint32_t *)(bpb + BPB_TotSec32);
    FATSz32 = *(uint32_t *)(bpb + BPB_FATSz32);
    NumFATs = *(bpb + BPB_NumFATs);

    assert(RootEntCnt == 0);

    //calculate the first data sector
    FirstDataSector = RsvdSecCnt + (NumFATs * FATSz32);
    //calculat the sector of the root cluster
    RootSector = FIRST_SECTOR_OF_CLUSTER(RootClus);
    //calculate total number of clusters in the volume
    TotalClusters = TotSec32/SecPerClus;

    DEBUG_PRINTF("BytsPerSec : %d\n", BytsPerSec);
    DEBUG_PRINTF("SecPerClus : %d\n", SecPerClus);
    DEBUG_PRINTF("RsvdSecCnt : %d\n", RsvdSecCnt);
    DEBUG_PRINTF("RootEntCnt : %d\n", RootEntCnt);
    DEBUG_PRINTF("RootClus : %d\n", RootClus);
    DEBUG_PRINTF("TotSec32 : %d\n", TotSec32);
    DEBUG_PRINTF("TotalClusters : %d\n", TotalClusters);
    DEBUG_PRINTF("FATSz32 : %d\n", FATSz32);
    DEBUG_PRINTF("NumFATs : %d\n", NumFATs);
    DEBUG_PRINTF("FirstDataSector : %d\n", FirstDataSector);
    DEBUG_PRINTF("RootSector : %d\n", RootSector);
    DEBUG_PRINTF("RootFATSector : %d\n", FAT_SECTOR(RootClus));
    DEBUG_PRINTF("RootFATOffset : %d\n", FAT_OFFSET(RootClus));
}

static errval_t refill_free_clusters(void) {
    if(FreeClustersToCheckFrom == TotalClusters)
        return FS_ERR_NO_FREE_BLOCKS;

    uint8_t FAT_block[SDHC_BLOCK_SIZE];

    //read first sector as offset may not be zero
    CHECK_ERR(sd_read_sector(FAT_SECTOR(DATA_CLUSTER_START), FAT_block), "FAT sector read failed");

    size_t pre_sz = free_clusters->size; 
    //iterate through free clusters
    int blocks = FREE_CLUSTERS_SCANNED_BLOCKS - 1;
    while((FreeClustersToCheckFrom != TotalClusters)) {
        int FAT_offset = FAT_OFFSET(FreeClustersToCheckFrom);

        //if we are the start of a new FAT sector, read it
        if(FAT_offset == 0) {
            CHECK_ERR(sd_read_sector(FAT_SECTOR(FreeClustersToCheckFrom), FAT_block), "FAT sector read failed");
            blocks--;
        }
        //grab entry from offset into block
        FAT_Entry entry = *(FAT_Entry *)(FAT_block + FAT_offset);
        //if free cluster, insert into free list
        if(entry == CLUSTER_FREE) {
            push_back(free_clusters, FreeClustersToCheckFrom);
        }

        if(!blocks && FAT_offset == 508)
            break;

        FreeClustersToCheckFrom++;
    }

    DEBUG_PRINTF("Found %d free clusters\n", free_clusters->size - pre_sz);

    return SYS_ERR_OK;
}

static errval_t initialize_free_clusters(void) {
    list_init(&free_clusters);
    
    FreeClustersToCheckFrom = DATA_CLUSTER_START;

    CHECK_ERR(refill_free_clusters(), "Failed to refill clusters");

    return SYS_ERR_OK;
}

errval_t fat32_init(void) { 

    uint8_t bpb[SDHC_BLOCK_SIZE];
    
    CHECK_ERR(sd_read_sector(BPB_SECTOR, bpb), "bad read");

    check_set_bpb_metadata(bpb);

    CHECK_ERR(initialize_free_clusters(), "Failed to find free clusters");

    return SYS_ERR_OK; 
}