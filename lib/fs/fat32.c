#include <stdio.h>
#include <string.h>
#include <aos/aos.h>
#include <aos/cache.h>

#include <fs/fs.h>
#include <fs/fat32.h>

#include "fs_internal.h"


struct sdhc_s *sd;

int ROOT_CLUSTER;

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
    
    return SYS_ERR_OK;
}

errval_t fat32_init(void) { 
    errval_t err;
    
    void *bpb = malloc(SDHC_BLOCK_SIZE);
    
    err = sd_read_sector(BPB_SECTOR, bpb);
    if(err_is_fail(err))
        return err;
    
    int root;
    uint8_t *blockbpb = (uint8_t *) bpb;
    
    memcpy((void *) &root, bpb + BPB_RootClus, BPB_RootClus_Size);

    assert(blockbpb[510] == 0x55);
    assert(blockbpb[511] == 0xAA);
    assert((blockbpb[0] == 0xEB && blockbpb[2] == 0x90) || blockbpb[0] == 0xE9);

    ROOT_CLUSTER = root;

    DEBUG_PRINTF("Root cluster : %d\n", root);

    //free_memory(BPB);
    return SYS_ERR_OK; 
}