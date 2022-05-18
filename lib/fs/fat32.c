#include <stdio.h>
#include <string.h>
#include <aos/aos.h>
#include <aos/cache.h>

#include <fs/fs.h>
#include <fs/fat32.h>

#include "fs_internal.h"


// struct sdhc_s *sd;

int ROOT_CLUSER;

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

struct memory_data {
    lvaddr_t paddr;
    lvaddr_t vaddr;
};

// //get a memory data struct of size
// static errval_t get_memory(size_t size, struct memory_data **ret_mem) {
//     errval_t err;

//     struct capref frame;
//     size_t ret_size;
//     err = frame_alloc(&frame, size, &ret_size);
//     if(err_is_fail(err))
//         return err;
    
//     struct frame_identity f_id;
//     err = frame_identify(frame, &f_id);
//     if(err_is_fail(err))
//         return err;

//     void *vaddr;
//     err = paging_map_frame(get_current_paging_state(), &vaddr, ret_size, frame);
//     if(err_is_fail(err))
//         return err;
    
//     struct memory_data *mem = malloc(sizeof(struct memory_data));
//     mem->paddr = f_id.base;
//     mem->vaddr = (lvaddr_t) vaddr;

//     *ret_mem = mem;

//     return SYS_ERR_OK;
// }

// //free a memory data region. it is the programmer's responsiblity to not reuse this mem
// static void free_memory(struct memory_data *mem) {
//     // free((void *)mem->vaddr);
//     free(mem);
// }

// void set_sd(struct sdhc_s *sdh) {
//     sd = sdh;
// }

//Read logical sector <sector> and return a pointer to the info
static errval_t sd_read_sector(struct sdhc_s *sd, int sector, void *data) {
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

    err = sdhc_read_block(sd, 0, f_id.base);
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

errval_t fat32_init(struct sdhc_s *sd) { 
    errval_t err;
    
    void *bpb = malloc(SDHC_BLOCK_SIZE);
    //err = get_memory(SDHC_BLOCK_SIZE, &BPB);
    // if(err_is_fail(err))
    //     return err;
    
    err = sd_read_sector(sd, 0, bpb);
    if(err_is_fail(err))
        return err;
    
    int root;
    char *bpb_block = (char *) bpb + BPB_RootClus;
    uint8_t *blockbpb = (uint8_t *) bpb;
    
    memcpy((void *) &root, (void *) bpb_block, BPB_RootClus_Size);

    assert(blockbpb[510] == 0x55);
    assert(blockbpb[511] == 0xAA);
    DEBUG_PRINTF("FIRST BYTE : %d", * (uint8_t *) bpb);
    assert(blockbpb[0] == 0xEB || blockbpb[0] == 0xE9);

    ROOT_CLUSER = root;

    char *data = calloc(0, 8);

    memcpy(data, bpb + 3, 8);

    DEBUG_PRINTF("STRING IS : %s\n", data);

    //free_memory(BPB);
    return SYS_ERR_OK; 
}