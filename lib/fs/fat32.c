#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <aos/cache.h>
#include <fs/fs.h>
#include <fs/fat32.h>
#include <fs/list.h>
#include <libgen.h>

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
int BlocksPerSec;

//tracking data for current cluster; used for getting free blocks
#define FREE_CLUSTERS_SCANNED_BLOCKS 2
int FreeClustersToCheckFrom;

#define FIRST_SECTOR_OF_CLUSTER(n) ((n-2) * SecPerClus) + FirstDataSector
#define FAT_SECTOR(n) RsvdSecCnt + (n * 4 / BytsPerSec)
#define FAT_OFFSET(n) (n*4) % BytsPerSec

#define CHECK_ERR(f, msg) ({\
            err = f;\
            if(err_is_fail(err)) {\
                DEBUG_ERR(err, msg);\
                return err;\
            }\
})

#define CHECK_ERR_PUSH(f, push) ({\
            err = f;\
            if(err_is_fail(err)) {\
                return err_push(err, push);\
            }\
})

int RootSector;

struct free_cluster_list *free_clusters;

struct fat32_dirent *current_directory;
struct fat32_dirent *root_directory;
char *mount;

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
    //calculate blocks per sector
    BlocksPerSec = BytsPerSec/SDHC_BLOCK_SIZE;

    //create and set root directory
    root_directory = malloc(sizeof(struct fat32_dirent));
    root_directory->Attr = ATTR_DIRECTORY;
    root_directory->FstCluster = RootClus;
    root_directory->name = malloc(1);
    root_directory->name[0] = '/';
    root_directory->parent = NULL;
    root_directory->size = -1;

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
    errval_t err;
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
        if((entry & CLUSTER_FREE_MASK) == CLUSTER_FREE) {
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
    errval_t err;
    list_init(&free_clusters);
    
    FreeClustersToCheckFrom = DATA_CLUSTER_START;

    CHECK_ERR(refill_free_clusters(), "Failed to refill clusters");

    return SYS_ERR_OK;
}

static void shortname_to_name(char *shortname, char **retname) {
    char *name = calloc(1, 12);
    int i = 0, k = 0;
    while(i < strlen(shortname) && shortname[i] != 0x20) name[k++] = shortname[i++];
    i = 8;
    if(shortname[i] != 0x20) name[k++] = '.';
    while(i < strlen(shortname) && shortname[i] != 0x20) name[k++] = shortname[i++];
    name[k] = '\0'; 
    *retname = name;
}

static errval_t get_next_cluster(int cluster, int *next_cluster) {
    errval_t err;
    uint8_t FAT_Sector[SDHC_BLOCK_SIZE];

    CHECK_ERR(sd_read_sector(FAT_SECTOR(cluster), FAT_Sector), "failed to read FAT");
    FAT_Entry *entry = (FAT_Entry *) (FAT_Sector + FAT_OFFSET(cluster));
    *next_cluster = *entry;

    return SYS_ERR_OK;
}

//given a 32 byte directory entry, extracts info out of it
//TODO : get file times
static void parse_directory_entry(uint8_t *dir, struct fat32_dirent *parent, struct fat32_dirent **retent) {

    struct fat32_dirent *dirent = malloc(sizeof(struct fat32_dirent));
    
    char shortname[11];
    memcpy(shortname, dir, 11);
    shortname_to_name(shortname, &dirent->name);

    dirent->Attr = *(dir + DIR_ATTR);

    if(dirent->Attr == ATTR_DIRECTORY)
        dirent->is_dir = true;
    else
        dirent->is_dir = false;

    uint16_t cluster_high = *(uint16_t *) (dir + DIR_FST_CLUSTER_HIGH), cluster_low = *(uint16_t *) (dir + DIR_FST_CLUSTER_LOW);
    dirent->FstCluster = (cluster_high << 2) + cluster_low;

    dirent->parent = parent;
    dirent->size = *(uint32_t *) (dir + DIR_FILE_SIZE);

    *retent = dirent;
}

static void free_dirent(struct fat32_dirent *dir, bool recursive) {
    if(dir == NULL)
        return;
    if(dir->name != NULL)
        free(dir->name);
    if(recursive)
        free_dirent(dir->parent, recursive);
    free(dir);
}

static errval_t find_in_directory(struct fat32_dirent *dir, const char *name, struct fat32_dirent **retdir) {
    errval_t err;
    int cluster = dir->FstCluster;
    while(cluster != EOC) {
        int start_sector = FIRST_SECTOR_OF_CLUSTER(dir->FstCluster);
        for(int sector = 0; sector < SecPerClus; sector++) {
            uint8_t sector_data[SDHC_BLOCK_SIZE];
            CHECK_ERR(sd_read_sector(start_sector + sector, sector_data), "bad sd read");
            for(int i = 0; i < SDHC_BLOCK_SIZE; i+=32) {
                if(sector_data[i] == 0x00)
                    return FS_ERR_NOTFOUND;
                if(sector_data[i] == 0xE5)
                    continue;
                struct fat32_dirent *dirent;
                parse_directory_entry(sector_data + i, dir, &dirent);
                if(strcmp(dirent->name, name) == 0) {
                    *retdir = dirent;
                    return SYS_ERR_OK;
                }
                free_dirent(dirent, false);
            }
        }
        CHECK_ERR(get_next_cluster(cluster, &cluster), "error getting next cluster");
    }

    return FS_ERR_NOTFOUND;
}

//TODO : Nasty bug when file not found : DEBUG_ERR reprints the same few lines multiple times..... 
static errval_t search_dirent(struct fat32_dirent *curr, const char *path, struct fat32_dirent **retent) {
    errval_t err;
    if(*path == '\0') {
        *retent = curr;
        return SYS_ERR_OK;
    }
    
    if(curr->Attr != ATTR_DIRECTORY)
        return FS_ERR_NOTDIR;
        

    while(*path != '\0') {
        int i = 0;
        while(path[i] != '\0' && path[i] != FS_PATH_SEP) i++;
        char *next_dir_name = malloc(i);
        memcpy(next_dir_name, path, i);
        path += i;
        if(*path != '\0')
            path ++;
        
        struct fat32_dirent *dir;
        err = find_in_directory(curr, next_dir_name, &dir);
        free(next_dir_name);
        if(err_is_fail(err)) {
            return err;
        }
        curr = dir;
    }

    *retent = curr;

    return SYS_ERR_OK;
}

static errval_t find_dirent(const char *mount_point, const char *path, struct fat32_dirent **retent) {
    errval_t err;
    bool from_root = strstr(path, mount_point) == path;

    struct fat32_dirent *dir;
    if(from_root) {
        path += strlen(mount_point);
        dir = root_directory;
    }
    else {
        dir = current_directory;
    }

    CHECK_ERR_PUSH(search_dirent(dir, path, retent), FS_ERR_SEARCH_FAIL);

    return SYS_ERR_OK;
}

errval_t fat32_opendir(const char *path, fat32_handle_t *rethandle) {
    errval_t err;
    struct fat32_dirent *dir;
    CHECK_ERR_PUSH(find_dirent(mount, path, &dir), FS_ERR_OPEN);
    
    if(dir->Attr != ATTR_DIRECTORY)
        return FS_ERR_NOTDIR;
    
    struct fat32_handle *handle = malloc(sizeof(struct fat32_handle));
    handle->dirent = dir;
    handle->isdir = true;
    handle->path = malloc(strlen(path));
    strncpy(handle->path, path, strlen(path));
    handle->pos = 0;

    *rethandle = handle;

    return SYS_ERR_OK;
}

static errval_t sector_from_cluster_offset(int cluster, int offset, int *retsector, int *retoffset) {
    errval_t err;
    if(offset > BytsPerSec * SecPerClus) {
        offset -= BytsPerSec * SecPerClus;
        int next_cluster;
        CHECK_ERR(get_next_cluster(cluster, &next_cluster), "");
        return sector_from_cluster_offset(next_cluster, offset, retsector, retoffset);
    }

    *retsector = FIRST_SECTOR_OF_CLUSTER(cluster) + (offset/BytsPerSec);
    *retoffset = offset % BytsPerSec;

    return SYS_ERR_OK;
}

errval_t fat32_dir_read_next(fat32_handle_t inhandle, char **retname, struct fs_fileinfo *info) {
    errval_t err;
    struct fat32_handle *handle = inhandle;
    if(!handle->isdir)
        return FS_ERR_NOTDIR;
    
    int sector,offset;
    uint8_t dir_block[SDHC_BLOCK_SIZE];
    CHECK_ERR(sector_from_cluster_offset(handle->dirent->FstCluster, handle->pos * 32, &sector, &offset), "");
    CHECK_ERR(sd_read_sector(sector, dir_block), "bad read");

    if(dir_block[offset] == DIR_ALL_FREE)
        return FS_ERR_INDEX_BOUNDS;
    else if(dir_block[offset] == DIR_FREE) {
        handle->pos++;
        return fat32_dir_read_next(inhandle, retname, info);
    }

    struct fat32_dirent *dir;
    parse_directory_entry(dir_block + offset, handle->dirent, &dir);

    *retname = dir->name;
    info->size = dir->size;
    info->type = FS_DIRECTORY;

    handle->pos++;

    return SYS_ERR_OK;
}

// Initialize the FAT32 filesystem, get all the necessary information, and populate the free block list with some free blocks
errval_t fat32_init(void) { 
    errval_t err;
    uint8_t bpb[SDHC_BLOCK_SIZE];
    
    CHECK_ERR(sd_read_sector(BPB_SECTOR, bpb), "bad read");

    check_set_bpb_metadata(bpb);

    CHECK_ERR(initialize_free_clusters(), "Failed to find free clusters");

    current_directory = NULL;

    mount = malloc(8);
    mount = "/"; 

    return SYS_ERR_OK; 
}

// static bool strisalnum(char *name, int len) {
//     for(int i=0;i<len;i++)
//         if(!isalnum(name[i]))
//             return false;
    
//     return true;
// }
// static bool valid_shortname(char *name) {
//     int len = strlen(name);
//     if(len > 12 || len == 0)
//         return false;
//     if(name[0] == '.' || isdigit(name[0]))
//         return false;
//     char *dot_pos = strchr(name, '.');
//     if(dot_pos == NULL)
//         if(len > 8 || !strisalnum(name, len))
//             return false;
//     else {
//         int lenfirst = dot_pos - name;
//         if(lenfirst > 8)
//             return false;
//         int lenext = len - (dot_pos - name) - 1;
//         if(lenext > 3)
//             return false;
//         if(!strisalnum(name, lenfirst) && !strisalnum(dot_pos+1, lenext))
//             return false;
//     }    
//     return true;
// }