#include <fs/fs.h>
#include <types.h>

typedef void *fat32_handle_t;
typedef void *fat32_mount_t;

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
