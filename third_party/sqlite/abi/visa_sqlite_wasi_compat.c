/* Build-only WASI compatibility for the unmodified SQLite amalgamation. */

#include "visa_sqlite_wasi_compat.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wasi/api.h>

#define VISA_SQLITE_ROOT_FD 3
#define VISA_WASI_IMPORT(module_name, symbol_name) \
    __attribute__((import_module(module_name), import_name(symbol_name)))

extern __wasi_errno_t visa_wasi_metadata_path_chmod(
    int32_t dirfd,
    const char *path,
    uint32_t path_len,
    uint32_t mode)
    VISA_WASI_IMPORT(
        "visa_wasi_metadata_v1",
        "visa_wasi_metadata_path_chmod");

static int posix_errno(__wasi_errno_t error)
{
    switch (error) {
    case __WASI_ERRNO_ACCES:
    case __WASI_ERRNO_NOTCAPABLE:
        return EACCES;
    case __WASI_ERRNO_FAULT:
        return EFAULT;
    case __WASI_ERRNO_INVAL:
        return EINVAL;
    case __WASI_ERRNO_IO:
        return EIO;
    case __WASI_ERRNO_NAMETOOLONG:
        return ENAMETOOLONG;
    case __WASI_ERRNO_NOENT:
        return ENOENT;
    case __WASI_ERRNO_NOTDIR:
        return ENOTDIR;
    case __WASI_ERRNO_NOTSUP:
        return ENOTSUP;
    case __WASI_ERRNO_PERM:
        return EPERM;
    case __WASI_ERRNO_ROFS:
        return EROFS;
    default:
        return EIO;
    }
}

int chmod(const char *path, mode_t mode)
{
    size_t path_len;
    __wasi_errno_t error;

    if (path == NULL) {
        errno = EFAULT;
        return -1;
    }
    path_len = strlen(path);
    if (path_len > UINT32_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    error = visa_wasi_metadata_path_chmod(
        VISA_SQLITE_ROOT_FD,
        path,
        (uint32_t)path_len,
        (uint32_t)mode);
    if (error == __WASI_ERRNO_SUCCESS) {
        return 0;
    }
    errno = posix_errno(error);
    return -1;
}

char *realpath(const char *restrict path, char *restrict resolved_path)
{
    (void)resolved_path;
    if (path == NULL) {
        errno = EINVAL;
    } else {
        errno = ENOTSUP;
    }
    return NULL;
}
