/*
 * Guest-side compatibility adapter for the unmodified zstd CLI.
 *
 * zstd uses the POSIX chmod(2) and chown(2) entry points when it copies input
 * metadata to an output file.  wasi-libc leaves those calls as `env` imports.
 * Wanco lowers every WebAssembly import to a native C symbol and prepends an
 * ExecEnv pointer.  Linking those bare imports against a native executable can
 * therefore resolve them to glibc's incompatible chmod/chown ABI.
 *
 * This object is linked into the WebAssembly module, not into the native AOT
 * executable.  It resolves the POSIX names inside the guest and forwards them
 * to unambiguous, length-delimited vISA imports.  Wanco then lowers the two
 * imports to the correspondingly named native bridge symbols.
 *
 * The imported functions return a WASI Preview1 errno (zero on success).
 * `VISA_WASI_METADATA_ROOT_FD` is the vISA root preopen exposed to the stock
 * application.  No zstd upstream source file is changed by this adapter.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wasi/api.h>

#ifndef VISA_WASI_METADATA_ROOT_FD
#define VISA_WASI_METADATA_ROOT_FD 3
#endif

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

extern __wasi_errno_t visa_wasi_metadata_path_chown(
    int32_t dirfd,
    const char *path,
    uint32_t path_len,
    uint32_t uid,
    uint32_t gid)
    VISA_WASI_IMPORT(
        "visa_wasi_metadata_v1",
        "visa_wasi_metadata_path_chown");

static int visa_posix_errno(__wasi_errno_t error)
{
    switch (error) {
    case __WASI_ERRNO_SUCCESS:
        return 0;
    case __WASI_ERRNO_ACCES:
    case __WASI_ERRNO_NOTCAPABLE:
        return EACCES;
    case __WASI_ERRNO_EXIST:
        return EEXIST;
    case __WASI_ERRNO_FAULT:
        return EFAULT;
    case __WASI_ERRNO_INVAL:
        return EINVAL;
    case __WASI_ERRNO_IO:
        return EIO;
    case __WASI_ERRNO_LOOP:
        return ELOOP;
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

static int visa_posix_result(__wasi_errno_t error)
{
    if (error == __WASI_ERRNO_SUCCESS) {
        return 0;
    }
    errno = visa_posix_errno(error);
    return -1;
}

int chmod(const char *path, mode_t mode)
{
    size_t path_len;

    if (path == NULL) {
        errno = EFAULT;
        return -1;
    }
    path_len = strlen(path);
    if (path_len > UINT32_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return visa_posix_result(visa_wasi_metadata_path_chmod(
        VISA_WASI_METADATA_ROOT_FD,
        path,
        (uint32_t)path_len,
        (uint32_t)mode));
}

int chown(const char *path, uid_t uid, gid_t gid)
{
    size_t path_len;

    if (path == NULL) {
        errno = EFAULT;
        return -1;
    }
    path_len = strlen(path);
    if (path_len > UINT32_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return visa_posix_result(visa_wasi_metadata_path_chown(
        VISA_WASI_METADATA_ROOT_FD,
        path,
        (uint32_t)path_len,
        (uint32_t)uid,
        (uint32_t)gid));
}
