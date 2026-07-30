/* Build-only WASI compatibility for the unmodified SQLite shell corpus. */

#include "sqlite-wasi-compat.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int chmod(const char *path, mode_t mode)
{
    (void)mode;
    if (path == NULL) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

char *realpath(const char *restrict path, char *restrict resolved_path)
{
    size_t length;
    char *result = resolved_path;

    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    length = strlen(path);
    if (length > PATH_MAX) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    if (result == NULL) {
        result = malloc(length + 1);
        if (result == NULL) {
            errno = ENOMEM;
            return NULL;
        }
    }
    memcpy(result, path, length + 1);
    return result;
}
