#ifndef VISA_WANCO_SQLITE_WASI_COMPAT_H
#define VISA_WANCO_SQLITE_WASI_COMPAT_H

#include <sys/stat.h>

int chmod(const char *path, mode_t mode);
char *realpath(const char *restrict path, char *restrict resolved_path);

#endif
