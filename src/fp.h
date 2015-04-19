#ifndef __FP_SRC_FP_H__
#define __FP_SRC_FP_H__

#include <ss.h>

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef void* (*fp_create)(const char *path, mode_t mode);
typedef void* (*fp_open)(const char *path, int flags);
typedef int (*fp_read)(void *fd, void *buf, size_t size);
typedef int (*fp_write)(void *fd, void *buf, size_t size);
typedef int (*fp_seek)(void *fd, off_t offset, int whence);
typedef int (*fp_delete)(const char *path);
typedef int (*fp_close)(void *fd);

typedef struct __fp_ops {
    fp_create create;
    fp_open open;
    fp_read read;
    fp_write write;
    fp_seek seek;
    fp_close close;
    fp_delete delete;
} fp_ops;

typedef struct __fp_ctx {
    ss_ctx ss;
    fp_ops ops;
} fp_ctx;

bool fp_init(fp_ctx *ctx, fp_ops *ops);
int fp_listen(fp_ctx *ctx, int port);
bool fp_run(fp_ctx *ctx, int listen_sd);

#endif
