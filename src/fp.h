#ifndef __FP_SRC_FP_H__
#define __FP_SRC_FP_H__

#include <ss.h>

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef void* (*fp_create)(const char *path, mode_t mode, void *arg);
typedef void* (*fp_open)(const char *path, int flags, void *arg);
typedef int (*fp_read)(void *fd, void *buf, size_t size, void *arg);
typedef int (*fp_write)(void *fd, void *buf, size_t size, void *arg);
typedef int (*fp_seek)(void *fd, off_t offset, int whence, void *arg);
typedef int (*fp_delete)(const char *path, void *arg);
typedef int (*fp_close)(void *fd, void *arg);

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
    void *ops_arg;
} fp_ctx;

bool fp_init(fp_ctx *ctx, fp_ops *ops, void *ops_arg);
int fp_listen(fp_ctx *ctx, int port);
bool fp_run(fp_ctx *ctx, int listen_sd);

#endif
