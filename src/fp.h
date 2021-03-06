#ifndef __FP_SRC_FP_H__
#define __FP_SRC_FP_H__

#include <ss.h>

#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define FP_LOG_FATAL SS_LOG_FATAL
#define FP_LOG_ERROR SS_LOG_ERROR
#define FP_LOG_WARN  SS_LOG_WARN
#define FP_LOG_INFO  SS_LOG_INFO
#define FP_LOG_DEBUG SS_LOG_DEBUG
#define FP_LOG_TRACE SS_LOG_TRACE

typedef void* (*fp_create)(const char *path, mode_t mode, void *arg);
typedef void* (*fp_open)(const char *path, int flags, void *arg);
typedef ssize_t (*fp_read)(void *fd, void *buf, size_t size, void *arg);
typedef ssize_t (*fp_pread)(void *fd, void *buf, size_t size, off_t offset, void *arg);
typedef ssize_t (*fp_write)(void *fd, void *buf, size_t size, void *arg);
typedef off_t (*fp_seek)(void *fd, off_t offset, int whence, void *arg);
typedef int64_t (*fp_size)(void *fd, void *arg);
typedef int64_t (*fp_df)(void *arg);
typedef int (*fp_delete)(const char *path, void *arg);
typedef int (*fp_close)(void *fd, void *arg);

typedef struct __fp_ops {
    fp_create create;
    fp_open open;
    fp_read read;
    fp_write write;
    fp_seek seek;
    fp_pread pread;
    fp_size size;
    fp_df df;
    fp_close close;
    fp_delete delete;
} fp_ops;

typedef struct __fp_ctx {
    ss_ctx ss;
    fp_ops ops;
    void *ops_arg;
    int bufsize;
} fp_ctx;

typedef void (*fp_logger)(void *arg, const char *format, va_list ap);

bool fp_init(fp_ctx *ctx, fp_ops *ops, void *ops_arg);
void fp_set_logger(fp_ctx *ctx, fp_logger logger, void *arg);
void fp_set_log_level(fp_ctx *ctx, int level);
void fp_set_thread_cache_size(fp_ctx *ctx, int size);
int fp_listen_tcp(fp_ctx *ctx, const char *ip, int port);
int fp_listen_uds(fp_ctx *ctx, const char *path);
bool fp_run(fp_ctx *ctx, int listen_sd);

#endif
