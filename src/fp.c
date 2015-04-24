#include "fp.h"
#include <ss.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <assert.h>
#include <errno.h>

// 現状の仕様
// 読み込みか書き込みどっちか専用で open

#define FP_NUM_CMDS 1
#define FP_DEFAULT_BUFSIZE (1024 * 16)

#define FP_CMD_NAME_LEN sizeof(uint64_t)
#define FP_CMD(name) (*((uint64_t*)(name)))
#define FP_CMD_OPEN FP_CMD("open\0\0\0\0")
#define FP_CMD_CREATE FP_CMD("create\0\0")
#define FP_CMD_READ FP_CMD("read\0\0\0\0")
#define FP_CMD_WRITE FP_CMD("write\0\0\0")
#define FP_CMD_SEEK FP_CMD("seek\0\0\0\0")
#define FP_CMD_CLOSE FP_CMD("close\0\0\0")
#define FP_CMD_DELETE FP_CMD("delete\0\0")
#define FP_CMD_SIZE FP_CMD("size\0\0\0\0")
#define FP_CMD_BUFSIZE FP_CMD("bufsize\0")

#define ERROR_OPEN_FAILURE "open_failure"
#define ERROR_INVALID_OPEN_FLAGS "invalid_open_flags"
#define ERROR_CREATE_FAILURE "create_failure"
#define ERROR_DELETE_FAILURE "delete_failure"
#define ERROR_READ_FAILURE "read_failure"
#define ERROR_WRITE_FAILURE "write_failure"
#define ERROR_SEEK_FAILURE "seek_failure"
#define ERROR_INVALID_SEEK_WHENCE "invalid_seek_whence"
#define ERROR_SIZE_FAILURE "size_failure"
#define ERROR_BUFSIZE_FAILURE "bufsize_failure"

#define OPEN_FLAG_RDONLY (0x01 << 0)
#define OPEN_FLAG_WRONLY (0x01 << 1)

#define FP_SEEK_WHENCE_SET 1
#define FP_SEEK_WHENCE_CUR 2
#define FP_SEEK_WHENCE_END 3

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline bool is_little_endian(void) {
    static const uint8_t d[4] = {0x01, 0x02, 0x03, 0x04};
    uint32_t h = *((uint32_t*)(d));
    uint32_t le = 0x04030201;
    return h == le;
}

static inline uint64_t reverse_if_little_endian(uint64_t n0) {
    if (is_little_endian()) {
        uint8_t *n0v = (uint8_t*)(&n0);
        uint8_t n1v[8];
        int i;
        for (i = 0; i < 8; i++) {
            n1v[8 - i - 1] = n0v[i];
        }
        return *((uint64_t*)(n1v));
    } else {
        return n0;
    }
}

#ifndef ntohll
static inline uint64_t ntohll(uint64_t n) {
    return reverse_if_little_endian(n);
}
#endif

#ifndef htonll
static inline uint64_t htonll(uint64_t h) {
    return reverse_if_little_endian(h);
}
#endif

typedef struct __fp_session {
    int sd;
    void *fd;
    char *path;
    char *buf;
    int bufsize;
    int bufidx;
    ss_logger *logger;
    fp_ops *ops;
    void *ops_arg;
} fp_session;

static bool readn(fp_session *session, void *buf, int n) {
    int sd = session->sd;
    int ret = read(sd, buf, n);
    ss_logger *logger = session->logger;

    // TODO 0 か -1 を返すまで読み込みを繰り返す。
    if (ret < n) {
        ss_err(logger, "failed to read %d bytes from client\n", n);
        return false;
    } else {
        return true;
    }
}

static bool writen(fp_session *session, const void *buf, int n) {
    int sd = session->sd;
    int ret = write(sd, buf, n);
    ss_logger *logger = session->logger;

    // TODO -1 を返すまで書き込みを繰り返す。
    if (ret < n) {
        ss_err(logger, "failed to write %d bytes to client\n", n);
        return false;
    } else {
        return true;
    }
}

static uint64_t readcmd(fp_session *session) {
    char buf[FP_CMD_NAME_LEN];

    if (readn(session, buf, FP_CMD_NAME_LEN)) {
        return FP_CMD(buf);
    } else {
        return 0;
    }
}

/**
 * - 入力
 *  - command: open\0\0\0\0 の8バイト固定
 *  - pathlen: pathの長さ、8バイト
 *  - flags: openのモードなどのflag群、8バイト
 *  - path: path文字列
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - open の失敗時はセッションを切る。
 */
static bool session_process_open(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    uint64_t len, flags_fp;
    int flags_sys = 0;
    fp_open op_open = session->ops->open;
    void *ops_arg = session->ops_arg;
    void *fd = NULL;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &len, sizeof(len))) {
        ss_err(logger, "failed to read open path length\n");
        goto err;
    }
    len = ntohll(len);

    if (!readn(session, &flags_fp, sizeof(flags_fp))) {
        ss_err(logger, "failed to read open flags\n");
        goto err;
    }
    flags_fp = ntohll(flags_fp);
    if (flags_fp & OPEN_FLAG_RDONLY) {
        flags_sys |= O_RDONLY;
    } else if (flags_fp & OPEN_FLAG_WRONLY) {
        flags_sys |= O_WRONLY;
    } else {
        errmsg = ERROR_INVALID_OPEN_FLAGS;
        errlen = sizeof(ERROR_INVALID_OPEN_FLAGS) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    assert(buf);
    if (!readn(session, buf, len)) {
        ss_err(logger, "failed to read open path\n");
        goto err;
    }

    path = malloc(len + 1);
    if (!path) {
        ss_err(logger, "failed to allocate memory: %s\n", strerror(errno));
        goto err;
    }
    memcpy(path, buf, len);
    path[len] = '\0';

    fd = op_open(path, flags_sys, ops_arg);
    if (!fd) {
        ss_err(logger, "failed to open %s: %s\n", path, strerror(errno));
        errmsg = ERROR_OPEN_FAILURE;
        errlen = sizeof(ERROR_OPEN_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    assert(!session->path);
    assert(session->fd == NULL);
    session->fd = fd;
    session->path = path;

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }
    return false;
}

/**
 * - 入力
 *  - command: create\0\0 の8バイト固定
 *  - pathlen: pathの長さ、4バイト
 *  - path: path文字列
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - create の失敗時はセッションを切る。
 */
static bool session_process_create(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    unsigned int len;
    fp_create op_create = session->ops->create;
    void *ops_arg = session->ops_arg;
    void *fd = NULL;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &len, sizeof(unsigned int))) {
        ss_err(logger, "failed to read create path length\n");
        goto err;
    }
    len = ntohl(len);

    assert(buf);
    if (!readn(session, buf, len)) {
        ss_err(logger, "failed to read create path\n");
        goto err;
    }

    path = malloc(len + 1);
    if (!path) {
        ss_err(logger, "failed to allocate memory: %s\n", strerror(errno));
        goto err;
    }
    memcpy(path, buf, len);
    path[len] = '\0';

    fd = op_create(path, S_IRUSR | S_IWUSR | S_IRGRP, ops_arg);
    if (!fd) {
        ss_err(logger, "failed to create %s: %s\n", path, strerror(errno));
        errmsg = ERROR_CREATE_FAILURE;
        errlen = sizeof(ERROR_CREATE_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    assert(!session->path);
    assert(session->fd == NULL);
    session->fd = fd;
    session->path = path;

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }
    return false;
}

/**
 * - 入力
 *  - command: delete\0\0 の8バイト固定
 *  - pathlen: pathの長さ、4バイト
 *  - path: path文字列
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - delete の失敗時はセッションを切る。
 */
static bool session_process_delete(fp_session *session) {
    char *buf = session->buf;
    ss_logger *logger = session->logger;
    unsigned int len;
    fp_delete op_delete = session->ops->delete;
    void *ops_arg = session->ops_arg;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &len, sizeof(unsigned int))) {
        ss_err(logger, "failed to read delete path length\n");
        goto err;
    }
    len = ntohl(len);

    assert(buf);
    if (!readn(session, buf, len)) {
        ss_err(logger, "failed to read delete path\n");
        goto err;
    }
    buf[len] = '\0';

    if (op_delete(buf, ops_arg) < 0) {
        ss_err(logger, "failed to delete %s: %s\n", buf, strerror(errno));
        errmsg = ERROR_DELETE_FAILURE;
        errlen = sizeof(ERROR_DELETE_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    return false;
}


/**
 * - 入力
 *  - command: read\0\0\0\0 の8バイト固定
 *  - len: 読み込む長さ、8バイト
 * - 出力
 *  - 以下のチャンクを繰り返し返す。len = 0 の場合はチャンク列の末端を示す。
 *   - チャンク長の8バイト整数
 *   - チャンク長分のデータ
 *  - 1つめのチャンク長が0の場合はEOFであることを示す。
 *  - read に失敗した場合はセッションを切る。
 */
static bool session_process_read(fp_session *session) {
    char *buf = session->buf;
    int bufsize = session->bufsize;
    ss_logger *logger = session->logger;
    uint64_t len, idx;
    fp_read op_read = session->ops->read;
    void *ops_arg = session->ops_arg;
    void *fd = session->fd;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, fin = 0;

    if (!readn(session, &len, sizeof(len))) {
        ss_err(logger, "failed to read read length\n");
        goto err;
    }
    len = ntohll(len);

    assert(buf);
    idx = 0;
    while (idx < len) {
        int s = min(len - idx, bufsize);
        int64_t reth = op_read(fd, buf, s, ops_arg);
        int64_t retn = htonll(reth);

        if (reth < 0) {
            ss_err(logger, "failed to read data: %s\n", strerror(errno));
            errmsg = ERROR_READ_FAILURE;
            errlen = sizeof(ERROR_READ_FAILURE) - 1;
            errhdr = htonll(-errlen);
            goto err;
        }
        if (reth == 0) { // EOF
            break;
        }
        // TODO writev でまとめて書き込む
        if (!writen(session, &retn, sizeof(retn))) {
            ss_err(logger, "failed to write response header\n", strerror(errno));
            goto err;
        }
        if (!writen(session, buf, reth)) {
            ss_err(logger, "failed to write response data\n", strerror(errno));
            goto err;
        }
        idx += reth;
    }
    if (!writen(session, &fin, sizeof(fin))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    return false;
}

/**
 * - 入力
 *  - command: write\0\0\0 の8バイト固定
 *  - datalen: dataの長さ、8バイト
 *  - data: writeするデータ
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - write の失敗時はセッションを切る。
 */
static bool session_process_write(fp_session *session) {
    char *buf = session->buf;
    int bufsize = session->bufsize;
    ss_logger *logger = session->logger;
    uint64_t len, idx;
    fp_write op_write = session->ops->write;
    void *ops_arg = session->ops_arg;
    void *fd = session->fd;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &len, sizeof(uint64_t))) {
        ss_err(logger, "failed to read write data length\n");
        goto err;
    }
    len = ntohll(len);

    assert(buf);
    for (idx = 0; idx < len; idx += bufsize) {
        int s = min(len - idx, bufsize);
        if (!readn(session, buf, s)) {
            ss_err(logger, "failed to read write data\n");
            goto err;
        }
        if (op_write(fd, buf, s, ops_arg) < 0) {
            ss_err(logger, "failed to write data: %s\n", strerror(errno));
            errmsg = ERROR_WRITE_FAILURE;
            errlen = sizeof(ERROR_WRITE_FAILURE) - 1;
            errhdr = htonll(-errlen);
            goto err;
        }
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    return false;
}

/**
 * - 入力
 *  - command: seek\0\0\0\0 の8バイト固定
 *  - type: seek のタイプ、4バイト
 *   - offset: シーク先のオフセット、8バイト
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - seek の失敗時はセッションを切る。
 */
static bool session_process_seek(fp_session *session) {
    ss_logger *logger = session->logger;
    int whence_fp, whence_sys;
    int64_t offset_fp;
    off_t offset_sys;
    fp_seek op_seek = session->ops->seek;
    void *ops_arg = session->ops_arg;
    void *fd = session->fd;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &whence_fp, sizeof(whence_fp))) {
        ss_err(logger, "failed to read seek whence\n");
        goto err;
    }
    whence_fp = ntohl(whence_fp);
    switch (whence_fp) {
        case FP_SEEK_WHENCE_SET:
            whence_sys = SEEK_SET;
            break;
        case FP_SEEK_WHENCE_CUR:
            whence_sys = SEEK_CUR;
            break;
        case FP_SEEK_WHENCE_END:
            whence_sys = SEEK_END;
            break;
        default:
            ss_err(logger, "invalid whence %d\n", whence_fp);
            errmsg = ERROR_INVALID_SEEK_WHENCE;
            errlen = sizeof(ERROR_INVALID_SEEK_WHENCE) - 1;
            errhdr = htonll(-errlen);
            break;
    }

    if (!readn(session, &offset_fp, sizeof(offset_fp))) {
        ss_err(logger, "failed to read seek offset\n");
        goto err;
    }
    offset_fp = ntohll(offset_fp);
    offset_sys = (off_t)offset_fp;
    if (op_seek(fd, offset_sys, whence_sys, ops_arg) < 0) {
        ss_err(logger,
               "failed to seek: whence = %d, offset = %lld, error = %s\n",
               whence_fp,
               offset_fp,
               strerror(errno));
        errmsg = ERROR_SEEK_FAILURE;
        errlen = sizeof(ERROR_SEEK_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    return false;
}

/**
 * - 入力
 *  - command: size\0\0\0\0 の8バイト固定
 * - 出力
 *  - 8バイトでファイルサイズを返す
 */
static bool session_process_size(fp_session *session) {
    ss_logger *logger = session->logger;
    fp_size op_size = session->ops->size;
    void *ops_arg = session->ops_arg;
    void *fd = session->fd;
    const char *errmsg = NULL;
    int64_t errlen, errhdr;
    int64_t rsphdr = htonll(sizeof(int64_t)), hsize, nsize;

    hsize = op_size(fd, ops_arg);
    if (hsize < 0) {
        ss_err(logger,
                "failed to get file size of %s: %s\n",
                session->path,
                strerror(errno));
        errmsg = ERROR_SIZE_FAILURE;
        errlen = sizeof(ERROR_SIZE_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    nsize = htonll(hsize);
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }
    if (!writen(session, &nsize, sizeof(nsize))) {
        ss_err(logger, "failed to write response data\n", strerror(errno));
        goto err;
    }

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    return false;
}

/**
 * - 入力
 *  - command: bufsize\0 の8バイト固定
 *  - datalen: 新たに設定するバッファサイズ、8バイト
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - 失敗時はセッションを切る。
 */
static bool session_process_bufsize(fp_session *session) {
    ss_logger *logger = session->logger;
    int64_t bufsize, rsphdr = 0;
    int64_t errlen, errhdr;
    const char *errmsg = NULL;

    if (!readn(session, &bufsize, sizeof(bufsize))) {
        ss_err(logger, "failed to read seek whence\n");
        goto err;
    }
    bufsize = ntohll(bufsize);

    free(session->buf);
    session->bufsize = bufsize;
    session->bufidx = 0;
    session->buf = malloc(bufsize);
    if (!session->buf) {
        ss_err(logger, "failed to reallocate client buffer\n");
        errmsg = ERROR_BUFSIZE_FAILURE;
        errlen = sizeof(ERROR_BUFSIZE_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    return false;
}

static bool session_start(fp_session *session) {
    uint64_t cmd = 0;
    ss_logger *logger = session->logger;

    cmd = readcmd(session);
    if (!cmd) {
        ss_err(logger, "failed to read command\n");
        goto err;
    }

    if (cmd == FP_CMD_OPEN) {
        if (!session_process_open(session)) {
            ss_err(logger, "open failed\n");
            goto err;
        }
    } else if (cmd == FP_CMD_CREATE) {
        if (!session_process_create(session)) {
            ss_err(logger, "create failed\n");
            goto err;
        }
    } else if (cmd == FP_CMD_DELETE) {
        if (!session_process_delete(session)) {
            ss_err(logger, "delete failed\n");
            goto err;
        }
    } else {
        ss_err(logger, "unexpected command given: command = %llx\n", cmd);
        goto err;
    }

    return true;

err:
    return false;
}

static void cbk(ss_logger *logger, int sd, void *arg) {
    fp_session session;
    fp_ctx *ctx = arg;
    fp_ops *ops = &ctx->ops;
    void *ops_arg = ctx->ops_arg;
    uint64_t cmd = 0;

    session.ops = ops;
    session.ops_arg = ops_arg;
    session.logger = logger;
    session.sd = sd;
    session.fd = NULL;
    session.path = NULL;
    session.bufsize = FP_DEFAULT_BUFSIZE;
    session.bufidx = 0;
    session.buf = malloc(FP_DEFAULT_BUFSIZE);
    if (!session.buf) {
        ss_err(logger, "failed to allocate client buffer\n");
        goto out;
    }

    if (!session_start(&session)) {
        goto out;
    }

    if (session.fd == NULL) {
        // delete などの場合は特に続けて行える操作がないので接続を切る。
        goto out;
    }

    while ((cmd = readcmd(&session)) != 0) {
        if (cmd == FP_CMD_READ) {
            if (!session_process_read(&session)) {
                ss_err(logger, "failed to process read command\n");
                goto out;
            }
        } else if (cmd == FP_CMD_WRITE) {
            if (!session_process_write(&session)) {
                ss_err(logger, "failed to process write command\n");
                goto out;
            }
        } else if (cmd == FP_CMD_SEEK) {
            if (!session_process_seek(&session)) {
                ss_err(logger, "failed to process seek command\n");
                goto out;
            }
        } else if (cmd == FP_CMD_SIZE) {
            if (!session_process_size(&session)) {
                ss_err(logger, "failed to process size command\n");
                goto out;
            }
        } else if (cmd == FP_CMD_BUFSIZE) {
            if (!session_process_bufsize(&session)) {
                ss_err(logger, "failed to process bufsize command\n");
                goto out;
            }
        } else if (cmd == FP_CMD_CLOSE) {
            goto out;
        } else {
            ss_err(logger, "unknown command given, cmd = %x\n", cmd);
            goto out;
        }
    }

out:
    if (session.buf) {
        free(session.buf);
    }
    if (session.path) {
        free(session.path);
    }
    if (session.fd) {
        ops->close(session.fd, ops_arg);
    }
}

bool fp_init(fp_ctx *ctx, fp_ops *ops, void *ops_arg) {
    ctx->ops = *ops;
    ctx->ops_arg = ops_arg;
    return ss_init(&ctx->ss, cbk, ctx);
}

int fp_listen(fp_ctx *ctx, int port) {
    return ss_listen(&ctx->ss, port);
}

bool fp_run(fp_ctx *ctx, int listen_sd) {
    return ss_run(&ctx->ss, listen_sd);
}
