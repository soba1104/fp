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
#define FP_DEFAULT_BUFSIZE 200

#define FP_CMD_NAME_LEN sizeof(uint64_t)
#define FP_CMD(name) (*((uint64_t*)(name)))
#define FP_CMD_OPEN FP_CMD("open\0\0\0\0")
#define FP_CMD_CREATE FP_CMD("create\0\0")
#define FP_CMD_READ FP_CMD("read\0\0\0\0")
#define FP_CMD_WRITE FP_CMD("write\0\0\0")
#define FP_CMD_SEEK FP_CMD("seek\0\0\0\0")
#define FP_CMD_CLOSE FP_CMD("close\0\0\0")
#define FP_CMD_DELETE FP_CMD("delete\0\0")

#define OPEN_FLAG_RDONLY (0x01 << 0)
#define OPEN_FLAG_WRONLY (0x01 << 1)

#define FP_SEEK_WHENCE_SET 1
#define FP_SEEK_WHENCE_CUR 2
#define FP_SEEK_WHENCE_END 3

#define min(a, b) ((a) < (b) ? (a) : (b))

#ifndef ntohll
static inline bool is_little_endian(void) {
    static const uint8_t d[4] = {0x01, 0x02, 0x03, 0x04};
    uint32_t h = *((uint32_t*)(d));
    uint32_t le = 0x04030201;
    return h == le;
}

static inline uint64_t ntohll(uint64_t n) {
    if (is_little_endian()) {
        uint8_t *nv = (uint8_t*)(&n);
        uint8_t hv[8];
        int i;
        for (i = 0; i < 8; i++) {
            hv[8 - i - 1] = nv[i];
        }
        return *((uint64_t*)(hv));
    } else {
        return n;
    }
}
#endif

static void mkpdir(const char *path, mode_t mode) {
    char *dir = NULL;
    int len = strlen(path);
    int i;

    dir = malloc(len + 1);
    if (!dir) {
        goto out;
    }
    strcpy(dir, path);

    for (i = len - 1; i >= 0; i--) {
        if (dir[i] == '/') {
            dir[i + 1] = '\0';
            break;
        }
    }
    if (i < 0) {
        goto out;
    }

    for (i = 0; dir[i] != '\0'; i++) {
        if (dir[i] == '/') {
            dir[i] = '\0';
            mkdir(dir, mode);
            dir[i] = '/';
        }
    }

out:
    if (dir) {
        free(dir);
    }
}

typedef struct __fp_session {
    int sd;
    int fd;
    char *path;
    char *buf;
    int bufsize;
    int bufidx;
    ss_logger *logger;
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

static bool writen(fp_session *session, void *buf, int n) {
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
 *  - pathlen: pathの長さ、4バイト
 *  - flags: openのモードなどのflag群、4バイト
 *  - path: path文字列
 * - 出力
 *  - 常に4バイトの0を返す。
 *  - open の失敗時はセッションを切る。
 */
static bool session_process_open(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    unsigned int len, flags_fp;
    int fd = -1, flags_sys = 0, response = 0;

    if (!readn(session, &len, sizeof(unsigned int))) {
        ss_err(logger, "failed to read open path length\n");
        goto err;
    }
    len = ntohl(len);

    if (!readn(session, &flags_fp, sizeof(unsigned int))) {
        ss_err(logger, "failed to read open flags\n");
        goto err;
    }
    flags_fp = ntohl(flags_fp);
    if (flags_fp & OPEN_FLAG_RDONLY) {
        flags_sys |= O_RDONLY;
    } else if (flags_fp & OPEN_FLAG_WRONLY) {
        flags_sys |= O_WRONLY;
    } else {
        ss_err(logger, "invalid open flags %x\n", flags_fp);
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

    fd = open(path, flags_sys);
    if (fd < 0) {
        ss_err(logger, "failed to open %s: %s\n", path, strerror(errno));
        goto err;
    }
    if (!writen(session, &response, sizeof(response))) {
        ss_err(logger, "failed to write open response\n", strerror(errno));
        goto err;
    }

    assert(!session->path);
    assert(session->fd < 0);
    session->fd = fd;
    session->path = path;

    return true;

err:
    if (path) {
        free(path);
    }
    if (fd >= 0) {
        close(fd);
    }

    return false;
}

/**
 * - 入力
 *  - command: create\0\0 の8バイト固定
 *  - pathlen: pathの長さ、4バイト
 *  - path: path文字列
 * - 出力
 *  - 常に4バイトの0を返す。
 *  - create の失敗時はセッションを切る。
 */
static bool session_process_create(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    unsigned int len;
    int fd = -1, response = 0;

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

    // TODO 外から mode を指定できるようにする。
    mkpdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        ss_err(logger, "failed to create %s: %s\n", path, strerror(errno));
        goto err;
    }
    if (!writen(session, &response, sizeof(response))) {
        ss_err(logger, "failed to write create response\n", strerror(errno));
        goto err;
    }

    assert(!session->path);
    assert(session->fd < 0);
    session->fd = fd;
    session->path = path;

    return true;

err:
    if (path) {
        free(path);
    }
    if (fd >= 0) {
        close(fd);
    }

    return false;
}

/**
 * - 入力
 *  - command: delete\0\0 の8バイト固定
 *  - pathlen: pathの長さ、4バイト
 *  - path: path文字列
 * - 出力
 *  - 常に4バイトの0を返す。
 *  - delete の失敗時はセッションを切る。
 */
static bool session_process_delete(fp_session *session) {
    char *buf = session->buf;
    ss_logger *logger = session->logger;
    unsigned int len, response = 0;

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

    if (unlink(buf) < 0) {
        ss_err(logger, "failed to delete %s: %s\n", buf, strerror(errno));
        goto err;
    }
    if (!writen(session, &response, sizeof(response))) {
        ss_err(logger, "failed to write delete response\n", strerror(errno));
        goto err;
    }

    return true;

err:

    return false;
}


/**
 * - 入力
 *  - command: read\0\0\0\0 の8バイト固定
 *  - len: 読み込む長さ、4バイト
 * - 出力
 *  - 以下のチャンクを繰り返し返す。len = 0 の場合はチャンク列の末端を示す。
 *   - チャンク長の4バイト整数
 *   - チャンク長分のデータ
 *  - 1つめのチャンク長が0の場合はEOFであることを示す。
 *  - read に失敗した場合はセッションを切る。
 */
static bool session_process_read(fp_session *session) {
    char *buf = session->buf;
    int bufsize = session->bufsize;
    int fd = session->fd;
    ss_logger *logger = session->logger;
    unsigned int len, idx, fin = 0;

    if (!readn(session, &len, sizeof(unsigned int))) {
        ss_err(logger, "failed to read read length\n");
        goto err;
    }
    len = ntohl(len);

    assert(buf);
    idx = 0;
    while (idx < len) {
        int s = min(len - idx, bufsize);
        int reth = read(fd, buf, s);
        int retn = htonl(reth);

        if (reth < 0) {
            ss_err(logger, "failed to read data: %s\n", strerror(errno));
            goto err;
        }
        if (reth == 0) { // EOF
            break;
        }
        // TODO writev でまとめて書き込む
        if (!writen(session, &retn, sizeof(retn))) {
            ss_err(logger, "failed to response chunk size\n", strerror(errno));
            goto err;
        }
        if (!writen(session, buf, reth)) {
            ss_err(logger, "failed to response read chunk\n", strerror(errno));
            goto err;
        }
        idx += reth;
    }
    if (!writen(session, &fin, sizeof(fin))) {
        ss_err(logger, "failed to response read end marker\n", strerror(errno));
        goto err;
    }

    return true;

err:
    return false;
}

/**
 * - 入力
 *  - command: write\0\0\0 の8バイト固定
 *  - datalen: dataの長さ、4バイト
 *  - data: writeするデータ
 * - 出力
 *  - 常に4バイトの0を返す。
 *  - write の失敗時はセッションを切る。
 */
static bool session_process_write(fp_session *session) {
    char *buf = session->buf;
    int bufsize = session->bufsize;
    int fd = session->fd;
    ss_logger *logger = session->logger;
    unsigned int len, idx, response = 0;

    if (!readn(session, &len, sizeof(unsigned int))) {
        ss_err(logger, "failed to read write data length\n");
        goto err;
    }
    len = ntohl(len);

    assert(buf);
    for (idx = 0; idx < len; idx += bufsize) {
        int s = min(len - idx, bufsize);
        if (!readn(session, buf, s)) {
            ss_err(logger, "failed to read write data\n");
            goto err;
        }
        if (write(fd, buf, s) < 0) {
            ss_err(logger, "failed to write data: %s\n", strerror(errno));
            goto err;
        }
    }
    if (!writen(session, &response, sizeof(response))) {
        ss_err(logger, "failed to write write response\n", strerror(errno));
        goto err;
    }

    return true;

err:
    return false;
}

/**
 * - 入力
 *  - command: seek\0\0\0\0 の8バイト固定
 *  - type: seek のタイプ、4バイト
 *   - offset: シーク先のオフセット、8バイト
 * - 出力
 *  - 常に4バイトの0を返す。
 *  - seek の失敗時はセッションを切る。
 */
static bool session_process_seek(fp_session *session) {
    int fd = session->fd;
    ss_logger *logger = session->logger;
    int whence_fp, whence_sys, response = 0;
    int64_t offset_fp;
    off_t offset_sys;

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
            ss_err(logger, "unknown whence %d\n", whence_fp);
            break;
    }

    if (!readn(session, &offset_fp, sizeof(offset_fp))) {
        ss_err(logger, "failed to read seek offset\n");
        goto err;
    }
    offset_fp = ntohll(offset_fp);
    offset_sys = (off_t)offset_fp;
    if (lseek(fd, offset_sys, whence_sys) < 0) {
        ss_err(logger,
               "failed to seek: whence = %d, offset = %lld, error = %s\n",
               whence_fp,
               offset_fp,
               strerror(errno));
        goto err;
    }
    if (!writen(session, &response, sizeof(response))) {
        ss_err(logger, "failed to write seek response\n", strerror(errno));
        goto err;
    }

    return true;

err:
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
    uint64_t cmd = 0;

    session.logger = logger;
    session.sd = sd;
    session.fd = -1;
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

    if (session.fd < 0) {
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
    if (session.fd >= 0) {
        close(session.fd);
    }
}

bool fp_init(fp_ctx *ctx) {
    return ss_init(&ctx->ss, cbk, NULL);
}

int fp_listen(fp_ctx *ctx, int port) {
    return ss_listen(&ctx->ss, port);
}

bool fp_run(fp_ctx *ctx, int listen_sd) {
    return ss_run(&ctx->ss, listen_sd);
}
