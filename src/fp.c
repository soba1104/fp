#include "fp.h"
#include <ss.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <assert.h>
#include <errno.h>

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

// 現状の仕様
// 読み込みか書き込みどっちか専用で open

#define FP_NUM_CMDS 1
#define FP_DEFAULT_BUFSIZE (1024 * 16)

#define FP_CMD_NAME_LEN sizeof(uint64_t)
#define FP_CMD(name) (*((uint64_t*)(name)))
#define FP_CMD_OPEN FP_CMD("open\0\0\0\0")
#define FP_CMD_CREATE FP_CMD("create\0\0")
#define FP_CMD_READ FP_CMD("read\0\0\0\0")
#define FP_CMD_PREAD FP_CMD("pread\0\0\0")
#define FP_CMD_WRITE FP_CMD("write\0\0\0")
#define FP_CMD_PWRITE FP_CMD("pwrite\0\0")
#define FP_CMD_SEEK FP_CMD("seek\0\0\0\0")
#define FP_CMD_CLOSE FP_CMD("close\0\0\0")
#define FP_CMD_DELETE FP_CMD("delete\0\0")
#define FP_CMD_SIZE FP_CMD("size\0\0\0\0")
#define FP_CMD_BUFSIZE FP_CMD("bufsize\0")
#define FP_CMD_DF FP_CMD("df\0\0\0\0\0\0")

#define ERROR_OPEN_FAILURE "open_failure"
#define ERROR_INVALID_OPEN_FLAGS "invalid_open_flags"
#define ERROR_CREATE_FAILURE "create_failure"
#define ERROR_DELETE_FAILURE "delete_failure"
#define ERROR_READ_FAILURE "read_failure"
#define ERROR_WRITE_FAILURE "write_failure"
#define ERROR_SEEK_FAILURE "seek_failure"
#define ERROR_INVALID_SEEK_WHENCE "invalid_seek_whence"
#define ERROR_SIZE_FAILURE "size_failure"
#define ERROR_BUFSIZE_REALLOC_FAILURE "bufsize_realloc_failure"
#define ERROR_BUFSIZE_SEEK_FAILURE "bufsize_seek_failure"
#define ERROR_DF_FAILURE "df_failure"
#define ERROR_CLOSE_FAILURE "close_failure"
#define ERROR_TOO_LONG_FILEPATH "too_long_filepath"

#define OPEN_FLAG_READ 'r'
#define OPEN_FLAG_WRITE 'w'

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
    char *buf;
    int bufsize;
    int bufstart;
    int bufend;
    off_t pos;
    ss_logger *logger;
    fp_ops *ops;
    void *ops_arg;
} fp_session;

static bool session_process_seek(fp_session *session, bool need_response);

static bool readn(fp_session *session, void *buf, int n) {
    int sd = session->sd;
    int idx = 0;

    while (idx < n) {
        int ret = read(sd, buf + idx, n - idx);
        if (ret <= 0) {
            break;
        }
        idx += ret;
    }

    if (idx < n) {
        ss_err(session->logger, "failed to read %d bytes from client\n", n);
        return false;
    } else {
        return true;
    }
}

static bool writen(fp_session *session, const void *buf, int n) {
    int sd = session->sd;
    int idx = 0;

    while (idx < n) {
        int ret = write(sd, buf + idx, n - idx);
        if (ret <= 0) {
            break;
        }
        idx += ret;
    }

    if (idx < n) {
        ss_err(session->logger, "failed to write %d bytes to client\n", n);
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
 *  - flags: openのモードなどのflag群、8バイト
 *  - pathlen: pathの長さ、8バイト
 *  - path: path文字列
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - open の失敗時はセッションを切る。
 */
static bool session_process_open(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    char flags_fp[sizeof(uint64_t)];
    ss_logger *logger = session->logger;
    uint64_t len;
    int flags_sys = 0, i;
    fp_open op_open = session->ops->open;
    void *ops_arg = session->ops_arg;
    void *fd = NULL;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, flags_fp, sizeof(flags_fp))) {
        ss_err(logger, "failed to read open flags\n");
        goto err;
    }
    if (flags_fp[0] == '\0') {
        errmsg = ERROR_INVALID_OPEN_FLAGS;
        errlen = sizeof(ERROR_INVALID_OPEN_FLAGS) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    for (i = 0; flags_fp[i] != '\0' && i < sizeof(flags_fp); i++) {
        char flag = flags_fp[i];
        switch (flag) {
            case OPEN_FLAG_READ:
                if (flags_sys & O_RDWR) {
                    // nothing to do
                } else if (flags_sys & O_WRONLY) {
                    flags_sys &= ~O_WRONLY;
                    flags_sys |= O_RDWR;
                } else {
                    flags_sys |= O_RDONLY;
                }
                break;
            case OPEN_FLAG_WRITE:
                if (flags_sys & O_RDWR) {
                    // nothing to do
                } else if (flags_sys & O_RDONLY) {
                    flags_sys &= ~O_RDONLY;
                    flags_sys |= O_RDWR;
                } else {
                    flags_sys |= O_WRONLY;
                }
                break;
            default:
                errmsg = ERROR_INVALID_OPEN_FLAGS;
                errlen = sizeof(ERROR_INVALID_OPEN_FLAGS) - 1;
                errhdr = htonll(-errlen);
                goto err;
        }
    }

    if (!readn(session, &len, sizeof(len))) {
        ss_err(logger, "failed to read open path length\n");
        goto err;
    }
    len = ntohll(len);
    if (len >= session->bufsize) {
        errmsg = ERROR_TOO_LONG_FILEPATH;
        errlen = sizeof(ERROR_TOO_LONG_FILEPATH) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    assert(buf);
    if (!readn(session, buf, len)) {
        ss_err(logger, "failed to read open path\n");
        goto err;
    }
    buf[len] = '\0';

    fd = op_open(buf, flags_sys, ops_arg);
    if (!fd) {
        ss_err(logger, "failed to open %s: %s\n", buf, strerror(errno));
        errmsg = ERROR_OPEN_FAILURE;
        errlen = sizeof(ERROR_OPEN_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    assert(session->fd == NULL);
    session->fd = fd;

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
 *  - pathlen: pathの長さ、8バイト
 *  - path: path文字列
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - create の失敗時はセッションを切る。
 */
static bool session_process_create(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    uint64_t len;
    fp_create op_create = session->ops->create;
    void *ops_arg = session->ops_arg;
    void *fd = NULL;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &len, sizeof(len))) {
        ss_err(logger, "failed to read create path length\n");
        goto err;
    }
    len = ntohll(len);
    if (len >= session->bufsize) {
        errmsg = ERROR_TOO_LONG_FILEPATH;
        errlen = sizeof(ERROR_TOO_LONG_FILEPATH) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    assert(buf);
    if (!readn(session, buf, len)) {
        ss_err(logger, "failed to read create path\n");
        goto err;
    }
    buf[len] = '\0';

    fd = op_create(buf, S_IRUSR | S_IWUSR | S_IRGRP, ops_arg);
    if (!fd) {
        ss_err(logger, "failed to create %s: %s\n", buf, strerror(errno));
        errmsg = ERROR_CREATE_FAILURE;
        errlen = sizeof(ERROR_CREATE_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    assert(session->fd == NULL);
    session->fd = fd;

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
 *  - pathlen: pathの長さ、8バイト
 *  - path: path文字列
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - delete の失敗時はセッションを切る。
 */
static bool session_process_delete(fp_session *session) {
    char *buf = session->buf;
    ss_logger *logger = session->logger;
    uint64_t len;
    fp_delete op_delete = session->ops->delete;
    void *ops_arg = session->ops_arg;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (!readn(session, &len, sizeof(uint64_t))) {
        ss_err(logger, "failed to read delete path length\n");
        goto err;
    }
    len = ntohll(len);
    if (len >= session->bufsize) {
        errmsg = ERROR_TOO_LONG_FILEPATH;
        errlen = sizeof(ERROR_TOO_LONG_FILEPATH) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

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
    while (true) {
        int64_t require = len - idx;
        int64_t bufrest = session->bufend - session->bufstart;
        int s;

        if (bufrest > 0) {
            int64_t reth = min(require, bufrest);
            int64_t retn = htonll(reth);

            // TODO writev でまとめて書き込む
            if (!writen(session, &retn, sizeof(retn))) {
                ss_err(logger, "failed to write response header\n", strerror(errno));
                goto err;
            }
            if (!writen(session, buf + session->bufstart, reth)) {
                ss_err(logger, "failed to write response data\n", strerror(errno));
                goto err;
            }
            session->bufstart += reth;
            idx += reth;
        }

        if (idx == len) {
            break;
        }
        assert(session->bufstart == session->bufend);
        session->bufstart = 0;
        session->bufend = 0;

        s = op_read(fd, buf, bufsize, ops_arg);
        if (s < 0) {
            ss_err(logger, "failed to read data: %s\n", strerror(errno));
            errmsg = ERROR_READ_FAILURE;
            errlen = sizeof(ERROR_READ_FAILURE) - 1;
            errhdr = htonll(-errlen);
            goto err;
        }
        session->pos += s;
        session->bufend = s;

        if (s == 0) { // EOF
            break;
        }
    }
    if (idx == len) {
        // 指定されたサイズ分送り終わった場合、
        // read に成功したことは自明なので、
        // 読み込み完了のメッセージは送らない。
        goto out;
    }

    if (!writen(session, &fin, sizeof(fin))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }
out:

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
 *  - command: pread\0\0\0 の8バイト固定
 *  - type: seek のタイプ、8バイト
 *  - offset: シーク先のオフセット、8バイト
 *  - len: 読み込む長さ、8バイト
 * - 出力
 *  - 以下のチャンクを繰り返し返す。len = 0 の場合はチャンク列の末端を示す。
 *   - チャンク長の8バイト整数
 *   - チャンク長分のデータ
 *  - 1つめのチャンク長が0の場合はEOFであることを示す。
 *  - seek もしくは read に失敗した場合はセッションを切る。
 */
static bool session_process_pread(fp_session *session) {
    ss_logger *logger = session->logger;
    const char *errmsg = NULL;
    int64_t errlen, errhdr;

    if (!session_process_seek(session, false)) {
        ss_err(logger, "pread: failed to seek: %s\n", strerror(errno));
        errmsg = ERROR_SEEK_FAILURE;
        errlen = sizeof(ERROR_SEEK_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    if (!session_process_read(session)) {
        ss_err(logger, "pread: failed to read: %s\n", strerror(errno));
        errmsg = ERROR_READ_FAILURE;
        errlen = sizeof(ERROR_READ_FAILURE) - 1;
        errhdr = htonll(-errlen);
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
        int r;
        if (!readn(session, buf, s)) {
            ss_err(logger, "failed to read write data\n");
            goto err;
        }
        if ((r = op_write(fd, buf, s, ops_arg)) < 0) {
            ss_err(logger, "failed to write data: %s\n", strerror(errno));
            errmsg = ERROR_WRITE_FAILURE;
            errlen = sizeof(ERROR_WRITE_FAILURE) - 1;
            errhdr = htonll(-errlen);
            goto err;
        }
        session->pos += r;
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
 *  - command: pwrite\0\0\0 の8バイト固定
 *  - type: seek のタイプ、8バイト
 *  - offset: シーク先のオフセット、8バイト
 *  - datalen: dataの長さ、8バイト
 *  - data: writeするデータ
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - seek もしくは write に失敗した場合はセッションを切る。
 */
static bool session_process_pwrite(fp_session *session) {
    ss_logger *logger = session->logger;
    const char *errmsg = NULL;
    int64_t errlen, errhdr;

    if (!session_process_seek(session, false)) {
        ss_err(logger, "pwrite: failed to seek: %s\n", strerror(errno));
        errmsg = ERROR_SEEK_FAILURE;
        errlen = sizeof(ERROR_SEEK_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    if (!session_process_write(session)) {
        ss_err(logger, "pwrite: failed to write: %s\n", strerror(errno));
        errmsg = ERROR_WRITE_FAILURE;
        errlen = sizeof(ERROR_WRITE_FAILURE) - 1;
        errhdr = htonll(-errlen);
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
 * seek 先がバッファ内に含まれているかどうかを判定する。
 * - 引数
 *  - bufend: session->bufend の値
 *  - offset: ファイル先頭からの seek の目標位置と session->pos の相対距離
 *            ファイル先頭からの seek の目標位置 - session->pos
 *            session->pos に対して相対的にどれくらい seek すべきかという値
 */
bool is_seek_pos_in_buffer(off_t bufend, off_t offset) {
    return (offset <= 0) && ((-offset) <= bufend);
}

/**
 * - 入力
 *  - command: seek\0\0\0\0 の8バイト固定
 *  - type: seek のタイプ、8バイト
 *  - offset: シーク先のオフセット、8バイト
 * - 出力
 *  - シーク後のファイル先頭からの位置を8バイトで返す。
 *  - seek の失敗時はセッションを切る。
 */
static bool session_process_seek(fp_session *session, bool need_response) {
    ss_logger *logger = session->logger;
    int64_t whence_fp;
    int whence_sys;
    int64_t offset_fp;
    off_t offset_sys;
    fp_seek op_seek = session->ops->seek;
    void *ops_arg = session->ops_arg;
    void *fd = session->fd;
    const char *errmsg = NULL;
    uint64_t response;
    int64_t errlen, errhdr, rsphdr = htonll(sizeof(response));
    off_t newpos;

    if (!readn(session, &whence_fp, sizeof(whence_fp))) {
        ss_err(logger, "failed to read seek whence\n");
        goto err;
    }
    whence_fp = ntohll(whence_fp);
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
    if (whence_fp == FP_SEEK_WHENCE_CUR) {
        int readahead = session->bufend - session->bufstart;
        offset_fp -= readahead;
        offset_sys -= readahead;
        if (is_seek_pos_in_buffer(session->bufend, offset_sys)) {
            session->bufstart = session->bufend + offset_fp;
            goto out;
        }
    } else if (whence_fp == FP_SEEK_WHENCE_SET) {
        off_t relative_offset = offset_sys - session->pos;
        if (is_seek_pos_in_buffer(session->bufend, relative_offset)) {
            session->bufstart = session->bufend + relative_offset;
            goto out;
        }
    }

    if ((newpos = op_seek(fd, offset_sys, whence_sys, ops_arg)) < 0) {
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
    session->bufstart = 0;
    session->bufend = 0;
    session->pos = newpos;
out:
    if (need_response) {
        if (!writen(session, &rsphdr, sizeof(rsphdr))) {
            ss_err(logger, "failed to write response header\n", strerror(errno));
            goto err;
        }
        response = htonll(session->pos - (session->bufend - session->bufstart));
        if (!writen(session, &response, sizeof(response))) {
            ss_err(logger, "failed to write response\n", strerror(errno));
            goto err;
        }
    }

    return true;

err:
    if (need_response) {
        if (errmsg) {
            writen(session, &errhdr, sizeof(errhdr));
            writen(session, errmsg, errlen);
        }
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
                "failed to get file size: %s\n",
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
    int64_t newbufsize, oldbufsize, rsphdr = 0;
    int64_t errlen, errhdr;
    const char *errmsg = NULL;
    char *newbuf = NULL;

    if (!readn(session, &newbufsize, sizeof(newbufsize))) {
        ss_err(logger, "failed to read new buffer size");
        goto err;
    }
    newbufsize = ntohll(newbufsize);
    oldbufsize = session->bufsize;

    newbuf = realloc(session->buf, newbufsize);
    if (!newbuf) {
        ss_err(logger, "failed to reallocate client buffer\n");
        errmsg = ERROR_BUFSIZE_REALLOC_FAILURE;
        errlen = sizeof(ERROR_BUFSIZE_REALLOC_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }
    session->buf = newbuf;
    session->bufsize = newbufsize;

    if (newbufsize < oldbufsize && session->bufend > 0) {
        // 要求サイズが現在のバッファサイズより小さかった場合は、
        // バッファ末尾の値が realloc によって破棄されてしまう。
        // ファイルポインタは現在のバッファの終端よりも先を指しているので、
        // クライアントが読んでいる位置まで seek してバッファを破棄する。
        fp_seek op_seek = session->ops->seek;
        void *ops_arg = session->ops_arg;
        int bufrest = session->bufend - session->bufstart;
        off_t newpos, offset;

        assert(session->fd != NULL);
        offset = session->pos - bufrest;
        if ((newpos = op_seek(session->fd, offset, SEEK_SET, ops_arg)) < 0) {
            ss_err(logger, "failed to reset position\n");
            errmsg = ERROR_BUFSIZE_SEEK_FAILURE;
            errlen = sizeof(ERROR_BUFSIZE_SEEK_FAILURE) - 1;
            errhdr = htonll(-errlen);
            goto err;
        }
        assert(offset == newpos);
        session->pos = newpos;
        session->bufstart = 0;
        session->bufend = 0;
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
 *  - command: df\0\0\0\0\0\0 の8バイト固定
 * - 出力
 *  - 8バイトでdisk空き容量を返す
 */
static bool session_process_df(fp_session *session) {
    ss_logger *logger = session->logger;
    fp_df op_df = session->ops->df;
    void *ops_arg = session->ops_arg;
    const char *errmsg = NULL;
    int64_t errlen, errhdr;
    int64_t rsphdr = htonll(sizeof(int64_t)), hdf, ndf;

    hdf = op_df(ops_arg);
    if (hdf < 0) {
        ss_err(logger, "failed to get disk free: %s\n", strerror(errno));
        errmsg = ERROR_DF_FAILURE;
        errlen = sizeof(ERROR_DF_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    ndf = htonll(hdf);
    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }
    if (!writen(session, &ndf, sizeof(ndf))) {
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
 * fd および buffer 管理に使用する状態をクリアする。
 */
static void clear_fd_and_buffer_state(fp_session *session) {
    session->fd = NULL;
    session->pos = 0;
    session->bufstart = 0;
    session->bufend = 0;
}

/**
 * - 入力
 *  - command: close\0\0\0 の8バイト固定
 * - 出力
 *  - 常に8バイトの0を返す。
 *  - close に失敗した場合はセッションを切る。
 */
static bool session_process_close(fp_session *session) {
    ss_logger *logger = session->logger;
    fp_close op_close = session->ops->close;
    void *ops_arg = session->ops_arg;
    void *fd = session->fd;
    const char *errmsg = NULL;
    int64_t errlen, errhdr, rsphdr = 0;

    if (op_close(fd, ops_arg) < 0) {
        ss_err(logger, "failed to close: %s\n", strerror(errno));
        errmsg = ERROR_CLOSE_FAILURE;
        errlen = sizeof(ERROR_CLOSE_FAILURE) - 1;
        errhdr = htonll(-errlen);
        goto err;
    }

    if (!writen(session, &rsphdr, sizeof(rsphdr))) {
        ss_err(logger, "failed to write response header\n", strerror(errno));
        goto err;
    }

    clear_fd_and_buffer_state(session);

    return true;

err:
    if (errmsg) {
        writen(session, &errhdr, sizeof(errhdr));
        writen(session, errmsg, errlen);
    }

    clear_fd_and_buffer_state(session);

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
    } else if (cmd == FP_CMD_DF) {
        if (!session_process_df(session)) {
            ss_err(logger, "failed to process df command\n");
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
    int nodelay = 1;

    session.ops = ops;
    session.ops_arg = ops_arg;
    session.logger = logger;
    session.sd = sd;
    session.fd = NULL;
    session.pos = 0;
    session.bufsize = ctx->bufsize > 0 ? ctx->bufsize : FP_DEFAULT_BUFSIZE;
    session.bufstart = 0;
    session.bufend = 0;
    session.buf = malloc(session.bufsize);
    if (!session.buf) {
        ss_err(logger, "failed to allocate client buffer\n");
        goto end;
    }

    if (setsockopt(session.sd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
        ss_err(logger, "failed to set nodelay: %s\n", strerror(errno));
        goto end;
    }

    if (!session_start(&session)) {
        goto end;
    }

    if (session.fd == NULL) {
        // delete などの場合は特に続けて行える操作がないので接続を切る。
        goto end;
    }

    while ((cmd = readcmd(&session)) != 0) {
        if (cmd == FP_CMD_READ) {
            if (!session_process_read(&session)) {
                ss_err(logger, "failed to process read command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_PREAD) {
            if (!session_process_pread(&session)) {
                ss_err(logger, "failed to process read command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_WRITE) {
            if (!session_process_write(&session)) {
                ss_err(logger, "failed to process write command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_PWRITE) {
            if (!session_process_pwrite(&session)) {
                ss_err(logger, "failed to process pwrite command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_SEEK) {
            if (!session_process_seek(&session, true)) {
                ss_err(logger, "failed to process seek command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_SIZE) {
            if (!session_process_size(&session)) {
                ss_err(logger, "failed to process size command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_BUFSIZE) {
            if (!session_process_bufsize(&session)) {
                ss_err(logger, "failed to process bufsize command\n");
                goto end;
            }
        } else if (cmd == FP_CMD_CLOSE) {
            if (!session_process_close(&session)) {
                ss_err(logger, "failed to process close command\n");
            }
            goto end;
        } else {
            ss_err(logger, "unknown command given, cmd = %x\n", cmd);
            goto end;
        }
    }

end:
    if (session.buf) {
        free(session.buf);
    }
    if (session.fd) {
        ops->close(session.fd, ops_arg);
    }
}

bool fp_init(fp_ctx *ctx, fp_ops *ops, void *ops_arg) {
    ctx->ops = *ops;
    ctx->ops_arg = ops_arg;
    ctx->bufsize = 0;
    return ss_init(&ctx->ss, cbk, ctx);
}

void fp_set_logger(fp_ctx *ctx, fp_logger logger, void *arg) {
    ss_set_logger_cbk(&ctx->ss, logger, arg);
}

void fp_set_log_level(fp_ctx *ctx, int level) {
    ss_set_log_level(&ctx->ss, level);
}

void fp_set_default_bufsize(fp_ctx *ctx, int size) {
    ctx->bufsize = size;
}

void fp_set_thread_cache_size(fp_ctx *ctx, int size) {
    ss_set_thread_cache_size(&ctx->ss, size);
}

int fp_listen_tcp(fp_ctx *ctx, const char *ip, int port) {
    return ss_listen_tcp(&ctx->ss, ip, port);
}

int fp_listen_uds(fp_ctx *ctx, const char *path) {
    return ss_listen_uds(&ctx->ss, path);
}

bool fp_run(fp_ctx *ctx, int listen_sd) {
    return ss_run(&ctx->ss, listen_sd);
}
