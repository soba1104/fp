#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
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

#define OPEN_FLAG_RDONLY (0x01 << 0)
#define OPEN_FLAG_WRONLY (0x01 << 1)

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

static uint64_t readcmd(fp_session *session) {
    char buf[FP_CMD_NAME_LEN];

    if (readn(session, buf, FP_CMD_NAME_LEN)) {
        return FP_CMD(buf);
    } else {
        return 0;
    }
}

static bool session_process_open(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    unsigned int len, flags_fp;
    int fd = -1, flags_sys = 0;

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

static bool session_process_create(fp_session *session) {
    char *buf = session->buf;
    char *path = NULL;
    ss_logger *logger = session->logger;
    unsigned int len;
    int fd = -1;

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

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL);
    if (fd < 0) {
        ss_err(logger, "failed to create %s: %s\n", path, strerror(errno));
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

static bool session_process_read(fp_session *session) {
    // TODO
    ss_logger *logger = session->logger;
    ss_err(logger, "session_process_read: not implemented\n");
    return false;
}

static bool session_process_write(fp_session *session) {
    // TODO
    ss_logger *logger = session->logger;
    ss_err(logger, "session_process_write: not implemented\n");
    return false;
}

static bool session_process_seek(fp_session *session) {
    // TODO
    ss_logger *logger = session->logger;
    ss_err(logger, "session_process_seek: not implemented\n");
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
    session.bufsize = 0;
    session.bufidx = 0;
    session.buf = malloc(FP_DEFAULT_BUFSIZE);
    if (!session.buf) {
        ss_err(logger, "failed to allocate client buffer\n");
        goto out;
    }

    ss_info(logger, "starting new session...\n");
    if (!session_start(&session)) {
        ss_err(logger, "failed to start session\n");
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

int main(int argc, char **argv) {
    int port;
    ss_ctx *ctx = NULL;

    if (argc < 2) {
        fprintf(stderr, "usage:   fp port\n");
        fprintf(stderr, "example: fp 1234\n");
        goto err;
    }

    port = atoi(argv[1]);
    if (port <= 0) {
        fprintf(stderr, "invalid port number %d\n", port);
        fprintf(stderr, "port number must be greater than 0\n");
        goto err;
    }
    if (port >= 65536) {
        fprintf(stderr, "invalid port number %d\n", port);
        fprintf(stderr, "port number must be less than 65536\n");
        goto err;
    }

    ctx = ss_new(cbk, NULL);
    if (!ss_run(ctx, port)) {
        fprintf(stderr, "failed to start server\n");
        goto err;
    }
    ss_free(ctx);

    return 0;

err:
    if (ctx) {
        ss_free(ctx);
    }
    return -1;
}
