#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <unistd.h>

#include <assert.h>
#include <errno.h>

// 現状の仕様
// 読み込みか書き込みどっちか専用で open

#define FP_NUM_CMDS 1
#define FP_DEFAULT_BUFSIZE 200

#define FP_CMD_NAME_LEN sizeof(uint64_t)
#define FP_CMD(name) (*((uint64_t*)(name)))
#define FP_CMD_OPEN FP_CMD("open\0\0\0\0")

typedef struct __fp_session {
    int sd;
    int fd;
    char *path;
    char *buf;
    int bufsize;
    int bufidx;
} fp_session;

typedef struct __fp_cmd_open {
    unsigned int len;
    char *path;
} fp_cmd_open;

typedef union __fp_cmd {
    fp_cmd_open open;
} fp_cmd;

static uint64_t readcmd(int sd) {
    char buf[FP_CMD_NAME_LEN];
    int ret = read(sd, buf, FP_CMD_NAME_LEN);

    // TODO 0 か -1 を返すまで読み込みを繰り返す。
    if (ret < FP_CMD_NAME_LEN) {
        return 0;
    }

    return FP_CMD(buf);
}

static bool session_start(fp_session *session, int sd, ss_logger *logger) {
    char *buf = NULL;
    uint64_t cmd = 0;

    buf = malloc(FP_DEFAULT_BUFSIZE);
    if (!buf) {
        ss_err(logger, "failed to allocate client buffer\n");
        goto err;
    }

    cmd = readcmd(sd);
    if (!cmd) {
        ss_err(logger, "failed to read command\n");
        goto err;
    }

    if (cmd == FP_CMD_OPEN) {
    } else {
        ss_err(logger, "unexpected command given: command = %llx\n", cmd);
        goto err;
    }

    // TODO パスの読み込み & path へのコピー & ファイルの open
    // TODO 読み書きモードの設定

    session->sd = sd;
    session->buf = buf;

    return true;

err:
    if (buf) {
        free(buf);
    }

    return false;
}

static void cbk(ss_logger *logger, int sd, void *arg) {
    fp_session session;

    ss_info(logger, "starting new session...\n");

    if (!session_start(&session, sd, logger)) {
        ss_err(logger, "failed to start session\n");
        return;
    }

    // TODO
    // 1: パスを読み込む
    // 2: 読み込んだパスに従って open & 構造体初期化
    // 3: ループ内でコマンド(read, write, seek, close)を解釈
    // 4: close コマンドが来るか client からの read で eof が返るまでループ継続
}

int main(void) {
    ss_ctx *ctx = ss_new(cbk, NULL);
    ss_run(ctx, 1234);
    ss_free(ctx);
    return 0;
}
