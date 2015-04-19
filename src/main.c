#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

void *op_create(const char *path, mode_t mode) {
    long fd;
    // TODO 外から mode を指定できるようにする。
    mkpdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    return fd >= 0 ? (void*)fd : NULL;
}

void *op_open(const char *path, int flags) {
    long fd = open(path, flags);
    return fd >= 0 ? (void*)fd : NULL;
}

int op_read(void *fd, void *buf, size_t size) {
    return read((long)fd, buf, size);
}

int op_write(void *fd, void *buf, size_t size) {
    return write((long)fd, buf, size);
}

int op_seek(void *fd, off_t offset, int whence) {
    return lseek((long)fd, offset, whence);
}

int op_close(void *fd) {
    return close((long)fd);
}

int op_delete(const char *path) {
    return unlink(path);
}

int main(int argc, char **argv) {
    int port;
    int listen_sd = -1;
    fp_ctx ctx;
    fp_ops ops;

    ops.create = op_create;
    ops.open = op_open;
    ops.read = op_read;
    ops.write = op_write;
    ops.seek = op_seek;
    ops.close = op_close;
    ops.delete = op_delete;

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

    if (!fp_init(&ctx, &ops)) {
        fprintf(stderr, "failed to initialize\n");
        goto err;
    }

    listen_sd = fp_listen(&ctx, port);
    if (listen_sd < 0) {
        fprintf(stderr, "failed to listen %d\n", port);
        goto err;
    }

    if (!fp_run(&ctx, listen_sd)) {
        fprintf(stderr, "failed to run server\n");
        goto err;
    }

    close(listen_sd);

    return 0;

err:
    if (listen_sd >= 0) {
        close(listen_sd);
    }

    return -1;
}
