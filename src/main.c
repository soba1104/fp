#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>

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

void *op_create(const char *path, mode_t mode, void *arg) {
    long fd;
    // TODO 外から mode を指定できるようにする。
    mkpdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    return fd >= 0 ? (void*)fd : NULL;
}

void *op_open(const char *path, int flags, void *arg) {
    long fd = open(path, flags);
    return fd >= 0 ? (void*)fd : NULL;
}

int op_read(void *fd, void *buf, size_t size, void *arg) {
    return read((long)fd, buf, size);
}

int op_write(void *fd, void *buf, size_t size, void *arg) {
    return write((long)fd, buf, size);
}

int op_seek(void *fd, off_t offset, int whence, void *arg) {
    return lseek((long)fd, offset, whence);
}

int op_close(void *fd, void *arg) {
    return close((long)fd);
}

int64_t op_size(void *fd, void *arg) {
    struct stat stat;

    if (fstat((long)fd, &stat) < 0) {
        return -1;
    }

    return stat.st_size;
}

int64_t op_df(void *arg) {
    struct statvfs stat;

    if (statvfs("/", &stat) < 0) {
        return -1;
    }

    return stat.f_frsize * stat.f_bavail;
}

int op_delete(const char *path, void *arg) {
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
    ops.size = op_size;
    ops.df = op_df;
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

    if (!fp_init(&ctx, &ops, NULL)) {
        fprintf(stderr, "failed to initialize\n");
        goto err;
    }

    listen_sd = fp_listen_tcp(&ctx, "127.0.0.1", port);
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
