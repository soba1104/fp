#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int port;
    int listen_sd = -1;
    fp_ctx ctx;

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

    if (!fp_init(&ctx)) {
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
