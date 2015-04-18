#include "fp.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int port;

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
    if (!fp_run(port)) {
        fprintf(stderr, "failed to run server\n");
        goto err;
    }

    return 0;

err:
    return -1;
}
