#include <stdio.h>

#include "fp.h"

void cbk(ss_logger *logger, int socket, void *arg) {
    ss_log(logger, SS_LOG_INFO, "Hello %s\n", "World");
}

int main(void) {
    ss_ctx *ctx = ss_new(cbk, NULL);
    ss_run(ctx, 1234);
    ss_free(ctx);
    return 0;
}
