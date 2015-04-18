#ifndef __FP_SRC_FP_H__
#define __FP_SRC_FP_H__

#include <stdbool.h>
#include <ss.h>

typedef struct __fp_ctx {
    ss_ctx ss;
} fp_ctx;

bool fp_init(fp_ctx *ctx);
int fp_listen(fp_ctx *ctx, int port);
bool fp_run(fp_ctx *ctx, int listen_sd);

#endif
