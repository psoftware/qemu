#include "bpfhv.h"
#include "bpfhv_sring.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

__section("txp")
int sring_txp(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->tail++;

    return 0;
}
