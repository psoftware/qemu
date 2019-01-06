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

    return priv->tail;
}

__section("txc")
int sring_txc(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    if (priv->head == priv->tail) {
        return 0;
    }

    priv->head++;

    return 1;
}

__section("rxp")
int sring_rxp(struct bpfhv_rx_context *ctx)
{
    return 0;
}

static int BPFHV_FUNC(pkt_alloc, struct bpfhv_rx_context *ctx);

__section("rxc")
int sring_rxc(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    int ret;

    if (priv->temp == 0) {
        return 0;
    }
    priv->temp--;
    ret = pkt_alloc(ctx);
    if (ret < 0) {
        return ret;
    }

    return 1;
}
