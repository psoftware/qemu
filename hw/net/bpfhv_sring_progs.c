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
    uint32_t prod = priv->prod;
    struct sring_tx_desc *txd;
    uint32_t i;

    if (ctx->num_bufs > BPFHV_MAX_TX_BUFS) {
        return -1;
    }

    for (i = 0; i < ctx->num_bufs; i++, prod++) {
        struct bpfhv_tx_buf *txb = ctx->bufs + i;

        txd = priv->desc + (prod % priv->num_slots);
        txd->paddr = txb->paddr;
        txd->len = txb->len;
        txd->flags = 0;
        txd->cookie = 0;
    }
    txd->flags = SRING_DESC_F_EOP;
    txd->cookie = ctx->cookie;
    priv->prod = prod;
    ctx->oflags = BPFHV_OFLAGS_NOTIF_NEEDED;

    return 0;
}

static inline uint32_t
sring_tx_get_one(struct bpfhv_tx_context *ctx,
                 struct sring_tx_context *priv, uint32_t start)
{
    for (;;) {
        struct sring_tx_desc *txd;

        txd = priv->desc + (start % priv->num_slots);
        start++;
        if (txd->flags & SRING_DESC_F_EOP) {
            ctx->cookie = txd->cookie;
            break;
        }
    }

    return start;
}

__section("txc")
int sring_txc(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t clear = priv->clear;
    uint32_t cons = priv->cons;

    if (clear == cons) {
        return 0;
    }

    priv->clear = sring_tx_get_one(ctx, priv, clear);
    ctx->oflags = 0;

    return 1;
}

__section("txr")
int sring_txr(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t cons = priv->cons;
    uint32_t prod = priv->prod;

    if (cons == prod) {
        return 0;
    }

    priv->cons = sring_tx_get_one(ctx, priv, cons);
    ctx->oflags = 0;

    return 1;
}

__section("rxp")
int sring_rxp(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t prod = priv->prod;
    struct sring_rx_desc *rxd;
    uint32_t i;

    if (ctx->num_bufs > BPFHV_MAX_RX_BUFS) {
        return -1;
    }

    for (i = 0; i < ctx->num_bufs; i++, prod++) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;

        rxd = priv->desc + (prod % priv->num_slots);
        rxd->cookie = rxb->cookie;
        rxd->paddr = rxb->paddr;
        rxd->len = rxb->len;
        rxd->flags = 0;
    }
    priv->prod = prod;
    ctx->oflags = BPFHV_OFLAGS_NOTIF_NEEDED;

    return 0;
}

static int BPFHV_FUNC(rx_pkt_alloc, struct bpfhv_rx_context *ctx);

__section("rxc")
int sring_rxc(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t clear = priv->clear;
    uint32_t cons = priv->cons;
    uint32_t i = 0;
    int ret;

    if (clear == cons) {
        /* No new packets to be received. */
        return 0;
    }

    /* Prepare the input arguments for rx_pkt_alloc(). */
    for (; clear != cons && i < BPFHV_MAX_RX_BUFS; i++) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;
        struct sring_rx_desc *rxd;

        rxd = priv->desc + (clear % priv->num_slots);
        clear++;
        rxb->cookie = rxd->cookie;
        rxb->paddr = rxd->paddr;
        rxb->len = rxd->len;

        if (rxd->flags & SRING_DESC_F_EOP) {
            break;
        }
    }
    priv->clear = clear;
    ctx->num_bufs = i + 1;

    ret = rx_pkt_alloc(ctx);
    if (ret < 0) {
        return ret;
    }

    /* Now ctx->packet contains the allocated OS packet. Return 1 to tell
     * the driver that ctx->packet is valid. Also set ctx->oflags to tell
     * the driver whether rescheduling is necessary. */
    ctx->oflags = 0;

    return 1;
}

__section("rxr")
int sring_rxr(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t cons = priv->cons;
    uint32_t prod = priv->prod;
    uint32_t i = 0;

    if (cons == prod) {
        return 0;
    }

    for (; cons != prod && i < BPFHV_MAX_RX_BUFS; i++) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;
        struct sring_rx_desc *rxd;

        rxd = priv->desc + (cons % priv->num_slots);
        cons++;
        rxb->cookie = rxd->cookie;
        rxb->paddr = rxd->paddr;
        rxb->len = rxd->len;
    }

    priv->cons = cons;
    ctx->num_bufs = i;
    ctx->oflags = 0;

    return 1;
}
