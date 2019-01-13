#include "bpfhv.h"
#include "bpfhv_sring.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define compiler_barrier() __asm__ __volatile__ ("");

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
        txd->cookie = txb->cookie;
        txd->paddr = txb->paddr;
        txd->len = txb->len;
        txd->flags = 0;
    }
    txd->flags = SRING_DESC_F_EOP;
    compiler_barrier();
    ACCESS_ONCE(priv->prod) = prod;
    compiler_barrier();
    ctx->oflags = ACCESS_ONCE(priv->kick_enabled) ?
                  BPFHV_OFLAGS_NOTIF_NEEDED : 0;

    return 0;
}

static inline uint32_t
sring_tx_get_one(struct bpfhv_tx_context *ctx,
                 struct sring_tx_context *priv, uint32_t start)
{
    uint32_t i;

    for (i = 0; i < BPFHV_MAX_TX_BUFS; ) {
        struct bpfhv_tx_buf *txb = ctx->bufs + i;
        struct sring_tx_desc *txd;

        txd = priv->desc + (start % priv->num_slots);
        start++;
        i++;
        txb->paddr = txd->paddr;
        txb->len = txd->len;
        txb->cookie = txd->cookie;
        if (txd->flags & SRING_DESC_F_EOP) {
            break;
        }
    }

    ctx->num_bufs = i;

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

    priv->cons = priv->clear = sring_tx_get_one(ctx, priv, cons);
    ctx->oflags = 0;

    return 1;
}

__section("txi")
int sring_txi(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    uint32_t nfree;
    uint32_t cons;

    cons = ACCESS_ONCE(priv->cons);
    nfree = priv->num_slots - (priv->prod - cons);

    if (nfree >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }
    ACCESS_ONCE(priv->intr_enabled) = 1;
    compiler_barrier();
    nfree += ACCESS_ONCE(priv->cons) - cons;
    if (nfree >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }

    return 0;
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
    compiler_barrier();
    ACCESS_ONCE(priv->prod) = prod;
    compiler_barrier();
    ctx->oflags = ACCESS_ONCE(priv->kick_enabled) ?
                  BPFHV_OFLAGS_NOTIF_NEEDED : 0;

    return 0;
}

static int BPFHV_FUNC(rx_pkt_alloc, struct bpfhv_rx_context *ctx);

__section("rxc")
int sring_rxc(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t clear = priv->clear;
    uint32_t cons = ACCESS_ONCE(priv->cons);
    uint32_t i;
    int ret;

    if (clear == cons) {
        return 0;
    }

    /* Prepare the input arguments for rx_pkt_alloc(). */
    for (i = 0; clear != cons && i < BPFHV_MAX_RX_BUFS;) {
        struct bpfhv_rx_buf *rxb = ctx->bufs + i;
        struct sring_rx_desc *rxd;

        rxd = priv->desc + (clear % priv->num_slots);
        clear++;
        i++;
        rxb->cookie = rxd->cookie;
        rxb->paddr = rxd->paddr;
        rxb->len = rxd->len;

        if (rxd->flags & SRING_DESC_F_EOP) {
            break;
        }
    }

    priv->clear = clear;
    ctx->num_bufs = i;

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

    priv->cons = priv->clear = cons;
    ctx->num_bufs = i;
    ctx->oflags = 0;

    return 1;
}

__section("rxi")
int sring_rxi(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    uint32_t ncompl;
    uint32_t cons;

    cons = ACCESS_ONCE(priv->cons);
    ncompl = cons - priv->clear;

    if (ncompl >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }
    ACCESS_ONCE(priv->intr_enabled) = 1;
    compiler_barrier();
    ncompl += ACCESS_ONCE(priv->cons) - cons;
    if (ncompl >= ctx->min_completed_bufs) {
        ACCESS_ONCE(priv->intr_enabled) = 0;
        return 1;
    }

    return 0;
}
