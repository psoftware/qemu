/*
 * BPFHV paravirtual network device
 *   Hypervisor-side implementation of the sring.
 *
 * Copyright (c) 2018 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "net/net.h"
#include "exec/memory.h"
#include "qemu/atomic.h"

#include "bpfhv.h"
#include "bpfhv_sring.h"
#include "bpfhv_sring_hv.h"

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define compiler_barrier() __asm__ __volatile__ ("");

void
sring_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->num_slots = num_rx_bufs;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_rx_bufs * sizeof(priv->desc[0]));
}

void
sring_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->num_slots = num_tx_bufs;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_tx_bufs * sizeof(priv->desc[0]));
}

ssize_t
sring_txq_drain(NetClientState *nc, struct bpfhv_tx_context *ctx,
                NetPacketSent *complete_cb, bool *notify)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    struct iovec iov[BPFHV_MAX_TX_BUFS];
    uint32_t prod = ACCESS_ONCE(priv->prod);
    uint32_t cons = priv->cons;
    uint32_t first = cons;
    int iovcnt = 0;
    int count = 0;
    int i;

    while (cons != prod) {
        struct sring_tx_desc *txd = priv->desc + (cons % priv->num_slots);
        hwaddr len;

        cons++;

        len = txd->len;
        iov[iovcnt].iov_base = cpu_physical_memory_map(txd->paddr,
                                                    &len, /*is_write*/0);
        iov[iovcnt].iov_len = len; /* technically, it may be len < txd->len */
        if (iov[iovcnt].iov_base == NULL) {
            /* Invalid descriptor, just skip it. */
        } else {
            iovcnt++;
        }

        if (txd->flags & SRING_DESC_F_EOP) {
            int ret = qemu_sendv_packet_async(nc, iov, iovcnt,
                                            /*sent_cb=*/complete_cb);

            for (i = 0; i < iovcnt; i++) {
                cpu_physical_memory_unmap(iov[i].iov_base, iov[i].iov_len,
                                        /*is_write=*/0, iov[i].iov_len);
            }

            if (ret == 0) {
                /* Backend is blocked, we need to stop. The last packet was not
                 * transmitted, so we need to rewind 'cons'. */
                cons = first;
                break;
            }

            if (++count >= BPFHV_HV_TX_BUDGET) {
                break;
            }

            iovcnt = 0;
            first = cons;
        }
    }

    smp_mb();
    priv->cons = cons;
    smp_mb();
    *notify = ACCESS_ONCE(priv->intr_enabled);

    return count;
}

void
sring_txq_notification(struct bpfhv_tx_context *ctx, int enable)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->kick_enabled = !!enable;
    if (enable) {
        smp_mb();
    }
}

bool
sring_can_receive(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;

    return (priv->cons != ACCESS_ONCE(priv->prod));
}

ssize_t
sring_receive_iov(struct bpfhv_rx_context *ctx, const struct iovec *iov,
                  int iovcnt, bool *notify)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    const struct iovec *const iov_end = iov + iovcnt;
    uint32_t cons = priv->cons;
    const uint32_t prod = ACCESS_ONCE(priv->prod);
    struct sring_rx_desc *rxd = priv->desc + (cons % priv->num_slots);
    hwaddr sspace = iov->iov_len;
    void *sbuf = iov->iov_base;
    hwaddr dspace = rxd->len;
    ssize_t totlen = 0;
    void *dbuf = NULL;
    size_t dofs = 0;

    while (cons != prod) {
        size_t copy = sspace < dspace ? sspace : dspace;

        if (!dbuf) {
            dbuf = cpu_physical_memory_map(rxd->paddr, &dspace, /*is_write*/1);
            if (!dbuf) {
                /* Invalid descriptor, just skip it. */
                *notify = false;
                return 0;
            }
        }

        memcpy(dbuf + dofs, sbuf, copy);
        totlen += copy;
        sspace -= copy;
        dspace -= copy;
        sbuf += copy;
        dofs += copy;

        if (sspace == 0) {
            iov++;
            sspace = iov->iov_len;
            sbuf = iov->iov_base;
        }

        if (iov == iov_end || dspace == 0) {
            cons++;
            cpu_physical_memory_unmap(dbuf, rxd->len, /*is_write=*/1,
                                      rxd->len);
            if (iov == iov_end) {
                rxd->len -= dspace;
                rxd->flags = SRING_DESC_F_EOP;
                break;
            }
            rxd->flags = 0;
            rxd = priv->desc + (cons % priv->num_slots);
            dspace = rxd->len;
            dbuf = NULL;
            dofs = 0;
        }
    }

    smp_mb();
    priv->cons = cons;
    smp_mb();
    *notify = ACCESS_ONCE(priv->intr_enabled);

    return totlen;
}

void
sring_rxq_notification(struct bpfhv_rx_context *ctx, int enable)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;

    priv->kick_enabled = !!enable;
    if (enable) {
        smp_mb();
    }
}
