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

#include "bpfhv.h"
#include "bpfhv_sring.h"
#include "bpfhv_sring_hv.h"

void
sring_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs)
{
}

void
sring_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->num_slots = num_tx_bufs;
    priv->prod = priv->cons = priv->clear = 0;
    memset(priv->desc, 0, num_tx_bufs * sizeof(priv->desc[0]));
}


void
sring_txq_drain(NetClientState *nc, struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    struct iovec iov[BPFHV_MAX_TX_BUFS];
    uint32_t prod = priv->prod;
    uint32_t cons = priv->cons;
    int iovcnt = 0;
    int i;

    while (cons != prod) {
        struct sring_tx_desc *txd = priv->desc + cons;
        hwaddr len;

        len = txd->len;
        iov[iovcnt].iov_base = cpu_physical_memory_map(txd->paddr,
                                                    &len, /*is_write*/0);
        iov[iovcnt].iov_len = len; /* technically, it may be len < txd->len */
        if (iov[iovcnt].iov_base == NULL) {
            /* Invalid descriptor, just skip it. */
        } else {
            iovcnt++;
        }

        if (++cons == priv->num_slots) {
            cons = 0;
        }

        if (txd->flags & TX_DESC_F_EOP) {
            qemu_sendv_packet_async(nc, iov, iovcnt, /*sent_cb=*/NULL);
            /* TODO handle return value */
            for (i = 0; i < iovcnt; i++) {
                cpu_physical_memory_unmap(iov[i].iov_base, iov[i].iov_len,
                                        /*is_write=*/0, iov[i].iov_len);
            }
            iovcnt = 0;
        }
    }

    priv->cons = cons;
}
