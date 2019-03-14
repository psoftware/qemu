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
#include "linux/virtio_net.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"

#include "bpfhv/bpfhv.h"
#include "bpfhv/sring.h"
#include "bpfhv/sring_hv.h"

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define compiler_barrier() __asm__ __volatile__ ("");

void
sring_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;

    assert((num_rx_bufs & (num_rx_bufs - 1)) == 0);
    priv->qmask = num_rx_bufs - 1;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_rx_bufs * sizeof(priv->desc[0]));
}

void
sring_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    assert((num_tx_bufs & (num_tx_bufs - 1)) == 0);
    priv->qmask = num_tx_bufs - 1;
    priv->prod = priv->cons = priv->clear = 0;
    priv->kick_enabled = priv->intr_enabled = 1;
    memset(priv->desc, 0, num_tx_bufs * sizeof(priv->desc[0]));
}

ssize_t
sring_txq_drain(struct BpfhvState *s, NetClientState *nc,
                struct bpfhv_tx_context *ctx,
                NetPacketSent *complete_cb,
                int vnet_hdr_len, bool *notify)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    struct iovec iov[BPFHV_MAX_TX_BUFS];
    uint32_t prod = ACCESS_ONCE(priv->prod);
    uint32_t cons = priv->cons;
    uint32_t first = cons;
    int iovcnt_start = vnet_hdr_len != 0 ? 1 : 0;
    int iovcnt = iovcnt_start;
    int count = 0;
    int i;

    /* Barrier between load(priv->prod) and load(sring entries). */
    smp_mb_acquire();

    while (cons != prod) {
        struct sring_tx_desc *txd = priv->desc + (cons & priv->qmask);
        hwaddr len;

        cons++;

        len = txd->len;
        iov[iovcnt].iov_base = bpfhv_mem_map(s, txd->paddr, &len,
                                             /*is_write*/0);
        iov[iovcnt].iov_len = len; /* technically, it may be len < txd->len */
        if (iov[iovcnt].iov_base == NULL) {
            /* Invalid descriptor, just skip it. */
        } else {
            iovcnt++;
        }

        if (txd->flags & SRING_DESC_F_EOP) {
            struct virtio_net_hdr_v1 hdr;
            int ret;

            if (vnet_hdr_len != 0) {
                hdr.flags = (txd->flags & SRING_DESC_F_NEEDS_CSUM) ?
                    VIRTIO_NET_HDR_F_NEEDS_CSUM : 0;
                hdr.csum_start = txd->csum_start;
                hdr.csum_offset = txd->csum_offset;
                hdr.hdr_len = txd->hdr_len;
                hdr.gso_size = txd->gso_size;
                hdr.gso_type = txd->gso_type;
                hdr.num_buffers = 0;
#if 0
                printf("tx hdr: {fl %x, cs %u, co %u, hl %u, gs %u, gt %u}\n",
                        hdr.flags, hdr.csum_start, hdr.csum_offset,
                        hdr.hdr_len, hdr.gso_size, hdr.gso_type);
#endif
                iov[0].iov_base = &hdr;
                iov[0].iov_len = sizeof(hdr);
            }

            ret = qemu_sendv_packet_async(nc, iov, iovcnt,
                                            /*sent_cb=*/complete_cb);

            for (i = iovcnt_start; i < iovcnt; i++) {
                bpfhv_mem_unmap(s, iov[i].iov_base, iov[i].iov_len,
                                /*is_write=*/0);
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

            iovcnt = iovcnt_start;
            first = cons;
        }
    }

    if (count > 0) {
        /* Barrier between stores to sring entries and store to priv->cons. */
        smp_mb_release();
        priv->cons = cons;
        /* Full memory barrier to ensure store(priv->cons) happens before
         * load(priv->intr_enabled). See the double-check in sring_txi(). */
        smp_mb();
        *notify = ACCESS_ONCE(priv->intr_enabled);
    }

    return count;
}

void
sring_txq_notification(struct bpfhv_tx_context *ctx, int enable)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;

    priv->kick_enabled = !!enable;
    if (enable) {
        smp_mb_acquire();
    }
}

char *
sring_txq_dump(struct bpfhv_tx_context *ctx)
{
    struct sring_tx_context *priv = (struct sring_tx_context *)ctx->opaque;
    size_t left = 100;
    char *dump;

    dump = g_malloc(left);
    snprintf(dump, left, "sring.txq cl %u co %u pr %u kick %u intr %u\n",
            ACCESS_ONCE(priv->clear), ACCESS_ONCE(priv->cons),
            ACCESS_ONCE(priv->prod), ACCESS_ONCE(priv->kick_enabled),
            ACCESS_ONCE(priv->intr_enabled));

    return dump;
}

bool
sring_can_receive(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;

    return (priv->cons != ACCESS_ONCE(priv->prod));
}


ssize_t
sring_receive_iov(struct BpfhvState *s, struct bpfhv_rx_context *ctx,
                  const struct iovec *iov, int iovcnt, int vnet_hdr_len,
                  bool *notify)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    const struct iovec *const iov_end = iov + iovcnt;
    uint32_t cons = priv->cons;
    uint32_t prod = ACCESS_ONCE(priv->prod);
    struct sring_rx_desc *rxd = priv->desc + (cons & priv->qmask);
    struct virtio_net_hdr_v1 *hdr = NULL;
    hwaddr sspace = iov->iov_len;
    void *sbuf = iov->iov_base;
    hwaddr dspace = rxd->len;
    ssize_t totlen = 0;
    void *dbuf = NULL;
    size_t dofs = 0;

    if (unlikely(sspace < vnet_hdr_len)) {
        error_report("Fatal: first iov entry is less than %d", vnet_hdr_len);
        abort();
    }
    if (vnet_hdr_len != 0) {
        hdr = (struct virtio_net_hdr_v1 *)sbuf;
        sspace -= sizeof(*hdr);
        sbuf += sizeof(*hdr);
    }

    /* Barrier between load(priv->prod) and load(sring entries). */
    smp_mb_acquire();

    for (;;) {
        size_t copy = sspace < dspace ? sspace : dspace;

        if (unlikely(cons == prod)) {
            /* We ran out of RX descriptors. Enable RX kicks and double
             * check for more available descriptors. */
            sring_rxq_notification(ctx, true);
            prod = ACCESS_ONCE(priv->prod);
            if (cons == prod) {
                /* Not enough space, we must send a backpressure signal
                 * to the net backend, by setting the return value to 0. */
#if 0
                printf("drop (totlen %zd)\n", totlen);
#endif
                return 0;
            }
            sring_rxq_notification(ctx, false);
        }

        if (!dbuf) {
            dbuf = bpfhv_mem_map(s, rxd->paddr, &dspace, /*is_write*/1);
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
            bpfhv_mem_unmap(s, dbuf, rxd->len, /*is_write=*/1);
            if (iov == iov_end) {
                rxd->len -= dspace;
                rxd->flags = SRING_DESC_F_EOP;
                if (vnet_hdr_len != 0) {
#if 0
                    printf("rx hdr: {fl %x, cs %u, co %u, hl %u, gs %u, "
                            "gt %u}\n",
                            hdr->flags, hdr->csum_start, hdr->csum_offset,
                            hdr->hdr_len, hdr->gso_size, hdr->gso_type);
#endif
                    rxd->csum_start = hdr->csum_start;
                    rxd->csum_offset = hdr->csum_offset;
                    rxd->hdr_len = hdr->hdr_len;
                    rxd->gso_size = hdr->gso_size;
                    rxd->gso_type = hdr->gso_type;
                    if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
                        rxd->flags |= SRING_DESC_F_NEEDS_CSUM;
                    }
                }
                break;
            }
            rxd->flags = 0;
            rxd = priv->desc + (cons & priv->qmask);
            dspace = rxd->len;
            dbuf = NULL;
            dofs = 0;
        }
    }

    /* Barrier between store(sring entries) and store(priv->cons). */
    smp_mb_release();
    priv->cons = cons;
    /* Full memory barrier to ensure store(priv->cons) happens before
     * load(priv->intr_enabled). See the double-check in sring_rxi().*/
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
        smp_mb_acquire();
    }
}

char *
sring_rxq_dump(struct bpfhv_rx_context *ctx)
{
    struct sring_rx_context *priv = (struct sring_rx_context *)ctx->opaque;
    size_t left = 100;
    char *dump;

    dump = g_malloc(left);
    snprintf(dump, left, "sring.rxq cl %u co %u pr %u kick %u intr %u\n",
            ACCESS_ONCE(priv->clear), ACCESS_ONCE(priv->cons),
            ACCESS_ONCE(priv->prod), ACCESS_ONCE(priv->kick_enabled),
            ACCESS_ONCE(priv->intr_enabled));

    return dump;
}
