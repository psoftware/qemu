/*
 * BPFHV paravirtual network device
 *   Definitions shared between the device emulation and the
 *   sring hv implementation.
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

#ifndef __BPFHV_SRING_HV_H__
#define __BPFHV_SRING_HV_H__

#include "sring.h"

struct BpfhvState_st;
void *bpfhv_mem_map(struct BpfhvState_st *s,
                    hwaddr paddr, hwaddr *plen, int is_write);
void bpfhv_mem_unmap(struct BpfhvState_st *s, void *buffer,
                     hwaddr len, int is_write);

#if 0
typedef struct BpfhvImplOps_st {
    size_t (*rx_ctx_size)(size_t num_rx_bufs);
    size_t (*tx_ctx_size)(size_t num_tx_bufs);
    void (*rx_ctx_init)(struct bpfhv_rx_context *ctx, size_t num_rx_bufs);
    void (*tx_ctx_init)(struct bpfhv_tx_context *ctx, size_t num_tx_bufs);
    bool (*can_receive)(struct bpfhv_rx_context *ctx);
    ssize_t (*sring_receive_iov)(struct BpfhvState_st *s,
            struct bpfhv_rx_context *ctx,
            const struct iovec *iov, int iovcnt,
            int vnet_hdr_len, bool *notify);
    void (*rxq_notification)(struct bpfhv_rx_context *ctx, int enable);
    void (*rxq_dump)(struct bpfhv_rx_context *ctx);
    ssize_t (*txq_drain)(struct BpfhvState_st *s, NetClientState *nc,
            struct bpfhv_tx_context *ctx,
            NetPacketSent *complete_cb, int vnet_hdr_len,
            bool *notify);
    void (*txq_notification)(struct bpfhv_tx_context *ctx, int enable);
    void (*txq_dump)(struct bpfhv_tx_context *ctx);
} BpfhvImplOps;
#endif

static inline size_t
sring_rx_ctx_size(size_t num_rx_bufs)
{
    return sizeof(struct sring_rx_context) +
	num_rx_bufs * sizeof(struct sring_rx_desc);
}

static inline size_t
sring_tx_ctx_size(size_t num_tx_bufs)
{
    return sizeof(struct sring_tx_context) +
	num_tx_bufs * sizeof(struct sring_tx_desc);
}

void sring_rx_ctx_init(struct bpfhv_rx_context *ctx, size_t num_rx_bufs);
void sring_tx_ctx_init(struct bpfhv_tx_context *ctx, size_t num_tx_bufs);

bool sring_can_receive(struct bpfhv_rx_context *ctx);
ssize_t sring_receive_iov(struct BpfhvState_st *s,
                          struct bpfhv_rx_context *ctx,
                          const struct iovec *iov, int iovcnt,
                          int vnet_hdr_len, bool *notify);
void sring_rxq_notification(struct bpfhv_rx_context *ctx, int enable);
char *sring_rxq_dump(struct bpfhv_rx_context *ctx);

#define BPFHV_HV_TX_BUDGET      64
ssize_t sring_txq_drain(struct BpfhvState_st *s, NetClientState *nc,
                        struct bpfhv_tx_context *ctx,
                        NetPacketSent *complete_cb, int vnet_hdr_len,
                        bool *notify);
void sring_txq_notification(struct bpfhv_tx_context *ctx, int enable);
char *sring_txq_dump(struct bpfhv_tx_context *ctx);

#endif  /*__BPFHV_SRING_HV_H__ */
