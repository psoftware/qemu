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

void sring_txq_drain(NetClientState *nc, struct bpfhv_tx_context *ctx,
                NetPacketSent *complete_cb);

#endif  /*__BPFHV_SRING_HV_H__ */
