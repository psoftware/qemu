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
    priv->tail = priv->head = 0;
    memset(priv->desc, 0, num_tx_bufs * sizeof(priv->desc[0]));
}
