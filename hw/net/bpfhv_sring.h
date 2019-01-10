/*
 * BPFHV paravirtual network device
 *   Definitions shared between the sring eBPF programs and the
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

#ifndef __BPFHV_SRING_H__
#define __BPFHV_SRING_H__

#include <stdint.h>

#define SRING_DESC_F_EOP     (1 << 0)

struct sring_tx_desc {
    uint64_t cookie;
    uint64_t paddr;
    uint32_t len;
    uint32_t flags;
};

/* TODO add proper padding to minimize cache misses */
struct sring_tx_context {
    uint32_t num_slots;
    uint32_t prod;
    uint32_t clear;
    uint32_t cons;
    struct sring_tx_desc desc[0];
};

struct sring_rx_desc {
    uint64_t cookie;
    uint64_t paddr;
    uint32_t len;
    uint32_t flags;
};

struct sring_rx_context {
    uint32_t num_slots;
    uint32_t prod;
    uint32_t clear;
    uint32_t cons;
    struct sring_rx_desc desc[0];
};

#endif  /* __BPFHV_SRING_H__ */
