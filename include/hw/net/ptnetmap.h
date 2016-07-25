/*
 * Copyright (c) Universita' di Pisa.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef PTNETMAP_H
#define PTNETMAP_H

#include <net/if.h>
#include "net/netmap.h"
#include "net/net.h"
#include "exec/memory.h"
#include "net/netmap_virt.h" /* from netmap sources */

typedef struct PTNetmapState {
    struct NetmapState *netmap;

    /* True if ptnetmap kthreads are running. */
    bool running;

    /* Feature acknowledgement support. */
    unsigned long features;
    unsigned long acked_features;

    /* Info about netmap memory. */
    uint32_t memsize;
    void *mem;
} PTNetmapState;

/* Used to get read-only info. */
typedef struct NetmapIf {
    uint32_t nifp_offset;
    uint16_t num_tx_rings;
    uint16_t num_rx_rings;
    uint16_t num_tx_slots;
    uint16_t num_rx_slots;
} NetmapIf;

uint32_t ptnetmap_ack_features(PTNetmapState *pt, uint32_t wanted_features);
int ptnetmap_get_netmap_if(PTNetmapState *pt, NetmapIf *nif);
int ptnetmap_get_hostmemid(PTNetmapState *pt);
int ptnetmap_create(PTNetmapState *nc, struct ptnetmap_cfg *conf);
int ptnetmap_delete(PTNetmapState *nc);
PTNetmapState *get_ptnetmap(NetClientState *nc);

int ptnetmap_memdev_create(void *mem_ptr, uint32_t mem_size, uint16_t mem_id);

#endif /* PTNETMAP_H */
