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

    /* True if the sync kloop has been started for ptnetmap. */
    bool worker_started;
    QemuThread th;

    /* Feature acknowledgement support. */
    unsigned long features;
    unsigned long acked_features;

    /* Info about netmap memory. */
    uint32_t memsize;
    void *mem;
} PTNetmapState;

uint32_t ptnetmap_ack_features(PTNetmapState *pt, uint32_t wanted_features);
int ptnetmap_kloop_start(PTNetmapState *pt, void *csb_gh, void *csb_hg,
                    unsigned int num_entries, int *ioeventfds, int *irqfds);
int ptnetmap_kloop_stop(PTNetmapState *pt);
PTNetmapState *get_ptnetmap(NetClientState *nc);
int netmap_get_port_info(NetClientState *nc, struct nmreq_port_info_get *nif);
int netmap_get_hostmemid(NetClientState *nc);
uint32_t netmap_get_nifp_offset(NetClientState *nc);

int ptnetmap_memdev_create(void *mem_ptr, struct nmreq_pools_info *pi);

#undef PTNET_DEBUG /* enable to add debug logs for ptnetmap netif and memdev */

#endif /* PTNETMAP_H */
