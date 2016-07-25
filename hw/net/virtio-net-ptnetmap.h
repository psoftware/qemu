/*
 * ptnetmap support for virtio-net
 *
 * Copyright (c) 2015 Stefano Garzarella
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

#ifndef _QEMU_VIRTIO_PTNETMAP_H
#define _QEMU_VIRTIO_PTNETMAP_H

#include "include/hw/net/ptnetmap.h"

/* ptnetmap virtio register BASE */
#define PTNETMAP_VIRTIO_IO_BASE         sizeof(struct virtio_net_config)

static int virtio_net_ptnetmap_up(VirtIODevice *vdev)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VirtIONet *n = VIRTIO_NET(vdev);
    PTNetmapState *ptns = n->ptn.state;
    struct ptnetmap_cfg *cfg;
    VirtQueueElement *elem;
    int i, ret, nvqs = 0;
    VirtIONetQueue *q;

    if (!k->set_guest_notifiers) {
        printf("ERROR ptnetmap: binding does not support notifiers\n");
        return ENOSYS;
    }

    if (ptns == NULL) {
        printf("ERROR ptnetmap: not supported by backend\n");
        return ENXIO;
    }

    if (n->ptn.csb == NULL) {
        printf("ERROR ptnetmap: CSB undefined\n");
        return ENXIO;
    }

    if (n->ptn.up) {
        printf("INFO ptnetmap: already UP\n");
        return 0;
    }

    /* TODO-ste: add support for multiqueue */
    printf("max_queues: %d\n", n->max_queues);
    nvqs += 2;

    /* Stop processing guest/host IO notifications in qemu.
     * Start processing them in ptnetmap.
     */
    for (i = 0; i < nvqs; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
        ret = virtio_bus_set_host_notifier(vbus, i, true);
        if (ret < 0) {
            printf("ERROR ptnetmap: VQ %d notifier binding failed %d\n", i, -ret);
            nvqs = i - 1;
            goto err_notifiers;
        }
    }
    ret = k->set_guest_notifiers(qbus->parent, nvqs, true);
    if (ret < 0) {
        printf("ERROR ptnetmap: binding guest notifier %d", -ret);
        goto err_notifiers;
    }

    /* TODO for (i = 0; i < n->max_queues; i++) { */
    i = 0;
    q = &n->vqs[i];
#if 0
    if (q->tx_timer) {
        timer_del(q->tx_timer);
    } else {
        qemu_bh_cancel(q->tx_bh);
    }
#endif
    cfg = g_malloc(sizeof(*cfg) + 2 * sizeof(cfg->entries[0]));

    /* Configure the TX ring */
    cfg->entries[0].ioeventfd =
        event_notifier_get_fd(virtio_queue_get_host_notifier(q->tx_vq));
    cfg->entries[0].irqfd =
        event_notifier_get_fd(virtio_queue_get_guest_notifier(q->tx_vq));

    /* Configure the RX ring */
    cfg->entries[1].ioeventfd =
        event_notifier_get_fd(virtio_queue_get_host_notifier(q->rx_vq));
    cfg->entries[1].irqfd =
        event_notifier_get_fd(virtio_queue_get_guest_notifier(q->rx_vq));

    /* Push fake responses in the used ring of the RX VQ to keep RX interrupts
     * enabled. */
    if ((elem = virtqueue_pop(q->rx_vq, sizeof(*elem)))) {
        virtqueue_push(q->rx_vq, elem, 0);
	g_free(elem);
    }

    /* Make sure TX/RX kicks are enabled. */
    virtio_queue_set_notification(q->rx_vq, 1);
    virtio_queue_set_notification(q->tx_vq, 1);

    /* Prepare CSB pointer for the host and complete CSB configuration. */
    cfg->features = PTNETMAP_CFG_FEAT_CSB | PTNETMAP_CFG_FEAT_EVENTFD;
    cfg->ptrings = &n->ptn.csb->tx_ring;
    cfg->num_rings = 2;

    n->ptn.csb->tx_ring.host_need_kick = 1;
    n->ptn.csb->tx_ring.guest_need_kick = 0;
    n->ptn.csb->rx_ring.guest_need_kick = 1;
    n->ptn.csb->rx_ring.host_need_kick = 1;

    /* Start ptnetmap on the backend. */
    ret = ptnetmap_create(n->ptn.state, cfg);
    g_free(cfg);
    if (ret)
        goto err_ptn_create;

    n->ptn.up = true;

    return 0;

err_ptn_create:
    k->set_guest_notifiers(qbus->parent, nvqs, false);
err_notifiers:
    for (i = 0; i < nvqs; i++) {
        virtio_bus_set_host_notifier(vbus, i, false);
    }
    return ret;
}

static int virtio_net_ptnetmap_down(VirtIODevice *vdev)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VirtIONet *n = VIRTIO_NET(vdev);
    int i, ret, nvqs = 0;

    if (!n->ptn.state || !n->ptn.up) {
        return 0;
    }
    n->ptn.up = false;

    printf("max_queues: %d\n", n->max_queues);
    nvqs += 2;
    /* TODO for (i = 0; i < n->max_queues; i++) { */
    i = 0;
    /* Start processing guest/host IO notifications in qemu.
     */
    for (i = 0; i < nvqs; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
        ret = virtio_bus_set_host_notifier(vbus, i, false);
        if (ret < 0) {
            printf("ERROR ptnetmap: VQ %d notifier binding failed %d\n", i, -ret);
        }
    }
    ret = k->set_guest_notifiers(qbus->parent, nvqs, false);
    if (ret < 0) {
        printf("ERROR ptnetmap: binding guest notifier %d", -ret);
        return -1;
    }

    return ptnetmap_delete(n->ptn.state);
}

static int virtio_net_ptnetmap_get_netmap_if(VirtIODevice *vdev)
{
    VirtIONet *n = VIRTIO_NET(vdev);
    PTNetmapState *ptns = n->ptn.state;
    struct paravirt_csb *csb = n->ptn.csb;
    NetmapIf nif;
    int ret;

    if (csb == NULL) {
        printf("ERROR ptnetmap: csb not initialized\n");
        return -1;
    }

    ret = ptnetmap_get_netmap_if(ptns, &nif);
    if (ret) {
        return ret;
    }

    csb->nifp_offset = nif.nifp_offset;
    csb->num_tx_rings = nif.num_tx_rings;
    csb->num_rx_rings = nif.num_rx_rings;
    csb->num_tx_slots = nif.num_tx_slots;
    csb->num_rx_slots = nif.num_rx_slots;
    printf("txr %u rxr %u txd %u rxd %u nifp_offset %u\n",
            csb->num_tx_rings,
            csb->num_rx_rings,
            csb->num_tx_slots,
            csb->num_rx_slots,
            csb->nifp_offset);

    return ret;
}

static void paravirt_configure_csb(struct paravirt_csb **csb, uint32_t csbbal,
                                   uint32_t csbbah)
{
    hwaddr len = 4096;
    hwaddr base = ((uint64_t)csbbah << 32) | csbbal;

    /*
     * We require that writes to the CSB address registers are in the
     * order CSBBAH , CSBBAL so on the second one we have a valid 64-bit
     * memory address.
     * Any previous region is unmapped, and  the CSB is then remapped if
     * the new pointer is != 0
     */
    if (*csb) {
        cpu_physical_memory_unmap(*csb, len, 1, len);
        *csb = NULL;
    }
    if (base) {
        *csb = cpu_physical_memory_map(base, &len, 1 /* is_write */);
    }
}

static void virtio_net_ptnetmap_set_reg(VirtIODevice *vdev,
                                        const uint8_t *config, uint32_t addr)
{
    VirtIONet *n = VIRTIO_NET(vdev);
    uint32_t *val, ret;

    if (n->ptn.state == NULL) {
        printf("ERROR ptnetmap: not supported by backend\n");
        return;
    }

    config += PTNETMAP_VIRTIO_IO_BASE;
    addr -= PTNETMAP_VIRTIO_IO_BASE;

    switch (addr) {
        case PTNETMAP_VIRTIO_IO_PTFEAT:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            val = (uint32_t *)(n->ptn.reg + addr);

            /* Pass requested features to the backend. */
            ret = ptnetmap_ack_features(n->ptn.state, *val);
            printf("ptnetmap acked features: %x\n", ret);

            n->ptn.reg[PTNETMAP_VIRTIO_IO_PTFEAT] = ret;
            break;

        case PTNETMAP_VIRTIO_IO_PTCTL:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            val = (uint32_t *)(n->ptn.reg + addr);

            ret = EINVAL;

            switch(*val) {
                case PTNETMAP_PTCTL_CONFIG:
                    /* Fill CSB fields: nifp_offset, num_*x_rings,
                     * and num_*x_slots. */
                    ret = virtio_net_ptnetmap_get_netmap_if(vdev);
                    break;

                case PTNETMAP_PTCTL_REGIF:
                    /* Emulate a REGIF for the guest. */
                    ret = virtio_net_ptnetmap_up(vdev);
                    break;

                case PTNETMAP_PTCTL_UNREGIF:
                    /* Emulate an UNREGIF for the guest. */
                    ret = virtio_net_ptnetmap_down(vdev);
                    break;

                case PTNETMAP_PTCTL_HOSTMEMID:
                    ret = ptnetmap_get_hostmemid(n->ptn.state);
                    break;

                case PTNETMAP_PTCTL_IFNEW:
                case PTNETMAP_PTCTL_IFDELETE:
                case PTNETMAP_PTCTL_FINALIZE:
                case PTNETMAP_PTCTL_DEREF:
                    /* Not implemented. */
                    ret = 0;
                    break;
            }
            n->ptn.reg[PTNETMAP_VIRTIO_IO_PTSTS] = ret;
            break;

        case PTNETMAP_VIRTIO_IO_CSBBAH:
        case PTNETMAP_VIRTIO_IO_CSBBAL:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            if (addr == PTNETMAP_VIRTIO_IO_CSBBAL) {
                /* Write to CSBBAL triggers the (un)mapping. */
                paravirt_configure_csb(&n->ptn.csb,
                    *((uint32_t *)(n->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAL)),
                    *((uint32_t *)(n->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAH)));
            }
            break;

        default:
            break;
    }
}

static PTNetmapState*
peer_get_ptnetmap(VirtIONet *n)
{
    NetClientState *nc = qemu_get_queue(n->nic);

    if (!nc->peer) {
        return NULL;
    }

    return get_ptnetmap(nc->peer);
}

static void virtio_net_ptnetmap_init(VirtIODevice *vdev)
{
    VirtIONet *n = VIRTIO_NET(vdev);

    n->ptn.up = false;
    n->ptn.state = peer_get_ptnetmap(n);
    if (n->ptn.state == NULL) {
        printf("%s: backend does not support ptnetmap\n", __func__);
    }
}
#endif /* _QEMU_VIRTIO_PTNETMAP_H */
