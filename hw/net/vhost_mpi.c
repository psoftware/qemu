/*
 * vhost-mpi support
 *
 * Copyright Nextworks 2014
 *
 * Authors:
 *  Vincenzo Maffione <v.maffione@nextworks.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "hw/virtio/virtio-mpi.h"
#include "net/vhost_mpi.h"
#include "qemu/error-report.h"

#include "config.h"

// TODO #ifdef CONFIG_VHOST_MPI
#include <linux/vhost.h>
#include <sys/socket.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/virtio_ring.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>

#include "hw/virtio/vhost.h"
#include "hw/virtio/virtio-bus.h"


struct vhost_mpi {
    struct vhost_dev dev;
    struct vhost_virtqueue vqs[2];
};

unsigned vhost_mpi_get_features(struct vhost_mpi *net, unsigned features)
{
    /* Clear features not supported by host kernel. */
    if (!(net->dev.features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY))) {
        features &= ~(1 << VIRTIO_F_NOTIFY_ON_EMPTY);
    }
    if (!(net->dev.features & (1 << VIRTIO_RING_F_INDIRECT_DESC))) {
        features &= ~(1 << VIRTIO_RING_F_INDIRECT_DESC);
    }
    if (!(net->dev.features & (1 << VIRTIO_RING_F_EVENT_IDX))) {
        features &= ~(1 << VIRTIO_RING_F_EVENT_IDX);
    }
    return features;
}

void vhost_mpi_ack_features(struct vhost_mpi *net, unsigned features)
{
    net->dev.acked_features = net->dev.backend_features;
    if (features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY)) {
        net->dev.acked_features |= (1 << VIRTIO_F_NOTIFY_ON_EMPTY);
    }
    if (features & (1 << VIRTIO_RING_F_INDIRECT_DESC)) {
        net->dev.acked_features |= (1 << VIRTIO_RING_F_INDIRECT_DESC);
    }
    if (features & (1 << VIRTIO_RING_F_EVENT_IDX)) {
        net->dev.acked_features |= (1 << VIRTIO_RING_F_EVENT_IDX);
    }
}

struct vhost_mpi *vhost_mpi_init(int devfd, bool force)
{
    int r;
    struct vhost_mpi *net = g_malloc(sizeof *net);
    net->dev.backend_features = 0;

    /* XXX probably VirtIODevice could be VirtIOMpi, and the
        caller needs to link the VirtIOMpi instance to the vhost_mpi instance
        allocated here.  */

    net->dev.nvqs = 2;
    net->dev.vqs = net->vqs;

    r = vhost_dev_init(&net->dev, devfd, "/dev/vhost-mpi", force);
    if (r < 0) {
        goto fail;
    }
    if (~net->dev.features & net->dev.backend_features) {
        fprintf(stderr, "vhost lacks feature mask %" PRIu64 " for backend\n",
                (uint64_t)(~net->dev.features & net->dev.backend_features));
        vhost_dev_cleanup(&net->dev);
        goto fail;
    }

    /* Set sane init value. Override when guest acks. */
    vhost_mpi_ack_features(net, 0);
    return net;
fail:
    g_free(net);
    return NULL;
}

bool vhost_mpi_query(VHostMpiState *net, VirtIODevice *dev)
{
    return vhost_dev_query(&net->dev, dev);
}

static int vhost_mpi_start_one(struct vhost_mpi *net,
                               VirtIODevice *dev,
                               int vq_index)
{
    int r;

    if (net->dev.started) {
        return 0;
    }

    net->dev.nvqs = 2;
    net->dev.vqs = net->vqs;
    net->dev.vq_index = vq_index;

    r = vhost_dev_enable_notifiers(&net->dev, dev);
    if (r < 0) {
        goto fail_notifiers;
    }

    r = vhost_dev_start(&net->dev, dev);
    if (r < 0) {
        goto fail_start;
    }

    /* XXX here used to be VHOST_NET_SET_BACKEND, that (IIRC)
        also starts the tap backend.. for vhost-mpi we don't
        need to pass file descriptors around, but probably we
        need an ioctl(VHOST_MPI_START), to make it possible for
        userspace to start write()/read().
    */

    return 0;

fail_start:
    vhost_dev_disable_notifiers(&net->dev, dev);
fail_notifiers:
    return r;
}

static void vhost_mpi_stop_one(struct vhost_mpi *net,
                               VirtIODevice *dev)
{
    if (!net->dev.started) {
        return;
    }

    /* XXX here used to be ioctl(VHOST_NET_SET_BACKEND, fd = -1), to disable
        the backend. We don't need to set any file descriptors, but we
        probably need an ioictl(VHOST_MPI_STOP) to prevent the userspace
        from write()/read().
    */

    vhost_dev_stop(&net->dev, dev);
    vhost_dev_disable_notifiers(&net->dev, dev);
}

int vhost_mpi_start(VirtIODevice *dev, int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VHostMpiState *net = VIRTIO_MPI(dev)->vhost_mpi;
    int r, i = 0;

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        r = -ENOSYS;
        goto err;
    }

    for (i = 0; i < total_queues; i++) {
        r = vhost_mpi_start_one(net, dev, i * 2);

        if (r < 0) {
            goto err;
        }
    }

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, true);
    if (r < 0) {
        error_report("Error binding guest notifier: %d", -r);
        goto err;
    }

    return 0;

err:
    while (--i >= 0) {
        vhost_mpi_stop_one(NULL, dev);
    }
    return r;
}

void vhost_mpi_stop(VirtIODevice *dev, int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VHostMpiState *net = VIRTIO_MPI(dev)->vhost_mpi;
    int i, r;

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, false);
    if (r < 0) {
        fprintf(stderr, "vhost guest notifier cleanup failed: %d\n", r);
        fflush(stderr);
    }
    assert(r >= 0);

    for (i = 0; i < total_queues; i++) {
        vhost_mpi_stop_one(net, dev);
    }
}

void vhost_mpi_cleanup(struct vhost_mpi *net)
{
    vhost_dev_cleanup(&net->dev);
    g_free(net);
}

bool vhost_mpi_virtqueue_pending(VHostMpiState *net, int idx)
{
    return vhost_virtqueue_pending(&net->dev, idx);
}

void vhost_mpi_virtqueue_mask(VHostMpiState *net, VirtIODevice *dev,
                              int idx, bool mask)
{
    vhost_virtqueue_mask(&net->dev, dev, idx, mask);
}
// TODO #endif  /* CONFIG_VHOST_MPI */
