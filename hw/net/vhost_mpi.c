/*
 * vhost support for MPI
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

#include <stdio.h>

#include "hw/virtio/vhost.h"
#include "hw/virtio/virtio-bus.h"


struct vhost_mpi {
    struct vhost_dev dev;
    struct vhost_virtqueue vqs[2];
};

unsigned vhost_mpi_get_features(struct vhost_mpi *mpi, unsigned features)
{
    /* Clear features not supported by host kernel. */
    if (!(mpi->dev.features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY))) {
        features &= ~(1 << VIRTIO_F_NOTIFY_ON_EMPTY);
    }
    if (!(mpi->dev.features & (1 << VIRTIO_RING_F_INDIRECT_DESC))) {
        features &= ~(1 << VIRTIO_RING_F_INDIRECT_DESC);
    }
    if (!(mpi->dev.features & (1 << VIRTIO_RING_F_EVENT_IDX))) {
        features &= ~(1 << VIRTIO_RING_F_EVENT_IDX);
    }
    return features;
}

void vhost_mpi_ack_features(struct vhost_mpi *mpi, unsigned features)
{
    mpi->dev.acked_features = mpi->dev.backend_features;
    if (features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY)) {
        mpi->dev.acked_features |= (1 << VIRTIO_F_NOTIFY_ON_EMPTY);
    }
    if (features & (1 << VIRTIO_RING_F_INDIRECT_DESC)) {
        mpi->dev.acked_features |= (1 << VIRTIO_RING_F_INDIRECT_DESC);
    }
    if (features & (1 << VIRTIO_RING_F_EVENT_IDX)) {
        mpi->dev.acked_features |= (1 << VIRTIO_RING_F_EVENT_IDX);
    }
}

struct vhost_mpi *vhost_mpi_init(int devfd, bool force)
{
    int r;
    struct vhost_mpi *mpi = g_malloc(sizeof *mpi);
    mpi->dev.backend_features = 0;

    /* XXX probably VirtIODevice could be VirtIOMpi, and the
        caller needs to link the VirtIOMpi instance to the vhost_mpi instance
        allocated here.  */

    mpi->dev.nvqs = 2;
    mpi->dev.vqs = mpi->vqs;

    r = vhost_dev_init(&mpi->dev, devfd, "/dev/vhost-mpi", force);
    if (r < 0) {
        goto fail;
    }
    if (~mpi->dev.features & mpi->dev.backend_features) {
        fprintf(stderr, "vhost lacks feature mask %" PRIu64 " for backend\n",
                (uint64_t)(~mpi->dev.features & mpi->dev.backend_features));
        vhost_dev_cleanup(&mpi->dev);
        goto fail;
    }

    /* Set sane init value. Override when guest acks. */
    vhost_mpi_ack_features(mpi, 0);
    return mpi;
fail:
    g_free(mpi);
    return NULL;
}

bool vhost_mpi_query(VHostMpiState *mpi, VirtIODevice *dev)
{
    return vhost_dev_query(&mpi->dev, dev);
}

struct vhost_mpi_command {
    unsigned int index;
    unsigned int enable;
};

/* Name overloading. Should be a temporary solution. */
#define VHOST_MPI_STARTSTOP     VHOST_NET_SET_BACKEND

static int vhost_mpi_start_one(struct vhost_mpi *mpi,
                               VirtIODevice *dev,
                               int vq_index)
{
    int r;
    struct vhost_mpi_command cmd = {
            .enable = 1,
        };

    if (mpi->dev.started) {
        return 0;
    }

    mpi->dev.nvqs = 2;
    mpi->dev.vqs = mpi->vqs;
    mpi->dev.vq_index = vq_index;

    r = vhost_dev_enable_notifiers(&mpi->dev, dev);
    if (r < 0) {
        goto fail_notifiers;
    }

    r = vhost_dev_start(&mpi->dev, dev);
    if (r < 0) {
        goto fail_start;
    }

    /* VHOST_NET_SET_BACKEND used to implement "VHOST_MPI_START" */
    for (cmd.index = 0; cmd.index < mpi->dev.nvqs; cmd.index++) {
        r = ioctl(mpi->dev.control, VHOST_MPI_STARTSTOP, &cmd);
        if (r < 0) {
            r = -errno;
            goto fail;
        }
    }

    return 0;
fail:
    cmd.enable = 0;
    while (cmd.index-- > 0) {
        int r = ioctl(mpi->dev.control, VHOST_NET_SET_BACKEND, &cmd);
        assert(r >= 0);
    }
    vhost_dev_stop(&mpi->dev, dev);
fail_start:
    vhost_dev_disable_notifiers(&mpi->dev, dev);
fail_notifiers:
    return r;
}

static void vhost_mpi_stop_one(struct vhost_mpi *mpi,
                               VirtIODevice *dev)
{
    struct vhost_mpi_command cmd = {
            .enable = 0,
        };

    if (!mpi->dev.started) {
        return;
    }

    /* VHOST_NET_SET_BACKEND used to implement "VHOST_MPI_STOP" */
    for (cmd.index = 0; cmd.index < mpi->dev.nvqs; cmd.index++) {
        int r = ioctl(mpi->dev.control, VHOST_MPI_STARTSTOP, &cmd);
        assert(r >= 0);
    }

    vhost_dev_stop(&mpi->dev, dev);
    vhost_dev_disable_notifiers(&mpi->dev, dev);
}

int vhost_mpi_start(VirtIODevice *dev, int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VHostMpiState *mpi = VIRTIO_MPI(dev)->vhost_mpi;
    int r, i = 0;

    IFV(printf("vhost_mpi_start\n"));

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        r = -ENOSYS;
        goto err;
    }

    for (i = 0; i < total_queues; i++) {
        r = vhost_mpi_start_one(mpi, dev, i * 2);

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
    VHostMpiState *mpi = VIRTIO_MPI(dev)->vhost_mpi;
    int i, r;

    IFV(printf("vhost_mpi_stop\n"));

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, false);
    if (r < 0) {
        fprintf(stderr, "vhost guest notifier cleanup failed: %d\n", r);
        fflush(stderr);
    }
    assert(r >= 0);

    for (i = 0; i < total_queues; i++) {
        vhost_mpi_stop_one(mpi, dev);
    }
}

void vhost_mpi_cleanup(struct vhost_mpi *mpi)
{
    vhost_dev_cleanup(&mpi->dev);
    g_free(mpi);
}

bool vhost_mpi_virtqueue_pending(VHostMpiState *mpi, int idx)
{
    return vhost_virtqueue_pending(&mpi->dev, idx);
}

void vhost_mpi_virtqueue_mask(VHostMpiState *mpi, VirtIODevice *dev,
                              int idx, bool mask)
{
    vhost_virtqueue_mask(&mpi->dev, dev, idx, mask);
}
// TODO #endif  /* CONFIG_VHOST_MPI */
