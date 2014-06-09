/*
 * virtio support for MPI
 *
 * Copyright Nextworks 2014
 *
 * Authors:
 *  Vincenzo Maffione   <v.maffione@nextworks>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "hw/virtio/virtio.h"
#include "qemu/error-report.h"
#include "hw/virtio/virtio-mpi.h"
#include "net/vhost_mpi.h"
#include "hw/virtio/virtio-bus.h"


#define VIRTIO_MPI_VM_VERSION   1
#define VIRTIO_MPI_RING_SIZE    256

static void virtio_mpi_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);
    struct virtio_mpi_config netcfg;

    stw_p(&netcfg.status, mpi->status);
    memcpy(config, &netcfg, sizeof(netcfg));

    IFV(printf("virtio_mpi_get_config\n"));
}

static void virtio_mpi_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);
    struct virtio_mpi_config netcfg = {};

    memcpy(&netcfg, config, sizeof(netcfg));
    mpi->status = netcfg.status;

    IFV(printf("virtio_mpi_set_config\n"));
}

static bool virtio_mpi_started(VirtIOMpi *mpi, uint8_t status)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(mpi);
    return (status & VIRTIO_CONFIG_S_DRIVER_OK) &&
                 vdev->vm_running;
}

static void virtio_mpi_vhost_status(VirtIOMpi *mpi, uint8_t status)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(mpi);
    int queues = 1;

    if (!!mpi->vhost_started ==
        (virtio_mpi_started(mpi, status))) {
        return;
    }
    if (!mpi->vhost_started) {
        int r;
        if (!vhost_mpi_query(mpi->vhost_mpi, vdev)) {
            return;
        }
        mpi->vhost_started = 1;
        r = vhost_mpi_start(vdev, queues);
        if (r < 0) {
            error_report("unable to start vhost net: %d: "
                         "falling back on userspace virtio", -r);
            mpi->vhost_started = 0;
        }
    } else {
        vhost_mpi_stop(vdev, queues);
        mpi->vhost_started = 0;
    }
}

static void virtio_mpi_set_status(struct VirtIODevice *vdev, uint8_t status)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);

    IFV(printf("virtio_mpi_set_status %d\n", status));

    virtio_mpi_vhost_status(mpi, status);
}

static void virtio_mpi_reset(VirtIODevice *vdev)
{
    IFV(VirtIOMpi *mpi = VIRTIO_MPI(vdev));
    IFV(printf("virtio_mpi_reset %p\n", mpi));
}

static uint32_t virtio_mpi_get_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);

    features = vhost_mpi_get_features(mpi->vhost_mpi, features);
    IFV(printf("virtio_mpi_get_features %x\n", features));

    return features;
}

static uint32_t virtio_mpi_bad_features(VirtIODevice *vdev)
{
    IFV(printf("virtio_mpi_bad_features\n"));

    return 0;
}

static void virtio_mpi_set_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);
    int i;

    for (i = 0;  i < 1; i++) {
        vhost_mpi_ack_features(mpi->vhost_mpi, features);
    }

    IFV(printf("virtio_mpi_set_features %x\n", features));
}

/* RX */

static void virtio_mpi_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);

    printf("RX kick %p\n", mpi);
}

/* TX */
static void virtio_mpi_handle_tx_bh(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK))) {
       IFV( printf("driver not ready\n"));
        return;
    }

    /* This happens when device was stopped but VCPU wasn't. */
    if (!vdev->vm_running) {
        IFV(printf("!vm_running\n"));
        return;
    }

    printf("TX kick %p\n", mpi);
}

static void virtio_mpi_save(QEMUFile *f, void *opaque)
{
    VirtIOMpi *mpi = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(mpi);

    /* At this point, backend must be stopped, otherwise
     * it might keep writing to memory. */
    assert(!mpi->vhost_started);
    virtio_save(vdev, f);

    qemu_put_be16(f, mpi->status);
}

static int virtio_mpi_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIOMpi *mpi = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(mpi);
    int ret;

    ret = virtio_load(vdev, f);
    if (ret) {
        return ret;
    }

    mpi->status = qemu_get_be16(f);

    return 0;
}

static bool virtio_mpi_guest_notifier_pending(VirtIODevice *vdev, int idx)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);

    IFV(printf("virtio_mpi_guest_notifier_pending\n"));
    assert(mpi->vhost_started);
    return vhost_mpi_virtqueue_pending(mpi->vhost_mpi, idx);
}

static void virtio_mpi_guest_notifier_mask(VirtIODevice *vdev, int idx,
                                           bool mask)
{
    VirtIOMpi *mpi = VIRTIO_MPI(vdev);

    IFV(printf("virtio_mpi_guest_notifier_mask\n"));
    assert(mpi->vhost_started);
    vhost_mpi_virtqueue_mask(mpi->vhost_mpi, vdev, idx, mask);
}

static void virtio_mpi_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOMpi *mpi = VIRTIO_MPI(dev);
    int queues = 1;

    virtio_init(vdev, "virtio-mpi", VIRTIO_ID_MPI,
                sizeof(struct virtio_mpi_config));

    mpi->vqs = g_malloc0(sizeof(VirtIOMpiQueue) * queues);
    mpi->vqs[0].rx_vq = virtio_add_queue(vdev, VIRTIO_MPI_RING_SIZE, virtio_mpi_handle_rx);
    mpi->vqs[0].mpi = mpi;

    mpi->vqs[0].tx_vq = virtio_add_queue(vdev, VIRTIO_MPI_RING_SIZE, virtio_mpi_handle_tx_bh);
    mpi->status = 1;

    mpi->qdev = dev;
    register_savevm(dev, "virtio-mpi", -1, VIRTIO_MPI_VM_VERSION,
                    virtio_mpi_save, virtio_mpi_load, mpi);

    IFV(printf("virtio_mpi_device_realize\n"));
}

static void virtio_mpi_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOMpi *mpi = VIRTIO_MPI(dev);

    /* This will stop vhost backend if appropriate. */
    virtio_mpi_set_status(vdev, 0);

    unregister_savevm(dev, "virtio-mpi", mpi);

    g_free(mpi->vqs);
    virtio_cleanup(vdev);

    IFV(printf("virtio_mpi_device_unrealize\n"));
}

static void virtio_mpi_instance_init(Object *obj)
{
    VirtIOMpi *mpi = VIRTIO_MPI(obj);

    mpi->vhost_mpi = vhost_mpi_init(-1, false);
    if (!mpi->vhost_mpi) {
        perror("vhost_mpi_init failed\n");
        exit(EXIT_FAILURE);
    }
    IFV(printf("vhost-mpi initialized\n"));
}

static Property virtio_mpi_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_mpi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_mpi_properties;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    vdc->realize = virtio_mpi_device_realize;
    vdc->unrealize = virtio_mpi_device_unrealize;
    vdc->get_config = virtio_mpi_get_config;
    vdc->set_config = virtio_mpi_set_config;
    vdc->get_features = virtio_mpi_get_features;
    vdc->set_features = virtio_mpi_set_features;
    vdc->bad_features = virtio_mpi_bad_features;
    vdc->reset = virtio_mpi_reset;
    vdc->set_status = virtio_mpi_set_status;
    vdc->guest_notifier_mask = virtio_mpi_guest_notifier_mask;
    vdc->guest_notifier_pending = virtio_mpi_guest_notifier_pending;
}

static const TypeInfo virtio_mpi_info = {
    .name = TYPE_VIRTIO_MPI,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOMpi),
    .instance_init = virtio_mpi_instance_init,
    .class_init = virtio_mpi_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_mpi_info);
}

type_init(virtio_register_types)
