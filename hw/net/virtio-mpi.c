/*
 * Virtio Support for MPI
 *
 * Authors:
 *  Vincenzo Maffione   <v.maffione@nextworks>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/iov.h"
#include "hw/virtio/virtio.h"
#include "net/net.h"
#include "net/checksum.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/virtio/virtio-mpi.h"
#include "net/vhost_mpi.h"
#include "hw/virtio/virtio-bus.h"
#include "qapi/qmp/qjson.h"
#include "monitor/monitor.h"


#define VIRTIO_MPI_VM_VERSION   1

static void virtio_mpi_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);
    struct virtio_mpi_config netcfg;

    stw_p(&netcfg.status, n->status);
    memcpy(config, &netcfg, sizeof(netcfg));

    printf("virtio_mpi_get_config\n");
}

static void virtio_mpi_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);
    struct virtio_mpi_config netcfg = {};

    memcpy(&netcfg, config, sizeof(netcfg));
    n->status = netcfg.status;

    printf("virtio_mpi_set_config\n");
}

static bool virtio_mpi_started(VirtIOMpi *n, uint8_t status)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    printf("virtio_mpi_started status %x running %d\n", status, vdev->vm_running);
    return (status & VIRTIO_CONFIG_S_DRIVER_OK) &&
                 vdev->vm_running;
}

static void virtio_mpi_vhost_status(VirtIOMpi *n, uint8_t status)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    int queues = 1;

    if (!!n->vhost_started ==
        (virtio_mpi_started(n, status))) {
        return;
    }
    if (!n->vhost_started) {
        int r;
        if (!vhost_mpi_query(n->vhost_mpi, vdev)) {
            return;
        }
        n->vhost_started = 1;
        r = vhost_mpi_start(vdev, queues);
        if (r < 0) {
            error_report("unable to start vhost net: %d: "
                         "falling back on userspace virtio", -r);
            n->vhost_started = 0;
        }
    } else {
        vhost_mpi_stop(vdev, queues);
        n->vhost_started = 0;
    }
}

static void virtio_mpi_set_status(struct VirtIODevice *vdev, uint8_t status)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    printf("virtio_mpi_set_status %d\n", status);

    virtio_mpi_vhost_status(n, status);
}

static void virtio_mpi_reset(VirtIODevice *vdev)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    printf("virtio_mpi_reset %p\n", n);
}

static uint32_t virtio_mpi_get_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    features = vhost_mpi_get_features(n->vhost_mpi, features);
    printf("virtio_mpi_get_features %x\n", features);

    return features;
}

static uint32_t virtio_mpi_bad_features(VirtIODevice *vdev)
{
    printf("virtio_mpi_bad_features\n");

    return 0;
}

static void virtio_mpi_set_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);
    int i;

    for (i = 0;  i < 1; i++) {
        vhost_mpi_ack_features(n->vhost_mpi, features);
    }

    printf("virtio_mpi_set_features %x\n", features);
}

/* RX */

static void virtio_mpi_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    printf("RX kick %p\n", n);
}

/* TX */
static void virtio_mpi_handle_tx_bh(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK))) {
        printf("driver not ready\n");
        return;
    }

    /* This happens when device was stopped but VCPU wasn't. */
    if (!vdev->vm_running) {
        printf("!vm_running\n");
        return;
    }

    printf("TX kick %p\n", n);
}

static void virtio_mpi_save(QEMUFile *f, void *opaque)
{
    VirtIOMpi *n = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(n);

    /* At this point, backend must be stopped, otherwise
     * it might keep writing to memory. */
    assert(!n->vhost_started);
    virtio_save(vdev, f);

    qemu_put_be16(f, n->status);
}

static int virtio_mpi_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIOMpi *n = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    int ret;

    ret = virtio_load(vdev, f);
    if (ret) {
        return ret;
    }

    n->status = qemu_get_be16(f);

    return 0;
}

static bool virtio_mpi_guest_notifier_pending(VirtIODevice *vdev, int idx)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    printf("virtio_mpi_guest_notifier_pending\n");
    assert(n->vhost_started);
    return vhost_mpi_virtqueue_pending(n->vhost_mpi, idx);
}

static void virtio_mpi_guest_notifier_mask(VirtIODevice *vdev, int idx,
                                           bool mask)
{
    VirtIOMpi *n = VIRTIO_MPI(vdev);

    printf("virtio_mpi_guest_notifier_mask\n");
    assert(n->vhost_started);
    vhost_mpi_virtqueue_mask(n->vhost_mpi, vdev, idx, mask);
}

static void virtio_mpi_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOMpi *n = VIRTIO_MPI(dev);
    int queues = 1;

    virtio_init(vdev, "virtio-mpi", VIRTIO_ID_MPI,
                sizeof(struct virtio_mpi_config));

    n->vqs = g_malloc0(sizeof(VirtIOMpiQueue) * queues);
    n->vqs[0].rx_vq = virtio_add_queue(vdev, 256, virtio_mpi_handle_rx);
    n->vqs[0].n = n;

    n->vqs[0].tx_vq = virtio_add_queue(vdev, 256, virtio_mpi_handle_tx_bh);
    n->status = 1;

    n->qdev = dev;
    register_savevm(dev, "virtio-mpi", -1, VIRTIO_MPI_VM_VERSION,
                    virtio_mpi_save, virtio_mpi_load, n);

    printf("virtio_mpi_device_realize\n");
}

static void virtio_mpi_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOMpi *n = VIRTIO_MPI(dev);

    /* This will stop vhost backend if appropriate. */
    virtio_mpi_set_status(vdev, 0);

    unregister_savevm(dev, "virtio-mpi", n);

    g_free(n->vqs);
    virtio_cleanup(vdev);

    printf("virtio_mpi_device_unrealize\n");
}

static void virtio_mpi_instance_init(Object *obj)
{
    VirtIOMpi *n = VIRTIO_MPI(obj);

    n->vhost_mpi = vhost_mpi_init(-1, false);
    if (!n->vhost_mpi) {
        perror("vhost_mpi_init failed\n");
        exit(EXIT_FAILURE);
    }
    printf("vhost-mpi initialized\n");
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
