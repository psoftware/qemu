/*
 * Virtio Prodcons Device
 *
 * Copyright Universita' di Pisa 2016
 *
 * Authors:
 *  Vincenzo Maffione
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/virtio/virtio.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/virtio/virtio-bus.h"
#include "qapi/qmp/qjson.h"
#include "qapi-event.h"
#include "hw/virtio/virtio-access.h"
#include "standard-headers/linux/virtio_ids.h"

#define TYPE_VIRTIO_PRODCONS "virtio-prodcons-device"
#define VIRTIO_PRODCONS(obj) \
        OBJECT_CHECK(VirtIOProdcons, (obj), TYPE_VIRTIO_PRODCONS)

typedef struct virtio_pc_conf
{
    int32_t wc;
} virtio_pc_conf;

typedef struct VirtIOProdcons {
    VirtIODevice parent_obj;
    uint16_t status;
    int32_t wc;
    VirtQueue *dvq;
    QEMUBH *bh;
    int waiting;
    virtio_pc_conf conf;
    DeviceState *qdev;
} VirtIOProdcons;

static void virtio_pc_set_status(struct VirtIODevice *vdev, uint8_t status)
{
}

static void virtio_pc_reset(VirtIODevice *vdev)
{
}

static uint64_t virtio_pc_get_features(VirtIODevice *vdev, uint64_t features,
                                             Error **errp)
{
    return 0;
}

static uint64_t virtio_pc_bad_features(VirtIODevice *vdev)
{
    return 0;
}

static void virtio_pc_set_features(VirtIODevice *vdev, uint64_t features)
{
}

static int32_t virtio_pc_dvq_flush(VirtIOProdcons *pc)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(pc);
    VirtQueueElement *elem;
    int32_t npkts = 0;

    for (;;) {
        unsigned int out_num;
        struct iovec *out_sg;

        elem = virtqueue_pop(pc->dvq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        out_num = elem->out_num;
        out_sg = elem->out_sg;
        if (out_num < 1) {
            virtio_error(vdev, "virtio-prodcons header not in first element");
            virtqueue_detach_element(pc->dvq, elem, 0);
            g_free(elem);
            return -EINVAL;
        }

        /* do something with out_sg, out_num */
        (void)out_sg; (void)out_num;
        /*virtio_queue_set_notification(pc->dvq, 0);*/

        virtqueue_push(pc->dvq, elem, 0);
        virtio_notify(vdev, pc->dvq);
        g_free(elem);

        if (++npkts >= 10) {
            break;
        }
    }

    return npkts;
}

static void virtio_pc_dvq_handler(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);

    if (unlikely(pc->waiting)) {
        return;
    }
    pc->waiting = 1;

    /* This happens when device was stopped but VCPU wasn't. */
    if (!vdev->vm_running) {
        return;
    }
    virtio_queue_set_notification(vq, 0);
    qemu_bh_schedule(pc->bh);
}

static void virtio_pc_dvq_bh(void *opaque)
{
    VirtIOProdcons *pc = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(pc);
    int32_t ret;

    /* This happens when device was stopped but BH wasn't. */
    if (!vdev->vm_running) {
        /* Make sure waiting is set, so we'll run when restarted. */
        assert(pc->waiting);
        return;
    }

    pc->waiting = 0;

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK))) {
        return;
    }

    ret = virtio_pc_dvq_flush(pc);
    if (ret == -EINVAL) {
        return; /* device broken */
    }

    /* If we flush a full burst of packets, assume there are
     * more coming and immediately reschedule */
    if (ret >= 10) {
        qemu_bh_schedule(pc->bh);
        pc->waiting = 1;
        return;
    }

    /* If less than a full burst, re-enable notification and flush
     * anything that may have come in while we weren't looking.  If
     * we find something, assume the guest is still active and reschedule */
    virtio_queue_set_notification(pc->dvq, 1);
    ret = virtio_pc_dvq_flush(pc);
    if (ret == -EINVAL) {
        return;
    } else if (ret > 0) {
        virtio_queue_set_notification(pc->dvq, 0);
        qemu_bh_schedule(pc->bh);
        pc->waiting = 1;
    }
}

static void virtio_pc_save_device(VirtIODevice *vdev, QEMUFile *f)
{
}

static int virtio_pc_load_device(VirtIODevice *vdev, QEMUFile *f, int version_id)
{
    return 0;
}

static void virtio_pc_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOProdcons *pc = VIRTIO_PRODCONS(dev);

    virtio_init(vdev, "virtio-prodcons", VIRTIO_ID_PRODCONS, 0 /* config size */);

    pc->dvq = virtio_add_queue(vdev, 256, virtio_pc_dvq_handler);
    pc->bh = qemu_bh_new(virtio_pc_dvq_bh, pc);
    pc->status = 0;
    pc->waiting = 0;
    pc->wc = pc->conf.wc;
    pc->qdev = dev;
}

static void virtio_pc_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOProdcons *pc = VIRTIO_PRODCONS(dev);

    virtio_del_queue(vdev, 0);
    qemu_bh_delete(pc->bh);
    virtio_cleanup(vdev);
}

static void virtio_pc_instance_init(Object *obj)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(obj);

    (void)pc;
}

static const VMStateDescription vmstate_virtio_pc = {
    .name = "virtio-prodcons",
    .minimum_version_id = 1,
    .version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property virtio_pc_properties[] = {
    DEFINE_PROP_INT32("wc", VirtIOProdcons, conf.wc, 100), /* ns */
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_pc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_pc_properties;
    dc->vmsd = &vmstate_virtio_pc;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_pc_device_realize;
    vdc->unrealize = virtio_pc_device_unrealize;
    vdc->get_features = virtio_pc_get_features;
    vdc->set_features = virtio_pc_set_features;
    vdc->bad_features = virtio_pc_bad_features;
    vdc->reset = virtio_pc_reset;
    vdc->set_status = virtio_pc_set_status;
    vdc->load = virtio_pc_load_device;
    vdc->save = virtio_pc_save_device;
}

static const TypeInfo virtio_pc_info = {
    .name = TYPE_VIRTIO_PRODCONS,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOProdcons),
    .instance_init = virtio_pc_instance_init,
    .class_init = virtio_pc_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_pc_info);
}

type_init(virtio_register_types)
