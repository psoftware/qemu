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
#include "hw/virtio/virtio-prodcons.h"
#include "qapi/qmp/qjson.h"
#include "qapi-event.h"
#include "hw/virtio/virtio-access.h"
#include "standard-headers/linux/virtio_ids.h"
#include <linux/vhost.h>
#include <linux/kvm.h>
#include "hw/virtio/vhost.h"


struct virtio_pc_config {
    uint32_t    wc;
    uint32_t    yc;
};

/******************************* TSC support ***************************/

/* initialize to avoid a division by 0 */
static uint64_t ticks_per_second = 1000000000; /* set by calibrate_tsc */

static inline uint64_t
rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/*
 * do an idle loop to compute the clock speed. We expect
 * a constant TSC rate and locked on all CPUs.
 * Returns ticks per second
 */
static uint64_t
calibrate_tsc(void)
{
    struct timeval a, b;
    uint64_t ta_0, ta_1, tb_0, tb_1, dmax = ~0;
    uint64_t da, db, cy = 0;
    int i;
    for (i=0; i < 3; i++) {
	ta_0 = rdtsc();
	gettimeofday(&a, NULL);
	ta_1 = rdtsc();
	usleep(20000);
	tb_0 = rdtsc();
	gettimeofday(&b, NULL);
	tb_1 = rdtsc();
	da = ta_1 - ta_0;
	db = tb_1 - tb_0;
	if (da + db < dmax) {
	    cy = (b.tv_sec - a.tv_sec)*1000000 + b.tv_usec - a.tv_usec;
	    cy = (double)(tb_0 - ta_1)*1000000/(double)cy;
	    dmax = da + db;
	}
    }
    ticks_per_second = cy;
    return cy;
}

#define NS2TSC(x) ((x)*ticks_per_second/1000000000UL)
#define TSC2NS(x) ((x)*1000000000UL/ticks_per_second)

static inline void
tsc_sleep_till(uint64_t when)
{
    while (rdtsc() < when)
        barrier();
}

/******************************* VHOST support ***************************/

static int virtio_pc_set_params(VirtIOProdcons *pc, unsigned int wc,
                                unsigned int yc)
{
    struct vhost_vring_file file;
    int r;

    pc->wc = wc;
    pc->yc = yc;

    if (!pc->vhost_running) {
        return 0;
    }

    /* We override the VHOST_NET_SET_BACKEND ioctl to pass the
     * wc parameter to the vhost-pc kernel module. */
    file.index = pc->wc;
    file.fd = (int)pc->yc;
    r = vhost_net_set_backend(&pc->hdev, &file);
    if (r < 0) {
        error_report("Error setting wc parameter: %d", -r);
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* Features supported by host kernel. */
static const int pc_kernel_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_VERSION_1,
    VHOST_INVALID_FEATURE_BIT
};

static uint64_t vhost_pc_get_features(VirtIOProdcons *pc, uint64_t features)
{
    return vhost_get_features(&pc->hdev, pc_kernel_feature_bits, features);
}

static void vhost_pc_ack_features(VirtIOProdcons *pc, uint64_t features)
{
    pc->hdev.acked_features = pc->hdev.backend_features; /* is this 0 = 0 ? */
    vhost_ack_features(&pc->hdev, pc_kernel_feature_bits, features);
}

static int vhost_pc_start(VirtIOProdcons *pc)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(pc);
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    int r;

    if (pc->vhost_running) {
        return 0;
    }
    pc->vhost_running = 1;

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        exit(EXIT_FAILURE);
    }

    r = k->set_guest_notifiers(qbus->parent, 1, true);
    if (r < 0) {
        error_report("Error binding guest notifier: %d", -r);
        exit(EXIT_FAILURE);
    }

    r = vhost_dev_enable_notifiers(&pc->hdev, vdev);
    if (r < 0) {
        error_report("Error binding host notifier: %d", -r);
        exit(EXIT_FAILURE);
    }

    r = vhost_dev_start(&pc->hdev, vdev);
    if (r < 0) {
        error_report("Error starting vhost device: %d", -r);
        exit(EXIT_FAILURE);
    }

    virtio_pc_set_params(pc, pc->wc, pc->yc);

    printf("vhost-pc started ...\n");

    return 0;
}

static int vhost_pc_stop(VirtIOProdcons *pc)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(pc);
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    int r;

    if (!pc->vhost_running) {
        return 0;
    }

    vhost_dev_stop(&pc->hdev, vdev);
    vhost_dev_disable_notifiers(&pc->hdev, vdev);

    r = k->set_guest_notifiers(qbus->parent, 1, false);
    if (r < 0) {
        fprintf(stderr, "vhost guest notifier cleanup failed: %d\n", r);
        exit(EXIT_FAILURE);
    }

    pc->vhost_running = 0;
    printf("vhost-pc stopped\n");

    return 0;
}

static int vhost_pc_init(VirtIOProdcons *pc)
{
    int vhostfd;
    int r;

    pc->hdev.max_queues = 1;
    pc->hdev.nvqs = 1;
    pc->hdev.vqs = &pc->hvq;
    pc->hdev.vq_index = 0;
    pc->hdev.protocol_features = 0;
    pc->hdev.backend_features = 0;

    vhostfd = open("/dev/vhost-pc", O_RDWR);
    if (vhostfd < 0) {
        error_report("Error opening vhost dev: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    r = vhost_dev_init(&pc->hdev, (void *)(uintptr_t)vhostfd,
                       VHOST_BACKEND_TYPE_KERNEL, 0);
    if (r < 0) {
        error_report("Error initializing vhost dev: %d", -r);
        exit(EXIT_FAILURE);
    }

    vhost_pc_ack_features(pc, 0); /* probably useless */

    return 0;
}

static void virtio_pc_set_status(struct VirtIODevice *vdev, uint8_t status)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);

    if (!pc->conf.vhost) {
        return;
    }

    if ((status & VIRTIO_CONFIG_S_DRIVER_OK) && vdev->vm_running) {
        vhost_pc_start(pc);
    } else {
        vhost_pc_stop(pc);
    }
}

static void virtio_pc_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);
    struct virtio_pc_config cfg;

    memcpy(&cfg, config, sizeof(cfg));
    virtio_pc_set_params(pc, cfg.wc, cfg.yc);
}

/***********************************************************************/

static void virtio_pc_reset(VirtIODevice *vdev)
{
}

static uint64_t virtio_pc_get_features(VirtIODevice *vdev, uint64_t features,
                                             Error **errp)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);

    if (!pc->conf.vhost) {
        return features;
    }

    return vhost_pc_get_features(pc, features);
}

static uint64_t virtio_pc_bad_features(VirtIODevice *vdev)
{
    return 0;
}

static void virtio_pc_set_features(VirtIODevice *vdev, uint64_t features)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);

    if (!pc->conf.vhost) {
        return;
    }

    vhost_pc_ack_features(pc, features);
}

#define MAX_BATCH   128

static unsigned int virtio_pc_dvq_flush(VirtIOProdcons *pc)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(pc);
    unsigned int items = 0;
    uint64_t next = rdtsc();

    do {
        VirtQueueElement *elem;

        tsc_sleep_till(next);
        next = rdtsc() + NS2TSC(pc->wc);

        elem = virtqueue_pop(pc->dvq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        /* We could do something with elem->out_sg, elem->out_num. */
#if 0
        printf("pc: in_num %u out_num %u\n", elem->in_num, elem->out_num);
#endif

        virtqueue_push(pc->dvq, elem, 0);
        g_free(elem);
        pc->stats.interrupts += virtio_notify(vdev, pc->dvq);

    } while (++ items < MAX_BATCH);

    pc->stats.items += items;
    if (unlikely(rdtsc() > pc->stats.next_dump)) {
        uint64_t mdiff = TSC2NS(rdtsc() - pc->stats.last_dump)/1000000;

        printf("PC: %6.3f Kitems, %6.3f Kkicks, %6.3f Kintrs\n",
                ((double)pc->stats.items)/mdiff,
                ((double)pc->stats.kicks)/mdiff,
                ((double)pc->stats.interrupts)/mdiff);
        pc->stats.items = pc->stats.kicks = pc->stats.interrupts = 0;
        pc->stats.last_dump = rdtsc();
        pc->stats.next_dump = pc->stats.last_dump + NS2TSC(1000000000);
    }

    return items;
}

static void virtio_pc_dvq_handler(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);

    pc->stats.kicks ++;

    if (unlikely(pc->dvq_pending)) {
        return;
    }
    pc->dvq_pending = 1;

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
    unsigned int ret;

    /* This happens when device was stopped but BH wasn't. */
    if (!vdev->vm_running) {
        /* Make sure dvq_pending is set, so we'll run when restarted. */
        assert(pc->dvq_pending);
        return;
    }

    pc->dvq_pending = 0;

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK))) {
        return;
    }

    ret = virtio_pc_dvq_flush(pc);

    /* If we flush a full burst of packets, assume there are
     * more coming and immediately reschedule */
    if (ret >= MAX_BATCH) {
        qemu_bh_schedule(pc->bh);
        pc->dvq_pending = 1;
        return;
    }

    /* If less than a full burst, re-enable notification and flush
     * anything that may have come in while we weren't looking.  If
     * we find something, assume the guest is still active and reschedule */
    virtio_queue_set_notification(pc->dvq, 1);
    ret = virtio_pc_dvq_flush(pc);
    if (ret > 0) {
        virtio_queue_set_notification(pc->dvq, 0);
        qemu_bh_schedule(pc->bh);
        pc->dvq_pending = 1;
    }
}

static void virtio_pc_save_device(VirtIODevice *vdev, QEMUFile *f)
{
}

static int virtio_pc_load_device(VirtIODevice *vdev, QEMUFile *f, int version_id)
{
    return 0;
}

static bool virtio_pc_guest_notifier_pending(VirtIODevice *vdev, int idx)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);
    assert(pc->vhost_running);
    return vhost_virtqueue_pending(&pc->hdev, idx);
}

static void virtio_pc_guest_notifier_mask(VirtIODevice *vdev, int idx,
                                           bool mask)
{
    VirtIOProdcons *pc = VIRTIO_PRODCONS(vdev);
    assert(pc->vhost_running);
    vhost_virtqueue_mask(&pc->hdev, vdev, idx, mask);
}

static void virtio_pc_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOProdcons *pc = VIRTIO_PRODCONS(dev);

    virtio_init(vdev, "virtio-prodcons", VIRTIO_ID_PRODCONS,
                sizeof(struct virtio_pc_config));

    pc->qdev = dev;
    pc->dvq = virtio_add_queue(vdev, pc->conf.l, virtio_pc_dvq_handler);
    pc->dvq_pending = 0;
    pc->wc = pc->conf.wc;
    pc->yc = pc->conf.yc;
    calibrate_tsc(); /* this could be done only once for all devices */
    pc->stats.last_dump = pc->stats.next_dump = rdtsc();
    pc->bh = qemu_bh_new(virtio_pc_dvq_bh, pc);
    if (pc->conf.vhost) {
        vhost_pc_init(pc);
    }
}

static void virtio_pc_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOProdcons *pc = VIRTIO_PRODCONS(dev);

    if (pc->conf.vhost) {
        vhost_pc_stop(pc);
        vhost_dev_cleanup(&pc->hdev);
    }
    qemu_bh_delete(pc->bh);
    virtio_del_queue(vdev, 0);
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
    DEFINE_PROP_BOOL("vhost", VirtIOProdcons, conf.vhost, false), /* ns */
    DEFINE_PROP_UINT32("wc", VirtIOProdcons, conf.wc, 400), /* ns */
    DEFINE_PROP_UINT32("yc", VirtIOProdcons, conf.wc, 5000), /* ns */
    DEFINE_PROP_UINT32("l", VirtIOProdcons, conf.l, 256), /* slots */
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
    vdc->set_config = virtio_pc_set_config;
    vdc->get_features = virtio_pc_get_features;
    vdc->set_features = virtio_pc_set_features;
    vdc->bad_features = virtio_pc_bad_features;
    vdc->reset = virtio_pc_reset;
    vdc->set_status = virtio_pc_set_status;
    vdc->load = virtio_pc_load_device;
    vdc->save = virtio_pc_save_device;
    vdc->guest_notifier_mask = virtio_pc_guest_notifier_mask;
    vdc->guest_notifier_pending = virtio_pc_guest_notifier_pending;
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
