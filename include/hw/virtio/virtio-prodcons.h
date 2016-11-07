#ifndef QEMU_VIRTIO_PRODCONS_H
#define QEMU_VIRTIO_PRODCONS_H

#include "hw/virtio/virtio.h"
#include "hw/virtio/vhost.h"

#define TYPE_VIRTIO_PRODCONS "virtio-prodcons-device"
#define VIRTIO_PRODCONS(obj) \
        OBJECT_CHECK(VirtIOProdcons, (obj), TYPE_VIRTIO_PRODCONS)

typedef struct virtio_pc_conf
{
    bool        vhost;
    uint32_t    wc;
    uint32_t    yc;
    uint32_t    l;
} virtio_pc_conf;

/* Layout of the virtio-prodcons config space */
struct virtio_pc_config {
    uint32_t    wc;
    uint32_t    yc;
    uint32_t    csleep;
    uint32_t    incsc;
};

typedef struct VirtIOProdcons {
    VirtIODevice parent_obj;
    struct vhost_dev hdev;
    struct vhost_virtqueue hvq;
    bool vhost_running;
    struct {
        uint32_t    items;
        uint32_t    kicks;
        uint32_t    interrupts;
        uint64_t    next_dump;
        uint64_t    last_dump;
    } stats;
    struct virtio_pc_config cfg;
    VirtQueue *dvq;
    QEMUBH *bh;
    int dvq_pending;
    virtio_pc_conf conf;
    DeviceState *qdev;
} VirtIOProdcons;

#endif
