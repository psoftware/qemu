/*
 * Virtio Network Device
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _QEMU_VIRTIO_MPI_H
#define _QEMU_VIRTIO_MPI_H

#include "hw/virtio/virtio.h"
#include "hw/pci/pci.h"
#include "net/vhost_mpi.h"

#define TYPE_VIRTIO_MPI "virtio-mpi-device"
#define VIRTIO_MPI(obj) \
        OBJECT_CHECK(VirtIOMpi, (obj), TYPE_VIRTIO_MPI)

/* The ID for virtio_mpi */
#define VIRTIO_ID_MPI  15

struct virtio_mpi_config
{
    /* See VIRTIO_MPI_F_STATUS and VIRTIO_MPI_S_* above */
    uint16_t status;
} QEMU_PACKED;

typedef struct VirtIOMpiQueue {
    VirtQueue *rx_vq;
    VirtQueue *tx_vq;
    struct VirtIOMpi *n;
} VirtIOMpiQueue;

typedef struct VirtIOMpi {
    VirtIODevice parent_obj;
    uint16_t status;
    VirtIOMpiQueue *vqs;
    uint8_t vhost_started;
    DeviceState *qdev;
    VHostMpiState *vhost_mpi;
} VirtIOMpi;


#define DEFINE_VIRTIO_MPI_FEATURES(_state, _field) \
        DEFINE_VIRTIO_COMMON_FEATURES(_state, _field), \
        DEFINE_PROP_BIT("any_layout", _state, _field, VIRTIO_F_ANY_LAYOUT, true)

#endif
