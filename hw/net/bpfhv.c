/*
 * BPFHV paravirtual network device
 *
 * Copyright (c) 2018 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/range.h"
#include "qapi/error.h"
#include "bpfhv.h"

#ifdef BPFHV_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "bpfhv-if: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

static const char *regnames[] = {
    "STATUS",
    "MAC_LO",
    "MAC_HI",
    "NUM_RX_QUEUES",
    "NUM_TX_QUEUES",
    "NUM_RX_BUFS",
    "NUM_TX_BUFS",
    "RX_CTX_SIZE",
    "TX_CTX_SIZE",
    "DOORBELL_SIZE",
    "QUEUE_SELECT",
    "CTX_PADDR_LO",
    "CTX_PADDR_HI",
    "PROG_SELECT",
    "PROG_SIZE",
};

#define REGNAMES_LEN  (sizeof(regnames) / (sizeof(regnames[0])))

typedef struct BpfHvProg_st {
    unsigned int num_insns;
    uint8_t *insns;
} BpfHvProg;

typedef struct BpfHvTxQueue_st {
    struct bpfhv_tx_context *ctx;
} BpfHvTxQueue;

typedef struct BpfHvRxQueue_st {
    struct bpfhv_rx_context *ctx;
} BpfHvRxQueue;

typedef struct BpfHvState_st {
    /* Parent class. This is a private field, and it cannot be used. */
    PCIDevice pci_device;

    NICState *nic;
    NICConf conf;
    MemoryRegion io;

    /* Storage for the I/O registers. */
    uint32_t ioregs[BPFHV_IO_END >> 2];

    /* Total number of queues, including both receive and transmit
     * ones. */
    unsigned int num_queues;

    /* eBPF programs associated to this device. */
    BpfHvProg progs[BPFHV_PROG_MAX];

    BpfHvRxQueue *rxq;
    BpfHvTxQueue *txq;
} BpfHvState;

/* Macro to generate I/O register indices. */
#define BPFHV_REG(x) ((BPFHV_IO_ ## x) >> 2)

#define TYPE_BPFHV_PCI  "bpfhv-pci"

#define BPFHV(obj) \
            OBJECT_CHECK(BpfHvState, (obj), TYPE_BPFHV_PCI)

static ssize_t
bpfhv_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    return size;
}

/* Device link status is up iff all the contexts are valid and
 * the network backend link status is up. */
static void
bpfhv_link_status_update(BpfHvState *s)
{
    bool status = !!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_LINK);
    NetClientState *nc = qemu_get_queue(s->nic);
    bool new_status = !(nc->link_down);
    int i;

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] && new_status; i++) {
        if (s->rxq[i].ctx == NULL) {
            new_status = false;
        }
    }

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)] && new_status; i++) {
        if (s->txq[i].ctx == NULL) {
            new_status = false;
        }
    }

    if (new_status == status) {
        return;
    }

    DBG("Link status goes %s", new_status ? "up" : "down");
    s->ioregs[BPFHV_REG(STATUS)] ^= BPFHV_STATUS_LINK;
}

static void
bpfhv_ctx_remap(BpfHvState *s)
{
    unsigned int qsel = s->ioregs[BPFHV_REG(QUEUE_SELECT)];
    hwaddr base, len;
    void **pvaddr;

    base = ((uint64_t)s->ioregs[BPFHV_REG(CTX_PADDR_HI)] << 32) |
                    s->ioregs[BPFHV_REG(CTX_PADDR_LO)];

    if (qsel < BPFHV_IO_NUM_RX_QUEUES) {
        pvaddr = (void **)&s->rxq[qsel].ctx;
        len = s->ioregs[BPFHV_REG(RX_CTX_SIZE)];
    } else {
        pvaddr = (void **)&s->txq[qsel].ctx;
        len = s->ioregs[BPFHV_REG(TX_CTX_SIZE)];
    }

    /* Unmap the previous context, if any. */
    if (*pvaddr) {
        cpu_physical_memory_unmap(*pvaddr, len, /*is_write=*/1, len);
        *pvaddr = NULL;
    }

    /* Map the new context if it is provided. */
    if (base != 0) {
        *pvaddr = cpu_physical_memory_map(base, &len, /*is_write=*/1);
    }

    /* Possibly update link status. */
    bpfhv_link_status_update(s);
}

static void
bpfhv_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int index;

    addr = addr & BPFHV_IO_MASK;
    index = addr >> 2;

    if (addr >= BPFHV_IO_END) {
        DBG("Unknown I/O write addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    assert(index < REGNAMES_LEN);

    switch (addr) {
    case BPFHV_IO_QUEUE_SELECT:
        if (val >= s->num_queues) {
            DBG("Guest tried to select invalid queue #"PRIx64"\n", val);
            break;
        }
        s->ioregs[index] = val;
        break;

    case BPFHV_IO_CTX_PADDR_LO:
        s->ioregs[index] = val;
        break;

    case BPFHV_IO_CTX_PADDR_HI:
        s->ioregs[index] = val;
        /* A write to the most significant 32-bit word also triggers context
         * mapping (or unmapping). */
        bpfhv_ctx_remap(s);
        break;

    case BPFHV_IO_PROG_SELECT:
        if (val >= BPFHV_PROG_MAX) {
            DBG("Guest tried to select invalid program #"PRIx64"\n", val);
            break;
        }
        s->ioregs[index] = val;
        s->ioregs[BPFHV_REG(PROG_SIZE)] = s->progs[val].num_insns;
        break;

    default:
        DBG("I/O write to %s ignored, val=0x%08" PRIx64,
            regnames[index], val);
        return;
        break;
    }

    DBG("I/O write to %s, val=0x%08" PRIx64, regnames[index], val);
}

static uint64_t
bpfhv_io_read(void *opaque, hwaddr addr, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int index;

    addr = addr & BPFHV_IO_MASK;
    index = addr >> 2;

    if (addr >= BPFHV_IO_END) {
        DBG("Unknown I/O read addr=0x%08"PRIx64, addr);
        return 0;
    }

    assert(index < REGNAMES_LEN);

    DBG("I/O read from %s, val=0x%08x", regnames[index], s->ioregs[index]);

    return s->ioregs[index];
}

static void
bpfhv_backend_link_status_changed(NetClientState *nc)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);

    bpfhv_link_status_update(s);
}

static const MemoryRegionOps bpfhv_io_ops = {
    .read = bpfhv_io_read,
    .write = bpfhv_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};
static const VMStateDescription vmstate_bpfhv = {
    .name = "bpfhv",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(pci_device, BpfHvState),
        VMSTATE_UINT32(ioregs[0], BpfHvState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static NetClientInfo net_bpfhv_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .receive = bpfhv_receive,
    .link_status_changed = bpfhv_backend_link_status_changed,
};

static void
pci_bpfhv_realize(PCIDevice *pci_dev, Error **errp)
{
    DeviceState *dev = DEVICE(pci_dev);
    BpfHvState *s = BPFHV(pci_dev);
    NetClientState *nc;
    uint8_t *pci_conf;
    int i;

    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Init I/O mapped memory region, exposing bpfhv registers. */
    memory_region_init_io(&s->io, OBJECT(s), &bpfhv_io_ops, s,
                          "bpfhv-io", BPFHV_IO_MASK + 1);
    pci_register_bar(pci_dev, BPFHV_IO_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

    qemu_macaddr_default_if_unset(&s->conf.macaddr);

    s->nic = qemu_new_nic(&net_bpfhv_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, s->conf.macaddr.a);

    /* Initialize device registers. */
    memset(s->ioregs, 0, sizeof(s->ioregs));
    s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] = 1;
    s->ioregs[BPFHV_REG(NUM_TX_QUEUES)] = 1;
    s->ioregs[BPFHV_REG(NUM_RX_BUFS)] = 256;
    s->ioregs[BPFHV_REG(NUM_TX_BUFS)] = 256;
    s->ioregs[BPFHV_REG(RX_CTX_SIZE)] = sizeof(struct bpfhv_rx_context)
						+ 1024;
    s->ioregs[BPFHV_REG(TX_CTX_SIZE)] = sizeof(struct bpfhv_tx_context)
						+ 1024;
    s->ioregs[BPFHV_REG(DOORBELL_SIZE)] = 8; /* could be 4096 */
    s->num_queues = s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] +
                    s->ioregs[BPFHV_REG(NUM_TX_QUEUES)];

    /* Initialize eBPF programs. */
    for (i = BPFHV_PROG_NONE; i < BPFHV_PROG_MAX; i++) {
        s->progs[i].num_insns = 0;
        s->progs[i].insns = NULL;
    }

    /* Initialize device queues. */
    s->rxq = g_malloc0(s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]
			* sizeof(s->rxq[0]));
    s->txq = g_malloc0(s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]
			* sizeof(s->txq[0]));

    /* Allocate a PCI bar to manage MSI-X information for this device. */
    if (msix_init_exclusive_bar(pci_dev, s->num_queues,
                                BPFHV_MSIX_PCI_BAR, NULL)) {
        error_setg(errp, "Failed to initialize MSI-X BAR");
        return;
    }

    DBG("%s(%p)", __func__, s);
}

static void
pci_bpfhv_uninit(PCIDevice *dev)
{
    BpfHvState *s = BPFHV(dev);

    g_free(s->rxq);
    g_free(s->txq);
    msix_uninit_exclusive_bar(PCI_DEVICE(s));
    qemu_del_nic(s->nic);

    DBG("%s: %p", __func__, s);
}

static void qdev_bpfhv_reset(DeviceState *dev)
{
    BpfHvState *s = BPFHV(dev);
    uint8_t *macaddr;

    /* Init MAC address registers. */
    macaddr = s->conf.macaddr.a;
    s->ioregs[BPFHV_REG(MAC_LO)] = (macaddr[0] << 8) | macaddr[1];
    s->ioregs[BPFHV_REG(MAC_HI)] = (macaddr[2] << 24) | (macaddr[3] << 16)
                                 | (macaddr[4] << 8) | macaddr[5];

    DBG("%s(%p)", __func__, s);
}

static Property bpfhv_properties[] = {
    DEFINE_NIC_PROPERTIES(BpfHvState, conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void bpfhv_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_bpfhv_realize;
    k->exit = pci_bpfhv_uninit;
    k->vendor_id = BPFHV_PCI_VENDOR_ID;
    k->device_id = BPFHV_PCI_DEVICE_ID;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "BPF network device";
    dc->reset = qdev_bpfhv_reset;
    dc->vmsd = &vmstate_bpfhv;
    dc->props = bpfhv_properties;
}

static void bpfhv_instance_init(Object *obj)
{
    BpfHvState *s = BPFHV(obj);
    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(s), NULL);
}

static const TypeInfo bpfhv_info = {
    .name          = TYPE_BPFHV_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(BpfHvState),
    .instance_init = bpfhv_instance_init,
    .class_init    = bpfhv_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { }
    },
};

static void bpfhv_register_types(void)
{
    type_register_static(&bpfhv_info);
}

type_init(bpfhv_register_types)
