/*
 * QEMU netmap passthrough device
 *
 * Copyright (c) 2015 Vincenzo Maffione <v.maffione@gmail.com>
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


#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "qemu/iov.h"
#include "qemu/range.h"

#include <net/if.h>
#include "net/netmap.h"
#include "dev/netmap/netmap_virt.h"

#define PTNET_DEBUG

#ifdef PTNET_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "ptnet: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(what, fmt, ...) do {} while (0)
#endif

#define CSB_SIZE      4096

#define PTNET_IO_PTFEAT         0
#define PTNET_IO_PTCTL          4
#define PTNET_IO_PTSTS          8
#define PTNET_IO_MAX            12
#define PTNET_IO_MASK           0xf

typedef struct PtNetState_st {
    PCIDevice pci_device; /* Private field. */

    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[PTNET_IO_MAX];
} PtNetState;

#define TYPE_PTNET_PCI  "ptnet-pci"

#define PTNET(obj) \
            OBJECT_CHECK(PtNetState, (obj), TYPE_PTNET_PCI)

static void
ptnet_set_link_status(NetClientState *nc)
{
    PtNetState *s = qemu_get_nic_opaque(nc);

    DBG("%s(%p)", __func__, s);
}

static int
ptnet_can_receive(NetClientState *nc)
{
    return false;
}

static ssize_t
ptnet_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    return size;
}

static void
ptnet_io_write(void *opaque, hwaddr addr, uint64_t val,
                 unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;
    const char *regname = "";

    addr = addr & PTNET_IO_MASK;
    index = addr >> 2;

    (void)s;

    if (addr >= PTNET_IO_MAX) {
        DBG("Unknown I/O write addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    switch (addr) {
        case PTNET_IO_PTFEAT:
            regname = "PTNET_IO_PTFEAT";
            break;

        case PTNET_IO_PTCTL:
            regname = "PTNET_IO_PTCTL";
            break;

        case PTNET_IO_PTSTS:
            regname = "PTNET_IO_PTSTS";
            break;
    }

    DBG("I/O write to %s, val=0x%08" PRIx64, regname, val);

    s->mac_reg[index] = val;
}

static uint64_t
ptnet_io_read(void *opaque, hwaddr addr, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;
    const char *regname = "";

    addr = addr & PTNET_IO_MASK;
    index = addr >> 2;

    (void)s;

    if (addr >= PTNET_IO_MAX) {
        DBG("Unknown I/O read addr=0x%08"PRIx64, addr);
        return 0;
    }

    switch (addr) {
        case PTNET_IO_PTFEAT:
            regname = "PTNET_IO_PTFEAT";
            break;

        case PTNET_IO_PTCTL:
            regname = "PTNET_IO_PTCTL";
            break;

        case PTNET_IO_PTSTS:
            regname = "PTNET_IO_PTSTS";
            break;
    }

    DBG("I/O read from %s, val=0x%04x", regname, s->mac_reg[index]);

    return s->mac_reg[index];
}

static const MemoryRegionOps ptnet_io_ops = {
    .read = ptnet_io_read,
    .write = ptnet_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t ptnet_mmio_read(void *opaque, hwaddr addr,
                                unsigned size)
{
    PtNetState *s = opaque;

    (void)s;
    return 0;
}

static void ptnet_mmio_write(void *opaque, hwaddr addr,
                             uint64_t val, unsigned size)
{
    PtNetState *s = opaque;

    (void)s;
}

static const MemoryRegionOps ptnet_mmio_ops = {
    .read = ptnet_mmio_read,
    .write = ptnet_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void ptnet_pre_save(void *opaque)
{
    PtNetState *s = opaque;
    DBG("%s(%p)", __func__, s);
}

static int ptnet_post_load(void *opaque, int version_id)
{
    PtNetState *s = opaque;
    DBG("%s(%p)", __func__, s);
    return 0;
}

static const VMStateDescription vmstate_ptnet = {
    .name = "ptnet",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = ptnet_pre_save,
    .post_load = ptnet_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(pci_device, PtNetState),
        VMSTATE_UINT32(mac_reg[PTNET_IO_PTFEAT], PtNetState),
        VMSTATE_UINT32(mac_reg[PTNET_IO_PTCTL], PtNetState),
        VMSTATE_UINT32(mac_reg[PTNET_IO_PTSTS], PtNetState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static void
pci_ptnet_uninit(PCIDevice *dev)
{
    PtNetState *s = PTNET(dev);

    qemu_del_nic(s->nic);

    DBG("%s: %p", __func__, s);
}

static NetClientInfo net_ptnet_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = ptnet_can_receive,
    .receive = ptnet_receive,
    .link_status_changed = ptnet_set_link_status,
};

static void ptnet_write_config(PCIDevice *pci_dev, uint32_t address,
                                uint32_t val, int len)
{
    PtNetState *s = PTNET(pci_dev);

    pci_default_write_config(pci_dev, address, val, len);

    if (range_covers_byte(address, len, PCI_COMMAND) &&
        (pci_dev->config[PCI_COMMAND] & PCI_COMMAND_MASTER)) {
        printf("%s(%p)", __func__, s);
    }
}

static void pci_ptnet_realize(PCIDevice *pci_dev, Error **errp)
{
    DeviceState *dev = DEVICE(pci_dev);
    PtNetState *s = PTNET(pci_dev);
    uint8_t *pci_conf;
    uint8_t *macaddr;

    pci_dev->config_write = ptnet_write_config;
    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Init I/O mapped memory region, exposing ptnetmap registers. */
    memory_region_init_io(&s->io, OBJECT(s), &ptnet_io_ops, s,
                          "ptnet-io", PTNET_IO_MAX);
    pci_register_bar(pci_dev, PTNETMAP_IO_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

    /* Init memory mapped memory region, exposing CSB. */
    memory_region_init_io(&s->mmio, OBJECT(s), &ptnet_mmio_ops, s,
                          "ptnet-mmio", CSB_SIZE);
    pci_register_bar(pci_dev, PTNETMAP_MEM_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    macaddr = s->conf.macaddr.a;

    s->nic = qemu_new_nic(&net_ptnet_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), macaddr);

    DBG("%s: %p", __func__, s);
}

static void qdev_ptnet_reset(DeviceState *dev)
{
    PtNetState *s = PTNET(dev);
    /* Init registers */
    printf("%s(%p)", __func__, s);
}

static Property ptnet_properties[] = {
    DEFINE_NIC_PROPERTIES(PtNetState, conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void ptnet_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_ptnet_realize;
    k->exit = pci_ptnet_uninit;
    k->vendor_id = PTNETMAP_PCI_VENDOR_ID;
    k->device_id = PTNETMAP_PCI_NETIF_ID;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Netmap passthrough network device";
    dc->reset = qdev_ptnet_reset;
    dc->vmsd = &vmstate_ptnet;
    dc->props = ptnet_properties;
}

static void ptnet_instance_init(Object *obj)
{
    PtNetState *s = PTNET(obj);
    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(s), NULL);
}

static const TypeInfo ptnet_info = {
    .name          = TYPE_PTNET_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PtNetState),
    .instance_init = ptnet_instance_init,
    .class_init    = ptnet_class_init,
};

static void ptnet_register_types(void)
{
    type_register_static(&ptnet_info);
}

type_init(ptnet_register_types)
