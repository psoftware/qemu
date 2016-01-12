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
#include "net/checksum.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include "qemu/iov.h"
#include "qemu/range.h"

#include <net/if.h>
#include "net/netmap.h"
#include "dev/netmap/netmap_virt.h"

#define PTNET_DEBUG

#ifdef PTNET_DEBUG
enum {
    DEBUG_GENERAL,      DEBUG_IO,       DEBUG_MMIO,     DEBUG_INTERRUPT,
    DEBUG_RX,           DEBUG_TX,       DEBUG_MDIC,     DEBUG_EEPROM,
    DEBUG_UNKNOWN,      DEBUG_TXSUM,    DEBUG_TXERR,    DEBUG_RXERR,
    DEBUG_RXFILTER,     DEBUG_PHY,      DEBUG_NOTYET,
};
#define DBGBIT(x)    (1<<DEBUG_##x)
static int debugflags = DBGBIT(TXERR) | DBGBIT(GENERAL);

#define DBGOUT(what, fmt, ...) do { \
    if (debugflags & DBGBIT(what)) \
        fprintf(stderr, "ptnet: " fmt, ## __VA_ARGS__); \
    } while (0)
#else
#define DBGOUT(what, fmt, ...) do {} while (0)
#endif

#define IOPORT_SIZE       0x40
#define PNPMMIO_SIZE      0x20000

typedef struct PtNetState_st {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[32];
} PtNetState;

typedef struct PTNETBaseClass {
    PCIDeviceClass parent_class;
    uint16_t phy_id2;
} PTNETBaseClass;

#define TYPE_PTNET_BASE "ptnet-pci"

#define PTNET(obj) \
    OBJECT_CHECK(PtNetState, (obj), TYPE_PTNET_BASE)

#define PTNET_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(PTNETBaseClass, (klass), TYPE_PTNET_BASE)
#define PTNET_DEVICE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(PTNETBaseClass, (obj), TYPE_PTNET_BASE)

static void
ptnet_set_link_status(NetClientState *nc)
{
    PtNetState *s = qemu_get_nic_opaque(nc);

    printf("%s(%p)\n", __func__, s);
}

static int
ptnet_can_receive(NetClientState *nc)
{
    return false;
}

static ssize_t
ptnet_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    return iov_size(iov, iovcnt);
}

static ssize_t
ptnet_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return ptnet_receive_iov(nc, &iov, 1);
}

static uint32_t
mac_readreg(PtNetState *s, int index)
{
    return s->mac_reg[index];
}

static void
mac_writereg(PtNetState *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
}

#define PTNET_IO_PTFEAT         0
#define PTNET_IO_PTCTL          4
#define PTNET_IO_PTSTS          8
#define PTNET_IO_MAX            12

#define getreg(x)    [x] = mac_readreg
static uint32_t (*macreg_readops[])(PtNetState *, int) = {
    [PTNET_IO_PTFEAT] = mac_readreg,
    [PTNET_IO_PTCTL] = mac_readreg,
    [PTNET_IO_PTSTS] = mac_readreg,
};
enum { NREADOPS = ARRAY_SIZE(macreg_readops) };

#define putreg(x)    [x] = mac_writereg
static void (*macreg_writeops[])(PtNetState *, int, uint32_t) = {
    [PTNET_IO_PTFEAT] = mac_writereg,
    [PTNET_IO_PTCTL] = mac_writereg,
    [PTNET_IO_PTSTS] = mac_writereg,
};

enum { NWRITEOPS = ARRAY_SIZE(macreg_writeops) };

static void
ptnet_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                 unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NWRITEOPS && macreg_writeops[index]) {
        macreg_writeops[index](s, index, val);
    } else if (index < NREADOPS && macreg_readops[index]) {
        DBGOUT(MMIO, "ptnet_mmio_writel RO %x: 0x%04"PRIx64"\n",
               index<<2, val);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown write addr=0x%08x,val=0x%08"PRIx64"\n",
               index<<2, val);
    }
}

static uint64_t
ptnet_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NREADOPS && macreg_readops[index]) {
        return macreg_readops[index](s, index);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown read addr=0x%08x\n", index<<2);
    }
    return 0;
}

static const MemoryRegionOps ptnet_mmio_ops = {
    .read = ptnet_mmio_read,
    .write = ptnet_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t ptnet_io_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    PtNetState *s = opaque;

    (void)s;
    return 0;
}

static void ptnet_io_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    PtNetState *s = opaque;

    (void)s;
}

static const MemoryRegionOps ptnet_io_ops = {
    .read = ptnet_io_read,
    .write = ptnet_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void ptnet_pre_save(void *opaque)
{
    PtNetState *s = opaque;
    printf("%s(%p)\n", __func__, s);
}

static int ptnet_post_load(void *opaque, int version_id)
{
    PtNetState *s = opaque;
    printf("%s(%p)\n", __func__, s);
    return 0;
}

static const VMStateDescription vmstate_ptnet = {
    .name = "ptnet",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = ptnet_pre_save,
    .post_load = ptnet_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, PtNetState),
        VMSTATE_UINT32(mac_reg[PTNET_IO_PTFEAT], PtNetState),
        VMSTATE_UINT32(mac_reg[PTNET_IO_PTCTL], PtNetState),
        VMSTATE_UINT32(mac_reg[PTNET_IO_PTSTS], PtNetState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static void
ptnet_mmio_setup(PtNetState *s)
{
    memory_region_init_io(&s->mmio, OBJECT(s), &ptnet_mmio_ops, s,
                          "ptnet-mmio", PNPMMIO_SIZE);
    memory_region_init_io(&s->io, OBJECT(s), &ptnet_io_ops, s, "ptnet-io", IOPORT_SIZE);
}

static void
pci_ptnet_uninit(PCIDevice *dev)
{
    PtNetState *s = PTNET(dev);

    qemu_del_nic(s->nic);
}

static NetClientInfo net_ptnet_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = ptnet_can_receive,
    .receive = ptnet_receive,
    .receive_iov = ptnet_receive_iov,
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

    ptnet_mmio_setup(s);

    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &s->io);

    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    macaddr = s->conf.macaddr.a;

    s->nic = qemu_new_nic(&net_ptnet_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);

    qemu_format_nic_info_str(qemu_get_queue(s->nic), macaddr);
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

typedef struct PTNETInfo {
    const char *name;
    uint16_t   device_id;
    uint8_t    revision;
    uint16_t   phy_id2;
} PTNETInfo;

static void ptnet_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    PTNETBaseClass *e = PTNET_DEVICE_CLASS(klass);
    const PTNETInfo *info = data;

    k->realize = pci_ptnet_realize;
    k->exit = pci_ptnet_uninit;
    k->romfile = "efi-ptnet.rom";
    k->vendor_id = PTNETMAP_PCI_VENDOR_ID;
    k->device_id = info->device_id;
    k->revision = info->revision;
    e->phy_id2 = info->phy_id2;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Netmap passthrough network device";
    dc->reset = qdev_ptnet_reset;
    dc->vmsd = &vmstate_ptnet;
    dc->props = ptnet_properties;
}

static void ptnet_instance_init(Object *obj)
{
    PtNetState *n = PTNET(obj);
    device_add_bootindex_property(obj, &n->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(n), NULL);
}

static const TypeInfo ptnet_info = {
    .name          = TYPE_PTNET_BASE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PtNetState),
    .instance_init = ptnet_instance_init,
    .class_init    = ptnet_class_init,
};

static const PTNETInfo ptnet_devices[] = {
    {
        .name      = "ptnet",
        .device_id = PTNETMAP_PCI_NETIF_ID,
        .revision  = 0x00,
        .phy_id2   = 0x00,
    },
};

static void ptnet_register_types(void)
{
    type_register_static(&ptnet_info);
}

type_init(ptnet_register_types)
